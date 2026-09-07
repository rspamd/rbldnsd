/* Portable, offset-based dnhash snapshots. All integers are big-endian u32.
 * No pointer or native structure is ever persisted. See README.snapshot.md. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <syslog.h>
#include "rbldnsd.h"
#include "rbldnsd_snapshot.h"
#include "rbldnsd_overlay.h"

#define SNAPSHOT_HEADER_SIZE 128U
#define SNAPSHOT_RECORD_SIZE 24U
#define SNAPSHOT_SIZE_LIMIT (1024U * 1024U * 1024U)

static unsigned read_u32(const void *v) {
  const unsigned char *data = v;

  return unpack32(data);
}

static void write_u32(void *v, unsigned n) {
  unsigned char *data = v;

  PACK32(data, n);
}

static uint32_t checksum(const unsigned char *data, size_t n) {
  uint32_t h = 2166136261U;
  for (size_t i = 0; i < n; i++) {
    h = (h ^ (i >= 24 && i < 28 ? 0 : data[i])) * 16777619U;
  }
  return h;
}

struct dsdata {
  unsigned char *map;
  size_t size;
  unsigned count;
};

definedstype(dnsnapshot, 0, "read-only compiled domain snapshot");

static void ds_dnsnapshot_reset(struct dsdata *d, int UNUSED all) {
  if (d->map) {
    munmap(d->map, d->size);
  }
  memset(d, 0, sizeof(*d));
}

static void ds_dnsnapshot_start(struct dataset *UNUSED ds) {
}

static int ds_dnsnapshot_line(struct dataset *UNUSED ds, char *UNUSED line,
                              struct dsctx *UNUSED ctx) {
  return 0;
}

static void ds_dnsnapshot_finish(struct dataset *ds, struct dsctx *ctx) {
  dsloaded(ctx, "entries=%u, mapped=%lu", ds->ds_dsd->count, (unsigned long)ds->ds_dsd->size);
}

static int compare_keys(unsigned t, const unsigned char *n, unsigned len, unsigned rt,
                        const unsigned char *rn, unsigned rlen) {
  if (t != rt) {
    return t < rt ? -1 : 1;
  }
  unsigned m = len < rlen ? len : rlen;
  int c = memcmp(n, rn, m);
  if (c != 0) {
    return c;
  }
  if (len == rlen) {
    return 0;
  }
  return len < rlen ? -1 : 1;
}

static void decode_entry(const struct dsdata *d, unsigned i, struct snapshot_entry *entry) {
  const unsigned char *record = d->map + SNAPSHOT_HEADER_SIZE + i * SNAPSHOT_RECORD_SIZE;
  entry->table = read_u32(record);
  entry->name = d->map + read_u32(record + 4);
  entry->namelen = read_u32(record + 8);
  entry->rr = read_u32(record + 12) ? (const char *)d->map + read_u32(record + 12) : NULL;
  entry->nparams = read_u32(record + 20);
  const unsigned char *data = d->map + read_u32(record + 16);
  for (unsigned j = 0; j < entry->nparams; j++) {
    entry->params[j].k = (const char *)d->map + read_u32(data + j * 8);
    entry->params[j].v = (const char *)d->map + read_u32(data + j * 8 + 4);
  }
}

int rbldnsd_snapshot_lookup(const struct dataset *ds, const unsigned char *n, unsigned len,
                            unsigned table, struct snapshot_entry *entry) {
  const struct dsdata *d = ds->ds_dsd;

  unsigned lo = 0;
  unsigned hi = d->count;

  while (lo < hi) {
    unsigned mid = lo + (hi - lo) / 2;
    const unsigned char *record = d->map + SNAPSHOT_HEADER_SIZE + mid * SNAPSHOT_RECORD_SIZE;
    int c = compare_keys(table, n, len, read_u32(record), d->map + read_u32(record + 4),
                         read_u32(record + 8));
    if (!c) {
      decode_entry(d, mid, entry);
      return 1;
    }
    if (c < 0) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }

  return 0;
}

int rbldnsd_snapshot_foreach(const struct dataset *ds, snapshot_visit_fn *visit, void *arg) {
  for (unsigned i = 0; i < ds->ds_dsd->count; i++) {
    struct snapshot_entry entry;
    decode_entry(ds->ds_dsd, i, &entry);
    if (!visit(&entry, arg)) {
      return 0;
    }
  }
  return 1;
}

static int valid_string(const unsigned char *data, size_t size, unsigned off, unsigned min,
                        unsigned max) {
  if (off < min || off >= size) {
    return 0;
  }
  size_t n = size - off;
  if (n > max + 1U) {
    n = max + 1U;
  }
  return memchr(data + off, 0, n) != NULL;
}

static unsigned domain_length(const unsigned char *data, size_t size, unsigned off,
                              unsigned start) {
  if (off < start || off >= size) {
    return 0;
  }
  unsigned pos = 0;
  while (pos < DNS_MAXDN && pos < size - off) {
    unsigned l = data[off + pos];
    pos++;
    if (!l) {
      return pos;
    }
    if (l > 63 || l > size - off - pos || pos + l >= DNS_MAXDN) {
      return 0;
    }
    pos += l;
  }
  return 0;
}

int rbldnsd_snapshot_load(struct dataset *ds, int fd, struct dsctx *ctx) {
  struct stat st;
  if (fstat(fd, &st) < 0 || st.st_size < SNAPSHOT_HEADER_SIZE || st.st_size > SNAPSHOT_SIZE_LIMIT) {
    goto bad;
  }

  size_t size = (size_t)st.st_size;
  unsigned char *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    goto bad;
  }

  /* Validate the header before following any stored offsets. */
  unsigned record_count = read_u32(data + 16);
  unsigned data_start;
  if (memcmp(data, "RBLDNSNP", 8) || read_u32(data + 8) != 1 || read_u32(data + 12) != size ||
      record_count > (size - SNAPSHOT_HEADER_SIZE) / SNAPSHOT_RECORD_SIZE ||
      read_u32(data + 24) != checksum(data, size) || read_u32(data + 28) || read_u32(data + 76) ||
      read_u32(data + 112) || read_u32(data + 116) || read_u32(data + 120) ||
      read_u32(data + 124)) {
    goto unmap;
  }

  data_start = SNAPSHOT_HEADER_SIZE + record_count * SNAPSHOT_RECORD_SIZE;
  for (unsigned i = 0; i < 11; i++) {
    if (read_u32(data + 32 + i * 4) &&
        !valid_string(data, size, read_u32(data + 32 + i * 4), data_start, 65535)) {
      goto unmap;
    }
  }

  /* Validate records, parameter strings, and ordering for binary lookup. */
  for (unsigned i = 0; i < record_count; i++) {
    const unsigned char *record = data + SNAPSHOT_HEADER_SIZE + i * SNAPSHOT_RECORD_SIZE;
    unsigned table = read_u32(record);
    unsigned name_offset = read_u32(record + 4);
    unsigned name_length = read_u32(record + 8);
    unsigned reply_offset = read_u32(record + 12);
    unsigned params_offset = read_u32(record + 16);
    unsigned param_count = read_u32(record + 20);
    if (table > 5 || name_length == 0 || name_length >= DNS_MAXDN || name_offset < data_start ||
        name_offset >= size || name_length >= size - name_offset ||
        data[name_offset + name_length]) {
      goto unmap;
    }
    unsigned position = 0;
    unsigned label_count = 0;
    while (position < name_length) {
      unsigned label_length = data[name_offset + position];
      if (!label_length || label_length > 63 || label_length + 1 > name_length - position) {
        goto unmap;
      }
      position += label_length + 1;
      label_count++;
    }
    if (position != name_length || (table && label_count != table)) {
      goto unmap;
    }
    if (reply_offset &&
        (reply_offset < data_start || reply_offset >= size || size - reply_offset < 5 ||
         !valid_string(data, size, reply_offset + 4, data_start, 255))) {
      goto unmap;
    }
    if (param_count > SNAPSHOT_MAX_PARAMS ||
        (param_count && (params_offset < data_start || params_offset >= size ||
                         param_count > (size - params_offset) / 8))) {
      goto unmap;
    }
    if (!param_count && params_offset) {
      goto unmap;
    }
    for (unsigned j = 0; j < param_count; j++) {
      if (!valid_string(data, size, read_u32(data + params_offset + j * 8), data_start, 65535) ||
          !valid_string(data, size, read_u32(data + params_offset + j * 8 + 4), data_start,
                        65535)) {
        goto unmap;
      }
    }
    if (i) {
      const unsigned char *prev = record - SNAPSHOT_RECORD_SIZE;
      if (compare_keys(read_u32(prev), data + read_u32(prev + 4), read_u32(prev + 8), table,
                       data + name_offset, name_length) >= 0) {
        goto unmap;
      }
    }
  }

  /* Validate zone metadata before publishing the mapped dataset. */
  unsigned soa_offset = read_u32(data + 80);
  unsigned ns_offset = read_u32(data + 84);
  unsigned ns_count = read_u32(data + 88);
  if (soa_offset && (soa_offset < data_start || soa_offset >= size || size - soa_offset < 32 ||
                     !domain_length(data, size, read_u32(data + soa_offset + 4), data_start) ||
                     !domain_length(data, size, read_u32(data + soa_offset + 8), data_start))) {
    goto unmap;
  }
  if (ns_count > 1024 ||
      (ns_count &&
       (ns_offset < data_start || ns_offset >= size || ns_count > (size - ns_offset) / 4)) ||
      (!ns_count && ns_offset)) {
    goto unmap;
  }
  for (unsigned i = 0; i < ns_count; i++) {
    if (!domain_length(data, size, read_u32(data + ns_offset + i * 4), data_start)) {
      goto unmap;
    }
  }
  uint64_t stamp = ((uint64_t)read_u32(data + 104) << 32) | read_u32(data + 108);
  if ((uint64_t)(time_t)stamp != stamp || (time_t)stamp <= 0) {
    goto unmap;
  }
  ds->ds_stamp = (time_t)stamp;
  uint64_t expiry = ((uint64_t)read_u32(data + 96) << 32) | read_u32(data + 100);
  if ((uint64_t)(time_t)expiry != expiry || (time_t)expiry < 0) {
    goto unmap;
  }

  if (soa_offset) {
    struct dssoa *out = mp_alloc(ds->ds_mp, sizeof(*out), 1);
    if (!out) {
      goto unmap;
    }
    out->dssoa_ttl = read_u32(data + soa_offset);
    out->dssoa_odn = data + read_u32(data + soa_offset + 4);
    out->dssoa_pdn = data + read_u32(data + soa_offset + 8);
    out->dssoa_serial = read_u32(data + soa_offset + 12);
    memcpy(out->dssoa_n, data + soa_offset + 16, 16);
    ds->ds_dssoa = out;
  }

  struct dsns **tail = &ds->ds_dsns;
  for (unsigned i = 0; i < ns_count; i++) {
    unsigned name_offset = read_u32(data + ns_offset + i * 4);
    unsigned name_bytes = domain_length(data, size, name_offset, data_start);
    struct dsns *ns = mp_alloc(ds->ds_mp, sizeof(*ns) + name_bytes, 1);
    if (!ns) {
      goto unmap;
    }
    ns->dsns_next = NULL;
    memcpy(ns->dsns_dn, data + name_offset, name_bytes);
    *tail = ns;
    tail = &ns->dsns_next;
  }

  ds->ds_nsttl = read_u32(data + 92);
  ds->ds_expires = (time_t)expiry;
  rbldnsd_overlay_loaded(ds, fd);
  ds->ds_dsd->map = data;
  ds->ds_dsd->size = size;
  ds->ds_dsd->count = record_count;
  ds->ds_ttl = read_u32(data + 20);
  for (unsigned i = 0; i < 11; i++) {
    ds->ds_subst[i] =
        read_u32(data + 32 + i * 4) ? (char *)data + read_u32(data + 32 + i * 4) : NULL;
  }

  return 1;

unmap:
  munmap(data, size);

bad:
  dslog(LOG_ERR, ctx, "invalid or unsupported dnsnapshot file");
  return 0;
}

static int answer_entry(const struct dataset *ds, const struct dnsqinfo *qi, struct dnspacket *pkt,
                        const struct snapshot_entry *entry) {
  if (!entry->rr) {
    return 0;
  }

  union {
    struct kv_params align;
    unsigned char bytes[sizeof(struct kv_params) + SNAPSHOT_MAX_PARAMS * sizeof(struct kv_pair)];
  } storage;
  struct kv_params *params = (struct kv_params *)storage.bytes;
  params->n = entry->nparams;
  params->storage = NULL;
  memcpy(params->kv, entry->params, entry->nparams * sizeof(struct kv_pair));

  struct entry_action act = {1, 0, 0};
  rbldnsd_apply_entry_params(pkt->p_peer, ds, qi, params, &act);
  if (!act.allow) {
    return 0;
  }
  if (act.delay_ms > pkt->p_delay_ms) {
    pkt->p_delay_ms = act.delay_ms;
  }

  char name[DNS_MAXDOMAIN + 1];
  dns_dntop(entry->name, name, sizeof(name));
  addrr_a_txt(pkt, qi->qi_tflag, entry->rr, name, ds);
  return NSQUERY_FOUND;
}

static int ds_dnsnapshot_query(const struct dataset *ds, const struct dnsqinfo *qi,
                               struct dnspacket *pkt) {
  const unsigned char *dn = qi->qi_dn;
  unsigned len = qi->qi_dnlen0;
  unsigned lab = qi->qi_dnlab;
  struct snapshot_entry entry;

  int overlay = rbldnsd_overlay_query(ds, qi, pkt);
  if (overlay >= 0) {
    return overlay;
  }
  if (!lab) {
    return 0;
  }

  check_query_overwrites(qi);
  if (rbldnsd_snapshot_lookup(ds, dn, len, 0, &entry)) {
    return answer_entry(ds, qi, pkt, &entry);
  }

  while (--lab) {
    len -= *dn + 1;
    dn += *dn + 1;
    if (lab <= 5 && rbldnsd_snapshot_lookup(ds, dn, len, lab, &entry) && entry.rr) {
      return answer_entry(ds, qi, pkt, &entry);
    }
  }
  return 0;
}
#ifndef NO_MASTER_DUMP
static void ds_dnsnapshot_dump(const struct dataset *ds, const unsigned char *UNUSED odn, FILE *f) {
  for (unsigned i = 0; i < ds->ds_dsd->count; i++) {
    struct snapshot_entry entry;
    char name[DNS_MAXDOMAIN + 4];
    decode_entry(ds->ds_dsd, i, &entry);
    if (entry.table) {
      name[0] = '*';
      name[1] = '.';
    }
    dns_dntop(entry.name, name + (entry.table ? 2 : 0), sizeof(name) - (entry.table ? 2 : 0));
    dump_a_txt(name, entry.rr, entry.table ? name + 2 : name, ds, f);
  }
}
#endif
struct saved_entry {
  const unsigned char *name;
  unsigned namelen;
  unsigned table;
  const char *rr;
  unsigned nparams;
  struct kv_pair *params;
};

struct writer {
  struct saved_entry *entries;
  size_t entry_count;
  size_t entry_capacity;
  unsigned char *buffer;
  size_t length;
  size_t buffer_capacity;
};

static int collect_entry(const struct snapshot_entry *entry, void *arg) {
  struct writer *writer = arg;
  if (!entry->name || !entry->namelen || entry->namelen >= DNS_MAXDN || entry->table > 5 ||
      entry->nparams > SNAPSHOT_MAX_PARAMS || entry->name[entry->namelen] ||
      (entry->rr && strlen(entry->rr + 4) > 255)) {
    return 0;
  }

  unsigned pos = 0;
  unsigned labels = 0;

  while (pos < entry->namelen) {
    unsigned len = entry->name[pos];
    if (!len || len > 63 || len + 1 > entry->namelen - pos) {
      return 0;
    }
    pos += len + 1;
    labels++;
  }
  if (entry->table && labels != entry->table) {
    return 0;
  }
  for (unsigned i = 0; i < entry->nparams; i++) {
    if (!entry->params[i].k || !entry->params[i].v || strlen(entry->params[i].k) > 65535 ||
        strlen(entry->params[i].v) > 65535) {
      return 0;
    }
  }

  if (writer->entry_count == writer->entry_capacity) {
    size_t cap = writer->entry_capacity ? writer->entry_capacity * 2 : 256;
    if (cap > SNAPSHOT_SIZE_LIMIT / SNAPSHOT_RECORD_SIZE) {
      return 0;
    }
    void *data = realloc(writer->entries, cap * sizeof(*writer->entries));
    if (!data) {
      return 0;
    }
    writer->entries = data;
    writer->entry_capacity = cap;
  }

  struct saved_entry *out = &writer->entries[writer->entry_count];
  out->name = entry->name;
  out->namelen = entry->namelen;
  out->table = entry->table;
  out->rr = entry->rr;
  out->nparams = entry->nparams;
  out->params = NULL;
  if (entry->nparams) {
    out->params = malloc(entry->nparams * sizeof(*out->params));
    if (!out->params) {
      return 0;
    }
    memcpy(out->params, entry->params, entry->nparams * sizeof(*out->params));
  }

  writer->entry_count++;
  return 1;
}

static int compare_entries(const void *a, const void *b) {
  const struct saved_entry *x = a, *y = b;
  return compare_keys(x->table, x->name, x->namelen, y->table, y->name, y->namelen);
}

static unsigned append_data(struct writer *writer, const void *data, size_t len) {
  if (len > SNAPSHOT_SIZE_LIMIT - writer->length) {
    return 0;
  }
  unsigned off = (unsigned)writer->length;
  if (writer->length + len > writer->buffer_capacity) {
    size_t cap = writer->buffer_capacity ? writer->buffer_capacity * 2 : 4096;
    if (cap < writer->length + len) {
      cap = writer->length + len;
    }
    if (cap > SNAPSHOT_SIZE_LIMIT) {
      cap = SNAPSHOT_SIZE_LIMIT;
    }
    void *resized = realloc(writer->buffer, cap);
    if (!resized) {
      return 0;
    }
    writer->buffer = resized;
    writer->buffer_capacity = cap;
  }
  memcpy(writer->buffer + writer->length, data, len);
  writer->length += len;
  return off;
}

int rbldnsd_snapshot_write_iter_ident(const struct dataset *ds, const char *path,
                                      snapshot_produce_fn *produce, void *arg, uint64_t *dev,
                                      uint64_t *ino) {
  struct writer writer = {0};
  int ok = 0;
  int fd = -1;
  char *tmp = NULL;

  if (!produce(collect_entry, &writer, arg) ||
      writer.entry_count > (SNAPSHOT_SIZE_LIMIT - SNAPSHOT_HEADER_SIZE) / SNAPSHOT_RECORD_SIZE) {
    goto done;
  }
  if (ds->ds_stamp <= 0 || ds->ds_expires < 0) {
    goto done;
  }

  qsort(writer.entries, writer.entry_count, sizeof(*writer.entries), compare_entries);
  for (size_t i = 1; i < writer.entry_count; i++) {
    if (compare_entries(&writer.entries[i - 1], &writer.entries[i]) >= 0) {
      goto done;
    }
  }

  /* Reserve the header and record directory; append offset-addressed data. */
  writer.length = SNAPSHOT_HEADER_SIZE + writer.entry_count * SNAPSHOT_RECORD_SIZE;
  writer.buffer_capacity = writer.length;
  writer.buffer = calloc(1, writer.length);
  if (!writer.buffer) {
    goto done;
  }
  memcpy(writer.buffer, "RBLDNSNP", 8);
  write_u32(writer.buffer + 8, 1);
  write_u32(writer.buffer + 16, writer.entry_count);
  write_u32(writer.buffer + 20, ds->ds_ttl);
  for (unsigned i = 0; i < 11; i++) {
    if (ds->ds_subst[i]) {
      if (strlen(ds->ds_subst[i]) > 65535) {
        goto done;
      }
      unsigned off = append_data(&writer, ds->ds_subst[i], strlen(ds->ds_subst[i]) + 1);
      if (!off) {
        goto done;
      }
      write_u32(writer.buffer + 32 + i * 4, off);
    }
  }

  if (ds->ds_dssoa) {
    const struct dssoa *so = ds->ds_dssoa;
    unsigned no = append_data(&writer, so->dssoa_odn, dns_dnlen(so->dssoa_odn));
    unsigned po = append_data(&writer, so->dssoa_pdn, dns_dnlen(so->dssoa_pdn));
    unsigned char rec[32];
    if (!no || !po) {
      goto done;
    }
    write_u32(rec, so->dssoa_ttl);
    write_u32(rec + 4, no);
    write_u32(rec + 8, po);
    write_u32(rec + 12, so->dssoa_serial);
    memcpy(rec + 16, so->dssoa_n, 16);
    unsigned off = append_data(&writer, rec, 32);
    if (!off) {
      goto done;
    }
    write_u32(writer.buffer + 80, off);
  }

  unsigned nc = 0;
  for (const struct dsns *ns = ds->ds_dsns; ns; ns = ns->dsns_next) {
    nc++;
    if (nc > 1024) {
      goto done;
    }
  }
  if (nc) {
    unsigned char *offsets = malloc((size_t)nc * 4);
    if (!offsets) {
      goto done;
    }
    unsigned j = 0;
    for (const struct dsns *ns = ds->ds_dsns; ns; ns = ns->dsns_next) {
      unsigned off = append_data(&writer, ns->dsns_dn, dns_dnlen(ns->dsns_dn));
      if (!off) {
        free(offsets);
        goto done;
      }
      write_u32(offsets + j * 4, off);
      j++;
    }
    unsigned off = append_data(&writer, offsets, (size_t)nc * 4);
    free(offsets);
    if (!off) {
      goto done;
    }
    write_u32(writer.buffer + 84, off);
    write_u32(writer.buffer + 88, nc);
  }

  write_u32(writer.buffer + 104, (uint64_t)ds->ds_stamp >> 32);
  write_u32(writer.buffer + 108, (uint64_t)ds->ds_stamp);
  write_u32(writer.buffer + 92, ds->ds_nsttl);
  write_u32(writer.buffer + 96, (uint64_t)ds->ds_expires >> 32);
  write_u32(writer.buffer + 100, (uint64_t)ds->ds_expires);

  for (unsigned i = 0; i < writer.entry_count; i++) {
    struct saved_entry *entry = &writer.entries[i];
    unsigned no;
    unsigned rr = 0;
    unsigned po = 0;
    no = append_data(&writer, entry->name, entry->namelen + 1);
    if (!no) {
      goto done;
    }
    if (entry->rr) {
      rr = append_data(&writer, entry->rr, strlen(entry->rr + 4) + 5);
      if (!rr) {
        goto done;
      }
    }
    if (entry->nparams) {
      unsigned char pairs[SNAPSHOT_MAX_PARAMS * 8];
      for (unsigned j = 0; j < entry->nparams; j++) {
        if (!entry->params[j].k || !entry->params[j].v) {
          goto done;
        }
        unsigned ko = append_data(&writer, entry->params[j].k, strlen(entry->params[j].k) + 1);
        unsigned vo = append_data(&writer, entry->params[j].v, strlen(entry->params[j].v) + 1);
        if (!ko || !vo) {
          goto done;
        }
        write_u32(pairs + j * 8, ko);
        write_u32(pairs + j * 8 + 4, vo);
      }
      po = append_data(&writer, pairs, entry->nparams * 8);
      if (!po) {
        goto done;
      }
    }
    unsigned char *record = writer.buffer + SNAPSHOT_HEADER_SIZE + i * SNAPSHOT_RECORD_SIZE;
    write_u32(record, entry->table);
    write_u32(record + 4, no);
    write_u32(record + 8, entry->namelen);
    write_u32(record + 12, rr);
    write_u32(record + 16, po);
    write_u32(record + 20, entry->nparams);
  }
  write_u32(writer.buffer + 12, writer.length);
  write_u32(writer.buffer + 24, checksum(writer.buffer, writer.length));

  /* Publish by rename so existing mappings remain valid. */
  tmp = malloc(strlen(path) + 16);
  if (!tmp) {
    goto done;
  }
  sprintf(tmp, "%s.XXXXXX", path);
  fd = mkstemp(tmp);
  if (fd < 0) {
    goto done;
  }

  size_t pos = 0;
  while (pos < writer.length) {
    ssize_t n = write(fd, writer.buffer + pos, writer.length - pos);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      goto done;
    }
    pos += n;
  }
  if (fchmod(fd, 0644) < 0 || fsync(fd) < 0) {
    goto done;
  }

  struct stat identity;
  if (fstat(fd, &identity) < 0) {
    goto done;
  }
  if (dev) {
    *dev = (uint64_t)identity.st_dev;
  }
  if (ino) {
    *ino = (uint64_t)identity.st_ino;
  }
  if (close(fd) < 0) {
    fd = -1;
    goto done;
  }
  fd = -1;
  if (rename(tmp, path) < 0) {
    goto done;
  }
  ok = 1;

done:
  if (fd >= 0) {
    close(fd);
  }
  if (tmp) {
    if (!ok) {
      unlink(tmp);
    }
    free(tmp);
  }
  for (size_t i = 0; i < writer.entry_count; i++) {
    free(writer.entries[i].params);
  }
  free(writer.entries);
  free(writer.buffer);
  return ok;
}

int rbldnsd_snapshot_write_iter(const struct dataset *ds, const char *path,
                                snapshot_produce_fn *produce, void *arg) {
  return rbldnsd_snapshot_write_iter_ident(ds, path, produce, arg, NULL, NULL);
}

static int dnhash_produce(snapshot_visit_fn *visit, void *visit_arg, void *arg) {
  return rbldnsd_dnhash_foreach(arg, visit, visit_arg);
}

int rbldnsd_snapshot_write(const struct dataset *ds, const char *path) {
  return rbldnsd_snapshot_write_iter(ds, path, dnhash_produce, (void *)ds);
}
