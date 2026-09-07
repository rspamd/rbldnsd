/* Bounded exact-domain overrides. Shared mutable storage is separate from the
 * immutable base. Atomic bytes avoid C data races during entry replacement.
 * One control-loop writer publishes each mutation using a sequence counter. */
#include "rbldnsd_overlay.h"
#include "dns_hash.h"
#include "ev.h"
#include "khash.h"
#include "rbldnsd.h"
#include "rbldnsd_control.h"
#include "rbldnsd_snapshot.h"
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define MAX_CAPACITY 65536U
struct value {
  unsigned char name[DNS_MAXDN];
  unsigned len;
  unsigned revision;
  unsigned rrlen;
  char rr[260];
};
struct slot {
  unsigned sequence;
  struct value value;
};
struct overlay {
  unsigned sequence;
  unsigned revision;
  unsigned count;
  uint64_t export_dev;
  uint64_t export_ino;
  struct slot slots[];
};
static unsigned capacity;
static unsigned tablesize;
static struct ev_loop *event_loop;
static struct zone *configured_zones;
static pid_t controller_pid;
static void (*control_action)(int);
static int initialized;

static unsigned key_length(const struct slot *slot) {
  unsigned len;
  unsigned char *dest = (unsigned char *)&len;
  const unsigned char *src = (const unsigned char *)&slot->value.len;

  for (size_t i = 0; i < sizeof(len); i++) {
    dest[i] = __atomic_load_n(src + i, __ATOMIC_RELAXED);
  }

  return len;
}

static unsigned key_hash(const struct slot *slot) {
  unsigned char name[DNS_MAXDN];
  unsigned len = key_length(slot);

  if (len >= sizeof(name)) {
    return 0;
  }

  for (unsigned i = 0; i < len; i++) {
    name[i] = __atomic_load_n(&slot->value.name[i], __ATOMIC_RELAXED);
  }

  return dns_label_hash(name, len);
}

static int key_equal(const struct slot *left, const struct slot *right) {
  if (!left || !right) {
    return 0;
  }

  unsigned len = key_length(left);
  if (len >= DNS_MAXDN || len != key_length(right)) {
    return 0;
  }

  for (unsigned i = 0; i < len; i++) {
    if (__atomic_load_n(&left->value.name[i], __ATOMIC_RELAXED) !=
        __atomic_load_n(&right->value.name[i], __ATOMIC_RELAXED)) {
      return 0;
    }
  }

  return 1;
}

/* Only this khash instantiation uses atomic flags and slot pointers. Its arrays
 * never move after fork; resizing and kh_clear are not used on shared storage.
 */
typedef _Atomic(khint32_t) overlay_flag;
typedef _Atomic(struct slot *) overlay_key;
#define khint32_t overlay_flag
KHASH_INIT(overlay, overlay_key, char, 0, key_hash, key_equal)
#undef khint32_t
struct overlay_target {
  struct dataset *dataset;
  struct overlay *shared;
  khash_t(overlay) index_table;
  unsigned id;
  unsigned next_slot;
  ev_child exporter;
  pid_t export_pid;
  unsigned export_revision;
  int export_online;
  int export_result;
  char *export_path;
  struct rbldnsd_overlay_identity base;
};
static struct overlay_target *targets;
static unsigned num_targets;
KHASH_MAP_INIT_INT64(overlay_targets, struct overlay_target *)
static khash_t(overlay_targets) * target_index;

struct loaded_identity {
  const struct dataset *dataset;
  struct rbldnsd_overlay_identity identity;
  struct loaded_identity *next;
};
static struct loaded_identity *loaded_identities;

static struct overlay_target *find_target(const struct dataset *dataset) {
  if (!target_index) {
    return NULL;
  }

  khiter_t bucket = kh_get(overlay_targets, target_index, (uintptr_t)dataset);
  if (bucket == kh_end(target_index)) {
    return NULL;
  }

  return kh_value(target_index, bucket);
}

static int read_slot(const struct slot *s, struct value *v) {
  for (unsigned attempt = 0; attempt < 64; attempt++) {
    unsigned seq = __atomic_load_n(&s->sequence, __ATOMIC_ACQUIRE);
    if (seq & 1) {
      continue;
    }
    unsigned char *out = (unsigned char *)v;
    const unsigned char *in = (const unsigned char *)&s->value;
    for (size_t i = 0; i < sizeof(*v); i++) {
      out[i] = __atomic_load_n(in + i, __ATOMIC_RELAXED);
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (seq == __atomic_load_n(&s->sequence, __ATOMIC_ACQUIRE)) {
      return 1;
    }
  }
  return 0; /* A stopped/dead writer must not stall the UDP event loop. */
}

static unsigned lookup(struct overlay_target *state, const unsigned char *name,
                       unsigned len, struct value *value) {
  struct slot key = {0};
  key.value.len = len;
  memcpy(key.value.name, name, len);

  for (unsigned attempt = 0; attempt < 64; attempt++) {
    unsigned sequence =
        __atomic_load_n(&state->shared->sequence, __ATOMIC_ACQUIRE);
    if (sequence & 1) {
      continue;
    }

    khiter_t bucket = kh_get(overlay, &state->index_table, &key);
    int stable = 1;
    unsigned result = capacity;
    if (bucket != kh_end(&state->index_table)) {
      struct slot *slot = kh_key(&state->index_table, bucket);
      if (slot) {
        stable = read_slot(slot, value);
        result = (unsigned)(slot - state->shared->slots);
      }
    }

    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (stable && sequence == __atomic_load_n(&state->shared->sequence,
                                              __ATOMIC_ACQUIRE)) {
      return result;
    }
  }

  return UINT32_MAX;
}

static void rebuild_index(struct overlay_target *state) {
  for (unsigned i = 0; i < __ac_fsize(tablesize); i++) {
    atomic_store_explicit(&state->index_table.flags[i], 0xaaaaaaaaU,
                          memory_order_relaxed);
  }
  state->index_table.size = 0;
  state->index_table.n_occupied = 0;

  for (unsigned i = 0; i < capacity; i++) {
    if (state->shared->slots[i].value.len) {
      int result;
      kh_put(overlay, &state->index_table, &state->shared->slots[i], &result);
    }
  }
}

static void publish(struct slot *slot, const struct value *v) {
  __atomic_fetch_add(&slot->sequence, 1, __ATOMIC_SEQ_CST);
  const unsigned char *in = (const unsigned char *)v;
  unsigned char *dest = (unsigned char *)&slot->value;
  for (size_t j = 0; j < sizeof(*v); j++) {
    __atomic_store_n(dest + j, in[j], __ATOMIC_RELAXED);
  }
  __atomic_fetch_add(&slot->sequence, 1, __ATOMIC_RELEASE);
}

void rbldnsd_overlay_loaded(const struct dataset *dataset, int fd) {
  struct stat identity;
  if (fstat(fd, &identity) != 0) {
    return;
  }

  struct overlay_target *state = find_target(dataset);
  if (state) {
    state->base.dev = identity.st_dev;
    state->base.ino = identity.st_ino;
    return;
  }

  if (initialized) {
    return;
  }

  struct loaded_identity *entry = loaded_identities;
  while (entry && entry->dataset != dataset) {
    entry = entry->next;
  }
  if (!entry) {
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
      return;
    }
    entry->dataset = dataset;
    entry->next = loaded_identities;
    loaded_identities = entry;
  }
  entry->identity.dev = identity.st_dev;
  entry->identity.ino = identity.st_ino;
}

unsigned rbldnsd_overlay_target_count(void) {
  return num_targets;
}

void rbldnsd_overlay_base_identities(
    struct rbldnsd_overlay_identity *identities, unsigned count) {
  if (!identities) {
    return;
  }
  memset(identities, 0, count * sizeof(*identities));
  for (unsigned i = 0; i < count && i < num_targets; i++) {
    identities[i] = targets[i].base;
  }
}

static void invalidate_compacted_source(struct overlay_target *state) {
  struct dsfile *file = state->dataset->ds_dsf;
  struct stat identity;
  if (file && !stat(file->dsf_name, &identity) &&
      (uint64_t)identity.st_dev == state->shared->export_dev &&
      (uint64_t)identity.st_ino == state->shared->export_ino) {
    file->dsf_stamp = 0;
    file->dsf_size = -1;
  }
}

static void retire_target(struct overlay_target *state, uint64_t dev,
                          uint64_t ino) {
  if (!state->shared || !state->export_online || state->export_result != 2) {
    return;
  }
  if (dev != state->shared->export_dev || ino != state->shared->export_ino) {
    invalidate_compacted_source(state);
    return;
  }
  __atomic_fetch_add(&state->shared->sequence, 1, __ATOMIC_SEQ_CST);
  for (unsigned i = 0; i < capacity; i++) {
    struct value value;
    if (!read_slot(&state->shared->slots[i], &value)) {
      continue;
    }
    if (value.len && value.revision <= state->export_revision) {
      khiter_t bucket =
          kh_get(overlay, &state->index_table, &state->shared->slots[i]);
      kh_del(overlay, &state->index_table, bucket);
      memset(&value, 0, sizeof(value));
      publish(&state->shared->slots[i], &value);
      state->shared->count--;
    }
  }
  rebuild_index(state);
  __atomic_fetch_add(&state->shared->sequence, 1, __ATOMIC_RELEASE);
  state->export_online = 0;
  free(state->export_path);
  state->export_path = NULL;
}

void rbldnsd_overlay_retired(const struct rbldnsd_overlay_identity *identities,
                             unsigned count) {
  if (count != num_targets || (count && !identities)) {
    return;
  }
  for (unsigned i = 0; i < count; i++) {
    retire_target(&targets[i], identities[i].dev, identities[i].ino);
  }
}

int rbldnsd_overlay_query(const struct dataset *ds, const struct dnsqinfo *qi,
                          struct dnspacket *pkt) {
  struct overlay_target *state = find_target(ds);
  struct value v;
  if (!state || !qi->qi_dnlab) {
    return -1;
  }
  unsigned slot = lookup(state, qi->qi_dn, qi->qi_dnlen0, &v);
  if (slot == UINT32_MAX) {
    return NSQUERY_SERVFAIL;
  }
  if (slot == capacity) {
    return -1;
  }
  if (!v.rrlen) {
    return 0; /* exact exclusion masks every wildcard */
  }
  check_query_overwrites(qi);
  char name[DNS_MAXDOMAIN + 1];
  dns_dntop(v.name, name, sizeof(name));
  addrr_a_txt(pkt, qi->qi_tflag, v.rr, name, ds);
  return NSQUERY_FOUND;
}
struct export_copy {
  struct overlay_target *state;
  struct slot *values;
};

struct merge {
  struct slot *values;
  khash_t(overlay) * index;
  snapshot_visit_fn *visit;
  void *arg;
};

static int base_visit(const struct snapshot_entry *entry, void *arg) {
  struct merge *merge = arg;
  if (!entry->table) {
    struct slot key = {0};
    key.value.len = entry->namelen;
    memcpy(key.value.name, entry->name, entry->namelen);
    if (kh_get(overlay, merge->index, &key) != kh_end(merge->index)) {
      return 1;
    }
  }

  return merge->visit(entry, merge->arg);
}

static int produce(snapshot_visit_fn *visit, void *arg, void *producer_arg) {
  struct export_copy *copy = producer_arg;
  struct overlay_target *state = copy->state;
  struct merge merge = {0};
  merge.values = copy->values;
  merge.index = kh_init(overlay);
  merge.visit = visit;
  merge.arg = arg;
  if (!merge.index) {
    return 0;
  }

  int ok = 0;
  for (unsigned i = 0; i < capacity; i++) {
    if (merge.values[i].value.len) {
      int result;
      kh_put(overlay, merge.index, &merge.values[i], &result);
      if (result < 0) {
        goto done;
      }
    }
  }

  ok = isdstype(state->dataset->ds_type, dnhash)
           ? rbldnsd_dnhash_foreach(state->dataset, base_visit, &merge)
           : rbldnsd_snapshot_foreach(state->dataset, base_visit, &merge);
  if (!ok) {
    goto done;
  }

  for (unsigned i = 0; i < capacity; i++) {
    struct value *value = &merge.values[i].value;
    if (value->len) {
      struct snapshot_entry entry = {0};
      entry.name = value->name;
      entry.namelen = value->len;
      entry.rr = value->rrlen ? value->rr : NULL;
      if (!visit(&entry, arg)) {
        ok = 0;
        break;
      }
    }
  }

done:
  kh_destroy(overlay, merge.index);
  return ok;
}

static void exported(struct ev_loop *loop, ev_child *w, int UNUSED revents) {
  struct overlay_target *state = w->data;
  state->export_result =
      WIFEXITED(w->rstatus) && WEXITSTATUS(w->rstatus) == 0 ? 2 : -1;
  state->export_pid = 0;
  ev_child_stop(loop, w);
  if (state->export_result == 2 && state->export_online) {
    invalidate_compacted_source(state);
    control_action(1);
  }
  if (state->export_result < 0) {
    state->export_online = 0;
  }
  if (!state->export_online) {
    free(state->export_path);
    state->export_path = NULL;
  }
}

static char *canonical_path(const char *path) {
  char *resolved = realpath(path, NULL);
  if (resolved) {
    return resolved;
  }

  char *copy = strdup(path);
  if (!copy) {
    return NULL;
  }
  char *slash = strrchr(copy, '/');
  const char *name = copy;
  const char *directory = ".";
  if (slash) {
    *slash = 0;
    name = slash + 1;
    directory = *copy ? copy : "/";
  }
  char *parent = realpath(directory, NULL);
  if (parent && *name && strcmp(name, ".") && strcmp(name, "..")) {
    size_t length = strlen(parent) + strlen(name) + 2;
    resolved = malloc(length);
    if (resolved) {
      snprintf(resolved, length, "%s/%s", parent, name);
    }
  }
  free(parent);
  free(copy);
  return resolved;
}

static int same_path(const char *canonical, const char *path) {
  struct stat left;
  struct stat right;
  if (!stat(canonical, &left) && !stat(path, &right) &&
      left.st_dev == right.st_dev && left.st_ino == right.st_ino) {
    return 1;
  }
  char *resolved = canonical_path(path);
  int same = resolved && !strcmp(canonical, resolved);
  free(resolved);
  return same;
}

static int export_snapshot(struct overlay_target *state, const char *path,
                           int online) {
  char *destination = canonical_path(path);
  if (!destination) {
    return 0;
  }
  unsigned running = 0;
  for (unsigned i = 0; i < num_targets; i++) {
    if (targets[i].export_pid) {
      running++;
    }
    if (targets[i].export_path &&
        same_path(destination, targets[i].export_path)) {
      free(destination);
      return 0;
    }
  }
  if (running >= 8) {
    free(destination);
    return 0;
  }

  struct dataset *dataset = NULL;
  while ((dataset = nextdataset(dataset)) != NULL) {
    for (struct dsfile *file = dataset->ds_dsf; file; file = file->dsf_next) {
      if ((!online || dataset != state->dataset) &&
          same_path(destination, file->dsf_name)) {
        free(destination);
        return 0;
      }
    }
  }
  struct slot *copy = calloc(capacity, sizeof(*copy));
  if (!copy) {
    free(destination);
    return 0;
  }
  for (unsigned i = 0; i < capacity; i++) {
    if (!read_slot(&state->shared->slots[i], &copy[i].value)) {
      free(copy);
      free(destination);
      return 0;
    }
  }
  pid_t pid = fork();
  if (pid < 0) {
    free(copy);
    free(destination);
    return 0;
  }
  if (!pid) {
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGALRM, SIG_DFL);
    alarm(60);
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0) {
      max = 65536;
    }
    for (int fd = 3; fd < max; fd++) {
      close(fd);
    }
    for (struct dsfile *f = state->dataset->ds_dsf; f; f = f->dsf_next) {
      f->stat_ev = NULL;
      f->dsf_stamp = 0;
      f->dsf_size = -1;
    }
    rbldnsd_snapshot_compiling = 1;
    struct export_copy data = {state, copy};
    int ok = loaddataset(state->dataset, event_loop) &&
             rbldnsd_snapshot_write_iter_ident(
                 state->dataset, destination, produce, &data,
                 &state->shared->export_dev, &state->shared->export_ino);
    _exit(ok ? 0 : 1);
  }
  free(copy);
  state->export_online = online;
  state->export_path = destination;
  state->export_pid = pid;
  state->export_revision = state->shared->revision;
  state->export_result = 1;
  ev_child_init(&state->exporter, exported, pid, 0);
  state->exporter.data = state;
  ev_child_start(event_loop, &state->exporter);
  return 1;
}

static int target_command(struct overlay_target *state, const char *command,
                          char *out, size_t size) {
  if (strncmp(command, "overlay", 7)) {
    return -1;
  }
  if (!strcmp(command, "overlay-status")) {
    return snprintf(out, size,
                    "{\"id\":%u,\"revision\":%u,\"entries\":%u,\"capacity\":%u,"
                    "\"ephemeral\":true,\"compaction_pending\":%s,\"export_"
                    "revision\":%u,\"export_state\":\"%s\"}",
                    state->id, state->shared->revision, state->shared->count,
                    capacity, state->export_online ? "true" : "false",
                    state->export_revision,
                    state->export_result == 1    ? "running"
                    : state->export_result == 2  ? "success"
                    : state->export_result == -1 ? "failed"
                                                 : "none");
  }
  char buf[4096];
  if (strlen(command) >= sizeof(buf)) {
    goto invalid;
  }
  strcpy(buf, command);
  char *save = NULL;
  char *op = strtok_r(buf, " ", &save);
  char *rev = strtok_r(NULL, " ", &save);
  char *name = strtok_r(NULL, " ", &save);
  if (!save) {
    save = "";
  }
  if (!rev || !*rev) {
    goto invalid;
  }
  for (char *p = rev; *p; p++) {
    if (*p < '0' || *p > '9') {
      goto invalid;
    }
  }
  errno = 0;
  char *end;
  unsigned long expected = strtoul(rev, &end, 10);
  if (errno || *end || expected > UINT32_MAX) {
    goto invalid;
  }
  if (expected != state->shared->revision) {
    return snprintf(out, size,
                    "{\"error\":\"revision conflict\",\"revision\":%u}",
                    state->shared->revision);
  }
  if (!strcmp(op, "overlay-compact")) {
    if (*save || state->export_pid || state->export_online) {
      goto invalid;
    }
    int online = !name;
    if (online && !isdstype(state->dataset->ds_type, dnsnapshot)) {
      goto invalid;
    }
    if (!export_snapshot(
            state, online ? state->dataset->ds_dsf->dsf_name : name, online)) {
      return snprintf(
          out, size,
          "{\"error\":\"cannot start export (use a separate output path)\"}");
    }
    return snprintf(out, size, "{\"accepted\":true,\"revision\":%u}",
                    state->shared->revision);
  }
  if (!name) {
    goto invalid;
  }
  int del = !strcmp(op, "overlay-del");
  if (!del && strcmp(op, "overlay-put")) {
    goto invalid;
  }
  struct value v = {0};
  struct value old;
  if (strchr(name, '*') || name[0] == '.' || strlen(name) > 253) {
    goto invalid;
  }
  unsigned n;
  char *rest = parse_dn(name, v.name, &n);
  if (!rest || *rest || n <= 1) {
    goto invalid;
  }
  dns_dntol(v.name, v.name);
  v.len = n - 1;
  if (del) {
    if (*save) {
      goto invalid;
    }
  } else {
    while (*save == ' ') {
      save++;
    }
    /* Deliberately use strict IPv4 + literal TXT, without implicit defaults or
     * entry parameters. This avoids silently losing customer ACL policies. */
    char *ip = save;
    char *txt = strchr(ip, ' ');
    if (!txt) {
      goto invalid;
    }
    *txt++ = 0;
    if (strlen(txt) > 255 || strchr(txt, '\n') || strchr(txt, '\r')) {
      goto invalid;
    }
    for (char *p = ip; *p; p++) {
      if ((*p < '0' || *p > '9') && *p != '.') {
        goto invalid;
      }
    }
    unsigned a;
    unsigned b;
    unsigned c;
    unsigned d;
    char extra;
    if (sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4 || a > 255 ||
        b > 255 || c > 255 || d > 255) {
      goto invalid;
    }
    v.rr[0] = a;
    v.rr[1] = b;
    v.rr[2] = c;
    v.rr[3] = d;
    strcpy(v.rr + 4, txt);
    v.rrlen = 5 + strlen(txt);
  }
  unsigned i = lookup(state, v.name, v.len, &old);
  if (i == UINT32_MAX) {
    goto invalid;
  }
  int insert = i == capacity;
  if (insert && state->shared->count == capacity) {
    return snprintf(
        out, size,
        "{\"error\":\"overlay full; compact the snapshot\",\"revision\":%u}",
        state->shared->revision);
  }
  if (state->shared->revision == UINT32_MAX) {
    goto invalid;
  }
  v.revision = state->shared->revision + 1;
  if (insert) {
    for (unsigned scanned = 0; scanned < capacity; scanned++) {
      unsigned candidate = (state->next_slot + scanned) % capacity;
      if (!state->shared->slots[candidate].value.len) {
        i = candidate;
        state->next_slot = (candidate + 1) % capacity;
        break;
      }
    }
    if (i == capacity) {
      goto invalid;
    }
  }
  __atomic_fetch_add(&state->shared->sequence, 1, __ATOMIC_SEQ_CST);
  publish(&state->shared->slots[i], &v);
  if (insert) {
    int result;
    kh_put(overlay, &state->index_table, &state->shared->slots[i], &result);
    state->shared->count++;
  }
  __atomic_fetch_add(&state->shared->sequence, 1, __ATOMIC_RELEASE);
  state->shared->revision++;
  return snprintf(out, size, "{\"ok\":true,\"revision\":%u}",
                  state->shared->revision);
invalid:
  return snprintf(out, size, "{\"error\":\"invalid overlay command\"}");
}

struct json_buffer {
  char *data;
  size_t size;
  size_t used;
  int failed;
};

static void json_append(struct json_buffer *buffer, const char *format, ...) {
  if (buffer->failed) {
    return;
  }
  va_list args;
  va_start(args, format);
  int length = vsnprintf(buffer->data + buffer->used,
                         buffer->size - buffer->used, format, args);
  va_end(args);
  if (length < 0 || (size_t)length >= buffer->size - buffer->used) {
    buffer->failed = 1;
    return;
  }
  buffer->used += length;
}

static void json_string(struct json_buffer *buffer, const char *string,
                        size_t limit) {
  size_t length = strlen(string);
  if (length > limit) {
    length = limit;
    while (length && ((unsigned char)string[length] & 0xc0) == 0x80) {
      length--;
    }
  }
  json_append(buffer, "\"");
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = string[i];
    if (byte == '\\' || byte == '\"') {
      json_append(buffer, "\\%c", byte);
    } else if (byte < 32) {
      json_append(buffer, "\\u%04x", byte);
    } else {
      json_append(buffer, "%c", byte);
    }
  }
  json_append(buffer, "\"");
}

static int zone_uses_target(const struct zone *zone,
                            const struct overlay_target *state) {
  for (struct dslist *entry = zone->z_dsl; entry; entry = entry->dsl_next) {
    if (entry->dsl_ds == state->dataset) {
      return 1;
    }
  }
  return 0;
}

static int list_targets(unsigned offset, char *out, size_t size) {
  if (offset > num_targets) {
    return snprintf(out, size, "{\"error\":\"invalid overlay offset\"}");
  }
  struct json_buffer result = {out, size, 0, 0};
  json_append(&result, "{\"targets\":[");
  unsigned emitted = 0;
  unsigned current = offset;
  for (; current < num_targets && emitted < 8; current++) {
    struct overlay_target *state = &targets[current];
    char row[10000];
    struct json_buffer entry = {row, sizeof(row), 0, 0};
    json_append(&entry, "{\"id\":%u,\"spec\":", state->id);
    json_string(&entry, state->dataset->ds_spec, 512);
    json_append(&entry, ",\"spec_truncated\":%s,\"zones\":[",
                strlen(state->dataset->ds_spec) > 512 ? "true" : "false");
    unsigned zones = 0;
    for (struct zone *zone = configured_zones; zone; zone = zone->z_next) {
      if (!zone_uses_target(zone, state)) {
        continue;
      }
      if (zones < 4) {
        json_append(&entry, "%s", zones ? "," : "");
        json_string(&entry, zone->z_name, DNS_MAXDOMAIN);
      }
      zones++;
    }
    json_append(&entry, "],\"zone_count\":%u,\"zones_truncated\":%s}", zones,
                zones > 4 ? "true" : "false");
    if (entry.failed || entry.used + result.used + 100 >= size) {
      break;
    }
    json_append(&result, "%s%s", emitted ? "," : "", row);
    emitted++;
  }
  if (!emitted && current < num_targets) {
    return snprintf(out, size,
                    "{\"error\":\"overlay discovery response too large\"}");
  }
  json_append(&result, "],\"target_count\":%u,\"next_offset\":%d}", num_targets,
              current < num_targets ? (int)current : -1);
  return result.failed ? -1 : (int)result.used;
}

static int parse_unsigned(const char *text, const char **end, unsigned *value) {
  if (*text < '0' || *text > '9') {
    return 0;
  }
  errno = 0;
  char *tail;
  unsigned long parsed = strtoul(text, &tail, 10);
  if (errno || parsed > UINT32_MAX) {
    return 0;
  }
  *end = tail;
  *value = parsed;
  return 1;
}

static int command(const char *text, char *out, size_t size) {
  if (strncmp(text, "overlay", 7)) {
    return -1;
  }
  if (!strncmp(text, "overlay-list", 12) && (!text[12] || text[12] == ' ')) {
    unsigned offset = 0;
    const char *end = text + 12;
    if (*end) {
      end++;
      if (!parse_unsigned(end, &end, &offset) || *end) {
        goto invalid;
      }
    }
    return list_targets(offset, out, size);
  }

  const char *space = strchr(text, ' ');
  const char *args = space ? space + 1 : text + strlen(text);
  unsigned id = 1;
  if (*args == '@') {
    args++;
    if (!parse_unsigned(args, &args, &id) || !id || id > num_targets ||
        (*args && *args != ' ')) {
      goto invalid;
    }
    while (*args == ' ') {
      args++;
    }
  } else if (num_targets != 1) {
    return snprintf(
        out, size,
        "{\"error\":\"overlay target required; use @ID and overlay-list\"}");
  }
  size_t operation = space ? (size_t)(space - text) : strlen(text);
  char normalized[4096];
  int length = snprintf(normalized, sizeof(normalized), "%.*s%s%s",
                        (int)operation, text, *args ? " " : "", args);
  if (length < 0 || (size_t)length >= sizeof(normalized)) {
    goto invalid;
  }
  return target_command(&targets[id - 1], normalized, out, size);

invalid:
  return snprintf(out, size,
                  "{\"error\":\"invalid overlay command or target\"}");
}

static void free_target(struct overlay_target *state) {
  size_t size = sizeof(*state->shared) + capacity * sizeof(struct slot);
  if (state->shared) {
    munmap(state->shared, size);
  }
  if (state->index_table.flags) {
    munmap(state->index_table.flags,
           __ac_fsize(tablesize) * sizeof(*state->index_table.flags));
  }
  if (state->index_table.keys) {
    munmap(state->index_table.keys,
           tablesize * sizeof(*state->index_table.keys));
  }
  free(state->export_path);
  memset(state, 0, sizeof(*state));
}

static int init_target(struct overlay_target *state) {
  size_t size = sizeof(*state->shared) + capacity * sizeof(struct slot);
  state->shared =
      mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (state->shared == MAP_FAILED) {
    state->shared = NULL;
    return -1;
  }
  state->index_table.n_buckets = tablesize;
  /* Capacity is capped at half the buckets; state->shared arrays must never
   * resize. */
  state->index_table.upper_bound = UINT32_MAX;
  size_t flags_size = __ac_fsize(tablesize) * sizeof(*state->index_table.flags);
  size_t keys_size = tablesize * sizeof(*state->index_table.keys);
  state->index_table.flags = mmap(NULL, flags_size, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANON, -1, 0);
  state->index_table.keys = mmap(NULL, keys_size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANON, -1, 0);
  if (state->index_table.flags == MAP_FAILED ||
      state->index_table.keys == MAP_FAILED) {
    int saved_errno = errno;
    if (state->index_table.flags != MAP_FAILED) {
      munmap(state->index_table.flags, flags_size);
    }
    if (state->index_table.keys != MAP_FAILED) {
      munmap(state->index_table.keys, keys_size);
    }
    munmap(state->shared, size);
    state->shared = NULL;
    state->index_table.flags = NULL;
    state->index_table.keys = NULL;
    errno = saved_errno;
    return -1;
  }
  for (unsigned i = 0; i < tablesize; i++) {
    atomic_init(&state->index_table.keys[i], NULL);
  }
  rebuild_index(state);
  return 0;
}

static void clear_loaded_identities(void) {
  while (loaded_identities) {
    struct loaded_identity *next = loaded_identities->next;
    free(loaded_identities);
    loaded_identities = next;
  }
}

int rbldnsd_overlay_init(struct ev_loop *loop, unsigned limit,
                         void (*action)(int), struct zone *zones) {
  initialized = 1;
  if (!limit) {
    clear_loaded_identities();
    return 0;
  }
  if (limit > MAX_CAPACITY) {
    errno = EINVAL;
    return -1;
  }
  if (ATOMIC_POINTER_LOCK_FREE != 2 || ATOMIC_INT_LOCK_FREE != 2) {
    errno = ENOTSUP;
    return -1;
  }

  unsigned count = 0;
  struct dataset *dataset = NULL;
  while ((dataset = nextdataset(dataset)) != NULL) {
    if (isdstype(dataset->ds_type, dnhash) ||
        isdstype(dataset->ds_type, dnsnapshot)) {
      count++;
    }
  }
  if (!count) {
    errno = EINVAL;
    return -1;
  }
  capacity = limit;
  tablesize = 4;
  while (tablesize < 2 * capacity) {
    tablesize *= 2;
  }
  targets = calloc(count, sizeof(*targets));
  target_index = kh_init(overlay_targets);
  if (!targets || !target_index) {
    goto fail;
  }

  dataset = NULL;
  while ((dataset = nextdataset(dataset)) != NULL) {
    if (!isdstype(dataset->ds_type, dnhash) &&
        !isdstype(dataset->ds_type, dnsnapshot)) {
      continue;
    }
    struct overlay_target *state = &targets[num_targets];
    if (init_target(state) < 0) {
      goto fail;
    }
    state->id = num_targets + 1;
    state->dataset = dataset;
    num_targets++;
    int result;
    khiter_t bucket =
        kh_put(overlay_targets, target_index, (uintptr_t)dataset, &result);
    if (result < 0) {
      goto fail;
    }
    kh_value(target_index, bucket) = state;
    for (struct loaded_identity *entry = loaded_identities; entry;
         entry = entry->next) {
      if (entry->dataset == dataset) {
        state->base = entry->identity;
        break;
      }
    }
  }
  clear_loaded_identities();
  configured_zones = zones;
  event_loop = loop;
  control_action = action;
  controller_pid = getpid();
  rbldnsd_control_extension(command);
  return 0;

fail: {
  int saved_errno = errno ? errno : ENOMEM;
  for (unsigned i = 0; i < num_targets; i++) {
    free_target(&targets[i]);
  }
  free(targets);
  targets = NULL;
  num_targets = 0;
  kh_destroy(overlay_targets, target_index);
  target_index = NULL;
  clear_loaded_identities();
  errno = saved_errno;
  return -1;
}
}

void rbldnsd_overlay_child(void) {
  if (getpid() == controller_pid) {
    return;
  }
  for (unsigned i = 0; i < num_targets; i++) {
    struct overlay_target *state = &targets[i];
    if (event_loop && ev_is_active(&state->exporter)) {
      ev_child_stop(event_loop, &state->exporter);
    }
    state->export_pid = 0;
  }
  event_loop = NULL;
}

void rbldnsd_overlay_close(void) {
  if (getpid() != controller_pid) {
    return;
  }
  for (unsigned i = 0; i < num_targets; i++) {
    if (targets[i].export_pid) {
      kill(targets[i].export_pid, SIGKILL);
    }
  }
  for (unsigned i = 0; i < num_targets; i++) {
    struct overlay_target *state = &targets[i];
    if (state->export_pid) {
      while (waitpid(state->export_pid, NULL, 0) < 0 && errno == EINTR) {
      }
    }
    if (event_loop && ev_is_active(&state->exporter)) {
      ev_child_stop(event_loop, &state->exporter);
    }
    free_target(state);
  }
  free(targets);
  targets = NULL;
  num_targets = 0;
  kh_destroy(overlay_targets, target_index);
  target_index = NULL;
}
