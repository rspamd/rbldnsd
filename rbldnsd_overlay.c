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
static struct overlay *shared;
static unsigned capacity;
static unsigned tablesize;
static unsigned next_slot;
static struct dataset *target;
static struct ev_loop *event_loop;
static ev_child exporter;
static pid_t export_pid;
static pid_t controller_pid;
static unsigned export_revision;
static int export_online;
static uint64_t base_dev;
static uint64_t base_ino;
static void (*control_action)(int);
static int export_result; /* 0 never, 1 running, 2 success, -1 failed */

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
static khash_t(overlay) index_table;

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

static unsigned lookup(const unsigned char *name, unsigned len,
                       struct value *value) {
  struct slot key = {0};
  key.value.len = len;
  memcpy(key.value.name, name, len);

  for (unsigned attempt = 0; attempt < 64; attempt++) {
    unsigned sequence = __atomic_load_n(&shared->sequence, __ATOMIC_ACQUIRE);
    if (sequence & 1) {
      continue;
    }

    khiter_t bucket = kh_get(overlay, &index_table, &key);
    int stable = 1;
    unsigned result = capacity;
    if (bucket != kh_end(&index_table)) {
      struct slot *slot = kh_key(&index_table, bucket);
      if (slot) {
        stable = read_slot(slot, value);
        result = (unsigned)(slot - shared->slots);
      }
    }

    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (stable &&
        sequence == __atomic_load_n(&shared->sequence, __ATOMIC_ACQUIRE)) {
      return result;
    }
  }

  return UINT32_MAX;
}

static void rebuild_index(void) {
  for (unsigned i = 0; i < __ac_fsize(tablesize); i++) {
    atomic_store_explicit(&index_table.flags[i], 0xaaaaaaaaU,
                          memory_order_relaxed);
  }
  index_table.size = 0;
  index_table.n_occupied = 0;

  for (unsigned i = 0; i < capacity; i++) {
    if (shared->slots[i].value.len) {
      int result;
      kh_put(overlay, &index_table, &shared->slots[i], &result);
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

void rbldnsd_overlay_loaded(const struct dataset *ds, int fd) {
  struct stat st;
  /* Startup's initial load can precede overlay initialization. */
  if (ds == nextdataset(NULL) && !fstat(fd, &st)) {
    base_dev = st.st_dev;
    base_ino = st.st_ino;
  }
}

void rbldnsd_overlay_base_identity(uint64_t *dev, uint64_t *ino) {
  *dev = base_dev;
  *ino = base_ino;
}

void rbldnsd_overlay_retired(uint64_t dev, uint64_t ino) {
  if (!shared || !export_online || export_result != 2 ||
      dev != shared->export_dev || ino != shared->export_ino) {
    return;
  }
  __atomic_fetch_add(&shared->sequence, 1, __ATOMIC_SEQ_CST);
  for (unsigned i = 0; i < capacity; i++) {
    struct value value;
    if (!read_slot(&shared->slots[i], &value)) {
      continue;
    }
    if (value.len && value.revision <= export_revision) {
      khiter_t bucket = kh_get(overlay, &index_table, &shared->slots[i]);
      kh_del(overlay, &index_table, bucket);
      memset(&value, 0, sizeof(value));
      publish(&shared->slots[i], &value);
      shared->count--;
    }
  }
  rebuild_index();
  __atomic_fetch_add(&shared->sequence, 1, __ATOMIC_RELEASE);
  export_online = 0;
}

int rbldnsd_overlay_query(const struct dataset *ds, const struct dnsqinfo *qi,
                          struct dnspacket *pkt) {
  struct value v;
  if (!shared || ds != target || !qi->qi_dnlab) {
    return -1;
  }
  unsigned slot = lookup(qi->qi_dn, qi->qi_dnlen0, &v);
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
  struct merge merge = {0};
  merge.values = producer_arg;
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

  ok = isdstype(target->ds_type, dnhash)
           ? rbldnsd_dnhash_foreach(target, base_visit, &merge)
           : rbldnsd_snapshot_foreach(target, base_visit, &merge);
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
  export_result =
      WIFEXITED(w->rstatus) && WEXITSTATUS(w->rstatus) == 0 ? 2 : -1;
  export_pid = 0;
  ev_child_stop(loop, w);
  if (export_result == 2 && export_online) {
    control_action(1);
  }
  if (export_result < 0) {
    export_online = 0;
  }
}

static int export_snapshot(const char *path, int online) {
  struct stat out;
  struct stat src;
  if (!online) {
    for (struct dsfile *f = target->ds_dsf; f; f = f->dsf_next) {
      if (!strcmp(path, f->dsf_name) ||
          (!stat(path, &out) && !stat(f->dsf_name, &src) &&
           out.st_ino == src.st_ino && out.st_dev == src.st_dev)) {
        return 0;
      }
    }
  }
  struct slot *copy = calloc(capacity, sizeof(*copy));
  if (!copy) {
    return 0;
  }
  for (unsigned i = 0; i < capacity; i++) {
    if (!read_slot(&shared->slots[i], &copy[i].value)) {
      free(copy);
      return 0;
    }
  }
  pid_t pid = fork();
  if (pid < 0) {
    free(copy);
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
    for (struct dsfile *f = target->ds_dsf; f; f = f->dsf_next) {
      f->stat_ev = NULL;
      f->dsf_stamp = 0;
      f->dsf_size = -1;
    }
    rbldnsd_snapshot_compiling = 1;
    int ok = loaddataset(target, event_loop) &&
             rbldnsd_snapshot_write_iter_ident(target, path, produce, copy,
                                               &shared->export_dev,
                                               &shared->export_ino);
    _exit(ok ? 0 : 1);
  }
  free(copy);
  export_online = online;
  export_pid = pid;
  export_revision = shared->revision;
  export_result = 1;
  ev_child_init(&exporter, exported, pid, 0);
  ev_child_start(event_loop, &exporter);
  return 1;
}

static int command(const char *command, char *out, size_t size) {
  if (strncmp(command, "overlay", 7)) {
    return -1;
  }
  if (!strcmp(command, "overlay-status")) {
    return snprintf(out, size,
                    "{\"revision\":%u,\"entries\":%u,\"capacity\":%u,"
                    "\"ephemeral\":true,\"compaction_pending\":%s,\"export_"
                    "revision\":%u,\"export_state\":\"%s\"}",
                    shared->revision, shared->count, capacity,
                    export_online ? "true" : "false", export_revision,
                    export_result == 1    ? "running"
                    : export_result == 2  ? "success"
                    : export_result == -1 ? "failed"
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
  if (expected != shared->revision) {
    return snprintf(out, size,
                    "{\"error\":\"revision conflict\",\"revision\":%u}",
                    shared->revision);
  }
  if (!strcmp(op, "overlay-compact")) {
    if (*save || export_pid || export_online) {
      goto invalid;
    }
    int online = !name;
    if (online && !isdstype(target->ds_type, dnsnapshot)) {
      goto invalid;
    }
    if (!export_snapshot(online ? target->ds_dsf->dsf_name : name, online)) {
      return snprintf(
          out, size,
          "{\"error\":\"cannot start export (use a separate output path)\"}");
    }
    return snprintf(out, size, "{\"accepted\":true,\"revision\":%u}",
                    shared->revision);
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
  unsigned i = lookup(v.name, v.len, &old);
  if (i == UINT32_MAX) {
    goto invalid;
  }
  int insert = i == capacity;
  if (insert && shared->count == capacity) {
    return snprintf(
        out, size,
        "{\"error\":\"overlay full; compact the snapshot\",\"revision\":%u}",
        shared->revision);
  }
  if (shared->revision == UINT32_MAX) {
    goto invalid;
  }
  v.revision = shared->revision + 1;
  if (insert) {
    for (unsigned scanned = 0; scanned < capacity; scanned++) {
      unsigned candidate = (next_slot + scanned) % capacity;
      if (!shared->slots[candidate].value.len) {
        i = candidate;
        next_slot = (candidate + 1) % capacity;
        break;
      }
    }
    if (i == capacity) {
      goto invalid;
    }
  }
  __atomic_fetch_add(&shared->sequence, 1, __ATOMIC_SEQ_CST);
  publish(&shared->slots[i], &v);
  if (insert) {
    int result;
    kh_put(overlay, &index_table, &shared->slots[i], &result);
    shared->count++;
  }
  __atomic_fetch_add(&shared->sequence, 1, __ATOMIC_RELEASE);
  shared->revision++;
  return snprintf(out, size, "{\"ok\":true,\"revision\":%u}", shared->revision);
invalid:
  return snprintf(out, size, "{\"error\":\"invalid overlay command\"}");
}

int rbldnsd_overlay_init(struct ev_loop *loop, unsigned limit,
                         void (*action)(int)) {
  if (!limit) {
    return 0;
  }
  if (ATOMIC_POINTER_LOCK_FREE != 2 || ATOMIC_INT_LOCK_FREE != 2) {
    errno = ENOTSUP;
    return -1;
  }

  target = nextdataset(NULL);
  if (limit > MAX_CAPACITY || !target || nextdataset(target) ||
      (!isdstype(target->ds_type, dnhash) &&
       !isdstype(target->ds_type, dnsnapshot))) {
    errno = EINVAL;
    return -1;
  }
  capacity = limit;
  tablesize = 4;
  while (tablesize < 2 * capacity) {
    tablesize *= 2;
  }
  size_t size = sizeof(*shared) + capacity * sizeof(struct slot);
  shared =
      mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (shared == MAP_FAILED) {
    shared = NULL;
    return -1;
  }
  index_table.n_buckets = tablesize;
  /* Capacity is capped at half the buckets; shared arrays must never resize. */
  index_table.upper_bound = UINT32_MAX;
  size_t flags_size = __ac_fsize(tablesize) * sizeof(*index_table.flags);
  size_t keys_size = tablesize * sizeof(*index_table.keys);
  index_table.flags = mmap(NULL, flags_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANON, -1, 0);
  index_table.keys = mmap(NULL, keys_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANON, -1, 0);
  if (index_table.flags == MAP_FAILED || index_table.keys == MAP_FAILED) {
    int saved_errno = errno;
    if (index_table.flags != MAP_FAILED) {
      munmap(index_table.flags, flags_size);
    }
    if (index_table.keys != MAP_FAILED) {
      munmap(index_table.keys, keys_size);
    }
    munmap(shared, size);
    shared = NULL;
    errno = saved_errno;
    return -1;
  }
  for (unsigned i = 0; i < tablesize; i++) {
    atomic_init(&index_table.keys[i], NULL);
  }
  rebuild_index();
  event_loop = loop;
  control_action = action;
  controller_pid = getpid();
  rbldnsd_control_extension(command);
  return 0;
}

void rbldnsd_overlay_child(void) {
  if (getpid() == controller_pid) {
    return;
  }
  /* libev's child watchers participate in a process-global SIGCHLD list;
   * detach this inherited watcher while its original loop is still valid. */
  if (event_loop && ev_is_active(&exporter)) {
    ev_child_stop(event_loop, &exporter);
  }
  export_pid = 0;
  event_loop = NULL;
}

void rbldnsd_overlay_close(void) {
  if (getpid() != controller_pid) {
    return;
  }
  if (export_pid) {
    kill(export_pid, SIGKILL);
    while (waitpid(export_pid, NULL, 0) < 0 && errno == EINTR) {
    }
    export_pid = 0;
  }
}
