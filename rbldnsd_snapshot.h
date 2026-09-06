#ifndef RBLDNSD_SNAPSHOT_H
#define RBLDNSD_SNAPSHOT_H
/* Borrowed pointers are valid until dataset reset. table 0=exact, 1..5=wildcard.
 * A successful lookup with rr==NULL is an explicit exclusion, not a miss.
 * Callback may return zero to stop enumeration. Params limited to 64 pairs. */
extern int rbldnsd_snapshot_compiling;
#define SNAPSHOT_MAX_PARAMS 64
struct snapshot_entry {
  const unsigned char *name;
  unsigned namelen, table;
  const char *rr;
  unsigned nparams;
  struct kv_pair params[SNAPSHOT_MAX_PARAMS];
};
typedef int snapshot_visit_fn(const struct snapshot_entry *, void *);
int rbldnsd_dnhash_foreach(const struct dataset *, snapshot_visit_fn *, void *);
int rbldnsd_snapshot_foreach(const struct dataset *, snapshot_visit_fn *, void *);
int rbldnsd_snapshot_lookup(const struct dataset *, const unsigned char *, unsigned,
                            unsigned, struct snapshot_entry *);
typedef int snapshot_produce_fn(snapshot_visit_fn *, void *visit_arg, void *producer_arg);
int rbldnsd_snapshot_write_iter(const struct dataset *metadata, const char *path,
                                snapshot_produce_fn *, void *producer_arg);
int rbldnsd_snapshot_write(const struct dataset *, const char *);
int rbldnsd_snapshot_load(struct dataset *, int, struct dsctx *);
#endif
