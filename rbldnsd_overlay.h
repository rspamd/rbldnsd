#ifndef RBLDNSD_OVERLAY_H
#define RBLDNSD_OVERLAY_H
#include <stdint.h>
struct ev_loop;
struct dataset;
struct dnsqinfo;
struct dnspacket;
struct zone;
/* One independently shared overlay per configured domain dataset. */
int rbldnsd_overlay_init(struct ev_loop *, unsigned capacity,
                         void (*action)(int), struct zone *zones);
/* -1 means no override; 0 is an exclusion, positive is NSQUERY_FOUND. */
int rbldnsd_overlay_query(const struct dataset *, const struct dnsqinfo *,
                          struct dnspacket *);
void rbldnsd_overlay_close(void);
/* Call in a fork child before destroying the inherited event loop. */
void rbldnsd_overlay_child(void);
void rbldnsd_overlay_loaded(const struct dataset *, int fd);
struct rbldnsd_overlay_identity {
  uint64_t dev;
  uint64_t ino;
};
unsigned rbldnsd_overlay_target_count(void);
void rbldnsd_overlay_base_identities(struct rbldnsd_overlay_identity *,
                                     unsigned count);
/* Controller calls only once all workers using older bases have exited. */
void rbldnsd_overlay_retired(const struct rbldnsd_overlay_identity *,
                             unsigned count);
#endif
