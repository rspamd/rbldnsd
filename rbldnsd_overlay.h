#ifndef RBLDNSD_OVERLAY_H
#define RBLDNSD_OVERLAY_H
#include <stdint.h>
struct ev_loop;
/* Exactly one domain dataset, controller-owned writes, shared atomic reads. */
int rbldnsd_overlay_init(struct ev_loop *, unsigned capacity, void (*action)(int));
/* -1 means no override; 0 is an exclusion, positive is NSQUERY_FOUND. */
int rbldnsd_overlay_query(const struct dataset *, const struct dnsqinfo *, struct dnspacket *);
void rbldnsd_overlay_close(void);
/* Call in a fork child before destroying the inherited event loop. */
void rbldnsd_overlay_child(void);
void rbldnsd_overlay_loaded(const struct dataset *, int fd);
void rbldnsd_overlay_base_identity(uint64_t *dev, uint64_t *ino);
/* Controller calls only once all workers using older bases have exited. */
void rbldnsd_overlay_retired(uint64_t active_dev, uint64_t active_ino);
#endif
