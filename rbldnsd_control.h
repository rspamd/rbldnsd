#ifndef RBLDNSD_CONTROL_H
#define RBLDNSD_CONTROL_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <ev.h>
/* Fixed shared accounting, separate from the CoW zone image. One writer per
 * live slot; the controller releases a slot only after reaping its process. */
int rbldnsd_control_init(struct ev_loop *, const char *, void (*)(int));
int rbldnsd_control_slot_alloc(unsigned generation);
void rbldnsd_control_child(void); /* closes inherited control listener only */
int rbldnsd_control_worker(int slot); /* returns zero if quarantined/stale */
void rbldnsd_control_release(int slot);
void rbldnsd_control_generation(unsigned generation);
/* Quarantine after generation owner death. Reuse waits for writer ESRCH;
 * PID-zero slots require the all-writers-dead API below. Controller only. */
void rbldnsd_control_release_generation(unsigned generation);
/* Controller only: requires proof ALL generation writers exited (e.g. EOF on
 * a liveness pipe held by every descendant); owner/guardian reap is insufficient. */
void rbldnsd_control_release_generation_dead(unsigned generation);
void rbldnsd_control_reload(int result); /* -1 loading, 0 failed, 1 successful */
void rbldnsd_control_draining(void);
void rbldnsd_control_query(unsigned bytes, int reply_bytes, unsigned rcode);
void rbldnsd_control_backlog(unsigned count, uint64_t bytes);
void rbldnsd_control_send_error(unsigned count);
void rbldnsd_control_receive_drop(unsigned count);
void rbldnsd_control_transport_support(int receive, int send);
void rbldnsd_control_rate_limited(void);
/* Extension returns response byte count, or -1 for an unknown command. */
void rbldnsd_control_extension(int (*)(const char *, char *, size_t));
void rbldnsd_control_close(void);
#endif
