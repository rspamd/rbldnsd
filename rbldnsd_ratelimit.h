#ifndef RBLDNSD_RATELIMIT_H
#define RBLDNSD_RATELIMIT_H
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
/* Initialize once in the root, before any forks/chroot. NULL disables quotas.
 * The inherited MAP_SHARED accounting survives workers and zone generations. */
int rbldnsd_ratelimit_init(const char *path, char *error, size_t size);
int rbldnsd_ratelimit_check(const struct sockaddr *peer, const char *zone,
                           const char *authenticated_key);
/* Explicit monotonic nanoseconds for deterministic tests; same shared state. */
int rbldnsd_ratelimit_check_at(const struct sockaddr *, const char *,
                              const char *, uint64_t now);
void rbldnsd_ratelimit_close(void);
#endif
