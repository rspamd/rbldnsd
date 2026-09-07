#ifndef RBLDNSD_UDP_H
#define RBLDNSD_UDP_H
#include <sys/socket.h>
#include <stdint.h>
/* All sockets are nonblocking. At most four EINTR retries per batch; on
 * backpressure or permanent failure the unsent tail is deliberately dropped. */
#ifdef WITH_RECVMMSG
void rbldnsd_udp_send(int fd, struct mmsghdr *, unsigned count);
#else
void rbldnsd_udp_send(int fd, struct msghdr *, unsigned count);
#endif
int rbldnsd_udp_init(unsigned fd_limit);
int rbldnsd_udp_enable(int fd);
void rbldnsd_udp_received(int fd, const struct msghdr *);
void rbldnsd_udp_overflow(int fd, uint32_t sample);
#endif
