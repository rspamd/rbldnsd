#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rbldnsd_udp.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

/* Keep the transport independently testable without the event loop. */
extern void rbldnsd_control_send_error(unsigned);
extern void rbldnsd_control_receive_drop(unsigned);

#ifdef WITH_RECVMMSG
void rbldnsd_udp_send(int fd, struct mmsghdr *msg, unsigned count) {
#else
void rbldnsd_udp_send(int fd, struct msghdr *msg, unsigned count) {
#endif
  unsigned done = 0;
  unsigned interrupted = 0;

  while (done < count) {
#ifdef WITH_RECVMMSG
    int n = sendmmsg(fd, msg + done, count - done, 0);
    if (n > 0) {
      done += (unsigned)n;
      continue;
    }
#else
    ssize_t n = sendmsg(fd, msg + done, 0);
    if (n >= 0) {
      ++done;
      continue;
    }
#endif
    if (n < 0 && errno == EINTR && interrupted++ < 4) {
      continue;
    }
    /* EAGAIN is normal overload. Retrying it in the read callback starves
     * receives, signals and timers. Datagram sends are atomic. */
    rbldnsd_control_send_error(count - done);
    break;
  }
}

static uint32_t *overflow;
static unsigned overflow_count;

int rbldnsd_udp_init(unsigned fd_limit) {
#ifdef SO_RXQ_OVFL
  overflow = mmap(NULL, (size_t)fd_limit * sizeof(*overflow), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (overflow == MAP_FAILED) {
    overflow = NULL;
    return -1;
  }
  overflow_count = fd_limit;
#else
  (void)fd_limit;
#endif
  return 0;
}

int rbldnsd_udp_enable(int fd) {
#ifdef SO_RXQ_OVFL
  int one = 1;
  return setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, &one, sizeof(one)) == 0;
#else
  (void)fd;
  return 0;
#endif
}

void rbldnsd_udp_overflow(int fd, uint32_t sample) {
  if (!overflow || fd < 0 || (unsigned)fd >= overflow_count) {
    return;
  }

  uint32_t previous = __atomic_load_n(&overflow[fd], __ATOMIC_RELAXED);
  for (;;) {
    uint32_t delta = sample - previous;
    /* Old and replacement workers briefly receive from the same socket.
     * Ignore stale samples delivered out of order, allowing wraparound.
     * Distinguishing wrap from stale requires fewer than 2^31 drops between
     * observations. The baseline is shared across all process generations. */
    if (!delta || delta >= UINT32_C(0x80000000)) {
      return;
    }
    if (__atomic_compare_exchange_n(&overflow[fd], &previous, sample, 0, __ATOMIC_RELAXED,
                                    __ATOMIC_RELAXED)) {
      rbldnsd_control_receive_drop(delta);
      return;
    }
  }
}

void rbldnsd_udp_received(int fd, const struct msghdr *msg) {
#ifdef SO_RXQ_OVFL
  /* A truncated ancillary buffer cannot provide reliable accounting. */
  if (msg->msg_flags & MSG_CTRUNC) {
    return;
  }

  struct msghdr copy = *msg;
  for (struct cmsghdr *c = CMSG_FIRSTHDR(&copy); c; c = CMSG_NXTHDR(&copy, c)) {
    size_t left = copy.msg_controllen - (size_t)((char *)c - (char *)copy.msg_control);
    if (c->cmsg_len < CMSG_LEN(0) || c->cmsg_len > left) {
      break;
    }
    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_RXQ_OVFL &&
        c->cmsg_len >= CMSG_LEN(sizeof(uint32_t))) {
      uint32_t sample;
      memcpy(&sample, CMSG_DATA(c), sizeof(sample));
      rbldnsd_udp_overflow(fd, sample);
    }
  }
#else
  (void)fd;
  (void)msg;
#endif
}
