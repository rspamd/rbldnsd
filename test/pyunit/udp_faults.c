#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef TEST_BATCH
#define WITH_RECVMMSG
#ifndef __linux__
struct mmsghdr { struct msghdr msg_hdr; unsigned msg_len; };
#endif
#endif
static int results[16], errors[16], calls, length;
static unsigned dropped, received, offset;
#ifdef TEST_BATCH
static struct mmsghdr messages[8];
static int injected_sendmmsg(int fd, struct mmsghdr *msg, unsigned count, int flags) {
  assert(fd == 42 && flags == 0 && calls < length);
  assert(msg == messages + offset && count == 5 - offset);
  int n = results[calls]; errno = errors[calls++];
  if (n > 0) offset += n;
  return n;
}
#define sendmmsg injected_sendmmsg
#else
static struct msghdr messages[8];
static ssize_t injected_sendmsg(int fd, const struct msghdr *msg, int flags) {
  assert(fd == 42 && flags == 0 && calls < length);
  assert(msg == messages + offset);
  int n = results[calls]; errno = errors[calls++];
  if (n >= 0) ++offset;
  return n;
}
#define sendmsg injected_sendmsg
#endif
void rbldnsd_control_send_error(unsigned n) { dropped += n; }
void rbldnsd_control_receive_drop(unsigned n) { received += n; }
#include "rbldnsd_udp.c"
static void reset(void) {
  memset(results, 0, sizeof(results)); memset(errors, 0, sizeof(errors));
  calls = length = 0; dropped = received = offset = 0;
}
static void add(int result, int error) { results[length] = result; errors[length++] = error; }
int main(void) {
  reset(); rbldnsd_udp_send(42, messages, 0); assert(!calls && !dropped);
  int fatal[] = { EAGAIN, EWOULDBLOCK, ENOBUFS, EINVAL, EMSGSIZE };
  for (unsigned i = 0; i < sizeof(fatal)/sizeof(fatal[0]); ++i) {
    reset(); add(-1, fatal[i]); rbldnsd_udp_send(42, messages, 5);
    assert(calls == 1 && dropped == 5 && offset == 0);
  }
  reset(); for (int i = 0; i < 5; ++i) add(-1, EINTR);
  rbldnsd_udp_send(42, messages, 5); assert(calls == 5 && dropped == 5);
  reset(); add(-1, EINTR);
#ifdef TEST_BATCH
  add(2,0); add(1,0); add(2,0);
#else
  for (int i = 0; i < 5; ++i) add(10,0);
#endif
  rbldnsd_udp_send(42, messages, 5); assert(offset == 5 && !dropped && calls == length);
  reset();
#ifdef TEST_BATCH
  add(2,0);
#else
  add(10,0); add(10,0);
#endif
  add(-1, EAGAIN); rbldnsd_udp_send(42, messages, 5);
  assert(offset == 2 && dropped == 3 && calls == length);
#ifdef TEST_BATCH
  reset(); add(0,0); rbldnsd_udp_send(42,messages,5); assert(calls == 1 && dropped == 5);
#endif
  uint32_t baseline[2] = {0}; overflow = baseline; overflow_count = 2;
  received = 0;
  rbldnsd_udp_overflow(1,10); rbldnsd_udp_overflow(1,10); rbldnsd_udp_overflow(1,9);
  rbldnsd_udp_overflow(1,12); rbldnsd_udp_overflow(2,100);
  assert(received == 12 && baseline[1] == 12);
  baseline[1] = UINT32_MAX - 2; received = 0;
  rbldnsd_udp_overflow(1,3); assert(received == 6);
#ifdef SO_RXQ_OVFL
  union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(uint32_t))]; } buf;
  struct msghdr hdr = {0}; hdr.msg_control = buf.data; hdr.msg_controllen = sizeof(buf.data);
  memset(&buf,0,sizeof(buf)); struct cmsghdr *c = CMSG_FIRSTHDR(&hdr);
  c->cmsg_level = SOL_SOCKET; c->cmsg_type = SO_RXQ_OVFL; c->cmsg_len = CMSG_LEN(4);
  uint32_t sample = 7; memcpy(CMSG_DATA(c),&sample,4);
  hdr.msg_flags = MSG_CTRUNC; rbldnsd_udp_received(1,&hdr); assert(received == 6);
  hdr.msg_flags = 0; c->cmsg_len = 999; rbldnsd_udp_received(1,&hdr); assert(received == 6);
  c->cmsg_len = CMSG_LEN(1); rbldnsd_udp_received(1,&hdr); assert(received == 6);
  c->cmsg_len = CMSG_LEN(4); rbldnsd_udp_received(1,&hdr); assert(received == 10);
  assert(rbldnsd_udp_init(2) == 0);
  received = 0;
  pid_t child = fork(); assert(child >= 0);
  if (!child) { rbldnsd_udp_overflow(1,100); _exit(0); }
  int status; assert(waitpid(child,&status,0) == child && WIFEXITED(status));
  rbldnsd_udp_overflow(1,104); assert(received == 4);
  munmap(overflow, 2 * sizeof(*overflow)); overflow = NULL;
#endif
  puts("UDP fault tests passed");
  return 0;
}
