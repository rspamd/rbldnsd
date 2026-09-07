/* Local, bounded datagram control protocol and fork-shared worker accounting. */
#include "rbldnsd_control.h"
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <inttypes.h>

#define SLOTS 257
/* Generation and phase are published in one atomic reservation. No killed
 * allocator can leave an unidentifiable slot with stale generation metadata. */
#define OWN(generation, phase) (((uint64_t)(generation) << 32) | (phase))
#define PHASE(ownership) ((unsigned)((ownership) & UINT32_MAX))
#define GENERATION(ownership) ((unsigned)((ownership) >> 32))
#define LOAD(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define ADD(ptr, value) __atomic_fetch_add((ptr), (value), __ATOMIC_RELAXED)
#define SET(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)

struct counts {
  uint64_t queries, in, replies, out, noerror, nxdomain, other, unanswered, send_errors,
      receive_drops, rate_limited;
};

struct slot {
  struct counts counts, baseline;
  uint64_t backlog, backlog_bytes;
  uint64_t ownership;
  pid_t pid;
};

static struct shared {
  struct slot slots[SLOTS];
  unsigned generation, receive_accounting, send_accounting;
  int reload_result;
  time_t reload_time;
} *shared;

static int current_slot = -1;
static int control_fd = -1;
static pid_t controller_pid;
#ifdef RBLDNSD_CONTROL_TESTING
static void (*reservation_hook)(void);
void rbldnsd_control_test_reservation_hook(void (*hook)(void)) {
  reservation_hook = hook;
}
#endif
static ev_io watcher;
static void (*action)(int);
static int (*extension)(const char *, char *, size_t);
static char bound_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static dev_t bound_dev;
static ino_t bound_ino;

/* Quarantine is distinct from draining: a quarantined worker may still write,
 * but it must never make its slot available to another process. PID reuse can
 * delay reclamation, which is conservative and preferable to shared writers. */
static void reclaim_quarantined(void) {
  if (!shared || getpid() != controller_pid) {
    return;
  }

  for (int i = 0; i < SLOTS; ++i) {
    struct slot *worker_slot = &shared->slots[i];
    uint64_t ownership = LOAD(&worker_slot->ownership);
    if (PHASE(ownership) != 5) {
      continue;
    }
    pid_t pid = LOAD(&worker_slot->pid);

    /* An unpublished child could still start: only all-writers-dead proof
     * can reclaim a PID-zero slot. */
    if (pid > 0 && kill(pid, 0) < 0 && errno == ESRCH) {
      __atomic_compare_exchange_n(&worker_slot->ownership, &ownership, 0, 0, __ATOMIC_RELEASE,
                                  __ATOMIC_RELAXED);
    }
  }
}

static void collect(struct counts *to, const struct counts *from) {
#define C(length) to->length += LOAD(&from->length)
  C(queries);
  C(in);
  C(replies);
  C(out);
  C(noerror);
  C(nxdomain);
  C(other);
  C(unanswered);
  C(send_errors);
  C(receive_drops);
  C(rate_limited);
#undef C
}

static void append(char **cursor, size_t *remaining, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int length = vsnprintf(*cursor, *remaining, fmt, ap);
  va_end(ap);
  if (length < 0 || (size_t)length >= *remaining) {
    *remaining = 0;
    return;
  }
  *cursor += length;
  *remaining -= length;
}

static void counters(char **cursor, size_t *remaining, const struct counts *counts) {
  append(cursor, remaining,
         "\"queries\":%" PRIu64 ",\"received_bytes\":%" PRIu64 ",\"responses_generated\":%" PRIu64
         ",\"response_bytes_generated\":%" PRIu64 ",\"noerror\":%" PRIu64 ",\"nxdomain\":%" PRIu64
         ",\"other_rcode\":%" PRIu64 ",\"unanswered\":%" PRIu64 ",\"send_errors\":%" PRIu64
         ",\"receive_drops\":%" PRIu64 ",\"rate_limited\":%" PRIu64,
         counts->queries, counts->in, counts->replies, counts->out, counts->noerror,
         counts->nxdomain, counts->other, counts->unanswered, counts->send_errors,
         counts->receive_drops, counts->rate_limited);
}

static void receive_command(struct ev_loop *loop, ev_io *w, int events) {
  char command[4096];
  char original[4096];
  char response[16384];
  char *cursor = response;
  struct sockaddr_un peer;
  struct iovec iov = {command, sizeof(command)};
  struct msghdr msg = {0};
  msg.msg_name = &peer;
  msg.msg_namelen = sizeof(peer);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  ssize_t length = recvmsg(control_fd, &msg, 0);
  if (length < 0) {
    return;
  }

  reclaim_quarantined();
  size_t remaining = sizeof(response);
  int operation = 0;

  /* Validate command framing before parsing optional pagination. */
  if (length >= (ssize_t)sizeof(command) || (msg.msg_flags & MSG_TRUNC)) {
    length = 0;
  }
  while (length > 0 && (command[length - 1] == '\n' || command[length - 1] == '\r')) {
    --length;
  }
  if (memchr(command, 0, (size_t)length)) {
    length = 0;
  }
  command[length] = 0;
  memcpy(original, command, (size_t)length + 1);

  unsigned first_slot = 0;
  char *space = strchr(command, ' ');
  if (space) {
    char *end;
    unsigned long value = strtoul(space + 1, &end, 10);
    if (space[1] < '0' || space[1] > '9' || *end || value >= SLOTS) {
      command[0] = 0;
    } else {
      *space = 0;
      first_slot = (unsigned)value;
    }
  }

  if (!strcmp(command, "status") || !strcmp(command, "stats")) {
    /* Lifetime totals include retired workers through their reused slots. */
    struct counts total = {0};
    for (int i = 0; i < SLOTS; ++i) {
      collect(&total, &shared->slots[i].counts);
    }
    append(&cursor, &remaining,
           "{\"pid\":%ld,\"generation\":%u,\"reload\":\"%s\",\"reload_time\":%ld,\"totals\":{",
           (long)getpid(), shared->generation,
           shared->reload_result < 0 ? "loading"
           : shared->reload_result   ? "success"
                                     : "failed",
           (long)shared->reload_time);
    counters(&cursor, &remaining, &total);
    append(&cursor, &remaining,
           "},\"receive_drop_accounting\":%s,\"send_error_accounting\":%s,\"workers\":[",
           LOAD(&shared->receive_accounting) ? "true" : "false",
           LOAD(&shared->send_accounting) ? "true" : "false");

    int worker_count = 0;
    int next_slot = -1;
    for (int i = (int)first_slot; i < SLOTS; ++i) {
      struct slot *worker_slot = &shared->slots[i];
      uint64_t ownership = LOAD(&worker_slot->ownership);
      if (!ownership || PHASE(ownership) >= 4) {
        continue;
      }
      if (worker_count == 8) {
        next_slot = i;
        break;
      }
      struct counts base = {0};
      struct counts counts = {0};
      collect(&base, &worker_slot->baseline);
      collect(&counts, &worker_slot->counts);
#define C(length) counts.length -= base.length
      C(queries);
      C(in);
      C(replies);
      C(out);
      C(noerror);
      C(nxdomain);
      C(other);
      C(unanswered);
      C(send_errors);
      C(receive_drops);
      C(rate_limited);
#undef C
      append(&cursor, &remaining, "%s{\"slot\":%d,\"pid\":%ld,\"generation\":%u,\"state\":\"%s\",",
             worker_count ? "," : "", i, (long)LOAD(&worker_slot->pid), GENERATION(ownership),
             PHASE(ownership) == 3   ? "draining"
             : PHASE(ownership) == 2 ? "running"
                                     : "starting");
      ++worker_count;
      counters(&cursor, &remaining, &counts);
      append(&cursor, &remaining, ",\"delayed_backlog\":%" PRIu64 ",\"delayed_bytes\":%" PRIu64 "}",
             LOAD(&worker_slot->backlog), LOAD(&worker_slot->backlog_bytes));
    }

    append(&cursor, &remaining, "],\"next_slot\":%d}\n", next_slot);
  } else if (!space && (!strcmp(command, "reload") || !strcmp(command, "shutdown"))) {
    operation = !strcmp(command, "reload") ? 1 : 2;
    append(&cursor, &remaining, "{\"accepted\":true}\n");
  } else {
    int length = extension && original[0] ? extension(original, response, sizeof(response)) : -1;
    if (length >= 0 && (size_t)length < sizeof(response)) {
      cursor = response + length;
      remaining = sizeof(response) - length;
    } else {
      append(&cursor, &remaining, "{\"error\":\"invalid or unsupported command\"}\n");
    }
  }

  /* Never wait for a slow or abandoned client. A dropped reply is retriable;
   * mutating commands have signal-like, idempotent acceptance semantics. */
  if (remaining &&
      sendto(control_fd, response, (size_t)(cursor - response), 0, (void *)&peer, msg.msg_namelen) <
          0 &&
      errno == EMSGSIZE) {
    static const char failure[] = "{\"error\":\"response exceeds socket limit\"}\n";
    sendto(control_fd, failure, sizeof(failure) - 1, 0, (void *)&peer, msg.msg_namelen);
  }
  if (operation) {
    action(operation);
  }
}

int rbldnsd_control_init(struct ev_loop *loop, const char *path, void (*callback)(int)) {
  if (!path) {
    return 0;
  }
  if (strlen(path) >= sizeof(bound_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (shared == MAP_FAILED) {
    shared = NULL;
    return -1;
  }
  control_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (control_fd < 0) {
    return -1;
  }

  int socket_buffer_size = 262144;
  if (setsockopt(control_fd, SOL_SOCKET, SO_SNDBUF, &socket_buffer_size,
                 sizeof(socket_buffer_size)) < 0 ||
      setsockopt(control_fd, SOL_SOCKET, SO_RCVBUF, &socket_buffer_size,
                 sizeof(socket_buffer_size)) < 0) {
    return -1;
  }
  if (fcntl(control_fd, F_SETFL, O_NONBLOCK) < 0 || fcntl(control_fd, F_SETFD, FD_CLOEXEC) < 0) {
    return -1;
  }

  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  mode_t previous_umask = umask(077);
  int bind_result = bind(control_fd, (void *)&addr, sizeof(addr));
  int bind_errno = errno;
  umask(previous_umask);
  errno = bind_errno;
  if (bind_result < 0) {
    return -1; /* Never unlink a pre-existing file or listener. */
  }
  strcpy(bound_path, path);
  if (chmod(path, 0600) < 0) {
    return -1;
  }

  struct stat st;
  if (lstat(path, &st) < 0) {
    return -1;
  }
  bound_dev = st.st_dev;
  bound_ino = st.st_ino;
  shared->reload_result = 1;
  shared->reload_time = time(NULL);
  controller_pid = getpid();
  action = callback;
  ev_io_init(&watcher, receive_command, control_fd, EV_READ);
  ev_io_start(loop, &watcher);
  return 0;
}

int rbldnsd_control_slot_alloc(unsigned generation) {
  if (!shared) {
    return -1;
  }

  reclaim_quarantined();
  for (int i = 0; i < SLOTS; ++i) {
    uint64_t empty = 0;
    uint64_t reserved = OWN(generation, 4);
    if (!__atomic_compare_exchange_n(&shared->slots[i].ownership, &empty, reserved, 0,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
      continue;
    }

#ifdef RBLDNSD_CONTROL_TESTING
    if (reservation_hook) {
      reservation_hook();
    }
#endif
    shared->slots[i].baseline = shared->slots[i].counts;
    shared->slots[i].backlog_bytes = 0;
    shared->slots[i].backlog = 0;
    shared->slots[i].pid = 0;

    if (!__atomic_compare_exchange_n(&shared->slots[i].ownership, &reserved, OWN(generation, 1), 0,
                                     __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
      return -1;
    }
    return i;
  }
  return -1;
}

void rbldnsd_control_child(void) {
  if (control_fd >= 0) {
    ev_io_stop(ev_default_loop(0), &watcher);
    close(control_fd);
    control_fd = -1;
  }
}

int rbldnsd_control_worker(int slot) {
  current_slot = -1;
  if (!shared) {
    return 1;
  }
  if (slot < 0 || slot >= SLOTS) {
    return 0;
  }
  SET(&shared->slots[slot].pid, getpid());
  uint64_t starting = LOAD(&shared->slots[slot].ownership);
  if (PHASE(starting) != 1) {
    return 0;
  }
  if (!__atomic_compare_exchange_n(&shared->slots[slot].ownership, &starting,
                                   OWN(GENERATION(starting), 2), 0, __ATOMIC_ACQ_REL,
                                   __ATOMIC_RELAXED)) {
    return 0;
  }
  current_slot = slot;
  return 1;
}

void rbldnsd_control_release(int slot) {
  if (shared && slot >= 0 && slot < SLOTS) {
    SET(&shared->slots[slot].ownership, 0);
  }
}

void rbldnsd_control_release_generation(unsigned generation) {
  if (!shared || getpid() != controller_pid) {
    return;
  }

  for (int i = 0; i < SLOTS; ++i) {
    uint64_t ownership = LOAD(&shared->slots[i].ownership);
    while (ownership && GENERATION(ownership) == generation && PHASE(ownership) < 5) {
      /* A reservation may retain the previous occupant's PID: phase 6 cannot
       * use PID-based reclamation and requires the all-writers-dead proof. */
      uint64_t quarantined = OWN(generation, PHASE(ownership) == 4 ? 6 : 5);
      if (__atomic_compare_exchange_n(&shared->slots[i].ownership, &ownership, quarantined, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
        break;
      }
    }
  }

  reclaim_quarantined();
}

void rbldnsd_control_release_generation_dead(unsigned generation) {
  if (!shared || getpid() != controller_pid) {
    return;
  }

  for (int i = 0; i < SLOTS; ++i) {
    uint64_t ownership = LOAD(&shared->slots[i].ownership);
    while (ownership && GENERATION(ownership) == generation &&
           !__atomic_compare_exchange_n(&shared->slots[i].ownership, &ownership, 0, 0,
                                        __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
    }
  }
}

void rbldnsd_control_generation(unsigned generation) {
  if (shared) {
    shared->generation = generation;
  }
}

void rbldnsd_control_reload(int result) {
  if (shared) {
    shared->reload_result = result;
    shared->reload_time = time(NULL);
  }
}

void rbldnsd_control_draining(void) {
  if (shared && current_slot >= 0) {
    uint64_t running = LOAD(&shared->slots[current_slot].ownership);
    if (PHASE(running) != 2) {
      return;
    }
    __atomic_compare_exchange_n(&shared->slots[current_slot].ownership, &running,
                                OWN(GENERATION(running), 3), 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
  }
}

void rbldnsd_control_query(unsigned bytes, int reply_bytes, unsigned rcode) {
  if (!shared || current_slot < 0) {
    return;
  }

  struct counts *counts = &shared->slots[current_slot].counts;
  ADD(&counts->queries, 1);
  ADD(&counts->in, bytes);
  if (reply_bytes > 0) {
    ADD(&counts->replies, 1);
    ADD(&counts->out, reply_bytes);
    if (rcode == 0) {
      ADD(&counts->noerror, 1);
    } else if (rcode == 3) {
      ADD(&counts->nxdomain, 1);
    } else {
      ADD(&counts->other, 1);
    }
  } else {
    ADD(&counts->unanswered, 1);
  }
}

void rbldnsd_control_backlog(unsigned count, uint64_t bytes) {
  if (shared && current_slot >= 0) {
    SET(&shared->slots[current_slot].backlog, count);
    SET(&shared->slots[current_slot].backlog_bytes, bytes);
  }
}

void rbldnsd_control_send_error(unsigned count) {
  if (shared && current_slot >= 0) {
    ADD(&shared->slots[current_slot].counts.send_errors, count);
  }
}

void rbldnsd_control_receive_drop(unsigned count) {
  if (shared && current_slot >= 0) {
    ADD(&shared->slots[current_slot].counts.receive_drops, count);
  }
}

void rbldnsd_control_transport_support(int receive, int send) {
  if (shared) {
    if (receive) {
      SET(&shared->receive_accounting, 1);
    }
    if (send) {
      SET(&shared->send_accounting, 1);
    }
  }
}

void rbldnsd_control_rate_limited(void) {
  if (shared && current_slot >= 0) {
    ADD(&shared->slots[current_slot].counts.rate_limited, 1);
  }
}

void rbldnsd_control_extension(int (*callback)(const char *, char *, size_t)) {
  extension = callback;
}

void rbldnsd_control_close(void) {
  if (control_fd >= 0) {
    close(control_fd);
    control_fd = -1;
    struct stat st;
    if (*bound_path && lstat(bound_path, &st) == 0 && st.st_dev == bound_dev &&
        st.st_ino == bound_ino) {
      unlink(bound_path);
    }
  }
}
