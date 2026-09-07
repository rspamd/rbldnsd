"""Deterministic controller tests for activation, identities, and retirement.

Compile the production timer callback against controlled clock/IPC/process
primitives. This tests the otherwise scheduling-dependent timeout race without
adding fault-injection paths to the daemon.
"""
import os
import pathlib
import subprocess
import tempfile
import unittest


class GenerationTimeout(unittest.TestCase):
    def run_controller(self, main):
        source = (pathlib.Path(__file__).resolve().parents[2] /
                  'rbldnsd_generation.c').read_text()
        callbacks = []
        for name in ('generation_collect', 'generation_supervise'):
            begin = source.index('static void ' + name + '(')
            opening = source.index('{', begin)
            depth = 1
            end = opening + 1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            callbacks.append(source[begin:end])
        harness = r'''
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
typedef double ev_tstamp;

struct ev_loop {
  int unused;
};

typedef struct {
  int unused;
} ev_timer;

struct generation_stamp {
  time_t stamp;
  off_t size;
};

struct generation_zone {
  time_t stamp, expires;
};

struct rbldnsd_overlay_identity {
  uint64_t dev;
  uint64_t ino;
};

struct generation_process {
  pid_t guardian, owner;
  int fd, life, state;
  unsigned long id;
  struct rbldnsd_overlay_identity *bases;
  unsigned base_count;
  ev_tstamp deadline;
  unsigned char *message;
  size_t used;
};

struct dsfile {
  time_t dsf_stamp;
  off_t dsf_size;
  struct dsfile *dsf_next;
};

struct dataset {
  struct dsfile *ds_dsf;
};

struct zone {
  time_t z_stamp, z_expires;
  struct zone *z_next;
};
static struct zone *zonelist;
static struct dsfile test_file;
static struct dataset test_dataset = {&test_file};
static int datasets_enabled;
static int invalidate_unmatched;
static unsigned start_calls;
static int start_saw_invalidated;
static struct generation_process generation_active, generation_candidate, generation_retiring;
static size_t generation_message_size = 1024;
static int generation_ever_active, worker_ready_fd = -1, can_reload, pending_reload;
static int ack_reads, retire_commands, kills;
static double now = 10;
static int life_closed;
static unsigned released_generation;
static unsigned retired_calls;
static unsigned retired_count;
static struct rbldnsd_overlay_identity retired_bases[3];
#define LOG_WARNING 1
#define LOG_INFO 2

static double ev_time(void) {
  return now;
}

static struct dataset *nextdataset(struct dataset *d) {
  return datasets_enabled && !d ? &test_dataset : NULL;
}

static void dslog(int level, void *context, const char *fmt, ...) {
  (void)level;
  (void)context;
  (void)fmt;
}

static int fake_kill(pid_t p, int s) {
  (void)p;
  (void)s;
  ++kills;
  return 0;
}

static ssize_t fake_read(int fd, void *data, size_t size) {
  if (fd == 20 && size == 1) {
    *(char *)data = 'A';
    ++ack_reads;
    return 1;
  }
  if (fd == 30 && life_closed) {
    return 0;
  }
  errno = EAGAIN;
  return -1;
}

static ssize_t fake_write(int fd, const void *data, size_t size) {
  if (fd == 10 && size == 1 && *(const char *)data == 'Q') {
    ++retire_commands;
  }
  return size;
}

static int fake_close(int fd) {
  (void)fd;
  return 0;
}

static int generation_start(struct ev_loop *loop) {
  (void)loop;
  ++start_calls;
  start_saw_invalidated = test_file.dsf_stamp == 0;
  pending_reload = 0;
  return 1;
}

/* Optional integration hooks leave the process/IPC state unchanged. */
static void rbldnsd_control_release_generation_dead(unsigned id) {
  released_generation = id;
}

static void rbldnsd_control_generation(unsigned id) {
  (void)id;
}

static void rbldnsd_control_reload(int result) {
  (void)result;
}

static void rbldnsd_overlay_retired(const struct rbldnsd_overlay_identity *bases,
                                    unsigned count) {
  ++retired_calls;
  retired_count = count;
  if (count > 0 && count <= 3) {
    memcpy(retired_bases, bases, count * sizeof(*bases));
  }
  if (invalidate_unmatched && count == 2 && bases[1].ino != 404) {
    test_file.dsf_stamp = 0;
  }
}

#define kill fake_kill
#define read fake_read
#define write fake_write
#define close fake_close
'''
        with tempfile.TemporaryDirectory() as tmp:
            cfile = pathlib.Path(tmp) / 'timeout.c'
            binary = pathlib.Path(tmp) / 'timeout'
            cfile.write_text(harness + '\n'.join(callbacks) + main)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11',
                            str(cfile), '-o', str(binary)], check=True,
                           capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)


    def test_expired_ack_never_promotes_on_current_or_following_tick(self):
        main = r'''
int main(void) {
  generation_active = (struct generation_process){.guardian = 456, .owner = 123, .fd = 10, .id = 1};
  generation_candidate = (struct generation_process){.guardian = 654,
                                                     .owner = 321,
                                                     .fd = 20,
                                                     .id = 2,
                                                     .state = 1,
                                                     .deadline = 9,
                                                     .message = calloc(1, 1024)};
  generation_ever_active = 1;
  generation_supervise(NULL, NULL, 0);
  if (kills != 2 || ack_reads || retire_commands || generation_active.owner != 123) {
    fprintf(stderr, "expired candidate promoted or ACK consumed in timeout tick\n");
    return 1;
  }
  /* Guardian reaping has not happened; its ACK remains buffered. The retry
   * deadline is in the future, so this also catches a return-only fix. */
  now = 10.1;
  generation_supervise(NULL, NULL, 0);
  if (kills != 2 || ack_reads || retire_commands || generation_active.owner != 123) {
    fprintf(stderr, "expired candidate promoted on following timer tick\n");
    return 2;
  }
  free(generation_candidate.message);
  return 0;
}
'''
        self.run_controller(main)

    def test_all_target_identities_survive_until_retiring_descendants_exit(self):
        self.run_controller(r'''
int main(void) {
  struct rbldnsd_overlay_identity expected[3] = {{11, 101}, {22, 202}, {33, 303}};
  generation_active = (struct generation_process){
    .guardian = 456,
    .owner = 123,
    .fd = 10,
    .life = 30,
    .id = 1,
    .bases = calloc(3, sizeof(*generation_active.bases)),
    .base_count = 3
  };
  generation_active.bases[2].ino = 999;
  generation_candidate = (struct generation_process){
    .guardian = 654,
    .owner = 321,
    .fd = 20,
    .id = 2,
    .state = 1,
    .deadline = 20,
    .message = calloc(1, sizeof(pid_t) + sizeof(expected)),
    .bases = calloc(3, sizeof(*generation_candidate.bases)),
    .base_count = 3
  };
  memcpy(generation_candidate.message + sizeof(pid_t), expected, sizeof(expected));
  generation_supervise(NULL, NULL, 0);
  if (generation_active.owner != 321 || generation_active.base_count != 3 ||
      memcmp(generation_active.bases, expected, sizeof(expected)) ||
      generation_retiring.bases[2].ino != 999 || retired_calls) {
    fprintf(stderr, "promotion lost target metadata or pruned before retirement\n");
    return 1;
  }

  generation_retiring.guardian = 0;
  generation_supervise(NULL, NULL, 0);
  if (retired_calls || released_generation || generation_retiring.id != 1 ||
      generation_retiring.bases[2].ino != 999) {
    fprintf(stderr, "metadata released before descendant liveness EOF\n");
    return 2;
  }

  life_closed = 1;
  generation_supervise(NULL, NULL, 0);
  if (retired_calls != 1 || released_generation != 1 || generation_retiring.id ||
      retired_count != 3 || memcmp(retired_bases, expected, sizeof(expected))) {
    fprintf(stderr, "retirement did not report every active target identity\n");
    return 3;
  }
  free(generation_active.bases);
  return 0;
}
''')

    def test_queued_compaction_rechecks_identities_after_candidate_metadata(self):
        self.run_controller(r'''
int main(void) {
  struct rbldnsd_overlay_identity loaded[2] = {{11, 303}, {22, 202}};
  struct generation_stamp stale = {55, 66};
  datasets_enabled = 1;
  invalidate_unmatched = 1;
  pending_reload = 1;
  test_file.dsf_stamp = 0;
  test_file.dsf_size = 66;
  generation_active = (struct generation_process){
    .guardian = 456,
    .owner = 123,
    .fd = 10,
    .life = 30,
    .id = 1,
    .bases = calloc(2, sizeof(*generation_active.bases)),
    .base_count = 2
  };
  generation_candidate = (struct generation_process){
    .guardian = 654,
    .owner = 321,
    .fd = 20,
    .id = 2,
    .state = 1,
    .deadline = 20,
    .message = calloc(1, sizeof(pid_t) + sizeof(stale) + sizeof(loaded)),
    .bases = calloc(2, sizeof(*generation_candidate.bases)),
    .base_count = 2
  };
  memcpy(generation_candidate.message + sizeof(pid_t), &stale, sizeof(stale));
  memcpy(generation_candidate.message + sizeof(pid_t) + sizeof(stale), loaded, sizeof(loaded));

  /* Target 2 has published inode 404 after this candidate loaded inode 202.
   * Its byte size and timestamp are unchanged. Promotion must not erase the
   * queued reload just because it restores the stale report's file stamps. */
  generation_supervise(NULL, NULL, 0);
  if (test_file.dsf_stamp != 55 || !pending_reload || start_calls) {
    fprintf(stderr, "candidate promotion lost the queued second compaction\n");
    return 1;
  }

  generation_retiring.guardian = 0;
  life_closed = 1;
  generation_supervise(NULL, NULL, 0);
  if (start_calls != 1 || !start_saw_invalidated || retired_count != 2 ||
      retired_bases[0].ino != 303 || retired_bases[1].ino != 202) {
    fprintf(stderr, "pending reload ran before per-target identity reconciliation\n");
    return 2;
  }
  free(generation_active.bases);
  return 0;
}
''')

    def test_zero_overlay_targets_need_no_identity_allocation(self):
        self.run_controller(r'''
int main(void) {
  generation_candidate = (struct generation_process){
    .guardian = 654,
    .owner = 321,
    .fd = 20,
    .id = 1,
    .state = 1,
    .deadline = 20,
    .message = calloc(1, sizeof(pid_t))
  };
  generation_supervise(NULL, NULL, 0);
  if (generation_active.owner != 321 || generation_active.base_count ||
      generation_active.bases || retired_calls != 1 || retired_count) {
    fprintf(stderr, "zero-target generation activation failed\n");
    return 1;
  }
  return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
