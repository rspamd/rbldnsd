"""Deterministic controller-state regression for a buffered activation ACK.

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
    def test_expired_ack_never_promotes_on_current_or_following_tick(self):
        source = (pathlib.Path(__file__).resolve().parents[2] /
                  'rbldnsd_generation.c').read_text()
        begin = source.index('static void generation_supervise(')
        opening = source.index('{', begin)
        depth = 1
        end = opening + 1
        while depth:
            depth += (source[end] == '{') - (source[end] == '}')
            end += 1
        callback = source[begin:end]
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
struct ev_loop { int unused; };
typedef struct { int unused; } ev_timer;
struct generation_stamp { time_t stamp; off_t size; };
struct generation_zone { time_t stamp, expires; };
struct generation_base { uint64_t dev, ino; };
struct generation_process {
  pid_t guardian, owner;
  int fd, life, state;
  unsigned long id;
  struct generation_base base;
  ev_tstamp deadline;
  unsigned char *message;
  size_t used;
};
struct dsfile { time_t dsf_stamp; off_t dsf_size; struct dsfile *dsf_next; };
struct dataset { struct dsfile *ds_dsf; };
struct zone { time_t z_stamp, z_expires; struct zone *z_next; };
static struct zone *zonelist;
static struct generation_process generation_active, generation_candidate,
                                 generation_retiring;
static size_t generation_message_size = 1024;
static int generation_ever_active, worker_ready_fd = -1, can_reload, pending_reload;
static int ack_reads, retire_commands, kills;
static double now = 10;
#define LOG_WARNING 1
#define LOG_INFO 2
static double ev_time(void) { return now; }
static struct dataset *nextdataset(struct dataset *d) { (void)d; return NULL; }
static void dslog(int level, void *context, const char *fmt, ...) {
  (void)level; (void)context; (void)fmt;
}
static int fake_kill(pid_t p, int s) { (void)p; (void)s; ++kills; return 0; }
static ssize_t fake_read(int fd, void *data, size_t size) {
  if (fd == 20 && size == 1) { *(char *)data = 'A'; ++ack_reads; return 1; }
  errno = EAGAIN; return -1;
}
static ssize_t fake_write(int fd, const void *data, size_t size) {
  if (fd == 10 && size == 1 && *(const char *)data == 'Q') ++retire_commands;
  return size;
}
static int fake_close(int fd) { (void)fd; return 0; }
static int generation_start(struct ev_loop *loop) { (void)loop; return 1; }
/* Optional integration hooks leave the process/IPC state unchanged. */
static void generation_collect(void) {}
static void rbldnsd_control_generation(unsigned id) { (void)id; }
static void rbldnsd_control_reload(int result) { (void)result; }
static void rbldnsd_overlay_retired(uint64_t dev, uint64_t ino) { (void)dev; (void)ino; }
#define kill fake_kill
#define read fake_read
#define write fake_write
#define close fake_close
'''
        main = r'''
int main(void) {
  generation_active = (struct generation_process){
    .guardian = 456, .owner = 123, .fd = 10, .id = 1
  };
  generation_candidate = (struct generation_process){
    .guardian = 654, .owner = 321, .fd = 20, .id = 2,
    .state = 1, .deadline = 9, .message = calloc(1, 1024)
  };
  generation_ever_active = 1;
  generation_supervise(NULL, NULL, 0);
  if (kills != 2 || ack_reads || retire_commands ||
      generation_active.owner != 123) {
    fprintf(stderr, "expired candidate promoted or ACK consumed in timeout tick\n");
    return 1;
  }
  /* Guardian reaping has not happened; its ACK remains buffered. The retry
   * deadline is in the future, so this also catches a return-only fix. */
  now = 10.1;
  generation_supervise(NULL, NULL, 0);
  if (kills != 2 || ack_reads || retire_commands ||
      generation_active.owner != 123) {
    fprintf(stderr, "expired candidate promoted on following timer tick\n");
    return 2;
  }
  free(generation_candidate.message);
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            cfile = pathlib.Path(tmp) / 'timeout.c'
            binary = pathlib.Path(tmp) / 'timeout'
            cfile.write_text(harness + callback + main)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=c11',
                            str(cfile), '-o', str(binary)], check=True,
                           capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
