/* Deterministic regression: a reaped generation owner does not prove that
 * inherited MAP_SHARED writers have stopped. Exercise the slot API directly. */
#include "rbldnsd_control.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static void stop_at_reservation(void) {
  raise(SIGSTOP);
}

static void no_action(int action) {
  (void)action;
}

static void receive_byte(int fd) {
  char marker;
  assert(read(fd, &marker, 1) == 1);
}

static void send_byte(int fd) {
  assert(write(fd, "X", 1) == 1);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(rbldnsd_control_init(ev_default_loop(0), argv[1], no_action) == 0);
  int slot = rbldnsd_control_slot_alloc(1);
  int commands[2];
  int replies[2];
  assert(slot >= 0 && pipe(commands) == 0 && pipe(replies) == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    close(commands[1]);
    close(replies[0]);
    rbldnsd_control_child();
    assert(rbldnsd_control_worker(slot));
    send_byte(replies[1]);
    receive_byte(commands[0]);

    /* Quarantine must survive an old worker changing into draining state. */
    rbldnsd_control_draining();
    rbldnsd_control_query(10, 20, 0);
    send_byte(replies[1]);
    receive_byte(commands[0]);
    _exit(0);
  }

  close(commands[0]);
  close(replies[1]);
  receive_byte(replies[0]);
  rbldnsd_control_release_generation(1);
  int other = rbldnsd_control_slot_alloc(2);
  assert(other >= 0 && other != slot);
  send_byte(commands[1]);
  receive_byte(replies[0]);
  int third = rbldnsd_control_slot_alloc(2);
  assert(third >= 0 && third != slot);
  send_byte(commands[1]);
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);

  /* ESRCH now permits automatic reclamation, without transferring counters. */
  assert(rbldnsd_control_slot_alloc(3) == slot);
  rbldnsd_control_release(slot);
  rbldnsd_control_release(other);
  rbldnsd_control_release(third);
  close(commands[1]);
  close(replies[0]);

  /* A forked child may not yet have published its PID when the owner dies. */
  slot = rbldnsd_control_slot_alloc(4);
  assert(pipe(commands) == 0 && pipe(replies) == 0);
  child = fork();
  assert(child >= 0);
  if (!child) {
    close(commands[1]);
    close(replies[0]);
    rbldnsd_control_child();
    receive_byte(commands[0]);
    assert(!rbldnsd_control_worker(slot)); /* cannot resurrect quarantine */
    send_byte(replies[1]);
    receive_byte(commands[0]);
    _exit(0);
  }

  close(commands[0]);
  close(replies[1]);
  rbldnsd_control_release_generation(4);
  other = rbldnsd_control_slot_alloc(5);
  assert(other >= 0 && other != slot);
  send_byte(commands[1]);
  receive_byte(replies[0]);
  third = rbldnsd_control_slot_alloc(5);
  assert(third >= 0 && third != slot);
  send_byte(commands[1]);
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
  rbldnsd_control_release_generation_dead(4);
  assert(rbldnsd_control_slot_alloc(6) == slot);
  close(commands[1]);
  close(replies[0]);
  rbldnsd_control_release_generation_dead(5);
  rbldnsd_control_release_generation_dead(6);

  /* More crashes than the entire slot pool: each allocator dies immediately
   * after reservation, before PID/baseline initialization. Reclaiming must
   * identify the new generation, not the previous occupant's metadata. */
  for (unsigned generation_id = 100; generation_id < 400; ++generation_id) {
    child = fork();
    assert(child >= 0);
    if (!child) {
      rbldnsd_control_child();
      rbldnsd_control_test_reservation_hook(stop_at_reservation);
      rbldnsd_control_slot_alloc(generation_id);
      _exit(99);
    }
    assert(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    rbldnsd_control_release_generation(generation_id);
    other = rbldnsd_control_slot_alloc(999);
    assert(other == 1);
    assert(kill(child, SIGKILL) == 0);
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    rbldnsd_control_release_generation_dead(generation_id);
    assert(rbldnsd_control_slot_alloc(1000) == 0);
    rbldnsd_control_release_generation_dead(999);
    rbldnsd_control_release_generation_dead(1000);
  }
  rbldnsd_control_close();
  puts("300 allocator crashes reclaimed; quarantine: live writer, late publisher, draining and "
       "safe reuse passed");
  return 0;
}
