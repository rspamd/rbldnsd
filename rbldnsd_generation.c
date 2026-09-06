/* Included by rbldnsd.c: process ownership for immutable worker generations.
 * The controller never loads dataset contents. A guardian bounds loading and
 * cleanup even when the controller dies while a loader is blocked in I/O.
 * Each generation owner keeps its image and is the only process forking its
 * query workers. No dataset pointers cross an IPC boundary.
 */
struct generation_stamp { time_t stamp; off_t size; };
struct generation_base { uint64_t dev, ino; };
struct generation_zone { time_t stamp, expires; };
struct generation_process {
  pid_t guardian, owner;
  int fd, life, state;
  unsigned long id;
  struct generation_base base;
  ev_tstamp deadline;
  unsigned char *message;
  size_t used;
};
static struct generation_process generation_active, generation_candidate,
                                 generation_retiring;
static size_t generation_message_size;
static int generation_ever_active, generation_startup_failed;

static int generation_write(int fd, const void *data, size_t length) {
  const char *p = data;
  while (length) {
    ssize_t n = write(fd, p, length);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    p += n;
    length -= n;
  }
  return 1;
}

static struct ev_loop *generation_new_loop(void) {
  struct ev_loop *loop = ev_default_loop(0);
  ev_child_stop(loop, &worker_reaper);
  ev_signal_stop(loop, &ev_hup);
  ev_signal_stop(loop, &ev_usr1);
  ev_signal_stop(loop, &ev_usr2);
  ev_signal_stop(loop, &ev_term);
  ev_signal_stop(loop, &ev_int);
  ev_default_destroy();
  loop = ev_default_loop(0);
  if (!loop) _exit(1);
  return loop;
}

static void generation_owner_control(struct ev_loop *loop, ev_io *w, int revents) {
  char command;
  ssize_t n = read(w->fd, &command, 1);
  if (!n || (n < 0 && errno != EAGAIN && errno != EINTR))
    ev_break(loop, EVBREAK_ALL);
}

static void generation_owner(int fd) {
  struct ev_loop *loop;
  ev_io control;
  ev_timer timer;
  is_generation = 1;
  generation_control = fd;
  worker_ready_fd = -1;
  workers_started = 0;
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT, SIG_DFL);
  loop = generation_new_loop();
  /* A candidate is based on the controller's empty configuration. Force all
   * inputs to load, including files unchanged since the previous generation. */
  struct dataset *ds = NULL;
  while ((ds = nextdataset(ds)) != NULL)
    for (struct dsfile *f = ds->ds_dsf; f; f = f->dsf_next) {
      f->dsf_stamp = 0;
      f->dsf_size = -1;
      f->stat_ev = NULL;
    }
  if (!do_reload(0, loop)) _exit(1);
  setup_signals(loop);
  ev_child_init(&worker_reaper, worker_exited, 0, 0);
  ev_child_start(loop, &worker_reaper);
  replace_workers(loop);
  /* Workers acknowledge initialization, but cannot accept queries until the
   * controller has received and validated the complete generation report. */
  ds = NULL;
  while ((ds = nextdataset(ds)) != NULL)
    for (struct dsfile *f = ds->ds_dsf; f; f = f->dsf_next) {
      struct generation_stamp stamp = { f->dsf_stamp, f->dsf_size };
      if (!generation_write(fd, &stamp, sizeof(stamp))) _exit(1);
    }
  for (struct zone *z = zonelist; z; z = z->z_next) {
    struct generation_zone state = { z->z_stamp, z->z_expires };
    if (!generation_write(fd, &state, sizeof(state))) _exit(1);
  }
  struct generation_base base;
  rbldnsd_overlay_base_identity(&base.dev, &base.ino);
  if (!generation_write(fd, &base, sizeof(base))) _exit(1);
  char command;
  if (read(fd, &command, 1) != 1 || command != 'A') _exit(1);
  for (int i = 0; i < nworkers; ++i)
    if (!generation_write(workers[i].control, "A", 1)) _exit(1);
  generation_activated = 1;
  if (!generation_write(fd, "A", 1)) _exit(1);
  make_socket_nonblocking(fd);
  ev_io_init(&control, generation_owner_control, fd, EV_READ);
  ev_io_start(loop, &control);
  ev_timer_init(&timer, worker_supervise, .1, .1);
  ev_timer_start(loop, &timer);
  ev_run(loop, 0);
  ev_tstamp deadline = ev_time() + 5.5;
  for (int i = 0; i < nworkers; ++i)
    if (workers[i].pid) shutdown(workers[i].control, SHUT_WR);
  for (int i = 0; i < nworkers; ++i) {
    if (!workers[i].pid) continue;
    wait_worker_shutdown(workers[i].pid, deadline);
    rbldnsd_control_release(workers[i].metrics);
  }
  _exit(0);
}

static void generation_guardian(int fd) {
  rbldnsd_control_child();
  int pair[2];
  /* Do not retain another generation's liveness channel. */
  struct generation_process *sets[] = { &generation_active, &generation_retiring };
  for (unsigned i = 0; i < 2; ++i)
    if (sets[i]->id) {
      if (sets[i]->guardian) close(sets[i]->fd);
      close(sets[i]->life);
    }
  if (worker_ready_fd >= 0) close(worker_ready_fd);
  signal(SIGCHLD, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT, SIG_DFL);
  signal(SIGHUP, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) _exit(1);
  pid_t owner = fork();
  if (!owner) {
    close(pair[0]);
    close(fd);
    setpgid(0, 0);
    char begin;
    if (read(pair[1], &begin, 1) != 1 || begin != 'L') _exit(1);
    generation_owner(pair[1]);
  }
  close(pair[1]);
  if (owner < 0) _exit(1);
  setpgid(owner, owner);
  if (!generation_write(fd, &owner, sizeof(owner))) {
    kill(-owner, SIGKILL);
    _exit(1);
  }
  if (!generation_write(pair[0], "L", 1)) { kill(-owner, SIGKILL); _exit(1); }
  for (int i = 0; i < nworkers; ++i)
    for (int j = 0; j < numsock; ++j) close(worker_sockets[i][j]);
  int stopping = 0;
  ev_tstamp deadline = 0;
  for (;;) {
    int status;
    pid_t done = waitpid(owner, &status, WNOHANG);
    if (done == owner || (done < 0 && errno == ECHILD)) {
      /* A crashed owner cannot reap its workers. Kill the entire group even
       * if workers are stopped or still waiting for activation. */
      kill(-owner, SIGKILL);
      _exit(done == owner && WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }
    if (stopping && ev_time() >= deadline) {
      kill(-owner, SIGKILL);
      while (waitpid(owner, NULL, 0) < 0 && errno == EINTR) {}
      _exit(0);
    }
    struct pollfd fds[2] = {
      { stopping ? -1 : fd, POLLIN, 0 },
      { stopping ? -1 : pair[0], POLLIN, 0 }
    };
    int r = poll(fds, 2, 50);
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) break;
    if (fds[0].revents) {
      char c;
      ssize_t n = read(fd, &c, 1);
      if (n != 1 || c == 'Q') {
        stopping = 1;
        deadline = ev_time() + 6;
        shutdown(pair[0], SHUT_WR);
        kill(owner, SIGTERM);
      }
      else if (c == 'A') {
        if (!generation_write(pair[0], &c, 1)) break;
      }
      else if (c == 'H' || c == '1' || c == '2')
        kill(owner, c == 'H' ? SIGHUP : c == '1' ? SIGUSR1 : SIGUSR2);
    }
    if (fds[1].revents && !stopping) {
      char buffer[4096];
      ssize_t n = read(pair[0], buffer, sizeof(buffer));
      if (n <= 0 || !generation_write(fd, buffer, n)) break;
    }
  }
  kill(-owner, SIGKILL);
  while (waitpid(owner, NULL, 0) < 0 && errno == EINTR) {}
  _exit(1);
}

static void generation_signal(char command) {
  if (generation_active.guardian)
    (void)write(generation_active.fd, &command, 1);
}

static int generation_start(struct ev_loop *loop) {
  if (generation_candidate.id || generation_retiring.id ||
      (generation_active.id && !generation_active.guardian)) {
    pending_reload = 1;
    return 1;
  }
  pending_reload = 0;
  if (generation_active.guardian && !nextdataset2reload(NULL) &&
      !call_hook(reload_check, (zonelist))) return 1;
  if (!generation_message_size) {
    generation_message_size = sizeof(pid_t) + sizeof(struct generation_base);
    struct dataset *ds = NULL;
    while ((ds = nextdataset(ds)) != NULL)
      for (struct dsfile *f = ds->ds_dsf; f; f = f->dsf_next)
        generation_message_size += sizeof(struct generation_stamp);
    for (struct zone *z = zonelist; z; z = z->z_next)
      generation_message_size += sizeof(struct generation_zone);
  }
  int pair[2], life[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) return 0;
  if (pipe(life) < 0) { close(pair[0]); close(pair[1]); return 0; }
  unsigned char *message = malloc(generation_message_size);
  if (!message) { close(pair[0]); close(pair[1]); close(life[0]); close(life[1]); return 0; }
  if (flog) fflush(flog);
  ++generation_id;
  pid_t pid = fork();
  if (!pid) {
    close(pair[0]); close(life[0]);
    /* Every descendant retains life[1]. EOF proves all generation writers
     * have exited, including orphaned workers after a guardian crash. */
    generation_guardian(pair[1]);
  }
  close(pair[1]); close(life[1]);
  if (pid < 0) { close(pair[0]); close(life[0]); free(message); return 0; }
  generation_candidate = (struct generation_process){
    .guardian = pid, .fd = pair[0], .life = life[0], .message = message, .id = generation_id,
    .deadline = ev_time() + generation_timeout
  };
  make_socket_nonblocking(pair[0]);
  make_socket_nonblocking(life[0]);
  can_reload = 0;
  rbldnsd_control_reload(-1);
  dslog(LOG_INFO, 0, "candidate guardian %d started", (int)pid);
  return 1;
}

static int generation_exited(pid_t pid) {
  struct generation_process *sets[] = {
    &generation_candidate, &generation_active, &generation_retiring
  };
  for (unsigned i = 0; i < 3; ++i) {
    struct generation_process *g = sets[i];
    if (g->guardian != pid) continue;
    if (!g->owner && g->message) {
      ssize_t n = read(g->fd, g->message + g->used, generation_message_size - g->used);
      if (n > 0) g->used += n;
      if (g->used >= sizeof(pid_t)) memcpy(&g->owner, g->message, sizeof(pid_t));
    }
    if (g->owner) kill(-g->owner, SIGKILL);
    close(g->fd);
    free(g->message);
    g->message = NULL;
    rbldnsd_control_release_generation((unsigned)g->id);
    g->guardian = 0;
    /* Keep the generation occupied until its inherited liveness pipe closes. */
    if (i == 0) rbldnsd_control_reload(0);
    if (i == 0) dslog(LOG_WARNING, 0, "candidate failed; retaining active generation");
    if (!generation_active.guardian && i != 2) {
      if (!generation_ever_active) {
        generation_startup_failed = 1;
        ev_break(ev_default_loop(0), EVBREAK_ALL);
      }
      else pending_reload = 1;
    }
    return 1;
  }
  return 0;
}

static void generation_collect(void) {
  struct generation_process *sets[] = {
    &generation_candidate, &generation_active, &generation_retiring
  };
  for (unsigned i = 0; i < 3; ++i) {
    struct generation_process *g = sets[i];
    if (!g->id || g->guardian) continue;
    char ignored;
    if (read(g->life, &ignored, 1) != 0) continue;
    close(g->life);
    rbldnsd_control_release_generation_dead((unsigned)g->id);
    memset(g, 0, sizeof(*g));
  }
}

static void generation_supervise(struct ev_loop *loop, ev_timer *w, int revents) {
  generation_collect();
  struct generation_process *g = &generation_candidate;
  if (g->guardian) {
    if (ev_time() >= g->deadline) {
      /* Terminal state: an activation ACK can already be buffered. Never
       * promote it after signalling termination, even before SIGCHLD runs. */
      g->state = -1;
      dslog(LOG_WARNING, 0, "candidate deadline exceeded; retaining active generation");
      (void)write(g->fd, "Q", 1);
      if (g->owner) kill(-g->owner, SIGKILL);
      kill(g->guardian, SIGKILL);
      g->deadline = ev_time() + 7;
    }
    if (g->state == 0) {
      ssize_t n = read(g->fd, g->message + g->used, generation_message_size - g->used);
      if (n > 0) g->used += n;
      if (!g->owner && g->used >= sizeof(pid_t))
        memcpy(&g->owner, g->message, sizeof(pid_t));
      if (g->used == generation_message_size) {
        if (write(g->fd, "A", 1) == 1) g->state = 1;
      }
    }
    if (g->state == 1 && (!generation_active.id || generation_active.guardian)) {
      char activated;
      if (read(g->fd, &activated, 1) == 1 && activated == 'A') {
        unsigned char *p = g->message + sizeof(pid_t);
        struct dataset *ds = NULL;
        while ((ds = nextdataset(ds)) != NULL)
          for (struct dsfile *f = ds->ds_dsf; f; f = f->dsf_next) {
            struct generation_stamp stamp;
            memcpy(&stamp, p, sizeof(stamp)); p += sizeof(stamp);
            f->dsf_stamp = stamp.stamp; f->dsf_size = stamp.size;
          }
        for (struct zone *z = zonelist; z; z = z->z_next) {
          struct generation_zone state;
          memcpy(&state, p, sizeof(state)); p += sizeof(state);
          z->z_stamp = state.stamp; z->z_expires = state.expires;
        }
        memcpy(&g->base, p, sizeof(g->base));
        free(g->message); g->message = NULL;
        generation_retiring = generation_active;
        generation_active = *g;
        generation_ever_active = 1;
        rbldnsd_control_generation((unsigned)generation_active.id);
        rbldnsd_control_reload(1);
        memset(g, 0, sizeof(*g));
        if (generation_retiring.guardian) (void)write(generation_retiring.fd, "Q", 1);
        dslog(LOG_INFO, 0, "generation owner %d active", (int)generation_active.owner);
        if (worker_ready_fd >= 0) {
          (void)write(worker_ready_fd, "", 1);
          close(worker_ready_fd); worker_ready_fd = -1;
        }
      }
    }
  }
  if (generation_active.guardian && !generation_retiring.id)
    rbldnsd_overlay_retired(generation_active.base.dev, generation_active.base.ino);
  can_reload = !generation_candidate.id && !generation_retiring.id &&
               (!generation_active.id || generation_active.guardian);
  if (can_reload && pending_reload) generation_start(loop);
}

static void generation_shutdown(void) {
  struct generation_process *sets[] = {
    &generation_active, &generation_candidate, &generation_retiring
  };
  ev_tstamp deadline = ev_time() + 7;
  for (unsigned i = 0; i < 3; ++i)
    if (sets[i]->guardian) (void)write(sets[i]->fd, "Q", 1);
  for (unsigned i = 0; i < 3; ++i) {
    struct generation_process *g = sets[i];
    if (!g->guardian) continue;
    wait_worker_shutdown(g->guardian, deadline);
    if (g->owner) kill(-g->owner, SIGKILL);
    close(g->fd);
  }
  for (int i = 1; i < nworkers; ++i)
    for (int j = 0; j < numsock; ++j) close(worker_sockets[i][j]);
}
