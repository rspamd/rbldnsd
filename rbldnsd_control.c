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
#define OWN(g,phase) (((uint64_t)(g)<<32) | (phase))
#define PHASE(ownership) ((unsigned)((ownership)&UINT32_MAX))
#define GENERATION(ownership) ((unsigned)((ownership)>>32))
#define LOAD(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define ADD(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
#define SET(p,n) __atomic_store_n((p),(n),__ATOMIC_RELEASE)
struct counts { uint64_t queries, in, replies, out, noerror, nxdomain, other,
  unanswered, send_errors, receive_drops, rate_limited; };
struct slot { struct counts c, baseline; uint64_t backlog, backlog_bytes;
  uint64_t ownership; pid_t pid; };
static struct shared { struct slot slots[SLOTS];
  unsigned generation, receive_accounting, send_accounting; int reload_result; time_t reload_time; } *shared;
static int current = -1, fd = -1;
static pid_t controller;
#ifdef RBLDNSD_CONTROL_TESTING
static void (*reservation_hook)(void);
void rbldnsd_control_test_reservation_hook(void (*hook)(void)) { reservation_hook=hook; }
#endif
static ev_io watcher;
static void (*action)(int);
static int (*extension)(const char *,char *,size_t);
static char bound_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static dev_t bound_dev;
static ino_t bound_ino;

/* Quarantine is distinct from draining: a quarantined worker may still write,
 * but it must never make its slot available to another process. PID reuse can
 * delay reclamation, which is conservative and preferable to shared writers. */
static void reclaim_quarantined(void) {
  if(!shared || getpid()!=controller) return;
  for(int i=0;i<SLOTS;++i) {
    struct slot *s=&shared->slots[i];
    uint64_t ownership=LOAD(&s->ownership);
    if(PHASE(ownership)!=5) continue;
    pid_t pid=LOAD(&s->pid);
    /* An unpublished child could still start: only all-writers-dead proof
     * can reclaim a PID-zero slot. */
    if(pid>0 && kill(pid,0)<0 && errno==ESRCH) {
      __atomic_compare_exchange_n(&s->ownership,&ownership,0,0,
        __ATOMIC_RELEASE,__ATOMIC_RELAXED);
    }
  }
}

static void collect(struct counts *to, const struct counts *from) {
#define C(n) to->n += LOAD(&from->n)
  C(queries); C(in); C(replies); C(out); C(noerror); C(nxdomain); C(other);
  C(unanswered); C(send_errors); C(receive_drops); C(rate_limited);
#undef C
}
static void append(char **p, size_t *left, const char *fmt, ...) {
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(*p, *left, fmt, ap); va_end(ap);
  if (n < 0 || (size_t)n >= *left) { *left = 0; return; }
  *p += n; *left -= n;
}
static void counters(char **p, size_t *left, const struct counts *c) {
  append(p,left,"\"queries\":%" PRIu64 ",\"received_bytes\":%" PRIu64
    ",\"responses_generated\":%" PRIu64 ",\"response_bytes_generated\":%" PRIu64
    ",\"noerror\":%" PRIu64 ",\"nxdomain\":%" PRIu64 ",\"other_rcode\":%" PRIu64
    ",\"unanswered\":%" PRIu64 ",\"send_errors\":%" PRIu64
    ",\"receive_drops\":%" PRIu64 ",\"rate_limited\":%" PRIu64,
    c->queries,c->in,c->replies,c->out,c->noerror,c->nxdomain,c->other,
    c->unanswered,c->send_errors,c->receive_drops,c->rate_limited);
}
static void receive_command(struct ev_loop *loop, ev_io *w, int events) {
  char command[4096], original[4096], response[16384], *p = response;
  struct sockaddr_un peer;
  struct iovec iov = { command, sizeof(command) };
  struct msghdr msg = {0};
  msg.msg_name = &peer; msg.msg_namelen = sizeof(peer);
  msg.msg_iov = &iov; msg.msg_iovlen = 1;
  ssize_t n = recvmsg(fd, &msg, 0);
  if (n < 0) return;
  reclaim_quarantined();
  size_t left = sizeof(response);
  int operation = 0;
  if (n >= (ssize_t)sizeof(command) || (msg.msg_flags & MSG_TRUNC)) n = 0;
  while (n > 0 && (command[n-1] == '\n' || command[n-1] == '\r')) --n;
  if (memchr(command, 0, (size_t)n)) n=0;
  command[n] = 0;
  memcpy(original,command,(size_t)n+1);
  unsigned first=0;
  char *space=strchr(command,' ');
  if(space) {
    char *end; unsigned long value=strtoul(space+1,&end,10);
    if(space[1]<'0' || space[1]>'9' || *end || value>=SLOTS) command[0]=0;
    else { *space=0; first=(unsigned)value; }
  }
  if (!strcmp(command,"status") || !strcmp(command,"stats")) {
    struct counts total = {0};
    for (int i=0;i<SLOTS;++i)
      collect(&total,&shared->slots[i].c);
    append(&p,&left,"{\"pid\":%ld,\"generation\":%u,\"reload\":\"%s\",\"reload_time\":%ld,\"totals\":{",
      (long)getpid(),shared->generation,
      shared->reload_result < 0 ? "loading" : shared->reload_result ? "success" : "failed",
      (long)shared->reload_time);
    counters(&p,&left,&total);
    append(&p,&left,"},\"receive_drop_accounting\":%s,\"send_error_accounting\":%s,\"workers\":[",
      LOAD(&shared->receive_accounting) ? "true" : "false",
      LOAD(&shared->send_accounting) ? "true" : "false");
    int comma=0, next=-1;
    for(int i=(int)first;i<SLOTS;++i) {
      struct slot *s=&shared->slots[i];
      uint64_t ownership=LOAD(&s->ownership);
      if(!ownership || PHASE(ownership)>=4) continue;
      if(comma==8) { next=i; break; }
      struct counts base={0}, c={0}; collect(&base,&s->baseline); collect(&c,&s->c);
#define C(n) c.n -= base.n
      C(queries); C(in); C(replies); C(out); C(noerror); C(nxdomain); C(other);
      C(unanswered); C(send_errors); C(receive_drops); C(rate_limited);
#undef C
      append(&p,&left,"%s{\"slot\":%d,\"pid\":%ld,\"generation\":%u,\"state\":\"%s\",",
        comma++ ? "," : "",i,(long)LOAD(&s->pid),GENERATION(ownership),
        PHASE(ownership)==3 ? "draining" : PHASE(ownership)==2 ? "running" : "starting");
      counters(&p,&left,&c);
      append(&p,&left,",\"delayed_backlog\":%" PRIu64 ",\"delayed_bytes\":%" PRIu64 "}",
        LOAD(&s->backlog),LOAD(&s->backlog_bytes));
    }
    append(&p,&left,"],\"next_slot\":%d}\n",next);
  } else if (!space && (!strcmp(command,"reload") || !strcmp(command,"shutdown"))) {
    operation = !strcmp(command,"reload") ? 1 : 2;
    append(&p,&left,"{\"accepted\":true}\n");
  } else {
    int length=extension && original[0] ? extension(original,response,sizeof(response)) : -1;
    if(length>=0 && (size_t)length<sizeof(response)) { p=response+length; left=sizeof(response)-length; }
    else append(&p,&left,"{\"error\":\"invalid or unsupported command\"}\n");
  }
  /* Never wait for a slow or abandoned client. A dropped reply is retriable;
   * mutating commands have signal-like, idempotent acceptance semantics. */
  if (left && sendto(fd,response,(size_t)(p-response),0,(void *)&peer,msg.msg_namelen)<0 && errno==EMSGSIZE) {
    static const char failure[]="{\"error\":\"response exceeds socket limit\"}\n";
    sendto(fd,failure,sizeof(failure)-1,0,(void *)&peer,msg.msg_namelen);
  }
  if (operation) action(operation);
}
int rbldnsd_control_init(struct ev_loop *loop,const char *path,void (*cb)(int)) {
  if (!path) return 0;
  if (strlen(path)>=sizeof(bound_path)) { errno=ENAMETOOLONG; return -1; }
  shared=mmap(NULL,sizeof(*shared),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANON,-1,0);
  if(shared==MAP_FAILED) { shared=NULL; return -1; }
  fd=socket(AF_UNIX,SOCK_DGRAM,0);
  if(fd<0) return -1;
  int sendbuf=262144;
  if(setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&sendbuf,sizeof(sendbuf))<0 ||
     setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&sendbuf,sizeof(sendbuf))<0) return -1;
  if(fcntl(fd,F_SETFL,O_NONBLOCK)<0 || fcntl(fd,F_SETFD,FD_CLOEXEC)<0) return -1;
  struct sockaddr_un addr={0}; addr.sun_family=AF_UNIX;
  strcpy(addr.sun_path,path);
  mode_t old=umask(077);
  int r=bind(fd,(void *)&addr,sizeof(addr));
  int saved=errno; umask(old); errno=saved;
  if(r<0) return -1; /* Never unlink a pre-existing file or listener. */
  strcpy(bound_path,path);
  if(chmod(path,0600)<0) return -1;
  struct stat st;
  if(lstat(path,&st)<0) return -1;
  bound_dev=st.st_dev; bound_ino=st.st_ino;
  shared->reload_result=1; shared->reload_time=time(NULL);
  controller=getpid();
  action=cb;
  ev_io_init(&watcher,receive_command,fd,EV_READ); ev_io_start(loop,&watcher);
  return 0;
}
int rbldnsd_control_slot_alloc(unsigned generation) {
  if(!shared) return -1;
  reclaim_quarantined();
  for(int i=0;i<SLOTS;++i) {
    uint64_t empty=0, reserved=OWN(generation,4);
    if(!__atomic_compare_exchange_n(&shared->slots[i].ownership,&empty,reserved,0,
        __ATOMIC_ACQUIRE,__ATOMIC_RELAXED)) continue;
#ifdef RBLDNSD_CONTROL_TESTING
    if(reservation_hook) reservation_hook();
#endif
    shared->slots[i].baseline=shared->slots[i].c;
    shared->slots[i].backlog=shared->slots[i].backlog_bytes=0;
    shared->slots[i].pid=0;

    if(!__atomic_compare_exchange_n(&shared->slots[i].ownership,&reserved,
         OWN(generation,1),0,__ATOMIC_RELEASE,__ATOMIC_RELAXED)) return -1;
    return i;
  }
  return -1;
}
void rbldnsd_control_child(void) {
  if(fd>=0) { ev_io_stop(ev_default_loop(0),&watcher); close(fd); fd=-1; }
}
int rbldnsd_control_worker(int slot) {
  current=-1;
  if(!shared) return 1;
  if(slot<0 || slot>=SLOTS) return 0;
  SET(&shared->slots[slot].pid,getpid());
  uint64_t starting=LOAD(&shared->slots[slot].ownership);
  if(PHASE(starting)!=1) return 0;
  if(!__atomic_compare_exchange_n(&shared->slots[slot].ownership,&starting,
       OWN(GENERATION(starting),2),0,
       __ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) return 0;
  current=slot;
  return 1;
}
void rbldnsd_control_release(int slot) {
  if(shared && slot>=0 && slot<SLOTS) {
    SET(&shared->slots[slot].ownership,0);
  }
}
void rbldnsd_control_release_generation(unsigned g) {
  if(!shared || getpid()!=controller) return;
  for(int i=0;i<SLOTS;++i) {
    uint64_t ownership=LOAD(&shared->slots[i].ownership);
    while(ownership && GENERATION(ownership)==g && PHASE(ownership)<5) {
      /* A reservation may retain the previous occupant's PID: phase 6 cannot
       * use PID-based reclamation and requires the all-writers-dead proof. */
      uint64_t quarantined=OWN(g,PHASE(ownership)==4 ? 6 : 5);
      if(__atomic_compare_exchange_n(&shared->slots[i].ownership,&ownership,
         quarantined,0,__ATOMIC_ACQ_REL,__ATOMIC_RELAXED)) break;
    }
  }
  reclaim_quarantined();
}
void rbldnsd_control_release_generation_dead(unsigned g) {
  if(!shared || getpid()!=controller) return;
  for(int i=0;i<SLOTS;++i) {
    uint64_t ownership=LOAD(&shared->slots[i].ownership);
    while(ownership && GENERATION(ownership)==g && !__atomic_compare_exchange_n(
      &shared->slots[i].ownership,&ownership,0,0,__ATOMIC_RELEASE,__ATOMIC_RELAXED)) {}
  }
}
void rbldnsd_control_generation(unsigned g) { if(shared) shared->generation=g; }
void rbldnsd_control_reload(int r) { if(shared) {shared->reload_result=r;shared->reload_time=time(NULL);} }
void rbldnsd_control_draining(void) { if(shared && current>=0) {
  uint64_t running=LOAD(&shared->slots[current].ownership);
  if(PHASE(running)!=2) return;
  __atomic_compare_exchange_n(&shared->slots[current].ownership,&running,
    OWN(GENERATION(running),3),0,
    __ATOMIC_RELEASE,__ATOMIC_RELAXED);
} }
void rbldnsd_control_query(unsigned b,int r,unsigned rc) {
  if(!shared || current<0) return;
  struct counts *c=&shared->slots[current].c;
  ADD(&c->queries,1); ADD(&c->in,b);
  if(r>0) { ADD(&c->replies,1); ADD(&c->out,r);
    if(rc==0) ADD(&c->noerror,1); else if(rc==3) ADD(&c->nxdomain,1); else ADD(&c->other,1);
  } else ADD(&c->unanswered,1);
}
void rbldnsd_control_backlog(unsigned n,uint64_t b) { if(shared && current>=0) {
  SET(&shared->slots[current].backlog,n); SET(&shared->slots[current].backlog_bytes,b); } }
void rbldnsd_control_send_error(unsigned n) { if(shared && current>=0) ADD(&shared->slots[current].c.send_errors,n); }
void rbldnsd_control_receive_drop(unsigned n) { if(shared && current>=0) ADD(&shared->slots[current].c.receive_drops,n); }
void rbldnsd_control_transport_support(int receive,int send) {
  if(shared) { if(receive) SET(&shared->receive_accounting,1); if(send) SET(&shared->send_accounting,1); }
}
void rbldnsd_control_rate_limited(void) { if(shared && current>=0) ADD(&shared->slots[current].c.rate_limited,1); }
void rbldnsd_control_extension(int (*cb)(const char *,char *,size_t)) { extension=cb; }
void rbldnsd_control_close(void) {
  if(fd>=0) { close(fd); fd=-1;
    struct stat st;
    if(*bound_path && lstat(bound_path,&st)==0 && st.st_dev==bound_dev && st.st_ino==bound_ino)
      unlink(bound_path);
  }
}
