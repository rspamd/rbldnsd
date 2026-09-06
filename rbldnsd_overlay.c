/* Bounded exact-domain overrides. Shared mutable storage is separate from the
 * immutable base. Atomic bytes avoid C data races during entry replacement.
 * One control-loop writer publishes each mutation using a sequence counter. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "ev.h"
#include "rbldnsd.h"
#include "rbldnsd_control.h"
#include "rbldnsd_snapshot.h"
#include "rbldnsd_overlay.h"
#define MAX_CAPACITY 65536U
struct value { unsigned char name[DNS_MAXDN]; unsigned len; unsigned revision; unsigned rrlen; char rr[260]; };
struct slot { unsigned sequence; struct value value; };
struct overlay { unsigned revision, count; uint64_t export_dev, export_ino; struct slot slots[]; };
static struct overlay *shared;
static unsigned capacity, tablesize;
static struct dataset *target;
static struct ev_loop *event_loop;
static ev_child exporter;
static pid_t export_pid, controller_pid;
static unsigned export_revision;
static int export_online;
static uint64_t base_dev, base_ino;
static void (*control_action)(int);
static int export_result; /* 0 never, 1 running, 2 success, -1 failed */

static unsigned hash(const unsigned char *p,unsigned len) {
  unsigned h=2166136261U; while(len--) h=(h^*p++)*16777619U; return h;
}
static int read_slot(const struct slot *s,struct value *v) {
  for (unsigned attempt=0;attempt<64;attempt++) {
    unsigned seq=__atomic_load_n(&s->sequence,__ATOMIC_ACQUIRE);
    if(seq&1) continue;
    unsigned char *out=(unsigned char *)v;
    const unsigned char *in=(const unsigned char *)&s->value;
    for(size_t i=0;i<sizeof(*v);i++) out[i]=__atomic_load_n(in+i,__ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if(seq==__atomic_load_n(&s->sequence,__ATOMIC_ACQUIRE)) return 1;
  }
  return 0; /* A stopped/dead writer must not stall the UDP event loop. */
}
/* Deleted hash slots preserve probe chains. At most capacity live entries,
 * even after arbitrarily many compaction cycles. */
#define DELETED UINT32_MAX
static unsigned find(const unsigned char *name,unsigned len,struct value *v) {
  unsigned i=hash(name,len)&(tablesize-1), first=DELETED;
  for(unsigned n=0;n<tablesize;n++,i=(i+1)&(tablesize-1)) {
    if(!read_slot(&shared->slots[i],v)) return DELETED;
    if(v->len==DELETED) { if(first==DELETED) first=i; continue; }
    if(!v->len) { if(first!=DELETED) i=first; v->len=0; return i; }
    if(v->len==len && !memcmp(v->name,name,len)) return i;
  }
  v->len=0; return first; /* capacity <= tablesize/2 */
}
static void publish(struct slot *slot,const struct value *v) {
  __atomic_fetch_add(&slot->sequence,1,__ATOMIC_SEQ_CST);
  const unsigned char *in=(const unsigned char *)v; unsigned char *dest=(unsigned char *)&slot->value;
  for(size_t j=0;j<sizeof(*v);j++) __atomic_store_n(dest+j,in[j],__ATOMIC_RELAXED);
  __atomic_fetch_add(&slot->sequence,1,__ATOMIC_RELEASE);
}
void rbldnsd_overlay_loaded(const struct dataset *ds,int fd) {
  struct stat st;
  /* Startup's initial load can precede overlay initialization. */
  if(ds==nextdataset(NULL) && !fstat(fd,&st)) { base_dev=st.st_dev; base_ino=st.st_ino; }
}
void rbldnsd_overlay_base_identity(uint64_t *dev,uint64_t *ino) { *dev=base_dev; *ino=base_ino; }
void rbldnsd_overlay_retired(uint64_t dev,uint64_t ino) {
  if(!shared || !export_online || export_result!=2 || dev!=shared->export_dev || ino!=shared->export_ino) return;
  for(unsigned i=0;i<tablesize;i++) {
    struct value v; if(!read_slot(&shared->slots[i],&v)) continue;
    if(v.len && v.len!=DELETED && v.revision<=export_revision) {
      memset(&v,0,sizeof(v)); v.len=DELETED; publish(&shared->slots[i],&v); shared->count--;
    }
  }
  export_online=0;
}
int rbldnsd_overlay_query(const struct dataset *ds,const struct dnsqinfo *qi,struct dnspacket *pkt) {
  struct value v;
  if(!shared || ds!=target || !qi->qi_dnlab) return -1;
  if(find(qi->qi_dn,qi->qi_dnlen0,&v)==DELETED) return NSQUERY_SERVFAIL;
  if(!v.len) return -1;
  if(!v.rrlen) return 0; /* exact exclusion masks every wildcard */
  check_query_overwrites(qi);
  char name[DNS_MAXDOMAIN+1]; dns_dntop(v.name,name,sizeof(name));
  addrr_a_txt(pkt,qi->qi_tflag,v.rr,name,ds);
  return NSQUERY_FOUND;
}
struct merge { struct value *values; snapshot_visit_fn *visit; void *arg; };
static int base_visit(const struct snapshot_entry *e,void *arg) {
  struct merge *m=arg;
  if(!e->table) {
    unsigned i=hash(e->name,e->namelen)&(tablesize-1);
    for(unsigned n=0;n<tablesize && m->values[i].len;n++,i=(i+1)&(tablesize-1)) {
      struct value *v=&m->values[i];
      if(v->len==e->namelen && !memcmp(v->name,e->name,e->namelen)) return 1;
    }
  }
  return m->visit(e,m->arg);
}
static int produce(snapshot_visit_fn *visit,void *arg,void *producer_arg) {
  struct merge m={producer_arg,visit,arg};
  int ok=isdstype(target->ds_type,dnhash)?rbldnsd_dnhash_foreach(target,base_visit,&m):rbldnsd_snapshot_foreach(target,base_visit,&m);
  if(!ok) return 0;
  for(unsigned i=0;i<tablesize;i++) if(m.values[i].len && m.values[i].len!=DELETED) {
    struct value *v=&m.values[i];
    struct snapshot_entry e={0}; e.name=v->name; e.namelen=v->len; e.rr=v->rrlen?v->rr:NULL;
    if(!visit(&e,arg)) return 0;
  }
  return 1;
}
static void exported(struct ev_loop *loop,ev_child *w,int UNUSED revents) {
  export_result=WIFEXITED(w->rstatus) && WEXITSTATUS(w->rstatus)==0 ? 2:-1;
  export_pid=0; ev_child_stop(loop,w);
  if(export_result==2 && export_online) control_action(1);
  if(export_result<0) export_online=0;
}
static int export_snapshot(const char *path,int online) {
  struct stat out,src;
  if(!online) for(struct dsfile *f=target->ds_dsf;f;f=f->dsf_next)
    if(!strcmp(path,f->dsf_name) || (!stat(path,&out) && !stat(f->dsf_name,&src) && out.st_ino==src.st_ino && out.st_dev==src.st_dev)) return 0;
  struct value *copy=calloc(tablesize,sizeof(*copy)); if(!copy) return 0;
  for(unsigned i=0;i<tablesize;i++) if(!read_slot(&shared->slots[i],&copy[i])) { free(copy); return 0; }
  pid_t pid=fork();
  if(pid<0) { free(copy); return 0; }
  if(!pid) {
    signal(SIGTERM,SIG_DFL); signal(SIGINT,SIG_DFL); signal(SIGHUP,SIG_DFL); signal(SIGALRM,SIG_DFL); alarm(60);
    long max=sysconf(_SC_OPEN_MAX); if(max<0) max=65536;
    for(int fd=3;fd<max;fd++) close(fd);
    for(struct dsfile *f=target->ds_dsf;f;f=f->dsf_next) {
      f->stat_ev=NULL; f->dsf_stamp=0; f->dsf_size=-1;
    }
    rbldnsd_snapshot_compiling=1;
    int ok=loaddataset(target,event_loop) && rbldnsd_snapshot_write_iter_ident(target,path,produce,copy,&shared->export_dev,&shared->export_ino);
    _exit(ok?0:1);
  }
  free(copy); export_online=online; export_pid=pid; export_revision=shared->revision; export_result=1;
  ev_child_init(&exporter,exported,pid,0); ev_child_start(event_loop,&exporter);
  return 1;
}
static int command(const char *command,char *out,size_t size) {
  if(strncmp(command,"overlay",7)) return -1;
  if(!strcmp(command,"overlay-status")) return snprintf(out,size,"{\"revision\":%u,\"entries\":%u,\"capacity\":%u,\"ephemeral\":true,\"compaction_pending\":%s,\"export_revision\":%u,\"export_state\":\"%s\"}",shared->revision,shared->count,capacity,export_online?"true":"false",export_revision,export_result==1?"running":export_result==2?"success":export_result==-1?"failed":"none");
  char buf[4096]; if(strlen(command)>=sizeof(buf)) goto invalid;
  strcpy(buf,command); char *save=NULL,*op=strtok_r(buf," ",&save),*rev=strtok_r(NULL," ",&save),*name=strtok_r(NULL," ",&save);
  if(!save) save="";
  if(!rev || !*rev) goto invalid;
  for(char *p=rev;*p;p++) if(*p<'0'||*p>'9') goto invalid;
  errno=0; char *end; unsigned long expected=strtoul(rev,&end,10);
  if(errno || *end || expected>UINT32_MAX) goto invalid;
  if(expected!=shared->revision) return snprintf(out,size,"{\"error\":\"revision conflict\",\"revision\":%u}",shared->revision);
  if(!strcmp(op,"overlay-compact")) {
    if(*save || export_pid || export_online) goto invalid;
    int online=!name;
    if(online && !isdstype(target->ds_type,dnsnapshot)) goto invalid;
    if(!export_snapshot(online?target->ds_dsf->dsf_name:name,online)) return snprintf(out,size,"{\"error\":\"cannot start export (use a separate output path)\"}");
    return snprintf(out,size,"{\"accepted\":true,\"revision\":%u}",shared->revision);
  }
  if(!name) goto invalid;
  int del=!strcmp(op,"overlay-del");
  if(!del && strcmp(op,"overlay-put")) goto invalid;
  struct value v={0},old;
  if(strchr(name,'*') || name[0]=='.' || strlen(name)>253) goto invalid;
  unsigned n; char *rest=parse_dn(name,v.name,&n);
  if(!rest || *rest || n<=1) goto invalid;
  dns_dntol(v.name,v.name); v.len=n-1;
  if(del) { if(*save) goto invalid; }
  else {
    while(*save==' ') save++;
    /* Deliberately use strict IPv4 + literal TXT, without implicit defaults or
     * entry parameters. This avoids silently losing customer ACL policies. */
    char *ip=save,*txt=strchr(ip,' '); if(!txt) goto invalid; *txt++=0;
    if(strlen(txt)>255 || strchr(txt,'\n') || strchr(txt,'\r')) goto invalid;
    for(char *p=ip;*p;p++) if((*p<'0'||*p>'9') && *p!='.') goto invalid;
    unsigned a,b,c,d; char extra;
    if(sscanf(ip,"%u.%u.%u.%u%c",&a,&b,&c,&d,&extra)!=4 || a>255||b>255||c>255||d>255) goto invalid;
    v.rr[0]=a; v.rr[1]=b; v.rr[2]=c; v.rr[3]=d; strcpy(v.rr+4,txt); v.rrlen=5+strlen(txt);
  }
  unsigned i=find(v.name,v.len,&old);
  if(i==DELETED) goto invalid;
  if(!old.len && shared->count==capacity) return snprintf(out,size,"{\"error\":\"overlay full; compact the snapshot\",\"revision\":%u}",shared->revision);
  if(shared->revision==UINT32_MAX) goto invalid;
  v.revision=shared->revision+1;
  publish(&shared->slots[i],&v);
  if(!old.len) shared->count++;
  shared->revision++;
  return snprintf(out,size,"{\"ok\":true,\"revision\":%u}",shared->revision);
invalid: return snprintf(out,size,"{\"error\":\"invalid overlay command\"}");
}
int rbldnsd_overlay_init(struct ev_loop *loop,unsigned limit,void (*action)(int)) {
  if(!limit) return 0;
  target=nextdataset(NULL);
  if(limit>MAX_CAPACITY || !target || nextdataset(target) || (!isdstype(target->ds_type,dnhash)&&!isdstype(target->ds_type,dnsnapshot))) { errno=EINVAL; return -1; }
  capacity=limit; tablesize=2; while(tablesize<2*capacity) tablesize*=2;
  size_t size=sizeof(*shared)+tablesize*sizeof(struct slot);
  shared=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANON,-1,0);
  if(shared==MAP_FAILED) { shared=NULL; return -1; }
  event_loop=loop; control_action=action; controller_pid=getpid(); rbldnsd_control_extension(command); return 0;
}
void rbldnsd_overlay_child(void) {
  if(getpid()==controller_pid) return;
  /* libev's child watchers participate in a process-global SIGCHLD list;
   * detach this inherited watcher while its original loop is still valid. */
  if(event_loop && ev_is_active(&exporter)) ev_child_stop(event_loop,&exporter);
  export_pid=0;
  event_loop=NULL;
}
void rbldnsd_overlay_close(void) {
  if(getpid()!=controller_pid) return;
  if(export_pid) { kill(export_pid,SIGKILL); while(waitpid(export_pid,NULL,0)<0 && errno==EINTR) {} export_pid=0; }
}
