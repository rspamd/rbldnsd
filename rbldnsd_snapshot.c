/* Portable, offset-based dnhash snapshots. All integers are big-endian u32.
 * No pointer or native structure is ever persisted. See README.snapshot.md. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <syslog.h>
#include "rbldnsd.h"
#include "rbldnsd_snapshot.h"
#include "rbldnsd_overlay.h"
#define HDR 128U
#define REC 24U
#define LIMIT (1024U * 1024U * 1024U)
static unsigned get(const void *v) { const unsigned char *p=v; return unpack32(p); }
static void put(void *v, unsigned n) { unsigned char *p=v; PACK32(p,n); }
static uint32_t checksum(const unsigned char *p, size_t n) {
  uint32_t h=2166136261U;
  for (size_t i=0;i<n;i++) h=(h ^ (i>=24 && i<28 ? 0 : p[i]))*16777619U;
  return h;
}
struct dsdata { unsigned char *map; size_t size; unsigned count; };
definedstype(dnsnapshot, 0, "read-only compiled domain snapshot");
static void ds_dnsnapshot_reset(struct dsdata *d, int UNUSED all) {
  if (d->map) munmap(d->map,d->size);
  memset(d,0,sizeof(*d));
}
static void ds_dnsnapshot_start(struct dataset *UNUSED ds) {}
static int ds_dnsnapshot_line(struct dataset *UNUSED ds, char *UNUSED line, struct dsctx *UNUSED ctx) { return 0; }
static void ds_dnsnapshot_finish(struct dataset *ds, struct dsctx *ctx) { dsloaded(ctx,"entries=%u, mapped=%lu",ds->ds_dsd->count,(unsigned long)ds->ds_dsd->size); }
static int cmpkey(unsigned t, const unsigned char *n, unsigned len,
                  unsigned rt,const unsigned char *rn,unsigned rlen) {
  if (t!=rt) return t<rt ? -1:1;
  unsigned m=len<rlen?len:rlen;
  int c=memcmp(n,rn,m);
  return c ? c : len==rlen ? 0 : len<rlen ? -1:1;
}
static void decode(const struct dsdata *d, unsigned i, struct snapshot_entry *e) {
  const unsigned char *r=d->map+HDR+i*REC;
  e->table=get(r); e->name=d->map+get(r+4); e->namelen=get(r+8);
  e->rr=get(r+12)?(const char *)d->map+get(r+12):NULL;
  e->nparams=get(r+20);
  const unsigned char *p=d->map+get(r+16);
  for(unsigned j=0;j<e->nparams;j++) {
    e->params[j].k=(const char *)d->map+get(p+j*8);
    e->params[j].v=(const char *)d->map+get(p+j*8+4);
  }
}
int rbldnsd_snapshot_lookup(const struct dataset *ds, const unsigned char *n,
                            unsigned len,unsigned table,struct snapshot_entry *e) {
  const struct dsdata *d=ds->ds_dsd;
  unsigned lo=0,hi=d->count;
  while(lo<hi) {
    unsigned mid=lo+(hi-lo)/2;
    const unsigned char *r=d->map+HDR+mid*REC;
    int c=cmpkey(table,n,len,get(r),d->map+get(r+4),get(r+8));
    if (!c) { decode(d,mid,e); return 1; }
    if (c<0) hi=mid; else lo=mid+1;
  }
  return 0;
}
int rbldnsd_snapshot_foreach(const struct dataset *ds,snapshot_visit_fn *visit,void *arg) {
  for(unsigned i=0;i<ds->ds_dsd->count;i++) {
    struct snapshot_entry e; decode(ds->ds_dsd,i,&e);
    if(!visit(&e,arg)) return 0;
  }
  return 1;
}
static int string_ok(const unsigned char *p,size_t size,unsigned off,unsigned min,unsigned max) {
  if(off<min || off>=size) return 0;
  size_t n=size-off; if(n>max+1U) n=max+1U;
  return memchr(p+off,0,n)!=NULL;
}
static unsigned dnvalid(const unsigned char *p,size_t size,unsigned off,unsigned start) {
  if(off<start || off>=size) return 0;
  unsigned pos=0;
  while(pos<DNS_MAXDN && pos<size-off) {
    unsigned l=p[off+pos++];
    if(!l) return pos;
    if(l>63 || l>size-off-pos || pos+l>=DNS_MAXDN) return 0;
    pos+=l;
  }
  return 0;
}
int rbldnsd_snapshot_load(struct dataset *ds,int fd,struct dsctx *ctx) {
  struct stat st;
  if(fstat(fd,&st)<0 || st.st_size<HDR || st.st_size>LIMIT) goto bad;
  size_t size=(size_t)st.st_size;
  unsigned char *p=mmap(NULL,size,PROT_READ,MAP_PRIVATE,fd,0);
  if(p==MAP_FAILED) goto bad;
  unsigned count=get(p+16), start;
  if(memcmp(p,"RBLDNSNP",8) || get(p+8)!=1 || get(p+12)!=size ||
     count>(size-HDR)/REC || get(p+24)!=checksum(p,size) || get(p+28) || get(p+76) || get(p+112) || get(p+116) || get(p+120) || get(p+124)) goto unmap;
  start=HDR+count*REC;
  for(unsigned i=0;i<11;i++) if(get(p+32+i*4) && !string_ok(p,size,get(p+32+i*4),start,65535)) goto unmap;
  for(unsigned i=0;i<count;i++) {
    const unsigned char *r=p+HDR+i*REC;
    unsigned table=get(r), off=get(r+4), len=get(r+8), rr=get(r+12), po=get(r+16), np=get(r+20);
    if(table>5 || len==0 || len>=DNS_MAXDN || off<start || off>=size || len>=size-off || p[off+len]) goto unmap;
    unsigned pos=0,labels=0;
    while(pos<len) { unsigned l=p[off+pos]; if(!l || l>63 || l+1>len-pos) goto unmap; pos+=l+1; labels++; }
    if(pos!=len || (table && labels!=table)) goto unmap;
    if(rr && (rr<start || rr>=size || size-rr<5 || !string_ok(p,size,rr+4,start,255))) goto unmap;
    if(np>SNAPSHOT_MAX_PARAMS || (np && (po<start || po>=size || np>(size-po)/8))) goto unmap;
    if(!np && po) goto unmap;
    for(unsigned j=0;j<np;j++) if(!string_ok(p,size,get(p+po+j*8),start,65535) || !string_ok(p,size,get(p+po+j*8+4),start,65535)) goto unmap;
    if(i) { const unsigned char *prev=r-REC;
      if(cmpkey(get(prev),p+get(prev+4),get(prev+8),table,p+off,len)>=0) goto unmap;
    }
  }
  unsigned so=get(p+80), no=get(p+84), nc=get(p+88);
  if(so && (so<start || so>=size || size-so<32 ||
      !dnvalid(p,size,get(p+so+4),start) || !dnvalid(p,size,get(p+so+8),start))) goto unmap;
  if(nc>1024 || (nc && (no<start || no>=size || nc>(size-no)/4)) || (!nc && no)) goto unmap;
  for(unsigned i=0;i<nc;i++) if(!dnvalid(p,size,get(p+no+i*4),start)) goto unmap;
  uint64_t stamp=((uint64_t)get(p+104)<<32)|get(p+108);
  if((uint64_t)(time_t)stamp!=stamp || (time_t)stamp<=0) goto unmap;
  ds->ds_stamp=(time_t)stamp;
  uint64_t expiry=((uint64_t)get(p+96)<<32)|get(p+100);
  if((uint64_t)(time_t)expiry!=expiry || (time_t)expiry<0) goto unmap;
  if(so) {
    struct dssoa *out=mp_alloc(ds->ds_mp,sizeof(*out),1); if(!out) goto unmap;
    out->dssoa_ttl=get(p+so); out->dssoa_odn=p+get(p+so+4); out->dssoa_pdn=p+get(p+so+8);
    out->dssoa_serial=get(p+so+12); memcpy(out->dssoa_n,p+so+16,16); ds->ds_dssoa=out;
  }
  struct dsns **tail=&ds->ds_dsns;
  for(unsigned i=0;i<nc;i++) {
    unsigned off=get(p+no+i*4), n=dnvalid(p,size,off,start);
    struct dsns *ns=mp_alloc(ds->ds_mp,sizeof(*ns)+n,1); if(!ns) goto unmap;
    ns->dsns_next=NULL; memcpy(ns->dsns_dn,p+off,n); *tail=ns; tail=&ns->dsns_next;
  }
  ds->ds_nsttl=get(p+92); ds->ds_expires=(time_t)expiry;
  rbldnsd_overlay_loaded(ds, fd);
  ds->ds_dsd->map=p; ds->ds_dsd->size=size; ds->ds_dsd->count=count;
  ds->ds_ttl=get(p+20);
  for(unsigned i=0;i<11;i++) ds->ds_subst[i]=get(p+32+i*4)?(char *)p+get(p+32+i*4):NULL;
  return 1;
unmap: munmap(p,size);
bad: dslog(LOG_ERR,ctx,"invalid or unsupported dnsnapshot file"); return 0;
}
static int answer(const struct dataset *ds,const struct dnsqinfo *qi,struct dnspacket *pkt,const struct snapshot_entry *e) {
  if(!e->rr) return 0;
  union { struct kv_params align; unsigned char bytes[sizeof(struct kv_params)+SNAPSHOT_MAX_PARAMS*sizeof(struct kv_pair)]; } storage;
  struct kv_params *params=(struct kv_params *)storage.bytes;
  params->n=e->nparams; params->storage=NULL;
  memcpy(params->kv,e->params,e->nparams*sizeof(struct kv_pair));
  struct entry_action act={1,0,0};
  rbldnsd_apply_entry_params(pkt->p_peer,ds,qi,params,&act);
  if(!act.allow) return 0;
  if(act.delay_ms>pkt->p_delay_ms) pkt->p_delay_ms=act.delay_ms;
  char name[DNS_MAXDOMAIN+1]; dns_dntop(e->name,name,sizeof(name));
  addrr_a_txt(pkt,qi->qi_tflag,e->rr,name,ds); return NSQUERY_FOUND;
}
static int ds_dnsnapshot_query(const struct dataset *ds,const struct dnsqinfo *qi,struct dnspacket *pkt) {
  const unsigned char *dn=qi->qi_dn; unsigned len=qi->qi_dnlen0,lab=qi->qi_dnlab;
  struct snapshot_entry e;
  int overlay = rbldnsd_overlay_query(ds, qi, pkt);
  if (overlay >= 0) return overlay;
  if(!lab) return 0;
  check_query_overwrites(qi);
  if(rbldnsd_snapshot_lookup(ds,dn,len,0,&e)) return answer(ds,qi,pkt,&e);
  while(--lab) {
    len-=*dn+1; dn+=*dn+1;
    if(lab<=5 && rbldnsd_snapshot_lookup(ds,dn,len,lab,&e) && e.rr) return answer(ds,qi,pkt,&e);
  }
  return 0;
}
#ifndef NO_MASTER_DUMP
static void ds_dnsnapshot_dump(const struct dataset *ds,const unsigned char *UNUSED odn,FILE *f) {
  for(unsigned i=0;i<ds->ds_dsd->count;i++) {
    struct snapshot_entry e; char name[DNS_MAXDOMAIN+4]; decode(ds->ds_dsd,i,&e);
    if(e.table) { name[0]='*'; name[1]='.'; }
    dns_dntop(e.name,name+(e.table?2:0),sizeof(name)-(e.table?2:0));
    dump_a_txt(name,e.rr,e.table?name+2:name,ds,f);
  }
}
#endif
struct saved_entry { const unsigned char *name; unsigned namelen, table; const char *rr; unsigned nparams; struct kv_pair *params; };
struct writer { struct saved_entry *entries; size_t n,cap; unsigned char *buf; size_t len,bufcap; };
static int collect(const struct snapshot_entry *e,void *arg) {
  struct writer *w=arg;
  if(!e->name || !e->namelen || e->namelen>=DNS_MAXDN || e->table>5 ||
     e->nparams>SNAPSHOT_MAX_PARAMS || e->name[e->namelen] ||
     (e->rr && strlen(e->rr+4)>255)) return 0;
  unsigned pos=0,labels=0;
  while(pos<e->namelen) {
    unsigned len=e->name[pos]; if(!len || len>63 || len+1>e->namelen-pos) return 0;
    pos+=len+1; labels++;
  }
  if(e->table && labels!=e->table) return 0;
  for(unsigned i=0;i<e->nparams;i++) if(!e->params[i].k || !e->params[i].v ||
    strlen(e->params[i].k)>65535 || strlen(e->params[i].v)>65535) return 0;
  if(w->n==w->cap) {
    size_t cap=w->cap?w->cap*2:256;
    if(cap>LIMIT/REC) return 0;
    void *p=realloc(w->entries,cap*sizeof(*w->entries)); if(!p) return 0;
    w->entries=p; w->cap=cap;
  }
  struct saved_entry *out=&w->entries[w->n];
  out->name=e->name; out->namelen=e->namelen; out->table=e->table;
  out->rr=e->rr; out->nparams=e->nparams; out->params=NULL;
  if(e->nparams) {
    out->params=malloc(e->nparams*sizeof(*out->params)); if(!out->params) return 0;
    memcpy(out->params,e->params,e->nparams*sizeof(*out->params));
  }
  w->n++; return 1;
}
static int entrycmp(const void *a,const void *b) {
  const struct saved_entry *x=a,*y=b;
  return cmpkey(x->table,x->name,x->namelen,y->table,y->name,y->namelen);
}
static unsigned append(struct writer *w,const void *data,size_t len) {
  if(len>LIMIT-w->len) return 0;
  unsigned off=(unsigned)w->len;
  if(w->len+len>w->bufcap) {
    size_t cap=w->bufcap ? w->bufcap*2 : 4096;
    if(cap<w->len+len) cap=w->len+len;
    if(cap>LIMIT) cap=LIMIT;
    void *p=realloc(w->buf,cap); if(!p) return 0;
    w->buf=p; w->bufcap=cap;
  } memcpy(w->buf+w->len,data,len); w->len+=len; return off;
}
int rbldnsd_snapshot_write_iter_ident(const struct dataset *ds,const char *path, snapshot_produce_fn *produce,void *arg,uint64_t *dev,uint64_t *ino) {
  struct writer w={0}; int ok=0,fd=-1; char *tmp=NULL;

  if(!produce(collect,&w,arg) || w.n>(LIMIT-HDR)/REC) goto done;
  if(ds->ds_stamp<=0 || ds->ds_expires<0) goto done;
  qsort(w.entries,w.n,sizeof(*w.entries),entrycmp);
  for(size_t i=1;i<w.n;i++) if(entrycmp(&w.entries[i-1],&w.entries[i])>=0) goto done;
  w.len=HDR+w.n*REC; w.bufcap=w.len; w.buf=calloc(1,w.len); if(!w.buf) goto done;
  memcpy(w.buf,"RBLDNSNP",8); put(w.buf+8,1); put(w.buf+16,w.n); put(w.buf+20,ds->ds_ttl);
  for(unsigned i=0;i<11;i++) if(ds->ds_subst[i]) {
    if(strlen(ds->ds_subst[i])>65535) goto done;
    unsigned off=append(&w,ds->ds_subst[i],strlen(ds->ds_subst[i])+1); if(!off) goto done;
    put(w.buf+32+i*4,off);
  }
  if(ds->ds_dssoa) {
    const struct dssoa *so=ds->ds_dssoa;
    unsigned no=append(&w,so->dssoa_odn,dns_dnlen(so->dssoa_odn));
    unsigned po=append(&w,so->dssoa_pdn,dns_dnlen(so->dssoa_pdn));
    unsigned char rec[32];
    if(!no || !po) goto done;
    put(rec,so->dssoa_ttl); put(rec+4,no); put(rec+8,po); put(rec+12,so->dssoa_serial);
    memcpy(rec+16,so->dssoa_n,16);
    unsigned off=append(&w,rec,32); if(!off) goto done; put(w.buf+80,off);
  }
  unsigned nc=0;
  for(const struct dsns *ns=ds->ds_dsns;ns;ns=ns->dsns_next) if(++nc>1024) goto done;
  if(nc) {
    unsigned char *offsets=malloc((size_t)nc*4); if(!offsets) goto done;
    unsigned j=0;
    for(const struct dsns *ns=ds->ds_dsns;ns;ns=ns->dsns_next) {
      unsigned off=append(&w,ns->dsns_dn,dns_dnlen(ns->dsns_dn));
      if(!off) { free(offsets); goto done; } put(offsets+j++*4,off);
    }
    unsigned off=append(&w,offsets,(size_t)nc*4); free(offsets);
    if(!off) goto done;
    put(w.buf+84,off); put(w.buf+88,nc);
  }
  put(w.buf+104,(uint64_t)ds->ds_stamp>>32); put(w.buf+108,(uint64_t)ds->ds_stamp);
  put(w.buf+92,ds->ds_nsttl);
  put(w.buf+96,(uint64_t)ds->ds_expires>>32); put(w.buf+100,(uint64_t)ds->ds_expires);
  for(unsigned i=0;i<w.n;i++) {
    struct saved_entry *e=&w.entries[i]; unsigned no,rr=0,po=0;
    no=append(&w,e->name,e->namelen+1); if(!no) goto done;
    if(e->rr && !(rr=append(&w,e->rr,strlen(e->rr+4)+5))) goto done;
    if(e->nparams) {
      unsigned char pairs[SNAPSHOT_MAX_PARAMS*8];
      for(unsigned j=0;j<e->nparams;j++) {
        if(!e->params[j].k || !e->params[j].v) goto done;
        unsigned ko=append(&w,e->params[j].k,strlen(e->params[j].k)+1);
        unsigned vo=append(&w,e->params[j].v,strlen(e->params[j].v)+1);
        if(!ko || !vo) goto done;
        put(pairs+j*8,ko); put(pairs+j*8+4,vo);
      }
      po=append(&w,pairs,e->nparams*8); if(!po) goto done;
    }
    unsigned char *r=w.buf+HDR+i*REC;
    put(r,e->table); put(r+4,no); put(r+8,e->namelen); put(r+12,rr); put(r+16,po); put(r+20,e->nparams);
  }
  put(w.buf+12,w.len); put(w.buf+24,checksum(w.buf,w.len));
  tmp=malloc(strlen(path)+16); if(!tmp) goto done;
  sprintf(tmp,"%s.XXXXXX",path); fd=mkstemp(tmp); if(fd<0) goto done;
  size_t pos=0;
  while(pos<w.len) { ssize_t n=write(fd,w.buf+pos,w.len-pos); if(n<0 && errno==EINTR) continue; if(n<=0) goto done; pos+=n; }
  if(fchmod(fd,0644)<0 || fsync(fd)<0) goto done;
  struct stat identity;
  if(fstat(fd,&identity)<0) goto done;
  if(dev) *dev=(uint64_t)identity.st_dev;
  if(ino) *ino=(uint64_t)identity.st_ino;
  if(close(fd)<0) { fd=-1; goto done; } fd=-1;
  if(rename(tmp,path)<0) goto done;
  ok=1;
done:
  if(fd>=0) close(fd);
  if(tmp) { if(!ok) unlink(tmp); free(tmp); }
  for(size_t i=0;i<w.n;i++) free(w.entries[i].params);
  free(w.entries); free(w.buf); return ok;
}

int rbldnsd_snapshot_write_iter(const struct dataset *ds,const char *path, snapshot_produce_fn *produce,void *arg) {
  return rbldnsd_snapshot_write_iter_ident(ds,path,produce,arg,NULL,NULL);
}

static int dnhash_produce(snapshot_visit_fn *visit,void *visit_arg,void *arg) {
  return rbldnsd_dnhash_foreach(arg,visit,visit_arg);
}
int rbldnsd_snapshot_write(const struct dataset *ds,const char *path) {
  return rbldnsd_snapshot_write_iter(ds,path,dnhash_produce,(void *)ds);
}
