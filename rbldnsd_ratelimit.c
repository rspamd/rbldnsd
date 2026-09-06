/* Customer quotas. Fixed-size conservative hash buckets never evict or reset
 * another customer's debt. Only atomic timestamps mutate the shared map. */
#include "rbldnsd_ratelimit.h"
#include <stdatomic.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#define MAX_RULES 32
#define DEFAULT_BUCKETS 16384
#define MAX_BUCKETS 65536
#define SECOND UINT64_C(1000000000)
struct rule {
  enum { KEY, ZONE, SOURCE4, SOURCE6 } kind;
  char selector[256];
  unsigned prefix;
  uint64_t interval, tolerance;
};
static struct rule rules[MAX_RULES];
static unsigned nrules, buckets = DEFAULT_BUCKETS;
static _Atomic uint64_t *accounting;
static size_t map_size;
static uint64_t secret[2];

/* SipHash-2-4. Random per-server secret keeps bucket targeting unpredictable. */
static uint64_t rot(uint64_t v, unsigned n) { return (v << n) | (v >> (64-n)); }
#define ROUND do { \
 v0+=v1; v1=rot(v1,13); v1^=v0; v0=rot(v0,32); \
 v2+=v3; v3=rot(v3,16); v3^=v2; \
 v0+=v3; v3=rot(v3,21); v3^=v0; \
 v2+=v1; v1=rot(v1,17); v1^=v2; v2=rot(v2,32); \
} while (0)
static uint64_t read64(const unsigned char *p) {
  uint64_t v = 0;
  for (unsigned i=0; i<8; ++i) v |= (uint64_t)p[i] << (8*i);
  return v;
}
static uint64_t bucket_hash(const unsigned char *p, size_t n) {
  uint64_t v0=secret[0]^UINT64_C(0x736f6d6570736575);
  uint64_t v1=secret[1]^UINT64_C(0x646f72616e646f6d);
  uint64_t v2=secret[0]^UINT64_C(0x6c7967656e657261);
  uint64_t v3=secret[1]^UINT64_C(0x7465646279746573);
  uint64_t tail=(uint64_t)n<<56;
  while (n>=8) { uint64_t m=read64(p); v3^=m; ROUND; ROUND; v0^=m; p+=8; n-=8; }
  for (unsigned i=0; i<n; ++i) tail |= (uint64_t)p[i]<<(8*i);
  v3^=tail; ROUND; ROUND; v0^=tail; v2^=255;
  ROUND; ROUND; ROUND; ROUND;
  return v0^v1^v2^v3;
}
#undef ROUND

static int number(const char *s, unsigned long *n) {
  char *end;
  if (!*s || !isdigit((unsigned char)*s)) return 0;
  errno=0; *n=strtoul(s,&end,10);
  return !errno && !*end;
}
void rbldnsd_ratelimit_close(void) {
  if (accounting) munmap(accounting,map_size);
  accounting=NULL; nrules=0; buckets=DEFAULT_BUCKETS;
}
int rbldnsd_ratelimit_init(const char *path, char *error, size_t size) {
  FILE *f;
  char line[1024], kind[32], selector[256], rate[32], burst[32], junk[2];
  unsigned lineno=0;
  rbldnsd_ratelimit_close();
  if (!path) return 0;
  f=fopen(path,"r");
  if (!f) { snprintf(error,size,"cannot open quota policy: %s",strerror(errno)); return -1; }
  while (fgets(line,sizeof(line),f)) {
    unsigned long r,b,p;
    ++lineno;
    if (!strchr(line,'\n') && !feof(f)) goto invalid;
    char *comment=strchr(line,'#'); if (comment) *comment=0;
    int fields=sscanf(line,"%31s %255s %31s %31s %1s",kind,selector,rate,burst,junk);
    if (fields<=0) continue;
    if (!strcmp(kind,"buckets")) {
      if (fields!=2 || nrules || !number(selector,&b) || b<1 || b>MAX_BUCKETS) goto invalid;
      buckets=(unsigned)b; continue;
    }
    if (fields!=4 || nrules==MAX_RULES || !number(rate,&r) || !number(burst,&b) ||
        r<1 || r>1000000000UL || b<1 || b>1000000UL) goto invalid;
    struct rule *rule=&rules[nrules];
    memset(rule,0,sizeof(*rule));
    if (!strcmp(kind,"key")) {
      rule->kind=KEY;
      if (strlen(selector)>63) goto invalid;
    }
    else if (!strcmp(kind,"zone")) rule->kind=ZONE;
    else if (!strcmp(kind,"source4") || !strcmp(kind,"source6")) {
      rule->kind=!strcmp(kind,"source4")?SOURCE4:SOURCE6;
      if (!number(selector,&p) || p>(rule->kind==SOURCE4?32:128)) goto invalid;
      rule->prefix=(unsigned)p;
    }
    else goto invalid;
    strcpy(rule->selector,selector);
    if (rule->kind==ZONE) {
      size_t n=strlen(rule->selector);
      if (n>1 && rule->selector[n-1]=='.') rule->selector[n-1]=0;
    }
    /* Ceiling keeps the specified rate an upper bound. */
    rule->interval=(SECOND+r-1)/r;
    rule->tolerance=(b-1)*rule->interval;
    ++nrules;
  }
  if (ferror(f)) goto invalid;
  fclose(f);
  if (!nrules) { snprintf(error,size,"empty quota policy"); goto fail; }
  f=fopen("/dev/urandom","rb");
  if (!f) { snprintf(error,size,"cannot initialize quota hash secret"); goto fail; }
  int ok=fread(secret,1,sizeof(secret),f)==sizeof(secret);
  fclose(f);
  if (!ok) { snprintf(error,size,"cannot read quota hash secret"); goto fail; }
  map_size=(size_t)nrules*buckets*sizeof(*accounting);
  accounting=mmap(NULL,map_size,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANON,-1,0);
  if (accounting==MAP_FAILED) { accounting=NULL; snprintf(error,size,"cannot map quota counters"); goto fail; }
  for (size_t i=0; i<(size_t)nrules*buckets; ++i) atomic_init(&accounting[i],0);
  if (!atomic_is_lock_free(accounting)) {
    snprintf(error,size,"quota accounting requires lock-free 64-bit atomics"); goto fail;
  }
  return 0;
invalid:
  fclose(f);
  snprintf(error,size,"invalid quota policy at line %u",lineno);
fail:
  rbldnsd_ratelimit_close(); return -1;
}

static int charge(_Atomic uint64_t *counter, const struct rule *r, uint64_t now) {
  uint64_t old=atomic_load_explicit(counter,memory_order_relaxed);
  /* Bounded contention: overload or a hot customer cannot spin indefinitely. */
  for (unsigned retries=0; retries<64; ++retries) {
    if (old>now && old-now>r->tolerance) return 0;
    uint64_t base=old>now?old:now;
    if (base>UINT64_MAX-r->interval) return 0;
    uint64_t next=base+r->interval;
    if (atomic_compare_exchange_weak_explicit(counter,&old,next,
          memory_order_relaxed,memory_order_relaxed)) return 1;
  }
  return 0;
}
int rbldnsd_ratelimit_check_at(const struct sockaddr *peer, const char *zone,
                              const char *key, uint64_t now) {
  if (!accounting) return 1;
  for (unsigned i=0; i<nrules; ++i) {
    const struct rule *r=&rules[i];
    const unsigned char *identity;
    unsigned char address[16];
    char canonical[256];
    size_t n;
    unsigned index=0;
    if (r->kind==KEY || r->kind==ZONE) {
      const char *name=r->kind==KEY?key:zone;
      if (!name) continue; /* Never charge unauthenticated labels as keys. */
      n=strlen(name);
      if (n>=sizeof(canonical)) return 0;
      if (r->kind==ZONE) {
        if (n>1 && name[n-1]=='.') --n;
        for (size_t j=0;j<n;++j) canonical[j]=(char)tolower((unsigned char)name[j]);
        canonical[n]=0; name=canonical;
      }
      if (strcmp(r->selector,"*")) {
        if (r->kind==ZONE?strcasecmp(r->selector,name):strcmp(r->selector,name)) continue;
      }
      else index=(unsigned)(bucket_hash((const unsigned char *)name,n)%buckets);
    }
    else {
      if (!peer) continue;
      if (r->kind==SOURCE4 && peer->sa_family==AF_INET) {
        identity=(const unsigned char *)&((const struct sockaddr_in *)peer)->sin_addr;
        n=4;
      }
      else if (r->kind==SOURCE6 && peer->sa_family==AF_INET6) {
        identity=(const unsigned char *)&((const struct sockaddr_in6 *)peer)->sin6_addr;
        n=16;
      }
      else continue;
      memcpy(address,identity,n);
      unsigned full=r->prefix/8, bits=r->prefix%8;
      if (bits) address[full++] &= (unsigned char)(255u<<(8-bits));
      memset(address+full,0,n-full);
      index=(unsigned)(bucket_hash(address,n)%buckets);
    }
    /* Earlier successful constraints stay charged if a later one rejects.
     * Rolling back a concurrent bucket could grant extra allowance. */
    if (!charge(&accounting[(size_t)i*buckets+index],r,now)) return 0;
  }
  return 1;
}
int rbldnsd_ratelimit_check(const struct sockaddr *peer, const char *zone,
                           const char *key) {
  struct timespec ts;
  if (!accounting) return 1;
  if (clock_gettime(CLOCK_MONOTONIC,&ts)<0) return 0;
  return rbldnsd_ratelimit_check_at(peer,zone,key,
    (uint64_t)ts.tv_sec*SECOND+(uint64_t)ts.tv_nsec);
}
