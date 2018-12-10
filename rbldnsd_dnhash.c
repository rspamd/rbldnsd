/* Dataset type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "khash.h"
#include "t1ha/t1ha.h"

#include "rbldnsd.h"

struct entry {
  const unsigned char *ldn;	/* DN key, mp-allocated, length byte first */
  const char *rr;		/* A and TXT RRs */
};

static unsigned hash_seed = 0xdeadbabe;

#define t1ha_str(key) t1ha2_atonce((key), strlen(key), hash_seed)
KHASH_INIT(dnhash, const unsigned char *, struct entry, 1, t1ha_str, kh_str_hash_equal);


/* There are two similar arrays -
 * for plain entries and for wildcard entries.
 */

struct dsdata {
  khash_t(dnhash) *h;
  const char *def_rr;		/* default A and TXT RRs */
};

definedstype(dnhash, 0, "set of (domain name, value) pairs, hashed version");

static void ds_dnhash_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  kh_clear(dnhash, dsd->h);
}

static void ds_dnhash_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  ds->ds_dsd->def_rr = def_rr;

  dsd->h = kh_init(dnhash);
}

static int
ds_dnhash_addent(struct dsdata *d,
                const unsigned char *ldn, const char *rr,
                unsigned dnlab) {
  struct entry *e;
  khiter_t k;
  int ret;

  k = kh_put(dnhash, d->h, ldn, &ret);

  if (ret < 0) {
    return 0;
  }

  e = &kh_value(d->h, k);
  e->ldn = ldn;
  e->rr = rr;

  return 1;
}

static int
ds_dnhash_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned char dn[DNS_MAXDN];
  const char *rr;
  unsigned char *ldn;
  unsigned dnlen, size;

  if (*s == ':') {		/* default entry */
    if (!(size = parse_a_txt(s, &rr, def_rr, dsc)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, size)))
      return 0;
    return 1;
  }

  /* check negation */
  if (*s == '!') {
    return 0;
  }

  /* disallow emptry DN to be listed (i.e. "all"?) */
  if (!(s = parse_dn(s, dn, &dnlen)) || dnlen == 1) {
    dswarn(dsc, "invalid domain name");
    return 1;
  }

  dns_dntol(dn, dn);		/* lowercase */
  /* else parse rest */
  SKIPSPACE(s);
  if (!*s || ISCOMMENT(*s))	/* use default if none given */
    rr = dsd->def_rr;
  else if (!(size = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
    return 1;
  else if (!(rr = mp_dmemdup(ds->ds_mp, rr, size)))
    return 0;

  ldn = (unsigned char*)mp_alloc(ds->ds_mp, dnlen + 1, 0);
  if (!ldn)
    return 0;
  ldn[0] = (unsigned char)(dnlen - 1);
  memcpy(ldn + 1, dn, dnlen);

  dnlen = dns_dnlabels(dn);
  if (!ds_dnhash_addent(dsd, ldn, rr, dnlen))
    return 0;

  return 1;
}


static void ds_dnhash_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  dsloaded(dsc, "e=%u", kh_size(dsd->h));
}

static int
ds_dnhash_query(const struct dataset *ds, const struct dnsqinfo *qi,
               struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  const unsigned char *dn = qi->qi_dn;
  unsigned qlab = qi->qi_dnlab;
  const struct entry *e;
  char name[DNS_MAXDOMAIN+1];
  khiter_t k;

  if (!qlab) return 0;		/* do not match empty dn */
  check_query_overwrites(qi);

  k = kh_get(dnhash, dsd->h, dn);

  if (k != kh_end(dsd->h)) {
    e = &kh_value(dsd->h, k);

    if (qi->qi_tflag & NSQUERY_TXT) {
      dns_dntop(e->ldn + 1, name, sizeof(name));
    }

    addrr_a_txt(pkt, qi->qi_tflag, e->rr, name, ds);

    return NSQUERY_FOUND;
  }

  return 0;
}

#ifndef NO_MASTER_DUMP

static void
ds_dnhash_dump(const struct dataset *ds,
              const unsigned char UNUSED *unused_odn,
              FILE *f) {
  const struct dsdata *dsd = ds->ds_dsd;
  struct entry e;
  char name[DNS_MAXDOMAIN+4];

  kh_foreach_value(dsd->h, e, {
    dns_dntop(e.ldn + 1, name, sizeof(name));
    dump_a_txt(name, e.rr, name, ds, f);
  });
}

#endif
