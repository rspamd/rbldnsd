/* Dataset type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "khash.h"

#include "rbldnsd.h"

#ifndef FIXED_HASHLEN
#define FIXED_HASHLEN 32
#endif


static inline int
key_hash_func(u_char *key)
{
  int k;
  memcpy (&k, key, sizeof (k));
  return k;
}

static inline int
key_eq_func(u_char *k1, u_char *k2)
{
  return memcmp(k1, k2, FIXED_HASHLEN) == 0;
}


KHASH_INIT(dnhash, u_char *, const char *, 1, key_hash_func, key_eq_func);


/* There are two similar arrays -
 * for plain entries and for wildcard entries.
 */

struct dsdata {
  khash_t(dnhash) *h;
  const char *def_rr;		/* default A and TXT RRs */
};

#define STRINGIFY_ARG(macro_or_string) #macro_or_string
#define STRINGIFY(macro_or_string) STRINGIFY_ARG(macro_or_string)
definedstype(dnhash_fixed, 0, "set of (domain name, value) pairs, fixed hash version (" STRINGIFY(FIXED_HASHLEN) " bytes)");

static void ds_dnhash_fixed_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  kh_clear(dnhash, dsd->h);
}

static void ds_dnhash_fixed_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  ds->ds_dsd->def_rr = def_rr;

  dsd->h = kh_init(dnhash);
}

static int
ds_dnhash_fixed_addent(struct dsdata *d,
                const unsigned char *ldn, const char *rr,
                unsigned dnlen) {
  khiter_t k;
  int ret;
  u_char key[FIXED_HASHLEN];
  const char **e;

  if (*ldn == FIXED_HASHLEN) {
    memcpy (key, ldn + 1, FIXED_HASHLEN);
    k = kh_put(dnhash, d->h, key, &ret);

    if (ret < 0) {
      return 0;
    }

    e = &kh_value(d->h, k);
    *e = rr;
  }
  else {
    return 0;
  }

  return 1;
}

static int
ds_dnhash_fixed_line(struct dataset *ds, char *s, struct dsctx *dsc) {
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

  ldn = (unsigned char*)mp_alloc(ds->ds_mp, dnlen, 0);
  if (!ldn)
    return 0;
  memcpy(ldn, dn, dnlen);

  if (!ds_dnhash_fixed_addent(dsd, ldn, rr, dnlen - 1)) {
    dswarn(dsc, "invalid domain name: %s", ldn + 1);
    return 0;
  }

  return 1;
}


static void ds_dnhash_fixed_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  dsloaded(dsc, "e=%u", kh_size(dsd->h));
}

static int
ds_dnhash_fixed_query(const struct dataset *ds, const struct dnsqinfo *qi,
               struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  const unsigned char *dn = qi->qi_dn;
  unsigned qlab = qi->qi_dnlab;
  const char *e;
  char name[DNS_MAXDOMAIN+1];
  khiter_t k;
  u_char srch[FIXED_HASHLEN];

  if (!qlab) return 0;		/* do not match empty dn */
  check_query_overwrites(qi);

  if (*dn != FIXED_HASHLEN) {
    return 0;
  }

  memcpy(srch, dn + 1, FIXED_HASHLEN);
  k = kh_get(dnhash, dsd->h, srch);

  if (k != kh_end(dsd->h)) {
    e = kh_value(dsd->h, k);

    if (qi->qi_tflag & NSQUERY_TXT) {
      dns_dntop(dn + 1, name, sizeof(name));
    }

    addrr_a_txt(pkt, qi->qi_tflag, e, name, ds);

    return NSQUERY_FOUND;
  }

  return 0;
}

#ifndef NO_MASTER_DUMP

static void
ds_dnhash_fixed_dump(const struct dataset *ds,
              const unsigned char UNUSED *unused_odn,
              FILE *f) {
  const struct dsdata *dsd = ds->ds_dsd;
  const char *e;
  u_char *ldn;
  char name[DNS_MAXDOMAIN+4];

  kh_foreach(dsd->h, ldn, e, {
    dns_dntop(ldn, name, sizeof(name));
    dump_a_txt(name, e, name, ds, f);
  });
}

#endif
