/*
 * RBLDNSD
 * Copyright (C) 2019 Vsevolod Stakhov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 */

/*
 * Hashed dataset with no wirldcards
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

#include "khash.h"
#include "t1ha/t1ha.h"

#include "rbldnsd.h"

struct key {
  unsigned len;
  const unsigned char *ldn;
};

struct entry {
  const char *rr;		/* A and TXT RRs */
};

static uint64_t hash_seed = 0x0f0a13905c0bfd77ULL;

static inline int64_t
key_hash_func(struct key k)
{
  return t1ha2_atonce(k.ldn, k.len, hash_seed);
}

static inline int
key_eq_func(struct key k1, struct key k2)
{
  return k1.len == k2.len && memcmp(k1.ldn, k2.ldn, k1.len) == 0;
}

KHASH_INIT(dnhash, struct key, struct entry, 1, key_hash_func, key_eq_func);


/* There are two similar arrays -
 * for plain entries and for wildcard entries.
 */
#define MAX_WILDCARD 5
struct dsdata {
  khash_t(dnhash) *direct;
  khash_t(dnhash) *wild[MAX_WILDCARD];
  const char *def_rr;		/* default A and TXT RRs */
  int w_maxlab;
};

definedstype(dnhash, 0, "set of (domain name, value) pairs, hashed version");

static void ds_dnhash_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  kh_destroy(dnhash, dsd->direct);
  for (int i = 0; i < MAX_WILDCARD; i ++) {
    kh_destroy(dnhash, dsd->wild[i]);
  }
  dsd->w_maxlab = 0;
}

static void ds_dnhash_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  ds->ds_dsd->def_rr = def_rr;

  dsd->w_maxlab = 0;
  dsd->direct = kh_init(dnhash);
  for (int i = 0; i < MAX_WILDCARD; i ++) {
    dsd->wild[i] = kh_init(dnhash);
  }
}

static int
ds_dnhash_addent(khash_t(dnhash) *h,
                const unsigned char *ldn,
                const char *rr,
                unsigned dnlen) {
  struct entry *e;
  khiter_t k;
  struct key key;
  int ret;

  key.ldn = ldn;
  key.len = dnlen;
  k = kh_put(dnhash, h, key, &ret);

  if (ret < 0) {
    return 0;
  }

  e = &kh_value(h, k);
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
  int not, iswild, isplain;

  if (*s == ':') {		/* default entry */
    if (!(size = parse_a_txt(s, &rr, def_rr, dsc)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, size)))
      return 0;
    return 1;
  }

  /* check negation */
  if (*s == '!') {
    not = 1;
    ++s; SKIPSPACE(s);
  }
  else {
    not = 0;
  }

  /* check for wildcard: .xxx or *.xxx */
  if (*s == '.') {
    iswild = 1; isplain = 1; ++s;
  }
  else if (s[0] == '*' && s[1] == '.') {
    iswild = 1; isplain = 0; s += 2;
  }
  else {
    iswild = 0; isplain = 1;
  }

  /* disallow emptry DN to be listed (i.e. "all"?) */
  if (!(s = parse_dn(s, dn, &dnlen)) || dnlen == 1) {
    dswarn(dsc, "invalid domain name");
    return 1;
  }

  dns_dntol(dn, dn);		/* lowercase */
  if (not) {
    rr = NULL;      /* negation entry */
  }
  else {
    /* else parse rest */
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s)) {
      /* use default if none given */
      rr = dsd->def_rr;
    } else if (!(size = parse_a_txt(s, &rr, dsd->def_rr, dsc))) {
      return 1;
    } else if (!(rr = mp_dmemdup(ds->ds_mp, rr, size))) {
      return 0;
    }
  }

  ldn = (unsigned char*)mp_alloc(ds->ds_mp, dnlen, 0);
  if (!ldn)
    return 0;
  memcpy(ldn, dn, dnlen);

  if (iswild) {
    int dnlab = dns_dnlabels(dn);

    if (dnlab <= 0 || dnlab > MAX_WILDCARD) {
      dslog(LOG_ERR, dsc, "cannot insert wildcard %s to hash table, too many labels", s);
      return 0;
    }

    if (dsd->w_maxlab < dnlab) {
      dsd->w_maxlab = dnlab;
    }

    if (!ds_dnhash_addent(dsd->wild[dnlab - 1], ldn, rr, dnlen - 1)) {
      return 0;
    }
  }

  if (isplain) {
    if (!ds_dnhash_addent(dsd->direct, ldn, rr, dnlen - 1)) {
      return 0;
    }
  }

  return 1;
}


static void ds_dnhash_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;

  unsigned nwild = 0;
  for (int i = 0; i < MAX_WILDCARD; i ++) {
    nwild += kh_size(dsd->wild[i]);
  }

  dsloaded(dsc, "plain=%u, wild=%u", kh_size(dsd->direct), nwild);
}

static int
ds_dnhash_query(const struct dataset *ds, const struct dnsqinfo *qi,
               struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  const unsigned char *dn = qi->qi_dn;
  unsigned qlab = qi->qi_dnlab;
  unsigned qlen0 = qi->qi_dnlen0;
  const struct entry *e;
  char name[DNS_MAXDOMAIN+1];
  khiter_t k;
  struct key srch, *pkey;

  if (!qlab) return 0;		/* do not match empty dn */
  check_query_overwrites(qi);

  /* First, search for plain match */
  srch.len = qi->qi_dnlen0;
  srch.ldn = dn;
  k = kh_get(dnhash, dsd->direct, srch);

  if (k != kh_end(dsd->direct)) {
    e = &kh_value(dsd->direct, k);

    if (qi->qi_tflag & NSQUERY_TXT) {
      pkey = &kh_key(dsd->direct, k);
      dns_dntop(pkey->ldn + 1, name, sizeof(name));
    }

    addrr_a_txt(pkt, qi->qi_tflag, e->rr, name, ds);

    return NSQUERY_FOUND;
  }

  /* Now check for wildcards */
  /*
   * remove labels until number of labels in query is greather
   * than we have in wildcard array, but remove at least 1 label
   * for wildcard itself.
   */
  do {
    --qlab, qlen0 -= *dn + 1, dn += *dn + 1;
  } while (qlab > dsd->w_maxlab);

  /* now, lookup every so long dn in wildcard array */
  for(;;) {
    if (qlab == 0) {
      break;
    }

    srch.len = qlen0;
    srch.ldn = dn;
    k = kh_get(dnhash, dsd->wild[qlab - 1], srch);

    if (k != kh_end(dsd->wild[qlab - 1])) {
      e = &kh_value(dsd->wild[qlab - 1], k);

      if (qi->qi_tflag & NSQUERY_TXT) {
        pkey = &kh_key(dsd->wild[qlab - 1], k);
        dns_dntop(pkey->ldn + 1, name, sizeof(name));
      }

      addrr_a_txt(pkt, qi->qi_tflag, e->rr, name, ds);

      return NSQUERY_FOUND;
    }

    /* remove next label at the end of rdn */
    qlen0 -= *dn + 1;
    dn += *dn + 1;
    --qlab;
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
  struct key k;
  char name[DNS_MAXDOMAIN+4];

  kh_foreach(dsd->direct, k, e, {
    dns_dntop(k.ldn + 1, name, sizeof(name));
    dump_a_txt(name, e.rr, name, ds, f);
  });

  for (unsigned int i = 0; i < MAX_WILDCARD; i++) {
    name[0] = '*'; name[1] = '.';

    kh_foreach(dsd->wild[i], k, e, {
      dns_dntop(k.ldn + 1, name + 2, sizeof(name) - 2);
      dump_a_txt(name, e.rr, name, ds, f);
    });
  }
}

#endif
