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
 * Hashed dataset with wildcards
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <syslog.h>

#include "khash.h"
#include "dns_hash.h"

#include "rbldnsd.h"

struct key {
  unsigned len;
  const unsigned char *ldn;
};

struct entry {
  const char *rr;		/* A and TXT RRs */
  const struct kv_params *params;
};

static inline int64_t
key_hash_func(struct key k)
{
  return (int64_t)dns_label_hash(k.ldn, k.len);
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

/* bloom filter for negative lookups */
#define DNHASH_BLOOM_BITS_PER_ENTRY 10U
#define DNHASH_BLOOM_K 3U
#define DNHASH_BLOOM_MIN_BITS (1U << 12)
#define DNHASH_BLOOM_MAX_BYTES (8U * 1024U * 1024U)

struct dnhash_bloom {
  uint32_t nbits;
  uint32_t mask;
  uint8_t k;
  uint64_t bits[];
};

static inline size_t
dnhash_pow2_round_up(size_t x)
{
  if (x <= 1) {
    return 1;
  }

  x--;
  for (size_t s = 1; s < sizeof(size_t) * 8; s <<= 1) {
    x |= x >> s;
  }
  return x + 1;
}

static inline size_t
dnhash_pow2_round_down(size_t x)
{
  if (x == 0) {
    return 0;
  }

  return dnhash_pow2_round_up(x + 1) >> 1;
}

static inline uint64_t
dnhash_bloom_mix(uint64_t x)
{
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

static inline void
dnhash_bloom_add(struct dnhash_bloom *b, const unsigned char *p, unsigned len)
{
  uint32_t h1 = dns_label_hash(p, len);
  uint64_t mixed = dnhash_bloom_mix(h1);
  uint32_t h2 = (uint32_t)(mixed >> 32) | 1u;  /* odd for coprimality with power-of-2 size */

  for (unsigned i = 0; i < b->k; i++) {
    uint32_t idx = (h1 + i * h2) & b->mask;
    b->bits[idx >> 6] |= 1ULL << (idx & 63);
  }
}

static inline int
dnhash_bloom_maybe_has(const struct dnhash_bloom *b, const unsigned char *p,
                       unsigned len)
{
  uint32_t h1 = dns_label_hash(p, len);
  uint64_t mixed = dnhash_bloom_mix(h1);
  uint32_t h2 = (uint32_t)(mixed >> 32) | 1u;

  for (unsigned i = 0; i < b->k; i++) {
    uint32_t idx = (h1 + i * h2) & b->mask;
    if ((b->bits[idx >> 6] & (1ULL << (idx & 63))) == 0) {
      return 0;
    }
  }

  return 1;
}

static struct dnhash_bloom *
dnhash_bloom_create(struct dataset *ds, size_t nbits)
{
  if (nbits < DNHASH_BLOOM_MIN_BITS) {
    return NULL;
  }

  size_t rounded = dnhash_pow2_round_up(nbits);
  if (rounded < nbits) {
    /* overflow during rounding */
    return NULL;
  }
  nbits = rounded;

  /* Keep mask/index math in uint32_t and protect mp_alloc(unsigned) */
  if (nbits > (1ULL << 31) || nbits > (size_t)DNHASH_BLOOM_MAX_BYTES * 8) {
    return NULL;
  }

  size_t nwords = (nbits + 63) / 64;
  if (nwords > (SIZE_MAX - sizeof(struct dnhash_bloom)) / sizeof(uint64_t)) {
    return NULL;
  }
  size_t alloc_size = sizeof(struct dnhash_bloom) + nwords * sizeof(uint64_t);
  if (alloc_size > UINT_MAX) {
    return NULL;
  }

  struct dnhash_bloom *b = mp_alloc(ds->ds_mp, (unsigned)alloc_size, 1);
  if (!b) {
    return NULL;
  }

  b->nbits = (uint32_t)nbits;
  b->mask = (uint32_t)(nbits - 1);
  b->k = (uint8_t)DNHASH_BLOOM_K;
  memset(b->bits, 0, nwords * sizeof(uint64_t));

  return b;
}

static struct dnhash_bloom *
dnhash_bloom_build(struct dataset *ds, khash_t(dnhash) *h, size_t nbits)
{
  struct dnhash_bloom *b = dnhash_bloom_create(ds, nbits);
  if (!b) {
    return NULL;
  }

  struct key k;
  struct entry e;
  kh_foreach(h, k, e, {
    dnhash_bloom_add(b, k.ldn, k.len);
  });

  return b;
}

struct dsdata {
  khash_t(dnhash) *direct;
  khash_t(dnhash) *wild[MAX_WILDCARD];
  struct dnhash_bloom *direct_bloom;
  struct dnhash_bloom *wild_bloom[MAX_WILDCARD];
  const char *def_rr;		/* default A and TXT RRs */
  int w_maxlab;
};

definedstype_update(dnhash, 0, "set of (domain name, value) pairs, hashed version");

static void ds_dnhash_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  kh_clear(dnhash, dsd->direct);
  for (int i = 0; i < MAX_WILDCARD; i ++) {
    kh_clear(dnhash, dsd->wild[i]);
  }
  dsd->direct_bloom = NULL;
  for (int i = 0; i < MAX_WILDCARD; i++) {
    dsd->wild_bloom[i] = NULL;
  }
  dsd->w_maxlab = 0;
}

static void ds_dnhash_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  ds->ds_dsd->def_rr = def_rr;

  dsd->w_maxlab = 0;

  if (dsd->direct == NULL) {
    dsd->direct = kh_init(dnhash);
    dsd->direct_bloom = NULL;
    for (int i = 0; i < MAX_WILDCARD; i++) {
      dsd->wild[i] = kh_init(dnhash);
      dsd->wild_bloom[i] = NULL;
    }
  }
}

static int
ds_dnhash_addent(khash_t(dnhash) *h,
                struct dnhash_bloom *bloom,
                const unsigned char *ldn,
                const char *rr,
                const struct kv_params *params,
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
  e->params = params;

  if (bloom && ret > 0) {
    dnhash_bloom_add(bloom, ldn, dnlen);
  }

  return 1;
}

static int
ds_dnhash_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned char dn[DNS_MAXDN];
  const char *rr;
  const struct kv_params *params = NULL;
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

    char *params_s = NULL;
    rbldnsd_split_entry_params(s, &params_s);
    params = rbldnsd_parse_kv_params(ds->ds_mp, dsc, params_s);

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

    if (!ds_dnhash_addent(dsd->wild[dnlab - 1], dsd->wild_bloom[dnlab - 1],
                          ldn, rr, params, dnlen - 1)) {
      return 0;
    }
  }

  if (isplain) {
    if (!ds_dnhash_addent(dsd->direct, dsd->direct_bloom, ldn, rr, params, dnlen - 1)) {
      return 0;
    }
  }

  return 1;
}

static int
ds_dnhash_update(struct dataset *ds, char *s, struct dsctx *dsc) {
  return ds_dnhash_line(ds, s, dsc);
}

static void ds_dnhash_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;

  enum { DNHASH_NTABLES = MAX_WILDCARD + 1 };
  size_t nent[DNHASH_NTABLES];
  size_t raw_bits[DNHASH_NTABLES];
  size_t bits[DNHASH_NTABLES];

  nent[0] = kh_size(dsd->direct);
  for (int i = 0; i < MAX_WILDCARD; i++) {
    nent[i + 1] = kh_size(dsd->wild[i]);
  }

  size_t sum_raw = 0;
  for (int i = 0; i < DNHASH_NTABLES; i++) {
    size_t raw = nent[i] * (size_t)DNHASH_BLOOM_BITS_PER_ENTRY;
    if (raw < DNHASH_BLOOM_MIN_BITS) {
      raw = 0;
    }
    raw_bits[i] = raw;
    sum_raw += raw;
  }

  size_t sum_bits = 0;
  for (int i = 0; i < DNHASH_NTABLES; i++) {
    bits[i] = raw_bits[i] ? dnhash_pow2_round_up(raw_bits[i]) : 0;
    sum_bits += bits[i];
  }

  const size_t cap_bits = (size_t)DNHASH_BLOOM_MAX_BYTES * 8;
  if (sum_bits > cap_bits && sum_raw > 0) {
    sum_bits = 0;
    for (int i = 0; i < DNHASH_NTABLES; i++) {
      size_t scaled = raw_bits[i] ? (raw_bits[i] * cap_bits) / sum_raw : 0;
      bits[i] = scaled ? dnhash_pow2_round_down(scaled) : 0;
      if (bits[i] < DNHASH_BLOOM_MIN_BITS) {
        bits[i] = 0;
      }
      sum_bits += bits[i];
    }

    while (sum_bits > cap_bits) {
      int max_i = -1;
      size_t max_b = 0;
      for (int i = 0; i < DNHASH_NTABLES; i++) {
        if (bits[i] > max_b) {
          max_b = bits[i];
          max_i = i;
        }
      }
      if (max_i == -1 || max_b <= DNHASH_BLOOM_MIN_BITS) {
        break;
      }
      bits[max_i] >>= 1;
      if (bits[max_i] < DNHASH_BLOOM_MIN_BITS) {
        bits[max_i] = 0;
      }

      sum_bits = 0;
      for (int i = 0; i < DNHASH_NTABLES; i++) {
        sum_bits += bits[i];
      }
    }
  }

  dsd->direct_bloom = dnhash_bloom_build(ds, dsd->direct, bits[0]);
  for (int i = 0; i < MAX_WILDCARD; i++) {
    dsd->wild_bloom[i] = dnhash_bloom_build(ds, dsd->wild[i], bits[i + 1]);
  }

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

  if (!dsd->direct_bloom || dnhash_bloom_maybe_has(dsd->direct_bloom, dn, srch.len)) {
    k = kh_get(dnhash, dsd->direct, srch);

    if (k != kh_end(dsd->direct)) {
      e = &kh_value(dsd->direct, k);

      /* Exclusion must override any wildcard matches (same semantics as dnset). */
      if (!e->rr) {
        return 0;
      }

      if (qi->qi_tflag & NSQUERY_TXT) {
        pkey = &kh_key(dsd->direct, k);
        dns_dntop(pkey->ldn, name, sizeof(name));
      }

      if (e->rr) {
        struct entry_action act;
        act.allow = 1;
        act.delay_ms = 0;
        act.flags = 0;
        rbldnsd_apply_entry_params(pkt->p_peer, ds, qi, e->params, &act);
        if (!act.allow) {
          return 0;
        }
        if (act.delay_ms > pkt->p_delay_ms) {
          pkt->p_delay_ms = act.delay_ms;
        }
      }
      addrr_a_txt(pkt, qi->qi_tflag, e->rr, name, ds);

      return NSQUERY_FOUND;
    }
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

    struct dnhash_bloom *wb = dsd->wild_bloom[qlab - 1];
    if (!wb || dnhash_bloom_maybe_has(wb, dn, srch.len)) {
      k = kh_get(dnhash, dsd->wild[qlab - 1], srch);

      if (k != kh_end(dsd->wild[qlab - 1])) {
        e = &kh_value(dsd->wild[qlab - 1], k);

        if (qi->qi_tflag & NSQUERY_TXT) {
          pkey = &kh_key(dsd->wild[qlab - 1], k);
          dns_dntop(pkey->ldn, name, sizeof(name));
        }

        if (e->rr) {
          struct entry_action act;
          act.allow = 1;
          act.delay_ms = 0;
          act.flags = 0;
          rbldnsd_apply_entry_params(pkt->p_peer, ds, qi, e->params, &act);
          if (!act.allow) {
            return 0;
          }
          if (act.delay_ms > pkt->p_delay_ms) {
            pkt->p_delay_ms = act.delay_ms;
          }

          addrr_a_txt(pkt, qi->qi_tflag, e->rr, name, ds);

          return NSQUERY_FOUND;
        }
      }
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
    dns_dntop(k.ldn, name, sizeof(name));
    dump_a_txt(name, e.rr, name, ds, f);
  });

  for (unsigned int i = 0; i < MAX_WILDCARD; i++) {
    name[0] = '*'; name[1] = '.';

    kh_foreach(dsd->wild[i], k, e, {
      dns_dntop(k.ldn, name + 2, sizeof(name) - 2);
      dump_a_txt(name, e.rr, name, ds, f);
    });
  }
}

#endif
