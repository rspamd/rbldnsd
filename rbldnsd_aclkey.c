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
 * Keys based control for zones
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rbldnsd.h"
#include "btrie.h"
#include "khash.h"
#include "t1ha/t1ha.h"

struct acl_key {
  unsigned len;
  const unsigned char *ldn;
};
struct acl_val {
  uint64_t requests;
  const char *rr;
};


static unsigned hash_seed = 0xdeadbabe;

static inline int
key_hash_func(struct acl_key k)
{
  return t1ha2_atonce(k.ldn, k.len, hash_seed);
}

static inline int
key_eq_func(struct acl_key k1, struct acl_key k2)
{
  return k1.len == k2.len && memcmp(k1.ldn, k2.ldn, k1.len) == 0;
}

KHASH_INIT(acl_key_hash, struct acl_key, struct acl_val, 1, key_hash_func, key_eq_func);

struct dsdata {
  const char *def_rr;
  const char *def_action;
  khash_t(acl_key_hash) *auth_keys;
};

/* special cases for pseudo-RRs */
static const struct {
  const char *name;
  unsigned long rr;
} keywords[] = {
  /* ignore (don't answer) queries from this IP */
#define RR_IGNORE	1
 { "ignore", RR_IGNORE },
 { "blackhole", RR_IGNORE },
 /* refuse *data* queries from this IP (but not metadata) */
#define RR_REFUSE	2
 { "refuse", RR_REFUSE },
 /* pretend the zone is completely empty */
#define RR_EMPTY	3
 { "empty", RR_EMPTY },
 /* a 'whitelist' entry: pretend this netrange isn't here */
#define RR_PASS		4
 { "pass", RR_PASS },
 { "accept", RR_PASS },
};

static void ds_aclkey_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  memset(dsd, 0, sizeof(*dsd));
}

static void ds_aclkey_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;

  dsd->def_rr = def_rr;
  dsd->def_action = (char*)RR_IGNORE;
  if (!dsd->auth_keys) {
    dsd->auth_keys = kh_init(acl_key_hash);
  }
}

static const char *keyword(const char *s) {
  const char *k, *p;
  unsigned i;
  if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')))
    return NULL;
  for (i = 0; i < sizeof(keywords)/sizeof(keywords[0]); ++i)
    for (k = keywords[i].name, p = s;;)
      if ((*p >= 'A' && *p <= 'Z' ? *p - 'A' + 'a' : *p) != *k++)
        break;
      else if (!*++p || *p == ':' || ISSPACE(*p) || ISCOMMENT(*p))
        return (const char *)(keywords[i].rr);
  return NULL;
}

static int
ds_aclkey_parse_val(char *s, const char **rr_p, struct dsdata *dsd,
                 struct dsctx *dsc) {
  int r;
  if (*s == '=') {
    if ((*rr_p = keyword(s+1)))
      return 0;
    dswarn(dsc, "invalid keyword");
    return -1;
  }
  if (*s == ':' && (*rr_p = keyword(s+1)))
    return 0;
  r = parse_a_txt(s, rr_p, dsd->def_rr, dsc);
  return r ? r : -1;
}

#define VALID_TAIL(c) ((c) == '\0' || ISSPACE(c) ||  ISCOMMENT(c) || (c) == ':')

static int
ds_aclkey_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  khiter_t k;
  char *tail, *key_storage;
  const char *rr;
  int rrl;
  struct acl_val *nval;
  struct acl_key key;

  if ((*s == ':' && s[1] != ':') || *s == '=') {
    if ((rrl = ds_aclkey_parse_val(s, &rr, dsd, dsc)) < 0) {
      return 1;
    }
    else if (!rrl) {
      dsd->def_action = rr;
    }
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl))) {
      return 0;
    }

    dsd->def_rr = dsd->def_action = rr;

    return 1;
  }

  rr = dsd->def_rr;

  /* Parse key name */
  tail = s + strcspn(s, ":= ");

  if (*tail) {
    SKIPSPACE(tail);

    if (!*tail || ISCOMMENT(*tail))
      rr = dsd->def_action;
    else if ((rrl = ds_aclkey_parse_val(tail, &rr, dsd, dsc)) < 0)
      return 1;
    else if (rrl && !(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
  }
  else {
    tail = s + strlen(s);
  }

  key_storage = mp_alloc(ds->ds_mp, tail - s + 1, 0);
  if (key_storage) {
    memcpy(key_storage, s, tail - s);
    key_storage[tail - s] = '\0';
  }
  else {
    dslog(LOG_ERR, dsc, "failed to allocate %d bytes", (int)(tail - s + 1));
    return 0;
  }

  key.ldn = key_storage;
  key.len = tail - s;

  k = kh_put(acl_key_hash, dsd->auth_keys, key, &rrl);

  switch(rrl) {
    case -1:
      dslog(LOG_ERR, dsc, "cannot insert value %s to hash table", key.ldn);
      return 0;
    case 0:
      dslog(LOG_INFO, dsc, "duplicate entry %s", key.ldn);
      break;
    default:
      break;
  }

  nval = &kh_value(dsd->auth_keys, k);
  nval->requests = 0;
  nval->rr = rr;

  return 1;
}

static void ds_aclkey_finish(struct dataset *ds, struct dsctx *dsc) {
  dsloaded(dsc, "loaded");
  dslog(LOG_INFO, dsc, "keys loaded: %d", kh_size(ds->ds_dsd->auth_keys));
}

int ds_aclkey_query(const struct dataset *ds, struct dnsqinfo *qi,
    struct dnspacket *pkt) {
  const char *rr;
  khiter_t k;
  struct acl_key key;

  if (qi->qi_dnlab <= 1) {
    rr = ds->ds_dsd->def_rr;
  }
  else {
    /* Move to the latest label */
    const unsigned char *cur_lab = qi->qi_dn;
    for (unsigned int i = 0; i < qi->qi_dnlab - 1; i++) {
      cur_lab += *cur_lab + 1;
    }

    key.ldn = cur_lab + 1;
    key.len = *cur_lab;

    k = kh_get(acl_key_hash, ds->ds_dsd->auth_keys, key);

    if (k == kh_end(ds->ds_dsd->auth_keys)) {
      rr = ds->ds_dsd->def_rr;
    }
    else {
      struct acl_val *val = &kh_value(ds->ds_dsd->auth_keys, k);

      rr = val->rr;
      val->requests ++;

      /* Also modify qi */
      qi->qi_dnlab --;
      qi->qi_dnlen0 -= key.len + 1;
    }
  }

  switch((unsigned long)rr) {
  case 0: return 0;
  case RR_IGNORE:	return NSQUERY_IGNORE;
  case RR_REFUSE:	return NSQUERY_REFUSE;
  case RR_EMPTY:	return NSQUERY_EMPTY;
  case RR_PASS:		return 0;
  }

  /* Substitute zone value and handle it further in check_query_overwrites */
  if (!pkt->p_substrr) {
    pkt->p_substrr = rr;
    pkt->p_substds = ds;
  }

  return NSQUERY_ALWAYS;
}

/*definedstype(acl, DSTF_SPECIAL, "Access Control List dataset");*/
const struct dstype dataset_aclkey_type = {
  "aclkey", DSTF_SPECIAL, sizeof(struct dsdata),
  ds_aclkey_reset, ds_aclkey_start, ds_aclkey_line, ds_aclkey_finish,
  NULL, NULL, "Keyed Access Control List dataset"
};
