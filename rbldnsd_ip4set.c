/* ip4set dataset: IP4 CIDR, a.b.c.d-e.f.g.h and prefix ranges with (A, TXT)
 * values, stored as a sorted array of disjoint address ranges.
 *
 * When entries nest, the most specific one wins (for ranges that are not
 * CIDRs: the latest-starting entry covering the address, then the shortest);
 * `!` exclusions remove addresses from any enclosing entry. When the same
 * range is listed more than once, an exclusion wins wherever it appears,
 * otherwise the first line wins. The input is flattened at load time into
 * disjoint ranges, adjacent ranges with the same value are merged, and a
 * lookup is one binary search narrowed by an index on the top address bits.
 *
 * Memory is 8 bytes per stored range, plus 4 bytes per range for a value
 * index when the entries do not all share one value. Input lines are kept
 * in a 16-byte-per-line array until the end of the load; unsorted input is
 * sorted first.
 *
 * The engine is based on the ip4range proposal in PR #22.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include "rbldnsd.h"

#define META_EXCLUDED (~0u)

struct raw {              /* one input line, kept until finish */
  ip4addr_t lo, hi;
  unsigned meta;          /* index into dsd->metas, or META_EXCLUDED */
  unsigned seq;           /* line order, so equal ranges keep their file
                           * order after sorting */
};

struct range {
  ip4addr_t lo, hi;
};

struct dsdata {
  /* loaded data */
  struct range *r;                 /* sorted, disjoint, nr entries */
  unsigned *rmeta;                 /* per range index into metas; NULL when
                                    * every range uses metas[uniform] */
  unsigned nr, ar;
  unsigned uniform;                /* meta index shared by all ranges */
  unsigned *idx;                   /* (1 << idx_bits) + 1 entries: first range
                                    * whose hi is >= (i << (32 - idx_bits)) */
  unsigned idx_bits;               /* 0: no index, search the whole array */
  const struct entry_meta **metas; /* distinct (rr, params) pairs */
  unsigned nmetas, ametas;
  /* load state */
  struct raw *raw;
  unsigned nraw, araw, hraw;       /* hraw: size hint from the last load */
  int sorted;
  unsigned nexcl, ndups;
  const char *def_rr;
  struct entry_cache ec;           /* shares params and entry_meta */
};

definedstype(ip4set, DSTF_IP4REV, "set of (ip4 range, value) pairs");

static void ds_ip4set_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  unsigned hraw = dsd->hraw;
  free(dsd->r);
  free(dsd->rmeta);
  free(dsd->idx);
  free(dsd->metas);
  free(dsd->raw);
  memset(dsd, 0, sizeof(*dsd));
  dsd->hraw = hraw;
  dsd->sorted = 1;
}

static void ds_ip4set_start(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  dsd->def_rr = def_rr;
  if (!dsd->raw)
    dsd->sorted = 1;
}

/* Index of m in the metas table: look at the last 16 entries, else append. */
static unsigned
ds_ip4set_meta_index(struct dsdata *dsd, const struct entry_meta *m) {
  unsigned i = dsd->nmetas, stop = i > 16 ? i - 16 : 0;
  while (i > stop)
    if (dsd->metas[--i] == m)
      return i;
  if (dsd->nmetas == dsd->ametas) {
    dsd->ametas = dsd->ametas ? dsd->ametas * 2 : 16;
    dsd->metas = trealloc(const struct entry_meta *, dsd->metas, dsd->ametas);
    if (!dsd->metas)
      return META_EXCLUDED;
  }
  dsd->metas[dsd->nmetas] = m;
  return dsd->nmetas++;
}

static int
ds_ip4set_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a, b;
  const char *rr;
  unsigned rrl;
  char *params_s = NULL;
  const struct kv_params *params = NULL;
  unsigned meta;
  const struct entry_meta *em;
  struct raw *e;
  int not, bits;

  if (*s == ':') {
    if (!(rrl = parse_a_txt(s, &rr, def_rr, dsc)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
    return 1;
  }

  if (*s == '!') {
    not = 1;
    ++s; SKIPSPACE(s);
  }
  else
    not = 0;
  /* bits is 0 for a /0 entry: one range covering everything, accepted like
   * ip4trie does (the octet-level engine rejected it, as it would have
   * expanded to every address) */
  if ((bits = ip4range(s, &a, &b, &s)) < 0 ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(dsc, "invalid address");
    return 1;
  }
  if (accept_in_cidr)
    a &= ip4mask(bits);
  else if (a & ~ip4mask(bits)) {
    dswarn(dsc, "invalid range (non-zero host part)");
    return 1;
  }
  if (dsc->dsc_ip4maxrange && dsc->dsc_ip4maxrange <= (b - a)) {
    dswarn(dsc, "too large range (%llu) ignored (%u max)",
           (unsigned long long)b - a + 1, dsc->dsc_ip4maxrange);
    return 1;
  }

  if (not) {
    meta = META_EXCLUDED;
    dsd->nexcl++;
  }
  else {
    SKIPSPACE(s);
    rbldnsd_split_entry_params(s, &params_s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
      return 1;
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
    if (!rbldnsd_entry_params(ds->ds_mp, dsc, &dsd->ec, params_s, &params))
      return 0;
    em = rbldnsd_entry_meta(ds->ds_mp, &dsd->ec, rr, params);
    if (!em)
      return 0;
    meta = ds_ip4set_meta_index(dsd, em);
    if (meta == META_EXCLUDED)
      return 0;                   /* oom */
  }

  if (dsd->nraw == dsd->araw) {
    dsd->araw = dsd->araw ? dsd->araw * 2 : (dsd->hraw ? dsd->hraw : 1024);
    dsd->raw = trealloc(struct raw, dsd->raw, dsd->araw);
    if (!dsd->raw)
      return 0;
  }
  e = dsd->raw + dsd->nraw;
  if (dsd->nraw && dsd->sorted) {
    const struct raw *p = e - 1;
    /* sorted means: by start ascending, enclosing (longer) range first */
    if (a < p->lo || (a == p->lo && b > p->hi))
      dsd->sorted = 0;
  }
  e->lo = a;
  e->hi = b;
  e->meta = meta;
  e->seq = dsd->nraw;
  dsd->nraw++;
  return 1;
}

static void ds_ip4set_sort(struct dsdata *dsd) {
# define QSORT_TYPE struct raw
# define QSORT_BASE dsd->raw
# define QSORT_NELT dsd->nraw
# define QSORT_LT(a,b) \
     a->lo < b->lo ? 1 : \
     a->lo > b->lo ? 0 : \
     a->hi > b->hi ? 1 : \
     a->hi < b->hi ? 0 : \
     a->seq < b->seq
# include "qsort.c"
}

/* Append [lo, hi] with the given meta to the output, merging with the
 * previous range when adjacent and equal. */
static int
ds_ip4set_emit(struct dsdata *dsd, ip4addr_t lo, ip4addr_t hi, unsigned meta) {
  struct range *r;

  if (dsd->nr) {
    r = dsd->r + dsd->nr - 1;
    if (r->hi + 1 == lo && r->hi != 0xffffffffu &&
        (dsd->rmeta ? dsd->rmeta[dsd->nr - 1] : dsd->uniform) == meta) {
      r->hi = hi;
      return 1;
    }
  }
  if (dsd->nr == dsd->ar) {
    dsd->ar = dsd->ar ? dsd->ar * 2 : 1024;
    dsd->r = trealloc(struct range, dsd->r, dsd->ar);
    if (!dsd->r)
      return 0;
    if (dsd->rmeta) {
      dsd->rmeta = trealloc(unsigned, dsd->rmeta, dsd->ar);
      if (!dsd->rmeta)
        return 0;
    }
  }
  if (!dsd->nr)
    dsd->uniform = meta;
  else if (!dsd->rmeta && meta != dsd->uniform) {
    /* first range with a different value: materialise the per-range index */
    unsigned i;
    dsd->rmeta = trealloc(unsigned, NULL, dsd->ar);
    if (!dsd->rmeta)
      return 0;
    for (i = 0; i < dsd->nr; i++)
      dsd->rmeta[i] = dsd->uniform;
  }
  r = dsd->r + dsd->nr;
  r->lo = lo;
  r->hi = hi;
  if (dsd->rmeta)
    dsd->rmeta[dsd->nr] = meta;
  dsd->nr++;
  return 1;
}

/* Assign every address from *pos up to limit to the innermost open entry
 * (top of the stack), emitting ranges; excluded entries leave gaps. */
static int
ds_ip4set_fill(struct dsdata *dsd, unsigned *stack, unsigned *sn,
                 uint64_t *pos, uint64_t limit) {
  while (*pos <= limit) {
    const struct raw *t;
    uint64_t end;
    while (*sn && dsd->raw[stack[*sn - 1]].hi < *pos)
      (*sn)--;
    if (!*sn) {                 /* nothing covers [*pos, limit]: unlisted */
      *pos = limit + 1;
      return 1;
    }
    t = dsd->raw + stack[*sn - 1];
    end = t->hi < limit ? t->hi : limit;
    if (t->meta != META_EXCLUDED &&
        !ds_ip4set_emit(dsd, (ip4addr_t)*pos, (ip4addr_t)end, t->meta))
      return 0;
    *pos = end + 1;
  }
  return 1;
}

/* Flatten the (possibly nested or overlapping) input entries into disjoint
 * ranges: a sweep in start order with a stack of open entries. */
static int ds_ip4set_flatten(struct dsdata *dsd) {
  unsigned *stack = NULL;
  unsigned sn = 0, sa = 0, i;
  uint64_t pos = 0;
  int ok = 0;

  for (i = 0; i < dsd->nraw; i++) {
    const struct raw *e = dsd->raw + i;
    unsigned j = i, pick;
    /* a run of identical ranges: an exclusion wins, else the first line */
    while (j + 1 < dsd->nraw && dsd->raw[j + 1].lo == e->lo && dsd->raw[j + 1].hi == e->hi)
      j++;
    if (j > i) {
      dsd->ndups += j - i;
      for (pick = i; pick <= j; pick++)
        if (dsd->raw[pick].meta == META_EXCLUDED)
          break;
      if (pick > j)
        pick = i;
      e = dsd->raw + pick;
      i = j;
    }
    if (e->lo && !ds_ip4set_fill(dsd, stack, &sn, &pos, (uint64_t)e->lo - 1))
      goto done;
    /* entries that end before this one starts can never apply again; pop
     * them now or sequential, adjacent ranges would pile up on the stack */
    while (sn && dsd->raw[stack[sn - 1]].hi < e->lo)
      sn--;
    if (sn == sa) {
      sa = sa ? sa * 2 : 64;
      stack = trealloc(unsigned, stack, sa);
      if (!stack)
        goto done;
    }
    stack[sn++] = (unsigned)(e - dsd->raw);
  }
  if (!ds_ip4set_fill(dsd, stack, &sn, &pos, 0xffffffffu))
    goto done;
  ok = 1;
done:
  free(stack);
  return ok;
}

static int ds_ip4set_index(struct dsdata *dsd) {
  unsigned i, k = 0, bits = 0, n;
  if (dsd->nr >= 64)
    while (bits < 16 && (1u << (bits + 1)) <= dsd->nr / 2)
      bits++;
  dsd->idx_bits = bits;
  n = 1u << bits;
  dsd->idx = trealloc(unsigned, NULL, n + 1);
  if (!dsd->idx)
    return 0;
  for (i = 0; i < n; i++) {
    ip4addr_t base = bits ? (ip4addr_t)i << (32 - bits) : 0;
    while (k < dsd->nr && dsd->r[k].hi < base)
      k++;
    dsd->idx[i] = k;
  }
  dsd->idx[n] = dsd->nr;
  return 1;
}

static void ds_ip4set_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned long mem;

  if (!dsd->sorted)
    ds_ip4set_sort(dsd);
  if (!ds_ip4set_flatten(dsd) || !ds_ip4set_index(dsd)) {
    dslog(LOG_ERR, dsc, "out of memory flattening ranges");
    ds_ip4set_reset(dsd, 0);
    dsc->dsc_failed = 1;        /* loaddataset() fails the load */
    return;
  }
  dsd->hraw = dsd->nraw;
  free(dsd->raw);
  dsd->raw = NULL;
  dsd->nraw = dsd->araw = 0;
  SHRINK_ARRAY(struct range, dsd->r, dsd->nr, dsd->ar);
  if (dsd->rmeta) {
    unsigned *t = trealloc(unsigned, dsd->rmeta, dsd->nr);
    if (t)
      dsd->rmeta = t;
  }
  mem = (unsigned long)dsd->nr * (sizeof(struct range) + (dsd->rmeta ? sizeof(unsigned) : 0))
      + ((1ul << dsd->idx_bits) + 1) * sizeof(unsigned)
      + dsd->nmetas * sizeof(void *);
  dsloaded(dsc, "e=%u r=%u x=%u dups=%u v=%u%s mem=%luk",
           dsd->hraw, dsd->nr, dsd->nexcl, dsd->ndups, dsd->nmetas,
           dsd->sorted ? "" : " (sorted on load)", mem >> 10);
}

static const struct entry_meta *
ds_ip4set_find(const struct dsdata *dsd, ip4addr_t q) {
  unsigned lo, hi;
  if (!dsd->nr)
    return NULL;
  if (dsd->idx_bits) {
    unsigned b = q >> (32 - dsd->idx_bits);
    lo = dsd->idx[b];
    hi = dsd->idx[b + 1];
  }
  else {
    lo = 0;
    hi = dsd->nr;
  }
  if (hi >= dsd->nr)
    hi = dsd->nr - 1;
  /* first range with r.hi >= q (hi is sorted because ranges are disjoint) */
  while (lo < hi) {
    unsigned m = lo + (hi - lo) / 2;
    if (dsd->r[m].hi < q)
      lo = m + 1;
    else
      hi = m;
  }
  if (dsd->r[lo].lo <= q && q <= dsd->r[lo].hi)
    return dsd->metas[dsd->rmeta ? dsd->rmeta[lo] : dsd->uniform];
  return NULL;
}

static int
ds_ip4set_query(const struct dataset *ds, const struct dnsqinfo *qi,
                  struct dnspacket *pkt) {
  const struct entry_meta *meta;
  const char *subst = NULL;
  struct entry_action act;

  if (!qi->qi_ip4valid)
    return 0;
  check_query_overwrites(qi);

  meta = ds_ip4set_find(ds->ds_dsd, qi->qi_ip4);
  if (!meta || !meta->rr)
    return 0;

  act.allow = 1;
  act.delay_ms = 0;
  act.flags = 0;
  rbldnsd_apply_entry_params(pkt->p_peer, ds, qi, meta->params, &act);
  if (!act.allow)
    return 0;
  if (act.delay_ms > pkt->p_delay_ms)
    pkt->p_delay_ms = act.delay_ms;

  if (qi->qi_tflag & NSQUERY_TXT)
    subst = ip4atos(qi->qi_ip4);
  addrr_a_txt(pkt, qi->qi_tflag, meta->rr, subst, ds);
  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP
static void
ds_ip4set_dump(const struct dataset *ds,
                 const unsigned char UNUSED *unused_odn,
                 FILE *f) {
  const struct dsdata *dsd = ds->ds_dsd;
  unsigned i;
  for (i = 0; i < dsd->nr; i++) {
    const struct entry_meta *m =
      dsd->metas[dsd->rmeta ? dsd->rmeta[i] : dsd->uniform];
    dump_ip4range(dsd->r[i].lo, dsd->r[i].hi, m->rr, ds, f);
  }
}
#endif
