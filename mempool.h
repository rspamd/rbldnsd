/* memory pool #include file
 *
 * Arena allocator: allocate many small blocks, free all at once.
 */

#ifndef _MEMPOOL_H_INCLUDED
#define _MEMPOOL_H_INCLUDED

struct mempool_chunk;

/* Number of recent buffers mp_dmemdup() compares against. Zone values
 * (A+TXT RRs) usually come from a handful of distinct strings that alternate
 * in any order, so remembering only the last one is not enough. */
#define MP_DEDUP_SLOTS 16

struct mp_dedup_slot {
  const char *buf;                /* NULL: empty slot */
  unsigned len;
  unsigned hash;
};

struct mempool {
  struct mempool_chunk *mp_chunk; /* list of all chunks */
  unsigned mp_nallocs;            /* number of allocations */
  unsigned mp_datasz;             /* total bytes allocated */
  struct mp_dedup_slot mp_dedup[MP_DEDUP_SLOTS]; /* for mp_dmemdup() */
  unsigned mp_dedup_next;         /* next slot to replace */
};

void mp_init(struct mempool *mp);
void *mp_alloc(struct mempool *mp, unsigned size, int align);
#define mp_talloc(mp, type) ((type*)mp_alloc((mp), sizeof(type), 1))
void mp_free(struct mempool *mp);
char *mp_strdup(struct mempool *mp, const char *str);
void *mp_memdup(struct mempool *mp, const void *buf, unsigned len);
const char *mp_dstrdup(struct mempool *mp, const char *str);
const void *mp_dmemdup(struct mempool *mp, const void *buf, unsigned len);

#endif
