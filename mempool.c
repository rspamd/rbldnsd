/* memory pool implementation
 *
 * Arena allocator for bulk allocation/deallocation.
 * All memory is freed at once via mp_free().
 */

#include <stdlib.h>
#include <string.h>
#include "mempool.h"

#define MEMPOOL_CHUNKSIZE (64 * 1024)
#define ALIGN_SIZE sizeof(void*)
#define ALIGN_MASK (ALIGN_SIZE - 1)
#define ALIGN_UP(x) (((x) + ALIGN_MASK) & ~ALIGN_MASK)

void *emalloc(size_t size);

/*
 * Single chunk type for all allocations.
 * Metadata at front, buffer follows via flexible array member.
 */
struct mempool_chunk {
  struct mempool_chunk *next;
  unsigned capacity;  /* total buffer size */
  unsigned used;      /* bytes used from end of buffer */
  char buf[];         /* flexible array member */
};

void mp_init(struct mempool *mp) {
  mp->mp_chunk = NULL;
  mp->mp_nallocs = 0;
  mp->mp_datasz = 0;
  mp->mp_lastbuf = NULL;
  mp->mp_lastlen = 0;
}

/*
 * Allocate a new chunk with given buffer capacity.
 */
static struct mempool_chunk *mp_newchunk(struct mempool *mp, unsigned capacity) {
  struct mempool_chunk *c = emalloc(sizeof(*c) + capacity);
  if (!c)
    return NULL;
  c->next = mp->mp_chunk;
  c->capacity = capacity;
  c->used = 0;
  mp->mp_chunk = c;
  return c;
}

void *mp_alloc(struct mempool *mp, unsigned size, int align) {
  struct mempool_chunk *c;
  unsigned alloc_size;
  char *ptr;

  if (align)
    alloc_size = ALIGN_UP(size);
  else
    alloc_size = size;

  /* Large allocation: dedicated chunk */
  if (alloc_size >= MEMPOOL_CHUNKSIZE / 2) {
    c = mp_newchunk(mp, alloc_size);
    if (!c)
      return NULL;
    c->used = alloc_size;
    return c->buf;
  }

  /* Try to fit in existing chunk */
  for (c = mp->mp_chunk; c; c = c->next) {
    unsigned free_space = c->capacity - c->used;
    if (free_space >= alloc_size) {
      /* Allocate from end of buffer (grows downward for alignment) */
      ptr = c->buf + c->capacity - c->used - alloc_size;
      c->used += alloc_size;
      mp->mp_nallocs++;
      mp->mp_datasz += size;
      return ptr;
    }
  }

  /* Need new chunk */
  c = mp_newchunk(mp, MEMPOOL_CHUNKSIZE);
  if (!c)
    return NULL;

  ptr = c->buf + c->capacity - alloc_size;
  c->used = alloc_size;
  mp->mp_nallocs++;
  mp->mp_datasz += size;
  return ptr;
}

void mp_free(struct mempool *mp) {
  struct mempool_chunk *c, *next;
  for (c = mp->mp_chunk; c; c = next) {
    next = c->next;
    free(c);
  }
  mp_init(mp);
}

void *mp_memdup(struct mempool *mp, const void *buf, unsigned len) {
  void *b = mp_alloc(mp, len, 0);
  if (b)
    memcpy(b, buf, len);
  return b;
}

char *mp_strdup(struct mempool *mp, const char *str) {
  return (char*)mp_memdup(mp, str, strlen(str) + 1);
}

/*
 * Deduplicating memdup/strdup: returns existing buffer if
 * content matches the last allocation (simple optimization
 * for repeated strings during parsing).
 */
const void *mp_dmemdup(struct mempool *mp, const void *buf, unsigned len) {
  if (mp->mp_lastlen == len && memcmp(mp->mp_lastbuf, buf, len) == 0)
    return mp->mp_lastbuf;

  buf = mp_memdup(mp, buf, len);
  if (buf) {
    mp->mp_lastbuf = buf;
    mp->mp_lastlen = len;
  }
  return buf;
}

const char *mp_dstrdup(struct mempool *mp, const char *str) {
  return (const char*)mp_dmemdup(mp, str, strlen(str) + 1);
}
