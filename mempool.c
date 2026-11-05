/* memory pool implementation
 *
 * Arena allocator for bulk allocation/deallocation.
 * All memory is freed at once via mp_free().
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mempool.h"

/* Total size of a regular chunk, header included, so that each chunk is
 * exactly one 64K allocation: jemalloc (and macOS malloc with 16K pages)
 * would round 64K plus the header up to an 80K size class. */
#define MEMPOOL_CHUNKSIZE (64 * 1024)
/* Aligned allocations must be 16-byte aligned: gcc -O3 emits aligned SSE
 * stores (movaps) for 16-byte struct copies of btrie nodes allocated from
 * this pool, and those fault on x86-64 when the pointer is only 8-aligned.
 * Alignment is applied to the address itself (see mp_carve()): neither the
 * chunk header size (12 bytes on 32-bit) nor malloc()'s alignment (8 on
 * armhf glibc) is the same everywhere, so offsets alone cannot be trusted. */
#define ALIGN_SIZE 16
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
  unsigned used;      /* bytes used in total (front + back) */
  unsigned front;     /* bytes used from the start by unaligned allocations */
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
  c->front = 0;
  mp->mp_chunk = c;
  return c;
}

/*
 * Carve alloc_size bytes from the free space in the middle of a chunk.
 * Unaligned allocations (strings, RR data) grow upward from the start and
 * aligned ones (structs) grow downward from the end, so the two never
 * interleave: aligned sizes are multiples of ALIGN_SIZE, and only the first
 * aligned allocation in a chunk may need padding to round its address down.
 * Returns NULL if it does not fit.
 */
static char *mp_carve(struct mempool_chunk *c, unsigned alloc_size, int align) {
  unsigned free_space = c->capacity - c->used;
  unsigned pad;
  char *ptr;

  if (free_space < alloc_size)
    return NULL;
  if (!align) {
    /* unaligned allocations grow upward from the start of the buffer */
    ptr = c->buf + c->front;
    c->front += alloc_size;
    c->used += alloc_size;
    return ptr;
  }
  /* aligned allocations grow downward from the end of the buffer */
  ptr = c->buf + c->capacity - (c->used - c->front) - alloc_size;
  pad = (unsigned)((uintptr_t)ptr & ALIGN_MASK);
  if (free_space - alloc_size < pad)
    return NULL;
  c->used += alloc_size + pad;
  return ptr - pad;
}

void *mp_alloc(struct mempool *mp, unsigned size, int align) {
  struct mempool_chunk *c;
  unsigned alloc_size;
  char *ptr = NULL;

  if (align)
    alloc_size = ALIGN_UP(size);
  else
    alloc_size = size;

  /* Large allocation: dedicated chunk, with room to align its address */
  if (alloc_size >= MEMPOOL_CHUNKSIZE / 2) {
    c = mp_newchunk(mp, align ? alloc_size + ALIGN_MASK : alloc_size);
    if (!c)
      return NULL;
    return mp_carve(c, alloc_size, align);
  }

  /* Try to fit in existing chunk */
  for (c = mp->mp_chunk; c; c = c->next) {
    ptr = mp_carve(c, alloc_size, align);
    if (ptr)
      break;
  }

  /* Need new chunk; always fits since alloc_size < MEMPOOL_CHUNKSIZE / 2 */
  if (!ptr) {
    c = mp_newchunk(mp, MEMPOOL_CHUNKSIZE - sizeof(struct mempool_chunk));
    if (!c)
      return NULL;
    ptr = mp_carve(c, alloc_size, align);
  }

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
