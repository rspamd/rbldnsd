/* Regression: mp_alloc(..., align=1) must return suitably aligned memory
 * even after unaligned allocations (mp_strdup, mp_memdup) have left the
 * chunk's used offset at an arbitrary byte. Before the fix the position was
 * never aligned, only the size, so every struct allocated after a string
 * was misaligned; on x86-64 gcc -O3 emits aligned SSE memory operands for
 * such structs (btrie), which raise #GP and kill the daemon with SIGSEGV as
 * soon as the first ip6trie/ip4trie dataset of a combined zone loads. */
#include "mempool.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WANT_ALIGN 16u          /* malloc's guarantee and what SSE needs */
#define MAX_ALLOCS 4096

void *emalloc(size_t size) {
  void *p = malloc(size);
  assert(p != NULL);
  return p;
}

struct block {
  unsigned char *ptr;
  unsigned len;
  unsigned char fill;
};

static struct block blocks[MAX_ALLOCS];
static unsigned nblocks;

static void remember(void *p, unsigned len, unsigned char fill) {
  assert(nblocks < MAX_ALLOCS);
  memset(p, fill, len);
  blocks[nblocks].ptr = p;
  blocks[nblocks].len = len;
  blocks[nblocks].fill = fill;
  nblocks++;
}

/* Every block still holds its own fill byte: no two allocations overlap. */
static void check_no_overlap(void) {
  unsigned i, j;
  for (i = 0; i < nblocks; i++)
    for (j = 0; j < blocks[i].len; j++)
      assert(blocks[i].ptr[j] == blocks[i].fill);
}

static unsigned misaligned(const void *p) {
  return (unsigned)((uintptr_t)p % WANT_ALIGN);
}

struct two_pointers { void *a; void *b; };

int main(void) {
  struct mempool mp;
  unsigned size, i, unaligned_bytes = 0;
  unsigned char fill = 1;

  mp_init(&mp);

  /* 1. An aligned allocation after an unaligned one of every small size.
   * The pre-fix allocator only ever got this right by accident. */
  for (size = 1; size <= 64; size++) {
    void *s = mp_alloc(&mp, size, 0);
    void *a;
    assert(s != NULL);
    remember(s, size, fill++);
    unaligned_bytes += size;
    a = mp_alloc(&mp, sizeof(struct two_pointers), 1);
    assert(a != NULL);
    if (misaligned(a)) {
      printf("FAIL: aligned allocation at %p is %u mod %u after an unaligned "
             "allocation of %u bytes\n", a, misaligned(a), WANT_ALIGN, size);
      return 1;
    }
    remember(a, sizeof(struct two_pointers), fill++);
  }

  /* 2. The same through the string helpers the zone loaders actually use. */
  for (i = 0; i < 64; i++) {
    char text[80];
    void *a;
    memset(text, 'x', i + 1);
    text[i + 1] = '\0';
    assert(mp_strdup(&mp, text) != NULL);
    assert(mp_memdup(&mp, text, i + 1) != NULL);
    assert(mp_dstrdup(&mp, text) != NULL);
    a = mp_talloc(&mp, struct two_pointers);
    assert(a != NULL);
    if (misaligned(a)) {
      printf("FAIL: mp_talloc at %p is %u mod %u after mp_strdup/mp_memdup "
             "of %u bytes\n", a, misaligned(a), WANT_ALIGN, i + 1);
      return 1;
    }
    remember(a, sizeof(struct two_pointers), fill++);
  }

  /* 3. Aligned allocations of every size up to and beyond the dedicated-chunk
   * threshold (MEMPOOL_CHUNKSIZE / 2 = 32K) stay aligned, with odd-sized
   * unaligned allocations interleaved. */
  for (size = 1; size <= 40000; size = size * 2 + 1) {
    void *a, *s;
    s = mp_alloc(&mp, 3, 0);
    assert(s != NULL);
    remember(s, 3, fill++);
    a = mp_alloc(&mp, size, 1);
    assert(a != NULL);
    if (misaligned(a)) {
      printf("FAIL: aligned allocation of %u bytes at %p is %u mod %u\n",
             size, a, misaligned(a), WANT_ALIGN);
      return 1;
    }
    remember(a, size, fill++);
  }

  check_no_overlap();

  printf("mempool alignment passed: %u allocations, %u unaligned bytes "
         "interleaved, every aligned block %u-byte aligned, no overlap\n",
         nblocks, unaligned_bytes, WANT_ALIGN);
  mp_free(&mp);
  return 0;
}
