/*
 * dns_hash.h - Platform-optimized hash for DNS labels
 *
 * Copyright (C) 2019-2026 Vsevolod Stakhov
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 *
 * Compile-time dispatch:
 *   x86_64:  requires SSE4.2 (-msse4.2)
 *   aarch64: requires ARMv8.1+ CRC (-march=armv8.1-a or -march=armv8-a+crc)
 *   other:   FNV-1a fallback
 */

#ifndef DNS_HASH_H
#define DNS_HASH_H

#include <stdint.h>
#include <stddef.h>

/* Platform detection */
#if defined(__SSE4_2__) && defined(__x86_64__)
#  define DNS_HASH_CRC32_X86 1
#  include <nmmintrin.h>
#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
#  define DNS_HASH_CRC32_ARM 1
#  include <arm_acle.h>
#endif

/*
 * Safe unaligned memory access helpers.
 * DNS wire format data is not guaranteed to be aligned.
 * Using __builtin_memcpy allows the compiler to optimize
 * to native unaligned loads where supported.
 */
static inline uint64_t
dns_hash_read64(const void *p)
{
	uint64_t v;
	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

static inline uint32_t
dns_hash_read32(const void *p)
{
	uint32_t v;
	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

#if defined(DNS_HASH_CRC32_X86)

/*
 * x86_64 SSE4.2 CRC32-C implementation.
 * Uses Castagnoli polynomial via hardware instruction.
 */
static inline uint32_t
dns_label_hash(const unsigned char *data, size_t len)
{
	uint64_t crc = 0;

	/* Process 8 bytes at a time */
	while (len >= 8) {
		crc = _mm_crc32_u64(crc, dns_hash_read64(data));
		data += 8;
		len -= 8;
	}

	/* Process 4 bytes if remaining */
	if (len >= 4) {
		crc = _mm_crc32_u32((uint32_t)crc, dns_hash_read32(data));
		data += 4;
		len -= 4;
	}

	/* Remaining 1-3 bytes */
	while (len--) {
		crc = _mm_crc32_u8((uint32_t)crc, *data++);
	}

	return (uint32_t)crc;
}

#elif defined(DNS_HASH_CRC32_ARM)

/*
 * ARM64 CRC32-C implementation via ACLE.
 * Uses Castagnoli polynomial (same as Intel SSE4.2).
 * Requires ARMv8.1-A or ARMv8-A with +crc extension.
 */
static inline uint32_t
dns_label_hash(const unsigned char *data, size_t len)
{
	uint32_t crc = 0;

	/* Process 8 bytes at a time */
	while (len >= 8) {
		crc = __crc32cd(crc, dns_hash_read64(data));
		data += 8;
		len -= 8;
	}

	/* Process 4 bytes if remaining */
	if (len >= 4) {
		crc = __crc32cw(crc, dns_hash_read32(data));
		data += 4;
		len -= 4;
	}

	/* Remaining 1-3 bytes */
	while (len--) {
		crc = __crc32cb(crc, *data++);
	}

	return crc;
}

#else

/*
 * FNV-1a fallback for non-x86_64/non-ARM64 platforms.
 * Simple, well-tested hash with good distribution for short strings.
 * Used extensively in DNS implementations.
 */
static inline uint32_t
dns_label_hash(const unsigned char *data, size_t len)
{
	uint32_t hash = 2166136261u;  /* FNV offset basis */

	while (len--) {
		hash ^= *data++;
		hash *= 16777619u;        /* FNV prime */
	}

	return hash;
}

#endif /* platform selection */

#endif /* DNS_HASH_H */
