/*
 * dns_simd.h - SIMD-optimized DNS string operations
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
 *   x86_64:  uses SSE2 (baseline for x86_64)
 *   aarch64: uses NEON (baseline for ARM64)
 *   other:   lookup table fallback
 */

#ifndef DNS_SIMD_H
#define DNS_SIMD_H

#include <stddef.h>
#include "dns.h"

/* Platform detection - SSE2 is baseline for x86_64, NEON for ARM64 */
#if defined(__x86_64__) || defined(_M_X64)
#  define DNS_SIMD_X86 1
#  include <emmintrin.h>  /* SSE2 */
#elif defined(__aarch64__) || defined(_M_ARM64)
#  define DNS_SIMD_ARM 1
#  include <arm_neon.h>
#endif

#if defined(DNS_SIMD_X86)

/*
 * SSE2 lowercase: process 16 bytes at a time.
 * Algorithm: check if byte is in 'A'-'Z' range, XOR with 0x20 if so.
 */
static inline void
dns_simd_lowercase(unsigned char *dst, const unsigned char *src, size_t len)
{
	const __m128i upper_a_minus_1 = _mm_set1_epi8('A' - 1);  /* 0x40 */
	const __m128i upper_z_plus_1 = _mm_set1_epi8('Z' + 1);   /* 0x5B */
	const __m128i case_bit = _mm_set1_epi8(0x20);

	/* Process 16 bytes at a time */
	while (len >= 16) {
		__m128i chunk = _mm_loadu_si128((const __m128i *)src);

		/* Find bytes > 'A'-1 AND < 'Z'+1 (i.e., 'A' <= byte <= 'Z') */
		__m128i gt_a = _mm_cmpgt_epi8(chunk, upper_a_minus_1);
		__m128i lt_z = _mm_cmplt_epi8(chunk, upper_z_plus_1);
		__m128i is_upper = _mm_and_si128(gt_a, lt_z);

		/* XOR with 0x20 only for uppercase letters */
		__m128i to_add = _mm_and_si128(is_upper, case_bit);
		__m128i lowered = _mm_xor_si128(chunk, to_add);

		_mm_storeu_si128((__m128i *)dst, lowered);

		src += 16;
		dst += 16;
		len -= 16;
	}

	/* Handle remaining bytes with lookup table */
	while (len--) {
		*dst++ = dns_lc_table[*src++];
	}
}

/*
 * In-place lowercase variant.
 */
static inline void
dns_simd_lowercase_inplace(unsigned char *data, size_t len)
{
	dns_simd_lowercase(data, data, len);
}

#elif defined(DNS_SIMD_ARM)

/*
 * ARM NEON lowercase: process 16 bytes at a time.
 * Uses unsigned comparison which is simpler for ASCII range.
 */
static inline void
dns_simd_lowercase(unsigned char *dst, const unsigned char *src, size_t len)
{
	const uint8x16_t upper_a = vdupq_n_u8('A');
	const uint8x16_t upper_z = vdupq_n_u8('Z');
	const uint8x16_t case_bit = vdupq_n_u8(0x20);

	/* Process 16 bytes at a time */
	while (len >= 16) {
		uint8x16_t chunk = vld1q_u8(src);

		/* Find bytes >= 'A' AND <= 'Z' */
		uint8x16_t ge_a = vcgeq_u8(chunk, upper_a);
		uint8x16_t le_z = vcleq_u8(chunk, upper_z);
		uint8x16_t is_upper = vandq_u8(ge_a, le_z);

		/* XOR with 0x20 only for uppercase letters */
		uint8x16_t to_add = vandq_u8(is_upper, case_bit);
		uint8x16_t lowered = veorq_u8(chunk, to_add);

		vst1q_u8(dst, lowered);

		src += 16;
		dst += 16;
		len -= 16;
	}

	/* Handle remaining bytes with lookup table */
	while (len--) {
		*dst++ = dns_lc_table[*src++];
	}
}

static inline void
dns_simd_lowercase_inplace(unsigned char *data, size_t len)
{
	dns_simd_lowercase(data, data, len);
}

#else

/*
 * Scalar fallback using lookup table.
 */
static inline void
dns_simd_lowercase(unsigned char *dst, const unsigned char *src, size_t len)
{
	while (len--) {
		*dst++ = dns_lc_table[*src++];
	}
}

static inline void
dns_simd_lowercase_inplace(unsigned char *data, size_t len)
{
	while (len--) {
		*data = dns_lc_table[*data];
		data++;
	}
}

#endif /* platform selection */

#endif /* DNS_SIMD_H */
