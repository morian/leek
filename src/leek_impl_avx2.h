#ifndef __LEEK_IMPL_AVX2_H
# define __LEEK_IMPL_AVX2_H
# include <stdint.h>
# include <immintrin.h>

/* AVX2: 8 x 32b lanes (256b of data in a single shot!) */
typedef __m256i vecx;

static inline vecx vecx_zero(void)
{
	return _mm256_setzero_si256();
}

static inline vecx vecx_set(uint32_t x)
{
	return _mm256_set_epi32(x, x, x, x, x, x, x, x);
}

static inline vecx vecx_load(const void *ptr)
{
	return _mm256_loadu_si256(ptr);
}

static inline void vecx_store(void *ptr, vecx x)
{
	_mm256_storeu_si256(ptr, x);
}

static inline vecx vecx_or(vecx x, vecx y)
{
	return _mm256_or_si256(x, y);
}

static inline vecx vecx_xor(vecx x, vecx y)
{
	return _mm256_xor_si256(x, y);
}

static inline vecx vecx_and(vecx x, vecx y)
{
	return _mm256_and_si256(x, y);
}

static inline vecx vecx_anot(vecx x, vecx y)
{
	return _mm256_andnot_si256(x, y);
}

static inline vecx vecx_add(vecx x, vecx y)
{
	return _mm256_add_epi32(x, y);
}

static inline vecx vecx_shl(vecx x, int y)
{
	return _mm256_slli_epi32(x, y);
}

static inline vecx vecx_rol(vecx x, int y)
{
	vecx a = vecx_shl(x, y);
	vecx b = _mm256_srli_epi32(x, 32 - y);
	return vecx_or(a, b);
}

static inline vecx vecx_ror(vecx x, int y)
{
	vecx a = _mm256_srli_epi32(x, y);
	vecx b = vecx_shl(x, 32 - y);
	return vecx_or(a, b);
}

static inline vecx vecx_bswap(vecx x)
{
	__m256i mask =
		_mm256_set_epi32(0x0c0d0e0fUL, 0x08090a0bUL, 0x04050607UL, 0x00010203UL,
		                 0x0c0d0e0fUL, 0x08090a0bUL, 0x04050607UL, 0x00010203UL);
	return _mm256_shuffle_epi8(x, mask);
}

static inline vecx vecx_even_numbers(void)
{
	return _mm256_set_epi32(14, 12, 10, 8, 6, 4, 2, 0);
}

/**
 * input rows:
 *   a1 b1 c1 d1 e1 f1 g1 h1
 *   a2 b2 c2 d2 e2 f2 g2 h2
 *   a3 b3 c3 d3 e3 f3 g3 h3
 *   a4 b4 c4 d4 e4 f4 g4 h4
 *
 * output rows:
 *   a1 a2 a3 a4 b1 b2 b3 b4
 *   c1 c2 c3 c4 d1 d2 d3 d4
 *   e1 e2 e3 e4 f1 f2 f3 f4
 *   g1 g2 g3 g4 h1 h2 h3 h4
 */
#define vecx_transpose(row0, row1, row2, row3)                          \
	do {                                                                  \
		__m256i __s0 = (row0), __s1 = (row1), __s2 = (row2), __s3 = (row3); \
		__m256i __t0 = _mm256_unpacklo_epi32 (__s0, __s1);                  \
		__m256i __t1 = _mm256_unpacklo_epi32 (__s2, __s3);                  \
		__m256i __t2 = _mm256_unpackhi_epi32 (__s0, __s1);                  \
		__m256i __t3 = _mm256_unpackhi_epi32 (__s2, __s3);                  \
		__s0 = _mm256_unpacklo_epi64 (__t0, __t1);                          \
		__s1 = _mm256_unpackhi_epi64 (__t0, __t1);                          \
		__s2 = _mm256_unpacklo_epi64 (__t2, __t3);                          \
		__s3 = _mm256_unpackhi_epi64 (__t2, __t3);                          \
		(row0) = _mm256_permute2x128_si256(__s0, __s1, 0x20);               \
		(row1) = _mm256_permute2x128_si256(__s2, __s3, 0x20);               \
		(row2) = _mm256_permute2x128_si256(__s0, __s1, 0x31);               \
		(row3) = _mm256_permute2x128_si256(__s2, __s3, 0x31);               \
	} while (0)


#define VECX_LANE_ORDER                         3
#define VECX_IMPL_NAME                     "AVX2"
#define VECX_IMPL_ISA                      "avx2"

/* Include macro expansion and generic SHA1 stuff here */
#include "leek_vecx_core.h"

#endif /* !__LEEK_IMPL_AVX2_H */
