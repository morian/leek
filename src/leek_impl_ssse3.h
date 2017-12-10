#ifndef __LEEK_IMPL_SSSE3_H
# define __LEEK_IMPL_SSSE3_H
# pragma GCC target "ssse3"
# include <stdint.h>
# include <immintrin.h>

/* SSE: 4 x 32b lanes (128b of data in a single shot!) */
typedef __m128i vecx;

static inline vecx vecx_zero(void)
{
	return _mm_setzero_si128();
}

static inline vecx vecx_set(uint32_t x)
{
	return _mm_set_epi32(x, x, x, x);
}

static inline vecx vecx_load(const void *ptr)
{
	return _mm_loadu_si128(ptr);
}

static inline void vecx_store(void *ptr, vecx x)
{
	_mm_storeu_si128(ptr, x);
}

static inline vecx vecx_or(vecx x, vecx y)
{
	return _mm_or_si128(x, y);
}

static inline vecx vecx_xor(vecx x, vecx y)
{
	return _mm_xor_si128(x, y);
}

static inline vecx vecx_and(vecx x, vecx y)
{
	return _mm_and_si128(x, y);
}

static inline vecx vecx_anot(vecx x, vecx y)
{
	return _mm_andnot_si128(x, y);
}

static inline vecx vecx_add(vecx x, vecx y)
{
	return _mm_add_epi32(x, y);
}

static inline vecx vecx_shl(vecx x, int y)
{
	return _mm_slli_epi32(x, y);
}

static inline vecx vecx_rol(vecx x, int y)
{
	vecx a = vecx_shl(x, y);
	vecx b = _mm_srli_epi32(x, 32 - y);
	return vecx_or(a, b);
}

static inline vecx vecx_ror(vecx x, int y)
{
	vecx a = _mm_srli_epi32(x, y);
	vecx b = vecx_shl(x, 32 - y);
	return vecx_or(a, b);
}

static inline vecx vecx_bswap(vecx x)
{
	vecx mask =
		_mm_set_epi32(0x0c0d0e0fUL, 0x08090a0bUL, 0x04050607UL, 0x00010203UL);
	return _mm_shuffle_epi8(x, mask);
}

static inline vecx vecx_even_numbers(void)
{
	return _mm_set_epi32(6, 4, 2, 0);
}

/**
 * input rows:
 *   a1 b1 c1 d1
 *   a2 b2 c2 d2
 *   a3 b3 c3 d3
 *   a4 b4 c4 d4
 *
 * output rows:
 *   a1 a2 a3 a4
 *   b1 b2 b3 b4
 *   c1 c2 c3 c4
 *   d1 d2 d3 d4
 */
#define vecx_transpose(row0, row1, row2, row3)                          \
	do {                                                                  \
		__m128i __s0 = (row0), __s1 = (row1), __s2 = (row2), __s3 = (row3); \
		__m128i __t0 = _mm_unpacklo_epi32 (__s0, __s1);                     \
		__m128i __t1 = _mm_unpacklo_epi32 (__s2, __s3);                     \
		__m128i __t2 = _mm_unpackhi_epi32 (__s0, __s1);                     \
		__m128i __t3 = _mm_unpackhi_epi32 (__s2, __s3);                     \
		(row0) = _mm_unpacklo_epi64 (__t0, __t1);                           \
		(row1) = _mm_unpackhi_epi64 (__t0, __t1);                           \
		(row2) = _mm_unpacklo_epi64 (__t2, __t3);                           \
		(row3) = _mm_unpackhi_epi64 (__t2, __t3);                           \
	} while (0)

#define VECX_LANE_ORDER                         2
#define VECX_IMPL_NAME                    "SSSE3"
#define VECX_IMPL_ISA                     "ssse3"
#define VECX_IMPL_STRUCT          leek_impl_ssse3

#endif /* !__LEEK_IMPL_SSSE3_H */
