#ifndef __LEEK_IMPL_AVX512_H
# define __LEEK_IMPL_AVX512_H
# pragma GCC target "avx512bw"
# include <stdint.h>
# include <immintrin.h>

/* AVX512: 16 x 32b lanes (512b of data in a single shot!) */
typedef __m512i vecx;

static inline vecx vecx_zero(void)
{
	return _mm512_setzero_si512();
}

static inline vecx vecx_set(uint32_t x)
{
	return _mm512_set_epi32(x, x, x, x, x, x, x, x,
	                        x, x, x, x, x, x, x, x);
}

static inline vecx vecx_load(const void *ptr)
{
	return _mm512_loadu_si512(ptr);
}

static inline void vecx_store(void *ptr, vecx x)
{
	_mm512_storeu_si512(ptr, x);
}

static inline vecx vecx_or(vecx x, vecx y)
{
	return _mm512_or_si512(x, y);
}

static inline vecx vecx_xor(vecx x, vecx y)
{
	return _mm512_xor_si512(x, y);
}

static inline vecx vecx_and(vecx x, vecx y)
{
	return _mm512_and_si512(x, y);
}

static inline vecx vecx_anot(vecx x, vecx y)
{
	return _mm512_andnot_si512(x, y);
}

static inline vecx vecx_add(vecx x, vecx y)
{
	return _mm512_add_epi32(x, y);
}

static inline vecx vecx_shl(vecx x, int y)
{
	return _mm512_slli_epi32(x, y);
}

static inline vecx vecx_rol(vecx x, int y)
{
	return _mm512_rol_epi32(x, y);
}

static inline vecx vecx_ror(vecx x, int y)
{
	return _mm512_ror_epi32(x, y);
}

static inline vecx vecx_bswap(vecx x)
{
	/* This instruction requires support for AVX-512BW extension (on slylake xeons).
	 * This means that this will *NOT* work on KNL targets and requires GCC 5 to compile.
	 * It is possible however to emulate it using 2 AVX2 256b equivalent instructions.
	 * Choice have been made to prefer AVX-512BW implementation **/
	vecx mask =
		_mm512_set_epi32(0x3c3d3e3f, 0x38393a3b, 0x34353637, 0x30313233,
		                 0x2c2d2e2f, 0x28292a2b, 0x24252627, 0x20212223,
		                 0x1c1d1e1f, 0x18191a1b, 0x14151617, 0x10111213,
		                 0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
	return _mm512_shuffle_epi8(x, mask);
}

static inline vecx vecx_even_numbers(void)
{
	return _mm512_set_epi32(30, 28, 26, 24, 22, 20, 18, 16,
	                        14, 12, 10,  8,  6,  4,  2,  0);
}

/**
 * input rows:
 *   a1 b1 c1 d1 e1 f1 g1 h1 i1 j1 k1 l1 m1 n1 o1 p1
 *   a2 b2 c2 d2 e2 f2 g2 h2 i2 j2 k2 l2 m2 n2 o2 p2
 *   a3 b3 c3 d3 e3 f3 g3 h3 i3 j3 k3 l3 m3 n3 o3 p3
 *   a4 b4 c4 d4 e4 f4 g4 h4 i4 j4 k4 l4 m4 n4 o4 p4
 *
 * output rows:
 *   a1 a2 a3 a4 b1 b2 b3 b4 c1 c2 c3 c4 d1 d2 d3 d4
 *   e1 e2 e3 e4 f1 f2 f3 f4 g1 g2 g3 g4 h1 h2 h3 h4
 *   i1 i2 i3 i4 j1 j2 j3 j4 k1 k2 k3 k4 l1 l2 l3 l4
 *   m1 m2 m3 m4 n1 n2 n3 n4 o1 o2 o3 o4 p1 p2 p3 p4
 */
#define vecx_transpose(row0, row1, row2, row3)                              \
	do {                                                                      \
		vecx __idx0 = _mm512_set_epi64(0xd, 0xc, 0x5, 0x4, 0x9, 0x8, 0x1, 0x0); \
		vecx __idx1 = _mm512_set_epi64(0x7, 0x6, 0xf, 0xe, 0x3, 0x2, 0xb, 0xa); \
		vecx __idx2 = _mm512_set_epi64(0xb, 0xa, 0x9, 0x8, 0x3, 0x2, 0x1, 0x0); \
		vecx __idx3 = _mm512_set_epi64(0xf, 0xe, 0xd, 0xc, 0x7, 0x6, 0x5, 0x4); \
		__m512i __s0 = (row0), __s1 = (row1), __s2 = (row2), __s3 = (row3);     \
		__m512i __t0 = _mm512_unpacklo_epi32 (__s0, __s1);                      \
		__m512i __t1 = _mm512_unpacklo_epi32 (__s2, __s3);                      \
		__m512i __t2 = _mm512_unpackhi_epi32 (__s0, __s1);                      \
		__m512i __t3 = _mm512_unpackhi_epi32 (__s2, __s3);                      \
		__s0 = _mm512_unpacklo_epi64 (__t0, __t1);                              \
		__s1 = _mm512_unpackhi_epi64 (__t0, __t1);                              \
		__s2 = _mm512_unpacklo_epi64 (__t2, __t3);                              \
		__s3 = _mm512_unpackhi_epi64 (__t2, __t3);                              \
		__t0 = _mm512_permutex2var_epi64(__s0, __idx0, __s1);                   \
		__t1 = _mm512_permutex2var_epi64(__s1, __idx1, __s0);                   \
		__t2 = _mm512_permutex2var_epi64(__s2, __idx0, __s3);                   \
		__t3 = _mm512_permutex2var_epi64(__s3, __idx1, __s2);                   \
		(row0) = _mm512_permutex2var_epi64(__t0, __idx2, __t2);                 \
		(row1) = _mm512_permutex2var_epi64(__t1, __idx2, __t3);                 \
		(row2) = _mm512_permutex2var_epi64(__t0, __idx3, __t2);                 \
		(row3) = _mm512_permutex2var_epi64(__t1, __idx3, __t3);                 \
	} while (0)


#define VECX_LANE_ORDER                           4
#define VECX_IMPL_NAME                     "AVX512"
#define VECX_IMPL_ISA                    "avx512bw"

/* This very dirty thing is necessary as GCC 5 does not recognize avx512bw
 * as a valid CPU option (but accepts to compile with it as a target...).
 * For now let's assume that avx512f is a sufficient discriminant
 * (it only affects KNL platforms when using GCC 5).
 * Please note that GCC 4.9 has no support for avx512bw */
#ifdef __GNUC__
# include <features.h>
# if !__GNUC_PREREQ(6,0)
#  undef VECX_IMPL_ISA
#  define VECX_IMPL_ISA "avx512f"
# endif
#endif

#endif /* !__LEEK_IMPL_AVX512_H */
