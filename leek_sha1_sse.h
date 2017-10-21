#ifndef __LEEK_SHA1_AVX2_H
# define __LEEK_SHA1_AVX2_H
# include <stdint.h>
# include <immintrin.h>

# include "leek_vec_common.h"
# define __hot     __attribute__((hot))

typedef __m128i vec4;


static inline vec4 vec4_zero(void)
{
	return _mm_setzero_si128();
}

static inline vec4 vec4_set(uint32_t x)
{
	return _mm_set_epi32(x, x, x, x);
}

static inline vec4 vec4_load(const void *ptr)
{
	return _mm_loadu_si128(ptr);
}

static inline void vec4_store(void *ptr, vec4 x)
{
	_mm_storeu_si128(ptr, x);
}

static inline vec4 vec4_or(vec4 x, vec4 y)
{
	return _mm_or_si128(x, y);
}

static inline vec4 vec4_xor(vec4 x, vec4 y)
{
	return _mm_xor_si128(x, y);
}

static inline vec4 vec4_and(vec4 x, vec4 y)
{
	return _mm_and_si128(x, y);
}

static inline vec4 vec4_anot(vec4 x, vec4 y)
{
	return _mm_andnot_si128(x, y);
}

static inline vec4 vec4_add(vec4 x, vec4 y)
{
	return _mm_add_epi32(x, y);
}

static inline vec4 vec4_shl(vec4 x, int y)
{
	return _mm_slli_epi32(x, y);
}

static inline vec4 vec4_rol(vec4 x, int y)
{
	vec4 a = vec4_shl(x, y);
	vec4 b = _mm_srli_epi32(x, 32 - y);
	return vec4_or(a, b);
}

static inline vec4 vec4_ror(vec4 x, int y)
{
	vec4 a = _mm_srli_epi32(x, y);
	vec4 b = vec4_shl(x, 32 - y);
	return vec4_or(a, b);
}

static inline vec4 vec4_bswap(vec4 x)
{
	vec4 mask =
		_mm_set_epi32(0x0c0d0e0fUL, 0x08090a0bUL, 0x04050607UL, 0x00010203UL);
	return _mm_shuffle_epi8(x, mask);
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
#define vec4_transpose_4x32(row0, row1, row2, row3)                     \
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


#define vec4_add3(a, ...) vec4_add(a, vec4_add(__VA_ARGS__))
#define vec4_add4(a, ...) vec4_add(a, vec4_add3(__VA_ARGS__))
#define vec4_add5(a, ...) vec4_add(a, vec4_add4(__VA_ARGS__))
#define vec4_xor2(a, ...) vec4_xor(a, __VA_ARGS__)
#define vec4_xor3(a, ...) vec4_xor(a, vec4_xor2(__VA_ARGS__))
#define vec4_xor4(a, ...) vec4_xor(a, vec4_xor3(__VA_ARGS__))

#define vec4_F1(x, y, z) vec4_or(vec4_and(x, y), vec4_anot(x, z))
#define vec4_F2(x, y, z) vec4_xor3(x, y, z)
#define vec4_F3(x, y, z) vec4_or(vec4_and(x, y), vec4_and(z, vec4_xor(x, y)))
#define vec4_F4(x, y, z) vec4_xor3(x, y, z)


/** Original round **/
#define vec4_W(x)   W[(x) & 15]         /* W is our internal working buffer name */
#define vec4_SRC(x) vec4_bswap(in[x])   /* in is our input data name */
#define vec4_MIX(x) vec4_rol(vec4_xor4(vec4_W(x + 13), vec4_W(x + 8), vec4_W(x + 2), vec4_W(x)), 1)

#define vec4_ROUND(f, s, x, a, b, c, d, e, k)                       \
	do{                                                               \
		vec4 tmp = s(x);                                                \
		vec4_W(x) = tmp;                                                \
		e = vec4_add5(e, tmp, vec4_rol(a, 5), f(b, c, d), vec4_set(k)); \
		b = vec4_ror(b, 2);                                             \
	} while (0)


/** Optimized rounds **/
#define vec4_LDW(x) W[(x)]              /* Load pre-computed word */

#define vec4_MX1(x) vec4_rol(         (W[(x)-3]                                ), 1)
#define vec4_MX3(x) vec4_rol(vec4_xor2(W[(x)-3], W[(x)-8]                      ), 1)
#define vec4_MX7(x) vec4_rol(vec4_xor3(W[(x)-3], W[(x)-8], W[(x)-14]           ), 1)
#define vec4_MX9(x) vec4_rol(vec4_xor2(W[(x)-3],                      W[(x)-16]), 1)
#define vec4_MXC(x) vec4_rol(vec4_xor2(                    W[(x)-14], W[(x)-16]), 1)
#define vec4_MXF(x) vec4_rol(vec4_xor4(W[(x)-3], W[(x)-8], W[(x)-14], W[(x)-16]), 1)


/* Optimized general round */
#define vec4_ROUND_O(f, s, x, a, b, c, d, e, k)                     \
	do{                                                               \
		vec4 tmp = s(x);                                                \
		W[(x)] = tmp;                                                   \
		e = vec4_add5(e, tmp, vec4_rol(a, 5), f(b, c, d), vec4_set(k)); \
		b = vec4_ror(b, 2);                                             \
	} while (0)

/* Final rounds / no store */
#define vec4_ROUND_F(f, s, x, a, b, c, d, e, k)                     \
	do{                                                               \
		vec4 tmp = s(x);                                                \
		e = vec4_add5(e, tmp, vec4_rol(a, 5), f(b, c, d), vec4_set(k)); \
		b = vec4_ror(b, 2);                                             \
	} while (0)

/* NULL data / no load & store */
#define vec4_ROUND_E(f, x, a, b, c, d, e, k)                        \
	do{                                                               \
		e = vec4_add4(e, vec4_rol(a, 5), f(b, c, d), vec4_set(k));      \
		b = vec4_ror(b, 2);                                             \
	} while (0)


#define byte_mask(x)  ((1 << (8 * (x))) - 1)


union vec_rawaddr {
	uint8_t buffer[VEC_RAWADDR_LEN];
	union leek_rawaddr addr;
};


struct leek_sha1 {
	/* Internal state for 4 SHA1 blocks (update only) */
	uint8_t block[4 * VEC_SHA1_BLOCK_SIZE];

	/* Where the exponent is located (MSB) */
	/* This also sets the number of static rounds */
	unsigned int expo_round;
	/* Where the exponent starts located in the last 32b word (0 to 3)*/
	unsigned int expo_pos;

	/* Hash state before last block */
	vec4 H[5];

	/* Base exponent snapshot (little-endian, High, Low) */
	vec4 vexpo[2];

	/* Pre-computed values (post stage 1) */
	vec4 __cache_align PH[5]; /* Values a, b, c, d, e */

	vec4 PW_C00; /* Static word 0 */
	vec4 PW_C01; /* Sttati word 1 */
	vec4 PW_C03; /* Static (stage 2) word 3 (exponent LSBs) */
	vec4 PW_C15; /* W word for cycle 15 (hash size) */

	vec4 PA_C03; /* 'add' pre-compute for cycle 3 (post stage 1) */

	/* Final resulting addresses (hashes) */
	union vec_rawaddr  R[4];
};

#endif /* !__LEEK_SHA1_AVX2_H */
