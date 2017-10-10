#ifndef __LEEK_SHA1_AVX2_H
# define __LEEK_SHA1_AVX2_H
# include <stdint.h>
# include <immintrin.h>

# include "leek_vec_common.h"
# define __hot     __attribute__((hot))

typedef __m256i vec8;


static inline vec8 vec8_zero(void)
{
	return _mm256_setzero_si256();
}

static inline vec8 vec8_set(uint32_t x)
{
	return _mm256_set_epi32(x, x, x, x, x, x, x, x);
}

static inline vec8 vec8_load(const void *ptr)
{
	return _mm256_loadu_si256(ptr);
}

static inline void vec8_store(void *ptr, vec8 x)
{
	_mm256_storeu_si256(ptr, x);
}

static inline vec8 vec8_or(vec8 x, vec8 y)
{
	return _mm256_or_si256(x, y);
}

static inline vec8 vec8_xor(vec8 x, vec8 y)
{
	return _mm256_xor_si256(x, y);
}

static inline vec8 vec8_and(vec8 x, vec8 y)
{
	return _mm256_and_si256(x, y);
}

static inline vec8 vec8_anot(vec8 x, vec8 y)
{
	return _mm256_andnot_si256(x, y);
}

static inline vec8 vec8_add(vec8 x, vec8 y)
{
	return _mm256_add_epi32(x, y);
}

static inline vec8 vec8_shl(vec8 x, int y)
{
	return _mm256_slli_epi32(x, y);
}

static inline vec8 vec8_rol(vec8 x, int y)
{
	vec8 a = vec8_shl(x, y);
	vec8 b = _mm256_srli_epi32(x, 32 - y);
	return vec8_or(a, b);
}

static inline vec8 vec8_ror(vec8 x, int y)
{
	vec8 a = _mm256_srli_epi32(x, y);
	vec8 b = vec8_shl(x, 32 - y);
	return vec8_or(a, b);
}

static inline vec8 vec8_bswap(vec8 x)
{
	__m256i mask =
		_mm256_set_epi32(0x0c0d0e0fUL, 0x08090a0bUL, 0x04050607UL, 0x00010203UL,
		                 0x0c0d0e0fUL, 0x08090a0bUL, 0x04050607UL, 0x00010203UL);
	return _mm256_shuffle_epi8(x, mask);
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
#define vec8_transpose_8x32(row0, row1, row2, row3)                     \
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


#define vec8_add3(a, ...) vec8_add(a, vec8_add(__VA_ARGS__))
#define vec8_add4(a, ...) vec8_add(a, vec8_add3(__VA_ARGS__))
#define vec8_add5(a, ...) vec8_add(a, vec8_add4(__VA_ARGS__))
#define vec8_xor3(a, ...) vec8_xor(a, vec8_xor(__VA_ARGS__))
#define vec8_xor4(a, ...) vec8_xor(a, vec8_xor3(__VA_ARGS__))

#define vec8_F1(x, y, z) vec8_or(vec8_and(x, y), vec8_anot(x, z))
#define vec8_F2(x, y, z) vec8_xor3(x, y, z)
#define vec8_F3(x, y, z) vec8_or(vec8_and(x, y), vec8_and(z, vec8_xor(x, y)))
#define vec8_F4(x, y, z) vec8_xor3(x, y, z)

#define vec8_W(x)   W[(x) & 15]         /* W is our internal working buffer name */
#define vec8_SRC(x) vec8_bswap(in[x])   /* in is our input data name */
#define vec8_EXP(x) vexpo[(x) - 2]      /* vexpo is our input vector */
#define vec8_END(x) vsize               /* vector of the last input word (hash size) */
#define vec8_MIX(x) vec8_rol(vec8_xor4(vec8_W(x + 13), vec8_W(x + 8), vec8_W(x + 2), vec8_W(x)), 1)

/* sub-mixes with known values */
#define vec8_MX0(x) vec8_zero()
/* TODO */
#define vec8_MX7(x) vec8_MIX(x)

#define vec8_ROUND(f, s, x, a, b, c, d, e, k)                       \
	do{                                                               \
		vec8 tmp = s(x);                                                \
		vec8_W(x) = tmp;                                                \
		e = vec8_add5(e, tmp, vec8_rol(a, 5), f(b, c, d), vec8_set(k)); \
		b = vec8_ror(b, 2);                                             \
	} while (0)

/* When loading empty data words (0) */
#define vec8_ROUND_E(f, x, a, b, c, d, e, k)                        \
	do{                                                               \
		vec8_W(x) = vec8_zero();                                        \
		e = vec8_add4(e, vec8_rol(a, 5), f(b, c, d), vec8_set(k));      \
		b = vec8_ror(b, 2);                                             \
	} while (0)

#define byte_mask(x)  ((1 << (8 * (x))) - 1)


union vec_rawaddr {
	uint8_t buffer[VEC_RAWADDR_LEN];
	uint32_t val[4];
	union leek_rawaddr addr;
};


struct leek_sha1 {
	/* Internal state for 8 SHA1 blocks */
	uint8_t block[8 * VEC_SHA1_BLOCK_SIZE];

	/* Where the exponent is located (MSB) */
	/* This also sets the number of static rounds */
	unsigned int expo_round;
	/* Where the exponent starts located in the last 32b word (0 to 3)*/
	unsigned int expo_pos;

	/* Current exponent values (little-endian, High, Low) */
	vec8 vexpo[2];

	vec8 H[5]; /* Updated hash states */

	/* Precomputed values */
	vec8 PH[5]; /* Values a, b, c, d, e */
	vec8 PW[3]; /* Two first static hash words + size word */

	/* Final resulting addresses (hashes) */
	union vec_rawaddr R[8];
};

#endif /* !__LEEK_SHA1_AVX2_H */
