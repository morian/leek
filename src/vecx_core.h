#ifndef __LEEK_VECX_CORE_H
# define __LEEK_VECX_CORE_H
# include <stdint.h>

/* VEC shared macros and constants */
# define VEC_SHA1_LBLOCK_SIZE    16
# define VEC_SHA1_BLOCK_SIZE     (VEC_SHA1_LBLOCK_SIZE * 4)
# define VEC_RAWADDR_LEN         16
# define VEC_CACHELINE_SIZE      64 /* hardwired to 512 bits */
# define __align(x)              __attribute__((aligned((x))))
# define __cache_align           __align(VEC_CACHELINE_SIZE)

/* SHA1 constants */
# define VEC_SHA1_H0    0x67452301
# define VEC_SHA1_H1    0xefcdab89
# define VEC_SHA1_H2    0x98badcfe
# define VEC_SHA1_H3    0x10325476
# define VEC_SHA1_H4    0xc3d2e1f0

# define VEC_SHA1_K1    0x5a827999
# define VEC_SHA1_K2    0x6ed9eba1
# define VEC_SHA1_K3    0x8f1bbcdc
# define VEC_SHA1_K4    0xca62c1d6

/* Let's enhance these sets of macros with relevant defines for SHA1 */
# define VECX_LANE_COUNT    (1 << VECX_LANE_ORDER)
# define VECX_WORD_SIZE      (4 * VECX_LANE_COUNT)
# define VECX_INCR_ORDER     (VECX_LANE_ORDER + 1)

# define vecx_add3(a, ...) vecx_add(a, vecx_add(__VA_ARGS__))
# define vecx_add4(a, ...) vecx_add(a, vecx_add3(__VA_ARGS__))
# define vecx_add5(a, ...) vecx_add(a, vecx_add4(__VA_ARGS__))
# define vecx_xor2(a, ...) vecx_xor(a, __VA_ARGS__)
# define vecx_xor3(a, ...) vecx_xor(a, vecx_xor2(__VA_ARGS__))
# define vecx_xor4(a, ...) vecx_xor(a, vecx_xor3(__VA_ARGS__))

# define vecx_F1(x, y, z) vecx_or(vecx_and(x, y), vecx_anot(x, z))
# define vecx_F2(x, y, z) vecx_xor3(x, y, z)
# define vecx_F3(x, y, z) vecx_or(vecx_and(x, y), vecx_and(z, vecx_xor(x, y)))
# define vecx_F4(x, y, z) vecx_xor3(x, y, z)


/** Original round **/
# define vecx_W(x)   W[(x) & 15]         /* W is our internal working buffer name */
# define vecx_SRC(x) vecx_bswap(in[x])   /* in is our input data name */
# define vecx_MIX(x) vecx_rol(vecx_xor4(vecx_W(x + 13), vecx_W(x + 8), vecx_W(x + 2), vecx_W(x)), 1)

/* Original round, W buffer is limited to 16 items */
# define vecx_ROUND(f, s, x, a, b, c, d, e, k)                      \
	do{                                                               \
		vecx tmp = s(x);                                                \
		vecx_W(x) = tmp;                                                \
		e = vecx_add5(e, tmp, vecx_rol(a, 5), f(b, c, d), vecx_set(k)); \
		b = vecx_ror(b, 2);                                             \
	} while (0)


/** Optimized rounds **/
# define vecx_LDW(x) W[(x)]              /* Load pre-computed word */

/* Some specific MIX operations (when W data is known to be zero) */
# define vecx_MX1(x) vecx_rol(         (W[(x)-3]                                ), 1)
# define vecx_MX3(x) vecx_rol(vecx_xor2(W[(x)-3], W[(x)-8]                      ), 1)
# define vecx_MX7(x) vecx_rol(vecx_xor3(W[(x)-3], W[(x)-8], W[(x)-14]           ), 1)
# define vecx_MX9(x) vecx_rol(vecx_xor2(W[(x)-3],                      W[(x)-16]), 1)
# define vecx_MXC(x) vecx_rol(vecx_xor2(                    W[(x)-14], W[(x)-16]), 1)
# define vecx_MXF(x) vecx_rol(vecx_xor4(W[(x)-3], W[(x)-8], W[(x)-14], W[(x)-16]), 1)

/* Optimized general round, our W buffer is not limited to 16 items */
# define vecx_ROUND_O(f, s, x, a, b, c, d, e, k)                    \
	do{                                                               \
		vecx tmp = s(x);                                                \
		W[(x)] = tmp;                                                   \
		e = vecx_add5(e, tmp, vecx_rol(a, 5), f(b, c, d), vecx_set(k)); \
		b = vecx_ror(b, 2);                                             \
	} while (0)

/* Final rounds, no store */
# define vecx_ROUND_F(f, s, x, a, b, c, d, e, k)                    \
	do{                                                               \
		vecx tmp = s(x);                                                \
		e = vecx_add5(e, tmp, vecx_rol(a, 5), f(b, c, d), vecx_set(k)); \
		b = vecx_ror(b, 2);                                             \
	} while (0)

/* Empty data, no load, no store */
# define vecx_ROUND_E(f, x, a, b, c, d, e, k)                       \
	do{                                                               \
		e = vecx_add4(e, vecx_rol(a, 5), f(b, c, d), vecx_set(k));      \
		b = vecx_ror(b, 2);                                             \
	} while (0)

# define byte_mask(x)  ((1 << (8 * (x))) - 1)


/* 'addr' is 10 bytes but we need to round to the next power of 2
 * This union just ensures that we are will be 16B aligned */
union vec_rawaddr {
	uint8_t padding[VEC_RAWADDR_LEN];
	union leek_rawaddr addr;
};


struct leek_vecx {
	/* Internal state for "LANE_COUNT" SHA1 blocks (update only) */
	uint8_t block[VECX_LANE_COUNT * VEC_SHA1_BLOCK_SIZE];

	/* Where the exponent is located (MSB) */
	/* This also sets the number of static rounds */
	unsigned int expo_round;
	/* Where the exponent starts located in the last 32b word (0 to 3)*/
	unsigned int expo_pos;

	/* Hash state before last block */
	vecx H[5];

	/* Base exponent snapshot (little-endian, High, Low) */
	vecx vexpo[2];

	/* Pre-computed values (post stage 1) */
	vecx __cache_align PH[5]; /* Values a, b, c, d, e */

	vecx PW_C00; /* Static word 0 */
	vecx PW_C01; /* Static word 1 */
	vecx PW_C03; /* Static (stage 2) word 3 (exponent LSBs) */
	vecx PW_C15; /* W word for cycle 15 (hash size) */

	vecx PA_C03; /* 'add' pre-compute for cycle 3 (post stage 1) */

	/* Final resulting addresses (hashes) */
	union vec_rawaddr  R[VECX_LANE_COUNT];
};

#endif /* !__LEEK_VECX_CORE_H */
