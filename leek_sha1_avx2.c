#include <stdint.h>

#ifdef DEBUG
static void leek_sha1_block_display(const struct leek_crypto *lc)
{
	printf("Internal block(s):\n");
	for (unsigned int i = 0; i < VEC_SHA1_LBLOCK_SIZE; ++i) {
		for (unsigned int j = 0; j < 32; ++j) {
			if (j && !(j & 3))
				printf(" ");
			printf("%02x", lc->sha1.block[32 * i + j]);
		}
		printf("\n");
	}
}
#else
# define leek_sha1_block_display(...)
#endif


int leek_sha1_init(void)
{
	if (leek.config.flags & LEEK_FLAG_VERBOSE)
		printf("[+] Leek is using custom AVX2 implementation.\n");
	return 0;
}

static void leek_sha1_reset(struct leek_crypto *lc)
{
	lc->sha1.H[0] = vec8_set(VEC_SHA1_H0);
	lc->sha1.H[1] = vec8_set(VEC_SHA1_H1);
	lc->sha1.H[2] = vec8_set(VEC_SHA1_H2);
	lc->sha1.H[3] = vec8_set(VEC_SHA1_H3);
	lc->sha1.H[4] = vec8_set(VEC_SHA1_H4);
}

/* Generic hash function (used for the first blocks) */
static void leek_sha1_update(struct leek_crypto *lc)
{
	const vec8 *in = (const vec8 *) lc->sha1.block;
	vec8 W[16];
	vec8 a, b, c, d, e;

	a = lc->sha1.H[0];
	b = lc->sha1.H[1];
	c = lc->sha1.H[2];
	d = lc->sha1.H[3];
	e = lc->sha1.H[4];

	vec8_ROUND(vec8_F1, vec8_SRC,  0, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  1, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  2, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  3, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  4, b, c, d, e, a, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  5, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  6, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  7, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  8, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  9, b, c, d, e, a, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC, 10, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC, 11, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC, 12, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC, 13, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC, 14, b, c, d, e, a, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC, 15, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_MIX, 16, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_MIX, 17, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_MIX, 18, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_MIX, 19, b, c, d, e, a, VEC_SHA1_K1);

	vec8_ROUND(vec8_F2, vec8_MIX, 20, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 21, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 22, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 23, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 24, b, c, d, e, a, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 25, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 26, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 27, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 28, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 29, b, c, d, e, a, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 30, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 31, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 32, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 33, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 34, b, c, d, e, a, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 35, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 36, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 37, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 38, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND(vec8_F2, vec8_MIX, 39, b, c, d, e, a, VEC_SHA1_K2);

	vec8_ROUND(vec8_F3, vec8_MIX, 40, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 41, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 42, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 43, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 44, b, c, d, e, a, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 45, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 46, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 47, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 48, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 49, b, c, d, e, a, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 50, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 51, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 52, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 53, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 54, b, c, d, e, a, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 55, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 56, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 57, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 58, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND(vec8_F3, vec8_MIX, 59, b, c, d, e, a, VEC_SHA1_K3);

	vec8_ROUND(vec8_F4, vec8_MIX, 60, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 61, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 62, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 63, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 64, b, c, d, e, a, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 65, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 66, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 67, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 68, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 69, b, c, d, e, a, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 70, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 71, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 72, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 73, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 74, b, c, d, e, a, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 75, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 76, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 77, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 78, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND(vec8_F4, vec8_MIX, 79, b, c, d, e, a, VEC_SHA1_K4);

	lc->sha1.H[0] = vec8_add(a, lc->sha1.H[0]);
	lc->sha1.H[1] = vec8_add(b, lc->sha1.H[1]);
	lc->sha1.H[2] = vec8_add(c, lc->sha1.H[2]);
	lc->sha1.H[3] = vec8_add(d, lc->sha1.H[3]);
	lc->sha1.H[4] = vec8_add(e, lc->sha1.H[4]);
}

/* Stage1: pre-compute all-time fixed values */
static void leek_exhaust_precalc_1(struct leek_crypto *lc)
{
	const vec8 *in = (const vec8 *) lc->sha1.block;
	vec8 a, b, c, d, e;
	vec8 W[2];

	a = lc->sha1.H[0];
	b = lc->sha1.H[1];
	c = lc->sha1.H[2];
	d = lc->sha1.H[3];
	e = lc->sha1.H[4];

	/* Pre-compute the first two rounds here (static data) */
	vec8_ROUND(vec8_F1, vec8_SRC,  0, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND(vec8_F1, vec8_SRC,  1, e, a, b, c, d, VEC_SHA1_K1);

	/* Store our current state(s) */
	lc->sha1.PW_C00 = W[0];         /* 1st static word */
	lc->sha1.PW_C01 = W[1];         /* 2nd static word */

	lc->sha1.PW_C15 = vec8_SRC(15);

	lc->sha1.PH[0] = a;
	lc->sha1.PH[1] = b;
	lc->sha1.PH[2] = c;
	lc->sha1.PH[3] = d;
	lc->sha1.PH[4] = e;
}


static void leek_exhaust_precalc_2(struct leek_crypto *lc, vec8 vexpo_1)
{
	lc->sha1.PW_C03 = vexpo_1;
#if 0
	/* This pre-computable data is not worth the memory load cost */
	lc->sha1.PW_C17 = vec8_rol(vec8_xor(vexpo_1, lc->sha1.PW_C01), 1);
	lc->sha1.PW_C20 = vec8_rol(lc->sha1.PW_C17, 1);
	lc->sha1.PW_C23 = vec8_rol(vec8_xor(lc->sha1.PW_C15, lc->sha1.PW_C20), 1);
#endif
}


/* Customized hash function (final block) */
static void __hot leek_sha1_finalize(struct leek_crypto *lc, vec8 vexpo_0)
{
	vec8 a, b, c, d, e;
	vec8 W[77]; /* 88 rounds minus the 3 finals */

	a = lc->sha1.PH[0];
	b = lc->sha1.PH[1];
	c = lc->sha1.PH[2];
	d = lc->sha1.PH[3];
	e = lc->sha1.PH[4];

	/* Load pre-computed data */
	W[0]  = lc->sha1.PW_C00;
	W[1]  = lc->sha1.PW_C01;
	W[2]  = vexpo_0;
	W[3]  = lc->sha1.PW_C03;
	W[15] = lc->sha1.PW_C15;

#if 0
	/* This would be the load of pre-computed data */
	W[17] = lc->sha1.PW_C17;
	W[20] = lc->sha1.PW_C20;
	W[23] = lc->sha1.PW_C23;
#endif

	vec8_ROUND_F(vec8_F1, vec8_LDW,  2, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND_F(vec8_F1, vec8_LDW,  3, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,            4, b, c, d, e, a, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,            5, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,            6, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,            7, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,            8, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,            9, b, c, d, e, a, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,           10, a, b, c, d, e, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,           11, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,           12, d, e, a, b, c, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,           13, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND_E(vec8_F1,           14, b, c, d, e, a, VEC_SHA1_K1);
	vec8_ROUND_F(vec8_F1, vec8_LDW, 15, a, b, c, d, e, VEC_SHA1_K1);

	vec8_ROUND_O(vec8_F1, vec8_MXC, 16, e, a, b, c, d, VEC_SHA1_K1);
	vec8_ROUND_O(vec8_F1, vec8_MXC, 17, d, e, a, b, c, VEC_SHA1_K1); /* pre-computable */
	vec8_ROUND_O(vec8_F1, vec8_MX9, 18, c, d, e, a, b, VEC_SHA1_K1);
	vec8_ROUND_O(vec8_F1, vec8_MX9, 19, b, c, d, e, a, VEC_SHA1_K1);

	vec8_ROUND_O(vec8_F2, vec8_MX1, 20, a, b, c, d, e, VEC_SHA1_K2); /* pre-computable */
	vec8_ROUND_O(vec8_F2, vec8_MX1, 21, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX1, 22, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX3, 23, c, d, e, a, b, VEC_SHA1_K2); /* pre-computable */
	vec8_ROUND_O(vec8_F2, vec8_MX3, 24, b, c, d, e, a, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX3, 25, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX3, 26, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX3, 27, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX3, 28, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX7, 29, b, c, d, e, a, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MX7, 30, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 31, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 32, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 33, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 34, b, c, d, e, a, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 35, a, b, c, d, e, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 36, e, a, b, c, d, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 37, d, e, a, b, c, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 38, c, d, e, a, b, VEC_SHA1_K2);
	vec8_ROUND_O(vec8_F2, vec8_MXF, 39, b, c, d, e, a, VEC_SHA1_K2);

	vec8_ROUND_O(vec8_F3, vec8_MXF, 40, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 41, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 42, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 43, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 44, b, c, d, e, a, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 45, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 46, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 47, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 48, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 49, b, c, d, e, a, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 50, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 51, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 52, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 53, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 54, b, c, d, e, a, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 55, a, b, c, d, e, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 56, e, a, b, c, d, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 57, d, e, a, b, c, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 58, c, d, e, a, b, VEC_SHA1_K3);
	vec8_ROUND_O(vec8_F3, vec8_MXF, 59, b, c, d, e, a, VEC_SHA1_K3);

	vec8_ROUND_O(vec8_F4, vec8_MXF, 60, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 61, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 62, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 63, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 64, b, c, d, e, a, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 65, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 66, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 67, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 68, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 69, b, c, d, e, a, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 70, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 71, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 72, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 73, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 74, b, c, d, e, a, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 75, a, b, c, d, e, VEC_SHA1_K4);
	vec8_ROUND_O(vec8_F4, vec8_MXF, 76, e, a, b, c, d, VEC_SHA1_K4);
	vec8_ROUND_F(vec8_F4, vec8_MXF, 77, d, e, a, b, c, VEC_SHA1_K4);
	vec8_ROUND_F(vec8_F4, vec8_MXF, 78, c, d, e, a, b, VEC_SHA1_K4);
	vec8_ROUND_F(vec8_F4, vec8_MXF, 79, b, c, d, e, a, VEC_SHA1_K4);


	/* We keep the first 3 words (12B) as we only need 10B */
	a = vec8_add(a, lc->sha1.H[0]);
	b = vec8_add(b, lc->sha1.H[1]);
	c = vec8_add(c, lc->sha1.H[2]);

	/* Here 'd' will contain garbage but we won't read anyway */
	vec8_transpose_8x32(a, b, c, d);

	vec8_store((void *) &lc->sha1.R[0], vec8_bswap(a));
	vec8_store((void *) &lc->sha1.R[2], vec8_bswap(b));
	vec8_store((void *) &lc->sha1.R[4], vec8_bswap(c));
	vec8_store((void *) &lc->sha1.R[6], vec8_bswap(d));
}


static void leek_sha1_block_update(struct leek_crypto *lc, const void *ptr)
{
	const uint32_t *ptr32 = ptr;

	for (int i = 0; i < VEC_SHA1_LBLOCK_SIZE; ++i)
		vec8_store(lc->sha1.block + 32 * i, vec8_set(ptr32[i]));
}


static void leek_sha1_block_finalize(struct leek_crypto *lc, const void *ptr,
                                     size_t total_len)
{
	const uint32_t *ptr32 = ptr;
	size_t len = total_len % VEC_SHA1_BLOCK_SIZE;
	size_t len32 = len >> 2;
	size_t remaining;
	size_t i;

	for (i = 0; i < len32; ++i)
		vec8_store(lc->sha1.block + 32 * i, vec8_set(ptr32[i]));

	/* Write the last word and try to finalize stuff */
	remaining = len - 4 * i;
	if (remaining) {
		uint32_t mask = (1 << (8 * remaining)) - 1;
		uint32_t sha1_end = 0x80 << (8 * remaining);
		uint32_t value = (ptr32[i] & mask) | sha1_end;

		vec8_store(lc->sha1.block + 32 * i, vec8_set(value));

		lc->sha1.expo_pos = 4 - remaining;
		lc->sha1.expo_round = i - 1;
	}
	else {
		vec8_store(lc->sha1.block + 32 * i, vec8_set(0x80));
		lc->sha1.expo_pos = 0;
		lc->sha1.expo_round = i - 2;
	}
	i++;

	for (; i < VEC_SHA1_LBLOCK_SIZE - 1; ++i)
		vec8_store(lc->sha1.block + 32 * i, vec8_zero());

	/* Time to write the total bit length in big endian */
	vec8_store(lc->sha1.block + 32 * i, vec8_set(htobe32(8 * total_len)));
}


/* Prepare exponent values used by exhaust loop */
static void leek_exhaust_prepare(struct leek_crypto *lc)
{
	unsigned int expo_shift = 8 * lc->sha1.expo_pos;
	void *ptr[2];
	vec8 adder;

	/* Values added to every lane */
	adder = vec8_shl(_mm256_set_epi32(14, 12, 10, 8, 6, 4, 2, 0), expo_shift);

	/* Pointer to exponent words */
	ptr[0] = &lc->sha1.block[32 * (lc->sha1.expo_round + 0)];
	ptr[1] = &lc->sha1.block[32 * (lc->sha1.expo_round + 1)];

	/* Store these values for use by the main exhaust loop */
	lc->sha1.vexpo[0] = vec8_bswap(vec8_load(ptr[0]));
	lc->sha1.vexpo[1] = vec8_add(vec8_bswap(vec8_load(ptr[1])), adder);
}


/* Stage0: pre-compute first full SHA1 blocks */
int leek_sha1_precalc(struct leek_crypto *lc, const void *ptr, size_t len)
{
	size_t rem = len;
	int ret = -1;

	leek_sha1_reset(lc);

	while (rem >= VEC_SHA1_BLOCK_SIZE) {
		leek_sha1_block_update(lc, ptr);
		leek_sha1_update(lc);
		rem -= VEC_SHA1_BLOCK_SIZE;
		ptr += VEC_SHA1_BLOCK_SIZE;
	}

	/* These checks are *HIGHLY* improbable in theory, but let's be safe here */
	if (rem < LEEK_RSA_E_SIZE) {
		/* This makes it impossible to iterate over exponent in the last block */
		fprintf(stderr, "SHA1 init failed: too few data in last hash block.\n");
		goto out;
	}

	if (rem > (VEC_SHA1_BLOCK_SIZE - sizeof(uint64_t) - 1)) {
		/* This makes it impossible to finalize hash in the same block as exponent */
		fprintf(stderr, "SHA1 init failed: too much data in last hash block.\n");
		goto out;
	}

	leek_sha1_block_finalize(lc, ptr, len);
	leek_exhaust_prepare(lc);

	ret = 0;
out:
	return ret;
}


int leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
{
	uint32_t increment = 1 << ((8 * lc->sha1.expo_pos) + 4);
	unsigned int iter_count = (LEEK_RSA_E_LIMIT - LEEK_RSA_E_START + 2) >> 4;
	unsigned int outer_count;
	unsigned int outer_init;
	unsigned int inner_count;
	unsigned int inner_init;
	vec8 vexpo[2];  /* current exponents words (high / low) */
	vec8 vincr[2];  /* increments (high / low)*/

	/* Handle different alignments (else clause will never happen anyway...) */
	if (lc->sha1.expo_pos) {
		outer_count = (LEEK_RSA_E_LIMIT + 2U) >> (8 * (4 - lc->sha1.expo_pos));
		outer_init = (LEEK_RSA_E_START) >> (8 * (4 - lc->sha1.expo_pos));
		inner_count = (1ULL << (8 * (4 - lc->sha1.expo_pos) - 4));
		inner_init = iter_count & (byte_mask(4 - lc->sha1.expo_pos) >> 4);
	}
	else {
		outer_count = 1;
		outer_init = 0;
		inner_count = (LEEK_RSA_E_LIMIT - LEEK_RSA_E_START + 2) >> 4;
		inner_init = LEEK_RSA_E_START >> 4;
	}

	vincr[0] = vec8_set(1);
	vincr[1] = vec8_set(increment);

	vexpo[0] = lc->sha1.vexpo[0];
	vexpo[1] = lc->sha1.vexpo[1];

	/* Stage1 pre-computation */
	leek_exhaust_precalc_1(lc);


	/* While using RSA 1024, inner is 16 and outer is 8388608
	 * This makes sense to perform the outer loop inside the inner loop
	 * to perform less stage 2 pre-comptutes */
	/* Total real e checked is 3FC00000 (~1.70GH):
	 * 8 * ((outer_count - outer_init) * inner_count - inner_init) */

	for (unsigned int i = inner_init; i < inner_count; ++i) {
		leek_exhaust_precalc_2(lc, vexpo[1]);
		vexpo[0] = lc->sha1.vexpo[0];

		for (unsigned int o = outer_init; o < outer_count; ++o) {
			leek_sha1_finalize(lc, vexpo[0]);

			/* Check results for all AVX2 lanes here */
			for (int r = 0; r < 8; ++r) {
				union leek_rawaddr *result;
				int length;
				int ret;

				result = &lc->sha1.R[r].addr;

				length = leek_lookup(result);
				if (length) {
					/* What's my e again? */
					uint32_t e = 16 * (o * inner_count + i) + 2 * r + 1;
					ret = leek_address_check(lc, e, result);
					if (ret < 0)
						__sync_add_and_fetch(&leek.error_hash_count, 1);
					else
						leek_result_display(lc->rsa, e, length, result);
				}
			}

			vexpo[0] = vec8_add(vexpo[0], vincr[0]);
			wk->hash_count += 8;
		}

		vexpo[1] = vec8_add(vexpo[1], vincr[1]);
	}

	return 0;
}
