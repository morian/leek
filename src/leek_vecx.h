#ifndef __LEEK_VECX_H
# define __LEEK_VECX_H
#include <stdint.h>
#include <string.h>

#include "leek_vecx_core.h"
#include "leek_lookup.h"


/* This avoids unwanted instructions in this function. */
#pragma GCC push_options
static int leek_vecx_available(void)
{
	return __builtin_cpu_supports(VECX_IMPL_ISA);
}

#pragma GCC pop_options
static void *leek_vecx_alloc(void)
{
	struct leek_vecx *lv;

	lv = aligned_alloc(LEEK_CACHELINE_SZ, sizeof(*lv));
	if (!lv)
		goto out;
	memset(lv, 0, sizeof(*lv));

out:
	return lv;
}

static void leek_vecx_reset(struct leek_vecx *lv)
{
	lv->H[0] = vecx_set(VEC_SHA1_H0);
	lv->H[1] = vecx_set(VEC_SHA1_H1);
	lv->H[2] = vecx_set(VEC_SHA1_H2);
	lv->H[3] = vecx_set(VEC_SHA1_H3);
	lv->H[4] = vecx_set(VEC_SHA1_H4);
}

/* Generic hash function (used for the first blocks) */
static void leek_vecx_update(struct leek_vecx *lv)
{
	const vecx *in = (const vecx *) lv->block;
	vecx W[16];
	vecx a, b, c, d, e;

	a = lv->H[0];
	b = lv->H[1];
	c = lv->H[2];
	d = lv->H[3];
	e = lv->H[4];

	vecx_ROUND(vecx_F1, vecx_SRC,  0, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  1, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  2, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  3, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  4, b, c, d, e, a, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  5, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  6, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  7, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  8, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC,  9, b, c, d, e, a, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC, 10, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC, 11, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC, 12, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC, 13, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC, 14, b, c, d, e, a, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_SRC, 15, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_MIX, 16, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_MIX, 17, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_MIX, 18, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND(vecx_F1, vecx_MIX, 19, b, c, d, e, a, VEC_SHA1_K1);

	vecx_ROUND(vecx_F2, vecx_MIX, 20, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 21, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 22, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 23, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 24, b, c, d, e, a, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 25, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 26, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 27, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 28, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 29, b, c, d, e, a, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 30, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 31, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 32, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 33, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 34, b, c, d, e, a, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 35, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 36, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 37, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 38, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND(vecx_F2, vecx_MIX, 39, b, c, d, e, a, VEC_SHA1_K2);

	vecx_ROUND(vecx_F3, vecx_MIX, 40, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 41, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 42, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 43, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 44, b, c, d, e, a, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 45, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 46, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 47, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 48, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 49, b, c, d, e, a, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 50, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 51, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 52, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 53, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 54, b, c, d, e, a, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 55, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 56, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 57, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 58, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND(vecx_F3, vecx_MIX, 59, b, c, d, e, a, VEC_SHA1_K3);

	vecx_ROUND(vecx_F4, vecx_MIX, 60, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 61, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 62, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 63, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 64, b, c, d, e, a, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 65, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 66, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 67, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 68, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 69, b, c, d, e, a, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 70, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 71, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 72, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 73, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 74, b, c, d, e, a, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 75, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 76, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 77, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 78, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND(vecx_F4, vecx_MIX, 79, b, c, d, e, a, VEC_SHA1_K4);

	lv->H[0] = vecx_add(a, lv->H[0]);
	lv->H[1] = vecx_add(b, lv->H[1]);
	lv->H[2] = vecx_add(c, lv->H[2]);
	lv->H[3] = vecx_add(d, lv->H[3]);
	lv->H[4] = vecx_add(e, lv->H[4]);
}

/* Stage1: pre-compute all-time fixed values */
static void leek_exhaust_precalc_1(struct leek_vecx *lv)
{
	const vecx *in = (const vecx *) lv->block;
	vecx a, b, c, d, e;
	vecx W[2];

	a = lv->H[0];
	b = lv->H[1];
	c = lv->H[2];
	d = lv->H[3];
	e = lv->H[4];

	/* Pre-compute the first few rounds here (static data) */
	vecx_ROUND_O(vecx_F1, vecx_SRC,  0, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND_O(vecx_F1, vecx_SRC,  1, e, a, b, c, d, VEC_SHA1_K1);

	/* This is partial pre-calculus for round 2 */
	vecx_ROUND_E(vecx_F1,            2, d, e, a, b, c, VEC_SHA1_K1);

	/* This is very partial pre-calculus or round 3 */
	lv->PA_C03 = vecx_add3(b, vecx_F1(d, e, a), vecx_set(VEC_SHA1_K1));
	d = vecx_ror(d, 2);

	/* Store our current state(s) */
	lv->PW_C00 = W[0];         /* 1st static word */
	lv->PW_C01 = W[1];         /* 2nd static word */

	lv->PW_C15 = vecx_SRC(15);

	lv->PH[0] = a;
	lv->PH[1] = b;
	lv->PH[2] = c;
	lv->PH[3] = d;
	lv->PH[4] = e;
}


static void leek_exhaust_precalc_2(struct leek_vecx *lv, vecx vexpo_1)
{
	lv->PW_C03 = vexpo_1;

	/* Enhance pre-compute for cycle 3 (here we have temporary value for 'b') */
	lv->PH[1] = vecx_add(lv->PA_C03, vexpo_1);
}


/* Customized hash function (final block) */
static void leek_vecx_finalize(struct leek_vecx *lv, vecx vexpo_0)
{
	void *resptr = (void *) &lv->R;
	vecx a, b, c, d, e;
	/* 80 rounds minus the 3 finals */
	vecx W[77];

	a = lv->PH[0];
	b = lv->PH[1];
	c = lv->PH[2];
	d = lv->PH[3];
	e = lv->PH[4];

	/* Load pre-computed data */
	W[0]  = lv->PW_C00;
	W[1]  = lv->PW_C01;
	W[2]  = vexpo_0;
	W[3]  = lv->PW_C03;
	W[15] = lv->PW_C15;

	/* This finishes round 2 gracefully */
	c = vecx_add(c, vexpo_0);

	/* This finishes round 3 gracefully as well */
	b = vecx_add(vecx_rol(c, 5), b);

	/* We choose not to pre-compute words for rounds 17, 20 and 23
	 * because benchmarks showed a performance regression probably due
	 * to memory loading. Over-optimization is not worth here. */

	vecx_ROUND_E(vecx_F1,            4, b, c, d, e, a, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,            5, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,            6, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,            7, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,            8, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,            9, b, c, d, e, a, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,           10, a, b, c, d, e, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,           11, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,           12, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,           13, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND_E(vecx_F1,           14, b, c, d, e, a, VEC_SHA1_K1);
	vecx_ROUND_F(vecx_F1, vecx_LDW, 15, a, b, c, d, e, VEC_SHA1_K1);

	vecx_ROUND_O(vecx_F1, vecx_MXC, 16, e, a, b, c, d, VEC_SHA1_K1);
	vecx_ROUND_O(vecx_F1, vecx_MXC, 17, d, e, a, b, c, VEC_SHA1_K1);
	vecx_ROUND_O(vecx_F1, vecx_MX9, 18, c, d, e, a, b, VEC_SHA1_K1);
	vecx_ROUND_O(vecx_F1, vecx_MX9, 19, b, c, d, e, a, VEC_SHA1_K1);

	vecx_ROUND_O(vecx_F2, vecx_MX1, 20, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX1, 21, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX1, 22, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX3, 23, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX3, 24, b, c, d, e, a, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX3, 25, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX3, 26, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX3, 27, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX3, 28, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX7, 29, b, c, d, e, a, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MX7, 30, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 31, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 32, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 33, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 34, b, c, d, e, a, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 35, a, b, c, d, e, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 36, e, a, b, c, d, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 37, d, e, a, b, c, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 38, c, d, e, a, b, VEC_SHA1_K2);
	vecx_ROUND_O(vecx_F2, vecx_MXF, 39, b, c, d, e, a, VEC_SHA1_K2);

	vecx_ROUND_O(vecx_F3, vecx_MXF, 40, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 41, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 42, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 43, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 44, b, c, d, e, a, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 45, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 46, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 47, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 48, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 49, b, c, d, e, a, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 50, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 51, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 52, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 53, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 54, b, c, d, e, a, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 55, a, b, c, d, e, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 56, e, a, b, c, d, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 57, d, e, a, b, c, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 58, c, d, e, a, b, VEC_SHA1_K3);
	vecx_ROUND_O(vecx_F3, vecx_MXF, 59, b, c, d, e, a, VEC_SHA1_K3);

	vecx_ROUND_O(vecx_F4, vecx_MXF, 60, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 61, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 62, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 63, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 64, b, c, d, e, a, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 65, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 66, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 67, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 68, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 69, b, c, d, e, a, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 70, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 71, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 72, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 73, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 74, b, c, d, e, a, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 75, a, b, c, d, e, VEC_SHA1_K4);
	vecx_ROUND_O(vecx_F4, vecx_MXF, 76, e, a, b, c, d, VEC_SHA1_K4);
	vecx_ROUND_F(vecx_F4, vecx_MXF, 77, d, e, a, b, c, VEC_SHA1_K4);
	vecx_ROUND_F(vecx_F4, vecx_MXF, 78, c, d, e, a, b, VEC_SHA1_K4);
	vecx_ROUND_F(vecx_F4, vecx_MXF, 79, b, c, d, e, a, VEC_SHA1_K4);

	/* We keep the first 3 words (12B) as we only need 10B for this attack */
	a = vecx_add(a, lv->H[0]);
	b = vecx_add(b, lv->H[1]);
	c = vecx_add(c, lv->H[2]);
	/* 'd' contains garbage but we will not read it anyway */

	vecx_transpose(a, b, c, d);

	/* Store all output results */
	vecx_store(resptr + 0 * VECX_WORD_SIZE, vecx_bswap(a));
	vecx_store(resptr + 1 * VECX_WORD_SIZE, vecx_bswap(b));
	vecx_store(resptr + 2 * VECX_WORD_SIZE, vecx_bswap(c));
	vecx_store(resptr + 3 * VECX_WORD_SIZE, vecx_bswap(d));
}


static void leek_vecx_block_finalize(struct leek_vecx *lv, const void *ptr,
                                     size_t total_len)
{
	const uint32_t *ptr32 = ptr;
	size_t len = total_len % VEC_SHA1_BLOCK_SIZE;
	size_t len32 = len >> 2;
	size_t remaining;
	size_t i;

	for (i = 0; i < len32; ++i)
		vecx_store(lv->block + VECX_WORD_SIZE * i, vecx_set(ptr32[i]));

	/* Write the last word and try to finalize stuff */
	remaining = len - 4 * i;
	if (remaining) {
		uint32_t mask = (1 << (8 * remaining)) - 1;
		uint32_t sha1_end = 0x80 << (8 * remaining);
		uint32_t value = (ptr32[i] & mask) | sha1_end;

		vecx_store(lv->block + VECX_WORD_SIZE * i, vecx_set(value));

		lv->expo_pos = 4 - remaining;
		lv->expo_round = i - 1;
	}
	else {
		vecx_store(lv->block + VECX_WORD_SIZE * i, vecx_set(0x80));
		lv->expo_pos = 0;
		lv->expo_round = i - 2;
	}
	i++;

	for (; i < VEC_SHA1_LBLOCK_SIZE - 1; ++i)
		vecx_store(lv->block + VECX_WORD_SIZE * i, vecx_zero());

	/* Time to write the total bit length in big endian */
	vecx_store(lv->block + VECX_WORD_SIZE * i, vecx_set(htobe32(8 * total_len)));
}


/* Prepare exponent values used by exhaust loop */
static void leek_exhaust_prepare(struct leek_vecx *lv)
{
	vecx adder = vecx_even_numbers();
	void *ptr[2];

	/* Values added to every lane (instruction requires an immediate). */
	switch (lv->expo_pos) {
		case 0:
			adder = vecx_shl(adder,  0);
			break;

		case 1:
			adder = vecx_shl(adder,  8);
			break;

		case 2:
			adder = vecx_shl(adder, 16);
			break;

		case 3:
			adder = vecx_shl(adder, 24);
			break;
	};

	/* Pointer to exponent words */
	ptr[0] = &lv->block[VECX_WORD_SIZE * (lv->expo_round + 0)];
	ptr[1] = &lv->block[VECX_WORD_SIZE * (lv->expo_round + 1)];

	/* Store these values for use by the main exhaust loop */
	lv->vexpo[0] = vecx_bswap(vecx_load(ptr[0]));
	lv->vexpo[1] = vecx_add(vecx_bswap(vecx_load(ptr[1])), adder);
}


static void leek_vecx_block_update(struct leek_vecx *lv, const void *ptr)
{
	const uint32_t *ptr32 = ptr;

	for (int i = 0; i < VEC_SHA1_LBLOCK_SIZE; ++i)
		vecx_store(lv->block + VECX_WORD_SIZE * i, vecx_set(ptr32[i]));
}


/* Stage0: pre-compute first full SHA1 blocks */
static int leek_vecx_precalc(struct leek_crypto *lc, const void *ptr, size_t len)
{
	struct leek_vecx *lv = lc->private_data;
	size_t rem = len;
	int ret = -1;

	leek_vecx_reset(lv);

	while (rem >= VEC_SHA1_BLOCK_SIZE) {
		leek_vecx_block_update(lv, ptr);
		leek_vecx_update(lv);
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

	leek_vecx_block_finalize(lv, ptr, len);
	leek_exhaust_prepare(lv);

	ret = 0;
out:
	return ret;
}

static int __leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc,
                          unsigned int mode)
{
	struct leek_vecx *lv = lc->private_data;
	uint32_t increment = 1 << ((8 * lv->expo_pos) + VECX_INCR_ORDER);
	unsigned int iter_count = (LEEK_RSA_E_LIMIT - LEEK_RSA_E_START + 2) >> 4;
	unsigned int outer_count;
	unsigned int outer_init;
	unsigned int inner_count;
	unsigned int inner_init;
	vecx vexpo[2];  /* current exponents words (high / low) */
	vecx vincr[2];  /* increments (high / low)*/

	/* Handle different alignments (else clause will never happen anyway...) */
	if (lv->expo_pos) {
		outer_count = (LEEK_RSA_E_LIMIT + 2U) >> (8 * (4 - lv->expo_pos));
		outer_init = (LEEK_RSA_E_START) >> (8 * (4 - lv->expo_pos));
		inner_count = (1ULL << (8 * (4 - lv->expo_pos) - VECX_INCR_ORDER));
		inner_init = iter_count & (byte_mask(4 - lv->expo_pos) >> VECX_INCR_ORDER);
	}
	else {
		outer_count = 1;
		outer_init = 0;
		inner_count = (LEEK_RSA_E_LIMIT - LEEK_RSA_E_START + 2) >> VECX_INCR_ORDER;
		inner_init = LEEK_RSA_E_START >> VECX_INCR_ORDER;
	}

	vincr[0] = vecx_set(1);
	vincr[1] = vecx_set(increment);

	vexpo[0] = lv->vexpo[0];
	vexpo[1] = lv->vexpo[1];

	/* Stage1 pre-computation */
	leek_exhaust_precalc_1(lv);

	/* While using RSA 1024, inner is 16 and outer is 8388608 (on AVX2)
	 * This makes sense to perform the outer loop inside the inner loop
	 * to perform less stage 2 pre-comptutes */
	/* Total real e checked is 3FC00000 (~1.70GH):
	 * 8 * ((outer_count - outer_init) * inner_count - inner_init) */

	for (unsigned int i = inner_init; i < inner_count; ++i) {
		leek_exhaust_precalc_2(lv, vexpo[1]);
		vexpo[0] = lv->vexpo[0];

		for (unsigned int o = outer_init; o < outer_count; ++o) {
			leek_vecx_finalize(lv, vexpo[0]);

			/* Check results for all lanes here */
			for (int r = 0; r < VECX_LANE_COUNT; ++r) {
				union leek_rawaddr *result;
				int length;
				int ret;

				result = &lv->R[r].addr;

				/* These branches are simplified in different hard copies of this function */
				switch (mode) {
					case LEEK_MODE_MULTI:
						length = leek_lookup_multi(result);
						break;

					case LEEK_MODE_SINGLE:
						length = leek_lookup_single(result);
						break;

					/* We don't need a 'default' case here since our parameter is a
					 * const value and this function is static. */
				}

				if (unlikely(length)) {
					/* What's my e again? */
					uint32_t e = 2 * (VECX_LANE_COUNT * (o * inner_count + i) + r) + 1;
					ret = leek_address_check(lc, e, result);
					if (ret < 0)
						__sync_add_and_fetch(&leek.error_hash_count, 1);
					else
						leek_result_display(lc->rsa, e, length, result);
				}
			}

			vexpo[0] = vecx_add(vexpo[0], vincr[0]);
			wk->hash_count += VECX_LANE_COUNT;
		}

		vexpo[1] = vecx_add(vexpo[1], vincr[1]);
	}

	return 0;
}

static int __flatten leek_vecx_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
{
	int ret;

	/* This dumb thing (and the __flatten attribute) enables code cloning of __leek_exhaust */
	switch (leek.config.mode) {
		case LEEK_MODE_MULTI:
			ret = __leek_exhaust(wk, lc, LEEK_MODE_MULTI);
			break;

		case LEEK_MODE_SINGLE:
			ret = __leek_exhaust(wk, lc, LEEK_MODE_SINGLE);
			break;

		default:
			ret = 0;
			break;
	}

	return ret;
}

#define LEEK_VECX_DEFINE(_name)                         \
	const struct leek_implementation _name = {            \
		.name      = VECX_IMPL_NAME,                        \
		.weight    = VECX_LANE_COUNT,                       \
		.available = leek_vecx_available,                   \
		.allocate  = leek_vecx_alloc,                       \
		.precalc   = leek_vecx_precalc,                     \
		.exhaust   = leek_vecx_exhaust,                     \
	}
#endif /* !__LEEK_VECX_H */
