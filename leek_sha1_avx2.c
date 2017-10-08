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


static void leek_sha1_init(struct leek_crypto *lc)
{
	lc->sha1.H[0] = vec8_set(VEC_SHA1_H0);
	lc->sha1.H[1] = vec8_set(VEC_SHA1_H1);
	lc->sha1.H[2] = vec8_set(VEC_SHA1_H2);
	lc->sha1.H[3] = vec8_set(VEC_SHA1_H3);
	lc->sha1.H[4] = vec8_set(VEC_SHA1_H4);
}


static void __hot leek_sha1_xfrm(struct leek_crypto *lc, int update)
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

	if (update) {
		lc->sha1.H[0] = vec8_add(a, lc->sha1.H[0]);
		lc->sha1.H[1] = vec8_add(b, lc->sha1.H[1]);
		lc->sha1.H[2] = vec8_add(c, lc->sha1.H[2]);
		lc->sha1.H[3] = vec8_add(d, lc->sha1.H[3]);
		lc->sha1.H[4] = vec8_add(e, lc->sha1.H[4]);
	}
	else {
		/* We keep the first 3 words (12B) as we only need 10B */
		a = vec8_add(a, lc->sha1.H[0]);
		b = vec8_add(b, lc->sha1.H[1]);
		c = vec8_add(c, lc->sha1.H[2]);
		d = vec8_zero();

		vec8_transpose_8x32(a, b, c, d);

		vec8_store((void *) &lc->sha1.R[0], vec8_bswap(a));
		vec8_store((void *) &lc->sha1.R[2], vec8_bswap(b));
		vec8_store((void *) &lc->sha1.R[4], vec8_bswap(c));
		vec8_store((void *) &lc->sha1.R[6], vec8_bswap(d));
	}
}

static inline void leek_sha1_finalize(struct leek_crypto *lc)
{
	/* Perform the last and store result in F */
	leek_sha1_xfrm(lc, 0);
}

static inline void leek_sha1_update(struct leek_crypto *lc)
{
	/* Perform a full update */
	leek_sha1_xfrm(lc, 1);
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


// #include <openssl/sha.h>
static void leek_exhaust_prepare(struct leek_crypto *lc)
// static void leek_exhaust_prepare(struct leek_crypto *lc, const void *der, size_t len)
{
	unsigned int expo_shift = 8 * lc->sha1.expo_pos;
	void *ptr[2];
	vec8 expo[2];
	vec8 adder;

	ptr[0] = &lc->sha1.block[32 * (lc->sha1.expo_round + 0)];
	ptr[1] = &lc->sha1.block[32 * (lc->sha1.expo_round + 1)];

	expo[0] = vec8_bswap(vec8_load(ptr[0]));
	expo[1] = vec8_bswap(vec8_load(ptr[1]));

	adder = vec8_shl(_mm256_set_epi32(14, 12, 10, 8, 6, 4, 2, 0), expo_shift);
	expo[1] = vec8_add(expo[1], adder);

	/* Store these values for use by the main exhaust loop */
	lc->sha1.vexpo[0] = expo[0];
	lc->sha1.vexpo[1] = expo[1];
}


int leek_sha1_precalc(struct leek_crypto *lc, const void *ptr, size_t len)
{
	size_t rem = len;
	int ret = -1;

	leek_sha1_init(lc);

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

	/* IDEAS:
	 * - precompute internal values for the first N rounds
	 *   (N + 1 when not touching MSBs of exponent :p, which is 94% with RSA 1024)
	*  - A lot of block data is made of padding (zeroes), this simplifies a bit some stuff
	*  - Byte swap can be performed upon block filling instead of being recomputed
	*    (this also changes the way we handle exponent increments...)
	*  - 'd' and 'e' are unused in final digest, this should help simplifying some stuff
	*  - More ideas: https://hashcat.net/events/p12/js-sha1exp_169.pdf
	 **/
	leek_sha1_block_finalize(lc, ptr, len);
	leek_exhaust_prepare(lc);

	ret = 0;
out:
	return ret;
}


int leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
{
	uint32_t increment = 1 << ((8 * lc->sha1.expo_pos) + 4);
	unsigned int outer_count;
	unsigned int inner_count;
	void *bexpo[2]; /* exponent pointer locations within the sha1 block */
	vec8 vexpo[2];  /* current exponents words (high / low) */
	vec8 vincr[2];  /* increments (high / low)*/

	/* Handle different alignments (else clause will never happen anyway...) */
	if (lc->sha1.expo_pos) {
		outer_count = (LEEK_RSA_E_LIMIT - LEEK_RSA_E_START + 2) >> (8 * (4 - lc->sha1.expo_pos));
		inner_count = (1ULL << (8 * (4 - lc->sha1.expo_pos) - 4));
	}
	else {
		outer_count = 1;
		inner_count = (LEEK_RSA_E_LIMIT - LEEK_RSA_E_START + 2) >> 4;
	}

	vincr[0] = vec8_set(1);
	vincr[1] = vec8_set(increment);

	bexpo[0] = &lc->sha1.block[32 * (lc->sha1.expo_round + 0)];
	bexpo[1] = &lc->sha1.block[32 * (lc->sha1.expo_round + 1)];

	vexpo[0] = lc->sha1.vexpo[0];
	vexpo[1] = lc->sha1.vexpo[1];


	for (unsigned int o = 0; o < outer_count; ++o) {
		/* Store current and increment outer exponents (MSBs) */
		vec8_store(bexpo[0], vec8_bswap(vexpo[0]));
		vexpo[0] = vec8_add(vexpo[0], vincr[0]);

		for (unsigned int i = 0; i < inner_count; ++i) {
			/* Store current and increment inner exponents (LSBs) */
			vec8_store(bexpo[1], vec8_bswap(vexpo[1]));
			vexpo[1] = vec8_add(vexpo[1], vincr[1]);

			leek_sha1_finalize(lc);

			/* Check results for all AVX2 lanes here */
			for (int r = 0; r < 8; ++r) {
				union leek_rawaddr *result;
				int length;
				int ret;

				result = &lc->sha1.R[r].addr;

				length = leek_lookup(result);
				if (length) {
					/* What's my e again? */
					uint32_t e = LEEK_RSA_E_START + 16 * (o * inner_count + i) + 2 * r;

					ret = leek_address_check(lc, e, result);
					if (ret < 0)
						__sync_add_and_fetch(&leek.error_hash_count, 1);
					else
						leek_result_display(lc->rsa, e, length, result);
				}
			}

			wk->hash_count += 8;
		}
	}

	return 0;
}
