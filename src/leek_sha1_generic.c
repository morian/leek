#include <stdint.h>

#define LEEK_SHA1_COPY_SIZE  (10 * sizeof(SHA_LONG))


int leek_sha1_init(void)
{
	if (leek.config.flags & LEEK_FLAG_VERBOSE)
		printf("[+] Leek is using OpenSSL implementation.\n");
	return 0;
}

int leek_sha1_precalc(struct leek_crypto *lc, const void *ptr, size_t len)
{
	SHA1_Init(&lc->sha1.hash);
	SHA1_Update(&lc->sha1.hash, ptr, len - LEEK_RSA_E_SIZE);

	return 0;
}

static int __hot __leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc,
                                unsigned int mode)
{
	uint8_t sha1_buffer[SHA_DIGEST_LENGTH];
	const union leek_rawaddr *sha1_addr;
	uint32_t e = LEEK_RSA_E_START - 2;
	uint32_t e_be;
	SHA_CTX hash;
	int length;
	int ret;

	sha1_addr = (const union leek_rawaddr *) &sha1_buffer;

	/* Here we take advantage of 32b overflow to detect end of loop */
	while(e < LEEK_RSA_E_LIMIT) {
		e += 2;
		e_be = htobe32(e);

		/* Copy internal state and relevant part of internal buffer
		 * Also copy "num" which is the state of internal buffer */
		memcpy(&hash, &lc->sha1.hash, LEEK_SHA1_COPY_SIZE);
		hash.num = lc->sha1.hash.num;

		SHA1_Update(&hash, &e_be, LEEK_RSA_E_SIZE);
		SHA1_Final(sha1_buffer, &hash);

		/* These branches are simplified in different hard copies of this function */
		switch (mode) {
			case LEEK_MODE_MULTI:
				length = leek_lookup_multi(sha1_addr);
				break;

			case LEEK_MODE_SINGLE:
				length = leek_lookup_single(sha1_addr);
				break;

			/* We don't need a 'default' case here since our parameter is a
			 * const value and this function is static. */
		}

		if (unlikely(length)) {
			ret = leek_address_check(lc, e, sha1_addr);
			if (ret < 0)
				__sync_add_and_fetch(&leek.error_hash_count, 1);
			else
				leek_result_display(lc->rsa, e, length, sha1_addr);
		}
		wk->hash_count++;
	}

	return 0;
}

int __flatten leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
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
