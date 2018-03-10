#include <stdint.h>
#include <string.h>

#include "leek.h"
#include "impl_openssl.h"
#include "lookup.h"


static int leek_openssl_available(void)
{
	/* This implementation is always available (hurray!) */
	return 1;
}

static void *leek_openssl_alloc(void)
{
	struct leek_crypto_openssl *lco;

	lco = aligned_alloc(LEEK_CACHELINE_SZ, sizeof(*lco));
	if (!lco)
		goto out;
	memset(lco, 0, sizeof(*lco));

out:
	return lco;
}

static int leek_openssl_precalc(struct leek_rsa_item *item, const void *ptr, size_t len)
{
	struct leek_crypto_openssl *lco = item->private_data;

	SHA1_Init(&lco->hash);
	SHA1_Update(&lco->hash, ptr, len - LEEK_RSA_E_SIZE);

	return 0;
}

static int __hot leek_openssl_exhaust(struct leek_rsa_item *item, struct leek_worker *wk)
{
	struct leek_crypto_openssl *lco = item->private_data;
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
		memcpy(&hash, &lco->hash, LEEK_SHA1_COPY_SIZE);
		hash.num = lco->hash.num;

		SHA1_Update(&hash, &e_be, LEEK_RSA_E_SIZE);
		SHA1_Final(sha1_buffer, &hash);

		length = leek_result_lookup(sha1_addr);
		if (unlikely(length)) {
			ret = leek_result_recheck(item, e, sha1_addr);
			if (ret < 0)
				__sync_add_and_fetch(&leek.stats.recheck_failures, 1);
			else
				leek_result_handle(item->rsa, e, length, sha1_addr);
		}
		wk->stats.hash_count++;
	}

	return 0;
}

const struct leek_implementation leek_impl_openssl = {
	.name      = "OpenSSL",
	.weight    = 1,
	.available = leek_openssl_available,
	.allocate  = leek_openssl_alloc,
	.precalc   = leek_openssl_precalc,
	.exhaust   = leek_openssl_exhaust,
};
