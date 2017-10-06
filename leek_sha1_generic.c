#include <stdint.h>

#define LEEK_SHA1_COPY_SIZE  (10 * sizeof(SHA_LONG))

static uint64_t leek_lookup_mask[LEEK_LENGTH_MAX + 1] = {
	0xFFFFFFFFFFFFFFFF, /* impossible (len = 0) */
	0xFFFFFFFFFFFFFFFF, /* disabled   (len = 1) */
	0xFFFFFFFFFFFFFFFF, /* disabled   (len = 2) */
	0xFFFFFFFFFFFFFFFF, /* disabled   (len = 3) */
	0xFFFFFFFFFFFFFF0F,
	0xFFFFFFFFFFFF7F00,
	0xFFFFFFFFFFFF0300,
	0xFFFFFFFFFF1F0000,
	0xFFFFFFFFFF000000,
	0xFFFFFFFF07000000,
	0xFFFFFF3F00000000,
	0xFFFFFF0100000000,
	0xFFFF0F0000000000,
	0xFF7F000000000000,
	0xFF03000000000000,
	0x1F00000000000000,
	0x0000000000000000,
};


static int leek_lookup(const union leek_rawaddr *addr)
{
	struct leek_prefix_bucket *bucket = &leek.prefixes->bucket[addr->index];
	uint64_t val;

	if (bucket->data) {
		for (unsigned int i = leek.config.len_min; i <= leek.config.len_max; ++i) {
			val = addr->suffix | leek_lookup_mask[i];
			if (bsearch(&val, bucket->data, bucket->cur_count, sizeof(val),
			            &leek_prefixes_suffix_cmp)) {
				return i; /* return found size */
			}
		}
	}
	return 0;
}


void leek_sha1_init(struct leek_crypto *lc)
{
	SHA1_Init(&lc->sha1.hash);
}

void leek_sha1_precalc(struct leek_crypto *lc, const void *ptr, size_t len)
{
	SHA1_Update(&lc->sha1.hash, ptr, len);
}

int leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
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

		length = leek_lookup(sha1_addr);
		if (length) {
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
