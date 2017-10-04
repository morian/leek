#define _DEFAULT_SOURCE
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "leek_cpu.h"


/* This value ensures that our exponent will always be 4 bytes wide
 * We may consider starting at RSA_F4 instead and handle 3 bytes exponent. */
#define LEEK_RSA_E_SIZE                 4 /* bytes */
#define LEEK_RSA_E_START       0x01000001
/* This limit allows for 8 parallel computations */
#define LEEK_RSA_E_LIMIT       0xFFFFFFF9


/* Holds the crypto stuff we need in workers */
struct leek_crypto {
	RSA          *rsa;
	SHA_CTX      hash;
	BIGNUM       *big_e;
	unsigned int e;
};


/* TODO: do something clean for SHA1 computation here */
static void leek_sha1_init(struct leek_crypto *lc)
{
	SHA1_Init(&lc->hash);
}

static void leek_sha1_update(struct leek_crypto *lc, const void *ptr, size_t len)
{
	SHA1_Update(&lc->hash, ptr, len);
}

#if 0
static void leek_sha1_final(struct leek_crypto *lc, uint8_t *buffer)
{
	SHA1_Final(buffer, &lc->hash);
}
#endif


static void leek_crypto_error(const char *prefix)
{
	const char *message;
	unsigned long error;

	error = ERR_get_error();
	message = ERR_reason_error_string(error);

	if (message)
		fprintf(stderr, "[-] %s: %s\n", prefix, message);
	else
		fprintf(stderr, "[-] %s: code %lu\n", prefix, error);
}


static int leek_crypto_rsa_rekey(struct leek_crypto *lc)
{
	uint8_t *der = NULL;
	uint8_t *tmp = NULL;
	int ret = -1;
	int derlen;

	if (lc->rsa)
		RSA_free(lc->rsa);
	lc->rsa = RSA_new();

	/* Bring more entropy to OpenSSL if needed
	 * This prevents RNG starvation during RSA generation phase */
	if (!RAND_status())
		RAND_load_file("/dev/urandom", 1024);

	ret = RSA_generate_key_ex(lc->rsa, leek.config.keysize, lc->big_e, NULL);
	if (!ret) {
		leek_crypto_error("RSA key generation failed");
		goto error;
	}

	/* Encode a PKCS#1 RSAPublicKey structure */
	ret = i2d_RSAPublicKey(lc->rsa, NULL);
	if (ret < 0) {
		leek_crypto_error("DER encoding failed");
		goto error;
	}
	derlen = ret;

	der = malloc(derlen);
	if (!der) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		goto error;
	}
	tmp = der;

	ret = i2d_RSAPublicKey(lc->rsa, &tmp);
	if (ret < 0) {
		leek_crypto_error("DER encoding failed");
		goto error;
	}


	leek_sha1_init(lc);
	leek_sha1_update(lc, der, derlen - LEEK_RSA_E_SIZE);

	printf("HASHLEN: %zu\n", 10 * sizeof(SHA_LONG));
	printf("DERLEN: %u\n", derlen);
	for (int i = 0; i < derlen; ++i) {
		printf("%02x", der[i]);
		if ((i & 0xF) == 0xF)
			printf("\n");
	}
	printf("\n");
	printf("SHA_NUM: %u\n", lc->hash.num);

	/* DER can be freed here since it only populates the initial SHA1 buffer */
	free(der);

	ret = 0;
out:
	return ret;

error:
	ret = -1;
	goto out;
}


#if 0
/**
 * Re-implement with void *src
 * - cast 'src' to uint64_t
 *
 * v = *((uint64_t *) (src + 0));
 * for (int i = 0; i < 8; ++i)
 *      dst[i] = LEEK_BASE32_ALPHABET[v & 0x1F]
 *      v >>= 5
 * v = *((uint64_t *) (src + 5));
 * for (int i = 8; i < 16; ++i)
 *      dst[i] = LEEK_BASE32_ALPHABET[v & 0x1F]
 *      v >>= 5
 *
 */


static void base32_enc(uint8_t *dst, uint8_t *src)
{
	dst[ 0] = LEEK_BASE32_ALPHABET[ (src[0] >> 3)                       ];
	dst[ 1] = LEEK_BASE32_ALPHABET[((src[0] << 2) | (src[1] >> 6))  & 31];
	dst[ 2] = LEEK_BASE32_ALPHABET[ (src[1] >> 1)                   & 31];
	dst[ 3] = LEEK_BASE32_ALPHABET[((src[1] << 4) | (src[2] >> 4))  & 31];
	dst[ 4] = LEEK_BASE32_ALPHABET[((src[2] << 1) | (src[3] >> 7))  & 31];
	dst[ 5] = LEEK_BASE32_ALPHABET[ (src[3] >> 2)                   & 31];
	dst[ 6] = LEEK_BASE32_ALPHABET[((src[3] << 3) | (src[4] >> 5))  & 31];
	dst[ 7] = LEEK_BASE32_ALPHABET[  src[4]                         & 31];

	dst[ 8] = LEEK_BASE32_ALPHABET[ (src[5] >> 3)                       ];
	dst[ 9] = LEEK_BASE32_ALPHABET[((src[5] << 2) | (src[6] >> 6))  & 31];
	dst[10] = LEEK_BASE32_ALPHABET[ (src[6] >> 1)                   & 31];
	dst[11] = LEEK_BASE32_ALPHABET[((src[6] << 4) | (src[7] >> 4))  & 31];
	dst[12] = LEEK_BASE32_ALPHABET[((src[7] << 1) | (src[8] >> 7))  & 31];
	dst[13] = LEEK_BASE32_ALPHABET[ (src[8] >> 2)                   & 31];
	dst[14] = LEEK_BASE32_ALPHABET[((src[8] << 3) | (src[9] >> 5))  & 31];
	dst[15] = LEEK_BASE32_ALPHABET[  src[9]                         & 31];

	dst[16] = '\0';
}
#endif


static void leek_crypto_exit(struct leek_crypto *lc)
{
	if (lc) {
		RSA_free(lc->rsa);
		BN_free(lc->big_e);
		free(lc);
	}
}


static struct leek_crypto *leek_crypto_init(void)
{
	struct leek_crypto *lc;

	lc = malloc(sizeof(*lc));
	if (!lc)
		goto out;
	memset(lc, 0, sizeof *lc);

	lc->big_e = BN_new();
	BN_set_word(lc->big_e, LEEK_RSA_E_START);

out:
	return lc;
}


/* TODO: move me elsewhere 'cause im hot */
static int leek_worker_rsa_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
{
	uint8_t sha1_buffer[SHA_DIGEST_LENGTH];
	unsigned int e = LEEK_RSA_E_START - 2;
	unsigned int e_be;
	SHA_CTX hash;

	while (e < LEEK_RSA_E_LIMIT) {
		/* TODO: optimize deeply sha1 computation here (gcc intrinsics, SSE, etc...) */
		e += 2;
		e_be = htobe32(e);
		memcpy(&hash, &lc->hash, 10 * sizeof(SHA_LONG));
		hash.num = lc->hash.num;

		SHA1_Update(&hash, &e_be, LEEK_RSA_E_SIZE);
		SHA1_Final(sha1_buffer, &hash);

		/* This is not required here */
		// base32_enc(onion_addr, sha1_buffer);
		wk->hash_count++;
	}

	return 0;
}


static void leek_crypto_test(void)
{
	uint8_t sha1_dgst[SHA_DIGEST_LENGTH];
	SHA_CTX sha1;

	SHA1_Init(&sha1);
	SHA1_Final(sha1_dgst, &sha1);

	for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
		printf("%02x", sha1_dgst[i]);
	printf("\n");
}


void *leek_worker(void *arg)
{
	struct leek_worker *wk = arg;
	struct leek_crypto *lc;
	long ret = -1;

	lc = leek_crypto_init();
	if (!lc)
		goto out;

	leek_crypto_test();

	while (1) {
		ret = leek_crypto_rsa_rekey(lc);
		if (ret < 0)
			goto wk_exit;

		ret = leek_worker_rsa_exhaust(wk, lc);
		if (ret < 0)
			goto wk_exit;
	}
	ret = 0;

wk_exit:
	leek_crypto_exit(lc);
out:
	return (void *) ret;
}
