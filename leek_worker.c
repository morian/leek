#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "leek_cpu.h"


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


static uint8_t *leek_crypto_der_alloc(const RSA *rsa, unsigned int *derlen)
{
	uint8_t *der = NULL;
	uint8_t *tmp = NULL;
	unsigned int len;
	int ret;

	/* Encode a PKCS#1 RSAPublicKey structure */
	ret = i2d_RSAPublicKey(rsa, NULL);
	if (ret < 0) {
		leek_crypto_error("DER encoding failed");
		goto out;
	}
	len = ret;

	der = malloc(len);
	if (!der) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		goto out;
	}
	tmp = der;

	ret = i2d_RSAPublicKey(rsa, &tmp);
	if (ret < 0) {
		leek_crypto_error("DER encoding failed");
		goto der_free;
	}

	if (derlen)
		*derlen = len;
out:
	return der;

der_free:
	free(der);
	return NULL;
}


static int leek_crypto_rsa_rekey(struct leek_crypto *lc)
{
	unsigned int derlen;
	uint8_t *der = NULL;
	RSA *rsa = NULL;
	int ret = -1;

	rsa = RSA_new();
	if (!rsa) {
		leek_crypto_error("RSA_new failed");
		goto error;
	}

	/* Bring more entropy to OpenSSL if needed
	 * This prevents RNG starvation during RSA generation phase */
	if (!RAND_status())
		RAND_load_file("/dev/urandom", 1024);

	ret = RSA_generate_key_ex(rsa, leek.config.keysize, lc->big_e, NULL);
	if (!ret) {
		leek_crypto_error("RSA key generation failed");
		goto error;
	}

	der = leek_crypto_der_alloc(rsa, &derlen);
	if (!der)
		goto error;

	if (lc->rsa)
		RSA_free(lc->rsa);
	lc->rsa = rsa;

	leek_sha1_init(lc);
	leek_sha1_precalc(lc, der, derlen - LEEK_RSA_E_SIZE);

#if 0
	printf("HASHLEN: %zu\n", 10 * sizeof(SHA_LONG));
	printf("DERLEN: %u\n", derlen);
	for (int i = 0; i < derlen; ++i) {
		printf("%02x", der[i]);
		if ((i & 0xF) == 0xF)
			printf("\n");
	}
	printf("\n");
	printf("SHA_NUM: %u\n", lc->sha1.hash.num);
#endif

	ret = 0;
out:
	if (der)
		free(der);
	return ret;

error:
	if (rsa)
		RSA_free(rsa);
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


#endif


static void leek_crypto_exit(struct leek_crypto *lc)
{
	if (lc) {
		if (lc->rsa)
			RSA_free(lc->rsa);
		if (lc->big_e)
			BN_free(lc->big_e);
		free(lc);
	}
}


static struct leek_crypto *leek_crypto_init(void)
{
	struct leek_crypto *lc;
	BIGNUM *big_e;

	lc = malloc(sizeof(*lc));
	if (!lc)
		goto out;
	memset(lc, 0, sizeof *lc);

	big_e = BN_new();
	if (!big_e) {
		leek_crypto_error("BN_new failed");
		goto lc_free;
	}

	lc->big_e = big_e;
	BN_set_word(lc->big_e, LEEK_RSA_E_START);

out:
	return lc;

lc_free:
	free(lc);
	return NULL;
}


static void leek_base32_enc(uint8_t *dst, const uint8_t *src)
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
}


static int leek_crypto_rsa_check(RSA *rsa)
{
	BN_CTX *ctx = BN_CTX_new();
	int is_valid = 0;

	BN_CTX_start(ctx);

	BIGNUM *p1 = BN_CTX_get(ctx);     /* p - 1 */
	BIGNUM *q1 = BN_CTX_get(ctx);     /* q - 1 */
	BIGNUM *gcd = BN_CTX_get(ctx);    /* GCD(p - 1, q - 1) */
	BIGNUM *lambda = BN_CTX_get(ctx); /* LCM(p - 1, q - 1) */
	BIGNUM *tmp = BN_CTX_get(ctx);    /* temporary storage */

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BIGNUM const *n = BN_CTX_get(ctx);
	BIGNUM const *e = BN_CTX_get(ctx),
	BIGNUM const *d = BN_CTX_get(ctx);
	BIGNUM const *p = BN_CTX_get(ctx),
	BIGNUM const *q = BN_CTX_get(ctx);
	BIGNUM const *dmp1 = BN_CTX_get(ctx),
	BIGNUM const *dmq1 = BN_CTX_get(ctx),
	BIGNUM const *iqmp = BN_CTX_get(ctx);

	RSA_get0_key(rsa, &n, &e, &d);
	if (!n || !e || !d) {
		leek_crypto_error("RSA_get0_key failed");
		goto out;
	}

	RSA_get0_factors(rsa, &p, &q);
	if (!p || !q) {
		leek_crypto_error("RSA_get0_factors failed");
		goto out;
	}

	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if (!dmp1 || !dmq1 || !iqmp) {
		leek_crypto_error("RSA_get0_crt_params failed");
		goto out;
	}

	BN_sub(p1, p, BN_value_one());      /* p - 1 */
	BN_sub(q1, q, BN_value_one());      /* q - 1 */
#else
	BN_sub(p1, rsa->p, BN_value_one()); /* p - 1 */
	BN_sub(q1, rsa->q, BN_value_one()); /* q - 1 */
#endif

	BN_gcd(gcd, p1, q1, ctx);           /* gcd(p - 1, q - 1) */

	BN_div(tmp, NULL, p1, gcd, ctx);
	BN_mul(lambda, q1, tmp, ctx);       /* lambda(n) */

	/* Check if e is coprime to lambda(n). */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BN_gcd(tmp, lambda, e, ctx);
#else
	BN_gcd(tmp, lambda, rsa->e, ctx);
#endif
	if (!BN_is_one(tmp))
		goto out;

	/* Check if public exponent e is less than n - 1. */
	/* Subtract n from e to avoid checking BN_is_zero. */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BN_sub(tmp, n, BN_value_one());
	if (BN_cmp(e, tmp) >= 0)
		goto out;
#else
	BN_sub(tmp, rsa->n, BN_value_one());
	if (BN_cmp(rsa->e, tmp) >= 0)
		goto out;
#endif

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BIGNUM *new_d = BN_new(),
	BIGNUM *new_dmp1 = BN_new(),
	BIGNUM *new_dmq1 = BN_new(),
	BIGNUM *new_iqmp = BN_new();

	BN_mod_inverse(new_d, e, lambda, ctx);  /* d */
	BN_mod(new_dmp1, new_d, p1, ctx);       /* d mod(p - 1) */
	BN_mod(new_dmq1, new_d, q1, ctx);       /* d mod(q - 1) */
	BN_mod_inverse(new_iqmp, q, p, ctx);    /* q ^ -1 mod p */

	if (!RSA_set0_key(rsa, NULL, NULL, new_d)) {
		leek_crypto_error("RSA_set0_key failed");
		goto out;
	}

	if (!RSA_set0_crt_params(rsa, new_dmp1, new_dmq1, new_iqmp)) {
		leek_crypto_error("RSA_set0_crt_params failed");
		goto out;
	}
#else
	BN_mod_inverse(rsa->d, rsa->e, lambda, ctx);     /* d */
	BN_mod(rsa->dmp1, rsa->d, p1, ctx);              /* d mod(p - 1) */
	BN_mod(rsa->dmq1, rsa->d, q1, ctx);              /* d mod(q - 1) */
	BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);  /* q ^ -1 mod p */
#endif

	/* In theory this should never be true,
	 * unless the guy before me made a mistake ;). */
	if (RSA_check_key(rsa) != 1) {
		leek_crypto_error("RSA_check_key failed");
		goto out;
	}

	is_valid = 1;
out:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return is_valid;
}


static int leek_adress_recheck(const union leek_rawaddr *addr, const RSA *rsa)
{
	union {
		uint8_t digest[SHA_DIGEST_LENGTH];
		union leek_rawaddr address;
	} sha1;
	unsigned int derlen;
	uint8_t *der = NULL;
	int ret = -1;

	der = leek_crypto_der_alloc(rsa, &derlen);
	if (der) {
		SHA1(der, derlen, sha1.digest);
		free(der);
	}
	else
		goto out;

	if (memcmp(&sha1.address, addr, sizeof(*addr))) {
		flockfile(stderr);
		fprintf(stderr, "\naddress recheck failed:\n");
		for (unsigned int i = 0; i < sizeof(*addr); ++i)
			fprintf(stderr, "%02x ", addr->buffer[i]);
		fprintf(stderr, "\n");
		for (unsigned int i = 0; i < sizeof(*addr); ++i)
			fprintf(stderr, "%02x ", sha1.digest[i]);
		fprintf(stderr, "\n");
		funlockfile(stderr);
		goto out;
	}

	ret = 0;
out:
	return ret;
}


static void leek_result_display(RSA *rsa, uint32_t e,
                                const union leek_rawaddr *addr, int length)
{
	uint8_t onion_address[LEEK_ADDRESS_LEN];
	unsigned int popcnt = __builtin_popcount(e);
	unsigned int found_hash_count;
	uint8_t *prv_output;
	BUF_MEM *buffer;
	BIO *bp;

	bp = BIO_new(BIO_s_mem());
	if (!bp)
		/* That would be *SO* bad isn't it? */
		return;

	PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);
	BIO_get_mem_ptr(bp, &buffer);

	prv_output = alloca(buffer->length);
	memcpy(prv_output, buffer->data, buffer->length);
	BIO_free(bp);

	/* Are you excited to find out wich domain we got? */
	leek_base32_enc(onion_address, addr->buffer);

	/* Avoid displaying one extra result */
	found_hash_count = __sync_add_and_fetch(&leek.found_hash_count, 1);
	if (!leek.config.stop_count || found_hash_count <= leek.config.stop_count) {
		flockfile(stdout);
		printf("\n");
		printf("[+] Found %.16s.onion (size=%u, popcnt(e)=%u, ID=%u)\n",
		       onion_address, length, popcnt, found_hash_count);
		printf("%s\n", prv_output);
		funlockfile(stdout);
	}

	/* We only perform exit if we are the thread issuing the last result */
	if (leek.config.stop_count && found_hash_count == leek.config.stop_count) {
		printf("[>] Mess with the best die like the rest!\n");
		exit(EXIT_SUCCESS);
	}
}


int leek_address_check(struct leek_crypto *lc, unsigned int e,
                       const union leek_rawaddr *addr, int length)
{
	uint32_t e_be = htobe32(e);
	int ret = -1;

	/* This is not supposed to happen but let's be carefull here */
	if (length <= 0)
		goto out;

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BIGNUM *new_e;

	new_e = BN_bin2bn(&e_be, LEEK_RSA_E_SIZE, NULL);
	if (!new_e) {
		leek_crypto_error("RSA e assignment failed");
		goto out;
	}

	if(!RSA_set0_key(lc->rsa, NULL, new_e, NULL)) {
		leek_crypto_error("RSA e assignment failed");
		BN_free(e);
		goto out;
	}
#else
	if (!BN_bin2bn((uint8_t *) &e_be, LEEK_RSA_E_SIZE, lc->rsa->e)) {
		leek_crypto_error("RSA e assignment failed");
		goto out;
	}
#endif

	/* Check for bad RSA keys and additional stuff */
	ret = leek_crypto_rsa_check(lc->rsa);
	if (ret < 0)
		goto out;

	/* Our RSA key is shiny as fuck, now we rechecking DER */
	ret = leek_adress_recheck(addr, lc->rsa);
	if (ret < 0)
		goto out;

	leek_result_display(lc->rsa, e, addr, length);
	ret = 0;

out:
	return ret;
}


void *leek_worker(void *arg)
{
	struct leek_worker *wk = arg;
	struct leek_crypto *lc;
	long ret = -1;

	lc = leek_crypto_init();
	if (!lc)
		goto out;

	while (1) {
		ret = leek_crypto_rsa_rekey(lc);
		if (ret < 0)
			goto wk_exit;

		ret = leek_exhaust(wk, lc);
		if (ret < 0)
			goto wk_exit;
	}
	ret = 0;

wk_exit:
	leek_crypto_exit(lc);
out:
	return (void *) ret;
}
