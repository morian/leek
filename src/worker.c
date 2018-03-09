#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "leek.h"


/* Bunch of beautiful wrappers here */
static void *leek_impl_allocate(void)
{
	return leek.implementation->allocate();
}

static int leek_impl_precalc(struct leek_crypto *lc, const uint8_t *der, size_t len)
{
	return leek.implementation->precalc(lc, der, len);
}

static int leek_impl_exhaust(struct leek_worker *wk, struct leek_crypto *lc)
{
	return leek.implementation->exhaust(wk, lc);
}


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


#ifdef DEBUG
static void leek_crypto_der_show(const uint8_t *der, unsigned int len, FILE *fp)
{
	flockfile(fp);

	fprintf(fp, "DER (%3u):\n", len);

	for (unsigned int i = 0; i < len; ++i) {
		fprintf(fp, "%02x", der[i]);
		if ((i & 0xF) == 0xF)
			fprintf(fp, "\n");
	}
	fprintf(fp, "\n");

	funlockfile(fp);
}
#else
# define leek_crypto_der_show(...)
#endif


static int leek_crypto_rsa_rekey(struct leek_crypto *lc)
{
	unsigned int derlen;
	uint8_t *der = NULL;
	RSA *rsa = NULL;
	int ret;

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

	ret = leek_impl_precalc(lc, der, derlen);
	if (ret < 0)
		goto error;
	lc->rsa = rsa;

	leek_crypto_der_show(der, derlen, stderr);

	ret = 0;
out:
	if (der)
		free(der);
	return ret;

error:
	if (rsa)
		RSA_free(rsa);
	ret = -1;
	goto out;
}


static void leek_crypto_exit(struct leek_crypto *lc)
{
	if (lc->rsa)
		RSA_free(lc->rsa);
	if (lc->big_e)
		BN_free(lc->big_e);
	if (lc->private_data)
		free(lc->private_data);
}


static int leek_crypto_init(struct leek_crypto *lc)
{
	int ret = -1;
	BIGNUM *big_e;
	void *prv_data;

	big_e = BN_new();
	if (!big_e) {
		leek_crypto_error("BN_new failed");
		goto out;
	}

	prv_data = leek_impl_allocate();
	if (!prv_data)
		goto out;

	memset(lc, 0, sizeof *lc);
	BN_set_word(big_e, LEEK_RSA_E_START);
	lc->big_e = big_e;
	lc->private_data = prv_data;
	ret = 0;

out:
	return ret;
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
	if (der)
		SHA1(der, derlen, sha1.digest);
	else
		goto out;

	if (memcmp(&sha1.address, addr, sizeof(*addr))) {
		flockfile(stderr);
		fprintf(stderr, "\naddress recheck failed\n");
		leek_crypto_der_show(der, derlen, stderr);
		funlockfile(stderr);
		goto der_free;
	}

	ret = 0;
der_free:
	free(der);
out:
	return ret;
}


static void leek_result_write(const uint8_t *onion, const uint8_t *prv_key,
                              size_t prv_len)
{
	size_t result_path_sz;
	char *result_path;
	int ret;
	int fd;

	result_path_sz = strlen(leek.config.result_dir) + LEEK_ADDRESS_LEN
	                 + strlen(".onion.key") + 2;
	result_path = alloca(result_path_sz);

	snprintf(result_path, result_path_sz, "%s/%.16s.onion.key",
	         leek.config.result_dir, onion);

	fd = open(result_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "[-] open failed: %s\n", strerror(errno));
		return;
	}

	ret = write(fd, prv_key, prv_len);
	if (ret < 0)
		fprintf(stderr, "[-] write failed: %s\n", strerror(errno));
	close(fd);
}


void leek_result_display(RSA *rsa, uint32_t e, int length,
                         const union leek_rawaddr *addr)
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

	/* Are you excited to find out which domain we got? */
	leek_base32_enc(onion_address, addr->buffer);

	/* Avoid displaying one extra result */
	found_hash_count = __sync_add_and_fetch(&leek.found_hash_count, 1);
	if (!leek.config.stop_count || found_hash_count <= leek.config.stop_count) {
		flockfile(stdout);
		printf("\n");
		printf("[+] Found %.16s.onion (size=%u, popcnt(e)=%u, ID=%u)\n",
		       onion_address, length, popcnt, found_hash_count);

		if (leek.config.result_dir)
			leek_result_write(onion_address, prv_output, buffer->length);
		else {
			fwrite_unlocked(prv_output, buffer->length, 1, stdout);
			putchar_unlocked('\n');
		}
		funlockfile(stdout);
	}

	/* Clear underlying memory for private key export. */
	memset(prv_output, 0, buffer->length);
	BIO_free(bp);

	/* We only perform exit if we are the thread issuing the last result */
	if (leek.config.stop_count && found_hash_count == leek.config.stop_count) {
		if (leek.config.flags & LEEK_OPTION_VERBOSE) {
			if (popcnt & 1)
				printf("[>] Mess with the best die like the rest!\n");
			else
				printf("[>] There is no right and wrong. There's only fun and boring.\n");
		}
		exit(EXIT_SUCCESS);
	}
}


int leek_address_check(struct leek_crypto *lc, unsigned int e,
                       const union leek_rawaddr *addr)
{
	uint32_t e_be = htobe32(e);
	int ret = -1;

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

	ret = 0;
out:
	return ret;
}


void *leek_worker(void *arg)
{
	struct leek_worker *wk = arg;
	struct leek_crypto *lc = alloca(sizeof(*lc));
	long ret;

	ret = leek_crypto_init(lc);
	if (ret < 0)
		goto out;

	while (1) {
		ret = leek_crypto_rsa_rekey(lc);
		if (ret < 0)
			goto wk_exit;

		ret = leek_impl_exhaust(wk, lc);
		if (ret < 0)
			goto wk_exit;
	}
	ret = 0;

wk_exit:
	leek_crypto_exit(lc);
out:
	return (void *) ret;
}
