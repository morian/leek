#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "leek.h"


static void leek_crypto_error(const char *prefix)
{
	const char *message;
	unsigned long error;

	error = ERR_get_error();
	message = ERR_reason_error_string(error);

	if (message)
		fprintf(stderr, "error: %s: %s\n", prefix, message);
	else
		fprintf(stderr, "error: %s: code %lu\n", prefix, error);
}


uint8_t *leek_crypto_der_alloc(const RSA *rsa, unsigned int *derlen)
{
	uint8_t *der = NULL;
	uint8_t *tmp = NULL;
	unsigned int len;
	int ret;

	/* Encode a PKCS#1 RSAPublicKey structure */
	ret = i2d_RSAPublicKey(rsa, NULL);
	if (ret < 0) {
		leek_crypto_error("i2d_RSAPublicKey");
		goto out;
	}
	len = ret;

	der = malloc(len);
	if (!der) {
		fprintf(stderr, "error: malloc: %s\n", strerror(errno));
		goto out;
	}
	tmp = der;

	ret = i2d_RSAPublicKey(rsa, &tmp);
	if (ret < 0) {
		leek_crypto_error("i2d_RSAPublicKey");
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


/* Borrowed from OpenSSL RSA generation and tuned here */
static int leek_item_rsa_generate_key(struct leek_rsa_item *item, BIGNUM *big_e)
{
	RSA *rsa = item->rsa;
	/* Meant to be transfered to RSA structure, allocated with BN_new() */
	BIGNUM *rsa_n = NULL;
	BIGNUM *rsa_d = NULL;
	BIGNUM *rsa_e = NULL;
	BIGNUM *rsa_p = NULL;
	BIGNUM *rsa_q = NULL;
	BIGNUM *rsa_dmp1 = NULL;
	BIGNUM *rsa_dmq1 = NULL;
	BIGNUM *rsa_iqmp = NULL;
	/* Used for temporary computations, allocated in context */
	BIGNUM *r0 = NULL;
	BIGNUM *r1 = NULL;
	BIGNUM *r2 = NULL;
	BN_CTX *ctx = NULL;
	int ret = -1;

	ctx = BN_CTX_new();
	if (!ctx)
		goto err;

	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	if (!r0 || !r1 || !r2)
		goto err;

	/* We need the RSA components non-NULL */
	rsa_n    = BN_new();
	rsa_d    = BN_new();
	rsa_e    = BN_new();
	rsa_p    = BN_new();
	rsa_q    = BN_new();
	rsa_dmp1 = BN_new();
	rsa_dmq1 = BN_new();
	rsa_iqmp = BN_new();

	if (!rsa_n || !rsa_d || !rsa_e || !rsa_p || !rsa_q ||
	    !rsa_dmp1 || !rsa_dmq1 || !rsa_iqmp)
		goto err;

	if (!BN_copy(rsa_e, big_e))
		goto err;
	if (!BN_copy(rsa_p, item->prime_p->p))
		goto err;
	if (!BN_copy(rsa_q, item->prime_q->p))
		goto err;

	/* Calculate N here */
	if (!BN_mul(rsa_n, rsa_p, rsa_q, ctx))
		goto err;

	/* Re-order primes */
	if (BN_cmp(rsa_p, rsa_q) < 0) {
		BIGNUM *tmp;

		tmp = rsa_p;
		rsa_p = rsa_q;
		rsa_q = tmp;
	}

	/* Calculate d */
	/* p - 1 */
	if (!BN_sub(r1, rsa_p, BN_value_one()))
		goto err;
	/* q - 1 */
	if (!BN_sub(r2, rsa_q, BN_value_one()))
		goto err;
	/* (p - 1)(q - 1) */
	if (!BN_mul(r0, r1, r2, ctx))
		goto err;

	{
		BIGNUM *pr0 = BN_new();

		if (!pr0)
			goto err;

		BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);

		if (!BN_mod_inverse(rsa_d, rsa_e, pr0, ctx)) {
			fprintf(stderr, "ERROR ON MOD INVERSE 1.\n");
			BN_free(pr0);
			goto err;
		}
		/* We MUST free pr0 before any further use of r0 */
		BN_free(pr0);
	}

	{
		BIGNUM *d = BN_new();

		if (!d)
			goto err;

		BN_with_flags(d, rsa_d, BN_FLG_CONSTTIME);

		/* calculate d mod (p-1) and d mod (q - 1) */
		if (!BN_mod(rsa_dmp1, d, r1, ctx)
				|| !BN_mod(rsa_dmq1, d, r2, ctx)) {
			fprintf(stderr, "ERROR ON MOD.\n");
			BN_free(d);
			goto err;
		}

		/* We MUST free d before any further use of rsa->d */
		BN_free(d);
	}

	{
		BIGNUM *p = BN_new();

		if (!p)
			goto err;

		BN_with_flags(p, rsa_p, BN_FLG_CONSTTIME);

		/* calculate inverse of q mod p */
		if (!BN_mod_inverse(rsa_iqmp, rsa_q, p, ctx)) {
			fprintf(stderr, "ERROR ON MOD INVERSE 2.\n");
			BN_free(p);
			goto err;
		}

		/* We MUST free p before any further use of rsa->p */
		BN_free(p);
	}

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	ret = RSA_set0_key(rsa, rsa_n, rsa_e, rsa_d);
	if (!ret)
		goto err;
	rsa_n = rsa_e = rsa_d = NULL;

	ret = RSA_set0_factors(rsa, rsa_p, rsa_q);
	if (!ret)
		goto err;
	rsa_p = rsa_q = NULL;

	ret = RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp);
	if (!ret)
		goto err;
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL;
#else
	rsa->n = rsa_n;
	rsa->d = rsa_d;
	rsa->e = rsa_e;
	rsa_n = rsa_e = rsa_d = NULL;

	rsa->p = rsa_p;
	rsa->q = rsa_q;
	rsa_p = rsa_q = NULL;

	rsa->dmp1 = rsa_dmp1;
	rsa->dmq1 = rsa_dmq1;
	rsa->iqmp = rsa_iqmp;
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL;
#endif

	ret = 0;
err:
	/* Pointers here are NULL when ownership has been transfered to RSA */
	BN_free(rsa_n);
	BN_free(rsa_d);
	BN_free(rsa_e);
	BN_free(rsa_p);
	BN_free(rsa_q);
	BN_free(rsa_dmp1);
	BN_free(rsa_dmq1);
	BN_free(rsa_iqmp);

	if (ret < 0)
		RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, ERR_LIB_BN);
	if (ctx)
		BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}


static int leek_item_primes_init(struct leek_rsa_item *item)
{
	struct leek_prime *prime_p;
	struct leek_prime *prime_q;
	int ret = -1;

	prime_p = leek_prime_fetch(NULL);
	if (!prime_p)
		goto out;

	prime_q = leek_prime_fetch(prime_p);
	if (!prime_q)
		goto free_p;

	item->prime_p = prime_p;
	item->prime_q = prime_q;

	ret = 0;
out:
	if (ret < 0)
		fprintf(stderr, "error: unable to fetch a prime number!\n");
	return ret;

free_p:
	leek_prime_recycle(prime_p);
	goto out;
}


static void *leek_impl_allocate(void)
{
	return leek.implementation->allocate();
}


static int leek_impl_precalc(struct leek_rsa_item *item, const uint8_t *der, size_t len)
{
	return leek.implementation->precalc(item, der, len);
}


static int leek_item_crypto_init(struct leek_rsa_item *item)
{
	/* Here we don't bother cleaning stuff as it is performed downstream by item_destroy */
	BIGNUM *big_e = NULL;
	void *prv;
	RSA *rsa;
	int ret = -1;

	big_e = BN_new();
	if (!big_e) {
		leek_crypto_error("BN_new");
		goto out;
	}
	BN_set_word(big_e, LEEK_RSA_E_START);

	rsa = RSA_new();
	if (!rsa) {
		leek_crypto_error("RSA_new");
		goto out;
	}
	item->rsa = rsa;

	/* This function replaces 'RSA_generate_key_ex' */
	ret = leek_item_rsa_generate_key(item, big_e);
	if (ret < 0) {
		leek_crypto_error("leek_item_rsa_generate_key");
		goto out;
	}

	prv = leek_impl_allocate();
	if (!prv)
		goto out;
	item->private_data = prv;

	ret = 0;
out:
	if (big_e)
		BN_free(big_e);
	return ret;
}


static int leek_item_crypto_precalc(struct leek_rsa_item *item)
{
	unsigned int derlen;
	uint8_t *der = NULL;
	int ret = -1;

	der = leek_crypto_der_alloc(item->rsa, &derlen);
	if (!der)
		goto out;

	ret = leek_impl_precalc(item, der, derlen);
	if (ret < 0)
		goto out;

out:
	if (der)
		free(der);
	return ret;
}


void leek_item_destroy(struct leek_rsa_item *item)
{
	if (item) {
		if (item->flags & LEEK_RSA_ITEM_DESTROY) {
			leek_prime_destroy(item->prime_p);
			leek_prime_destroy(item->prime_q);
		}
		else {
			leek_prime_recycle(item->prime_p);
			leek_prime_recycle(item->prime_q);
		}
		if (item->rsa)
			RSA_free(item->rsa);
		if (item->private_data)
			free(item->private_data);
		free(item);
	}
}


struct leek_rsa_item *leek_item_generate(void)
{
	struct leek_rsa_item *item;
	int ret;

	item = malloc(sizeof *item);
	if (!item)
		goto out;
	memset(item, 0, sizeof *item);

	ret = leek_item_primes_init(item);
	if (ret < 0)
		goto error;

	ret = leek_item_crypto_init(item);
	if (ret < 0)
		goto error;

	ret = leek_item_crypto_precalc(item);
	if (ret < 0)
		goto error;

out:
	return item;

error:
	leek_item_destroy(item);
	return NULL;
}
