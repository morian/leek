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

	ret = RSA_generate_key_ex(rsa, LEEK_RSA_KEYSIZE, lc->big_e, NULL);
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
