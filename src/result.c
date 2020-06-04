#include <alloca.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "leek.h"


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
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;
	const BIGNUM *p;
	const BIGNUM *q;
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;

	RSA_get0_key(rsa, &n, &e, &d);
	if (!n || !e || !d)
		goto out;

	RSA_get0_factors(rsa, &p, &q);
	if (!p || !q)
		goto out;

	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if (!dmp1 || !dmq1 || !iqmp)
		goto out;

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
	BIGNUM *new_d = BN_new();
	BIGNUM *new_dmp1 = BN_new();
	BIGNUM *new_dmq1 = BN_new();
	BIGNUM *new_iqmp = BN_new();

	BN_mod_inverse(new_d, e, lambda, ctx);  /* d */
	BN_mod(new_dmp1, new_d, p1, ctx);       /* d mod(p - 1) */
	BN_mod(new_dmq1, new_d, q1, ctx);       /* d mod(q - 1) */
	BN_mod_inverse(new_iqmp, q, p, ctx);    /* q ^ -1 mod p */

	if (!RSA_set0_key(rsa, NULL, NULL, new_d))
		goto out;

	if (!RSA_set0_crt_params(rsa, new_dmp1, new_dmq1, new_iqmp))
		goto out;

#else
	BN_mod_inverse(rsa->d, rsa->e, lambda, ctx);     /* d */
	BN_mod(rsa->dmp1, rsa->d, p1, ctx);              /* d mod(p - 1) */
	BN_mod(rsa->dmq1, rsa->d, q1, ctx);              /* d mod(q - 1) */
	BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);  /* q ^ -1 mod p */
#endif

	/* In theory this should never be true,
	 * unless the guy before me made a mistake ;). */
	if (RSA_check_key(rsa) != 1)
		goto out;

	is_valid = 1;
out:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return is_valid;
}


static struct leek_result *leek_result_alloc(void)
{
	struct leek_result *result;

	result = malloc(sizeof *result);
	if (result)
		memset(result, 0, sizeof *result);
	return result;
}


static void leek_result_free(struct leek_result *result)
{
	if (result) {
		free(result->prv_data);
		free(result);
	}
}


void leek_results_purge(void)
{
	struct leek_result *item;
	struct leek_result *item_next;
	struct leek_result *head;

	pthread_mutex_lock(&leek.terminal.ring.lock);
	head = leek.terminal.ring.head;
	item = head;

	do {
		if (item) {
			item_next = item->next;
			leek_result_free(item);
			item = item_next;
		}
	} while (item != head);

	pthread_mutex_unlock(&leek.terminal.ring.lock);
}


static void leek_result_display(struct leek_result *item, bool verbose)
{
	unsigned int popcnt = __builtin_popcount(item->exponent);

	printf("> %.16s.onion (len:%u, e:0x%08x (%2u), id=%u)\n",
	       item->address, item->address_length, item->exponent,
	       popcnt, item->id);

	if (verbose) {
		fwrite(item->prv_data, item->prv_length, 1, stdout);
		putchar('\n');
	}
}


void leek_result_new_display(bool verbose)
{
	struct leek_result *item;
	unsigned int count;

	pthread_mutex_lock(&leek.terminal.ring.lock);
	count = leek.terminal.ring.count;
	if (count) {
		item = leek.terminal.ring.head;

		count = 0;
		do {
			if (item && !(item->flags & LEEK_RESULT_FLAG_DISPLAYED)) {
				leek_result_display(item, verbose);
				__sync_fetch_and_or(&item->flags, LEEK_RESULT_FLAG_DISPLAYED);
				item = item->next;
				count++;
			}
		} while (item && !(item->flags & LEEK_RESULT_FLAG_DISPLAYED));

		if (count > 1)
			printf("\n");
	}
	pthread_mutex_unlock(&leek.terminal.ring.lock);
}


void leek_result_found_display(bool verbose)
{
	struct leek_result *head;
	struct leek_result *item;
	unsigned int count;

	pthread_mutex_lock(&leek.terminal.ring.lock);
	count = leek.terminal.ring.count;
	if (!count)
		printf("[+] No result to display.\n\n");
	else {
		printf("[+] Showing list of last %u items (%lu successes)\n",
		       leek.terminal.ring.count, leek.stats.successes);
		head = leek.terminal.ring.head;
		item = head;

		do {
			if (item) {
				leek_result_display(item, verbose);
				item = item->next;
			}
		} while (item != head);

		if (count > 1)
			printf("\n");
	}
	pthread_mutex_unlock(&leek.terminal.ring.lock);
}


static void leek_result_push(struct leek_result *result)
{
	struct leek_result *cleanup = NULL;
	struct leek_result *cleanup_next;
	struct leek_result *head;
	unsigned int count;

	pthread_mutex_lock(&leek.terminal.ring.lock);
	count = leek.terminal.ring.count;
	head = leek.terminal.ring.head;

	if (count >= LEEK_TERMINAL_RING_MAX) {
		unsigned int remove_count = LEEK_TERMINAL_RING_MAX - count + 1;
		struct leek_result *item;

		count = count - remove_count;
		cleanup = head->prev;

		for (item = cleanup; remove_count > 0; remove_count--)
			item = item->prev;

		/* item is the first item we do not want to remove */
		item->next->prev = NULL;
		item->next = head;
		head->prev = item;
	}

	/* Set the bidirectional links up */
	if (head) {
		result->next = head;
		result->prev = head->prev;
		head->prev->next = result;
		head->prev = result;
	}
	else {
		result->next = result;
		result->prev = result;
	}

	leek.terminal.ring.head = result;
	leek.terminal.ring.count = count + 1;
	pthread_mutex_unlock(&leek.terminal.ring.lock);

	while (cleanup) {
		cleanup_next = cleanup->prev;
		leek_result_free(cleanup);
		cleanup = cleanup_next;
	}
}


static int leek_result_address_recheck(const union leek_rawaddr *addr, const RSA *rsa)
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

	if (memcmp(&sha1.address, addr, sizeof(*addr)))
		goto der_free;

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

	result_path_sz = strlen(leek.options.result_dir) + LEEK_ADDRESS_LEN
	                 + strlen(".onion.key") + 2;
	result_path = alloca(result_path_sz);

	snprintf(result_path, result_path_sz, "%s/%.16s.onion.key",
	         leek.options.result_dir, onion);

	fd = open(result_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		ret = write(fd, prv_key, prv_len);
		if (ret < 0)
			fprintf(stderr, "error: result write: %s\n", strerror(errno));
		close(fd);
	}
	else
		fprintf(stderr, "error: result open: %s\n", strerror(errno));
}


void leek_result_handle(RSA *rsa, uint32_t exponent, int length,
                        const union leek_rawaddr *addr)
{
	uint8_t onion_address[LEEK_ADDRESS_LEN];
	unsigned int popcnt = __builtin_popcount(exponent);
	struct leek_result *result = NULL;
	bool prv_output_free = true;
	unsigned int result_id;
	uint8_t *prv_output;
	BUF_MEM *buffer;
	BIO *bp;

	bp = BIO_new(BIO_s_mem());
	if (!bp)
		/* That would be *SO* bad isn't it? */
		return;

	PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);
	BIO_get_mem_ptr(bp, &buffer);

	prv_output = malloc(buffer->length);
	if (!prv_output) {
		prv_output = alloca(buffer->length);
		prv_output_free = false;
	}

	memcpy(prv_output, buffer->data, buffer->length);

	/* Are you excited to find out which domain we got? */
	leek_base32_enc(onion_address, addr->buffer);

	if (leek.options.result_dir)
		leek_result_write(onion_address, prv_output, buffer->length);

	result_id = __sync_fetch_and_add(&leek.stats.successes, 1);

	/* It is useless to create a structure if we cannot attach prv_output to it */
	if (prv_output_free)
		result = leek_result_alloc();

	if (!result) {
		/* We don't want to loose a potential important result so we print it */
		flockfile(stdout);
		printf("> %.16s.onion (len:%u, e:0x%08x (%2u), id=%u)\n",
		       onion_address, length, exponent, popcnt, result_id);

		if (!leek.options.result_dir) {
			fwrite_unlocked(prv_output, buffer->length, 1, stdout);
			putchar_unlocked('\n');
		}
		funlockfile(stdout);

		prv_output_free = true;
	}
	else {
		result->id = result_id;
		memcpy(&result->address, onion_address, LEEK_ADDRESS_LEN);
		result->address_length = length;
		result->prv_data = prv_output;
		result->prv_length = buffer->length;
		result->exponent = exponent;
		result->flags = 0;

		leek_result_push(result);
		prv_output_free = false;
	}

	leek_events_notify(LEEK_EVENT_NEW_RESULT);

	if (prv_output_free)
		free(prv_output);
	BIO_free(bp);
}


int leek_result_recheck(struct leek_rsa_item *item, unsigned int exponent,
                        const union leek_rawaddr *addr)
{
	uint32_t e_be = htobe32(exponent);
	RSA *rsa = item->rsa;
	int ret = -1;

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1
	BIGNUM *new_e;

	new_e = BN_bin2bn((uint8_t *) &e_be, LEEK_RSA_E_SIZE, NULL);
	if (!new_e)
		goto out;

	if (!RSA_set0_key(rsa, NULL, new_e, NULL)) {
		BN_free(new_e);
		goto out;
	}
#else
	if (!BN_bin2bn((uint8_t *) &e_be, LEEK_RSA_E_SIZE, rsa->e))
		goto out;
#endif

	/* Check for bad RSA keys and additional stuff */
	ret = leek_crypto_rsa_check(rsa);
	if (ret < 0)
		goto out;

	/* Our RSA key is shiny as fuck, now we rechecking DER */
	ret = leek_result_address_recheck(addr, rsa);
	if (ret < 0)
		goto out;

	ret = 0;
out:
	return ret;
}
