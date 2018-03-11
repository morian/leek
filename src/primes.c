#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "leek.h"


/* Create a new prime number for provided pool_id (no attach) */
static struct leek_prime *leek_prime_create(unsigned int pool_id)
{
	struct leek_prime *prime;
	bool is_valid = false;
	BN_CTX *ctx = NULL;
	BIGNUM *p;
	BIGNUM *r1;
	BIGNUM *r2;

	prime = malloc(sizeof *prime);
	if (!prime)
		goto out;

	p = BN_new();
	if (!p)
		goto prime_free;

	ctx = BN_CTX_new();
	if (!ctx)
		goto p_free;
	BN_CTX_start(ctx);

	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	if (!r1 || !r2)
		goto ctx_free;

	do {
		/* Ensures that OpenSSL has enought entropy */
		if (!RAND_status())
			RAND_load_file("/dev/urandom", 4096);

		if (!BN_generate_prime_ex(p, LEEK_RSA_PRIME_SIZE, 0, NULL, NULL, NULL))
			goto ctx_free;
		if (!BN_sub(r2, p, BN_value_one()))
			goto ctx_free;
		if (!BN_gcd(r1, r2, leek.primes.e, ctx))
			goto ctx_free;

		is_valid = BN_is_one(r1);
	} while (!is_valid);

	prime->pool_id = pool_id;
	prime->lifetime = LEEK_PRIME_LIFETIME;
	prime->next_pool = LEEK_PRIME_NEXT_POOL(pool_id);
	prime->match_mask = 0;
	prime->p = p;

	__sync_fetch_and_add(&leek.primes.stats.generated, 1);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
out:
	return prime;

ctx_free:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
p_free:
	BN_free(p);
prime_free:
	free(prime);
	goto out;
}


static struct leek_prime *leek_prime_pool_fetch(unsigned int pool_id)
{
	struct leek_primes_pool *pool = &leek.primes.pool[pool_id];
	struct leek_prime *prime = NULL;
	unsigned int read;

	if (pool_id < LEEK_PRIMES_POOL_COUNT) {
		pthread_spin_lock(&pool->lock);
		read = pool->read;
		prime = pool->prime[read];
		pool->prime[read] = NULL;

		if (prime)
			pool->read = (read + 1) & LEEK_PRIMES_POOL_DEPTH_MASK;
		pthread_spin_unlock(&pool->lock);

		if (!prime)
			prime = leek_prime_create(pool_id);
	}

	return prime;
}


/* Global next pool to be used for first prime */
static inline unsigned int leek_primes_next_pool(void)
{
	return (__sync_fetch_and_add(&leek.primes.next_pool_id, 1)
	        & LEEK_PRIMES_POOL_MASK);
}


/* Whether a prime has a match with provided pool_id */
static inline bool leek_prime_has_match(struct leek_prime *prime, unsigned int pool_id)
{
	prime_mask_t check = ((prime_mask_t) 1) << pool_id;
	return !!(check & prime->match_mask);
}

/* Record a matched encounter between prime and the pool_id */
static inline void leek_prime_set_match(struct leek_prime *prime, unsigned int pool_id)
{
	prime_mask_t mask = (((prime_mask_t) 1) << pool_id);

	/* Do not decrement lifetime when bit is already set */
	if (!(prime->match_mask & mask)) {
		prime->match_mask |= mask;
		prime->lifetime--;
	}
}


/* Find the next matching pool of a used prime */
static inline unsigned int leek_prime_next_pool(struct leek_prime *prime)
{
	unsigned int next_pool;

	for (unsigned int i = 0; i < LEEK_PRIMES_POOL_COUNT; ++i) {
		next_pool = (prime->next_pool + i) & LEEK_PRIMES_POOL_MASK;
		if (!leek_prime_has_match(prime, next_pool))
			return next_pool;
	}
	/* This is an error condition here (but cannot happen in theory) */
	return LEEK_PRIMES_POOL_COUNT;
}


/* Fetch a first or second prime here (depends on partner is NULL) */
struct leek_prime *leek_prime_fetch(struct leek_prime *partner)
{
	struct leek_prime *prime;
	unsigned int pool_id;
	bool has_prime = false;

	/* Check if we need to find a partner to an existing prime */
	pool_id = (partner) ? leek_prime_next_pool(partner)
	                    : leek_primes_next_pool();

	do {
		prime = leek_prime_pool_fetch(pool_id);

		if (partner && prime) {
			/* Do it again if both of our primes are the same
			 * This is highly improbable but let us make safe here */
			if (!BN_cmp(prime->p, partner->p)) {
				leek_prime_destroy(prime);
				continue;
			}

			/* Record the encounter so that both will not be matched again */
			leek_prime_set_match(prime, partner->pool_id);
			leek_prime_set_match(partner, prime->pool_id);
			partner->next_pool = (partner->next_pool + 1) & LEEK_PRIMES_POOL_MASK;
		}

		has_prime = true;
	} while (!has_prime);

	return prime;
}


void leek_prime_destroy(struct leek_prime *prime)
{
	if (prime) {
		BN_free(prime->p);
		free(prime);
	}
}


static void leek_prime_requeue(struct leek_prime *n_prime)
{
	struct leek_primes_pool *pool = &leek.primes.pool[n_prime->pool_id];
	struct leek_prime *o_prime = NULL;
	unsigned int write;

	pthread_spin_lock(&pool->lock);
	write = pool->write;
	o_prime = pool->prime[write];

	if (o_prime && o_prime->lifetime > n_prime->lifetime)
		o_prime = n_prime;
	else
		pool->prime[write] = n_prime;
	pool->write = (write + 1) & LEEK_PRIMES_POOL_DEPTH_MASK;
	pthread_spin_unlock(&pool->lock);

	if (o_prime) {
		__sync_fetch_and_add(&leek.primes.stats.evicted, 1);
		leek_prime_destroy(o_prime);
	}
	__sync_fetch_and_add(&leek.primes.stats.requeued, 1);
}


void leek_prime_recycle(struct leek_prime *prime)
{
	if (prime) {
		if (prime->lifetime)
			leek_prime_requeue(prime);
		else {
			/* End of life was reached for this sir */
			leek_prime_destroy(prime);
			__sync_fetch_and_add(&leek.primes.stats.exhausted, 1);
		}
	}
}


int leek_primes_init(void)
{
	int ret = 0;
	BIGNUM *e;

	/* Everything else is already initialized to zero here */

	e = BN_new();
	if (!e)
		goto out;
	BN_set_word(e, LEEK_RSA_E_START);

	leek.primes.e = e;
	for (unsigned int i = 0; i < LEEK_PRIMES_POOL_COUNT; ++i)
		pthread_spin_init(&leek.primes.pool[i].lock, PTHREAD_PROCESS_PRIVATE);

	ret = 0;
out:
	return ret;
}


void leek_primes_exit(void)
{
	for (unsigned int i = 0; i < LEEK_PRIMES_POOL_COUNT; ++i) {
		for (unsigned int j = 0; j < LEEK_PRIMES_POOL_DEPTH; ++j)
			leek_prime_destroy(leek.primes.pool[i].prime[j]);
		pthread_spin_destroy(&leek.primes.pool[i].lock);
	}
	BN_free(leek.primes.e);
}
