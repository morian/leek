#ifndef __LEEK_PRIMES_H
# define __LEEK_PRIMES_H
# include <pthread.h>
# include <stdint.h>
# include <openssl/bn.h>

/* How many primes we keep in each pool */
# define LEEK_PRIMES_POOL_DEPTH_ORDER                                   5

# define LEEK_PRIMES_POOL_DEPTH    (1ULL << LEEK_PRIMES_POOL_DEPTH_ORDER)
# define LEEK_PRIMES_POOL_DEPTH_MASK         (LEEK_PRIMES_POOL_DEPTH - 1)

/* How many pools of prime numbers we have */
# define LEEK_PRIMES_POOL_ORDER                                         4

/* Dirty way to create a bitmask (but is fine for our use) */
# if   LEEK_PRIMES_POOL_ORDER == 3
	typedef uint8_t prime_mask_t;
# elif LEEK_PRIMES_POOL_ORDER == 4
	typedef uint16_t prime_mask_t;
# elif LEEK_PRIMES_POOL_ORDER == 5
	typedef uint32_t prime_mask_t;
# elif LEEK_PRIMES_POOL_ORDER == 6
	typedef uint64_t prime_mask_t;
# elif LEEK_PRIMES_POOL_ORDER == 7
	typedef __uint128_t prime_mask_t;
# else
#  error "Invalid value for PRIMES_POOL_ORDER."
# endif

# define LEEK_PRIMES_POOL_COUNT (((prime_mask_t) 1) << LEEK_PRIMES_POOL_ORDER)
# define LEEK_PRIMES_POOL_MASK                    (LEEK_PRIMES_POOL_COUNT - 1)

/* How many times a prime number can be used (at most) */
# define LEEK_PRIME_LIFETIME                     LEEK_PRIMES_POOL_COUNT
# define LEEK_PRIME_NEXT_POOL(_pool_id)          \
	(((_pool_id) + (1 << (LEEK_PRIMES_POOL_ORDER - 1))) & LEEK_PRIMES_POOL_MASK)


struct leek_prime {
	unsigned int pool_id;    /* Where do I belong */
	unsigned int lifetime;   /* Number of prime usage */
	unsigned int next_pool;  /* Which pool to select from */
	prime_mask_t match_mask; /* Mask of the met prime pools */
	BIGNUM *p;
};


struct leek_primes_pool {
	/* List of prime numbers in this pool */
	struct leek_prime *prime[LEEK_PRIMES_POOL_DEPTH];

	unsigned int read;  /* where to extract the next prime */
	unsigned int write; /* where to write the next prime */

	/* Avoid concurrent accesses within the same pool */
	pthread_spinlock_t lock;
};


struct leek_primes {
	unsigned int next_pool_id; /* Next target to be fetched */

	/* All prime number pools */
	struct leek_primes_pool pool[LEEK_PRIMES_POOL_COUNT];

	BIGNUM *e;            /* Public exponent used for checking */

	struct {
		uint64_t generated; /* Number of generated primes */
		uint64_t requeued;  /* Number of requeued primes */
		uint64_t evicted;   /* Number of dropped primes (no space for requeue) */
		uint64_t exhausted; /* Number of dropped primes (end of life) */
	} stats;
};


/* Initialize and destroy the prime pools and everything */
int leek_primes_init(void);
void leek_primes_exit(void);

/* Get a new prime number (NULL for new) */
struct leek_prime *leek_prime_fetch(struct leek_prime *partner);

/* Recycles or destroys an already used prime number */
void leek_prime_recycle(struct leek_prime *prime);
void leek_prime_destroy(struct leek_prime *prime);

#endif /* !__LEEK_PRIMES_H */
