#ifndef __LEEK_H
# define __LEEK_H
# include <pthread.h>
# include <stdint.h>
# include <stdio.h>
# include <time.h>

# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "helper.h"
# include "options.h"

# define LEEK_CPU_VERSION          "v1.9.9"

# define LEEK_LENGTH_MIN                  4
# define LEEK_LENGTH_MAX   LEEK_ADDRESS_LEN
# define LEEK_THREADS_MAX               512
# define LEEK_KEYSIZE_MIN         (1 << 10)
# define LEEK_KEYSIZE_MAX         (1 << 13)
# define LEEK_MONITOR_INTERVAL          200 /* msecs */
# define LEEK_CACHELINE_SZ               64 /* bytes */

# ifndef OPENSSL_VERSION_1_1
#  define OPENSSL_VERSION_1_1   0x10100000L
# endif

/* This value ensures that our exponent will always be 4 bytes wide
 * We may consider starting at RSA_F4 instead and handle 3 bytes exponent. */
# define LEEK_RSA_E_SIZE                 4 /* bytes */
# define LEEK_RSA_E_START       0x00800001u
/* This limit allows for 8 parallel computations */
# define LEEK_RSA_E_LIMIT       0x7FFFFFFFu

/* For functions or variables that can be unused */
# define __unused                __attribute__((unused))
# define __flatten               __attribute__((flatten))
# define __hot                   __attribute__((hot))

/* Help compiler in generating more optimized code for some expected branches */
# define likely(x)               __builtin_expect(!!(x), 1)
# define unlikely(x)             __builtin_expect(!!(x), 0)


/* Holds the crypto stuff we need in workers */
struct leek_crypto {
	/* Implementation specific data */
	void   *private_data;

	/* RSA stuff */
	RSA    *rsa;
	BIGNUM *big_e;
};

/* Holds worker related information */
struct leek_worker {
	uint64_t hash_count;
	unsigned int id;
	pthread_t thread;
};

# include "impl.h"


/* leek application context */
struct leek_context {
	/* All command line options */
	struct leek_options config;

	/* Chosen implementation */
	const struct leek_implementation *implementation;

	/* All worker structures (one per-thread) */
	struct leek_worker *worker;

	union {
		/* Tree of loaded prefixes from input file. */
		struct leek_prefixes *prefixes;

		/* Single address lookup mode */
		union leek_rawaddr address;
	};

	unsigned int found_hash_count;
	unsigned int error_hash_count;

	/* Hash-rate and Statistics */
	struct timespec ts_start;
	struct timespec ts_last;
	uint64_t last_hash_count;

	/* Probability to have a hit on a single hash try. */
	long double prob_find_1;
};

/* Worker function (thread point of entry) */
void *leek_worker(void *arg);

/* Address post validation (called by exhaust) */
int leek_address_check(struct leek_crypto *lc, unsigned int e,
                       const union leek_rawaddr *addr);

/* Show a final result */
void leek_result_display(RSA *rsa, uint32_t e, int length,
                         const union leek_rawaddr *addr);

/* Global program context structure. */
extern struct leek_context leek;

#endif /* !__LEEK_H */
