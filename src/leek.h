#ifndef __LEEK_H
# define __LEEK_H
# include <pthread.h>
# include <stdint.h>
# include <stdio.h>
# include <time.h>

# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "hashes.h"
# include "helper.h"
# include "impl.h"
# include "options.h"
# include "stats.h"

# define LEEK_CPU_VERSION          "v1.9.9"

# define LEEK_LENGTH_MIN                  4
# define LEEK_LENGTH_MAX   LEEK_ADDRESS_LEN
# define LEEK_THREADS_MAX               512
# define LEEK_MONITOR_INTERVAL          200 /* msecs */


# ifndef OPENSSL_VERSION_1_1
#  define OPENSSL_VERSION_1_1   0x10100000L
# endif


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


/* leek application context */
struct leek_context {
	/* All command line options */
	struct leek_options options;

	/* Chosen implementation (best available by default) */
	const struct leek_implementation *implementation;

	/* All loaded hashes */
	struct leek_hashes hashes;


	/* All worker structures (one per-thread) */
	struct leek_worker *worker;

	/* All predictions and measurements */
	struct leek_stats stats;


	/* TODO: move this to statistics structure */
	unsigned int found_hash_count;
	unsigned int error_hash_count;

	/* Hash-rate and Statistics */
	struct timespec ts_start;
	struct timespec ts_last;
	uint64_t last_hash_count;
};

/* Worker function (thread point of entry) */
void *leek_worker(void *arg);

/* Show a final result */
int leek_result_recheck(struct leek_crypto *lc, uint32_t e,
                        const union leek_rawaddr *addr);
void leek_result_display(RSA *rsa, uint32_t e, int length,
                         const union leek_rawaddr *addr);

/* Global program context structure. */
extern struct leek_context leek;

#endif /* !__LEEK_H */
