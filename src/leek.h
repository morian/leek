#ifndef __LEEK_H
# define __LEEK_H
# include <pthread.h>
# include <stdint.h>

# include "hashes.h"
# include "helper.h"
# include "impl.h"
# include "options.h"
# include "stats.h"
# include "terminal.h"

# define LEEK_CPU_VERSION          "v1.9.9"

# define LEEK_THREADS_MAX               512

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
	/* Chosen implementation (best available by default) */
	const struct leek_implementation *implementation;

	/* All command line options */
	struct leek_options options;

	/* All loaded hashes */
	struct leek_hashes hashes;

	/* Terminal related data and events */
	struct leek_terminal terminal;

	/* All worker structures (one per-thread) */
	struct leek_worker *worker;

	/* All predictions and measurements */
	struct leek_stats stats;
};

/* Worker function (thread point of entry) */
void *leek_worker(void *arg);
uint8_t *leek_crypto_der_alloc(const RSA *rsa, unsigned int *derlen);

/* Global program context structure. */
extern struct leek_context leek;

#endif /* !__LEEK_H */
