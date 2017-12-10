#ifndef __LEEK_CPU_H
# define __LEEK_CPU_H
# include <pthread.h>
# include <stdint.h>
# include <stdio.h>
# include <time.h>

# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "leek_helper.h"

# ifndef OPENSSL_VERSION_1_1
#  define OPENSSL_VERSION_1_1   0x10100000L
# endif

/* Arbitrary maximum thread count */
# define LEEK_CPU_VERSION            "v1.3"
# define LEEK_LENGTH_MIN                  4
# define LEEK_LENGTH_MAX   LEEK_ADDRESS_LEN
# define LEEK_THREADS_MAX               512
# define LEEK_KEYSIZE_MIN         (1 << 10)
# define LEEK_KEYSIZE_MAX         (1 << 13)
# define LEEK_MONITOR_INTERVAL          200 /* msecs */
# define LEEK_CACHELINE_SZ               64 /* bytes */

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

# include "leek_impl.h"

struct leek_context {
	/* Structure holding configuration from argument parsing */
	struct {
		const char *input_path;     /* Input prefix file */
		const char *prefix;         /* Single prefix mode */
		const char *output_path;    /* Output directory */
		const char *implementation; /* Choosen implementation */

		unsigned int keysize;       /* RSA key size */
		unsigned int threads;       /* Number of running threads */
		unsigned int stop_count;    /* Stop after # successes (with LEEK_FLAG_STOP) */
		unsigned int len_min;       /* Minimum prefix size */
		unsigned int len_max;       /* Maximum prefix size */
		unsigned int flags;         /* See enum bellow */
		unsigned int mode;          /* See other enum bellow */
	} config;

	/* Locks provided to OpenSSL */
	pthread_mutex_t *openssl_locks;

	/* Refers to all implementations known at build time */
	const struct leek_implementation **implementations;

	/* Chosen implementation */
	const struct leek_implementation *current_impl;

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

/* Enumeration of individual flags from configuration */
enum {
	LEEK_FLAG_VERBOSE   = (1 << 0),  /* Run in verbose mode */
	LEEK_FLAG_STOP      = (1 << 1),  /* Stop after a single success */
	LEEK_FLAG_BENCHMARK = (1 << 2),  /* Show overall hashrate instead of local */
};

/* Enumeration of different lookup modes available */
enum {
	LEEK_MODE_MULTI     =  0,  /* Multiple prefixes lookup */
	LEEK_MODE_SINGLE    =  1,  /* Single prefix lookup */
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

#endif /* !__LEEK_CPU_H */
