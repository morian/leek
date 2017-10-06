#ifndef __LEEK_CPU_H
# define __LEEK_CPU_H
# include <pthread.h>
# include <stdint.h>
# include <stdio.h>
# include <time.h>

# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "leek_helper.h"
# include "leek_sha1.h"

# ifndef OPENSSL_VERSION_1_1
#  define OPENSSL_VERSION_1_1   0x10100000L
# endif

/* Arbitrary maximum thread count */
# define LEEK_CPU_VERSION            "v0.9"
# define LEEK_LENGTH_MIN                  4
# define LEEK_LENGTH_MAX   LEEK_ADDRESS_LEN
# define LEEK_THREADS_MAX               512
# define LEEK_KEYSIZE_MIN         (1 << 10)
# define LEEK_KEYSIZE_MAX         (1 << 13)
# define LEEK_MONITOR_INTERVAL          200 /* msecs */

/* This value ensures that our exponent will always be 4 bytes wide
 * We may consider starting at RSA_F4 instead and handle 3 bytes exponent. */
# define LEEK_RSA_E_SIZE                 4 /* bytes */
# define LEEK_RSA_E_START       0x01000001
/* This limit allows for 8 parallel computations */
# define LEEK_RSA_E_LIMIT       0xFFFFFFF9


/* Holds the crypto stuff we need in workers */
struct leek_crypto {
	RSA              *rsa;
	BIGNUM           *big_e;
	struct leek_sha1 sha1;
};

/* Holds worker related information */
struct leek_worker {
	uint64_t hash_count;
	unsigned int id;
	pthread_t thread;
};

struct leek_context {
	/* Structure holding configuration from argument parsing */
	struct {
		const char *input_path;    /* Input prefix file */
		const char *output_path;   /* Output directory */
		unsigned int keysize;      /* RSA key size */
		unsigned int threads;      /* Number of running threads */
		unsigned int stop_count;   /* Stop after # successes (with LEEK_FLAG_STOP) */
		unsigned int len_min;      /* Minimum prefix size */
		unsigned int len_max;      /* Maximum prefix size */
		unsigned int flags;        /* See enum bellow */
	} config;

	/* Locks provided to OpenSSL */
	pthread_mutex_t *openssl_locks;

	/* Tree of loaded prefixes from input file. */
	struct leek_prefixes *prefixes;
	struct leek_worker *worker;

	unsigned int found_hash_count;
	unsigned int error_hash_count;

	/* Hash-rate and Statistics */
	struct timespec ts_start;
	struct timespec ts_last;
	uint64_t last_hash_count;
};

/* Enumeration of individual flags from configuration */
enum {
	LEEK_FLAG_VERBOSE = (1 << 0), /* Run in verbose mode */
	LEEK_FLAG_STOP    = (1 << 1), /* Stop after a single success */
};


/* Global program context structure. */
extern struct leek_context leek;


/* Main worker function */
void *leek_worker(void *arg);
/* Exhaust function for current RSA configuration */
int leek_exhaust(struct leek_worker *wk, struct leek_crypto *lc);

/* Address post validation (called by exhaust) */
int leek_address_check(struct leek_crypto *lc, unsigned int e,
                       const union leek_rawaddr *addr);
void leek_result_display(RSA *rsa, uint32_t e, int length,
                         const union leek_rawaddr *addr);

/* SHA1 unit interface */
void leek_sha1_init(struct leek_crypto *lc);
void leek_sha1_precalc(struct leek_crypto *lc, const void *ptr, size_t len);

#endif /* !__LEEK_CPU_H */
