#ifndef __LEEK_CPU_H
# define __LEEK_CPU_H
# include <pthread.h>
# include <stdint.h>
# include <stdio.h>
# include <time.h>

# include "leek_helper.h"

/* Arbitrary maximum thread count */
#define LEEK_THREADS_MAX          512
#define LEEK_KEYSIZE_MIN    (1 << 10)
#define LEEK_KEYSIZE_MAX    (1 << 16)


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
		unsigned int keysize;      /* RSA key size */
		unsigned int threads;      /* Number of running threads */
		unsigned int flags;        /* See enum bellow */
	} config;

	/* Tree of loaded prefixes from input file. */
	struct leek_prefixes *prefixes;
	struct leek_worker *worker;

	/* Hash-rate and Statistics */
	struct timespec last_ts;
	uint64_t last_hash_count;
	uint64_t found_hashes;
};

/* Global program context structure. */
extern struct leek_context leek;

/* Main worker function */
void *leek_worker(void *arg);

#endif /* !__LEEK_CPU_H */
