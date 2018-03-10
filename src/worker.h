#ifndef __LEEK_WORKER_H
# define __LEEK_WORKER_H
# include <pthread.h>
# include <stdint.h>
# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "stats.h"

/* Holds the crypto stuff we need in workers */
struct leek_rsa_item {
	/* Implementation specific data */
	void   *private_data;

	/* RSA stuff */
	RSA    *rsa;
	BIGNUM *big_e;
};


/* Holds worker related information */
struct leek_worker {
	pthread_t thread;       /* OpenSSL thread */

	/* Worker specific statistics */
	struct {
		uint64_t ts_start;    /* Time of thread start */
		uint64_t ts_stop;     /* Time of thread stop */
		uint64_t hash_count;  /* Number of computed hashes */
	} stats;
};


struct leek_workers {
	struct leek_worker *worker; /* Worker structure */
	unsigned int count;         /* Number of active workers */
};


/* Start / stop all workers */
int leek_workers_start(void);
int leek_workers_stop(void);

/* Shared helper to create a DER structure from a RSA keypair */
uint8_t *leek_crypto_der_alloc(const RSA *rsa, unsigned int *derlen);

#endif /* !__LEEK_WORKER_H */
