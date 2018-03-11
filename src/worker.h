#ifndef __LEEK_WORKER_H
# define __LEEK_WORKER_H
# include <pthread.h>
# include <stdint.h>
# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "item.h"
# include "stats.h"


/* Holds worker related information */
struct leek_worker {
	pthread_t thread;       /* Thread structure */
	unsigned int flags;     /* Worker specific flags */

	/* Worker specific statistics */
	struct {
		uint64_t ts_start;    /* Time of thread start */
		uint64_t ts_stop;     /* Time of thread stop */
		uint64_t hash_count;  /* Number of computed hashes */
	} stats;
};

enum {
	LEEK_WORKER_FLAG_STARTED = (1 << 0), /* Thread was created */
	LEEK_WORKER_FLAG_STOPPED = (1 << 1), /* Thread has stopped */
	LEEK_WORKER_FLAG_ERROR   = (1 << 2), /* Thread encountered an error */
	LEEK_WORKER_FLAG_EXITING = (1 << 3), /* We received an exit request */
};


struct leek_workers {
	struct leek_worker *worker; /* Worker structure */
	unsigned int count;         /* Number of active workers */
};


/* Start / stop all workers */
int leek_workers_start(void);
void leek_workers_stop(void);

#endif /* !__LEEK_WORKER_H */
