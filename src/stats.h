#ifndef __LEEK_STATS_H
# define __LEEK_STATS_H
# include <stdbool.h>
# include <stdint.h>

struct leek_stats {
	/* Time and global program metrics */
	uint64_t ts_start;            /* Time at which the application started */
	uint64_t successes;           /* Success count */
	uint64_t recheck_failures;    /* Failure count during recheck */

	/* Global propabilities */
	long double proba_one;        /* One hash to have a success */

	/* Runtime stuff */
	unsigned int flags;           /* Global program state flags */
};

enum {
	LEEK_STATS_FLAG_RUNNING  = (1 << 0),
};


/** Monitoring **/
/* Individual statistics display (called by leek_status_display) */
void leek_stats_application_display(void);
void leek_stats_perf_display(bool individual);
void leek_stats_primes_display(void);

/* Show all statuses listed above */
void leek_status_display(bool verbose);

/** Probability computations **/
/* Update probability statistics (to do after lookup length is chosen). */
void leek_stats_proba_update(void);

/* Get a 64b timestamp on a MONOTONIC clock (in micro-secs) */
uint64_t leek_timestamp(void);

#endif /* !__LEEK_STATS_H */
