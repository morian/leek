#include <math.h>

#include "leek.h"


static long double leek_stats_proba_one(void)
{
	unsigned int len_min = leek.options.len_min;
	unsigned int len_max = leek.options.len_max;
	long double proba_one = 0;

	for (unsigned int i = len_min - 1; i < len_max; ++i) {
		proba_one += (((long double) leek.hashes.stats.length[i])
		              / powl(2, LEEK_RAWADDR_CHAR_BITS * (i + 1)));
	}
	return proba_one;
}


void leek_stats_proba_update(void)
{
	leek.stats.proba_one = leek_stats_proba_one();
}


/* Generic way to get current timestamp in micro-seconds (for measurements) */
uint64_t leek_timestamp(void)
{
	struct timespec timespec;
	uint64_t timestamp;

	clock_gettime(CLOCK_MONOTONIC, &timespec);
	timestamp = (timespec.tv_sec * 1000000ULL) + (timespec.tv_nsec / 1000ULL);

	return timestamp;
}
