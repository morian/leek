#include <math.h>
#include <stdio.h>
#include <time.h>

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


static unsigned long leek_stats_tavg_estimate(double hash_rate)
{
	long double tgt_time = (1 / (leek.stats.proba_one * hash_rate));
	return tgt_time;
}


static void leek_stats_humanize_d(double value, double *r_value,
                                  unsigned char *r_unit, double base)
{
	static unsigned char units[] = " KMGTPE";
	static unsigned int units_len = sizeof(units);

	for (unsigned int i = 0; i < units_len; ++i) {
		if (value > base)
			value /= base;
		else {
			*r_value = value;
			*r_unit = units[i];
			return;
		}
	}

	*r_unit = ' ';
	*r_value = value;
}


static void leek_stats_duration_display(uint64_t secs)
{
	unsigned int seconds  = (secs /     1) % 60;
	unsigned int minutes  = (secs /    60) % 60;
	unsigned int hours    = (secs /  3600) % 24;
	unsigned int days     = (secs / 86400);

	printf("%u:%02u:%02u:%02u", days, hours, minutes, seconds);
}


void leek_stats_application_display(void)
{
	uint64_t ts_now = leek_timestamp();
	uint64_t elapsed = (ts_now - leek.stats.ts_start) / 1000000ULL;
	uint64_t remaining;

	printf("Elapsed...........: ");
	leek_stats_duration_display(elapsed);

	if (leek.options.duration) {
		remaining = (leek.options.duration > elapsed)
		          ? (leek.options.duration - elapsed): 0;
		printf(" (");
		leek_stats_duration_display(remaining);
		printf(" remaining)");
	}
	if (leek.stats.successes)
		printf(", success: %lu", leek.stats.successes);
	if (leek.stats.recheck_failures)
		printf(", failure: %lu", leek.stats.recheck_failures);
	printf("\n");
}


void leek_stats_primes_display(void)
{
	unsigned char a_unit;
	unsigned char b_unit;
	double a_value;
	double b_value;

	leek_stats_humanize_d(leek.primes.stats.generated, &a_value, &a_unit, 1000);
	leek_stats_humanize_d(leek.primes.stats.requeued, &b_value, &b_unit, 1000);

	printf("Prime.numbers.....: Count:%5.1lf%c  Reuse:%5.1lf%c    ",
	       a_value, a_unit, b_value, b_unit);

	leek_stats_humanize_d(leek.primes.stats.evicted, &a_value, &a_unit, 1000);
	leek_stats_humanize_d(leek.primes.stats.exhausted, &b_value, &b_unit, 1000);

	printf("Evicted.:%5.1lf%c  Exhaust.:%5.1lf%c\n", a_value, a_unit, b_value, b_unit);
}


static void leek_stats_worker_perf_get(struct leek_worker *wk,
                                       double *perf_hashcount, double *perf_hashrate)
{
	uint64_t ts_end = (wk->flags & LEEK_WORKER_FLAG_STOPPED)
	                ? wk->stats.ts_stop : leek_timestamp();
	double total_time = (ts_end - wk->stats.ts_start);
	double hash_count = wk->stats.hash_count;

	*perf_hashcount = hash_count;

	if (total_time)
		*perf_hashrate = 1000000.0 * hash_count / total_time;
	else
		*perf_hashrate = 0.0;
}


static void leek_stats_worker_perf_show(unsigned int wid, double perf_hashcount,
                                        double perf_hashrate)
{
	unsigned char c_unit;
	unsigned char s_unit;
	double c_value;
	double s_value;

	printf("Perform.worker_%03u: ", wid);

	leek_stats_humanize_d(perf_hashcount, &c_value, &c_unit, 1000);
	leek_stats_humanize_d(perf_hashrate, &s_value, &s_unit, 1000);

	printf("Hashs:%5.1lf%c  Rate:%5.1lf%cH/s\n", c_value, c_unit, s_value, s_unit);
}


static void leek_stats_worker_perf_show_all(double total_hashcount, double total_hashrate)
{
	long double proba_found = 100.0 * (1.0 -  powl(1.0 - leek.stats.proba_one, total_hashcount));
	uint64_t time_to_avg = leek_stats_tavg_estimate(total_hashrate);
	unsigned char c_unit;
	unsigned char s_unit;
	double c_value;
	double s_value;

	printf("Perform.(all).....: ");

	leek_stats_humanize_d(total_hashcount, &c_value, &c_unit, 1000);
	leek_stats_humanize_d(total_hashrate, &s_value, &s_unit, 1000);

	printf("Hashs:%5.1lf%c  Rate:%5.1lf%cH/s  Tavg:", c_value, c_unit, s_value, s_unit);
	leek_stats_duration_display(time_to_avg);
	printf("  (%.3Lf%%)\n", proba_found);
}


void leek_stats_perf_display(bool individual)
{
	unsigned int count = leek.workers.count;
	double total_hashcount = 0;
	double total_hashrate = 0;

	if (count < 2)
		individual = true;

	for (unsigned int i = 0; i < count; ++i) {
		struct leek_worker *wk = &leek.workers.worker[i];
		double perf_hashcount;
		double perf_hashrate;

		if (wk && (wk->flags & LEEK_WORKER_FLAG_STARTED)) {
			leek_stats_worker_perf_get(wk, &perf_hashcount, &perf_hashrate);

			total_hashcount += perf_hashcount;
			total_hashrate += perf_hashrate;

			if (individual)
				leek_stats_worker_perf_show(i, perf_hashcount, perf_hashrate);
		}
	}

	leek_stats_worker_perf_show_all(total_hashcount, total_hashrate);
}


void leek_status_display(bool verbose)
{
	printf("[+] Current %sstatus:\n", (verbose) ? "detailled " : "");
	leek_stats_application_display();

	if (verbose)
		leek_stats_primes_display();

  leek_stats_perf_display(verbose);
	printf("\n");
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
