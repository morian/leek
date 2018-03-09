#define _XOPEN_SOURCE   500
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>

#include "leek.h"


/* Global leek context structure */
struct leek_context leek;


static void leek_exit(void)
{
	if (leek.prefixes) {
		leek_prefixes_free(leek.prefixes);
		leek.prefixes = NULL;
	}
	if (leek.worker) {
		free(leek.worker);
		leek.worker = NULL;
	}

	leek_openssl_exit();
}


/* returns microseconds delta since last update */
static uint64_t leek_clock_update(void)
{
	uint64_t timediff_usec = 0;
	struct timespec curr_ts;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &curr_ts);
	if (ret < 0)
		goto out;

	timediff_usec = 1000000 * (curr_ts.tv_sec - leek.ts_last.tv_sec);

	if (leek.ts_last.tv_nsec > curr_ts.tv_nsec)
		timediff_usec -= ((leek.ts_last.tv_nsec - curr_ts.tv_nsec) / 1000);
	else
		timediff_usec += (curr_ts.tv_nsec - leek.ts_last.tv_nsec) / 1000;

	leek.ts_last = curr_ts;

out:
	return timediff_usec;
}


/* returns milliseconds delta from start */
static uint64_t leek_clock_elapsed(void)
{
	uint64_t timediff_msec = 0;

	timediff_msec = 1000 * (leek.ts_last.tv_sec - leek.ts_start.tv_sec);

	if (leek.ts_start.tv_nsec > leek.ts_last.tv_nsec)
		timediff_msec -= ((leek.ts_start.tv_nsec - leek.ts_last.tv_nsec) / 1000000);
	else
		timediff_msec += (leek.ts_last.tv_nsec - leek.ts_start.tv_nsec) / 1000000;
	return timediff_msec;
}


static int leek_workers_init(void)
{
	struct leek_worker *worker;
	int ret = 0;

	ERR_load_crypto_strings();

	worker = calloc(leek.config.threads, sizeof *worker);
	if (!worker)
		goto out;
	leek.worker = worker;

	for (unsigned int i = 0; i < leek.config.threads; ++i) {
		worker[i].id = i;

		ret = pthread_create(&worker[i].thread, NULL, leek_worker, &worker[i]);
		if (ret < 0) {
			fprintf(stderr, "[-] pthread_create: %s\n", strerror(errno));
			goto out;
		}
	}
	leek_clock_update();
	/* Set the start timer to the current timespec value. */
	leek.ts_start = leek.ts_last;

	ret = 0;
out:
	return ret;
}


static int leek_worker_join(void)
{
	int has_error = 0;
	void *retval;
	int ret = 0;

	for (unsigned int i = 0; i < leek.config.threads; ++i) {
		ret = pthread_join(leek.worker[i].thread, &retval);
		if (ret < 0) {
			fprintf(stderr, "[-] pthread_join: %s\n", strerror(errno));
			has_error = 1;
		}
		if (retval) {
			fprintf(stderr, "[-] worker %u terminated unsuccessfully.\n", i);
			has_error = 1;
		}
	}
	return (has_error) ? -1 : 0;
}


static int leek_init_prefix(void)
{
	unsigned int length = strlen(leek.config.prefix);
	int ret = -1;

	if (length < leek.config.len_min || length > leek.config.len_max) {
		fprintf(stderr, "[-] error: input prefix is out of range.\n");
		goto out;
	}

	ret = leek_prefix_parse(&leek.address, leek.config.prefix, length);
	if (ret < 0) {
		fprintf(stderr, "[-] error: unable to parse provided input prefix.\n");
		goto out;
	}

	leek.config.len_min = length;
	leek.config.len_max = leek.config.len_min;
	leek.prob_find_1 = 1.0 / powl(2, LEEK_RAWADDR_CHAR_BITS * length);

	if (leek.config.flags & LEEK_OPTION_VERBOSE)
		printf("[+] Loaded a single target address with size %u\n", length);

out:
	return ret;
}


static int leek_init_prefixes(void)
{
	struct leek_prefixes *lp;
	int ret = -1;

	lp = leek_readfile(leek.config.input_path, leek.config.len_min, leek.config.len_max);
	if (!lp)
		goto out;

	if (!lp->word_count) {
		fprintf(stderr, "[-] error: no matching prefix in %s.\n", leek.config.input_path);
		goto lp_free;
	}

	/* Update min and max length based on the loaded dictionary */
	leek.config.len_min = lp->length_min;
	leek.config.len_max = lp->length_max;
	leek.prob_find_1 = lp->prob_find_1;
	leek.prefixes = lp;

	if (leek.config.flags & LEEK_OPTION_VERBOSE) {
		if (lp->length_min == lp->length_max)
			printf("[+] Loaded %u valid prefixes with size %u.\n",
			       lp->word_count, lp->length_min);
		else
			printf("[+] Loaded %u valid prefixes in range %u:%u.\n",
			       lp->word_count, lp->length_min, lp->length_max);

		if (lp->invalid_count || lp->duplicate_count || lp->filtered_count)
			printf("[!] Rejected %u invalid, %u filtered and %u duplicate prefixes.\n",
			       lp->invalid_count, lp->filtered_count, lp->duplicate_count);
	}

	ret = 0;
out:
	return ret;

lp_free:
	free(lp);
	ret = -1;
	goto out;
}


static int leek_init(void)
{
	int ret = -1;

	printf(".________________________________________________.\n");
	printf("|                                                |\n");
	printf("|         Pool on the root must have a           |\n");
	printf("|   .____     ______________________ ____  __.   |\n");
	printf("|   |    |    \\_   _____/\\_   _____/|    |/ _|   |\n");
	printf("|   |    |     |    __)_  |    __)_ |      <     |\n");
	printf("|   |    |___  |        \\ |        \\|    |  \\    |\n");
	printf("|   |_______ \\/_______  //_______  /|____|__ \\   |\n");
	printf("|           \\/        \\/         \\/  %6s \\/   |\n", LEEK_CPU_VERSION);
	printf(".________________________________________________.\n\n");


	/* Create output directory if needed */
	if (leek.config.result_dir) {
		ret = leek_result_dir_init();
		if (ret < 0)
			goto out;
	}

	/* OpenSSL locks allocation (required in MT environment) */
	ret = leek_openssl_init();
	if (ret < 0)
		goto out;

	switch (leek.config.mode) {
		/* Initialize prefix list from file (lookup in multi-hash mode) */
		case LEEK_MODE_MULTI:
			ret = leek_init_prefixes();
			break;

		/* Initialize a single prefix attack from user-provided parameter */
		case LEEK_MODE_SINGLE:
			ret = leek_init_prefix();
			break;

		default:
			ret = -1;
			break;
	}

	if (ret < 0)
		goto out;

	if (leek.config.flags & LEEK_OPTION_VERBOSE) {
		printf("[+] Using %s implementation on %u worker threads.\n",
		       leek.implementation->name, leek.config.threads);
	}

	ret = leek_workers_init();
	if (ret < 0)
		goto out;

	ret = 0;
out:
	return ret;
}


static uint64_t leek_hashcount_update(void)
{
	uint64_t hash_count = 0;
	uint64_t hash_diff = 0;

	for (unsigned int i = 0; i < leek.config.threads; ++i)
		hash_count += leek.worker[i].hash_count;

	hash_diff = hash_count - leek.last_hash_count;
	leek.last_hash_count = hash_count;

	return hash_diff;
}


static void leek_metric_humanize(double value, double *result,
                                 unsigned char *result_unit)
{
	static unsigned char units[] = " KMGTPE";
	static unsigned int units_len = sizeof(units);

	for (unsigned int i = 0; i < units_len; ++i) {
		if (value > 1000.0)
			value /= 1000.0;
		else {
			*result = value;
			*result_unit = units[i];
			return;
		}
	}

	/* Default behavior (wtf!) */
	*result_unit = ' ';
	*result = value;
}

static void leek_metric_timer_display(const char *prefix, uint64_t msecs)
{
	unsigned int seconds  = (msecs /     1000) % 60;
	unsigned int minutes  = (msecs /    60000) % 60;
	unsigned int hours    = (msecs /  3600000) % 24;
	unsigned int days     = (msecs / 86400000);

	printf("%s%2u:%02u:%02u:%02u", prefix, days, hours, minutes, seconds);
}


static uint64_t leek_metric_estimate_get(uint64_t hash_count, uint64_t elapsed)
{
	long double tgt_time;
	tgt_time = (((long double) elapsed) / (leek.prob_find_1 * hash_count));
	return tgt_time;
}


static void leek_metric_display(void)
{
	static const unsigned char anim_chars[] = {'-','\\','|','/'};
	static unsigned int anim_id = 0;

	uint64_t hash_diff = leek_hashcount_update();
	uint64_t time_diff = leek_clock_update(); /* usecs */
	uint64_t elapsed = leek_clock_elapsed(); /* msecs */
	uint64_t time_prc;
	unsigned char hash_rate_unit, hash_total_unit;
	double hash_rate_raw, hash_total_raw;
	double hash_rate, hash_total;
	long double prob_found;

	/* On benchmark configuration we show the overall hash/rate */
	if (leek.config.flags & LEEK_OPTION_BENCHMARK)
		hash_rate_raw = (1000.0 * leek.last_hash_count) / elapsed;
	else
		hash_rate_raw = (1000000.0 * hash_diff) / time_diff;

	leek_metric_humanize(hash_rate_raw, &hash_rate, &hash_rate_unit);

	hash_total_raw = leek.last_hash_count;
	leek_metric_humanize(hash_total_raw, &hash_total, &hash_total_unit);

	flockfile(stdout);

	printf("\r");
	printf("[%c] Speed:%5.1lf%cH/s   Total:%6.2lf%cH",
	       anim_chars[anim_id],
	       hash_rate, hash_rate_unit,
	       hash_total, hash_total_unit);

	if (leek.last_hash_count) {
		time_prc = leek_metric_estimate_get(leek.last_hash_count, elapsed);
		leek_metric_timer_display("   T(avg):", time_prc);
	}

	leek_metric_timer_display("   Elapsed:", elapsed);

	if (leek.last_hash_count && !leek.found_hash_count) {
		prob_found = 100.0 * (1.0 -  powl(1.0 - leek.prob_find_1, leek.last_hash_count));

		/* Probability to already have a result. */
		printf(" (%6.2Lf%%)", prob_found);
	}
	else if (leek.error_hash_count)
		printf("   ERR:%u", leek.error_hash_count);

	fflush(stdout);

	funlockfile(stdout);

	anim_id = (anim_id + 1) % sizeof(anim_chars);
}


int main(int argc, char *argv[])
{
	int ret = -1;

	/* Link known implementations to global leek structure */
	leek_implementations_init();

	ret = leek_options_parse(argc, argv);
	if (ret < 0)
		goto out;

	ret = leek_init();
	if (ret < 0)
		goto exit;

	while (1) {
		usleep(LEEK_MONITOR_INTERVAL * 1000);
		leek_metric_display();
	}

	ret = leek_worker_join();
	if (ret < 0)
		goto exit;

exit:
	leek_exit();
out:
	return (ret < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
