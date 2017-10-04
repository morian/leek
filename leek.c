#define _POSIX_C_SOURCE 199309L
#define _DEFAULT_SOURCE 1
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>

#include "leek_cpu.h"

struct leek_context leek;

/* Enumeration of individual flags from configuration */
enum {
	LEEK_FLAG_VERBOSE = (1 << 0), /* Run in verbose mode */
	LEEK_FLAG_STOP    = (1 << 1), /* Stop after a single success */
};


static struct option leek_long_options[] = {
	{"input",    1, 0, 'i'},
	{"length",   1, 0, 'l'},
	{"key-size", 1, 0, 'k'},
	{"threads",  1, 0, 't'},
	{"stop",     2, 0, 's'},
	{"verbose",  0, 0, 'v'},
	{"help",     0, 0, 'h'},
	{NULL, 0, 0, 0},
};


static void leek_usage(FILE *fp, const char *prog_name)
{
	fprintf(fp, "Usage: %s [OPTIONS]\n", prog_name);
	fprintf(fp, "\n");
	fprintf(fp, " -i, --input        input file containing prefixes.\n");
	fprintf(fp, " -l, --length=N:M   length range filter [%u-%u].\n",
	        LEEK_LENGTH_MIN, LEEK_LENGTH_MAX);
	fprintf(fp, " -k, --key-size     RSA key size (default is 1024).\n");
	fprintf(fp, " -t, --threads=#    number of threads to start (default is 1).\n");
	fprintf(fp, " -s, --stop(=1)     stop processing after # success (default is infinite).\n");
	fprintf(fp, " -v, --verbose      show verbose run information.\n");
	fprintf(fp, " -h, --help         show this help and exit.\n");
	fprintf(fp, "\n");
}


static int leek_range_parse(const char * ptr_a,
                            unsigned int * arg_a, unsigned int * arg_b)
{
	const char *ptr_b;
	unsigned long val_a;
	unsigned long val_b;
	int ret = -1;

	ptr_b = strchr(ptr_a, ':');
	if (!ptr_b)
		goto out;
	ptr_b++;

	val_a = strtoul(ptr_a, NULL, 10);
	if (errno == ERANGE || val_a > UINT_MAX)
		goto out;

	val_b = strtoul(ptr_b, NULL, 10);
	if (errno == ERANGE || val_b > UINT_MAX)
		goto out;

	*arg_a = val_a;
	*arg_b = val_b;

	ret = 0;
out:
	return ret;
}


static int leek_options_parse(int argc, char *argv[])
{
	int ret = -1;

	/* Automatically configured while loading prefixes */
	leek.config.len_min = LEEK_LENGTH_MIN;
	leek.config.len_max = LEEK_LENGTH_MAX;

	/* These are default values */
	leek.config.threads = 1;
	leek.config.keysize = LEEK_KEYSIZE_MIN;

	while (1) {
		unsigned long val;
		int c;

		c = getopt_long(argc, argv, "l:i:k:t:s::vh", leek_long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 'k':
				val = strtoul(optarg, NULL, 10);
				if (errno == ERANGE || val > UINT_MAX) {
					fprintf(stderr, "[-] error: unable to read key size argument.\n");
					goto out;
				}
				leek.config.keysize = val;
				break;

			case 't':
				val = strtoul(optarg, NULL, 10);
				if (errno == ERANGE || val > UINT_MAX) {
					fprintf(stderr, "[-] error: unable to read threads count argument.\n");
					goto out;
				}
				leek.config.threads = val;
				break;

			case 'l':
				ret = leek_range_parse(optarg, &leek.config.len_min, &leek.config.len_max);
				if (ret < 0) {
					fprintf(stderr, "[-] error: unable to read length argument.\n");
					goto out;
				}
				break;

			case 'i':
				leek.config.input_path = optarg;
				break;

			case 's':
				leek.config.flags |= LEEK_FLAG_STOP;
				if (!optarg)
					leek.config.stop_count = 1;
				else {
					val = strtoul(optarg, NULL, 10);
					if (errno == ERANGE || val > UINT_MAX) {
						fprintf(stderr, "[-] error: unable to read stop argument.\n");
						goto out;
					}
					leek.config.stop_count = val;
				}
				break;

			case 'v':
				leek.config.flags |= LEEK_FLAG_VERBOSE;
				break;

			case 'h':
				leek_usage(stdout, argv[0]);
				exit(EXIT_SUCCESS);

			default:
				leek_usage(stderr, argv[0]);
				goto out;
		}
	}
	ret = 0;

	if (!leek.config.threads || leek.config.threads > LEEK_THREADS_MAX) {
		fprintf(stderr, "[-] error: thread count must be in range [1 - %u].\n", LEEK_THREADS_MAX);
		ret = -1;
	}

	if (leek.config.keysize < LEEK_KEYSIZE_MIN || leek.config.keysize > LEEK_KEYSIZE_MAX) {
		fprintf(stderr, "[-] error: key size must be in range [%u - %u].\n",
		        LEEK_KEYSIZE_MIN, LEEK_KEYSIZE_MAX);
		ret = -1;
	}

	if (__builtin_popcount(leek.config.keysize) > 1) {
		fprintf(stderr, "[-] error: key size must be a power of 2.\n");
		ret = -1;
	}

	if (   (leek.config.len_min < LEEK_LENGTH_MIN)
	    || (leek.config.len_max > LEEK_LENGTH_MAX)
	    || (leek.config.len_min > leek.config.len_max)) {
		fprintf(stderr, "[-] error: provided length range is invalid [%u-%u].\n",
		        LEEK_LENGTH_MIN, LEEK_LENGTH_MAX);
		ret = -1;
	}


	if ((leek.config.flags & LEEK_FLAG_STOP) && !leek.config.stop_count) {
		fprintf(stderr, "[-] error: stop argument cannot be 0.\n");
		ret = -1;
	}

	if (!leek.config.input_path) {
		fprintf(stderr, "[-] error: no input prefix file provided.\n");
		ret = -1;
	}
out:
	return ret;
}


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


static int leek_init(void)
{
	struct leek_prefixes *lp;
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

	lp = leek_readfile(leek.config.input_path, leek.config.len_min, leek.config.len_max);
	if (!lp)
		goto out;

	if (!lp->word_count) {
		fprintf(stderr, "[-] error: no matching prefix in %s.\n", leek.config.input_path);
		goto lp_free;
	}
	leek.prefixes = lp;

	if (leek.config.flags & LEEK_FLAG_VERBOSE) {
		if (lp->length_min == lp->length_max)
			printf("[+] Loaded %u valid prefixes with size %u.\n",
			       lp->word_count, lp->length_min);
		else
			printf("[+] Loaded %u valid prefixes in range %u:%u.\n",
			       lp->word_count, lp->length_min, lp->length_max);

		/* Update attack range with dictionnary content. */
		leek.config.len_min = lp->length_min;
		leek.config.len_max = lp->length_max;

		if (lp->invalid_count || lp->duplicate_count)
			printf("[!] Rejected %u invalid and %u duplicate prefixes.\n",
			       lp->invalid_count, lp->duplicate_count);
	}

	ret = leek_workers_init();
	if (ret < 0)
		goto out;

	if (leek.config.flags & LEEK_FLAG_VERBOSE)
		printf("[>] There is no right and wrong. There's only fun and boring.\n");

	ret = 0;
out:
	return ret;

lp_free:
	free(lp);
	goto out;
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


void leek_metric_humanize(double value, double *result,
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
	unsigned int seconds  = (msecs /    1000) % 60;
	unsigned int minutes  = (msecs /   60000) % 60;
	unsigned int hours    = (msecs / 3600000);

	printf("%s%3u:%02u:%02u", prefix, hours, minutes, seconds);
}


static uint64_t leek_metric_estimate_get(uint64_t elapsed)
{
	uint128_t msecs =
		(leek.prefixes->hash_count_target * elapsed) / leek.last_hash_count;
	return msecs;
}


static void leek_metric_display(void)
{
	static const unsigned char anim_chars[] = {'-','/','|','\\'};
	static unsigned int anim_id = 0;

	uint64_t hash_diff = leek_hashcount_update();
	uint64_t time_diff = leek_clock_update(); /* usecs */
	uint64_t elapsed = leek_clock_elapsed(); /* msecs */
	uint64_t estimate;
	unsigned char hash_rate_unit, hash_total_unit;
	double hash_rate_raw, hash_total_raw;
	double hash_rate, hash_total;
	double progress;

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
		estimate = leek_metric_estimate_get(elapsed);
		leek_metric_timer_display("   Estimate:", estimate);
		progress = (100.0L * elapsed) / estimate;
	}

	leek_metric_timer_display("   Elapsed:", elapsed);

	if (leek.last_hash_count)
		printf(" (%6.2lf%%)", progress);

	fflush(stdout);

	funlockfile(stdout);

	anim_id = (anim_id + 1) % sizeof(anim_chars);
}


int main(int argc, char *argv[])
{
	int ret;

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
