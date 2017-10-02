#define _POSIX_C_SOURCE  199309L
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
	{"key-size", 1, 0, 'k'},
	{"input",    1, 0, 'i'},
	{"threads",  1, 0, 't'},
	{"stop",     0, 0, 's'},
	{"verbose",  0, 0, 'v'},
	{"help",     0, 0, 'h'},
	{NULL, 0, 0, 0},
};


static void leek_usage(FILE *fp, const char *prog_name)
{
	fprintf(fp, "Usage: %s [OPTIONS]\n", prog_name);
	fprintf(fp, "\n");
	fprintf(fp, " -i, --input       input file containing prefixes.\n");
	fprintf(fp, " -k, --key-size    RSA key size (default is 1024).\n");
	fprintf(fp, " -t, --threads=#   number of threads to start (default is 1).\n");
	fprintf(fp, " -s, --stop        stop processing after one success.\n");
	fprintf(fp, " -v, --verbose     show verbose run information.\n");
	fprintf(fp, " -h, --help        show this help and exit.\n");
	fprintf(fp, "\n");
}


static int leek_options_parse(int argc, char *argv[])
{
	int ret = -1;

	/* default slicing configuration */
	leek.config.threads = 1;
	leek.config.keysize = LEEK_KEYSIZE_MIN;

	while (1) {
		unsigned long val;
		int c;

		c = getopt_long(argc, argv, "i:k:t:svh", leek_long_options, NULL);
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

			case 'i':
				leek.config.input_path = optarg;
				break;

			case 's':
				leek.config.flags |= LEEK_FLAG_STOP;
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


static uint64_t leek_clock_update(void)
{
	uint64_t timediff_usec = 0;
	struct timespec curr_ts;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &curr_ts);
	if (ret < 0)
		goto out;

	if (leek.last_ts.tv_nsec > curr_ts.tv_nsec)
		timediff_usec = 1000000 - (leek.last_ts.tv_nsec - curr_ts.tv_nsec) / 1000;
	else
		timediff_usec = (curr_ts.tv_nsec - leek.last_ts.tv_nsec) / 1000;

	timediff_usec += 1000000 * (curr_ts.tv_sec - leek.last_ts.tv_sec);
	leek.last_ts = curr_ts;

out:
	return timediff_usec;
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

	lp = leek_readfile(leek.config.input_path);
	if (!lp)
		goto out;

	if (!lp->word_count) {
		fprintf(stderr, "[-] error: no valid prefix in %s.\n", leek.config.input_path);
		goto lp_free;
	}
	leek.prefixes = lp;

	if (leek.config.flags & LEEK_FLAG_VERBOSE) {
#if 0
		for (unsigned int i = 0; i < LEEK_BUCKETS; ++i)
			for (unsigned int j = 0; j < lp->bucket[i].cur_count; ++j)
				printf("%04x - %016lx\n", i, lp->bucket[i].data[j]);
#endif

		printf("word count: %u\n", lp->word_count);
		printf("inv. count: %u\n", lp->invalid_count);
		printf("dup. count: %u\n", lp->duplicate_count);
	}

	ret = leek_workers_init();
	if (ret < 0)
		goto out;

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
}


static void leek_metric_display(void)
{
	uint64_t hash_diff = leek_hashcount_update();;
	uint64_t time_diff = leek_clock_update();;
	unsigned char hash_found_unit = ' ';
	unsigned char hash_rate_unit = ' ';
	unsigned char hash_total_unit = ' ';
	double hash_found_raw;
	double hash_rate_raw;
	double hash_total_raw;
	double hash_found;
	double hash_rate;
	double hash_total;

	hash_rate_raw = (1000000.0 * hash_diff) / time_diff;
	leek_metric_humanize(hash_rate_raw, &hash_rate, &hash_rate_unit);

	hash_total_raw = leek.last_hash_count;
	leek_metric_humanize(hash_total_raw, &hash_total, &hash_total_unit);

	hash_found_raw = leek.found_hashes;
	leek_metric_humanize(hash_found_raw, &hash_found, &hash_found_unit);


	/* Show elasped time (?) */

	printf("Hashes: %6.2lf%cH/s   Total: %6.2lf%cH   Found: %6.2lf%cH\r",
	       hash_rate, hash_rate_unit,
	       hash_total, hash_total_unit,
	       hash_found, hash_found_unit);
	fflush(stdout);
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
		sleep(1);
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
