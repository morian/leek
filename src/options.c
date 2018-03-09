#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>

#include "leek.h"

/**
 * TODO:
 * - Remove benchmark mode (default)
 * - Remove key-size (default to 1024)
 * - Implement --no-results and --duration
 * - Refactor all included files and file names
 * - Separate all options in a option.h file
 **/


static const struct option leek_long_options[] = {
	{"input",      1, 0, 'i'},
	{"prefix",     1, 0, 'p'},
	{"output",     1, 0, 'o'},
	{"length",     1, 0, 'l'},
	{"duration",   1, 0, 'd'},
	{"key-size",   1, 0, 'k'},
	{"benchmark",  0, 0, 'b'},
	{"threads",    1, 0, 't'},
	{"impl",       1, 0, 'I'},
	{"stop",       2, 0, 's'},
	{"verbose",    0, 0, 'v'},
	{"help",       0, 0, 'h'},
	{"no-results", 0, 0, 0x1},
	{NULL,         0, 0, 0x0},
};


static void leek_usage_show(FILE *fp, const char *prog_name)
{
	fprintf(fp, "Usage: %s [OPTIONS]\n", prog_name);
	fprintf(fp, "\n");
	fprintf(fp, " -p, --prefix       single prefix attack.\n");
	fprintf(fp, " -i, --input        input dictionary with prefixes.\n");
	fprintf(fp, " -o, --output       output directory (default prints on stdout).\n");
	fprintf(fp, " -l, --length=N:M   length filter for dictionary attack [%u-%u].\n",
	        LEEK_LENGTH_MIN, LEEK_LENGTH_MAX);
	fprintf(fp, " -d, --duration     how long to run (in seconds, default is infinite).\n");
	fprintf(fp, " -t, --threads=#    worker threads count (default is all cores).\n");
	fprintf(fp, " -I, --impl=#       select implementation (see bellow).\n");
	fprintf(fp, " -s, --stop(=1)     stop processing after # success (default is infinite).\n");
	fprintf(fp, " -b, --benchmark    show average speed instead of current speed.\n");
	fprintf(fp, " -v, --verbose      show verbose run information.\n");
	fprintf(fp, " -h, --help         show this help and exit.\n");
	fprintf(fp, "     --no-results   do not display live results on stdout.\n");
	fprintf(fp, "\n");

	fprintf(fp, "Available implementations:\n");

	for (int i = 0; leek_implementations[i]; ++i) {
		fprintf(fp, "  %s", leek_implementations[i]->name);
		if (leek_implementations[i] == leek.implementation)
			fprintf(fp, " (default)");
		fprintf(fp, "\n");
	}
}


static int leek_range_parse(const char *ptr_a,
                            unsigned int *arg_a, unsigned int *arg_b)
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


static int leek_options_check(void)
{
	int ret = 0;

	if (leek.config.implementation)
		ret = leek_implementation_select(leek.config.implementation);

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

	if ((leek.config.flags & LEEK_OPTION_STOP) && !leek.config.stop_count) {
		fprintf(stderr, "[-] error: stop argument cannot be 0.\n");
		ret = -1;
	}

	if (!leek.config.input_path && !leek.config.prefix) {
		fprintf(stderr, "[-] error: no prefix file or single prefix provided.\n");
		ret = -1;
	}

	return ret;
}


int leek_options_parse(int argc, char *argv[])
{
	int ret = -1;

	/* Automatically configured while loading prefixes */
	leek.config.len_min = LEEK_LENGTH_MIN;
	leek.config.len_max = LEEK_LENGTH_MAX;

	/* These are default values */
	leek.config.threads = get_nprocs();
	leek.config.keysize = LEEK_KEYSIZE_MIN;
	leek.config.mode = LEEK_MODE_MULTI;

	while (1) {
		unsigned long val;
		int c;

		c = getopt_long(argc, argv, "l:p:i:o:I:k:bt:s::vh", leek_long_options, NULL);
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

			case 'o':
				leek.config.result_dir = optarg;
				break;

			case 'i':
				leek.config.mode = LEEK_MODE_MULTI;
				leek.config.input_path = optarg;
				break;

			case 'p':
				leek.config.mode = LEEK_MODE_SINGLE;
				leek.config.prefix = optarg;
				break;

			case 'I':
				leek.config.implementation = optarg;
				break;

			case 's':
				leek.config.flags |= LEEK_OPTION_STOP;
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

			case 'b':
				leek.config.flags |= LEEK_OPTION_BENCHMARK;
				break;

			case 'v':
				leek.config.flags |= LEEK_OPTION_VERBOSE;
				break;

			case 'h':
				leek_usage_show(stdout, argv[0]);
				exit(EXIT_SUCCESS);

			default:
				leek_usage_show(stderr, argv[0]);
				goto out;
		}
	}

	ret = leek_options_check();
out:
	return ret;
}


