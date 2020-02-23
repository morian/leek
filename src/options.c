#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>

#include "leek.h"


static const struct option leek_long_options[] = {
	{"input",      1, 0, 'i'},
	{"prefix",     1, 0, 'p'},
	{"output",     1, 0, 'o'},
	{"length",     1, 0, 'l'},
	{"duration",   1, 0, 'd'},
	{"refresh",    1, 0, 'r'},
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
	        LEEK_PREFIX_LENGTH_MIN, LEEK_PREFIX_LENGTH_MAX);
	fprintf(fp, " -d, --duration     how long to run (in seconds, default is infinite).\n");
	fprintf(fp, " -r, --refresh      how often to auto-refresh status (default is disabled).\n");
	fprintf(fp, " -t, --threads=#    worker threads count (default is all cores).\n");
	fprintf(fp, " -I, --impl=#       select implementation (see bellow).\n");
	fprintf(fp, " -s, --stop(=1)     stop processing after # success (default is infinite).\n");
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


static unsigned long leek_options_scan_duration(const char *arg)
{
	unsigned long value;
	char *end;

	value = strtoul(arg, &end, 10);
	if (value == ULONG_MAX && errno) {
		value = 0;
		goto done;
	}

	switch (*end) {
		/* Weeks */
		case 'W':
		case 'w':
			value *= 7;
		/* fall-through */

		/* Days */
		case 'D':
		case 'd':
			value *= 24;
		/* fall-through */

		/* Hours */
		case 'H':
		case 'h':
			value *= 60;
		/* fall-through */

		/* Minutes */
		case 'M':
		case 'm':
			value *= 60;
		/* fall-through */

		case '\0':
		case 'S':
		case 's':
			break;

		default:
			/* Unrecognized unit = abort */
			value = 0;
	};

done:
	return value;
}


static int leek_options_check(void)
{
	int ret = 0;

	if (leek.options.implementation)
		ret = leek_implementation_select(leek.options.implementation);

	if (!leek.options.threads || leek.options.threads > LEEK_THREADS_MAX) {
		fprintf(stderr, "error: thread count must be in range [1 - %u].\n", LEEK_THREADS_MAX);
		ret = -1;
	}

	if (   (leek.options.len_min < LEEK_PREFIX_LENGTH_MIN)
	    || (leek.options.len_max > LEEK_PREFIX_LENGTH_MAX)
	    || (leek.options.len_min > leek.options.len_max)) {
		fprintf(stderr, "error: provided length range is invalid [%u-%u].\n",
		        LEEK_PREFIX_LENGTH_MIN, LEEK_PREFIX_LENGTH_MAX);
		ret = -1;
	}

	if ((leek.options.flags & LEEK_OPTION_STOP) && !leek.options.stop_count) {
		fprintf(stderr, "error: stop argument cannot be 0.\n");
		ret = -1;
	}

	if (!leek.options.prefix_file && !leek.options.prefix_single) {
		fprintf(stderr, "error: no prefix file or single prefix provided.\n");
		ret = -1;
	}

	return ret;
}


int leek_options_parse(int argc, char *argv[])
{
	int ret = -1;

	/* Automatically configured while loading prefixes */
	leek.options.len_min = LEEK_PREFIX_LENGTH_MIN;
	leek.options.len_max = LEEK_PREFIX_LENGTH_MAX;
	leek.options.flags |= LEEK_OPTION_SHOW_RESULTS;

	/* These are default values */
	leek.options.threads = get_nprocs();

	while (1) {
		unsigned long uval;
		int c;

		c = getopt_long(argc, argv, "l:d:p:i:o:I:t:s::vh", leek_long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 't':
				uval = strtoul(optarg, NULL, 10);
				if (errno == ERANGE || uval > UINT_MAX) {
					fprintf(stderr, "error: unable to read threads count argument.\n");
					goto out;
				}
				leek.options.threads = uval;
				break;

			case 'l':
				ret = leek_range_parse(optarg, &leek.options.len_min, &leek.options.len_max);
				if (ret < 0) {
					fprintf(stderr, "error: unable to read length argument.\n");
					goto out;
				}
				break;

			case 'd':
				uval = leek_options_scan_duration(optarg);
				if (!uval) {
					fprintf(stderr, "error: invalid duration specificed (accepted suffixes are s,m,h,d,w).\n");
					goto out;
				}
				leek.options.duration = uval;
				break;

			case 'r':
				uval = leek_options_scan_duration(optarg);
				if (!uval) {
					fprintf(stderr, "error: invalid refresh duration specificed (accepted suffixes are s,m,h,d,w).\n");
					goto out;
				}
				leek.options.refresh = uval;
				break;

			case 'o':
				leek.options.result_dir = optarg;
				break;

			case 'i':
				leek.options.prefix_file = optarg;
				break;

			case 'p':
				leek.options.flags |= LEEK_OPTION_SINGLE;
				leek.options.prefix_single = optarg;
				break;

			case 'I':
				leek.options.implementation = optarg;
				break;

			case 's':
				leek.options.flags |= LEEK_OPTION_STOP;
				if (!optarg)
					leek.options.stop_count = 1;
				else {
					uval = strtoul(optarg, NULL, 10);
					if (errno == ERANGE || uval > UINT_MAX) {
						fprintf(stderr, "error: unable to read stop argument.\n");
						goto out;
					}
					leek.options.stop_count = uval;
				}
				break;

			case 'v':
				leek.options.flags |= LEEK_OPTION_VERBOSE;
				break;

			case 'h':
				leek_usage_show(stdout, argv[0]);
				exit(EXIT_SUCCESS);

			case 0x1:
				leek.options.flags &= ~LEEK_OPTION_SHOW_RESULTS;
				break;

			default:
				leek_usage_show(stderr, argv[0]);
				goto out;
		}
	}

	ret = leek_options_check();
out:
	return ret;
}
