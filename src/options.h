#ifndef __LEEK_OPTIONS_H
# define __LEEK_OPTIONS_H

	/* Structure holding configuration from argument parsing */
struct leek_options {
	const char *prefix_file;    /* Input prefix file */
	const char *prefix_single;  /* Single prefix mode */
	const char *result_dir;     /* Output directory */
	const char *implementation; /* Choosen implementation */

	unsigned int threads;       /* Number of running threads */
	unsigned int stop_count;    /* Stop after # successes (with LEEK_FLAG_STOP) */
	unsigned int len_min;       /* Minimum prefix size */
	unsigned int len_max;       /* Maximum prefix size */
	unsigned int flags;         /* See enum bellow */
};


/* Leek option flags */
enum {
	LEEK_OPTION_VERBOSE   = (1 << 0),  /* Run in verbose mode */
	LEEK_OPTION_STOP      = (1 << 1),  /* Stop after a single success */
	LEEK_OPTION_BENCHMARK = (1 << 2),  /* Show overall hashrate instead of local */
	LEEK_OPTION_SINGLE    = (1 << 3),  /* Whether we are running in single prefix mode */
};

/* Parse options and fill the options structure */
int leek_options_parse(int argc, char *argv[]);

#endif /* !__LEEK_OPTIONS_H */
