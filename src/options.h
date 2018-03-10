#ifndef __LEEK_OPTIONS_H
# define __LEEK_OPTIONS_H
# include "helper.h"

# define LEEK_PREFIX_LENGTH_MIN                 4
# define LEEK_PREFIX_LENGTH_MAX  LEEK_ADDRESS_LEN


	/* Structure holding configuration from argument parsing */
struct leek_options {
	const char *prefix_file;    /* Input prefix file */
	const char *prefix_single;  /* Single prefix mode */
	const char *result_dir;     /* Output directory */
	const char *implementation; /* Choosen implementation */

	unsigned int threads;       /* Number of running threads */
	unsigned int stop_count;    /* Stop after # successes (with LEEK_FLAG_STOP) */
	unsigned long duration;     /* For how long we shall run */

	unsigned int len_min;       /* Minimum prefix size */
	unsigned int len_max;       /* Maximum prefix size */

	unsigned int flags;         /* See enum bellow */
};


/* Leek option flags */
enum {
	/* Run in verbose mode */
	LEEK_OPTION_VERBOSE      = (1 << 0),
	/* Stop after a single success */
	LEEK_OPTION_STOP         = (1 << 1),
	/* Whether we are running in single prefix mode */
	LEEK_OPTION_SINGLE       = (1 << 2),
	/* Run with a higher verbosity level */
	LEEK_OPTION_SHOW_RESULTS = (1 << 3),
};

/* Parse options and fill the options structure */
int leek_options_parse(int argc, char *argv[]);

#endif /* !__LEEK_OPTIONS_H */
