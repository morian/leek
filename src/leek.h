#ifndef __LEEK_H
# define __LEEK_H
# include "hashes.h"
# include "helper.h"
# include "impl.h"
# include "options.h"
# include "primes.h"
# include "stats.h"
# include "terminal.h"
# include "worker.h"

# define LEEK_CPU_VERSION          "v2.0.4"

/* leek application context */
struct leek_context {
	/* Chosen implementation (best available by default) */
	const struct leek_implementation *implementation;

	/* All command line options */
	struct leek_options options;

	/* All loaded hashes */
	struct leek_hashes hashes;

	/* Terminal related data and events */
	struct leek_terminal terminal;

	/* Prime number sub-system for RSA generation */
	struct leek_primes primes;

	/* All worker structures (one per-thread) */
	struct leek_workers workers;

	/* All predictions and measurements */
	struct leek_stats stats;
};

/* Global program context structure. */
extern struct leek_context leek;

#endif /* !__LEEK_H */
