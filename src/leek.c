#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

#include "leek.h"


/* Global leek context structure */
struct leek_context leek;


static void leek_exit(void)
{
	leek_workers_stop();
	leek_events_exit();
	leek_hashes_clean();
	leek_openssl_exit();
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
	if (leek.options.result_dir) {
		ret = leek_result_dir_init();
		if (ret < 0)
			goto out;
	}

	/* OpenSSL locks allocation (required in MT environment) */
	ret = leek_openssl_init();
	if (ret < 0)
		goto out;

	/* Load all input hashes and perform first stage statistics */
	ret = leek_hashes_load();
	if (ret < 0)
		goto openssl_exit;

	/* Build hash statistics and check for any errors */
	ret = leek_hashes_stats();
	if (ret < 0)
		goto hashes_exit;

	ret = 0;
out:
	return ret;

hashes_exit:
	leek_hashes_clean();
openssl_exit:
	leek_openssl_exit();
	goto out;
}

static int leek_start(void)
{
	int ret;

	/* Avoids further improper closing on eventfd descriptor */
	leek.terminal.efd = -1;

	/* Create the terminal notification backend */
	ret = leek_events_init();
	if (ret < 0)
		goto out;

	/* This is where the story officially begins */
	leek.stats.ts_start = leek_timestamp();
	leek.stats.flags |= LEEK_STATS_FLAG_RUNNING;

	ret = leek_workers_start();
	if (ret < 0)
		goto events_exit;

	ret = leek_terminal_runner();
out:
	return ret;

events_exit:
	leek_events_exit();
	goto out;
}


int main(int argc, char *argv[])
{
	int ret = -1;

	/* Chose by default the best available implementation at run-time */
	leek_implementations_init();

	ret = leek_options_parse(argc, argv);
	if (ret < 0)
		goto out;

	ret = leek_init();
	if (ret < 0)
		goto out;

	ret = leek_start();
	if (ret < 0)
		goto exit;

exit:
	leek_exit();
out:
	return (ret < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
