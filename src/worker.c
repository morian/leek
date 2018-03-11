#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "leek.h"


static int leek_impl_exhaust(struct leek_rsa_item *item, struct leek_worker *wk)
{
	int ret;

	ret = leek.implementation->exhaust(item, wk);

	/* Destroy the RSA item and recycle primes if relevant */
	leek_item_destroy(item);
	return ret;
}


static void *leek_worker(void *arg)
{
	struct leek_worker *wk = (struct leek_worker *) arg;
	struct leek_rsa_item *item;
	void *retp = PTHREAD_CANCELED;
	unsigned int flags = 0;
	long ret;

	wk->stats.ts_start = leek_timestamp();

	while (1) {
		item = leek_item_generate();
		if (!item)
			goto out;

		/* This wrapper also take care of item destruction */
		ret = leek_impl_exhaust(item, wk);
		if (ret < 0)
			goto out;

		/* Calling convention ret = 0 means exiting from request */
		if (!ret)
			break;
	}
	retp = NULL;

out:
	if (retp)
		flags |= LEEK_WORKER_FLAG_ERROR;
	flags |= LEEK_WORKER_FLAG_STOPPED;

	wk->stats.ts_stop = leek_timestamp();
	__sync_fetch_and_or(&wk->flags, flags);

	return retp;
}


int leek_workers_start(void)
{
	struct leek_worker *workers;
	int ret = 0;

	workers = calloc(leek.options.threads, sizeof *workers);
	if (!workers)
		goto out;
	leek.workers.worker = workers;
	leek.workers.count = leek.options.threads;

	for (unsigned int i = 0; i < leek.workers.count; ++i) {
		ret = pthread_create(&workers[i].thread, NULL, leek_worker, &workers[i]);
		if (ret < 0) {
			fprintf(stderr, "error: pthread_create: %s\n", strerror(errno));
			goto out;
		}
		/* This thread is now active! */
		__sync_fetch_and_or(&workers[i].flags, LEEK_WORKER_FLAG_STARTED);
	}

	ret = 0;
out:
	return ret;
}


static void leek_worker_stop(struct leek_worker *wk)
{
	if (wk && (wk->flags & LEEK_WORKER_FLAG_STARTED))
		__sync_fetch_and_or(&wk->flags, LEEK_WORKER_FLAG_EXITING);
}


static void leek_worker_join(struct leek_worker *wk)
{
	if (wk && (wk->flags & LEEK_WORKER_FLAG_STARTED))
		pthread_join(wk->thread, NULL);
}


void leek_workers_stop(void)
{
	bool verbose = !!(leek.options.flags & LEEK_OPTION_VERBOSE);

	if (leek.workers.worker) {
		for (unsigned int i = 0; i < leek.workers.count; ++i)
			leek_worker_stop(&leek.workers.worker[i]);
		for (unsigned int i = 0; i < leek.workers.count; ++i)
			leek_worker_join(&leek.workers.worker[i]);
		/* Show all gathered statistics before quitting for real */
		leek_stats_perf_display(verbose);

		free(leek.workers.worker);
	}

	leek.workers.count = 0;
}
