#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "leek.h"


/* Locks provided to OpenSSL */
static pthread_mutex_t *leek_openssl_locks;


int leek_result_dir_init(void)
{
	int ret;

	ret = access(leek.options.result_dir, W_OK);
	if (ret < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "error: access: %s\n", strerror(errno));
			goto out;
		}

		ret = mkdir(leek.options.result_dir, 0700);
		if (ret < 0) {
			fprintf(stderr, "error: mkdir: %s\n", strerror(errno));
			goto out;
		}
	}

out:
	return ret;
}


static __attribute__((unused))
void leek_lock_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&leek_openssl_locks[type]);
	else
		pthread_mutex_unlock(&leek_openssl_locks[type]);

	(void) file;
	(void) line;
}


static __attribute__((unused))
unsigned long leek_thread_id(void)
{
	return (unsigned long) pthread_self();
}


int leek_openssl_init(void)
{
	int ret = -1;

	leek_openssl_locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!leek_openssl_locks) {
		fprintf(stderr, "error: OPENSSL_malloc failed.\n");
		goto out;
	}

	for(int i = 0; i < CRYPTO_num_locks(); ++i)
		pthread_mutex_init(&leek_openssl_locks[i], NULL);

	CRYPTO_THREADID_set_callback(leek_thread_id);
	CRYPTO_set_locking_callback(leek_lock_callback);

	ret = 0;
out:
	return ret;
}


void leek_openssl_exit(void)
{
	if (leek_openssl_locks) {
		CRYPTO_set_locking_callback(NULL);

		for(int i = 0; i < CRYPTO_num_locks(); ++i)
			pthread_mutex_destroy(&leek_openssl_locks[i]);

		OPENSSL_free(leek_openssl_locks);
		leek_openssl_locks = NULL;
	}
}
