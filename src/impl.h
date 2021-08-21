#ifndef __LEEK_IMPL_H
# define __LEEK_IMPL_H
# include "item.h"
# include "worker.h"


/* Holds different leek implementations */
struct leek_implementation {
	/* Readable name of the target implementation */
	const char *name;

	/* Weight of the implementation (more is better) */
	unsigned int weight;

	/* Checks whether the current implementation is available at runtime */
	int (*available) (void);

	/* Initialize local structures (set lc->private_data, must be free-able) */
	void *(*allocate) (void);

	/* Perform SHA1 precalculus after a new RSA key pair had been generated */
	int (*precalc) (struct leek_rsa_item *item, const void *ptr, size_t len);

	/* Perform SHA1 full exhaust for the current RSA key pair */
	int (*exhaust) (struct leek_rsa_item *item, struct leek_worker *wk);
};


/* Link all implementations to the global structure */
void leek_implementations_init(void);

/* Select implementation by name */
int leek_implementation_select(const char *name);


/** All known implementations (build time) **/
extern const struct leek_implementation leek_impl_openssl;
extern const struct leek_implementation leek_impl_uint;
extern const struct leek_implementation leek_impl_ssse3;
extern const struct leek_implementation leek_impl_avx2;
extern const struct leek_implementation leek_impl_avx512;

/* All built implementations in a nice structure */
extern const struct leek_implementation *leek_implementations[];

#endif /* !__LEEK_IMPL_H */
