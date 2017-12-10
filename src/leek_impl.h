#ifndef __LEEK_IMPL_H
# define __LEEK_IMPL_H

/** DO NOT INCLUDE THIS FILE DIRECTLY **/
/** PLEASE INCLUDE leek_cpu.h instead **/


/* Holds different leek implementations */
struct leek_implementation {
	/* Readable name of the target implementation */
	const char *name;

	/* Weight of the implementation (more is better) */
	unsigned int weight;

	/* Checks whether the current implementation is available at runtime */
	int (*available) (void);

	/* Initialize local structures (set lc->private_data, must be free-able) */
	void *(*init) (void);

	/* Perform SHA1 precalculus after a new RSA key pair had been generated */
	int (*precalc) (struct leek_crypto *lc, const void *ptr, size_t len);

	/* Perform SHA1 full exhaust for the current RSA key pair */
	int (*exhaust) (struct leek_worker *wk, struct leek_crypto *lc);
};


/* Link all implementations to the global structure */
void leek_implementations_init(void);

/* Find best implementation to use (default) */
void leek_implementation_select_best(void);

/* Select implementation by name */
int leek_implementation_select(const char *name);

/** All known implementations (build time) **/
extern const struct leek_implementation leek_impl_openssl;
extern const struct leek_implementation leek_impl_ssse3;
extern const struct leek_implementation leek_impl_avx2;

#endif /* !__LEEK_IMPL_H */
