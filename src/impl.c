#include <stdio.h>
#include <string.h>

#include "leek.h"
#include "config.h"


/* All built implementations are here. */
const struct leek_implementation *leek_implementations[] = {
	&leek_impl_openssl, /* OpenSSL implementation */
	&leek_impl_uint,    /* uint32_t implementation */
#ifdef HAVE_SIMD_SSSE3
	&leek_impl_ssse3,   /* SSSE3 implementation */
#endif
#ifdef HAVE_SIMD_AVX2
	&leek_impl_avx2,    /* AVX2 implementation */
#endif
#ifdef HAVE_SIMD_AVX512
	&leek_impl_avx512,  /* AVX512 implementation */
#endif
	NULL,
};


static void leek_implementation_select_best(void)
{
	const struct leek_implementation *impl;
	unsigned int best_weight = 0;
	unsigned int best_pos = 0;

	for (int i = 0; leek_implementations[i]; ++i) {
		impl = leek_implementations[i];

		if (!impl->available())
			continue;

		if (impl->weight > best_weight) {
			best_weight = impl->weight;
			best_pos = i;
		}
	}

	leek.implementation = leek_implementations[best_pos];
}


int leek_implementation_select(const char *name)
{
	const struct leek_implementation *selected = NULL;

	for (int i = 0; leek_implementations[i]; ++i) {
		if (!strcmp(name, leek_implementations[i]->name))
			selected = leek_implementations[i];
	}

	if (selected) {
		if (!selected->available())
			fprintf(stderr, "[!] Selected %s implementation (not supported by your CPU).\n", selected->name);
		leek.implementation = selected;
	}
	else
		fprintf(stderr, "error: unable to find matching implementation.\n");

	return (selected) ? 0 : -1;
}


void leek_implementations_init(void)
{
	leek_implementation_select_best();
}
