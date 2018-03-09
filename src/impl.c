#include <string.h>

#include "leek.h"


/* All built implementations are here. */
static const struct leek_implementation *leek_implementations[] = {
	&leek_impl_openssl, /* OpenSSL implementation */
	&leek_impl_ssse3,   /* SSSE3 implementation */
	&leek_impl_avx2,    /* AVX2 implementation */
	&leek_impl_avx512,  /* AVX512 implementation */
	NULL,
};


void leek_implementation_select_best(void)
{
	const struct leek_implementation *impl;
	unsigned int best_weight = 0;
	unsigned int best_pos = 0;

	for (int i = 0; leek.implementations[i]; ++i) {
		impl = leek.implementations[i];

		if (!impl->available())
			continue;

		if (impl->weight > best_weight) {
			best_weight = impl->weight;
			best_pos = i;
		}
	}

	leek.current_impl = leek.implementations[best_pos];
}


int leek_implementation_select(const char *name)
{
	const struct leek_implementation *selected = NULL;

	for (int i = 0; leek.implementations[i]; ++i) {
		if (!strcmp(name, leek.implementations[i]->name))
			selected = leek.implementations[i];
	}

	if (selected) {
		if (!selected->available())
			fprintf(stderr, "[!] Selected %s implementation (not supported by your CPU).\n", selected->name);
		leek.current_impl = selected;
	}
	else
		fprintf(stderr, "[-] Unable to find matching implementation.\n");

	return (selected) ? 0 : -1;
}


void leek_implementations_init(void)
{
	leek.implementations = leek_implementations;
	leek_implementation_select_best();
}
