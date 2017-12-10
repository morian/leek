#include <string.h>

#include "leek_cpu.h"


/* All built implementations are here. */
static const struct leek_implementation *leek_implementations[] = {
	&leek_impl_openssl, /* OpenSSL implementation */
	&leek_impl_ssse3,   /* SSSE3 implementation */
	&leek_impl_avx2,    /* AVX2 implementation */
	NULL,
};

/* Lookup masks for last 64 LSBs (used by lookup functions) */
static uint64_t leek_lookup_mask[LEEK_LENGTH_MAX + 1] = {
	0xFFFFFFFFFFFFFFFF, /* impossible (len = 0) */
	0xFFFFFFFFFFFFFFFF, /* disabled   (len = 1) */
	0xFFFFFFFFFFFFFFFF, /* disabled   (len = 2) */
	0xFFFFFFFFFFFFFFFF, /* disabled   (len = 3) */
	0xFFFFFFFFFFFFFF0F,
	0xFFFFFFFFFFFF7F00,
	0xFFFFFFFFFFFF0300,
	0xFFFFFFFFFF1F0000,
	0xFFFFFFFFFF000000,
	0xFFFFFFFF07000000,
	0xFFFFFF3F00000000,
	0xFFFFFF0100000000,
	0xFFFF0F0000000000,
	0xFF7F000000000000,
	0xFF03000000000000,
	0x1F00000000000000,
	0x0000000000000000,
};

static int leek_bucket_lookup(const struct leek_prefix_bucket *bucket, uint64_t val)
{
	int max = bucket->cur_count - 1;
	int min = 0;
	int piv;

	while (min < max) {
		piv = (min + max) / 2;

		if (bucket->data[piv] < val)
			min = piv + 1;
		else
			max = piv - 1;
	}

	return (bucket->data[max] == val);
}

int leek_lookup_multi(const union leek_rawaddr *addr)
{
	struct leek_prefix_bucket *bucket = &leek.prefixes->bucket[addr->index];
	uint64_t val;

	if (bucket->cur_count) {
		for (unsigned int i = leek.config.len_min; i <= leek.config.len_max; ++i) {
			val = addr->suffix | leek_lookup_mask[i];
			if (leek_bucket_lookup(bucket, val))
				return i;
		}
	}
	return 0;
}

int leek_lookup_single(const union leek_rawaddr *addr)
{
	unsigned int len = leek.config.len_min;
	uint64_t val;

	if (leek.address.index == addr->index) {
		val = addr->suffix | leek_lookup_mask[len];
		if (unlikely(leek.address.suffix == val))
			return leek.config.len_min;
	}
	return 0;
}


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
