#include <string.h>

#include "leek_cpu.h"


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

/* These functions might be unused by specific implementations. */
static int __unused leek_lookup_multi(const union leek_rawaddr *addr)
{
	struct leek_prefix_bucket *bucket = &leek.prefixes->bucket[addr->index];
	uint64_t val;

	if (bucket->data) {
		for (unsigned int i = leek.config.len_min; i <= leek.config.len_max; ++i) {
			val = addr->suffix | leek_lookup_mask[i];
			if (bsearch(&val, bucket->data, bucket->cur_count, sizeof(val),
			            &leek_prefixes_suffix_cmp)) {
				return i; /* return found size */
			}
		}
	}
	return 0;
}

static int __unused leek_lookup_single(const union leek_rawaddr *addr)
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


#if defined(__AVX2__) || defined(__SSSE3__)
# include "leek_sha1_specific.c"
#else
# include "leek_sha1_generic.c"
#endif
