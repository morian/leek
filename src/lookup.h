#ifndef __LEEK_LOOKUP_H
# define __LEEK_LOOKUP_H
# include <stdint.h>

# include "hashes.h"

/* Lookup masks for last 64 LSBs (used by lookup functions) */
static uint64_t leek_lookup_mask[LEEK_PREFIX_LENGTH_MAX + 1] = {
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

static int leek_result_lookup(const union leek_rawaddr *addr)
{
	struct leek_hash_bucket *bucket = &leek.hashes.bucket[addr->index];
	uint64_t val;

	if (bucket->cur_count) {
		for (unsigned int i = leek.options.len_min; i <= leek.options.len_max; ++i) {
			val = addr->suffix | leek_lookup_mask[i];
			if (leek_bucket_lookup(bucket, val))
				return i;
		}
	}
	return 0;
}

#endif /* !__LEEK_LOOKUP_H */
