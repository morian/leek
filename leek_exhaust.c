#include <endian.h>
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


static int __unused leek_lookup(const union leek_rawaddr *addr)
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


#if defined(__AVX2__)
# include "leek_sha1_avx2.c"
/* TODO: handle __SSSE3__ instruction set */
#else
# include "leek_sha1_generic.c"
#endif
