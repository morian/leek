#ifndef __LEEK_HASHES_H
# define __LEEK_HASHES_H
# include <stdint.h>

# include "helper.h"

# define LEEK_BASE32_ALPHABET   "abcdefghijklmnopqrstuvwxyz234567"
# define LEEK_HASH_BUCKETS      (1 << 16)
# define LEEK_HASH_BUCKETS_INC  8

/* Describes a raw onion address structure */
union leek_rawaddr {
	uint8_t buffer[LEEK_RAWADDR_LEN];
	struct {
		uint16_t index;
		uint64_t suffix;
	} __packed;
	struct {
		uint32_t prefix;
		uint32_t middle;
		uint16_t tail;
	} __packed;
};

struct leek_hash_bucket {
	unsigned int cur_count;
	unsigned int max_count;
	unsigned int flags;
	uint64_t *data;
};

enum {
	LEEK_HASH_BUCKET_SORTED = (1 <<  0),
};

struct leek_hashes {
	/* All buckets of loaded hashes */
	struct leek_hash_bucket bucket[LEEK_HASH_BUCKETS];

	/* Statistics on loaded hashes */
	struct {
		/* Number of loaded items by length */
		unsigned int length[LEEK_ADDRESS_LEN];

		unsigned int duplicates;
		unsigned int filtered;
		unsigned int invalids;
		unsigned int valids;

		unsigned int len_min;
		unsigned int len_max;
	} stats;
};

/* Encode a base32 address in a humanly readable way */
void leek_base32_enc(uint8_t *restrict dst, const uint8_t *restrict src);

/* Either from file or single prefix mode */
int leek_hashes_load(void);

/* Clean everything allocating during hash load */
void leek_hashes_clean(void);

/* Check loaded hashes and build initial statistics */
int leek_hashes_stats(void);


/* We need this inlined in several files for performance reasons */
static inline int leek_bucket_lookup(const struct leek_hash_bucket *bucket, uint64_t val)
{
	int max = bucket->cur_count - 1;
	int min = 0;
	int piv;

	while (min < max) {
		piv = (min + max) / 2;

		if (bucket->data[piv] < val)
			min = piv + 1;
		else
			max = piv;
	}

	return (bucket->data[max] == val);
}

#endif /* !__LEEK_HASHES_H */
