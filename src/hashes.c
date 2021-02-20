#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "leek.h"


static void leek_base32_convert(uint8_t *restrict dst, const char *restrict src)
{
	uint8_t tmp[LEEK_ADDRESS_LEN + 1];

	for (unsigned int i = 0; i < 16; ++i) {
		if (src[i] >= 'a' && src[i] <= 'z')
			tmp[i] = src[i] - 'a';
		else if (src[i] >= '2' && src[i] <= '7')
			tmp[i] = src[i] - '1' + ('z' - 'a');
		else
			/* Unknown garbage (this should not happen) */
			tmp[i] = 0x1F;
	}

	dst[0] = (tmp[ 0] << 3) | (tmp[ 1] >> 2);
	dst[1] = (tmp[ 1] << 6) | (tmp[ 2] << 1) | (tmp[ 3] >> 4);
	dst[2] = (tmp[ 3] << 4) | (tmp[ 4] >> 1);
	dst[3] = (tmp[ 4] << 7) | (tmp[ 5] << 2) | (tmp[ 6] >> 3);
	dst[4] = (tmp[ 6] << 5) | (tmp[ 7] << 0);
	dst[5] = (tmp[ 8] << 3) | (tmp[ 9] >> 2);
	dst[6] = (tmp[ 9] << 6) | (tmp[10] << 1) | (tmp[11] >> 4);
	dst[7] = (tmp[11] << 4) | (tmp[12] >> 1);
	dst[8] = (tmp[12] << 7) | (tmp[13] << 2) | (tmp[14] >> 3);
	dst[9] = (tmp[14] << 5) | (tmp[15] << 0);
}


void leek_base32_enc(uint8_t *restrict dst, const uint8_t *restrict src)
{
	dst[ 0] = LEEK_BASE32_ALPHABET[ (src[0] >> 3)                       ];
	dst[ 1] = LEEK_BASE32_ALPHABET[((src[0] << 2) | (src[1] >> 6))  & 31];
	dst[ 2] = LEEK_BASE32_ALPHABET[ (src[1] >> 1)                   & 31];
	dst[ 3] = LEEK_BASE32_ALPHABET[((src[1] << 4) | (src[2] >> 4))  & 31];
	dst[ 4] = LEEK_BASE32_ALPHABET[((src[2] << 1) | (src[3] >> 7))  & 31];
	dst[ 5] = LEEK_BASE32_ALPHABET[ (src[3] >> 2)                   & 31];
	dst[ 6] = LEEK_BASE32_ALPHABET[((src[3] << 3) | (src[4] >> 5))  & 31];
	dst[ 7] = LEEK_BASE32_ALPHABET[  src[4]                         & 31];

	dst[ 8] = LEEK_BASE32_ALPHABET[ (src[5] >> 3)                       ];
	dst[ 9] = LEEK_BASE32_ALPHABET[((src[5] << 2) | (src[6] >> 6))  & 31];
	dst[10] = LEEK_BASE32_ALPHABET[ (src[6] >> 1)                   & 31];
	dst[11] = LEEK_BASE32_ALPHABET[((src[6] << 4) | (src[7] >> 4))  & 31];
	dst[12] = LEEK_BASE32_ALPHABET[((src[7] << 1) | (src[8] >> 7))  & 31];
	dst[13] = LEEK_BASE32_ALPHABET[ (src[8] >> 2)                   & 31];
	dst[14] = LEEK_BASE32_ALPHABET[((src[8] << 3) | (src[9] >> 5))  & 31];
	dst[15] = LEEK_BASE32_ALPHABET[  src[9]                         & 31];
}


static int leek_address_check(unsigned int len, const char *word)
{
	for (unsigned int i = 0; i < len; ++i) {
		if ((word[i] < 'a' || word[i] > 'z') && (word[i] < '2' || word[i] > '7'))
			return 0;
	}
	return 1;
}


static int leek_hash_bucket_enqueue(const union leek_rawaddr *addr)
{
	struct leek_hash_bucket *bucket;
	unsigned int cur_count;
	uint64_t *ptr;
	int ret = -1;

	bucket = &leek.hashes.bucket[addr->index];
	cur_count = bucket->cur_count;

	if (cur_count == bucket->max_count) {
		ptr = realloc(bucket->data, (cur_count + LEEK_HASH_BUCKETS_INC) * sizeof(*bucket->data));
		if (!ptr) {
			fprintf(stderr, "error: realloc: %s\n", strerror(errno));
			goto out;
		}
		bucket->max_count += LEEK_HASH_BUCKETS_INC;
		bucket->data = ptr;
	}
	bucket->data[cur_count] = addr->suffix;
	bucket->cur_count++;
	bucket->flags &= ~LEEK_HASH_BUCKET_SORTED;

	ret = 0;
out:
	return ret;
}


static int leek_hashes_cmp(const void *a, const void *b)
{
	const uint64_t *va = a;
	const uint64_t *vb = b;

	if (*va > *vb)
		return +1;
	if (*va < *vb)
		return -1;
	return 0;
}


static void leek_hashes_bucket_sort(struct leek_hash_bucket *bucket)
{
	unsigned int duplicates = 0;
	unsigned int count;

	count = bucket->cur_count;
	if (count) {
		/* By design, duplicates are not possible here but we're being safe */
		qsort(bucket->data, count, sizeof *bucket->data, leek_hashes_cmp);
		for (unsigned int j = 1; j < count; ++j) {
			if (bucket->data[j] == bucket->data[j - 1]) {
				bucket->data[j - 1] = 0xFFFFFFFFFFFFFFFFUL;
				duplicates++;
			}
		}

		if (duplicates) {
			qsort(bucket->data, count, sizeof *bucket->data, leek_hashes_cmp);
			bucket->cur_count -= duplicates;
			count = bucket->cur_count;
		}
		bucket->flags |= LEEK_HASH_BUCKET_SORTED;

		leek.hashes.stats.duplicates += duplicates;
		leek.hashes.stats.valids += count;
	}
}


static int leek_address_lookup(const union leek_rawaddr *addr)
{
	struct leek_hash_bucket *bucket = &leek.hashes.bucket[addr->index];

	if (bucket->cur_count) {
		if (bucket->flags & LEEK_HASH_BUCKET_SORTED)
			leek_hashes_bucket_sort(bucket);
		return leek_bucket_lookup(bucket, addr->suffix);
	}

	return 0;
}


/* Defines positive return codes for the following function */
enum {
	LEEK_HASH_ENQUEUE_INVALID   = 0,
	LEEK_HASH_ENQUEUE_DUPLICATE = 1,
	LEEK_HASH_ENQUEUE_SUCCESS   = 2,
};


static int leek_hash_enqueue(unsigned int len, const char *word)
{
	union leek_rawaddr addr;
	int ret = -1;

	if (leek_address_check(len, word)) {
		leek_base32_convert(addr.buffer, word);

		/* Only enqueue when no there is no duplicate */
		if (!leek_address_lookup(&addr)) {
			ret = leek_hash_bucket_enqueue(&addr);
			if (ret < 0)
				goto out;

			ret = LEEK_HASH_ENQUEUE_SUCCESS;
		}
		else {
			leek.hashes.stats.duplicates++;
			ret = LEEK_HASH_ENQUEUE_DUPLICATE;
		}
	}
	else {
		leek.hashes.stats.invalids++;
		ret = LEEK_HASH_ENQUEUE_INVALID;
	}

out:
	return ret;
}


static int leek_hashes_readfp(FILE *fp)
{
	size_t line_size = LEEK_ADDRESS_LEN + 1;
	unsigned int len_min = LEEK_ADDRESS_LEN;
	unsigned int len_max = 0;
	char *line;
	int ret = -1;

	line = calloc(1, line_size);
	if (!line) {
		fprintf(stderr, "error: calloc: %s\n", strerror(errno));
		goto out;
	}

	while (1) {
		unsigned int line_len;
		unsigned int length;

		ret = getline(&line, &line_size, fp);
		if (ret < 0)
			break;

		line_len = ret;

		if (line_len > LEEK_ADDRESS_LEN && !strncmp(&line[LEEK_ADDRESS_LEN], ".onion", 6))
			length = LEEK_ADDRESS_LEN;
		else
			length = (line[line_len - 1] == '\n') ? line_len - 1 : line_len;
		line[length] = 0;

		/* Ensures that everything is cleared in the destination address buffer */
		for (unsigned int i = length + 1; i < LEEK_ADDRESS_LEN + 1; ++i)
			line[i] = 0;

		if (length < leek.options.len_min || length > leek.options.len_max)
			leek.hashes.stats.filtered++;
		else {
			ret = leek_hash_enqueue(length, line);
			if (ret < 0)
				goto line_free;

			/* No break here, this is intended */
			switch (ret) {
				case LEEK_HASH_ENQUEUE_SUCCESS:
					leek.hashes.stats.length[length - 1]++;
				/* fall-through */

				case LEEK_HASH_ENQUEUE_DUPLICATE:
					len_min = (length < len_min) ? length : len_min;
					len_max = (length > len_max) ? length : len_max;
			}
		}
	}

	leek.hashes.stats.len_min = len_min;
	leek.hashes.stats.len_max = len_max;

	ret = 0;
line_free:
	free(line);
out:
	return ret;
}


static int leek_hashes_readfile(const char *filename)
{
	int ret = -1;
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "error: fopen: %s\n", strerror(errno));
		goto out;
	}

	ret = leek_hashes_readfp(fp);
	if (ret < 0)
		goto close;

close:
	if (fp)
		fclose(fp);
out:
	return ret;
}


/* Add a single item to the 'hashlist' (--prefix option) */
static int leek_hash_add(const char *word)
{
	size_t length = strlen(word);
	int ret = 0;

	if (length < leek.options.len_min || length > leek.options.len_max)
		leek.hashes.stats.filtered++;
	else {
		char buffer[LEEK_ADDRESS_LEN + 1] = { 0 };

		/* Ensures that hash enqueue does not read garbage data */
		strncpy(buffer, word, LEEK_ADDRESS_LEN);

		ret = leek_hash_enqueue(length, buffer);
		if (ret < 0)
			goto out;

		leek.hashes.stats.length[length - 1]++;
		leek.hashes.stats.len_min = length;
		leek.hashes.stats.len_max = length;
	}

out:
	return ret;
}


static void leek_hashes_sort(void)
{
	for (unsigned int i = 0; i < LEEK_HASH_BUCKETS; ++i)
		leek_hashes_bucket_sort(&leek.hashes.bucket[i]);
}


int leek_hashes_stats(void)
{
	unsigned int len_min;
	unsigned int len_max;
	int ret = -1;

	if (!leek.hashes.stats.valids) {
		fprintf(stderr, "error: no valid hash was loaded, please check your parameters.\n");
		goto out;
	}

	len_min = leek.hashes.stats.len_min;
	len_max = leek.hashes.stats.len_max;

	if (len_min == len_max) {
		if (len_min == LEEK_ADDRESS_LEN)
			printf("[+] Loaded %u valid target onion addresses.\n",
			       leek.hashes.stats.valids);
		else
			printf("[+] Loaded %u valid prefixes with size %u.\n",
			       leek.hashes.stats.valids, len_max);
	}
	else
		printf("[+] Loaded %u valid prefixes in range %u:%u.\n",
		       leek.hashes.stats.valids, len_min, len_max);

	if (leek.options.flags & LEEK_OPTION_VERBOSE) {
		if (   leek.hashes.stats.invalids
		    || leek.hashes.stats.duplicates
		    || leek.hashes.stats.filtered) {
			printf("[!] Rejected %u invalid, %u duplicate and %u filtered hash prefixes.\n",
		       leek.hashes.stats.invalids, leek.hashes.stats.duplicates,
		       leek.hashes.stats.filtered);
		}
	}

	/* Update min and max length based on the loaded dictionary */
	leek.options.len_min = len_min;
	leek.options.len_max = len_max;

	if (leek.options.flags & LEEK_OPTION_VERBOSE) {
		printf("[+] Using %s implementation on %u worker threads.\n",
		       leek.implementation->name, leek.options.threads);
	}

	leek_stats_proba_update();
	ret = 0;
out:
	return ret;
}


void leek_hashes_clean(void)
{
	for (unsigned int i = 0; i < LEEK_HASH_BUCKETS; ++i) {
		if (leek.hashes.bucket[i].data)
			free(leek.hashes.bucket[i].data);
	}
}


int leek_hashes_load(void)
{
	int ret;

	/* Make sure everything is zeroed appropriately. */
	memset(&leek.hashes, 0, sizeof(leek.hashes));

	if (leek.options.flags & LEEK_OPTION_SINGLE)
		ret = leek_hash_add(leek.options.prefix_single);
	else
		ret = leek_hashes_readfile(leek.options.prefix_file);

	if (ret < 0)
		goto out;

	leek_hashes_sort();

out:
	return ret;
}
