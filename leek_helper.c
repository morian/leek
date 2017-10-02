#define _POSIX_C_SOURCE  200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "leek_helper.h"

/* abcdefghijklmnopqrstuvwxyz234567 */

/* TODO (library):
 * - Read input file into an allocated list of items
 * - Remove and count duplicates and invalids
 * - Count duplicates, invalids and final wordcount
*/


static void leek_base32_dec(uint8_t *dst, const char *src)
{
	uint8_t tmp[LEEK_ADDRESS_LEN + 1];

	for (unsigned int i = 0; i < 16; ++i) {
		if (src[i] >= 'a' && src[i] <= 'z')
			tmp[i] = src[i] - 'a';
		else if (src[i] >= '2' && src[i] <= '7')
			tmp[i] = src[i] - '1' + ('z' - 'a');
		else
			/* Unknown garbage, fill with 0x1F */
			tmp[i] = 31;
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


static struct leek_prefixes *leek_prefixes_alloc(void)
{
	struct leek_prefixes * lp;

	lp = malloc(sizeof *lp);
	if (lp)
		memset(lp, 0, sizeof *lp);
	return lp;
}


void leek_prefixes_free(struct leek_prefixes *lp)
{
	if (lp) {
		for (unsigned int i = 0; i < LEEK_BUCKETS; ++i)
			if (lp->bucket[i].data)
				free(lp->bucket[i].data);
		free(lp);
	}
}

static int leek_word_validate(const char *word, unsigned int len)
{
	if (!len || len > LEEK_ADDRESS_LEN)
		return 0;
	for (unsigned int i = 0; i < len; ++i) {
		if ((word[i] < 'a' || word[i] > 'z') && (word[i] < '2' || word[i] > '7'))
			return 0;
	}
	return 1;
}


static int leek_prefixes_enqueue(struct leek_prefixes *lp,
                                 const char *word, unsigned int len)
{
	struct leek_prefix_bucket *bucket;
	union leek_rawaddr addr;
	unsigned int cur_count;
	uint64_t *ptr;

	if (leek_word_validate(word, len)) {
		leek_base32_dec(addr.buffer, word);
		bucket = &lp->bucket[addr.index];
		cur_count = bucket->cur_count;

		if (cur_count == bucket->max_count) {
			ptr = realloc(bucket->data, (cur_count + LEEK_BUCKETS_INC) * sizeof(*bucket->data));
			if (!ptr) {
				fprintf(stderr, "[-] realloc: %s\n", strerror(errno));
				return -1;
			}
			bucket->max_count += LEEK_BUCKETS_INC;
			bucket->data = ptr;
		}
		bucket->data[cur_count] = addr.suffix;
		bucket->cur_count++;
	}
	else
		lp->invalid_count++;
	return 0;
}


static int leek_prefixes_parse(struct leek_prefixes *lp, FILE *fp)
{
	size_t line_size = LEEK_ADDRESS_LEN + 1;
	char *line;
	int ret = -1;

	line = calloc(1, line_size);
	if (!line) {
		fprintf(stderr, "[-] calloc: %s\n", strerror(errno));
		goto out;
	}

	while (1) {
		unsigned int length;

		ret = getline(&line, &line_size, fp);
		if (ret < 0)
			break;

		length = ret - 1;
		line[length] = 0;

		ret = leek_prefixes_enqueue(lp, line, length);
		if (ret < 0)
			goto line_free;
	}

	ret = 0;

line_free:
	free(line);
out:
	return ret;
}


static int leek_prefix_cmp(const void *a, const void *b)
{
	const uint64_t *va = a;
	const uint64_t *vb = b;

	if (*va > *vb)
		return +1;
	if (*va < *vb)
		return -1;
	return 0;
}


static void leek_prefixes_sort(struct leek_prefixes *lp)
{

	for (unsigned int i = 0; i < LEEK_BUCKETS; ++i) {
		struct leek_prefix_bucket *bucket = &lp->bucket[i];
		unsigned int duplicates = 0;
		unsigned int count;

		count = bucket->cur_count;
		if (!count)
			continue;

		qsort(bucket->data, count, sizeof *bucket->data, leek_prefix_cmp);
		for (unsigned int j = 1; j < count; ++j) {
			if (bucket->data[j] == bucket->data[j - 1]) {
				bucket->data[j - 1] = 0xFFFFFFFFFFFFFFFFUL;
				duplicates++;
			}
		}

		if (duplicates > 0) {
			qsort(bucket->data, count, sizeof *bucket->data, leek_prefix_cmp);
			bucket->cur_count -= duplicates;
			count = bucket->cur_count;
		}
		lp->duplicate_count += duplicates;
		lp->word_count += count;
	}
}


struct leek_prefixes * leek_readfile(const char *filename)
{
	struct leek_prefixes * lp = NULL;
	FILE *fp;
	int ret;

	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "[-] fopen: %s\n", strerror(errno));
		goto out;
	}

	lp = leek_prefixes_alloc();
	if (!lp)
		goto close;

	ret = leek_prefixes_parse(lp, fp);
	if (ret < 0)
		goto error_free;

	leek_prefixes_sort(lp);


close:
	fclose(fp);
out:
	return lp;

error_free:
	leek_prefixes_free(lp);
	lp = NULL;
	goto close;
}

