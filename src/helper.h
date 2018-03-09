#ifndef __LEAK_HELPER_H
# define __LEAK_HELPER_H
# include <stdint.h>

# define LEEK_BASE32_ALPHABET          "abcdefghijklmnopqrstuvwxyz234567"
# define LEEK_ADDRESS_LEN              16
# define LEEK_RAWADDR_LEN              10
# define LEEK_CACHELINE_SZ             64 /* bytes */

/* Number of bits per base32 character */
# define LEEK_RAWADDR_CHAR_BITS        5

/* This value ensures that our exponent will always be 4 bytes wide
 * We may consider starting at RSA_F4 instead and handle 3 bytes exponent. */
# define LEEK_RSA_E_SIZE               4 /* bytes */
# define LEEK_RSA_E_START              0x00800001u
/* This limit allows for 8 parallel computations */
# define LEEK_RSA_E_LIMIT              0x7FFFFFFFu
# define LEEK_RSA_KEYSIZE              1024
# define LEEK_RSA_PRIME_SIZE           (LEEK_RSA_KEYSIZE / 2)

/* Compiler short flags for functions and structures */
# define __packed                      __attribute__((packed))
# define __flatten                     __attribute__((flatten))
# define __hot                         __attribute__((hot))

/* Help compiler generating more optimized code for some expected branches */
# define likely(x)                     __builtin_expect(!!(x), 1)
# define unlikely(x)                   __builtin_expect(!!(x), 0)


# define LEEK_BUCKETS                  (1 << 16)
# define LEEK_BUCKETS_INC              8

union leek_rawaddr {
	uint8_t buffer[LEEK_RAWADDR_LEN];
	struct {
		uint16_t index;
		uint64_t suffix;
	} __packed;
};


struct leek_prefix_bucket {
	unsigned int cur_count;
	unsigned int max_count;
	uint64_t *data;
};


struct leek_prefixes {
	unsigned int duplicate_count;
	unsigned int filtered_count;
	unsigned int invalid_count;
	unsigned int word_count;

	unsigned int length_min;
	unsigned int length_max;

	long double prob_find_1;

	/* Amount of data is provided in word_count field */
	struct leek_prefix_bucket bucket[LEEK_BUCKETS];
};

/** Common shared functions **/

/* Read a single prefix from parameter */
int leek_prefix_parse(union leek_rawaddr *laddr, const char *word, unsigned int len);

/* Build a prefix list from file */
struct leek_prefixes *leek_readfile(const char *filename,
                                    unsigned int flt_min, unsigned int flt_max);
void leek_prefixes_free(struct leek_prefixes *lp);


/* Create result directory if needed */
int leek_result_dir_init(void);

/* OpenSSL locks (required for MT operations) */
int leek_openssl_init(void);

/* Corresponding destructor for these locks and cache cleanup */
void leek_openssl_exit(void);


#endif /* !__LEAK_HELPER_H */
