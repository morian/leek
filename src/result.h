#ifndef __LEEK_RESULT_H
# define __LEEK_RESULT_H

# include <stdbool.h>

# include <openssl/opensslv.h>
# include <openssl/rsa.h>

# ifndef OPENSSL_VERSION_1_1
#  define OPENSSL_VERSION_1_1    0x10100000L
# endif

/* Forward declaration */
struct leek_result;

/* Describes a single result item */
struct leek_result {
	struct leek_result *next;            /* Next in the global linked list */
	struct leek_result *prev;            /* Prev in the global linked list */

	unsigned int id;                     /* Result number */

	uint8_t address[LEEK_ADDRESS_LEN];   /* ASCII address */
	unsigned int address_length;         /* Number of matching characters */

	uint8_t *prv_data;                   /* RSA Private key pointer */
	unsigned int prv_length;             /* RSA Private key length */

	uint32_t exponent;                   /* Found exponent */
	unsigned int flags;                  /* See bellow */
};

enum {
	/* Whether this item has been displayed by the main thread */
	LEEK_RESULT_FLAG_DISPLAYED    = (1 <<  0),
};


/* Recheck a promising candidate */
int leek_result_recheck(struct leek_crypto *item, uint32_t exponent,
                        const union leek_rawaddr *addr);

/* Handle a valid result (writing to file, displaying, etc...) */
void leek_result_handle(RSA *rsa, uint32_t exponent, int length,
                        const union leek_rawaddr *addr);

/* Show all items in queue */
void leek_result_found_display(bool verbose);

/* Show un-displayed results in the main thread */
void leek_result_new_display(bool verbose);

/* Clean the whole list of results */
void leek_results_purge(void);


#endif /* !__LEEK_RESULT_H */
