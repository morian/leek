#ifndef __LEEK_ITEM_H
# define __LEEK_ITEM_H
# include <pthread.h>

# include <openssl/bn.h>
# include <openssl/rsa.h>

# include "primes.h"


struct leek_rsa_item {
	/* Internal prime P used for RSA structure */
	struct leek_prime *prime_p;
	/* Internal prime Q used for RSA structure */
	struct leek_prime *prime_q;

	RSA *rsa;           /* Generated RSA key-pair */

	void *private_data; /* Implementation specific data */
	unsigned int flags; /* Dynamic flags linked to this item */
};

enum {
	LEEK_RSA_ITEM_DESTROY   = (1 <<  0),
};


/* Generate a new RSA item ready for duty */
struct leek_rsa_item *leek_item_generate(void);

/* Free an allocated RSA item */
void leek_item_destroy(struct leek_rsa_item *item);

/* Generate a DER encoded ASN1 structure for the target RSA structure */
uint8_t *leek_crypto_der_alloc(const RSA *rsa, unsigned int *derlen);

#endif /* !__LEEK_ITEM_H */
