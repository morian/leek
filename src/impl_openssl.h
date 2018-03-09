#ifndef __LEEK_IMPL_OPENSSL_H
# define __LEEK_IMPL_OPENSSL_H
# include <openssl/sha.h>

# define LEEK_SHA1_COPY_SIZE  (10 * sizeof(SHA_LONG))

struct leek_crypto_openssl {
	SHA_CTX hash;
};

#endif /* !__LEEK_IMPL_OPENSSL_H */
