#ifndef __LEEK_SHA1_GENERIC_H
# define __LEEK_SHA1_GENERIC_H
# include <openssl/sha.h>

struct leek_sha1 {
	SHA_CTX hash;
};

#endif /* !__LEEK_SHA1_GENERIC_H */
