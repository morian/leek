#ifndef __LEEK_SHA1_H
# define __LEEK_SHA1_H

# if defined(__AVX2__)
#  error "Oops, not yet implemented"
# else
#  include <openssl/sha.h>

	struct leek_sha1 {
		SHA_CTX hash;
	};
# endif


#endif /* !__LEEK_SHA1_H */
