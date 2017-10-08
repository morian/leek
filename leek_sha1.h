#ifndef __LEEK_SHA1_H
# define __LEEK_SHA1_H

# if defined(__AVX2__)
#  include "leek_sha1_avx2.h"
# else
#  include "leek_sha1_generic.h"
# endif

#endif /* !__LEEK_SHA1_H */
