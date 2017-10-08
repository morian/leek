#ifndef __LEEK_VEC_COMMON_H
# define __LEEK_VEC_COMMON_H

# define VEC_SHA1_LBLOCK_SIZE    16
# define VEC_SHA1_BLOCK_SIZE     (VEC_SHA1_LBLOCK_SIZE * 4)
# define VEC_RAWADDR_LEN         16

/* SHA1 constants */

# define VEC_SHA1_H0    0x67452301
# define VEC_SHA1_H1    0xefcdab89
# define VEC_SHA1_H2    0x98badcfe
# define VEC_SHA1_H3    0x10325476
# define VEC_SHA1_H4    0xc3d2e1f0

# define VEC_SHA1_K1    0x5a827999
# define VEC_SHA1_K2    0x6ed9eba1
# define VEC_SHA1_K3    0x8f1bbcdc
# define VEC_SHA1_K4    0xca62c1d6

#endif /* !__LEEK_VEC_COMMON_H */
