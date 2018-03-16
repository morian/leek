#ifndef __LEEK_IMPL_UINT_H
# define __LEEK_IMPL_UINT_H
# include <byteswap.h>
# include <stdint.h>

/* Plain uint32_t implementation */
typedef uint32_t vecx;


static inline vecx vecx_zero(void)
{
	return 0;
}

static inline vecx vecx_set(uint32_t x)
{
	return x;
}

static inline vecx vecx_load(const void *ptr)
{
	const vecx *ptrv = (const vecx *) ptr;
	return *ptrv;
}

static inline void vecx_store(void *ptr, vecx x)
{
	vecx *ptrv = (vecx *) ptr;
	*ptrv = x;
}

static inline vecx vecx_or(vecx x, vecx y)
{
	return (x | y);
}

static inline vecx vecx_xor(vecx x, vecx y)
{
	return (x ^ y);
}

static inline vecx vecx_and(vecx x, vecx y)
{
	return (x & y);
}

static inline vecx vecx_anot(vecx x, vecx y)
{
	return (~x & y);
}

static inline vecx vecx_add(vecx x, vecx y)
{
	return (x + y);
}

static inline vecx vecx_shl(vecx x, int y)
{
	return (x << y);
}

static inline vecx vecx_shr(vecx x, int y)
{
	return (x >> y);
}

static inline vecx vecx_rol(vecx x, int y)
{
	vecx a = vecx_shl(x, y);
	vecx b = vecx_shr(x, 32 - y);
	return vecx_or(a, b);
}

static inline vecx vecx_ror(vecx x, int y)
{
	vecx a = vecx_shr(x, y);
	vecx b = vecx_shl(x, 32 - y);
	return vecx_or(a, b);
}

static inline vecx vecx_bswap(vecx x)
{
	return bswap_32(x);
}

static inline vecx vecx_even_numbers(void)
{
	return 0;
}

#define vecx_transpose(row0, row1, row2, row3)

#define VECX_LANE_ORDER                         0
#define VECX_IMPL_NAME                   "UINT32"
/* dummy instruction to avoid full rewriting */
#define VECX_IMPL_ISA                       "mmx"

/* Include macro expansion and generic SHA1 stuff here */
#include "vecx_core.h"

#endif /* !__LEEK_IMPL_UINT_H */
