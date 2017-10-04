#include <endian.h>
#include <string.h>

#include "leek_cpu.h"


#if defined(__AVX2__)
#elif defined(__SSSE3__)
#else
# include "leek_sha1_generic.c"
#endif
