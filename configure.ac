AC_PREREQ(2.64)

AC_INIT([leek], [2.0.6], [morian@xdec.net])

AC_PREFIX_DEFAULT([/usr])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/leek.c])

AM_INIT_AUTOMAKE([foreign -Wall silent-rules tar-pax dist-bzip2 subdir-objects])

AC_LANG_C
AC_PROG_SED
AC_PROG_MKDIR_P

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_SILENT_RULES([yes])


AC_CHECK_LIB(pthread, pthread_mutex_init,
	[PTHREAD_CFLAGS="" PTHREAD_LIBS="-lpthread"],
	[AC_MSG_FAILURE(Unable to find libpthread.)]
)
PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 1.0.0])


AX_CHECK_COMPILE_FLAG([-std=c11],
	[AX_APPEND_FLAG([-std=c11])],
	[AX_CHECK_COMPILE_FLAG([-std=c99],
		[AX_APPEND_FLAG([-std=c99])],
		[AC_MSG_FAILURE(C compiler cannot compile C99 or C11 code)
	])
])

CFLAGS+=" -D_GNU_SOURCE -DOPENSSL_API_COMPAT=0x10000000L -DOPENSSL_NO_DEPRECATED=1 \
-pipe -Wall -Wextra -Wno-missing-braces -Wmissing-declarations \
-Wmissing-prototypes -Wlogical-op -Wshadow -Wstrict-prototypes \
-Wwrite-strings -Wvla -Wformat-security -Wformat=2 -Wnested-externs \
-Wchar-subscripts -Wtype-limits -Wno-unused-parameter"

# The following flags are not supported by all compilers.
AX_CHECK_COMPILE_FLAG([-Wnormalized], [AX_APPEND_FLAG([-Wnormalized])], [])
AX_CHECK_COMPILE_FLAG([-Wnull-dereference], [AX_APPEND_FLAG([-Wnull-dereference])], [])

CFLAGS+=" ${OPENSSL_CFLAGS} ${PTHREAD_CFLAGS}"
LIBS="${OPENSSL_LIBS} ${PTHREAD_LIBS} -lm"


AX_CHECK_COMPILE_FLAG([-mssse3], [
	AC_DEFINE([HAVE_SIMD_SSSE3], [1], [Compiler supports ssse3])
	HAVE_SIMD_SSSE3=true
])
AM_CONDITIONAL([HAVE_SIMD_SSSE3],  [test x${HAVE_SIMD_SSSE3} = xtrue])

AX_CHECK_COMPILE_FLAG([-mavx2], [
	AC_DEFINE([HAVE_SIMD_AVX2], [1], [Compiler supports avx2])
	HAVE_SIMD_AVX2=true
])
AM_CONDITIONAL([HAVE_SIMD_AVX2],   [test x${HAVE_SIMD_AVX2} = xtrue])

AX_CHECK_COMPILE_FLAG([-mavx512bw], [
	AC_DEFINE([HAVE_SIMD_AVX512], [1], [Compiler supports avx512])
	HAVE_SIMD_AVX512=true
])
AM_CONDITIONAL([HAVE_SIMD_AVX512], [test x${HAVE_SIMD_AVX512} = xtrue])


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	pkg/centos/leek.spec
])

AC_OUTPUT
AC_MSG_RESULT([
    ${PACKAGE} ${VERSION}
    =====

    prefix:        ${prefix}
    sysconfdir:    ${sysconfdir}
    libdir:        ${libdir}
    includedir:    ${includedir}

    compiler:      ${CC}
    cflags:        ${CFLAGS}
    ldflags:       ${LDFLAGS} ${LIBS}
])
