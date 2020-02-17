AC_PREREQ(2.60)

AC_INIT([leek], [2.0.4], [morian@xdec.net])

AC_PREFIX_DEFAULT([/usr])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/leek.c])

AM_INIT_AUTOMAKE([foreign -Wall
                  silent-rules tar-pax dist-bzip2 subdir-objects])

AC_LANG_C
AC_PROG_SED
AC_PROG_CC_STDC
AC_PROG_MKDIR_P

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_SILENT_RULES([yes])

AX_CHECK_COMPILE_FLAG(-mssse3, [
		AC_DEFINE([HAVE_SIMD_SSSE3], [1], [Compiler supports ssse3])
		HAVE_SIMD_SSSE3=true
	])
AM_CONDITIONAL([HAVE_SIMD_SSSE3],  [test x${HAVE_SIMD_SSSE3} = xtrue])

AX_CHECK_COMPILE_FLAG(-mavx2, [
		AC_DEFINE([HAVE_SIMD_AVX2], [1], [Compiler supports avx2])
		HAVE_SIMD_AVX2=true
	])
AM_CONDITIONAL([HAVE_SIMD_AVX2],   [test x${HAVE_SIMD_AVX2} = xtrue])

AX_CHECK_COMPILE_FLAG(-mavx512bw, [
		AC_DEFINE([HAVE_SIMD_AVX512], [1], [Compiler supports avx512])
		HAVE_SIMD_AVX512=true
	])
AM_CONDITIONAL([HAVE_SIMD_AVX512], [test x${HAVE_SIMD_AVX512} = xtrue])

PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0.0])
AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])

AC_CHECK_LIB(pthread, pthread_mutex_init, [PTHREAD_CFLAGS="" PTHREAD_LIBS="-lpthread"],
             [AC_MSG_FAILURE(Unable to find libpthread.)])
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LIBS)

LEEK_CFLAGS="-std=gnu11 -pipe -O3 -D_GNU_SOURCE \
-Wall -Wextra -Wmissing-declarations -Wmissing-prototypes \
-Wshadow -Wnested-externs -Wformat=2 -Wchar-subscripts \
-Wtype-limits -Wno-missing-braces -Wno-unused-parameter"
AC_SUBST([LEEK_CFLAGS], "${LEEK_CFLAGS}")

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
    cflags:        ${CFLAGS} ${OPENSSL_CFLAGS} ${PTHREAD_CFLAGS}
    ldflags:       ${LDFLAGS} ${OPENSSL_LIBS} ${PTHREAD_LIBS}
])
