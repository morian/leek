EXTRA_DIST =
CLEANFILES =
PHONY =

AM_MAKEFLAGS = --no-print-directory
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

bin_PROGRAMS = leek
leek_SOURCES =        \
	src/hashes.c        \
	src/hashes.h        \
	src/helper.c        \
	src/helper.h        \
	src/impl.c          \
	src/impl.h          \
	src/impl_openssl.c  \
	src/impl_openssl.h  \
	src/impl_uint.c     \
	src/impl_uint.h     \
	src/item.c          \
	src/item.h          \
	src/leek.c          \
	src/leek.h          \
	src/lookup.h        \
	src/options.c       \
	src/options.h       \
	src/primes.c        \
	src/primes.h        \
	src/result.c        \
	src/result.h        \
	src/stats.c         \
	src/stats.h         \
	src/terminal.c      \
	src/terminal.h      \
	src/vecx.h          \
	src/vecx_core.h     \
	src/worker.c        \
	src/worker.h

if HAVE_SIMD_SSSE3
leek_SOURCES +=       \
	src/impl_ssse3.c    \
	src/impl_ssse3.h
src/impl_ssse3.${OBJEXT}: CFLAGS+=-mssse3
endif

if HAVE_SIMD_AVX2
leek_SOURCES +=       \
	src/impl_avx2.c     \
	src/impl_avx2.h
src/impl_avx2.$(OBJEXT): CFLAGS+=-mavx2
endif

if HAVE_SIMD_AVX512
leek_SOURCES +=       \
	src/impl_avx512.c   \
	src/impl_avx512.h
src/impl_avx512.$(OBJEXT): CFLAGS+=-mavx512bw
endif

DEB_BUILD_ROOT = @abs_top_builddir@/_build/DEBIAN
RPM_BUILD_ROOT = @abs_top_builddir@/_build
RPM_SOURCE_DIR = $(RPM_BUILD_ROOT)/SOURCES
RPM_TARBALL    = $(RPM_SOURCE_DIR)/@PACKAGE@-@VERSION@.tar.bz2
PKG_DIRNAME    = @PACKAGE@-@VERSION@

$(RPM_TARBALL): dist
	mkdir --parents "$(RPM_SOURCE_DIR)"
	cp --archive "${PKG_DIRNAME}.tar.bz2" $@

PHONY += rpm
rpm: $(RPM_TARBALL)
	rpmbuild -bb --define "%_topdir $(RPM_BUILD_ROOT)" pkg/centos/leek.spec

$(DEB_BUILD_ROOT): dist
	mkdir -p "$@/${PKG_DIRNAME}"
	tar --directory="$@" -xf "${PKG_DIRNAME}.tar.bz2"
	cp --archive pkg/debian "$@/${PKG_DIRNAME}/"

PHONY += deb
deb: $(DEB_BUILD_ROOT)
	(cd "$</${PKG_DIRNAME}/" && debuild -i -us -uc -b)

.PHONY: $(PHONY)
