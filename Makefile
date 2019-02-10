CFLAGS    := -std=gnu11 -pipe -O3 -D_GNU_SOURCE                          \
             -fvisibility=hidden -ffunction-sections -fdata-sections     \
             -Wall -Wextra -Wmissing-declarations -Wmissing-prototypes   \
             -Wshadow -Wnested-externs -Wformat=2 -Wchar-subscripts      \
             -Wtype-limits -Wno-missing-braces -Wno-unused-parameter ${CFLAGS}
LDFLAGS   := -Wl,-O1 -Wl,--gc-sections -Wl,--as-needed -Wl,--discard-all \
             -pthread ${LDFLAGS}
LIBS      := -lm -lssl -lcrypto

PREFIX    ?= /usr/
BINDIR    ?= ${PREFIX}/bin

L_SOURCES := $(wildcard src/*.c)
L_HEADERS := $(wildcard src/*.h)
L_OBJECTS := $(patsubst %.c,%.o,${L_SOURCES})
L_PROGS   := leek


PHYONY += all
all: ${L_PROGS}

leek: ${L_OBJECTS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

${L_OBJECTS}: ${L_HEADERS}

PHONY += install
install: ${L_PROGS}
	install -m 755 -d ${DESTDIR}${BINDIR}
	install -m 755 ${L_PROGS} ${DESTDIR}${BINDIR}

PHONY += clean
clean:
	rm --force ${L_OBJECTS}
	rm --force ${L_PROGS}

# Target specific compile options.
src/impl_ssse3.o:  CFLAGS+=-mssse3
src/impl_avx2.o:   CFLAGS+=-mavx2
src/impl_avx512.o: CFLAGS+=-mavx512bw

.PHONY: ${PHONY}
