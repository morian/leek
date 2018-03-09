CFLAGS  := -std=gnu11 -pipe -O3 -D_GNU_SOURCE                          \
           -fvisibility=hidden -ffunction-sections -fdata-sections     \
           -Wall -Wextra -Wmissing-declarations -Wmissing-prototypes   \
           -Wshadow -Wnested-externs -Wformat=2 -Wchar-subscripts      \
           -Wtype-limits -Wno-missing-braces -Wno-unused-parameter $(CFLAGS)
LDFLAGS := -Wl,-O1 -Wl,--gc-sections -Wl,--as-needed -Wl,--discard-all \
           -pthread $(LDFLAGS)
LDLIBS  := -lm -lssl -lcrypto

L_SOURCES := $(wildcard src/*.c)
L_HEADERS := $(wildcard src/*.h)
L_OBJECTS := $(patsubst %.c,%.o,$(L_SOURCES))
L_PROGS   := leek

PHYONY += all
all: $(L_PROGS)

leek: $(L_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(L_OBJECTS): $(L_HEADERS)

PHONY += clean
clean:
	rm --force $(L_OBJECTS)
	rm --force $(L_PROGS)

# Target specific compile options.
src/leek_impl_ssse3.o:  CFLAGS+=-mssse3
src/leek_impl_avx2.o:   CFLAGS+=-mavx2
src/leek_impl_avx512.o: CFLAGS+=-mavx512bw

.PHONY: $(PHONY)
