override CFLAGS  += -std=gnu11 -pipe -O3 -Wall -Werror -Wextra -Wshadow \
                    -Wformat=2 -Wnested-externs -Wchar-subscripts
override LDFLAGS += -pthread
override LDLIBS  += -lm -lssl -lcrypto

LEEK_IMPL := $(wildcard leek_impl_*.c)
LEEK_OBJS := leek.o leek_helper.o leek_worker.o leek_impl.o
LEEK_OBJS += $(LEEK_IMPL:.c=.o)
LEEK_BIN  := leek

OBJECTS   := $(LEEK_OBJS)
BINARIES  := $(LEEK_BIN)

PHYONY += all
all: $(BINARIES)

PHONY += clean
clean:
	rm --force $(BINARIES) $(OBJECTS)

$(LEEK_BIN): $(LEEK_OBJS)

# Target specific compile options.
leek_impl_ssse3.o:  CFLAGS+=-mssse3
leek_impl_avx2.o:   CFLAGS+=-mavx2
leek_impl_avx512.o: CFLAGS+=-mavx512bw

.PHONY: $(PHONY)
