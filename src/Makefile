override CFLAGS  += -std=gnu11 -pipe -O3 -Wall -Werror -Wextra -Wshadow \
                    -Wformat=2 -Wnested-externs -Wchar-subscripts
override LDFLAGS += -pthread
override LDLIBS  += -lm -lssl -lcrypto

# This disables all avx512 implementations on GCC-4 (and lower)
# These versions do not support avx512bw which is necessary.
GCCVERSIONLTE5 := $(shell expr `$(CC) -dumpversion | cut -f1 -d.` \< 5)
ifeq ($(GCCVERSIONLTE5),1)
	override CFLAGS += -DNOAVX512
endif

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

.PHONY: $(PHONY)
