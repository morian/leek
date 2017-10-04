CFLAGS    := -std=gnu11 -pipe -O3                      \
             -Wall -Werror -Wextra -Wshadow -Wformat=2 \
             -Wnested-externs -Wchar-subscripts -Wpointer-arith
LDLIBS    := -lssl -lcrypto
LDFLAGS   := -pthread

LEEK_BIN  := leek
LEEK_OBJS := leek.o leek_helper.o leek_worker.o leek_exhaust.o
LEEK_SHA1 := $(wildcard leek_sha1_*.c)
BINARIES  := $(LEEK_BIN)
OBJECTS   := $(LEEK_OBJS)

$(LEEK_BIN): $(LEEK_OBJS)

PHYONY += all
all: $(BINARIES)

# SHA1 dependencies.
leek_exhaust.o: $(LEEK_SHA1)


PHONY += clean
clean:
	rm -f $(BINARIES) $(LIBRARIES) $(OBJECTS)

.PHONY: $(PHONY)
