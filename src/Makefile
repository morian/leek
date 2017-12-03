CFLAGS    := -std=gnu11 -pipe -O3 -march=native                         \
             -Wall -Werror -Wextra -Wshadow -Wformat=2 -Wnested-externs \
             -Wchar-subscripts
LDLIBS    := -lm -lssl -lcrypto
LDFLAGS   := -pthread

LEEK_OBJS := leek.o leek_helper.o leek_worker.o leek_exhaust.o
LEEK_SHA1 := $(wildcard leek_sha1_*.c)
LEEK_BIN  := leek

OBJECTS   := $(LEEK_OBJS)
BINARIES  := $(LEEK_BIN)

PHYONY += all
all: $(BINARIES)

PHONY += clean
clean:
	rm --force $(BINARIES) $(OBJECTS)

$(LEEK_BIN): $(LEEK_OBJS)

# This is dependency stuff here.
# SHA1 implementations are hard-included by leek_exhaust.c
leek_exhaust.o: $(LEEK_SHA1) leek_exhaust.c

.PHONY: $(PHONY)
