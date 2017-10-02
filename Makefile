CFLAGS   = -W -Wall -Werror -Wextra -std=c99 -O3 -march=native
LDLIBS   = -lssl -lcrypto
LDFLAGS  = -pthread

LEEK_BIN  = leek
LEEK_OBJS = leek.o leek_helper.o leek_worker.o
BINARIES  = $(LEEK_BIN)
OBJECTS   = $(LEEK_OBJS)

$(LEEK_BIN): $(LEEK_OBJS)

PHYONY += all
all: $(BINARIES)

PHONY += clean
clean:
	rm -f $(BINARIES) $(LIBRARIES) $(OBJECTS)

.PHONY: $(PHONY)
