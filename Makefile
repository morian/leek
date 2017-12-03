# Available binary files.
BINARIES    := leek
PASSTHROUGH := all clean
TARGETS     := $(PASSTHROUGH) $(BINARIES)
SRCDIR      := src/

PHONY += $(PASSTHROUGH)
$(TARGETS):
	$(MAKE) -C $(SRCDIR) $@

.PHONY: $(PHONY)
