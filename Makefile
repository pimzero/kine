# RENDERERS ?= sdl2
RENDERERS ?= sdl3

CPPFLAGS=-D_GNU_SOURCE -MMD
CFLAGS=-std=c99 -Wall -Wextra -m32
LDFLAGS=-m32
LDLIBS=-lpthread

OBJS=kine.o syscalls.o vgapalette.o
BIN=kine

DEPS=$(OBJS:.o=.d)

$(foreach renderer,$(RENDERERS),\
	$(eval include $(renderer).mk) \
	$(foreach var,LDLIBS OBJS, \
		$(eval $(var) += $($(var)_$(renderer))))\
	$(eval $(OBJS_$(renderer)): CFLAGS += $(CFLAGS_$(renderer))))
$(foreach x,$(RENDERERS),\
	$(foreach y,$(RENDERERS),\
		$(if $(findstring $(x),$(CONFLICTS_$(y))), \
			$(error Conflicting renderers "$(x)" and "$(y)" ))))

all: $(BIN)

$(BIN): $(OBJS)

$(OBJS): kstd.h

# Files to generate from github.com/lse/k
GEN=kstd.h vgapalette.c
kstd.h: ./third_party/k/k/include/k/kstd.h
	grep -E '^(#define|#ifndef|#ifdef|#endif)' $< | sed -E 's/^#define\s+([^\s]+\s)/#define K\1/' >$@

vgapalette.c: ./third_party/k/k/libvga.c
	sed -nE -e 's/^static/const/g' -e '/libvga_default_palette\[/,/}/ { p }' $< >$@

clean:
	$(RM) $(BIN) $(OBJS) $(DEPS) $(GEN)

-include $(DEPS)

.PHONY: all clean
