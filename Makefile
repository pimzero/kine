CPPFLAGS=-D_GNU_SOURCE -MMD -DDEFAULT_RENDERER=\"sdl2\"
CFLAGS=-std=c99 -Wall -Wextra -m32 `pkg-config --cflags sdl2`
LDFLAGS=-m32
LDLIBS=`pkg-config --libs sdl2` -lpthread

OBJS=kine.o syscalls.o sdl2.o vgapalette.o
BIN=kine

DEPS=$(OBJS:.o=.d)

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
