HAVE_SDL3=y
HAVE_SDL2=n

CFLAGS_SDL2=`pkg-config --cflags sdl2`
LDLIBS_SDL2=`pkg-config --libs sdl2`
OBJS_SDL2=sdl2.o
RENDERERS_SDL2=sdl2
CFLAGS_SDL3=`pkg-config --cflags sdl3`
LDLIBS_SDL3=`pkg-config --libs sdl3`
OBJS_SDL3=sdl3.o
RENDERERS_SDL3=sdl3

ifeq ($(HAVE_SDL2),y)
ifeq ($(HAVE_SDL3),y)
# SDL2 and SDL3 symbols conflict, therefore it is not possible to link against
# both libraries.
$(error SDL2 and SDL3 can't be enabled together)
endif
endif

$(foreach renderer,SDL2 SDL3,$(foreach var,CFLAGS LDLIBS OBJS RENDERERS,$(eval $(var)-$(HAVE_$(renderer)) += $($(var)_$(renderer)))))

CPPFLAGS=-D_GNU_SOURCE -MMD -DDEFAULT_RENDERER=\"$(firstword $(RENDERERS-y))\"
CFLAGS=-std=c99 -Wall -Wextra -m32 $(CFLAGS-y)
LDFLAGS=-m32
LDLIBS=-lpthread $(LDLIBS-y)

OBJS=kine.o syscalls.o vgapalette.o $(OBJS-y)
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
