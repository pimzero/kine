# RENDERERS ?= sdl2
RENDERERS ?= sdl3

CPPFLAGS=-D_GNU_SOURCE -MMD -I third_party/k/k/include
CFLAGS=-std=c99 -Wall -Wextra
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

$(OBJS): i386_gen.h kstd.h

# Files to generate from github.com/lse/k
GEN= \
     i386_gen.h \
     kstd.h \
     vgapalette.c \

kstd.h: ./third_party/k/k/include/k/kstd.h
	sed -E -e 's/^#define\s+([^\s]+\s)/#define K\1/' \
	       -e 's/\<off_t\>/koff_t/g' \
	       -e 's/\<ssize_t\>/kssize_t/g' \
	       $< >$@

vgapalette.c: ./third_party/k/k/libvga.c
	sed -nE -e 's/^static/const/g' -e '/libvga_default_palette\[/,/}/ { p }' $< >$@

gen_i386_hdr: CFLAGS:=-std=c99 -Wall -Wextra -m32
gen_i386_hdr: CPPFLAGS:=
gen_i386_hdr: LDLIBS:=

i386_gen.h: gen_i386_hdr
	./$^ > $@

clean:
	$(RM) $(BIN) $(OBJS) $(DEPS) $(GEN)

-include $(DEPS)

.PHONY: all clean
