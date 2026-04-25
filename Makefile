# RENDERERS ?= sdl2
RENDERERS ?= sdl3 sdl2_dl

K=./third_party/k

CPPFLAGS=-MMD
CFLAGS=-std=c99 -Wall -Wextra

BINS=kine gen_i386_hdr

kine_CPPFLAGS=-D_GNU_SOURCE -I $(K)/k/include
kine_LDLIBS=-lpthread
kine_OBJS=kine.o syscalls.o vgapalette.o mode_syscall_user_dispatch.o mode_ptrace.o

gen_i386_hdr_OBJS=gen_i386_hdr.o

OBJS=$(kine_OBJS) $(gen_i386_hdr_OBJS)
DEPS=$(OBJS:.o=.d)

$(foreach renderer,$(RENDERERS),\
	$(eval include $(renderer).mk) \
	$(foreach var,LDLIBS OBJS, \
		$(eval kine_$(var) += $($(var)_$(renderer))))\
	$(eval $(OBJS_$(renderer)): CFLAGS += $(CFLAGS_$(renderer))))
$(foreach x,$(RENDERERS),\
	$(foreach y,$(RENDERERS),\
		$(if $(findstring $(x),$(CONFLICTS_$(y))), \
			$(error Conflicting renderers "$(x)" and "$(y)" ))))

all: kine

kine $(kine_OBJS): CPPFLAGS:=$(CPPFLAGS) $(kine_CPPFLAGS)
kine $(kine_OBJS): CFLAGS:=$(CFLAGS) $(kine_CFLAGS)
kine: LDLIBS:=$(kine_LDLIBS)
kine: $(kine_OBJS)

$(kine_OBJS): i386_gen.h kstd.h

# Files to generate from github.com/lse/k
GEN= \
     i386_gen.h \
     kstd.h \
     vgapalette.c \

kstd.h: $(K)/k/include/k/kstd.h
	sed -E -e 's/^#define\s+([^\s]+\s)/#define K\1/' \
	       -e 's/\<off_t\>/koff_t/g' \
	       -e 's/\<ssize_t\>/kssize_t/g' \
	       $< >$@

vgapalette.c: $(K)/k/libvga.c
	sed -nE -e 's/^static/const/g' -e '/libvga_default_palette\[/,/}/ { p }' $< >$@

gen_i386_hdr: CFLAGS:=$(CFLAGS) -m32
gen_i386_hdr: LDFLAGS:=$(LDFLAGS) -m32
gen_i386_hdr: $(gen_i386_hdr_OBJS)

i386_gen.h: gen_i386_hdr
	./$^ > $@

clean:
	$(RM) $(BINS) $(OBJS) $(DEPS) $(GEN)
	make -f testrom.mk clean K="$(K)"

testrom: FORCE
	make -f testrom.mk testrom K="$(K)"

tests: testrom FORCE
	./testcases.sh ./kine testrom

-include $(DEPS)

run-%: $(K)/roms/% kine FORCE
	$(MAKE) -C "$(K)"
	echo "$$(make -C $< -p | grep '^TARGET\>' | sed 's/TARGET\s*=\s*//')"
	./kine -p "$(K)/iso/" "$(<)/$$(make -C "$<" -p | grep '^TARGET\>' | sed 's/TARGET\s*=\s*//')" $(FLAGS)

FORCE:

.PHONY: all clean
