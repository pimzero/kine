CPPFLAGS=-D_GNU_SOURCE -MMD
CFLAGS=-std=c99 -Wall -Wextra -m32 `pkg-config --cflags sdl2`
LDFLAGS=-m32
LDLIBS=`pkg-config --libs sdl2` -lpthread

OBJS=kine.o syscalls.o sdl.o vgapalette.o
BIN=kine

DEPS=$(OBJS:.o=.d)

$(BIN): $(OBJS)

clean:
	$(RM) $(BIN) $(OBJS) $(DEPS)

-include $(DEPS)

.PHONY: clean
