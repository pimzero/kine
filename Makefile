CPPFLAGS=-D_GNU_SOURCE
CFLAGS=-std=c99 -Wall -Wextra -m32 `pkg-config --cflags sdl2`
LDFLAGS=-m32 -ggdb
LDLIBS=`pkg-config --libs sdl2` -lpthread

runk: runk.o syscalls.o sdl.o

clean:
	$(RM) runk

.PHONY: clean
