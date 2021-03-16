CPPFLAGS=-D_GNU_SOURCE
CFLAGS=-std=c99 -Wall -Wextra -m32 `pkg-config --cflags sdl2`
LDFLAGS=-m32
LDLIBS=`pkg-config --libs sdl2` -lpthread

runk:

clean:
	$(RM) runk

.PHONY: clean
