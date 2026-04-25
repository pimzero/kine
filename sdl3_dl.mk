CFLAGS_sdl3_dl=`pkg-config --cflags sdl3` -DUSE_DL_LAZY=1
LDLIBS_sdl3_dl=-ldl
OBJS_sdl3_dl=sdl3.o
CONFLICTS_sdl3_dl=sdl3
