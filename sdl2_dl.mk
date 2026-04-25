CFLAGS_sdl2_dl=`pkg-config --cflags sdl2` -DUSE_DL_LAZY=1
LDLIBS_sdl2_dl=-ldl
OBJS_sdl2_dl=sdl2.o
CONFLICTS_sdl2_dl=sdl2
