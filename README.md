Kine: Kine Is Not an Emulator
=============================

[K](https://k.lse.epita.fr/) is a toy kernel used as a kernel project at EPITA
([Sources](https://github.com/lse/k)). This kernel can run userland
programs/videogames called roms. Those roms are statically linked i386 ELFs,
but K has its own syscall interface, and its own memory layout, both not
compatible with Linux. In order to be able to run those roms in Linux, one
solution is to use a custom loader (like wine, but way simpler). This project
is this loader.

Usage
-----

```
$ git submodule update --recursive --init
$ make -C ./third_party/k/
$ ROOT_PATH="./third_party/k/iso"
$ ROM_PATH="./third_party/k/roms/skate/skate" # Or any other rom
$ make
$ ./kine -p "$ROOT_PATH" "$ROM_PATH"
```

Build
-----

Kine can use different framework for its UI (renderers). They can be selected
at build time with the RENDERERS= variable. It is possible to specify multiple
renderers in this variable.

Currently the supported values are:

- `sdl3`: Use and link with SDL3
- `sdl2`: Use and link with SDL2
- `sdl3_dl`: Use SDL3, but don't link with it
- `sdl2_dl`: Use SDL2, but don't link with it
- `noop`: A test renderer, that does nothing

Because `libSDL2` and `libSDL3` symbols conflicts, we can't link them at the
same time. The `sdl2_dl`/`sdl3_dl` renderers exist to solve this issue: they
will resolve the symbols at runtime and not link with the libraries.

For instance, if we want to default to sdl3, but allow running with sdl2, we
can build with:

$ make RENDERERS='sdl3 sdl2_dl'
$ K=third_party/k
$ ./kine -p $K/iso/ $K/roms/chichepong/pong # Uses SDL3
$ ./kine -r sdl2 -p $K/iso/ $K/roms/chichepong/pong # Uses SDL2

We can do the same thing with SDL2 as default:

$ make RENDERERS='sdl2 sdl3_dl'
$ K=third_party/k
$ ./kine -p $K/iso/ $K/roms/chichepong/pong # Uses SDL2
$ ./kine -r sdl3 -p $K/iso/ $K/roms/chichepong/pong # Uses SDL2

For UX reasons `sdl3` conflicts with `sdl3_dl`, and `sdl2` conflicts with
`sdl2_dl`.

Motivation
----------

I wanted to play with the new `prctl` `PR_SET_SYSCALL_USER_DISPATCH`, so I
wrote an emulation layer for github.com/lse/k. It also seemed like a good
opportunity to throw some assembly and few calls to `modify_ldt(2)` :).
