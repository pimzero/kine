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

Motivation
----------

I wanted to play with the new `prctl` `PR_SET_SYSCALL_USER_DISPATCH`, so I
wrote an emulation layer for github.com/lse/k. It also seemed like a good
opportunity to throw some assembly and few calls to `modify_ldt(2)` :).
