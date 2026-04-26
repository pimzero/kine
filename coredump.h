#ifndef KINE_COREDUMP_H
#define KINE_COREDUMP_H

#if __x86_64__
#include "i386_gen.h"
#else
#include <sys/procfs.h>
#include <sys/user.h>
#define elf_prstatus_i386 elf_prstatus
#define user_regs_struct_i386 user_regs_struct
#endif

void coredump_write(const struct user_regs_struct_i386 *regs);

#endif
