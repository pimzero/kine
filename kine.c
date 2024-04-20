/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <asm/ldt.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "kine.h"
#include "kstd.h"

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif

#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)

#define USER_ESP 0x90000
#define BASE 65536
#define LIMIT 10240

typedef void (*entry_t)(void);
int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args);

struct k_state_t k_state = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.video_mode = KVIDEO_TEXT,
	.key = -1,
	.pressed = RING_INITIALIZER,
	.released = RING_INITIALIZER
};

struct config_t config = {
	.path = ".",
	.base = BASE,
	.limit = LIMIT,
	.sp = USER_ESP,
	.brk = USER_ESP,
};

void lock(void) {
	if (pthread_mutex_lock(&k_state.lock))
		err(1, "pthread_mutex_lock");
}

void unlock(void) {
	if (pthread_mutex_unlock(&k_state.lock))
		err(1, "pthread_mutex_unlock");
}

uint32_t getms(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int set_syscall_user_dispatch(void* start, void* end) {
	return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start,
		     end, NULL);
}

static int modify_ldt(int func, struct user_desc* ptr, unsigned long count) {
    return syscall(SYS_modify_ldt, func, ptr, count);
}

static void sigsys_handler(int n, siginfo_t* siginfo, void* ucontext) {
	(void) n;

	struct ucontext_t* ctx = ucontext;
	uint32_t args[] = {
		ctx->uc_mcontext.gregs[REG_EBX],
		ctx->uc_mcontext.gregs[REG_ECX],
		ctx->uc_mcontext.gregs[REG_EDX],
		ctx->uc_mcontext.gregs[REG_ESI],
	};

	ctx->uc_mcontext.gregs[REG_EAX] =
		syscall_dispatch(siginfo->si_syscall, args);
}

static void readat(int fd, size_t off, void* buf, size_t count) {
	if (lseek(fd, off, SEEK_SET) < 0)
		err(1, "lseek");
	if (read(fd, buf, count) < (int)count)
		err(1, "read");
}

static entry_t load_elf(const char* fname) {
	int fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "open");

	Elf32_Ehdr ehdr;
	if (read(fd, &ehdr, sizeof(ehdr)) < (int)sizeof(ehdr))
		err(1, "read");

	Elf32_Ehdr sig = {
		.e_ident = {
			ELFMAG0,
			ELFMAG1,
			ELFMAG2,
			ELFMAG3,
			ELFCLASS32,
			ELFDATA2LSB,
			EV_CURRENT,
			ELFOSABI_SYSV
		},
		.e_type = ET_EXEC,
		.e_machine = EM_386,
		.e_version = EV_CURRENT,
	};
	if (memcmp(&ehdr, &sig, offsetof(Elf32_Ehdr, e_entry)))
		errx(1, "invalid file \"%s\"", fname);

	void* map = mmap((void*)config.base, config.limit * 4096, PROT_RWX,
			 MAP_PRIVATE|MAP_FIXED|MAP_ANON, -1, 0);
	if (!map)
		err(1, "mmap");

	for (size_t i = 0; i < ehdr.e_phnum; i++) {
		Elf32_Phdr phdr;
		readat(fd, ehdr.e_phoff + i * sizeof(phdr), &phdr,
		       sizeof(phdr));

		if (phdr.p_type != PT_LOAD)
			continue;

		readat(fd, phdr.p_offset, (char*)map + phdr.p_vaddr,
		       phdr.p_filesz);
	}

	k_state.brk = config.brk;

	if (set_syscall_user_dispatch((char*)config.base + config.limit * 4096,
				      (void*)-1) < 0)
		err(1, "set_syscall_user_dispatch");

	close(fd);

	return (entry_t)ehdr.e_entry;
}

static void set_ldt_entry(unsigned nr, unsigned content,
				 unsigned read_exec_only) {
	struct user_desc ldt_entry = {
		.entry_number = nr,
		.base_addr = config.base,
		.limit = config.limit,
		.limit_in_pages = 1,
		.seg_32bit = 1,
		.contents = content,
		.read_exec_only = read_exec_only,
	};
	if (modify_ldt(0x11, &ldt_entry, sizeof(ldt_entry)) < 0)
		err(1, "modify_ldt");
}

static void k_start(entry_t entry) {
	k_state.starttime = getms();

	__asm__ volatile(
	"mov $23, %%bx\n\t"
	"mov %%bx, %%ss\n\t"
	"mov %%bx, %%ds\n\t"
	"mov %%bx, %%es\n\t"
	"mov %%bx, %%fs\n\t"

	"mov %[sp], %%esp\n\t"
	"pushl $15\n\t"
	"pushl %[entry]\n\t"

	"xor %%eax, %%eax\n\t"
	"xor %%ebx, %%ebx\n\t"
	"xor %%ecx, %%ecx\n\t"
	"xor %%edx, %%edx\n\t"
	"xor %%esi, %%esi\n\t"
	"xor %%edi, %%edi\n\t"
	"xor %%ebp, %%ebp\n\t"
	"lret\n\t"
	: /* outputs */
	: [entry]"r"(entry), [sp]"r"(config.sp)
	: "memory");
}

static void k_setup_sighandler(void) {
	stack_t ss = {
		.ss_sp = malloc(SIGSTKSZ * 16),
		.ss_size = SIGSTKSZ * 16,
		.ss_flags = 0
	};
	if (!ss.ss_sp)
		err(1, "malloc");

	if (sigaltstack(&ss, NULL) < 0)
		err(1, "sigaltstack");

	struct sigaction sa = {
		.sa_sigaction = sigsys_handler,
		.sa_flags = SA_SIGINFO|SA_ONSTACK,
	};
	if (sigaction(SIGSYS, &sa, NULL) < 0)
		err(1, "sigaction");
}

static void* k_thread(void* fname) {
	entry_t entry = load_elf(fname);

	k_setup_sighandler();

	set_ldt_entry(1, 2, 1);
	set_ldt_entry(2, 0, 0);

	k_start(entry);

	return NULL;
}

static void init_k_state(void) {
	k_state.sdl_palette = SDL_AllocPalette(256);
	if (!k_state.sdl_palette)
		errx(1, "SDL_AllocPalette: %s", SDL_GetError());

	for (unsigned i = 0; i < 256; i++) {
		k_state.palette[i].b = libvga_default_palette[i] & 0xff;
		k_state.palette[i].g = (libvga_default_palette[i] >> 8) & 0xff;
		k_state.palette[i].r = (libvga_default_palette[i] >> 16) & 0xff;
	}
}

static uint32_t parse_ptr(const char* str) {
	return strtol(str, NULL, 0);
}

static void help(const char* argv0) {
	fprintf(stderr,
	"Usage: %s [arguments] /path/to/rom\n"
	"\n"
	"Arguments:\n"
	"  -h     \tShow this message\n"
	"  -s     \tTrace syscalls\n"
	"  -S addr\tStart value of stack pointer (default: %#x)\n"
	"  -H addr\tStart value of heap pointer (default: %#x)\n"
	"  -b addr\tAddress to load the rom (default: %#x)\n"
	"  -l num \tSize (limit) of the rom's segment (in pages) (default: %#x)\n",
	argv0, USER_ESP, USER_ESP, BASE, LIMIT);
}

int main(int argc, char** argv) {
	int opt;

	while ((opt = getopt(argc, argv, "p:sS:H:b:hl:")) != -1) {
		switch (opt) {
		case 'p':
			config.path = strdup(optarg);
			break;
		case 'S': /* stack */
			config.sp = parse_ptr(optarg);
			break;
		case 'H': /* heap */
			config.brk = parse_ptr(optarg);
			break;
		case 'b': /* base address */
			config.base = parse_ptr(optarg);
			break;
		case 's':
			config.strace = 1;
			break;
		default:
			fprintf(stderr, "\n");
			/* fallthrough */
		case 'h':
			help(argv[0]);
			exit(opt != 'h');
		}
	}

	if (!argv[optind])
		errx(1, "missing rom file");

	init_k_state();

	SDL_Renderer* renderer = init_window();

	pthread_t k_tid;
	if (pthread_create(&k_tid, NULL, k_thread, argv[optind]) < 0)
		err(1, "pthread_create");

	while (!k_state.quit) {
		update_inputs();
		update_renderer(renderer);
	}

	pthread_cancel(k_tid);
	SDL_Quit();
}
