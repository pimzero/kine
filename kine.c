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
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "kine.h"
#include "kstd.h"

#define XSTR(S) STR(S)
#define STR(S) #S

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

#define SEGMENT_CODE 1
#define SEGMENT_DATA 2
#define SEGMENT_LINUX_GS 12 /* TODO: This is only correct on x86-64 */

#define SEGMENT_LDT (1 << 2)
#define SEGMENT_GDT 0
#define SEGMENT_RPL3 (0x3)
#define SEG_REG(Segment, Table, Rpl) \
	((SEGMENT_##Segment << 3) | SEGMENT_##Table | SEGMENT_RPL##Rpl)

typedef void (*entry_t)(void);
int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args);

static struct render_state render_state_default;

struct k_state_t k_state = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.video_mode = KVIDEO_TEXT,
	.key = -1,
	.pressed = RING_INITIALIZER,
	.released = RING_INITIALIZER,
	.render_state = &render_state_default,
};

struct config_t config = {
	.path = ".",
	.base = BASE,
	.limit = LIMIT,
	.sp = USER_ESP,
	.brk = USER_ESP,
};

void k_lock(struct k_state_t* k) {
	if (pthread_mutex_lock(&k->lock))
		err(1, "pthread_mutex_lock");
}

void k_unlock(struct k_state_t* k) {
	if (pthread_mutex_unlock(&k->lock))
		err(1, "pthread_mutex_unlock");
}

uint32_t getms(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void busy_wait_ready_set_palette(struct render_state* r, const uint32_t* arr, size_t sze) {
	(void) r;
	while (k_state.render_state == &render_state_default)
		;
	k_state.render_state->set_palette(k_state.render_state, arr, sze);
}

static void wait_ready_swap_frontbuffer(struct render_state* r, uint32_t* arr) {
	(void) r;
	while (k_state.render_state == &render_state_default)
		;
	k_state.render_state->swap_frontbuffer(k_state.render_state, arr);
}

static struct render_state render_state_default = {
	.set_palette = busy_wait_ready_set_palette,
	.swap_frontbuffer = wait_ready_swap_frontbuffer,
};

static int set_syscall_user_dispatch(void* start, void* end) {
	return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start,
		     end, NULL);
}

static int modify_ldt(int func, struct user_desc* ptr, unsigned long count) {
    return syscall(SYS_modify_ldt, func, ptr, count);
}

void sigsys_handler_asm(int, siginfo_t*, void*);

__asm__(".pushsection .text\n"
"sigsys_handler_asm:\n\t"
"push %ebp\n\t"
"mov %esp, %ebp\n\t"

"mov $0, %bx\n\t"
"mov %bx, %fs\n\t"
"mov $" XSTR(SEG_REG(LINUX_GS, GDT, 3)) ", %bx\n\t"
"mov %bx, %gs\n\t"

"push 16(%ebp)\n\t" /* ctx */
"push 12(%ebp)\n\t" /* siginfo */

"call sigsys_handler\n\t"

"mov $" XSTR(SEG_REG(DATA, LDT, 3)) ", %bx\n\t"
"mov %bx, %fs\n\t"
"mov %bx, %gs\n\t"

"leave\n\t"
"ret\n"
".popsection\n"
);

__attribute__ ((used))
static void sigsys_handler(siginfo_t* siginfo, struct ucontext_t* ctx) {
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
	"mov $" XSTR(SEG_REG(DATA, LDT, 3)) ", %%bx\n\t"
	"mov %%bx, %%ss\n\t"
	"mov %%bx, %%ds\n\t"
	"mov %%bx, %%es\n\t"
	"mov %%bx, %%fs\n\t"
	"mov %%bx, %%gs\n\t"

	"mov %[sp], %%esp\n\t"
	"pushl $" XSTR(SEG_REG(CODE, LDT, 3)) "\n\t"
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
		.sa_sigaction = sigsys_handler_asm,
		.sa_flags = SA_SIGINFO|SA_ONSTACK,
	};
	if (sigaction(SIGSYS, &sa, NULL) < 0)
		err(1, "sigaction");
}

static void* k_thread(void* fname) {
	entry_t entry = load_elf(fname);

	k_setup_sighandler();

	set_ldt_entry(SEGMENT_CODE, 2, 1);
	set_ldt_entry(SEGMENT_DATA, 0, 0);

	k_start(entry);

	return NULL;
}

extern const struct k_renderer __start_renderers, __stop_renderers;

const char* list_renderers(void) {
	static char* list = NULL;
	if (list)
		return list;

	size_t sz = 0;
	for (const struct k_renderer* r = &__start_renderers;
	     r < &__stop_renderers; r++)
		sz += strlen(r->name) + 1;

	list = calloc(1, sz);
	if (!list)
		err(1, "calloc");

	for (const struct k_renderer* r = &__start_renderers;
	     r < &__stop_renderers; r++) {
		if (r != &__start_renderers)
			strcat(list, ",");
		strcat(list, r->name);
	}

	return list;
}

static render_thread get_renderer(const char* name) {
	for (const struct k_renderer* r = &__start_renderers;
	     r < &__stop_renderers; r++)
		if (!strcmp(r->name, name))
			return r->render_thread;

	return NULL;
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
	"  -s         \tTrace syscalls\n"
	"  -S addr    \tStart value of stack pointer (default: %#x)\n"
	"  -H addr    \tStart value of heap pointer (default: %#x)\n"
	"  -b addr    \tAddress to load the rom (default: %#x)\n"
	"  -l num     \tSize (limit) of the rom's segment (in pages) (default: %#x)\n"
	"  -T         \tRuns k on the main thread\n"
	"  -r renderer\tSelects the renderer (one of: [%s], default: %s)\n",
	argv0, USER_ESP, USER_ESP, BASE, LIMIT, list_renderers(), DEFAULT_RENDERER);
}

int main(int argc, char** argv) {
	int opt;

	void* (*render_thread)(struct k_state_t*) = NULL;

	while ((opt = getopt(argc, argv, "p:sS:H:b:hl:Tr:")) != -1) {
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
		case 'T':
			config.k_on_main_thread = 1;
			break;
		case 'r':
			render_thread = get_renderer(optarg);
			if (render_thread)
				break;
			warnx("Invalid renderer \"%s\"", optarg);
			help(argv[0]);
			exit(1);
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

	if (!render_thread)
		render_thread = get_renderer(DEFAULT_RENDERER);

	pthread_t tid;
	if (config.k_on_main_thread) {
		if (pthread_create(&tid, NULL, (void* (*)(void*))render_thread, &k_state) < 0)
			err(1, "pthread_create");

		k_thread(argv[optind]);
	} else {
		if (pthread_create(&tid, NULL, k_thread, argv[optind]) < 0)
			err(1, "pthread_create");

		render_thread(&k_state);
	}
}
