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
#include <asm/prctl.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "kine.h"
#include "kstd.h"

#if __x86_64__
#include "i386_gen.h"
#define elf_prstatus elf_prstatus_i386
#define user_regs_struct user_regs_struct_i386
#endif

#define XSTR(S) STR(S)
#define STR(S) #S

#define ALIGN_UP(X, N) (((X) + (N - 1)) & ~(N - 1))

#ifndef typeof
#define typeof(Value) __typeof__(Value)
#endif

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE        (1 << 1)
#endif
#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif

#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)

#define ELF_NOTE_CORE "CORE"

#define USER_ESP 0x90000
#define BASE 65536
#define LIMIT 10240

#define SEGMENT_CODE 1
#define SEGMENT_DATA 2

#define SEGMENT_LDT (1 << 2)
#define SEGMENT_GDT 0
#define SEGMENT_RPL3 (0x3)
#define SEG_REG(Segment, Table, Rpl) \
	((SEGMENT_##Segment << 3) | SEGMENT_##Table | SEGMENT_RPL##Rpl)

typedef void (*entry_t)(void);

static struct render_state render_state_default;

struct k_state_t k_state = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.video_mode = KVIDEO_TEXT,
	.key = -1,
	.keys = RING_INITIALIZER,
	.render_state = &render_state_default,
};

static void init_k_state_t(struct k_state_t *state) {
	for (size_t i = 0; i < ARRSZE(state->fds); i++)
		state->fds[i] = -1;
}

struct config_t config = {
	.root = -1,
	.base = BASE,
	.limit_as_pages = LIMIT,
	.sp = USER_ESP,
	.brk = USER_ESP,
};

static int seterrno(int val) {
	if (val == 0)
		return 0;

	errno = val;
	return -1;
}

void k_lock(struct k_state_t* k) {
	if (seterrno(pthread_mutex_lock(&k->lock)))
		err(1, "pthread_mutex_lock");
}

void k_unlock(struct k_state_t* k) {
	if (seterrno(pthread_mutex_unlock(&k->lock)))
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

#ifdef __x86_64__
static int supports_fsgsbase(void) {
	return !!(getauxval(AT_HWCAP2) & HWCAP2_FSGSBASE);
}
#endif

#ifdef __x86_64__
#define R(R) "%r"#R
#else
#define R(R) "%e"#R
#endif

#define MAKE_SIGNAL_HANDLERS_ASM(Name, Prepare)		\
void sigsys_##Name(int sig, siginfo_t *info, void *ucontext);	\
void coredump_##Name(int sig, siginfo_t *info, void *ucontext);	\
							\
__asm__(						\
".pushsection .text\n"					\
"sigsys_" #Name ":\n\t"					\
"push " R(bp) "\n\t"					\
"mov " R(sp) ", " R(bp) "\n\t"				\
Prepare							\
"call sigsys_handler\n\t"				\
"leave\n\t"						\
"ret\n"							\
".size sigsys_" #Name ", .-sigsys_" #Name "\n"		\
"\n"							\
"coredump_" #Name ":\n\t"				\
"push " R(bp) "\n\t"					\
"mov " R(sp) ", " R(bp) "\n\t"				\
Prepare							\
"call coredump_handler\n\t"				\
"leave\n\t"						\
"ret\n"							\
".size coredump_" #Name ", .-coredump_" #Name "\n"	\
".popsection\n"						\
)

#ifdef __x86_64__

MAKE_SIGNAL_HANDLERS_ASM(handler_asm,
"push %rdi\n\t"
"push %rsi\n\t"
"push %rdx\n\t"

"mov $" XSTR(SYS_arch_prctl) ", %rax\n\t"
"mov $" XSTR(ARCH_SET_FS) ", %rdi\n\t"
"mov k_thread_fs(%rip), %rsi\n\t"
"syscall\n\t"

"pop %rsi\n\t" /* ucontext */
"pop %rdi\n\t" /* siginfo */
"add $8, %rsp\n\t");

MAKE_SIGNAL_HANDLERS_ASM(handler_asm_fsgsbase,
"mov k_thread_fs(%rip), %rdi\n\t"
"wrfsbase %rdi\n\t"
"mov %rsi, %rdi\n\t"
"mov %rdx, %rsi\n\t");

#define GET_SIGACTION(Kind) (supports_fsgsbase() ? Kind##_handler_asm_fsgsbase : Kind##_handler_asm)

#else

MAKE_SIGNAL_HANDLERS_ASM(handler_asm,
"mov $0, %bx\n\t"
"mov %bx, %fs\n\t"
"mov $" XSTR(SEG_REG(LINUX_GS, GDT, 3)) ", %bx\n\t"
"mov %bx, %gs\n\t"

"push 16(%ebp)\n\t" /* ctx */
"push 12(%ebp)\n\t" /* siginfo */);

#define GET_SIGACTION(Kind) Kind##_handler_asm

#endif

__attribute__ ((used))
static void sigsys_handler(siginfo_t* siginfo, struct ucontext_t* ctx) {
	if (siginfo->si_code != SYS_USER_DISPATCH)
		return;

#ifdef __x86_64__
#define REG(X) REG_R##X
#else
#define REG(X) REG_E##X
#endif
	uint32_t args[] = {
		ctx->uc_mcontext.gregs[REG(BX)],
		ctx->uc_mcontext.gregs[REG(CX)],
		ctx->uc_mcontext.gregs[REG(DX)],
		ctx->uc_mcontext.gregs[REG(SI)],
	};

	ctx->uc_mcontext.gregs[REG(AX)] =
		syscall_dispatch(siginfo->si_syscall, args);
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

	void* map = mmap((void*)config.base, config.limit, PROT_RWX,
			 MAP_PRIVATE|MAP_FIXED_NOREPLACE|MAP_ANON, -1, 0);
	if (map == MAP_FAILED)
		err(1, "mmap");

	for (size_t i = 0; i < ehdr.e_phnum; i++) {
		Elf32_Phdr phdr;
		if (pread(fd, &phdr, sizeof(phdr),
			  ehdr.e_phoff + i * sizeof(phdr)) != sizeof(phdr))
			err(1, "pread(phdr)");

		if (phdr.p_type != PT_LOAD)
			continue;

		if (pread(fd, map + phdr.p_vaddr, phdr.p_filesz,
			  phdr.p_offset) != (ssize_t)phdr.p_filesz)
			err(1, "pread(map)");
	}

	k_state.brk = config.brk;

	if (set_syscall_user_dispatch((char*)config.base + config.limit,
				      (void*)~(0x1ULL<<63)) < 0)
		err(1, "set_syscall_user_dispatch");

	close(fd);

	return (entry_t)(uintptr_t)ehdr.e_entry;
}

static void set_ldt_entry(unsigned nr, unsigned content,
			  unsigned read_exec_only) {
	struct user_desc ldt_entry = {
		.entry_number = nr,
		.base_addr = config.base,
		.limit = config.limit_as_pages,
		.limit_in_pages = 1,
		.seg_32bit = 1,
		.contents = content,
		.read_exec_only = read_exec_only,
	};
	if (modify_ldt(0x11, &ldt_entry, sizeof(ldt_entry)) < 0)
		err(1, "modify_ldt");
}

__attribute((noreturn))
static void k_start(entry_t entry) {
	k_state.starttime = getms();

	__asm__ volatile(
	"mov $" XSTR(SEG_REG(DATA, LDT, 3)) ", %%ebx\n\t"
	"mov %%bx, %%ss\n\t"
	"mov %%bx, %%ds\n\t"
	"mov %%bx, %%es\n\t"
	"mov %%bx, %%fs\n\t"
	"mov %%bx, %%gs\n\t"

	"mov %[sp], %%esp\n\t"
	"push $" XSTR(SEG_REG(CODE, LDT, 3)) "\n\t"
	"push %[entry]\n\t"

	"xor %%eax, %%eax\n\t"
	"xor %%ebx, %%ebx\n\t"
	"xor %%ecx, %%ecx\n\t"
	"xor %%edx, %%edx\n\t"
	"xor %%esi, %%esi\n\t"
	"xor %%edi, %%edi\n\t"
	"xor %%ebp, %%ebp\n\t"
#ifdef __x86_64__
	"lretq\n\t"
#else
	"lret\n\t"
#endif
	: /* outputs */
	: [entry]"r"(entry), [sp]"r"((uint32_t)config.sp)
	: "memory", "ebx");

	__builtin_unreachable();
}

static void k_setup_sighandler(void) {
	stack_t ss = {
		.ss_sp = malloc(SIGSTKSZ),
		.ss_size = SIGSTKSZ,
		.ss_flags = 0
	};
	if (!ss.ss_sp)
		err(1, "malloc");

	if (sigaltstack(&ss, NULL) < 0)
		err(1, "sigaltstack");

	struct sigaction sa = {
		.sa_sigaction = GET_SIGACTION(sigsys),
		.sa_flags = SA_SIGINFO|SA_ONSTACK,
	};
	if (sigaction(SIGSYS, &sa, NULL) < 0)
		err(1, "sigaction");
}

#if __x86_64__
static unsigned long k_thread_fs;

static int arch_prctl(int op, unsigned long* addr) {
	return syscall(SYS_arch_prctl, op, addr);
}
#endif

static void* k_thread(void* fname) {
	entry_t entry = load_elf(fname);

	k_setup_sighandler();

#if __x86_64__
	if (arch_prctl(ARCH_GET_FS, &k_thread_fs) < 0)
		err(1, "arch_prctl(ARCH_GET_FS)");
#endif

	set_ldt_entry(SEGMENT_CODE, 2, 1);
	set_ldt_entry(SEGMENT_DATA, 0, 0);

	k_start(entry);

	return NULL;
}

static const char* coredump_name(void) {
	static char out[128];

	snprintf(out, sizeof(out), "kine.%d.dump", getpid());

	return out;
}

static uint16_t get_cs(const ucontext_t* ctx) {
#if __x86_64__
	return ctx->uc_mcontext.gregs[REG_CSGSFS] & 0xffff;
#else
	return ctx->uc_mcontext.gregs[REG_CS];
#endif
}

static void *memrchr_inv(const void *s, int c, size_t n) {
	const char *ptr = s;
	while (n && ptr[n - 1] == c)
		--n;

	return (void *)&ptr[n];
}

__attribute__ ((used))
static void coredump_handler(siginfo_t *si, void *ucontext) {
	ucontext_t *ctx = ucontext;

	if (get_cs(ctx) != SEG_REG(CODE, LDT, 3)) {
		struct sigaction sa = {
			.sa_handler = SIG_DFL,
		};
		if (sigaction(si->si_signo, &sa, NULL) < 0)
			err(1, "sigaction(SIG_DFL)");

		return;
	}

	const char* last_set_byte = memrchr_inv((void*)config.base, 0, config.limit);
	size_t filesz = last_set_byte - (const char*)config.base;

	int fd = open(coredump_name(), O_CREAT|O_WRONLY, 0644);
	if (fd < 0)
		err(1, "open");

	enum {
		PHDR_NOTE,
		PHDR_LOAD,
		PHDR_END,
	};

	struct {
		Elf32_Ehdr ehdr;
		Elf32_Phdr phdrs[PHDR_END];
		struct {
			struct {
				Elf32_Nhdr hdr;
				char name[ALIGN_UP(sizeof(ELF_NOTE_CORE), 4)];
				struct elf_prstatus desc;
			} prstatus;
		} notes __attribute__((aligned(4)));
	} coredump = {
		.ehdr = {
			.e_ident = {
				[EI_MAG0] = ELFMAG0,
				[EI_MAG1] = ELFMAG1,
				[EI_MAG2] = ELFMAG2,
				[EI_MAG3] = ELFMAG3,
				[EI_CLASS] = ELFCLASS32,
				[EI_DATA] = ELFDATA2LSB,
				[EI_VERSION] = EV_CURRENT,
				[EI_OSABI] = ELFOSABI_SYSV,
			},
			.e_type = ET_CORE,
			.e_machine = EM_386,
			.e_version = EV_CURRENT,
			.e_phoff = offsetof(typeof(coredump), phdrs),
			.e_ehsize = sizeof(coredump.ehdr),
			.e_phentsize = sizeof(coredump.phdrs[0]),
			.e_phnum = ARRSZE(coredump.phdrs),
		},
		.phdrs = {
			[PHDR_NOTE] = {
				.p_type = PT_NOTE,
				.p_offset = offsetof(typeof(coredump), notes),
				.p_filesz = sizeof(coredump.notes),
				.p_align = 4,
			},
			[PHDR_LOAD] = {
				.p_type = PT_LOAD,
				.p_offset = ALIGN_UP(sizeof(coredump), PAGE_SIZE),
				.p_filesz = filesz,
				.p_memsz = config.limit,
				.p_flags = PF_R|PF_W|PF_X,
				.p_align = PAGE_SIZE,
			},
		},
		.notes = {
			.prstatus = {
				.hdr = {
					.n_namesz = sizeof(coredump.notes.prstatus.name),
					.n_descsz = ALIGN_UP(sizeof(coredump.notes.prstatus.desc), 4),
					.n_type = NT_PRSTATUS,
				},
				.name = ELF_NOTE_CORE,
			},
		},
	};

	struct user_regs_struct regs = {
		.ebx = ctx->uc_mcontext.gregs[REG(BX)],
		.ecx = ctx->uc_mcontext.gregs[REG(CX)],
		.edx = ctx->uc_mcontext.gregs[REG(DX)],
		.esi = ctx->uc_mcontext.gregs[REG(SI)],
		.edi = ctx->uc_mcontext.gregs[REG(DI)],
		.ebp = ctx->uc_mcontext.gregs[REG(BP)],
		.eax = ctx->uc_mcontext.gregs[REG(AX)],
		.eip = ctx->uc_mcontext.gregs[REG(IP)],
		.esp = ctx->uc_mcontext.gregs[REG(SP)],
		.eflags = ctx->uc_mcontext.gregs[REG_EFL],
		.orig_eax = ctx->uc_mcontext.gregs[REG(AX)],
	};
	memcpy(&coredump.notes.prstatus.desc.pr_reg, &regs, sizeof(regs));

	if (write(fd, &coredump, sizeof(coredump)) != sizeof(coredump))
		err(1, "write");

	if (lseek(fd, coredump.phdrs[PHDR_LOAD].p_offset, SEEK_SET) < 0)
		err(1, "lseek");

	if (write(fd, (void*)config.base, filesz) < 0)
		err(1, "write");

	close(fd);

	const char core_dumped_log[] = "Core dumped.\n";
	write(2, core_dumped_log, sizeof(core_dumped_log) - 1);
	_Exit(1);
}

static void setup_sighandlers(void) {
	const int signals[] = {
		SIGBUS,
		SIGFPE,
		SIGILL,
		SIGSEGV,
		SIGTRAP,
	};

	struct sigaction sa = {
		.sa_sigaction = GET_SIGACTION(sigsys),
		.sa_flags = SA_SIGINFO|SA_ONSTACK,
	};
	for (size_t i = 0; i < ARRSZE(signals); i++)
		if (sigaction(signals[i], &sa, NULL) < 0)
			err(1, "sigaction");
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

static renderer_t get_renderer(const char* name) {
	for (const struct k_renderer* r = &__start_renderers;
	     r < &__stop_renderers; r++)
		if (!strcmp(r->name, name))
			return r->render_thread;

	return NULL;
}

static uint32_t parse_u32_or_die(const char* str) {
	char *endptr = NULL;
	errno = 0;
	long long r = strtoll(str, &endptr, 0);
	if (!errno && (r < 0 || r > INT32_MAX))
		errno = ERANGE;

	if (errno)
		err(1, "strtoll(%s)", str);

	if (*endptr)
		errx(1, "strtoul(%s): Trailing \"%s\"", str, endptr);

	return r;
}

static void help(const char* argv0) {
	fprintf(stderr,
	"Usage: %s [arguments] /path/to/rom\n"
	"\n"
	"Arguments:\n"
	"  -h         \tShow this message\n"
	"  -s         \tTrace syscalls\n"
	"  -S addr    \tStart value of stack pointer (default: %#x)\n"
	"  -H addr    \tStart value of heap pointer (default: %#x)\n"
	"  -b addr    \tAddress to load the rom (default: %#x)\n"
	"  -l num     \tSize (limit) of the rom's segment (in pages) (default: %#x)\n"
	"  -T         \tRuns k on the main thread\n"
	"  -C         \tSave rom coredump\n"
	"  -r renderer\tSelects the renderer (one of: [%s], default: %s)\n",
	argv0, USER_ESP, USER_ESP, BASE, LIMIT, list_renderers(),
	__start_renderers.name);
}

static void* render_thread(void *data) {
	renderer_t renderer = data;

	sigset_t sigset;
	if (sigemptyset(&sigset) < 0)
		err(1, "sigemptyset");
	if (sigaddset(&sigset, SIGSYS) < 0)
		err(1, "sigaddset");
	if (seterrno(pthread_sigmask(SIG_BLOCK, &sigset, NULL)))
		err(1, "pthread_sigmask");

	return renderer(&k_state);
}

int main(int argc, char** argv) {
	int opt;

	renderer_t renderer = __start_renderers.render_thread;

	while ((opt = getopt(argc, argv, "p:sS:H:b:hl:Tr:C")) != -1) {
		switch (opt) {
		case 'p':
			if (config.root != -1)
				errx(1, "-p can only be specified once");
			if ((config.root = open(optarg, O_RDONLY|O_DIRECTORY|O_PATH)) < 0)
				err(1, "open(%s)", optarg);
			break;
		case 'S': /* stack */
			config.sp = parse_u32_or_die(optarg);
			break;
		case 'H': /* heap */
			config.brk = parse_u32_or_die(optarg);
			break;
		case 'b': /* base address */
			config.base = parse_u32_or_die(optarg);
			break;
		case 'l': /* limit */
			config.limit_as_pages = parse_u32_or_die(optarg);
			break;
		case 's':
			config.strace = 1;
			break;
		case 'T':
			config.k_on_main_thread = 1;
			break;
		case 'r':
			renderer = get_renderer(optarg);
			if (renderer)
				break;
			warnx("Invalid renderer \"%s\"", optarg);
			help(argv[0]);
			exit(1);
		case 'C':
			setup_sighandlers();
			break;
		default:
			fprintf(stderr, "\n");
			/* fallthrough */
		case 'h':
			help(argv[0]);
			exit(opt != 'h');
		}
	}
	if (config.root == -1)
		errx(1, "Argument -p must be specfied");

	if (!argv[optind])
		errx(1, "missing rom file");

	init_k_state_t(&k_state);

	pthread_t tid;
	if (config.k_on_main_thread) {
		if (seterrno(pthread_create(&tid, NULL, render_thread, renderer)) < 0)
			err(1, "pthread_create");

		k_thread(argv[optind]);
	} else {
		if (seterrno(pthread_create(&tid, NULL, k_thread, argv[optind])) < 0)
			err(1, "pthread_create");

		render_thread(renderer);
	}
}
