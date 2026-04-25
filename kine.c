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
#include <errno.h>
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

#define ALIGN_UP(X, N) (((X) + (N - 1)) & ~(N - 1))

#ifndef typeof
#define typeof(Value) __typeof__(Value)
#endif

#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)

#define ELF_NOTE_CORE "CORE"

#define USER_ESP 0x90000
#define BASE 65536
#define LIMIT 10240

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

static void busy_wait_render_state_initialized(void) {
	while (__atomic_load_n(&k_state.render_state, __ATOMIC_RELAXED) == &render_state_default)
		;
}

static void busy_wait_ready_set_palette(struct render_state* r,
					const palette_t* palette, size_t sze) {
	(void) r;
	busy_wait_render_state_initialized();
	k_state.render_state->set_palette(k_state.render_state, palette, sze);
}

static void wait_ready_swap_frontbuffer(struct render_state* r,
					const framebuffer_t* fb) {
	(void) r;
	busy_wait_render_state_initialized();
	k_state.render_state->swap_frontbuffer(k_state.render_state, fb);
}

static struct render_state render_state_default = {
	.set_palette = busy_wait_ready_set_palette,
	.swap_frontbuffer = wait_ready_swap_frontbuffer,
};

void render_state_set(struct k_state_t* k, struct render_state* render_state) {
	render_state = render_state ?: &render_state_default;
	__atomic_store_n(&k->render_state, render_state, __ATOMIC_RELAXED);
}

static int modify_ldt(int func, struct user_desc* ptr, unsigned long count) {
	return syscall(SYS_modify_ldt, func, ptr, count);
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
			 MAP_SHARED|MAP_FIXED_NOREPLACE|MAP_ANON, -1, 0);
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

void k_prepare(void) {
	set_ldt_entry(SEGMENT_CODE, 2, 1);
	set_ldt_entry(SEGMENT_DATA, 0, 0);

	k_state.starttime = getms();
}

__attribute((noreturn))
void k_start(entry_t entry) {
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

static void *memrchr_inv(const void *s, int c, size_t n) {
	const char *ptr = s;
	while (n && ptr[n - 1] == c)
		--n;

	return (void *)&ptr[n];
}

static const char* coredump_name(void) {
	static char out[128];

	snprintf(out, sizeof(out), "kine.%d.dump", getpid());

	return out;
}

void coredump_write(const struct user_regs_struct_i386 *regs) {
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
				struct elf_prstatus_i386 desc;
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

	memcpy(&coredump.notes.prstatus.desc.pr_reg, regs, sizeof(*regs));

	if (write(fd, &coredump, sizeof(coredump)) != sizeof(coredump))
		err(1, "write");

	if (lseek(fd, coredump.phdrs[PHDR_LOAD].p_offset, SEEK_SET) < 0)
		err(1, "lseek");

	if (write(fd, (void*)config.base, filesz) < 0)
		err(1, "write");

	close(fd);
}

static const char* list_modules(const struct module_class* class) {
	const char join[] = ", ";

	size_t n = 0;
	for (size_t i = 0; i < class->size(); i++)
		n += strlen(class->names[i]) + strlen(join);

	char *list, *end = list = malloc(n * sizeof(*list));
	if (!list)
		err(1, "calloc");

	for (size_t i = 0; i < class->size(); i++) {
		if (i)
			end = stpcpy(end, join);
		end = stpcpy(end, class->names[i]);
	}

	return list;
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

typedef void* k_thread_t(void* entry);

void* k_thread_syscall_user_dispatch(void* entry);
void* k_thread_ptrace(void* entry);

static void* k_thread_auto(void* entry) {
	extern int k_thread_syscall_user_dispatch_ex(entry_t entry, int probe);

	if (k_thread_syscall_user_dispatch_ex(entry, 1) < 0)
		return k_thread_ptrace(entry);
	return NULL;
}

static struct {
	const char* name;
	k_thread_t* fn;
} modes[] = {
#define MODE(X) { .name = #X, .fn = k_thread_##X, }
	MODE(auto),
	MODE(syscall_user_dispatch),
	MODE(ptrace),
#undef MODE
};

static k_thread_t* get_mode(const char* name) {
	for (size_t i = 0; i < ARRSZE(modes); i++)
		if (!strcmp(name, modes[i].name))
			return modes[i].fn;

	errx(1, "Unsupported mode \"%s\"", name);
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
	"  -M mode    \tSelect emulation mode (one of [auto, syscall_user_dispatch,\n"
	"             \tptrace], default: auto)\n"
	"  -C         \tSave rom coredump\n"
	"  -r renderer\tSelects the renderer (one of: [%s], default: %s)\n",
	argv0, USER_ESP, USER_ESP, BASE, LIMIT, list_modules(&module_renderer),
	module_renderer.names[0]);
}

static void* render_thread(void *data) {
	renderer_t renderer = data;

	sigset_t sigset;
	if (sigfillset(&sigset) < 0)
		err(1, "sigfillset");

	if (seterrno(pthread_sigmask(SIG_BLOCK, &sigset, NULL)))
		err(1, "pthread_sigmask");

	return renderer(&k_state);
}

int main(int argc, char** argv) {
	int opt;

	renderer_t renderer = *module_renderer_get(0);
	k_thread_t* k_thread_fn = modes[0].fn;

	while ((opt = getopt(argc, argv, "p:sS:H:b:hl:Tr:CM:")) != -1) {
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
		case 'r': {
			const renderer_t* found = module_renderer_find(optarg);
			if (!found) {
				warnx("Invalid renderer \"%s\"", optarg);
				help(argv[0]);
				exit(1);
			}
			renderer = *found;
			break;
		}
		case 'C':
			config.coredump = 1;
			break;
		case 'M':
			k_thread_fn = get_mode(optarg);
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
		warnx("Argument -p should be specfied");

	if (!argv[optind])
		errx(1, "missing rom file");

	init_k_state_t(&k_state);
	entry_t entry = load_elf(argv[optind]);

	if (config.k_on_main_thread) {
		if (seterrno(pthread_create(&(pthread_t){}, NULL, render_thread,
					    renderer)) < 0)
			err(1, "pthread_create");

		k_thread_fn(entry);
	} else {
		if (seterrno(pthread_create(&(pthread_t){}, NULL, k_thread_fn,
					    entry)) < 0)
			err(1, "pthread_create");

		render_thread(renderer);
	}
}
