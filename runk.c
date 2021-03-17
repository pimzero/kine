#include <asm/ldt.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include "runk.h"
#include <stddef.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif

#define ARRSZE(X) (sizeof(X) / sizeof(*(X)))
#define PAGE_MASK (~(unsigned)(0x1000 - 1))
#define PROT_RW (PROT_READ|PROT_WRITE|PROT_EXEC)

typedef void (*entry_t)(void);
int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args);

struct k_state_t k_state = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.video_mode = VIDEO_TEXT,
	.key = -1,
};

struct config_t config = {
	.path = "/home/pim/Workspace/ref-k/iso",
	.strace = 1,
	.segment = 1,
	//.path = ".",
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

static entry_t load_elf(const char* fname) {
	int fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "open");

	struct stat st;
	if (fstat(fd, &st) < 0)
		err(1, "fstat");

	Elf32_Ehdr* ehdr = mmap(0, st.st_size, PROT_RW, MAP_PRIVATE, fd, 0);
	if (ehdr == MAP_FAILED)
		err(1, "mmap");

	Elf32_Ehdr sig = {
		.e_ident = {
			ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS32,
			ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV
		},
		.e_type = ET_EXEC,
		.e_machine = EM_386,
		.e_version = EV_CURRENT,
	};
	if (memcmp(ehdr, &sig, offsetof(Elf32_Ehdr, e_entry)))
		errx(1, "invalid file \"%s\"", fname);

	void* t = mmap((void*)BASE, LIMIT * 4096, PROT_RW,
		       MAP_PRIVATE|MAP_FIXED|MAP_ANON, -1, 0);
	if (!t)
		err(1, "mmap");

	Elf32_Phdr* phdrs = ((void*)ehdr) + ehdr->e_phoff;
	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		if (lseek(fd, phdrs[i].p_offset, SEEK_SET) < 0)
			err(1, "lseek");

		if (read(fd, (config.segment ? t : 0) + phdrs[i].p_vaddr, phdrs[i].p_filesz) < 0)
			err(1, "read");

		lock();

		if (phdrs[i].p_vaddr + phdrs[i].p_memsz > k_state.brk)
			k_state.brk = phdrs[i].p_vaddr + phdrs[i].p_memsz + 512;

		unlock();

		if (phdrs[i].p_flags & PF_X)
			if (set_syscall_user_dispatch((void*)k_state.brk, (void*)-1) < 0)
				err(1, "set_syscall_user_dispatch");
	}

	void* entry = (void*)ehdr->e_entry;

	if (munmap(ehdr, st.st_size) < 0)
		err(1, "munmap");

	if (config.segment) {
		k_state.brk = 0x20000;
	}

	return entry;
}

static void* k_thread(void* fname) {
	entry_t entry = load_elf(fname);

	stack_t ss;
	ss.ss_sp = malloc(SIGSTKSZ * 16);
	if (!ss.ss_sp)
		err(1, "malloc");
	ss.ss_size = SIGSTKSZ * 16;
	ss.ss_flags = 0;

	if (sigaltstack(&ss, NULL) < 0)
		err(1, "sigaltstack");

	struct sigaction sa = {
		.sa_sigaction = sigsys_handler,
		.sa_flags = SA_SIGINFO|SA_ONSTACK,
	};

	sigaction(SIGSYS, &sa, NULL);

	k_state.starttime = getms();

	if (!config.segment) {
		entry();
	} else {
		struct user_desc ldt_entry = {
			.entry_number = 1,
			.base_addr = BASE,
			.limit = LIMIT,
			.limit_in_pages = 1,
			.seg_32bit = 1,
			.contents = 2,
			.read_exec_only = 1,

		};
		if (modify_ldt(0x11, &ldt_entry, sizeof(ldt_entry)) < 0)
			err(1, "modify_ldt");

		ldt_entry.entry_number = 2;
		ldt_entry.contents = 0;
		ldt_entry.base_addr = BASE;
		ldt_entry.limit = LIMIT;
		ldt_entry.limit_in_pages = 1;
		ldt_entry.seg_32bit = 1;
		ldt_entry.read_exec_only = 0;

		if (modify_ldt(0x11, &ldt_entry, sizeof(ldt_entry)) < 0)
			err(1, "modify_ldt");

		__asm__ volatile(
		"pushl $15\n\t"
		"pushl %[entry]\n\t"

		"mov $23, %%bx\n\t"
		"mov %%bx, %%ss\n\t"
		"mov %%bx, %%ds\n\t"
		"mov %%bx, %%es\n\t"
		"mov %%bx, %%fs\n\t"

		"mov $" XSTR(USER_ESP) ", %%ebx\n\t"
		"mov %%ebx, %%esp\n\t"
		"pushl $15\n\t"
		"pushl %[entry]\n\t"

		"xor %%eax, %%eax\n\t"
		"xor %%ebx, %%ebx\n\t"
		"xor %%ecx, %%ecx\n\t"
		"xor %%edx, %%edx\n\t"
		"xor %%esi, %%esi\n\t"
		"xor %%edi, %%edi\n\t"
		"xor %%ebp, %%ebp\n\t"
		"lret\n\t": : [entry]"r"(entry));
	}

	return NULL;
}

static void init_k_state(void) {
	k_state.sdl_palette = SDL_AllocPalette(256);
	if (!k_state.sdl_palette)
		errx(1, "SDL_AllocPalette: %s", SDL_GetError());

	for (unsigned i = 0; i < 256; i++) {
		k_state.palette[i].r = i & 0xe;
		k_state.palette[i].g = (i & 0x1c) << 3;
		k_state.palette[i].b = (i & 0x3) << 6;
	}
}

int main(int argc, char** argv) {
	if (argc < 2)
		errx(1, "Not enough arguments");

	init_k_state();

	SDL_Renderer* renderer = init_window();

	pthread_t k_tid;
	if (pthread_create(&k_tid, NULL, k_thread, argv[1]) < 0)
		err(1, "pthread_create");

	while (!k_state.quit) {
		update_inputs();
		update_renderer(renderer);
	}

	pthread_cancel(k_tid);
	SDL_Quit();
}
