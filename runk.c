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

void* get_user(uint32_t ptr) {
#if 1
	return (void*)(ptr + (config.segment ? 0 : 0));
#else
	return (void*)(ptr + (config.segment ? 65536 : 0));
#endif
}


int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args);

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

	void* file = mmap(0, st.st_size, PROT_RW, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED)
		err(1, "mmap");

	Elf32_Ehdr* ehdr = file;

	// TODO check ehdr

	// FIX ADDRSPACE
	void* t = mmap((void*)65536, 0x0200000, PROT_RW,
		       MAP_PRIVATE|MAP_FIXED|MAP_ANON, -1, 0);
	if (!t)
		err(1, "mmap0");

	memset(t, 0, 0x0200000);

	Elf32_Phdr* phdrs = file + ehdr->e_phoff;
	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		if (lseek(fd, phdrs[i].p_offset, SEEK_SET) < 0)
			err(1, "lseek");

		if (read(fd, (config.segment ? t : 0) + phdrs[i].p_vaddr, phdrs[i].p_filesz) < 0)
			err(1, "read");

		lock();

		if (phdrs[i].p_vaddr + phdrs[i].p_memsz > k_state.brk)
			k_state.brk = phdrs[i].p_vaddr + phdrs[i].p_memsz;

		unlock();

		//printf("%p-%p\n", map, map + phdrs[i].p_filesz);

#if 0
		uint32_t start_zeros = align_up(phdrs[i].p_vaddr +
						phdrs[i].p_filesz);

		void* map = mmap((void*)(phdrs[i].p_vaddr & PAGE_MASK),
				phdrs[i].p_filesz, flags,
				MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
		if (map == MAP_FAILED)
			err(1, "mmap");
#endif

		if (phdrs[i].p_flags & PF_X)
			if (set_syscall_user_dispatch((void*)k_state.brk, (void*)-1) < 0)
				err(1, "set_syscall_user_dispatch");
	}

	return (void*)ehdr->e_entry;
}

static SDL_Renderer* init_window(void) {
	SDL_Init(SDL_INIT_VIDEO);

	SDL_Window* window = SDL_CreateWindow("Run K", SDL_WINDOWPOS_UNDEFINED,
					      SDL_WINDOWPOS_UNDEFINED, 640, 400,
					      SDL_WINDOW_OPENGL);
	if (!window)
		errx(1, "SDL_CreateWindow: %s", SDL_GetError());

	SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, 0);
	if (!renderer)
		errx(1, "SDL_CreateRenderer: %s", SDL_GetError());

	return renderer;
}

static int32_t scancode(SDL_Scancode orig) {
	switch (orig) {
	case SDL_SCANCODE_DOWN:
		return 0x50;
	case SDL_SCANCODE_UP:
		return 0x48;
	default:
		return -1;
	}
}

static void update_inputs() {
	SDL_Event event;

	lock();
	while (SDL_PollEvent(&event)) {
		switch (event.type) {
		case SDL_QUIT:
			k_state.quit = 1;
			break;

		case SDL_KEYDOWN:
			k_state.key = scancode(event.key.keysym.scancode);
			break;
		default:
			break;
		}
	}
	unlock();
}

static void update_renderer(SDL_Renderer* renderer) {
	lock();

	SDL_Surface* surface =
		SDL_CreateRGBSurfaceFrom(&k_state.framebuffer, 320, 200, 8, 320,
					 0, 0, 0, 0);

	if (!surface)
		errx(1, "SDL_CreateRGBSurfaceFrom: %s", SDL_GetError());

	if (SDL_SetPaletteColors(k_state.sdl_palette, k_state.palette, 0, 256))
		errx(1, "SDL_SetPaletteColors: %s", SDL_GetError());

	unlock();

	if (SDL_SetSurfacePalette(surface, k_state.sdl_palette))
		errx(1, "SDL_SetSurfacePalette: %s", SDL_GetError());

	SDL_Texture* texture =
		SDL_CreateTextureFromSurface(renderer, surface);
	if (!texture)
		errx(1, "SDL_CreateTextureFromSurface: %s", SDL_GetError());
	SDL_FreeSurface(surface);

	SDL_SetRenderDrawColor(renderer, 0, 0, 0, 0);
	SDL_RenderClear(renderer);
	SDL_RenderCopy(renderer, texture, 0, 0);
	SDL_RenderPresent(renderer);

	SDL_DestroyTexture(texture);
}

static int modify_ldt(int func, struct user_desc* ptr, unsigned long count) {
    return syscall(SYS_modify_ldt, func, ptr, count);
}

#if 0
static void test() {
	__asm__("\n"
		"mov $65540, %ebx\n\t"
		"pushw %es:(%ebx)\n\t"
		"mov (%ebx), %eax\n\t"
		"L1:\n\t"
		"jmp L1\n\t");
	exit(1);
}
#endif

static void* k_thread(void* fname) {
	entry_t entry = load_elf(fname);

	struct sigaction sa = {
		.sa_sigaction = sigsys_handler,
		.sa_flags = SA_SIGINFO,
	};

	sigaction(SIGSYS, &sa, NULL);

	k_state.starttime = getms();

	if (!config.segment) {
		entry();
	} else {
		struct user_desc ldt_entry = {
			.entry_number = 1,
			.base_addr = 65536,
			.limit = 0xfffff,
			.seg_32bit = 1,
			.contents = 2,
			.read_exec_only = 1,

		};
		if (modify_ldt(0x11, &ldt_entry, sizeof(ldt_entry)) < 0)
			err(1, "modify_ldt");

		ldt_entry.entry_number = 2;
		ldt_entry.contents = 0;
		ldt_entry.base_addr = 65536;
		ldt_entry.limit = 0xfffff;
		ldt_entry.seg_32bit = 1;
		ldt_entry.read_exec_only = 0;
		// ldt_entry.seg_not_present = 1;

		if (modify_ldt(0x11, &ldt_entry, sizeof(ldt_entry)) < 0)
			err(1, "modify_ldt");

	__asm__ volatile(
		"pushl $15\n\t"
		//"pushl $35\n\t"
		"pushl %[entry]\n\t"

		"mov $23, %%ax\n\t"
		"mov %%ax, %%ds\n\t"

#if 0
		"mov $0x2000, %%ebx\n\t"
		"mov (%%esp), %%ecx\n\t"
		"mov %%ecx, (%%ebx)\n\t"
		"mov -4(%%esp), %%ecx\n\t"
		"mov %%ecx, -4(%%ebx)\n\t"
		"mov -8(%%esp), %%ecx\n\t"
		"mov %%ecx, -8(%%ebx)\n\t"
		"mov 4(%%esp), %%ecx\n\t"
		"mov %%ecx, 4(%%ebx)\n\t"
		"mov 8(%%esp), %%ecx\n\t"
		"mov %%ecx, 8(%%ebx)\n\t"
		//"mov $23, %%ax\n\t"
		//"mov %%ax, %%ss\n\t"
		//"mov $0x2000, %%esp\n\t"
#endif
		//"lret\n\t": : [entry]"r"(test));
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
