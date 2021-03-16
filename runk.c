#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "SDL.h"

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif

#define ARRSZE(X) (sizeof(X) / sizeof(*(X)))
#define PAGE_MASK (~(unsigned)(0x1000 - 1))
#define PROT_RWX (PROT_READ|PROT_WRITE|PROT_EXEC)
#define PROT_RW (PROT_READ|PROT_WRITE)
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

#define SYSCALL_WRITE			1
#define SYSCALL_SBRK			2
#define SYSCALL_GETKEY			3
#define SYSCALL_GETTICK			4
#define SYSCALL_OPEN			5
#define SYSCALL_READ			6
#define SYSCALL_SEEK			7
#define SYSCALL_CLOSE			8
#define SYSCALL_SETVIDEO		9
#define SYSCALL_SWAP_FRONTBUFFER	10
#define SYSCALL_PLAYSOUND		11
#define SYSCALL_SETPALETTE		12
#define SYSCALL_GETMOUSE		13
#define SYSCALL_GETKEYMODE		14
#define NR_SYSCALL			(SYSCALL_GETKEYMODE + 1)

#define KENOMEM				1 /* Not enough space */
#define KENOENT				2 /* No such file or directory */
#define KEIO				3 /* I/O error */
#define KEINVAL				4 /* Invalid argument */
#define KENOSYS				5 /* Invalid system call number */
#define KEBADF				6 /* fd is not an open file descriptor */
#define KEAGAIN				7 /* Temporary unavailable */

#define VIDEO_GRAPHIC	0
#define VIDEO_TEXT	1

typedef int32_t (*syscall_t)();
typedef void (*entry_t)(void);

static struct {
	pthread_mutex_t lock;
	int video_mode;
	int quit;
	uint32_t framebuffer[320 * 200];
	SDL_Color palette[256];
	SDL_Palette* sdl_palette;
	int32_t key;

	/* unlocked */
	uint32_t brk;
	uint32_t starttime;
} k_state = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.video_mode = VIDEO_TEXT,
	.key = -1,
};

static struct {
	char* path;
	int strace;
} config = {
	.path = "/home/pim/Workspace/ref-k/iso",
	//.path = ".",
};

static void lock() {
	if (pthread_mutex_lock(&k_state.lock))
		err(1, "pthread_mutex_lock");
}

static void unlock() {
	if (pthread_mutex_unlock(&k_state.lock))
		err(1, "pthread_mutex_unlock");
}

static uint32_t align_up(uint32_t ptr) {
	return (ptr + 0xfff) & ~(uint32_t)0xfff;
}

static uint32_t getms(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int elf_2_mmap_prot(int f) {
	int out = 0;

	if (f & PF_X)
		out |= PROT_EXEC;
	if (f & PF_R)
		out |= PROT_READ;
	if (f & PF_W)
		out |= PROT_WRITE;

	return out;
}

static int set_syscall_user_dispatch(void* start, void* end) {
	return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start,
		     end, NULL);
}

static int32_t sys_write(void* buf, size_t len) {
	return write(1, buf, len);
}

static int32_t sys_setvideo(int type) {
	if (config.strace)
		fprintf(stderr, "setvideo(%d)\n", type);

	switch (type) {
	case VIDEO_TEXT:
	case VIDEO_GRAPHIC:
		lock();

		k_state.video_mode = type;

		unlock();
		return 0;
	default:
		return -KEINVAL;
	}
}

static int32_t sys_open(const char* pathname, int flags) {
	(void) flags;

	char path[2048];

	snprintf(path, sizeof(path) - 1, "%s%s", config.path, pathname);

	int ret = open(path, O_RDONLY);
	if (ret < 0)
		ret = -KENOENT;

	if (config.strace)
		fprintf(stderr, "open(%s) = %d\n", path, ret);

	return ret;
}

static int32_t sys_close(int fd) {
	if (config.strace)
		fprintf(stderr, "close(%d)\n", fd);

	close(fd);

	return 0;
}

static int32_t sys_swap_frontbuffer(const char* buffer) {
	if (config.strace)
		fprintf(stderr, "swap_frontbuffer()\n");

	lock();

	memcpy(&k_state.framebuffer, buffer, 320 * 200);

	unlock();

	return 0;
}

static int32_t sys_read(int fd, void* buf, uint32_t count) {
	int ret = read(fd, buf, count);

	if (config.strace)
		fprintf(stderr, "read(%d, %p, %u) = %d (%m)\n", fd, buf, count,
			ret);

	if (ret < 0) {
		switch (ret) {
		case EBADF:
			ret = -KEBADF;
			break;
		case EINVAL:
		default:
			ret = -KEINVAL;
			break;
		}
	}

	return ret;
}

static uint32_t sys_sbrk(int32_t inc) {
	if (inc < 0)
		inc = 0;

	uint32_t out = k_state.brk;

	k_state.brk += inc;

	uint32_t next = align_up(out);
	if (k_state.brk >= next) {
		void* p = mmap((void*)next, k_state.brk - next + 1, PROT_RW,
			       MAP_PRIVATE|MAP_ANON, -1, 0);
		if (p == MAP_FAILED)
			err(1, "mmap");
	}

	if (config.strace)
		fprintf(stderr, "sbrk(%d) = %#x\n", inc, out);

	return out;
}

static uint32_t sys_gettick(void) {
	uint32_t ticks = getms() - k_state.starttime;

	if (config.strace)
		fprintf(stderr, "gettick() = %u\n", ticks);

	return ticks;
}

static int32_t sys_seek(int fd, int32_t off, int whence) {
	if (config.strace)
		fprintf(stderr, "seek(%d, %d, %d)\n", fd, off, whence);

	switch (whence) {
	case 0:
		whence = SEEK_SET;
		break;
	case 1:
		whence = SEEK_CUR;
		break;
	case 2:
		whence = SEEK_END;
		break;
	default:
		return -KEINVAL;
	};

	return lseek(fd, off, whence);
}

static int32_t sys_getkey(void) {
	int32_t out = -1;

	lock();

	out = k_state.key;
	k_state.key = -1;

	unlock();

	if (config.strace)
		fprintf(stderr, "getkey() = %d\n", out);

	return out;
}

static uint32_t sys_noop(void) {
	if (config.strace)
		fprintf(stderr, "noop()\n");
	return 0;
}

static syscall_t syscalls[] = {
	[SYSCALL_WRITE] = (syscall_t)sys_write,
	[SYSCALL_OPEN] = (syscall_t)sys_open,
	[SYSCALL_CLOSE] = (syscall_t)sys_close,
	[SYSCALL_SETVIDEO] = (syscall_t)sys_setvideo,
	[SYSCALL_SWAP_FRONTBUFFER] = (syscall_t)sys_swap_frontbuffer,
	[SYSCALL_READ] = (syscall_t)sys_read,
	[SYSCALL_SBRK] = (syscall_t)sys_sbrk,
	[SYSCALL_GETTICK] = (syscall_t)sys_gettick,
	[SYSCALL_SEEK] = (syscall_t)sys_seek,
	[SYSCALL_PLAYSOUND] = (syscall_t)sys_noop,
	[SYSCALL_GETMOUSE] = (syscall_t)sys_noop,
	[SYSCALL_GETKEY] = (syscall_t)sys_getkey,
};

static int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args) {
	if (sysnr > ARRSZE(syscalls) || !syscalls[sysnr]) {
		fprintf(stderr, "unsupported syscall: %d\n", sysnr);
		return -KENOSYS;
	}

	return syscalls[sysnr](args[0], args[1], args[2], args[3]);
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

	void* file = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (file == MAP_FAILED)
		err(1, "mmap");

	Elf32_Ehdr* ehdr = file;

	// TODO check ehdr

	Elf32_Phdr* phdrs = file + ehdr->e_phoff;
	for (size_t i = 0; i < ehdr->e_phnum; i++) {
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		int flags = elf_2_mmap_prot(phdrs[i].p_flags);
		void* map;


		map = mmap((void*)(phdrs[i].p_vaddr & PAGE_MASK),
			   align_up(phdrs[i].p_memsz), flags,
			   MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
		if (map == MAP_FAILED)
			err(1, "mmap");

		map = mmap((void*)(phdrs[i].p_vaddr & PAGE_MASK),
			   align_up(phdrs[i].p_filesz), flags,
			   MAP_PRIVATE | MAP_FIXED,
			   fd, phdrs[i].p_offset & PAGE_MASK);
		if (map == MAP_FAILED)
			err(1, "mmap");

		lock();

		k_state.brk = (uint32_t)map + phdrs[i].p_memsz;

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

		void* map_end = map + phdrs[i].p_filesz;
		if (phdrs[i].p_flags & PF_X)
			if (set_syscall_user_dispatch(map_end, (void*)-1) < 0)
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

static void* k_thread(void* fname) {
	entry_t entry = load_elf(fname);

	struct sigaction sa = {
		.sa_sigaction = sigsys_handler,
		.sa_flags = SA_SIGINFO,
	};

	sigaction(SIGSYS, &sa, NULL);

	k_state.starttime = getms();

	entry();

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
		k_state.palette[i].a = 0xff;
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
