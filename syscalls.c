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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <printf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kine.h"

#include "kstd.h"

static void* get_user(uint32_t ptr) {
	if (ptr >= config.limit)
		return NULL;
	return (void*)(ptr + config.base);
}

static char* str_from_user(uint32_t ptr) {
	char* str = get_user(ptr);
	if (!str)
		return NULL;

	if (!memchr(str, 0, config.limit - ptr))
		return NULL;

	return str;
}

static void* mem_from_user(uint32_t ptr, size_t size) {
	if (ptr + size > config.limit)
		return NULL;

	return get_user(ptr);
}

static int32_t errno2k(int32_t r)
{
	if (r >= 0)
		return r;

	switch (errno) {
	case ENOMEM:
		return -KENOMEM;
	case ENOENT:
		return -KENOENT;
	case EIO:
		return -KEIO;
	case EBADF:
		return -KEBADF;
	case EAGAIN:
		return -KEAGAIN;
	case EINVAL:
	default:
		return -KEINVAL;
	/* ENOSYS: should not happen. */
	}
}

#define ON_FD(Fn, Fd, ...) ({ \
		(Fd) > ARRSZE(k_state.fds) ? -KEBADF : \
		errno2k((Fn)(k_state.fds[(Fd)] __VA_OPT__(,) __VA_ARGS__)); \
	})

static int32_t sys_WRITE(uint32_t buf, uint32_t len) {
	void* buf_ptr = mem_from_user(buf, len);
	if (!buf_ptr)
		return -KEINVAL;

	return errno2k(write(1, buf_ptr, len));
}

static int32_t sys_SETVIDEO(int32_t type) {
	K_LOCK_SCOPPED(lock, &k_state);

	switch (type) {
	case KVIDEO_TEXT:
	case KVIDEO_GRAPHIC:
		k_state.video_mode = type;
		return 0;
	default:
		return -KEINVAL;
	}
}

static long linux_openat2(int dirfd, const char *path, struct open_how *how,
			  size_t size) {
	return syscall(SYS_openat2, dirfd, path, how, size);
}

static int32_t sys_OPEN(uint32_t pathname, uint32_t flags) {
	(void) flags;

	int *fd_orig = NULL;
	for (size_t i = 0; i < ARRSZE(k_state.fds); i++) {
		if (k_state.fds[i] == -1) {
			fd_orig = &k_state.fds[i];
			break;
		}
	}
	if (!fd_orig)
		return -KENOMEM;

	char* pathname_ptr = str_from_user(pathname);
	if (!pathname_ptr)
		return -KEINVAL;

	struct open_how how = {
		.resolve = RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS,
		.mode = O_RDONLY,
	};

	int ret = errno2k(linux_openat2(config.root, pathname_ptr, &how, sizeof(how)));
	if (ret < 0)
		return ret;

	struct stat st;
	if ((fstat(ret, &st) < 0) || S_ISDIR(st.st_mode)) {
		close(ret);
		return -KENOENT;
	}

	*fd_orig = ret;
	return fd_orig - k_state.fds;
}

static int32_t sys_CLOSE(uint32_t fd) {
	int32_t ret = ON_FD(close, fd);
	if (ret >= 0)
		k_state.fds[fd] = -1;

	return ret;
}

static int32_t sys_SWAP_FRONTBUFFER(uint32_t buffer) {
	const framebuffer_t* fb = mem_from_user(buffer, sizeof(*fb));
	if (!fb)
		return -KEINVAL;

	k_state.render_state->swap_frontbuffer(k_state.render_state, fb);

	return 0;
}

static int32_t sys_READ(uint32_t fd, uint32_t buf, uint32_t count) {
	void* buf_ptr = mem_from_user(buf, count);
	if (!buf_ptr)
		return -KEINVAL;

	return ON_FD(read, fd, buf_ptr, count);
}

static int32_t sys_SBRK(int32_t inc) {
	int32_t new_brk = (int32_t)k_state.brk + inc;

	if (new_brk < 0 || new_brk >= (int32_t)config.limit)
		return -KENOMEM;

	int32_t out = k_state.brk;
	k_state.brk = new_brk;

	return out;
}

static int32_t sys_GETTICK(void) {
	return getms() - k_state.starttime;
}

static int32_t sys_SEEK(uint32_t fd, int32_t off, int32_t whence) {
	switch (whence) {
	case KSEEK_SET:
		whence = SEEK_SET;
		break;
	case KSEEK_CUR:
		whence = SEEK_CUR;
		break;
	case KSEEK_END:
		whence = SEEK_END;
		break;
	default:
		return -KEINVAL;
	};

	return ON_FD(lseek, fd, off, whence);
}

static int32_t sys_GETKEY(void) {
	K_LOCK_SCOPPED(lock, &k_state);

	return k_state.key;
}

static int32_t sys_SETPALETTE(uint32_t palette, uint32_t sze) {
	const palette_t* p = mem_from_user(palette, sizeof(*p));
	if (!p)
		return -KEINVAL;

	if (sze > ARRSZE(*p))
		sze = ARRSZE(*p);

	K_LOCK_SCOPPED(lock, &k_state);

	k_state.render_state->set_palette(k_state.render_state, p, sze);

	return 0;
}

static int32_t sys_READKEY(uint32_t uaddr) {
	struct key_event* ev = mem_from_user(uaddr, sizeof(*ev));
	if (!ev)
		return -KEINVAL;

	K_LOCK_SCOPPED(lock, &k_state);

	uint8_t c = 0;
	if (ring_pop(&k_state.keys, &c) < 0)
		return -KEAGAIN;

	ev->state = c & FLAG_KEY_RELEASED ? KEY_RELEASED : KEY_PRESSED;
	ev->key = c & ~FLAG_KEY_RELEASED;

	return 0;
}

typedef union {
	int32_t (*v  )(void);
	int32_t (*u  )(uint32_t);
	int32_t (*s  )(int32_t);
	int32_t (*uu )(uint32_t, uint32_t);
	int32_t (*uuu)(uint32_t, uint32_t, uint32_t);
	int32_t (*uss)(uint32_t, int32_t, int32_t);
} syscall_t;

static const struct {
	syscall_t f;
	const char* name;
	const char* fmt;
} syscalls[] = {
#define SYS(T, Name, Fmt) [KSYSCALL_##Name] = { .f.T = sys_##Name, .name = #Name, .fmt = Fmt, }
	SYS(uu,  WRITE, "%S, %u"),
	SYS(s,   SBRK, "%d"),
	SYS(v,   GETKEY, ""),
	SYS(v,   GETTICK, ""),
	SYS(uu,  OPEN, "%S, %u"),
	SYS(uuu, READ, "%d, %#x, %u"),
	SYS(uss, SEEK, "%u, %d, %d"),
	SYS(u,   CLOSE, "%d"),
	SYS(s,   SETVIDEO,"%d"),
	SYS(u,   SWAP_FRONTBUFFER, "%#x"),
	/* SYS(PLAYSOUND), // not implemented. */
	SYS(uu,  SETPALETTE, "%#x, %u"),
	/* SYS(GETMOUSE), // not implemented. */
	SYS(u,   READKEY, "%#x"),
#undef SYS
};

static int print_string_arg(FILE* f, const struct printf_info* info,
			    const void* const* args) {
	(void) info;
	uint32_t arg = *(uint32_t*)(args[0]);
	const char* s = str_from_user(arg);
	if (s)
		return fprintf(f, "\"%s\"", s);
	else
		return fprintf(f, "%#x", arg);
}

__attribute((constructor))
static void syscalls_init_strace(void) {
	if (register_printf_specifier('S', print_string_arg, NULL) < 0)
		err(1, "register_printf_specifier");
}

static void syscall_trace(uint32_t nr, uint32_t arg1, uint32_t arg2,
			  uint32_t arg3, int32_t ret) {
	fprintf(stderr, "%s(", syscalls[nr].name);
	fprintf(stderr, syscalls[nr].fmt, arg1, arg2, arg3);

	static const char* errnos[] = {
#define X(X) [K##X] = #X
		X(ENOMEM),
		X(ENOENT),
		X(EIO),
		X(EINVAL),
		X(ENOSYS),
		X(EBADF),
		X(EAGAIN),
#undef X
	};
	if (-ret > 0 && -ret < (int32_t)ARRSZE(errnos) && errnos[-ret])
		fprintf(stderr, ") = -%s\n", errnos[-ret]);
	else
		fprintf(stderr, ") = %d\n", ret);
}

int32_t syscall_dispatch(uint32_t nr, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
	if (nr > ARRSZE(syscalls) || !syscalls[nr].f.uuu) {
		fprintf(stderr, "unsupported syscall: %d\n", nr);
		return -KENOSYS;
	}

	int32_t ret = syscalls[nr].f.uuu(arg1, arg2, arg3);

	if (config.strace)
		syscall_trace(nr, arg1, arg2, arg3, ret);

	return ret;
}
