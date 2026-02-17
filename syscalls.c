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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kine.h"

#include "kstd.h"

typedef int32_t (*syscall_t)();

static void* get_user(uint32_t ptr) {
	if (ptr >= config.limit)
		return NULL;
	return (void*)(ptr + config.base);
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
	void* buf_ptr = get_user(buf);
	if (!buf_ptr)
		return -KEINVAL;

	return errno2k(write(1, buf_ptr, len));
}

static int32_t sys_SETVIDEO(int type) {
	switch (type) {
	case KVIDEO_TEXT:
	case KVIDEO_GRAPHIC:
		k_lock(&k_state);

		k_state.video_mode = type;

		k_unlock(&k_state);
		return 0;
	default:
		return -KEINVAL;
	}
}

static long openat2(int dirfd, const char *path, struct open_how *how,
		    size_t size) {
	return syscall(SYS_openat2, dirfd, path, how, size);
}

static int32_t sys_OPEN(uint32_t pathname, int flags) {
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

	char* pathname_ptr = get_user(pathname);
	if (!pathname_ptr)
		return -KEINVAL;

	struct open_how how = {
		.resolve = RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS,
		.mode = O_RDONLY,
	};

	int ret = errno2k(openat2(config.root, pathname_ptr, &how, sizeof(how)));
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
	uint32_t *arr = get_user(buffer);
	if (!arr)
		return -KEINVAL;

	k_state.render_state->swap_frontbuffer(k_state.render_state, arr);

	return 0;
}

static int32_t sys_READ(uint32_t fd, uint32_t buf, uint32_t count) {
	void* buf_ptr = get_user(buf);
	if (!buf_ptr)
		return -KEINVAL;

	return ON_FD(read, fd, buf_ptr, count);
}

static uint32_t sys_SBRK(int32_t inc) {
	if (inc < 0)
		inc = 0;

	uint32_t out = k_state.brk;
	k_state.brk += inc;

	return out;
}

static uint32_t sys_GETTICK(void) {
	return getms() - k_state.starttime;
}

static int32_t sys_SEEK(uint32_t fd, int32_t off, int whence) {
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
	int32_t out = -1;

	k_lock(&k_state);

	out = k_state.key;

	k_unlock(&k_state);

	return out;
}

static uint32_t sys_SETPALETTE(uint32_t palette, uint32_t sze) {
	uint32_t* arr = get_user(palette);

	if (!arr)
		return -KEINVAL;

	k_lock(&k_state);
	k_state.render_state->set_palette(k_state.render_state, arr, sze);
	k_unlock(&k_state);

	return 0;
}

static int32_t sys_READKEY(uint32_t uaddr) {
	int32_t out = -KEAGAIN;
	struct key_event *ev = get_user(uaddr);
	if (!ev)
		return -KEINVAL;

	k_lock(&k_state);
	uint8_t c = 0;
	if (ring_pop(&k_state.keys, &c) < 0)
		goto unlock;

	ev->state = c & FLAG_KEY_RELEASED ? KEY_RELEASED : KEY_PRESSED;
	ev->key = c & ~FLAG_KEY_RELEASED;

	out = 0;
unlock:
	k_unlock(&k_state);

	return out;
}

#define FMT_STRING ((void *)1)

static const struct {
	syscall_t f;
	const char *name;
	const char *fmt[ARRSZE((syscall_args_t){})];
} syscalls[] = {
#define SYS(Name, ...) [KSYSCALL_##Name] = { .f = (syscall_t)sys_##Name, .name = #Name, .fmt = { __VA_ARGS__ }, }
	SYS(WRITE, "%#x", "%u"),
	SYS(SBRK, "%d"),
	SYS(GETKEY),
	SYS(GETTICK),
	SYS(OPEN, "%#x"),
	SYS(READ, "%d", "%#x", "%u"),
	SYS(SEEK, "%u", "%d", "%d"),
	SYS(CLOSE, "%d"),
	SYS(SETVIDEO, "%d"),
	SYS(SWAP_FRONTBUFFER, "%#x"),
	/* SYS(PLAYSOUND), // not implemented. */
	SYS(SETPALETTE, "%#x", "%u"),
	/* SYS(GETMOUSE), // not implemented. */
	SYS(READKEY, "%#x"),
#undef SYS
};

int32_t syscall_dispatch(uint32_t nr, const syscall_args_t args) {
	if (nr > ARRSZE(syscalls) || !syscalls[nr].f) {
		fprintf(stderr, "unsupported syscall: %d\n", nr);
		return -KENOSYS;
	}

	int32_t ret = syscalls[nr].f(args[0], args[1], args[2], args[3]);

	if (config.strace) {
		fprintf(stderr, "%s(", syscalls[nr].name);
		for (size_t i = 0; i < ARRSZE(syscalls[nr].fmt) && syscalls[nr].fmt[i]; i++) {
			if (i)
				fprintf(stderr, ", ");
			fprintf(stderr, syscalls[nr].fmt[i], args[i]);
		}

		fprintf(stderr, ") = %d\n", ret);
	}

	return ret;
}
