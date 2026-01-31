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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kine.h"

#include "kstd.h"

extern struct config_t config;
extern struct k_state_t k_state;

typedef int32_t (*syscall_t)();

static void* get_user(uint32_t ptr) {
	if (ptr >= config.limit * 4096)
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

static int32_t sys_write(uint32_t buf, uint32_t len) {
	if (config.strace)
		fprintf(stderr, "write(%#x, %u)\n", buf, len);

	void* buf_ptr = get_user(buf);
	if (!buf_ptr)
		return -KEINVAL;

	return errno2k(write(1, buf_ptr, len));
}

static int32_t sys_setvideo(int type) {
	if (config.strace)
		fprintf(stderr, "setvideo(%d)\n", type);

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

static int32_t sys_open(uint32_t pathname, int flags) {
	(void) flags;

	char* pathname_ptr = get_user(pathname);
	if (!pathname_ptr)
		goto exit;

	struct open_how how = {
		.resolve = RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS,
		.mode = O_RDONLY,
	};

	int ret = errno2k(openat2(config.root, pathname_ptr, &how, sizeof(how)));
	if (ret < 0)
		goto exit;

	struct stat st;
	if ((fstat(ret, &st) < 0) || S_ISDIR(st.st_mode)) {
		close(ret);
		ret = -KENOENT;
	}

exit:
	if (config.strace)
		fprintf(stderr, "open(%s) = %d\n", pathname_ptr, ret);

	return ret;
}

static int32_t sys_close(int fd) {
	if (config.strace)
		fprintf(stderr, "close(%d)\n", fd);

	return errno2k(close(fd));
}

static int32_t sys_swap_frontbuffer(uint32_t buffer) {
	if (config.strace)
		fprintf(stderr, "swap_frontbuffer(%#x)\n", buffer);

	uint32_t *arr = get_user(buffer);
	if (!arr)
		return -KEINVAL;

	k_state.render_state->swap_frontbuffer(k_state.render_state, arr);

	return 0;
}

static int32_t sys_read(int fd, uint32_t buf, uint32_t count) {
	if (config.strace)
		fprintf(stderr, "read(%d, %#x, %u)\n", fd, buf, count);

	void* buf_ptr = get_user(buf);
	if (!buf_ptr)
		return -KEINVAL;

	return errno2k(read(fd, buf_ptr, count));
}

static uint32_t sys_sbrk(int32_t inc) {
	if (inc < 0)
		inc = 0;

	uint32_t out = k_state.brk;
	k_state.brk += inc;

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

	return errno2k(lseek(fd, off, whence));
}

static int32_t sys_getkey(void) {
	int32_t out = -1;

	k_lock(&k_state);

	out = k_state.key;

	k_unlock(&k_state);

	if (config.strace)
		fprintf(stderr, "getkey() = %d\n", out);

	return out;
}

static uint32_t sys_set_palette(uint32_t palette, uint32_t sze) {
	uint32_t* arr = get_user(palette);
	if (config.strace)
		fprintf(stderr, "set_palette(%#x, %u)\n", palette, sze);

	if (!arr)
		return -KEINVAL;

	k_lock(&k_state);
	k_state.render_state->set_palette(k_state.render_state, arr, sze);
	k_unlock(&k_state);

	return 0;
}

static int32_t sys_readkey(uint32_t uaddr) {
	if (config.strace)
		fprintf(stderr, "readkey(%#x)\n", uaddr);

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

#define not_implemented NULL

static syscall_t syscalls[] = {
	[KSYSCALL_WRITE] = (syscall_t)sys_write,
	[KSYSCALL_SBRK] = (syscall_t)sys_sbrk,
	[KSYSCALL_GETKEY] = (syscall_t)sys_getkey,
	[KSYSCALL_GETTICK] = (syscall_t)sys_gettick,
	[KSYSCALL_OPEN] = (syscall_t)sys_open,
	[KSYSCALL_READ] = (syscall_t)sys_read,
	[KSYSCALL_SEEK] = (syscall_t)sys_seek,
	[KSYSCALL_CLOSE] = (syscall_t)sys_close,
	[KSYSCALL_SETVIDEO] = (syscall_t)sys_setvideo,
	[KSYSCALL_SWAP_FRONTBUFFER] = (syscall_t)sys_swap_frontbuffer,
	[KSYSCALL_PLAYSOUND] = (syscall_t)not_implemented, /* not implemented */
	[KSYSCALL_SETPALETTE] = (syscall_t)sys_set_palette,
	[KSYSCALL_GETMOUSE] = (syscall_t)not_implemented, /* not implemented */
	[KSYSCALL_READKEY] = (syscall_t)sys_readkey,
};

int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args) {
	if (sysnr > ARRSZE(syscalls) || !syscalls[sysnr]) {
		fprintf(stderr, "unsupported syscall: %d\n", sysnr);
		return -KENOSYS;
	}

	return syscalls[sysnr](args[0], args[1], args[2], args[3]);
}
