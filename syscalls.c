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
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kine.h"

#include "kstd.h"

typedef int32_t (*syscall_t)();

static void* get_user(uint32_t ptr) {
	return (void*)(ptr + config.base);
}

static int32_t sys_write(uint32_t buf, size_t len) {
	void* buf_ptr = get_user(buf);

	if (config.strace)
		fprintf(stderr, "write(%p)\n", buf_ptr);

	return write(1, buf_ptr, len);
}

static int32_t sys_setvideo(int type) {
	if (config.strace)
		fprintf(stderr, "setvideo(%d)\n", type);

	switch (type) {
	case KVIDEO_TEXT:
	case KVIDEO_GRAPHIC:
		lock();

		k_state.video_mode = type;

		unlock();
		return 0;
	default:
		return -KEINVAL;
	}
}

static int32_t sys_open(uint32_t pathname, int flags) {
	(void) flags;

	char* pathname_ptr = get_user(pathname);

	char path[2048];

	snprintf(path, sizeof(path) - 1, "%s%s", config.path, pathname_ptr);

	int ret = open(path, O_RDONLY);
	if (ret < 0)
		ret = -KENOENT;

	struct stat st = { 0 };
	fstat(ret, &st);
	if (S_ISDIR(st.st_mode)) {
		close(ret);
		ret = -KENOENT;
	}

	if (config.strace)
		fprintf(stderr, "open(%s) = %d\n", pathname_ptr, ret);

	return ret;
}

static int32_t sys_close(int fd) {
	if (config.strace)
		fprintf(stderr, "close(%d)\n", fd);

	close(fd);

	return 0;
}

static int32_t sys_swap_frontbuffer(uint32_t buffer) {
	if (config.strace)
		fprintf(stderr, "swap_frontbuffer()\n");

	lock();

	memcpy(&k_state.framebuffer, get_user(buffer), 320 * 200);

	unlock();

	return 0;
}

static int32_t sys_read(int fd, uint32_t buf, uint32_t count) {
	void* buf_ptr = get_user(buf);

	int ret = read(fd, buf_ptr, count);

	if (config.strace)
		fprintf(stderr, "read(%d, %p, %u) = %d\n", fd, buf_ptr,
			count, ret);

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

	return lseek(fd, off, whence);
}

static int32_t sys_getkey(void) {
	int32_t out = -1;

	lock();

	out = k_state.key;

	unlock();

	if (config.strace)
		fprintf(stderr, "getkey() = %d\n", out);

	return out;
}

static uint32_t sys_set_palette(uint32_t palette, size_t sze) {
	uint32_t* arr = get_user(palette);
	if (config.strace)
		fprintf(stderr, "set_palette(%x, %zu)\n", palette, sze);

	if (sze > ARRSZE(k_state.palette))
		sze = ARRSZE(k_state.palette);

	lock();
	for (size_t i = 0; i < sze; i++) {
		k_state.palette[i].b = (arr[i] & 0xff) >> 0;
		k_state.palette[i].r = (arr[i] & 0xff0000) >> 16;
		k_state.palette[i].g = (arr[i] & 0xff00) >> 8;
	}
	unlock();

	return 0;
}

static int32_t sys_getkeymode(int released) {
	int32_t out = -KEAGAIN;
	struct ring* r = released ? &k_state.released : &k_state.pressed ;

	lock();
	uint8_t c = 0;
	if (ring_pop(r, &c) >= 0)
		out = c;
	unlock();

	if (config.strace)
		fprintf(stderr, "getkeymode(%d) = %d\n", released, out);

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
	[14] = (syscall_t)sys_getkeymode,
};

int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args) {
	if (sysnr > ARRSZE(syscalls) || !syscalls[sysnr]) {
		fprintf(stderr, "unsupported syscall: %d\n", sysnr);
		return -KENOSYS;
	}

	return syscalls[sysnr](args[0], args[1], args[2], args[3]);
}
