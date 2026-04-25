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

#ifndef KINE_H
#define KINE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define ARRSZE(X) (sizeof(X) / sizeof(*(X)))

#define XSTR(S) STR(S)
#define STR(S) #S

#define container_of(ptr, type, member) \
	((type *)(((void *)(ptr)) - offsetof(type, member)))

struct ring {
	uint8_t buf[256];
	uint8_t a, z;
};
#define RING_INITIALIZER { .a = -1 }

typedef uint32_t palette_t[256];
typedef uint32_t framebuffer_t[320 * 200];

struct render_state {
	void (*set_palette)(struct render_state*, const palette_t*, size_t);
	void (*swap_frontbuffer)(struct render_state*, const framebuffer_t*);
};

extern const palette_t libvga_default_palette;

struct k_state_t {
	pthread_mutex_t lock;
	int video_mode;
	int quit;
	int32_t key;
	struct render_state* render_state;

	struct ring keys;

	/* unlocked */
	uint32_t brk; /* only accessed by k_thread */
	uint32_t starttime; /* only read */

	int fds[64];
};

void render_state_set(struct k_state_t* k, struct render_state* render_state);

struct config_t {
	int root;
	int strace, coredump, k_on_main_thread;

	uintptr_t base, sp, brk;
	union {
		uint32_t limit;
		struct {
			uint32_t __zeros:12;
			uint32_t limit_as_pages:20;
		};
	};
};

void k_lock(struct k_state_t*);
void k_unlock(struct k_state_t*);

static inline void k_unlock_ref(struct k_state_t** ptr) {
	k_unlock(*ptr);
}

#define K_LOCK_SCOPPED(Lck, State) \
	struct k_state_t *Lck __attribute__((cleanup(k_unlock_ref))) = \
	({ struct k_state_t *val_ = (State); k_lock(val_); val_; })

extern struct config_t config;
extern struct k_state_t k_state;

typedef void (*entry_t)(void);
void k_prepare(void);
__attribute((noreturn))
void k_start(entry_t entry);

#define SEGMENT_CODE 1
#define SEGMENT_DATA 2
#define SEGMENT_LINUX_GS 12

#define SEGMENT_LDT (1 << 2)
#define SEGMENT_GDT 0
#define SEGMENT_RPL3 (0x3)
#define SEG_REG(Segment, Table, Rpl) \
	((SEGMENT_##Segment << 3) | SEGMENT_##Table | SEGMENT_RPL##Rpl)

#if __x86_64__
#include "i386_gen.h"
#else
#include <sys/procfs.h>
#include <sys/user.h>
#define elf_prstatus_i386 elf_prstatus
#define user_regs_struct_i386 user_regs_struct
#endif

void coredump_write(const struct user_regs_struct_i386 *regs);

static inline int ring_push(struct ring* rb, uint8_t c) {
	if ((rb->z + 1) % ARRSZE(rb->buf) == rb->a)
		return -1;

	rb->buf[rb->z++] = c;

	return 0;
}

static inline int ring_pop(struct ring* rb, uint8_t* c) {
	if ((rb->a + 1) % ARRSZE(rb->buf) == rb->z)
		return -1;

	*c = rb->buf[++rb->a];

	return 0;
}

typedef uint32_t syscall_args_t[3];

int32_t syscall_dispatch(uint32_t sysnr, const syscall_args_t args);
uint32_t getms(void);

typedef void* (*renderer_t)(struct k_state_t*);

struct k_renderer {
	const char* name;
	const renderer_t render_thread;
};

#define DEFINE_RENDERER(Name, Func) \
	__attribute__((section("renderers"))) const struct k_renderer k_render_##Name = { \
		.name = #Name, \
		.render_thread = Func, \
	};

#define FLAG_KEY_RELEASED 0x80

#endif
