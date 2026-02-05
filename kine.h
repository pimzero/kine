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

#include <stdint.h>
#include <pthread.h>
#include <stddef.h>

#define ARRSZE(X) (sizeof(X) / sizeof(*(X)))

#define container_of(ptr, type, member) \
	((type *)(((void *)(ptr)) - offsetof(type, member)))

struct ring {
	uint8_t buf[256];
	uint8_t a, z;
};
#define RING_INITIALIZER { .a = -1 }

struct render_state {
	void (*set_palette)(struct render_state*, const uint32_t*, size_t);
	void (*swap_frontbuffer)(struct render_state*, uint32_t*);
};

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

struct config_t {
	int root;
	int strace, k_on_main_thread;

	uintptr_t base, limit, sp, brk;
};

void k_lock(struct k_state_t*);
void k_unlock(struct k_state_t*);

extern struct config_t config;
extern struct k_state_t k_state;

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

int32_t syscall_dispatch(uint32_t sysnr, uint32_t* args);
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
