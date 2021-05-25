#ifndef KINE_H
#define KINE_H

#include <stdint.h>

#include "SDL.h"

#define ARRSZE(X) (sizeof(X) / sizeof(*(X)))

#define VIDEO_GRAPHIC	0
#define VIDEO_TEXT	1

struct ring {
	uint8_t buf[256];
	uint8_t a, z;
};
#define RING_INITIALIZER { .a = -1 }

struct k_state_t {
	pthread_mutex_t lock;
	int video_mode;
	int quit;
	uint32_t framebuffer[320 * 200];
	SDL_Color palette[256];
	SDL_Palette* sdl_palette;
	int32_t key;

	struct ring pressed, released;

	/* unlocked */
	uint32_t brk; /* only accessed by k_thread */
	uint32_t starttime; /* only read */
};

struct config_t {
	char* path;
	int strace;

	uint32_t base, limit, sp, brk;
};

extern struct k_state_t k_state;
extern struct config_t config;

void lock(void);
void unlock(void);

static inline int ring_push(struct ring* rb, uint8_t c) {
	if ((rb->z + 1) % 256 == rb->a)
		return -1;

	rb->buf[rb->z++] = c;

	return 0;
}

static inline int ring_pop(struct ring* rb, uint8_t* c) {
	if ((rb->a + 1) % 256 == rb->z)
		return -1;

	*c = rb->buf[++rb->a];

	return 0;
}

uint32_t getms(void);

static inline uint32_t align_up(uint32_t ptr) {
	return (ptr + 0xfff) & ~(uint32_t)0xfff;
}

SDL_Renderer* init_window(void);
void update_inputs();
void update_renderer(SDL_Renderer* renderer);

#endif
