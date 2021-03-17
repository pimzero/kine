#ifndef RUNK_H
#define RUNK_H

#include "stdint.h"

#include "SDL.h"

#define VIDEO_GRAPHIC	0
#define VIDEO_TEXT	1

struct k_state_t {
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

uint32_t getms(void);

static inline uint32_t align_up(uint32_t ptr) {
	return (ptr + 0xfff) & ~(uint32_t)0xfff;
}

SDL_Renderer* init_window(void);
void update_inputs();
void update_renderer(SDL_Renderer* renderer);

#endif
