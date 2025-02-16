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
#include "SDL.h"

#include "kine.h"

extern const unsigned int libvga_default_palette[256];

struct render_state_sdl {
	struct render_state base;
	SDL_Color palette[256];
	SDL_Palette* sdl_palette;
	SDL_Renderer* renderer;
	uint32_t sdl_ev_swap_frontbuffer;
	uint32_t framebuffer[320 * 200];
};

static SDL_Renderer* init_window(void) {
	if (SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1") == SDL_FALSE)
		warnx("SDL_SetHint(NO_SIGNAL_HANDLERS) failed");

	if (SDL_Init(SDL_INIT_VIDEO) < 0)
		errx(1, "SDL_Init: %s", SDL_GetError());

	SDL_Window* window = SDL_CreateWindow("kine", SDL_WINDOWPOS_UNDEFINED,
					      SDL_WINDOWPOS_UNDEFINED, 640, 400,
					      SDL_WINDOW_OPENGL);
	if (!window)
		errx(1, "SDL_CreateWindow: %s", SDL_GetError());

	SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, 0);
	if (!renderer)
		errx(1, "SDL_CreateRenderer: %s", SDL_GetError());

	return renderer;
}

static const unsigned char keymap[] = {
#define X(A, B) [A] = B,
#include "keymap.inc"
#undef X
};

static int32_t scancode(SDL_Scancode orig) {
	int32_t out = -1;
	if (orig <= ARRSZE(keymap) && keymap[orig])
		out = keymap[orig];

	return out;
}

static void update_renderer(struct render_state_sdl* r) {
	SDL_Surface* surface =
		SDL_CreateRGBSurfaceFrom(r->framebuffer, 320, 200, 8, 320, 0, 0,
					 0, 0);
	if (!surface)
		errx(1, "SDL_CreateRGBSurfaceFrom: %s", SDL_GetError());

	if (SDL_SetPaletteColors(r->sdl_palette, r->palette, 0, 256))
		errx(1, "SDL_SetPaletteColors: %s", SDL_GetError());

	if (SDL_SetSurfacePalette(surface, r->sdl_palette))
		errx(1, "SDL_SetSurfacePalette: %s", SDL_GetError());

	SDL_Texture* texture =
		SDL_CreateTextureFromSurface(r->renderer, surface);
	if (!texture)
		errx(1, "SDL_CreateTextureFromSurface: %s", SDL_GetError());
	SDL_FreeSurface(surface);
	SDL_RenderCopy(r->renderer, texture, 0, 0);
	SDL_DestroyTexture(texture);
	SDL_RenderPresent(r->renderer);
}

static void update_inputs(struct k_state_t* k, struct render_state_sdl* r) {
	SDL_Event event = {};

	if (!SDL_WaitEvent(&event))
		warnx("SDL_WaitEvent: %s", SDL_GetError());

	k_lock(k);
	if (event.type == SDL_QUIT) {
		k->quit = 1;
	} else if (event.type == SDL_KEYDOWN) {
		k->key = scancode(event.key.keysym.scancode);
		ring_push(&k->pressed, k->key);
	} else if (event.type == SDL_KEYUP) {
		if (k->key == scancode(event.key.keysym.scancode))
			k->key = -1;
		ring_push(&k->released, scancode(event.key.keysym.scancode));
	}
	k_unlock(k);

	if (event.type == r->sdl_ev_swap_frontbuffer)
		update_renderer(r);
}

static void set_palette(struct render_state* base, const uint32_t* arr,
			size_t sze) {
	struct render_state_sdl* r =
		container_of(base, struct render_state_sdl, base);

	if (sze > ARRSZE(r->palette))
		sze = ARRSZE(r->palette);

	for (size_t i = 0; i < sze; i++) {
		r->palette[i].b = (arr[i] & 0xff) >> 0;
		r->palette[i].r = (arr[i] & 0xff0000) >> 16;
		r->palette[i].g = (arr[i] & 0xff00) >> 8;
	}
}

static void swap_frontbuffer(struct render_state* base, uint32_t* arr) {
	struct render_state_sdl* r =
		container_of(base, struct render_state_sdl, base);
	memcpy(&r->framebuffer, arr, sizeof(r->framebuffer));
	if (SDL_PushEvent(&(SDL_Event){ .type = r->sdl_ev_swap_frontbuffer }) < 0)
		warnx("SDL_PushEvent: %s", SDL_GetError());
}

void* render_thread(void* k_ptr) {
	struct k_state_t* k = k_ptr;

	struct render_state_sdl r = {
		.base = {
			.set_palette = set_palette,
			.swap_frontbuffer = swap_frontbuffer,
		},
		.sdl_palette = SDL_AllocPalette(256),
		.renderer = init_window(),
	};
	if (!r.sdl_palette)
		errx(1, "SDL_AllocPalette: %s", SDL_GetError());

	r.sdl_ev_swap_frontbuffer = SDL_RegisterEvents(1);
	if (r.sdl_ev_swap_frontbuffer == (uint32_t)-1)
		errx(1, "SDL_RegisterEvents");

	set_palette(&r.base, libvga_default_palette,
		    ARRSZE(libvga_default_palette));

	k->render_state = &r.base;

	while (!k->quit)
		update_inputs(k, &r);

	SDL_Quit();

	return NULL;
}
