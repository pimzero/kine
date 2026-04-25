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

#ifdef USE_DL_LAZY
#include "dl_lazy.h"

static void *sdl2_handle;

#define SDL(X) DL_LAZY(SDL_##X, sdl2_handle)
#else
#define SDL(X) SDL_##X
#endif

struct render_state_sdl {
	struct render_state base;
	SDL_Color palette[256];
	SDL_Palette* sdl_palette;
	SDL_Renderer* renderer;
	uint32_t sdl_ev_swap_frontbuffer;
	framebuffer_t framebuffer;
};

static SDL_Renderer* init_window(void) {
	if (SDL(SetHint)(SDL_HINT_NO_SIGNAL_HANDLERS, "1") == SDL_FALSE)
		warnx("SDL_SetHint(NO_SIGNAL_HANDLERS) failed");

	if (SDL(Init)(SDL_INIT_VIDEO) < 0)
		errx(1, "SDL_Init: %s", SDL(GetError)());

	SDL_Window* window = SDL(CreateWindow)("kine", SDL_WINDOWPOS_UNDEFINED,
					      SDL_WINDOWPOS_UNDEFINED, 640, 400,
					      SDL_WINDOW_OPENGL);
	if (!window)
		errx(1, "SDL_CreateWindow: %s", SDL(GetError)());

	SDL_Renderer* renderer = SDL(CreateRenderer)(window, -1, 0);
	if (!renderer)
		errx(1, "SDL_CreateRenderer: %s", SDL(GetError)());

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
		SDL(CreateRGBSurfaceFrom)(r->framebuffer, 320, 200, 8, 320, 0,
					  0, 0, 0);
	if (!surface)
		errx(1, "SDL_CreateRGBSurfaceFrom: %s", SDL(GetError)());

	if (SDL(SetPaletteColors)(r->sdl_palette, r->palette, 0, 256))
		errx(1, "SDL_SetPaletteColors: %s", SDL(GetError)());

	if (SDL(SetSurfacePalette)(surface, r->sdl_palette))
		errx(1, "SDL_SetSurfacePalette: %s", SDL(GetError)());

	SDL_Texture* texture =
		SDL(CreateTextureFromSurface)(r->renderer, surface);
	if (!texture)
		errx(1, "SDL_CreateTextureFromSurface: %s", SDL(GetError)());
	SDL(FreeSurface)(surface);
	SDL(RenderCopy)(r->renderer, texture, 0, 0);
	SDL(DestroyTexture)(texture);
	SDL(RenderPresent)(r->renderer);
}

static void update_inputs(struct k_state_t* k, struct render_state_sdl* r) {
	SDL_Event event = {};

	if (!SDL(WaitEvent)(&event))
		warnx("SDL_WaitEvent: %s", SDL(GetError)());

	k_lock(k);
	if (event.type == SDL_QUIT) {
		k->quit = 1;
	} else if (event.type == SDL_KEYDOWN) {
		k->key = scancode(event.key.keysym.scancode);
		ring_push(&k->keys, k->key);
	} else if (event.type == SDL_KEYUP) {
		if (k->key == scancode(event.key.keysym.scancode))
			k->key = -1;
		ring_push(&k->keys, scancode(event.key.keysym.scancode) |
			  FLAG_KEY_RELEASED);
	}
	k_unlock(k);

	if (event.type == r->sdl_ev_swap_frontbuffer)
		update_renderer(r);
}

static void set_palette(struct render_state* base, const palette_t* palette,
			size_t sze) {
	struct render_state_sdl* r =
		container_of(base, struct render_state_sdl, base);

	for (size_t i = 0; i < sze; i++) {
		r->palette[i].b = ((*palette)[i] & 0xff) >> 0;
		r->palette[i].r = ((*palette)[i] & 0xff0000) >> 16;
		r->palette[i].g = ((*palette)[i] & 0xff00) >> 8;
	}
}

static void swap_frontbuffer(struct render_state* base, const framebuffer_t* fb) {
	struct render_state_sdl* r =
		container_of(base, struct render_state_sdl, base);
	memcpy(&r->framebuffer, fb, sizeof(r->framebuffer));
	if (SDL(PushEvent)(&(SDL_Event){ .type = r->sdl_ev_swap_frontbuffer }) < 0)
		warnx("SDL_PushEvent: %s", SDL(GetError)());
}

static void* render_thread_sdl2(struct k_state_t* k) {
#if USE_DL_LAZY
	if ((sdl2_handle = dlopen("libSDL2.so", RTLD_LAZY|RTLD_LOCAL)) == NULL)
		errx(1, "dlopen: %s", dlerror());
#endif

	struct render_state_sdl r = {
		.base = {
			.set_palette = set_palette,
			.swap_frontbuffer = swap_frontbuffer,
		},
		.sdl_palette = SDL(AllocPalette)(256),
		.renderer = init_window(),
	};
	if (!r.sdl_palette)
		errx(1, "SDL_AllocPalette: %s", SDL(GetError)());

	r.sdl_ev_swap_frontbuffer = SDL(RegisterEvents)(1);
	if (r.sdl_ev_swap_frontbuffer == (uint32_t)-1)
		errx(1, "SDL_RegisterEvents");

	set_palette(&r.base, &libvga_default_palette,
		    ARRSZE(libvga_default_palette));

	render_state_set(k, &r.base);

	while (!k->quit)
		update_inputs(k, &r);

	SDL(Quit)();

	render_state_set(k, NULL);

	return NULL;
}

DEFINE_RENDERER(sdl2, render_thread_sdl2);
