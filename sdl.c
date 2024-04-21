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

#include "kine.h"

SDL_Renderer* init_window(void) {
	if (SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1") == SDL_FALSE)
		warnx("SDL_SetHint(NO_SIGNAL_HANDLERS) failed");

	SDL_Init(SDL_INIT_VIDEO);

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

void update_inputs() {
	SDL_Event event;

	lock();
	while (SDL_PollEvent(&event)) {
		switch (event.type) {
		case SDL_QUIT:
			k_state.quit = 1;
			break;
		case SDL_KEYDOWN:
			k_state.key = scancode(event.key.keysym.scancode);
			ring_push(&k_state.pressed, k_state.key);
			break;
		case SDL_KEYUP:
			if (k_state.key == scancode(event.key.keysym.scancode))
				k_state.key = -1;
			ring_push(&k_state.released,
				  scancode(event.key.keysym.scancode));
			break;
		default:
			break;
		}
	}
	unlock();
}

void update_renderer(SDL_Renderer* renderer) {
	lock();

	SDL_Surface* surface =
		SDL_CreateRGBSurfaceFrom(&k_state.framebuffer, 320, 200, 8, 320,
					 0, 0, 0, 0);

	if (!surface)
		errx(1, "SDL_CreateRGBSurfaceFrom: %s", SDL_GetError());

	if (SDL_SetPaletteColors(k_state.sdl_palette, k_state.palette, 0, 256))
		errx(1, "SDL_SetPaletteColors: %s", SDL_GetError());

	unlock();

	if (SDL_SetSurfacePalette(surface, k_state.sdl_palette))
		errx(1, "SDL_SetSurfacePalette: %s", SDL_GetError());

	SDL_Texture* texture =
		SDL_CreateTextureFromSurface(renderer, surface);
	if (!texture)
		errx(1, "SDL_CreateTextureFromSurface: %s", SDL_GetError());
	SDL_FreeSurface(surface);

	SDL_SetRenderDrawColor(renderer, 0, 0, 0, 0);
	SDL_RenderClear(renderer);
	SDL_RenderCopy(renderer, texture, 0, 0);
	SDL_RenderPresent(renderer);

	SDL_DestroyTexture(texture);
}

