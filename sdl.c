#include <err.h>

#include "runk.h"

SDL_Renderer* init_window(void) {
	SDL_Init(SDL_INIT_VIDEO);

	SDL_Window* window = SDL_CreateWindow("Run K", SDL_WINDOWPOS_UNDEFINED,
					      SDL_WINDOWPOS_UNDEFINED, 640, 400,
					      SDL_WINDOW_OPENGL);
	if (!window)
		errx(1, "SDL_CreateWindow: %s", SDL_GetError());

	SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, 0);
	if (!renderer)
		errx(1, "SDL_CreateRenderer: %s", SDL_GetError());

	return renderer;
}

static int32_t scancode(SDL_Scancode orig) {
	switch (orig) {
	case SDL_SCANCODE_DOWN:
		return 0x50;
	case SDL_SCANCODE_UP:
		return 0x48;
	default:
		return -1;
	}
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

