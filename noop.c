#include <sched.h>
#include <err.h>

#include "kine.h"

static void set_palette(struct render_state* base, const palette_t* palette,
			size_t sze) {
	(void) base;
	(void) palette;
	(void) sze;
}

static void swap_frontbuffer(struct render_state* base, const framebuffer_t* fb) {
	(void) base;
	(void) fb;
}

static void* render_thread_noop(struct k_state_t* k) {
	struct render_state r = {
		.set_palette = set_palette,
		.swap_frontbuffer = swap_frontbuffer,
	};
	k->render_state = &r;

	while (!k->quit)
		sched_yield();

	k->render_state = NULL;

	return NULL;
}

DEFINE_RENDERER(noop, render_thread_noop);
