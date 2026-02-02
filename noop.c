#include <sched.h>
#include <err.h>

#include "kine.h"

static void set_palette(struct render_state* base, const uint32_t* arr,
			size_t sze) {
	(void) base;
	(void) arr;
	(void) sze;
}

static void swap_frontbuffer(struct render_state* base, uint32_t* arr) {
	(void) base;
	(void) arr;
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
