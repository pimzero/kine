#include <err.h>

#include "kine.h"

static void* k_thread_auto(void* entry) {
	static int check_recursion = 0;

	if (check_recursion)
		return K_THREAD_FAILED_INIT;

	check_recursion = 1;

	for (size_t i = 0; i < module_mode_size(); i++) {
		void* ret = (*module_mode_get(i))(entry);
		if (ret != K_THREAD_FAILED_INIT)
			return ret;
	}

	errx(1, "Unable to find a suitable mode");
}

DEFINE_MODE(auto, k_thread_auto);
