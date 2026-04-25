#include <kstd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

static void alloc_all_space(void)
{
	size_t inc = (size_t)(INT_MAX + 1UL);

	while (inc) {
		void *p = sbrk(inc);

		if ((long)p > 0)
			memset(p, 'a', inc);

		inc /= 2;
	}
}


static const char ok[] = "ok\n";
void entry(void)
{
	alloc_all_space();

	swap_frontbuffer(sbrk(0));

	write(ok, sizeof(ok));

	while (1)
		;
}
