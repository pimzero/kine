#ifndef DL_LAZY_H
#define DL_LAZY_H

#include <dlfcn.h>
#include <err.h>

static inline void *_dlsym_or_die(void *handle, const char *symbol)
{
	void *ret = dlsym(handle, symbol);
	if (ret)
		return ret;

	errx(1, "dlsym(%s): %s", symbol, dlerror());
}

#define _xstr(s) _str(s)
#define _str(s) #s

#define DL_LAZY(X, Handle) ({ \
	extern __typeof__(X)* DL_LAZY_sym_##X; \
	__asm__ __volatile__(".comm DL_LAZY_sym_" #X ", " \
			     _xstr(__SIZEOF_POINTER__) ", " \
			     _xstr(__SIZEOF_POINTER__) "\n"); \
	if (!DL_LAZY_sym_##X) \
		DL_LAZY_sym_##X = _dlsym_or_die(Handle, #X); \
	DL_LAZY_sym_##X; \
})

#endif
