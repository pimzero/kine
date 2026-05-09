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

static inline void *_dlopen_or_die(const char *libname, int flags)
{
	void *ret = dlopen(libname, flags);
	if (ret)
		return ret;

	errx(1, "dlopen(%s): %s", libname, dlerror()); \
}

#define _xstr(s) _str(s)
#define _str(s) #s

#define DL_LAZY_SYM(Lib, Sym) \
	"DL_LAZY_sym_" Lib "." Sym
#define DL_LAZY_LIB(Lib) \
	"DL_LAZY_lib_" Lib

#define DL_LAZY_DECL_COMMON(Decl, Symname) \
	__asm__ __volatile__(".comm " Symname ", " \
			     _xstr(__SIZEOF_POINTER__) ", " \
			     _xstr(__SIZEOF_POINTER__) "\n"); \
	extern Decl __asm__(Symname); \

#define DL_LAZY(Lib, X) ({ \
	DL_LAZY_DECL_COMMON(void *_lib,  DL_LAZY_LIB(Lib)); \
	DL_LAZY_DECL_COMMON(__typeof__(X)* _sym_##X,  DL_LAZY_SYM(Lib, #X)); \
	if (!_sym_##X) { \
		if (!_lib) \
			_lib = _dlopen_or_die(Lib, RTLD_LAZY|RTLD_LOCAL); \
		_sym_##X = _dlsym_or_die(_lib, #X); \
	} \
	_sym_##X; \
})

#endif
