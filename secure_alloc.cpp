#include "secure_alloc.h"
#include "co.h"

#ifdef _WIN32
#include <Windows.h>
#elif defined __linux__
#include <unistd.h>
#endif

inline size_t _getpagesize()
{
#ifdef _WIN32
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return si.dwAllocationGranularity;
#elif defined __linux__
	return sysconf(_SC_PAGESIZE);
#endif
}

void* secure_alloc(size_t sz)
{
	size_t pagesize = _getpagesize();
	sz = pagesize * ((sz / pagesize) + 1);
	void* mem = sodium_malloc(sz);
	if (!mem) throw std::bad_alloc();
	sodium_memzero(mem, sz);
	return mem;
}