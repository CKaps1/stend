#pragma once
#include <system_error>

static int error_condition = 0;

#define co(x) _co(x,#x,__FUNCTION__)
#define ca(x) _ca(x,#x,__FUNCTION__)
#define dynamic_assert(cond) __dynamic_assert(cond,#cond,__FUNCTION__)
#define cb dynamic_assert

#define cleanup(x) __attribute__((__cleanup__(x)))
#define safe_cleanup(type,funct) __attribute__((__cleanup__(safe_do<type,funct>)))


template <typename ty,void (*des)(ty ptr)> inline void safe_do(ty ptr)
{
	if (ptr) des(ptr);
}

template <typename t> inline t _co(t x, const char* line, const char* funct)
{
	using string = std::string;
	if (x < 0) throw std::runtime_error(string("0>") + string(line) + string(" ") + string(funct));
	else return x;
}

template <typename t> inline t _ca(t x, const char* line, const char* funct)
{
	using string = std::string;
	if (x == 0) throw std::runtime_error(string("0==") + string(line) + string(" ") + string(funct));
	else return x;
}

inline void __dynamic_assert(bool cond, const char* msg, const char* funct)
{
	using string = std::string;
	if (!cond) throw std::runtime_error(string(msg) + string(" ") + string(funct));
}

template <typename t> inline void fread_safe(t buf, size_t sz, FILE* file)
{
	dynamic_assert(sz == fread(reinterpret_cast<void*>(buf), 1, sz, file));
}

template <typename t, size_t sz> inline void fread_safe(t(&buf)[sz], FILE* file)
{
	dynamic_assert(sz == fread(reinterpret_cast<void*>(buf), 1, sz, file));
}
