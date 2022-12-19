#pragma once
#pragma once
#include <sys/types.h>
#include <sodium.h>

void* secure_alloc(size_t sz);
#define secure_free sodium_free