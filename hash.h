#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t hash64_init(void);
uint64_t hash64_update(uint64_t, const char *, size_t);

#endif
