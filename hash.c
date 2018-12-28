#include <stddef.h>
#include <string.h>

#include "hash.h"

/*
 * We use the FNV-1a hash algorithm for constructing session IDs
 * due to its simplicity.
 *
 * http://www.isthe.com/chongo/tech/comp/fnv/
 *
 * TODO: use GCC optimization with shifts, inline
 */
#define FNV_PRIME64 1099511628211ULL
#define FNV_BASIS64 14695981039346656037ULL
uint64_t
hash64_init(void)
{
	return FNV_BASIS64;
}

uint64_t
hash64_update(uint64_t hash, const char *s, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		/* TODO: use GCC optimization with shifts */
		hash ^= s[i];
		hash *= FNV_PRIME64;
	}
	return hash;
}

/*
 * Hashes an IP address without the port number.
 */
uint64_t
hash64_update_ipaddr(uint64_t hash, const char *s)
{
	size_t hash_len = strcspn(s, ": \t\n\v\r");
	return hash64_update(hash, s, hash_len);
}
