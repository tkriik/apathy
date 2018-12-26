#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

#include "request.h"

typedef uint64_t session_id_t;
#define PRIuSID PRIu64

struct session_request {
	request_id_t rid;
	uint64_t     ts;
};

/* Session-specific information, stored in a hash table. */
struct session_map_entry {
	session_id_t sid;                       /* Session ID */
	size_t       nrequests;                 /* Number of requests in session */
#define SESSION_MAP_ENTRY_INIT_CAPREQUESTS 8
	size_t       caprequests;               /* Request buffer capacity */
	struct       session_request *requests; /* Request buffer */

	UT_hash_handle hh;
};

#define SESSION_MAP_NBUCKETS    (1 << 16)
#define SESSION_MAP_BUCKET_MASK (SESSION_MAP_NBUCKETS - 1)
struct session_map {
	struct session_map_entry *handles[SESSION_MAP_NBUCKETS];
	pthread_spinlock_t    locks[SESSION_MAP_NBUCKETS];
};

void init_session_map(struct session_map *);
void amend_session_map_entry(struct session_map *, session_id_t, uint64_t ts, request_id_t);

#endif
