#ifndef REQUEST_H
#define REQUEST_H

#include <ck_spinlock.h>
#include <stdint.h>
#include <inttypes.h>

#include "lib/uthash.h"

#include "truncate.h"

typedef uint64_t request_id_t;
#define PRIuRID PRIu64

struct request_info {
	const char *request; /* If this is null, the fields below are set, and vice versa. */
	const char *method;
	const char *protocol;
	const char *domain;
	const char *endpoint;
};

/* Request field data and incremental ID, stored in a hash table. */
struct request_set_entry {
	char         *data;
	uint64_t      hash;
	request_id_t  rid;

	UT_hash_handle hh;
};

struct request_set {
#define REQUEST_SET_NBUCKETS           (1 << 8)
#define REQUEST_SET_BUCKET_MASK        (REQUEST_SET_NBUCKETS - 1)
#define REQUEST_SET_INIT_LIM_NREQUESTS 8
	struct request_set_entry *handles[REQUEST_SET_NBUCKETS];
	ck_spinlock_t             locks[REQUEST_SET_NBUCKETS];
	size_t                    nrequests; /* Unique request count */
#define REQUEST_ID_INVAL UINT64_MAX
#define REQUEST_ID_START 0
	ck_spinlock_t             rid_lock;
	request_id_t              rid_ctr; /* Incremental request ID */
};

/* Mapping from incremental request IDs to request strings. */
struct request_table {
	size_t         nrequests; /* Unique request count */
	const char   **requests;  /* Request ID to string */
	uint64_t      *hashes;    /* Request ID to hash */
};

request_id_t add_request_set_entry(struct request_set *, struct request_info *, struct truncate_patterns *);

void init_request_set(struct request_set *);
void gen_request_table(struct request_table *, struct request_set *);

#endif
