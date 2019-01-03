#include <assert.h>
#include <ck_spinlock.h>
#include <pthread.h>

#include "hash.h"
#include "session.h"
#include "util.h"

void
init_session_map(struct session_map *sm)
{
	for (size_t i = 0; i < SESSION_MAP_NBUCKETS; i++) {
		sm->handles[i] = NULL;
		ck_spinlock_init(&sm->locks[i]);
	}
}

/*
 * Creates or modifies a session entry in the session table, with
 * session ID sid as the key. Since multiple threads may be editing
 * the same session entry at different times, the timestamp is used
 * to keep the session request list in order at each modification.
 */
void
amend_session_map_entry(struct session_map *sm, session_id_t sid, uint64_t ts,
                        request_id_t rid)
{
	assert(sm != NULL);

	struct session_map_entry *entry = NULL;

	/* TODO: make sid better distributed */
	size_t bucket_idx = hash64_init();
	bucket_idx = hash64_update(bucket_idx, (void *)&sid, sizeof(sid));
	bucket_idx &= SESSION_MAP_BUCKET_MASK;

	/*
	 * We have to use pointer to a pointer, otherwise the uthash
	 * macros don't work as intended.
	 */
	struct session_map_entry **handlep = &sm->handles[bucket_idx];
	ck_spinlock_t *lock = &sm->locks[bucket_idx];

	ck_spinlock_lock(lock);

	HASH_FIND_INT(*handlep, &sid, entry);
	if (entry == NULL) {
		entry = calloc(1, sizeof(*entry));
		if (entry == NULL)
			ERR("%s", "calloc");
		entry->sid = sid;
		entry->nrequests = 1;
		entry->caprequests = SESSION_MAP_ENTRY_INIT_CAPREQUESTS;
		entry->requests = calloc(SESSION_MAP_ENTRY_INIT_CAPREQUESTS,
		    sizeof(*entry->requests));
		if (entry->requests == NULL)
			ERR("%s", "calloc");

		entry->requests[0].rid = rid;
		entry->requests[0].ts = ts;

		HASH_ADD_INT(*handlep, sid, entry);
		goto finish;
	}

	if (entry->nrequests == entry->caprequests) {
		assert(entry->caprequests < (SIZE_MAX / sizeof(*entry->requests) / 2));

		size_t new_caprequests = 2 * entry->caprequests;
		size_t new_size = new_caprequests * sizeof(*entry->requests);
		struct session_request *new_requests = realloc(entry->requests,
		    new_size);
		if (new_requests == NULL)
			ERR("%s", "realloc");

		entry->caprequests = new_caprequests;
		entry->requests = new_requests;
	}

	size_t r = entry->nrequests;
	entry->requests[r].rid = rid;
	entry->requests[r].ts = ts;
	entry->nrequests++;
finish:
	ck_spinlock_unlock(lock);
}
