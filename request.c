#include <assert.h>
#include <pthread.h>

#include "hash.h"
#include "request.h"
#include "truncate.h"
#include "util.h"

/*
 * Stores a request field pointed to by src into the request set rs.
 * Returns a numeric request ID.
 */
request_id_t
add_request_set_entry(struct request_set *rs, const char *src,
                      struct truncate_patterns *tp)
{
	assert(src != NULL);

	size_t hash = hash64_init();
	struct request_set_entry **handlep;
	pthread_spinlock_t *bucket_lock;
	struct request_set_entry *entry;

	/* Compute request field length */
	const char *s = src;
	size_t method_size = strcspn(s, " ");
	s += method_size + 1;
	size_t sep_size = strspn(s, " \t\v");
	s += sep_size + 1;
	size_t url_size = strcspn(s, "?\" \n");

	size_t req_len = method_size + sep_size + url_size + 2;

#define REQUEST_LEN_MAX 4096
	if (REQUEST_LEN_MAX < req_len)
		WARNX("truncating request over %d bytes long", REQUEST_LEN_MAX);
	req_len = MIN(req_len, REQUEST_LEN_MAX);

	char raw_buf[req_len + 1];
	memcpy(raw_buf, src, req_len);
	raw_buf[req_len] = '\0';

	char trunc_buf[req_len + tp->max_alias_size * REQUEST_NTRUNCS_MAX + 1];
	size_t trunc_size = truncate_raw_request(trunc_buf, sizeof(trunc_buf) - 1,
	    raw_buf, req_len, tp);

	hash = hash64_update(hash, trunc_buf, trunc_size);
	size_t bucket_idx = hash & REQUEST_SET_BUCKET_MASK;
	handlep = &rs->handles[bucket_idx];
	bucket_lock = &rs->locks[bucket_idx];
	entry = NULL;

	if (pthread_spin_lock(bucket_lock) != 0)
		ERR("%s", "pthread_spin_lock");

	HASH_FIND(hh, *handlep, trunc_buf, trunc_size, entry);
	if (entry != NULL)
		goto finish;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		ERR("%s", "calloc");

	entry->data = calloc(1, trunc_size + 1);
	if (entry->data == NULL)
		ERR("%s", "calloc");
	memcpy((char *)entry->data, trunc_buf, trunc_size);

	if (pthread_spin_lock(&rs->rid_lock) != 0)
		ERR("%s", "pthread_spin_lock");

	entry->hash = hash;
	entry->rid = rs->rid_ctr++;
	if (pthread_spin_unlock(&rs->rid_lock) != 0)
		ERR("%s", "pthread_spin_unlock");

	HASH_ADD_KEYPTR(hh, *handlep, entry->data, trunc_size, entry);
	rs->nrequests++;

finish:
	if (pthread_spin_unlock(bucket_lock) != 0)
		ERR("%s", "pthread_spin_unlock");

	return entry->rid;
}

void
init_request_set(struct request_set *rs)
{
	for (size_t i = 0; i< REQUEST_SET_NBUCKETS; i++) {
		rs->handles[i] = NULL;
		if (pthread_spin_init(&rs->locks[i], PTHREAD_PROCESS_PRIVATE) != 0)
			ERR("%s", "pthread_spin_init");
	}

	if (pthread_spin_init(&rs->rid_lock, PTHREAD_PROCESS_PRIVATE) != 0)
		ERR("%s", "pthread_spin_init");

	rs->nrequests = 0;
	rs->rid_ctr = REQUEST_ID_START;
}

void
gen_request_table(struct request_table *rt, struct request_set *rs)
{
	assert(rt != NULL);
	assert(rs != NULL);

	rt->nrequests = rs->nrequests;
	rt->requests = calloc(rt->nrequests, sizeof(*rt->requests));
	if (rt->requests == NULL)
		ERR("%s", "calloc");

	rt->hashes = calloc(rt->nrequests, sizeof(*rt->hashes));
	if (rt->hashes == NULL)
		ERR("%s", "calloc");

	for (size_t bucket_idx = 0; bucket_idx < REQUEST_SET_NBUCKETS; bucket_idx++) {
		struct request_set_entry *entry, *tmp;
		HASH_ITER(hh, rs->handles[bucket_idx], entry, tmp) {
			request_id_t rid = entry->rid;
			rt->requests[rid] = entry->data;
			rt->hashes[rid] = entry->hash;
		}
	}
}
