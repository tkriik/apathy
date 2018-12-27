#include <assert.h>
#include <pthread.h>

#include "hash.h"
#include "request.h"
#include "truncate.h"
#include "util.h"

static size_t
init_raw_request_from_src(const char *src, char *raw_buf, size_t raw_size)
{
	/* Compute request field length */
	const char *s = src;
	size_t method_size = strcspn(s, " ");
	s += method_size + 1;
	size_t sep_size = strspn(s, " \t\v");
	s += sep_size + 1;
	size_t url_size = strcspn(s, "?\" \n");

	size_t req_size = method_size + sep_size + url_size + 2;
	if (raw_size < req_size)
		WARNX("truncating request over %zu bytes long", raw_size);
	req_size = MIN(req_size, raw_size);

	memcpy(raw_buf, src, req_size);
	raw_buf[req_size] = '\0';

	return req_size;
}

static size_t
init_raw_request_from_fields(struct request_info *ri, char *raw_buf, size_t raw_size)
{
	assert(ri->method != NULL);
	assert(ri->domain != NULL);
	assert(ri->endpoint != NULL);

	size_t method_size = strcspn(ri->method, " \t");
	size_t sep_size = 1;
	size_t protocol_size = 0;
	size_t protocol_sep_size = 0; /* ":// */
	if (ri->protocol != NULL) {
		protocol_size = strcspn(ri->protocol, " \t");
		protocol_sep_size = 3;
	}
	size_t domain_size = strcspn(ri->domain, " \t");
	size_t endpoint_size = strcspn(ri->endpoint, " \t");

	size_t req_size = method_size + sep_size + protocol_size
	    + protocol_sep_size + domain_size + endpoint_size;
	if (raw_size < req_size)
		WARNX("truncating request over %zu bytes long", raw_size);
	req_size = MIN(req_size, raw_size);

	char *s = raw_buf;
	memcpy(s, ri->method, method_size);
	s += method_size;
	*s++ = ' ';
	if (ri->protocol != NULL) {
		memcpy(s, ri->protocol, protocol_size);
		s += protocol_size;
		memcpy(s, "://", protocol_sep_size);
		s += protocol_sep_size;
	}
	memcpy(s, ri->domain, domain_size);
	s += domain_size;
	memcpy(s, ri->endpoint, endpoint_size);
	s += endpoint_size;

	raw_buf[req_size] = '\0';

	return req_size;
}

/*
 * Stores a request field pointed to by src into the request set rs.
 * Returns a numeric request ID.
 */
request_id_t
add_request_set_entry(struct request_set *rs, struct request_info *ri,
                      struct truncate_patterns *tp)
{
	assert(rs != NULL);
	assert(ri != NULL);
	assert(tp != NULL);

	size_t hash = hash64_init();
	struct request_set_entry **handlep;
	pthread_spinlock_t *bucket_lock;
	struct request_set_entry *entry;

#define REQUEST_LEN_MAX 4096
	char raw_buf[REQUEST_LEN_MAX + 1] = {0};
	size_t req_size = 0;
	if (ri->request != NULL)
		req_size = init_raw_request_from_src(ri->request, raw_buf, sizeof(raw_buf) - 1);
	else
		req_size = init_raw_request_from_fields(ri, raw_buf, sizeof(raw_buf) - 1);

	char trunc_buf[req_size + tp->max_alias_size * REQUEST_NTRUNCS_MAX + 1];
	size_t trunc_size = truncate_raw_request(trunc_buf, sizeof(trunc_buf) - 1,
	    raw_buf, req_size, tp);

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
