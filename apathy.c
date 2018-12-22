/*
 * HOW THIS PROGRAM WORKS:
 *
 * -----------------------------------------------------------------------------
 *
 * 1. We map the log file into memory, so that multiple gigabyte sized
 *    log files pose no issues.
 *
 *    - init_log_view()
 *
 * -----------------------------------------------------------------------------
 *
 * 2. We look at the first line to infer indices of fields relevant to us,
 *    such as timestamp, IP addresses, request info (method + URL)
 *    and user agent.
 *
 *    - init_line_config()
 *
 * -----------------------------------------------------------------------------
 *
 * 3. We split the memory area into N chunks, where N is the number of threads
 *    available. By default, we use the number of logical CPU cores as
 *    the thread count.
 *    After the chunks have been divided, we start N worker threads,
 *    each with a context (struct thread_ctx) containing pointers to shared
 *    data, such as log information, line configuration, request and session
 *    tables etc.
 *
 *    - init_work_ctx()
 *
 * -----------------------------------------------------------------------------
 *
 * 4. Each threads scans their respective chunks for lines, from which
 *    they split the line into fields delimited by spaces or double quotes.
 *
 *    - run_thread()
 *
 *    4.1. A session ID (sid) is constructed from one line, which is a 64-bit
 *         hash consisting of one or more of the following fields:
 *           * first IP address (should be source address)
 *           * second IP address (should be destination address)
 *           * user agent
 *
 *         If the log file is from a proxy (such as Cloudfront), it is
 *         recommended to use only the user agent string for identifying
 *         one session, since the IP addresses don't correspond to the
 *         actual origins of a request.
 *         Otherwise it is recommended to use the first or second
 *         IP address (whichever is the source address) plus the user agent,
 *         for more accuracy. This is the default mode.
 *
 *    --------------------------------------------------------------------------
 *
 *    4.2 A truncated copy of the request field, with only method and URL,
 *        is stored in a hash table, for avoiding duplicate storage for
 *        identical requests.
 *        There are multiple hash tables (REQUEST_SET_NBUCKETS),
 *        each with separate locks, in order to reduce lock contention
 *        across multiple threads.
 *
 *          - add_request_set_entry()
 *
 *    --------------------------------------------------------------------------
 *
 *    4.3 A pointer to the copied request field is then added to the
 *        session entry pointed to by sid, unless it does not exist, in which
 *        case it is created. The request is sorted according to its timestamp,
 *        since they may arrive in different order, and it will not be merged
 *        to the session entry if it is a repeated request, in which case
 *        only the repeat count for that request is incremented.
 *        As with request table, there are
 *        multiple hash tables (SESSION_MAP_NBUCKETS) for session entries,
 *        each with separate locks.
 *
 *          - amend_session_map_entry()
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/uthash.h"

#define VERSION "0.1.0"

#define MIN(A, B) ((A) < (B) ? (A) : (B))

#define ERR(fmt, ...) err(1, "error at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define ERRX(fmt, ...) errx(1, "error at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define WARN(fmt, ...) warn("warning at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define WARNX(fmt, ...) warnx("warning at %s:%d (%s): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

struct log_view {
	size_t      len;  /* Size of log file plus one */
	const char *path; /* Path to log file */
	const char *src;  /* Memory-mapped log contents */
};

enum field_type {
	FIELD_TS_RFC3339 = 1,
	FIELD_IPADDR,
	FIELD_REQUEST,
	FIELD_USERAGENT,
	FIELD_UNKNOWN
};

/* Tells what type of field lies at a certain index. */
struct field_idx {
	enum field_type type;
	int  i;
	int  is_session; /* 1 if this field is used to construct session IDs */
};

/*
 * This is used to index certain fields in each line.
 *
 * The program reads the first line of a log file and uses that to
 * infer indices of fields relevant to us, so that when we are doing
 * a full scan we can find the desired fields more quickly.
 *
 * This only works if each line contains the same number of fields in
 * same order, but that should not be a problem with most log files.
 *
 * All of the 5 indices below are -1 if they're not found.
 */
struct line_config {
#define LC_FIELDS_MAX 5
	int    ts_rfc3339; /* Index to RFC3339 timestamp; REQUIRED */
	int    ip1;        /* Index to first IP address;  optional */
	int    ip2;        /* Index to second IP address; optional */
	int    request;    /* Index to request field;     REQUIRED */
	int    useragent;  /* Index to user agent string; optional */
	/*
	 * XXX:
	 * While the IP address fields and user agent fields are optional
	 * individually, it's required to have at least one of the three
	 * to get any meaningful path info out of the log file.
	 */

	int         ntotal_fields;
	int         nfields;
	struct      field_idx indices[LC_FIELDS_MAX + 1];
	const char *sfields;
};

/* Working area for one thread. */
struct thread_chunk {
	size_t      size;
	const char *start;
	const char *end;   /* start + size bytes */
};

typedef size_t request_id_t;

/* Request field data and incremental ID, stored in a hash table. */
struct request_set_entry {
	const char   *data;
	request_id_t  rid;

	UT_hash_handle hh;
};

struct request_set {
#define REQUEST_SET_NBUCKETS           (1 << 8)
#define REQUEST_SET_BUCKET_MASK        (REQUEST_SET_NBUCKETS - 1)
#define REQUEST_SET_INIT_LIM_NREQUESTS 8
	struct request_set_entry *handles[REQUEST_SET_NBUCKETS];
	pthread_spinlock_t        locks[REQUEST_SET_NBUCKETS];
	size_t                    nrequests; /* Unique request count */
#define REQUEST_ID_INVAL UINT64_MAX
#define REQUEST_ID_START 0
	pthread_spinlock_t        rid_lock;
	request_id_t              rid_ctr;    /* Incremental request ID */
};

/* Mapping from incremental request IDs to request strings. */
struct request_table {
	size_t       nrequests; /* Unique request count */
	const char **requests;  /* Mapping from request IDs to strings */
};

typedef uint64_t session_id_t;

/* Session-specific information, stored in a hash table. */
struct session_map_entry {
#define SESSION_MAP_ENTRY_MAX_NREQUESTS 16
	session_id_t sid;       /* Session ID */
	size_t       nrequests; /* Number of requests in session */
	/* Request timestamps */
	uint64_t     timestamps[SESSION_MAP_ENTRY_MAX_NREQUESTS];
	/* Request fields */
	request_id_t requests[SESSION_MAP_ENTRY_MAX_NREQUESTS];

	UT_hash_handle hh;
};

#define SESSION_MAP_NBUCKETS    (1 << 16)
#define SESSION_MAP_BUCKET_MASK (SESSION_MAP_NBUCKETS - 1)
struct session_map {
	struct session_map_entry *handles[SESSION_MAP_NBUCKETS];
	pthread_spinlock_t    locks[SESSION_MAP_NBUCKETS];
};

struct path_graph_edge {
	request_id_t rid;   /* Outward request edge */
	uint64_t     nhits; /* Hits per this edge */
};

/* Path edge information. */
struct path_graph_vertex {
#define PATH_GRAPH_VERTEX_INIT_LIM_NEDGES 8
	request_id_t rid;                    /* Request ID */
	size_t       nedges;                 /* Number of outward edges */
	size_t       lim_nedges;             /* Edge buffer limit */
	struct       path_graph_edge *edges; /* Outward edges */
	uint64_t     total_nhits_in;         /* Total number of hits to this vertex */
	uint64_t     total_nhits_out;        /* Total number of hits from this vertex */
};

const struct path_graph_vertex NULL_VERTEX = {
	.rid             = REQUEST_ID_INVAL,
	.nedges          = 0,
	.lim_nedges      = 0,
	.edges           = NULL,
	.total_nhits_in  = 0,
	.total_nhits_out = 0
};

struct path_graph {
	size_t total_nedges;                /* Total number of unique path edges */
	size_t nvertices;                   /* Number of vertices */
	size_t capvertices;                 /* Vertex buffer capacity */
	struct path_graph_vertex *vertices; /* Vertex buffer */
};

/* Thread-specific context. */
struct thread_ctx {
	int    id;

	struct log_view *log_view;
	struct line_config *line_config;
	struct thread_chunk chunk;
	struct request_set *request_set;
	struct session_map *session_map;
};

/*
 * These patterns are deliberately liberal, since we don't use them in
 * any strict way.
 */
struct regex_info {
#define RFC3339_PATTERN   "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
#define IPV4_PATTERN      "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
#define REQUEST_PATTERN   "(GET|HEAD|POST|PUT|OPTIONS|PATCH)\\s+(http|https)://.+"
#define USERAGENT_PATTERN "Mozilla.+"
	regex_t rfc3339;
	regex_t ipv4;
	regex_t request;
	regex_t useragent;
};

/*
 * Work context with all threads.
 * We limit threads to 4096 to avoid memory allocation.
 */
struct work_ctx {
#define NTHREADS_DEFAULT   4
#define NTHREADS_MAX       4096
	int       nthreads;
	pthread_t thread[NTHREADS_MAX];
	struct    thread_ctx thread_ctx[NTHREADS_MAX];
};

/*
 * View to a single field in a line.
 * We limit field views to 256 to avoid memory allocation.
 */
struct field_view {
#define NFIELDS_MAX 256
	int         len;
	const char *src;
};

void debug_request_set(struct request_set *);
void debug_request_table(struct request_table *);
void debug_session_map(struct session_map *);
void debug_path_graph(struct path_graph *);
void usage(void);

void *
mmap_file(const char *path, size_t *sizep)
{
	assert(path != NULL);
	assert(sizep != NULL);

	struct stat sb;

	int fd = open(path, O_RDONLY);
	if (fd == -1)
		ERR( "failed to open file at '%s'", path);

	if (fstat(fd, &sb) == -1)
		ERR( "failed to read file status for %s", path);

	*sizep = (size_t)sb.st_size;
	void *p = mmap(NULL, (size_t)sb.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		ERR("failed to map %s into memory", path);

	return p;
}

void
compile_regex(regex_t *preg, const char *pattern)
{
	assert(preg != NULL);
	assert(pattern != NULL);

	int rc;
	char errbuf[256] = {0};

	rc = regcomp(preg, pattern, REG_EXTENDED | REG_NOSUB);
	if (rc != 0) {
		regerror(rc, preg, errbuf, sizeof(errbuf));
		ERRX("failed to compile regex '%s': %s", RFC3339_PATTERN,
		    errbuf);
	}
}

/*
 * Fills *fvs with at most max_fields number of field views
 * found in *src, and stores the end of seeking area to **endp,
 * or NULL if a '\0' is reached.
 *
 * If skip_line_seek is true, we assume we are at the beginning
 * of a line. Otherwise we skip to the next line before
 * parsing field views.
 *
 * Currently parses standalone fields, such as '1 2 3' into "1", "2" and "3",
 * and double-quoted fields, so that '"GET http://my-api/"' is read as
 * "GET http://my-api/" instead of '"GET' and 'http://my-api/"'.
 *
 * Returns the number of fields found.
 *
 * TODO: use strspn(3), strcspn(3)
 */
int
get_fields(struct field_view *fvs, int max_fields, const char *src,
           int skip_line_seek, const char **endp)
{
	assert(fvs != NULL);
	assert(0 < max_fields);
	assert(src != NULL);
	assert(endp != NULL);

	enum {
		FIELD_SEEK,
		FIELD_STANDALONE,
		FIELD_DOUBLE_QUOTED
	} state = FIELD_SEEK;

	char c;
	int nfields = 0;
	int i = 0;

	if (skip_line_seek)
		goto fill_fields;

	while (1) {
		c = *src++;
		if (c == '\n' || c == '\0')
			break;
	}


fill_fields:
	while (1) {
		if (nfields == max_fields) {
			*endp = src;
			return nfields;
		}

		struct field_view *fv = &fvs[i];
		c = *src;

		switch (state) {
		case FIELD_SEEK:
			switch (c) {
			case '\0':
				*endp = NULL;
				return nfields;
			case '\n':
				*endp = src;
				return nfields;
			case '\v':
			case '\t':
			case ' ':
				src++;
				continue;
			case '"':
				src++;
				fv->len = 0;
				fv->src = src;
				nfields++;
				state = FIELD_DOUBLE_QUOTED;
				continue;
			default:
				fv->len = 1;
				fv->src = src;
				nfields++;
				src++;
				state = FIELD_STANDALONE;
				continue;
			}
		case FIELD_STANDALONE:
			switch (c) {
			case '\v':
			case '\t':
			case ' ':
				i++;
				src++;
				state = FIELD_SEEK;
				continue;
			case '\0':
				*endp = NULL;
				return nfields;
			case '\n':
				*endp = src;
				return nfields;
			default:
				fv->len++;
				src++;
				continue;
			}
		case FIELD_DOUBLE_QUOTED:
			switch (c) {
			case '\0':
				*endp = NULL;
				return nfields;
			case '\n':
				*endp = src;
				return nfields;
			case '"':
				i++;
				src++;
				state = FIELD_SEEK;
				continue;
			default:
				fv->len++;
				src++;
				continue;
			}
		}
	}
}

void
init_log_view(struct log_view *ctx, const char *path)
{
	ctx->src = mmap_file(path, &ctx->len);
	ctx->path = path;
}

void
init_regex_info(struct regex_info *rx_info)
{
	assert(rx_info != NULL);

	compile_regex(&rx_info->rfc3339, RFC3339_PATTERN);
	compile_regex(&rx_info->ipv4, IPV4_PATTERN);
	compile_regex(&rx_info->request, REQUEST_PATTERN);
	compile_regex(&rx_info->useragent, USERAGENT_PATTERN);
}

int
regex_does_match(regex_t *preg, const char *s)
{
	regmatch_t pmatch[1];
	return regexec(preg, s, 1, pmatch, 0) == 0;
}

enum field_type
infer_field_type(struct field_view *fv, struct regex_info *rx_info)
{
#define FIELD_MAX 4096
	char field[FIELD_MAX + 1] = {0};
	int ncopy = MIN(fv->len, FIELD_MAX);
	memcpy(field, fv->src, ncopy);

	if (regex_does_match(&rx_info->rfc3339, field))
		return FIELD_TS_RFC3339;

	if (regex_does_match(&rx_info->ipv4, field))
		return FIELD_IPADDR;

	if (regex_does_match(&rx_info->request, field))
		return FIELD_REQUEST;

	if (regex_does_match(&rx_info->useragent, field))
		return FIELD_USERAGENT;

	return FIELD_UNKNOWN;
}

void
amend_line_config(struct line_config *lc, enum field_type ftype, int idx)
{
	if (LC_FIELDS_MAX <= lc->nfields)
		return;

	int is_session = 0;;

	switch (ftype) {
	case FIELD_TS_RFC3339:
		if (lc->ts_rfc3339 == -1)
			lc->ts_rfc3339 = idx;
		else
			return;
		break;
	case FIELD_IPADDR:
		if (lc->ip1 == -1) {
			lc->ip1 = idx;
			if (strstr(lc->sfields, "ip1") != NULL)
				is_session = 1;
		} else if (lc->ip2 == -1) {
			lc->ip2 = idx;
			if (strstr(lc->sfields, "ip2") != NULL)
				is_session = 1;
		} else
			return;
		break;
	case FIELD_REQUEST:
		if (lc->request == -1)
			lc->request = idx;
		else
			return;
		break;
	case FIELD_USERAGENT:
		if (lc->useragent == -1) {
			lc->useragent = idx;
			if (strstr(lc->sfields, "useragent") != NULL)
				is_session = 1;
		} else
			return;
		break;
	default:
		return;
	}

	lc->indices[lc->nfields] = (struct field_idx){
		.type       = ftype,
		.i          = idx,
		.is_session = is_session
	};
	lc->nfields++;
}

void
check_line_config(struct line_config *lc)
{
	if (lc->ip1 == -1 || lc->ip2 == -1)
		WARNX("%s", "source and/or destination IP address fields not found");
	if (lc->useragent == -1)
		WARNX("%s", "user agent field not found");
	if (lc->ts_rfc3339 == -1)
		ERRX("%s", "timestamp field not found");
	if (lc->request == -1)
		ERRX("%s", "request field not found");
	if (lc->ip1 == -1 && lc->ip2 == -1 && lc->useragent == -1)
		ERRX("%s", "source IP address, destination IP address nor user agent field found");
}

/*
 * Convert RFC3339 timestamp to an roughly estimated number of milliseconds.
 *
 * We don't need accurate timekeeping since we are only
 * concerned with average durations between path transitions, so
 * we can take this faster shortcut with manual parsing.
 */
uint64_t
ts_rfc3339_to_ms(const char *s)
{
	static const char ctoi[256] = {
	    ['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3, ['4'] = 4,
	    ['5'] = 5, ['6'] = 6, ['7'] = 7, ['8'] = 8, ['9'] = 9
	};

	uint64_t year = (ctoi[(int)s[0]] * 1000
	              +  ctoi[(int)s[1]] * 100
	              +  ctoi[(int)s[2]] * 10
	              +  ctoi[(int)s[3]])
	              - 1970;
	s += 5; // Skip '-'
	uint64_t month = ctoi[(int)s[0]] * 10
	               + ctoi[(int)s[1]];
	s += 3; // Skip '-'
	uint64_t day = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 3; // Skip 'T'
	uint64_t hour = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 3; // Skip ':'
	uint64_t min = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 3; // Skip ':'
	uint64_t sec = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 3; // Skip '.'
	uint64_t ms = ctoi[(int)s[0]] * 100
	            + ctoi[(int)s[1]] * 10
	            + ctoi[(int)s[2]];

#define MS_IN_YEAR  31104000000ULL
#define MS_IN_MONTH 2592000000ULL
#define MS_IN_DAY   86400000ULL
#define MS_IN_HOUR  3600000ULL
#define MS_IN_MIN   60000ULL
#define MS_IN_SEC   1000ULL
	return year  * MS_IN_YEAR
	     + month * MS_IN_MONTH
	     + day   * MS_IN_DAY
	     + hour  * MS_IN_HOUR
	     + min   * MS_IN_MIN
	     + sec   * MS_IN_SEC
	     + ms;
}

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

uint64_t
hash64_update_char(uint64_t hash, char c)
{
	return (hash ^ c) * FNV_PRIME64;
}

/*
 * Stores a request field pointed to by src into the request set rs.
 * Returns a numeric request ID.
 */
request_id_t
add_request_set_entry(struct request_set *rs, const char *src)
{
	assert(src != NULL);

	size_t bucket_idx = hash64_init();
	struct request_set_entry **handlep;
	pthread_spinlock_t *bucket_lock;
	struct request_set_entry *entry;

	int rc;
	const char *s = src;
	int req_len = 0;
	int spaces_remaining = 2;
	while (0 < spaces_remaining) {
		char c = *s++;
		switch (c) {
		case ' ':
			spaces_remaining--;
			break;
		case '?':
		case '"':
			req_len++;
			goto effective_req;
		case '\0':
		case '\n':
		case '\v':
		case '\t':
			ERRX("unexpected whitespace or null terminator after request field: '%.*s'",
			     req_len + 1, s);
			/* NOTREACHED */
			break;
		default:
			bucket_idx = hash64_update_char(bucket_idx, c);
			req_len++;
			break;
		}
	}

effective_req:
	bucket_idx &= REQUEST_SET_BUCKET_MASK;
	handlep = &rs->handles[bucket_idx];
	bucket_lock = &rs->locks[bucket_idx];
	entry = NULL;

	rc = pthread_spin_lock(bucket_lock);
	if (rc != 0)
		ERR("%s", "pthread_spin_lock");

	HASH_FIND(hh, *handlep, src, req_len, entry);
	if (entry != NULL)
		goto finish;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		ERR("%s", "calloc");

	entry->data = calloc(1, req_len + 1);
	if (entry->data == NULL)
		ERR("%s", "calloc");
	memcpy((char *)entry->data, src, req_len);

	if (pthread_spin_lock(&rs->rid_lock) != 0)
		ERR("%s", "pthread_spin_lock");

	entry->rid = rs->rid_ctr++;
	if (pthread_spin_unlock(&rs->rid_lock) != 0)
		ERR("%s", "pthread_spin_unlock");

	HASH_ADD_KEYPTR(hh, *handlep, entry->data, req_len, entry);
	rs->nrequests++;

finish:
	rc = pthread_spin_unlock(bucket_lock);
	if (rc != 0)
		ERR("%s", "pthread_spin_unlock");

	return entry->rid;
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

	int rc;
	int i;
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
	pthread_spinlock_t *lock = &sm->locks[bucket_idx];

	rc = pthread_spin_lock(lock);
	if (rc != 0)
		ERR("%s", "pthread_spin_lock");

	HASH_FIND_INT(*handlep, &sid, entry);
	if (entry != NULL) {
		if (entry->nrequests == SESSION_MAP_ENTRY_MAX_NREQUESTS)
			goto finish;
		else
			goto amend;
	}

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		ERR("%s", "calloc");
	entry->sid = sid;
	entry->nrequests = 0;

	HASH_ADD_INT(*handlep, sid, entry);
amend:
	i = entry->nrequests;
	if (i == 0)
		goto first;

	/* Rewind index to sorted timestamp position. */
	for (; 0 < i && ts < entry->timestamps[i - 1]; i--);

	/*
	 * Check if request at previous or current index is identical;
	 * if yes, increment repeat count accordingly.
	 * */
	if (entry->requests[i - 1] == rid)
		goto finish;
	if (entry->requests[i] == rid)
		goto finish;

	/*
	 * Shift the more recent requests up one index
	 * to make room for the current request.
	 */
	int nmove = entry->nrequests - i;
	memmove(&entry->timestamps[i + 1], &entry->timestamps[i],
	    nmove * sizeof(entry->timestamps[0]));
	memmove(&entry->requests[i + 1], &entry->requests[i],
	    nmove * sizeof(entry->requests[0]));
first:
	entry->requests[i] = rid;
	entry->timestamps[i] = ts;
	entry->nrequests++;
finish:
	rc = pthread_spin_unlock(lock);
	if (rc != 0)
		ERR("%s", "pthread_spin_unlock");
}

void *
run_thread(void *ctx)
{
	assert(ctx != NULL);

	struct thread_ctx *thread_ctx = ctx;
	struct log_view *log_view = thread_ctx->log_view;
	const char *src = thread_ctx->chunk.start;
	struct line_config *lc = thread_ctx->line_config;
	struct request_set *rs = thread_ctx->request_set;
	struct session_map *sm = thread_ctx->session_map;

	while (1) {
		if (thread_ctx->chunk.end <= src || src == NULL)
			break;

		int skip_line_seek = log_view->src == src;
		struct field_view fvs[NFIELDS_MAX] = {0};

		int nfields = get_fields(fvs, NFIELDS_MAX, src, skip_line_seek, &src);
		if (nfields != lc->ntotal_fields)
			continue;

		uint64_t ts = 0;
		session_id_t sid = hash64_init();
		request_id_t rid;

		for (int i = 0; i < lc->nfields; i++) {
			struct field_idx *fidx = &lc->indices[i];
			struct field_view *fv = &fvs[fidx->i];

			if (fidx->is_session)
				sid = hash64_update(sid, fv->src, fv->len);

			switch (fidx->type) {
			case FIELD_TS_RFC3339:
				ts = ts_rfc3339_to_ms(fv->src);
				break;
			case FIELD_REQUEST:
				rid = add_request_set_entry(rs, fv->src);
				break;
			default:
				break;
			}
		}

		amend_session_map_entry(sm, sid, ts, rid);
	} 

	pthread_exit(NULL);
}

void
init_line_config(struct line_config *lc, struct log_view *log_view,
		 struct regex_info *rx_info, const char *session_fields)
{
	assert(lc != NULL);
	assert(log_view != NULL);
	assert(rx_info != NULL);

	const char *src = log_view->src;

	memset(lc, 0, sizeof(*lc));
	*lc = (struct line_config){
		.ts_rfc3339    = -1,
		.ip1           = -1,
		.ip2           = -1,
		.request       = -1,
		.useragent     = -1,

		.ntotal_fields =  0,
		.nfields       =  0,
		.sfields       = session_fields
	};

	struct field_view fvs[NFIELDS_MAX] = {0};
	const char *endp;
	int nfields = get_fields(fvs, NFIELDS_MAX, src, 1, &endp);
	lc->ntotal_fields = nfields;
	for (int i = 0; i < nfields; i++) {
		struct field_view *fv = &fvs[i];
		enum field_type ftype = infer_field_type(fv, rx_info);
		amend_line_config(lc, ftype, i);
	}
	
	check_line_config(lc);
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
init_session_map(struct session_map *sm)
{
	for (size_t i = 0; i < SESSION_MAP_NBUCKETS; i++) {
		sm->handles[i] = NULL;
		if (pthread_spin_init(&sm->locks[i], PTHREAD_PROCESS_PRIVATE) != 0)
			ERR("%s", "pthread_spin_init");
	}
}

void
init_path_graph(struct path_graph *pg, struct request_table *rt)
{
	assert(pg != NULL);
	assert(rt != NULL);

	pg->total_nedges = 0;
	pg->nvertices = 0;
	pg->capvertices = rt->nrequests;
	pg->vertices = calloc(pg->capvertices, sizeof(*pg->vertices));
	if (pg->vertices == NULL)
		ERR("%s", "calloc");

	for (size_t v = 0; v < pg->capvertices; v++)
		pg->vertices[v] = NULL_VERTEX;
}

void
init_work_ctx(struct work_ctx *work_ctx, int nthreads, struct log_view *log_view,
              struct line_config *lc, struct request_set *rs,
	      struct session_map *sm)
{
	assert(work_ctx != NULL);
	assert(log_view != NULL);
	assert(lc != NULL);
	assert(rs != NULL);
	assert(sm != NULL);

	int rc;

#define MT_THRESHOLD (4 * 1024 * 1024)
	/* If log size is under MT_THRESHOLD, use one thread. */
	if (log_view->len < MT_THRESHOLD)
		nthreads = 1;
	else if (nthreads == -1) {
		nthreads = 1;
		/* TODO: uncomment this when multithreading is deterministic
		 * nthreads = sysconf(_SC_NPROCESSORS_CONF);
		 * if (nthreads == -1) {
		 * 	warn("failed to read CPU core count, using %d threads by default",
		 * 	     NTHREADS_DEFAULT);
		 * 	nthreads = NTHREADS_DEFAULT;
		 * }
		 */
	}

	if (nthreads > NTHREADS_MAX)
		ERRX("thread count must be under %d", NTHREADS_MAX);

	assert(0 < nthreads && nthreads <= NTHREADS_MAX);

	work_ctx->nthreads = nthreads;

	size_t chunk_size = log_view->len / nthreads;
	size_t chunk_rem = log_view->len % nthreads;
	for (int tid = 0; tid < nthreads; tid++) {
		size_t start_offset;
		size_t end_offset;
		struct thread_ctx *thread_ctx;

		start_offset = tid * chunk_size;
		if (tid < nthreads - 1)
			end_offset = start_offset + chunk_size;
		else
			end_offset = start_offset + chunk_size + chunk_rem;

		thread_ctx = &work_ctx->thread_ctx[tid];

		thread_ctx->log_view    = log_view;
		thread_ctx->line_config = lc;
		thread_ctx->id          = tid;
		thread_ctx->chunk.start = log_view->src + start_offset;
		thread_ctx->chunk.end   = log_view->src + end_offset;
		thread_ctx->chunk.size  = end_offset - start_offset;
		thread_ctx->request_set = rs;
		thread_ctx->session_map = sm;

		rc = pthread_create(&work_ctx->thread[tid], NULL, run_thread,
		                    (void *)thread_ctx);
		if (rc != 0)
			ERR("%s", "pthread_create");
	}
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

	for (size_t bucket_idx = 0; bucket_idx < REQUEST_SET_NBUCKETS; bucket_idx++) {
		struct request_set_entry *entry, *tmp;
		HASH_ITER(hh, rs->handles[bucket_idx], entry, tmp) {
			rt->requests[entry->rid] = entry->data;
		}
	}
}

int
is_null_vertex(struct path_graph_vertex *v)
{
	assert(v != NULL);
	return v->rid == REQUEST_ID_INVAL;
}

void
amend_path_graph_vertex(struct path_graph *pg, request_id_t rid, request_id_t edge_rid)
{
	assert(pg != NULL);
	assert(rid != REQUEST_ID_INVAL);

	struct path_graph_edge *edge;
	struct path_graph_vertex *vertex = &pg->vertices[rid];

	if (is_null_vertex(vertex)) {
		vertex->rid = rid;
		vertex->edges = calloc(PATH_GRAPH_VERTEX_INIT_LIM_NEDGES, sizeof(*vertex->edges));
		if (vertex->edges == NULL)
			ERR("%s", "calloc");
		vertex->lim_nedges = PATH_GRAPH_VERTEX_INIT_LIM_NEDGES;

		if (edge_rid != REQUEST_ID_INVAL) {
			edge = &vertex->edges[0];
			edge->rid = edge_rid;
			edge->nhits = 1;
			vertex->nedges = 1;
			vertex->total_nhits_out++;
			pg->total_nedges++;
		}

		vertex->total_nhits_in++;
		pg->nvertices++;

		return;
	}

	vertex->total_nhits_in++;

	if (edge_rid == REQUEST_ID_INVAL)
		return;

	/* See if edge request already exists, if yes, increment hit count */
	size_t edge_idx;
	for (edge_idx = 0; edge_idx < vertex->nedges; edge_idx++) {
		edge = &vertex->edges[edge_idx];
		if (edge->rid == edge_rid) {
			edge->nhits++;
			vertex->total_nhits_out++;
			return;
		}
	}

	/* Resize edge buffer if needed */
	if (vertex->nedges == vertex->lim_nedges) {
		size_t new_lim = vertex->lim_nedges * 2;
		/* TODO: overflow check */
		size_t new_size = new_lim * sizeof(*vertex->edges);
		struct path_graph_edge *new_edges = realloc(vertex->edges, new_size);
		if (new_edges == NULL)
			ERR("%s", "realloc");
		vertex->edges = new_edges;
		vertex->lim_nedges = new_lim;
	}

	/* Set new edge at this point */
	edge_idx = vertex->nedges;
	edge = &vertex->edges[edge_idx];
	edge->rid = edge_rid;
	edge->nhits = 1;
	vertex->nedges++;
	vertex->total_nhits_out++;
	pg->total_nedges++;
}

int
cmp_path_graph_edge(const void *p1, const void *p2)
{
	assert(p1 != NULL);
	assert(p2 != NULL);

	const struct path_graph_edge *e1 = p1;
	const struct path_graph_edge *e2 = p2;

	return e1->nhits < e2->nhits;
}

void
gen_path_graph(struct path_graph *pg, struct request_set *rs,
               struct session_map *sm)
{
	assert(pg != NULL);
	assert(rs != NULL);
	assert(sm != NULL);

	/* Generate request path edges */
	for (size_t bucket_idx = 0; bucket_idx < SESSION_MAP_NBUCKETS;
	     bucket_idx++) {
		struct session_map_entry *entry, *tmp;
		HASH_ITER(hh, sm->handles[bucket_idx], entry, tmp) {
			for (size_t request_idx = 0, edge_idx = 1;
			     request_idx < entry->nrequests;
			     request_idx++, edge_idx++) {
				request_id_t rid = entry->requests[request_idx];
				request_id_t edge_rid = edge_idx < entry->nrequests
				                      ? entry->requests[edge_idx]
						      : REQUEST_ID_INVAL;
				amend_path_graph_vertex(pg, rid, edge_rid);
			}
		}
	}
}

void
output_dot_graph(FILE *out, struct path_graph *pg, struct request_table *rt)
{
	assert(out != NULL);
	assert(pg != NULL);
	assert(rt != NULL);

	struct path_graph_vertex *vertex;
	request_id_t rid;
	const char *request_data;

	fprintf(out, "digraph apathy_graph {\n");

	/* Declare nodes with labels */
	for (size_t v = 0; v < pg->capvertices; v++) {
		vertex = &pg->vertices[v];
		if (is_null_vertex(vertex))
			continue;

		rid = vertex->rid;
		request_data = rt->requests[rid];
		fprintf(out,
"  r%" PRIu64 " [label=\"%s\\n(%" PRIu64 " hits in, %" PRIu64 " hits out)\"];\n",
		    rid, request_data, vertex->total_nhits_in, vertex->total_nhits_out);
	}

	fprintf(out, "\n");

	/* Link nodes */
	for (size_t v = 0; v < pg->capvertices; v++) {
		vertex = &pg->vertices[v];
		if (is_null_vertex(vertex))
			continue;

		rid = vertex->rid;
		for (size_t e = 0; e < vertex->nedges; e++) {
			struct path_graph_edge *edge = &vertex->edges[e];
			fprintf(out,
"  r%" PRIu64 " -> r%" PRIu64 " [xlabel=\"%" PRIu64 "\"];\n",
			    rid, edge->rid, edge->nhits);
		}
	}

	fprintf(out, "}\n");
}

void
finish_work_ctx(struct work_ctx *work_ctx)
{
	for (int tid = 0; tid < work_ctx->nthreads; tid++) {
		int rc = pthread_join(work_ctx->thread[tid], NULL);
		if (rc != 0)
			ERR("%s", "pthread_join");
	}
}

void
validate_session_fields(const char *session_fields)
{
	char buf[64] = {0};
	int ncopy = MIN(strlen(session_fields), sizeof(buf) - 1);
	memcpy(buf, session_fields, ncopy);
	char *s = buf;
	char *endp = s;
	while ((s = strtok(endp, ",")) != NULL) {
		endp = NULL;
		if (strcmp(s, "ip1") == 0)
			continue;
		if (strcmp(s, "ip2") == 0)
			continue;
		if (strcmp(s, "useragent") == 0)
			continue;
		errx(1, "error: invalid session field: %s\n", s);
	}
}

int
main(int argc, char **argv)
{
	//char *ignore_patterns = NULL;
	//char *merge_patterns  = NULL;
	const char *session_fields = "ip1,useragent";
	long nthreads = -1;

	struct log_view log_view;
	struct regex_info rx_info;
	struct line_config lc;
	struct request_set rs;
	struct request_table rt;
	struct session_map sm;
	struct work_ctx work_ctx;

	/* Post-processing data */
	struct path_graph pg;

	const char *output_path = "-";
	const char *output_format = "dot-graph";
	FILE *out = stdout;

	while (1) {
		int opt_idx = 0;
		static struct option long_opts[] = {
			{"format",          required_argument, 0, 'f' },
			{"help",            no_argument,       0, 'h' },
			{"ignore-patterns", required_argument, 0, 'I' },
			{"merge-patterns",  required_argument, 0, 'M' },
			{"output",          required_argument, 0, 'o' },
			{"session",         required_argument, 0, 'S' },
			{"threads",         required_argument, 0, 'T' },
			{"version",         no_argument,       0, 'V' },
			{0,                 0,                 0,  0  }
		};

		int c = getopt_long(argc, argv, "f:hI:M:o:S:T:V", long_opts, &opt_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			if (strcmp(optarg, "dot-graph") == 0)
				output_format = optarg;
			else
				ERRX("invalid output format: %s", optarg);
			break;
		case 'h':
			usage();
			break;

		case 'I':
			//ignore_patterns = optarg;
			break;

		case 'M':
			//merge_patterns = optarg;
			break;
		case 'o':
			output_path = optarg;
			if (strcmp(output_path, "-") != 0) {
				out = fopen(output_path, "w");
				if (out == NULL)
					ERR("failed to create output file at '%s'", output_path);
			}
			break;
		case 'S':
			session_fields = optarg;
			validate_session_fields(session_fields);
			break;
		case 'T':
			nthreads = strtol(optarg, NULL, 10);
			if (nthreads == 0
		         || nthreads > INT_MAX
			 || nthreads < INT_MIN)
				ERRX("invalid thread count: %s", optarg);
			break;

		case 'V':
			printf("%s\n", VERSION);
			break;

		default:
			return 1;
		};
	}

	argc -= optind;
	argv += optind;
	if (argc == 0)
		ERRX("%s", "missing access log");
	if (argc > 1)
		ERRX("%s", "only one access log allowed");

	init_log_view(&log_view, argv[0]);
	init_regex_info(&rx_info);
	init_line_config(&lc, &log_view, &rx_info, session_fields);
	init_request_set(&rs);
	init_session_map(&sm);

	/* Start worker threads */
	init_work_ctx(&work_ctx, nthreads, &log_view, &lc, &rs, &sm);

	/* Wait for worker threads to finish */
	finish_work_ctx(&work_ctx);

	/* Do post-processing */
	gen_request_table(&rt, &rs);
	init_path_graph(&pg, &rt);
	gen_path_graph(&pg, &rs, &sm);

	/* DEBUG */
	//debug_request_set(&rs);
	//debug_request_table(&rt);
	//debug_session_map(&sm);
	//debug_path_graph(&pg);

	/* Write output */
	if (strcmp(output_format, "dot-graph") == 0)
		output_dot_graph(out, &pg, &rt);
	else
		ERRX("invalid output format: %s", output_format);

	return 0;
}

void
usage(void)
{
	fprintf(stderr,
"apathy %s\n"
"Access log path analyzer\n"
"\n"
"    apathy [OPTIONS] <ACCESS_LOG>\n"
"\n"
"FLAGS:\n"
"    -h, --help       Prints help information\n"
"    -V, --version    Prints version information\n"
"\n"
"OPTIONS:\n"
"    -I, --ignore-patterns <pattern_file>    File containing URL patterns for ignoring HTTP requests\n"
"    -M, --merge-patterns <pattern_file>     File containing URL patterns for merging HTTP requests\n"
"\n"
"    -o, --output <output_file>              File for output\n"
"                                              default: \"-\" (standard output)\n"
"\n"
"    -S, --session <session_fields>          Comma-separated fields used to construct a session ID for a request\n"
"                                              available fields: ip1,ip2,useragent\n"
"                                              default: ip1,useragent\n"
"\n"
"    -T, --threads <num_threads>             Number of worker threads\n"
"                                              default: number of logical CPU cores, or 4 as a fallback\n"
"\n"
"ARGUMENTS:\n"
"    <ACCESS_LOG>    Access log file containing HTTP request timestamps, IP addresses, methods, URLs and User Agent headers\n",
	    VERSION);
	exit(EXIT_FAILURE);
}

void
debug_request_set(struct request_set *rs)
{
	printf("----- BEGIN REQUEST SET -----\n");
	uint64_t min_bucket_count = HASH_COUNT(rs->handles[0]);
	uint64_t max_bucket_count = HASH_COUNT(rs->handles[0]);
	uint64_t total_count = 0;
	for (size_t i = 1; i < REQUEST_SET_NBUCKETS; i++) {
		size_t bucket_count = HASH_COUNT(rs->handles[i]);
		total_count += bucket_count;
		if (bucket_count < min_bucket_count)
			min_bucket_count = bucket_count;
		if (max_bucket_count < bucket_count)
			max_bucket_count = bucket_count;
	}
	printf("min_bucket_count: %" PRIu64 "\n", min_bucket_count);
	printf("max_bucket_count: %" PRIu64 "\n", max_bucket_count);
	printf("avg_bucket_count: %lf\n", (double)total_count / REQUEST_SET_NBUCKETS);
	printf("total_count: %" PRIu64 "\n", total_count);
	for (size_t i = 0; i < REQUEST_SET_NBUCKETS; i++) {
		struct request_set_entry *entry, *tmp;
		HASH_ITER(hh, rs->handles[i], entry, tmp) {
			printf("%5" PRIu64 " %p \"%s\"\n", entry->rid, entry->data, entry->data);
		}
	}
	printf("----- END REQUEST SET -----\n");
}

void
debug_request_table(struct request_table *rt)
{
	printf("----- BEGIN REQUEST TABLE -----\n");
	for (size_t i = REQUEST_ID_START; i < rt->nrequests; i++)
		printf("%-5zu %p \"%s\"\n", i, rt->requests[i], rt->requests[i]);
	printf("----- END REQUEST TABLE -----\n");
}

void
debug_session_map(struct session_map *sm)
{
	printf("----- BEGIN SESSION MAP -----\n");
	uint64_t min_bucket_count = HASH_COUNT(sm->handles[0]);
	uint64_t max_bucket_count = HASH_COUNT(sm->handles[0]);
	uint64_t total_count = 0;
	for (size_t i = 1; i < SESSION_MAP_NBUCKETS; i++) {
		size_t bucket_count = HASH_COUNT(sm->handles[i]);
		total_count += bucket_count;
		if (bucket_count < min_bucket_count)
			min_bucket_count = bucket_count;
		if (max_bucket_count < bucket_count)
			max_bucket_count = bucket_count;
	}
	printf("min_bucket_count: %" PRIu64 "\n", min_bucket_count);
	printf("max_bucket_count: %" PRIu64 "\n", max_bucket_count);
	printf("avg_bucket_count: %lf\n", (double)total_count / SESSION_MAP_NBUCKETS);
	printf("total_count: %" PRIu64 "\n", total_count);
	size_t session_idx = 0;
	for (size_t bucket_idx = 0; bucket_idx < SESSION_MAP_NBUCKETS; bucket_idx++) {
		struct session_map_entry *entry, *tmp;
		HASH_ITER(hh, sm->handles[bucket_idx], entry, tmp) {
			printf("[%zu]:\n", session_idx);
			printf("    sid: %016" PRIx64 "\n", entry->sid);
			printf("    nrequests: %zu\n", entry->nrequests);
			printf("    requests: %p\n", entry->requests);
			for (size_t i = 0; i < entry->nrequests; i++) {
				printf("        %" PRIu64 " %" PRIu64 "\n",
				       entry->timestamps[i] / 1000, entry->requests[i]);
			}
			session_idx++;
		}
	}
	printf("----- END SESSION MAP -----\n");
}

void
debug_path_graph(struct path_graph *pg)
{
	printf("----- BEGIN PATH GRAPH -----\n");
	printf("total_nedges: %zu\n", pg->total_nedges);
	printf("nvertices: %zu\n", pg->nvertices);
	printf("vertices:\n");
	for (size_t v = 0; v < pg->capvertices; v++) {
		struct path_graph_vertex *vertex = &pg->vertices[v];
		if (is_null_vertex(vertex))
			continue;
		printf("    [%zu]:\n", v);
		printf("        rid: %" PRIu64 "\n", vertex->rid);
		printf("        nedges: %zu\n", vertex->nedges);
		printf("        lim_nedges: %zu\n", vertex->lim_nedges);
		printf("        edges: %p\n", vertex->edges);
		for (size_t e = 0; e < vertex->nedges; e++) {
			struct path_graph_edge *edge = &vertex->edges[e];
			printf("            %" PRIu64 " (%" PRIu64 " hits)\n", edge->rid, edge->nhits);
		}
	}
	printf("----- END PATH GRAPH -----\n");
}
