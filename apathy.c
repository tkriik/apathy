/*
 MIT License

 Copyright (c) 2018 Tanel Kriik

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

/*
 * HOW THIS PROGRAM WORKS:
 *
 * -----------------------------------------------------------------------------
 *
 * 1. We map the log file into memory, so that multiple gigabyte sized
 *    log files pose no issues.
 *
 *    - init_log_ctx()
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
 *        There are multiple hash tables (REQUEST_TABLE_NBUCKETS),
 *        each with separate locks, in order to reduce lock contention
 *        across multiple threads.
 *
 *          - set_request_entry()
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
 *        multiple hash tables (SESSION_TABLE_NBUCKETS) for session entries,
 *        each with separate locks.
 *
 *          - amend_session_entry()
 */
#include <sys/types.h>
#include <sys/stat.h>
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

#include "uthash.h"

#define VERSION "0.1.0"

#define MIN(A, B) ((A) < (B) ? (A) : (B))

struct log_ctx {
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

/* Request-specific info, stored in a hash table. */
struct request_entry {
	char *data;
	UT_hash_handle hh;
};

#define REQUEST_TABLE_NBUCKETS    (1 << 8)
#define REQUEST_TABLE_BUCKET_MASK (REQUEST_TABLE_NBUCKETS - 1)
struct request_table {
	struct request_entry *handles[REQUEST_TABLE_NBUCKETS];
	pthread_spinlock_t    locks[REQUEST_TABLE_NBUCKETS];
};

/* Session-specific information, stored in a hash table. */
struct session_entry {
#define MAX_DEPTH 16
	uint64_t  sid;                   /* Session ID */
	int       nrequests;             /* Number of requests in session */
	uint64_t  timestamps[MAX_DEPTH]; /* Request timestamps */
	char     *requests[MAX_DEPTH];   /* Request fields */
	uint64_t  repeats[MAX_DEPTH];    /* Repeats per request */
	UT_hash_handle hh;
};

#define SESSION_TABLE_NBUCKETS    (1 << 16)
#define SESSION_TABLE_BUCKET_MASK (SESSION_TABLE_NBUCKETS - 1)
struct session_table {
	struct session_entry *handles[SESSION_TABLE_NBUCKETS];
	pthread_spinlock_t    locks[SESSION_TABLE_NBUCKETS];
};

/* Aggregated path information. */
struct path_entry {
	size_t   nrequests;           /* Number of requests */
	uint64_t total_hits;          /* Total path hits */
	char    *requests[MAX_DEPTH]; /* Request fields */
	uint64_t hits[MAX_DEPTH];     /* Total hits up until each request */
	/* TODO: average pauses, repeats */
};

struct path_list {
	size_t total_npaths;
	size_t common_npaths;
	struct path_entry *paths;
};

/* Thread-specific context. */
struct thread_ctx {
	int    id;

	struct log_ctx *log_ctx;
	struct line_config *line_config;
	struct thread_chunk chunk;
	struct request_table *request_table;
	struct session_table *session_table;
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

void debug_request_table(struct request_table *);
void debug_session_table(struct session_table *);
void usage(void);

void *
mmap_file(const char *path, size_t *sizep)
{
	assert(path != NULL);
	assert(sizep != NULL);

	struct stat sb;

	int fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "failed to open %s", path);

	if (fstat(fd, &sb) == -1)
		err(1, "failed to read file status for %s", path);

	*sizep = (size_t)sb.st_size;
	void *p = mmap(NULL, (size_t)sb.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(1, "failed to map %s into memory", path);

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
		errx(1, "failed to compile regex '%s': %s\n", RFC3339_PATTERN,
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
init_log_ctx(struct log_ctx *ctx, const char *path)
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
		warnx("warning: source and/or destination IP address fields not found");
	if (lc->useragent == -1)
		warnx("warning: user agent field not found");
	if (lc->ts_rfc3339 == -1)
		warnx("error: timestamp field not found");
	if (lc->request == -1)
		errx(1, "error: request field not found");
	if (lc->ip1 == -1 && lc->ip2 == -1 && lc->useragent == -1)
		errx(1, "error: source IP address, destination IP address nor user agent field found");
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
 * Stores a request field pointed to by src into the request table rt.
 * Returns a pointer to a unique request field contained in a newly created,
 * or existing, request entry.
 */
char *
set_request_entry(const char *src, struct request_table *rt)
{
	assert(src != NULL);

	size_t bucket_idx = hash64_init();
	struct request_entry **handlep;
	pthread_spinlock_t *lock;
	struct request_entry *re;

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
			errx(1, "error: unexpected whitespace or null terminator after request field: %.*s\n",
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
	bucket_idx &= REQUEST_TABLE_BUCKET_MASK;
	handlep = &rt->handles[bucket_idx];
	lock = &rt->locks[bucket_idx];
	re = NULL;

	rc = pthread_spin_lock(lock);
	if (rc != 0)
		err(1, "error: pthread_spin_lock");

	HASH_FIND(hh, *handlep, src, req_len, re);
	if (re != NULL)
		goto finish;

	re = calloc(1, sizeof(*re));
	if (re == NULL)
		err(1, "error: calloc");

	re->data = calloc(1, req_len + 1);
	if (re->data == NULL)
		err(1, "error: calloc");
	memcpy(re->data, src, req_len);

	HASH_ADD_KEYPTR(hh, *handlep, re->data, req_len, re);
finish:
	rc = pthread_spin_unlock(lock);
	if (rc != 0)
		err(1, "error: pthread_spin_unlock");

	return re->data;
}

/*
 * Creates or modifies a session entry in the session table, with
 * session ID sid as the key. Since multiple threads may be editing
 * the same session entry at different times, the timestamp is used
 * to keep the session request list in order at each modification.
 */
void
amend_session_entry(struct session_table *st, uint64_t sid, uint64_t ts, char *re_data)
{
	assert(st != NULL);
	assert(re_data != NULL);

	int rc;
	int i;
	struct session_entry *se = NULL;

	/* TODO: more event bucket indexing */
	size_t bucket_idx = hash64_init();
	bucket_idx = hash64_update(bucket_idx, (void *)&sid, sizeof(sid));
	bucket_idx &= SESSION_TABLE_BUCKET_MASK;
	/* We have to use pointer to a pointer, otherwise the uthash
	 * macros don't work as intended.  */
	struct session_entry **handlep = &st->handles[bucket_idx];
	pthread_spinlock_t *lock = &st->locks[bucket_idx];

	rc = pthread_spin_lock(lock);
	if (rc != 0)
		err(1, "error: pthread_spin_lock");

	HASH_FIND_INT(*handlep, &sid, se);
	if (se != NULL) {
		//printf("found sid %" PRIx64 " in bucket %zu\n", sid, bucket_idx);
		if (se->nrequests == MAX_DEPTH)
			goto finish;
		else
			goto amend;
	}

	se = calloc(1, sizeof(*se));
	if (se == NULL)
		err(1, "error: calloc");
	se->sid = sid;
	se->nrequests = 0;

	HASH_ADD_INT(*handlep, sid, se);
	//printf("added sid %" PRIx64 " in bucket %zu\n", sid, bucket_idx);
	//struct session_entry *tmp_se;
	//HASH_FIND_INT(handle, &sid, tmp_se);
	//if (tmp_se != NULL) {
	//	printf("added sid %" PRIx64 " in bucket %zu\n", sid, bucket_idx);
	//}
amend:
	i = se->nrequests;
	if (i == 0)
		goto first;

	/* Rewind index to sorted timestamp position. */
	for (; 0 < i && ts < se->timestamps[i - 1]; i--);

	/*
	 * Check if request at previous or current index is identical;
	 * if yes, increment repeat count accordingly.
	 * */
	if (se->requests[i - 1] == re_data) {
		se->repeats[i - 1]++;
		goto finish;
	}
	if (se->requests[i] == re_data) {
		se->repeats[i]++;
		goto finish;
	}

	/* Shift the more recent requests up one index
	 * to make room for the current request. */
	int nmove = se->nrequests - i;
	memmove(&se->timestamps[i + 1], &se->timestamps[i],
	    nmove * sizeof(se->timestamps[0]));
	memmove(&se->requests[i + 1], &se->requests[i],
	    nmove * sizeof(se->requests[0]));
first:
	se->requests[i] = re_data;
	se->timestamps[i] = ts;
	se->nrequests++;
finish:
	rc = pthread_spin_unlock(lock);
	if (rc != 0)
		err(1, "error: pthread_spin_unlock");
}

void *
run_thread(void *ctx)
{
	assert(ctx != NULL);

	struct thread_ctx *thread_ctx = ctx;
	struct log_ctx *log_ctx = thread_ctx->log_ctx;
	const char *src = thread_ctx->chunk.start;
	struct line_config *lc = thread_ctx->line_config;
	struct request_table *rt = thread_ctx->request_table;
	struct session_table *st = thread_ctx->session_table;

	while (1) {
		if (thread_ctx->chunk.end <= src || src == NULL)
			break;

		int skip_line_seek = log_ctx->src == src;
		struct field_view fvs[NFIELDS_MAX] = {0};

		int nfields = get_fields(fvs, NFIELDS_MAX, src, skip_line_seek, &src);
		if (nfields != lc->ntotal_fields)
			continue;

		uint64_t ts = 0;
		uint64_t sid = hash64_init();
		char *re_data = NULL;

		for (int i = 0; i < lc->nfields; i++) {
			struct field_idx *fidx = &lc->indices[i];
			struct field_view *fv = &fvs[fidx->i];

			if (fidx->is_session)
				sid = hash64_update(sid, fv->src, fv->len);

			switch (fidx->type) {
			case FIELD_TS_RFC3339:
				ts = ts_rfc3339_to_ms(fv->src);
				break;
			case FIELD_IPADDR:
				sid = hash64_update(sid, fv->src, fv->len);
				break;
			case FIELD_REQUEST:
				re_data = set_request_entry(fv->src, rt);
				break;
			case FIELD_USERAGENT:
				sid = hash64_update(sid, fv->src, fv->len);
				break;
			default:
				break;
			}
		}

		amend_session_entry(st, sid, ts, re_data);
	} 

	pthread_exit(NULL);
}

void
init_line_config(struct line_config *lc, struct log_ctx *log_ctx,
		 struct regex_info *rx_info, const char *session_fields)
{
	assert(lc != NULL);
	assert(log_ctx != NULL);
	assert(rx_info != NULL);

	const char *src = log_ctx->src;

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
init_request_table(struct request_table *rt)
{
	for (size_t i = 0; i< REQUEST_TABLE_NBUCKETS; i++) {
		rt->handles[i] = NULL;
		if (pthread_spin_init(&rt->locks[i], PTHREAD_PROCESS_PRIVATE) != 0)
			err(1, "error: pthread_spin_init");
	}
}

void
init_session_table(struct session_table *st)
{
	for (size_t i = 0; i < SESSION_TABLE_NBUCKETS; i++) {
		st->handles[i] = NULL;
		if (pthread_spin_init(&st->locks[i], PTHREAD_PROCESS_PRIVATE) != 0)
			err(1, "error: pthread_spin_init");
	}
}

void
init_work_ctx(struct work_ctx *work_ctx, int nthreads, struct log_ctx *log_ctx,
              struct line_config *lc, struct request_table *rt,
	      struct session_table *st)
{
	assert(work_ctx != NULL);
	assert(log_ctx != NULL);
	assert(lc != NULL);
	assert(rt != NULL);
	assert(st != NULL);

	int rc;

#define MT_THRESHOLD (4 * 1024 * 1024)
	/* If log size is under MT_THRESHOLD, we use 1 thread. */
	if (log_ctx->len < MT_THRESHOLD)
		nthreads = 1;
	else if (nthreads == -1) {
		nthreads = sysconf(_SC_NPROCESSORS_CONF);
		if (nthreads == -1) {
			warn("failed to read CPU core count, using %d threads by default",
			     NTHREADS_DEFAULT);
			nthreads = NTHREADS_DEFAULT;
		}
	}

	if (nthreads > NTHREADS_MAX)
		errx(1, "thread count must be under %d\n", NTHREADS_MAX);

	assert(0 < nthreads && nthreads <= NTHREADS_MAX);

	work_ctx->nthreads = nthreads;

	size_t chunk_size = log_ctx->len / nthreads;
	size_t chunk_rem = log_ctx->len % nthreads;
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

		thread_ctx->log_ctx       = log_ctx;
		thread_ctx->line_config   = lc;
		thread_ctx->id            = tid;
		thread_ctx->chunk.start   = log_ctx->src + start_offset;
		thread_ctx->chunk.end     = log_ctx->src + end_offset;
		thread_ctx->chunk.size    = end_offset - start_offset;
		thread_ctx->request_table = rt;
		thread_ctx->session_table = st;

		rc = pthread_create(&work_ctx->thread[tid], NULL, run_thread,
		                    (void *)thread_ctx);
		if (rc != 0)
			err(1, "pthread_create");
	}
}

int
cmp_path_entries_by_request_order(const void *p1, const void *p2)
{
	const struct path_entry *pe1 = p1;
	const struct path_entry *pe2 = p2;
	size_t ncmp = sizeof(pe1->requests) * sizeof(pe1->requests[0]);
	return -(memcmp(pe1->requests, pe2->requests, ncmp));
}

/* Returns 1 if requests in `b` are contained in `a`. */
int
is_subpath(struct path_entry *a, struct path_entry *b)
{
	size_t min_nrequests = MIN(a->nrequests, b->nrequests);
	size_t ncmp = min_nrequests * sizeof(a->requests[0]);
	return b->nrequests <= a->nrequests
	    && memcmp(a->requests, b->requests, ncmp) == 0;
}

/* Merges information in path entry `b` to `a`. */
void
merge_path_entries(struct path_entry *a, struct path_entry *b)
{
	assert(b->nrequests <= a->nrequests);

	for (size_t ri = 0; ri < b->nrequests; ri++) {
		a->total_hits += b->total_hits;
		a->hits[ri] += b->hits[ri];
	}
}

int
cmp_path_entries_by_hit_count(const void *p1, const void *p2)
{
	const struct path_entry *pe1 = p1;
	const struct path_entry *pe2 = p2;
	return pe1->total_hits <= pe2->total_hits;
}

void
gen_path_list(struct path_list *pl, struct request_table *rt,
               struct session_table *st)
{
	assert(rt != NULL);
	assert(st != NULL);

	/* Compute total non-unique path count and allocate that many
	 * path list nodes. */
	size_t total_npaths = 0;
	for (size_t i = 0; i < SESSION_TABLE_NBUCKETS; i++)
		total_npaths += HASH_COUNT(st->handles[i]);

	pl->paths = calloc(total_npaths, sizeof(pl->paths[0]));
	if (pl->paths == NULL)
		err(1, "error: calloc");
	pl->total_npaths = total_npaths;

	/* Initialize newly allocated path list nodes
	 * with each session's request hit counts set to 1. */
	size_t pi = 0;
	for (size_t bi = 0; bi < SESSION_TABLE_NBUCKETS; bi++) {
		struct session_entry *se, *tmp;
		HASH_ITER(hh, st->handles[bi], se, tmp) {
			struct path_entry *pe = &pl->paths[pi];
			pe->nrequests = se->nrequests;
			for (size_t ri = 0; ri < pe->nrequests; ri++) {
				pe->requests[ri] = se->requests[ri];
				pe->total_hits = 1;
				pe->hits[ri] = 1;
			}
			pi++;
		}
	}

	/* Sort path list nodes according to request pointer layout */
	qsort(pl->paths, pl->total_npaths, sizeof(pl->paths[0]),
	    cmp_path_entries_by_request_order);

	/* At this point, we can merge subsequent path chains into one. */
	size_t pi_start = 0;
	size_t pi_end = 1;
	size_t common_npaths = 0;
	while (pi_end < total_npaths) {
		struct path_entry *pe_start = &pl->paths[pi_start];
		struct path_entry *pe_end = &pl->paths[pi_end];

		if (is_subpath(pe_start, pe_end)) {
			merge_path_entries(pe_start, pe_end);
			pi_end++;
		} else {
			pi_start = pi_end;
			pi_end++;
			pl->paths[common_npaths] = *pe_start;
			common_npaths++;
		}
	}

	pl->common_npaths = common_npaths;

	/* Finally sort by total hit counts. */
	qsort(pl->paths, pl->common_npaths, sizeof(pl->paths[0]),
	    cmp_path_entries_by_hit_count);
}

void
output_yaml(struct path_list *pl, FILE *out)
{
	fprintf(out, "---\n");

	fprintf(out,
"total_sessions: %zu\n"
"common_paths: %zu\n"
"paths:\n", pl->total_npaths, pl->common_npaths);

	for (size_t pi = 0; pi < pl->common_npaths; pi++) {
		struct path_entry *pe = &pl->paths[pi];
		fprintf(out,
"    - %zu:\n"
"        - hits: %" PRIu64 "\n"
"        - requests:\n", pi + 1, pe->total_hits);
		for (size_t ri = 0; ri < pe->nrequests; ri++) {
			char *re_data = pe->requests[ri];
			fprintf(out,
"            - %s\n"
"                - hits: %" PRIu64 "\n", re_data, pe->hits[ri]);
		}
	}

	fprintf(out, "...\n");
}

void
cleanup_work_ctx(struct work_ctx *work_ctx)
{
	for (int tid = 0; tid < work_ctx->nthreads; tid++) {
		int rc = pthread_join(work_ctx->thread[tid], NULL);
		if (rc != 0)
			err(1, "pthread_join");
	}
}

void
cleanup_request_table(struct request_table *rt)
{
	for (size_t i = 0; i < REQUEST_TABLE_NBUCKETS; i++) {
		struct request_entry *r, *tmp;
		HASH_ITER(hh, rt->handles[i], r, tmp) {
			HASH_DEL(rt->handles[i], r);
			free(r->data);
			free(r);
		}
		if (pthread_spin_destroy(&rt->locks[i]) != 0)
			warn("warning: pthread_spin_destroy");
	}
}

void
cleanup_session_table(struct session_table *st)
{
	for (int i = 0; i < SESSION_TABLE_NBUCKETS; i++) {
		struct session_entry *s, *tmp;
		HASH_ITER(hh, st->handles[i], s, tmp) {
			HASH_DEL(st->handles[i], s);
			free(s);
		}
		int rc = pthread_spin_destroy(&st->locks[i]);
		if (rc != 0)
			warn("warning: pthread_spin_destroy");
	}
}

void
cleanup_regex_info(struct regex_info *rx_info)
{
	assert(rx_info != NULL);

	regfree(&rx_info->rfc3339);
	regfree(&rx_info->ipv4);
	regfree(&rx_info->request);
	regfree(&rx_info->useragent);
}

void
cleanup_log_ctx(struct log_ctx *log_ctx)
{
	if (munmap((char *)log_ctx->src, log_ctx->len) == -1)
		warn("munmap");
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

	struct log_ctx log_ctx;
	struct regex_info rx_info;
	struct line_config lc;
	struct request_table rt;
	struct session_table st;
	struct work_ctx work_ctx;

	/* Post-processing data */
	struct path_list pl;

	const char *output_path = "-";
	FILE *out = stdout;

	while (1) {
		int opt_idx = 0;
		static struct option long_opts[] = {
			{"help",            no_argument,       0, 'h' },
			{"ignore-patterns", required_argument, 0, 'I' },
			{"merge-patterns",  required_argument, 0, 'M' },
			{"output",          required_argument, 0, 'o' },
			{"session",         required_argument, 0, 'S' },
			{"threads",         required_argument, 0, 'T' },
			{"version",         no_argument,       0, 'V' },
			{0,                 0,                 0,  0  }
		};

		int c = getopt_long(argc, argv, "hI:M:o:S:T:V", long_opts, &opt_idx);
		if (c == -1)
			break;

		switch (c) {
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
					err(1, "failed to create output file at %s", output_path);
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
				errx(1, "invalid thread count: %s", optarg);
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
		errx(1, "missing access log");
	if (argc > 1)
		errx(1, "only one access log allowed");

	init_log_ctx(&log_ctx, argv[0]);
	init_regex_info(&rx_info);
	init_line_config(&lc, &log_ctx, &rx_info, session_fields);
	init_request_table(&rt);
	init_session_table(&st);

	/* Start worker threads */
	init_work_ctx(&work_ctx, nthreads, &log_ctx, &lc, &rt, &st);

	/* Wait for worker threads to finish */
	cleanup_work_ctx(&work_ctx);

	/* Do post-processing */
	gen_path_list(&pl, &rt, &st);
	output_yaml(&pl, out);

	//debug_request_table(&rt);
	//debug_session_table(&st);

	cleanup_request_table(&rt);
	cleanup_session_table(&st);
	cleanup_regex_info(&rx_info);
	cleanup_log_ctx(&log_ctx);

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
debug_request_table(struct request_table *rt)
{
	printf("----- BEGIN REQUEST TABLE -----\n");
	uint64_t min_bucket_count = HASH_COUNT(rt->handles[0]);
	uint64_t max_bucket_count = HASH_COUNT(rt->handles[0]);
	uint64_t total_count = 0;
	for (size_t i = 1; i < REQUEST_TABLE_NBUCKETS; i++) {
		size_t bucket_count = HASH_COUNT(rt->handles[i]);
		total_count += bucket_count;
		if (bucket_count < min_bucket_count)
			min_bucket_count = bucket_count;
		if (max_bucket_count < bucket_count)
			max_bucket_count = bucket_count;
	}
	printf("min_bucket_count: %" PRIu64 "\n", min_bucket_count);
	printf("max_bucket_count: %" PRIu64 "\n", max_bucket_count);
	printf("avg_bucket_count: %lf\n", (double)total_count / REQUEST_TABLE_NBUCKETS);
	printf("total_count: %" PRIu64 "\n", total_count);
	//for (size_t i = 0; i < REQUEST_TABLE_NBUCKETS; i++) {
	//	struct request_entry *r, *tmp;
	//	HASH_ITER(hh, rt->handles[i], r, tmp) {
	//		printf("%p %s\n", r->data, r->data);
	//	}
	//}
	printf("----- END REQUEST TABLE -----\n");
}

void
debug_session_table(struct session_table *st)
{
	printf("----- BEGIN SESSION TABLE -----\n");
	uint64_t min_bucket_count = HASH_COUNT(st->handles[0]);
	uint64_t max_bucket_count = HASH_COUNT(st->handles[0]);
	uint64_t total_count = 0;
	for (size_t i = 1; i < SESSION_TABLE_NBUCKETS; i++) {
		size_t bucket_count = HASH_COUNT(st->handles[i]);
		total_count += bucket_count;
		if (bucket_count < min_bucket_count)
			min_bucket_count = bucket_count;
		if (max_bucket_count < bucket_count)
			max_bucket_count = bucket_count;
	}
	printf("min_bucket_count: %" PRIu64 "\n", min_bucket_count);
	printf("max_bucket_count: %" PRIu64 "\n", max_bucket_count);
	printf("avg_bucket_count: %lf\n", (double)total_count / SESSION_TABLE_NBUCKETS);
	printf("total_count: %" PRIu64 "\n", total_count);
	//for (int i = 0; i < SESSION_TABLE_NBUCKETS; i++) {
	//	struct session_entry *se, *tmp;
	//	HASH_ITER(hh, st->handles[i], se, tmp) {
	//		printf("%016" PRIx64 ":\n", se->sid);
	//		for (int i = 0; i < se->nrequests; i++) {
	//			printf("    %" PRIu64 " %p %s (%"PRIu64" repeats)\n",
	//			       se->timestamps[i] / 1000, se->requests[i],
        //	                       se->requests[i], se->repeats[i]);
	//		}
	//	}
	//	printf("\n");
	//}
	printf("----- END SESSION TABLE -----\n");
}
