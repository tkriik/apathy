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
 *    - start_work_ctx()
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

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/uthash.h"

#include "debug.h"
#include "dot.h"
#include "field.h"
#include "file_view.h"
#include "hash.h"
#include "path_graph.h"
#include "regex.h"
#include "request.h"
#include "session.h"
#include "time.h"
#include "truncate.h"
#include "util.h"

#define APATHY_VERSION "0.2.0"

/* Working area for one thread. */
struct thread_chunk {
	size_t      size;
	const char *start;
	const char *end;   /* start + size bytes */
};

/* Thread-specific context. */
struct thread_ctx {
	int    tid;

	struct file_view *log_view;
	struct line_config *line_config;
	struct truncate_patterns *truncate_patterns;
	struct thread_chunk chunk;
	struct request_set *request_set;
	struct session_map *session_map;
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

void usage(void);

void *
run_thread(void *ctx)
{
	assert(ctx != NULL);

	struct thread_ctx *thread_ctx = ctx;
	struct file_view *log_view = thread_ctx->log_view;
	struct truncate_patterns *tp = thread_ctx->truncate_patterns;
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

			if (fidx->is_session) {
				sid = hash64_update(sid, fv->src, fv->len);
			}

			switch (fidx->type) {
			case FIELD_TS_RFC3339:
				ts = ts_rfc3339_to_ms(fv->src);
				break;
			case FIELD_REQUEST:
				rid = add_request_set_entry(rs, fv->src, tp);
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
start_work_ctx(struct work_ctx *work_ctx, int nthreads, struct file_view *log_view,
               struct truncate_patterns *tp, struct line_config *lc,
	       struct request_set *rs, struct session_map *sm)
{
	assert(work_ctx != NULL);
	assert(log_view != NULL);
	assert(tp != NULL);
	assert(lc != NULL);
	assert(rs != NULL);
	assert(sm != NULL);

	int rc;

#define MT_THRESHOLD (4 * 1024 * 1024)
	/* If log size is under MT_THRESHOLD, use one thread. */
	if (log_view->size < MT_THRESHOLD)
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
		ERRX("thread count must be under %d", NTHREADS_MAX);

	assert(0 < nthreads && nthreads <= NTHREADS_MAX);

	work_ctx->nthreads = nthreads;

	size_t chunk_size = log_view->size / nthreads;
	size_t chunk_rem = log_view->size % nthreads;
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

		thread_ctx->log_view          = log_view;
		thread_ctx->truncate_patterns = tp;
		thread_ctx->line_config       = lc;
		thread_ctx->tid               = tid;
		thread_ctx->chunk.start       = log_view->src + start_offset;
		thread_ctx->chunk.end         = log_view->src + end_offset;
		thread_ctx->chunk.size        = end_offset - start_offset;
		thread_ctx->request_set       = rs;
		thread_ctx->session_map       = sm;

		rc = pthread_create(&work_ctx->thread[tid], NULL, run_thread,
		                    (void *)thread_ctx);
		if (rc != 0)
			ERR("%s", "pthread_create");
	}
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

int
main(int argc, char **argv)
{
	//char *merge_patterns  = NULL;
	const char *session_fields = "ip1,useragent";
	const char *truncate_patterns_path = NULL;
	long nthreads = -1;

	struct file_view log_view;
	struct truncate_patterns tp;
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
			{"concurrency",       required_argument, 0, 'C' },
			{"format",            required_argument, 0, 'f' },
			{"help",              no_argument,       0, 'h' },
			{"ignore-patterns",   required_argument, 0, 'I' },
			{"truncate-patterns", required_argument, 0, 'T' },
			{"output",            required_argument, 0, 'o' },
			{"session",           required_argument, 0, 'S' },
			{"version",           no_argument,       0, 'V' },
			{0,                   0,                 0,  0  }
		};

		int c = getopt_long(argc, argv, "C:f:hI:T:M:o:S:V", long_opts, &opt_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'C':
			nthreads = strtol(optarg, NULL, 10);
			if (nthreads == 0
		         || nthreads > INT_MAX
			 || nthreads < INT_MIN)
				ERRX("invalid thread count: %s", optarg);
			break;
		case 'f':
			if (strcmp(optarg, "dot-graph") == 0)
				output_format = optarg;
			else
				ERRX("invalid output format: %s", optarg);
			break;
		case 'h':
			usage();
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
			truncate_patterns_path = optarg;
			break;
		case 'V':
			printf("%s\n", APATHY_VERSION);
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

	init_file_view_readonly(&log_view, argv[0]);

	if (truncate_patterns_path != NULL)
		init_truncate_patterns(&tp, truncate_patterns_path);
	else
		memset(&tp, 0, sizeof(tp));
	//debug_truncate_patterns(&tp);

	init_regex_info(&rx_info);
	init_line_config(&lc, &log_view, &rx_info, session_fields);
	init_request_set(&rs);
	init_session_map(&sm);

	/* Start worker threads */
	start_work_ctx(&work_ctx, nthreads, &log_view, &tp, &lc, &rs, &sm);

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
"    -C, --concurrency <num_threads>         Number of worker threads\n"
"                                              default: number of logical CPU cores, or 4 as a fallback\n"
"\n"
"    -I, --ignore-patterns <pattern_file>    File containing URL patterns for ignoring HTTP requests\n"
"    -T, --truncate-patterns <pattern_file>  File containing URL patterns for merging HTTP requests\n"
"\n"
"    -o, --output <output_file>              File for output\n"
"                                              default: \"-\" (standard output)\n"
"\n"
"    -S, --session <session_fields>          Comma-separated fields used to construct a session ID for a request\n"
"                                              available fields: ip1,ip2,useragent\n"
"                                              default: ip1,useragent\n"
"\n"
"ARGUMENTS:\n"
"    <ACCESS_LOG>    Access log file containing HTTP request timestamps, IP addresses, methods, URLs and User Agent headers\n",
	    APATHY_VERSION);
	exit(EXIT_FAILURE);
}
