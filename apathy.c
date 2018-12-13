#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(void);

#define VERSION         "0.1.0"

#define RFC3339_PATTERN "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
#define IPV4_PATTERN    "[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"

/* Log size threshold after which multithreading is enabled. */
#define MT_THRESHOLD     (2 * 1024 * 1024)

struct log_ctx {
	const char *path;
	size_t      len;
	const char *src;
};

struct thread_chunk {
	const char *start;
	const char *end;
	size_t      size;
};

struct thread_ctx {
	struct log_ctx *log_ctx;
	int    id;
	struct thread_chunk chunk;
};

struct re_info {
	regex_t rfc3339;
	regex_t ipv4;
};

#define THREADS_DEFAULT   4
#define THREADS_MAX       4096

struct work_ctx {
	int       nthreads;
	pthread_t thread[THREADS_MAX];
	struct    thread_ctx thread_ctx[THREADS_MAX];
};

struct line_config {
	int total_fields;
	int timestamp;
	int ip_primary;
	int ip_secondary;
	int request;
	int useragent;
};

struct line_view {
	const char *src;
	size_t      len;
};

struct field_view {
	const char *src;
	size_t      len;
};

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

int
next_line(struct line_view *lv, const char *src, int skip_seek)
{
	assert(lv != NULL);
	assert(src != NULL);

	char c;

	if (skip_seek)
		goto fill_line;

	while (1) {
		c = *src;
		if (c == '\n') {
			src++;
			break;
		}

		if (c == '\0')
			return 0;

		src++;
	}

fill_line:
	lv->src = src;
	lv->len = 0;

	while (1) {
		c = *src;
		if (c == '\n' || c == '\0')
			break;

		lv->len++;
		src++;
	}

	return 1;
}

/* TODO: delimiters */
int
next_field(struct field_view *fv, const char *src)
{
	assert(fv != NULL);
	assert(src != NULL);

	char c;

	while (1) {
		c = *src;

		switch (c) {
		case '\n':
		case '\0':
			return 0;
		case ' ':
			src++;
			continue;
		default:
			src++;
			break;
		}
	}

	fv->src = src;
	fv->len = 0;

	while (1) {
		c = *src;
		switch (c) {
		case '\n':
		case '\0':
			break;
		default:
			fv->len++;
		}
	}

	return 1;
}

void *
run_thread(void *ctx)
{
	struct      line_view lv;
	int         has_next;

	struct thread_ctx *thread_ctx = ctx;
	struct log_ctx *log_ctx = thread_ctx->log_ctx;

	if (log_ctx->src < thread_ctx->chunk.start)
		has_next = next_line(&lv, thread_ctx->chunk.start, 0);
	else
		has_next = next_line(&lv, thread_ctx->chunk.start, 1);

	if (has_next)
		printf("%d:\n|%.*s|\n", thread_ctx->id, (int)lv.len, lv.src);
	else
		printf("%d:\tNO LINE\n", thread_ctx->id);

	pthread_exit(NULL);
}

void
init_log_ctx(struct log_ctx *ctx, const char *path)
{
	ctx->src = mmap_file(path, &ctx->len);
	ctx->path = path;
}

void
init_re_info(struct re_info *re_info)
{
	assert(re_info != NULL);
	compile_regex(&re_info->rfc3339, RFC3339_PATTERN);
	compile_regex(&re_info->ipv4, IPV4_PATTERN);
}

void
init_work_ctx(struct work_ctx *work_ctx, int nthreads, struct log_ctx *log_ctx)
{
	assert(work_ctx != NULL);

	if (nthreads == -1)
		nthreads = THREADS_DEFAULT;
	else if (log_ctx->len < MT_THRESHOLD)
		nthreads = 1;
	else if (nthreads > THREADS_MAX)
		errx(1, "thread count must be under %d\n", THREADS_MAX);

	assert(0 < nthreads && nthreads <= THREADS_MAX);

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
		thread_ctx->log_ctx = log_ctx;
		thread_ctx->id = tid;
		thread_ctx->chunk.start = log_ctx->src + start_offset;
		thread_ctx->chunk.end = log_ctx->src + end_offset;
		thread_ctx->chunk.size = end_offset - start_offset;

		int rc = pthread_create(&work_ctx->thread[tid], NULL,
				        run_thread, (void *)thread_ctx);
		if (rc != 0)
			err(1, "pthread_create");
	}
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
cleanup_re_info(struct re_info *re_info)
{
	assert(re_info != NULL);

	regfree(&re_info->rfc3339);
	regfree(&re_info->ipv4);
}

//void
//init_line_config(void)
//{
//	struct line_view lv;
//	const char *src = log_src;
//	struct line_config *lc = &line_config;
//
//	src = log_src;
//
//	if (!next_line(&lv, src, 1))
//		exit(EXIT_SUCCESS); /* Ignore empty logs */
//
//	lc->total_fields =  0;
//	lc->timestamp    = -1;
//	lc->ip_primary   = -1;
//	lc->ip_secondary = -1;
//	lc->request      = -1;
//	lc->useragent    = -1;
//}
//

int
main(int argc, char **argv)
{
	//char *ignore_patterns = NULL;
	//char *merge_patterns  = NULL;
	long nthreads         = -1;

	struct log_ctx log_ctx;
	struct re_info re_info;
	struct work_ctx work_ctx;

	while (1) {
		int opt_idx = 0;
		static struct option long_opts[] = {
			{"help",            no_argument,       0, 'h' },
			{"ignore-patterns", required_argument, 0, 'I' },
			{"merge-patterns",  required_argument, 0, 'M' },
			{"threads",         required_argument, 0, 'T' },
			{"version",         no_argument,       0, 'V' },
			{0,                 0,                 0,  0  }
		};

		int c = getopt_long(argc, argv, "hI:M:T:V", long_opts, &opt_idx);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			printf("option %s", long_opts[opt_idx].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
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
	init_re_info(&re_info);
	init_work_ctx(&work_ctx, nthreads, &log_ctx);

	cleanup_work_ctx(&work_ctx);
	cleanup_re_info(&re_info);

	return 0;
}

void
usage(void)
{
	fprintf(stderr,
"apathy %s\n"
"Access Log Path Analyzer\n"
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
"ARGUMENTS:\n"
"    <ACCESS_LOG>    Access log file containing HTTP request timestamps, IP addresses, methods, URLs and User Agent headers\n",
	    VERSION);
	exit(EXIT_FAILURE);
}
