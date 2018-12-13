#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void usage(void);

#define VERSION         "0.1.0"

#define RFC3339_PATTERN "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
#define IPV4_PATTERN    "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"

/* Log size threshold after which multithreading is enabled. */
#define MT_THRESHOLD     (2 * 1024 * 1024)

#define MIN(A, B) ((A) < (B) ? (A) : (B))

struct log_ctx {
	size_t      len;
	const char *path;
	const char *src;
};

#define LC_FIELDS_MAX 5
struct line_config {
	int ts_rfc3339;
	int ipv4_fst;
	int ipv4_snd;
	int request;
	int useragent;

	int nfields;
	int fields[LC_FIELDS_MAX + 1];
};

struct result {
	unsigned long fields_iterated;
};

struct thread_chunk {
	size_t      size;
	const char *start;
	const char *end;
};

struct thread_ctx {
	int    id;
	struct log_ctx *log_ctx;
	struct line_config *line_config;
	struct thread_chunk chunk;
	struct result result;
};

struct re_info {
	regex_t rfc3339;
	regex_t ipv4;
};

#define NTHREADS_DEFAULT   4
#define NTHREADS_MAX       4096
struct work_ctx {
	int       nthreads;
	pthread_t thread[NTHREADS_MAX];
	struct    thread_ctx thread_ctx[NTHREADS_MAX];
};

enum field_type {
	FIELD_TS_RFC3339,
	FIELD_IPV4,
	FIELD_REQUEST,
	FIELD_USERAGENT,
	FIELD_UNKNOWN,
	FIELD_STOP
};

#define NFIELDS_MAX 256
struct field_view {
	int         len;
	const char *src;
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

void *
run_thread(void *ctx)
{
	assert(ctx != NULL);

	struct thread_ctx *thread_ctx = ctx;
	struct log_ctx *log_ctx = thread_ctx->log_ctx;
	const char *src = thread_ctx->chunk.start;
	struct result *res = &thread_ctx->result;

	while (1) {
		if (thread_ctx->chunk.end <= src || src == NULL)
			break;

		int skip_line_seek = log_ctx->src == src;
		struct field_view fvs[NFIELDS_MAX] = {0};
		get_fields(fvs, NFIELDS_MAX, src, skip_line_seek, &src);
		struct line_config *lc = thread_ctx->line_config;
		for (int i = 0; i < lc->nfields; i++) {
			res->fields_iterated++;
		}
	} 

	printf("%02d -- %lu fields iterated\n", thread_ctx->id, res->fields_iterated);

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

int
regex_does_match(regex_t *preg, const char *s)
{
	regmatch_t pmatch[1];
	return regexec(preg, s, 1, pmatch, 0) == 0;
}

enum field_type
infer_field_type(struct field_view *fv, struct re_info *re_info)
{
#define FIELD_MAX 4096
	char field[FIELD_MAX + 1] = {0};
	int ncopy = MIN(fv->len, FIELD_MAX);
	memcpy(field, fv->src, ncopy);

	if (regex_does_match(&re_info->rfc3339, field)) {
		printf("timestamp: %s\n", field);
		return FIELD_TS_RFC3339;
	}

	if (regex_does_match(&re_info->ipv4, field)) {
		printf("ipv4: %s\n", field);
		return FIELD_IPV4;
	}

	// TODO: request, useragent

	return FIELD_UNKNOWN;
}

void
amend_line_config(struct line_config *lc, enum field_type ftype, int idx)
{
	if (LC_FIELDS_MAX <= lc->nfields)
		return;

	switch (ftype) {
	case FIELD_TS_RFC3339:
		if (lc->ts_rfc3339 == -1)
			lc->ts_rfc3339 = idx;
		else
			return;
		break;
	case FIELD_IPV4:
		if (lc->ipv4_fst == -1)
			lc->ipv4_fst = idx;
		else if (lc->ipv4_snd == -1)
			lc->ipv4_snd = idx;
		else
			return;
		break;
	default:
		return;
	}

	lc->fields[lc->nfields] = idx;
	lc->nfields++;
}

void
check_line_config(struct line_config *lc)
{
	printf("%d line fields found\n", lc->nfields);
}

void
init_line_config(struct line_config *lc, struct log_ctx *log_ctx,
		 struct re_info *re_info)
{
	assert(lc != NULL);
	assert(log_ctx != NULL);
	assert(re_info != NULL);

	const char *src = log_ctx->src;

	*lc = (struct line_config){
		.nfields    =  0,
		.ts_rfc3339 = -1,
		.ipv4_fst   = -1,
		.ipv4_snd   = -1,
		.request    = -1,
		.useragent  = -1
	};

	struct field_view fvs[NFIELDS_MAX] = {0};
	const char *endp;
	int nfields = get_fields(fvs, NFIELDS_MAX, src, 1, &endp);
	for (int i = 0; i < nfields; i++) {
		struct field_view *fv = &fvs[i];
		enum field_type ftype = infer_field_type(fv, re_info);
		amend_line_config(lc, ftype, i);
		//printf("%02d: |%.*s|\n", i, fvs[i].len, fvs[i].src);
	}
	//printf("endp: %.40s\n", endp);
	
	check_line_config(lc);
}

void
init_result(struct result *res)
{
	assert(res != NULL);

	res->fields_iterated = 0;
}

void
init_work_ctx(struct work_ctx *work_ctx, int nthreads, struct log_ctx *log_ctx,
              struct line_config *lc)
{
	assert(work_ctx != NULL);

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
		thread_ctx->log_ctx     = log_ctx;
		thread_ctx->line_config = lc;
		thread_ctx->id          = tid;
		thread_ctx->chunk.start = log_ctx->src + start_offset;
		thread_ctx->chunk.end   = log_ctx->src + end_offset;
		thread_ctx->chunk.size  = end_offset - start_offset;
		init_result(&thread_ctx->result);

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
cleanup_result(struct result *res)
{
	assert(res != NULL);
}

void
cleanup_re_info(struct re_info *re_info)
{
	assert(re_info != NULL);

	regfree(&re_info->rfc3339);
	regfree(&re_info->ipv4);
}

void
cleanup_log_ctx(struct log_ctx *log_ctx)
{
	if (munmap((char *)log_ctx->src, log_ctx->len) == -1)
		warn("munmap");
}

int
main(int argc, char **argv)
{
	//char *ignore_patterns = NULL;
	//char *merge_patterns  = NULL;
	long nthreads = -1;

	struct log_ctx log_ctx;
	struct re_info re_info;
	struct line_config lc;
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
	init_line_config(&lc, &log_ctx, &re_info);
	init_work_ctx(&work_ctx, nthreads, &log_ctx, &lc);

	cleanup_work_ctx(&work_ctx);
	cleanup_re_info(&re_info);
	cleanup_log_ctx(&log_ctx);

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
