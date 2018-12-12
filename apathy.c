#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION         "0.1.0"

#define RFC3339_PATTERN "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
#define IPV4_PATTERN    "[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"

#define DEFAULT_NTHREADS 4
#define MT_THRESHOLD     (2 * 1024 * 1024)

struct thread_ctx {
	int         id;
	const char *start;
	const char *end;
	size_t      size;
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
	const char *start;
	size_t      size;
};

char      *log_src;
size_t     log_size;

regex_t    rfc3339_re;
regex_t    ipv4_re;

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

void *
mmap_file(const char *path, size_t *sizep)
{
	int fd;
	struct stat sb;
	void *p;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "failed to open %s", path);

	if (fstat(fd, &sb) == -1)
		err(1, "failed to read file status for %s", path);

	*sizep = (size_t)sb.st_size;
	p = mmap(NULL, (size_t)sb.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(1, "failed to map %s into memory", path);

	return p;
}

void
compile_regex(regex_t *preg, const char *pattern)
{
	int rc;
	char errbuf[256];

	memset(errbuf, '\0', sizeof(errbuf));
	rc = regcomp(preg, pattern, REG_EXTENDED | REG_NOSUB);
	if (rc != 0) {
		regerror(rc, preg, errbuf, sizeof(errbuf));
		errx(1, "failed to compile regex '%s': %s\n", RFC3339_PATTERN,
		    errbuf);
	}
}

void
init_line_config(struct line_config *lc)
{
	lc->total_fields =  0;
	lc->timestamp    = -1;
	lc->ip_primary   = -1;
	lc->ip_secondary = -1;
	lc->request      = -1;
	lc->useragent    = -1;
}

int
next_line(struct line_view *lv, const char *start, int skip_seek)
{
	char c;

	if (skip_seek)
		goto fill_line;

	while (1) {
		c = *start;
		if (c == '\n') {
			start++;
			break;
		}

		if (c == '\0')
			return 0;

		start++;
	}

fill_line:
	lv->start = start;
	lv->size = 0;

	while (1) {
		c = *start;
		if (c == '\0' || c == '\n')
			break;

		lv->size++;
		start++;
	}

	return 1;
}

void *
run_thread(void *thread_ctx)
{
	struct      thread_ctx *ctx;
	struct      line_config lc;
	struct      line_view lv;
	int         has_next;
	const char *src;

	ctx = thread_ctx;
	init_line_config(&lc);

	if (ctx->start > log_src)
		has_next = next_line(&lv, ctx->start, 0);
	else
		has_next = next_line(&lv, ctx->start, 1);

	if (has_next)
		printf("%.*s\n", (int)lv.size, lv.start);
	else
		printf("NO LINE\n");

	pthread_exit(NULL);
}

int
main(int argc, char **argv)
{
	int c;
	int rc;

	char *log_path = NULL;
	char *ignore_patterns = NULL;
	char *merge_patterns = NULL;
	long nthreads_arg = -1;

	size_t i;
	size_t block_size;
	size_t block_rem;
	size_t nthreads;
	struct thread_ctx *thread_ctxs;
	pthread_t *threads;

	/* Command line options */
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

		c = getopt_long(argc, argv, "hI:M:T:V", long_opts, &opt_idx);
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
			ignore_patterns = optarg;
			break;

		case 'M':
			merge_patterns = optarg;
			break;

		case 'T':
			nthreads_arg = strtol(optarg, NULL, 10);
			if (nthreads_arg == 0
		         || nthreads_arg == LONG_MAX
			 || nthreads_arg == LONG_MIN)
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

	/* Log setup */
	log_path = argv[0];
	log_src = mmap_file(log_path, &log_size);

	/* Regex setup */
	compile_regex(&rfc3339_re, RFC3339_PATTERN);
	compile_regex(&ipv4_re, IPV4_PATTERN);

	/* Thread setup */
	if (nthreads_arg == -1)
		nthreads = DEFAULT_NTHREADS;
	else if (log_size > MT_THRESHOLD)
		nthreads = (size_t)nthreads_arg;
	else
		nthreads = 1;

	thread_ctxs = calloc(nthreads, sizeof(*thread_ctxs));
	if (thread_ctxs == NULL)
		err(1, "calloc");

	threads = calloc(nthreads, sizeof(*threads));
	if (threads == NULL)
		err(1, "calloc");

	block_size = log_size / nthreads;
	block_rem = log_size % nthreads;
	for (i = 0; i < nthreads; i++) {
		size_t start_offset;
		size_t end_offset;
		struct thread_ctx *ctx;

		start_offset = i * block_size;
		if (i < nthreads - 1)
			end_offset = start_offset + block_size;
		else
			end_offset = start_offset + block_size + block_rem;

		ctx = &thread_ctxs[i];
		ctx->id = (int)i;
		ctx->start = log_src + start_offset;
		ctx->end = log_src + end_offset;
		ctx->size = end_offset - start_offset;

		rc = pthread_create(&threads[i], NULL, run_thread, (void *)ctx);
		if (rc != 0)
			err(1, "pthread_create");
	}

	/* Cleanup */
	for (i = 0; i < nthreads; i++) {
		rc = pthread_join(threads[i], NULL);
		if (rc != 0)
			err(1, "pthread_join");
	}

	return 0;
}
