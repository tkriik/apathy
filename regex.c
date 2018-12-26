#include <assert.h>
#include <regex.h>
#include <stddef.h>

#include "regex.h"
#include "util.h"

void
compile_regex(regex_t *preg, const char *pattern, int cflags)
{
	assert(preg != NULL);
	assert(pattern != NULL);

	int rc;
	char errbuf[256] = {0};

	rc = regcomp(preg, pattern, cflags);
	if (rc != 0) {
		regerror(rc, preg, errbuf, sizeof(errbuf));
		ERRX("failed to compile regex '%s': %s", pattern, errbuf);
	}
}

void
init_regex_info(struct regex_info *rx_info)
{
	assert(rx_info != NULL);

	int cflags = REG_EXTENDED | REG_NOSUB | REG_NEWLINE;
	compile_regex(&rx_info->rfc3339, RFC3339_PATTERN, cflags);
	compile_regex(&rx_info->ipv4, IPV4_PATTERN, cflags);
	compile_regex(&rx_info->request, REQUEST_PATTERN, cflags);
	compile_regex(&rx_info->useragent, USERAGENT_PATTERN, cflags);
}

int
regex_does_match(regex_t *preg, const char *s)
{
	regmatch_t pmatch[1];
	return regexec(preg, s, 1, pmatch, 0) == 0;
}

int
get_regex_matches(regex_t *preg, const char *s, regmatch_t *matches, size_t nmatches)
{
	return regexec(preg, s, nmatches, matches, 0);
}
