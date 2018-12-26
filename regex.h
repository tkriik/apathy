#ifndef REGEX_H
#define REGEX_H

#include <regex.h>

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

void compile_regex(regex_t *, const char *, int);
void init_regex_info(struct regex_info *);
int  regex_does_match(regex_t *, const char *);
int  get_regex_matches(regex_t *, const char *, regmatch_t *, size_t);

#endif
