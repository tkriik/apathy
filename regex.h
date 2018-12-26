#ifndef REGEX_H
#define REGEX_H

#include <regex.h>

void compile_regex(regex_t *, const char *, int);
int  regex_does_match(regex_t *, const char *);
int  get_regex_matches(regex_t *, const char *, regmatch_t *, size_t);

#endif
