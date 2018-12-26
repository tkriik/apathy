#ifndef TRUNCATE_H
#define TRUNCATE_H

#include "regex.h"

#define REQUEST_NTRUNCS_MAX 8

struct truncate_patterns {
#define TRUNCATE_NPATTERNS_MAX 512
	int         npatterns;
	regex_t     regexes[TRUNCATE_NPATTERNS_MAX];
	const char *patterns[TRUNCATE_NPATTERNS_MAX];
	const char *aliases[TRUNCATE_NPATTERNS_MAX];
	size_t      alias_sizes[TRUNCATE_NPATTERNS_MAX];
	size_t      max_alias_size;
};

void   init_truncate_patterns(struct truncate_patterns *, const char *);
size_t truncate_raw_request(char *, size_t, const char *, size_t, struct truncate_patterns *);

#endif
