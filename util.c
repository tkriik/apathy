#include <stdlib.h>

#include "util.h"

long
parse_long(const char *s)
{
	char *endptr = NULL;
	long n = strtol(s, &endptr, 10);
	if (*endptr != '\0')
		ERRX("invalid integer: %s", s);
	return n;
}
