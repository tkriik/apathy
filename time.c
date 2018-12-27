#include <assert.h>
#include <string.h>

#include "time.h"

/*
 * Rough millisecond estimations.
 *
 * We don't need accurate timekeeping since we are only
 * concerned with average durations between path transitions, so
 * we can take this faster shortcut with manual parsing.
 */

static const char ctoi[256] = {
	['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3, ['4'] = 4,
	['5'] = 5, ['6'] = 6, ['7'] = 7, ['8'] = 8, ['9'] = 9
};

#define MS_IN_YEAR  31104000000ULL
#define MS_IN_MONTH 2592000000ULL
#define MS_IN_DAY   86400000ULL
#define MS_IN_HOUR  3600000ULL
#define MS_IN_MIN   60000ULL
#define MS_IN_SEC   1000ULL

uint64_t
rfc3339_with_ms_to_ms(const char *s)
{
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

	return year  * MS_IN_YEAR
	     + month * MS_IN_MONTH
	     + day   * MS_IN_DAY
	     + hour  * MS_IN_HOUR
	     + min   * MS_IN_MIN
	     + sec   * MS_IN_SEC
	     + ms;
}

uint64_t
date_to_ms(const char *s, const char **endp)
{
	assert(s != NULL);
	assert(strnlen(s, 10) == 10);

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
	s += 2;

	uint64_t ms = year  * MS_IN_YEAR
	            + month * MS_IN_MONTH
		    + day   * MS_IN_DAY;

	if (endp != NULL)
		*endp = s;

	return ms;
}

uint64_t
time_without_ms_to_ms(const char *s, const char **endp)
{
	uint64_t hour = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 3; // Skip ':'
	uint64_t min = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 3; // Skip ':'
	uint64_t sec = ctoi[(int)s[0]] * 10 + ctoi[(int)s[1]];
	s += 2;

	uint64_t ms = hour * MS_IN_HOUR
	            + min  * MS_IN_MIN
	            + sec  * MS_IN_SEC;

	if (endp != NULL)
		*endp = s;

	return ms;
}
