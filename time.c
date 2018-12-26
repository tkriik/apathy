#include "time.h"

/*
 * Convert RFC3339 timestamp to an roughly estimated number of milliseconds.
 *
 * We don't need accurate timekeeping since we are only
 * concerned with average durations between path transitions, so
 * we can take this faster shortcut with manual parsing.
 */
uint64_t
ts_rfc3339_to_ms(const char *s)
{
	static const char ctoi[256] = {
	    ['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3, ['4'] = 4,
	    ['5'] = 5, ['6'] = 6, ['7'] = 7, ['8'] = 8, ['9'] = 9
	};

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

#define MS_IN_YEAR  31104000000ULL
#define MS_IN_MONTH 2592000000ULL
#define MS_IN_DAY   86400000ULL
#define MS_IN_HOUR  3600000ULL
#define MS_IN_MIN   60000ULL
#define MS_IN_SEC   1000ULL
	return year  * MS_IN_YEAR
	     + month * MS_IN_MONTH
	     + day   * MS_IN_DAY
	     + hour  * MS_IN_HOUR
	     + min   * MS_IN_MIN
	     + sec   * MS_IN_SEC
	     + ms;
}
