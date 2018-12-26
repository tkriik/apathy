#include <assert.h>
#include <regex.h>
#include <stddef.h>
#include <string.h>

#include "field.h"
#include "regex.h"
#include "util.h"

static const enum field_type FIELD_TYPES[NFIELD_TYPES] = {
	FIELD_RFC3339,
	FIELD_DATE,
	FIELD_TIME,

	FIELD_IPADDR,
	FIELD_USERAGENT,

	FIELD_REQUEST,
	FIELD_METHOD,
	FIELD_PROTOCOL,
	FIELD_DOMAIN,
	FIELD_ENDPOINT
};

#define RFC3339_PATTERN   "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
#define DATE_PATTERN      "^[0-9]{4}-[0-9]{2}-[0-9]{2}"
#define TIME_PATTERN      "^[0-9]{2}:[0-9]{2}:[0-9]{2}"

#define IPV4_PATTERN      "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
#define USERAGENT_PATTERN "^(Mozilla|http-kit)"

#define REQUEST_PATTERN   "^(GET|HEAD|POST|PUT|OPTIONS|PATCH)\\s+(http|https)://.+"
#define METHOD_PATTERN    "^(GET|HEAD|POST|PUT|OPTIONS|PATCH)$"
#define PROTOCOL_PATTERN  "^(http|https)$"
//#define DOMAIN_PATTERN    "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$" TODO: fix
#define DOMAIN_PATTERN    "^.+\\..+$"
#define ENDPOINT_PATTERN  "^\\/.+$"

static const char *FIELD_PATTERNS[NFIELD_TYPES] = {
	[FIELD_RFC3339]   = RFC3339_PATTERN,
	[FIELD_DATE]      = DATE_PATTERN,
	[FIELD_TIME]      = TIME_PATTERN,

	[FIELD_IPADDR]    = IPV4_PATTERN,
	[FIELD_USERAGENT] = USERAGENT_PATTERN,

	[FIELD_REQUEST]   = REQUEST_PATTERN,
	[FIELD_METHOD]    = METHOD_PATTERN,
	[FIELD_PROTOCOL]  = PROTOCOL_PATTERN,
	[FIELD_DOMAIN]    = DOMAIN_PATTERN,
	[FIELD_ENDPOINT]  = ENDPOINT_PATTERN
};

/*
 * Fills *fvs with at most max_fields number of field views
 * found in *src, and stores the end of seeking area to **endp,
 * or NULL if a '\0' is reached.
 *
 * If skip_line_seek is true, we assume we are at the beginning
 * of a line. Otherwise we skip to the next line before
 * parsing field views.
 *
 * Currently parses standalone fields, such as '1 2 3' into "1", "2" and "3",
 * and double-quoted fields, so that '"GET http://my-api/"' is read as
 * "GET http://my-api/" instead of '"GET' and 'http://my-api/"'.
 *
 * Returns the number of fields found.
 *
 * TODO: use strspn(3), strcspn(3)
 */
size_t
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

const char *
field_type_str(enum field_type ftype)
{
	static const char *table[NFIELD_TYPES] = {
		[FIELD_RFC3339]   = "rfc3339",
		[FIELD_DATE]      = "date",
		[FIELD_TIME]      = "time",

		[FIELD_IPADDR]    = "ipaddr",
		[FIELD_USERAGENT] = "useragent",

		[FIELD_REQUEST]   = "request",
		[FIELD_METHOD]    = "method",
		[FIELD_PROTOCOL]  = "protocol",
		[FIELD_DOMAIN]    = "domain",
		[FIELD_ENDPOINT]  = "endpoint"
	};

	if (ftype == FIELD_UNKNOWN)
		return "UNKNOWN";

	if (ftype < NFIELD_TYPES)
		return table[ftype];

	return "INVALID";
}

enum field_type
infer_field_type(struct line_config *lc, struct field_view *fv)
{
#define FIELD_MAX 4096
	char field[FIELD_MAX + 1] = {0};
	int ncopy = MIN(fv->len, FIELD_MAX);
	memcpy(field, fv->src, ncopy);

	for (size_t i = 0; i < NFIELD_TYPES; i++) {
		enum field_type ftype = FIELD_TYPES[i];
		regex_t *r = &lc->regexes[ftype];
		if (regex_does_match(r, field)) {
			return ftype;
		}
	}

	return FIELD_UNKNOWN;
}

void
amend_line_config(struct line_config *lc, enum field_type ftype, size_t idx)
{
	assert(ftype < NFIELD_TYPES);

	if (NFIELD_TYPES <= lc->ntotal_field_info)
		return;

	struct field_info *fi = &lc->total_field_info[ftype];
	if (fi->is_custom)
		return;

	if (lc->active_fields[idx] != FIELD_UNKNOWN) {
		ERRX("cannot re-use field '%s' at index %zu for field '%s'",
		    field_type_str(lc->active_fields[idx]),
		    idx,
		    field_type_str(ftype));
	}

	if (fi->type == FIELD_UNKNOWN) {
		fi->type = ftype;
		fi->index = idx;
		lc->ntotal_field_info++;
		lc->active_fields[idx] = ftype;
	}

	fi->nmatches++;

	if (1 < fi->nmatches)
		WARNX(
"multiple matches for field '%s', "
"consider using the '--index %s=...' command line option "
"for specifying a custom field index",
		    field_type_str(ftype),
		    field_type_str(ftype));

}

static int
is_field_set(struct line_config *lc, enum field_type ftype)
{
	assert(ftype < NFIELD_TYPES);
	return lc->total_field_info[ftype].type == ftype;
}

static int
is_session_field(struct line_config *lc, enum field_type ftype)
{
	assert(ftype < NFIELD_TYPES);
	return lc->total_field_info[ftype].is_session;
}

static void
set_scan_field(struct line_config *lc, enum field_type ftype)
{
	assert(is_field_set(lc, ftype));
	assert(lc->nscan_field_info < lc->ntotal_field_info);
	lc->scan_field_info[lc->nscan_field_info++] = lc->total_field_info[ftype];
	assert(lc->nscan_field_info <= lc->ntotal_field_info);
}

static void
init_scan_fields(struct line_config *lc)
{
	if (is_field_set(lc, FIELD_RFC3339)) {
		set_scan_field(lc, FIELD_RFC3339);
	} else if (is_field_set(lc, FIELD_DATE) && is_field_set(lc, FIELD_TIME)) {
		set_scan_field(lc, FIELD_DATE);
		set_scan_field(lc, FIELD_TIME);
	} else {
		ERRX("%s", "could not find RFC3339 timestamp, nor date and time fields");
	}

	if (is_session_field(lc, FIELD_IPADDR)) {
		if (is_field_set(lc, FIELD_IPADDR))
			set_scan_field(lc, FIELD_IPADDR);
		else
			ERRX("%s", "could not find IP address field");
	}

	if (is_session_field(lc, FIELD_USERAGENT)) {
		if (is_field_set(lc, FIELD_USERAGENT))
			set_scan_field(lc, FIELD_USERAGENT);
		else
			ERRX("%s", "could not find user agent field");
	}

	if (is_field_set(lc, FIELD_REQUEST)) {
		set_scan_field(lc, FIELD_REQUEST);
	} else if (is_field_set(lc, FIELD_METHOD)
	        && is_field_set(lc, FIELD_DOMAIN)
		&& is_field_set(lc, FIELD_ENDPOINT)) {
		set_scan_field(lc, FIELD_METHOD);
		set_scan_field(lc, FIELD_DOMAIN);
		set_scan_field(lc, FIELD_ENDPOINT);
	} else {
		ERRX("%s", "could not find request, nor method, domain and endpoint fields");
	}
}

static void override_line_config(struct line_config *, const char *);

static struct field_info *
get_field_info(struct line_config *lc, enum field_type ftype)
{
	assert(ftype < NFIELD_TYPES);

	return &lc->total_field_info[ftype];
}

static void
parse_session_fields(struct line_config *lc, const char *session_fields)
{
	assert(lc != NULL);
	assert(session_fields != NULL);

	char buf[64] = {0};
	int ncopy = MIN(strlen(session_fields), sizeof(buf) - 1);
	memcpy(buf, session_fields, ncopy);

	char *s = buf;
	char *endp = s;
	while ((s = strtok(endp, ",")) != NULL) {
		endp = NULL;
		struct field_info *fi;
		if (strcmp(s, "ipaddr") == 0) {
			fi = get_field_info(lc, FIELD_IPADDR);
			fi->is_session = 1;
			continue;
		}

		if (strcmp(s, "useragent") == 0) {
			fi = get_field_info(lc, FIELD_USERAGENT);
			fi->is_session = 1;
			continue;
		}

		ERRX("invalid session field: '%s'", s);
	}
}

void
init_line_config(struct line_config *lc, struct file_view *log_view,
		 const char *index_fields, const char *session_fields)
{
	assert(lc != NULL);
	assert(log_view != NULL);
	assert(session_fields != NULL);

	const char *src = log_view->src;

	memset(lc, 0, sizeof(*lc));
	*lc = (struct line_config){
	    .nall_fields       = 0,
	    .ntotal_field_info = 0,
	    .nscan_field_info  = 0
	};

	static const struct field_info null_field_info = {
		.type       = FIELD_UNKNOWN,
		.index      = -1,
		.nmatches   = 0,
		.is_session = 0,
		.is_custom  = 0
	};

	for (size_t i = 0; i < NFIELD_TYPES; i++) {
		lc->total_field_info[i] = null_field_info;
		lc->scan_field_info[i] = null_field_info;
	}

	for (size_t i = 0; i < NALL_FIELDS_MAX; i++)
		lc->active_fields[i] = FIELD_UNKNOWN;

	int cflags = REG_EXTENDED | REG_NOSUB | REG_NEWLINE;
	for (size_t i = 0; i < NFIELD_TYPES; i++) {
		enum field_type ftype = FIELD_TYPES[i];
		const char *pattern = FIELD_PATTERNS[ftype];
		regex_t *re = &lc->regexes[ftype];
		compile_regex(re, pattern, cflags);
	}

	parse_session_fields(lc, session_fields);

	struct field_view fvs[NALL_FIELDS_MAX] = {0};
	const char *endp;
	size_t nall_fields = get_fields(fvs, NALL_FIELDS_MAX, src, 1, &endp);
	if (nall_fields == NALL_FIELDS_MAX)
		WARNX("found possibly more than %d fields, ignoring the rest", NALL_FIELDS_MAX);

	lc->nall_fields = nall_fields;

	if (index_fields != NULL)
		override_line_config(lc, index_fields);

	for (size_t i = 0; i < nall_fields; i++) {
		struct field_view *fv = &fvs[i];
		enum field_type ftype = infer_field_type(lc, fv);
		if (ftype == FIELD_UNKNOWN)
			continue;

		amend_line_config(lc, ftype, i);
	}
	
	init_scan_fields(lc);
}

static enum field_type
str_to_field_type(const char *s)
{
	const static struct {
		const char *name;
		enum field_type type;
	} table[NFIELD_TYPES] = {
	    { "rfc3339",   FIELD_RFC3339   },
	    { "date",      FIELD_DATE,     },
	    { "time",      FIELD_TIME,     },
	    { "useragent", FIELD_USERAGENT },
	    { "ipaddr",    FIELD_IPADDR    },
	    { "request",   FIELD_REQUEST   },
	    { "method",    FIELD_METHOD    },
	    { "protocol",  FIELD_PROTOCOL  },
	    { "domain",    FIELD_DOMAIN    },
	    { "endpoint",  FIELD_ENDPOINT  }
	};

	for (size_t i = 0; i < NFIELD_TYPES; i++) {
		if (strcmp(table[i].name, s) == 0)
			return table[i].type;
	}

	return FIELD_UNKNOWN;
}

static void
override_line_config(struct line_config *lc, const char *index_fields)
{
	assert(lc != NULL);
	assert(index_fields != NULL);

	char buf[256] = {0};
	size_t ncopy = MIN(strlen(index_fields), sizeof(buf) - 1);
	memcpy(buf, index_fields, ncopy);

	char *s = buf;
	char *endp = s;

	while ((s = strtok(endp, ",")) != NULL) {
		endp = NULL;
		const char *field = s;
		size_t field_len = strcspn(s, "=");
		s[field_len] = '\0';

		const char *indexp = s + field_len + 1;
		int index = parse_long(indexp);
		if (index < 0 || lc->nall_fields <= (size_t)index) {
			ERRX("index for field '%s' out of range: %d\n",
			    field, index);
		}

		enum field_type ftype = str_to_field_type(field);
		if (ftype == FIELD_UNKNOWN)
			ERRX("unknown field type: '%s'", field);

		struct field_info *fi = &lc->total_field_info[ftype];
		fi->type = ftype;
		fi->index = index;
		fi->is_custom = 1;
		lc->active_fields[index] = ftype;
		lc->ntotal_field_info++;
	}
}
