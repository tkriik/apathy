#ifndef FIELD_H
#define FIELD_H

#include "file_view.h"
#include "regex.h"

#define NFIELD_TYPES 11
enum field_type {
	FIELD_RFC3339 = 0,
	FIELD_RFC3339_NO_MS,
	FIELD_DATE,
	FIELD_TIME,

	FIELD_IPADDR,
	FIELD_USERAGENT,

	FIELD_REQUEST,
	FIELD_METHOD,
	FIELD_PROTOCOL,
	FIELD_DOMAIN,
	FIELD_ENDPOINT,
	/* TODO: query */

	FIELD_UNKNOWN
};

struct field_view {
	int         len;
	const char *src;
};

struct field_info {
	enum   field_type type;
	int    index;
	size_t nmatches;
	int    is_session;
	int    is_custom;
};

struct line_config {
	regex_t     regexes[NFIELD_TYPES];

	size_t  nall_fields;
#define NALL_FIELDS_MAX 512
	enum    field_type active_fields[NALL_FIELDS_MAX];

	size_t  ntotal_field_info;
	struct  field_info total_field_info[NFIELD_TYPES];

	size_t nscan_field_info;
	struct field_info scan_field_info[NFIELD_TYPES];
};

size_t      get_fields(struct field_view *, int, const char *, int , const char **);
enum        field_type infer_field_type(struct line_config *, struct field_view *);
const char *field_type_str(enum field_type);
void        amend_line_config(struct line_config *, enum field_type, size_t);
void        init_line_config(struct line_config *, struct file_view *, const char *, const char *);

#endif
