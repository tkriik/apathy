#ifndef FIELD_H
#define FIELD_H

#include "file_view.h"
#include "regex.h"

enum field_type {
	FIELD_TS_RFC3339 = 1,
	FIELD_IPADDR,
	FIELD_REQUEST,
	FIELD_USERAGENT,
	FIELD_UNKNOWN
};

/*
 * View to a single field in a line.
 * We limit field views to 256 to avoid memory allocation.
 */
struct field_view {
#define NFIELDS_MAX 256
	int         len;
	const char *src;
};

/* Tells what type of field lies at a certain index. */
struct field_idx {
	enum field_type type;
	int  i;
	int  is_session; /* 1 if this field is used to construct session IDs */
};

/*
 * This is used to index certain fields in each line.
 *
 * The program reads the first line of a log file and uses that to
 * infer indices of fields relevant to us, so that when we are doing
 * a full scan we can find the desired fields more quickly.
 *
 * This only works if each line contains the same number of fields in
 * same order, but that should not be a problem with most log files.
 *
 * All of the 5 indices below are -1 if they're not found.
 */
struct line_config {
#define LC_FIELDS_MAX 5
	int    ts_rfc3339; /* Index to RFC3339 timestamp; REQUIRED */
	int    ip1;        /* Index to first IP address;  optional */
	int    ip2;        /* Index to second IP address; optional */
	int    request;    /* Index to request field;     REQUIRED */
	int    useragent;  /* Index to user agent string; optional */
	/*
	 * XXX:
	 * While the IP address fields and user agent fields are optional
	 * individually, it's required to have at least one of the three
	 * to get any meaningful path info out of the log file.
	 */

	int         ntotal_fields;
	int         nfields;
	struct      field_idx indices[LC_FIELDS_MAX + 1];
	const char *sfields;
};

int  get_fields(struct field_view *, int, const char *, int , const char **);
enum field_type infer_field_type(struct field_view *, struct regex_info *);
void amend_line_config(struct line_config *, enum field_type, int);
void check_line_config(struct line_config *);
void init_line_config(struct line_config *, struct file_view *, struct regex_info *, const char *);
void validate_session_fields(const char *);

#endif
