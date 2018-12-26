#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "field.h"
#include "util.h"

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
int
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

enum field_type
infer_field_type(struct field_view *fv, struct regex_info *rx_info)
{
#define FIELD_MAX 4096
	char field[FIELD_MAX + 1] = {0};
	int ncopy = MIN(fv->len, FIELD_MAX);
	memcpy(field, fv->src, ncopy);

	if (regex_does_match(&rx_info->rfc3339, field))
		return FIELD_TS_RFC3339;

	if (regex_does_match(&rx_info->ipv4, field))
		return FIELD_IPADDR;

	if (regex_does_match(&rx_info->request, field))
		return FIELD_REQUEST;

	if (regex_does_match(&rx_info->useragent, field))
		return FIELD_USERAGENT;

	return FIELD_UNKNOWN;
}

void
amend_line_config(struct line_config *lc, enum field_type ftype, int idx)
{
	if (LC_FIELDS_MAX <= lc->nfields)
		return;

	int is_session = 0;;

	switch (ftype) {
	case FIELD_TS_RFC3339:
		if (lc->ts_rfc3339 == -1)
			lc->ts_rfc3339 = idx;
		else
			return;
		break;
	case FIELD_IPADDR:
		if (lc->ip1 == -1) {
			lc->ip1 = idx;
			if (strstr(lc->sfields, "ip1") != NULL)
				is_session = 1;
		} else if (lc->ip2 == -1) {
			lc->ip2 = idx;
			if (strstr(lc->sfields, "ip2") != NULL)
				is_session = 1;
		} else
			return;
		break;
	case FIELD_REQUEST:
		if (lc->request == -1)
			lc->request = idx;
		else
			return;
		break;
	case FIELD_USERAGENT:
		if (lc->useragent == -1) {
			lc->useragent = idx;
			if (strstr(lc->sfields, "useragent") != NULL)
				is_session = 1;
		} else
			return;
		break;
	default:
		return;
	}

	lc->indices[lc->nfields] = (struct field_idx){
		.type       = ftype,
		.i          = idx,
		.is_session = is_session
	};
	lc->nfields++;
}

void
check_line_config(struct line_config *lc)
{
	if (lc->ip1 == -1 || lc->ip2 == -1)
		WARNX("%s", "source and/or destination IP address fields not found");
	if (lc->useragent == -1)
		WARNX("%s", "user agent field not found");
	if (lc->ts_rfc3339 == -1)
		ERRX("%s", "timestamp field not found");
	if (lc->request == -1)
		ERRX("%s", "request field not found");
	if (lc->ip1 == -1 && lc->ip2 == -1 && lc->useragent == -1)
		ERRX("%s", "source IP address, destination IP address nor user agent field found");
}

void
init_line_config(struct line_config *lc, struct file_view *log_view,
		 struct regex_info *rx_info, const char *session_fields)
{
	assert(lc != NULL);
	assert(log_view != NULL);
	assert(rx_info != NULL);

	const char *src = log_view->src;

	memset(lc, 0, sizeof(*lc));
	*lc = (struct line_config){
		.ts_rfc3339    = -1,
		.ip1           = -1,
		.ip2           = -1,
		.request       = -1,
		.useragent     = -1,

		.ntotal_fields =  0,
		.nfields       =  0,
		.sfields       = session_fields
	};

	struct field_view fvs[NFIELDS_MAX] = {0};
	const char *endp;
	int nfields = get_fields(fvs, NFIELDS_MAX, src, 1, &endp);
	lc->ntotal_fields = nfields;
	for (int i = 0; i < nfields; i++) {
		struct field_view *fv = &fvs[i];
		enum field_type ftype = infer_field_type(fv, rx_info);
		amend_line_config(lc, ftype, i);
	}
	
	check_line_config(lc);
}

void
validate_session_fields(const char *session_fields)
{
	char buf[64] = {0};
	int ncopy = MIN(strlen(session_fields), sizeof(buf) - 1);
	memcpy(buf, session_fields, ncopy);
	char *s = buf;
	char *endp = s;
	while ((s = strtok(endp, ",")) != NULL) {
		endp = NULL;
		if (strcmp(s, "ip1") == 0)
			continue;
		if (strcmp(s, "ip2") == 0)
			continue;
		if (strcmp(s, "useragent") == 0)
			continue;
		errx(1, "error: invalid session field: %s\n", s);
	}
}
