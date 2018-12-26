#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <regex.h>
#include <string.h>

#include "file_view.h"
#include "regex.h"
#include "truncate.h"
#include "util.h"

static char *
trim_line(char *src, size_t *line_sizep)
{
	assert(src != NULL);
	assert(line_sizep != NULL);

	char *line = src;
	while (isspace(*line))
		*line++ = '\0';

	size_t line_size = strcspn(line, "\n");
	line[line_size] = '\0';
	for (size_t i = line_size - 1; 0 < i; i--) {
		if (isspace(line[i])) {
			line[i] = '\0';
		} else
			break;
	}

	*line_sizep = line_size;

	assert(!isspace(*line) && !isspace(line[line_size - 1]));

	return line;
}

static int
is_comment_line(const char *line)
{
	assert(line != NULL);

	return *line == '#';
}

static void
get_pattern_alias(char *line, const char **aliasp, const char **pattern_linep)
{
	assert(line != NULL);
	assert(*line != '\0' && !isspace(*line));
	assert(aliasp != NULL);
	assert(pattern_linep != NULL);

	*aliasp = line;

	if (*line != '$') {
		*pattern_linep = line;
		return;
	}

	size_t alias_size = 0;
	char c;
	char *s = line;
	while ((c = *s++) != '\0' && (!isspace(c) && c != '='))
		alias_size++;
	line[alias_size] = '\0';

	size_t sep_size = 1;
	while ((c = *s++) != '\0' && (isspace(c) || c == '='))
		sep_size++;
	*pattern_linep = line + alias_size + sep_size;
}

void
init_truncate_patterns(struct truncate_patterns *tp, const char *path)
{
	assert(tp != NULL);
	assert(path != NULL);

	struct file_view file_view;
	init_file_view_readwrite(&file_view, path);

	tp->npatterns = 0;
	tp->max_alias_size = 0;

	char *src = file_view.src;
	char *line = src;
	while (*line != '\0' && tp->npatterns < TRUNCATE_NPATTERNS_MAX) {
		size_t line_size;
		line = trim_line(line, &line_size);

		if (line_size == 0) {
			line += line_size + 1;
			continue;
		}

		if (is_comment_line(line)) {
			line += line_size + 1;
			continue;
		}

		const char *alias;
		const char *pattern;
		get_pattern_alias(line, &alias, &pattern);

		regex_t regex = {0};
		int cflags = REG_EXTENDED | REG_NEWLINE;
		compile_regex(&regex, pattern, cflags);
		tp->regexes[tp->npatterns] = regex;
		tp->patterns[tp->npatterns] = pattern;
		tp->aliases[tp->npatterns] = alias;
		size_t alias_size = strlen(alias);
		tp->alias_sizes[tp->npatterns] = alias_size;
		tp->max_alias_size = MAX(alias_size, tp->max_alias_size);
		tp->npatterns++;

		line += line_size + 1;
	}
}

/*
 * Checks if the request data in raw_buf matches against any truncate
 * patterns, and replaces any matches with their respective aliases.
 * The resulting modified request data is stored in trunc_buf.
 *
 * Returns the size of the (possibly) modified request data.
 */
size_t
truncate_raw_request(char *trunc_buf, size_t trunc_buf_size,
    const char *raw_buf, size_t raw_buf_size, struct truncate_patterns *tp)
{
	assert(trunc_buf != NULL);
	assert(raw_buf != NULL);
	assert(tp != NULL);

	memset(trunc_buf, '\0', trunc_buf_size);
	size_t trunc_size = 0;

	int pattern_idx = -1;
	int npatterns = tp->npatterns;
	regex_t *regex = NULL;
	const char *pattern = NULL;
	const char *alias = NULL;
	size_t alias_size = 0;
	regmatch_t matches[1];
	for (int p = 0; p < npatterns; p++) {
		regex = &tp->regexes[p];
		pattern = tp->patterns[p];
		alias = tp->aliases[p];
		if (get_regex_matches(regex, raw_buf, matches, 1) == REG_NOMATCH)
			continue;
		pattern_idx = p;
		break;
	}

	if (pattern_idx == -1) {
		memcpy(trunc_buf, raw_buf, raw_buf_size);
		return raw_buf_size;
	}

	assert(regex != NULL);
	assert(pattern != NULL);
	assert(alias != NULL);

	regmatch_t *match = &matches[0];
	alias_size = tp->alias_sizes[pattern_idx];
	size_t end_offset;
	do {
		assert(match->rm_so != -1);

		size_t start_offset = match->rm_so;
		end_offset = match->rm_eo;

		memcpy(trunc_buf + trunc_size, raw_buf, start_offset);
		trunc_size += start_offset;

		memcpy(trunc_buf + trunc_size, alias, alias_size);
		trunc_size += alias_size;

		raw_buf += end_offset;
	} while (get_regex_matches(regex, raw_buf, matches, 1) != REG_NOMATCH);

	assert(trunc_size == strlen(trunc_buf));
	return trunc_size;
}
