#include <inttypes.h>
#include <stdio.h>

#include "debug.h"
#include "field.h"

void
debug_line_config(struct line_config *lc)
{
//struct line_config {
//	int    rfc3339;   /* Index to RFC3339 timestamp; REQUIRED */
//	int    ipaddr;    /* IP address;  optional */
//	int    request;   /* Index to request field;     REQUIRED */
//	int    useragent; /* Index to user agent string; optional */
//
//	int         ntotal_fields;
//	int         nfields;
//	struct      field_idx indices[NFIELD_TYPES];
//	const char *session_fields;
//
//	regex_t regexes[NFIELD_TYPES];
//};

	printf("----- BEGIN LINE CONFIG -----\n");
	printf(
"- ntotal_field_info: %zu\n"
"- total_field_info:\n",
	    lc->ntotal_field_info);
	for(size_t i = 0; i < NFIELD_TYPES; i++) {
		struct field_info *fi = &lc->total_field_info[i];
		printf(
"    [%zu]:\n"
"        - type: %s\n"
"        - index: %d\n"
"        - nmatches: %zu\n"
"        - is_session: %s\n"
"        - is_custom: %s\n",
		    i,
		    field_type_str(fi->type),
		    fi->index,
		    fi->nmatches,
		    fi->is_session ? "true" : "false",
		    fi->is_custom ? "true" : "false");
	}

	printf(
"- nscan_field_info: %zu\n"
"- scan_field_info:\n",
	    lc->nscan_field_info);
	for(size_t i = 0; i < lc->nscan_field_info; i++) {
		struct field_info *fi = &lc->scan_field_info[i];
		printf(
"    [%zu]:\n"
"        - type: %s\n"
"        - index: %d\n"
"        - nmatches: %zu\n"
"        - is_session: %s\n"
"        - is_custom: %s\n",
		    i,
		    field_type_str(fi->type),
		    fi->index,
		    fi->nmatches,
		    fi->is_session ? "true" : "false",
		    fi->is_custom ? "true" : "false");
	}

	printf("----- END LINE CONFIG -----\n");
}

void
debug_truncate_patterns(struct truncate_patterns *tp)
{
	printf("----- BEGIN TRUNCATE PATTERNS -----\n");
	for (int p = 0; p < tp->npatterns; p++) {
		printf("[%d]:\n", p);
		printf("    - pattern: \"%s\"\n", tp->patterns[p]);
		printf("    - alias: \"%s\"\n", tp->aliases[p]);
	}
	printf("----- END TRUNCATE PATTERNS -----\n");
}
void
debug_request_set(struct request_set *rs)
{
	printf("----- BEGIN REQUEST SET -----\n");
	uint64_t min_bucket_count = HASH_COUNT(rs->handles[0]);
	uint64_t max_bucket_count = HASH_COUNT(rs->handles[0]);
	uint64_t total_count = 0;
	for (size_t i = 1; i < REQUEST_SET_NBUCKETS; i++) {
		size_t bucket_count = HASH_COUNT(rs->handles[i]);
		total_count += bucket_count;
		if (bucket_count < min_bucket_count)
			min_bucket_count = bucket_count;
		if (max_bucket_count < bucket_count)
			max_bucket_count = bucket_count;
	}
	printf("min_bucket_count: %" PRIu64 "\n", min_bucket_count);
	printf("max_bucket_count: %" PRIu64 "\n", max_bucket_count);
	printf("avg_bucket_count: %lf\n", (double)total_count / REQUEST_SET_NBUCKETS);
	printf("total_count: %" PRIu64 "\n", total_count);
	for (size_t i = 0; i < REQUEST_SET_NBUCKETS; i++) {
		struct request_set_entry *entry, *tmp;
		HASH_ITER(hh, rs->handles[i], entry, tmp) {
			printf("%5" PRIu64 " %p \"%s\"\n", entry->rid, entry->data, entry->data);
		}
	}
	printf("----- END REQUEST SET -----\n");
}

void
debug_request_table(struct request_table *rt)
{
	printf("----- BEGIN REQUEST TABLE -----\n");
	for (size_t i = REQUEST_ID_START; i < rt->nrequests; i++)
		printf("%-5zu %p \"%s\"\n", i, rt->requests[i], rt->requests[i]);
	printf("----- END REQUEST TABLE -----\n");
}

void
debug_session_map(struct session_map *sm)
{
	printf("----- BEGIN SESSION MAP -----\n");
	uint64_t min_bucket_count = HASH_COUNT(sm->handles[0]);
	uint64_t max_bucket_count = HASH_COUNT(sm->handles[0]);
	uint64_t total_count = 0;
	for (size_t i = 1; i < SESSION_MAP_NBUCKETS; i++) {
		size_t bucket_count = HASH_COUNT(sm->handles[i]);
		total_count += bucket_count;
		if (bucket_count < min_bucket_count)
			min_bucket_count = bucket_count;
		if (max_bucket_count < bucket_count)
			max_bucket_count = bucket_count;
	}
	printf("min_bucket_count: %" PRIu64 "\n", min_bucket_count);
	printf("max_bucket_count: %" PRIu64 "\n", max_bucket_count);
	printf("avg_bucket_count: %lf\n", (double)total_count / SESSION_MAP_NBUCKETS);
	printf("total_count: %" PRIu64 "\n", total_count);
	size_t session_idx = 0;
	for (size_t bucket_idx = 0; bucket_idx < SESSION_MAP_NBUCKETS; bucket_idx++) {
		struct session_map_entry *entry, *tmp;
		HASH_ITER(hh, sm->handles[bucket_idx], entry, tmp) {
			printf("[%zu]:\n", session_idx);
			printf("    sid: %016" PRIx64 "\n", entry->sid);
			printf("    nrequests: %zu\n", entry->nrequests);
			printf("    requests: %p\n", entry->requests);
			for (size_t i = 0; i < entry->nrequests; i++) {
				printf("        %" PRIu64 " %" PRIuRID "\n",
				       entry->requests[i].ts / 1000, entry->requests[i].rid);
			}
			session_idx++;
		}
	}
	printf("----- END SESSION MAP -----\n");
}

void
debug_path_graph(struct path_graph *pg)
{
	printf("----- BEGIN PATH GRAPH -----\n");
	printf("total_nedges: %zu\n", pg->total_nedges);
	printf("nvertices: %zu\n", pg->nvertices);
	printf("vertices:\n");
	for (size_t v = 0; v < pg->capvertices; v++) {
		struct path_graph_vertex *vertex = &pg->vertices[v];
		if (is_null_vertex(vertex))
			continue;
		printf("    [%zu]:\n", v);
		printf("        rid: %" PRIu64 "\n", vertex->rid);
		printf("        nedges: %zu\n", vertex->nedges);
		printf("        lim_nedges: %zu\n", vertex->lim_nedges);
		printf("        edges: %p\n", vertex->edges);
		for (size_t e = 0; e < vertex->nedges; e++) {
			struct path_graph_edge *edge = &vertex->edges[e];
			printf("            %" PRIu64 " (%" PRIu64 " hits)\n", edge->rid, edge->nhits);
		}
	}
	printf("----- END PATH GRAPH -----\n");
}
