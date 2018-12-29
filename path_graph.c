#include <assert.h>

#include "path_graph.h"
#include "request.h"
#include "session.h"
#include "util.h"

static void
amend_path_graph_vertex(struct path_graph *pg, uint64_t depth,
                        request_id_t rid, request_id_t edge_rid,
			uint64_t ts, uint64_t edge_ts)
{
	assert(pg != NULL);
	assert(rid != REQUEST_ID_INVAL);

	struct path_graph_edge *edge;
	struct path_graph_vertex *vertex = &pg->vertices[rid];

	if (is_null_vertex(vertex)) {
		vertex->rid = rid;
		vertex->edges = calloc(PATH_GRAPH_VERTEX_INIT_LIM_NEDGES, sizeof(*vertex->edges));
		if (vertex->edges == NULL)
			ERR("%s", "calloc");
		vertex->lim_nedges = PATH_GRAPH_VERTEX_INIT_LIM_NEDGES;

		if (edge_rid != REQUEST_ID_INVAL) {
			edge = &vertex->edges[0];
			edge->rid = edge_rid;
			edge->nhits = 1;
			edge->duration_cma = (double)edge_ts - (double)ts;
			vertex->nedges = 1;
			vertex->total_nhits_out++;
			pg->total_nedges++;
		}

		vertex->total_nhits_in++;
		vertex->min_depth = depth;
		pg->total_nhits++;
		pg->nvertices++;

		return;
	}

	vertex->total_nhits_in++;
	vertex->min_depth = MIN(depth, vertex->min_depth);
	pg->total_nhits++;

	if (edge_rid == REQUEST_ID_INVAL)
		return;

	/* See if edge request already exists, if yes, increment hit count */
	size_t edge_idx;
	for (edge_idx = 0; edge_idx < vertex->nedges; edge_idx++) {
		edge = &vertex->edges[edge_idx];
		if (edge->rid == edge_rid) {
			double duration = (double)edge_ts - (double)ts;
			double duration_cma = edge->duration_cma;
			edge->duration_cma =
			    (duration + (double)edge->nhits * duration_cma)
			    / ((double)edge->nhits + 1);
			edge->nhits++;
			vertex->total_nhits_out++;
			return;
		}
	}

	/* Resize edge buffer if needed */
	if (vertex->nedges == vertex->lim_nedges) {
		size_t new_lim = vertex->lim_nedges * 2;
		/* TODO: overflow check */
		size_t new_size = new_lim * sizeof(*vertex->edges);
		struct path_graph_edge *new_edges = realloc(vertex->edges, new_size);
		if (new_edges == NULL)
			ERR("%s", "realloc");
		vertex->edges = new_edges;
		vertex->lim_nedges = new_lim;
	}

	/* Set new edge at this point */
	edge_idx = vertex->nedges;
	edge = &vertex->edges[edge_idx];
	edge->rid = edge_rid;
	edge->nhits = 1;
	edge->duration_cma = (double)edge_ts - (double)ts;

	vertex->nedges++;
	vertex->total_nhits_out++;
	pg->total_nedges++;
}

static int
cmp_session_request(const void *p1, const void *p2)
{
	const struct session_request *r1 = p1;
	const struct session_request *r2 = p2;

	if (r1->ts == r2->ts)
		return 0;
	else
		return r1->ts > r2->ts;
}

static int
cmp_path_graph_vertex_by_hits(const void *p1, const void *p2)
{
	const struct path_graph_vertex *v1 = p1;
	const struct path_graph_vertex *v2 = p2;

	if (v1->min_depth < v2->min_depth)
		return -1;
	else if (v1->min_depth > v2->min_depth)
		return 1;

	uint64_t score1 = v1->total_nhits_in + v1->total_nhits_out;
	uint64_t score2 = v2->total_nhits_in + v2->total_nhits_out;

	if (score1 == score2)
		return 0;
	else
		return score1 < score2;
}

static int
cmp_path_graph_edge_by_hits(const void *p1, const void *p2)
{
	const struct path_graph_edge *e1 = p1;
	const struct path_graph_edge *e2 = p2;

	if (e1->nhits == e2->nhits)
		return 0;
	else
		return e1->nhits < e2->nhits;
}

void
init_path_graph(struct path_graph *pg, struct request_table *rt)
{
	assert(pg != NULL);
	assert(rt != NULL);

	pg->total_nedges = 0;
	pg->total_nhits = 0;
	pg->nvertices = 0;
	pg->capvertices = rt->nrequests;
	pg->vertices = calloc(pg->capvertices, sizeof(*pg->vertices));
	if (pg->vertices == NULL)
		ERR("%s", "calloc");

	for (size_t v = 0; v < pg->capvertices; v++)
		pg->vertices[v] = NULL_VERTEX;
}

int
is_null_vertex(struct path_graph_vertex *v)
{
	assert(v != NULL);
	return v->rid == REQUEST_ID_INVAL;
}

void
gen_path_graph(struct path_graph *pg, struct request_set *rs,
               struct session_map *sm)
{
	assert(pg != NULL);
	assert(rs != NULL);
	assert(sm != NULL);

	/* Generate request path edges */
	for (size_t bucket_idx = 0; bucket_idx < SESSION_MAP_NBUCKETS;
	     bucket_idx++) {
		struct session_map_entry *entry, *tmp;
		HASH_ITER(hh, sm->handles[bucket_idx], entry, tmp) {
			qsort(entry->requests, entry->nrequests,
			    sizeof(*entry->requests), cmp_session_request);
			uint64_t depth = 1;
			for (size_t r = 0, e = 1; r < entry->nrequests; r++, e++) {
				struct session_request *node_req = &entry->requests[r];
				request_id_t rid = node_req->rid;
				uint64_t ts = node_req->ts;

				struct session_request *edge_req = NULL;
				request_id_t edge_rid = REQUEST_ID_INVAL;
				uint64_t edge_ts = 0;
				if (e < entry->nrequests) {
					edge_req = &entry->requests[e];
					edge_rid = edge_req->rid;
					edge_ts = edge_req->ts;
				}
				amend_path_graph_vertex(pg, depth, rid, edge_rid,
				    ts, edge_ts);
				depth = rid == edge_rid ? depth : depth + 1;
			}
		}
	}

	/* Sort vertices and edges by hit counts */
	qsort(pg->vertices, pg->nvertices, sizeof(*pg->vertices),
	    cmp_path_graph_vertex_by_hits);
	for (size_t v = 0; v < pg->nvertices; v++) {
		struct path_graph_vertex *vertex = &pg->vertices[v];
		qsort(vertex->edges, vertex->nedges, sizeof(*vertex->edges),
		    cmp_path_graph_edge_by_hits);
	}
}
