#ifndef PATH_GRAPH_H
#define PATH_GRAPH_H

#include "request.h"
#include "session.h"

struct path_graph_edge {
	request_id_t rid;          /* Outward request edge */
	uint64_t     nhits;        /* Hits per this edge */
	double       duration_cma; /* Cumulative moving average for duration (milliseconds) */
};

/* Path edge information. */
struct path_graph_vertex {
#define PATH_GRAPH_VERTEX_INIT_LIM_NEDGES 8
	request_id_t rid;                    /* Request ID */
	size_t       nedges;                 /* Number of outward edges */
	size_t       lim_nedges;             /* Edge buffer limit */
	struct       path_graph_edge *edges; /* Outward edges */
	uint64_t     total_nhits_in;         /* Total number of hits to this vertex */
	uint64_t     total_nhits_out;        /* Total number of hits from this vertex */
	uint64_t     min_depth;
};

static const struct path_graph_vertex NULL_VERTEX = {
	.rid             = REQUEST_ID_INVAL,
	.nedges          = 0,
	.lim_nedges      = 0,
	.edges           = NULL,
	.total_nhits_in  = 0,
	.total_nhits_out = 0
};

struct path_graph {
	size_t total_nedges;                /* Total number of unique path edges */
	size_t nvertices;                   /* Number of vertices */
	size_t capvertices;                 /* Vertex buffer capacity */
	struct path_graph_vertex *vertices; /* Vertex buffer */

	/* Statistics */
	uint64_t total_nhits;               /* Total number of hits */
};

void init_path_graph(struct path_graph *, struct request_table *);
int  is_null_vertex(struct path_graph_vertex *);
void gen_path_graph(struct path_graph *, struct request_set *, struct session_map *);

#endif
