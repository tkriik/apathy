#include <assert.h>
#include <inttypes.h>
#include <math.h>

#include "dot.h"
#include "util.h"

static double
calc_dot_weight(uint64_t total_nhits, uint64_t nhits)
{
	assert(nhits <= total_nhits);
	double weight = sqrt((double)nhits / (double)total_nhits);
	assert(0.0 <= weight && weight <= 1.0);
	return weight;
}

static int
calc_dot_font_size(double weight)
{
#define DOT_WEAK_FONT_SIZE 14
#define DOT_STRONG_FONT_SIZE (3 * DOT_WEAK_FONT_SIZE)
#define DOT_FONT_SCALE (DOT_STRONG_FONT_SIZE - DOT_WEAK_FONT_SIZE)
	int font_size = DOT_WEAK_FONT_SIZE + (int)(weight * DOT_FONT_SCALE);
	assert(DOT_WEAK_FONT_SIZE <= font_size && font_size <= DOT_STRONG_FONT_SIZE);
	return font_size;
}

static double
calc_dot_pen_width(double weight)
{
#define DOT_WEAK_PEN_WIDTH 2.0
#define DOT_STRONG_PEN_WIDTH 6.0
#define DOT_PEN_WIDTH_SCALE (DOT_STRONG_PEN_WIDTH - DOT_WEAK_PEN_WIDTH)
	double pen_width = DOT_WEAK_PEN_WIDTH + weight * DOT_PEN_WIDTH_SCALE;
	assert(DOT_WEAK_PEN_WIDTH <= pen_width && pen_width <= DOT_STRONG_PEN_WIDTH);
	return pen_width;
}

typedef uint32_t color_t;

#define COLOR_R(c)       (((c) >> 16) & 0xFF)
#define COLOR_G(c)       (((c) >>  8) & 0xFF)
#define COLOR_B(c)       (((c) >>  0) & 0xFF)

static color_t
mkcolor(uint8_t r, uint8_t g, uint8_t b)
{
	color_t c = (r << 16) | (g << 8) | b;
	assert(c < (1 << 24));
	return c;
}

static color_t
hash_to_node_color(uint64_t hash)
{
	uint8_t r = 0x80 | (0xFF & (hash >> 16));
	uint8_t g = 0x80 | (0xFF & (hash >>  8));
	uint8_t b = 0x80 | (0xFF & (hash >>  0));
	return mkcolor(r, g, b);
}

static color_t
node_to_edge_color(color_t c, double mult)
{
	uint8_t r = MAX(COLOR_R(c) * mult, 0x00);
	uint8_t g = MAX(COLOR_G(c) * mult, 0x00);
	uint8_t b = MAX(COLOR_B(c) * mult, 0x00);
	return mkcolor(r, g, b);
}

#define COLOR_FMT "\"#%06" PRIx32 "\""

void
output_dot_graph(FILE *out, struct path_graph *pg, struct request_table *rt)
{
	assert(out != NULL);
	assert(pg != NULL);
	assert(rt != NULL);

	struct path_graph_vertex *vertex;
	request_id_t rid;
	const char *request_data;
	uint64_t request_hash;

	fprintf(out,
"digraph apathy_graph {\n"
"    nodesep=1.0;\n"
"    rankdir=LR;\n"
"    ranksep=1.0;\n"
"\n");


	uint64_t prev_depth = 0, cur_depth = 0;
	int first = 1;
	int open_subgraph = 1;

	/* Declare nodes with labels, and rank by minimum depth */
	size_t v = 0;
	uint64_t subgraph_id = 0;
	while (v < pg->capvertices) {
		vertex = &pg->vertices[v];
		if (is_null_vertex(vertex))
			continue;

		if (open_subgraph) {
			fprintf(out,
"    subgraph s%" PRIu64 " {\n"
"        rank = same;\n",
			    subgraph_id);
			open_subgraph = 0;
			subgraph_id++;
		}

		if (first) {
			cur_depth = vertex->min_depth;
			prev_depth = cur_depth;
			first = 0;
		} else {
			prev_depth = cur_depth;
			cur_depth = vertex->min_depth;
			if (prev_depth != cur_depth)
				goto close_subgraph;
		}

		rid = vertex->rid;
		request_data = rt->requests[rid];
		request_hash = rt->hashes[rid];

		double pct_in = 100 * ((double)vertex->total_nhits_in / (double)pg->total_nhits);
		double pct_out = 100 * ((double)vertex->total_nhits_out / (double)vertex->total_nhits_in);
		double weight = calc_dot_weight(pg->total_nhits, vertex->total_nhits_in);
		int font_size = calc_dot_font_size(weight);
		double pen_width = calc_dot_pen_width(weight);
		color_t node_color = hash_to_node_color(request_hash);

		fprintf(out,
"        r%" PRIuRID " [label=\"%s\\n(in %.2lf%% (%" PRIu64 "), out %.2lf%% (%" PRIu64 "))\", "
                       "fontsize=%d, "
		       "style=filled, "
		       "fillcolor=" COLOR_FMT ", "
		       "penwidth=%lf];\n",
		    rid, request_data, pct_in, vertex->total_nhits_in,
		    pct_out, vertex->total_nhits_out,
		    font_size, node_color, pen_width);

		v++;
close_subgraph:
		if (prev_depth != cur_depth) {
			fprintf(out,
"    }\n\n");
			open_subgraph = 1;
		}
	}

	if (!open_subgraph) {
			fprintf(out,
"    }\n\n");
	}

	/* Link nodes */
	for (size_t v = 0; v < pg->capvertices; v++) {
		vertex = &pg->vertices[v];
		if (is_null_vertex(vertex))
			continue;

		rid = vertex->rid;
		request_hash = rt->hashes[rid];
		for (size_t e = 0; e < vertex->nedges; e++) {
			struct path_graph_edge *edge = &vertex->edges[e];

			double pct = 100 *
			    ((double)edge->nhits / (double)pg->total_edge_nhits);
			double weight = calc_dot_weight(pg->total_nhits,
			    edge->nhits);
			int font_size = calc_dot_font_size(weight);
			double pen_width = calc_dot_pen_width(weight);

			request_id_t edge_rid = edge->rid;
			struct path_graph_vertex *edge_vertex = &pg->vertices[edge_rid];
			assert(!is_null_vertex(edge_vertex));
			const char *style;
			if (rid == edge_rid)
				style = "dotted";
			else if (vertex->min_depth <= edge_vertex->min_depth)
				style = "solid";
			else
				style = "dashed";

			color_t node_color = hash_to_node_color(request_hash);
			double edge_mult = 0.8;
			double edge_label_mult = 0.6;
			color_t edge_color =
			    node_to_edge_color(node_color, edge_mult);
			color_t edge_label_color =
			    node_to_edge_color(node_color, edge_label_mult);

			double duration_sec = edge->duration_cma / 1000.0;

			fprintf(out,
"    r%" PRIuRID " -> r%" PRIuRID " [xlabel=\"%.2lf%% (%" PRIu64 ")\\n%.1lfs\", "
                                    "fontsize=%d, "
				    "style=\"%s\", "
				    "color=" COLOR_FMT ", "
				    "fontcolor=" COLOR_FMT ", "
				    "penwidth=%lf];\n",
			    rid, edge->rid, pct, edge->nhits, duration_sec,
			    font_size, style, edge_color, edge_label_color,
			    pen_width);
		}
	}

	fprintf(out, "}\n");
}
