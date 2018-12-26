#ifndef DEBUG_H
#define DEBUG_H

#include "path_graph.h"
#include "request.h"
#include "session.h"
#include "truncate.h"

void debug_truncate_patterns(struct truncate_patterns *);
void debug_request_set(struct request_set *);
void debug_request_table(struct request_table *);
void debug_session_map(struct session_map *);
void debug_path_graph(struct path_graph *);

#endif
