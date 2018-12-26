#ifndef DOT_H
#define DOT_H

#include <stdio.h>

#include "path_graph.h"
#include "request.h"

void output_dot_graph(FILE *, struct path_graph *, struct request_table *);

#endif
