#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "interval_tree.h"
#include "interval_tree_generic.h"

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

#if 0
INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     unsigned long, __subtree_last,
		     START, LAST,, interval_tree)
#else
INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     itvt_val_t, __subtree_last,
		     START, LAST,, interval_tree)
#endif
