#ifndef __MITVT_H__
#define __MITVT_H__

#include <interval_tree.h>
#include <rule_trace.h>

#if 0
enum {
	MITVT_DIM_SRC = 0,
	MITVT_DIM_DST,
	MITVT_DIM_SP,
	MITVT_DIM_DP,
	MITVT_DIM_PROTO,
	MITVT_DIM_NIC,

	MITVT_DIM_MAX
};
#endif

typedef struct nibble{
	uint8_t h : 4;
	uint8_t l : 4;
 }__attribute__((packed, aligned(1)))  nibble_t;

typedef unsigned char* bitmap_t;

#define MITVT_MAX_CONCURRENT 	10

// Multi-Dimensional Interval Tree
typedef struct mitvt_s {
	rb_root_t root[DIM_MAX];
	
	nibble_t 	*matched;
	int 		matched_len;

	itvt_node_t *nodes;
	int 		nnodes;

} mitvt_t;


#if 0
typedef struct range_s {
	itvt_val_t start, end;
} range_t;

typedef struct rule_s {
	range_t range[MITVT_DIM_MAX];
} rule_t;
#endif

#endif
