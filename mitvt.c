#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "rule_trace.h"

#include "mitvt.h"

#define	printk	printf
#define	KERN_ALERT	""
#define	u32	uint32_t
#define	cycles_t	time_t
#define	get_cycles()	time(NULL)
#define	div_u64(numerator, denominator)	(numerator / denominator)
#define	prandom_seed_state(arg1, arg2)	srand((unsigned int)arg2)
#define	prandom_u32_state(arg1)	rand()

////////////////////////////////////////////////////

mitvt_t g_mitvt;

#define  MAX_TEST_RULE 5

//rule_t g_rules[MAX_TEST_RULE];

//////////////////////////////////////////////

#if 0
static void uint128_to_str_iter(uint128_t n, char *out,int firstiter)
{
	static int offset=0;
	if (firstiter){
		offset=0;
	}
	if (n == 0) {
		return;
	}
	uint128_to_str_iter(n/10,out,0);
	out[offset++]=n%10+0x30;
}

static char* uint128_to_str(uint128_t n)
{
	char *out=calloc(sizeof(char),40);

	if (n == 0) {
		out[0] = '0';
		out[1] = 0;

		return out;
	}

	uint128_to_str_iter(n, out, 1);

	return out;
}
#endif

#if 0
void set_bitmap(bitmap_t b, int i) 
{
    b[i / 8] |= 1 << (i & 7);
}

void unset_bitmap(bitmap_t b, int i) 
{
    b[i / 8] &= ~(1 << (i & 7));
}

int get_bitmap(bitmap_t b, int i) 
{
    return b[i / 8] & (1 << (i & 7)) ? 1 : 0;
}

bitmap_t create_bitmap(int n) 
{
    return malloc((n + 7) / 8);
}
#endif

static unsigned long
mitvt_search_single_dim(rb_root_t *root,  itvt_val_t start, itvt_val_t end, nibble_t *matched, int dim)
{
	struct interval_tree_node *node;
	unsigned long results = 0;

	for (node = interval_tree_iter_first(root, start, end); node;
		 node = interval_tree_iter_next(node, start, end)) {

		results++;
		
#if 0
		char *s = uint128_to_str(node->start);
		char *e = uint128_to_str(node->last);
		printf("node[%u]: dim:%d, %s - %s \n", node->idx, dim, s, e);
		free(s);
		free(e);
#endif

		uint32_t idx = node->idx >> 1;

		if (node->idx & 0x01) {
			dim == 0 ? (matched[idx].h = 1) : matched[idx].h ++;
		}
		else {
			dim == 0 ? (matched[idx].l = 1) : matched[idx].l ++;
		}
	}

	printf("matched result:%lu \n", results);

	return results;
}

int mitvt_search(mitvt_t *mitvt, struct packet *pkt)
{
	int i;

	memset(mitvt->matched, 0, mitvt->matched_len);

	for (i=0; i<DIM_MAX; i++) {
		mitvt_search_single_dim(&mitvt->root[i], 
						  pkt->dims[i],
						  pkt->dims[i],
						  mitvt->matched, i);
	}

	for (i=0; i<mitvt->matched_len; i++) {
#if 0 
		printf("Matched Count: [%d]:%d, [%d]:%d \n", 
			   i,
			   mitvt->matched[i].l,
			   i+1,
			   mitvt->matched[i].h);
#endif

		if (mitvt->matched[i].l == DIM_MAX) {
			printf("Matched Rule Idx: %d\n", i);
			break;
		}

		if (mitvt->matched[i].h == DIM_MAX) {
			printf("Matched Rule Idx: %d\n", i+1);
			break;
		}
	}

	return 0;
}

int mitvt_insert_node(mitvt_t *mitvt, struct rule_set *rset)
{
	int i,j;
	struct rule *r;
	int l,c,idx;
	itvt_node_t *n;
	int nrule;

	if (rset->rule_num < 1) {
		printf("no Rules !\n");
		return -1;
	}
	
	memset(mitvt, 0, sizeof(mitvt_t));

	nrule = rset->rule_num;
	c = DIM_MAX * nrule;
	l = c * sizeof(itvt_node_t);
	
	mitvt->nodes = (itvt_node_t*)malloc(l);

	if (mitvt->nodes == NULL) {
		printf("no Momory for node\n");
		return -1;
	}
	
	mitvt->nnodes = c;
	mitvt->matched_len = nrule/2;
	if (mitvt->matched_len < 1) {
		mitvt->matched_len = 1;
	}

	printf("# nibble: %d(%d)\n", mitvt->matched_len, nrule);

	mitvt->matched =  malloc(mitvt->matched_len);
	if (mitvt->matched == NULL) {
		goto ERR;
	}

	idx = 0;
	for (i=0; i<nrule; i++) {
		r = &rset->rules[i];

		for (j=0; j<DIM_MAX; j++) {
			n = &mitvt->nodes[idx];
			n->start = r->dims[j][0];
			n->last  = r->dims[j][1];
			n->idx   = i;

			interval_tree_insert(n, &mitvt->root[j]);

			idx ++;
		}
	}

	return 0;

ERR:
	if (mitvt->nodes != NULL) {
		free(mitvt->nodes);
	}

	if (mitvt->matched != NULL) {
		free(mitvt->matched);
	}

	return -1;
}

int test_search_trace(struct trace *trace)
{
	int i;
	register const struct packet *p_pkt;

	if (!trace || !trace->pkts) {
		return -EINVAL;
	}

	for (i = 0; i < trace->pkt_num; i++) {
		/* For each tree */
		//pri = hsret->def_rule;
		p_pkt = &trace->pkts[i];

		mitvt_search(&g_mitvt, (struct packet*)p_pkt);
	}

	return 0;
}

int test_insert_node(struct rule_set *rset)
{
	mitvt_insert_node(&g_mitvt, rset);

	return 0;
}

#if 0
//////////////////////////////////////////////////////

static void init_test_data(void)
{
	g_rules[0].range[MITVT_DIM_SRC].start = 0;
	g_rules[0].range[MITVT_DIM_SRC].end   = 255;
	g_rules[0].range[MITVT_DIM_DST].start = 0;
	g_rules[0].range[MITVT_DIM_DST].end   = 255;
	g_rules[0].range[MITVT_DIM_SP].start = 0;
	g_rules[0].range[MITVT_DIM_SP].end   = 255;
	g_rules[0].range[MITVT_DIM_DP].start = 80;
	g_rules[0].range[MITVT_DIM_DP].end   = 80;
	g_rules[0].range[MITVT_DIM_PROTO].start = 0;
	g_rules[0].range[MITVT_DIM_PROTO].end   = 255;
	g_rules[0].range[MITVT_DIM_NIC].start = 0;
	g_rules[0].range[MITVT_DIM_NIC].end   = 255;

	g_rules[1].range[MITVT_DIM_SRC].start = 0;
	g_rules[1].range[MITVT_DIM_SRC].end   = 255;
	g_rules[1].range[MITVT_DIM_DST].start = 0;
	g_rules[1].range[MITVT_DIM_DST].end   = 255;
	g_rules[1].range[MITVT_DIM_SP].start = 0;
	g_rules[1].range[MITVT_DIM_SP].end   = 255;
	g_rules[1].range[MITVT_DIM_DP].start = 90;
	g_rules[1].range[MITVT_DIM_DP].end   = 90;
	g_rules[1].range[MITVT_DIM_PROTO].start = 0;
	g_rules[1].range[MITVT_DIM_PROTO].end   = 255;
	g_rules[1].range[MITVT_DIM_NIC].start = 0;
	g_rules[1].range[MITVT_DIM_NIC].end   = 255;

	insert_node(&g_mitvt, g_rules, 2);

#if 0
		nodes[0].start = 0;
	nodes[0].last   = 100;
	nodes[0].idx   = 1;
	nodes[1].start = 10;
	nodes[1].last   = 90;
	nodes[1].idx   = 2;
	nodes[2].start = 30;
	nodes[2].last   = 95;
	nodes[2].idx   = 3;
	nodes[3].start = 20;
	nodes[3].last   = 50;
	nodes[3].idx   = 4;

	queries[0] = 45;
	queries[1] = 20;
	queries[2] = 90;
	queries[3] = 60;
#endif
}

static void init_search_data()
{
	rule_t r;

	r.range[MITVT_DIM_SRC].start = 4;
	r.range[MITVT_DIM_SRC].end   = 4;
	r.range[MITVT_DIM_DST].start = 5;
	r.range[MITVT_DIM_DST].end   = 5;
	r.range[MITVT_DIM_SP].start  = 6;
	r.range[MITVT_DIM_SP].end    = 6;
	r.range[MITVT_DIM_DP].start  = 80;
	r.range[MITVT_DIM_DP].end    = 80;
	r.range[MITVT_DIM_PROTO].start = 7;
	r.range[MITVT_DIM_PROTO].end   = 7;
	r.range[MITVT_DIM_NIC].start = 1;
	r.range[MITVT_DIM_NIC].end   = 1;

	search(&g_mitvt, &r);
}


static int interval_tree_test_init(void)
{
	//int i, j;
	//unsigned long results, n;

	printk(KERN_ALERT "interval tree insert/remove\n");

	init_test_data();

	init_search_data();

	return 0;
}

static void interval_tree_test_exit(void)
{
	printk(KERN_ALERT "test exit\n");
}

int main(int argc, char **argv)
{
	printf("nibble_t: %lu\n", sizeof(nibble_t));

	interval_tree_test_init();
	interval_tree_test_exit();
	return 0;
}
#endif
