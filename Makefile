
OBJ_DIR = obj
BIN = $(OBJ_DIR)/hs

SRC=hypersplit.c  impl.c  mpool.c  main.c  point_range.c  rfg.c  rule_trace.c  sort.c  utils.c
SRC+=interval_tree.c mitvt.c rbtree.c
HEADERS=buffer.h  hypersplit.h  impl.h  mpool.h  point_range.h  rfg.h  rule_trace.h  sort.h  utils.h

DEP = $(patsubst %.c, $(OBJ_DIR)/%.d, $(SRC))
OBJ = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRC))

CC = gcc
CFLAGS = -Wall -g -I./
#CFLAGS = -Wall -O2 -DNDEBUG -I$(INC_DIR)/

all: $(BIN) run_pc

ifneq "$(MAKECMDGOALS)" "clean"
    -include $(DEP)
endif

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/%.d: %.c
	@set -e; rm -f $@; [ ! -e $(dir $@) ] & mkdir -p $(dir $@); \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

$(BIN): $(OBJ)
	ctags -R
	$(CC) -o $@ $^ -lrt

clean:
	rm -rf $(OBJ_DIR);
	rm -f tags

custom tag:
	ctags -R

run_grp:
	./bin/hs -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K

run_pc:
#	./bin/hs -p hs -f wustl_g -r rule_trace/rules/rfg/fw1_10K -t rule_trace/traces/origin/fw1_10K_trace
#	./bin/hs -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K
#	./bin/hs -p hs -f wustl -r rule_trace/rules/origin/acl1_10K -t rule_trace/traces/origin/acl1_10K_trace
#	./bin/hs -p hs -f wustl -r rule_trace/rules/origin/fw1_10K -t rule_trace/traces/origin/fw1_10K_trace
#	./bin/hs -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/origin/fw2_trace
#	gdb -ex=r --args ./bin/hs -p hs -f wustl -r rule_trace/rules/origin/fw2 -t rule_trace/traces/origin/fw2_trace
#	./$(OBJ_DIR)/hs -p hs -f wustl -r conf/rules/origin/fw2 -t conf/traces/origin/fw2_trace

	./$(OBJ_DIR)/hs -p hs -f wustl -r fw2 -t fw2_trace
#	./$(OBJ_DIR)/hs -p hs -f wustl -r conf/rules/origin/fw1_10K -t conf/traces/origin/fw1_10K_trace

format: $(SRC) $(HEADERS)
	 uncrustify --no-backup --mtime -c ./formatter.cfg $^
