#Make file included from apps folder
sp		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

LIBRARY		:= $(OBJ_DIR)/libcvmhfa.a
OBJS_$(d)	:= $(OBJ_DIR)/cvm-hfa-cluster.o $(OBJ_DIR)/cvm-hfa-graph.o $(OBJ_DIR)/cvm-hfa.o \
			   $(OBJ_DIR)/cvm-hfa-search.o $(OBJ_DIR)/cvm-hfa-pp.o $(OBJ_DIR)/cvm-hfa-res.o $(OBJ_DIR)/cvm-hfa-stats.o

ifeq (linux,$(findstring linux,$(OCTEON_TARGET)))
OBJS_$(d)       += $(OBJ_DIR)/hfa-malloc.o
endif

$(OBJS_$(d)):	CFLAGS_LOCAL := -I$(d)/../../cmd/hfac -I$(d)/../include -I$(d)/../../utils/hfa-malloc/ -g $(CFLAGS_LOCAL) -DLIBRARY -DOCTEON_HFA -Wall 
DEPS_$(d)	:= $(OBJS_$(d):.o=.d)
LIBS_LIST	:= $(LIBS_LIST) $(LIBRARY)
CLEAN_LIST	:= $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d)) $(LIBRARY)

-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

ifeq (linux,$(findstring linux,$(OCTEON_TARGET)))
CFLAGS_SPEC := -I$(d)/../../utils/hfa-malloc -O2 -g
endif

$(OBJ_DIR)/hfa-malloc.o: $(d)/../../utils/hfa-malloc/malloc.c
	$(CC) $(CFLAGS_GLOBAL) $(CFLAGS_SPEC) -MD -c -o $@ $<

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
