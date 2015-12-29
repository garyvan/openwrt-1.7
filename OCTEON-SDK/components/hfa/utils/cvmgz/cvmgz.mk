#Make file included from apps folder
sp		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

LIBRARY		:= $(OBJ_DIR)/libcvmgz.a
OBJZ := $(OBJ_DIR)/adler32.o $(OBJ_DIR)/crc32.o $(OBJ_DIR)/deflate.o $(OBJ_DIR)/infback.o $(OBJ_DIR)/inffast.o $(OBJ_DIR)/inflate.o $(OBJ_DIR)/inftrees.o $(OBJ_DIR)/trees.o $(OBJ_DIR)/zutil.o
OBJG := $(OBJ_DIR)/compress.o $(OBJ_DIR)/uncompr.o $(OBJ_DIR)/gzclose.o $(OBJ_DIR)/gzlib.o $(OBJ_DIR)/gzread.o $(OBJ_DIR)/gzwrite.o $(OBJ_DIR)/misc_defs.o
OBJS_$(d)	:= $(OBJZ) $(OBJG) 

$(OBJS_$(d)):	CFLAGS_LOCAL := -O3 -g  -DHAVE_HIDDEN
DEPS_$(d)	:= $(OBJS_$(d):.o=.d)
LIBS_LIST	:= $(LIBS_LIST) $(LIBRARY)
CLEAN_LIST	:= $(CLEAN_LIST) $(OBJS_$(d)) $(DEPS_$(d)) $(LIBRARY)

-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	$(AR) -r $@ $^

$(OBJ_DIR)/%.o:	$(d)/%.c
	$(COMPILE)

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
