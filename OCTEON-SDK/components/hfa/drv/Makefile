# Makefile to build HFA kernel library module
# check if HFAROOT is set
ifeq ($(OCTEON_ROOT),)
$(error OCTEON_ROOT is not set)
endif

# check if HFAROOT is set
ifeq ($(HFAROOT),)
$(error HFAROOT is not set)
endif

ifneq ($(HFAENV),kernel)
$(error 'use top Makefile to compile')
endif

DEFAULT_CROSS_COMPILE = $(shell \
	if grep -q ^CONFIG_CPU_LITTLE_ENDIAN $(KERNELSRC)/../../kernel/linux/.config && \
	which mips64el-octeon-linux-gnu-gcc > /dev/null 2>&1 ; then \
		echo -n mips64el-octeon-linux-gnu-; \
	else \
		echo -n mips64-octeon-linux-gnu-; fi)


export CROSS_COMPILE ?= $(strip $(DEFAULT_CROSS_COMPILE))
export ARCH = mips

HFADRVDIR = $(HFAROOT)/drv
BASE := $(HFADRVDIR)
KERNELSRC := $(OCTEON_ROOT)/linux/kernel/linux
LIB_SRC = $(BASE)/../lib/octeon/pp/kernel
$(shell ln -sf $(LIB_SRC)/pp-lib.o $(BASE)/pp-lib.o)

EXTRA_CFLAGS += -I$(BASE)/include
EXTRA_CFLAGS += -DKERNEL -DOCTEON_HFA -DLIBRARY

obj-m := cvm-hfa-lib.o

cvm-hfa-lib-objs := 				\
		pp-lib.o					\
		src/cvm-hfa-pp.o			\
		src/cvm-hfa-res.o			\
		src/cvm-hfa-module.o		\
		src/cvm-hfa-napi.o			\
		src/cvm-hfa-cluster.o		\
		src/cvm-hfa-graph.o			\
		src/cvm-hfa.o				\
		src/cvm-hfa-search.o        \
		src/cvm-hfa-stats.o         

all:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(HFADRVDIR) modules 
	-cp -rf cvm-hfa-lib.ko  ../lib/octeon/hfa/kernel/
	-cp Module.symvers ../lib/octeon/hfa/kernel/

clean:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(HFADRVDIR) clean
	-rm -f pp-lib.o

cvm-hfa-lib.o: $(cvm-hfa-lib-objs)
	$(LD) -r $^-o $@
