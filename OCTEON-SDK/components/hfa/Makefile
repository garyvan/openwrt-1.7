# Makefile to compile HFA SDK and reference apps for given
# env.(se|seum|kernel). Default mode is se
#     make OCTEON_MODE=<se|seum|kernel>
#

ifeq ($(OCTEON_ROOT),)
$(error OCTEON_ROOT is not set)
endif

ifndef OCTEON_MODE
OCTEON_MODE = se
endif

ifeq ($(OCTEON_MODE),se)
export OCTEON_TARGET=cvmx_64
else
 ifeq ($(OCTEON_MODE),seum)
 export OCTEON_TARGET=linux_64
 endif
endif
export HFAROOT = $(shell pwd)
export HFAENV = $(OCTEON_MODE)
export HFAARCH = octeon

all: 
ifeq ($(OCTEON_MODE), kernel)
	+make -C drv/ # build cvm-hfa-lib.ko
	+make -C apps/func # sync-app
	+make -C apps/func target=async
	+make -C apps/func target=nctx
	+make -C apps/func target=nctx-lock
	+make -C apps/func target=wqe
	+make -C apps/func target=wqe-lock
	+make -C apps/func target=linkgraph
	+make -C apps/perf target=ctx
else # SE or SEUM
	+make -C drv/src/ # build libcvmhfa.a
	+make -C apps/func # sync-app
	+make -C apps/func target=async
	+make -C apps/func target=nctx
	+make -C apps/func target=nctx-lock
	+make -C apps/func target=wqe
	+make -C apps/func target=wqe-lock
	+make -C apps/func target=flow
	+make -C apps/func target=flow-wqe
	+make -C apps/func target=xml-parser
	+make -C apps/func target=linkgraph
	+make -C apps/func target=ngraphs
	+make -C apps/perf target=ctx
endif

clean:
ifeq ($(OCTEON_MODE), kernel)
	+make -C drv/ clean # build cvm-hfa-lib.ko
	+make -C apps/func clean # sync-app
	+make -C apps/func target=async clean
	+make -C apps/func target=nctx clean
	+make -C apps/func target=nctx-lock clean
	+make -C apps/func target=wqe clean
	+make -C apps/func target=wqe-lock clean
	+make -C apps/func target=linkgraph clean
	+make -C apps/perf target=ctx clean
	+@rm -f lib/octeon/hfa/kernel/*
else # SE or SEUM
	+make -C drv/src/ clean # build libcvmhfa.a
	+make -C apps/func clean # sync-app
	+make -C apps/func target=async clean
	+make -C apps/func target=nctx clean
	+make -C apps/func target=nctx-lock clean
	+make -C apps/func target=wqe clean
	+make -C apps/func target=wqe-lock clean
	+make -C apps/func target=flow clean
	+make -C apps/func target=flow-wqe clean
	+make -C apps/func target=xml-parser clean
	+make -C apps/func target=linkgraph clean
	+make -C apps/func target=ngraphs clean
	+make -C apps/perf target=ctx clean
	+@rm -f lib/octeon/hfa/$(HFAENV)/*
endif

symlinks:
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-cluster.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-common.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-error.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-graph.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-instr.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-module.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-osapi.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-res.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-stats.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa-search.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/cvm-hfa.h $(OCTEON_ROOT)/target/include
	ln -fs $(OCTEON_ROOT)/executive/cvmx-hfa.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/hfa-tools-version.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/pp.h $(OCTEON_ROOT)/target/include
	ln -fs $(HFAROOT)/drv/include/ppdfa.h $(OCTEON_ROOT)/target/include

symlinks-del:
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-cluster.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-common.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-error.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-graph.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-instr.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-module.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-osapi.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-res.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-stats.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa-search.h
	rm -f $(OCTEON_ROOT)/target/include/cvm-hfa.h
	rm -f $(OCTEON_ROOT)/target/include/cvmx-hfa.h
	rm -f $(OCTEON_ROOT)/target/include/hfa-tools-version.h
	rm -f $(OCTEON_ROOT)/target/include/pp.h 
	rm -f $(OCTEON_ROOT)/target/include/ppdfa.h 
