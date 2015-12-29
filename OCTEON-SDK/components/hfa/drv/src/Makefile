# Makefile to create HFA as library for SE and SEUM environment. 
#

# check if HFAROOT is set
ifeq ($(OCTEON_ROOT),)
$(error OCTEON_ROOT is not set)
endif

ifeq ($(HFAROOT),)
$(error HFAROOT is not set)
endif

ifeq ($(HFAENV),kernel)
$(error use top Makefile to compile library)
endif

# set toolchain
ifeq ($(HFAARCH),octeon)
CVMX_CONFIG = config/cvmx-config.h
CVMX_OTHER_CONFIGS := config/*-config.h
CVMX_OTHER_CONFIGS := $(shell echo $(CVMX_OTHER_CONFIGS) | sed 's/config\/cvmx-config.h//')

ifeq ($(HFAENV), se)
OCTEON_TARGET=cvmx_64
else
OCTEON_TARGET=linux_64
endif

include $(OCTEON_ROOT)/common.mk

PROJECT = libcvmhfa.a
HFAOBJS =  cvm-hfa-pp.o cvm-hfa-res.o cvm-hfa.o cvm-hfa-cluster.o \
			cvm-hfa-graph.o cvm-hfa-search.o cvm-hfa-stats.o 
CFLAGS += -I. -I../../utils/app-utils/ -I../include -I./config
CFLAGS += -I../../utils/hfa-malloc/ 
CFLAGS += -DHFA_BUILD_FOR_LIBRARY
CFLAGS += -g -O2 -Wall 
#CFLAGS +=-DTRACE

all: $(CVMX_CONFIG) $(PROJECT)
	-cp $(PROJECT) $(HFAROOT)/lib/octeon/hfa/$(HFAENV)/

$(CVMX_CONFIG): $(CVMX_OTHER_CONFIGS)
	cvmx-config $(CVMX_OTHER_CONFIGS)

$(PROJECT): $(HFAOBJS)
	 $(AR) rcs $(PROJECT) $(HFAOBJS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(CFLAGS_LOCAL) $(CFLAGS_GLOBAL) $<

clean:
	rm -f *.o *.a config/cvmx-config.h
endif
