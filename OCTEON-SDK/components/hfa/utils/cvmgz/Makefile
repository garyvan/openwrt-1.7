# Makefile for cvmgzlib made from zlib sources
# Makefile for zlib
# Copyright (C) 1995-2011 Jean-loup Gailly.
# For conditions of distribution and use, see copyright notice in zlib.h

CC=$(CROSS)-gcc
AR=$(CROSS)-ar
RANLIB=$(CROSS)-ranlib
CFLAGS=-O3 -g  -DHAVE_HIDDEN
LIBS=libcvmgz.a

ARFLAGS=rc

OBJZ = adler32.o crc32.o deflate.o infback.o inffast.o inflate.o inftrees.o trees.o zutil.o
OBJG = compress.o uncompr.o gzclose.o gzlib.o gzread.o gzwrite.o misc_defs.o
OBJS = $(OBJZ) $(OBJG)

all: libcvmgz.a 

libcvmgz.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)
	-@ ($(RANLIB) $@ || true) >/dev/null 2>&1

clean:
	rm -f *.o libcvmgz.*

