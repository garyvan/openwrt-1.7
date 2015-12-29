BASEDIR=../../
ENGINEDIR=$(BASEDIR)/src/dynamic-plugins/sf_engine
PLUGINDIR=$(BASEDIR)/src/dynamic-plugins
ENGINE=$(BASEDIR)/src/dynamic-plugins/sf_engine/.libs/libsf_engine.so
SNORT=$(BASEDIR)/src/snort
SNORT_VERSION=2.9.0.0

PATH:=$(PATH):/opt/intel/compiler70/ia32/bin
CC=$(shell if PATH=$(PATH) which icc > /dev/null 2>&1; then echo icc; else echo gcc; fi)


# RANDSTRING=$(shell perl -e 'for($$i=0;$$i<128;$$i++){$$_ .= unpack("h*",chr(int(rand(256))));} print')
# For now, a static rand string is good enough, since we are not using it yet.
RANDSTRING=e57509e0e8702d1794fd29f0741f74e0d649aff186ffc1aa0dab1d6817e3ea35ee6153f553ea923c4d49b5f

MYCFLAGS = $(CFLAGS) -ggdb -I$(ENGINEDIR) -I$(PLUGINDIR) -fPIC `pcre-config --cflags` -DVRT_RAND_STRING=\"$(RANDSTRING)\" -Wall

ifeq ($(CC),gcc)
MYCFLAGS += -Wno-unused-variable -std=c99 -pedantic -Wformat -Wuninitialized -O2 -Wno-strict-aliasing -D_GNU_SOURCE
endif
ifeq ($(CC),icc)
MYCFLAGS += -wd1418,1419,810,193,177 -w2
LD_FLAGS += -lirc -static-libcxa
endif

# comment the following line out if you want to enable all of the previously
# "Deleted" so rules
MYCFLAGS+= -DMISSING_DELETED=1

ifeq (${SNORT_VERSION},2.8.5)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9 -DMISSING_PKT_HEADER=1 -DMISSING_CUSTOM_DESTRUCTOR=1 -DMISSING_BYTE_JUMP_FIX=1 -DMISSING_STREAM_REASS=1
SEEN=1
endif
ifeq (${SNORT_VERSION},2.8.5.1)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9 -DMISSING_PKT_HEADER=1 -DMISSING_CUSTOM_DESTRUCTOR=1 -DMISSING_BYTE_JUMP_FIX=1 -DMISSING_STREAM_REASS=1
SEEN=1
endif
ifeq (${SNORT_VERSION},2.8.5.2)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9 -DMISSING_PKT_HEADER=1 -DMISSING_CUSTOM_DESTRUCTOR=1 -DMISSING_BYTE_JUMP_FIX=1 -DMISSING_STREAM_REASS=1
SEEN=1
endif
ifeq (${SNORT_VERSION},2.8.5.3)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9 -DMISSING_PKT_HEADER=1 -DMISSING_CUSTOM_DESTRUCTOR=1 -DMISSING_BYTE_JUMP_FIX=1 -DMISSING_STREAM_REASS=1
SEEN=1
endif
ifeq (${SNORT_VERSION},2.8.6.0)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9 -DMISSING_PKT_HEADER=1 -DMISSING_CUSTOM_DESTRUCTOR=1 -DMISSING_BYTE_JUMP_FIX=1 -DMISSING_STREAM_REASS=1
SEEN=1
endif
ifeq (${SNORT_VERSION},2.8.6.1)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9 -DMISSING_PKT_HEADER=1 -DMISSING_CUSTOM_DESTRUCTOR=1 -DMISSING_STREAM_REASS=1
SEEN=1
endif
ifeq (${SNORT_VERSION},2.9.0.0)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9
SEEN=1
endif
ifeq (${SNORT_VERSION},2.9.0.1)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9
SEEN=1
endif
ifeq (${SNORT_VERSION},2.9.0.2)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9
SEEN=1
endif
ifeq (${SNORT_VERSION},2.9.0.3)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=9
SEEN=1
endif
ifeq (${SNORT_VERSION},2.9.0.4)
MYCFLAGS += -DREQ_ENGINE_LIB_MINOR=13
SEEN=1
endif

libs := $(shell ls ?*\_*.c | cut -d_ -f1 | grep -v deleted | uniq)
files := $(shell for i in ${libs}; do ls $$i\_*.c | cut -d. -f1; done)

OS=$(shell echo $$OSTYPE)
ifeq ($(OS),darwin8.0)
export MACOSX_DEPLOYMENT_TARGET=10.4
LD_FLAGS = -bundle -undefined dynamic_lookup -lSystemStubs /usr/lib/bundle1.o 
else
LD_FLAGS = -shared
endif

ifneq (,$(findstring freebsd, $(OS)))
LD_FLAGS += -ldl
endif



all: $(files) $(libs)
	@rm -f test.conf
	@for i in ${libs}; do echo include $$i.rules >> test.conf; done

$(files):
ifneq (${SEEN}, 1)
	@echo "Unsupported snort version - ${SNORT_VERSION}"
	@false
endif
	@$(CC) -c $(MYCFLAGS) -o $@.o $@.c

$(libs):
	@echo -n "building $@ ... "
	@perl category-build.pl $@
	@$(CC) -c $(MYCFLAGS) -D DETECTION_LIB_NAME=\"$@\" -o $@.o $@.c
	@$(CC) -c $(MYCFLAGS) -D DETECTION_LIB_NAME=\"$@\" -o _meta.o _meta.c
	@$(CC) $(LD_FLAGS) $@_*.o _meta.o $@.o -o $@.so
	@$(SNORT) -q --dynamic-engine-lib=$(ENGINE) \
		--dynamic-detection-lib=./$@.so \
		--dump-dynamic-rules=./
	@echo done
	-@rm _meta.o

test:
	@perl tests/test.pl -basedir ${BASEDIR} -testdir tests -version ${SNORT_VERSION} >/dev/null

write-results:
	@perl tests/write.pl -basedir ${BASEDIR} -testdir tests -version ${SNORT_VERSION} >/dev/null

distclean: clean

clean:
	-@rm -rf *.o *.so *.rules
	-@for i in ${libs}; do rm -f $$i.c; done
