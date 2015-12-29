# Makefile to compile all functionl apps
# Apps are valid in their respective environment set (se|seum|kernel)
# Usage: 
#     make [target=]
#

ifeq ($(OCTEON_ROOT),)
$(error OCTEON_ROOT is not set)
endif
ifeq ($(HFAROOT),)
$(error HFAROOT is not set)
endif

ifneq ($(HFAARCH), octeon)
$(error 'use top Makefile to compile apps)
endif

APPSDIR = $(HFAROOT)/apps/perf

#KERNEL Environment
ifeq ($(HFAENV), kernel)
#Check the target
ifeq ($(target), )
HFATARGET=hfa-lnx-ctx
HFAFILE=hfa-kernel-ctx
else
HFATARGET=hfa-lnx-$(target)
HFAFILE=hfa-kernel-$(target)
endif

DEFAULT_CROSS_COMPILE = $(shell \
	if grep -q ^CONFIG_CPU_LITTLE_ENDIAN $(KERNELSRC)/../../kernel/linux/.config && \
	which mips64el-octeon-linux-gnu-gcc > /dev/null 2>&1 ; then \
		echo -n mips64el-octeon-linux-gnu-; \
	else \
		echo -n mips64-octeon-linux-gnu-; fi)


export CROSS_COMPILE ?= $(strip $(DEFAULT_CROSS_COMPILE))
export ARCH = mips

BASE := $(APPSDIR)
KERNELSRC := $(OCTEON_ROOT)/linux/kernel/linux
$(shell cp -rf $(BASE)/../../lib/octeon/hfa/kernel/Module.symvers $(BASE)/)

EXTRA_CFLAGS += -I$(BASE)/../../drv/include
EXTRA_CFLAGS += -I$(BASE)/../../utils/app-utils -I$(BASE)/../../utils/pcap 
EXTRA_CFLAGS += -I$(BASE)/../../utils/cvmgz 
EXTRA_CFLAGS += -DKERNEL -DLOOPBACK -DMATCHCB -O2 -g -Wall
obj-m := $(HFAFILE).o	

dir := $(BASE)/../../utils/cvmgz
include $(dir)/cvmgz-lib.mk

$(HFAFILE)-objs :=										\
	../../utils/pcap/pcap.o								\
	../../utils/app-utils/app-utils.o					\
	../../utils/cvmgz/cvmgz-lib.o						\
	$(HFATARGET).o

all:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(APPSDIR) modules
clean:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(APPSDIR) clean
	@rm -f ../../utils/app-utils/*.o
	@rm -f ../../utils/app-utils/*.ko
	@rm -f ../../utils/app-utils/app-utils.mod.c
	@rm -f ../../utils/app-utils/.*.cmd
	@rm -f ../../utils/pcap/*.o
	@rm -f ../../utils/pcap/*.ko
	@rm -f ../../utils/cvmgz/*.o
	@rm -f ../../utils/cvmgz/*.ko
	@rm -f ../../utils/cvmgz/.*.cmd
	@rm -f ../../utils/cvmgz/*.mod.c
	@rm -f ../../utils/pcap/pcap.mod.c
	@rm -f ../../utils/pcap/.*.cmd

else #SE and SE-UM 
#Check the target
ifeq ($(target), )
HFATARGET=hfa-$(HFAENV)-ctx
HFAFILE=hfa-se-ctx
else
HFATARGET=hfa-$(HFAENV)-$(target)
HFAFILE=hfa-se-$(target)
endif
CFLAGS_GLOBAL += -G0 
CFLAGS_LOCAL += -g -O2 -DLOOPBACK -DMATCHCB
CFLAGS_LOCAL += -I. -I../../drv/include 
CFLAGS_LOCAL += -I../../utils/pcap
CFLAGS_LOCAL += -I../../utils/app-utils -Wall
CFLAGS_LOCAL += -I../../utils/cvmgz 

#Simple Executive Environment
ifeq ($(HFAENV),se)

OCTEON_TARGET=cvmx_64

default: $(HFATARGET)

include $(OCTEON_ROOT)/common.mk

CC += -I../../drv/include
dir := $(APPSDIR)/../../drv/src
include $(dir)/octeon-hfa.mk

dir := $(APPSDIR)/../../utils/cvmgz
include $(dir)/cvmgz.mk
LDFLAGS_GLOBAL += -Wl,--no-warn-mismatch
LIBS_LIST += $(HFAROOT)/lib/octeon/pp/$(HFAENV)/libpp.a

dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

$(OBJ_DIR)/pcap.o: $(d)../../utils/pcap/pcap.c
	$(CC) $(CFLAGS_GLOBAL) $(CFLAGS_LOCAL) -MD -c -o $@ $<

$(OBJ_DIR)/app-utils.o: $(d)../../utils/app-utils/app-utils.c
	$(CC) $(CFLAGS_GLOBAL) $(CFLAGS_LOCAL) -MD -c -o $@ $<


TARGET = $(HFATARGET)
OBJS = $(OBJ_DIR)/$(HFAFILE).o
OBJS += $(OBJ_DIR)/pcap.o
OBJS += $(OBJ_DIR)/app-utils.o

include $(OCTEON_ROOT)/application.mk

call:
	rm -f config/cvmx-config.h 
	rm -f $(OBJ_DIR)/$(TARGET).o
	rm -f $(OBJ_DIR)/$(TARGET).d
	rm -rf $(TARGET)
clean:
	rm -f config/cvmx-config.h 
	rm -rf $(OBJ_DIR)
	rm -rf $(TARGET)
else                                        #End of HFAENV == se
	
#Simple Executive -User mode Environment
ifeq ($(HFAENV),seum)

OCTEON_TARGET=linux_64

default: $(HFATARGET)

include $(OCTEON_ROOT)/common.mk

CC += -I../../drv/include
dir := $(APPSDIR)/../../drv/src
include $(dir)/octeon-hfa.mk

dir := $(APPSDIR)/../../utils/cvmgz
include $(dir)/cvmgz.mk
LDFLAGS_GLOBAL += -Wl,--no-warn-mismatch
LIBS_LIST += $(HFAROOT)/lib/octeon/pp/$(HFAENV)/libpp.a

dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

$(OBJ_DIR)/pcap.o: $(d)../../utils/pcap/pcap.c
	$(CC) $(CFLAGS_GLOBAL) $(CFLAGS_LOCAL) -MD -c -o $@ $<

$(OBJ_DIR)/app-utils.o: $(d)../../utils/app-utils/app-utils.c
	$(CC) $(CFLAGS_GLOBAL) $(CFLAGS_LOCAL) -MD -c -o $@ $<

TARGET = $(HFATARGET)
OBJS = $(OBJ_DIR)/$(HFAFILE).o
OBJS += $(OBJ_DIR)/pcap.o
OBJS += $(OBJ_DIR)/hfa-malloc.o
OBJS += $(OBJ_DIR)/app-utils.o

CFLAGS_LOCAL += -I../../utils/hfa-malloc 


include $(OCTEON_ROOT)/application.mk

call:
	rm -f config/cvmx-config.h 
	rm -f $(OBJ_DIR)/$(TARGET).o
	rm -f $(OBJ_DIR)/$(TARGET).d
	rm -rf $(TARGET)
clean:
	rm -f config/cvmx-config.h 
	rm -rf $(OBJ_DIR)
	rm -rf $(TARGET)

endif #ifeq HFAENV == seum
endif #ifeq HFAENV == se
endif #ifeq (HFAENV == kernel)
