#**********************license start***************                              
#* Copyright (c) 2008-2015 Cavium Inc. All rights reserved.
#*                                                                                 
#*                                                                                 
#* Redistribution and use in source and binary forms, with or without              
#* modification, are permitted provided that the following conditions are          
#*  met->                                                                            
#* 										  
#*   * Redistributions of source code must retain the above copyright              
#*     notice, this list of conditions and the following disclaimer.               
#*                                                                                 
#*   * Redistributions in binary form must reproduce the above                     
#*     copyright notice, this list of conditions and the following                 
#*     disclaimer in the documentation and/or other materials provided             
#*     with the distribution.                                                      
#*                                                                                 
#*   * Neither the name of Cavium Inc. nor the names of                            
#*     its contributors may be used to endorse or promote products                 
#*     derived from this software without specific prior written                   
#*     permission.                                                                 
#										  
#*This Software,including technical data,may be subject to U.S. export control
#* laws, including the U.S. Export Administration Act and its  associated          
#* regulations, and may be subject to export or import  regulations in other       
#* countries.                                                                      
#										  
#* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
#* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
#*WARRANTIES,EITHER EXPRESS, IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO   
#*THE SOFTWARE,INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR  
#* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
#* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
#* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
#* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
#* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
#* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
#***********************license end**************************************/


ifneq (${OCTEONTARGET},x86)
ifeq ($(OCTEON_ROOT),)
$(error OCTEON_ROOT is not set)
endif
ifeq ($(HFAROOT),)
export HFAROOT=$(OCTEON_ROOT)/components/hfa
endif
endif

ifeq ($(OCTEONTARGET),)
export OCTEONTARGET=linux_64
$(shell rm -f install;ln -s install.linux install)
else ifeq ($(OCTEONTARGET),x86)
$(shell rm -f install;ln -s install.x86 install)
endif

#to be fixed
ifeq ($(OCTEONTARGET),cvmx_64)
export OCTEONTARGET=
endif

export HFAC_TARGET=cn68xx
ifneq (,$(findstring CN68XX,$(OCTEON_MODEL)))
export HFAC_TARGET=cn68xx
octeon_mode=octeon2
else
ifneq (,$(findstring CN70XX,$(OCTEON_MODEL)))
export HFAC_TARGET=cn70xx
octeon_mode=octeon3
else
ifneq (,$(findstring CN71XX,$(OCTEON_MODEL)))
export HFAC_TARGET=cn70xx
octeon_mode=octeon3
endif
endif
endif
export ac_cv_func_malloc_0_nonnull=yes
export SNORTROOTDIR=$(shell pwd)
OBJ_DIR1 = obj-linux_64-$(octeon_mode)

ifeq (${OCTEONTARGET},x86)
export SNORTINSTALLDIR=$(SNORTROOTDIR)/install.x86
else
export SNORTINSTALLDIR=$(SNORTROOTDIR)/install
endif
export PCRE_DIR = pcre-8.12
export MISC_DIR = misc
export MEMFS_DIR = snortRuleDir
export PCAP_DIR = libpcap-1.0.0 
export DAQ_DIR = daq-0.5
export LIBDNET_DIR = libdnet-1.12
export SNORT_DIR = snort-2.9.3.1
# Modify HFA_DIR if not at default PATH
export HFA_DIR = $(OCTEON_ROOT)/components/hfa
ifeq (${OCTEONTARGET},linux_64)   
export CROSS=mips64-octeon-linux-gnu
export CUSTOM_FLAGS=-g -march=$(octeon_mode) -O2 -DCAV_OCT_HFA -DCAV_OCT_LINUX -g -DUSE_RUNTIME_MODEL_CHECKS=1 -I$(OCTEON_ROOT)/executive -DUSER_MODE -DSDK_3_1 -Wl,--no-warn-mismatch -Wno-unused-but-set-variable -Wno-unused-function -Wno-implicit-function-declaration
export LD_LIBRARY_PATH=$(SNORTROOTDIR)/install/lib
else ifeq (${OCTEONTARGET},x86)
export CROSS= 
export CUSTOM_FLAGS= -g -O0 -DCAV_OCT_HFA_GCOMPILE
else
export CROSS=mipsisa64-octeon-elf
export CUSTOM_FLAGS=-march=$(octeon_mode) -O2 -DCAV_OCT_HFA -DCAV_OCT_SE -g -DUSE_RUNTIME_MODEL_CHECKS=1 -I$(OCTEON_ROOT)/executive -DUSER_MODE $(OCTEON_CPPFLAGS_GLOBAL_ADD) -DSDK_3_1 -Wl,--no-warn-mismatch
endif


include $(OCTEON_ROOT)/common.mk

default: all

# "Available targets:"
# "     For the very first time you should issue make"
# "     For repeated builds use one or more of the following"
# "         hfa misc pcre pcap daq dnet snort"
# "     You can repeat the above with -all and -clean suffix"
# "         Ex: pcre-all or pcap-clean"
# "     If compiling for linux use flag OCTEONTARGET=linux_64"
# "     If compiling for graph generation on x86 use flag OCTEONTARGET=x86"

ifeq (${OCTEONTARGET},x86)
all:  dnet-all pcre-all miscx86-all snort-all
clean: snort-clean  miscx86-clean pcre-clean dnet-clean
else
all: hfa-all misc-all snort-all
dev: hfa-all pcre-all misc-all  pcap-all daq-all dnet-all snort-all
clean: snort-clean misc-clean hfa-clean
	rm -f install
endif

misc-all: misc-clean misc
miscx86-all: miscx86-clean miscx86
hfa-all:  hfa-clean hfa
pcre-all: pcre-clean pcre-configure pcre
pcap-all: pcap-clean pcap-configure pcap
daq-all: daq-clean daq-configure daq
dnet-all: dnet-clean dnet-configure dnet
snort-all: snort-clean snort-configure snort

pcre-clean:
	-cd $(PCRE_DIR); [ ! -f Makefile ] && { exit 0; }; make uninstall clean distclean; 
	 rm -f $(SNORTINSTALLDIR)/.pcreconfigured
pcre-configure:
	cd $(PCRE_DIR); ./configure --host=$(CROSS) --prefix=/$(SNORTROOTDIR)/install CFLAGS="$(CUSTOM_FLAGS) -fPIC" CXXFLAGS="$(CUSTOM_FLAGS)" --disable-shared;
	cd $(SNORTINSTALLDIR); touch .pcreconfigured
pcre-configured:
	cd $(SNORTINSTALLDIR) 2> /dev/null; \
	[ -f .pcreconfigured ] && { exit 0; }; \
	echo "RUN make pcre-configure first"; exit 1;
pcre: pcre-configured pcre-build pcre-install
pcre-build:
	cd $(PCRE_DIR); make
pcre-install:
	cd $(PCRE_DIR); make install

misc-clean:
	cd $(MISC_DIR); make clean
.PHONY misc: misc-build misc-install
misc-build:
	cd $(MISC_DIR); make 
misc-install:
	cd $(MISC_DIR); make install

miscx86-clean:
	cd $(MISC_DIR); make -f Makefile.x86 clean
.PHONY miscx86: miscx86-build miscx86-install
miscx86-build:
	cd $(MISC_DIR); make -f Makefile.x86 
miscx86-install:
	-mkdir -p install.x86/{bin,include,lib,man,share}
	-rm -f install;ln -s install.x86 install
	cd $(MISC_DIR); make -f Makefile.x86 install

ifeq (${OCTEONTARGET},linux_64)
hfa-clean:
	#cd $(HFA_DIR); . ./env.bash cn68xx octeon linux;
	#cd $(HFA_DIR)/examples/octeon-examples/linux-user-poll; make target=hfap clean
	cd $(HFAROOT); make clean OCTEON_MODE=seum;
	-rm -f $(SNORTINSTALLDIR)/lib/{libcvmhfao.a,libcvmhfap.a,libcvmx.a,libfdt.a,libocteon-hfa.a,libppdfa.a,libpp.a}
.PHONY hfa: hfa-build hfa-install
hfa-build:
	cd $(HFAROOT); make OCTEON_MODE=seum;
hfa-install:
	-mkdir -p install.linux/{bin,include,lib,man,share}
	-rm -f install;ln -s install.linux install
	cp $(HFAROOT)/apps/func/$(OBJ_DIR1)/libcvmhfa.a $(SNORTINSTALLDIR)/lib/
	cp $(HFAROOT)/apps/func/$(OBJ_DIR1)/cvmx-config-init.o $(SNORTINSTALLDIR)/lib/
	cp $(OCTEON_ROOT)/executive/$(OBJ_DIR1)/libcvmx.a $(SNORTINSTALLDIR)/lib/
	cp $(OCTEON_ROOT)/executive/$(OBJ_DIR1)/libfdt.a $(SNORTINSTALLDIR)/lib/
	cp $(HFAROOT)/lib/octeon/pp/seum/libpp.a $(SNORTINSTALLDIR)/lib/
	cp $(HFAROOT)/apps/func/$(OBJ_DIR1)/libcvmgz.a $(SNORTINSTALLDIR)/lib/
	#cp $(HFAROOT)/utils/cvmgz/{hfa-zlib.h,zconf.h,gzguts.h} $(SNORTROOTDIR)/include/
	cp $(HFAROOT)/utils/cvmgz/hfa-zlib.h $(SNORTROOTDIR)/include/
	cp $(HFAROOT)/utils/cvmgz/zconf.h $(SNORTROOTDIR)/include/
	cp $(HFAROOT)/utils/cvmgz/gzguts.h $(SNORTROOTDIR)/include/
	$(AR) -r $(SNORTINSTALLDIR)/lib/libcvmx.a $(SNORTINSTALLDIR)/lib/cvmx-config-init.o

else	
hfa-clean:
	cd $(HFAROOT); make clean;
	-rm -f $(SNORTINSTALLDIR)/lib/{libcvmhfao.a,libcvmhfap.a,libcvmx.a,libfdt.a,libocteon-hfa.a,libppdfa.a,libpp.a,libcvmgz.a}
	-rm -f $(SNORTROOTDIR)/include/{gzguts.h,zconf.h,hfa-zlib.h}
.PHONY hfa: hfa-build hfa-install
hfa-build:
	cd $(HFAROOT); make OCTEON_MODE=se;
hfa-install:
	-mkdir -p install.se/{bin,include,lib,man,share}
	-rm -f install;ln -s install.se install
	cp $(HFAROOT)/drv/src/libcvmhfa.a $(SNORTINSTALLDIR)/lib/
	cp $(HFAROOT)/apps/func/$(OBJ_DIR)/cvmx-config-init.o $(SNORTINSTALLDIR)/lib/
	cp $(OCTEON_ROOT)/executive/$(OBJ_DIR)/libcvmx.a $(SNORTINSTALLDIR)/lib/
	cp $(OCTEON_ROOT)/executive/$(OBJ_DIR)/libfdt.a $(SNORTINSTALLDIR)/lib/
	cp $(HFAROOT)/lib/octeon/pp/se/libpp.a $(SNORTINSTALLDIR)/lib/
	cp $(HFAROOT)/apps/func/$(OBJ_DIR)/libcvmgz.a $(SNORTINSTALLDIR)/lib/
	#cp $(HFAROOT)/utils/cvmgz/{hfa-zlib.h,zconf.h,gzguts.h} $(SNORTROOTDIR)/include/
	cp $(HFAROOT)/utils/cvmgz/hfa-zlib.h $(SNORTROOTDIR)/include/
	cp $(HFAROOT)/utils/cvmgz/zconf.h $(SNORTROOTDIR)/include/
	cp $(HFAROOT)/utils/cvmgz/gzguts.h $(SNORTROOTDIR)/include/	
	$(AR) -r $(SNORTINSTALLDIR)/lib/libcvmx.a $(SNORTINSTALLDIR)/lib/cvmx-config-init.o
endif
pcap-clean:
	-cd $(PCAP_DIR); [ ! -f Makefile ] && { exit 0; }; make uninstall clean distclean;
	 rm -f $(SNORTINSTALLDIR)/.pcapconfigured
pcap-configure:
ifeq (${OCTEONTARGET},linux_64)
	cd $(PCAP_DIR); CFLAGS="-DOCTEON_MODEL=$(OCTEON_MODEL) -I$(HFA_DIR)/drv/src/config/ $(CUSTOM_FLAGS)" CPPFLAGS="$(CUSTOM_FLAGS)" ac_cv_linux_vers=2 ./configure --host=$(CROSS) --prefix=$(SNORTINSTALLDIR) --with-pcap=linux
	cd $(SNORTINSTALLDIR); touch .pcapconfigured
else
	cd $(PCAP_DIR); CFLAGS="-I$(SNORTROOTDIR)/include -I$(HFAROOT)/drv/src/config/ $(CUSTOM_FLAGS)" CPPFLAGS="$(CUSTOM_FLAGS)" ./configure --host=$(CROSS) --prefix=$(SNORTINSTALLDIR) --with-pcap=null
	cd $(SNORTINSTALLDIR); touch .pcapconfigured
endif
pcap-configured:
	cd $(SNORTINSTALLDIR) 2> /dev/null; \
	[ -f .pcapconfigured ] && { exit 0; }; \
	echo "RUN make pcap-configure first"; exit 1;
pcap: pcap-configured pcap-build pcap-install
pcap-build:
	cd $(PCAP_DIR); make
pcap-install:
	if test -d $(SNORTINSTALLDIR)/share/man/man3; then rm -rf $(SNORTINSTALLDIR)/share/man/man3; fi
	cd $(PCAP_DIR); make install

daq-clean:
	-cd $(DAQ_DIR); [ ! -f Makefile ] && { exit 0; }; make uninstall clean;
	 rm -f $(SNORTINSTALLDIR)/.daqconfigured
ifeq (${OCTEONTARGET},linux_64)
daq-configure:
	cd $(DAQ_DIR);CFLAGS="-DOCTEON_MODEL=$(OCTEON_MODEL) $(CUSTOM_FLAGS)" CPPFLAGS="$(CUSTOM_FLAGS)"  ac_cv_func_malloc_0_nonnull=yes LDFLAGS=-L$(SNORTINSTALLDIR)/lib LIBS="-lcvmx -lfdt" ./configure --host=mips64-octeon-linux-gnu --prefix=$(SNORTINSTALLDIR) --with-libpcap-libraries=$(SNORTINSTALLDIR)/lib --with-libpcap-includes=$(SNORTINSTALLDIR)/include --with-dnet-includes=$(SNORTINSTALLDIR)/include --with-dnet-libraries=$(SNORTINSTALLDIR)/lib
	cd $(SNORTINSTALLDIR); touch .daqconfigured
else
daq-configure:
	cd $(DAQ_DIR); CFLAGS="-I$(SNORTROOTDIR)/include -DOCTEON_MODEL=$(OCTEON_MODEL) $(CUSTOM_FLAGS)" CPPFLAGS="$(CUSTOM_FLAGS)" LDFLAGS=-L$(SNORTINSTALLDIR)/lib  ac_cv_func_malloc_0_nonnull=yes LIBS="-lmisc -lse -lcvmx -lfdt -lcvmgz" ./configure --host=$(CROSS) --prefix=$(SNORTINSTALLDIR) --disable-ipfw-module --with-libpcap-includes=$(SNORTINSTALLDIR)/include/ --with-libpcap-libraries=$(SNORTINSTALLDIR)/lib/
	cd $(SNORTINSTALLDIR); touch .daqconfigured
endif
daq-configured:
	cd $(SNORTINSTALLDIR) 2> /dev/null; \
	[ -f .daqconfigured ] && { exit 0; };\
	echo "Run make daq-configure first"; exit 1;
daq: daq-configured daq-build daq-install
daq-build:
	cd $(DAQ_DIR); make
daq-install:
	cd $(DAQ_DIR); make install

dnet-clean:
	-cd $(LIBDNET_DIR); [ ! -f Makefile ] && { exit 0; }; make uninstall clean distclean;
	 rm -f $(SNORTINSTALLDIR)/.dnetconfigured
dnet-configure:
	cd $(LIBDNET_DIR); CFLAGS="-I$(SNORTROOTDIR)/include $(CUSTOM_FLAGS)" CXXFLAGS="$(CUSTOM_FLAGS)" ./configure --host=$(CROSS) --prefix=/$(SNORTINSTALLDIR);
	cd $(SNORTINSTALLDIR); touch .dnetconfigured
dnet-configured:
	cd $(SNORTINSTALLDIR) 2> /dev/null; \
	[ -f .dnetconfigured ] && { exit 0; }; \
	echo "RUN make dnet-configure first"; exit 1;
dnet: dnet-configured dnet-build dnet-install
dnet-build:
	cd $(LIBDNET_DIR); make
dnet-install:
	cd $(LIBDNET_DIR); make install
ifeq (${OCTEONTARGET},x86)
snort-clean:
	-cd $(SNORT_DIR); [ ! -f Makefile ] && { exit 0; }; make uninstall ; make  clean  ; make distclean;
	 rm -f $(SNORTINSTALLDIR)/.snortconfigured
else
snort-clean:
	-cd $(SNORT_DIR); [ ! -f Makefile ] && { exit 0; }; make uninstall clean distclean;
	 rm -f $(SNORTINSTALLDIR)/.snortconfigured
endif
ifeq (${OCTEONTARGET},linux_64)
snort-configure:
	ar crv $(SNORTINSTALLDIR)/lib/libmalloc.a $(HFAROOT)/apps/func/$(OBJ_DIR1)/hfa-malloc.o
	cd $(SNORT_DIR); PATH="$(SNORTINSTALLDIR)/bin:$(PATH)" CFLAGS="-I$(SNORTROOTDIR)/include -I$(HFAROOT)/utils/hfa-malloc -I$(HFA_DIR)/drv/src/config/ -I$(SNORTROOTDIR)/$(MISC_DIR)/ -I$(HFAROOT)/drv/include/  -I$(HFA_DIR)/examples/octeon-examples/linux-user-poll/config -DOCTEON_MODEL=$(OCTEON_MODEL) -DHFAC_TARGET=$(HFAC_TARGET) $(CUSTOM_FLAGS) -g" CPPFLAGS="$(CUSTOM_FLAGS)" ac_cv_type_uint64_t=no ac_cv_lib_pcap_pfring_open=yes LDFLAGS=-L$(SNORTINSTALLDIR)/lib LIBS="-lse -lmisc -lcvmhfa -lpp -lcvmx -lcvmgz -lfdt -lsfbpf -ldaq_static_modules -lpthread -lmalloc -lrt -Xlinker -T -Xlinker $(OCTEON_ROOT)/target/lib/cvmx-shared-linux.ld" ./configure --host=mips64-octeon-linux-gnu --with-libpcap-libraries=$(SNORTINSTALLDIR)/lib --with-libpcap-includes=$(SNORTINSTALLDIR)/include --with-libpcre-includes=$(SNORTINSTALLDIR)/include/ --with-libpcre-libraries=$(SNORTINSTALLDIR)/lib --with-dnet-includes=$(SNORTINSTALLDIR)/include --with-dnet-libraries=$(SNORTINSTALLDIR)/lib --with-daq-includes=$(SNORTINSTALLDIR)/include --with-daq-libraries=$(SNORTINSTALLDIR)/lib --prefix=$(SNORTINSTALLDIR) --disable-zlib --disable-targetbased --disable-pthread --disable-reload --disable-active-response --disable-ipv6 --disable-gre --disable-mpls --disable-ppm  --disable-ppm-test --disable-reload-error-restart  --disable-react  --disable-paf
	cd $(SNORTINSTALLDIR); touch .snortconfigured
else ifeq (${OCTEONTARGET},x86)
snort-configure:
	cd $(SNORT_DIR); CFLAGS="-I$(SNORTROOTDIR)/include/x86 -I$(SNORTROOTDIR)/$(MISC_DIR)/ -DCVMX_MAX_CORES=32 -DHFAC_TARGET=$(HFAC_TARGET) $(CUSTOM_FLAGS) -Dx86" CPPFLAGS="$(CUSTOM_FLAGS)" LDFLAGS=" -L$(SNORTINSTALLDIR)/lib -L$(SNORTROOTDIR)/install.x86/lib" LIBS="-lmiscx86 -lstdc++ -lgcrypt -lgpg-error  -ldnet -lpcre " ./configure.x86 --prefix=$(SNORTINSTALLDIR) --with-libpcap-includes=$(SNORTROOTDIR)/install.x86/include --with-libpcre-includes=$(SNORTROOTDIR)/install.x86/include --with-libpcre-libraries=$(SNORTINSTALLDIR)/lib --with-dnet-includes=$(SNORTINSTALLDIR)/include --with-dnet-libraries=$(SNORTINSTALLDIR)/lib --with-daq-includes=$(SNORTROOTDIR)/install.x86/include --prefix=$(SNORTINSTALLDIR)  --disable-zlib   --disable-reload  --disable-ppm --disable-targetbased  --disable-ppm-test  --disable-reload-error-restart  --disable-perfprofiling  --disable-static-daq --disable-paf 

	cd $(SNORTINSTALLDIR); touch .snortconfigured
else
export OCTEON_TARGET = cvmx_64
snort-configure:
	cd $(SNORT_DIR); CFLAGS="-I$(SNORTROOTDIR)/include -I$(HFAROOT)/drv/src/config/ -I$(SNORTROOTDIR)/$(MISC_DIR)/ -I$(HFAROOT)/drv/include/ -DOCTEON_MODEL=$(OCTEON_MODEL) -DHFAC_TARGET=$(HFAC_TARGET) $(CUSTOM_FLAGS) -include $(SNORTROOTDIR)/$(SNORT_DIR)/src/sf_types.h" CPPFLAGS="$(CUSTOM_FLAGS)" LDFLAGS=-L$(SNORTINSTALLDIR)/lib LIBS="-lmisc -lse -lcvmhfa -lcvmx -lfdt -lpp -ldaq -lcvmgz" ac_cv_host=mipsisa64-octeon-elf  ./configure --host=mipsisa64-octeon-elf --prefix=$(SNORTINSTALLDIR) --with-libpcap-includes=$(SNORTINSTALLDIR)/include --with-libpcap-libraries=$(SNORTINSTALLDIR)/lib --with-libpcre-includes=$(SNORTINSTALLDIR)/include/ --with-libpcre-libraries=$(SNORTINSTALLDIR)/lib --with-dnet-includes=$(SNORTINSTALLDIR)/include --with-dnet-libraries=$(SNORTINSTALLDIR)/lib --with-daq-includes=$(SNORTINSTALLDIR)/include --with-daq-libraries=$(SNORTINSTALLDIR)/lib --enable-shared=no  --disable-zlib --disable-targetbased  --disable-pthread --disable-reload --disable-active-response --disable-dynamicplugin --disable-ipv6 --disable-gre --disable-mpls --disable-ppm --disable-ppm-test --disable-reload-error-restart --disable-paf --disable-react --disable-flexresp3 --disable-static-daq
	cd $(SNORTINSTALLDIR); touch .snortconfigured
endif
snort-configured:
	cd $(SNORTINSTALLDIR) 2> /dev/null; \
	[ -f .snortconfigured ] && { exit 0; };\
	echo "Run make snort-configure first"; exit 1;
snort: snort-configured snort-build snort-install
snort-build:
	cd $(SNORT_DIR);touch src/snort.c; make
snort-install:
	cd $(SNORT_DIR); make install
ifeq (${OCTEONTARGET},x86)
	cp -f $(SNORTINSTALLDIR)/bin/snort $(SNORTINSTALLDIR)/bin/snortrc
endif
