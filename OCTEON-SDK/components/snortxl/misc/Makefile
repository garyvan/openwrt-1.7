#/***********************license start***************                              
#* Copyright (c) 2008-2015 Cavium Inc. All rights reserved.
#*                                                                                 
#*                                                                                 
#* Redistribution and use in source and binary forms, with or without              
#* modification, are permitted provided that the following conditions are   
#*  met->                                                                            
#								
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
#* WARRANTIES,EITHER EXPRESS,IMPLIED,STATUTORY,OR OTHERWISE,WITH RESPECT TO   
#* THE SOFTWARE,INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR
#* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
#* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
#* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
#* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
#* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
#* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
#***********************license end**************************************/


ifeq ($(OCTEON_ROOT),)
$(error OCTEON_ROOT is not set)
endif
ifeq ($(HFAROOT),)
$(error HFAROOT is not set)
endif

all: libmisc.a libse.a

libmisc.a: octeon-uart.o sha1.o misc_defs.o 
	$(CROSS)-ar -crus $@ $^

FLAGS= -I$(OCTEON_ROOT)/target/include -I../include -DOCTEON_MODEL=$(OCTEON_MODEL) -march=octeon3 $(CUSTOM_FLAGS) -L$(SNORTINSTALLDIR)/lib/libcvmgz.a 

octeon-uart.o: octeon-uart.c
	$(CROSS)-gcc -c -o $@ $^ $(FLAGS)
sha1.o: sha1.c ../include/sha1.h 
	$(CROSS)-gcc -c -o $@ -I$(OCTEON_ROOT)/target/include sha1.c $(FLAGS)
	cp -f ../include/sha1.h $(SNORTINSTALLDIR)/include
misc_defs.o: misc_defs.c ../include/misc_defs.h
	$(CROSS)-gcc -c -o $@ misc_defs.c $(FLAGS)
	cp -f ../include/misc_defs.h $(SNORTINSTALLDIR)/include
heaptrace.o: heaptrace.c
	$(CROSS)-gcc -c -o $@ $^ $(FLAGS)

install:
	mkdir -p $(SNORTINSTALLDIR)/lib; cp libmisc.a libse.a $(SNORTINSTALLDIR)/lib/

clean:
	rm -f *.o *.a memfs.bin; rm -f $(SNORTINSTALLDIR)/lib/libse.a $(SNORTINSTALLDIR)/lib/libmisc.a $(SNORTROOTDIR)/include/timersub.h

INET_SRC= inet_addr.c inet_ntoa.c inet_ntop.c inet_pton.c
INET_OBJ= inet_addr.o inet_ntoa.o inet_ntop.o inet_pton.o

ifneq (${OCTEONTARGET},linux_64)
libse.a: cli.o passthrough.o $(INET_OBJ)
libse.a: memfslib.o cli.o passthrough.o $(INET_OBJ)
else
libse.a: cli.o passthrough.o $(INET_OBJ)
endif
	$(CROSS)-ar -crus $@ $^

passthrough.o: passthrough.c
	cp -f ../$(SNORT_DIR)/src/timersub.h $(SNORTINSTALLDIR)/include/
ifeq (${OCTEONTARGET},linux_64)
	$(CROSS)-gcc -I../include -I$(OCTEON_ROOT)/target/include -I$(HFAROOT)/drv/include -I$(HFAROOT)/drv/src/config -I$(OCTEON_SDK)/bootloader/u-boot/include/asm/arch -I$(OCTEON_ROOT)/executive/libfdt -I$(SNORTINSTALLDIR)/include -DOCTEON_MODEL=$(OCTEON_MODEL) -DOCTEON_TARGET=cvmx_64 -DHFAP -I$(HFAROOT)/lib-octeon -I$(HFAROOT)/drv/inc $(FLAGS) -MD -c -o passthrough.o passthrough.c
else
	$(CROSS)-gcc -I../include -I$(OCTEON_ROOT)/target/include -I$(HFAROOT)/drv/include -I$(HFAROOT)/drv/src/config -I$(OCTEON_SDK)/bootloader/u-boot/include/asm/arch -I$(OCTEON_ROOT)/executive/libfdt -I$(SNORTINSTALLDIR)/include -DOCTEON_MODEL=$(OCTEON_MODEL) -DOCTEON_TARGET=cvmx_64 -DHFAP -I$(HFAROOT)/lib-octeon -I$(HFAROOT)/drv/inc $(FLAGS) -MD -c -o passthrough.o passthrough.c
endif

$(INET_OBJ): $(INET_SRC)
	$(CROSS)-gcc -I../include -I$(OCTEON_ROOT)/target/include -I$(OCTEON_ROOT)/executive/ -DHAVE_CONFIG_H -I$(SNORTROOTDIR)/$(SNORT_DIR) -I$(SNORTROOTDIR)/$(SNORT_DIR)/src/ -I$(SNORTINSTALLDIR)/include -DOCTEON_MODEL=$(OCTEON_MODEL) -DOCTEON_TARGET=cvmx_64 -MD -c  $^ $(FLAGS)

cli.o: cli.c
ifeq (${OCTEONTARGET},linux_64)
	$(CROSS)-gcc -c -I$(HFAROOT)/examples/octeon-examples/linux-user-poll/config -o $@ $^ $(FLAGS)
else
	$(CROSS)-gcc -c -I$(HFAROOT)/examples/octeon-examples/config -o $@ $^ $(FLAGS)
endif

memfslib.o: memfslib.c
ifeq (${OCTEONTARGET},linux_64)
	$(CROSS)-gcc -c -I$(HFAROOT)/examples/octeon-examples/linux-user-poll/config -o $@ $^ $(FLAGS)
else
	$(CROSS)-gcc -c -o $@ $^ $(FLAGS)
endif
