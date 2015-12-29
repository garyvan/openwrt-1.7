/***********************license start***************                              
* Copyright (c) 2008-2015 Cavium Inc. All rights reserved.
*                                                                                 
*                                                                                 
* Redistribution and use in source and binary forms, with or without              
* modification, are permitted provided that the following conditions are          
* met:                                                                            
                                                                                  
*   * Redistributions of source code must retain the above copyright              
*     notice, this list of conditions and the following disclaimer.               
*                                                                                 
*   * Redistributions in binary form must reproduce the above                     
*     copyright notice, this list of conditions and the following                 
*     disclaimer in the documentation and/or other materials provided             
*     with the distribution.                                                      
*                                                                                 
*   * Neither the name of Cavium Inc. nor the names of                            
*     its contributors may be used to endorse or promote products                 
*     derived from this software without specific prior written                   
*     permission.                                                                 
                                                                                  
*This Software,including technical data,may be subject to U.S. export control 
* laws, including the U.S. Export Administration Act and its  associated          
* regulations, and may be subject to export or import  regulations in other       
* countries.                                                                      
                                                                                  
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
*WARRANTIES,EITHER EXPRESS,IMPLIED,STATUTORY,OR OTHERWISE,WITH RESPECT TO   
*THE SOFTWARE,INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR  
* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
***********************license end**************************************/         

#include <stdio.h>

void
ip_checksum(void *buf, size_t len){}


int
rand_shuffle(void *r, void *base, size_t nmemb, size_t size){return 0;}


void *
rand_close(void *r) {return NULL;}


void *
rand_open(void) {return NULL;}


int
rand_get(void *r, void *buf, size_t len) {return 0;}

int
pcap_findalldevs(void **alldevsp, char *errbuf) {return 0;}


int
pcap_lookupnet(device, netp, maskp, errbuf)
   register const char *device;
   register void *netp, *maskp;
   register char *errbuf;
{ return 0;}


void
pcap_freealldevs(void *alldevs){}

 
void *pcap_open_dead(int linktype, int snaplen) {}


void *pcap_dump_open(void *p, const char *fname) {}


void  pcap_dump_close(void *p){}


void  pcap_dump(void *user, const void *h, const void *sp) {}


void  pcap_close(void *p){}


int daq_get_capabilities(const void *module, void *handle){return 0;}


const char* pcre_version(void) {return NULL;}


int daq_initialize(const void *module, const void *config, void **handle, char *errbuf, size_t len){ return 0;}


int daq_set_filter(const  *module, void *handle, const char *filter){return 0;}


int daq_start(const void *module, void *handle){return 0;}


int daq_acquire(const void *module, void *handle, int cnt, void* callback, void *user) {return 0;}


int daq_inject(const void *module, void *handle, const void *hdr, const char *packet_data, int len, int reverse) {return 0;}


int daq_breakloop(const void *module, void *handle) {return 0;}


int daq_stop(const void *module, void *handle) {return 0;}


int daq_shutdown(const void *module, void *handle){return 0;}


void daq_check_status(const void *module, void *handle){}


int daq_get_stats(const void *module, void *handle, void *stats) {return 0;}


void daq_reset_stats(const void *module, void *handle){}


int daq_get_snaplen(const void *module, void *handle){return 0;}


int daq_get_datalink_type(const void *module, void *handle){return 0;}


const char *daq_get_error(const void *module, void *handle) {return NULL;}


void daq_clear_error(const void *module, void *handle){}


const char *daq_get_name(const void *module) {return NULL;}


int daq_get_type(const void *module){return 0;}


void daq_set_verbosity(int level){}


int daq_load_modules(const char *module_dirs[]){return 0;}


const void *daq_find_module(const char *name){return NULL;}


int daq_get_module_list(void *list[]){return 0;}


void daq_free_module_list(void *list, int size){}


void daq_unload_modules(void){}


void daq_print_stats(void *stats, void *fp){}


const char *daq_mode_string(void* mode){return NULL;}


void daq_config_set_value(void *config, const char *key, const char *value){}


void daq_config_clear_values(void *config){}


int pcre_exec(const void *argument_re, const void *extra_data,
 void* subject, int length, int start_offset, int options, int *offsets,
 int offsetcount){return 0;}


int pcre_fullinfo(const void *argument_re, const void *extra_data, int what,
 void *where){return 0;}
#if 0
void *pcre_compile(const char *pattern, int options, const char **errorptr,
 int *erroroffset, const unsigned char *tables){ return NULL;}
#endif

void *pcre_study(const void *external_re, int options, const char **errorptr){return NULL;}

