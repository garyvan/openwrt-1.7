/***********************license start***************                              
* Copyright (c) 2003-2013  Cavium Inc. (support@cavium.com). All rights           
* reserved.                                                                       
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
                                                                                  
* This Software, including technical data, may be subject to U.S. export  control 
* laws, including the U.S. Export Administration Act and its  associated          
* regulations, and may be subject to export or import  regulations in other       
* countries.                                                                      
                                                                                  
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
* WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO   
* THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR  
* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
***********************license end**************************************/         


/**
 * @file 
 * This is header file for kernel library module
 */
#ifndef _CVM_HFA_MODULE_H_
#define _CVM_HFA_MODULE_H_

#include <linux/netdevice.h>
#include <asm/octeon/octeon-ethernet-user.h>

#define HFA_MAX_WQEGRP_ALLOWED          15
#define OCTEON_HFA_MEMORY_SIZE          hfa_mem_sz

/**IBUFPOOL macros are used by HFA-SDK applications, HFA-SDK API do not use 
 * these macros*/
#define OCTEON_IBUFPOOL                 0
#define OCTEON_IBUFPOOL_SIZE           CVMX_FPA_PACKET_POOL_SIZE
#define OCTEON_IBUFPOOL_COUNT          60000

/*hfa_ppbuf_cnt, hfa_tbuf_cnt and hfa_cmdbuf_cnt can be set using commmand
 * line while loading the HFA_LIB_MODULE*/
#define OCTEON_PPBUFPOOL                (4)   
#define OCTEON_PPBUFPOOL_SIZE           (2 * CVMX_CACHE_LINE_SIZE)
#define OCTEON_PPBUFPOOL_COUNT          hfa_ppbuf_cnt

#define OCTEON_TBUFPOOL                 (5)  
#define OCTEON_TBUFPOOL_SIZE            (3 * CVMX_CACHE_LINE_SIZE)
#define OCTEON_TBUFPOOL_COUNT           hfa_tbuf_cnt

#define OCTEON_HFAPOOL                  CVMX_FPA_DFA_POOL
#define OCTEON_HFAPOOL_SIZE             CVMX_FPA_DFA_POOL_SIZE
#define OCTEON_HFAPOOL_COUNT            hfa_cmdbuf_cnt 

#define DONT_WRITEBACK(x)               (x)
#define USE_ASYNC_IOBDMA                (CONFIG_CAVIUM_OCTEON_CVMSEG_SIZE > 0)

/*Typedefs*/
/**Intercept callback type for HFA NAPI*/
typedef cvm_oct_callback_result_t (*hfa_napi_interceptcb_t)
       (struct net_device *dev,void *work_queue_entry, struct sk_buff *skb);

/*Intercept callback type of Ethernet driver device cb*/
typedef struct netdevice * 
        (*ethernetdrv_cb_t)(const char *, hfa_napi_interceptcb_t);

/**@cond INTERNAL */
/**Napi wrapeer structure*/
struct hfa_napi_wrapper {
    struct napi_struct napi;
    int available;
}____cacheline_aligned_in_smp;

struct hfa_core_state {
    int             baseline_cores;

    /*this variable isread without lock*/
    volatile int    active_cores;

    /*to guard hfa_napi_wrapper.available + active_cores*/
    spinlock_t      lock;
}____cacheline_aligned_in_smp;

/**Function Declarations*/
extern char *hfa_mem_nb_name;
extern int octeon_ethernet_driver_pow_group;
int hfa_register_hwwqe_interceptcb (hfa_napi_interceptcb_t );
int hfa_register_packet_interceptcb (hfa_napi_interceptcb_t );
int hfa_oct_fill_hw_memory(int pool, int size, int elements);
void hfa_oct_free_hw_memory(int pool, int size, int elements);
void hfa_napi_rx_initialize(void);
void hfa_napi_rx_shutdown(void);
int  hfa_napi_free_work(void *);
int  hfa_isethernetdrv_present(void);
int  hfa_oct_initialize_sso(int);
/**@endcond*/
#endif
