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
 *
 * This is header file for statistics related macros and APIs
 *
 */
#ifndef _CVM_HFA_STATS_H_
#define _CVM_HFA_STATS_H_

#include "cvm-hfa-common.h"
#include "cvm-hfa.h"

/* Enable statistics */
#undef       HFA_STATS

#ifdef HFA_STATS
/** Enable statistics of each HW Instruction */
#undef      HFA_EXTENDED_STATS   
/** Enable per core search context statistics */
#define     HFA_PER_CORE_CTX_STATS          0x1
/** Enable shared search context statistics */
#define     HFA_SHARED_CTX_STATS            0x2
/** Enable core memory statistics */
#undef      HFA_CORE_MEMORY_STATS    

/* Magic number to validate search ctx when tracking 
 * search ctx ppbuf statistics. 
 */
#define     HFA_STATS_PPALLOC_MAGICNO       0xA5A5

/** Enable search context statistics */ 
#undef      HFA_CTX_STATS           
#ifdef HFA_CTX_STATS 
/** Decides per context or shared context */
#define     HFA_SCTX_STATS                   HFA_PER_CORE_CTX_STATS
/** Enable ctx memory statistics */
#define     HFA_CTX_MEMORY_STATS     
#endif /* End of HFA_CTX_STATS */

/** Arena size for hfa stats */
#define     HFA_STATS_ARENA_SIZE            0x100000
/** Macros to handle core statistics */
#define     HFA_CORE_STATS_INC(x,c,v)       hfa_stats[(c)]->x += (v);
#define     HFA_CORE_STATS_DEC(x,c,v)       hfa_stats[(c)]->x -= (v);
#define     HFA_CORE_STATS_SET(x,c,v)       hfa_stats[(c)]->x = (v);
#define     HFA_CORE_STATS_GET(x,c)         hfa_stats[(c)]->x
#endif /* End of #ifdef HFA_STATS */

#ifdef HFA_CTX_STATS
/** Macros to handle search context statistics */
#if (HFA_SCTX_STATS == HFA_PER_CORE_CTX_STATS)
#define     HFA_CTX_STATS_INC(ctx,x,c,v)    (ctx)->ctx_stats.x += (v);
#define     HFA_CTX_STATS_DEC(ctx,x,c,v)    (ctx)->ctx_stats.x -= (v);
#define     HFA_CTX_STATS_SET(ctx,x,c,v)    (ctx)->ctx_stats.x = (v);
#define     HFA_CTX_STATS_GET(ctx,x,c)      (ctx)->ctx_stats.x
#elif (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
#define     HFA_CTX_STATS_INC(ctx,x,c,v)    (ctx)->ctx_stats[(c)]->x += (v);
#define     HFA_CTX_STATS_DEC(ctx,x,c,v)    (ctx)->ctx_stats[(c)]->x -= (v);
#define     HFA_CTX_STATS_SET(ctx,x,c,v)    (ctx)->ctx_stats[(c)]->x = (v);
#define     HFA_CTX_STATS_GET(ctx,x,c)      (ctx)->ctx_stats[(c)]->x
#endif

#ifdef HFA_CTX_MEMORY_STATS
/**
 * This macro handle the searchctx memory statistics. It increments the 
 * curent memory usage counter and set the peak and maximum memory counters. 
 */
#define hfa_searchctx_mem_stats_inc(ctx, memtype, size)  ({  \
    hfa_cntrs_size_t peaksize = 0;                           \
    HFA_CTX_STATS_INC(ctx, memtype.curent, cvmx_get_core_num(), size);        \
    if((HFA_CTX_STATS_GET(ctx, memtype.max, cvmx_get_core_num())) < size)      \
        HFA_CTX_STATS_SET(ctx, memtype.max, cvmx_get_core_num(), size);        \
    peaksize = HFA_CTX_STATS_GET(ctx, memtype.curent, cvmx_get_core_num());   \
    if((HFA_CTX_STATS_GET(ctx, memtype.peak, cvmx_get_core_num())) < peaksize) \
        HFA_CTX_STATS_SET(ctx, memtype.peak, cvmx_get_core_num(), peaksize);   \
})
/**
 * This macro handle the searchctx memory statistics. It decrements the 
 * curent memory usage counter.
 */
#define hfa_searchctx_mem_stats_dec(ctx, memtype, size)        \
({                                                             \
    HFA_CTX_STATS_DEC(ctx, memtype.curent, cvmx_get_core_num(), size); \
})
#else 
/* Dummy macros for ctx memory statistics */
#define     hfa_searchctx_mem_stats_inc(ctx, memtype, size) 
#define     hfa_searchctx_mem_stats_dec(ctx, memtype, size) 
#endif /* End of HFA_CTX_MEMORY_STATS */
#else   
#define     hfa_searchctx_mem_stats_inc(ctx, memtype, size) 
#define     hfa_searchctx_mem_stats_dec(ctx, memtype, size) 
#endif  /* End of HFA_CTX_STATS */ 

#ifdef HFA_CORE_MEMORY_STATS
/**
 * This Macro handle the core memory statistics. It increments the 
 * curent memory usage counter and set the peak and maximum memory counters. 
 */
#define hfa_core_mem_stats_inc(memtype,size)  ({       \
    int c = cvmx_get_core_num();                       \
    hfa_cntrs_size_t peaksize = 0;                     \
    HFA_CORE_STATS_INC(memtype.curent, c, size);      \
    if((HFA_CORE_STATS_GET(memtype.max, c)) < size)    \
        HFA_CORE_STATS_SET(memtype.max, c, size);      \
    peaksize = HFA_CORE_STATS_GET(memtype.curent, c); \
    if((HFA_CORE_STATS_GET(memtype.peak, c)) < peaksize) \
        HFA_CORE_STATS_SET(memtype.peak, c, peaksize); \
})
/**
 * This macro handle the core memory statistics. It decrements the 
 * curent memory usage counter.
 */
#define hfa_core_mem_stats_dec(memtype, size)            \
({                                                       \
    HFA_CORE_STATS_DEC(memtype.curent, cvmx_get_core_num(), size); \
})
#else 
/* Dummy macros for core memory statistics */
#define     hfa_core_mem_stats_inc(memtype, size)
#define     hfa_core_mem_stats_dec(memtype, size)
#endif /* End of #ifdef HFA_CORE_MEMORY_STATS */

typedef  long int  hfa_cntrs_size_t;

struct hfa_searchctx;

/** Data structure for memory counters */ 
typedef struct {
    /** Peak memory used */
    hfa_cntrs_size_t    peak;
    /** Current memory usage */
    hfa_cntrs_size_t    curent;
    /** Maximum memory of all allocated memories */
    hfa_cntrs_size_t    max;
}hfa_memory_cntrs_t;

/** Data structure for instructon counters */
typedef struct {
    /** Total pending instructions in the HW*/
    hfa_cntrs_size_t    pending;
    /** Total processed instructions */
    hfa_cntrs_size_t    success;
    /** Total failed instructions */
    hfa_cntrs_size_t    failed;
}hfa_instr_cntrs_t;

/** Data structure for core statistics */
typedef struct {
    /** MLOAD instruction statistics */
    hfa_instr_cntrs_t   mload;
    /** CLOAD instruction statistics */
    hfa_instr_cntrs_t   cload;
    /** GWALk instruction statistics */
    hfa_instr_cntrs_t   gwalk;
    /** GFREE instruction statisticss */
    hfa_instr_cntrs_t   gfree;
    /** Total instructions statistics */
    hfa_instr_cntrs_t   total;       
    /** Number of contexts */         
    hfa_cntrs_size_t    nctxts;    
    /** HTE stats for gwalk instruction*/    
    hfa_cntrs_size_t    *htestats; 
    /** Number of matches found */        
    hfa_cntrs_size_t    nmatches;
#ifdef HFA_CORE_MEMORY_STATS
    /** Boot memory statistics 
     * (APIs are hfa_bootmem_alloc and hfa_bootmem_free) */
    hfa_memory_cntrs_t  bootmem;
    /** System memory statistics 
     * (APIs are kmalloc, vmalloc, kfree, vfree) */
    hfa_memory_cntrs_t  sysmem;
    /** Temp buffers statistics 
     * (APIs are hfa_os_malloc and hfa_os_free) */
    hfa_memory_cntrs_t  tempbuf;
    /** HFA_ARENA statistics 
     * (APIs are hfa_os_memoryalloc and hfa_os_memoryfree) */
    hfa_memory_cntrs_t  hfaarena;
    /** PP buffers statistics 
     * (APIs are hfa_defaultfn_ppalloc and hfa_defaultfn_ppfree */
    hfa_memory_cntrs_t  ppbuf;
#endif
}hfa_core_stats_t;

/** Data structure for Context stats */
typedef struct {
    /** gwalk instruction statistics */
    hfa_instr_cntrs_t  gwalk;
    /** hte statistics */
    hfa_cntrs_size_t   *htestats;
    /** Number of matches found */
    hfa_cntrs_size_t   nmatches;
    /** Matches found in HFA HW */
    hfa_cntrs_size_t   dfamatches;
#ifdef HFA_CTX_MEMORY_STATS
    /** Boot memory statistics 
     * (APIs are hfa_bootmem_alloc and hfa_bootmem_free) */
    hfa_memory_cntrs_t  bootmem;
    /** System memory statistics 
     * (APIs are kmalloc, vmalloc, kfree, vfree) */
    hfa_memory_cntrs_t  sysmem;
    /** PP buffers statistics 
     * (APIs are hfa_defaultfn_ppalloc and hfa_defaultfn_ppfree */
    hfa_memory_cntrs_t  ppbuf;
#endif
}hfa_ctx_stats_t;

/* Export variables to use in other files */
extern CVMX_SHARED  hfa_core_stats_t     **hfa_stats;

/*Function Declarations*/
hfa_return_t hfa_dev_stats_init(hfa_dev_t *);
void hfa_dev_stats_cleanup(hfa_dev_t *); 
void hfa_dev_stats_reset(hfa_dev_t *); 
void hfa_dev_stats_print(hfa_dev_t *);
hfa_return_t hfa_searchctx_stats_init(struct hfa_searchctx *);
void hfa_searchctx_stats_cleanup(struct hfa_searchctx *); 
hfa_return_t hfa_searchctx_stats_reset(struct hfa_searchctx *); 
void hfa_searchctx_stats_print(struct hfa_searchctx *);
#endif

