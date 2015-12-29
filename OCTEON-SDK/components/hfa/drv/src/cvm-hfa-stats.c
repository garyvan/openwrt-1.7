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
 * This file contains APIs to Initialize, manage and cleanup hfa related 
 * statistics. cvm-hfa-stats.h is the corresponding header file to be included
 * for prototypes and typedefs.
 *
 */
#include "cvm-hfa-stats.h"
#include "cvm-hfa-search.h"

/** @cond INTERNAL */
CVMX_SHARED     hfa_core_stats_t     **hfa_stats = NULL;
CVMX_SHARED     void                 *arena = NULL;
#ifndef KERNEL
CVMX_SHARED     cvmx_arena_list_t    hfa_stats_arena;
CVMX_SHARED     cvmx_spinlock_t      malloc_lock;
#endif
/** @endcond */

#ifdef HFA_STATS

#ifdef KERNEL  
#define     hfa_stats_memoryalloc(size, align)      vmalloc(size)
#define     hfa_stats_memoryfree(ptr,size)          vfree(ptr)
#else /* Start of #ifndef KERNEL */
/**
 * This routine allocates required memory from STATS ARENA
 *
 * @param    size    size to be allocate
 * @param    align   alignment
 *
 * @return  pointer to allocated memory region
 */ 
static inline void * 
hfa_stats_memoryalloc(uint64_t size, uint64_t align) 
{                              
    void        *ptr = NULL, *newptr = NULL;   
                                   
    cvmx_spinlock_lock(&malloc_lock);                                  
    if ((ptr = cvmx_malloc(hfa_stats_arena, size+align)) != NULL) {    
        newptr = (void * )((((unsigned long)ptr)+align)&(~(align-1))); 
        ((unsigned char *)newptr)[-1] = (unsigned char)(newptr - ptr); 
    }                                                                  
    cvmx_spinlock_unlock(&malloc_lock);                                
    return newptr;                                                            
}
/**
 * This routine frees memory to STATS ARENA 
 *
 * @param   ptr     ptr to be free
 * @param   size    size to be free 
 */ 
static inline void 
hfa_stats_memoryfree(void *ptr, uint64_t size)    
{                               
    unsigned char offset = ((unsigned char *)ptr)[-1];                 

    cvmx_spinlock_lock(&malloc_lock);                                  
    cvmx_free(((char *)ptr)-offset);                                   
    cvmx_spinlock_unlock(&malloc_lock);                                
}
#endif /* End of #def KERNEL */
/**
 * Create ARENA for hfa statistics. 
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline  hfa_return_t 
hfa_stats_create_arena(void)
{
#ifndef KERNEL
    hfa_size_t        nbsize=0;                      
    
    nbsize = HFA_STATS_ARENA_SIZE;
    hfa_dbg("hfa_stats arena nbsize: %lu\n", nbsize);
    if(HFA_SUCCESS != hfa_find_named_block("statsarena", &arena,
                                           &nbsize, hfa_get_mem_align())){
        return HFA_FAILURE;
    }
    hfa_dbg("arena =%p, sz: %lu\n", arena, nbsize);
    if (cvmx_add_arena(&hfa_stats_arena, arena, nbsize) < 0) {
        hfa_err(CVM_HFA_EDEVINIT, ("Unable to add memory to STATS ARENA\n"));
        return HFA_FAILURE;
    }

    /* threadsafe cvmx_malloc spin lock initialization */
    cvmx_spinlock_init(&malloc_lock);
#endif
    return HFA_SUCCESS;
}
/**
 * This routine allocates memory for counters to maintain statistics of each 
 * processing core. One core should initialize this statistics.
 *
 * Statistics are.
 *
 * HW instruction statistics(MLOAD,CLOAD,GWALK,GFREE) - 
 * This statistics tells how many instructions are pending in HW,
 * how many are successfully processed by HW and how many are failed.
 *
 * nctxts - This statistic tells how many search contexts are created for 
 * each core. 
 *
 * htestats - This statistic tells each hte engine processed how many walk
 * instructions on corresponding core.
 *
 * nmatches - This statistic tells number of matches found on corresponding 
 * core.
 *
 * memory statistics(boot memory, system memory, temp buffers, pp buffers, 
 * hfa arena) - 
 * This statistics tells memory usage of a core.
 *
 * The corresponding cleanup routine is hfa_dev_stats_cleanup()
 *
 * @return HFA_SUCCESS/HFA_FAILURE 
 */ 
hfa_return_t 
hfa_dev_stats_init(hfa_dev_t *pdev)
{
    hfa_core_stats_t    **ppstats = NULL;
    int                 i = 0;
    int                 cores = 0, hsize = 0;

    cores = cvmx_coremask_get_core_count(&cvmx_sysinfo_get()->core_mask);
    hsize = sizeof(hfa_cntrs_size_t) * hfa_get_max_htes();     
    
    if(HFA_SUCCESS != hfa_stats_create_arena()){
        hfa_log("Unable to create arena for hfa stats\n");
        return HFA_FAILURE;
    }
    if(NULL==(hfa_stats = hfa_stats_memoryalloc(sizeof(void *) * cores, 8))) {
        hfa_log("Memory allocation failed for hfa_stats of size %lu\n",
                                              (sizeof(void *) * cores));
        return HFA_FAILURE;
    }
    memset(hfa_stats, 0, sizeof(void *) * cores);
    for(i = 0; i < cores; i++) {
        ppstats = (hfa_core_stats_t **)&(hfa_stats[i]);
        if(NULL == (*ppstats = 
            hfa_stats_memoryalloc(sizeof(hfa_core_stats_t), 8))){
            hfa_log("Memory allocation failed for hte stats\n");
            goto free_corestats;
        }
        memset(*ppstats, 0, sizeof(hfa_core_stats_t));
        if(NULL == ((*ppstats)->htestats = 
            (hfa_cntrs_size_t *)hfa_stats_memoryalloc(hsize, 8))) {
            hfa_log("Memory allocation failed for ctx htestats of size %d\n",
                                                                       hsize);
            goto free_corestats;
        }
        memset((*ppstats)->htestats, 0, hsize);
    }
    return HFA_SUCCESS;

free_corestats:
    for(i = 0; i < cores; i++){
        ppstats = (hfa_core_stats_t **)&((hfa_stats[i]));
        if(*ppstats){
            if((*ppstats)->htestats)
                hfa_stats_memoryfree((*ppstats)->htestats, hsize);
            hfa_stats_memoryfree(*ppstats, sizeof(hfa_core_stats_t));
        }
    }
    hfa_stats_memoryfree(hfa_stats, sizeof(void *) * cores);

    return HFA_FAILURE;
}
/**
 * This routine is the counterpart of hfa_dev_init_stats(). 
 * One core should cleanup this statistics.  
 */
void 
hfa_dev_stats_cleanup(hfa_dev_t *pdev)
{
    int                 i, cores = 0, hsize = 0;
    hfa_cntrs_size_t    *phtes = NULL;

    cores = cvmx_coremask_get_core_count(&cvmx_sysinfo_get()->core_mask);
    hsize = sizeof(hfa_cntrs_size_t) * hfa_get_max_htes();
    if(hfa_stats){ 
        for(i = 0; i < cores; i++){
            if(hfa_stats[i]){
                phtes = (hfa_cntrs_size_t *)(hfa_stats[i]->htestats);
                if(phtes) {
                    memset(phtes, 0, hsize);
                    hfa_stats_memoryfree(phtes, hsize);
                }
                memset(hfa_stats[i], 0, sizeof(hfa_core_stats_t));
                hfa_stats_memoryfree(hfa_stats[i], sizeof(hfa_core_stats_t));
            }
        }
        memset(hfa_stats, 0, sizeof(void *) * cores);
        hfa_stats_memoryfree(hfa_stats, sizeof(void *) * cores);
        hfa_stats = NULL;
    }
#ifndef KERNEL   
    memset(&hfa_stats_arena, 0, sizeof(cvmx_arena_list_t));
#endif    
}
/**
 * This routine resets core statistics counters.
 * One core should call this routine.
 */
void 
hfa_dev_stats_reset(hfa_dev_t *pdev)
{
    int                   i = 0;
    int                   cores = 0, hsize = 0;
    hfa_cntrs_size_t      *htestats_bkp = NULL; 

    cores = cvmx_coremask_get_core_count(&cvmx_sysinfo_get()->core_mask);
    hsize = sizeof(hfa_cntrs_size_t) * hfa_get_max_htes();    
    if(hfa_stats) { 
        for(i = 0; i < cores; i++) {
            if(hfa_stats[i] && (hfa_stats[i])->htestats) {
                htestats_bkp = (hfa_stats[i])->htestats;
                
                memset(htestats_bkp, 0, hsize);
            }
            memset(hfa_stats[i], 0, sizeof(hfa_core_stats_t));
            hfa_stats[i]->htestats = htestats_bkp;
        }
    }
}
/**
 * This routine allocates the memory for counters to maintain the statistics 
 * of search context.
 * This routine handles per core context statistics and shared context 
 * statistics.
 * Per core context means each core have it's own search context. 
 * So, each core maintains the statistics of it's own search context.
 * Shared context means all cores process only one shared context.
 * So, one core initializes the statistics of context but statistics are 
 * tracked per core(means each core statistics on that shared context).
 *  
 * Statistics are. 
 *
 * gwalk - This statistic tells how many walks are done on search context.
 *
 * htestats - This statistic tells each hte engine processed how many walk
 * instructions on context.
 *
 * nmatches - This statistic tells number of matches found on search context. 
 *
 * memory statistics(boot memory, system memory, pp buffers, hfa_arena) -
 * This statistics tells memory usage of search context.
 *
 * The corresponding cleanup routine is hfa_searchctx_stats_cleanup()
 *
 * @param  psctx    pointer to search context
 *
 * @return HFA_SUCCESS/HFA_FAILURE 
 */ 
hfa_return_t 
hfa_searchctx_stats_init(hfa_searchctx_t *psctx)
{
#ifdef HFA_CTX_STATS

#if (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    hfa_ctx_stats_t     **ctx_stats = NULL;
    hfa_ctx_stats_t     **ppctxs = NULL;
    int                 i = 0, cores = 0;
#endif
    int                 hsize = 0;
    
    hsize = sizeof(hfa_cntrs_size_t) * hfa_get_max_htes();     
    
    if(hfa_os_unlikely(psctx == NULL)) {
        hfa_log("NULL psctx %p\n", psctx);
        return HFA_FAILURE;
    }
#if (HFA_SCTX_STATS == HFA_PER_CORE_CTX_STATS)     
    
    if(NULL == ((psctx->ctx_stats).htestats = 
        (hfa_cntrs_size_t *)hfa_stats_memoryalloc(hsize, 8))) {
        hfa_log("Memory allocation failed for ctx htestats of size %d\n",
                                                                  hsize);
        return HFA_FAILURE;
    }
    memset((psctx->ctx_stats).htestats, 0, hsize);
    
    return HFA_SUCCESS;
#elif (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    
    cores = cvmx_coremask_get_core_count(&cvmx_sysinfo_get()->core_mask);
    
    if(NULL == (ctx_stats = hfa_stats_memoryalloc(sizeof(void *) * cores, 8))){
        hfa_log("Memory allocation failed for ctx_stats\n");
        return HFA_FAILURE;
    }
    memset(ctx_stats, 0, sizeof(void *) * cores);
    for(i = 0; i < cores; i++) {
        ppctxs = (hfa_ctx_stats_t **)(&(ctx_stats[i]));
        if(NULL == (*ppctxs = (hfa_ctx_stats_t *)
            hfa_stats_memoryalloc(sizeof(hfa_ctx_stats_t), 8))){
            hfa_log("Memory allocation failed for ppctxs\n");
            goto free_ctxstats;
        }
        memset(*ppctxs, 0, sizeof(hfa_ctx_stats_t));
        if(NULL == ((*ppctxs)->htestats = (hfa_cntrs_size_t *)
                                    hfa_stats_memoryalloc(hsize, 8))) {
            hfa_log("Memory allocation failed for ctx htestats of size %d\n",
                                                                       hsize);
            goto free_ctxstats;
        }
        memset((*ppctxs)->htestats, 0, hsize);
    }
    psctx->ctx_stats = ctx_stats;
    
    return HFA_SUCCESS;

free_ctxstats:
    for(i = 0; i < cores; i++) {
        ppctxs = (hfa_ctx_stats_t **)&(ctx_stats[i]);
        if(*ppctxs) {
            if((*ppctxs)->htestats)
                hfa_stats_memoryfree((*ppctxs)->htestats, hsize);
            hfa_stats_memoryfree(*ppctxs, sizeof(hfa_ctx_stats_t));
        }
    }
    hfa_stats_memoryfree(ctx_stats, sizeof(void *) * cores);

    return HFA_FAILURE;

#endif   /* End of HFA_PER_CORE_STATS */
#endif /* End of HFA_CTX_STATS */
    
    return HFA_SUCCESS;
}
/**
 * This routine is the counterpart of hfa_searchctx_init_stats(). If context is
 * per core, each core should cleanup it's own context statistics. 
 * If context is shared, one core should cleanup context statistics. 
 * HFA_CTX_STATS should be enabled to use this routine 
 *
 * @param  psctx    pointer to search context 
 */
void
hfa_searchctx_stats_cleanup(hfa_searchctx_t *psctx)
{
#ifdef HFA_CTX_STATS
#if (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    hfa_ctx_stats_t     **ctx_stats = NULL, **ppctxs = NULL;
    int                 i, cores = 0;
#endif
    int                 hsize = 0;

    hsize = sizeof(hfa_cntrs_size_t) * hfa_get_max_htes();

#if (HFA_SCTX_STATS == HFA_PER_CORE_CTX_STATS)
    if(psctx && (psctx->ctx_stats).htestats){
        memset((psctx->ctx_stats).htestats, 0, hsize);
        hfa_stats_memoryfree((psctx->ctx_stats).htestats, hsize);
        memset(&(psctx->ctx_stats), 0, sizeof(hfa_ctx_stats_t));
    }
#elif (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    cores = cvmx_coremask_get_core_count(&cvmx_sysinfo_get()->core_mask);
    if(psctx) {
        ctx_stats = psctx->ctx_stats;
        psctx->ctx_stats = NULL;
    }
    if(ctx_stats) {
        for(i = 0; i < cores; i++) {
            ppctxs = (hfa_ctx_stats_t **)&(ctx_stats[i]);
            if(*ppctxs){
                if((*ppctxs)->htestats) {
                    memset((*ppctxs)->htestats, 0, hsize);
                    hfa_stats_memoryfree((*ppctxs)->htestats, hsize);
                }
                memset(*ppctxs, 0, sizeof(hfa_ctx_stats_t));
                hfa_stats_memoryfree(*ppctxs, sizeof(hfa_ctx_stats_t));
            }
        }
        memset(ctx_stats, 0, sizeof(void *) * cores);
        hfa_stats_memoryfree(ctx_stats, sizeof(void *) * cores);
    }
#endif /* End of HFA_PER_CORE_STATS */
#endif /* End of HFA_CTX_STATS */
}
/**
 * This routine resets search context statistics counters.
 * Each core should reset it's own context statistics. 
 * HFA_CTX_STATS should be enabled to use this routine 
 *
 * @param  psctx    pointer to search context 
 *
 * @return HFA_SUCCESS/HFA_FAILURE 
 */
hfa_return_t 
hfa_searchctx_stats_reset(hfa_searchctx_t *psctx)
{
#ifdef HFA_CTX_STATS
#if (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    int                 core = cvmx_get_core_num();
#endif
    int                 hsize = 0;
    hfa_cntrs_size_t    *htestats_bkp = NULL; 

    hsize = sizeof(hfa_cntrs_size_t) * hfa_get_max_htes();     
    if(hfa_os_unlikely(psctx == NULL)) {
        hfa_log("NULL psctx %p\n", psctx);
        return HFA_FAILURE;
    }
#if (HFA_SCTX_STATS == HFA_PER_CORE_CTX_STATS)

    if((psctx->ctx_stats).htestats) {   
        htestats_bkp = (psctx->ctx_stats).htestats;
        memset(htestats_bkp, 0, hsize);
    }
    memset(&psctx->ctx_stats, 0, sizeof(hfa_ctx_stats_t));
    (psctx->ctx_stats).htestats = htestats_bkp;

#elif (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
   
    if(psctx->ctx_stats && psctx->ctx_stats[core]) {
        
        if((psctx->ctx_stats[core])->htestats) {
            htestats_bkp = (psctx->ctx_stats[core])->htestats;
            memset(htestats_bkp, 0, hsize);
        }
        memset(psctx->ctx_stats[core], 0, sizeof(hfa_ctx_stats_t));
        psctx->ctx_stats[core]->htestats = htestats_bkp;
    }

#endif
#endif /* End of HFA_CTX_STATS */
    return HFA_SUCCESS;
}
/**
 * This routine prints statistics of each core. 
 * One core should print this statistics.
 */
void 
hfa_dev_stats_print(hfa_dev_t *pdev)
{
    int                  core, hte;
    hfa_instr_cntrs_t    global_instr_stats = {0};
    hfa_cntrs_size_t     *phtes = NULL;
    int                  cores = 0;

    cores = cvmx_coremask_get_core_count(&cvmx_sysinfo_get()->core_mask);
    for(core = 0; core < cores; core++) {
        if(hfa_stats && hfa_stats[core]) {

        hfa_log("CORE %d STATS\n", core);
        hfa_dbg("INSTRUCTION STATS\n");
#ifdef HFA_EXTENDED_STATS
        hfa_log("MLOAD: Pending:%ld  Failed:%ld  Success:%ld\n",
                                   HFA_CORE_STATS_GET(mload.pending, core),
                                   HFA_CORE_STATS_GET(mload.failed, core),
                                   HFA_CORE_STATS_GET(mload.success, core));
        hfa_log("CLOAD: Pending:%ld  Failed:%ld  Success:%ld\n",
                                   HFA_CORE_STATS_GET(cload.pending, core),
                                   HFA_CORE_STATS_GET(cload.failed, core),
                                   HFA_CORE_STATS_GET(cload.success, core));
        hfa_log("GWALK: Pending:%ld  Failed:%ld  Success:%ld\n",
                                   HFA_CORE_STATS_GET(gwalk.pending, core),
                                   HFA_CORE_STATS_GET(gwalk.failed, core),
                                   HFA_CORE_STATS_GET(gwalk.success, core));
        hfa_log("GFREE: Pending:%ld  Failed:%ld  Success:%ld\n",
                                   HFA_CORE_STATS_GET(gfree.pending, core),
                                   HFA_CORE_STATS_GET(gfree.failed, core),
                                   HFA_CORE_STATS_GET(gfree.success, core));
#endif
        hfa_log("TOTAL: Pending:%ld  Failed:%ld  Success:%ld\n",
                                   HFA_CORE_STATS_GET(total.pending, core),
                                   HFA_CORE_STATS_GET(total.failed, core),
                                   HFA_CORE_STATS_GET(total.success, core));

        global_instr_stats.pending = global_instr_stats.pending + 
                                   HFA_CORE_STATS_GET(total.pending, core);
        global_instr_stats.success = global_instr_stats.success + 
                                   HFA_CORE_STATS_GET(total.success, core);
        global_instr_stats.failed = global_instr_stats.failed + 
                                   HFA_CORE_STATS_GET(total.failed, core);


        hfa_log("HTE GWALK STATS\n");
        phtes = (hfa_cntrs_size_t *)hfa_stats[core]->htestats;
        for(hte = 0; hte < hfa_get_max_htes(); hte++){
            if(phtes && phtes[hte]){
                hfa_log("%d:%ld ", hte, phtes[hte]);
                phtes[hte] = 0;
            }
        }
        hfa_dbg("\n");
        hfa_log("NCONTEXTS:%ld\n", HFA_CORE_STATS_GET(nctxts, core));
        hfa_log("NMATCHES:%ld\n", HFA_CORE_STATS_GET(nmatches, core));
#ifdef HFA_CORE_MEMORY_STATS
        hfa_log("BOOTMEM:%ld need to be freed, peak usage %ld  max usage %ld\n",
                                    HFA_CORE_STATS_GET(bootmem.curent, core),
                                    HFA_CORE_STATS_GET(bootmem.peak, core),
                                    HFA_CORE_STATS_GET(bootmem.max, core));
#ifdef KERNEL
        hfa_log("SYSMEM: %ld need to be freed, peak usage %ld  max usage %ld\n",
                                    HFA_CORE_STATS_GET(sysmem.curent, core),
                                    HFA_CORE_STATS_GET(sysmem.peak, core),
                                    HFA_CORE_STATS_GET(sysmem.max, core));
#endif 
        hfa_log("HFA_ARENA:%ld need to be freed,peak usage %ld  max usage %ld\n",
                                    HFA_CORE_STATS_GET(hfaarena.curent, core),
                                    HFA_CORE_STATS_GET(hfaarena.peak, core),
                                    HFA_CORE_STATS_GET(hfaarena.max, core));
        hfa_log("TEMP BUFFERS: %ld need to be freed, peak usage %ld\n",
                                    HFA_CORE_STATS_GET(tempbuf.curent, core),
                                    HFA_CORE_STATS_GET(tempbuf.peak, core));
        hfa_log("PPBUF: %ld need to be freed, peak usage %ld \n",
                                    HFA_CORE_STATS_GET(ppbuf.curent, core),
                                    HFA_CORE_STATS_GET(ppbuf.peak, core));
#endif
        hfa_log("\n");
        }
    }
}
/**
 * This routine prints search context statistics. Each core should print this 
 * statistics.  
 * HFA_CTX_STATS should be enabled to use this routine 
 *
 * @param  psctx    pointer to search context 
 */
void 
hfa_searchctx_stats_print(hfa_searchctx_t *psctx) 
{
#ifdef HFA_CTX_STATS
    hfa_ctx_stats_t     *pctxstats = NULL;
    int                 hte = 0;
     
    if(psctx == NULL) {
        hfa_log("NULL psctx\n");
        return;
    }
#if (HFA_SCTX_STATS == HFA_PER_CORE_CTX_STATS)
    pctxstats = &(psctx->ctx_stats);
#elif (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    if(psctx->ctx_stats)
        pctxstats = (hfa_ctx_stats_t *)psctx->ctx_stats[cvmx_get_core_num()];
    else 
        return;
#endif
    if(pctxstats) { 
        hfa_log("gwalk:Pending:%ld Failed:%ld Success:%ld\n",
            HFA_CTX_STATS_GET(psctx, gwalk.pending, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, gwalk.failed, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, gwalk.success, cvmx_get_core_num()));
        
        if(pctxstats->htestats){
            for(hte = 0; hte < hfa_get_max_htes(); hte++){
                if(pctxstats->htestats[hte]){
                    hfa_log("HTE%d : %ld ", hte, 
                    HFA_CTX_STATS_GET(psctx, htestats[hte], 
                                      cvmx_get_core_num()));
                }
            }
        }
        /* Print post process statistics */
        hfa_searchctx_ppstats_print(psctx);
        hfa_log("NMATCHES:%ld\n", HFA_CTX_STATS_GET(psctx, nmatches, 
                                                cvmx_get_core_num()));
        hfa_log("DFA MATCHES:%ld\n", HFA_CTX_STATS_GET(psctx, dfamatches,
                                                cvmx_get_core_num()));
#ifdef HFA_CTX_MEMORY_STATS
        hfa_log("BOOTMEM:%ld need to be freed, peak usage %ld  max usage %ld\n",
            HFA_CTX_STATS_GET(psctx, bootmem.curent, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, bootmem.peak, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, bootmem.max, cvmx_get_core_num()));
#ifdef KERNEL
        hfa_log("SYSMEM:%ld need to be freed, peak usage %ld  max usage %ld\n",
            HFA_CTX_STATS_GET(psctx, sysmem.curent, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, sysmem.peak, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, sysmem.max, cvmx_get_core_num()));
#endif 
        hfa_log("PPBUF:%ld need to be freed, peak usage %ld \n",
            HFA_CTX_STATS_GET(psctx, ppbuf.curent, cvmx_get_core_num()),
            HFA_CTX_STATS_GET(psctx, ppbuf.peak, cvmx_get_core_num()));
#endif  
        hfa_log("\n");
    }
#endif
}
/**@cond INTERNAL*/
#ifdef KERNEL
EXPORT_SYMBOL (hfa_dev_stats_init);
EXPORT_SYMBOL (hfa_dev_stats_cleanup);
EXPORT_SYMBOL (hfa_dev_stats_reset);
EXPORT_SYMBOL (hfa_dev_stats_print);
EXPORT_SYMBOL (hfa_searchctx_stats_init);
EXPORT_SYMBOL (hfa_searchctx_stats_cleanup);
EXPORT_SYMBOL (hfa_searchctx_stats_reset);
EXPORT_SYMBOL (hfa_searchctx_stats_print);
EXPORT_SYMBOL (hfa_stats);
#endif
/**@endcond*/
#endif /* End of HFA_STATS */
