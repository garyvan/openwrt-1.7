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
 * This file contains HFA device related APIs. cvm-hfa.h is the corresponding
 * header file to be included for prototypes and typedefs
 *
 */
#include <cvm-hfa.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-stats.h>
#include <pp.h>

/** @cond INTERNAL */
#ifdef KERNEL

#include <cvm-hfa-module.h>
extern  int                         hfa_cmdbuf_cnt;
extern  int                         hfa_tbuf_cnt;
extern  int                         hfa_mem_sz;
#else

CVMX_SHARED cvmx_arena_list_t       hfa_arena;
CVMX_SHARED cvmx_spinlock_t         cvmx_malloc_lock;
CVMX_SHARED void*                   global_arena = NULL;
char *                              hfa_mem_nb_name = HFA_MEMORY_NB;
CVMX_SHARED int                     hfa_ppbuf_pool;
CVMX_SHARED int                     hfa_ppbuf_sz;
CVMX_SHARED int                     hfa_ppbuf_cnt;
CVMX_SHARED int                     hfa_tbuf_cnt;
CVMX_SHARED int                     hfa_cmdbuf_cnt;

#endif  /*End of #ifdef KERNEL*/

CVMX_SHARED uint64_t                hfa_isdevinit = 0;
extern CVMX_SHARED uint64_t         hfa_clust_init [HFA_MAX_NCLUSTERS];
extern CVMX_SHARED uint64_t         hfa_isclustinit_byapi [HFA_MAX_NCLUSTERS];
CVMX_SHARED void*                   global_hfamem_nbptr= NULL; 
CVMX_SHARED char                    hfa_pp_ver[50];
CVMX_SHARED uint32_t                hfapools_controlled_byapp = HFA_FALSE;

/**Variable defining Valid Targets for OCTENII HFA*/
CVMX_SHARED char                    *octeon_hfa_targetname[] = {
                                    "Target(0x0)",
                                    "Target(0x1)",
                                    "Target(0x2)",
        [OCTEON_HFA_63XX_TARGET] =  "cn63xx",               
                                    "Target(0x4)",
        [OCTEON_HFA_68XX_TARGET] =  "cn68xx",                                   
        [OCTEON_HFA_61XX_TARGET] =  "cn61xx",                                 
        [OCTEON_HFA_66XX_TARGET] =  "cn66xx",
                                    "Target(0x8)",
        [OCTEON_HFA_70XX_TARGET] =  "cn70xx"
};
/** @endcond */
/** Error code set by HFA SDK API */
uint64_t                            hfa_ecode;

/**
 * @cond INTERNAL
 * Sets device pointer in unit
 *
 * @param   pdevice         Pointer to device
 * @param   punit           Pointer to unit
 * @return  Void
 */
static inline void
hfa_unit_set_pdev(hfa_dev_t *pdevice, hfa_unit_t *punit)
{
    HFA_SET(punit, s, pdev, (void *) pdevice);
}
/**
 * Initializes Cache Load Lock
 *
 * @param   punit           Pointer to unit
 * @return  Void
 */
static inline void
hfa_unit_init_cloadlock(hfa_unit_t *punit)
{
    hfa_os_rwlockinit(&(punit->s.cload_lock));
}
/**
 * Get Device Name
 *
 * @param   name         String Pointer
 * @return  Void
 */
static inline
void hfa_get_devname(char *name)
{
    switch (OCTEON_HFA_CHIP()){
        case OCTEON_HFA_CN63XX_CID:
            memcpy(name, "cn63xx", strlen("cn63xx"));
        break;

        case OCTEON_HFA_CN68XX_CID:
            memcpy(name, "cn68xx", strlen("cn68xx"));
        break;

        case OCTEON_HFA_CN66XX_CID:
            memcpy(name, "cn66xx", strlen("cn66xx"));
        break;
        case OCTEON_HFA_CN61XX_CID:
            memcpy(name, "cn61xx", strlen("cn61xx"));
        break;
        case OCTEON_HFA_CN70XX_CID:
            memcpy(name, "cn70xx", strlen("cn70xx"));
        break;

        default:
            memcpy(name, "invalid_dev", strlen("invalid_dev"));
    }
}
/**
 * Basis on processor ID returns whether target has HFAmemory
 *
 * @return  1 if present, 0 othertwise
 */
static inline hfa_bool_t 
hfa_ishwmemory(void)
{
    switch(OCTEON_HFA_CHIP()){
/* In simulator mem portion for 63 and 66 is allocated locally */
#ifndef HFA_SIM
        case OCTEON_HFA_CN63XX_CID:
        case OCTEON_HFA_CN66XX_CID:
            return(HFA_TRUE);
        break;
#endif
        default:
            return(HFA_FALSE);
    }
}
/* In simulator mem portion of graph is dynamically allocated 
 * irrespective of board */
#ifndef HFA_SIM
/**
 * Get Configured Memory attributes (addr, size)
 *
 * @param   pdevinfo        Pointer to device Info
 * @return  Void
 */
static inline
void hfa_get_meminfo(hfa_devinfo_t *pdevinfo)
{
    cvmx_dfm_config_t dfm_config;

    if(pdevinfo->hwhasownmem){
        dfm_config.u64 = cvmx_read_csr(CVMX_DFM_CONFIG);
        pdevinfo->minfo.size = ((1ull << (dfm_config.s.pbank_lsb+ 25)));
        pdevinfo->minfo.addr  = 0; 
    } else {
        pdevinfo->minfo.size  = 0; 
        pdevinfo->minfo.addr  = 0; 
    }
}
#endif
/**
 * Get Configured Cache Attributes(addr, Size)
 *
 * @param   pdevinfo        Pointer to Device Info
 * @return  Void
 */
static inline
void hfa_get_cacheinfo(hfa_devinfo_t *pdevinfo)
{
    pdevinfo->cinfo[0].addr = 0;
    if (OCTEON_HFA_ISCHIP(OCTEON_HFA_CN61XX_CID) || 
        OCTEON_HFA_ISCHIP(OCTEON_HFA_CN70XX_CID)) {
        pdevinfo->cinfo[0].size = 4096;     /*4KB*/
    } else {
        pdevinfo->cinfo[0].size = 16384;    /*16KB*/
    }
    pdevinfo->cinfo[1].addr = 0;
    pdevinfo->cinfo[1].size = 512;          /*512 bytes*/
    pdevinfo->cinfo[2].addr = 0;
    pdevinfo->cinfo[2].size = 4096;
}
/**\endcond*/

/**
 * Create FPA pools for HFA
 * This is a utility routine which applications can use to intialize an FPA
 * pool. hfa_dev_init() uses this routine to setup pools needed for HFA SDK.
 *
 * @param   pool            Pool Number
 * @param   name            Pool Name
 * @param   block_size      Size of each block
 * @param   num_blocks      Number of blocks
 * @param   free_mask       Free Mask Flag
 */
hfa_return_t
hfa_create_fpa_pool (hfa_size_t pool, const char *name, hfa_size_t block_size, 
                     hfa_size_t num_blocks, int *free_mask)
{
    const char    *reswarn = "Error! resources are not freed!\n";
#ifdef KERNEL    
    int           ret;
#else    
    void          *p;
#endif    
    hfa_size_t    nbuffers=0;

/* no need of FPA pools in simulator */
#ifndef HFA_SIM
    if ((nbuffers = cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (pool)))){
        hfa_dbg("Warning!! \nFPA Pool- %lu (%s) already initialized and " \
                      "having %lu buffers\n", pool, name, nbuffers);
    } else {
#else
           {
#endif
#ifdef KERNEL
        if ((ret = hfa_oct_fill_hw_memory(pool, block_size, num_blocks)) 
                                                         != num_blocks) {
            hfa_oct_free_hw_memory(pool, block_size, ret);
            hfa_err(CVM_HFA_ENOMEM, ("unable to allocate FPA Pool %lu (%s) "\
                 "with %lu buffers. Size: %luMB\n", pool, name, num_blocks, 
                 ((block_size * num_blocks) >> 20)));
            hfa_log (reswarn);
            return HFA_FAILURE;
        }
        *free_mask |= (1 << pool);
#else        
        p = hfa_bootmem_alloc ((long) block_size * (long) num_blocks, block_size);
        if (p == NULL) {
            hfa_err(CVM_HFA_ENOMEM, ("unable to allocate FPA Pool %lu (%s) "\
                 "with %lu buffers. Size: %luMB\n", pool, name, num_blocks, 
                 ((block_size * num_blocks) >> 20)));
            hfa_log(reswarn);
            return HFA_FAILURE;
        }
        /* Increment the memory counter of bootmemory to the allocated size */
#ifdef HFA_STATS
        if(hfa_stats) {
            hfa_core_mem_stats_inc(bootmem, 
                (long) block_size * (long) num_blocks);
        }
#endif
        cvmx_fpa_setup_pool (pool, name, p, block_size, num_blocks);
#endif
        hfa_log("FPA Pool %lu (%s) created with %lu buffers. Size: %luMB\n",
             pool, name, num_blocks, ((block_size * num_blocks) >> 20));
    }
    return HFA_SUCCESS;
}
/* no hardware tests and no named block scenario's in simulator */
#ifndef HFA_SIM
/**
 * @cond INTERNAL
 * Performs HFA Built-in Self Test
 * @param   Void
 * @return  1 if PASS, 0 otherwise
 */
static inline 
int hfa_bist (void)
{
    cvmx_dfa_bist0_t    b0;
    cvmx_dfa_bist1_t    b1;

    b0.u64 = cvmx_read64_uint32 (CVMX_DFA_BIST0);
    b1.u64 = cvmx_read_csr (CVMX_DFA_BIST1);
    if (b0.u64 != 0 || b1.u64 != 0) {
        hfa_log ("BIST0\n");
        if (OCTEON_IS_MODEL(OCTEON_CN68XX))
            hfa_log ("\tmrp:%d\n", b0.cn68xx.mrp);
        if (OCTEON_IS_MODEL(OCTEON_CN63XX) || OCTEON_IS_MODEL(OCTEON_CN66XX))
            hfa_log ("\tmwb:%d\n", b0.cn63xx.mwb);
        hfa_log ("\tgfb:%d\n", b0.s.gfb);
        hfa_log ("\tstx2:%d\n", b0.s.stx2);
        hfa_log ("\tstx1:%d\n", b0.s.stx1);
        hfa_log ("\tstx:%d\n", b0.s.stx);
        hfa_log ("\tdtx2:%d\n", b0.s.dtx2);
        hfa_log ("\tdtx1:%d\n", b0.s.dtx1);
        hfa_log ("\tdtx:%d\n", b0.s.dtx);
        hfa_log ("\trdf:%d\n", b0.s.rdf);
        hfa_log ("\tpdb:%d\n", b0.s.pdb);
        hfa_log ("BIST1\n");
        hfa_log ("\tdlc1ram:%d\n", b1.s.dlc1ram);
        hfa_log ("\tdlc0ram:%d\n", b1.s.dlc0ram);
        hfa_log ("\tdc2ram3:%d\n", b1.s.dc2ram3);
        hfa_log ("\tdc2ram2:%d\n", b1.s.dc2ram2);
        hfa_log ("\tdc2ram1:%d\n", b1.s.dc2ram1);
        hfa_log ("\tdc1ram3:%d\n", b1.s.dc1ram3);
        hfa_log ("\tdc1ram2:%d\n", b1.s.dc1ram2);
        hfa_log ("\tdc1ram1:%d\n", b1.s.dc1ram1);
        hfa_log ("\tram3:%d\n", b1.s.ram3);
        hfa_log ("\tram2:%d\n", b1.s.ram2);
        hfa_log ("\tram1:%d\n", b1.s.ram1);
        hfa_log ("\tcrq:%d\n", b1.s.crq);
        hfa_log ("\tgutv:%d\n", b1.s.gutv);
        hfa_log ("\tgutp:%d\n", b1.s.gutp);
        hfa_log ("\tncd:%d\n", b1.s.ncd);
        hfa_log ("\tgif:%d\n", b1.s.gif);
        hfa_log ("\tgib:%d\n", b1.s.gib);
        hfa_log ("\tgfu:%d\n", b1.s.gfu);
        hfa_log ("BIST failed\n");
        return 0;
    }
    return 1;
}

/**@endcond*/
/**
 * This is a utility routine to find or allocate a named block.
 * If @b name named block found, return named-block base address and size in
 * @b *ppnbase and @b *psize resp.
 * If not found then allocate named block of with settings (@b name, @b *psize,
 * @b align) and return based address in @b *ppnbase
 * This is a utility routine which applications can use to find/create a
 * named-block for further use within the application. It is used by HFA SDK as
 * part of hfa_dev_init() to setup arena-memory regions.
 * A named-block allocated using this routine should be freed using
 * hfa_free_named_block()
 *
 * @param           name        Name of the named block
 * @param[out]      ppnbase     Address of Pointer to base addr
 * @param[in,out]   psize       Pointer to the size of named block
 * @param           align       alignment of base_Addr
 *
 * @return HFA_SUCCESS if @b ppnbase is set, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_find_named_block(const char *name, void **ppnbase, 
                     hfa_size_t *psize, uint64_t align)
{
    const cvmx_bootmem_named_block_desc_t *block_desc = NULL;
    hfa_size_t        size = 0;
    
    if(ppnbase && psize && name) {
        block_desc = hfa_bootmem_find_named_block(name);
        size = *psize;
        if(NULL == block_desc){
            hfa_dbg("Allocating nb: %s of size: %lu MB\n", name, size>>20);
            if(!(size)){
                hfa_err(CVM_HFA_ENOPERM, 
                ("Nb %s of size 0 can't be allocated\n", name));
                return HFA_FAILURE;
            }
            if(NULL == (*ppnbase = 
                        hfa_bootmem_alloc_named(size, align, name))){
                hfa_err(CVM_HFA_ENOMEM,("Unable to create named block: %s"\
                            " of size (%luMB)\n", name, ((size)/(1 << 20))));
                return HFA_FAILURE;
            }
        } else {
            if(!block_desc->size) {
                hfa_err(CVM_HFA_ENOPERM, ("Nb %s of size 0 found\n", name));
                return HFA_FAILURE;
            }
            /* Dynamically Creating a named block, Usefull for SEUM mode */
            if(size && (size != block_desc->size)) {
                /* Frees existing named block and creates a named block 
                 * with requested size */
                hfa_free_named_block(name);   
                if(NULL == (*ppnbase = 
                            hfa_bootmem_alloc_named(size, align, name))){
                    hfa_err(CVM_HFA_ENOMEM,("Unable to create named block: %s"\
                                " of size (%luMB)\n", name, ((size)/(1 << 20))));
                    return HFA_FAILURE;
                }
            } else {
                *ppnbase = cvmx_phys_to_ptr(block_desc->base_addr);
                *psize = block_desc->size;
                hfa_dbg("Found nb: %s of size: %lu MB\n", name, (*psize)>>20);
            }
       }
#ifdef HFA_STRICT_CHECK
        if (_HFA_ISMEM_NOTALIGNED(cvmx_ptr_to_phys(*ppnbase), align)){
            hfa_bootmem_free_named(name);
            hfa_err(CVM_HFA_EALIGNMENT, 
                    ("Nb %s base addr %p is unaligned\n", name, *ppnbase));
            return HFA_FAILURE;
        }
#endif
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Free the named block allocated using hfa_find_named_block(). This is a
 * utility routine which complements the hfa_find_named_block() routine.
 *
 * @param   name        Name of named block
 * @return HFA_SUCCESS if nb is freed or not found, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_free_named_block(const char *name)
{
    const cvmx_bootmem_named_block_desc_t *block_desc = NULL;
    int                                    status =0;
    
    block_desc = hfa_bootmem_find_named_block(name);

    if(block_desc){
        status = hfa_bootmem_free_named(name);
        hfa_dbg("status = %d\n",status);
        if (!status){
            hfa_err(CVM_HFA_EGEN, ("Unable to free nb %s\n", name));
            return HFA_FAILURE;
        }
    }
    return HFA_SUCCESS;
}
#endif
/**
 *  API to set PP resource allocator for partial matches. 
 *  hfa_dev_set_fnp_ppfree() and hfa_dev_set_fnp_ppsize() should be used to
 *  configure routines for partial match memory deallocator and size. This
 *  routine should be called after hfa_dev_init(), but preferrably before
 *  calling any other HFA SDK API. It is an optional API to customize HFA SDK
 *  behaviour.
 *  See hfa_defaultfn_ppalloc() for additional details.
 *
 *  @param  alloc   Function pointer for pp alloc
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_ppalloc (hfa_fnp_ppalloc_cb_t alloc)
{
    if(alloc){
        hfa_os_ppbuf_alloc =alloc;
        return (0);
    }
    return (-1);
}
/**
 *  API to set PP resource deallocator for partial matches.
 *  See hfa_dev_set_fnp_ppalloc() and hfa_defaultfn_ppfree() for more details.
 *
 *  @param  free   Function pointer for pp free
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_ppfree (hfa_fnp_ppfree_cb_t free)
{
    if(free){
        hfa_os_ppbuf_free =free;
        return (0);
    }
    return (-1);
}
/**
 *  API to set PP buffer size function pointer.
 *  See hfa_dev_set_fnp_ppalloc() and hfa_defaultfn_ppsize() for more details.
 *
 *  @param  size   Function pointer for ppbuf size
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_ppsize (hfa_fnp_ppsize_cb_t size)
{
    if(size){
        hfa_os_ppbuf_size =size;
        return (0);
    }
    return (-1);
}
/**
 *  API to set PP resource allocator for temporary memory.
 *  hfa_dev_set_fnp_pptfree() and hfa_dev_set_fnp_pptsize() should be used
 *  to configure routines for temporary memory deallocator and size.  This
 *  routine should be called after hfa_dev_init(), but preferrably before
 *  calling any other HFA SDK API. It is an optional API to customize HFA SDK
 *  behaviour.
 *  See hfa_defaultfn_ppalloc() for additional details.
 *
 *  @param  alloc   Function pointer for pp talloc
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_pptalloc (hfa_fnp_ppalloc_cb_t alloc)
{
    if(alloc){
        hfa_os_ppbuf_talloc =alloc;
        return (0);
    }
    return (-1);
}
/**
 *  API to set PP resource deallocator for temporary memory.
 *  See hfa_dev_set_fnp_pptalloc() and hfa_defaultfn_ppfree() for more details.
 *
 *  @param  free   Function pointer for pp tfree
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_pptfree (hfa_fnp_ppfree_cb_t free)
{
    if(free){
        hfa_os_ppbuf_tfree =free;
        return (0);
    }
    return (-1);
}
/**
 *  API to set temporary memory size function pointer.
 *  See hfa_dev_set_fnp_pptalloc() and hfa_defaultfn_ppsize() for more details.
 *
 *  @param  size   Function pointer for ppbuf tsize
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_pptsize (hfa_fnp_ppsize_cb_t size)
{
    if(size){
        hfa_os_ppbuf_tsize =size;
        return (0);
    }
    return (-1);
}
/**
 *  API to set PP resource allocator for match/result buffer.
 *  hfa_dev_set_fnp_ppmatchfree() and hfa_dev_set_fnp_ppmatchsize() should be
 *  used to configure routines for match-buffer memory deallocator and size.
 *  This routine should be called after hfa_dev_init(), but preferrably before
 *  calling any other HFA SDK API. It is an optional API to customize HFA SDK
 *  behaviour.
 *  See hfa_defaultfn_ppalloc() for additional details.
 *
 *  @param  alloc   Function pointer for pp matchalloc
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_ppmatchalloc (hfa_fnp_ppalloc_cb_t alloc)
{
    if(alloc){
        hfa_os_ppbuf_matchalloc =alloc;
        return (0);
    }
    return (-1);
}
/**
 *  API to set PP resource deallocator for result/match buf.
 *  See hfa_dev_set_fnp_ppmatchalloc() and hfa_defaultfn_ppfree() for more
 *  details.
 *
 *  @param  free   Function pointer for pp matchfree
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_ppmatchfree (hfa_fnp_ppfree_cb_t free)
{
    if(free){
        hfa_os_ppbuf_matchfree =free;
        return (0);
    }
    return (-1);
}
/**
 *  API to set match buffer size function pointer.
 *  See hfa_dev_set_fnp_ppmatchalloc() and hfa_defaultfn_ppsize() for more
 *  details.
 *
 *  @param  size   Function pointer for ppbuf matchsize
 *  @return -1 if assignment fails, 0 for success
 */
int
hfa_dev_set_fnp_ppmatchsize (hfa_fnp_ppsize_cb_t size)
{
    if(size){
        hfa_os_ppbuf_matchsize =size;
        return (0);
    }
    return (-1);
}
/**
 * API to set PP error callback.
 * This routine is used to register a callback which will be invoked when the
 * post-processing library encounters errors. This is an optional routine which
 * application can use. The HFA SDK registers a default callback
 * hfa_defaultfn_pperr(). Application should call it after hfa_dev_init() and
 * preferrably before calling any other HFA SDK API.
 * 
 * @param   cb  Function to handle the error.
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 *
 */
hfa_return_t
hfa_dev_set_fnp_pperror(hfa_fnp_pperr_cb_t cb)
{
    if(cb){
        hfa_os_pperr = cb;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}

/**
 * Default function pointer for PP errors.
 * This routine is of type @ref hfa_fnp_pperr_cb_t. HFA SDK registers it as
 * the default error callback routine for PP. It prints an informative error
 * message and suspends execution.
 * See also hfa_dev_set_fnp_pperror().
 *
 * This is not an HFA SDK API routine. It cannot be called by the application.
 *
 * @param   ecode   PP error codes defined in pp.h
 * @param   uarg    uarg per searchctx passed in ppstate
 *
 * @return void
 */
static inline void 
hfa_defaultfn_pperr(uint32_t ecode, void * uarg)
{
    if(ecode > HFA_PPERROR_COUNT)
        ecode = 0;
    hfa_err(CVM_HFA_EPPASSERT, ("PP error : %s\n", hfa_err_messages[ecode]));
    assert(0);
}

/**
 * Default function pointer for PP allocations.
 * This routine is of type @ref hfa_fnp_ppalloc_cb_t.
 *
 * Whenever pp library requires memory it calls following function pointers 
 * 1) For partial memory:                   (*hfa_os_ppbuf_alloc)(uarg)
 * 2) For temporary memory:                 (*hfa_os_ppbuf_talloc)(uarg)
 * 3) For match buffer (if matchcb not used):(*hfa_os_ppbuf_matchalloc)(uarg)
 *
 * The HFA SDK uses this routine as the default allocator for the above needs.
 * This is registered as the default as part of hfa_dev_init(). The default
 * routine ignores @b uarg argument.
 *
 * The default behavior for above three pp allocations can be optionally
 * overridden using the following routines to configure user-defined allocator
 * routines.
 *
 *  - hfa_dev_set_fnp_ppalloc()
 *  - hfa_dev_set_fnp_pptalloc()
 *  - hfa_dev_set_fnp_ppmatchalloc()
 *
 * The memory returned by the user-defined allocator must be
 * CVMX_CACHE_LINE_SIZE aligned. 
 * The @b uarg is a user-defined argument, which can be used to further
 * customize the behaviour at run-time. However, the user-defined allocator must
 * return valid memory for the case when uarg == NULL. Application can set uarg
 * argument using hfa_searchctx_setppuarg(). If not set uarg will be NULL.
 *
 * The PP library uses fixed-size buffers for its memory requirements. So the
 * allocator must return fixed-size buffers. See hfa_defaultfn_ppfree() and
 * hfa_defaultfn_ppsize() on how PP queries for the size of these buffers when
 * using them and how PP deallocates the buffers after using them.
 *
 * This is not an HFA SDK API routine. It cannot be called by the application.
 *
 * @param  uarg   user-defined by argument or NULL.
 *
 * @return pointer to allocated memory
 */
static inline 
void * hfa_defaultfn_ppalloc(void *uarg)
{
    void *ptr = NULL;

    ptr = cvmx_fpa_alloc(hfa_ppbuf_pool);
#ifdef HFA_STATS
    if(ptr && hfa_stats) {
        hfa_core_mem_stats_inc(ppbuf, 1);
#ifdef HFA_CTX_STATS 
        if(uarg && ((hfa_searchctx_t *)uarg)->ppalloc_magicno == 
                                    HFA_STATS_PPALLOC_MAGICNO) {
            hfa_searchctx_mem_stats_inc((hfa_searchctx_t *)uarg, ppbuf, 1);
        }
#endif
    }
#endif
    return (ptr);
}
/**
 * Default function pointer for PP deallocations.
 * This routine is of type @ref hfa_fnp_ppfree_cb_t.
 *
 * pp library frees allocated memory using following function pointers 
 * uarg as an argument.  
 * 1) For partial memory:                   (*hfa_os_ppbuf_free)(uarg)
 * 2) For temporary memory:                 (*hfa_os_ppbuf_tfree)(uarg)
 * 3) For match buffer (if matchcb not used):(*hfa_os_ppbuf_matchfree)(uarg)
 *
 * The HFA SDK uses this routine as the default deallocator for the above needs.
 * This is registered as the default as part of hfa_dev_init(). The default
 * routine ignores @b uarg argument.
 *
 * The default behavior for above three pp deallocations can be optionally
 * overridden using the following routines to configure user-defined allocator
 * routines.
 *
 *  - hfa_dev_set_fnp_ppfree()
 *  - hfa_dev_set_fnp_pptfree()
 *  - hfa_dev_set_fnp_ppmatchfree()
 *
 * This is not an HFA SDK API routine. It cannot be called by the application.
 *
 * @param  ptr    pointer to memory to be freed.
 * @param  uarg   user-defined by argument or NULL. See hfa_defaultfn_ppalloc()
 *                for more details.
 *
 * @return void
 */
static inline 
void hfa_defaultfn_ppfree(void *ptr, void *uarg)
{
#ifdef HFA_STATS
    if(hfa_stats){
        hfa_core_mem_stats_dec(ppbuf, 1);
#ifdef HFA_CTX_STATS
        if(uarg && ((hfa_searchctx_t *)uarg)->ppalloc_magicno == 
                                    HFA_STATS_PPALLOC_MAGICNO) {
            hfa_searchctx_mem_stats_dec((hfa_searchctx_t *)uarg, ppbuf, 1);
        }
#endif
    }
#endif
    cvmx_fpa_free(ptr, hfa_ppbuf_pool, 0);
}
/**
 * Default function pointer for PP size.
 * This routine is of type @ref hfa_fnp_ppfree_cb_t.
 *
 * pp library uses fixed-size buffers for its memory needs and it queries the
 * size of various types of memory resources using the following function
 * pointers.
 * 1) For partial memory:                   (*hfa_os_ppbuf_size)(uarg)
 * 2) For temporary memory:                 (*hfa_os_ppbuf_tsize)(uarg)
 * 3) For match buffer (if matchcb not used):(*hfa_os_ppbuf_matchsize)(uarg)
 *
 * The HFA SDK uses this routine as the default to obtain the size for the above
 * needs. This is registered as the default as part of hfa_dev_init(). The
 * default routine ignores @b uarg argument.
 *
 * The default behavior for above three pp deallocations can be optionally
 * overridden using the following routines to configure user-defined allocator
 * routines.
 *
 *  - hfa_dev_set_fnp_ppsize()
 *  - hfa_dev_set_fnp_pptsize()
 *  - hfa_dev_set_fnp_ppmatchsize()
 *
 * The size returned by the user-defined routine must be a constant(per-uarg)
 * which is a multiple of CVMX_CACHE_LINE_SIZE.
 *      
 * This is not an HFA SDK API routine. It cannot be called by the application.
 *
 * @param  uarg   user-defined by argument or NULL. See hfa_defaultfn_ppalloc()
 *                for more details.
 * @return uint64_t    Size of the buffer allocated.
 */
static inline 
uint64_t hfa_defaultfn_ppsize(void *uarg)
{
    return (OCTEON_PPBUFPOOL_SIZE);
}

/**@cond INTERNAL*/
/**
 * Setup memory and Initializes HFA hardware block
 *
 * @param pdev  Pointer to HFA device
 */
static inline 
hfa_return_t hfa_block_init (hfa_dev_t *pdev)
{
    int             free_mask = 0;
#ifndef KERNEL
    hfa_size_t        nbsize=0;                      
#endif        
  

    /* initialize the chip */
    if (!hfa_bist())
        return HFA_FAILURE;

    cvmx_fpa_enable ();

    hfa_ppbuf_pool = OCTEON_PPBUFPOOL;
    hfa_ppbuf_sz = OCTEON_PPBUFPOOL_SIZE;
    if(!hfapools_controlled_byapp){
        /*Setup pplibrary fpa variables*/ 
        hfa_ppbuf_cnt = OCTEON_PPBUFPOOL_COUNT; /*Redundant for KERNEL*/
#ifndef KERNEL
        hfa_tbuf_cnt = OCTEON_TBUFPOOL_COUNT;
        hfa_cmdbuf_cnt = OCTEON_HFAPOOL_COUNT;
#endif                
    }

    if (hfa_create_fpa_pool (OCTEON_TBUFPOOL, "temp buffers", 
                             OCTEON_TBUFPOOL_SIZE, hfa_tbuf_cnt, 
                             &free_mask)) {
        hfa_err(CVM_HFA_ENOMEM, ("Unable to create TBUFPOOL\n"));
        return HFA_FAILURE;
    }
    if (hfa_create_fpa_pool (OCTEON_HFAPOOL, "HFA cmd buffers", 
                             OCTEON_HFAPOOL_SIZE, hfa_cmdbuf_cnt,  
                             &free_mask)) {
        hfa_err(CVM_HFA_ENOMEM, ("Unable to create HFAPOOL\n"));
        return HFA_FAILURE;
    }
#if (OCTEON_HFAPOOL != OCTEON_PPBUFPOOL)        
    if (hfa_create_fpa_pool (hfa_ppbuf_pool, "Match buffers", hfa_ppbuf_sz, 
                             hfa_ppbuf_cnt, &free_mask)) {
        hfa_err(CVM_HFA_ENOMEM, ("Unable to create PPBUFPOOL\n"));
        return HFA_FAILURE;
    }
#endif
    
/* no arena concept in simulator */
#if !(defined KERNEL) && !(defined HFA_SIM)
    nbsize = OCTEON_HFA_ARENA_SIZE;
    hfa_dbg("nbsize: %lu\n", nbsize);
    if(HFA_SUCCESS != hfa_find_named_block(HFA_ARENA_NB, &global_arena,
                                           &nbsize, 0x10000)){
        return HFA_FAILURE;
    }
    hfa_dbg("global_arena =%p, sz: %lu\n",global_arena, nbsize);
    if (cvmx_add_arena(&hfa_arena, global_arena, nbsize) < 0) {
        hfa_err(CVM_HFA_EDEVINIT, ("Unable to add memory to HFA ARENA\n"));
        return HFA_FAILURE;
    }
    /* threadsafe cvmx_malloc spin lock initialization */
    cvmx_spinlock_init(&cvmx_malloc_lock);
#endif
    /*Initialize HFA HW*/
#ifndef HFA_SIM 
    if (cvmx_hfa_initialize ()) {
#else
    /*Initialize HFA simulator*/
    if (sim_hfa_initialize ()) {
#endif
        hfa_err (CVM_HFA_EDEVINIT, ("Unable to initialize HFA block\n"));
        return HFA_FAILURE;
    }
    hfa_os_sync();
    return HFA_SUCCESS;
}
/**
 * Cleanup HFA hardware block
 *
 * @param   pdev        Pointer to HFA Device
 * @return  HFA_FAILURE  
 *          HFA_SUCCESS
 */
static inline
hfa_return_t hfa_block_cleanup(hfa_dev_t *pdev)
{
    hfa_return_t    retval = HFA_SUCCESS;
/* no arena concept in simulator */
#if !(defined KERNEL) && !(defined HFA_SIM)
    if(hfa_os_likely(pdev)){
        memset(&hfa_arena, 0, sizeof(cvmx_arena_list_t));
    } else {
        hfa_err(CVM_HFA_EINVALARG, ("Null pdev rcvd\n"));
        retval = HFA_FAILURE;
    }
#endif    
#ifndef HFA_SIM   
    if(cvmx_hfa_shutdown()) {
#else
    /* simulate HFA shutdown */
    free(global_hfamem_nbptr);
    if(sim_hfa_shutdown()) {
#endif    
        hfa_err(CVM_HFA_EFAULT, ("cvmx_hfa_shutdown failed\n"));
        retval = HFA_FAILURE;
    }

    hfa_os_sync();
    return retval;
}
/**
 * Each HFA device has one or more Unit
 * Each Unit has one or more clusters
 * This function initializes unit which in turn 
 * initializes clusters
 *
 * @param   pdev    Pointer to HFA Device
 * @return  HFA_SUCCESS 
 *          HFA_FAILURE
 */
static inline 
hfa_return_t hfa_unit_init(hfa_dev_t *pdev)
{
    int             cnt;
    hfa_unit_t      *punit = NULL;
    hfa_addr_t      memaddr=0;
    hfa_size_t      memsize=0;

#ifdef KERNEL    
    memsize = OCTEON_HFA_MEMORY_SIZE;
#endif    
    
    /*Allocate buffer for unit pointer*/
    punit = hfa_os_malloc(sizeof(hfa_unit_t));
    if(hfa_os_unlikely(NULL == punit)){
        hfa_err(CVM_HFA_EUNITINIT, ("Failure in allocating hfa_unit_t\n"));
        return HFA_FAILURE;
    }
    memset(punit, 0, sizeof(hfa_unit_t));
    
    /*Link punit tp pdev*/
    pdev->punit = punit;

    /*Initialise punit members*/
    hfa_unit_set_pdev(pdev, punit);
    hfa_unit_init_cloadlock(punit);

    /*Initialise static variables maintaining cluster init*/
    for(cnt = 0; cnt< hfa_get_max_clusters(); cnt++){
        hfa_clust_init[cnt] = 0; 
        hfa_isclustinit_byapi[cnt]=0;
    }
    /*Initialise all clusters*/
    for(cnt = 0; cnt< hfa_dev_get_nclusters(pdev); cnt++){
        punit->pclust[cnt] = hfa_os_malloc(sizeof(hfa_cluster_t));
        if(hfa_os_likely(punit->pclust[cnt])){
            if(hfa_os_unlikely(HFA_SUCCESS != 
                    hfa_cluster_init(pdev, punit->pclust[cnt], cnt))){
                hfa_err(CVM_HFA_ECLUSTERINIT,
                        ("Cluster_Init Failed for clno [%u]\n", cnt));
                hfa_os_free(punit->pclust[cnt], sizeof(hfa_cluster_t));
                punit->pclust[cnt--] = NULL;
                goto cl_init_failure;
            } else {
                /*If cluster 0 then allocate HFA_MEMORY otherwise
                 * share mem*/
                if(cnt){
                    hfa_cluster_share_mem(punit->pclust[0], punit->pclust[cnt]);
                } else {
                    if(hfa_dev_haspvt_hfamemory(pdev)){
                        memaddr = hfa_dev_get_memaddr(pdev);
                        memsize = hfa_dev_get_memsize(pdev);
                    } else {
                        /* For kernel memsize = hfa_mem_sz << 20
                         * in SE memsize = OCTEON_HFA_MEMORY_SIZE << 20
                         * */
                        memsize = (((unsigned long long)
                                   (OCTEON_HFA_MEMORY_SIZE)) << 20);

                        if(HFA_SUCCESS != hfa_find_named_block(hfa_mem_nb_name, 
                                          &global_hfamem_nbptr, &memsize, 
                                          hfa_get_mem_align())){
                            return HFA_FAILURE;
                        }
                        memaddr = cvmx_ptr_to_phys(global_hfamem_nbptr);
                        hfa_dbg("memaddr: %p, memsize = %lu\n",memaddr,memsize);
                    }
                    if(HFA_SUCCESS != hfa_cluster_setmem(punit->pclust[cnt],
                                                      memaddr, memsize)){
                        hfa_err(CVM_HFA_EDEVINIT, ("cluster_setmem error\n"));
                        return HFA_FAILURE;
                    }
                }
                hfa_isclustinit_byapi[cnt] = HFA_CLUSTER_INIT_BYAPI; 
            }
        }else {
            hfa_err(CVM_HFA_EUNITINIT, 
                    ("Failed allocation cluster no(%d)", cnt));
            cnt--;
            goto cl_init_failure;
        }
    }
    return(HFA_SUCCESS);

cl_init_failure:
    for(;cnt>=0;cnt--){
        hfa_cluster_cleanup(punit->pclust[cnt]);
    }
    return(HFA_FAILURE);
}
/**
 * Cleanup HFA unit which in turn also cleanup
 * involved clusters
 *
 * @param   pdev    Pointer to device
 * @return  HFA_SUCCESS if cleanup successful, HFA_FAILURE otherwise
 */
static inline 
hfa_return_t hfa_unit_cleanup(hfa_dev_t *pdev)
{
    uint32_t cnt;
    hfa_unit_t *punit = NULL;

    if(hfa_os_likely(pdev)){
        punit = pdev->punit;
         if(hfa_os_likely(punit)){
            for(cnt=0; cnt < hfa_dev_get_nclusters(pdev); cnt++){
                if(punit->pclust[cnt]){
                    hfa_cluster_cleanup(punit->pclust[cnt]);
                }
            }
            /*Free  Unit Pointer*/
            hfa_os_free(punit, sizeof(punit));
         }
        return(HFA_SUCCESS);
    }
    return (HFA_FAILURE);
}
/**@endcond*/
/**
 * Displays HFA Device info. 
 * This is a utility routine that application use to display HFA device
 * information obtained from hfa_dev_getdevinfo().
 *
 * @param pdinfo Pointer to hfa device info
 * @return void
 */
void hfa_dev_display_info(hfa_devinfo_t *pdinfo)
{
    int     cache=0;
    char    str[50];

    /*Print OCTEON MODEL VER, HFA SW VER*/
    if(pdinfo){
        pp_get_version_string_ex((char *)str, 50);
        hfa_log("\n%s\n", HFA_VERSION);
#ifdef HFA_SIM        
        hfa_log("Device %s Chip %u. Clusters: %d\n", 
                pdinfo->name,
                pdinfo->chipid, pdinfo->nclusters);
#else
        hfa_log("Device %s Chip %u. Clusters: %d\n", 
                hfa_octeon_model_get_string(pdinfo->chipid),
                pdinfo->chipid, pdinfo->nclusters);
#endif                
        hfa_log("PP Library Version: [%s]\n", str);
        hfa_log("HasMem: %s, Mbase: 0x%lx, MSize: %luMB\n",
                            ((pdinfo->hwhasownmem) ? "TRUE":"FALSE"), 
                             pdinfo->minfo.addr, ((pdinfo->minfo.size) >>20));
        for(cache=0; cache < HFA_MAX_CACHE_PER_CLUSTER; cache++){
            if(pdinfo->cinfo[cache].size){
                hfa_log("Cache%d: Base: 0x%lx, Size: %lu\n", cache,  
                    pdinfo->cinfo[cache].addr, pdinfo->cinfo[cache].size);
            }
        }
    }
#ifdef KERNEL  
    if (OCTEON_IS_MODEL(OCTEON_CN63XX_PASS1_X))
        hfa_log("\nWARNING: Pass1 chip does not support all graph sizes."\
                " Use a Pass2 chip instead !\n");    
#endif
}
/**
 * Provides device-specific information
 * This is a utility routine used to obtain HFA device-specific details.
 * hfa_dev_display_info() can used to print this information.
 *
 * @param   pdevinfo    Pointer to HFA Device Info
 * @return  void
 */
void
hfa_dev_getdevinfo(hfa_devinfo_t *pdevinfo)
{
    if(hfa_os_likely(pdevinfo)){
        pdevinfo->nclusters = hfa_get_max_clusters();
        pdevinfo->clmsk = hfa_get_max_clmsk();
        pdevinfo->chipid = cvmx_get_proc_id();
        pdevinfo->pass= (int)(((cvmx_get_proc_id())>>3)&7) +1;
        hfa_get_devname(pdevinfo->name);
        pdevinfo->hwhasownmem = hfa_ishwmemory();
        if(pdevinfo->hwhasownmem) 
            pdevinfo->mbasealignbits = 10;
        else 
            pdevinfo->mbasealignbits = 16;
        hfa_get_meminfo(pdevinfo);
        hfa_get_cacheinfo(pdevinfo);
    }
}
/**
 * This function must be called by application to initialize HFA engine
 * and setup resources for HFA hardware. It must be called by only one core. It
 * must be called before calling another HFA API.
 *
 * For cn61xx/cn68xx: hfa_dev_init() searches for uboot named block of name @ref
 * HFA_MEMORY_NB. If found, named block is assigned to and shared among all
 * available clusters. Otherwise a named block of that name will be allocated
 * wth size OCTEON_HFA_MEMORY_SIZE.
 *
 * Also, in case of SE/SEUM mode, hfa_dev_init() creates named block
 * of name @ref HFA_ARENA_NB and size OCTEON_HFA_ARENA_SIZE. This memory
 * arena is used as storage for various graph meta-data during the lifetime of a
 * graph. It is also used as temporary storage to hold the graph-data in the
 * form a gather list when downloading the graph.
 *
 * The corresponding cleanup routine is hfa_dev_cleanup()
 *
 * @param   pdev    Pointer to HFA Device
 * @return  HFA_SUCCESS, HFA_FAILURE
 */          
hfa_return_t hfa_dev_init (hfa_dev_t *pdev)
{
    char            pname[HFA_MAXNAMELEN];

    hfa_ecode =0;
    hfa_get_devname(pname);
    /*Check if HW supports HFA*/
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_is_supported())){
        hfa_err(CVM_HFA_ENOPERM, ("HFA not supported in %s\n", pname));
        return (HFA_FAILURE);
    }
    if (hfa_os_unlikely(NULL == pdev)) {
        hfa_err(CVM_HFA_EINVALARG, ("NULL input device pointer\n")); 
        return (HFA_FAILURE);
    }
    if(HFA_DEV_INITDONE != hfa_isdevinit){
#ifdef HFA_STATS        
        /* Initialize core statistics */
        if(HFA_FAILURE == hfa_dev_stats_init(pdev)) {
            hfa_log("hfa_dev_stats_init failed\n");
            return HFA_FAILURE;
        }
#endif
        /*Mark dev init as initialized to allow further initializations*/
        hfa_isdevinit = HFA_DEV_INITDONE;

        memset (pdev, 0, sizeof (hfa_dev_t));
        hfa_dev_getdevinfo (&(pdev->devinfo));

        /*Underlying OS dependent initialization */
        if (hfa_os_unlikely(HFA_SUCCESS != hfa_block_init(pdev))){ 
            hfa_log("ERROR: hfa_block_init failed \n"); 
            hfa_isdevinit = 0;
            return (HFA_FAILURE);
        }   
        pp_get_version_string((char *)hfa_pp_ver, 50);
        hfa_dev_display_info(&(pdev->devinfo));
        /*Allocate and init pdev->punit*/
        if(hfa_os_unlikely(HFA_SUCCESS != hfa_unit_init(pdev))){
            hfa_err(CVM_HFA_EUNITINIT, ("hfa_unit_init() failed\n"));
            hfa_block_cleanup(pdev);
            hfa_isdevinit = 0;
            return (HFA_FAILURE);
        }
        /*Initialize pp allocators*/
        hfa_dev_set_fnp_ppalloc(hfa_defaultfn_ppalloc);
        hfa_dev_set_fnp_ppfree(hfa_defaultfn_ppfree);
        hfa_dev_set_fnp_ppsize (hfa_defaultfn_ppsize);
        hfa_dev_set_fnp_pptalloc(hfa_defaultfn_ppalloc);
        hfa_dev_set_fnp_pptfree(hfa_defaultfn_ppfree);
        hfa_dev_set_fnp_pptsize (hfa_defaultfn_ppsize);
        hfa_dev_set_fnp_ppmatchalloc(hfa_defaultfn_ppalloc);
        hfa_dev_set_fnp_ppmatchfree(hfa_defaultfn_ppfree);
        hfa_dev_set_fnp_ppmatchsize (hfa_defaultfn_ppsize);

        hfa_dev_set_fnp_pperror(hfa_defaultfn_pperr);
        hfa_os_sync ();
        return (HFA_SUCCESS);
    } else {
        hfa_err(CVM_HFA_EDEVEXIST, ("%s() already done\n", __func__));
    }
    return(HFA_FAILURE);
}
/**
 * This function is called by application to cleanup all resources configured
 * for HFA device and then shutdown HFA engine. It undoes the effect of
 * hfa_dev_init(). No HFA API should be called after invoking this routine.
 *
 * @param   pdev    Pointer to HFA device
 * @return  HFA_SUCCESS
 *          HFA_FAILURE
 */
hfa_return_t hfa_dev_cleanup (hfa_dev_t *pdev)
{
    uint32_t retval=0; 
    
    hfa_dbg("pdev: %p\n", pdev);
    if(hfa_os_likely(pdev) && HFA_DEV_INITDONE == hfa_isdevinit){
        retval |= hfa_unit_cleanup (pdev); 
        retval |= hfa_block_cleanup (pdev);
        hfa_isdevinit = 0;

        hfa_os_sync();
#ifdef HFA_STATS
        hfa_dev_stats_cleanup(pdev);
        hfa_dev_stats_print(pdev);
#endif
        if(!retval){
            return(HFA_SUCCESS);
        }
    } else {
        hfa_err(CVM_HFA_ENOPERM, ("No Permission to allow dev cleanup\n"));
    }
    return(HFA_FAILURE);
}
/**
 * Asynchronous instruction submit to HFA hardware
 * Do not wait for instruction to complete. Queue the instruction to the HFA
 * engine queue and return immediately.
 * Use hfa_dev_getasyncstatus() to know the status of instruction       
 *
 * @param   pdev    Pointer to device which tries to submit instr
 * @param   pinstr  Pointer to HFA instr which has to be submitted
 * @return  Zero on success, negative on failure
 */
int hfa_dev_submitasync (hfa_dev_t *pdev, hfa_instr_t *pinstr)
{      
    int ret = 0;
#ifdef HFA_STATS
    int                 core = cvmx_get_core_num();
#ifdef HFA_EXTENDED_STATS    
    cvm_hfa_itype_t     itype;
    itype = pinstr->word0.itype;
#endif    
#endif

#ifndef HFA_SIM
    ret = cvmx_hfa_submit (pinstr);
#else
    /* simulate HFA submit */
    ret = sim_hfa_submit (pinstr);
#endif
#ifdef HFA_STATS    
    if(hfa_stats){
        if(ret == 0){
#ifdef HFA_EXTENDED_STATS
            switch(itype) {
                case CVMX_HFA_ITYPE_GRAPHWALK:
                   HFA_CORE_STATS_INC(gwalk.pending, core, 1);
                   break;
                case CVMX_HFA_ITYPE_MEMLOAD:
                   HFA_CORE_STATS_INC(mload.pending, core, 1);
                   break;
                case CVMX_HFA_ITYPE_CACHELOAD:
                   HFA_CORE_STATS_INC(cload.pending, core, 1);
                   break;
                case CVMX_HFA_ITYPE_GRAPHFREE:
                   HFA_CORE_STATS_INC(gfree.pending, core, 1);
                   break;
                default:
                    /* do nothing */
                   break;
            }
#endif
            HFA_CORE_STATS_INC(total.pending, core, 1);
        }
        else {
#ifdef HFA_EXTENDED_STATS
            switch(itype) {
                case CVMX_HFA_ITYPE_GRAPHWALK:
                    HFA_CORE_STATS_INC(gwalk.failed, core, 1);
                    break;
                case CVMX_HFA_ITYPE_MEMLOAD:
                    HFA_CORE_STATS_INC(mload.failed, core, 1);
                    break;
                case CVMX_HFA_ITYPE_CACHELOAD:
                    HFA_CORE_STATS_INC(cload.failed, core, 1);
                    break;
                case CVMX_HFA_ITYPE_GRAPHFREE:
                    HFA_CORE_STATS_INC(gfree.failed, core, 1);
                    break;
                default:
                    /* do nothing */
                    break;
            }
#endif
            HFA_CORE_STATS_INC(total.failed, core, 1);
        }
    }
#endif
    return ret;
}
/**
 * Obtain status of submitted insruction.
 *
 * @param   pdev    Pointer to HFA device
 * @param   rmdata  Result Meta Data
 * @return  CVM_HFA_EAGAIN if instruction is still pending in HFA engine queue.
 *          Otherwise one of the reason codes from RWORD0
 */           
int hfa_dev_getasyncstatus (hfa_dev_t *pdev, volatile hfa_rmdata_t *rmdata)
{
    uint32_t            reason;
    hfa_bool_t          done;

    cvm_hfa_rslt_getdone (rmdata, &done);
    if (done) { 
#ifdef HFA_STATS    
        int                 core;
#ifdef HFA_EXTENDED_STATS        
        cvm_hfa_itype_t     itype = -1;
        
        itype = rmdata->s.itype;
#endif        
        core =cvmx_get_core_num();
         
        if(hfa_stats){
#ifdef HFA_EXTENDED_STATS 
            switch(itype) {
                case CVMX_HFA_ITYPE_GRAPHWALK:
                    HFA_CORE_STATS_INC(gwalk.success, core, 1);
                    HFA_CORE_STATS_DEC(gwalk.pending, core, 1);
                    break;
                case CVMX_HFA_ITYPE_MEMLOAD:
                    HFA_CORE_STATS_INC(mload.success, core, 1);
                    HFA_CORE_STATS_DEC(mload.pending, core, 1);
                    break;
                case CVMX_HFA_ITYPE_CACHELOAD:
                    HFA_CORE_STATS_INC(cload.success, core, 1);
                    HFA_CORE_STATS_DEC(cload.pending, core, 1);
                    break;
                case CVMX_HFA_ITYPE_GRAPHFREE:
                    HFA_CORE_STATS_INC(gfree.success, core, 1);
                    HFA_CORE_STATS_DEC(gfree.pending, core, 1);
                    break;
                default:
                    /* do nothing */
                    break;
            }
#endif
            HFA_CORE_STATS_INC(total.success, core, 1);
            HFA_CORE_STATS_DEC(total.pending, core, 1);
        }
#endif
        cvm_hfa_rslt_getreason((cvm_hfa_rmdata_t *)rmdata, &reason);
        return reason;
    }
    return CVM_HFA_EAGAIN; 
}
/**
 * Synchronous instruction submit to HFA hardware
 * Block until submitted instruction completes.
 *
 * @param   pdev    Pointer to device which tries to submit instr
 * @param   pinstr  Pointer to HFA instr which has to be submitted
 * @return  Zero on success, negative on failure
 */
int hfa_dev_submit (hfa_dev_t *pdev, hfa_instr_t *pinstr)
{      
    int             ret = 0;
    hfa_rmdata_t    *rmdata = NULL;

    rmdata = (hfa_rmdata_t *) phys_to_ptr(pinstr->word1.rptr);

#ifndef HFA_SIM
    ret = cvmx_hfa_submit (pinstr);
#else
    /* simulate HFA submit */
    ret = sim_hfa_submit (pinstr);
#endif
    if (!ret) {
        do{
            ret = hfa_dev_getasyncstatus (pdev, rmdata);
          } while (ret == CVM_HFA_EAGAIN);
    }    
    return ret;
}
/**
 * This API allows application to control FPA pool counts at Runtime
 * This API is for non-kernel mode and should be called before hfa_dev_init()
 *
 * In Kernel mode application can control FPA pool counts (runtime) by using
 * HFA_LIB_MODULE command line options
 *
 * @param   cmdbufcnt  HFA command buffer pool count
 * @param   tbufcnt    HFA Temporary buffer count
 * @param   ppbufcnt   HFA PP buffer count
 *
 * @return  Zero
 */
hfa_return_t
hfa_set_fpapools_cnt(uint64_t cmdbufcnt, uint64_t tbufcnt, uint64_t ppbufcnt)
{
#ifdef KERNEL
    /*In KERNEL mode hfa_ppbuf_cnt, hfa_tbuf_cnt and hfa_cmdbuf_cnt are 
     * configurable by HFA_LIB_MODULE command line options using insmod
     */
    return HFA_FAILURE;
#else    
    hfa_tbuf_cnt = tbufcnt;
    hfa_cmdbuf_cnt = cmdbufcnt;
#if (OCTEON_HFAPOOL != OCTEON_PPBUFPOOL)
    hfa_ppbuf_cnt = ppbufcnt;    
#endif    
    hfapools_controlled_byapp = HFA_TRUE;
    return HFA_SUCCESS;
#endif    
}
/**@cond INTERNAL*/
#ifdef KERNEL
EXPORT_SYMBOL (hfa_ecode);
EXPORT_SYMBOL (hfa_dev_init);
EXPORT_SYMBOL (hfa_dev_cleanup);
EXPORT_SYMBOL (hfa_dev_getdevinfo);
EXPORT_SYMBOL (hfa_dev_submitasync);
EXPORT_SYMBOL (hfa_dev_submit);
EXPORT_SYMBOL (hfa_dev_getasyncstatus);
EXPORT_SYMBOL (hfa_dev_display_info);
EXPORT_SYMBOL (hfa_create_fpa_pool);
EXPORT_SYMBOL (hfa_dev_set_fnp_ppalloc);
EXPORT_SYMBOL (hfa_dev_set_fnp_ppfree);
EXPORT_SYMBOL (hfa_dev_set_fnp_ppsize);
EXPORT_SYMBOL (hfa_dev_set_fnp_pptalloc);
EXPORT_SYMBOL (hfa_dev_set_fnp_pptfree);
EXPORT_SYMBOL (hfa_dev_set_fnp_pptsize);
EXPORT_SYMBOL (hfa_dev_set_fnp_ppmatchalloc);
EXPORT_SYMBOL (hfa_dev_set_fnp_ppmatchfree);
EXPORT_SYMBOL (hfa_dev_set_fnp_ppmatchsize);
EXPORT_SYMBOL (hfa_dev_set_fnp_pperror);
EXPORT_SYMBOL (hfa_set_fpapools_cnt);
#endif
/**@endcond*/
