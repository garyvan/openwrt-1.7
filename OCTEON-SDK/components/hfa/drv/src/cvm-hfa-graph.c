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
 * This file contains graphs Init, download/load cleanup APIs
 * 
 */
#include "cvm-hfa-common.h"
#include "cvm-hfa-graph.h"
#include "cvm-hfa-stats.h"
#include "cvm-hfa-search.h"
#include "ppdfa.h"
/**@cond INTERNAL */
extern CVMX_SHARED char             *octeon_hfa_targetname[];

/**Customised memcpy for OCTEON2 chips where HFA memory is reserved from DDR */
#define memcopy(daddr, saddr, size)  do{        \
    memcpy(phys_to_ptr(daddr), saddr, size);    \
    hfa_os_sync();                              \
    hfa_l2c_flush ();                           \
}while(0)

/**Array used to know which bit is set from right in clmsk range [0..7]*/
int hfa_firstbit_setr [8] = {-1, 0, 1, 0, 2, 0, 1, 0};

/**Array used to know how many bits are set in clmsk range [0..7]*/
int hfa_noofbit_set [8] = {0, 1, 1, 2, 1, 2, 2, 3};

extern uint32_t  hfa_pclbuf_idx[HFA_MAX_NCLUSTERS][HFA_68XX_MAX_CLMSK +1];

/*Does OCTEON2 has HFA mem*/
static hfa_bool_t                      ishfamem;

/*Alignemt*/
static hfa_size_t               alignment;
extern CVMX_SHARED uint64_t     hfa_isdevinit;
extern CVMX_SHARED char         hfa_pp_ver[50];
/**@endcond*/

/**@cond INTERNAL*/
/**Static inline Function Declarations*/
static inline hfa_return_t 
hfa_mload_perm_denied_hndlr(hfa_graph_t *,uint8_t *,hfa_size_t , hfa_size_t *);

static inline hfa_return_t 
hfa_mload_firstchunk(hfa_graph_t *, uint8_t *, hfa_size_t , hfa_size_t *);

static inline hfa_return_t 
hfa_mload_designated_mem(hfa_graph_t *, uint8_t *, hfa_size_t , hfa_size_t *);

static inline hfa_return_t 
hfa_mload_ddr_mem(hfa_graph_t *, uint8_t *, hfa_size_t , hfa_size_t *);

static inline hfa_return_t 
hfa_mload_cache(hfa_graph_t *, uint8_t *, hfa_size_t , hfa_size_t *);

static inline hfa_return_t 
hfa_mload_readinfo(hfa_graph_t *, uint8_t *, hfa_size_t , hfa_size_t *);

static inline hfa_return_t 
hfa_mload_designated_mem_skiplen(hfa_graph_t *,uint8_t *,hfa_size_t,hfa_size_t*);

/**@endcond*/
/**
 * @cond INTERNAL
 * State machine used to load non-iovec chunks of graphs
 * Supports all OCTEON2 chipsets, 
 *
 * HFA_MEM_TYPE:            Whether OCTEON2 chip has HFA memory
 * HFA_MAX_GRAPHTYPE:       Memonly/Cacheonly/Linked Graph
 * HFA_MAX_GRAPHSTATES:      Various states of graph during graph download
 */ 
hfa_graphload_sm_tbl_t 
hfa_mload_sm [HFA_MEM_TYPE][HFA_MAX_GRAPHTYPE][HFA_MAX_GRAPHSTATES] = 
{
    /**Chip without HFA MEMORY CN68XX/CN61XX*/
    {
        /*memonly graph */
        {
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_INITIAL},
            {hfa_mload_firstchunk, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CACHE_LOADING},
            {hfa_mload_ddr_mem, HFA_GRAPH_INFO_READING},
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_MEM_SKIPLEN},
            {hfa_mload_readinfo, HFA_GRAPHLOAD_FINISH},        
            {hfa_mload_perm_denied_hndlr, HFA_GRAPHLOAD_FINISH}, 
            {hfa_mload_perm_denied_hndlr, HFA_GRAPHLOAD_FINISH} 
        },
        /*MIX Graph having both Mem and Cache portion*/
        {
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_INITIAL},
            {hfa_mload_firstchunk, HFA_GRAPH_CACHE_LOADING},
            {hfa_mload_cache, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_ddr_mem, HFA_GRAPH_INFO_READING},
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_MEM_SKIPLEN},
            {hfa_mload_readinfo, HFA_GRAPH_CLOAD_PENDING},        
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}, 
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}        
        },
        /*Link graph*/
        {
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_INITIAL},
            {hfa_mload_firstchunk, HFA_GRAPH_CACHE_LOADING},
            {hfa_mload_cache, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_ddr_mem, HFA_GRAPH_INFO_READING},
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_MEM_SKIPLEN},
            {hfa_mload_readinfo, HFA_GRAPH_CLOAD_PENDING},        
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}, 
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}  
        }       
    },
    /*CHIP with HFA_MEMORY CN63XX/CN66XX*/
    {
        /*memonly graph */
        {
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_INITIAL},
            {hfa_mload_firstchunk, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_designated_mem, HFA_GRAPH_MEM_SKIPLEN},
            {hfa_mload_designated_mem_skiplen, HFA_GRAPH_INFO_READING},
            {hfa_mload_readinfo, HFA_GRAPHLOAD_FINISH},        
            {hfa_mload_perm_denied_hndlr, HFA_GRAPHLOAD_FINISH}, 
            {hfa_mload_perm_denied_hndlr, HFA_GRAPHLOAD_FINISH}        
        },
        /*MIX Graph having both Mem and Cache portion*/
        {
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_INITIAL},
            {hfa_mload_firstchunk, HFA_GRAPH_CACHE_LOADING},
            {hfa_mload_cache, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_designated_mem, HFA_GRAPH_MEM_SKIPLEN},
            {hfa_mload_designated_mem_skiplen, HFA_GRAPH_INFO_READING},
            {hfa_mload_readinfo, HFA_GRAPH_CLOAD_PENDING},        
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}, 
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}  
        },
        /*Link graph*/
        {
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_INITIAL},
            {hfa_mload_firstchunk, HFA_GRAPH_CACHE_LOADING},
            {hfa_mload_cache, HFA_GRAPH_MEM_LOADING},
            {hfa_mload_designated_mem, HFA_GRAPH_MEM_SKIPLEN},
            {hfa_mload_designated_mem_skiplen, HFA_GRAPH_INFO_READING},
            {hfa_mload_readinfo, HFA_GRAPH_CLOAD_PENDING},        
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}, 
            {hfa_mload_perm_denied_hndlr, HFA_GRAPH_CLOAD_PENDING}  
        }       
    }
};
/**@endcond*/
/**@cond INTERNAL*/
/**
 *  Swaps provided buffer
 *  @param  p       Pointer to the buffer
 *  @param  size    size of buffer
 */
static inline void 
eswap (void *p, uint64_t size) 
{ 
    uint64_t             *tu64; 
    int                  i; 
    
    tu64 = p; 
    size = (size + 7) >> 3; 
    hfa_dbg("eswap for size: %lu\n", size);
    for (i = 0; i < size; ++i) 
        tu64[i] = cvmx_swap64 (tu64[i]); 
}
static inline void 
hfa_display_graphattr(hfa_graphattr_t *pattr, char *version, int size)
{
    if(hfa_os_likely(pattr)){
        hfa_log("[");
        hfa_tools_version_to_string(&(pattr->version),version,size);
        hfa_log("Version: %s", version);
        if(pattr->target < OCTEON_HFA_MAX_TARGETS){
            hfa_log(", %s", octeon_hfa_targetname[pattr->target]);
        }else {
            hfa_log(", Target(0x%x)", pattr->target);
        }
        if(pattr->rc)
            hfa_log(", RC");
        if(pattr->sc)
            hfa_log(", SC");
        if(pattr->strings)
            hfa_log(", Strings");
        if(pattr->dfa)
            hfa_log(", DFA");
        if(pattr->memonly)
            hfa_log(", Memonly");
        if(pattr->linkable)
            hfa_log(", Linkable");
        if(pattr->linked)
            hfa_log(", Linked");
        if(pattr->submitall)
            hfa_log(", SubmitAll");
        if(pattr->dict)
            hfa_log(", Dict");
        if(pattr->compmulti)
            hfa_log(", CompMulti");
        if(pattr->rcprof)
            hfa_log(", RCProf");
        hfa_log(", Algo:0x%x", pattr->cachealgo);

        hfa_log("]\n");
    }
}
static inline hfa_return_t
hfa_mload_alloc_mbuf(hfa_graph_t *pgraph, hfa_graph_mbufptr_t **ppbuf)
{
    hfa_graph_mbufptr_t     *pbuf = NULL;
    if(hfa_os_likely(ppbuf)){
        *ppbuf = NULL;
        if(hfa_os_unlikely(NULL == (pbuf = 
            hfa_os_memoryalloc(sizeof(hfa_graph_mbufptr_t), 8)))){
            hfa_err(CVM_HFA_ENOMEM, ("hfa_graph_mbufptr_t alloc error\n"));
            return HFA_FAILURE;
        }
        memset(pbuf, 0, sizeof(hfa_graph_mbufptr_t));
        if(hfa_os_unlikely(NULL == (pbuf->ptr =
            hfa_os_memoryalloc(pgraph->mload_triggersz, 128)))){
            hfa_os_memoryfree(pbuf, sizeof(hfa_graph_mbufptr_t));
            hfa_err(CVM_HFA_ENOMEM, ("mbufptr->ptr  alloc error\n"));
            return HFA_FAILURE;
        }
        memset(pbuf->ptr, 0, pgraph->mload_triggersz);
        HFA_OS_LISTHEAD_INIT(&pbuf->list);
        pbuf->status = HFA_MLOAD_COPYING;
        pbuf->copypend = pgraph->mload_triggersz;
        *ppbuf = pbuf;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
static inline void
hfa_mload_destroy_mbuf(hfa_graph_t *pgraph, hfa_graph_mbufptr_t *pmbuf)
{
    if(hfa_os_likely(pgraph && pmbuf)){
        hfa_os_memoryfree(pmbuf->ptr, pgraph->mload_triggersz);
        hfa_os_memoryfree(pmbuf, sizeof(hfa_graph_mbufptr_t));
    }
}
static inline void
hfa_graph_mload_destroy_mbufs(hfa_graph_t *pgraph)
{
    hfa_os_listhead_t       *p1=NULL, *p2 = NULL;
    hfa_graph_mbufptr_t     *pmbuf = NULL;

    if(hfa_os_likely(pgraph)){
        if(!hfa_os_listempty(&pgraph->mload.list)){
            hfa_os_listforeachsafe(p1, p2, &pgraph->mload.list){
                pmbuf = hfa_os_listentry(p1, hfa_graph_mbufptr_t, list);
                hfa_os_listdel(&pmbuf->list);
                hfa_mload_destroy_mbuf(pgraph, pmbuf);
            }
        }
    }
}
/**
 *  Validates graph pointer and its state/status
 *
 *  @param      pgraph          Pointer to the graph
 *  @param      chkstate        if non-zero then graph state should be this
 *  @return     HFA_SUCCESS if validation passes, HFA_FAILURE otherwise   
 */
static inline hfa_return_t
hfa_graph_validate(hfa_graph_t *pgraph, uint32_t chkstate)
{
    if(hfa_os_unlikely (NULL == pgraph)){
        hfa_err(CVM_HFA_EINVALARG, ("pgraph is NULL\n"));
        return HFA_FAILURE;
    }
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely (HFA_DEV_INITDONE != hfa_isdevinit)){
        hfa_err(CVM_HFA_EDEVINITPEND,("hfa_dev_init() not performed\n"));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (NULL == pgraph->pdev)){
        hfa_err(CVM_HFA_EINVALARG,("pdev in pgraph: %p found NULL\n", pgraph));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (HFA_GRAPH_INITDONE != pgraph->isinit)){
        hfa_err(CVM_HFA_EGINITPEND, ("Graph init pending\n"));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (!(pgraph->clmsk) || 
                (pgraph->clmsk > hfa_get_max_clmsk()))){
        hfa_err(CVM_HFA_ENOPERM, 
                ("Graph clmsk 0x%x invalid\n", pgraph->clmsk));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (pgraph->state != chkstate)){
        hfa_err(CVM_HFA_EGINVAL_STATE, 
                ("State :0x%x Expected: 0x%x\n",pgraph->state, chkstate));
        return HFA_FAILURE;
    }
#endif    
    return HFA_SUCCESS;
}
/**
 * Permission denied handler used in state machine
 *
 * @return Always return HFA_FAILURE
 */
static inline hfa_return_t 
hfa_mload_perm_denied_hndlr(hfa_graph_t *pgraph, uint8_t *pdata, 
                            hfa_size_t ilen, hfa_size_t *olen)
{
    if(hfa_os_likely(pgraph)){
        hfa_err(CVM_HFA_EGINVAL_STATE, ("Permission denied for pgraph: %p"
            " state: 0x%x\n", pgraph, pgraph->state));
    }
    return HFA_FAILURE;
}
/**
 *  Cleanups every memory setup in hfa_graph_firstchunk()
 */
static inline hfa_return_t
hfa_mload_firstchunk_cleanup(hfa_graph_t *pgraph)
{
    hfa_dbg("pgraph: %p\n", pgraph);
    if(hfa_os_likely(pgraph)){
        if(pgraph->obj){
            hfa_os_memoryfree(pgraph->obj, HFA_GOBJ_SIZE(pgraph));
            pgraph->obj = NULL;
        }
        if(pgraph->irt){
            hfa_os_memoryfree(pgraph->irt, HFA_GPPINFO_SIZE(pgraph));
            pgraph->irt = NULL;
       }
        if(pgraph->pibuf){
            hfa_os_memoryfree(pgraph->pibuf, HFA_GINFO_SIZE(pgraph));
            pgraph->pibuf = NULL;
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * In case clusters share memory resources then memory is allocated
 * once and pointer is marked in all cluster_buf.mbase
 *
 *  @param      pbuf            Pointer to the clusterbuf
 *  @param      idx             Index of the cluster who actually allocates
 *  @param      msk             Bitmsk indicating shared cluster mask
 *  @return     HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_gclustbuf_share_mbase(hfa_graph_clbuf_t *pbuf, int idx, hfa_clmsk_t msk)
{
    int _i, _cl;
    hfa_dbg("pclbuf: %p, idx: %d, msk: 0x%x\n", pbuf, idx, msk);

    HFA_FOREACHBIT_SET(msk){
        pbuf[_i].mbase = pbuf[idx].mbase;
        hfa_dbg("Sharing Mbase idx(clno): %d(%d) = %d(%d)\n", 
                 _i, _cl, idx, pbuf[idx].clno);
    }
    return HFA_SUCCESS;
}
/**
 * Allocates cluster resources for the graph to be downloaded
 * If resources are shared then allocate once and marked the pointer
 * among shared clusters
 *
 * @param   pgraph      Pointer to the graph
 * @param   clno        Cluster in focus
 * @param   idx         Index of cluster in pgraph->pclustbuf
 * @param   msz         Memory size 
 * @param   csz         Cache size (currently cache is not shared in any OCTEON)
 * @param   *pmsk       Bitmask pointer (graph clustermask)
 *
 * @return HFA_SUCCESS if initialization successful, HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_alloc_pclustbuf(hfa_graph_t *pgraph, int clno, int idx,
                    hfa_size_t msz, hfa_size_t csz, hfa_clmsk_t *pmsk)
{
    int                 refcnt = 0;
    hfa_cluster_t       *pclust = NULL;
    hfa_clmsk_t         bitmsk=0, msk;
    hfa_graph_clbuf_t   *pclbuf = NULL;

    hfa_dbg("pgraph: %p clno: %d msz: %lu, csz: %lu\n", pgraph,clno,msz,csz);

    if(hfa_os_likely(pgraph && clno < hfa_get_max_clusters() && pmsk)){
         /* If all sharing done than return SUCCESS*/
        if(hfa_os_unlikely(!(*pmsk))){
            hfa_dbg("All sharing done\n");
            return HFA_SUCCESS;
        }
        /*If no memory return*/
       /* In simulator if the mem portion is zero we need valid address*/
#ifdef HFA_SIM
        if(!msz)
            msz = 36;
#endif
        if(hfa_os_unlikely(!msz)){
            hfa_dbg("Mem portion is Zero, No allocation\n");
            *pmsk=0;
            return HFA_SUCCESS;
        } 
        /*Get cluster pointer*/
        if(hfa_os_unlikely(HFA_SUCCESS != 
                    hfa_get_cluster(pgraph->pdev, &pclust, clno))){
            hfa_err(CVM_HFA_EINVAL_CLSTATE,("get cluster: %d failed\n", clno));
            return HFA_FAILURE;
        }
        pclbuf = (pgraph->clinfo).pclustbuf;
        /*Allocating and Sharing memory portions*/
        if(hfa_os_likely(pclust && pclbuf)){
            HFA_ALIGNED(msz, alignment);
            hfa_dbg("Aligned msz to %lu\n", msz);

            /*Allocate mbase resources and calculate refcnt for new memnode
             * Usecases:
             * a) gclmsk = 101 && mem_msk = 101 => refcnt =2, mbase allocated
             *    once for cluster 0 marked shared in cluster 2
             * b) gclmsk = 101 && mem_msk = 110 =>refcnt =1, mbase allocated 
             *    for clno: 2 only no sharing marked in cluster 1
             * c) gclmsk = 111 && mem_msk = 0 => refcnt =1, mbase allocated
             *    3 times for each cluster: 0, 1, 2
             * d) gclmsk = 111 && mem_msk = 101 => mbase allocated two times
             *    1) (refcnt=2 shared among cluster 0 and 2) 
             *    2) (refcnt =1 shares among cluster 1
             */
            msk = pclust->s.memshare_msk;
            bitmsk = (pgraph->clmsk) & msk;
            HFA_BITSET(bitmsk, clno);
            refcnt = hfa_noofbit_set[bitmsk];

            hfa_dbg("Cl: %d, GClmsk: 0x%x, MemMsk: 0x%x\n", 
                                                    clno, pgraph->clmsk, msk);
            hfa_dbg("Idx: %d, RBitmsk 0x%x, refcnt: %d\n", idx, bitmsk, refcnt);

            /*Allocate one node for all shared clusters, refcnt == no of 
             * clusters shared*/
            if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_memcalloc(pclust, msz, 
                              &(pclbuf[idx].mbase), refcnt))){
                hfa_err(CVM_HFA_ECLUSREALLOC,
                   ("calloc: Not enough memory in cl: %d mempool\n", clno));
                return HFA_FAILURE;
            }
            HFA_BITSET((pgraph->clinfo).mbase_alloc_msk, clno);
            hfa_dbg("Setting cl: %d in mbase_alloc_msk: 0x%x\n", clno,
                     (pgraph->clinfo).mbase_alloc_msk);
            hfa_dbg("Clearing bitmsk: 0x%x in *pmsk: 0x%x\n", bitmsk, *pmsk);
            HFA_BITMSKCLR(*pmsk, bitmsk);
            hfa_dbg("Resultant *pmsk: 0x%x\n", *pmsk);
            
            /*Share Mbase*/
            if(hfa_noofbit_set[bitmsk] > 1){
                hfa_gclustbuf_share_mbase(pclbuf, idx, bitmsk);
            }

            return HFA_SUCCESS;
        }
    }
    /*As of now cluster caches are not shared hence in future sharing of
     * cache may required*/
    return HFA_FAILURE;
}
/**
 * Cleanup all memory setup in hfa_mload_objinit()
 *
 * @param   pgraph  Pointer to the graph
 * @return  HFA_SUCCESS if cleanup successful, HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_mload_objcleanup(hfa_graph_t *pgraph)
{
    hfa_size32_t        sz;
    hfa_clmsk_t         gclmsk;
    hfa_cluster_t       *pcluster = NULL;
    hfa_graph_clbuf_t   *pclbuf = NULL;
    int                 _i, _cl, cntr;

    hfa_dbg("pgraph: %p\n", pgraph);
    if(hfa_os_likely(pgraph)){
        /*pclustinfo.rmdata and mbase*/
        pclbuf = (pgraph->clinfo).pclustbuf;
        if(hfa_os_likely(pclbuf)){
            gclmsk = pgraph->clmsk;
            HFA_FOREACHBIT_SET(gclmsk){
#ifndef HFA_GRAPH_ALLOC_RMDATA_DYN                
                if(pclbuf[_i].rmdata){
                    hfa_dbg("Free rmdata for cluster: %d\n", _cl);
                    hfa_os_free(pclbuf[_i].rmdata, HFA_RMDATA_SIZE);
                    pclbuf[_i].rmdata = NULL;
                }
#endif                
                if(pclbuf[_i].pending_instr){
                    hfa_dbg("Free pending_instr for cluster: %d\n", _cl);
                    hfa_os_free(pclbuf[_i].pending_instr, 
                                sizeof(hfa_graph_pending_instr_t));
                    pclbuf[_i].pending_instr = NULL;
                }
                pcluster = NULL;
                hfa_get_cluster(pgraph->pdev, &pcluster, _cl);
                hfa_dbg("Free mbase: 0x%x, pcluster: %p(%d)", 
                    pclbuf[_i].mbase, pcluster, _cl);
                if(pcluster && pclbuf[_i].mbase){
                    hfa_cluster_memfree(pcluster, pclbuf[_i].mbase);
                    pclbuf[_i].mbase = 0;
                }
            }
        }
        sz = hfa_noofbit_set[pgraph->clmsk] * sizeof(hfa_graph_clbuf_t);
        /*Clean pclustinfo*/
        if((pgraph->clinfo).pclustbuf){
            hfa_os_free((pgraph->clinfo).pclustbuf, sz);
            (pgraph->clinfo).pclustbuf = NULL;
        }
        /*Info portion*/
        for(cntr =0; cntr < pgraph->ninfo; cntr++){
            if(pgraph->pibuf){
                if((pgraph->pibuf[cntr]).ptr){
                    hfa_os_infofree((pgraph->pibuf[cntr]).ptr,
                                (pgraph->pibuf[cntr]).size);
                    (pgraph->pibuf[cntr]).ptr = NULL;
                }
            }
        }
        /*Cache portion*/
        if(pgraph->cbuf.ptr){
            hfa_os_memoryfree(pgraph->cbuf.ptr, pgraph->cbuf.size);
            pgraph->cbuf.ptr = NULL;
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Allocates / Initialisez objects of graph
 * Memory/Cache/Info
 *
 * @param       pgraph          Pointer to the graph
 * @param       hasmem          Variable indicating whether OCTEON2 has HFA mem
 * @param       msz             Total memory size in graph
 * @param       csz             Total cache size in graph
 *
 * @return      HFA_SUCCESS if initialization successfule HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_mload_objinit(hfa_graph_t *pgraph, hfa_bool_t  hasmem, 
                  hfa_size_t  msz, hfa_size_t csz)
{
    int                 _i, _cl, cntr;
    uint32_t            clustbufsz=0;
    hfa_clmsk_t         gclmsk;
    hfa_graph_clbuf_t   **ppclbuf = NULL;

    hfa_dbg("pgraph:%p, ismem:%d, msz=%lu, csz=%lu\n",pgraph,hasmem,msz,csz);
    
    /*Allocate mem chunk when hfamem present*/
    memset(&(pgraph->mload), 0, sizeof(hfa_graph_mloadinfo_t));
    HFA_OS_LISTHEAD_INIT(&pgraph->mload.list);
    (pgraph->mbuf).size = msz;

    /*Allocate info chunk in all chips but for cached graph*/
    switch(pgraph->nobj){
        case 2:
            /*Allocate info*/
            hfa_dbg("Allocating pibuf[0] of size %u\n", 
                                           (pgraph->obj[1]).size);
            (pgraph->pibuf[0]).size = (pgraph->obj[1]).size;
            if(hfa_os_unlikely(NULL == ((pgraph->pibuf[0]).ptr = 
                hfa_os_infoalloc((pgraph->obj[1]).size, 128)))){
                hfa_err(CVM_HFA_ENOMEM, ("pibuf[0] alloc failure\n"));
                goto mload_obj_cleanup;
            }
        break;
        default:
            hfa_dbg("Allocating cbuf.ptr of size %lu\n", csz);
            if(hfa_os_unlikely(NULL == ((pgraph->cbuf).ptr = 
                hfa_os_memoryalloc(csz, 128)))){
                hfa_err(CVM_HFA_ENOMEM, ("cbuf.ptr alloc failed\n"));
                goto mload_obj_cleanup;
            }
            (pgraph->cbuf).size = csz; 

            /*Allocate info*/ 
            for(cntr = 0; cntr < pgraph->ninfo; cntr++){
                (pgraph->pibuf[cntr]).size = (pgraph->obj[cntr+2]).size;
                hfa_dbg("Allocating pibuf[%d] of size %lu\n", cntr, 
                                           pgraph->pibuf[cntr].size);
                if(hfa_os_unlikely(NULL == ((pgraph->pibuf[cntr]).ptr = 
                    hfa_os_infoalloc((pgraph->pibuf[cntr]).size, 128)))){
                    hfa_err(CVM_HFA_ENOMEM,("pibuf[%d] alloc failure\n",cntr));
                    goto mload_obj_cleanup;
                }
            }
        break;
    }
    /*Fill clustbuf for each cluster. Take care of memshare_msk
     * and cacheshare_msk
     *
     * Allocate mbase in following cases
     * 1) If cluster set in clmsk but not in memshare_msk
     * 2) If cluster set in clmsk and in memshare_msk then 
     *    allocate mbase once and make them share to other
     *    shared clusters
     * 3) rmdata can be allocted for each cluster to separate 
     *    result buffer
     */
    gclmsk = pgraph->clmsk;
    clustbufsz = hfa_noofbit_set[gclmsk] * sizeof(hfa_graph_clbuf_t);
    hfa_dbg("Allocating pclustbuf sz (%u) for clusters: %d. gclmsk: 0x%x\n", 
              clustbufsz, hfa_noofbit_set[gclmsk], gclmsk);

    /*Allocate pclustbuf for all clusters set in gclmsk*/
    ppclbuf = &((pgraph->clinfo).pclustbuf);
    if(hfa_os_unlikely(NULL == (*ppclbuf = hfa_os_malloc(clustbufsz)))){
        hfa_err(CVM_HFA_ENOMEM, ("pclustbuf alloc error\n"));
        goto mload_obj_cleanup;
    }
    memset(*ppclbuf, 0, clustbufsz);
    (pgraph->clinfo).mbase_alloc_msk =0;
    hfa_dbg("Setting mbase_alloc_msk =%d\n", (pgraph->clinfo).mbase_alloc_msk);
 
    /*Allocate rmdata + mbase (and share mbase if needed) for each cluster
     * in pgraph->clmsk*/ 
    HFA_FOREACHBIT_SET(gclmsk){
        hfa_dbg("Clno: %d\n", _cl);
        (*ppclbuf)[_i].clno = _cl;
#ifndef HFA_GRAPH_ALLOC_RMDATA_DYN        
        if(NULL == ((*ppclbuf)[_i].rmdata = hfa_os_malloc(HFA_RMDATA_SIZE))){
            hfa_err(CVM_HFA_ENOMEM, ("rmdata allocation failed\n"));
            goto mload_obj_cleanup;
        }
        hfa_dbg("Allocated rmdata for cluster: %d\n", _i);
        memset((*ppclbuf)[_i].rmdata, 0, HFA_RMDATA_SIZE);
#else
        (*ppclbuf)[_i].rmdata = NULL;

#endif
        if(NULL == ((*ppclbuf)[_i].pending_instr = 
                    hfa_os_malloc(sizeof(hfa_graph_pending_instr_t)))){
            hfa_err(CVM_HFA_ENOMEM, ("pending_instr allocation failed\n"));
            goto mload_obj_cleanup;
        }
        memset((*ppclbuf)[_i].pending_instr, 0, 
                sizeof(hfa_graph_pending_instr_t));
    }
    gclmsk = pgraph->clmsk;
    HFA_FOREACHBIT_SET(gclmsk){
        if(hfa_os_unlikely(HFA_SUCCESS != 
            hfa_alloc_pclustbuf(pgraph,_cl,_i,msz,0, &gclmsk))){
            hfa_err(CVM_HFA_EGEN, ("Error from hfa_allocate_pclustbuf()\n"));
            goto mload_obj_cleanup;
        }
        hfa_dbg("Received gclmsk: 0x%x\n", gclmsk);
    }
    return HFA_SUCCESS;
mload_obj_cleanup:    
    hfa_mload_objcleanup(pgraph);
    return HFA_FAILURE;
}
/**
 * First chunks which validates Graph header and initializes various
 * data members of graph structure
 *
 * @param       pgraph          Pointer to the graph
 * @param       pdata           Pointerto the data chunk
 * @param       currlen         Size of current data chunk
 * @param       consumed        Pointer variable set to the amount of size 
 *                              consumed in this API 
 */
static inline hfa_return_t 
hfa_mload_firstchunk(hfa_graph_t *pgraph, uint8_t *pdata, 
                     hfa_size_t currlen, hfa_size_t *consumed)
{
    uint32_t        cntr=0, i;
    hfa_size_t      hdrlen=0;
    uint64_t        toff=0;
    hfa_graphobj_t  *pobj = NULL;
    hfa_size_t      msize=0;
    hfa_size_t      csize=0;
    hfa_graphattr_t temp;
    uint32_t        *pu32 = NULL;
    uint64_t         *pu64 = NULL;
    char            version_str[64];

    hfa_dbg("graph: %p, pdata: %p, clen: %lu\n", pgraph, pdata, currlen);
    if (hfa_os_unlikely((currlen < HFA_GRAPHHDR_MINLEN))){
        hfa_err(CVM_HFA_EINVALARG, 
                ("Graph first chunk %lu fails min. requirement\n", currlen));
        return (HFA_FAILURE);
    }
    /* check for HFA graph file */
    if(hfa_os_unlikely(pdata[0] != 0x48 || pdata[1] != 0x46 || 
                pdata[2] != 0x41 || pdata[3] != 0x00)) {
        hfa_err (CVM_HFA_EINVALARG, ("Invalid Graph Header\n"));
        return (HFA_FAILURE);
    }
    pgraph->nobj = hfa_os_le32toh(*(uint32_t *)(pdata +HFA_GRAPHHDR_NOBJ_OFF));

    switch(pgraph->nobj){
        case 0:
        case 1:
           hfa_err(CVM_HFA_ENOPERM, ("Invalid nobj: %d found\n",pgraph->nobj));
            return HFA_FAILURE;
            break;

        case 2:
            hfa_dbg("This is Memonly Graph\n");
            pgraph->gtype = HFA_GRAPH_MEMONLY;
            pgraph->ninfo = 1; 
            pgraph->nirt = 1;
            break;

        case 3:
            hfa_dbg("This is Mixed Graph\n");
            pgraph->gtype = HFA_GRAPH_MIXTYPE;
            pgraph->ninfo = 1; /* pgraph->nobj - 2*/
            pgraph->nirt = 1; 
            break;    

        default:
            hfa_dbg("This is Linked Graph\n");
            pgraph->ninfo = pgraph->nobj - 2; 
            pgraph->nirt = pgraph->nobj - 2; 
            pgraph->gtype = HFA_GRAPH_LINKGRAPH;
            break;
    }
    hdrlen = HFA_GHDRLEN(pgraph);
    hfa_dbg("Total Header Len: %lu\n", hdrlen);
    if(hfa_os_unlikely(currlen < hdrlen)){
        hfa_err (CVM_HFA_EINVALARG, 
                ("Datalen %lu must be > Hdrlen: %lu\n", currlen, hdrlen));
        return (HFA_FAILURE);
    }
    /*Flags and Savelen*/
    toff = HFA_GFLAG_OFF(pgraph);
    pgraph->info.flags = hfa_os_le32toh(*(uint32_t *) (pdata + toff));

    toff = HFA_GSAVELEN_OFF(pgraph);
    pgraph->info.savelen = hfa_os_le32toh(*(uint32_t *) (pdata + toff));

    hfa_dbg("Flags: 0x%x, Savelen: %d\n", pgraph->info.flags, 
                                       pgraph->info.savelen);
    /*GraphAttr*/
    toff = HFA_GATTR_OFF(pgraph);

    memcpy(&temp, pdata + toff, sizeof(hfa_graphattr_t));
    pu64 = (uint64_t *)&temp;
    *pu64 = hfa_os_le64toh(*pu64);
    pu64++;
    pu32 = (uint32_t *)pu64;
    *pu32 = hfa_os_le32toh(*pu32);
    pu32 ++;

    memcpy(&(pgraph->info.attr), &temp, sizeof(hfa_graphattr_t));
    hfa_log("Graph: ");
    hfa_display_graphattr(&(pgraph->info.attr), version_str, 
                          sizeof(version_str)/sizeof(version_str[0]));
    /*Target*/
    cntr = HFA_GET_GRAPHATTR(pgraph, target);
    /*Validate PP library version + Graph version*/
    if(hfa_os_unlikely(strncmp(hfa_pp_ver, version_str, strlen(hfa_pp_ver)))){
        hfa_err(CVM_HFA_EGRAPHVER, 
            ("Version mismatch with PP Library\n"));
        return HFA_FAILURE;
     }
    if(hfa_os_likely(cntr < OCTEON_HFA_MAX_TARGETS)){
        if(strncmp((const char *)&((pgraph->pdev->devinfo).name),
                    octeon_hfa_targetname[cntr], 6)){
            hfa_err(CVM_HFA_EINVALDEV, ("Graph compiled for %s expected %s\n",
                                        octeon_hfa_targetname[cntr], 
                                      (char *)&((pgraph->pdev->devinfo).name)));
            return HFA_FAILURE;
        }
    } else {
        hfa_err(CVM_HFA_EINVALDEV,("Graph compiled for %x expected %s\n", cntr,
                                  (char *)&((pgraph->pdev->devinfo).name)));
        return HFA_FAILURE;
    }
    if(HFA_ISBITMSKSET (pgraph->info.flags, CVM_HFA_FSUBMITALL)){
        hfa_dbg("Submitall flag is set\n");
        /*Mark graph as submitall*/
        HFA_SET_GRAPHATTR(pgraph, submitall, HFA_TRUE);
    }
    pgraph->ngraphs = pgraph->ninfo;
    /**Allocate object attributes*/
    if(hfa_os_unlikely(NULL == (pgraph->obj = 
        hfa_os_memoryalloc(HFA_GOBJ_SIZE(pgraph), 8)))){
        hfa_err(CVM_HFA_ENOMEM, ("pgraph-obj allocation failure\n"));
        return HFA_FAILURE;
    }
    pobj = pgraph->obj;
    memset(pobj, 0, HFA_GOBJ_SIZE(pgraph));
    memcpy(pobj, pdata + HFA_GRAPHHDR_MINLEN, HFA_GOBJ_SIZE(pgraph));
    
    switch(pgraph->nobj){
        /*Memonly graph*/
        case 2:
            /*Memory*/
            pobj[0].off = hfa_os_le32toh(pobj[0].off);
            pobj[0].size = hfa_os_le32toh(pobj[0].size);
            /*Info*/
            pobj[1].off = hfa_os_le32toh(pobj[1].off);
            pobj[1].size = hfa_os_le32toh(pobj[1].size);
            msize = (pobj[0].size - sizeof(hfa_tstamp_t));
            csize =0;
            cntr=2;
            if(hfa_os_unlikely(!msize)){
                hfa_err(CVM_HFA_EBADFILE, ("Mem portion can't be zero\n"));
                return HFA_FAILURE;
            }
        break;

            /*nobj >= 3*/
        default:
            for(cntr=0; cntr < pgraph->ninfo + 2; cntr++){
                pobj[cntr].off = hfa_os_le32toh(pobj[cntr].off);
                pobj[cntr].size = hfa_os_le32toh(pobj[cntr].size);
            }
            csize = pobj[0].size - sizeof(hfa_tstamp_t);
            msize = pobj[1].size - sizeof(hfa_tstamp_t);
            if(hfa_os_unlikely(!csize)){
                hfa_err(CVM_HFA_EBADFILE, ("Cache portion can't be zero\n"));
                return HFA_FAILURE;
            }
            break;
    }

    for(i=0; i <cntr; i++){
        pgraph->totlen += pobj[i].size;
        hfa_dbg("OBJ[%d].size=%u\n", i, pobj[i].size);
        if(hfa_os_unlikely(!(pobj[i].size))){
            hfa_err(CVM_HFA_EBADFILE, 
                   ("Bad Graph File: OBJ[%d]: %u\n", i, pobj[i].size));
            goto mload_firstchunk_error;
        }
    }
    /**Allocate ppinfo buffer for all graphs (irt)*/
    if(hfa_os_unlikely(NULL ==(pgraph->irt = 
        hfa_os_memoryalloc(HFA_GPPINFO_SIZE(pgraph), 128)))){
        hfa_err(CVM_HFA_ENOMEM, ("pgraph-ppinfoirt allocation failure\n"));
        goto mload_firstchunk_error;
    }  
    memset(pgraph->irt, 0, HFA_GPPINFO_SIZE(pgraph));

    /**Allocate info part attributes*/
    if(hfa_os_unlikely(NULL ==(pgraph->pibuf = 
        hfa_os_memoryalloc(HFA_GINFO_SIZE(pgraph),128)))){
        hfa_err(CVM_HFA_ENOMEM, ("pgraph-ninfo allocation failure\n"));
        goto mload_firstchunk_error;
    }
    memset(pgraph->pibuf, 0, HFA_GINFO_SIZE(pgraph));

    /*Initialize mbuf + cbuf*/ 
    memset(&pgraph->mbuf, 0, sizeof(hfa_graphchunk_t));
    memset(&pgraph->cbuf, 0, sizeof(hfa_graphchunk_t));

    /**Mark how much byte is consumed in this function*/
    *consumed = HFA_GHDRLEN(pgraph);
    pgraph->totlen += *consumed;
    hfa_dbg("Totlen: %lu\n", pgraph->totlen);
    if(hfa_os_unlikely(HFA_SUCCESS != 
        hfa_mload_objinit(pgraph, ishfamem, msize, csize))){
        hfa_err(CVM_HFA_EBADFILE, ("hfa_mload_objinit error\n"));
        goto mload_firstchunk_error;
    }
    /*Change graph state*/
    pgraph->state = (hfa_mload_sm[ishfamem][pgraph->gtype]
                    [pgraph->state]).next_state;
    return HFA_SUCCESS;
mload_firstchunk_error:
    hfa_mload_firstchunk_cleanup(pgraph);
    return HFA_FAILURE;    
}
/**
 * Copies cache portion from the input chunk
 *
 * @param       pgraph          Pointer to the graph
 * @param       pdata           Pointerto the data chunk
 * @param       currlen         Size of current data chunk
 * @param       consumed        Pointer variable set to the amount of size 
 *                              consumed in this API 
 */
static inline hfa_return_t 
hfa_mload_cache(hfa_graph_t *pgraph, uint8_t *pdata, 
                hfa_size_t    currlen, hfa_size_t *consumed)
{
    hfa_size_t          csz=0, skip;
    long int            pendinglen=-1, copydone=0, adjustlen;

    hfa_dbg("pgraph: %p, data: %p, datalen:%lu\n", pgraph, pdata, currlen);
    if(hfa_os_likely(pgraph && pdata && currlen && consumed)){
        *consumed =0;
        csz = (pgraph->cbuf).size;
        skip = pgraph->skiplen;

        /*Calculate how much cache copying pending*/
        pendinglen = HFA_GHDRLEN(pgraph) + csz + skip - pgraph->curr_seek;

        /*Calculate how much cache is already copied*/
        copydone = csz- pendinglen;

#ifdef HFA_STRICT_CHECK
        if(hfa_os_unlikely((pendinglen <0) || (copydone < 0))){
            hfa_err(CVM_HFA_ENOPERM, ("-Ve pendinglen=%ld,copydone:%ld\n", 
                                     pendinglen, copydone));
            return HFA_FAILURE;
        }
#endif
        /*Calculate how much memory part can be copied from current*/
        adjustlen = (currlen >= pendinglen) ? pendinglen : currlen;

        hfa_dbg("Copydone:%ld, Pendingmem:%ld,Currcopysz: %ld\n",
                 copydone, pendinglen, adjustlen);

        if(adjustlen > 0){

            /*Copy memory buffer*/
            memcpy(pgraph->cbuf.ptr + copydone, pdata, adjustlen); 

            /*Mark how much length is consumed in this function*/
            *consumed = adjustlen;
    
            /*Increment copying*/
            copydone += adjustlen;
        }

        /*Once all cache part copied*/
        if(copydone == csz){
            /*Skip timestamp portion*/
            pendinglen = currlen - adjustlen;
            skip = sizeof(hfa_tstamp_t) - pgraph->skiplen;

            if(pendinglen >= skip){
                *consumed += skip;
                pgraph->skiplen += skip;
            } else {
                *consumed += pendinglen;
                pgraph->skiplen += pendinglen;
            }
            if(pgraph->skiplen == sizeof(hfa_tstamp_t)){
                pgraph->skiplen=0;
                /*Move to next state*/
                pgraph->state = 
                hfa_mload_sm[ishfamem][pgraph->gtype][pgraph->state].next_state;
                hfa_dbg("Changing state to 0x%x\n", pgraph->state);
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
static inline hfa_return_t
hfa_mload_designated_mem_submitinstr(hfa_graph_t *pgraph)
{
    hfa_os_listhead_t       *p1 = NULL, *p2 = NULL;
    hfa_graph_mbufptr_t     *pmbuf = NULL;
    hfa_graph_clbuf_t       *pclbuf = NULL;
    hfa_instr_t             instr;
    hfa_size_t              bufsz=0;
    hfa_size32_t            *psubmitdone = NULL;
    cvmx_wqe_t              *wqe = NULL;
    hfa_wqe_pktdata_overload_t *pktdata = NULL;

    hfa_dbg("pgraph: %p\n", pgraph);
    psubmitdone = &(pgraph->mbuf.submittedsz);
    if(hfa_os_likely(!hfa_os_listempty(&pgraph->mload.list) 
                                    && !(pgraph->submittedinstr_clmsk))){
        hfa_os_listforeachsafe(p1, p2, &pgraph->mload.list){
            pmbuf = hfa_os_listentry(p1, hfa_graph_mbufptr_t, list);
#ifdef HFA_STRICT_CHECK            
            if(hfa_os_unlikely(HFA_MLOAD_READY2SUBMIT != pmbuf->status)){
                hfa_err(CVM_HFA_EGEN, ("Incomplete buf added in list\n"));
                return HFA_FAILURE;
            }
#endif            
            pclbuf = (pgraph->clinfo).pclustbuf;
            /*Check that last chunk should be aligned size*/
            if(pmbuf->copypend){
                bufsz = pgraph->mload_triggersz - pmbuf->copypend;
                memset(pmbuf->ptr + bufsz, 0, pmbuf->copypend);
            } else {
                bufsz = pgraph->mload_triggersz;
            }
            memset(&instr, 0, sizeof(hfa_instr_t));
            cvm_hfa_instr_init(&instr, CVMX_HFA_ITYPE_MEMLOAD);
            cvm_hfa_instr_setle(&instr, HFA_FALSE);
            cvm_hfa_instr_setgather(&instr, HFA_FALSE);
            cvm_hfa_instr_setdptr(&instr, ptr_to_phys(pmbuf->ptr));

            /*Set RMAX[11:0]DLEN[15:0]*/
            cvm_hfa_instr_setrmax(&instr, 
                ((pgraph->mload_triggersz >> 16) & 0xffff));
            cvm_hfa_instr_setdlen(&instr, ((pgraph->mload_triggersz) & 0xffff));
            /*clbuf index is always 0 for cn63xx and cn66xx*/
            cvm_hfa_instr_setmbase(&instr,
                                  (pclbuf[0].mbase + *psubmitdone) >> 10);
#ifdef HFA_GRAPH_ALLOC_RMDATA_DYN
            if(pclbuf[0].rmdata){
                hfa_err(CVM_HFA_EMEMEXIST, ("rmdata already there cl: 0\n")); 
                return HFA_FAILURE;
            }
            if(NULL == (pclbuf[0].rmdata = hfa_os_malloc(HFA_RMDATA_SIZE))){
                hfa_err(CVM_HFA_ENOMEM, ("rmdata allocation failed\n"));
                return HFA_FAILURE;
            }
#endif                        
            memset(pclbuf[0].rmdata, 0, HFA_RMDATA_SIZE);
            ((hfa_mload_rmdata_overload_t *)(pclbuf[0].rmdata))->ptr = 
                                                                (uint64_t)pmbuf;

            cvm_hfa_instr_setrptr(&instr, ptr_to_phys(pclbuf[0].rmdata));
        
            /*cluster mask is always 1 for 63xx and 66xx*/
            cvm_hfa_instr_setclmsk(&instr, HFA_63XX_MAX_CLMSK);

#ifdef HFA_DUMP
            hfa_dump_buf("63xx mload", instr.u64, sizeof(cvmx_hfa_command_t));
#endif            
            wqe = pclbuf[0].wqe; 
            if(wqe) {
                cvmx_wqe_set_unused8 (wqe, HFA_GRAPH_HWWQE_UNUSED_FIELD);
                pktdata = (hfa_wqe_pktdata_overload_t *)(wqe->packet_data);
                pktdata->pgraph = (uint64_t)pgraph;
                pktdata->itype = (uint64_t)CVMX_HFA_ITYPE_MEMLOAD;
                cvm_hfa_instr_setwqptr(&instr, (uint64_t)(ptr_to_phys(wqe)));
                hfa_graph_setwqe(pgraph, 0, NULL);
            }

            hfa_dbg("Submitting for mload\n");
            if(hfa_os_unlikely(hfa_dev_submitasync(pgraph->pdev, &instr))){
                hfa_err(CVM_HFA_EHWERROR, ("Mload error\n"));
                return HFA_FAILURE;
            }
            hfa_os_sync();
            HFA_GRAPH_PENDING_INSTR_INC(pclbuf[0].pending_instr, mload);
            hfa_os_listdel(&pmbuf->list);
            pgraph->mload.nbufs -=1;
            pmbuf->status = HFA_MLOAD_SUBMITTED;
            
            HFA_BITSET(pgraph->submittedinstr_clmsk, 0);
            /*Once submit is successful Adjust pgraph->mbuf.submittedsz*/
            *psubmitdone += bufsz;

            /*Submit instruction one at a time*/
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}

static inline hfa_return_t 
hfa_mload_designated_mem_skiplen(hfa_graph_t *pgraph, uint8_t *pdata, 
                                 hfa_size_t currlen, hfa_size_t *consumed)
{
    long int        skip=0;

    hfa_dbg("pgraph: %p, data: %p, datalen:%lu\n", pgraph, pdata, currlen);
    if(pgraph->mload.nbufs && !(pgraph->submittedinstr_clmsk)){
        if(HFA_SUCCESS != hfa_mload_designated_mem_submitinstr(pgraph)){
            return HFA_FAILURE;
        }
    }
    /*If all memory portion is loaded + submitted then copy skiplen and 
     * switch graph state to next*/
    if(pgraph->mbuf.submittedsz == pgraph->mbuf.size){
         /*Skip timestamp portion*/
        skip = sizeof(hfa_tstamp_t) - pgraph->skiplen;

        if(currlen >= skip){
            *consumed += skip;
            pgraph->skiplen += skip;
        } else {
            *consumed += currlen;
            pgraph->skiplen += currlen;
        }
        if(pgraph->skiplen == sizeof(hfa_tstamp_t)){
            pgraph->skiplen=0;
            /*Destroy all mbufs allocated during designated_memload
             */
            hfa_graph_mload_destroy_mbufs(pgraph);
            /*Move to next state*/
            pgraph->state = 
            hfa_mload_sm[ishfamem][pgraph->gtype][pgraph->state].next_state;
            hfa_dbg("Changing state to 0x%x\n", pgraph->state);
        }
    }
    return HFA_SUCCESS;
}
/**
 * Copies and submits memory portion to OCTEON HFA from the input chunk
 * Called in cn63xx/cn66xx OCTEON chipsets only
 *
 * @param       pgraph          Pointer to the graph
 * @param       pdata           Pointerto the data chunk
 * @param       currlen         Size of current data chunk
 * @param       consumed        Pointer variable set to the amount of size 
 *                              consumed in this API 
 */
static inline hfa_return_t 
hfa_mload_designated_mem(hfa_graph_t *pgraph, uint8_t *pdata, 
                         hfa_size_t currlen, hfa_size_t *consumed)
{
    hfa_size_t              msz=0, csz=0;
    long int                pendinglen=0,  adjustlen=0, copydone=0, skip;
    hfa_graph_mbufptr_t     *pmbuf = NULL;
    long int                datalen;
    hfa_return_t            retval = HFA_SUCCESS;

    hfa_dbg("pgraph: %p, data: %p, datalen:%lu\n", pgraph, pdata, currlen);
    if(hfa_os_likely(pgraph && pdata && currlen && consumed)){
        /*Enforce memload_trggersz*/
        if(hfa_os_unlikely(currlen > pgraph->mload_triggersz)){
            hfa_err(CVM_HFA_E2BIG, ("Currlen :%lu > Triggersz: %lu\n", currlen,
                                   pgraph->mload_triggersz));
            return HFA_FAILURE;
        }
        *consumed =0;
        msz = pgraph->mbuf.size;
        csz = pgraph->cbuf.size;
        csz += (!!csz) * sizeof(hfa_tstamp_t);
        skip = pgraph->skiplen;

        /*Calculate how much mem copying pending*/
        pendinglen = HFA_GHDRLEN(pgraph) + msz + csz + skip - pgraph->curr_seek;
        hfa_dbg("MemCopypend: %lu\n", pendinglen);

#ifdef HFA_STRICT_CHECK
        if(hfa_os_unlikely(pendinglen < 0)){
            hfa_err(CVM_HFA_ENOPERM, ("negative pendinglen=%ld\n", pendinglen));
            return HFA_FAILURE;
        }
#endif
        /*Calculate how much memory part can be copied from current*/
        datalen = (currlen >= pendinglen) ? pendinglen : currlen;
        if(datalen >0){
            pmbuf = pgraph->mbuf.ptr;
            /*Either mbuf.ptr is NULL or no space to copy then we need more 
             *buffer*/
            if((NULL == pmbuf) || (!pmbuf->copypend)){
                if(HFA_SUCCESS != hfa_mload_alloc_mbuf(pgraph, &pmbuf)){
                    goto mload_mbuf_cleanup;
                } 
            }
            /*pmbuf points to buffer where something can be copied*/
            adjustlen = (datalen < pmbuf->copypend) ? datalen: pmbuf->copypend;
            
            copydone = pgraph->mload_triggersz - pmbuf->copypend;
            
            hfa_dbg("CurrBuf: Copydone:%ld,Pendingmem:%ld, Currcopysz: %ld\n",
                     copydone, pmbuf->copypend, adjustlen);

            if(adjustlen >0){
                memcpy(pmbuf->ptr + copydone, pdata, adjustlen);
                *consumed += adjustlen;
                pmbuf->copypend -= adjustlen;
                hfa_dbg("CopiedMem: %ld\n", adjustlen);

                /*If buffer is exhausted add to the tail list and mark it 
                 * as NULL*/
                if(!pmbuf->copypend){
                    pmbuf->status = HFA_MLOAD_READY2SUBMIT;
                    hfa_os_listaddtail(&pmbuf->list, &pgraph->mload.list);
                    (pgraph->mload.nbufs) += 1;
                    pgraph->mbuf.ptr = NULL;
                    hfa_dbg("Added to list. Totalbufs: %u\n",
                                        pgraph->mload.nbufs);
                } else {
                    hfa_dbg("copied to mbuf.ptr\n");
                    pgraph->mbuf.ptr = pmbuf;
                }
            }
        }
        if(pgraph->mload.nbufs && !(pgraph->submittedinstr_clmsk)){
            retval = hfa_mload_designated_mem_submitinstr(pgraph);
        }
        if(!pendinglen){
            if(pgraph->mbuf.ptr){
                pmbuf = pgraph->mbuf.ptr;
                pmbuf->status = HFA_MLOAD_READY2SUBMIT;
                hfa_os_listaddtail(&pmbuf->list, &pgraph->mload.list);
                (pgraph->mload.nbufs) += 1;
                pgraph->mbuf.ptr = NULL;
            }
            /*Move to next state*/
            pgraph->state = 
            hfa_mload_sm[ishfamem][pgraph->gtype][pgraph->state].next_state;
            hfa_dbg("Changing state to 0x%x\n", pgraph->state);
        }
        return retval;
mload_mbuf_cleanup:
    hfa_graph_mload_destroy_mbufs(pgraph);
    }
    return HFA_FAILURE;    
}
/**
 * Copies memory portion from input chunk
 * Called in cn61xx/cn68xx/cn70xx OCTEON chipsets only
 *
 * @param       pgraph          Pointer to the graph
 * @param       pdata           Pointerto the data chunk
 * @param       currlen         Size of current data chunk
 * @param       consumed        Pointer variable set to the amount of size 
 *                              consumed in this API 
 */
static inline hfa_return_t 
hfa_mload_ddr_mem(hfa_graph_t *pgraph, uint8_t *pdata, 
              hfa_size_t currlen, hfa_size_t *consumed)
{
    hfa_size_t          msz=0, csz=0, bitmsk;
    hfa_size32_t        *psubmitdone = NULL;
    long int            pendinglen=0, copydone, adjustlen, skip;
    hfa_graph_clbuf_t   *pclbuf = NULL;
    int                 _i, _cl;

    hfa_dbg("pgraph: %p, data: %p, datalen:%lu\n", pgraph, pdata, currlen);
    if(hfa_os_likely(pgraph && pdata && currlen && consumed)){
        *consumed =0;
        msz = pgraph->mbuf.size;
        csz = pgraph->cbuf.size;
        /*If cache portion present, count tstamp also*/
        csz += (!!(csz)) * sizeof(hfa_tstamp_t);
        skip = pgraph->skiplen;

        psubmitdone = &(pgraph->mbuf.submittedsz);

        hfa_dbg("Msize: %lu, Csize: %lu\n", msz, csz);
        /*Calculate how much mem copying pending*/
        pendinglen = HFA_GHDRLEN(pgraph)+ msz + csz + skip - pgraph->curr_seek;

        pclbuf = (pgraph->clinfo).pclustbuf;
#ifdef HFA_STRICT_CHECK
        if(hfa_os_unlikely((pendinglen <0) || (NULL == pclbuf))){
            hfa_err(CVM_HFA_ENOPERM, 
                ("Pendinglen=%ld, pclbuf: %p\n", pendinglen, pclbuf));
            return HFA_FAILURE;
        }
#endif
        /*Calculate how much memory is already copied*/
        copydone = msz - pendinglen;

        /*Calculate how much memory part can be copied from current*/
        adjustlen = (currlen >= pendinglen) ? pendinglen : currlen;

        hfa_dbg("Copydone:%ld,Submitdone:%u,Pendingmem:%ld,Currcopysz: %ld\n",
                copydone, *psubmitdone, pendinglen, adjustlen);
        if(adjustlen > 0){

            bitmsk = (pgraph->clinfo).mbase_alloc_msk;
            /*Copy memory buffer to all clusters in mbase_alloc_msk*/
            HFA_FOREACHBIT_SET(bitmsk){
                memcopy(pclbuf[_i].mbase + copydone, pdata,adjustlen); 
            }

            /*Mark how much length is consumed in this function*/
            *consumed = adjustlen;
            *psubmitdone += adjustlen;
        }
        hfa_dbg("CopiedMemlen: %ld\n", adjustlen);

        if(*psubmitdone == msz){
            hfa_dbg("msz: %lu ready for eswap\n", msz);
            if(msz){
                bitmsk = (pgraph->clinfo).mbase_alloc_msk;
                HFA_FOREACHBIT_SET(bitmsk){
                    hfa_dbg("Swapping for cl: %d, idx: %d\n", _cl, _i);
                    eswap(phys_to_ptr((pclbuf[_i]).mbase), msz);
                }
                hfa_os_sync();
                hfa_l2c_flush();
            }
            /*Skip timestamp portion*/
            pendinglen = currlen - adjustlen;
            skip = sizeof(hfa_tstamp_t) - pgraph->skiplen;

            if(pendinglen >= skip){
                *consumed += skip;
                pgraph->skiplen += skip;
            } else {
                *consumed += pendinglen;
                pgraph->skiplen += pendinglen;
            }
            if(pgraph->skiplen == sizeof(hfa_tstamp_t)){
                pgraph->skiplen=0;
                /*Move to next state*/
                pgraph->state = 
                hfa_mload_sm[ishfamem][pgraph->gtype][pgraph->state].next_state;
                hfa_dbg("Changing state to 0x%x\n", pgraph->state);
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Copies info portion from input chunk.
 * Called in all supported OCTEON chips
 *
 * @param       pgraph          Pointer to the graph
 * @param       pdata           Pointerto the data chunk
 * @param       currlen         Size of current data chunk
 * @param       consumed        Pointer variable set to the amount of size 
 *                              consumed in this API 
 */
static inline hfa_return_t 
hfa_mload_readinfo(hfa_graph_t *pgraph, uint8_t *pdata, 
                        hfa_size_t currlen, hfa_size_t *consumed)
{
    int                 cntr;
    long int            pendinglen = -1, inputlen=-1, adjustlen;
    hfa_return_t        retval = HFA_FAILURE;
    hfa_graphchunk_t    *pibuf = NULL;
    ppdfa_tstamp_t      *ptstamp = NULL;
    ppdfa_tstamp_t      l_tstamp;
    uint32_t            *pu32 = NULL;
    uint64_t            *pu64 = NULL;
    char                str[64];

    hfa_dbg("pgraph: %p, data: %p, datalen:%lu\n", pgraph, pdata, currlen);
    if(hfa_os_likely(pgraph && pdata && currlen && consumed)){
        *consumed =0;
        inputlen = currlen;
        for(cntr=0; (cntr < pgraph->ninfo) && (inputlen >0); cntr++){

            pibuf = &(pgraph->pibuf[cntr]);
            if(pibuf->size == pibuf->submittedsz){
                continue;
            } else {
                pendinglen = pibuf->size - pibuf->submittedsz; 
                adjustlen = (inputlen >= pendinglen) ? pendinglen: inputlen;
                hfa_dbg("Info[%d]: PendingCopy: %ld, CurrCopying: %ld\n",
                                               cntr, pendinglen,adjustlen);
                memcpy(pibuf->ptr + pibuf->submittedsz, pdata, adjustlen);
                pibuf->submittedsz += adjustlen;

                /*consumedlen*/
                *consumed += adjustlen;
                inputlen  -= adjustlen;
                hfa_dbg("consumed: %u, Pending: %u\n", *consumed, inputlen);
                retval = HFA_SUCCESS;
            }
            /*If Info copy is completed then read timestamp*/
            if(pibuf->size == pibuf->submittedsz){

                /*Do Info Time stamp parsing*/
                pibuf = &(pgraph->pibuf[cntr]);
                ptstamp = (ppdfa_tstamp_t *)((char *)pibuf->ptr + 
                        (pibuf->size - sizeof(ppdfa_tstamp_t)));
                hfa_dbg("pibuf->ptr: %p, pibuf->size: %u, ptstamp: %p\n", 
                         pibuf->ptr, pibuf->size, ptstamp);
                memcpy(&l_tstamp, ptstamp, sizeof(ppdfa_tstamp_t));

                pu64 = (uint64_t *)&l_tstamp;
                *pu64 = hfa_os_le64toh(*pu64);
                pu64++;
                pu32 = (uint32_t *)pu64;
                *pu32 = hfa_os_le32toh(*pu32);
                pu32 ++;
                *pu32 = hfa_os_le32toh(*pu32);
                pu32 ++;
                *pu32 = hfa_os_le32toh(*pu32);
                pu32 ++;
                
                hfa_tools_version_to_string(&(l_tstamp.version), str,
                                              sizeof str);
                /*Validate PP library version + Graph version*/
                if(hfa_os_unlikely(strncmp(hfa_pp_ver,str,strlen(hfa_pp_ver)))){
                    hfa_err(CVM_HFA_EGRAPHVER,("Info %u timestamp version %s "\
                       "mismatch with PP Library\n", cntr, str));
                    return HFA_FAILURE;
                }
                if((l_tstamp.options.dfa != HFA_GET_GRAPHATTR(pgraph,dfa)) ||
          (l_tstamp.options.memonly != HFA_GET_GRAPHATTR(pgraph,memonly))||
          (l_tstamp.options.strings != HFA_GET_GRAPHATTR(pgraph,strings))||
          (l_tstamp.options.cachealgo != HFA_GET_GRAPHATTR(pgraph,cachealgo))||
          (l_tstamp.options.linkable != HFA_GET_GRAPHATTR(pgraph,linkable))||
          (l_tstamp.options.linked != HFA_GET_GRAPHATTR(pgraph,linked))){
                    hfa_err(CVM_HFA_EGRAPHVER, ("Info %d Timestamp does not"\
                        " match with Graph Hdr\n", cntr));
                    return HFA_FAILURE;
                }
                if(HFA_GET_GRAPHATTR(pgraph, dfa)){
                    hfa_dbg("Setting PPDFA function pointers\n");
                    ppdfa_initinfo((ppdfa_infort_t *)&(pgraph->irt[cntr]), 
                                    (pgraph->pibuf[cntr]).ptr);
                } else {
                    hfa_dbg("Setting PP function pointers\n");
                    ppinitinfo(&(pgraph->irt[cntr]), (pgraph->pibuf[cntr]).ptr);
                }
                pgraph->irt[cntr].base = pgraph->pibuf[cntr].ptr;
                break;
            }
        }
        cntr = (pgraph->ninfo -1);
        pibuf = &(pgraph->pibuf[cntr]);

        if((cntr == (pgraph->ninfo-1)) && 
           (pibuf->size == pibuf->submittedsz)){ 
           
           /*Mark that whole graph is comsumed here*/
           *consumed = currlen;

            /*Change state to next state*/
            pgraph->state=(hfa_mload_sm[ishfamem][pgraph->gtype][pgraph->state])
                              .next_state;
             hfa_dbg("Pgraph: %p Changing state to 0x%x\n", 
                            pgraph, pgraph->state);
        }
    }
    return (retval);
}
/**@endcond*/
/**
 * This routine initializes a graph object which can be used to perform various
 * operations on a graph file. A graph is a file produced by compiling a list
 * of patterns using @ref hfa_compiler "hfac". The graph operations are:
 * -# Download the Graph into HFA Memory(designated or reserved) using
 * hfa_graph_memload_data().
 * -# Load the cache-portion of the graph into a HFA cluster cache using
 * hfa_graph_cacheload().
 * -# Unload a graph from HFA cluster cache using hfa_graph_cacheunload().
 * -# Remove a graph from HFA Memory using hfa_dev_graph_cleanup().
 *
 * The cleanup counterpart for this routine is hfa_dev_graph_cleanup().
 * This routine must be called before any other API associated with graphs.
 *
 * @param   pdev    Pointer to device
 * @param   pgraph  Pointer to graph
 *
 * @return  HFA_FAILURE when failure, HFA_SUCCESS otherwise
 */
hfa_return_t 
hfa_dev_graph_init (hfa_dev_t *pdev, hfa_graph_t *pgraph)
{
    hfa_dbg("pdev: %p, pgraph: %p\n", pdev, pgraph);
    if(hfa_os_unlikely (HFA_DEV_INITDONE != hfa_isdevinit)){
        hfa_err(CVM_HFA_EDEVINITPEND,("hfa_dev_init() not performed\n"));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely((NULL == pdev) || (NULL == pgraph))) {
        hfa_err(CVM_HFA_EINVALARG, ("Null pointer %p, %p\n", pdev, pgraph)); 
        return HFA_FAILURE;
    }
    /*Check if graph is already initialized*/
    if(hfa_os_unlikely (HFA_GRAPH_INITDONE == pgraph->isinit)){
        hfa_err(CVM_HFA_EGEXIST, ("Graph already initalized\n")); 
        return HFA_FAILURE;
    }
    memset (pgraph, 0, sizeof (hfa_graph_t));
    hfa_os_rwlockinit (&pgraph->lock);
    hfa_os_wlock (&pgraph->lock);
    pgraph->pdev   = pdev;
    pgraph->isinit = HFA_GRAPH_INITDONE;
    /*By default setting triggersz as 64k*/
    pgraph->mload_triggersz = 0x10000;
    pgraph->state = HFA_GRAPH_INITIAL;
    hfa_os_wunlock (&pgraph->lock);
    return HFA_SUCCESS;
}
/**
 * This routine is the counterpart of hfa_dev_graph_init(). No graph API should
 * be called after calling this API on the graph object.
 *
 * See hfa_dev_graph_init() for more information on graphs.
 *
 * @param   pdev    pointer to device
 * @param   pgraph  pointer to graph
 *
 * @return  hfa_success if cleanup successful, hfa_failure otherwise
 */
hfa_return_t 
hfa_dev_graph_cleanup (hfa_dev_t *pdev, hfa_graph_t *pgraph)
{
    hfa_dbg("pdev: %p, pgraph: %p\n", pdev, pgraph);
    if (hfa_os_unlikely(NULL == pdev) || hfa_os_unlikely(NULL == pgraph)) {
        hfa_err(CVM_HFA_EINVALARG, ("Null pointer %p, %p\n", pdev, pgraph)); 
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_GRAPH_INITDONE != pgraph->isinit)){
        hfa_err(CVM_HFA_ENOPERM, ("Graph cleanup before init not allowed\n")); 
        return HFA_FAILURE;
    }
    hfa_os_rwlockdestroy(&pgraph->lock);
    hfa_graph_mload_destroy_mbufs(pgraph);
    hfa_mload_objcleanup(pgraph);
    hfa_mload_firstchunk_cleanup(pgraph);
    memset (pgraph, 0, sizeof (hfa_graph_t));
    return HFA_SUCCESS;
}
/**
 * This routine sets the cluster-mask for the graph. The cluster-mask is used
 * by hfa_graph_cacheload_async()/ hfa_graph_cacheload() routines to determine
 * which HFA clusters will cache the graph.
 *
 * See hfa_dev_graph_init() and hfa_cluster_init() for more information.
 *
 * @param   pgraph  pointer to graph
 * @param   clmsk  bitmask, each bit indicating cluster
 *
 * @return  HFA_SUCCESS if cluster is set, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_graph_setcluster (hfa_graph_t *pgraph, uint32_t clmsk)
{
    hfa_dbg("pgraph: %p, clmsk: 0x%x\n", pgraph, clmsk);
    if(hfa_os_unlikely((NULL == pgraph) || (!clmsk) || 
                       (clmsk > hfa_get_max_clmsk()))){
        hfa_err(CVM_HFA_EINVALARG, ("pgraph: %p, clmsk 0x%x\n", pgraph, clmsk));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_GRAPH_INITDONE != pgraph->isinit)){
        hfa_err(CVM_HFA_EGINITPEND, ("graph %p init pending\n", pgraph));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_GRAPH_INITIAL != pgraph->state)){
        hfa_err(CVM_HFA_EGINVAL_STATE, 
               ("Invalid graph state: 0x%x\n", pgraph->state));
        return HFA_FAILURE;
    }

    hfa_os_wlock (&pgraph->lock);
    pgraph->clmsk = clmsk;
    pgraph->state = HFA_GRAPH_CLMSK_SET;
    hfa_os_wunlock (&pgraph->lock);
    return HFA_SUCCESS;
}
/**
 * This is a utility routine which application can use in order to flush graph
 * file data to HFA memory. The @b size argument dictates how much of the graph
 * data is accumulated (in chunks) by the HFA SDK before it is actually
 * downloaded to HFA memory using the @ref CVMX_HFA_ITYPE_MEMLOAD HFA command.
 * The default is 64KB. It can be increased or reduced but needs to maintain
 * the device-specific alignment(currently 1KB for 63XX/66XX). The upper limit
 * is @ref HFA_NONIOVEC_MAX_MEMLOADSZ, which is the HFA engine limit for a
 * single @ref CVMX_HFA_ITYPE_MEMLOAD operation. 
 *
 * The hfa_graph_setcluster() routine should be called before calling this API.
 * This routine should not be called after calling
 * hfa_graph_memload_data_async()/ hfa_graph_memload_data() routines.
 *
 * This routine is applicable only for devices which use designated HFA
 * memory(63XX and 66XX). See hfa_dev_graph_init(), hfa_cluster_init(),
 * hfa_graph_memload_data() for more information.
 *
 * @param   pgraph  pointer to graph
 * @param   size    Aligned size
 *
 * @return  HFA_SUCCESS if triggersize is allowed to se, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_graph_setmemloadtrigger (hfa_graph_t *pgraph, hfa_size_t size)
{
    hfa_dbg("pgraph: %p, size: %lu\n", pgraph, size);

    if(hfa_os_likely(size && size <= HFA_NONIOVEC_MAX_MEMLOADSZ)){
        if(hfa_os_unlikely(HFA_SUCCESS != 
                    hfa_graph_validate(pgraph, HFA_GRAPH_CLMSK_SET))){
            hfa_err(CVM_HFA_EINVALARG,("Graph %p validation fails\n", pgraph));
            return HFA_FAILURE;
        }
        if(hfa_os_unlikely(HFA_IS_MEM_NOT_ALIGNED(size))){
            hfa_err(CVM_HFA_EALIGNMENT, ("size is not aligned to 0x%lx\n",
                        hfa_get_mem_align()));
            return HFA_FAILURE;
        }
        hfa_os_wlock(&pgraph->lock);
        pgraph->mload_triggersz = size;
        hfa_os_wunlock(&pgraph->lock);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine downloads graph data to the HFA engine in a non-blocking
 * manner. The graph data is typically a chunk of a graph file. The routine
 * parses the graph file for validation and then segregates the file into
 * @b cache, @b memory and/or @b info portions transparently. It will attempt
 * to download the memory portion of the graph onto the HFA engine. In case of
 * 63XX/61XX, which use designated HFA memory, the memory-download operation is
 * performed using the @ref CVMX_HFA_ITYPE_MEMLOAD HFA command. On 61XX/68XX,
 * the memory-download is a transfer of the memory-portion to the reserved HFA
 * memory.
 *
 * The routine will accumulate chunks of graph data as part of its segregation.
 * This allows large graphs to be downloaded in an iterative manner and thus
 * avoid exhorbitant memory usage.
 *
 * Since this routine is non-blocking, the application should check for the
 * status of the graph download using hfa_graph_getstatus().
 *
 * On the 63XX/66XX, the hfa_graph_setmemloadtrigger() routine can be used to
 * control at what size accumulated chunks will be downloaded to HFA memory by
 * issuing @ref CVMX_HFA_ITYPE_MEMLOAD HFA command. The default is 64KB. If the
 * chunk size (datalen) is greater than the size set in
 * hfa_graph_setmemloadtrigger(), hfa_graph_memload_data_async() will return
 * HFA_FAILURE.
 *
 * Once the entire graph file has been memload'ed using this routine, the graph
 * can be cacheload'ed using hfa_graph_cacheload(), if it is cacheable. It can
 * then be used to perform searches. Refer to hfa_searchctx_setgraph() for more
 * details.
 *
 * @param   pgraph      Pointer to the graph
 * @param   data        Pointer to the data chunk
 * @param   datalen     Size of the datalen 
 *
 * @return HFA_SUCCESS, if data buffer consumed, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_graph_memload_data_async(hfa_graph_t *pgraph, uint8_t *data,
                             hfa_size_t datalen)
{
    hfa_size_t          curr_dlen = datalen;
    uint8_t             *curr_data = data;
    hfa_size_t          consumedlen;
    hfa_graphstatus_t   status = CVM_HFA_EAGAIN;

    hfa_dbg("pgraph: %p, data: %p, datalen:%lu\n", pgraph, data, datalen);

    if(hfa_os_unlikely(NULL == data) || (!datalen)) {
        hfa_err(CVM_HFA_EINVALARG, 
                ("Null ptr data: %p, datalen: %lu\n", data, datalen)); 
        return HFA_FAILURE;
    }
#ifdef HFA_STRICT_CHECK
    if(datalen > HFA_NONIOVEC_MAX_MEMLOADSZ){
        hfa_err(CVM_HFA_E2BIG,
               ("Too Big Memload len %lu MB\n", (datalen/(1024*1024))));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != 
                       hfa_graph_validate(pgraph, pgraph->state))){
        hfa_err(CVM_HFA_ENOPERM, 
                ("Validation for pgraph: %p fails\n", pgraph));
        return HFA_FAILURE;
    }
#endif    
    ishfamem = hfa_dev_haspvt_hfamemory(pgraph->pdev);
    alignment = hfa_get_mem_align();

    hfa_os_wlock(&pgraph->lock);
    while (curr_dlen > 0){
        if(hfa_os_likely (pgraph->state < HFA_MAX_GRAPHSTATES)){
            consumedlen = 0;
            hfa_dbg("GraphSeek: %lu, Pending: %ld, Currlen: %lu\n", 
                    pgraph->curr_seek, (long long int)(pgraph->totlen - pgraph->curr_seek), 
                    curr_dlen);
            if(HFA_SUCCESS != 
                 ((hfa_mload_sm[ishfamem][pgraph->gtype][pgraph->state]).hndlr)
                    (pgraph, curr_data, curr_dlen, &consumedlen)){
                hfa_err(CVM_HFA_EMLOAD, ("Failure returned: type: 0x%x, "\
                            "state: 0x%x\n",pgraph->gtype, pgraph->state));
                hfa_os_wunlock(&pgraph->lock);
                return HFA_FAILURE;
            }
            if((HFA_GRAPH_MEM_SKIPLEN == pgraph->state) && !consumedlen){
                hfa_graph_getstatus(pgraph, &status);
            }
            hfa_dbg("Consumedlen: %lu\n", consumedlen);
            curr_data += consumedlen;
            pgraph->curr_seek += consumedlen;
            curr_dlen -= consumedlen;
        }
    }
    hfa_os_wunlock(&pgraph->lock);
    return HFA_SUCCESS;  
}
/**
 * This routine downloads graph data to the HFA engine in a blocking
 * manner. The routine is identical to hfa_graph_memload_data_async() in
 * behaviour, except it busy-waits for completion of any memory-load
 * operations(performed using @ref CVMX_HFA_ITYPE_MEMLOAD HFA command).
 * 
 * @param   pgraph      Pointer to the graph
 * @param   data        Pointer to the data chunk
 * @param   datalen     Size of the datalen 
 *
 * @return HFA_SUCCESS, if data buffer consumed, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_graph_memload_data (hfa_graph_t *pgraph, uint8_t *data, hfa_size_t datalen)
{
    uint32_t    status=0;

    if(hfa_os_unlikely(HFA_SUCCESS != 
        hfa_graph_memload_data_async(pgraph, data, datalen))){
        hfa_err(CVM_HFA_EMLOAD, ("memload failure: %p\n", pgraph));
        return HFA_FAILURE;
    }
    do {
        if(hfa_os_unlikely(HFA_SUCCESS != 
            hfa_graph_getstatus(pgraph, &status))){
            hfa_err(CVM_HFA_EMLOAD,("hfa_graph_getstatus Err:0x%x\n", status));
            return HFA_FAILURE;
        }
    }while (CVM_HFA_EAGAIN == status);
    
    return HFA_SUCCESS;
}
/**
 * This routine is used to cacheload a cacheable graph in a non-blocking manner.
 * The graph should have been fully memload'ed using
 * hfa_graph_memload_data_async()/ hfa_graph_memload_data(). The application
 * should check that the graph is cacheable using @b memonly attribute obtained
 * using HFA_GET_GRAPHATTR(). If the @b memonly attribute is set, then the graph
 * is not cacheable. Otherwise it can be loaded into the HFA clusters using this
 * routine. 
 *
 * The graph is cacheload'ed using the @ref CVMX_HFA_ITYPE_CACHELOAD HFA
 * command. The clusters for the command should be specified using
 * hfa_graph_setcluster(). Since this routine is non-blocking, the application
 * should check for the status of the cacheload-operation using
 * hfa_graph_getstatus(). Once the graph is cacheload'ed, it can used for
 * pattern searches. Refer to hfa_searchctx_setgraph() for more details.
 *
 * The amount of cache is limited in the HFA clusters. So an application can
 * selectively cacheload graphs and ration the cache among multiple graphs. In
 * order to so the graphs should be cacheload'ed and cacheunload'ed on a
 * need-basis. A graph can be cacheunload'ed using
 * hfa_graph_cacheunload_async()/ hfa_graph_cacheunload()
 * 
 * @param   pgraph      Pointer to the graph
 *
 * @return HFA_SUCCESS  if CLOAD instruction submitted with success
 *         HFA_FAILURE  otherwise
 */
hfa_return_t
hfa_graph_cacheload_async (hfa_graph_t *pgraph)
{
    hfa_clmsk_t         bitmsk;
    hfa_cluster_t       *pclust = NULL;
    hfa_graph_clbuf_t   *pclbuf = NULL;
    hfa_size_t          cbasesz, tsz;
    hfa_snode_t         snode;
    hfa_instr_t         instr;
    int                 _i, _cl;
    cvmx_wqe_t          *wqe = NULL;
    hfa_wqe_pktdata_overload_t   *pktdata = NULL;
  
    hfa_dbg("pgraph: %p\n", pgraph);

    if(hfa_os_unlikely(HFA_SUCCESS != 
                      hfa_graph_validate(pgraph, HFA_GRAPH_CLOAD_PENDING))){
        hfa_err(CVM_HFA_ENOPERM, ("No permissin for cacheload\n"));
        return HFA_FAILURE;
    }
    switch(pgraph->nobj){
        case 0:
        case 1:
        case 2:
            hfa_log("Warning !! Graph is Memonly, Cacheload not allowed\n");
            return HFA_SUCCESS;
        break;

        default:
            /*Do Nothing*/
        break;
    }
    
    hfa_os_wlock(&pgraph->lock);

    if(hfa_os_unlikely(pgraph->submittedinstr_clmsk)){
        hfa_err(CVM_HFA_EHWBUSY, 
            ("instruction pending clmsk: 0x%x\n", pgraph->submittedinstr_clmsk));
        hfa_os_wunlock(&pgraph->lock);
        return HFA_FAILURE;
    }
    snode.u64 = pgraph->irt[0].snode;
    cvm_hfa_instr_init (&instr, CVMX_HFA_ITYPE_CACHELOAD);
    cvm_hfa_instr_setle (&instr, 0);
    cvm_hfa_instr_setgather (&instr, 0);
    cvm_hfa_instr_setdsize (&instr, snode.s.ndnodes);
    cvm_hfa_instr_setdptr (&instr, ptr_to_phys(pgraph->cbuf.ptr));

    tsz = pgraph->cbuf.size;
    cvm_hfa_instr_setrmax (&instr, (tsz >> 16) & 0x7);
    cvm_hfa_instr_setdlen (&instr, tsz  & 0xffff);
    if(snode.s.zerobdn){
        cvm_hfa_instr_setf4 (&instr, 0);
    } else {
        cvm_hfa_instr_setf4 (&instr, snode.s.nbdnodes + 1);
    }
    
    bitmsk = pgraph->clmsk;
    pclbuf = (pgraph->clinfo).pclustbuf;
    HFA_FOREACHBIT_SET(bitmsk){
#ifdef HFA_GRAPH_ALLOC_RMDATA_DYN
        if(pclbuf[_i].rmdata){
            hfa_err(CVM_HFA_EMEMEXIST, ("rmdata already there cl: %d\n", _i)); 
            return HFA_FAILURE;
        }
        if(hfa_os_unlikely(NULL == 
            (pclbuf[_i].rmdata = hfa_os_malloc(HFA_RMDATA_SIZE)))){
            hfa_err(CVM_HFA_ENOMEM, ("rmdata allocation failed\n"));
            return HFA_FAILURE;
        }
#endif  
        /*memset rmdata*/
        hfa_dbg("pclbuf[_i].rmdata = %p\n",pclbuf[_i].rmdata);
        memset(pclbuf[_i].rmdata, 0, HFA_RMDATA_SIZE);
        
        pclust = NULL;
        hfa_get_cluster(pgraph->pdev, &pclust, _cl);

        /*Allocate pgid, dbase and cbase*/
        if(hfa_os_unlikely(HFA_SUCCESS !=  hfa_cluster_cachecalloc(pclust, 
                                    HFA_RAM3, 64, &(pclbuf[_i].pgid), 1))){
            hfa_err(CVM_HFA_EMEMLISTFULL, 
                 ("pgid allocation error cl: %d, _i: %d\n", _cl, _i));
            goto cacheload_free_pclustinfo;
        }

        if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_cachecalloc(pclust, 
                    HFA_RAM2, snode.s.ndnodes, &(pclbuf[_i].dbase), 1))){
            hfa_err(CVM_HFA_EMEMLISTFULL, ("dbase allocation error "\
            "cl: %d, _i: %d, ndnodes:%u\n", _cl, _i, snode.s.ndnodes));
            goto cacheload_free_pclustinfo;
        }
        cbasesz = tsz >> 3;
        cbasesz -= 32 + HFA_RNDUP2(snode.s.ndnodes);
        cbasesz = HFA_RNDUP2(cbasesz);
        if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_cachecalloc(pclust, 
                            HFA_RAM1, cbasesz, &(pclbuf[_i].cbase), 1))){
            hfa_err(CVM_HFA_EMEMLISTFULL, ("cbase allocation error "\
                  "cl: %d, _i: %d, cbasesz:%lu\n", _cl, _i, cbasesz));
            goto cacheload_free_pclustinfo;
        }
        /* Calculating vgid based on pgid of a cluster on which graph
         * loaded first as vgid should be unique for each graph. */ 
        pclbuf[_i].vgid = (HFA_CLUSTER_MAX_NGRAPHS * 
                          hfa_firstbit_setr[pgraph->clmsk]) + 
                          ((pclbuf[0].pgid) >> 6); 
       
        hfa_dbg("[%d] cl:%u, ndnodes: %u, cbasesz: %lu\n", 
                                     _i, _cl, snode.s.ndnodes, cbasesz);
        hfa_dbg("PGID: 0x%x, VGID: %d\n", (pclbuf[_i].pgid), pclbuf[_i].vgid);
        hfa_dbg("DBASE: 0x%x, CBASE: 0x%x\n", (pclbuf[_i].dbase),
                                                (pclbuf[_i].cbase));

        /*Submit instruction*/
        cvm_hfa_instr_setcbase(&instr, pclbuf[_i].cbase);
        cvm_hfa_instr_setdbase(&instr, pclbuf[_i].dbase);
        cvm_hfa_instr_setpgid(&instr, (pclbuf[_i].pgid)>>6);
        cvm_hfa_instr_setvgid(&instr, pclbuf[_i].vgid);
        cvm_hfa_instr_setrptr(&instr, ptr_to_phys(pclbuf[_i].rmdata));
        cvm_hfa_instr_setclmsk (&instr, 1 << _cl);
        cvm_hfa_instr_setwqptr(&instr, 0);
        wqe = pclbuf[_i].wqe; 
        if(wqe) {
            cvmx_wqe_set_unused8 (wqe, HFA_GRAPH_HWWQE_UNUSED_FIELD);
            pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data;
            pktdata->pgraph = (uint64_t)pgraph;
            pktdata->itype = (uint64_t)CVMX_HFA_ITYPE_CACHELOAD;
            pktdata->clno = (uint64_t)_cl;
            cvm_hfa_instr_setwqptr(&instr,(uint64_t)(ptr_to_phys(wqe)));
            hfa_graph_setwqe(pgraph, _cl, NULL);
        }
#ifdef HFA_DUMP
        hfa_dump_buf("cload", instr.u64, sizeof(cvmx_hfa_command_t));
#endif       

        hfa_dbg("Submitting for cload\n");
        if(hfa_os_unlikely(hfa_dev_submitasync(pgraph->pdev, &instr))){
            hfa_err(CVM_HFA_EHWERROR, ("hfa_dev_submitasync error\n"));
            goto cacheload_free_pclustinfo;
        }
        hfa_os_sync();
        HFA_GRAPH_PENDING_INSTR_INC(pclbuf[_i].pending_instr, cload);
        HFA_BITSET(pgraph->submittedinstr_clmsk, _cl);
    }
    hfa_os_wunlock(&pgraph->lock);
    return HFA_SUCCESS;

cacheload_free_pclustinfo:
    hfa_os_wunlock(&pgraph->lock);
    return HFA_FAILURE;    
}
/**
 * This routine is used to cacheload a cacheable graph in a blocking manner.
 * The routine is identical to hfa_graph_cacheload_async() in
 * behaviour, except it busy-waits for completion of the cacheload
 * operation(performed using @ref CVMX_HFA_ITYPE_CACHELOAD HFA command).
 * 
 * @param   pgraph      Pointer to the graph
 *
 * @return HFA_SUCCESS  if CLOAD instruction submitted with success
 *         HFA_FAILURE  otherwise
 */
hfa_return_t
hfa_graph_cacheload (hfa_graph_t *pgraph)
{
    uint32_t    status=0;

    if(hfa_os_unlikely(HFA_SUCCESS != hfa_graph_cacheload_async(pgraph))){
        hfa_err(CVM_HFA_ECLOAD, ("hfa_graph_cacheload_async() failure\n"));
        return HFA_FAILURE;
    }
    do {
        if(hfa_os_unlikely(HFA_SUCCESS !=hfa_graph_getstatus(pgraph, &status))){
            hfa_err(CVM_HFA_ECLOAD,("hfa_graph_getstatus Err:0x%x\n", status));
            return HFA_FAILURE;
        }
    }while(CVM_HFA_EAGAIN == status);
    return HFA_SUCCESS;
}
/**
 * This routine is used to cacheunload a cacheload'ed graph in a non-blocking
 * manner. The graph should have been previously cacheload'ed using
 * hfa_graph_cacheload_async()/ hfa_graph_cacheload(). The application should
 * ensure that there are no outstanding search operations on the graph before
 * cacheunload'ing it.
 *
 * The graph is cacheunload'ed using the @ref CVMX_HFA_ITYPE_GRAPHFREE HFA
 * command. The clusters for the command should be specified using
 * hfa_graph_setcluster(). Since this routine is non-blocking, the application
 * should check for the status of the cacheload-operation using
 * hfa_graph_getstatus(). Once the graph is cacheunload'ed, it can no longer be
 * used for pattern searches. It can be re-cacheload'ed using
 * hfa_graph_cacheload_async()/ hfa_graph_cacheload() to restore the search
 * capability.
 * 
 * @param   pgraph      Pointer to the graph
 *
 * @return HFA_SUCCESS  if GRAPHFREE instruction submitted with success
 *         HFA_FAILURE  otherwise
 */
hfa_return_t
hfa_graph_cacheunload_async (hfa_graph_t *pgraph)
{
    hfa_clmsk_t         bitmsk;
    hfa_instr_t         instr;
    hfa_graph_clbuf_t   *pclbuf = NULL;
    hfa_return_t        retval = HFA_SUCCESS;
    int                 _i, _cl;
    cvmx_wqe_t          *wqe = NULL;
    hfa_wqe_pktdata_overload_t  *pktdata = NULL;
 
    hfa_dbg("pgraph: %p\n", pgraph);
    
    if(hfa_os_unlikely(HFA_SUCCESS != 
                       hfa_graph_validate (pgraph, HFA_GRAPHLOAD_FINISH))){
        hfa_err(CVM_HFA_EGINVAL_STATE,("Graph: %p validation fails\n", pgraph));
        return HFA_FAILURE;
    }
    switch(pgraph->nobj){
        case 0:
        case 1:
            hfa_err(CVM_HFA_EBADFILE, ("Invalid nobjs: %d\n", pgraph->nobj));
            return HFA_FAILURE;
        break;
        case 2:
            hfa_log("Warning !!. Graph is memonly, Cacheunload not allowed\n");
            return HFA_SUCCESS;
        break;
        default:
            /*Do Nothing*/
        break;
    }
    
    pclbuf = (pgraph->clinfo).pclustbuf;
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely(NULL == pclbuf)){
        hfa_err(CVM_HFA_ENOPERM, ("pclusterbuf found NULL\n"));
        return HFA_FAILURE;
    }
#endif    

    hfa_os_wlock(&pgraph->lock);
    bitmsk = pgraph->cload_clmsk;
    HFA_FOREACHBIT_SET(bitmsk){
        memset(&instr, 0, sizeof(hfa_instr_t));
        cvm_hfa_instr_init(&instr, CVMX_HFA_ITYPE_GRAPHFREE);
#ifdef HFA_GRAPH_ALLOC_RMDATA_DYN
        if(pclbuf[_i].rmdata){
            hfa_err(CVM_HFA_EMEMEXIST, ("rmdata already there cl: %d\n", _i)); 
            return HFA_FAILURE;
        }
        if(NULL == (pclbuf[_i].rmdata = hfa_os_malloc(HFA_RMDATA_SIZE))){
            hfa_err(CVM_HFA_ENOMEM, ("rmdata allocation failed\n"));
            return HFA_FAILURE;
        }
#endif        
        hfa_dbg("idx = %d clno = %d\n", _i, _cl);
        /*memset rmdata*/
        memset(pclbuf[_i].rmdata, 0, HFA_RMDATA_SIZE);
        hfa_dbg("PGID: 0x%x, VGID: %d\n", (pclbuf[_i].pgid), pclbuf[_i].vgid);
        hfa_dbg("DBASE: 0x%x, CBASE: 0x%x\n", (pclbuf[_i].dbase), 
                                            (pclbuf[_i].cbase));
        cvm_hfa_instr_setrptr(&instr, ptr_to_phys(pclbuf[_i].rmdata));
        cvm_hfa_instr_setclmsk(&instr, 1 << _cl);
        cvm_hfa_instr_setvgid(&instr, pclbuf[_i].vgid);
#ifdef HFA_DUMP
        hfa_dump_buf("Gfree", instr.u64, sizeof(cvmx_hfa_command_t));
#endif       
        wqe = pclbuf[_i].wqe; 
        if(wqe) {
            cvmx_wqe_set_unused8 (wqe, HFA_GRAPH_HWWQE_UNUSED_FIELD);
            pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data;
            pktdata->pgraph = (uint64_t)pgraph;
            pktdata->itype = (uint64_t)CVMX_HFA_ITYPE_GRAPHFREE;
            pktdata->clno = (uint64_t)_cl;
            cvm_hfa_instr_setwqptr(&instr, (uint64_t)(ptr_to_phys(wqe)));
            hfa_graph_setwqe(pgraph, _cl, NULL);
        }

        hfa_dbg("Submitting for cunload\n");
        if(hfa_os_unlikely(hfa_dev_submitasync(pgraph->pdev, &instr))){
            retval = HFA_FAILURE;
        }
        hfa_os_sync();
        HFA_GRAPH_PENDING_INSTR_INC(pclbuf[_i].pending_instr, gfree);
        HFA_BITSET(pgraph->submittedinstr_clmsk, _cl);
    }
    hfa_os_wunlock(&pgraph->lock);
    return retval;
}
/**
 * This routine is used to cacheunload a cacheload'ed graph in a non-blocking
 * manner. The routine is identical to hfa_graph_cacheunload_async() in
 * behaviour, except it busy-waits for completion of the cacheunload
 * operation(performed using @ref CVMX_HFA_ITYPE_GRAPHFREE HFA command).
 *
 * @param   pgraph      Pointer to the graph
 *
 * @return HFA_SUCCESS  if GRAPHFREE instruction submitted with success
 *         HFA_FAILURE  otherwise
 */
hfa_return_t
hfa_graph_cacheunload (hfa_graph_t *pgraph)
{
    uint32_t    status =0;
    hfa_dbg("pgraph: %p", pgraph);
    
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_graph_cacheunload_async(pgraph))){
        return HFA_FAILURE;
    }
    do {
        if(hfa_os_unlikely(HFA_SUCCESS !=hfa_graph_getstatus(pgraph, &status))){
            hfa_err(CVM_HFA_EGFREE, 
                ("Failure from hfa_graph_getstatus(%p)\n", pgraph));
            return HFA_FAILURE;
        }
    }while (CVM_HFA_EAGAIN == status);

    return HFA_SUCCESS;
}
/** 
 * This routine is used to free the buffers and change the graph
 * load status after instruction completion on the cluster.
 *
 * @param   pgraph      Pointer to the graph
 * @param   itype       Instruction type
 * @param   clno        On which cluster instruction processed
 * @param   idx         pclbuf idx for the cluster
 *
 * @return HFA_SUCCESS/HFA_FAILURE  
 */ 
static inline hfa_return_t
__hfa_graph_processstatus(hfa_graph_t *pgraph, hfa_itype_t itype, 
                        int clno, int idx)
{
    hfa_graph_mbufptr_t *pmbuf = NULL;
    hfa_graph_clbuf_t   *pclbuf = NULL;
    hfa_cluster_t       *pclust = NULL;
    hfa_graph_pending_instr_t  *pendinstr = NULL;
    

    hfa_dbg("pgraph: %p itype %d clno %d idx %d\n", pgraph, itype, clno, idx);
    pclbuf = (pgraph->clinfo).pclustbuf;
    hfa_dbg("pclustbuf 0x%x", pclbuf);
    if(!HFA_ISBITSET(pgraph->submittedinstr_clmsk, clno)) {
        return HFA_SUCCESS;
    }
    pendinstr = pclbuf[idx].pending_instr;

    switch(itype){
        case CVMX_HFA_ITYPE_MEMLOAD:
#ifdef HFA_STRICT_CHECK
            if(!pendinstr->mload) {
                hfa_err(CVM_HFA_EHWERROR, 
                        ("invalid itype found: %u in memload\n", itype));
                return HFA_FAILURE;
            }
#endif              
            HFA_GRAPH_PENDING_INSTR_DEC(pendinstr, mload);
            pmbuf = (hfa_graph_mbufptr_t *)
                ((hfa_mload_rmdata_overload_t *)(pclbuf[idx].rmdata))->ptr;
            hfa_mload_destroy_mbuf(pgraph, pmbuf);

            hfa_dbg("Clearing memload pending status\n");
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
#ifdef HFA_STRICT_CHECK
            if(!pendinstr->cload) {
                hfa_err(CVM_HFA_EHWERROR, 
                        ("invalid itype found: %u in cacheload\n", itype));
                return HFA_FAILURE;
            }
#endif 
            HFA_GRAPH_PENDING_INSTR_DEC(pendinstr, cload);
            /*Once Cache load is completed do not free temp buffer 
             * for cache portion as user may do cacheload later for
             * same graph*/
            HFA_BITSET(pgraph->cload_clmsk, clno);
            /* Changing the graph state to FINISH if cload done on all clusters*/
            if(pgraph->cload_clmsk == pgraph->clmsk) 
                pgraph->state = HFA_GRAPHLOAD_FINISH;
            break;

        case CVMX_HFA_ITYPE_GRAPHFREE:
#ifdef HFA_STRICT_CHECK
            if(!pendinstr->gfree) {
                hfa_err(CVM_HFA_EHWERROR, 
                        ("invalid itype found: %u in cacheunload\n", itype));
                return HFA_FAILURE;
            }
#endif                
            HFA_GRAPH_PENDING_INSTR_DEC(pendinstr, gfree);
            /*Free pgid, dbase and cbase*/
            hfa_get_cluster(pgraph->pdev, &pclust, clno);
#ifdef HFA_STRICT_CHECK
            if(HFA_SUCCESS != hfa_cluster_isinit(pclust)){
                hfa_err(CVM_HFA_EINVAL_CLSTATE, 
                        ("cl: %p validation fails\n", pclust));
                return HFA_FAILURE;
            }
#endif                    
            hfa_dbg("Freeing clbuf for cl: %d\n", clno);
            hfa_dbg("PGID 0x%x DBASE: 0x%x, CBASE: 0x%x\n", (pclbuf[idx].pgid), 
                                    (pclbuf[idx].dbase), (pclbuf[idx].cbase));
            hfa_cluster_cachefree(pclust, HFA_RAM1, pclbuf[idx].cbase);
            hfa_cluster_cachefree(pclust, HFA_RAM2, pclbuf[idx].dbase);
            hfa_cluster_cachefree(pclust, HFA_RAM3, pclbuf[idx].pgid);
            pclbuf[idx].cbase=0;
            pclbuf[idx].dbase=0;
            pclbuf[idx].pgid=0;
            pclbuf[idx].vgid = -1;
            HFA_BITCLR(pgraph->cload_clmsk, clno);
            /*Change state even if one cluster among three has done cache unloaded*/
            if(pgraph->cload_clmsk != pgraph->clmsk)
                pgraph->state = HFA_GRAPH_CLOAD_PENDING;
            break;
        default:
            hfa_err(CVM_HFA_EHWERROR, ("Bad Itype returned from HW\n"));
            return HFA_FAILURE;
            break;
    }
    if(!pendinstr->cload && !pendinstr->gfree && !pendinstr->mload) 
        HFA_BITCLR(pgraph->submittedinstr_clmsk, clno);

#ifdef HFA_GRAPH_ALLOC_RMDATA_DYN
    hfa_os_free(pclbuf[idx].rmdata, HFA_RMDATA_SIZE);
    pclbuf[idx].rmdata = NULL;
#endif            
    return HFA_SUCCESS;
}
/**
 * This routine is used to check the status of the graph. A graph can be in
 * various states depending on the operation initiated on it. The list below
 * shows the different @b status values after invoking different graph API.
 *
 * @table
 * |@b After                       |@b status                                  |
 * |-------------------------------|-------------------------------------------|
 * |hfa_dev_graph_init()           |HFA_REASON_DDONE                           |
 * |hfa_graph_setcluster()         |HFA_REASON_DDONE                           |
 * |hfa_graph_memload_data_async() |CVM_HFA_EAGAIN if HFA command is pending OR|
 * |                               |A HFA reason code @ref cvm_hfa_reason_t    |
 * |hfa_graph_cacheload_async()    |CVM_HFA_EAGAIN if HFA command is pending OR|
 * |                               |A HFA reason code @ref cvm_hfa_reason_t    |
 * |hfa_graph_cacheunload_async()  |CVM_HFA_EAGAIN if HFA command is pending OR|
 * |                               |A HFA reason code @ref cvm_hfa_reason_t    |
 * |hfa_graph_memload_data()       |A HFA reason code @ref cvm_hfa_reason_t    |
 * |hfa_graph_cacheload()          |A HFA reason code @ref cvm_hfa_reason_t    |
 * |hfa_graph_cacheunload()        |A HFA reason code @ref cvm_hfa_reason_t    |
 * @endtable
 *
 * If this routine returns a @b status of @ref CVM_HFA_EAGAIN, it indicates that
 * a HFA command is still outstanding on the graph and hence the application
 * must recheck the status again using this API
 *
 * @param   pgraph      Pointer to the graph
 * @param   status      Pointer to the status,
 *                      Set to CVM_HFA_EAGAIN if retry required
 *                      otherwise set to valid graph_status
 *
 * @return HFA_SUCCESS  if graph_get_Status is successful
 *         HFA_FAILURE  otherwise
 */
hfa_return_t 
hfa_graph_getstatus (hfa_graph_t *pgraph, uint32_t *status)
{ 
    hfa_itype_t         itype = -1;
    hfa_clmsk_t         bitmsk;
    hfa_graph_clbuf_t   *pclbuf = NULL;
    int                 _i, _cl;

    hfa_dbg("pgraph %p, status: %p\n", pgraph, status);

#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely(NULL == status)){
        hfa_err(CVM_HFA_EINVALARG, ("Status found Null\n"));
        return HFA_FAILURE;
    }
#endif    
    if(hfa_os_unlikely(HFA_SUCCESS !=
                            hfa_graph_validate(pgraph, pgraph->state))){
        hfa_err(CVM_HFA_EINVALARG, ("Validation fails for %p\n", pgraph));
        return HFA_FAILURE;
    }
    *status = CVM_HFA_EAGAIN;
    if(!pgraph->submittedinstr_clmsk){
        *status = HFA_REASON_DDONE;
        return HFA_SUCCESS;
    }

    bitmsk = pgraph->clmsk;
    pclbuf = (pgraph->clinfo).pclustbuf;
    HFA_FOREACHBIT_SET(bitmsk){
        *status = hfa_dev_getasyncstatus(pgraph->pdev, pclbuf[_i].rmdata);
        hfa_os_sync();
        cvm_hfa_rslt_getitype(pclbuf[_i].rmdata, &itype);

        if(HFA_REASON_GDONE == *status){
            __hfa_graph_processstatus(pgraph, itype, _cl, _i);
        }
    }
    return HFA_SUCCESS;
}
/**
 * This is a utility routine which returns the savelen property of the graph.
 * This is useful for an application to determine how much back-buffer memory
 * must be preserved when using cross-packet matching. The back-buffer memory
 * is input data which must be preserved and supplied to
 * hfa_searchctx_getmatches() in order to look for NFA matches.
 *
 * @param   pgraph      Pointer to the graph
 * @param   len         Pointer to the len
 *
 * @return HFA_SUCCESS if fetch is succesfule, HFA_FAILURE otherwise
 */
hfa_return_t 
hfa_graph_getsavelen (hfa_graph_t *pgraph, int *len)
{
    hfa_dbg("pgraph: %p, len: %p\n", pgraph, len);
    if(hfa_os_likely(pgraph && len)){
        if(hfa_os_unlikely(HFA_SUCCESS != hfa_graph_validate(pgraph, 
                                                      HFA_GRAPHLOAD_FINISH))){
            hfa_err(CVM_HFA_ENOPERM, 
                ("Savelen can't be fetched for unloaded graph: %p\n",pgraph));
            return HFA_FAILURE;
        }
        *len = (pgraph->info).savelen;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine provides the number of subgraphs in a linked graph. A linked
 * graph is created by linked 2 or more graphs using @ref hfa_linker. This
 * routine will typically be used to extract a certain subgraph using
 * hfa_graph_getsubgraph(). If @b *ngraphs is returned as 1, then the graph is
 * not a linked graph. This routine should be called after the graph has
 * been memload'ed and/ or cacheload'ed using hfa_graph_memload_data() and
 * hfa_graph_cacheload() respectively.
 *
 * @param   pgraph      Pointer to the graph
 * @param   ngraphs     Pointer containing graph count
 *
 * @return HFA_SUCCESS if graph is loaded, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_graph_getgraph_count(hfa_graph_t *pgraph, uint32_t *ngraphs)
{
    if(hfa_os_likely(ngraphs)){
        if(hfa_os_unlikely(HFA_SUCCESS != hfa_graph_validate(pgraph, 
                                            HFA_GRAPHLOAD_FINISH))){
            hfa_err(CVM_HFA_ENOPERM, 
                   ("Graph count can be fetched after successful graphload\n"));
            return HFA_FAILURE;
        }
        *ngraphs = pgraph->ngraphs;
        return HFA_SUCCESS;            
    }
    return HFA_FAILURE;
}
/**
 * This routine returns a subgraph of a linked graph. The subgraph can be used
 * to perform searches. The @b graphno is a range from @b 0 to @b *ngraphs-1
 * returned by hfa_graph_getgraph_count(). Refer to hfa_searchctx_setgraph() for
 * more details.
 *
 * @param   plinkgraph     Pointer to source linkgraph
 * @param   psubgraph      Pointer to destination subgraph
 * @param   graphno        Graph number within Linked graph 
 *
 * @return HFA_SUCCESS if graph is loaded, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_graph_getsubgraph(hfa_graph_t *plinkgraph, hfa_graph_t *psubgraph, 
                             uint32_t graphno)
{
    hfa_dbg("plinkgraph: %p, psubgraph: %p, graphno: %u\n", 
                             plinkgraph, psubgraph, graphno);
    if(hfa_os_likely(plinkgraph && psubgraph)){
        if(HFA_SUCCESS != hfa_graph_validate(plinkgraph,HFA_GRAPHLOAD_FINISH)){
            hfa_err (CVM_HFA_EGRAPH, ("Invalid Graph %p\n", plinkgraph));
            return HFA_FAILURE;
        }
        if(plinkgraph->ngraphs < graphno){
            hfa_err(CVM_HFA_ENOPERM, ("Graph contains %u subgraphs, Invalid "\
                    "subgraph %u tried\n", plinkgraph->ngraphs, graphno));
            return HFA_FAILURE;
        }
        /*Make copy of the graph*/
        memcpy(psubgraph, plinkgraph, sizeof(hfa_graph_t));

        /*Separately reset data members of sub graph*/
        HFA_OS_LISTHEAD_INIT(&psubgraph->list);

        /*Subgraph lock should share lock with Linked graph due to  
         * hfa_graph_clbuf_t data strucutes*/
        //hfa_os_rwlockinit(&psubgraph->lock);
        
        /*Sub graph is not a Linked graph*/
        psubgraph->info.flags = 0;
        
        if(HFA_GET_GRAPHATTR(plinkgraph, memonly)){
            psubgraph->gtype = HFA_GRAPH_MEMONLY;
            psubgraph->nobj=2;
        } else {
            psubgraph->gtype = HFA_GRAPH_MIXTYPE;
            psubgraph->nobj=3;
        }
        psubgraph->ninfo = 1;
        psubgraph->nirt = 1; 
        psubgraph->ngraphs = 1; 

        /*Allocate pibuf and irt*/
        psubgraph->pibuf = NULL;
        psubgraph->irt = NULL;
        if(hfa_os_unlikely(NULL == (psubgraph->pibuf = 
            hfa_os_memoryalloc(HFA_GINFO_SIZE(psubgraph),128)))){
            hfa_err(CVM_HFA_ENOMEM, ("pibuf allocation failure\n"));
            return HFA_FAILURE;
        }
        /* Allocate ppinfo buffer for all graphs (irt)*/
        if(hfa_os_unlikely(NULL ==(psubgraph->irt = 
            hfa_os_memoryalloc(HFA_GPPINFO_SIZE(psubgraph), 128)))){
            hfa_err(CVM_HFA_ENOMEM, ("ppinfoirt allocation failure\n"));
            hfa_os_memoryfree(psubgraph->pibuf, HFA_GINFO_SIZE(psubgraph));
            return HFA_FAILURE;
        }  

        /*Memcpy pibuf from linked graph to subgraph*/
        memcpy(psubgraph->pibuf, &(plinkgraph->pibuf[graphno]), 
                                    sizeof(hfa_graphchunk_t));
        /*Memcpy ppinfo from linked graph to subgraph*/
        memcpy(psubgraph->irt, &(plinkgraph->irt[graphno]), sizeof(ppinfo_t)); 
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine sets WQE field in graph data structure.
 * WQE has to be provided if WQE based ASYNC graph load used.
 *  
 * @param   pgraph     Pointer to graph
 * @param   wqe        Pointer to wqe
 * @param   clno       cluster number 
 *   
 * @return  HFA_SUCCESS if pgraph is not NULL, 
 *           HFA_FAILURE otherwise
 */
hfa_return_t 
hfa_graph_setwqe(hfa_graph_t *pgraph, int clno, cvmx_wqe_t *wqe)
{   
    hfa_graph_clbuf_t   *pclbuf = NULL;
    int                 idx = 0;
   
#ifdef HFA_STRICT_CHECK 
    if(hfa_os_unlikely(NULL == pgraph)) {
        hfa_err(CVM_HFA_EINVALARG, ("Null ptr pgraph: %p\n", pgraph));
        return (HFA_FAILURE);
    }
    if(hfa_os_unlikely(HFA_ISBITCLR(pgraph->clmsk, clno))) {
        hfa_err(CVM_HFA_ENOPERM, ("Cluster %d is not set in Graph ClMsk"
                    " 0x%x\n", clno, pgraph->clmsk));
        return HFA_FAILURE;
    }
#endif        
    /* Do not check for NULL == WQE as Application
     * can reset the value using hfa_graph_setwqe(pgraph,0)
     */
    pclbuf = (pgraph->clinfo).pclustbuf;
    idx = hfa_pclbuf_idx[clno][pgraph->clmsk]; 
    if(pclbuf) {
        pclbuf[idx].wqe = wqe;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/*
 * This routine handles HFA WQE posted by HFA engine to indicate 
 * GRAPH LOAD instruction completion. 
 *
 * @param   wqe         pointer to WQE received from HFA HW
 * @param   ppgraph     pointer to pgraph
 * 
 * return HFA_SUCCESS /HFA_FAILURE
 */
hfa_return_t
hfa_graph_processwork(cvmx_wqe_t *wqe, hfa_graph_t **ppgraph)
{

    hfa_wqe_pktdata_overload_t  *wqe_pkt = NULL;
    hfa_itype_t                 itype = -1;
    int                         idx = 0, clno = 0;
    hfa_graph_t                 *pgraph = NULL;

    if(hfa_os_likely(wqe && ppgraph)) {
        wqe_pkt = (hfa_wqe_pktdata_overload_t *)(wqe->packet_data);
        pgraph = (hfa_graph_t *) wqe_pkt->pgraph;
        hfa_dbg("pgraph: 0x%x\n", pgraph);
        if(hfa_os_unlikely(NULL == pgraph)) {
            hfa_err(CVM_HFA_EGRAPH,
                   ("Graph ptr in WQE found NULL %p\n", pgraph));
            return HFA_FAILURE;
        }
        *ppgraph = pgraph;
        itype = (hfa_itype_t)wqe_pkt->itype;
        clno = (int)wqe_pkt->clno;
        idx = hfa_pclbuf_idx[clno][pgraph->clmsk]; 
       
        __hfa_graph_processstatus(pgraph, itype, clno, idx);
       
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine returns pending instructions(MLOAD, CLOAD, GFREE) 
 * on given cluster.  
 *
 * @param       pgraph       pointer to graph
 * @param       clno         cluster number
 * @param       ppendinstr   API returns all pending instrunctions on the graph 
 *                           cluster through this pointer.
 *
 * @return  whether any instructions pending on given cluster or not.
 */
hfa_bool_t 
hfa_graph_is_instr_pending(hfa_graph_t *pgraph, int clno, 
                           hfa_graph_pending_instr_t **ppendinstr)
{
    hfa_graph_pending_instr_t   *pendinstr = NULL;
    hfa_graph_clbuf_t           *pclbuf = NULL;
    int                         idx = 0;

#ifdef ADD_THIS_CODE
    if(hfa_os_unlikely(NULL == pgraph || NULL == ppendinstr)) {
        hfa_err(CVM_HFA_EINVALARG,
               ("NULL Ptrs pgraph: %p ppendinstr:%p\n", pgraph, ppendinstr));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_ISBITCLR(pgraph->clmsk, clno))) {
        hfa_err(CVM_HFA_ENOPERM, ("Cluster %d is not set in Graph ClMsk"
                    " 0x%x\n", clno, pgraph->clmsk));
        return HFA_FAILURE;
    }
#endif
    pclbuf = (pgraph->clinfo).pclustbuf;

#ifdef ADD_THIS_CODE
    if(hfa_os_unlikely(NULL == pclbuf)) {
        hfa_err(CVM_HFA_ENOPERM, ("pclbuf found NULL\n"));
        return HFA_FAILURE;
    }
#endif
    idx = hfa_pclbuf_idx[clno][pgraph->clmsk]; 
    
    pendinstr = pclbuf[idx].pending_instr;
    *ppendinstr = pendinstr;

    /*Return most frequent used instruction first. Even if all types of 
     * instructions are pending*/
    return ((pendinstr->gwalk) || 
            (pendinstr->cload) ||
            (pendinstr->gfree) ||
            (pendinstr->mload));
}
/**@cond INTERNAL*/
#ifdef KERNEL
EXPORT_SYMBOL (hfa_dev_graph_init);
EXPORT_SYMBOL (hfa_dev_graph_cleanup);
EXPORT_SYMBOL (hfa_graph_setcluster);
EXPORT_SYMBOL (hfa_graph_memload_data);
EXPORT_SYMBOL (hfa_graph_memload_data_async);
EXPORT_SYMBOL (hfa_graph_cacheload);
EXPORT_SYMBOL (hfa_graph_cacheload_async);
EXPORT_SYMBOL (hfa_graph_cacheunload);
EXPORT_SYMBOL (hfa_graph_cacheunload_async);
EXPORT_SYMBOL (hfa_graph_getstatus);
EXPORT_SYMBOL (hfa_graph_getgraph_count);
EXPORT_SYMBOL (hfa_graph_getsubgraph);
EXPORT_SYMBOL (hfa_graph_getsavelen);
EXPORT_SYMBOL (hfa_graph_setwqe);
EXPORT_SYMBOL (hfa_graph_processwork);
EXPORT_SYMBOL (hfa_graph_is_instr_pending);
#endif
/**@endcond*/
