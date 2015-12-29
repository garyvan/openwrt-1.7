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
 * This file contains APIs to initialize, configure and cleanup Search 
 * Context which are used to perform HFA pattern search.
 *
 */
#include "cvm-hfa-search.h"
#include "cvm-hfa-res.h"
#include "ppdfa.h"

/**@cond INTERNAL */
#define HFA_HW_RBUF_MIN_LEN     32
#define HFA_RPTR_RWORD0_SIZE    sizeof(cvm_hfa_rmdata_t)
#define HFA_RBUF_MIN_LEN        HFA_HW_RBUF_MIN_LEN + \
                                sizeof(hfa_rptr_reserve_t);

extern CVMX_SHARED uint64_t     hfa_isdevinit;
/**Hash array used to calculate cluster index (bit location from right)
 * in pgraph->clmsk*/
uint32_t    hfa_pclbuf_idx[HFA_MAX_NCLUSTERS][HFA_68XX_MAX_CLMSK +1] = {
 /*Clmsk: 0x0   0x1    0x2      0x3     0x4     0x5     0x6     0x7 */
/*Bit 0*/{-1,    0,     -1,      0,      -1,      0,     -1,      0},
/*Bit 1*/{-1,    -1,     0,      1,      -1,     -1,      0,      1},
/*Bit 2*/{-1,    -1,    -1,     -1,       0,      1,      1,      2}};
/**Array used to know which bit is set from right in clmsk range [0..7]*/
extern int hfa_firstbit_setr [8];
/**@endcond*/

/**
 * @cond INTERNAL
 * Validate Search Context
 *
 * @param   psctx       Pointer to Search Context
 * @param   pgraph      Pointer to Graph on which context to be configured
 * @param   ctx_status  Valid context status expected
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_searchctx_graph_validate (hfa_searchctx_t *psctx, hfa_graph_t *pgraph, 
                        hfa_searchctx_status_t ctx_status)
{
    uint32_t    temp_status=0;

    if(hfa_os_unlikely((NULL == psctx) || (NULL == pgraph))){
        hfa_err(CVM_HFA_EINVALARG, 
               ("Null ptrs psctx: %p, pgraph: %p\n", psctx, pgraph));
        return (HFA_FAILURE);
    }
#ifdef HFA_STRICT_CHECK    
    /*Check whether Search Ctx status is ok
     * Special case of PPUARG set, sctx can be submitted if either
     * ctx_status == HFA_SCTX_SGRAPH_SET or 
     * ctx_status == HFA_SCTX_SPPUARG_SET | HFA_SCTX_SGRAPH_SET*/
    temp_status = psctx->ctx_status;
    if(HFA_ISBITMSKSET(temp_status, HFA_SEARCHCTX_SPPUARG_SET)){
        HFA_BITMSKCLR(temp_status, HFA_SEARCHCTX_SPPUARG_SET);
    }
    if(hfa_os_unlikely(HFA_ISBITMSKCLR(temp_status, ctx_status))){
        hfa_err(CVM_HFA_EINVALSRCHSTATE, ("Ctx State Invalid - Found[%d]."
                    " Should be [%d]\n", temp_status, ctx_status));
        return (HFA_FAILURE);
    }
#endif    
    return (HFA_SUCCESS);
}
/**
 * Validate Search Parameters
 *
 * @param   psctx       Pointer to Search Context
 * @param   psparam     Pointer to Search Parameters
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_searchctx_sparams_validate(hfa_searchctx_t *psctx, 
                               hfa_searchparams_t *psparam)
{
    hfa_graph_t                 *pgraph = NULL;
    int                         i, cno, idx;
    uint8_t                     *ptr = NULL;
    hfa_graph_clbuf_t           *pclbuf = NULL;
    hfa_graph_pending_instr_t   *pendinstr = NULL;

    if(hfa_os_likely(psparam)){
        pgraph = psctx->pgraph;
        cno = psparam->clusterno;
        if(hfa_os_unlikely(cno != HFA_ANY_CLUSTER_SEARCH && 
                           HFA_ISBITCLR(pgraph->clmsk, cno))){
            hfa_err(CVM_HFA_ENOPERM, ("Cluster %d is not set in Graph ClMsk"
                    " 0x%x\n", psparam->clusterno, psctx->pgraph->clmsk));
            return HFA_FAILURE;
        }
        /*Graph should be completely loaded before submitting 
         *search instruction */
        if(cno == HFA_ANY_CLUSTER_SEARCH) {
            if(hfa_os_unlikely(HFA_GRAPHLOAD_FINISH != pgraph->state)){
                hfa_err(CVM_HFA_EGINVAL_STATE, 
                        ("GraphState: 0x%x, load pending\n", pgraph->state));
                return (HFA_FAILURE);
            }
        } else {
            idx = hfa_pclbuf_idx[cno][pgraph->clmsk]; 
            pclbuf = (pgraph->clinfo).pclustbuf;
            pendinstr = pclbuf[idx].pending_instr;
            if(hfa_os_unlikely(pendinstr->cload && pendinstr->mload)) {
                hfa_err(CVM_HFA_ENOPERM, ("Graph load pending\n"));
                return (HFA_FAILURE);
            } 
        }
        if(hfa_os_unlikely(NULL == psparam->output.ptr)){
            hfa_err(CVM_HFA_EBADADDR, ("Output ptr found NULL\n"));
            return HFA_FAILURE;
        }
        if(hfa_os_unlikely(NULL == psparam->input_n.piovec)){
            hfa_err(CVM_HFA_EBADADDR, ("Input_n ptr found NULL\n"));
            return HFA_FAILURE;
        }
        if(hfa_os_unlikely(NULL == psparam->input_0_n.piovec)){
            hfa_err(CVM_HFA_EBADADDR, ("Input_0_n ptr found NULL\n"));
            return HFA_FAILURE;
        }
        /*Result buffer check*/
        if (hfa_os_unlikely(psparam->output.is_iovec)){
#ifdef NOTYET
            uint64_t        minlen=0;
            int ioveclen = psparam->output.g.ioveclen;
            for (i = 0; i < ioveclen; ++i){
                if(i){
                    minlen = HFA_HW_RBUF_MIN_LEN;
                } else {
                    minlen = HFA_RBUF_MIN_LEN;
                }
                if(NULL == psparam->output.g.piovec[i].ptr){
                    hfa_err(CVM_HFA_EBADADDR,("Null RBuf Gather ptr %d\n", i));
                    return HFA_FAILURE;
                }
                if(psparam->output.g.piovec[i].len < minlen){
                    hfa_err(CVM_HFA_E2SMALL, ("Rbuf IOV : %d len < minlen", i));
                    return HFA_FAILURE;
                }
                ptr = (uint8_t *)psparam->output.g.piovec[i].ptr + minlen;
                if(_HFA_ISMEM_NOTALIGNED(cvmx_ptr_to_phys(ptr), 8)){
                    hfa_err(CVM_HFA_EALIGNMENT, 
                        ("Rbuf iov[%d] ptr: %p not 8 byte aligned\n", i, ptr));
                    return HFA_FAILURE;
                }
            }         
#else
        hfa_err(CVM_HFA_EBADOIOV,("Output buffer cannot be an IO vector\n"));
        return HFA_FAILURE;
#endif /* NOTYET */
        } else {
            if(psparam->output.d.len < 32) {
                hfa_err(CVM_HFA_E2SMALL, ("Result buffer length %d < "
                        "minimum required length\n", psparam->output.d.len));
                return (HFA_FAILURE);
            }
            if(NULL == psparam->output.d.ptr) {
                hfa_err(CVM_HFA_EBADADDR, ("Result buffer found NULL\n"));
                return HFA_FAILURE;
            }
            ptr = psparam->output.d.ptr + HFA_RBUF_MIN_LEN;
            if(_HFA_ISMEM_NOTALIGNED(cvmx_ptr_to_phys(ptr), 8)){
                hfa_err(CVM_HFA_EALIGNMENT, 
                       ("Rbuf direct ptr: %p not 8 byte aligned\n", ptr));
                return HFA_FAILURE;
            }
        }
        /*Input buffer*/
        if (hfa_os_unlikely(!(psparam->input_n.ioveclen))) {
            hfa_err(CVM_HFA_E2SMALL, ("Input ioveclen found 0\n"));
            return HFA_FAILURE;
        }
        if(hfa_os_unlikely(psparam->input_n.ioveclen > 
                                    HFA_SEARCH_MAX_IOVECLEN)){
            hfa_err(CVM_HFA_E2BIG, ("Iovec len exceeds  maximum required "
                                    "length: 65535\n"));
            return (HFA_FAILURE);
        }
        for(i=0; i< psparam->input_n.ioveclen; i++){
            if(hfa_os_unlikely(NULL ==(((psparam->input_n).piovec) + i)->ptr)){
                hfa_err(CVM_HFA_EBADIIOV, ("Ibuf gather ptr %d NULL\n",i));
                return HFA_FAILURE;
            }
            if(hfa_os_unlikely(((((psparam->input_n).piovec) + i)->len) > 
                                                      HFA_SEARCH_MAX_GM_LEN)){
                hfa_err(CVM_HFA_E2BIG, ("Iovec: %d len > 64K\n", i));
                return HFA_FAILURE;
            }
        }
        return (HFA_SUCCESS);
    }
    return HFA_FAILURE;
}
/**
 * @internal
 * Submit search instruction to hardware
 *
 * @param   psctx       pointer to search context
 * @param   psparam     pointer to Search parameter
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
__hfa_searchctx_search_submit (hfa_searchctx_t *psctx, 
                               hfa_searchparams_t *psparam)
{
    int                         i, clno, idx = 0, retval =0;
    hfa_gptr_t                  *gptr = NULL, *start_ptr = NULL;
    hfa_instr_t                 instr;
    hfa_iovec_t                 *pi_iovec = NULL;
    uint64_t                    ilen, olen;
    uint64_t                    *po_direct = NULL;
    hfa_rptr_overload_t         *rbuf = NULL;
    hfa_wqe_pktdata_overload_t  *pktdata = NULL;
    uint32_t                    clmsk = 0x0;
    int                         _i, _cl;
    hfa_addr_t                  mbase = 0;
    hfa_graph_t                 *pgraph = psctx->pgraph;

    if(hfa_os_unlikely(psparam->output.is_iovec)) {
        rbuf = (hfa_rptr_overload_t *)(psparam->output.g.piovec[0].ptr);
        olen = psparam->output.g.piovec[0].len - (sizeof(hfa_rptr_reserve_t));
    } else {
        rbuf = ((hfa_rptr_overload_t *)(psparam->output.d.ptr));
        /* olen goes into RMAX. So reserve space for software and RWORD0 */
        olen = psparam->output.d.len - (sizeof(hfa_rptr_reserve_t)) - 
                                         sizeof(hfa_rmdata_t);
    }
    po_direct = &(rbuf->rptrbase);

    pi_iovec = psparam->input_n.piovec;
    ilen     = psparam->input_n.ioveclen;

    if(hfa_os_unlikely(NULL == (gptr = 
                    hfa_os_malloc(sizeof(hfa_gptr_t) * ilen)))){
        hfa_err(CVM_HFA_ENOMEM, ("Failure in allocating hfa_gptr_t\n"));
        return HFA_FAILURE;
    }
    start_ptr = gptr;
    for(i = 0; i < ilen; i++, gptr++){
        gptr->u64 =0;
        gptr->s.addr = ptr_to_phys(pi_iovec[i].ptr);
        gptr->s.size = pi_iovec[i].len;
    }

    clno = psparam->clusterno;
    if(clno == HFA_ANY_CLUSTER_SEARCH) {
#ifdef HFA_STRICT_CHECK        
        clmsk = pgraph->clmsk;
        /* For any cluster search mbase should be same for all clusters */
        HFA_FOREACHBIT_SET(clmsk) {
            if(mbase) {
                if(mbase != (pgraph->clinfo).pclustbuf[_i].mbase) {
                    hfa_log("Mbase must be same for all clusters\n");
                    hfa_os_free (start_ptr, (sizeof(hfa_gptr_t) * ilen));
                    return HFA_FAILURE;
                }
            }
            mbase = (pgraph->clinfo).pclustbuf[_i].mbase;
        }
#endif        
        clmsk = pgraph->clmsk;
    }
    else {
        idx = hfa_pclbuf_idx[clno][pgraph->clmsk]; 

        if(hfa_os_unlikely(idx < 0)){
            hfa_err(CVM_HFA_ENOPERM, ("Invalid cluster idx[%d][0x%x]: %d\n",
                                 clno, pgraph->clmsk, idx));
            hfa_os_free (start_ptr, (sizeof(hfa_gptr_t) * ilen));
            return HFA_FAILURE;
        }
    }
    /*Explicitly memset RWORD0 so that if application passes reused rptr
     * without doing memset*/
    memset(po_direct, 0, HFA_RPTR_RWORD0_SIZE);

    cvm_hfa_instr_init(&instr, CVMX_HFA_ITYPE_GRAPHWALK);
    mbase = ((pgraph->clinfo).pclustbuf[idx].mbase >> 
             pgraph->pdev->devinfo.mbasealignbits);
    cvm_hfa_instr_setmbase(&instr, mbase);

    cvm_hfa_instr_setgather(&instr, HFA_TRUE);
    cvm_hfa_instr_setsnode(&instr, psctx->savedctx.enode.s.nextnode);
    cvm_hfa_instr_setf1(&instr, psctx->savedctx.enode.s.ntype);
    cvm_hfa_instr_setsmallmem(&instr, psctx->savedctx.enode.s.smdtomtype);
    cvm_hfa_instr_setle(&instr, HFA_FALSE);

    cvm_hfa_instr_setf2(&instr, psctx->savedctx.enode.s.hash);
    cvm_hfa_instr_setrptr(&instr, ptr_to_phys(po_direct));
    cvm_hfa_instr_setrmax(&instr, olen >> 3);

    cvm_hfa_instr_setdptr(&instr, ptr_to_phys(start_ptr));
    if(clno == HFA_ANY_CLUSTER_SEARCH) 
        cvm_hfa_instr_setclmsk(&instr, clmsk);
    else
        cvm_hfa_instr_setclmsk(&instr, (1 << clno));
    cvm_hfa_instr_setdlen(&instr, ilen);
    cvm_hfa_instr_setf5(&instr, psctx->savedctx.enode2.s.srepl); 

    cvm_hfa_instr_setf3(&instr, psctx->savedctx.enode.s.dnodeid);
    cvm_hfa_instr_setvgid(&instr,(pgraph->clinfo).pclustbuf[idx].vgid);
    if (psparam->wqe) {
        cvmx_wqe_set_unused8 (psparam->wqe, HFA_SEARCH_HWWQE_UNUSED_FIELD);
        
        pktdata = (hfa_wqe_pktdata_overload_t *)psparam->wqe->packet_data; 
        pktdata->psctx = (uint64_t)psctx;
        pktdata->psparam = (uint64_t)psparam;
        pktdata->itype = (uint64_t)CVMX_HFA_ITYPE_GRAPHWALK;
        
        cvm_hfa_instr_setwqptr(&instr, (uint64_t)(ptr_to_phys(psparam->wqe)));
    }
#ifdef HFA_DUMP
    hfa_dump_buf("search", instr.u64, sizeof(cvmx_hfa_command_t));
#endif    
    {
        (rbuf->reserve).start_ptr = (uint64_t)start_ptr;
        (rbuf->reserve).ilen = (uint64_t) ilen;
    }
    retval = hfa_dev_submitasync(pgraph->pdev, &instr);
    if(hfa_os_unlikely(HFA_FAILURE == retval)){
        hfa_os_free (start_ptr, (sizeof(hfa_gptr_t) * ilen));
    }
#ifdef HFA_CTX_STATS
    if(HFA_FAILURE == retval){
        HFA_CTX_STATS_INC(psctx, gwalk.failed, cvmx_get_core_num(), 1);
    } else {
        HFA_CTX_STATS_INC(psctx, gwalk.pending, cvmx_get_core_num(), 1);
    }
#endif
    return(retval);
}
/**@endcond*/
/**
 * This routine initializes a Search Context. A Search Context(sctx) is
 * necessary to perform a pattern search on the HFA engine. It brings together
 * the payload/buffer to be search, the graph which holds the pattern
 * information and the search options/settings under a single-roof.
 * 
 * This routine intializes an sctx object which can subsequently by the API used
 * to perform the search
 * hfa_searchctx_setgraph() - associate a sctx with a graph.
 * hfa_searchctx_search_async() - perform a pattern search in a payload
 * hfa_searchctx_get_searchstatus() - retrieve the status of a pending search
 * hfa_searchctx_getmatches() - retrieve the pattern match information and
 * report the matches found.
 *
 * This routine should be called before any other searchctx API. The
 * counterpart for this routine is hfa_dev_searchctx_cleanup().
 *
 * @param   pdev        Pointer to Device structure
 * @param   psctx       Pointer to Search Context
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_dev_searchctx_init(hfa_dev_t *pdev, hfa_searchctx_t *psctx)
{
    hfa_dbg("pdev: %p, psctx: %p\n", pdev, psctx);

    if(hfa_os_unlikely (HFA_DEV_INITDONE != hfa_isdevinit)){
        hfa_err(CVM_HFA_EDEVINITPEND,("hfa_dev_init() not performed\n"));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely((NULL == pdev) || (NULL == psctx))){
        hfa_err(CVM_HFA_EINVALARG, ("Null pointers pdev: %p, psctx: %p\n",
                                                              pdev, psctx));
        return HFA_FAILURE;
    }
    memset(psctx, 0, sizeof(hfa_searchctx_t));

    /*Initialise data members*/
    psctx->ctx_status = HFA_SEARCHCTX_SINITIAL;
#ifdef HFA_CTX_STATS
    if(hfa_os_unlikely(HFA_FAILURE == 
            hfa_searchctx_stats_init(psctx))){
       hfa_log("hfa_searchctx_stats_init failed\n");
       return HFA_FAILURE;
    }
    psctx->ppalloc_magicno = HFA_STATS_PPALLOC_MAGICNO;
#endif
    return(HFA_SUCCESS); 
}
/**
 * This routine cleans-up a Search Context. It is the counterpart of
 * hfa_dev_searchctx_init(). No searchctx API should be called after calling
 * this routine.
 *
 * @param   pdev        Pointer to Device structure
 * @param   psctx       Pointer to Search Context
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_dev_searchctx_cleanup (hfa_dev_t *pdev, hfa_searchctx_t *psctx)
{
    ppstate_t       *pstate = NULL;
    hfa_graph_t     *pgraph = NULL;
    hfa_ppstats_t   *ppstats = NULL;

    hfa_dbg("pdev: %p, psctx: %p\n", pdev, psctx);
    if(hfa_os_unlikely (NULL == psctx) || (NULL == pdev) || 
                        NULL == (psctx->pgraph)) {
        hfa_err (CVM_HFA_EINVALARG, ("Null pointers: psctx:%p pdev:%p "\
                 "pgraph:%p\n",psctx, pdev, psctx->pgraph));
        return HFA_FAILURE;
    }
    pstate = &((psctx->savedctx).state); 
    pgraph = psctx->pgraph;

    if(hfa_os_likely(pgraph && pgraph->irt)) {
        /* Cleanup memory allocated for PP statistics */
        ppstats = ppgetstats(pstate, &pgraph->irt[0]); 
        if(ppstats) {
            ppcleanstats(pstate, &pgraph->irt[0]); 
            hfa_os_free(ppstats, sizeof(hfa_ppstats_t));
        }
        ppcleanup(pstate, pgraph->irt);
    }
#ifdef HFA_CTX_STATS
    hfa_searchctx_stats_cleanup(psctx);
#endif
    memset(psctx, 0, sizeof(hfa_searchctx_t));
    return HFA_SUCCESS;
}
/**
 * This routine is used to specify settings used during the search and
 * getmatches API. The settings are in the form bit-wise ORed flag bits. The
 * flag bits are as per @ref hfa_searchctx_iflags_t
 *
 * @param   psctx       Pointer to Search Context
 * @param   flags       64 bit Flag mask
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_setflags (hfa_searchctx_t *psctx, hfa_size_t flags)
{
    hfa_graph_t     *pgraph = NULL;
    ppstate_t       *pstate = NULL;
    hfa_ppstats_t   *ppstats = NULL;

    hfa_dbg("psctx: %p, flags: 0x%x\n", psctx, flags);
    if(hfa_os_unlikely((NULL == psctx) || (NULL == psctx->pgraph))) {
        hfa_err(CVM_HFA_EINVALARG, ("Null pointers psctx: %p, pgraph: %p\n",
                                                    psctx, psctx->pgraph));
        return HFA_FAILURE;
    }
    /**If singlematch + cross packet match
    then disable CROSS match in order to align with post-processing*/
    if( (HFA_ISBITMSKSET (flags, HFA_SEARCHCTX_FSINGLEMATCH)) &&
        (HFA_ISBITMSKCLR(flags, HFA_SEARCHCTX_FNOCROSS))){
        HFA_BITMSKSET (flags, HFA_SEARCHCTX_FNOCROSS);
        hfa_log("[%s] Warning: CROSSPACKET search and SINGLEMATCH search can't"\
                " exist together. Disabling CROSSPACKET search\n", __func__);
    }
    psctx->flags = flags;
    /* Initialize Post Process statistics, if HFA_SEARCHCTX_FENABLE_PPSTATS 
     * flag set in searchctx flags.*/
    if(HFA_ISBITMSKSET (flags, HFA_SEARCHCTX_FENABLE_PPSTATS)) {
        pgraph = psctx->pgraph;

        if(hfa_os_unlikely(HFA_SUCCESS !=  hfa_searchctx_graph_validate
                    (psctx, pgraph, HFA_SEARCHCTX_SGRAPH_SET))){
            hfa_err(CVM_HFA_EGEN, ("Before setting flags valid graph has to "\
                    "be set in searchctx: %p\n", psctx));
            return HFA_FAILURE;
        }
        pstate = &((psctx->savedctx).state); 
        /* Initializing pp stats if is not initialized before */
        if(NULL == (ppstats = ppgetstats(pstate, &pgraph->irt[0]))) {
            if(hfa_os_unlikely(NULL == (ppstats = 
                            hfa_os_malloc(sizeof(hfa_ppstats_t))))) {
                hfa_err(CVM_HFA_ENOMEM, ("Failure in allocating hfa_ppstats_t\n"));
                return HFA_FAILURE;
            }
            ppassignstats(pstate, &pgraph->irt[0], ppstats);
        }
    } 
    return(HFA_SUCCESS);
}
/**
 * This routine associates a graph with sctx. The graph must be in a state ready
 * for search. So hfa_graph_memload_data() and/or hfa_graph_cacheload() should
 * be done before this routine. The sctx can be associated with only one graph.
 * But the graph can be associated with more than one sctx.
 *
 * @param   psctx       pointer to search context
 * @param   pgraph      pointer to graph
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_setgraph(hfa_searchctx_t *psctx, hfa_graph_t *pgraph)
{
    hfa_dbg("psctx: %p, pgraph: %p\n", psctx, pgraph);

    if(hfa_os_likely(HFA_SUCCESS !=  hfa_searchctx_graph_validate
                                    (psctx, pgraph, HFA_SEARCHCTX_SINITIAL))){
        hfa_err(CVM_HFA_EGEN,("Failure frm valid ctx_graph ctx: %p\n", psctx));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(ppinit(&((psctx->savedctx).state), 
                                &pgraph->irt[0], NULL))){
        hfa_err(CVM_HFA_EPPINIT, ("PPinit failure\n"));
        return HFA_FAILURE;
    }

    HFA_SET(psctx, savedctx, enode.u64,  pgraph->irt[0].snode);  
    HFA_SET(psctx, savedctx, enode2.u64, pgraph->irt[0].snode2);
    psctx->pgraph = pgraph;
    /*Indicate that Graph is set*/
    psctx->ctx_status = HFA_SEARCHCTX_SGRAPH_SET;
#ifdef HFA_STATS
    HFA_CORE_STATS_INC(nctxts, cvmx_get_core_num(), 1);
#endif
#ifdef HFA_CTX_STATS
    hfa_searchctx_setppuarg(psctx, psctx);        
#endif
    /*Link Graph Implementation pending*/
    return (HFA_SUCCESS);
}
/**
 * This is a utility routine which associates an application-specifc cookie in
 * the sctx. The cookie(puarg) is a 64-bit value can point to
 * application-specific data structure. The cookie is passed back to the
 * application as part of post-processing during hfa_searchctx_getmatches(). The
 * callback routines which use the cookie are as follows:
 * - @ref hfa_fnp_ppalloc_cb_t
 * - @ref hfa_fnp_pperr_cb_t
 * - @ref hfa_fnp_ppfree_cb_t
 * - @ref hfa_fnp_ppsize_cb_t
 *
 * The application can register these callbacks using 
 *  - hfa_dev_set_fnp_ppalloc() 
 *  - hfa_dev_set_fnp_ppfree()
 *  - hfa_dev_set_fnp_ppsize()
 *  - hfa_dev_set_fnp_pptalloc()
 *  - hfa_dev_set_fnp_pptfree()
 *  - hfa_dev_set_fnp_pptsize()
 *  - hfa_dev_set_fnp_ppmatchalloc()
 *  - hfa_dev_set_fnp_ppmatchfree()
 *  - hfa_dev_set_fnp_ppmatchsize()
 *  - hfa_dev_set_fnp_pperror()
 *
 * This API should be called after hfa_searchctx_setgraph() but before
 * hfa_searchctx_search_async()/hfa_searchctx_search().
 *
 * @param   psctx    hfa_searchctx_t    pointer to search context
 * @param   puarg    void *             Pointer to ppuarg
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_setppuarg(hfa_searchctx_t *psctx, void *puarg)
{
    ppstate_t       *pstate = NULL;
    hfa_graph_t     *pgraph = NULL;
    hfa_dbg("psctx: %p, pgraph: %p\n", psctx, pgraph);

    if(hfa_os_unlikely((NULL == psctx)  || (NULL == puarg))){
        hfa_err(CVM_HFA_EINVALARG,("Null psctx: %p, puarg: %p\n", psctx,puarg));
        return HFA_FAILURE;
    }
    pgraph = psctx->pgraph;

#ifdef HFA_STRICT_CHECK   
    if(hfa_os_unlikely(HFA_SUCCESS !=  hfa_searchctx_graph_validate
                                    (psctx, pgraph, HFA_SEARCHCTX_SGRAPH_SET))){
        hfa_err(CVM_HFA_EGEN,("Failure frm valid ctx_graph ctx: %p\n", psctx));
        return HFA_FAILURE;
    }

    if(hfa_os_unlikely(HFA_ISBITMSKSET(psctx->ctx_status, 
                                            HFA_SEARCHCTX_SPPUARG_SET))){
        hfa_err(CVM_HFA_ENOPERM,("ppuarg is already set psctx: %p\n", psctx));
        return HFA_FAILURE;
    }
#endif  
    pstate = &((psctx->savedctx).state); 
    if(hfa_os_likely(pstate)){
        memset(pstate, 0, sizeof(ppstate_t));
        if(hfa_os_unlikely(ppinit(pstate, &pgraph->irt[0], puarg))){
            hfa_err(CVM_HFA_EPPINIT, ("PPinit failure\n"));
            return HFA_FAILURE;
        }
        HFA_SET(psctx, savedctx, enode.u64,  pgraph->irt[0].snode);  
        HFA_SET(psctx, savedctx, enode2.u64, pgraph->irt[0].snode2);
        /*Indicate that PPUARG is set*/
        HFA_BITMSKSET(psctx->ctx_status, HFA_SEARCHCTX_SPPUARG_SET);
        return (HFA_SUCCESS);
    }
    return (HFA_FAILURE);
}
/**
 * This routine returns a copy of Post Process statistics to the application 
 * through a pointer provided by application. 
 * This routine depends on hfa_searchctx_setflags().
 *
 * @param   psctx       hfa_searchctx_t    pointer to search context
 * @param   ppstats     hfa_ppstats_t      Variable where ppstats pointer 
 *                                         is written by API. 
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfa_searchctx_get_ppstats(hfa_searchctx_t *psctx, hfa_ppstats_t **ppstats) 
{
    ppstate_t       *pstate = NULL;
    hfa_graph_t     *pgraph = NULL;

    if(hfa_os_unlikely((NULL == psctx) || (NULL == psctx->pgraph))) {
        hfa_err(CVM_HFA_EINVALARG,("Null psctx:%p pgraph:%p\n", 
                psctx, psctx->pgraph));
        return HFA_FAILURE;
    }
    pgraph = psctx->pgraph;
    pstate = &((psctx->savedctx).state); 
    *ppstats = ppgetstats(pstate, &pgraph->irt[0]); 
    if(hfa_os_unlikely(NULL == *ppstats)) {
        hfa_err(CVM_HFA_ENOPERM,("ppstats is not set initialized\n"));
        return HFA_FAILURE;
    }
    return HFA_SUCCESS;
}
/**
 * This routine is used to print PP statistics while post processing is
 * going on. This routine depends on hfa_searchctx_ppstats_init().
 *
 * @param   psctx    hfa_searchctx_t    pointer to search context
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfa_searchctx_ppstats_print(hfa_searchctx_t *psctx) 
{
    ppstate_t       *pstate = NULL;
    hfa_graph_t     *pgraph = NULL;
    hfa_ppstats_t   *ppstats = NULL;

    if(hfa_os_unlikely((NULL == psctx) || (NULL == psctx->pgraph))) {
        hfa_err(CVM_HFA_EINVALARG,("Null psctx:%p pgraph:%p\n", 
                psctx, psctx->pgraph));
        return HFA_FAILURE;
    }
    pgraph = psctx->pgraph;
    pstate = &((psctx->savedctx).state); 
    ppstats = ppgetstats(pstate, &pgraph->irt[0]); 
    if(ppstats) {
       hfa_log("Current Rword : %d Total Rwords : %d\n", 
              ppstats->curr_rword, ppstats->tot_rwords); 
       hfa_log("Rstack Count : %d Sstack Count : %d\n",
              ppstats->rstack, ppstats->sstack);
#ifdef KERNEL
       hfa_log("Start Cycle  : %llu Current Cycle : %llu\n",
              ppstats->scycle, ppstats->ccycle);
#else
       hfa_log("Start Cycle  : %lu Current Cycle : %lu\n",
              ppstats->scycle, ppstats->ccycle);
#endif
       hfa_log("\n");
    }
    return HFA_SUCCESS;
}
/**
 * This routine performs a pattern search using the given parameters in a
 * non-blocking manner. This routine requires that the sctx is properly
 * initialized with appropriate settings using other searchctx API. Similarly
 * the sparams must be properly initialized using the searchparams API. The
 * search is performed using @ref CVMX_HFA_ITYPE_GRAPHWALK HFA command.
 *
 * The status of the search operation can be collected using
 * hfa_searchctx_get_searchstatus() if a WQE is not associated with sparam. If a
 * WQE is used, then hfa_searchctx_processwork() should be used to process the
 * WQE and then hfa_searchparam_get_hwsearch_reason() will provide the status of
 * the search operation. Subsequently hfa_searchctx_getmatches() can be used to
 * obtain the pattern-matches found in the search.
 *
 * @param   psctx       pointer to search context
 * @param   psparam     pointer to Search parameter
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_search_async(hfa_searchctx_t *psctx, 
                           hfa_searchparams_t *psparam)
{
    hfa_dbg("psctx: %p, psparam: %p\n", psctx, psparam);

    if(hfa_os_unlikely((NULL == psctx) || (NULL == psparam))){
        hfa_err(CVM_HFA_EINVALARG, ("Found Psctx: %p, param: %p\n",
                psctx, psparam));
        return HFA_FAILURE;
    }
#ifdef HFA_STRICT_CHECK
    if(hfa_os_unlikely(HFA_SUCCESS !=  
       hfa_searchctx_graph_validate(psctx,psctx->pgraph, 
                                    HFA_SEARCHCTX_SGRAPH_SET))){
        return (HFA_FAILURE);
    }
    if(hfa_os_unlikely(HFA_SUCCESS !=  
              hfa_searchctx_sparams_validate (psctx, psparam))){
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_searchctx_search_submit(psctx, psparam));
}
/**
 * This routine provides the status of an outstanding pattern search operation
 * initiated using hfa_searchctx_search_async(). The status values returned
 * correspond to @ref hfa_searchstatus_t. This routine should not be used if a
 * WQE was assocated with the sparam using hfa_searchparam_set_wqe(). When using
 * a WQE, the hfa_searchctx_processwork() routine should used to process the WQE
 * after picking it up from the SSO unit.
 *
 * @param   psctx       pointer to search context
 * @param   psparam     pointer to Search parameter
 * @param   psstatus    pointer to Search Status
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_get_searchstatus(hfa_searchctx_t *psctx, 
                               hfa_searchparams_t *psparam, 
                               hfa_searchstatus_t *psstatus)
{
    hfa_dev_t               *pdev = NULL;
    hfa_rmdata_t            *prmdata = NULL;
    uint64_t                *po_direct = NULL;
    hfa_gptr_t              *start_ptr = NULL;
    hfa_rptr_overload_t     *rbuf = NULL;
    int                     ilen;
    
    hfa_dbg("psctx: %p, psparam: %p,psstatus: %p\n", psctx, psparam, psstatus);
    if(hfa_os_likely(psctx && psparam && psstatus && psctx->pgraph)){
        pdev      = psctx->pgraph->pdev;
        *psstatus = HFA_SEARCH_SEAGAIN;
    
        if(hfa_os_unlikely(psparam->output.is_iovec)){
            rbuf = ((hfa_rptr_overload_t *)(psparam->output.g.piovec[0].ptr));
        } else {
            rbuf = ((hfa_rptr_overload_t *)(psparam->output.d.ptr));
        }
       
        po_direct = &(rbuf->rptrbase);
        prmdata = (hfa_rmdata_t *)po_direct;
        *psstatus = hfa_dev_getasyncstatus (pdev, prmdata);

        if (HFA_SEARCH_SEAGAIN != *psstatus) {
            start_ptr = (hfa_gptr_t *)((rbuf->reserve).start_ptr);
            ilen      = (rbuf->reserve).ilen;
            hfa_os_free (start_ptr, (sizeof(hfa_gptr_t) * ilen));
#ifdef HFA_CTX_STATS
        HFA_CTX_STATS_INC(psctx, gwalk.success, cvmx_get_core_num(), 1);
        HFA_CTX_STATS_DEC(psctx, gwalk.pending, cvmx_get_core_num(), 1);
#endif
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine performs a pattern search using the given parameters in a
 * blocking manner. The routine is identical to hfa_searchctx_search_async()
 * in behaviour, except it busy-waits for completion of the search
 * operation(performed using @ref CVMX_HFA_ITYPE_GRAPHWALK) HFA command).
 *
 * @param   psctx       pointer to search context
 * @param   psparam     pointer to Search parameter
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_search(hfa_searchctx_t *psctx, hfa_searchparams_t *psparam)
{
    uint32_t    status = HFA_SEARCH_SEAGAIN;

    hfa_dbg("psctx: %p, psparam: %p\n", psctx, psparam);
    if(hfa_os_unlikely(HFA_SUCCESS != 
                 hfa_searchctx_search_async (psctx, psparam))){
        return HFA_FAILURE;
    }
    while (HFA_SEARCH_SEAGAIN == status)
        hfa_searchctx_get_searchstatus (psctx, psparam, &status);

    return HFA_SUCCESS;
}
#ifdef HFA_CTX_STATS
/**
 * This routine is for counting number of matches for each search 
 * context via match buffer when HFA_CTX_STATS enabled.
 *
 * @param  psctx      pointer to search context
 * @param  pmatches   pointer to match buffer
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_get_matchcount(hfa_searchctx_t *psctx, uint64_t *pmatches)
{
    uint64_t        *ptr;
    int             len = 0;
    hfa_meta_t      meta;
    hfa_return_t    retval = HFA_SUCCESS;

    if ((uint64_t *)pmatches != NULL) {
        ptr = (uint64_t *)pmatches;
        len = 0;
        meta.u64 =  hfa_match_get(psctx, &ptr, &len);
        if (meta.s.allocerr){
            hfa_log ("not enough memory to report all matches\n");
            retval = HFA_FAILURE;
        } else {
            HFA_CTX_STATS_INC(psctx, nmatches, cvmx_get_core_num(), 
                                                    meta.s.nmatch);
        }
    }
    return (retval);
}
/**
 * This routine is for counting number of matches for each search context 
 * when HFA_CTX_STATS enabled. It will called whenever match found in pp.
 *
 * @param   patno   pattern number
 * @param   mno     match number with in pattern (for captured groups)
 * @param   soff    start offset
 * @param   eoff    end offset
 * @param   arg     callback argument
 */
void 
hfa_local_matchcb(int patno, int mno, int soff, int eoff, void *arg)
{
    hfa_searchparams_t      *psparam = (hfa_searchparams_t *)arg;
    
    if(hfa_os_likely(psparam)) {
        /* Increment search ctx nmatches statistics */ 
        HFA_CTX_STATS_INC(psparam->psctx, nmatches, cvmx_get_core_num(), 1);
        
        /* Call match call back provided by application */ 
        psparam->matchcb (patno, mno, soff, eoff, psparam->cbarg); 
    }
}
#endif
/**
 * This routine post-processes the search results from the HFA engine and
 * reports the pattern matches found. The matches can be reported either via an
 * application-specific callback registered using hfa_searchparam_set_matchcb()
 * OR via the match-buffer(@b *ppmatch), the memory for which will be allocated
 * by the routine. The default behaviour is to use the match-buffer. If the
 * application registers a match-callback, then the callback will be invoked and
 * match-buffer will not be allocated. 
 *
 * The match-buffer is a linked-list of identical-sized buffers. The routine
 * will try to allocate as many buffers as necessary to report all the matches
 * found(based on search settings). The match-buffer allocation is done using
 * the routine registered via hfa_dev_set_fnp_ppmatchalloc(). The default
 * allocator is hfa_defaultfn_ppalloc(). The application should subsequently
 * free the match-buffers using hfa_matches_cleanup().
 *
 * @param   psctx       pointer to search context
 * @param   psparam     pointer to Search parameter
 * @param   ppmatch     pointer to match buffer (allocated by pp)
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_getmatches (hfa_searchctx_t *psctx, 
                          hfa_searchparams_t *psparam, uint64_t **ppmatch)
{
    hfa_ppiflags_t          ppiflags = 0;
    hfa_rmdata_t            *prmdata = NULL;
    hfa_rword_t             *prword = NULL;
    uint64_t                _rmdata, _rword;
    hfa_iovec_t             *pi_iovec = NULL;
    uint64_t                *ptr_odata = NULL;
    int                     ilen, tlen;
    hfa_rptr_overload_t     *rbuf = NULL;
#ifdef HFA_STATS
    int                     hteno = 0;
#endif
    hfa_dbg("psctx: %p, psparam: %p, ppmatch: %p\n", psctx, psparam, ppmatch);
    if(hfa_os_likely(psctx && psparam && ppmatch && psctx->pgraph)){
#ifdef HFA_STRICT_CHECK        
        if(hfa_os_unlikely((NULL == psparam->input_0_n.piovec) ||
                           (NULL == psparam->output.ptr))){
            hfa_dbg("psparam->input_0_n.piovec: %p, psparam->output.ptr: %p\n",
             psparam->input_0_n.piovec, psparam->output.ptr);
            return HFA_FAILURE;
        }
#endif        
        *ppmatch = NULL;
        pi_iovec = psparam->input_0_n.piovec;
        tlen     = psparam->input_0_n.ioveclen;
        ilen     = psparam->input_n.ioveclen;
          
        rbuf = (hfa_rptr_overload_t *)(psparam->output.ptr);
        ptr_odata = &(rbuf->rptrbase); 

#ifdef HFA_DUMP
        hfa_dump_buf("HWResultbuffer", ptr_odata, 256);
#endif        

        _rmdata = (((uint64_t *) ptr_odata)[0]);
        prmdata = ((hfa_rmdata_t *) &_rmdata);
        _rword = (((uint64_t *) ptr_odata)[prmdata->s.nument]);
        prword = (hfa_rword_t *) &_rword;
#ifdef HFA_STATS
        hteno = ((prmdata->s.rsvd >> 36) & 0x3) << 4;
        hteno += (prmdata->s.rsvd >> 32) & 0xf;
        HFA_CORE_STATS_INC(htestats[hteno], cvmx_get_core_num(), 1);
#ifdef  HFA_CTX_STATS
        HFA_CTX_STATS_INC(psctx, htestats[hteno], cvmx_get_core_num(), 1);
        HFA_CTX_STATS_INC(psctx, dfamatches, cvmx_get_core_num(), 
                                             (prmdata->s.nument -1));
#endif 
#endif        
        hfa_dbg("numnet %d\n", prmdata->s.nument-1); 
       /**Save hw fields reference for application*/ 
        psparam->ofields.pdboffset = prword->s.offset + 1;
        psparam->ofields.reason = prmdata->s.reason;

        if (hfa_os_unlikely(prmdata->s.reason != HFA_REASON_DDONE &&
                prmdata->s.reason != HFA_REASON_RFULL)){
            hfa_err(CVM_HFA_EHWERROR, ("ERR in prmdata->s.reason: 0x%x\n",
                        prmdata->s.reason));
            return HFA_FAILURE;
        }

        if(HFA_ISBITMSKCLR(psctx->flags, HFA_SEARCHCTX_FNOCROSS)){
            HFA_SET(psctx, savedctx, enode.s.nextnode, prword->s.nextnode);
            HFA_SET(psctx, savedctx, enode.s.ntype, prword->s.f1);
            HFA_SET(psctx, savedctx, enode.s.hash, prword->s.f2);
            HFA_SET(psctx, savedctx, enode.s.dnodeid, prword->s.f3);
        }
        ppiflags |= (psctx->flags & HFA_SEARCHCTX_FNOCROSS) ? PPIFNOCROSS : 0; 
        ppiflags |= (psctx->flags & HFA_SEARCHCTX_FSINGLEMATCH)? 
                                              PPIFSINGLEMATCH:0;
        
#ifdef HFA_CTX_STATS
        psparam->psctx = psctx;
        if(psparam->matchcb) {
            *ppmatch =  pp(&(psctx->savedctx.state), 
                        (ppdfa_infort_t *)(psctx->pgraph->irt), pi_iovec, tlen,
                        ilen, ptr_odata, hfa_local_matchcb, psparam, ppiflags,
                        &(psparam->ofields.oflags));
        }
        else {
            *ppmatch =  pp(&(psctx->savedctx.state), 
                        (ppdfa_infort_t *)(psctx->pgraph->irt), pi_iovec, tlen,
                        ilen, ptr_odata, NULL, NULL, ppiflags,
                        &(psparam->ofields.oflags));

            hfa_get_matchcount(psctx, *ppmatch);
        }
#else
        *ppmatch =  pp(&(psctx->savedctx.state), 
                    (ppdfa_infort_t *)(psctx->pgraph->irt), pi_iovec, tlen,
                    ilen, ptr_odata, psparam->matchcb, psparam->cbarg, ppiflags,
                    &(psparam->ofields.oflags));
#endif
        return HFA_SUCCESS; 
    }
    return HFA_FAILURE;
}
/**
 * This routine returns a match by parsing through the match buffer.
 * 
 * @param   psctx       pointer to search context
 * @param   pmatch      pointer to match buffer (allocated by pp)
 * @param   len         tracks starting point of a match                 
 *
 * @return match 
 */
uint64_t  
hfa_match_get(hfa_searchctx_t *psctx, uint64_t **pmatch, int *len)
{
    state_dfa_t   *state = (state_dfa_t *)(&(psctx->savedctx.state));

    if(*len >= RMAX(state->mcb.uarg)) {
        *pmatch = RNEXT(*pmatch, state->mcb.uarg);
        *len = 0;
    }
    return (*pmatch)[(*len)++];
}
/**
 * This routine cleans-up the match-buffers allocated by
 * hfa_searchctx_getmatches().
 * 
 * @param   state       ppstate of graph
 * @param   pmatch      pointer to match buffer (allocated by pp)
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_matches_cleanup(ppstate_t *state, uint64_t *pmatch)
{
    hfa_dbg("pmatch: %p\n", pmatch);
    if (hfa_os_likely(state)) {
        Rfree(pmatch, (state_dfa_t *)state);
        return (HFA_SUCCESS);
    }
    return (HFA_FAILURE);
}
/**
 * This routine handles HFA WQE posted by HFA engine to indicate instruction
 * completion. The HFA engine indicates completion of HFA commands back to the
 * software using one of the following two means:
 * - Update @ref cvm_hfa_rmdata_t::done
 * - Update @ref cvm_hfa_rmdata_t::done and post a software-supplied WQE to the
 *   SSO unit.
 *
 * For the second situation, the application should call this routine to process
 * the WQE after picking it up from the SSO unit. When using the WQE, the HFA
 * SDK can save the search settings in sctx and sparam within the WQE. This
 * routine will extract those settings and return them back to the application
 * for subsequent reporting of pattern matches. The status of the search
 * operation can be obtained using hfa_searchparam_get_hwsearch_reason().
 * Subsequently matches can be reported using hfa_searchctx_getmatches().
 *
 * @param   wqe         Pointer to WQE received from HFA HW
 * @param   ppsctx      Pointer to search context
 * @param   ppsparam    Pointer to Search parameter
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfa_searchctx_processwork (cvmx_wqe_t *wqe, hfa_searchctx_t **ppsctx,
                                            hfa_searchparams_t **ppsparam)
{
    hfa_gptr_t                  *start_ptr = NULL;
    int                         ilen;
    hfa_wqe_pktdata_overload_t  *wqe_pkt = NULL;
    hfa_rptr_overload_t         *rbuf = NULL;
    hfa_itype_t                 itype = -1;

    hfa_dbg("wqe: %p\n", wqe);
    if(hfa_os_likely(wqe && ppsctx && ppsparam)) {
        wqe_pkt = (hfa_wqe_pktdata_overload_t *)(wqe->packet_data); 
        
        *ppsctx = (hfa_searchctx_t *)(wqe_pkt->psctx);
        *ppsparam = (hfa_searchparams_t *)(wqe_pkt->psparam); 
        itype = (hfa_itype_t)wqe_pkt->itype;
        hfa_dbg("psctx: %p, psparam: %p\n", *ppsctx, *ppsparam);
        switch(itype) {
            case CVMX_HFA_ITYPE_GRAPHWALK:
                break;
            default:
                hfa_err(CVM_HFA_EGEN, ("invalid itype\n"));
                return HFA_FAILURE;
        }
        if(hfa_os_likely(*ppsctx && *ppsparam)){
            if(hfa_os_unlikely((*ppsparam)->output.is_iovec)){
                rbuf = ((hfa_rptr_overload_t *)
                             ((*ppsparam)->output.g.piovec[0].ptr));
            } else {
                rbuf = ((hfa_rptr_overload_t *)
                             ((*ppsparam)->output.d.ptr));
            }
            start_ptr = (hfa_gptr_t *)((rbuf->reserve).start_ptr);
            ilen      = (rbuf->reserve).ilen;
            hfa_os_free (start_ptr, (sizeof(hfa_gptr_t) * ilen));
#ifdef HFA_STATS 
        HFA_CORE_STATS_INC(gwalk.success, cvmx_get_core_num(), 1);
        HFA_CORE_STATS_DEC(gwalk.pending, cvmx_get_core_num(), 1);
        HFA_CORE_STATS_INC(total.success, cvmx_get_core_num(), 1);
        HFA_CORE_STATS_DEC(total.pending, cvmx_get_core_num(), 1);
#endif
#ifdef HFA_CTX_STATS
        HFA_CTX_STATS_INC((*ppsctx), gwalk.success, cvmx_get_core_num(), 1);
        HFA_CTX_STATS_DEC((*ppsctx), gwalk.pending, cvmx_get_core_num(), 1);
#endif
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/**
 * This is a utility routine to reuse a previously intialized search context
 * with minimal clean up. Specifically, it cleans up the post-processing state
 * saved for cross-packet matching during searches. The graph association is
 * preserved. The flags set using hfa_searchctx_setflags() are also preserved.
 * The state of sctx is equivalent to that after invoking
 * hfa_searchctx_setgraph().
 
 * @param   psctx       pointer to search context
 
 * @return HFA_SUCCESS/HFA_FAILURE
 * */
hfa_return_t
hfa_savedctx_cleanup(hfa_searchctx_t *psctx)
{
    hfa_dbg("psctx: %p\n", psctx);
    if(hfa_os_unlikely (NULL == psctx)){
        hfa_err (CVM_HFA_EINVALARG, ("Null pointers: psctx:%p\n",psctx));
        return HFA_FAILURE;
    }
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely(NULL == psctx->pgraph)){
        hfa_err (CVM_HFA_EGINVAL_STATE,("graph found Null in sctx%p\n", psctx));
        return HFA_FAILURE;
    }
#endif    
    ppcleanup(&((psctx->savedctx).state), psctx->pgraph->irt);

    if(hfa_os_unlikely(ppinit(&((psctx->savedctx).state), 
                        &psctx->pgraph->irt[0], NULL))){
        hfa_err(CVM_HFA_EPPINIT, ("PPinit failure\n"));
        return HFA_FAILURE;
    }

    HFA_SET(psctx, savedctx, enode.u64,  psctx->pgraph->irt[0].snode);  
    HFA_SET(psctx, savedctx, enode2.u64, psctx->pgraph->irt[0].snode2);
    psctx->ctx_status = HFA_SEARCHCTX_SGRAPH_SET;
    return HFA_SUCCESS;
}
/**@cond INTERNAL*/
#ifdef KERNEL
EXPORT_SYMBOL (hfa_dev_searchctx_init);
EXPORT_SYMBOL (hfa_dev_searchctx_cleanup);
EXPORT_SYMBOL (hfa_searchctx_setgraph);
EXPORT_SYMBOL (hfa_searchctx_setflags);
EXPORT_SYMBOL (hfa_searchctx_search_async);
EXPORT_SYMBOL (hfa_searchctx_search);
EXPORT_SYMBOL (hfa_searchctx_get_searchstatus);
EXPORT_SYMBOL (hfa_searchctx_getmatches);
EXPORT_SYMBOL (hfa_searchctx_processwork);
EXPORT_SYMBOL (hfa_searchctx_setppuarg);
EXPORT_SYMBOL (hfa_searchctx_ppstats_print);
EXPORT_SYMBOL (hfa_searchctx_get_ppstats);
EXPORT_SYMBOL (hfa_matches_cleanup);
EXPORT_SYMBOL (hfa_savedctx_cleanup);
EXPORT_SYMBOL (hfa_match_get);
#endif
/**@endcond*/
