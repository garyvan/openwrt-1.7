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
 * This is header file for search related macros and APIs
 *
 */
#ifndef _CVM_HFA_SEARCH_H_
#define _CVM_HFA_SEARCH_H_

#include "cvm-hfa-common.h"
#include "cvm-hfa-cluster.h"
#include "cvm-hfa-graph.h"
#include "cvm-hfa-stats.h"
#include "cvm-hfa.h"
#include "ppdfa.h"

/** Maximum number of chunks in payload/buffer IO vector */
#define HFA_SEARCH_MAX_IOVECLEN     ((64<<10)-1) /* 64K - 1 */
/** Maximum total payload/buffer size for a search */
#define HFA_SEARCH_MAX_GM_LEN       ((64<<10)-1) /* 64K - 1 */
/** choose anyone available cluster for search based on load */
#define HFA_ANY_CLUSTER_SEARCH      -1

/** Search Context Flags */
typedef enum {
    HFA_SEARCHCTX_FDEFAULTFLAGS = 0,
    /**Do not perform cross-packet match. */
    HFA_SEARCHCTX_FNOCROSS = PPIFNOCROSS,
    /**Report only the first match per search */
    HFA_SEARCHCTX_FSINGLEMATCH = PPIFSINGLEMATCH,
    /**Initialize post process statistics */
    HFA_SEARCHCTX_FENABLE_PPSTATS = 4
}hfa_searchctx_iflags_t;

/** Output flags from post-processor */
typedef enum {
    HFA_PP_OFLAGS_FSAVEBUF = PPOFBUFFER
}hfa_pp_oflags_t;

/** Search Context Status*/
typedef enum {
    HFA_SEARCHCTX_SINITIAL   = 1,
    HFA_SEARCHCTX_SGRAPH_SET = 2,
    HFA_SEARCHCTX_SPPUARG_SET = 4,
    HFA_SEARCHCTX_SPPSTATS_SET = 8
} hfa_searchctx_status_t;

/** Search Status*/
typedef enum {
    /** try to get status again later */
    HFA_SEARCH_SEAGAIN   = CVM_HFA_EAGAIN,
    /** Reason code returned by HFA engine */ 
    HFA_SEARCH_SDONE     = HFA_REASON_DDONE,
    HFA_SEARCH_SERR      = HFA_REASON_ERR,
    HFA_SEARCH_SRFULL    = HFA_REASON_RFULL,
    HFA_SEARCH_STERM     = HFA_REASON_TERM,
    HFA_SEARCH_SNOGRAPH  = HFA_REASON_NOGRAPH,
    HFA_SEARCH_SGDONE    = HFA_REASON_GDONE,
    HFA_SEARCH_SGERR     = HFA_REASON_GERR
} hfa_searchstatus_t;

/** Hardware and software search context */
typedef struct hfa_savedsearchctx {
    /**HW state*/
    hfa_snode_t         enode;
    /**HW state*/
    hfa_snode2_t        enode2;
    /**Post processing State*/
    ppstate_t           state;
} hfa_savedsearchctx_t;

/** Search context data structure */
typedef struct hfa_searchctx { 
    /** Search context flags such as Singlematch, Cross pkt match*/
    uint64_t                flags;
    /** Pointer to Graph*/
    hfa_graph_t             *pgraph;
    /** Savedsearch context - HW and SW state*/
    hfa_savedsearchctx_t    savedctx;
    /** Keeping track of search status from HFA HW*/
    uint32_t                ctx_status;
#ifdef HFA_CTX_STATS
#if (HFA_SCTX_STATS == HFA_PER_CORE_CTX_STATS)
    /*Context statistics */
    hfa_ctx_stats_t         ctx_stats;
#elif (HFA_SCTX_STATS == HFA_SHARED_CTX_STATS)
    hfa_ctx_stats_t         **ctx_stats;
#endif
    uint32_t                ppalloc_magicno;                
#endif    
} hfa_searchctx_t;

/**
 * Output search parameter provided by application
 * Depending upon used mode - Single or Gather
 */
typedef union {
    struct {
        /**Input Iovec List pointer or Input buffer pointer*/
        void            *ptr;
        /**Input Iovec Len or Input buffer size*/
        uint32_t        length;
        /**Is iovec*/
        uint32_t        is_iovec;
    };
    /**Direct output buffer (Non-iovec)*/
    struct sparam_data_direct {
        uint8_t         *ptr;             /**Single*/
        uint32_t        len;
        uint32_t        is_iovec;
    } d;
    /**Output buffer - gather mode*/
    struct sparam_data_gather{
        hfa_iovec_t     *piovec;
        uint32_t        ioveclen;
        uint32_t        is_iovec;
    } g;                                 /**Gather Mode*/
} hfa_output_t;

/**
 * Gather input search parameter
 */
typedef struct {
    /** Iovec List*/
    hfa_iovec_t     *piovec;
    /**Number of Iovecs*/
    uint32_t        ioveclen;
} hfa_input_t;

/**
 * HFA hardware and Post processing fields returned to 
 * Application
 */
typedef struct {
    /**Reason from Hardware RWORD0[ 63:61]*/
    hfa_reason_t   reason;

    /**Output flags from post-processing*/
    hfa_ppoflags_t      oflags;

    /**Packet data byte offset which indicate last input
     * HTE byte processed*/    
    hfa_pdboff_t        pdboffset;

}hfa_search_hwpp_ofields_t;

/**
 * Search Parameters set by Application.
 * Application needs to set following parameters depending upon the 
 * different search modes supported by OCTEON HFA block
 */
typedef struct hfa_searchparams { 
    /** WQE has to be provided if WQE based ASYNC search used*/
    cvmx_wqe_t                  *wqe;
    
    /** Cluster number on which search has to be done */
    int                         clusterno;
    
    /** For nth iovec search, total iovecs [0...n] to be provided if flags
     * HFA_SEARCHCTX_FNOCROSS (unset) + HFA_SEARCHCTX_FSAVEBUF (set) found
     * in psparam->ofields->oflags after completing post processing of 
     * n-1 iovec
     */
    hfa_input_t                 input_0_n;
    
    /** current nth iovec ready for submit to hardware*/
    hfa_input_t                 input_n;
    
    /**Output buffer parameters*/
    hfa_output_t                output;
  
    /**HW and Post processing search fields provided to 
     * application*/ 
    hfa_search_hwpp_ofields_t   ofields;
    hfa_matchcb_t               matchcb;
    void                        *cbarg; 
#ifdef HFA_CTX_STATS
    hfa_searchctx_t             *psctx;
#endif
} hfa_searchparams_t;

/*Buffer to overload wqe->packet_data */
typedef struct hfa_wqe_pktdata_overload{
    uint64_t                    psctx;
    uint64_t                    psparam;
    uint64_t                    rptr;
    uint64_t                    pktwqe;
    uint64_t                    pnctx;
    uint64_t                    pgraph;
    uint64_t                    itype;
    uint64_t                    clno;
    uint64_t                    unused0;
    uint64_t                    unused1;
    uint64_t                    unused2;
    uint64_t                    unused3;
}hfa_wqe_pktdata_overload_t;

/**Reserve elements saved by HFA API in rptr*/
typedef struct {
    uint64_t                    start_ptr;
    uint64_t                    ilen;
}hfa_rptr_reserve_t;

/**Result buffer overload structure*/
typedef struct {
    hfa_rptr_reserve_t          reserve;
    uint64_t                    rptrbase;
}hfa_rptr_overload_t; 
/** 
 * This routine is a variant of hfa_searchparam_set_inputiovec() when the
 * previously searched input IO vectors are also set in sparam.
 * Only a portion of the input IO vectors will be used to perform the
 * pattern-search. The @b ioveclen_0_n parameter specifies the total number of
 * IO vectors including the older IO vectors and newest IO vector yet to be
 * scanned. The @b ioveclen parameter specifies the number of IO vectors that
 * need to be scanned(i.e. the Nth set of IO vectors). The IO vectors from @b 0
 * to <b>[ioveclen_0_n - ioveclen]</b> represent the older(previously searched
 * IO vectors).
 *
 * This routine should be used when hfa_searchparam_get_ppoflags() returns the
 * HFA_SEARCHCTX_FSAVEBUF flag. This indicates that the post-processor(as part
 * of hfa_searchctx_getmatches()) may require access to previous input buffers
 * in order to report some matches. As a result the application must preserve
 * these buffers and should not free them. hfa_searchctx_getmatches() will make
 * use of all the IO vectors from @b 0 to @b N.
 *
 * If ioveclen_0_n and ioveclen are equal, this routine is effectively same as
 * hfa_searchparam_set_inputiovec().
 * 
 * @param   psparam         Pointer to search parameter
 * @param   piovec_0_n      Pointer to iovec array [0..n]
 * @param   ioveclen_0_n    Length of total iovecs including nth iovec len
 * @param   ioveclen        Length of nth iovec len 
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_searchparam_set_inputiovec_0_n (hfa_searchparams_t *psparam, 
     hfa_iovec_t *piovec_0_n, uint32_t ioveclen_0_n, uint32_t ioveclen)
{
    hfa_iovec_t *piovec_n = NULL;
    uint32_t    off=0;

    if(hfa_os_likely(psparam && piovec_0_n)){
        if(ioveclen > ioveclen_0_n){
            return HFA_FAILURE;
        }
        HFA_SET (psparam, input_0_n, piovec, piovec_0_n); 
        HFA_SET (psparam, input_0_n, ioveclen, ioveclen_0_n); 

        /*Set input iovec_n*/
        off = ioveclen_0_n - ioveclen;
        piovec_n = piovec_0_n + off;
        HFA_SET (psparam, input_n, piovec, piovec_n); 
        HFA_SET (psparam, input_n, ioveclen, ioveclen); 

        return HFA_SUCCESS;
    } 
    return HFA_FAILURE;
}
/**
 * This routine adds a new input IO vector to Search Param. The Search
 * Param(sparam) represets a set parameters necessary to perform a pattern
 * search. It includes the input buffer/payload, the buffer to hold the HFA
 * engine search results, a match callback setting, a WQE pointer, cluster
 * setting, and post-processing flags.
 *
 * The input IO vector contains chunks of buffer/payload data which will be
 * searched by HFA engine for patterns. The application must ensure that the
 * buffers are readable by HFA engine, by using appropriate type of memory.
 *
 * Refer to hfa_searchparam_set_inputiovec_0_n() for a variant of this routine
 * and its use-case.
 * 
 * @param   psparam         Pointer to search parameter
 * @param   piovec          Pointer to iovec array [0..n]
 * @param   ioveclen        Length of iovec array(number of IO vectors)
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_searchparam_set_inputiovec (hfa_searchparams_t *psparam, 
                                hfa_iovec_t *piovec, uint32_t ioveclen)
{
    if(hfa_os_likely(psparam && piovec)){
        HFA_SET (psparam, input_n, piovec, piovec); 
        HFA_SET (psparam, input_n, ioveclen, ioveclen); 

        HFA_SET (psparam, input_0_n, piovec, piovec); 
        HFA_SET (psparam, input_0_n, ioveclen, ioveclen); 
        return HFA_SUCCESS;
    } 
    return HFA_FAILURE;
}
/**
 * @cond INTERNAL
 * This routine sets the output IO vectors in the sparam. The output IO vectors
 * hold the HFA engine search results and hence the application must ensure
 * that the memory used is writable by the HFA engine.
 *
 * @param   psparam         Pointer to search parameter
 * @param   piovec          Pointer to output iovec array
 * @param   ioveclen        Length of iovec len 
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t 
hfa_searchparam_set_outputiovec (hfa_searchparams_t *psparam, 
                           hfa_iovec_t *piovec, uint32_t ioveclen)
{
    if(hfa_os_likely(psparam && piovec)){
        HFA_SET (psparam, output, g.piovec, piovec); 
        HFA_SET (psparam, output, g.ioveclen, ioveclen); 
        HFA_SET (psparam, output, g.is_iovec, 1);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/** @endcond */
/**
 * This routine sets the output buffer in the sparam. The output buffer holds
 * the HFA engine search results and hence the application must ensure that the
 * memory used is writable by the HFA engine.
 *
 * @param   psparam         Pointer to search parameter
 * @param   ptr             Pointer to the buffer
 * @param   len             Length of the output buffer
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t 
hfa_searchparam_set_output (hfa_searchparams_t *psparam, 
                            uint8_t *ptr, uint32_t len)
{
    if(hfa_os_likely(psparam && ptr)){
        HFA_SET (psparam, output, d.ptr, ptr); 
        HFA_SET (psparam, output, d.len, len); 
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/** 
 * This routine configures the application callback routine which will be
 * invoked when a pattern match is found. The callback will be invoked as part
 * of the application invocation of hfa_searchctx_getmatches(). The callback
 * will be invoked for every match found based on search settings.
 *
 * @param   psparam     pointer to Search parameter
 * @param   cb          pointer to match callback function
 * @param   cbarg       arguments to match callback function
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_searchparam_set_matchcb(hfa_searchparams_t *psparam, hfa_matchcb_t cb, 
                            void *cbarg)
{
    hfa_dbg("psparam: %p\n", psparam);
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely(NULL == psparam)){
        hfa_err(CVM_HFA_EINVALARG, ("psparam: %p\n", psparam));
        return HFA_FAILURE;
    }
#endif
    psparam->matchcb = cb;
    psparam->cbarg = cbarg;
    return HFA_SUCCESS; 
}
/**
 * This routine retrieves the reason code after a search operation has been
 * completed by the HFA engine. The reason code is written by the hardware to
 * the output buffer set in sparam using hfa_searchparam_set_output(). The
 * routine extracts it from the output buffer and makes it available to the
 * caller.
 *
 * @param   psparam         Pointer to search parameter
 * @param   preason         Address of variable where API writes hardware reason
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 *
 */
static inline hfa_return_t
hfa_searchparam_get_hwsearch_reason (hfa_searchparams_t *psparam,
                                     hfa_reason_t *preason)
{
    uint64_t                *ptr_odata = NULL;
    uint64_t                _rmdata = 0;
    hfa_rmdata_t            *prmdata = NULL;
    hfa_rptr_overload_t     *rbuf = NULL;
    
    if(hfa_os_likely(psparam && preason)){
        rbuf = (hfa_rptr_overload_t *)psparam->output.ptr;
        ptr_odata = &(rbuf->rptrbase);

        _rmdata = (((uint64_t *) ptr_odata)[0]);
        prmdata = ((hfa_rmdata_t *) &_rmdata);
    
        psparam->ofields.reason = prmdata->s.reason;
        *preason = psparam->ofields.reason;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine retrieves flags returned by post-processor. The post-processor
 * can return the HFA_SEARCHCTX_FSAVEBUF flag to indicate that the application
 * must preserve the input buffer and provide it during subsequent invocations
 * of hfa_searchctx_getmatches(). The application should call this routine and
 * check if HFA_SEARCHCTX_FSAVEBUF is set and act accordingly. This routine
 * should be called after hfa_searchctx_getmatches().
 *
 * @param   psparam         Pointer to search parameter
 * @param   pppoflags      Pointer to ppoflags
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfa_searchparam_get_ppoflags (hfa_searchparams_t *psparam,
                              hfa_ppoflags_t    *pppoflags)
{
    if(hfa_os_likely(psparam && pppoflags)){
        *pppoflags = psparam->ofields.oflags;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * This routine returns the data-buffer offset. The data-buffer offset indicates
 * how much of the input buffer has been searched by the HFA engine. Ideally the
 * HFA engine will search the entire buffer and write the results to the output
 * buffer. However, under some circumstances(for ex: if output buffer is full
 * and hardware cannot write any more results), the search is incomplete and HFA
 * engine indicates the progress made using the data-buffer offset.
 * Application must check this field if HFA engine returned HFA_REASON_RFULL as
 * the reason code(via hfa_searchparam_get_hwsearch_reason()) and launch another
 * search after providing a new output buffer. The data-buffer offset should be
 * used to adjust the input IO vectors such that data that has already been
 * searched by the hardware is not searched again.
 *
 * @param   psparam         Pointer to search parameter
 * @param   ppdboff          Pointer to pdboffset
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 *
 */
static inline hfa_return_t
hfa_searchparam_get_hwsearch_pdboff (hfa_searchparams_t *psparam,
                                     hfa_pdboff_t *ppdboff)
{
    uint64_t                *ptr_odata = NULL;
    uint64_t                _rmdata = 0, _rword = 0;
    hfa_rmdata_t            *prmdata = NULL;
    hfa_rword_t             *prword = NULL;
    hfa_rptr_overload_t     *rbuf = NULL;
    
    if(hfa_os_likely(psparam && ppdboff && psparam->output.ptr)){
        rbuf = (hfa_rptr_overload_t *)psparam->output.ptr;
        ptr_odata = &(rbuf->rptrbase);        
        
        _rmdata = (((uint64_t *) ptr_odata)[0]);
        prmdata = ((hfa_rmdata_t *) &_rmdata);
        _rword = (((uint64_t *) ptr_odata)[prmdata->s.nument]);
        prword = (hfa_rword_t *) &_rword;

        psparam->ofields.pdboffset = prword->s.offset +1;
        *ppdboff = psparam->ofields.pdboffset;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Set WQE field in Search parameter
 *
 * @param   psparam     Pointer to Search parameter
 * @param   wqe         Pointer to WQE
 *
 * @return  HFA_SUCCESS if wqe is set to psparam, HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_searchparam_set_wqe (hfa_searchparams_t *psparam, cvmx_wqe_t *wqe)
{
    if(hfa_os_likely(psparam && wqe)){
        psparam->wqe = wqe;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}

/**@cond INTERNAL */
/*Function Declarations*/
hfa_return_t hfa_dev_searchctx_init (hfa_dev_t *, hfa_searchctx_t*);
hfa_return_t hfa_dev_searchctx_cleanup (hfa_dev_t *, hfa_searchctx_t*);
hfa_return_t hfa_searchctx_setgraph (hfa_searchctx_t*, hfa_graph_t *);
hfa_return_t hfa_searchctx_setppuarg(hfa_searchctx_t *, void *);
hfa_return_t hfa_searchctx_get_ppstats(hfa_searchctx_t *, hfa_ppstats_t **);
hfa_return_t hfa_searchctx_ppstats_print(hfa_searchctx_t *);
hfa_return_t hfa_searchctx_setflags (hfa_searchctx_t*, hfa_size_t flags);
hfa_return_t hfa_searchctx_search_async (hfa_searchctx_t *, 
                                         hfa_searchparams_t *);
hfa_return_t hfa_searchctx_search (hfa_searchctx_t*, hfa_searchparams_t *);
hfa_return_t hfa_searchctx_get_searchstatus(hfa_searchctx_t *, 
                                            hfa_searchparams_t *, 
                                            hfa_searchstatus_t *);
hfa_return_t hfa_searchctx_processwork (cvmx_wqe_t *wqe, hfa_searchctx_t **,
                                                         hfa_searchparams_t **);
hfa_return_t hfa_searchctx_getmatches (hfa_searchctx_t *, 
                                       hfa_searchparams_t *, uint64_t **);
uint64_t hfa_match_get(hfa_searchctx_t *, uint64_t **, int *);
hfa_return_t hfa_matches_cleanup(ppstate_t *, uint64_t *);
hfa_return_t hfa_savedctx_cleanup(hfa_searchctx_t *psctx);
/**@endcond */
#endif
