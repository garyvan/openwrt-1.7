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
 * SE/SEUM:
 * Reference application to showcase HFA API in asynchronous mode of operation
 * using WQE(rather than poll-mode) and multiple search contexts across cores.
 * It reports the pattern-matches(only one core will report matches) found in
 * the payload based on graph(compiled using the pattern file). Each core
 * submits search operation on its context and gets a WQE entry from SSO. The
 * WQE may or may not correspond to the search operation submitted by the same
 * core. Hence the contexts are shared and locking is required. The following
 * lists the operational aspects of this application.
 * - Multicore - YES
 * - Type of API 
 *       - Asynchronous OO API(cacheload and search)
 *       - Synchronous OO API(memload)
 * - Cluster resources - Managed by HFA API.
 * - Clusters shared among cores - YES
 * - Graph count - 1 (loaded by first core)
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Shared among cores(initialized by first core).
 * - Number of ctx - 1 per core by default. Configurable using cmdline option
 * - Locks used by app - Spinlock to protect access to search ctx.
 * - WQE - group is set to 0 corenum and the cores dont specify SSO group_mask.
 *   So any core can pick up any WQE.
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - 0 by default. Configurable, but limited to 1 cluster
 * - Buffer Payload - Supported. Same payload is used by all cores
 * - Pcap Payload - Supported. All packets from the pcap file are processed 
 *                  by all cores. The packets are duplicated for each core
 * - Cross Packet Search - Enabled
 * - FSAVEBUF - Not Supported
 *
 */

#include <cvm-hfa-graph.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa.h>
#include <pcap.h>
#include <app-utils.h>
#include <cvmx-sysinfo.h>

typedef struct {
    hfautils_lock_t     lock;
    uint32_t            ctxid;
    hfa_searchctx_t     sctx;
    hfa_iovec_t         iovec;
    void                *curr_payload;
    int64_t             curr_psize;
}hfa_ctx_t;

typedef struct {
    uint32_t            nctx;
    hfa_ctx_t           **ctx_ptrs;
}hfa_ctxdb_t;

typedef struct {
    hfautils_lock_t     lock;
    int64_t             nchunks;
}hfa_track_matches_t;

CVMX_SHARED options_t             options;
CVMX_SHARED hfa_dev_t             hfa_dev;
CVMX_SHARED hfa_graph_t           graph; 
CVMX_SHARED void                  *graph_data = NULL;
CVMX_SHARED hfa_track_matches_t   track_matches; 
CVMX_SHARED hfa_ctxdb_t           ctxdb;
CVMX_SHARED uint32_t              nctx_per_core=0;
CVMX_SHARED uint64_t              rsize =0;
CVMX_SHARED uint32_t              init_success=0;
uint32_t                          current_idx=0;
hfa_size_t                        nmatches;
hfautils_payload_attr_t           pattr;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT = 4,
    PATTR_INIT  
}error_stage_t;

/** 
 * Classify the given number of ctx  among cores
 * based on nctx_per_core 
 */
uint32_t classify(void)
{
    uint32_t    id;
    uint32_t    corenum = cvmx_get_core_num();

    id = (nctx_per_core * corenum) + current_idx;

    current_idx++;

    if(current_idx >= nctx_per_core){
        current_idx = 0;
    }
    return id;
}
/**
 * Cleanup memory allocated for context 
 */
hfa_return_t 
ctxdb_cleanup() 
{  
    int i = 0;
    hfa_ctx_t *pctx = NULL;
    
    for (i = 0; i < options.nsearchctx; i++) {
        pctx = (hfa_ctx_t *)((ctxdb.ctx_ptrs)[i]); 
        if(pctx) {
            if((&pctx->sctx)->pgraph)
                hfa_dev_searchctx_cleanup(&hfa_dev, &pctx->sctx);
            hfautils_memoryfree(pctx, sizeof(hfa_ctx_t), 
                                (hfa_searchctx_t *)NULL);
        }
    }
    if(ctxdb.ctx_ptrs) {
        hfautils_memoryfree(ctxdb.ctx_ptrs, sizeof(hfa_ctx_t *) * ctxdb.nctx, 
                                              (hfa_searchctx_t *)NULL); 
    }
    memset(&ctxdb, 0, sizeof(hfa_ctxdb_t)); 
    return HFA_SUCCESS; 
}
/**
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(int stage) 
{
    switch(stage) {
        case CTX_INIT:
            ctxdb_cleanup();
        case GRAPH_INIT:
            if(!HFA_GET_GRAPHATTR((&graph), memonly)){
                hfa_graph_cacheunload (&graph);
            }
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
        case DEV_INIT:
            hfa_dev_cleanup (&hfa_dev);      
        case OPTIONS_INIT:      
            hfautils_memoryfree(graph_data, options.graphsize, 
                                    (hfa_searchctx_t *)NULL);
        default:
            hfautils_reset_octeon();
            break;
    }
}
/**
 * Allocates memory to store the pointer of each context
 */
hfa_return_t
ctxdb_init(uint32_t nctx)
{
    if(hfautils_likely(nctx)){
        memset(&ctxdb, 0, sizeof(hfa_ctxdb_t));
        if(NULL == (ctxdb.ctx_ptrs = (hfa_ctx_t **)
            hfautils_memoryalloc((sizeof(hfa_ctx_t *) * nctx), 8, 
                                    (hfa_searchctx_t *)NULL))){
            ERR("error in memoryalloc\n");
            return HFA_FAILURE;
        }
        DBG("ctx_ptrs : %p\n",ctxdb.ctx_ptrs);
        ctxdb.nctx = nctx;
        memset(ctxdb.ctx_ptrs, 0, sizeof(hfa_ctx_t *) * nctx);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}

/**
 * Initializes each context database and initializes the 
 * search context object of each context 
 */
hfa_return_t
Initialize_Ctx (uint32_t ctxid, uint64_t flags)
{
    hfa_ctx_t **ppctx = NULL, *pctx = NULL;

    if((ctxdb.ctx_ptrs)[ctxid]){
        ERR("ctx: %d already configured in database\n", ctxid);
        return HFA_FAILURE;
    }
    ppctx = (hfa_ctx_t **)&(((ctxdb.ctx_ptrs)[ctxid]));

    if(NULL == (*ppctx = 
        hfautils_memoryalloc(sizeof(hfa_ctx_t), 8, (hfa_searchctx_t *)NULL))){
        ERR("memoryalloc failure\n");
        return HFA_FAILURE;
    }
    pctx = *ppctx;
    DBG("pctx: %p\n",pctx);
    memset(pctx, 0 , sizeof(hfa_ctx_t));
    hfautils_lockinit(&pctx->lock);
    pctx->ctxid = ctxid;

    /*initialise search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init(&hfa_dev, &pctx->sctx)){
        ERR("error from searchctx_init\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph(&pctx->sctx, &graph)){
        ERR("setgraph failure\n");
        return HFA_FAILURE;
    }
    /*set flags for search*/
    hfa_searchctx_setflags(&pctx->sctx, flags);
    
    return HFA_SUCCESS;
}

/** 
 * Set search parameters and submit WQE to the HW 
 */
hfa_return_t submit_wqe(hfa_ctx_t *pctx)
{
    cvmx_wqe_t                  *wqe = NULL;
    hfa_searchparams_t          *sparam = NULL;
    void                        *rptr = NULL;
    hfa_wqe_pktdata_overload_t  *pktdata = NULL;
   

    if(NULL==(sparam = hfautils_memoryalloc(sizeof(hfa_searchparams_t), 8, 
                                        (hfa_searchctx_t *)(&pctx->sctx)))){
        ERR("memory allocation for sparam failed\n");
        return HFA_FAILURE;
    }
    if(NULL==(rptr = 
        hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)(&pctx->sctx)))){
        ERR("memory allocation for rptr failed\n");
        goto m_free_sparam;
    }
    wqe = cvmx_fpa_alloc (CVMX_FPA_WQE_POOL);
    if(wqe == NULL){
        ERR("wqe allocation failed\n");
        goto m_free_rptr;
    }
    memset (sparam, 0, sizeof(hfa_searchparams_t));
    memset (wqe, 0, sizeof (cvmx_wqe_t));
    memset (&pctx->iovec, 0, sizeof(hfa_iovec_t));
    cvmx_wqe_set_grp(wqe, 0);
        
    pctx->iovec.ptr = pctx->curr_payload;
    pctx->iovec.len = pctx->curr_psize;
    
    DBG("psize: %lu\n", pattr.psize);
    sparam->clusterno = options.cluster;
    /*set input parameters to search*/
    hfa_searchparam_set_inputiovec (sparam, &pctx->iovec, 1);

    /*set output parameters to search */
    hfa_searchparam_set_output(sparam, rptr, rsize);

    pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data; 
    pktdata->rptr = (uint64_t)rptr; 
    pktdata->pnctx = (uint64_t)pctx; 

    sparam->wqe = wqe;

    /* Submit search instruction to the HW(submit wqe to the HW) */
    if(HFA_SUCCESS != 
            hfa_searchctx_search_async (&pctx->sctx, sparam)){
        ERR("hfa_searchctx_search() failure\n");
        goto m_free_wqe;
    }
    hfautils_lock(&track_matches.lock);
    track_matches.nchunks++;
    hfautils_unlock(&track_matches.lock);
    return HFA_SUCCESS;
m_free_wqe:
    cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
m_free_rptr:
    hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)(&pctx->sctx));
m_free_sparam:
    hfautils_memoryfree(sparam, sizeof(hfa_searchparams_t),
                             (hfa_searchctx_t *)(&pctx->sctx));

    return HFA_FAILURE;   
}     
/**
 * Process search for given contexts 
 */
hfa_return_t process_nctx(void)
{
    cvmx_wqe_t                  *wqe = NULL;
    uint32_t                    ctx_id;
    hfa_searchctx_t             *psctx = NULL;
    hfa_searchparams_t          *psparam = NULL;
    hfa_ctx_t                   *pctx = NULL;
    void                        *rptr;
    uint64_t                    *pmatches = NULL;
    hfa_wqe_pktdata_overload_t  *packet_data = NULL;
    int                         boffset = 0;
    hfa_pdboff_t                pdboffset = 0;

    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    /* Initialize attributes for parsing the payload file */
    if(HFA_SUCCESS != 
        hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        return HFA_FAILURE;
    }
    
    /* Parse through payload and process search  */     
    while(!gzeof(pattr.gzf)) {
        /* Get a pcacket buffer from payload file */
        if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
            if(gzeof(pattr.gzf))
                break;
            ERR("Failure in hfautils_parse_payload\n");
            goto pattr_cleanup;
        }
        do
        {
            ctx_id = classify();
            /*Get the pointer to ctx database for the core */
            pctx = (hfa_ctx_t *)((ctxdb.ctx_ptrs)[ctx_id]);
            if(hfautils_unlikely(NULL == pctx)){
                ERR("ctx NULL\n");
                goto process_wqe;
            }
            pctx->curr_payload = pattr.payload;
            pctx->curr_psize = pattr.psize;
            if(HFA_SUCCESS!= submit_wqe(pctx)){
                ERR("submit wqe failed\n");
                goto process_wqe;
            }
            DBG("ctx_id = %u\n",ctx_id);
        }while(current_idx);     
     
/* Get the HW WQE and process them*/
process_wqe:    
        while(track_matches.nchunks){
            wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);

            if(wqe == NULL){
                continue;
            }
            switch(hfa_get_wqe_type(wqe)) {

                case HFA_SEARCH_HWWQE:
                    packet_data = (hfa_wqe_pktdata_overload_t *)
                                  (wqe->packet_data); 
                    /*Process HW WQE */
                    hfa_searchctx_processwork(wqe, &psctx, &psparam);
                    pctx = (hfa_ctx_t *)packet_data->pnctx;
                    rptr = (void*)packet_data->rptr;

                    hfautils_lock(&pctx->lock);

                    /*Get the pdboffset from hardware*/
                    hfa_searchparam_get_hwsearch_pdboff (psparam, &pdboffset);
                    DBG("pdboffset = %lu\n", pdboffset);

                    hfa_searchctx_getmatches(psctx, psparam, &pmatches);

                    DBG("wqe:%p pctx:%p \n", wqe,pctx);

                    hfautils_print_matches(psctx, pmatches, &nmatches, 
                            boffset, options.verbose);
                    DBG("nchunks: %ld \n",track_matches.nchunks);
                    hfautils_lock(&track_matches.lock);
                    track_matches.nchunks--;
                    hfautils_unlock(&track_matches.lock);

                    pctx->curr_payload += pdboffset;
                    pctx->curr_psize -= pdboffset;

                    hfautils_unlock(&pctx->lock);
                    hfautils_memoryfree(rptr, rsize, 
                            (hfa_searchctx_t *)(&pctx->sctx));
                    cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
                    hfautils_memoryfree(psparam, sizeof(hfa_searchparams_t), 
                            (hfa_searchctx_t *)(&pctx->sctx));
                    if(pctx->curr_psize > 0) {
                        hfautils_lock(&pctx->lock);
                        submit_wqe(pctx);
                        hfautils_unlock(&pctx->lock);
                    }
                    break;
                default:
                    cvmx_pow_work_submit(wqe, wqe->word1.tag, 
                                        wqe->word1.tag_type,
                                        cvmx_wqe_get_qos(wqe), 
                                        cvmx_wqe_get_grp(wqe));
                    break;
            }
        }
        /* Cleanup allocated memory for payload buffer */
        hfautils_memoryfree(pattr.payload, pattr.psize, 
                             (hfa_searchctx_t *)NULL);
    }
    LOG("Total matches  %lu\n", nmatches);
    return HFA_SUCCESS;
pattr_cleanup:
    hfautils_cleanup_payload_attributes(&pattr, &options);
    return HFA_FAILURE;
}
/**
 * Load graph into HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    uint32_t                    status=0;
    
    /*initialise graph object*/
    if(HFA_SUCCESS != hfa_dev_graph_init (&hfa_dev, &graph)){
        ERR("hfa_dev_graph_init() failure\n");
        return HFA_FAILURE;
    }
    /* set the cluster on which this graph will be loaded*/
    if(HFA_SUCCESS != hfa_graph_setcluster (&graph, options.graph_clmsk)){
        ERR("hfa_graph_setcluster() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to HFA memory*/
    if(HFA_SUCCESS != hfautils_download_graph(&graph, graph_data, 
                options.graphsize, GRAPHCHUNK, HFA_TRUE)){
        ERR("hfautils_download_graph() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to cache */
    if(!HFA_GET_GRAPHATTR((&graph), memonly)){
        if( HFA_SUCCESS != hfa_graph_cacheload_async (&graph)){
            ERR("Graph Cacheload failure\n");
            goto graph_cleanup; 
        }
        status=0;
        do {
            if(HFA_SUCCESS != hfa_graph_getstatus(&graph, &status)){
                ERR("hfa_graph_getstatus() 0x%x\n", status);
                goto graph_cleanup; 
            }
        }while(CVM_HFA_EAGAIN == status);
    }
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;

graph_cleanup:
    hfa_dev_graph_cleanup(&hfa_dev, &graph);
    return HFA_FAILURE;
}
/** 
 * Process command line options,read graph 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    int                         ncores=0; 
    
    hfautils_options_init(&options);
    options.nsearchctx = hfautils_get_number_of_cores();
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return HFA_FAILURE;
    }
    if(options.chunksize < options.payloadsize) {
        LOG("WARNING: This application doesn't support FSAVEBUF. " 
            "The application might not find all the matches in the payload\n");
    }
    ncores = hfautils_get_number_of_cores();
    if(!options.nsearchctx){
        ERR("nctx should not be zero\n");
        return HFA_FAILURE;
    } 
    if(options.nsearchctx % ncores){
        ERR("nctx should be multiple of number of cores processing\n");
        return HFA_FAILURE;
    }
    nctx_per_core = options.nsearchctx/ncores;

    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);

    /* Read graph */
    if(HFA_SUCCESS != hfautils_read_file(options.graph,
                &graph_data, options.graphsize)){
        ERR ("Error in reading graph\n");
        return HFA_FAILURE;
    }
    return HFA_SUCCESS;
}         
int 
main (int argc, char **argv)
{
    uint32_t                    i=0;
    int                         stage = -1; 
    hfa_return_t                retval = HFA_FAILURE;
    uint64_t                    wqe_pool_count = 0, ibuf_pool_count = 0;

    cvmx_user_app_init ();
    hfautils_register_signalhandler();
    if (cvmx_is_init_core ()) {
        
        /* Process command line options, read graph */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto error;
        }
        /*initialise HFA device and device driver*/
        if(HFA_SUCCESS != hfa_dev_init(&hfa_dev)){
            ERR("hfa_dev_init failed \n");
            stage = OPTIONS_INIT;
            goto error;
        }
        /* Initialize graph object and load graph */
        if(HFA_SUCCESS != graph_load()) {
            ERR("Failure in graph_load\n");
            stage = DEV_INIT;
            goto error;
        }
        wqe_pool_count = OCTEON_IBUFPOOL_COUNT;
        ibuf_pool_count = 0;

        /* Initialize WQE pools */
        if(HFA_SUCCESS != 
            hfautils_initialize_wqepool(ibuf_pool_count, wqe_pool_count)){
            ERR("wqe pool initialization failed\n");
            stage = GRAPH_INIT;
            goto error;
        } 
        if(HFA_SUCCESS != ctxdb_init(options.nsearchctx)){
            ERR("ctxdb_init failed\n");
            stage = GRAPH_INIT;
            goto error;
        }
        for(i=0; i<options.nsearchctx; i++){
            if(HFA_SUCCESS != Initialize_Ctx(i, options.pfflags)){
                ERR("Failure in creating flow: %d\n", i);
                stage = CTX_INIT;
                goto error;
            }
        }
        hfautils_lockinit(&track_matches.lock);
        init_success = 1;
    }
error:
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    
    if(init_success){
        if(HFA_SUCCESS != process_nctx()){
            LOG("failure in process_nctx\n");
            stage = CTX_INIT;
        }
        cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
        if(stage == CTX_INIT)
            goto m_cleanup;

        retval = HFA_SUCCESS;
        stage = PATTR_INIT;
    } else {
        retval = HFA_FAILURE;
    }
    if(stage == PATTR_INIT) {
        hfautils_cleanup_payload_attributes(&pattr, &options);
        stage = CTX_INIT;
    }
m_cleanup:
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if (cvmx_is_init_core ()) { 
        cleanup(stage);
    }
    return retval;
}
