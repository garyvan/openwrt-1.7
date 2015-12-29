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
 * using WQE(rather than poll-mode). It performs multiple searches per core. It
 * reports the pattern-matches found in the payload based on graph(compiled
 * using the pattern file). The following lists the operational aspects of this
 * application.
 * - Multicore - YES
 * - Type of API 
 *       - Asynchronous OO API(cacheload and search)
 *       - Synchronous OO API(memload)
 * - Cluster resources - Managed by HFA API.
 * - Clusters shared among cores - YES
 * - Graph count - 1 (loaded by first core)
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Private to each core.
 * - Number of searches - 1 per core by default. Configurable using cmdline
 *   option(nctx option)
 * - Locks used by app - NONE(since contexts are private to each core and WQE is
 *   picked up by the core which submitted)
 * - WQE - group is set to each corenum and each will set SSO group_mask to
 *   ensure it only picks up the WQE that the same core submitted.
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - 0 by default. Configurable, but limited to 1 cluster
 * - Buffer Payload - Supported. Same payload is used by all cores
 * - Pcap Payload - Supported. All packets from the pcap file are processed 
 *                  by all cores. The packets are duplicated for each core
 * - Cross Packet Search - Enabled
 * - FSAVEBUF - Not Supported
 */

#include <cvm-hfa-graph.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa.h>
#include <pcap.h>
#include <app-utils.h>

typedef struct {
    hfa_searchctx_t     sctx;
    hfa_iovec_t         iovec;
    void                *curr_payload;
    int64_t             curr_psize;
}hfa_ctx_t;

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         graph; 
CVMX_SHARED void                *graph_data = NULL;
CVMX_SHARED uint32_t            init_success=0;
CVMX_SHARED uint64_t            nctx_onthis_core = 0;
CVMX_SHARED hfa_size_t          rsize=0;

hfa_size_t                      nmatches = 0;
int64_t                         nchunks = 0;
uint64_t                        coregrp = 0;
hfautils_payload_attr_t         pattr;
hfa_ctx_t                       *ppctx = NULL;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    RESTORE_CGRP = 4,
    CTX_INIT  = 5,
    PATTR_INIT 
}error_stage_t;

/**
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(int stage) 
{
    switch (stage) {
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
    }
}
/**
 * Cleanup memory allocated for context 
 */
static inline void 
cleanup_ctx()
{
    int    ctxid = 0;

    for(ctxid=0; ctxid < nctx_onthis_core; ctxid++) {
        if((&ppctx[ctxid].sctx)->pgraph)
            hfa_dev_searchctx_cleanup(&hfa_dev, &(ppctx[ctxid].sctx));
    }
}
/**
 * Initializes the search context object of each context 
 */
hfa_return_t
Initialize_Ctx (uint32_t ctxid)
{
    hfa_ctx_t       *pctx = NULL;

    pctx = &ppctx[ctxid];
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
    hfa_searchctx_setflags(&pctx->sctx, options.pfflags);
    
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
    cvmx_wqe_set_grp(wqe, cvmx_get_core_num());
        
    pctx->iovec.ptr = pctx->curr_payload;
    pctx->iovec.len = pctx->curr_psize;
    
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
    nchunks++;
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
static inline hfa_return_t 
process_nctx(void)
{
    int                         ctxid = 0;
    hfa_ctx_t                   *pctx = NULL;
    hfa_wqe_pktdata_overload_t  *packet_data = NULL;
    hfa_searchctx_t             *psctx = NULL;
    hfa_searchparams_t          *psparam = NULL;
    cvmx_wqe_t                  *wqe = NULL;
    void                        *rptr;
    uint64_t                    *pmatches = NULL;
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
        for(ctxid=0; ctxid < nctx_onthis_core; ctxid++) {
            pctx = &ppctx[ctxid];
            pctx->curr_payload = pattr.payload;
            pctx->curr_psize = pattr.psize;
            if(HFA_SUCCESS != submit_wqe(pctx)){
                ERR("submit wqe failed\n");
                goto process_wqe;
            }
        }
process_wqe:
        while(nchunks){
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

                    /*Get the pdboffset from hardware*/
                    hfa_searchparam_get_hwsearch_pdboff (psparam, &pdboffset);
                    DBG("pdboffset = %lu\n", pdboffset);

                    hfa_searchctx_getmatches(psctx, psparam, &pmatches);

                    DBG("wqe:%p pctx:%p \n", wqe,pctx);

                    hfautils_print_matches(psctx, pmatches, &nmatches, 
                            boffset, options.verbose);
                    DBG("nchunks: %ld \n",nchunks);
                    nchunks--;

                    pctx->curr_payload += pdboffset;
                    pctx->curr_psize -= pdboffset;

                    hfautils_memoryfree(rptr, rsize, 
                            (hfa_searchctx_t *)(&pctx->sctx));
                    cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
                    hfautils_memoryfree(psparam, sizeof(hfa_searchparams_t), 
                            (hfa_searchctx_t *)(&pctx->sctx));
                    if(pctx->curr_psize > 0) {
                        submit_wqe(pctx);
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
 * Process command line options. 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    uint32_t                    ncores=0;
    
    hfautils_options_init(&options);
    options.nsearchctx = hfautils_get_number_of_cores();
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return HFA_FAILURE;
    }
    if(options.chunksize < options.payloadsize) {
        LOG("WARNING: This application doesn't support FSAVEBUF. " 
            "The application might not find all the matches in the payload\n");
    }
    ncores=hfautils_get_number_of_cores();
    if(!options.nsearchctx){
        ERR("nctx should not be zero\n");
        return HFA_FAILURE;
    } 
    if(options.nsearchctx % ncores){
        ERR("nctx should be multiple of number of cores processing\n");
        return HFA_FAILURE;
    }
    nctx_onthis_core = options.nsearchctx/ncores;
    /* Read graph */
    if(HFA_SUCCESS != hfautils_read_file(options.graph, 
                    &graph_data, options.graphsize)){
        ERR ("Error in reading graph \n");
        return HFA_FAILURE;
    }
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    
    return HFA_SUCCESS;
}
int 
main (int argc, char **argv)
{
    hfa_return_t                retval = HFA_FAILURE;
    int                         stage = -1, i = 0;
    uint64_t                    wqe_pool_count = 0, ibuf_pool_count =0; 

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
        /*Initialize FPA_WQE_POOL */
        hfautils_initialize_wqepool(ibuf_pool_count, wqe_pool_count);
        
        init_success = 1;
    }
error:        
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
     
    if(init_success == 1){
     
        coregrp = (unsigned long int)
                  hfautils_get_core_grpmsk(cvmx_get_core_num()); 
        /* set core group mask */
        cvmx_pow_set_group_mask(cvmx_get_core_num(), 1ULL<<cvmx_get_core_num());
        
        if(NULL == (ppctx = 
            hfautils_memoryalloc(sizeof(hfa_ctx_t) * nctx_onthis_core, 8, 
                                            (hfa_searchctx_t *)NULL))){
            ERR("memoryalloc failure\n");
            stage = RESTORE_CGRP;
            goto m_cleanup;
        }
        memset(ppctx, 0 , sizeof(hfa_ctx_t) * nctx_onthis_core);
        
        for(i=0; i < nctx_onthis_core; i++){
            if(HFA_SUCCESS != Initialize_Ctx(i)){
                LOG("Failure in Initialize_Ctx\n");
                stage = CTX_INIT;
                goto m_cleanup;
            }
        }
        if(HFA_SUCCESS != process_nctx()) {
            LOG("failure in process_nctx\n");
            stage = CTX_INIT;
            goto m_cleanup;
        }
        LOG("Total Matches = %lu\n", nmatches);
        retval = HFA_SUCCESS;
        stage = PATTR_INIT;
    }else {
        retval = HFA_FAILURE;
    }
m_cleanup:
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    switch (stage) {
        case PATTR_INIT:
            hfautils_cleanup_payload_attributes(&pattr, &options);
        case CTX_INIT:
            cleanup_ctx(); 
            hfautils_memoryfree(ppctx, sizeof(hfa_ctx_t) * nctx_onthis_core,
                                                (hfa_searchctx_t *)NULL); 
        case RESTORE_CGRP:
            cvmx_pow_set_group_mask(cvmx_get_core_num(), coregrp);
            stage = GRAPH_INIT;
        default:
            break;
    }
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if (cvmx_is_init_core ()) {
        cleanup(stage);
    }
    return retval;
}
