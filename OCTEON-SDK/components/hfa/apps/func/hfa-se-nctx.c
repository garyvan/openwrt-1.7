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
 * using poll mode and multiple search-ctx per core.Each core maintains a 
 * linked list of all search ctxts.Each core gets the packet to be searched 
 * and performs search on each ctx by parsing through the linked list.Each core
 * submits a search on a ctx if no other search is pending on that ctx.After 
 * submission each core polls once for all submitted searches.If a search is 
 * completed the result is processed otherwise it moves to the next context. 
 * The core will not block till search completes. Each core moves to the next 
 * packet after it completes the search process on each ctx. The result buffer 
 * is allocated per ctx. The following lists the operational aspects of this 
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
 * - Number of ctx - 1 per core by default. Configurable using cmdline option
 * - Locks used by app - NONE(since contexts are private to each core)
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - 0 by default. Configurable, but limited to 1 cluster
 * - Buffer Payload - Supported. Same payload is used by all cores
 * - PCAP Payload - Not Supported
 * - Cross Packet Search - Enabled
 * - FSAVEBUF - Not Supported
 */

#include <cvm-hfa-graph.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa.h>
#include <pcap.h>
#include <app-utils.h>

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         graph; 
CVMX_SHARED void                *graph_data = NULL, *payload_data = NULL;
CVMX_SHARED uint32_t            init_success=0;
CVMX_SHARED hfa_size_t          rsize = 0;

GLOBAL hfautils_listhead_t             nctx_glist;
GLOBAL hfautils_listhead_t             subctx_glist;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT = 4,
    PATTR_INIT = 5,
    PKTBUF_INIT        
}error_stage_t;

typedef enum {
    SUBMITTED =1,
    PROCESSED
}ctxstatus_t;

typedef struct {
    /* list for ncontexts */
    hfautils_listhead_t glist;
    /* list for submitted contexts */
    hfautils_listhead_t slist;
    hfa_searchctx_t     ctx;
    hfa_searchparams_t  sparam;
    hfa_iovec_t         input;
    void                *rptr;
    ctxstatus_t         status;
}hfa_searchnode_t;

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
                    (hfa_searchctx_t *) NULL);
        default:
            hfautils_reset_octeon ();
            break;
    }
}
/**
 * cleanup search ctx and search node  
 */
static inline void 
snode_cleanup(void) 
{
    hfautils_listhead_t *gnode = NULL, *gnode_next = NULL;
    hfa_searchnode_t    *pnode = NULL;

    hfautils_listforeachsafe(gnode, gnode_next, &nctx_glist){
        pnode = hfautils_listentry (gnode, hfa_searchnode_t, glist);
        if(pnode->rptr) {
            hfautils_memoryfree(pnode->rptr, rsize, 
                            (hfa_searchctx_t *) NULL);
        }
        if((pnode->ctx).pgraph)
            hfa_dev_searchctx_cleanup (&hfa_dev, &pnode->ctx);
        hfautils_memoryfree(pnode, sizeof(hfa_searchnode_t),
                                    (hfa_searchctx_t *) NULL);
    }
}
/**
 * Set search parameters and submit a search instruction to HW 
 */
static inline hfa_return_t
submit(hfa_searchnode_t *pnode, void *payload, int64_t psize) 
{
    hfa_searchparams_t      *psparam = NULL;   

    psparam = &pnode->sparam;
    memset (&pnode->input, 0, sizeof(hfa_iovec_t));
    memset (psparam, 0, sizeof (hfa_searchparams_t));

    /* setup all input buffers as needed for parse results*/
    psparam->clusterno = options.cluster;

    pnode->input.ptr = payload;
    pnode->input.len = psize;

    /*set input parameters to search*/
    hfa_searchparam_set_inputiovec (psparam, &pnode->input, 1);

    /*set output parameters to search */
    hfa_searchparam_set_output(psparam, pnode->rptr, rsize);
    
    /*Submit a search instruction to the HW */
    if(HFA_SUCCESS != hfa_searchctx_search_async(&pnode->ctx, psparam)){
        ERR("hfa_searchctx_search() failure\n");
        return HFA_FAILURE;
    }
    pnode->status = SUBMITTED;
    return HFA_SUCCESS;
}
/**
 * Post process the results from HFA and record found matches
 */
static inline hfa_return_t
post_process(hfa_searchnode_t *pnode, hfa_size_t *nmatches, 
                                    hfa_pdboff_t *pdboffset)
{
    uint64_t                *pmatches = NULL;
    int                     boffset = 0; 
    uint32_t                reason = 0;


    /*Get the search reason from hardware*/
    hfa_searchparam_get_hwsearch_reason(&pnode->sparam, &reason);

    if (reason != HFA_REASON_DDONE &&
            reason != HFA_REASON_RFULL){
        ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
        hfa_dump_regs();
        return HFA_FAILURE;
    }
    /*Get the pdboffset from hardware*/
    hfa_searchparam_get_hwsearch_pdboff (&pnode->sparam, pdboffset);
    DBG("pdboffset = %lu\n", *pdboffset);
    /* Post process the results from HFA and record found matches*/
    if(HFA_SUCCESS != hfa_searchctx_getmatches (&pnode->ctx, 
                                &pnode->sparam, &pmatches)){
        ERR ("searchctx getmatches failure()\n");
        return HFA_FAILURE;
    }
    /*matches points to match buffer allocated by post processing*/
    hfautils_print_matches (&pnode->ctx, pmatches, nmatches, boffset, 
                                                     options.verbose);
    
    return HFA_SUCCESS;
}
/**
 * Poll for the pending search instructions in the HW
 * (blocked till instruction completes) and process them. 
 */
static inline void 
poll(hfa_size_t *nmatches, hfa_pdboff_t *pdboffset) 
{
    uint32_t            status = 0;
    hfautils_listhead_t *snode = NULL, *snode_next = NULL;
    hfa_searchnode_t    *pnode = NULL;

    /* Parse through the submitted list and process  
     * pending instructions in the HW */
    hfautils_listforeachsafe(snode, snode_next, &subctx_glist){
        pnode = hfautils_listentry (snode, hfa_searchnode_t, slist);

        do {
            status=0;
            if(HFA_SUCCESS != hfa_searchctx_get_searchstatus(&pnode->ctx, 
                                        &pnode->sparam, &status)){
                ERR("from hfa_searchctx_get_searchstatus: 0x%x\n", status);
            }
        }while(CVM_HFA_EAGAIN == status);

        pnode->status = PROCESSED;
        
        /*Remove node from submitted list*/
        hfautils_listdel(&pnode->slist);

        post_process(pnode, nmatches, pdboffset);
    }
}
/**
 * Initialize search context object for nctxts and a global list 
 * to track nctxts. 
 */
static inline hfa_return_t 
initialize_ctx_glist(void)
{
    hfa_searchnode_t    *pnode = NULL;
    int                 i = 0;
    
    /*Initialize Global list maintaining search ctx/sparam*/
    HFA_OS_LISTHEAD_INIT(&nctx_glist);

    for(i = 0; i< options.nsearchctx; i++){
        /*Allocate node*/
        if(NULL == (pnode = hfautils_memoryalloc(sizeof(hfa_searchnode_t), 8, 
                                                   (hfa_searchctx_t *)NULL))){
            ERR("Failure in allocating search node\n");
            goto snode_cleanup;
        }     
        memset(pnode, 0, sizeof(hfa_searchnode_t));
        
        /* Create a global list for contexts */
        HFA_OS_LISTHEAD_INIT(&pnode->glist);

        /*initialize search context object */
        if(HFA_SUCCESS != hfa_dev_searchctx_init (&hfa_dev, &pnode->ctx)){
            ERR("SearchCtx Init Failure\n");
            hfautils_memoryfree(pnode, sizeof(hfa_searchnode_t),
                                        (hfa_searchctx_t *) NULL);
            goto snode_cleanup;
        }
        /*bind graph to the context */
        if(HFA_SUCCESS != hfa_searchctx_setgraph (&pnode->ctx, &graph)){
            ERR("Searchctx_setgraph Failure\n");
            hfautils_memoryfree(pnode, sizeof(hfa_searchnode_t),
                                        (hfa_searchctx_t *) NULL);
            goto snode_cleanup;
        }
        if(NULL == (pnode->rptr = 
            hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)NULL))){
            ERR("Rptr allocation failure\n");
            hfautils_memoryfree(pnode, sizeof(hfa_searchnode_t),
                                        (hfa_searchctx_t *) NULL);
            goto snode_cleanup;
        }

        /*set flags for search*/
        hfa_searchctx_setflags (&pnode->ctx, options.pfflags);

        /*Add node to global list to process search later*/
        hfautils_listadd(&pnode->glist, &nctx_glist);
    }
    return HFA_SUCCESS;

snode_cleanup:
    snode_cleanup();
    return HFA_FAILURE; 
}
/**
 * Load graph into HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    uint32_t                    status = 0;
    
    /*initialize graph object*/
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
 * Process command line options, read graph 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    hfautils_options_init(&options);
    options.nsearchctx = 1;
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return HFA_FAILURE;
    }
    if(options.pcap){
        ERR("PCAP file not supported\n");
        return HFA_FAILURE;
    }
    if(options.chunksize < options.payloadsize) {
        LOG("WARNING: This application doesn't support FSAVEBUF. " 
            "The application might not find all the matches in the payload\n");
    }
    /* Read graph and payload */
    if(HFA_SUCCESS != hfautils_read_file(options.graph, 
                &graph_data, options.graphsize)){
        ERR ("Error in reading graph\n");
        return HFA_FAILURE;
    }
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    
    return HFA_SUCCESS;
}

int 
main (int argc, char **argv)
{
    uint64_t                    nmatches=0 , tot_matches=0;
    uint32_t                    status = 0;
    hfa_return_t                retval = HFA_FAILURE;
    hfa_searchnode_t            *pnode = NULL;
    hfautils_listhead_t         *gnode = NULL, *gnode_next = NULL;
    hfautils_listhead_t         *snode = NULL, *snode_next = NULL;
    int64_t                     psize=0;
    void                        *payload = NULL;
    hfautils_payload_attr_t     pattr;
    hfa_pdboff_t                pdboffset = 0;
    int                         stage = -1;
    
    cvmx_user_app_init ();
    hfautils_register_signalhandler();
    if (cvmx_is_init_core ()) {
        
        /* Process command line options, read graph */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto error;
        }
        /*initialize HFA device and device driver*/
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
        init_success = 1;
    }
error:
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    
    if(init_success){

        /* Initialize a global list to track nctxts */
        if(HFA_SUCCESS != initialize_ctx_glist()) {
            ERR("Failure in intialize_ctx_glist\n");   
            stage = GRAPH_INIT;
            goto m_cleanup;
        } 
        memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
        /* Initialize attributes for parsing the payload file */
        if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
            ERR ("Failure in hfautils_init_payload_attributes\n");
            stage = CTX_INIT;
            goto m_cleanup;
        }
        /*Initialize Global list maintaining submitted ctx/sparam*/
        HFA_OS_LISTHEAD_INIT(&subctx_glist);
    
        /* Parse through payload and process search  */     
        while(!gzeof(pattr.gzf)) {
            /* Get a pcacket buffer from payload file */
            if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
                if(gzeof(pattr.gzf))
                    break;
                ERR("Failure in hfautils_parse_payload\n");
                stage = PATTR_INIT;
                goto m_cleanup;
            }
            psize = pattr.psize;
            payload = pattr.payload;
            /* This while loop is for RFULL case, if RFULL occures it will 
             * keep sending the data till all data consumed in a packet 
             * by HFA engine */
            while(psize > 0) {
                hfautils_listforeachsafe(gnode, gnode_next, &nctx_glist){
                    pnode = hfautils_listentry (gnode, hfa_searchnode_t, glist);

                    /* submit if no other search pending on context */ 
                    if(pnode->status != SUBMITTED) {
                        if(HFA_SUCCESS != submit(pnode, payload, psize)) {
                            ERR("submit failed \n");
                            stage = PKTBUF_INIT;
                            goto m_cleanup;
                        }
                        /* Create a list for submitted contexts */
                        HFA_OS_LISTHEAD_INIT(&pnode->slist);
                        /*Add node to list and check search status later*/
                        hfautils_listadd(&pnode->slist, &subctx_glist);
                    }
                    /* Poll once for all submitted searches */
                    hfautils_listforeachsafe(snode, snode_next, &subctx_glist){
                        pnode =hfautils_listentry(snode,hfa_searchnode_t,slist);

                        hfa_searchctx_get_searchstatus(&pnode->ctx,
                                &pnode->sparam, &status);
                        if(HFA_SEARCH_SEAGAIN == status){
                            continue;
                        }
                        pnode->status = PROCESSED;
                        /*Remove node from submitted list*/
                        hfautils_listdel(&pnode->slist);
                        post_process(pnode, &nmatches, &pdboffset);
                    }  
                }
                /* poll for pending search instructions in HW, 
                 * blocked till instruction completes*/
                poll(&nmatches, &pdboffset); 
                psize -= pdboffset;
                payload += pdboffset;
                tot_matches += nmatches;
                nmatches = 0;
            }
            /* Cleanup allocated memory for payload buffer */
            hfautils_memoryfree(pattr.payload, pattr.psize, 
                                        (hfa_searchctx_t *)NULL);
        }
        LOG("Total matches: %lu (%lu per sctx) \n", tot_matches, 
                                (tot_matches/options.nsearchctx));
        retval = HFA_SUCCESS;
        stage = PATTR_INIT;
    } else {
        retval = HFA_FAILURE;
    }

m_cleanup:
    switch(stage) {
        case PKTBUF_INIT:
            hfautils_memoryfree(pattr.payload, pattr.psize, 
                                        (hfa_searchctx_t *)NULL);
        case PATTR_INIT:
            hfautils_cleanup_payload_attributes(&pattr, &options);
            poll(&nmatches, &pdboffset);
        case CTX_INIT:
            snode_cleanup();
            stage = GRAPH_INIT;
        default:
            break;
    }
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if (cvmx_is_init_core ())
        cleanup(stage);
    
    return retval;
}
