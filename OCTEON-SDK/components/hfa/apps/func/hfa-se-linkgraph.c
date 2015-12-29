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
 * Reference application to showcase simple HFA API with Link graph. It reports
 * the pattern-matches found in the payload based on each graph linked. The
 * following lists the operational aspects of this application.
 * - Multicore - NO(runs on single core)
 * - Type of API - Synchronous OO API
 * - Cluster resources - Managed by HFA API.
 * - Type of graph - Link Graph/Normal Graph 
 * - Graph count - Number of graphs linked in graph file
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Private to the core
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

/* @cond APPINTERNAL */

typedef struct {
    hfa_searchctx_t     sctx;
    hfa_size_t          nmatches;
    int                 boffset;
    hfa_graph_t         subgraph; 
}subgraph_t;

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         graph;

GLOBAL subgraph_t                      *sgraph = NULL;
GLOBAL hfautils_payload_attr_t         pattr;
GLOBAL hfa_searchparams_t              param;    
GLOBAL hfa_size_t                      rsize=0;
GLOBAL void                            *graph_data = NULL;
GLOBAL void                            *rptr = NULL;
GLOBAL hfa_iovec_t                     input;
GLOBAL int                             stage = -1;
GLOBAL int                             graphcount=0;
/* @endcond APPINTERNAL */

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    RPTR_INIT = 4,
    CTX_INIT = 5,
    PKTBUF_INIT
}error_stage_t;

/** 
 * Cleanup will be done by this routine 
 */
static inline void 
cleanup(void) 
{
    int     cnt = 0;

    switch(stage) {
        case PKTBUF_INIT:
            hfautils_memoryfree(pattr.payload, pattr.psize, 
                                    (hfa_searchctx_t *)NULL);
        case CTX_INIT:
            for(cnt = 0; cnt < graphcount; cnt++) 
                hfa_dev_searchctx_cleanup (&hfa_dev, &(sgraph[cnt].sctx));
            hfautils_memoryfree(sgraph, sizeof(subgraph_t) * graphcount, 
                                        (hfa_searchctx_t *)NULL);
        case RPTR_INIT:
            hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)NULL);
        case GRAPH_INIT:        
            if(!HFA_GET_GRAPHATTR((&graph), memonly)){ 
                hfa_graph_cacheunload (&graph);
            }
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
        case DEV_INIT:
            hfa_dev_cleanup (&hfa_dev);        
        case OPTIONS_INIT:      
            hfautils_cleanup_payload_attributes(&pattr, &options);
            hfautils_memoryfree(graph_data, options.graphsize, 
                                            (hfa_searchctx_t *)NULL);
        default:
            hfautils_reset_octeon();
            break;
    }
}
/**
 * Initialize search ctx for each subgraph.
 */ 
static inline hfa_return_t 
Initialize_Ctx(void) 
{
    int cnt = 0;

    if(NULL == (sgraph = hfautils_memoryalloc(sizeof(subgraph_t) * graphcount, 
                                            8, (hfa_searchctx_t *)NULL))) { 
        ERR("Memory allocation failed for CTX\n");
        return HFA_FAILURE;
    }
    memset(sgraph, 0, sizeof(subgraph_t) * graphcount);
    for(cnt=0; cnt < graphcount; cnt++){

        if(HFA_SUCCESS != 
                hfa_graph_getsubgraph(&graph, &(sgraph[cnt].subgraph), cnt)){
            ERR("Error oin fetching subgraph: %d\n", cnt);
            continue;
        }
        /*initialise search context object */
        if(HFA_SUCCESS != 
            hfa_dev_searchctx_init (&hfa_dev, &(sgraph[cnt].sctx))){
            ERR("SearchCtx Init Failure\n");
            goto sgraph_free;
        }
        /*bind graph to the context */
        if(HFA_SUCCESS != hfa_searchctx_setgraph (&(sgraph[cnt].sctx), 
                                        &(sgraph[cnt].subgraph))){
            ERR("Searchctx_setgraph Failure\n");
            goto sgraph_free;
        }
        /*set flags for search*/
        hfa_searchctx_setflags (&(sgraph[cnt].sctx), options.pfflags);
    }
    return HFA_SUCCESS;
sgraph_free:
    hfautils_memoryfree(sgraph, sizeof(subgraph_t) * graphcount, 
                                        (hfa_searchctx_t *)NULL); 
    return HFA_FAILURE;
}

/**
 * Load graph to HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
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
                options.graphsize, GRAPHCHUNK, 0)){
        ERR("hfautils_download_graph() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to cache, if it is a cacheable graph */
    if(!HFA_GET_GRAPHATTR((&graph), memonly)){ 
        if( HFA_SUCCESS != hfa_graph_cacheload (&graph)){
            ERR("Graph Cacheload failure\n");
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
            return HFA_FAILURE; 
        }
    }
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;
}
/** 
 * Process command line options and read graph. 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    hfautils_options_init(&options);
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return (HFA_FAILURE);
    }
    if(options.chunksize < options.payloadsize) {
        LOG("WARNING: This application doesn't support FSAVEBUF. " 
            "The application might not find all the matches in the payload\n");
    }
    /* Read graph */
    if(HFA_SUCCESS != hfautils_read_file(options.graph, 
                        &graph_data, options.graphsize)){
        ERR ("Error in reading graph\n");
        return (HFA_FAILURE);
    }
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    /* Initialize attributes for parsing the payload file */
    if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        goto gfree;
    }
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    
    return HFA_SUCCESS;
gfree:
    hfautils_memoryfree(graph_data, options.graphsize, 
                                  (hfa_searchctx_t *)NULL);
    return HFA_FAILURE;
}
int 
main (int argc, char **argv)
{ 
    uint32_t                    reason = 0;
    uint64_t                    *pmatches = NULL;
    int                         cnt;
    hfa_pdboff_t                pdboffset = 0;
    int64_t                     psize = 0;
    void                        *payload = NULL;

    cvmx_user_app_init ();
    hfautils_register_signalhandler();
    if (cvmx_is_init_core ()) {

        /* Process command line options, read graph */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto m_cleanup;
        }
        /*initialise HFA device and device driver*/
        if(HFA_SUCCESS != hfa_dev_init(&hfa_dev)){
            ERR("hfa_dev_init failed \n");
            stage = OPTIONS_INIT;
            goto m_cleanup;
        }
        /* Initialize graph object and load graph */
        if(HFA_SUCCESS != graph_load()) {
            ERR("Failure in graph_load\n");
            stage = DEV_INIT;
            goto m_cleanup;
        }
        /* setup result buffer for the search. It will hold output from
         * HFA
         */
        if(NULL == (rptr = 
            hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)NULL))){
            ERR("Rptr allocation failure\n");
            stage = GRAPH_INIT;
            goto m_cleanup;
        }   
        /*Get how many graphs are linked*/
        hfa_graph_getgraph_count(&graph, (uint32_t *)&graphcount);

        /* Initialize Search Ctx Object for each subgraph */
        if(HFA_SUCCESS != Initialize_Ctx()) {
            ERR("Failure in Initialize_Ctx\n");
            stage = RPTR_INIT;
            goto m_cleanup;
        }
        /* Parse through PCAP/NORMAL payload and process search  */     
        while(!gzeof(pattr.gzf)) {
            /* Get a pcacket buffer from PCAP/NORMAL payload file */
            if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
                if(gzeof(pattr.gzf))
                    break;
                ERR("Failure in hfautils_parse_payload\n");
                stage = CTX_INIT;
                goto m_cleanup;
            }
            for(cnt=0; cnt < graphcount; cnt++) {
                psize = pattr.psize;
                payload = pattr.payload;
               /* This while loop is for RFULL case, if RFULL occures it will 
                * keep sending the data till all data consumed in a packet 
                * by HFA engine */
                while(psize > 0) {

                    /*Reset payload data, search parameters */ 
                    memset (&param, 0, sizeof (hfa_searchparams_t));
                    param.clusterno = options.cluster;
                    memset (&input, 0, sizeof(hfa_iovec_t));

                    input.ptr = payload;
                    input.len = psize;

                    /*set input parameters to search*/
                    hfa_searchparam_set_inputiovec (&param, &input, 1);

                    /*set output parameters to search */
                    hfa_searchparam_set_output(&param, rptr, rsize);

                    /* Perform search using search context and search 
                     * parameters. This call will block till instruction 
                     * completes in HFA */
                    if(HFA_SUCCESS != 
                        hfa_searchctx_search (&(sgraph[cnt].sctx),&param)){
                        ERR("hfa_searchctx_search() failure\n");
                        stage = PKTBUF_INIT;
                        goto m_cleanup;
                    }
                    /*Get the search reason from hardware*/
                    hfa_searchparam_get_hwsearch_reason(&param, &reason);
                    if (reason != HFA_REASON_DDONE &&
                            reason != HFA_REASON_RFULL){
                        ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
                        hfa_dump_regs();
                        stage = PKTBUF_INIT;
                        goto m_cleanup;
                    }
                    /*Get the pdboffset from hardware*/
                    hfa_searchparam_get_hwsearch_pdboff (&param, &pdboffset);
                    DBG("pdboffset = %lu\n", pdboffset);

                    /* Post process the results from HFA and record 
                     * found matches*/
                    if(HFA_SUCCESS != 
                        hfa_searchctx_getmatches (&(sgraph[cnt].sctx), 
                                                  &param, &pmatches)){
                        ERR ("searchctx getmatches failure()\n");
                        stage = PKTBUF_INIT;
                        goto m_cleanup;
                    }
                    /*matches points to match buffer allocated by post 
                     *processing*/
                    hfautils_print_matches(&(sgraph[cnt].sctx), pmatches, 
                             &(sgraph[cnt].nmatches), sgraph[cnt].boffset, 
                             options.verbose);
                    sgraph[cnt].boffset += pdboffset;
                    psize -= pdboffset;
                    payload += pdboffset;
                }
            }
            /* Cleanup allocated memory for payload buffer */
            hfautils_memoryfree(pattr.payload, pattr.psize, 
                                    (hfa_searchctx_t *)NULL);
        }
        for(cnt = 0; cnt < graphcount; cnt++) {
            LOG("Graph %d: Total matches: %lu\n\n", 
                        cnt +1, sgraph[cnt].nmatches);
        }
        stage = CTX_INIT;
m_cleanup:
        cleanup();
    }
    return 0;
}
