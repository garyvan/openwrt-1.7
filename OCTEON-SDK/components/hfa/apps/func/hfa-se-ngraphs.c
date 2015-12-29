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
 * Reference application to showcase HFA API with loading multiple graphs and 
 * processing multiple graphs across cores.It reports the pattern-matches found 
 * in the payload based on each graph. The following lists the operational 
 * aspects of this application.
 * - Multicore - YES
 * - Type of API - Synchronous OO API
 * - Cluster resources - Managed by HFA API.
 * - Type of graph - Normal Graph 
 * - Graph count - Configurable using cmdline option
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
#include <stdio.h>

/* @cond APPINTERNAL */
typedef struct {
    hfa_searchctx_t     sctx;
    hfa_size_t          nmatches;
    int                 boffset;
}graph_t;

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         *graph_arr;
CVMX_SHARED void                **graphdata_arr = NULL;
CVMX_SHARED hfa_size_t          *graphsize_arr = NULL;
CVMX_SHARED uint32_t            ngraphs_per_core = 0;
CVMX_SHARED int                 init_success = 0; 
CVMX_SHARED hfa_size_t          rsize=0;
CVMX_SHARED graph_t             *sgraph = NULL;

GLOBAL hfa_searchctx_t                 ctx;    
GLOBAL hfa_searchparams_t              param;    
GLOBAL int                             i; 
GLOBAL void                            *rptr = NULL;
GLOBAL hfa_iovec_t                     input;
GLOBAL hfa_searchctx_t                 *psctx = NULL;
GLOBAL int                             stage = -1;
GLOBAL uint32_t                        current_idx=0;
GLOBAL hfautils_payload_attr_t         pattr;

/* @endcond APPINTERNAL */
typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT  = 4,
    RPTR_INIT = 5,
    PATTR_INIT = 6,
    PKTBUF_INIT 
}error_stage_t;

/**
 * Cleanup memory allocated for graphs
 */
static inline void 
graphptrs_cleanup(void) 
{
    for (i = 0; i < options.ngraphs; i++) {
        if(graphdata_arr[i]){
            hfautils_memoryfree(graphdata_arr[i], graphsize_arr[i], 
                                            (hfa_searchctx_t *)NULL);
        }
        graphdata_arr[i] = NULL;
    }
    hfautils_memoryfree(graphdata_arr, options.ngraphs*sizeof(void *), 
                                            (hfa_searchctx_t *)NULL);
    hfautils_memoryfree(graphsize_arr,options.ngraphs*sizeof(hfa_size_t), 
                                                (hfa_searchctx_t *)NULL);
    hfautils_memoryfree(graph_arr, options.ngraphs*sizeof(hfa_graph_t), 
                                                (hfa_searchctx_t *)NULL);
}
/** 
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(void) 
{
    int         cnt = 0;

    switch(stage) {
        case CTX_INIT:
            for(cnt = 0; cnt < options.ngraphs; cnt++) 
                hfa_dev_searchctx_cleanup (&hfa_dev, &(sgraph[cnt].sctx));
            hfautils_memoryfree(sgraph, sizeof(graph_t) * options.ngraphs, 
                                                (hfa_searchctx_t *)NULL);

        case GRAPH_INIT:
            for(i = 0;i < options.ngraphs; i++){        
                if(!HFA_GET_GRAPHATTR((&graph_arr[i]),memonly)){ 
                    hfa_graph_cacheunload (&graph_arr[i]);
                }
                hfa_dev_graph_cleanup(&hfa_dev, &graph_arr[i]);
            }
        case DEV_INIT:
            hfa_dev_cleanup (&hfa_dev);   
        case OPTIONS_INIT:
            graphptrs_cleanup();
        default:
            hfautils_reset_octeon();
    }
}
/** 
 * Classify the given number of graphs among cores
 * based on ngraphs per core 
 */
uint32_t classify(void)
{
    uint32_t    id;
    uint32_t    corenum = cvmx_get_core_num();

    id = (ngraphs_per_core * corenum) + current_idx;

    current_idx++;

    if(current_idx >= ngraphs_per_core){
        current_idx = 0;
    }
    return id;
}
/**
 * Allocate memory to store graph pointers and graph size and 
 * read graphs 
 */ 
static inline hfa_return_t
ngraphs_read (void)
{ 
    char graph_name[10];
    
    if(0 == options.ngraphs){
        ERR("Minimum number of graphs(ngraphs) should be one\n:");
        return HFA_FAILURE;
    }
    if(options.ngraphs > (64 * hfa_get_max_clusters())) {
        ERR("Total number of graphs exceeds maximum limit for cluster\n");
        return HFA_FAILURE; 
    }
    if(NULL == (graph_arr = 
        hfautils_memoryalloc(options.ngraphs*sizeof(hfa_graph_t), 8, 
                                            (hfa_searchctx_t *)NULL))){
        ERR ("unable to alloc graph_arr\n");
        return HFA_FAILURE; 
    }
    if(NULL == (graphsize_arr = 
        hfautils_memoryalloc(options.ngraphs*sizeof(hfa_size_t), 8, 
                                            (hfa_searchctx_t *)NULL))){
        ERR ("unable to alloc graphsize_arr");
        goto m_free_graph_arr;
    }         
    if(NULL== (graphdata_arr = 
        hfautils_memoryalloc(options.ngraphs*sizeof(void *) ,8, 
                                        (hfa_searchctx_t *)NULL))){
        ERR("error in allocating graphdata_arr\n");
        goto m_free_graphsize_arr;
    }
    for (i = 0; i < options.ngraphs; i++) {
        sprintf(graph_name, "%s%d", options.graph, i+1);
        if(HFA_SUCCESS != hfautils_file_size(graph_name, &graphsize_arr[i])){
            ERR("invalid graph name :%s\n",graph_name);
            goto m_ngraphs_free;
        }
        else
            LOG("Size of graph (%s): %lu\n", graph_name, graphsize_arr[i]);
        
        if(HFA_SUCCESS != 
            hfautils_read_file(graph_name, &graphdata_arr[i],graphsize_arr[i])){
            ERR ("Error in reading graph");
            goto m_ngraphs_free;
        }
    } 
    return (HFA_SUCCESS);
m_ngraphs_free:
    for (i = 0; i < options.ngraphs; i++) {
        if(graphdata_arr[i])
            hfautils_memoryfree(graphdata_arr[i], graphsize_arr[i], 
                                            (hfa_searchctx_t *)NULL);
    }
    hfautils_memoryfree(graphdata_arr, options.ngraphs*sizeof(void *), 
                                            (hfa_searchctx_t *)NULL);
m_free_graphsize_arr:
    hfautils_memoryfree(graphsize_arr,options.ngraphs*sizeof(hfa_size_t), 
                                             (hfa_searchctx_t *)NULL);
m_free_graph_arr:
    hfautils_memoryfree(graph_arr,options.ngraphs*sizeof(hfa_graph_t),
                                                (hfa_searchctx_t *)NULL);
    return HFA_FAILURE;
}
/**
 * Initialize search ctx for each graph.
 */ 
static inline hfa_return_t 
Initialize_Ctx(void) 
{
    int     cnt = 0;

    if(NULL == (sgraph=hfautils_memoryalloc(sizeof(graph_t) * options.ngraphs, 
                                            8, (hfa_searchctx_t *)NULL))) { 
        ERR("Memory allocation failed for CTX\n");
        return HFA_FAILURE;
    }
    memset(sgraph, 0, sizeof(graph_t) * options.ngraphs);
    for (cnt = 0; cnt < options.ngraphs; cnt++) 
    {
        /*initialise search context object */
        if(HFA_SUCCESS != 
            hfa_dev_searchctx_init (&hfa_dev, &(sgraph[cnt].sctx))){
            ERR("SearchCtx Init Failure\n");
            goto sgraph_free;
        }
        /*bind graph to the context */
        if(HFA_SUCCESS != hfa_searchctx_setgraph (&(sgraph[cnt].sctx), 
                                                  &graph_arr[cnt])){
            ERR("Searchctx_setgraph Failure\n");
            goto sgraph_free;
        }
        /*set flags for search*/
        hfa_searchctx_setflags (&(sgraph[cnt].sctx), options.pfflags);
    }
    return HFA_SUCCESS;
sgraph_free:
    hfautils_memoryfree(sgraph, sizeof(graph_t) * options.ngraphs, 
                                        (hfa_searchctx_t *)NULL); 
    return HFA_FAILURE;
}
/**
 * Load ngraphs into HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    int     er = 0;

    for(i = 0;i < options.ngraphs; i++){
        /*initialize graph object*/
        if(HFA_SUCCESS != hfa_dev_graph_init (&hfa_dev, &graph_arr[i])){
            ERR("hfa_dev_graph_init() failure\n");
            goto cleanup;
        }
        /* set the cluster on which this graph will be loaded*/
        if(HFA_SUCCESS != 
            hfa_graph_setcluster (&graph_arr[i], options.graph_clmsk)){
            ERR("hfa_graph_setcluster() failure\n");
            goto cleanup;
        }
        /* load graph to HFA memory*/
        if(HFA_SUCCESS!=hfautils_download_graph(&graph_arr[i],graphdata_arr[i], 
                    graphsize_arr[i], GRAPHCHUNK, 0)){
            ERR("hfautils_download_graph() failure\n");
            goto cleanup;
        }
        /* load graph to cache, if it is a cacheable graph */
        if(!HFA_GET_GRAPHATTR((&graph_arr[i]), memonly)){ 
            if( HFA_SUCCESS != hfa_graph_cacheload (&graph_arr[i])){
                ERR("Graph Cacheload failure\n");
                er = 1;
                goto cleanup; 
            }
        }
    }
    return HFA_SUCCESS;  
cleanup:
    if(er)
        hfa_dev_graph_cleanup(&hfa_dev, &graph_arr[i]);
    i--; 
    for(; i >= 0; i--) {        
        if(!HFA_GET_GRAPHATTR((&graph_arr[i]),memonly)){ 
                hfa_graph_cacheunload (&graph_arr[i]);
        }
        hfa_dev_graph_cleanup(&hfa_dev, &graph_arr[i]);
    }
    return HFA_FAILURE;
}
/** 
 * Process command line options, read graph. 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    int         ncores = 0;

    hfautils_options_init(&options);
    options.verbose=1;
    options.ngraphs=1;
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return (HFA_FAILURE);
    }
    if(options.chunksize < options.payloadsize) {
        LOG("WARNING: This application doesn't support FSAVEBUF. " 
            "The application might not find all the matches in the payload\n");
    }
    ncores = hfautils_get_number_of_cores();
    if(options.ngraphs % ncores){
        ERR("ngraphs should be multiple of number of cores processing\n");
        return HFA_FAILURE;
    }
    if(HFA_SUCCESS != ngraphs_read()){
        return (HFA_FAILURE);
    }
    ngraphs_per_core = options.ngraphs/ncores;
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize, 128);
    
    return HFA_SUCCESS;
}

int main (int argc, char **argv)
{ 
    void                        *payload=NULL;
    uint32_t                    reason = 0;
    uint64_t                    *pmatches = NULL;
    uint64_t                    psize=0;
    hfa_pdboff_t                pdboffset = 0;
    uint32_t                    gid = 0, cnt = 0;
    int                         retval = 0;

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
        if(HFA_SUCCESS != Initialize_Ctx()) {
            ERR("Failure in Initialize_Ctx\n");
            stage = GRAPH_INIT;
            goto error;
        }
        init_success = 1;
        LOG("Graph download, Cache download completed\n");
    }
error:
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if(init_success) {
        if(NULL == (rptr = 
            hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)NULL))){
            ERR("Rptr allocation failure\n");
            stage = CTX_INIT;
            goto m_cleanup;
        }
        memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
        /* Initialize attributes for parsing the payload file */
        if(HFA_SUCCESS != 
            hfautils_init_payload_attributes (&pattr, &options)){
            ERR ("Failure in hfautils_init_payload_attributes\n");
            stage = RPTR_INIT;
            goto m_cleanup;
        }
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
            /* Process search on each graph */
            do
            {
                gid = classify();

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

                    /* Perform search using search context and search parameters.
                     * This call will block till instruction completes in HFA
                     */
                    if(HFA_SUCCESS != 
                        hfa_searchctx_search (&(sgraph[gid].sctx), &param)){
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
                    /* Post process the results from HFA and record found matches*/
                    if(HFA_SUCCESS != 
                        hfa_searchctx_getmatches (&(sgraph[gid].sctx), 
                                                  &param, &pmatches)){
                        ERR ("searchctx getmatches failure()\n");
                        stage = PKTBUF_INIT;
                        goto m_cleanup;
                    }
                    /*matches points to match buffer allocated by post processing*/
                    hfautils_print_matches (&(sgraph[gid].sctx), pmatches, 
                            &(sgraph[gid].nmatches), sgraph[gid].boffset, 
                            options.verbose);
                    sgraph[gid].boffset += pdboffset;
                    payload += pdboffset;
                    psize -= pdboffset;
                }
                hfa_dev_searchctx_cleanup (&hfa_dev, &ctx);
            }while(current_idx);
            /* Cleanup allocated memory for payload buffer */
            hfautils_memoryfree(pattr.payload, pattr.psize, 
                                    (hfa_searchctx_t *)NULL);
        }
        stage = PATTR_INIT;   
        retval = HFA_SUCCESS;
        cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
        if(cvmx_is_init_core ()) { 
            for(cnt = 0; cnt < options.ngraphs; cnt++) {
                LOG("Graph %d: Total matches: %lu\n\n", 
                        cnt +1, sgraph[cnt].nmatches);
            }
        }
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
        case RPTR_INIT: 
            hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)NULL);
            stage = CTX_INIT;
        default:
            break;
    }
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if(cvmx_is_init_core ()) 
        cleanup();
    return retval;
}
