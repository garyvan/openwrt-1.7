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
 * Reference application to showcase simple HFA API. It reports the
 * pattern-matches found in the payload based on graph(compiled using the
 * pattern file). The following lists the operational aspects of this
 * application.
 * - Multicore - NO(runs on single core)
 * - Type of API - Synchronous OO API
 * - Cluster resources - Managed by HFA API.
 * - Graph count - 1
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Private to the core
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - 0 by default. Configurable, but limited to 1 cluster
 * - Buffer Payload - Supported. Same payload is used by all cores
 * - Pcap Payload - Supported. All packets from the pcap file are processed by 
 *                  all cores. The packets are duplicated for each core
 * - Cross Packet Search - Enabled
 * - FSAVEBUF - Supported. Application checks ppoflags set by HFA HW, 
 *              if FSAVEBUF sets in ppoflags then the application provides
                back buffer of savelen + current buffer to the search otherwise 
                it will provide current chunk buffer to the search 
*/ 
#include <cvm-hfa-graph.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa.h>
#include <pcap.h>
#include <app-utils.h>

/* @cond APPINTERNAL */

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         graph;

GLOBAL hfautils_payload_attr_t         pattr;
GLOBAL hfa_searchctx_t                 ctx;    
GLOBAL hfa_searchparams_t              param;    
GLOBAL hfa_size_t                      rsize=0;
GLOBAL void                            *graph_data = NULL;
GLOBAL int                             iovlen_0_n = 0; 
GLOBAL void                            *rptr = NULL;
GLOBAL hfa_searchctx_t                 *psctx = NULL;
GLOBAL int                             stage = -1;
GLOBAL hfa_iovec_t                     *input = NULL;
GLOBAL int                             savelen = 0;

/* @endcond APPINTERNAL */
typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT  = 4,
    INPUT_INIT = 5,
    PKTBUF_INIT  
}error_stage_t;

/** 
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(int iovlen_0_n) 
{
    int     i = 0;

    switch(stage) {
        case PKTBUF_INIT:
            for(i = 0; i < iovlen_0_n; i++) {
                /* Cleanup allocated memory for payload buffer */
                hfautils_memoryfree(input[i].ptr, input[i].len, 
                                    (hfa_searchctx_t *)NULL);
            }
        case INPUT_INIT:
            hfautils_memoryfree(input,sizeof(hfa_iovec_t) * (iovlen_0_n+1), 
                                        (hfa_searchctx_t *)(psctx));
        case CTX_INIT:
            hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)(psctx));
            hfa_dev_searchctx_cleanup (&hfa_dev, &ctx);
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
                                    (hfa_searchctx_t *) NULL);
        default:
            hfautils_reset_octeon();
            break;
    }
}
/**
 * Initialize search context 
 */ 
static inline hfa_return_t 
initialize_ctx(void)
{
    /*initialize search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init (&hfa_dev, &ctx)){
        ERR("SearchCtx Init Failure\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph (&ctx, &graph)){
        ERR("Searchctx_setgraph Failure\n");
        return HFA_FAILURE;
    }
    /*set flags for search*/
    hfa_searchctx_setflags (&ctx, options.pfflags);

    psctx = &ctx; 
    if(NULL == (rptr = 
                hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)(psctx)))){
        ERR("Rptr allocation failure\n");
        goto ctx_cleanup;
    }
    return HFA_SUCCESS;
ctx_cleanup:
    hfa_dev_searchctx_cleanup (&hfa_dev, &ctx);
    return HFA_FAILURE;
} 
/**
 * Load graph into HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    /*initialize graph object*/
    if(HFA_SUCCESS != hfa_dev_graph_init (&hfa_dev, &graph)){
        ERR("hfa_dev_graph_init() failure\n");
        return HFA_FAILURE;
    }
    /* set cluster on which this graph will be loaded*/
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
    /* Get savelen for cross packet matching */
    hfa_graph_getsavelen(&graph, &savelen);
    if(savelen <= 0)
        savelen = MAXSAVELEN;
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;
}
/** 
 * Process command line options and read graph 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    hfautils_options_init(&options);
    options.verbose=1;
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return (HFA_FAILURE);
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
                                (hfa_searchctx_t *) NULL);
    return HFA_FAILURE;
}
int 
main (int argc, char **argv)
{ 
    uint32_t                    tot_iov_datalen = 0;
    hfa_ppoflags_t              ppoflags = 0;
    uint32_t                    reason = 0;
    uint64_t                    *pmatches = NULL;
    uint64_t                    nmatches=0;
    int                         boffset = 0, i = 0;
    hfa_pdboff_t                pdboffset = 0;
    hfa_iovec_t                 *input_tmp = NULL;
    int64_t                     psize = 0;
    void                        *payload = NULL;
     
    cvmx_user_app_init ();
    hfautils_register_signalhandler();
    if (cvmx_is_init_core ()) {

        /* Process command line options, read graph and payload */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto m_cleanup;
        }
        /*initialize HFA device and device driver*/
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
        /* Initialize search context */
        if(HFA_SUCCESS != initialize_ctx()) {
            ERR("Failure in initialize_ctx\n");
            stage = GRAPH_INIT;
            goto m_cleanup;
        }
        if (NULL == (input = hfautils_memoryalloc(sizeof(hfa_iovec_t), 8, 
                        (hfa_searchctx_t *)(psctx)))){
            ERR ("unable to alloc iovec entries for payload");
            stage = CTX_INIT;
            goto m_cleanup;
        }
        memset (&param, 0, sizeof (hfa_searchparams_t));
        param.clusterno = options.cluster;
        boffset=0;
        iovlen_0_n = 0;
        /* Parse through PCAP/NORMAL payload and process search  */     
        while(!gzeof(pattr.gzf)) {
            /* Get a pcacket buffer from PCAP/NORMAL payload file */
            if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
                if(gzeof(pattr.gzf))
                    break;
                ERR("Failure in hfautils_parse_payload\n");
                stage = INPUT_INIT;
                goto m_cleanup;
            }
            psize = pattr.psize;
            payload = pattr.payload;
            /* This while loop is for RFULL case, if RFULL occures it will 
             * keep sending the data till all data consumed in a packet 
             * by HFA engine */
            while(psize > 0) {
                input[iovlen_0_n].ptr = payload;
                input[iovlen_0_n].len = psize;
                if(options.pcap)
                    tot_iov_datalen += input[iovlen_0_n].len;
                else 
                    tot_iov_datalen += options.chunksize;
                iovlen_0_n++;
                /*set input parameters to search*/
                hfa_searchparam_set_inputiovec_0_n (&param, input, 
                                                   iovlen_0_n, 1);

                /*set output parameters to search */
                hfa_searchparam_set_output(&param, rptr, rsize);

                /* Perform search using search context and search parameters.
                 * This call will block till instruction completes in HFA
                 */
                if(HFA_SUCCESS != hfa_searchctx_search (&ctx, &param)){
                    ERR("hfa_searchctx_search() failure\n");
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }
                /*Get the search reason from hardware*/
                hfa_searchparam_get_hwsearch_reason(&param, &reason);

                if (reason != HFA_REASON_DDONE &&
                        reason != HFA_REASON_RFULL){
                    ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }
                /*Get the pdboffset from hardware*/
                hfa_searchparam_get_hwsearch_pdboff (&param, &pdboffset);
                DBG("pdboffset = %lu\n", pdboffset);

                /* Post process the results from HFA and record found matches*/
                if(HFA_SUCCESS != 
                        hfa_searchctx_getmatches (&ctx, &param, &pmatches)){
                    ERR ("searchctx getmatches failure()\n");
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }
                /*matches points to match buffer allocated by post processing*/
                hfautils_print_matches (&ctx, pmatches, &nmatches, boffset, 
                                         options.verbose);
                boffset += pdboffset;
                psize -= pdboffset;
                payload += pdboffset;
                /*Get ppoflags 
                 *If FSAVEBUF set in ppoflags then the application has to provide
                 *back buffer of savelen + current buffer to the search otherwise 
                 *it has to provide current chunk buffer to the serach*/ 
                hfa_searchparam_get_ppoflags (&param, &ppoflags);
                if(HFA_ISBITMSKCLR(ppoflags, HFA_PP_OFLAGS_FSAVEBUF)){
                    iovlen_0_n = 0;
                }
                else if (boffset < tot_iov_datalen-input[iovlen_0_n-1].len)
                {
                    /*
                     * HFA engine did not consume all the input data in this
                     * instruction.So erase the last iovec. It will be refilled
                     * in the next iteration of the loop with adjusted
                     * input payload(based pdboffset...which is accounted for
                     * above).
                     */
                    iovlen_0_n--;
                    /* Cleanup allocated memory for payload buffer */
                    hfautils_memoryfree(input[iovlen_0_n].ptr, 
                        input[iovlen_0_n].len, (hfa_searchctx_t *)NULL);
                    if(options.pcap)
                        tot_iov_datalen -= input[iovlen_0_n].len;
                    else
                        tot_iov_datalen -= options.chunksize;
                }
                else if ((tot_iov_datalen - input[iovlen_0_n-1].len) < savelen)
                {
                    /* Savelen is how much back buffer memory must be preserved 
                     * when using cross-packet matching. Allocates memory for 
                     * iovecs till back buffer + current buffer fit in 
                     * the iovecs 
                     */
                    if (NULL == (input_tmp = 
                        hfautils_memoryalloc(sizeof(hfa_iovec_t)*(iovlen_0_n+1),
                                         8, (hfa_searchctx_t *)(psctx)))){
                        ERR ("unable to alloc iovec entries for payload");
                        stage = PKTBUF_INIT;
                        goto m_cleanup;
                    }
                    for (i = iovlen_0_n-1; i >=0; i--) {
                        input_tmp[i].ptr = input[i].ptr; 
                        input_tmp[i].len = input[i].len; 
                    }
                    hfautils_memoryfree(input,sizeof(hfa_iovec_t)*iovlen_0_n, 
                                                    (hfa_searchctx_t *)(psctx));
                    input = input_tmp;
                }
                else 
                {
                    /* If allocated iovecs are enough to store back buffer + 
                     * current buffer then adjust the buffer ptrs */ 
                    iovlen_0_n--;
                    /* Cleanup allocated memory for payload buffer */
                    hfautils_memoryfree(input[0].ptr, input[0].len, 
                                            (hfa_searchctx_t *)NULL);
                    for(i = 0; i < iovlen_0_n; i++) {
                        input[i].ptr = input[i+1].ptr;
                        input[i].len = input[i+1].len;
                    }
                }
            }
            if(HFA_ISBITMSKCLR(ppoflags, HFA_PP_OFLAGS_FSAVEBUF)){
                hfautils_memoryfree(pattr.payload, pattr.psize, 
                                     (hfa_searchctx_t *)NULL);
            }
        }
        stage = PKTBUF_INIT;
        LOG("Total matches: %lu\n", nmatches);
m_cleanup:
        cleanup(iovlen_0_n);
    }
    return 0;
}
