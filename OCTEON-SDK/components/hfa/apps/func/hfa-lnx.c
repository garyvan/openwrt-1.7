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
 * Linux Kernel mode:
 * Reference application to showcase simple HFA API. It reports the
 * pattern-matches found in the payload based on graph(compiled using the
 * pattern file). The following lists the operational aspects of this
 * application.
 * - Multicore - NO(runs on single core)
 * - Type of API - Synchronous OO API
 * - Cluster resources - Managed by HFA API
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
 *
 */
#include <cvm-hfa-graph.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa.h>
#include <pcap.h>
#include <app-utils.h>

/* @cond APPINTERNAL */

MODULE_AUTHOR ("cavium_networks");

static char     *graph = "graph";
module_param (graph, charp, 0444);
MODULE_PARM_DESC (graph, "graph file");

static char     *payload = "payload";
module_param (payload, charp, 0444);
MODULE_PARM_DESC (payload, "payload file");

static int      chunksize = 65535;
module_param (chunksize, int, 0444);
MODULE_PARM_DESC (chunksize, "chunk size");

static int      matchacross=1;
module_param (matchacross, int, 0444);
MODULE_PARM_DESC (matchacross, "flags to enable or disable cross packet search");

static int      singlematch=0;
module_param (singlematch, int, 0444);
MODULE_PARM_DESC (singlematch, "flags to enable or disable singlematch");

static unsigned int  cluster=0;
module_param (cluster, uint, 0444);
MODULE_PARM_DESC (cluster, "cluster number used to run HFA search");

static unsigned int clmsk=0x0;
module_param (clmsk, uint, 0444);
MODULE_PARM_DESC (clmsk, "Clusters on which graph to be loaded");

static int      pcap=0;
module_param (pcap, int, 0444);
MODULE_PARM_DESC (pcap, "payload file is pcap file");

static int      rbufsize = 64;
module_param (rbufsize, int, 0444);
MODULE_PARM_DESC (rbufsize, "result buffer size");

static int      verbose = 1;
module_param (verbose, int, 0444);
MODULE_PARM_DESC (verbose, "verbose option to print matches");

static hfa_dev_t        octeon_hfa_dev;
hfa_graph_t             gstruct;
hfa_searchctx_t         sctx;
hfa_searchctx_t         *psctx = NULL;
hfa_searchparams_t      sparam;
hfa_iovec_t             *input = NULL;
int                     iovlen_0_n = 0;
void                    *gbuf= NULL;
hfa_size_t              rsize;
void                    *rptr = NULL;
options_t               options;
int                     pfflags = 0;
hfa_size_t              gsize=0, psize = 0;
int                     stage = -1;
hfautils_payload_attr_t pattr;
int                     savelen = 0;
char                    *buf = NULL;
/* @endcond APPINTERNAL */

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT = 4,
    INPUT_INIT = 5,
    PKTBUF_INIT  
}error_stage_t;
/**
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(void) {
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
            hfautils_memoryfree (rptr, rsize, (hfa_searchctx_t *)(psctx));
            hfa_dev_searchctx_cleanup(&octeon_hfa_dev, &sctx);        
        case GRAPH_INIT:
            if(!HFA_GET_GRAPHATTR((&gstruct), memonly)){
                hfa_graph_cacheunload(&gstruct);
            }
            hfa_dev_graph_cleanup(&octeon_hfa_dev, &gstruct);       
        case DEV_INIT:
            hfa_dev_cleanup(&octeon_hfa_dev);        
        case OPTIONS_INIT:
            hfautils_cleanup_payload_attributes(&pattr, &options);
            hfautils_memoryfree(buf, 100*sizeof(char), (hfa_searchctx_t *)NULL);
            hfautils_vmmemoryfree(gbuf, gsize, (hfa_searchctx_t *)NULL);
        default:
            break;
    }
}
/**
 * Initialize search context 
 */ 
static inline hfa_return_t 
initialize_ctx(void)
{
    /*initialise search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init(&octeon_hfa_dev, &sctx)){
        ERR("Failure from SearchCtx Init\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph(&sctx, &gstruct)){
        ERR("Failure from SearchCtx Init\n");
        return HFA_FAILURE;
    }
    /*set flags for search*/
    hfa_searchctx_setflags(&sctx, pfflags);

    psctx = &sctx;
    if(NULL == (rptr = 
        hfautils_memoryalloc(rsize, HFA_FALSE, (hfa_searchctx_t *)(psctx)))){
        ERR("Failure in allocating rptr\n");
        goto ctx_cleanup;
    }
    return HFA_SUCCESS;
ctx_cleanup:
    hfa_dev_searchctx_cleanup (&octeon_hfa_dev, &sctx);
    return HFA_FAILURE;
}

/**
 * Load graph to HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    /*initialise graph object*/
    if(HFA_SUCCESS != hfa_dev_graph_init(&octeon_hfa_dev, &gstruct)){
        ERR("Graph Init Failed\n");
        return HFA_FAILURE;
    }
    /* set the cluster on which this graph will be loaded*/
    if(HFA_SUCCESS != hfa_graph_setcluster(&gstruct, clmsk)){
        ERR("Failure in setting cluster in graph\n");
        return HFA_FAILURE;
    }
    /* load graph to HFA memory*/
    if(HFA_SUCCESS != 
            hfautils_download_graph(&gstruct, gbuf, gsize, GRAPHCHUNK, 0)){
        ERR("Error in downloading the graph\n");
        return HFA_FAILURE;
    }
    /* load graph to cache, if it is a cacheable graph */
    if(!HFA_GET_GRAPHATTR((&gstruct), memonly)){
        if(HFA_SUCCESS != hfa_graph_cacheload(&gstruct)){
            ERR("Failure in Graph Cache Load\n");
            hfa_dev_graph_cleanup(&octeon_hfa_dev, &gstruct);
            return HFA_FAILURE;
        }
    }
    /* Get savelen for cross packet matching */
    hfa_graph_getsavelen(&gstruct, &savelen);
    if(savelen <= 0)
        savelen = MAXSAVELEN;
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;
}
/** 
 * Process command line options,
 * Read graph and payload 
 */
static inline hfa_return_t 
process_options (void) 
{
    hfa_size_t          read_off=0;
    char                *cwd = NULL;
    struct path         pwd, root;
    
    /* Validate Cluster */
    if(cluster <0 || cluster > hfa_get_max_clusters()){
        ERR("Invalid cluster provided\n");
        return HFA_FAILURE;
    }
    if(clmsk == 0)
        clmsk = hfa_get_max_clmsk();

    if(clmsk > hfa_get_max_clmsk()){
        ERR("Invalid Graph Cluster Mask: 0x%x\n", clmsk);
        return HFA_FAILURE;
    }
    if(matchacross == 0)
        pfflags |= HFA_SEARCHCTX_FNOCROSS;
    else
        pfflags &= ~HFA_SEARCHCTX_FNOCROSS;

    if(singlematch == 1)
        pfflags |= HFA_SEARCHCTX_FSINGLEMATCH;
    else
        pfflags &= ~HFA_SEARCHCTX_FSINGLEMATCH;

    /* Read graph and payload */
    hfautils_file_size(graph, &gsize);
    hfautils_file_size(payload, &psize);
    if(HFA_SUCCESS != hfautils_validate_chunksize(&chunksize, psize)){
        ERR("Validation of chunksize failed\n");
        return HFA_FAILURE;
    }
    if(HFA_SUCCESS != hfautils_read_file(graph, &gbuf, 
                gsize, &read_off, HFA_TRUE)){
        ERR("In reading graph file\n");
        return HFA_FAILURE;
    }
    rsize = MAXRBUFSIZE;
    HFA_ALIGNED (rsize, 128);

    options.payloadsize = psize;
    options.chunksize = chunksize;
    options.pcap = pcap;
    options.payload = payload;
    
    /* Get Current Working Directory */
    if(current && current->fs) {
        pwd = current->fs->pwd;
        path_get(&pwd);
        root= current->fs->root;
        path_get(&root);
        buf = (char *)hfautils_memoryalloc(100*sizeof(char), 8, 
                                        (hfa_searchctx_t *)NULL);
        if(buf == NULL) {
            ERR ("Memory allocation failed for path \n");
            goto gfree;
        }
        cwd = d_path(&pwd, buf, 100*sizeof(char));
    }
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    
    pattr.path = cwd;
    /* Initialize attributes for parsing the payload file */
    if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        goto buf_free;
    }
    return HFA_SUCCESS;
buf_free:
    hfautils_memoryfree(buf, 100 * sizeof(char), (hfa_searchctx_t *)NULL); 
gfree:
    hfautils_vmmemoryfree(gbuf, gsize, (hfa_searchctx_t *)NULL);
    return HFA_FAILURE;
}
int
entry (void)
{
    hfa_ppoflags_t      ppoflags = 0;
    uint32_t            reason = 0;
    uint64_t            *pmatches = NULL;
    hfa_size_t          nmatches=0;
    int                 boffset = 0, i = 0;
    uint32_t            tot_iov_datalen = 0;
    hfa_pdboff_t        pdboffset = 0;
    hfa_iovec_t         *input_tmp = NULL;
    int64_t             psize = 0;
    void                *payload = NULL;

    /* Process command line options, read graph and payload */ 
    if(HFA_SUCCESS != process_options()) {
        ERR("failure in process_options\n");
        goto m_cleanup;
    }
    /*initialise HFA device and device driver*/
    if(HFA_SUCCESS != hfa_dev_init(&octeon_hfa_dev)){
        ERR("Dev Init Failed\n");
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
    memset(&sparam, 0, sizeof(hfa_searchparams_t)); 
    sparam.clusterno = cluster;
    boffset=0;
    iovlen_0_n = 0;
    tot_iov_datalen = 0;
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
            if(pcap)
                tot_iov_datalen += input[iovlen_0_n].len;
            else 
                tot_iov_datalen += chunksize;
            iovlen_0_n++;

            /*set input parameters to search*/
            hfa_searchparam_set_inputiovec_0_n(&sparam, input, iovlen_0_n, 1);

            /*setup result buffer for the search. It will hold output from
            * HFA
            */
            hfa_searchparam_set_output(&sparam, rptr, rsize);

            /* Perform search using search context and search parameters.
             * This call will block till instruction completes in HFA
             */
            if(HFA_SUCCESS != hfa_searchctx_search( &sctx, &sparam)){
                ERR("Failure in hfa_Search\n");
                stage = PKTBUF_INIT;
                goto m_cleanup;
            }

            /*Get the search reason from hardware*/
            hfa_searchparam_get_hwsearch_reason(&sparam, &reason);

            if (reason != HFA_REASON_DDONE &&
                    reason != HFA_REASON_RFULL){
                ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
                hfa_dump_regs();
                stage = PKTBUF_INIT;
                goto m_cleanup;
            }
            /*Get the pdboffset from hardware*/
            hfa_searchparam_get_hwsearch_pdboff (&sparam, &pdboffset);
            DBG("pdboffset = %lu\n", pdboffset);

            /* Post process the results from HFA and record found matches*/
            if(HFA_SUCCESS != 
                    hfa_searchctx_getmatches (&sctx, &sparam, &pmatches)){
                ERR ("searchctx getmatches failure()\n");
                stage = PKTBUF_INIT;
                goto m_cleanup;
            }
            /*matches points to match buffer allocated by post processing*/
            hfautils_print_matches(&sctx, pmatches, &nmatches, boffset, verbose);
            boffset += pdboffset;
            psize -= pdboffset;
            payload += pdboffset;
            /*Get ppoflags 
             *If FSAVEBUF set in ppoflags then the application has to provide
             *back buffer of savelen + current buffer to the search otherwise 
             *it has to provide current chunk buffer to the serach*/ 
            hfa_searchparam_get_ppoflags (&sparam, &ppoflags);
            if(HFA_ISBITMSKCLR(ppoflags, HFA_PP_OFLAGS_FSAVEBUF)){
                iovlen_0_n = 0;
            }
            else if (boffset < tot_iov_datalen-input[iovlen_0_n-1].len)
            {
                /*
                 * HFA engine did not consume all the input data in this
                 * instruction.  So erase the last iovec. It will be refilled
                 * in the next iteration of the loop with adjusted
                 * input payload(based pdboffset...which is accounted for
                 * above).
                 */
                iovlen_0_n--;
                /* Cleanup allocated memory for payload buffer */
                hfautils_memoryfree(input[iovlen_0_n].ptr, 
                        input[iovlen_0_n].len, (hfa_searchctx_t *)NULL);
                if(pcap)
                    tot_iov_datalen -= input[iovlen_0_n].len;
                else
                    tot_iov_datalen -= chunksize;
            }
            else if ((tot_iov_datalen - input[iovlen_0_n-1].len) < savelen)
            {
                /* Savelen is how much back buffer memory must be preserved 
                 * when using cross-packet matching. Allocates memory for 
                 * iovecs till all back buffer + current buffer fit in 
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
    LOG("Total matches: %lu\n", nmatches);
    LOG("hfa-lnx-app inserted successfully\n");
    return HFA_SUCCESS;

m_cleanup:
    cleanup();
    return HFA_FAILURE;
}

void exit (void)
{
    stage = PKTBUF_INIT;
    cleanup();
    LOG("hfa-lnx-app removed successfully\n");
}
/* @cond APPINTERNAL */
module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
/* @endcond APPINTERNAL */
