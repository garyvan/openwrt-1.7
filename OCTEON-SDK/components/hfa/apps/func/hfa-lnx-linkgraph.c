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

static int      matchacross = 1;
module_param (matchacross, int, 0444);
MODULE_PARM_DESC (matchacross, "flags to enable or disable cross packet search");

static int      singlematch = 0;
module_param (singlematch, int, 0444);
MODULE_PARM_DESC (singlematch, "flags to enable or disable singlematch");

static unsigned int  cluster = 0;
module_param (cluster, uint, 0444);
MODULE_PARM_DESC (cluster, "cluster number used to run HFA search");

static unsigned int clmsk = 0x0;
module_param (clmsk, uint, 0444);
MODULE_PARM_DESC (clmsk, "Clusters on which graph to be loaded");

static int      pcap = 0;
module_param (pcap, int, 0444);
MODULE_PARM_DESC (pcap, "payload file is pcap file");

static int      rbufsize = 64;
module_param (rbufsize, int, 0444);
MODULE_PARM_DESC (rbufsize, "result buffer size");

unsigned int tasks_mask = 0x0;
module_param (tasks_mask, uint, 0444);
MODULE_PARM_DESC (tasks_mask, "coremask to run tasklets");

unsigned int threads_mask = 0x1;
module_param (threads_mask, uint, 0444);
MODULE_PARM_DESC (threads_mask, "coremask to run threads");

static int      verbose = 0;
module_param (verbose, int, 0444);
MODULE_PARM_DESC (verbose, "verbose option to print matches");

typedef struct {
    hfa_searchctx_t     sctx;
    hfa_size_t          nmatches;
    int                 boffset;
    hfa_graph_t         subgraph; 
}subgraph_t;

subgraph_t              *sgraph = NULL;
static hfa_dev_t        octeon_hfa_dev;
hfa_graph_t             gstruct;
hfa_searchctx_t         sctx;
hfa_searchparams_t      sparam;
hfa_iovec_t             input;
void                    *gbuf= NULL;
hfa_size_t              gsize=0, psize=0;
hfa_size_t              rsize;
void                    *rptr = NULL;
options_t               options;
int                     pfflags = 0;
char                    *buf = NULL;
int                     graphcount = 0;
hfautils_payload_attr_t pattr;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    RPTR_INIT = 4,
    CTX_INIT = 5,
    PKTBUF_INIT 
}error_stage_t;
/* @endcond APPINTERNAL */

/** 
 * Cleanup will be done by this routine 
 */
static inline void 
cleanup(int stage) 
{
    int     cnt = 0;
    
    switch(stage) {
        case PKTBUF_INIT:
            hfautils_memoryfree(pattr.payload, pattr.psize, 
                                    (hfa_searchctx_t *)NULL);
        case CTX_INIT:
            for(cnt = 0; cnt < graphcount; cnt++) 
                hfa_dev_searchctx_cleanup(&octeon_hfa_dev, &(sgraph[cnt].sctx));        
            hfautils_memoryfree(sgraph, sizeof(subgraph_t) * graphcount, 
                                        (hfa_searchctx_t *)NULL);
        case RPTR_INIT:
            hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)NULL);
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
                hfa_graph_getsubgraph(&gstruct, &(sgraph[cnt].subgraph), cnt)){
            ERR("Error oin fetching subgraph: %d\n", cnt);
            continue;
        }
        /*initialise search context object */
        if(HFA_SUCCESS != 
            hfa_dev_searchctx_init (&octeon_hfa_dev, &(sgraph[cnt].sctx))){
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
        hfa_searchctx_setflags (&(sgraph[cnt].sctx), pfflags);
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
    if(chunksize < psize) {
        LOG("WARNING: This application doesn't support FSAVEBUF. " 
            "The application might not find all the matches in the payload\n");
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
    uint32_t            reason = 0;
    uint64_t            *pmatches = NULL;
    void                *payload = NULL;  
    int64_t             cpsize = 0;
    int                 cnt = 0;
    hfa_pdboff_t        pdboffset = 0;
    int                 stage = -1;

    /* Process command line options, read graph and payload */ 
    if(HFA_SUCCESS != process_options()) {
        ERR("failure in process_options\n");
        goto m_cleanup;
    }
    /*initialise HFA device and device driver*/
    if(HFA_SUCCESS != hfa_dev_init(&octeon_hfa_dev)){
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
    if(NULL == (rptr = 
        hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)NULL))){
        ERR("Failure in allocating rptr\n");
        stage = GRAPH_INIT;
        goto m_cleanup;
    }
    /*Get how many graphs are linked*/
	hfa_graph_getgraph_count(&gstruct, (uint32_t *)&graphcount);

    /* Initialize Search Ctx Object for each subgraph */
    if(HFA_SUCCESS != Initialize_Ctx()) {
        ERR("Failure in Initialize_Ctx\n");
        stage = RPTR_INIT;
        goto m_cleanup;
    }
    LOG("graphcount %d\n", graphcount);
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
        for(cnt = 0; cnt < graphcount; cnt++)
	    { 
            cpsize = pattr.psize;
            payload = pattr.payload;
            /* This while loop is for RFULL case, if RFULL occures it will 
             * keep sending the data till all data consumed in a packet 
             * by HFA engine */
            while(cpsize > 0) {

                /*Reset payload data, search parameters */ 
                memset (&sparam, 0, sizeof (hfa_searchparams_t));
                sparam.clusterno = options.cluster;
                memset (&input, 0, sizeof(hfa_iovec_t));

                input.ptr = payload;
                input.len = cpsize;

			    /*set input parameters to search*/
			    hfa_searchparam_set_inputiovec (&sparam, &input, 1);

			    /*setup result buffer for the search. It will hold output from
			    * HFA
			    */
			    hfa_searchparam_set_output(&sparam, rptr, rsize);

			    /* Perform search using search context and search parameters.
			    * This call will block till instruction completes in HFA
			    */
			    if(HFA_SUCCESS != hfa_searchctx_search(&(sgraph[cnt].sctx), &sparam)){
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
                    hfa_searchctx_getmatches (&(sgraph[cnt].sctx), 
                                              &sparam, &pmatches)){
                    ERR ("searchctx getmatches failure()\n");
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }

                /*matches points to match buffer allocated by post processing*/
                hfautils_print_matches(&(sgraph[cnt].sctx), pmatches, 
                        &(sgraph[cnt].nmatches), sgraph[cnt].boffset, verbose); 
                sgraph[cnt].boffset += pdboffset;
                cpsize -= pdboffset;
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
    return(0);
m_cleanup:
    cleanup(stage);
    return (-1);
}

void exit (void)
{
    int         stage = CTX_INIT;

    cleanup(stage);
    LOG("hfa-lnx-linkgraph app removed successfully\n");
}
/* @cond APPINTERNAL */
module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
/* @endcond APPINTERNAL */
