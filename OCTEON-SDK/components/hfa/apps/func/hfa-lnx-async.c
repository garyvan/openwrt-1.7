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
 * Reference application to showcase HFA API in asynchronous mode of operation.
 * It reports the pattern-matches found in the payload based on graph(compiled
 * using the pattern file). The following lists the operational aspects of this
 * application.
 * - Multicore - YES. 
 * - Tasklets - Supported.
 * - Kernel threads - Supported.
 *   Each kernel thread/kernel tasklet bind to perticular core.
 *   Configurable using cmdline options.
 * - Type of API 
 *       - Asynchronous OO API(cacheload and search)
 *       - Synchronous OO API(memload)
 * - Cluster resources - per core(setup by first core). Managed by application.
 * - Clusters shared among cores - YES
 * - Graph count - 1 (loaded by first core)
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Private to each core.
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

static unsigned int chunksize = 65535;
module_param (chunksize, uint, 0444);
MODULE_PARM_DESC (chunksize, "chunk size");

static unsigned int cluster=0;
module_param (cluster, uint, 0444);
MODULE_PARM_DESC (cluster, "cluster number used to run HFA search");

static unsigned int clmsk=0x0;
module_param (clmsk, uint, 0444);
MODULE_PARM_DESC (clmsk, "Clusters on which graph to be loaded");

static int  matchacross=1;
module_param (matchacross, int, 0444);
MODULE_PARM_DESC (matchacross, "flags to enable or disable cross packet search");

static int  singlematch=0;
module_param (singlematch, int, 0444);
MODULE_PARM_DESC (singlematch, "flags to enable or disable singlematch");

static int  pcap=0;
module_param (pcap, int, 0444);
MODULE_PARM_DESC (pcap, "payload file is pcap file");

unsigned long int tasks_mask=0x0;
module_param (tasks_mask, ulong, 0444);
MODULE_PARM_DESC (tasks_mask, "coremask to run tasklets");

unsigned long int threads_mask=0x1;
module_param (threads_mask, ulong, 0444);
MODULE_PARM_DESC (threads_mask, "coremask to run threads");

static int   verbose = 0;
module_param (verbose, int, 0444);
MODULE_PARM_DESC (verbose, "verbose option to print matches");

CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         gstruct; 
CVMX_SHARED hfa_cluster_t       *hfa_cluster[HFA_MAX_NCLUSTERS];
CVMX_SHARED void                *graph_data = NULL, *payload_data = NULL;
CVMX_SHARED hfa_size_t          gsize=0, psize=0;
CVMX_SHARED options_t           options;
CVMX_SHARED int                 pfflags = 0;
CVMX_SHARED uint64_t            rsize =0;
CVMX_SHARED int                 savelen = 0;
CVMX_SHARED task_attr_t         t_attr;
uint32_t                        cnt=0;
char                            *buf = NULL;
coremask_attr_t                 cmsk_attr;
/* @endcond APPINTERNAL */

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT 
}error_stage_t;

/**
 * Cleanup cluster memory resources 
 */
static inline void 
cluster_cleanup(int nclusters)
{
    for(cnt = 0; cnt < nclusters; cnt++){
        if(hfa_cluster[cnt]) {
            hfautils_memoryfree(hfa_cluster[cnt], sizeof(hfa_cluster_t), 
                                (hfa_searchctx_t *)NULL);
            hfa_cluster[cnt]=NULL;
        }
    }   
}
/**
 * Application cleanup will be done by this routine 
 */
static inline void
cleanup(int stage)
{
    int     nclusters = 0;

    switch(stage) {
        case GRAPH_INIT:
            if(!HFA_GET_GRAPHATTR((&gstruct), memonly)){
                hfa_graph_cacheunload (&gstruct);
            }
            hfa_dev_graph_cleanup(&hfa_dev, &gstruct);
            if(buf) {
                hfautils_memoryfree(buf, 100 * sizeof(char), 
                                        (hfa_searchctx_t *)NULL);
            }
        case DEV_INIT:
            nclusters = hfa_dev_get_nclusters(&hfa_dev);
            hfa_dev_cleanup (&hfa_dev);   
            cluster_cleanup(nclusters);
        case OPTIONS_INIT:
            hfautils_vmmemoryfree(graph_data, gsize, (hfa_searchctx_t *)NULL);       
            if(payload_data) {
                hfautils_vmmemoryfree(payload_data, t_attr.size, 
                                            (hfa_searchctx_t *)NULL);   
            }
        default:
            break;
    }
}
/**
 * Process search for given payload and graph 
 */
hfa_return_t process_search(char *path)
{
    void                            *rptr = NULL;
    uint32_t                        status=0;
    hfa_searchctx_t                 ctx;    
    hfa_searchctx_t                 *psctx;    
    hfa_searchparams_t              param;    
    hfa_iovec_t                     *input_tmp = NULL, *input = NULL;
    int                             iovlen_0_n = 0;
    uint32_t                        tot_iov_datalen = 0;
    hfa_ppoflags_t                  ppoflags = 0;
    uint32_t                        reason=0;
    uint32_t                        core = cvmx_get_core_num();
    uint64_t                        *pmatches = NULL;
    hfa_size_t                      nmatches = 0;
    void                            *payload = NULL;
    int64_t                         psize = 0;
    int                             boffset = 0, i = 0;
    hfa_return_t                    retval = HFA_FAILURE;
    hfa_pdboff_t                    pdboffset = 0;
    hfautils_payload_attr_t         pattr;
    
    cvmx_write_csr(CVMX_CIU_WDOGX(core), 0);
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    /*initialise search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init (&hfa_dev, &ctx)){
        ERR("SearchCtx Init Failure\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph (&ctx, &gstruct)){
        ERR("Searchctx_setgraph Failure\n");
        return HFA_FAILURE;
    }
    /*use default flags for search*/
    hfa_searchctx_setflags (&ctx, pfflags);

    psctx = &ctx; 
    if(NULL == (rptr = 
        hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)(psctx)))){
        ERR("Rptr allocation failure\n");
        goto m_ctx_cleanup;
    }
    pattr.path = path;
    /* Initialize attributes for parsing the payload file */
    if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        goto m_free_rptr;
    }
    if (NULL == (input = hfautils_memoryalloc(sizeof(hfa_iovec_t), 8, 
                    (hfa_searchctx_t *)(psctx)))){
        ERR ("unable to alloc iovec entries for payload");
        goto m_pattr_cleanup;
    }
    /* setup all input buffers as needed for parse results*/
    memset (input, 0, sizeof(hfa_iovec_t));
    memset (&param, 0, sizeof (hfa_searchparams_t));
    param.clusterno = cluster;

    boffset = 0;        
    iovlen_0_n = 0;
    tot_iov_datalen = 0;
    /* Parse through PCAP/NORMAL payload and process search  */     
    while(!gzeof(pattr.gzf)) {
        /* Get a pcacket buffer from PCAP/NORMAL payload file */
        if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
            if(gzeof(pattr.gzf))
                break;
            ERR("Failure in hfautils_parse_payload\n");
            goto m_free_input;
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
            hfa_searchparam_set_inputiovec_0_n(&param, input, iovlen_0_n, 1);

            /*set output parameters to search */
            hfa_searchparam_set_output(&param, rptr, rsize);

            /* Submit the search instruction to the HW 
            */
            if(HFA_SUCCESS != hfa_searchctx_search_async (&ctx, &param)){
                ERR("hfa_searchctx_search() failure\n");
                goto m_free_pktbuf;
            }
            /* poll for the status of search until search completes */
            do {
                status=0;
                if(HFA_SUCCESS != 
                        hfa_searchctx_get_searchstatus(&ctx, &param, &status)){
                    ERR("from hfa_searchctx_get_searchstatus: 0x%x\n", status);
                    goto m_free_pktbuf;
                }
            }while(CVM_HFA_EAGAIN == status);

            /*Get the search reason from hardware*/
            hfa_searchparam_get_hwsearch_reason(&param, &reason);

            if (reason != HFA_REASON_DDONE &&
                    reason != HFA_REASON_RFULL){
                ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
                hfa_dump_regs();
                goto m_free_pktbuf;
            }
            /*Get the pdboffset from hardware*/
            hfa_searchparam_get_hwsearch_pdboff (&param, &pdboffset);
            DBG("pdboffset = %lu\n", pdboffset);

            /* Post process the results from HFA and record found matches*/
            if(HFA_SUCCESS != hfa_searchctx_getmatches (&ctx, &param, 
                        &pmatches)){
                ERR ("searchctx getmatches failure()\n");
                goto m_free_pktbuf;
            }
            /*matches points to match buffer allocated by post processing*/
            hfautils_print_matches(&ctx, pmatches, &nmatches, boffset, verbose);

            boffset += pdboffset;
            payload += pdboffset;
            psize -= pdboffset;
            /*Get ppoflags 
             *If FSAVEBUF set in ppoflags then the application has to provide
             *total payload buffer to the search otherwise it has to provide 
             *current chunk buffer to the serach*/ 
            hfa_searchparam_get_ppoflags (&param, &ppoflags);
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
                 * iovecs till back buffer + current buffer fit in 
                 * the iovecs 
                 */
                if (NULL == (input_tmp = 
                    hfautils_memoryalloc(sizeof(hfa_iovec_t)*(iovlen_0_n+1),
                                8, (hfa_searchctx_t *)(psctx)))){
                    ERR ("unable to alloc iovec entries for payload");
                    goto m_free_pktbuf;
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
    LOG("total matches %lu\n", nmatches);
    retval = HFA_SUCCESS;
m_free_pktbuf:
    for(i = 0; i < iovlen_0_n; i++) {
        /* Cleanup allocated memory for payload buffer */
        hfautils_memoryfree(input[i].ptr, input[i].len, 
                            (hfa_searchctx_t *)NULL);
    }
m_free_input:
    hfautils_memoryfree(input, sizeof(hfa_iovec_t) * (iovlen_0_n+1), 
                                        (hfa_searchctx_t *)(psctx));
m_pattr_cleanup:
    hfautils_cleanup_payload_attributes(&pattr, &options);
m_free_rptr:
    hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)(psctx));
m_ctx_cleanup:
    hfa_dev_searchctx_cleanup (&hfa_dev, &ctx);
    return retval;
}

/*tasklet callback function */
void tasklet_callback(unsigned long path)
{
    task_attr_t     *task_attr = NULL;
    
    try_module_get(THIS_MODULE);

    if(NULL == (task_attr = hfautils_memoryalloc(sizeof(task_attr_t), 8, 
                                        (hfa_searchctx_t *)NULL))){
        ERR("Memory allocation failed task_attr \n");
        return ;
    }
    task_attr->data = t_attr.data;
    task_attr->size = t_attr.size;
    if(HFA_SUCCESS != process_search((char *)task_attr)){
        ERR("process_search failed for tasklet\n");
    }
    hfautils_memoryfree(task_attr,sizeof(task_attr_t),(hfa_searchctx_t *) NULL);
    module_put(THIS_MODULE);
    return ; 
}
/*thread callback function */
int thread_callback(void *path)
{
    try_module_get(THIS_MODULE);
    if(HFA_SUCCESS != process_search((char *)path)){
        ERR("process_search failed for thread\n");
    }
    module_put(THIS_MODULE);

    return 0;
}
/**
 * Load graph to HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    uint32_t                        graph_status=0;
    
    /*initialise graph object*/
    if(HFA_SUCCESS != hfa_dev_graph_init (&hfa_dev, &gstruct)){
        ERR("hfa_dev_graph_init() failure\n");
        return HFA_FAILURE;
    }
    /* set the cluster on which this graph will be loaded*/
    if(HFA_SUCCESS != hfa_graph_setcluster (&gstruct, clmsk)){
        ERR("hfa_graph_setcluster() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to HFA memory*/
    if(HFA_SUCCESS != hfautils_download_graph(&gstruct, graph_data, 
                gsize, GRAPHCHUNK, HFA_TRUE)){
        ERR("hfautils_download_graph() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to cache, if it is a cacheable graph */
    if(!HFA_GET_GRAPHATTR((&gstruct), memonly)){
        if( HFA_SUCCESS != hfa_graph_cacheload_async(&gstruct)){
            ERR("Graph Cacheload failure\n");
            goto graph_cleanup; 
        }
        graph_status=0;
        do {
            if(HFA_SUCCESS != hfa_graph_getstatus(&gstruct,&graph_status)){
                ERR("hfa_graph_getstatus() 0x%x\n", graph_status);
                goto graph_cleanup; 
            }
        }while(graph_status==CVM_HFA_EAGAIN);
    }
    /* Get savelen for cross packet matching */
    hfa_graph_getsavelen(&gstruct, &savelen);
    if(savelen <= 0)
        savelen = MAXSAVELEN;
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;

graph_cleanup:
    hfa_dev_graph_cleanup(&hfa_dev, &gstruct);       
    
    return HFA_FAILURE;
} 
/**
 * Configure cluster memory resources 
 */
static inline hfa_return_t 
configure_cluster_memory_resources(void) 
{
    int             i = 0;
    hfa_addr_t      mem_addr = 0; 
    hfa_size_t      mem_size=0;
    void            *hfa_mem = NULL;

    for (i = 0; i < hfa_dev_get_nclusters(&hfa_dev); ++i) {
        hfa_get_cluster(&hfa_dev, &hfa_cluster[i], i);
        hfa_cluster_cleanup(hfa_cluster[i]);
        hfa_cluster[i] = NULL;
    }
    for(cnt = 0; cnt< hfa_dev_get_nclusters(&hfa_dev); cnt++){
        hfa_cluster[cnt] = hfautils_memoryalloc(sizeof(hfa_cluster_t),
                                      8, (hfa_searchctx_t *)NULL);
        if(hfa_cluster[cnt]){
            if(HFA_SUCCESS != hfa_cluster_init(&hfa_dev, 
                        hfa_cluster[cnt],cnt)){
                ERR("hfa_cluster_init failed for clno %d\n",cnt);
                hfautils_memoryfree(hfa_cluster[cnt], sizeof(hfa_cluster_t), 
                                    (hfa_searchctx_t *)NULL);
                hfa_cluster[cnt--]=NULL;
                return HFA_FAILURE;
            }
        }
        else{
            ERR("memory allocation failed for cluster clno %d\n",cnt);
            cnt--;
            return HFA_FAILURE;
        }
    }
    if(hfa_dev_haspvt_hfamemory(&hfa_dev)){
        mem_addr = hfa_dev_get_memaddr(&hfa_dev);
        mem_size = hfa_dev_get_memsize(&hfa_dev);
        if(!mem_size){
            ERR("Zero Memory size found in device\n");
            return HFA_FAILURE;
        }
    } else {
        if(HFA_SUCCESS != hfautils_read_nb(hfa_mem_nb_name, &hfa_mem)){
            ERR("Error in reading HFA memory nb :%s\n", hfa_mem_nb_name);
            return HFA_FAILURE;
        }
        mem_addr = cvmx_ptr_to_phys(hfa_mem);
        hfautils_getnb_size(hfa_mem_nb_name, &mem_size);
    }   

    /*Setup Memory portion for all clusters*/
    if(HFA_SUCCESS != 
            hfa_cluster_setmem(hfa_cluster[0], mem_addr, mem_size)){
        ERR("hfa_cluster_setmem() failure\n");
        return HFA_FAILURE;
    }
    /*Share above allocated memory with other clusters*/
    for (i = 1; i < hfa_dev_get_nclusters(&hfa_dev); ++i){
        hfa_cluster_share_mem(hfa_cluster[0], hfa_cluster[i]);
    }
    return HFA_SUCCESS;
}
/** 
 * Process command line options,
 * Read graph and payload 
 */
static inline hfa_return_t 
process_options (void) 
{
    hfa_size_t                  read_off=0;
    
    /*Validate Cluster */
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

    cmsk_attr.tasks_mask = tasks_mask;
    cmsk_attr.threads_mask = threads_mask;
    
    if(HFA_SUCCESS != 
        hfautils_validate_threads_and_tasklets_coremask(&cmsk_attr)) {
        ERR("Threads and Tasklets Coremask validation failed\n");
        return HFA_FAILURE;
    }
    /* Read graph and payload */
    hfautils_file_size(graph, &gsize);
    hfautils_file_size(payload, &psize);
    
    if(HFA_SUCCESS != hfautils_validate_chunksize(&chunksize, psize)){
        ERR("Validation of chunksize failed\n");
        return HFA_FAILURE;
    }
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    if(HFA_SUCCESS != hfautils_read_file(graph, 
                &graph_data, gsize, &read_off, HFA_TRUE)){
        ERR ("Error in reading graph\n");
        return HFA_FAILURE;
    }
    read_off = 0;
    /* Tasklet has the limitation to open a file(filp_open()), So
     * read total payload(compressed or uncompressed) to a buffer.
     * Then each tasklet will get the data of requested size from 
     * that buffer.*/
    if(HFA_SUCCESS != hfautils_read_payload(payload, &payload_data, 
                                             &read_off, &t_attr)) {
        ERR("Error in reading payload\n");
        goto gfree;
    }
    options.payloadsize = psize;
    options.chunksize = chunksize;
    options.pcap = pcap;
    options.payload = payload;

    return HFA_SUCCESS;
gfree:
    hfautils_vmmemoryfree(graph_data, gsize, (hfa_searchctx_t *)NULL);       
    return HFA_FAILURE;
}

int 
entry(void)
{
    int                 stage = -1; 
    char                *cwd = NULL;
    struct path         pwd, root;

    /* Process command line options, read graph and payload */ 
    if(HFA_SUCCESS != process_options()) {
        ERR("failure in process_options\n");
        return HFA_FAILURE;
    }
    /*initialise HFA device and device driver*/
    if(HFA_SUCCESS != hfa_dev_init(&hfa_dev)){
        ERR("hfa_dev_init failed \n");
        stage = OPTIONS_INIT;
        goto m_cleanup;
    }
    /* 
     * This application explicitly configures the cluster memory resources,
     * instead of using the default in the HFA library.
     */
    if(HFA_SUCCESS != configure_cluster_memory_resources()) {
        ERR("Failure in configure_cluster_memory_resources\n");
        stage = DEV_INIT;
        goto m_cleanup;
    }
    /* Initialize graph object and load graph */
    if(HFA_SUCCESS != graph_load()) {
        ERR("Failure in graph_load\n");
        stage = DEV_INIT;
        goto m_cleanup;
    }
    /* Get current working directory */
    if(current && current->fs) {
        pwd = current->fs->pwd;
        path_get(&pwd);
        root= current->fs->root;
        path_get(&root);
        buf = (char *)hfautils_memoryalloc(100*sizeof(char), 8, 
                                        (hfa_searchctx_t *)NULL);
        if(buf == NULL) {
            ERR ("Memory allocation failed for path \n");   
            stage = GRAPH_INIT;
            goto m_cleanup;
        } 
        cwd = d_path(&pwd, buf, 100 * sizeof(char));
    }
    /* Launch threads and tasklets */
    if(HFA_SUCCESS != hfautils_launch_thread_and_tasklet(thread_callback,
                        tasklet_callback, &cmsk_attr, cwd)){
        ERR("launching threads and tasklets failed\n"); 
        stage = GRAPH_INIT;
        goto m_cleanup;
    }
    return (0);

m_cleanup:
    cleanup(stage);
    return (-1); 
}

void exit (void)
{
    int     stage = GRAPH_INIT;
    
    /*Kill all tasklets */
    hfautils_kill_tasklets(&cmsk_attr);
    cleanup(stage);
    LOG("hfa-lnx-async app removed successfully\n");
}
/* @cond APPINTERNAL */
module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
/* @endcond APPINTERNAL */
