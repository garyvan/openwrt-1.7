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
 * Reference application to showcase HFA API in asynchronous mode of operation
 * using WQE(rather than poll-mode). It performs multiple searches per core. It
 * reports the pattern-matches found in the payload based on graph(compiled
 * using the pattern file). The following lists the operational aspects of this
 * application.
 * - Multicore - YES. 
 * - Tasklets - Not supported.
 * - Kernel threads - Supported.
 *   Each kernel thread bind to perticular core.
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

static unsigned int nctx=0;
module_param (nctx, uint, 0444);
MODULE_PARM_DESC (cluster, "number of search ctx");

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

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    HWWQE_CB_REGISTER
}error_stage_t;

typedef enum {
    FREE_TO_SUBMIT = 0,
    PROCESSED = 1 
}ctxstatus_t;

typedef struct {
    hfa_searchctx_t     sctx;
    hfa_searchparams_t  sparam;
    hfa_iovec_t         iovec;
    void                *rptr;
volatile ctxstatus_t    status;
}hfa_ctx_t;

CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         gstruct; 
CVMX_SHARED void                *graph_data = NULL, *payload_data = NULL;
CVMX_SHARED hfa_size_t          gsize=0, psize=0;
CVMX_SHARED options_t           options;
CVMX_SHARED int                 pfflags=0;
CVMX_SHARED uint32_t            ncores=0;
CVMX_SHARED uint64_t            rsize =0;
CVMX_SHARED task_attr_t         t_attr;
CVMX_SHARED uint32_t            nctx_onthis_core=0;
atomic_t                        pend_wqe_cnt = ATOMIC_INIT(0);
char                            *buf = NULL; 
coremask_attr_t                 cmsk_attr;

/*Variables Export from HFA_LIB_MODULE*/
extern int                      hfa_pow_rcv_grp[NR_CPUS];
extern int                      hfa_napi_perf;
extern int                      hfa_distribute_load;

cvm_oct_callback_result_t intercept_callback(struct net_device*, void*, struct sk_buff*);

/**
 * Application cleanup will be done by this routine 
 */
static inline void
cleanup(int stage)
{
    switch(stage) {
        case HWWQE_CB_REGISTER:
            hfa_register_hwwqe_interceptcb(NULL);
            if(buf) {
                hfautils_memoryfree(buf, 100 * sizeof(char), 
                                        (hfa_searchctx_t *)NULL);
            }
        case GRAPH_INIT:
            if(!HFA_GET_GRAPHATTR((&gstruct), memonly)){
                hfa_graph_cacheunload (&gstruct);
            }
            hfa_dev_graph_cleanup(&hfa_dev, &gstruct);
        case DEV_INIT:
            hfa_dev_cleanup (&hfa_dev);        
        case OPTIONS_INIT: 
            hfautils_vmmemoryfree(graph_data, gsize, (hfa_searchctx_t *)NULL);       
            if(tasks_mask) {
                hfautils_vmmemoryfree(payload_data, t_attr.size, 
                                            (hfa_searchctx_t *)NULL);    
            }   
        default:
            break;
    }
}
/**
 * Cleanup memory allocated for context 
 */
static inline void 
cleanup_ctx(hfa_ctx_t *ppctx)
{
    int    ctxid = 0;

    for(ctxid=0; ctxid < nctx_onthis_core; ctxid++) {
        if(ppctx[ctxid].rptr) {
            hfautils_memoryfree(ppctx[ctxid].rptr, rsize, 
                                (hfa_searchctx_t *)NULL);
            ppctx[ctxid].rptr = NULL;
        }
        if((&(ppctx[ctxid].sctx))->pgraph)
            hfa_dev_searchctx_cleanup(&hfa_dev, &(ppctx[ctxid].sctx));
    }
    hfautils_memoryfree(ppctx, sizeof(hfa_ctx_t) * nctx_onthis_core,
                                        (hfa_searchctx_t *)NULL); 
}
/**
 * Initializes the search context object of each context 
 */
hfa_return_t
Initialize_Ctx (hfa_ctx_t *pctx)
{

    /*initialise search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init(&hfa_dev, &pctx->sctx)){
        ERR("error from searchctx_init\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph(&pctx->sctx, &gstruct)){
        ERR("setgraph failure\n");
        return HFA_FAILURE;
    }
    /*set flags for search*/
    hfa_searchctx_setflags(&pctx->sctx, pfflags);
    
    if(NULL == (pctx->rptr = 
        hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)NULL))) {
        ERR("memory allocation failed for rptr \n");
        return HFA_FAILURE;
    }
    return HFA_SUCCESS;
}
/** 
 * Set search parameters and submit WQE to the HW 
 */
hfa_return_t submit_wqe(hfa_ctx_t *pctx, void *payload, int64_t cpsize)
{
    cvmx_wqe_t                  *wqe = NULL;
    hfa_wqe_pktdata_overload_t  *pktdata = NULL;
    

    wqe = cvmx_fpa_alloc (CVMX_FPA_WQE_POOL);
    if(wqe == NULL){
        ERR("wqe allocation failed\n");
        return HFA_FAILURE;
    }

    memset(&pctx->sparam, 0, sizeof(hfa_searchparams_t));
    memset (wqe, 0, sizeof (cvmx_wqe_t));
    memset (&pctx->iovec, 0, sizeof(hfa_iovec_t));
    
    pctx->iovec.ptr = payload;
    pctx->iovec.len = cpsize;
   
    pctx->sparam.clusterno = cluster;
    
    /*set input parameters to search*/
    hfa_searchparam_set_inputiovec(&pctx->sparam, &pctx->iovec, 1);

    /*set output parameters to search */
    hfa_searchparam_set_output(&pctx->sparam, pctx->rptr, rsize);

    pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data; 
    pktdata->pnctx = (uint64_t)pctx; 
   
    if(hfa_pow_rcv_grp[cvmx_get_core_num()] == -1){
        ERR("The WQE group for this core (%d) is not enabled\n",
                                               cvmx_get_core_num()); 
        goto m_free_wqe;
    }
    cvmx_wqe_set_grp(wqe, hfa_pow_rcv_grp[cvmx_get_core_num()]);

    pctx->sparam.wqe = wqe;

    /* Submit the search instruction to the HW(submit wqe to the HW) */
    if(HFA_SUCCESS != 
            hfa_searchctx_search_async (&pctx->sctx, &pctx->sparam)){
        ERR("hfa_searchctx_search() failure\n");
        goto m_free_wqe;
    }
    atomic_inc(&pend_wqe_cnt);
    return HFA_SUCCESS;

m_free_wqe:
    cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
    
    return HFA_FAILURE;   
}     
/**
 * Post process the results from HFA and record found matches
 */
static inline hfa_return_t
post_process(hfa_ctx_t *pctx, hfa_size_t *nmatches, hfa_pdboff_t *pdboffset)
{
    uint64_t                *pmatches = NULL;
    int                     boffset = 0; 
    uint32_t                reason = 0;


    /*Get the search reason from hardware*/
    hfa_searchparam_get_hwsearch_reason(&pctx->sparam, &reason);

    if (reason != HFA_REASON_DDONE &&
            reason != HFA_REASON_RFULL){
        ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
        hfa_dump_regs();
        return HFA_FAILURE;
    }
    /*Get the pdboffset from hardware*/
    hfa_searchparam_get_hwsearch_pdboff (&pctx->sparam, pdboffset);
    DBG("pdboffset = %lu\n", *pdboffset);
    /* Post process the results from HFA and record found matches*/
    if(HFA_SUCCESS != hfa_searchctx_getmatches (&pctx->sctx, 
                                &pctx->sparam, &pmatches)){
        ERR ("searchctx getmatches failure()\n");
        return HFA_FAILURE;
    }
    /*matches points to match buffer allocated by post processing*/
    hfautils_print_matches (&pctx->sctx, pmatches, nmatches, boffset, 
                                                     verbose);
    return HFA_SUCCESS;
}

hfa_return_t process_search(char *path)
{
    uint32_t                    ctxid = 0;
    hfa_ctx_t                   *ppctx = NULL, *pctx = NULL; 
    hfautils_payload_attr_t     pattr;
    hfa_size_t                  nmatches = 0;
    hfa_pdboff_t                pdboffset = 0;
    int64_t                     cpsize = 0;
    void                        *payload = NULL; 
    hfa_return_t                retval = HFA_FAILURE;
    
    if(NULL == (ppctx = 
        hfautils_memoryalloc(sizeof(hfa_ctx_t) * nctx_onthis_core, 8, 
                                       (hfa_searchctx_t *)NULL))){
        ERR("memory allocation failed for ppctx \n");
        return HFA_FAILURE;
    }
    memset(ppctx, 0 , sizeof(hfa_ctx_t) * nctx_onthis_core);

    for(ctxid = 0; ctxid < nctx_onthis_core; ctxid++){

        if(HFA_SUCCESS != Initialize_Ctx(&ppctx[ctxid])){
            LOG("Failure in Initialize_Ctx\n");
            goto cleanup_ctx;
        }
    }
    /* Initialize attributes for parsing the payload file */
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    pattr.path = path;
    
    if(HFA_SUCCESS != 
        hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        goto cleanup_ctx;
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
        cpsize = pattr.psize;
        payload = pattr.payload;
        /* This while loop is for RFULL case, if RFULL occures it will 
         * keep sending the data till all data consumed in a packet 
         * by HFA engine */
        while(cpsize > 0) {
            /* submit a packet on each context */
            for (ctxid = 0; ctxid < nctx_onthis_core; ctxid++) {
                pctx = &ppctx[ctxid];
                if(HFA_SUCCESS != submit_wqe(pctx, payload, cpsize)) {
                    ERR("submit wqe failed\n");
                    hfautils_memoryfree(pattr.payload, pattr.psize, 
                                        (hfa_searchctx_t *)NULL);
                    goto pattr_cleanup;
                }
            }
            /* Check Context status for pending search instructions in HW, 
             * blocked till instruction completes*/
            for (ctxid = 0; ctxid < nctx_onthis_core; ctxid++) {
                pctx = &ppctx[ctxid];
                /* loop till instruction completes */
                while(1) {
                    if(pctx->status == PROCESSED) {
                        break;
                    }
                }
                pctx->status = FREE_TO_SUBMIT;
                post_process(pctx, &nmatches, &pdboffset);
            }
            cpsize -= pdboffset;
            payload += pdboffset;
        }
        /* Cleanup allocated memory for payload buffer */
        hfautils_memoryfree(pattr.payload, pattr.psize, 
                            (hfa_searchctx_t *)NULL);
    }
    LOG("Total matches: %lu (%lu per sctx) \n", nmatches, 
                        (nmatches/nctx_onthis_core));

    retval = HFA_SUCCESS;
pattr_cleanup:
    hfautils_cleanup_payload_attributes(&pattr, &options);
cleanup_ctx:
    cleanup_ctx(ppctx);
    return retval;
}

/*Tasklet callback function */
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
    return; 
}

/*thread callback function */
int thread_callback(void *path)
{
    try_module_get(THIS_MODULE);
    if(HFA_SUCCESS != process_search((char *)path)){
        ERR("process_search failed for thread\n");
    }
    /* Threads will loop till all WQEs are processed */ 
    while(atomic_read(&pend_wqe_cnt)){
    }
    module_put(THIS_MODULE);
    
    return 0;
}
/**
 * Load graph into HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    uint32_t                    graph_status=0;
    
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
    /* load graph to cache */
    if(!HFA_GET_GRAPHATTR((&gstruct), memonly)){
        if( HFA_SUCCESS != hfa_graph_cacheload_async (&gstruct)){
            ERR("Graph Cacheload failure\n");
            goto graph_cleanup; 
        }
        graph_status=0;
        do {
            if(HFA_SUCCESS != hfa_graph_getstatus(&gstruct, &graph_status)){
                ERR("hfa_graph_getstatus() 0x%x\n", graph_status);
                goto graph_cleanup; 
            }
        }while(CVM_HFA_EAGAIN == graph_status);
    }
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;

graph_cleanup:
    hfa_dev_graph_cleanup(&hfa_dev, &gstruct);
    return HFA_FAILURE;
}
/** 
 * Process command line options,
 * Read graph and payload 
 */
static inline hfa_return_t 
process_options (void) 
{
    hfa_size_t                  read_off = 0;
        
    if(!hfa_napi_perf){
        ERR("Reinsert HFA_LIB_MODULE with hfa_napi_perf=1\n"\
       "\t eg. insmod cvm-hfa-lib.ko hfa_distribute_load=1 hfa_napi_perf=1\n");
        return HFA_FAILURE;
    }
    if(!hfa_distribute_load){
        ERR("Reinsert HFA_LIB_MODULE with hfa_distribute_load=1\n"\
       "\t eg. insmod cvm-hfa-lib.ko hfa_distribute_load=1 hfa_napi_perf=1\n");
        return HFA_FAILURE;
    }
    if(cluster < 0 || cluster > hfa_get_max_clusters()){
        ERR("Invalid cluster provided\n");
        return HFA_FAILURE;
    }
    if(clmsk == 0)
        clmsk = hfa_get_max_clmsk();

    if(clmsk > hfa_get_max_clmsk()){
        ERR("Invalid Graph Cluster Mask: 0x%x\n", clmsk);
        return HFA_FAILURE;
    }
    if(tasks_mask) {
        ERR("tasks_mask not supported\n");
        return HFA_FAILURE;
    }
    cmsk_attr.tasks_mask = tasks_mask;
    cmsk_attr.threads_mask = threads_mask;
    
    if(HFA_SUCCESS != 
        hfautils_validate_threads_and_tasklets_coremask(&cmsk_attr)) {
        ERR("Threads and Tasklets Coremask validation failed\n");
        return HFA_FAILURE;
    }
    ncores = cmsk_attr.task_cores + cmsk_attr.thread_cores;
    if(nctx == 0)
        nctx = ncores;
         
    if(nctx % ncores){
        ERR("nctx should be multiple of number of cores processing\n");
        return HFA_FAILURE;
    }
    nctx_onthis_core = nctx/ncores;
    
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
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    
    /*Read Graph file*/
    if(HFA_SUCCESS != hfautils_read_file(graph, 
                &graph_data, gsize, &read_off, HFA_TRUE)){
        ERR ("Error in reading graph\n");
        return HFA_FAILURE;
    }
    read_off = 0;
    if(tasks_mask) {
        /* Tasklet has the limitation to open a file(filp_open()), So
        * read total payload(compressed or uncompressed) to a buffer.
        * Then each tasklet will get the data of requested size from 
        * that buffer. */
        if(HFA_SUCCESS != hfautils_read_payload(payload, &payload_data, 
                                             &read_off, &t_attr)) {
            ERR("Error in reading payload\n");
            goto gfree;
        }
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
entry (void)
{
    int                         free_mask = 0;
    int                         stage = -1;
    char                        *cwd = NULL;
    struct path                 pwd, root;
     
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
    /* Initialize graph object and load graph */
    if(HFA_SUCCESS != graph_load()) {
        ERR("Failure in graph_load\n");
        stage = DEV_INIT;
        goto m_cleanup;
    }
    if(!hfa_isethernetdrv_present()){
        if (hfa_create_fpa_pool (CVMX_FPA_WQE_POOL, "Work queue entry",
                128, 60000, &free_mask)){
            stage = GRAPH_INIT;
            goto m_cleanup;
        }
        if (octeon_has_feature(OCTEON_FEATURE_CN68XX_WQE) &&
                    (!cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (8))))
            hfa_oct_initialize_sso(60000);
    }
    /*Register the callback for HW WQE */ 
    if(HFA_SUCCESS != hfa_register_hwwqe_interceptcb(intercept_callback)){
        ERR("Error in registering cb for HW WQE\n");
        stage = GRAPH_INIT;
        goto m_cleanup;
    }
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
            stage = HWWQE_CB_REGISTER;
            goto m_cleanup;
        } 
        cwd = d_path(&pwd, buf, 100*sizeof(char));
    }
    
    /*launch threads and tasklets */ 
    if(HFA_SUCCESS != hfautils_launch_thread_and_tasklet(thread_callback, 
                             tasklet_callback, &cmsk_attr, cwd)){
        ERR("launching threads and tasklets failed\n"); 
        stage = HWWQE_CB_REGISTER;
        goto m_cleanup;
    }
    return (0);

m_cleanup:
    cleanup(stage);
 
    return -1;
}

/* 
 * This callback is called when a HFA WQE is available from SSO. This callback
 * is invoked in a softirq context and so appropriate precautions must be taken
 * in its implementation.
 */ 
cvm_oct_callback_result_t intercept_callback(struct net_device *dev, void *wqe,
                                                            struct sk_buff *skb)
{
    cvmx_wqe_t                  *t_wqe = NULL;
    hfa_ctx_t                   *pctx = NULL;
    hfa_searchctx_t             *psctx = NULL;
    hfa_searchparams_t          *psparam = NULL;
    hfa_wqe_pktdata_overload_t  *packet_data = NULL;
   
    t_wqe = (cvmx_wqe_t *)wqe;
    
    if(t_wqe == NULL){
        return CVM_OCT_TAKE_OWNERSHIP_WORK;
    }
    switch(hfa_get_wqe_type(t_wqe)) { 
        /* WQE is a search instruction response */
        case HFA_SEARCH_HWWQE:
            packet_data = (hfa_wqe_pktdata_overload_t *)(t_wqe->packet_data); 
            /*Process HW WQE */
            hfa_searchctx_processwork(t_wqe, &psctx, &psparam);
            pctx = (hfa_ctx_t *)packet_data->pnctx;
            /* Free memory to WQE pool */
            cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
            /* Change status to submit next packet */	
            pctx->status = PROCESSED;
            atomic_dec(&pend_wqe_cnt);
            break;
        default:
            break;
    }
    return CVM_OCT_TAKE_OWNERSHIP_WORK;
}
void exit (void)
{
    int         stage = HWWQE_CB_REGISTER;

    cleanup(stage);
    LOG("hfa-lnx-wqe app removed successfully\n");
}

module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
