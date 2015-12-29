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
 * using WQE(rather than poll-mode) and multiple search contexts across cores.
 * It reports the pattern-matches(only one core will report matches) found in
 * the payload based on graph(compiled using the pattern file). Each core
 * submits search operation on its context and gets a WQE entry from SSO. The
 * WQE may or may not correspond to the search operation submitted by the same
 * core. Hence the contexts are shared and locking is required. The following
 * lists the operational aspects of this application.
 * - Multicore - YES
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
 * - Nature of ctx - Shared among cores(initialized by first core).
 * - Number of ctx - 1 per core by default. Configurable using cmdline option
 * - Locks used by app - Spinlock_bh to protect access to search ctx.
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

static unsigned int nctx=0;
module_param (nctx, uint, 0444);
MODULE_PARM_DESC (cluster, "number of search ctx");

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

typedef enum {
    FREE_TO_SUBMIT = 0,
    SUBMITTED = 1,
    PROCESSED = 2 
}ctxstatus_t;

typedef struct {
    hfautils_lock_t     lock;
    uint32_t            ctxid;
    hfa_searchctx_t     sctx;
    hfa_searchparams_t  sparam;
    void                *rptr;
    hfa_iovec_t         iovec;
    ctxstatus_t         ctx_status;
volatile ctxstatus_t    status;
}hfa_ctx_t;

typedef struct {
    uint32_t            nctx;
    hfa_ctx_t           **ctx_ptrs;
}hfa_ctxdb_t;

CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         gstruct; 
CVMX_SHARED void                *graph_data = NULL, *payload_data = NULL;
CVMX_SHARED hfa_size_t          gsize=0, psize=0;
CVMX_SHARED options_t           options;
CVMX_SHARED int                 pfflags=0;
CVMX_SHARED uint32_t            ncores=0;
CVMX_SHARED uint64_t            rsize =0;
CVMX_SHARED hfa_ctxdb_t         ctxdb;
CVMX_SHARED task_attr_t         t_attr;
CVMX_SHARED uint32_t            nctx_per_core = 0;
atomic_t                        pend_wqe_cnt = ATOMIC_INIT(0);
char                            *buf = NULL; 
coremask_attr_t                 cmsk_attr;
/*Variables Export from HFA_LIB_MODULE*/
extern int                      hfa_pow_rcv_grp[NR_CPUS];
extern int                      hfa_napi_perf;
extern int                      hfa_distribute_load;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT = 4,
    HWWQE_CB_REGISTER 
}error_stage_t;

cvm_oct_callback_result_t process_hwwqe(struct net_device*, void*, struct sk_buff*);

/**
 * Classify the given number of ctx  among cores
 * based on nctx_per_core
 */
uint32_t classify(uint32_t *current_idx)
{
    uint32_t    id;
    uint32_t    corenum = cvmx_get_core_num();

    id = (nctx_per_core * corenum) + (*current_idx);
    (*current_idx)++;

    if((*current_idx) >= nctx_per_core){
        (*current_idx) = 0;
    }
    return id;
}
/**
 * Cleanup memory allocated for context 
 */
hfa_return_t 
ctxdb_cleanup(void) 
{   
    int i = 0;
    hfa_ctx_t *pctx = NULL;
    
    for (i = 0; i < nctx; i++) {
        pctx = (hfa_ctx_t *)((ctxdb.ctx_ptrs)[i]); 
        if(pctx) {
            if((&pctx->sctx)->pgraph)
                hfa_dev_searchctx_cleanup(&hfa_dev, &pctx->sctx);
            if(pctx->rptr) {
                hfautils_memoryfree(pctx->rptr, rsize, 
                                (hfa_searchctx_t *)NULL);
                pctx->rptr = NULL;
            }
            hfautils_memoryfree(pctx, sizeof(hfa_ctx_t),
                                (hfa_searchctx_t *)NULL);
        }
    }
    if(ctxdb.ctx_ptrs)   
        hfautils_memoryfree(ctxdb.ctx_ptrs, sizeof(hfa_ctx_t *) * ctxdb.nctx, 
                                            (hfa_searchctx_t *)NULL); 
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
        case HWWQE_CB_REGISTER:
            hfa_register_hwwqe_interceptcb(NULL);
            if(buf) {
                hfautils_memoryfree(buf, 100 * sizeof(char), 
                                        (hfa_searchctx_t *)NULL);
            }
        case CTX_INIT:
            ctxdb_cleanup();
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
            ERR("Memory allocation failed for ctx_ptrs\n");
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
 * Initializes each context database and
 * initializes the search context of each context 
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

    if(NULL == (*ppctx = hfautils_memoryalloc(sizeof(hfa_ctx_t), 8, 
                                                (hfa_searchctx_t *)NULL))){
        ERR("Memory allocation failed for pctx\n");
        return HFA_FAILURE;
    }
    pctx = *ppctx;
    DBG("pctx: %p\n",pctx);
    memset(pctx, 0 , sizeof(hfa_ctx_t));
    hfautils_lockinit(&pctx->lock);
    pctx->ctxid = ctxid;

    /*initialise search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init(&hfa_dev, &pctx->sctx)) {
        ERR("error from searchctx_init\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph(&pctx->sctx, &gstruct)) {
        ERR("setgraph failure\n");
        return HFA_FAILURE;
    }
    /*set flags for search*/
    hfa_searchctx_setflags(&pctx->sctx, flags);
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
    memset(wqe, 0, sizeof (cvmx_wqe_t));
    memset(&pctx->iovec, 0, sizeof (hfa_iovec_t));
    
    pctx->iovec.ptr = payload;
    pctx->iovec.len = cpsize;
    
    pctx->sparam.clusterno = cluster;
    /*set input parameters to search*/
    hfa_searchparam_set_inputiovec(&pctx->sparam, &pctx->iovec, 1);

    /*set output parameters to search */
    hfa_searchparam_set_output(&pctx->sparam, pctx->rptr, rsize);

    pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data;
    /*Initialize wqe_pktdata */ 
    pktdata->pnctx = (uint64_t)pctx; 
   
    cvmx_wqe_set_grp(wqe, hfa_pow_rcv_grp[cvmx_get_core_num()]);
    DBG("wqe_grp = %d\n",hfa_pow_rcv_grp[cvmx_get_core_num()]); 
    pctx->sparam.wqe = wqe;
    
    /* Submit the search instruction to the HW(submit wqe to the HW) */
    if(HFA_SUCCESS != 
            hfa_searchctx_search_async (&pctx->sctx, &pctx->sparam)){
        ERR("hfa_searchctx_search() failure\n");
        goto m_free_wqe;
    }
    pctx->ctx_status = SUBMITTED;
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
    uint32_t                    ctx_id = 0, current_idx = 0;
    hfa_ctx_t                   *pctx = NULL; 
    hfautils_payload_attr_t     pattr;
    hfa_size_t                  nmatches = 0;
    int64_t                     cpsize = 0;
    void                        *payload = NULL; 
    hfa_return_t                retval = HFA_FAILURE;
    hfa_pdboff_t                pdboffset = 0;
    
    /* Initialize attributes for parsing the payload file */
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    pattr.path = path;
    
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
        cpsize = pattr.psize;
        payload = pattr.payload;
        /* This while loop is for RFULL case, if RFULL occures it will 
         * keep sending the data till all data consumed in a packet 
         * by HFA engine */
        while(cpsize > 0) {
            /* submit a packet on each context */
            do
            {
                ctx_id = classify(&current_idx);
                /*Get the pointer to ctx database for the core */
                pctx = (hfa_ctx_t *)((ctxdb.ctx_ptrs)[ctx_id]);
                if(hfautils_unlikely(NULL == pctx)){
                    ERR("ctx NULL\n");
                    goto pktbuf_free;
                }
                hfautils_lock(&pctx->lock);
                if(HFA_SUCCESS!= submit_wqe(pctx, payload, cpsize)){
                    ERR("submit wqe failed\n");
                    hfautils_unlock(&pctx->lock);
                    goto pktbuf_free;
                }
                hfautils_unlock(&pctx->lock);
            }while(current_idx);      
            /* Check Context status for pending search instructions in HW, 
             * blocked till instruction completes*/
            do
            {
                ctx_id = classify(&current_idx);
                /*Get the pointer to ctx database for the core */
                pctx = (hfa_ctx_t *)((ctxdb.ctx_ptrs)[ctx_id]);
                if(hfautils_unlikely(NULL == pctx)){
                    ERR("ctx NULL\n");
                    goto pktbuf_free;
                }
                /* loop till instruction completes */
                if(pctx->ctx_status == SUBMITTED) {
                    while(1) {
                        hfautils_lock(&pctx->lock);
                        if(pctx->status == PROCESSED) {
                            hfautils_unlock(&pctx->lock);
                            break;
                        }
                        hfautils_unlock(&pctx->lock);
                    }
                    hfautils_lock(&pctx->lock); 
                    pctx->status = FREE_TO_SUBMIT;
                    post_process(pctx, &nmatches, &pdboffset);
                    pctx->ctx_status = FREE_TO_SUBMIT;
                    hfautils_unlock(&pctx->lock);
                }
            }while(current_idx);      
            
            cpsize -= pdboffset;
            payload += pdboffset;
        }
        /* Cleanup allocated memory for payload buffer */
        hfautils_memoryfree(pattr.payload, pattr.psize, 
                            (hfa_searchctx_t *)NULL);
    }
    LOG("Total matches: %lu \n", nmatches);
    retval = HFA_SUCCESS;
pktbuf_free:
    if(retval != HFA_SUCCESS) {
        hfautils_memoryfree(pattr.payload, pattr.psize, 
                            (hfa_searchctx_t *)NULL);
    }
pattr_cleanup:
    hfautils_cleanup_payload_attributes(&pattr, &options);
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
    return ; 
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
    hfa_size_t                  read_off=0;
     
    if(!hfa_napi_perf){
        ERR("Reinsert HFA_LIB_MODULE with hfa_napi_perf=1\n"\
       "\t eg. insmod cvm-hfa-lib.ko hfa_distribute_load=0 hfa_napi_perf=1\n");
        return HFA_FAILURE;
    }
    if(hfa_distribute_load){
        ERR("Reinsert HFA_LIB_MODULE with hfa_distribute_load=0\n"\
       "\t eg. insmod cvm-hfa-lib.ko hfa_distribute_load=0 hfa_napi_perf=1\n");
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
    nctx_per_core = nctx/ncores; 
    
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
    int                         stage = -1; 
    uint32_t                    i = 0;
    int                         free_mask = 0;
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

    if(HFA_SUCCESS != ctxdb_init(nctx)){
        ERR("ctxdb_init failed\n");
        stage = GRAPH_INIT;
        goto m_cleanup;
    }
    for(i=0; i<nctx; i++){
        if(HFA_SUCCESS != Initialize_Ctx(i, pfflags)){
            ERR("Failure in creating flow: %d\n", i);
            stage = CTX_INIT;
            goto m_cleanup;
        }
    }
    /*Register the callback for HW WQE */ 
    if(HFA_SUCCESS != hfa_register_hwwqe_interceptcb(process_hwwqe)){
        ERR("Error in registering cb for HW WQE\n");
        stage = CTX_INIT;
        goto m_cleanup;
    }
    /* Get Current Working Directory */
    if(current && current->fs) {
        pwd = current->fs->pwd;
        path_get(&pwd);
        root= current->fs->root;
        path_get(&root);
        buf = (char *)hfautils_memoryalloc(100 * sizeof(char), 8, 
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
    return (-1);
}
cvm_oct_callback_result_t process_hwwqe(struct net_device *dev, void *wqe, 
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
    switch(hfa_get_wqe_type(wqe)) {
        /* WQE is a search instruction response */
        case HFA_SEARCH_HWWQE:
            packet_data = (hfa_wqe_pktdata_overload_t *)(t_wqe->packet_data); 
            pctx = (hfa_ctx_t *)packet_data->pnctx;
            /*Process HW WQE */
            hfa_searchctx_processwork(t_wqe, &psctx, &psparam);
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
    LOG("hfa-lnx-wqe-lock app removed successfully\n");
}

module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
