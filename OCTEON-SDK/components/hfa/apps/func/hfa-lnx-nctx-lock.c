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
 * using poll-mode and multiple search-ctx across cores. It reports the 
 * pattern-matches found in the payload based on graph.A global linked list 
 * (sharable by all cores)is created by one core with all search contexts.
 * Each core gets the packet to be searched and submits search operation on 
 * available context by parsing through the gloabal linked list. Each context 
 * submitted only once by any core.The context may or may not correspond to the
 * search operation submitted by the same core. Hence the contexts are shared 
 * and locking is required. Each core submits a search on a ctx if no other 
 * search is pending on that ctx.After submission each core polls once for all 
 * submitted searches.If a search is completed the result is processed otherwise
 * it moves to the next context.The core will not block till search completes.
 * Each core moves to the next packet after all contexts has processed.
 * The result buffer is allocated per ctx.The following lists the operational 
 * aspects of this application.
 * - Multicore - YES. 
 * - Tasklets - Supported.
 * - Kernel threads - Supported.
 *   Each kernel thread/kernel tasklet bind to perticular core.
 *   Configurable using cmdline options.
 * - Type of API 
 *       - Asynchronous OO API(cacheload and search)
 *       - Synchronous OO API(memload)
 * - Cluster resources - Managed by HFA API.
 * - Clusters shared among cores - YES
 * - Graph count - 1 (loaded by first core)
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Shared among cores(initialized by first core).
 * - Number of ctx - 1 per core by default. Configurable using cmdline option
 * - Locks used by app - Spinlock to protect access to search ctx.
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - 0 by default. Configurable, but limited to 1 cluster
 * - Buffer Payload - Supported. Same payload is used by all cores.
 * - PCAP Payload - Not Supported
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

static unsigned int clmsk=0x0;
module_param (clmsk, uint, 0444);
MODULE_PARM_DESC (clmsk, "Clusters on which graph to be loaded");

static unsigned int nctx=1;
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

static int      verbose = 0;
module_param (verbose, int, 0444);
MODULE_PARM_DESC (verbose, "verbose option to print matches");

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         gstruct; 
CVMX_SHARED void                *graph_data = NULL, *payload_data = NULL;
CVMX_SHARED hfa_size_t          gsize=0, psize=0;
CVMX_SHARED hfautils_listhead_t nctx_glist;
CVMX_SHARED hfautils_listhead_t subctx_glist;
CVMX_SHARED int                 pfflags = 0;
CVMX_SHARED hfa_size_t          rsize = 0;
CVMX_SHARED task_attr_t         t_attr;
atomic_t                        core_cnt = ATOMIC_INIT(0);
char                            *buf = NULL;
coremask_attr_t                 cmsk_attr;

typedef enum {
    FREE_TO_SUBMIT = 0,
    SUBMITTED =1,
    PROCESSED
}ctxstatus_t;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT 
}error_stage_t;

typedef struct {
    hfautils_lock_t     lock;
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
 * Parse through global linked list and 
 * cleanup each search node  
 */
static inline void 
snode_cleanup(void) 
{
    hfautils_listhead_t *gnode = NULL, *gnode_next = NULL;
    hfa_searchnode_t    *pnode = NULL;
    
    hfautils_listforeachsafe(gnode, gnode_next, &nctx_glist){
        pnode = hfautils_listentry (gnode, hfa_searchnode_t, glist);
        if(pnode->rptr) {
            hfautils_memoryfree(pnode->rptr, rsize, (hfa_searchctx_t *) NULL);
        }
        if((pnode->ctx).pgraph)
            hfa_dev_searchctx_cleanup (&hfa_dev, &pnode->ctx);

        hfautils_memoryfree(pnode, sizeof(hfa_searchnode_t), 
                                    (hfa_searchctx_t *) NULL);
    }
}
/**
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(int stage) 
{
    switch(stage) {
        case CTX_INIT :
            snode_cleanup();
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
            hfautils_vmmemoryfree(graph_data, gsize, (hfa_searchctx_t *) NULL);
            if(payload_data) {
                hfautils_vmmemoryfree(payload_data, t_attr.size, 
                                            (hfa_searchctx_t *)NULL);   
            }
        default:
            break;          
    }
}
/**
 * Set search parameters and submit a search instruction to HW 
 */
static inline hfa_return_t
submit(hfa_searchnode_t *pnode, void *payload, int64_t psize) 
{
    hfa_searchparams_t      *psparam = NULL;   
    int                     len = 0; 

    psparam = &pnode->sparam;
    memset (&pnode->input, 0, sizeof(hfa_iovec_t));
    memset (psparam, 0, sizeof (hfa_searchparams_t));

    /* setup all input buffers as needed for parse results*/
    psparam->clusterno = cluster;

    len = (psize < chunksize) ? psize : chunksize;
    pnode->input.ptr = payload;
    pnode->input.len = len;

    /*set input parameters to search*/
    hfa_searchparam_set_inputiovec (psparam, &pnode->input, 1);

    /*set output parameters to search */
    hfa_searchparam_set_output(psparam, pnode->rptr, rsize);

    /* Submit a search instruction to the HW 
    */
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
post_process(hfa_searchnode_t *pnode, hfa_size_t *nmatches)
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
    /* Post process the results from HFA and record found matches*/
    if(HFA_SUCCESS != hfa_searchctx_getmatches (&pnode->ctx, 
                                &pnode->sparam, &pmatches)){
        ERR ("searchctx getmatches failure()\n");
        return HFA_FAILURE;
    }
    /*matches points to match buffer allocated by post processing*/
    hfautils_print_matches (&pnode->ctx, pmatches, nmatches, boffset, 
                                                           verbose);
    return HFA_SUCCESS;
}
/**
 * Poll for the pending search instructions in the HW
 * (blocked till instruction completes) and process them. 
 */
static inline void 
poll(hfa_size_t *nmatches) 
{
    uint32_t            status = 0;
    hfautils_listhead_t *snode = NULL, *snode_next = NULL;
    hfa_searchnode_t    *pnode = NULL;

    /* Parse through the submitted list and process  
     * pending instructions in the HW */
    hfautils_listforeachsafe(snode, snode_next, &subctx_glist){
        pnode = hfautils_listentry (snode, hfa_searchnode_t, slist);
        
        if((hfautils_trylock(&pnode->lock))) {
            if(pnode->status == SUBMITTED) {
                do {
                    status=0;
                    if(HFA_SUCCESS!=hfa_searchctx_get_searchstatus(&pnode->ctx, 
                                                    &pnode->sparam, &status)){
                        ERR("from hfa_searchctx_get_searchstatus:0x%x\n",status);
                    }
                }while(CVM_HFA_EAGAIN == status);

                pnode->status = PROCESSED;

                /*Remove node from submitted list*/
                hfautils_lock(&subctx_glist.lock);
                hfautils_listdel(&pnode->slist);
                hfautils_unlock(&subctx_glist.lock);

                post_process(pnode, nmatches);
            }
            hfautils_unlock(&pnode->lock);
        }
    }
}
/**
 * Performs search process for each core 
 */
hfa_return_t process_search(char *path)
{
    hfa_searchnode_t            *pnode = NULL;
    hfa_size_t                  nmatches = 0;
    uint32_t                    status=0;
    hfautils_listhead_t         *gnode = NULL, *gnode_next = NULL;
    hfautils_listhead_t         *snode = NULL, *snode_next = NULL;
    void                        *payload = NULL;
    int64_t                     cpsize=0;
    hfautils_payload_attr_t     pattr;
    
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    pattr.path = path;
    /* Initialize attributes for parsing the payload file */
    if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        atomic_dec(&core_cnt);
        return HFA_FAILURE;
    }
    /* Parse through payload and process search  */     
    while(!gzeof(pattr.gzf)) {
        /* Get a pcacket buffer from payload file */
        if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
            if(gzeof(pattr.gzf)) {
                break;
            }
            atomic_dec(&core_cnt);
            ERR("Failure in hfautils_parse_payload\n");
            goto pattr_cleanup;
        }
        payload = pattr.payload;
        cpsize = pattr.psize;
        DBG("payload %p cpsize = %u\n", payload, cpsize);
    
        hfautils_listforeachsafe(gnode, gnode_next, &nctx_glist){
            pnode = hfautils_listentry (gnode, hfa_searchnode_t, glist);
                
            if((hfautils_trylock(&pnode->lock))) {
                /* submit if no other search pending on context */ 
                if(pnode->status == FREE_TO_SUBMIT) {
                    submit(pnode, payload, cpsize);
                    /* Create a list for submitted contexts */
                    HFA_OS_LISTHEAD_INIT(&pnode->slist);
                    
                    /*Add node to submitted list to check status later*/
                    hfautils_lock(&subctx_glist.lock);
                    hfautils_listadd(&pnode->slist, &subctx_glist);
                    hfautils_unlock(&subctx_glist.lock);
                }
                hfautils_unlock(&pnode->lock);
            }  
            /* Poll once for all submitted searches */
            hfautils_listforeachsafe(snode, snode_next, &subctx_glist){
                pnode = hfautils_listentry (snode, hfa_searchnode_t, slist);
                 
                if(hfautils_trylock(&pnode->lock)) {
                    if(pnode->status == SUBMITTED) {
                        hfa_searchctx_get_searchstatus(&pnode->ctx,
                                       &pnode->sparam, &status);
                        if(HFA_SEARCH_SEAGAIN == status){
                            hfautils_unlock(&pnode->lock);
                            continue;
                        }
                        pnode->status = PROCESSED;
                       
                        /*Remove node from submitted list*/
                        hfautils_lock(&subctx_glist.lock);
                        hfautils_listdel(&pnode->slist);
                        hfautils_unlock(&subctx_glist.lock);
                        post_process(pnode, &nmatches);
                    }
                    hfautils_unlock(&pnode->lock);
                }
            }
        }
        /* poll for pending search instructions in HW, 
         * blocked till instruction completes*/
        poll(&nmatches);
        
        atomic_dec(&core_cnt);
        /* Loop till all cores comes here */ 
        while(atomic_read(&core_cnt)){
        }
        /* Change status of all contexts to submit next packet */ 
        hfautils_listforeachsafe(gnode, gnode_next, &nctx_glist){
            pnode = hfautils_listentry (gnode, hfa_searchnode_t, glist);
            if((hfautils_trylock(&pnode->lock))) {
                pnode->status = FREE_TO_SUBMIT;
                hfautils_unlock(&pnode->lock);
            }
        }
        /* Cleanup allocated memory for payload buffer */
        hfautils_memoryfree(pattr.payload, pattr.psize, 
                            (hfa_searchctx_t *)NULL);
        atomic_inc(&core_cnt);
    }
    LOG("total matches %lu\n", nmatches);
pattr_cleanup:
    hfautils_cleanup_payload_attributes(&pattr, &options);

    return HFA_SUCCESS;
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
    module_put(THIS_MODULE);
    
    return 0;
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
    
    /*Initialize a list maintaining submitted ctx/sparam*/
    HFA_OS_LISTHEAD_INIT(&subctx_glist); 
    hfautils_lockinit(&subctx_glist.lock);
    
    for(i=0; i< nctx; i++){
        /*Allocate node*/
        if(NULL == (pnode = hfautils_memoryalloc(sizeof(hfa_searchnode_t), 8,  
                                                (hfa_searchctx_t *)NULL))){
            ERR("Failure in allocating search node\n");
            goto snode_cleanup;
        }
        memset(pnode, 0, sizeof(hfa_searchnode_t));

        HFA_OS_LISTHEAD_INIT(&pnode->glist);
        /*initialise search context object */
        if(HFA_SUCCESS != hfa_dev_searchctx_init (&hfa_dev, &pnode->ctx)){
            ERR("SearchCtx Init Failure\n");
            goto snode_cleanup;
        }
        /*bind graph to the context */
        if(HFA_SUCCESS != hfa_searchctx_setgraph(&pnode->ctx, &gstruct)){
            ERR("Searchctx_setgraph Failure\n");
            goto snode_cleanup;
        }
        if(NULL == (pnode->rptr = hfautils_memoryalloc(rsize, 128, 
                                            (hfa_searchctx_t *)NULL))){
            ERR("Rptr allocation failure\n");
            goto snode_cleanup;
        }
        /*set flags for search*/
        hfa_searchctx_setflags (&pnode->ctx, pfflags);

        hfautils_lockinit(&pnode->lock);
        /*Add node to list and process search later*/
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

    /* load graph to cache, if it is a cacheable graph */
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
    int                         ncores = 0;

    /* Validate cluster */
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
    if(pcap){
        ERR("PCAP file not supported\n");
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
    if(nctx < ncores){
        ERR("nctx should be >= number of cores processing\n");
        return HFA_FAILURE;
    } 
    atomic_set(&core_cnt, ncores);
    if(HFA_SUCCESS != hfautils_read_file(graph, 
                &graph_data, gsize, &read_off, HFA_TRUE)){
        ERR ("Error in reading graph\n");
        return HFA_FAILURE;
    }
    read_off = 0;
    /* Tasklet has the limitation to open a file(filp_open()), So
     * read total payload(compressed or uncompressed) to a buffer.
     * Then each tasklet will get the data of requested size from 
     * that buffer. */
    if(HFA_SUCCESS != hfautils_read_payload(payload, &payload_data, 
                                             &read_off, &t_attr)) {
        ERR("Error in reading payload\n");
        goto gfree;
    }
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    
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
    /* Initialize a global list to track nctxts */
    if(HFA_SUCCESS != initialize_ctx_glist()) {
        ERR("Failure in intialize_ctx_glist\n");   
        stage = GRAPH_INIT;
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
            stage = CTX_INIT;
            goto m_cleanup;
        } 
        cwd = d_path(&pwd,buf,100*sizeof(char));
    }
    /*launch threads and tasklets */ 
    if(HFA_SUCCESS != hfautils_launch_thread_and_tasklet(thread_callback, 
                             tasklet_callback, &cmsk_attr, cwd)){
        ERR("launching threads and tasklets failed\n"); 
        stage = CTX_INIT;
        goto m_cleanup;
    }
    return (0);

m_cleanup:
    cleanup(stage);
    return -1;
}

void exit (void)
{
    int         stage = CTX_INIT;
     
    /*Kill all tasklets */
    hfautils_kill_tasklets(&cmsk_attr);
    cleanup(stage);
    LOG("hfa-lnx-nctx-lock app removed successfully\n");
}

module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
