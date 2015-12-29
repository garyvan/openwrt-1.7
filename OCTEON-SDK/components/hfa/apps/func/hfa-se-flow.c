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
 * Reference application to showcase HFA usage in flow-based scenario. Flow (or
 * stateful context) is computed on the basis of received packet WQE tag.
 * Packet having same tag belongs to one flow hence to one core. This
 * applications works in network mode only. It uses asynchronous mode of
 * operation using poll-mode response-status-check
 *
 * A local flow(per core) database is used to track packet traffic per flow. 
 * During initialization flow database is created to support number of flows 
 * (provided as an argument). However flows are created at run time whenever 
 * first packet is received for that flow. 
 * When the packet arrive, the flow is looked-up based on the flowid (tag-value) 
 * and the packet is queued to the flow. Each core receives (and queue) the 
 * packet depends on the WQE group of a packet and submits packet for the flow to 
 * HFA Engine for scan. The same core will later do polling for the completion 
 * of HFA Walk instruction. Subsequents packets on the same flow will be 
 * pending-submission till an earlier packet's HFA walk operation is completed.
 * The response status is checked using a regular poll. The core which owns the 
 * flow(and hence the search ctx) will submited the queued packets one-at-a-time 
 * to HFA engine. The application, therefore, does not need locks to protect 
 * the searchctx.
 *
 * The following lists the operational aspects of this application.
 * - Multicore - YES
 * - Type of API
 *       - Asynchronous OO API(cacheload and search)
 *       - Synchronous OO API(memload)
 * - Cluster resources - Managed by HFA API.
 * - Clusters shared among cores - YES
 * - Graph count - 1 (loaded by first core)
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - private to each core.
 * - Locks used by app - NONE
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - Perform search on cluster which is free to submit.
 * - Buffer Payload  - Not Supported
 * - PCAP Payload    - Not supported
 * - Network traffic - Supported. Each flow is owned by single core. Packets 
 *                     having same tag belong to one flow hence to single core. 
 *                     Ingress traffic should have multiple flows/tag value 
 *                     for better result
 * - Cross Packet Search - Disabled
 * - FSAVEBUF  - Not Supported
 *                    
 */
#include <cvm-hfa.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-search.h>
#include <pcap.h>
#include <flow.h>
#include <app-utils.h>

#ifdef APP_DEBUG
#define dbgprintf printf("[%d]: ", __LINE__); printf
#define _dbgprintf printf
#else
#define dbgprintf(...);
#define _dbgprintf(...);
#endif
#define RCU_COUNT                       5
#define POLL_FLOW                       254
#define SUBMIT_FLOW                     255
#define RBUFSIZE                        8192
/* Specifies which of the least-significant bits(6Bits) of
 * the work-queue entry Tag field to exclude from the 
 * computation.
 */
#define HFAF_TAG_MASK                   0x3F

#define HFAF_SPARAM_FPA_POOL            6
#define HFAF_SPARAM_FPA_POOL_CNT        60000
#define HFAF_SPARAM_FPA_POOL_SIZE       paramsz
        
#define HFAF_RPTR_FPA_POOL              7
#define HFAF_RPTR_FPA_POOL_CNT          60000
#define HFAF_RPTR_FPA_POOL_SIZE         rptrsz

#define POOLCNT                         (OCTEON_IBUFPOOL_COUNT*2)   

/*Shared variables*/
CVMX_SHARED options_t                   options;
CVMX_SHARED hfa_dev_t                   dev;
CVMX_SHARED hfa_graph_t                 graph;
CVMX_SHARED hfautils_fau_perfcntrs_t    stats;
CVMX_SHARED void                        *graph_data = NULL;
CVMX_SHARED uint32_t                    maxflows=0;
CVMX_SHARED uint32_t                    ncores=0, rem = 0, wqegrp_bits = 0;
CVMX_SHARED uint32_t                    flowspercore=0;
CVMX_SHARED hfautils_rwlock_t           lock;
extern CVMX_SHARED cvmx_fau_reg_64_t    faubase;
CVMX_SHARED cvmx_fau_reg_64_t           addcache_refill;
CVMX_SHARED cvmx_fau_reg_64_t           submitcache_refill;
CVMX_SHARED int                         init_success = 0;
CVMX_SHARED uint64_t                    paramsz=0, rptrsz =0;
CVMX_SHARED                             volatile int STOP=1;

/*Per core variables*/
hfaf_flowdb_t                           flowdb;
uint64_t                                coregrp = 0;
uint32_t                                flows_percore=0;
/*Probable flows that can be submitted on local core*/
hfautils_rcu_t                          added_cache;
/*Probable flows that can be processed on local core*/
hfautils_rcu_t                          submitted_cache;
uint64_t                                wqe_pool_cnt = 0, ibuf_pool_cnt = 0;


typedef struct {
    cvmx_wqe_t      *wqe;
    hfaf_sparam_t   *psparam;
}freecb_arg_t;

typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    FLOWDB_INIT = 4,
    RCU_INIT  = 5, 
    SUCCESS 
}error_stage_t;

void process_packets(void);
hfa_return_t refill_submitted_flow(int);
hfa_return_t refill_added_flow(int);

/**
 * Signal handler to handle CTRL-C (SIGINT).
 */
#ifdef __linux__
void sigint_handler(int sig) {
    if (cvmx_is_init_core ()) {
        STOP=0;
        HFAUTILS_FAU_WR (stats, tot_bytes, 0ULL);
        cvmx_helper_setup_red (ibuf_pool_cnt, ibuf_pool_cnt+8); 
        printf("\n\tCTRL-C detected \n");
        printf("\tProgram Exiting in a few moments...\n");
    }
}
#endif
/* Cleanup will be done by this routine */
static inline void 
cleanup(int stage) 
{
    switch(stage) {
        case GRAPH_INIT:
            if(!HFA_GET_GRAPHATTR(&graph, memonly)){
                hfa_graph_cacheunload (&graph);
            }
            hfa_dev_graph_cleanup(&dev, &graph);
        case DEV_INIT:
            hfa_dev_cleanup (&dev);      
        case OPTIONS_INIT:
            cvmx_helper_setup_red(256, 128);
            cvmx_helper_shutdown_packet_io_global();
            hfautils_memoryfree(graph_data, options.graphsize, 
                                    (hfa_searchctx_t *)NULL);
        default:
            hfautils_reset_octeon();
            break;
    }
}
/**
 * Free wqe to the WQE fpa pool
 */
static inline void 
freewqe (cvmx_wqe_t *wqe)
{
    dbgprintf(".\n");
    if(wqe){
        cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
    }
}
/**
 * Free packet buffer and wqe to the corresponding fpa pools
 */
void send (cvmx_wqe_t *wqe)
{
    dbgprintf(".\n");
    if(wqe){
        cvmx_helper_free_packet_data(wqe);
        cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
    }
}
/**
 * Cleanup memory allocated for search parameters
 */
hfa_return_t
freeparam(void *cba, int t)
{
    hfaf_sparam_t    *param = NULL;
    if(cba){
        param = (hfaf_sparam_t *)cba;
        if(NULL == param){
            ERR("Null param found\n");
            return HFA_FAILURE;
        }
        if(t){
            HFAUTILS_FAU_INCBY(stats, tot_bytes, 
                 cvmx_wqe_get_len(param->pktwqe));
            HFAUTILS_FAU_INC(stats, out);
        } else {
            HFAUTILS_FAU_INC(stats, dropped);
        }
        send(param->pktwqe);
        if((param->sparam).output.ptr){
            cvmx_fpa_free((param->sparam).output.ptr, HFAF_RPTR_FPA_POOL, 0); 
        }
        cvmx_fpa_free(param, HFAF_SPARAM_FPA_POOL, 0); 
        return HFA_SUCCESS;
    } else {
        LOG("Null cba in freeparam\n");
    }
    return HFA_FAILURE;
}
/**
 * Allocate and set parameters for search 
 */
hfa_return_t
get_fparam(hfaf_sparam_t **ppfparam, cvmx_wqe_t *pktwqe)
{
    hfaf_sparam_t   *param = NULL;
    void            *rptr = NULL;

    if(hfautils_likely(ppfparam && pktwqe)){
        param = cvmx_fpa_alloc(HFAF_SPARAM_FPA_POOL);
        rptr = cvmx_fpa_alloc(HFAF_RPTR_FPA_POOL);
        if(param && rptr){
            memset(param, 0, sizeof(hfaf_sparam_t));
            memset(rptr, 0, HFAF_RPTR_FPA_POOL_SIZE);
            memset(&param->input, 0, sizeof(hfa_iovec_t));

            HFA_OS_LISTHEAD_INIT(&param->list);
            hfautils_rwlockinit(&param->lock);
            param->pktwqe = pktwqe;
            param->cb = freeparam;
            param->cba = param;
            *ppfparam = param;

            hfa_searchparam_set_matchcb(&param->sparam, hfautils_matchcb,&stats);
            (param->input).ptr = cvmx_phys_to_ptr((pktwqe->packet_ptr).s.addr);
            (param->input).len = cvmx_wqe_get_len(pktwqe);

            hfa_searchparam_set_inputiovec(&param->sparam,
                                           &param->input, 1);
            hfa_searchparam_set_output(&param->sparam, 
                      rptr, HFAF_RPTR_FPA_POOL_SIZE);
            return HFA_SUCCESS;
        }
        else {
            if(rptr){
                cvmx_fpa_free(rptr, HFAF_RPTR_FPA_POOL, 0);
            }
            if(param){
                cvmx_fpa_free(param, HFAF_SPARAM_FPA_POOL, 0);
            }
        }
    }
    return HFA_FAILURE;
}
/**
 * Load graph to HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    /*Initialise graph*/
    hfa_dev_graph_init(&dev, &graph);

    /*Set cluster mask*/
    if(HFA_SUCCESS != hfa_graph_setcluster(&graph, options.graph_clmsk)){
        ERR("Failure returned from hfa_graph_setcluster\n");
        return HFA_FAILURE;
    }
    /*Download Graph*/
    if(HFA_SUCCESS != hfautils_download_graph(&graph, graph_data,
                options.graphsize, GRAPHCHUNK, 0)){
        ERR("Failure in downloading the graph\n");
        return HFA_FAILURE;
    }
    /*Cacheload Graph*/
    if(!HFA_GET_GRAPHATTR(&graph, memonly)){
        if(HFA_SUCCESS != hfa_graph_cacheload(&graph)){
            ERR("Failure in Graph Cache Load\n");
            hfa_dev_graph_cleanup(&dev, &graph);
            return HFA_FAILURE;
        }
    }
    return HFA_SUCCESS;
}
/**
 * Initialize the interfaces to receive network traffic.
 */
static inline void
init_interfaces(void) 
{
    hfa_prt_cfg_t       prt_cfg;
    int                 active_cores = 0, cnt = 0, wqegrps = 0;
    uint8_t             tagmask = 0, tagmask_msb = 0, tagmask_lsb = 0;

    /*In case of 68xx we need more FPA pools to hit the max performance
    */
    if((OCTEON_HFA_ISCHIP(OCTEON_HFA_CN68XX_CID))){
        hfa_set_fpapools_cnt(60000, POOLCNT, 60000);
        wqe_pool_cnt = POOLCNT; 
        ibuf_pool_cnt = POOLCNT; 
    } else {
        wqe_pool_cnt = OCTEON_IBUFPOOL_COUNT; 
        ibuf_pool_cnt = OCTEON_IBUFPOOL_COUNT; 
    }
    /*Initialize FPA_WQE_POOL */
    hfautils_initialize_wqepool(ibuf_pool_cnt, wqe_pool_cnt);

    /* Configure PIP_PRT_TAG register to compute the work-queue entry 
     * group from tag bits. 
     */
    memset(&prt_cfg, 0, sizeof(hfa_prt_cfg_t));
   
    /* Computing how many bits need to be used for wqe group 
     * calculation from tag bits depending on the active 
     * cores. For example 
     * 2 cores - 1 bit from tag bits.
     * 3 cores - 2 bits
     * 4 cores - 2 bits
     * 8 cores - 3 bits ..
     */   
    active_cores = ncores;

    for(cnt=0; active_cores; active_cores >>= 1) {
        cnt++;
    }
    /*If power of 2 then reduce one bit*/
    if(!((ncores) & (ncores-1))) {
        cnt--;
    }
    /* Computing GRPTAGMASK MSB(2 bits) and LSB(4bits) depending on 
     * the active cores.
     * GRPTAGMASK specifies which of the least-significant bits of
     * the work-queue entry Tag field to exclude from the computation.
     */ 
    tagmask = HFAF_TAG_MASK << cnt;
    tagmask_msb = (tagmask >> 4) & 0x0F;
    tagmask_msb = tagmask_msb & 0x3;
    tagmask_lsb = tagmask & 0x0F;
    /* If grptag is 1. Enables the use of the least-significant
     * bits of the work-queue entry Tag field to determine the 
     * work-queue entry group.
     * 
     * wqe group = (WORD2[Tag<5:0>] AND ~(GRPTAGMASK)) + GRPTAGBASE
     *
     */
    prt_cfg.grptag = 1;
    /* least significant 4 bits of the GRPTAGMASK */
    prt_cfg.tagmask_lsb = tagmask_lsb;
    /* most significant 2 bits of the GRPTAGMASK */
    prt_cfg.tagmask_msb = tagmask_msb;
    
    /*Initialize interfaces */
    hfautils_initinterfaces(&prt_cfg);
   
    /* Calculating number of wqe groups will be generated from the 
     * tag bits depending on the PIP configuration.
     * If the wqe groups are more than number of cores, some cores will 
     * recieve work from multiple wqe groups. 
     */
    wqegrps = (~((tagmask_msb << 4) | tagmask_lsb)) & HFAF_TAG_MASK;
    wqegrps += 1;
    rem = wqegrps % ncores;  
    wqegrp_bits = cnt;
    
}

/** 
 * Process command line options and read graph 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    hfautils_options_init(&options); 

    ncores = hfautils_get_number_of_cores();

    /*options.nflows is per core so calculate actual flows depending upon
     * how many cores are active*/
    options.nflows = HFA_NBITS;

    /*Set cluster to invalid one*/
    options.pfflags = HFA_SEARCHCTX_FNOCROSS | HFA_SEARCHCTX_FSINGLEMATCH;
    /*Assert network option only*/
    options.networkpayload=1;
    /* Enable any cluster search */ 
    options.cluster = -1;

    /*Parse arguments*/
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return HFA_FAILURE;
    }
    if(!options.networkpayload) {
        ERR("This application works in network mode only\n");
        return HFA_FAILURE;
    }
    /*Validate Npkts and Flow count*/
    if(!(options.nflows)) {
        ERR("Invalid value: Nflows: %lu\n", options.nflows)
        return HFA_FAILURE;
    }
    if(options.nflows > 128) {
        LOG("WARNING: nflows > 128 (max limit) setting it to defualt nflows\n");
        options.nflows = HFA_NBITS; 
    }
    /*Read Graph file*/
    if(HFA_SUCCESS != hfautils_read_file(options.graph, &graph_data, 
                options.graphsize)){
        ERR("failure in reading graph: %s\n", options.graph);
        return HFA_FAILURE;
    }
    maxflows = options.nflows * ncores;
    /*Maxflows should be in multiples of 64*/
    if(!(maxflows/(ncores * HFA_NBITS))){
        maxflows = HFA_NBITS * ncores;
    }
    HFA_ALIGNED(maxflows, HFA_NBITS);
    printf("MAXFLOWS: %u\n", maxflows);

    paramsz = sizeof(hfaf_sparam_t);
    rptrsz = RBUFSIZE;
    HFA_ALIGNED(paramsz, 128);
    HFA_ALIGNED(rptrsz, 128);

    return HFA_SUCCESS;
}
/**
 * Implementation 
 *
 * All flows are divided among cores. A flow database is maintained for 
 * each core.
 *
 * Each core also maintains a (software cache) list of recently used flows or 
 * rcu_cache. 
 *
 * Each core process packets as follows
 *
 * Addition:
 * - Get WQE -> Fetch flowid from WQE tag -> If flowid is not created, create 
 *   at runtime -> Create search parameter -> Add search parameter to flow.
 *
 * Submission:
 * -> Loop over cached flow ptrs and tries to submit only one search parameter 
 *  of an owned flows ->If RCU is Empty, Refill cache and during refilling try
 *  to submit only one search parameter.
 * 
 * Process flow:
 * -> Loop over cached flow ptrs and tries to process only one search parameter 
 *  of an owned flows ->If RCU is Empty, Refill cache and during refilling try
 *  to process only one search parameter. If processed, post process the search 
 *  and send(wqe)
 *
 */
int  
main(int argc, char **argv)
{
    int                 msk=0;
    int                 stage = -1, wqegrp = 0;
    int                 retval = HFA_FAILURE;

    cvmx_user_app_init ();
    if (cvmx_is_init_core ()) {
        
        /* Process command line options, read graph */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto error;
        }
        /* Initialize the interfaces to receive network traffic. */
        init_interfaces();

        /*Initialise HFA device*/
        if(HFA_SUCCESS != hfa_dev_init(&dev)){
            ERR("Dev Init Failed\n");
            stage = OPTIONS_INIT;
            goto error; 
        }
        /* Initialize graph object and load graph */
        if(HFA_SUCCESS != graph_load()) {
            ERR("Failure in graph_load\n");
            stage = DEV_INIT;
            goto error;
        }
        if (hfa_create_fpa_pool(HFAF_SPARAM_FPA_POOL, "SParam Nodes", 
                   HFAF_SPARAM_FPA_POOL_SIZE, HFAF_SPARAM_FPA_POOL_CNT, &msk)){ 
            hfa_err(CVM_HFA_ENOMEM, ("Unable to create search Param FPA\n"));
            stage = GRAPH_INIT;
            goto error;
        }
        if (hfa_create_fpa_pool(HFAF_RPTR_FPA_POOL, "Result buffers", 
                       HFAF_RPTR_FPA_POOL_SIZE, HFAF_RPTR_FPA_POOL_CNT, &msk)){ 
            hfa_err(CVM_HFA_ENOMEM, ("Unable to create search Param FPA\n"));
            stage = GRAPH_INIT;
            goto error;
        }

        hfautils_init_perf_cntrs(&stats);
        
        addcache_refill = faubase;
        faubase += 8;
        submitcache_refill = faubase;
        faubase += 8;

        if(!(ncores -1)){
            /*Single core Execution*/
            flowspercore = maxflows;
        } else {
            flowspercore = maxflows/ncores;
            if(!flowspercore){
                flowspercore =1;
            }
            HFA_ALIGNED(flowspercore, HFA_NBITS);
        }
        hfautils_rwlockinit(&lock);
        init_success = 1;
    }
error:
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);

#ifdef __linux__
    signal(SIGINT, sigint_handler);
#endif               
    if(init_success){ 
        /*Flow database Init*/
        flows_percore = flowspercore;
        memset(&flowdb, 0, sizeof(hfaf_flowdb_t));
        flowdb.wqegrp_bits = wqegrp_bits;
        if(HFA_SUCCESS != hfaf_flowdb_init(&dev, &flowdb, &flows_percore)){
            ERR("Failure in creating flows\n");
            stage = GRAPH_INIT;
            goto m_cleanup;
        }
        LOG("Resultant Total Flows: %u\n", flows_percore);

        if(HFA_SUCCESS != hfautils_rcu_init(&added_cache, RCU_COUNT)){
            ERR("Failure from rcu_init\n");
            stage = FLOWDB_INIT;
            goto m_cleanup; 
        }
        if(HFA_SUCCESS != hfautils_rcu_init(&submitted_cache, RCU_COUNT)){
            ERR("Failure from rcu_init\n");
            stage = RCU_INIT;
            goto m_cleanup;
        }
        coregrp = (unsigned long int)
                  hfautils_get_core_grpmsk(cvmx_get_core_num()); 
        
        /* Set core group mask depending on the wqe groups generated
         * from the tag bits(tagmask).*/
        if(rem) {
            /* If wqe groups are more than number of cores, some cores will
             * recieve work from multiple wqe groups.
             */
            if (cvmx_is_init_core ()) {
                for(wqegrp = 0; wqegrp < rem; wqegrp++) {
                    cvmx_pow_set_group_mask(wqegrp, 
                        (1ULL<<(wqegrp))|(1ULL<<(ncores+wqegrp)));
                }
                for(; wqegrp < ncores; wqegrp++)
                    cvmx_pow_set_group_mask(wqegrp, 1ULL << wqegrp);
            }
        }
        else { 
            /* If wqe groups are equal to number of cores, one core recieves 
             * work from only one wqe group.
             */
            cvmx_pow_set_group_mask(cvmx_get_core_num(),
                                    1ULL << cvmx_get_core_num());
        }
        cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
        
        /*Process Packets*/
        process_packets();
        
        stage = SUCCESS;
        retval = HFA_SUCCESS;
    }else {
        retval = HFA_FAILURE;
    }
    DBG("Exiting\n");
  
m_cleanup:
    switch(stage) { 
        case SUCCESS :
            cvmx_pow_set_group_mask(cvmx_get_core_num(), coregrp);
            hfautils_rcu_cleanup(&submitted_cache);   
        case RCU_INIT:
            hfautils_rcu_cleanup(&added_cache);   
        case FLOWDB_INIT:
            hfaf_flowdb_cleanup(&flowdb);
            stage = GRAPH_INIT;
        default: 
            break;
    }
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if(cvmx_is_init_core())
        cleanup(stage);
    
    return retval;
}
/**
 * Submits a packet of a flow to the HFA Engine if no pending instruction 
 * on that flow 
 */
static inline hfa_return_t
__submitflow(hfaf_flow_t *pflow, flowid_t flowid, hfaf_paramstatus_t *status)
{
    dbgprintf("Submitting to flow: %p", pflow);
    if(HFA_SUCCESS != hfaf_submit_pktflow(pflow, status)){
        _dbgprintf("..Failed");
        HFAUTILS_FAU_INC(stats, sdfail);
        return HFA_FAILURE;
    } else {
        switch(*status){
            case HFAF_PARAM_SUBMITTED:
                _dbgprintf("..Submitted");
                HFAUTILS_FAU_INC(stats, sdsuccess);
            break;

            default:
                _dbgprintf("..Retry");
                HFAUTILS_FAU_INC(stats, sdretry);
            break;
        }
    }
    return HFA_SUCCESS;
}
/**
 * Polls for a submitted search instruction of a flow
 */
static inline hfa_return_t
__processflow(hfaf_flow_t *pflow, flowid_t flowid, hfaf_paramstatus_t *status)
{
    dbgprintf("Polling to flow: %p", pflow);
    
    if(HFA_SUCCESS != hfaf_process_pktflow(pflow, status)){
        _dbgprintf("..Failure");
        HFAUTILS_FAU_INC(stats, pdfail);
        return HFA_FAILURE;
    } else {
        switch((*status)){
            case HFAF_PARAM_PROCESSED:
                _dbgprintf("..Processed");
                HFAUTILS_FAU_INC(stats, pdsuccess);
            break;
    
            case HFAF_PARAM_SUBMITTED:
                _dbgprintf("..Submit");
                HFAUTILS_FAU_INC(stats, pdsuccess);
                HFAUTILS_FAU_INC(stats, sdsuccess);
            break;

            default:  
                _dbgprintf("..Retry");
                HFAUTILS_FAU_INC(stats, pdretry);
            break;
        }
        return HFA_SUCCESS;
    }
}
/**
 * Get flow pointer from Flow database,
 * If flow ptr is NULL then create at runtime
 */
hfa_return_t
get_flowptr(flowid_t flowid, hfaf_flow_t **pp)
{
    dbgprintf("Flowid: %u\n", flowid);

    if(HFA_SUCCESS != hfaf_isflow_exist(&flowdb, flowid, pp)){
        dbgprintf("\n");
        ERR("isflow_exist failure\n:");
        return HFA_FAILURE;
    }

    if(hfautils_likely(*pp)){
        dbgprintf("Flowptr for flowid (%u): %p\n", flowid, *pp);
    } else {
        dbgprintf("Creating flow for id: %u\n", flowid);
        if(HFA_SUCCESS != hfaf_create_pktflow(&flowdb, flowid, &graph, 
                                              NULL, options.pfflags)){
            ERR("Failure from hfaf_create_pktflow flowid: %u\n", flowid);
            return HFA_FAILURE;
        }
        hfaf_isflow_exist(&flowdb, flowid, pp);
        LOG("Flow created pflow: %p(%u)\n", *pp, (*pp)->flowid);
    }
    return HFA_SUCCESS;
}
/**
 * Iterate over flowdb and found flow which is free to submit.
 */
hfa_return_t
refill_cache(int refill_budget)
{
    hfaf_flow_t           *pflow = NULL;
    long int              idx;
    hfaf_flowdb_node_t    *pdbnode = NULL;
    hfaf_flowid_ptr_map_t *pmap = NULL;
    hfa_os_listhead_t     *p1 = NULL, *p2 = NULL;

    for(idx = 0; idx < flowdb.maxflows; idx++) { 
        pdbnode = (hfaf_flowdb_node_t *)&((flowdb.pnodes)[idx]);
        hfa_os_listforeachsafe(p1, p2, &pdbnode->list){
            pmap = hfa_os_listentry(p1, hfaf_flowid_ptr_map_t, list);
            pflow = pmap->pflow;
            if(hfautils_likely(pflow)) {
                if(pflow->added) {
                    if(added_cache.nonzerocnt >= added_cache.count){
                        break;
                    }
                    hfautils_rcu_setatnull(&added_cache, pflow);
                }
                if(pflow->submitted) {
                    if(submitted_cache.nonzerocnt >= submitted_cache.count){
                        break;
                    }
                    hfautils_rcu_setatnull(&submitted_cache, pflow);
                }
            }
        }
    }
    return HFA_SUCCESS;
}
/**
 * Submitting or Polling flows from the software recently used cache
 * IF Cache is empty, it tries to refill it
 *
 * @param       pc      Recently Cache used structure
 * @param       cmd     Whether to submit or poll
 * @param       budget  Max flows that can be submitted/processed
 * @param       *pcnt   Pointer to how many flows are actually submitted
 *                      or processed by the API
 *
 * @return      HFA_SUCCESS/HFA_FAILURE                     
 *
 */
static inline hfa_return_t
do_cache (hfautils_rcu_t *pc, int cmd, int budget, int *pcnt)
{
    uint32_t            cnt;
    hfaf_flow_t         *pflow=NULL;
    hfaf_paramstatus_t  fstatus;

    if(pc && pcnt && budget > 0){
        *pcnt=0;
        /*If addded cache is empty perform refilling*/
        if((!pc->nonzerocnt) && (cmd == SUBMIT_FLOW)){
            refill_cache(pc->count);
            dbgprintf("Refilling Add Cache, nfills: %u\n", pc->nonzerocnt);
            cvmx_fau_atomic_add64(addcache_refill, pc->nonzerocnt);
        }
        /*If submitted cache is empty perform refilling*/
        if((!pc->nonzerocnt) && (cmd == POLL_FLOW)){
            refill_cache(pc->count);
            dbgprintf("Refilling Submit Cache, nfills: %u\n", pc->nonzerocnt);
            cvmx_fau_atomic_add64(submitcache_refill, pc->nonzerocnt);
        }
        /*Submit or Poll 'budget' number of flow from cache*/
        for(cnt=0; ((cnt< pc->count) && ((*pcnt)< budget)); cnt++){
            pflow = NULL;
            hfautils_rcu_get(pc, cnt, (uint64_t **)&pflow);
            if(NULL == pflow){
                continue;
            }
            dbgprintf("Cache Entry: %d. Flowid: %u\n", cnt, pflow->flowid);
            switch (cmd){
                case SUBMIT_FLOW:
                    dbgprintf("Submitting");
                    if(HFA_SUCCESS ==__submitflow(pflow, pflow->flowid, &fstatus)) {
                        /*Add this flow at empty location of submitted cache*/
                        switch(fstatus){
                            case HFAF_PARAM_SUBMITTED:
                                hfautils_rcu_setatnull(&submitted_cache, pflow);
                                (*pcnt)++; 
                                /*Remove this flow from added cache to add later*/
                                hfautils_rcu_set(pc, 0, cnt);
                            default:
                                dbgprintf("ERR invalid fstatus\n");
                                break;
                        }
                    }
                    break;

                case POLL_FLOW:
                    /*Poll flow*/
                    if(HFA_SUCCESS == 
                            __processflow(pflow, pflow->flowid, &fstatus)){
                        switch(fstatus){
                            case HFAF_PARAM_SUBMITTED:
                                /*If processed + submitted then do remove
                                 * from submit_cache to poll later, By then
                                 * cache other flows*/
                                (*pcnt)++; 
                                /*Remove this flow from poll cache*/
                                dbgprintf("Removed frm submit rcu\n");
                                hfautils_rcu_set(&submitted_cache, 0, cnt);
                                break;
                            case HFAF_PARAM_PROCESSED:
                                /*If only processed then remove from
                                 * submitted_cache*/
                                (*pcnt)++; 
                                /*Remove this flow from poll cache*/
                                dbgprintf("Removed frm submit rcu\n");
                                hfautils_rcu_set(&submitted_cache, 0, cnt);
                                break;

                            default:
                                dbgprintf("ERR invalid fstatus\n");
                                break;
                        }
                    }
                    break;

                default:
                    ERR("INvalid command %u Found\n", cmd);
                    break;
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/** 
 * Receive network packets and process
 */
void process_packets()
{
    hfaf_flow_t         *pflow = NULL;
    hfaf_sparam_t       *pfparam = NULL;
    cvmx_wqe_t          *wqe = NULL;
    uint32_t            tag=0; 
    uint64_t            flowid;
    int                 flag, ncnt;
    hfaf_paramstatus_t  fstatus;

    cvmx_pow_work_request_null_rd();

    while(1) {
        if(!cvmx_get_core_num()){
            hfautils_printstats(&stats, 0, 0, options.verbose, NULL);
        }
#ifdef __linux__       
        if(!STOP){ 
            break;
        }
#endif        
        if(NULL == (wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT))){
            continue;
        }
        HFAUTILS_FAU_INC(stats, in);

        if(cvmx_wqe_get_len(wqe) < 14){
            HFAUTILS_FAU_INC(stats, dropped);
            freewqe(wqe);
            continue;
        }
        /*get WQE tag to determine the flow*/
        tag = cvmx_wqe_get_tag(wqe); 
        hfaf_get_flowidx(&flowdb, tag, &flowid);

        dbgprintf("Tag: -1x%x, Flowidx: 0x%x\n", tag, flowid);
        dbgprintf("wqe grp %d\n", cvmx_wqe_get_grp(wqe));

        /*Retrieve flow ptr from flowdb. If this tag arrives
         * first time then create pflow for it and add to flowdb*/
        if(HFA_SUCCESS != get_flowptr(flowid, &pflow)){
            HFAUTILS_FAU_INC(stats, dropped);
            send(wqe);
            goto submit;
        }
#ifdef HFA_STRICT_CHECK
        if(pflow->flowid != flowid){
            dbgprintf("ERR: pflowid->flowid: %u, flowid: %u\n", pflow->flowid,
                              flowid);
            send(wqe);
            goto submit;
        }
#endif                
        if(pflow->added >= HFAF_MAX_ALLOWED_PARAMS){
            HFAUTILS_FAU_INC(stats, dropped);
            send(wqe);
            goto submit;
        }
        /*Get search parameters*/
        if(HFA_SUCCESS != get_fparam(&pfparam, wqe)){
            HFAUTILS_FAU_INC(stats, dropped);
            send(wqe);
            goto submit;
        }
        (pfparam->sparam).clusterno= options.cluster; 
        
        /*Add packet to the flow. If add failure then continue to while loop*/
        if(HFA_SUCCESS != hfaf_addsparam(pflow, pfparam)){
            dbgprintf("Add Failure %u\n", pflow->flowid);
            HFAUTILS_FAU_INC(stats, adfail);
            freeparam((void *)pfparam, HFA_FALSE);
        } else {
            if(HFAF_PARAM_ADDED != pfparam->status){
                dbgprintf("Add Failure. Status: 0x%x\n", pfparam->status);
                HFAUTILS_FAU_INC(stats, adretry);
                freeparam((void *)pfparam, HFA_FALSE);
            } else {
                HFAUTILS_FAU_INC(stats, adsuccess);
            }
        }
submit:
        /*Try to submit just received flow otherwise try to submit one flow
         * from core added cache*/
        flag=1;
        if(HFA_SUCCESS == __submitflow(pflow, flowid, &fstatus)){
            flag=0;
        }
        if(flag){
            hfautils_rcu_setatnull(&added_cache, pflow);
            do_cache(&added_cache, SUBMIT_FLOW, 1, &ncnt); 
        } else {
            /*Try to add this flow in submitted cache*/
            hfautils_rcu_setatnull(&submitted_cache, pflow);
        }

        /*Once submitted try to poll from poll cache*/
        do_cache(&submitted_cache, POLL_FLOW, 1, &ncnt); 
    }
}
