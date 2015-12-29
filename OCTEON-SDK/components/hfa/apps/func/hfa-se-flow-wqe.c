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
 * operation using wqe mode response-status-check
 *
 * A local flow(per core) database is used to track packet traffic per flow. 
 * During initialization flow database is created to support number of flows 
 * (provided as an argument). However flows are created at run time whenever 
 * first packet is received for that flow. 
 * When the packet arrive, the flow is looked-up based on the flowid (tag-value) 
 * and the packet is queued to the flow. Each core receives (and queue) the 
 * packet depends on the WQE group of a packet and submits packet for the flow to 
 * HFA Engine for scan. The same core will later get the completion response 
 * through HW WQE then the core post processes the search and submits next packet 
 * of same flow. Subsequents packets on the same flow will be pending-submission
 * till an earlier packet's HFA walk operation is completed. The core which owns the 
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
 * - FSAVEBUF - Not Supported
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
CVMX_SHARED int                         init_success = 0;
CVMX_SHARED uint64_t                    paramsz=0, rptrsz =0;
CVMX_SHARED                             volatile int STOP=1;

/*Per core variables*/
hfaf_flowdb_t                           flowdb;
uint64_t                                coregrp = 0;
uint32_t                                flows_percore=0;
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
    SUCCESS 
}error_stage_t;

void process_packets(void);

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
static inline hfa_return_t 
freeparam(void *hwwqe, int t)
{
    hfa_wqe_pktdata_overload_t  *wqe_pktdata = NULL;
    hfaf_sparam_t    *param = NULL;
    cvmx_wqe_t       *wqe = (cvmx_wqe_t *)hwwqe;

    if(hfautils_likely(wqe)){
        wqe_pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data;
        param = (hfaf_sparam_t *)wqe_pktdata->unused0;
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
        cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
#ifdef __linux__
/** 
 * Receive pending HW WQE's from the SSO and frees them when 
 * application receives CTRL-C.
 */
static inline void 
cleanup_pendwqe()
{
    cvmx_wqe_t                  *wqe = NULL;
    hfa_searchctx_t             *psctx = NULL;
    hfa_searchparams_t          *psparam = NULL;

    while(HFAUTILS_FAU_FETCH(stats.pend_wqe, 0ULL)){
        wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
        if(!hfautils_read_iqcomcnt())
            break;
        if(wqe == NULL)
            continue; 
        switch(hfa_get_wqe_type(wqe)) {
            case HFA_SEARCH_HWWQE:
                hfa_searchctx_processwork(wqe, &psctx, &psparam);
                freeparam(wqe, 0);
                HFAUTILS_FAU_DEC(stats, pend_wqe);
                break;
            default:
                break;
        }
    }
}
#endif
/**
 * Allocate and set parameters for search 
 */
hfa_return_t
get_fparam(hfaf_sparam_t **ppfparam, cvmx_wqe_t *pktwqe, hfaf_flow_t *pflow)
{
    hfaf_sparam_t   *param = NULL;
    void            *rptr = NULL;
    cvmx_wqe_t      *wqe = NULL;
    hfa_wqe_pktdata_overload_t  *wqe_pktdata = NULL;

    if(hfautils_likely(ppfparam && pktwqe)){
        param = cvmx_fpa_alloc(HFAF_SPARAM_FPA_POOL);
        rptr = cvmx_fpa_alloc(HFAF_RPTR_FPA_POOL);
        wqe = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
        if(param && rptr && wqe){
            memset(param, 0, sizeof(hfaf_sparam_t));
            memset(wqe, 0, CVMX_FPA_WQE_POOL_SIZE);

            HFA_OS_LISTHEAD_INIT(&param->list);
            hfautils_rwlockinit(&param->lock);
            param->pktwqe = pktwqe;
            param->hwwqe = wqe;
            param->cb = freeparam;
            param->cba = param;
            
            cvmx_wqe_set_grp(wqe, cvmx_get_core_num());
            cvmx_wqe_set_qos(wqe, 4);
            wqe_pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data;
            wqe_pktdata->unused0 = (uint64_t)param;
            wqe_pktdata->unused1 = (uint64_t)pflow;

            hfa_searchparam_set_matchcb(&param->sparam, hfautils_matchcb,&stats);
            (param->input).ptr = cvmx_phys_to_ptr((pktwqe->packet_ptr).s.addr);
            (param->input).len = cvmx_wqe_get_len(pktwqe);

            hfa_searchparam_set_inputiovec(&param->sparam,
                                           &param->input, 1);
            hfa_searchparam_set_output(&param->sparam, 
                      rptr, HFAF_RPTR_FPA_POOL_SIZE);

            (param->sparam).wqe = wqe;
            (param->sparam).clusterno = options.cluster;
            
            *ppfparam = param;
            
            return HFA_SUCCESS;
        }
        else {
            if(rptr){
                cvmx_fpa_free(rptr, HFAF_RPTR_FPA_POOL,0);
            }
            if(param){
                cvmx_fpa_free(param, HFAF_SPARAM_FPA_POOL, 0);
            }
            if(wqe) {
                cvmx_fpa_free(param, CVMX_FPA_WQE_POOL, 0);
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
 * Configure qos priority for each core. Setting higher priority
 * for HFA response wqe(qos 4) from HW than packet wqe. 
 */
static inline void 
qos_config(void) 
{
  cvmx_sso_ppx_qos_pri_t    qos_config;
  
  qos_config.u64 = cvmx_read_csr(CVMX_SSO_PPX_QOS_PRI(cvmx_get_core_num())); 
  qos_config.s.qos0_pri = 0x1;
  qos_config.s.qos1_pri = 0x1;
  qos_config.s.qos2_pri = 0x1;
  qos_config.s.qos3_pri = 0x1;
  qos_config.s.qos4_pri = 0x0;
  qos_config.s.qos5_pri = 0x1;
  qos_config.s.qos6_pri = 0x1;
  qos_config.s.qos7_pri = 0x1;
  cvmx_write_csr(CVMX_SSO_PPX_QOS_PRI(cvmx_get_core_num()), qos_config.u64); 
  
  return;
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
 * Process command line options, read graph 
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

    /*Parse argument*/
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return HFA_FAILURE;
    }
    if(!options.networkpayload) {
        ERR("This application works in network mode only\n");
        return HFA_FAILURE;
    }
    /*Validate Npkts and Flow count*/
    if(!(options.nflows)){
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
 * Each core process packets as follows
 *
 * Addition:
 * - Get WQE -> Fetch flowid from WQE tag -> If flowid is not created, create 
 *   at runtime -> Create search parameter -> Add search parameter to flow.
 *
 * Submission:
 * -> After adding search parameter to flow, core tries to submit a search 
 *  on same flow if no pending search on that flow otherwise it will submit 
 *  after getting completion response of previous search.
 * 
 * Process flow:
 * -> Process when core receives search completion response through HW WQE.
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
    if(init_success) { 
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
                        (1ULL << (wqegrp))|(1ULL << (ncores+wqegrp)));
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
        /* Configure qos priority for each core */
        qos_config();
        
        /*Process Packets*/
        process_packets();
#ifdef __linux__
        cleanup_pendwqe();
#endif
        
        stage = FLOWDB_INIT;
        retval = HFA_SUCCESS;
    }else {
        retval = HFA_FAILURE;
    }
    DBG("Exiting\n");
  
m_cleanup:
    switch(stage) { 
        case FLOWDB_INIT:
            cvmx_pow_set_group_mask(cvmx_get_core_num(), coregrp);
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
                HFAUTILS_FAU_INC(stats, pend_wqe);
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
 * Receive network packets and process
 */
void process_packets()
{
    hfaf_flow_t         *pflow = NULL;
    hfaf_sparam_t       *pfparam = NULL;
    cvmx_wqe_t          *wqe = NULL;
    uint32_t            tag=0; 
    uint64_t            flowid;
    hfaf_paramstatus_t  fstatus;
    hfa_searchctx_t     *psctx = NULL;
    hfa_searchparams_t  *psparam = NULL;
    uint64_t            *pmatches = NULL;
    hfa_wqe_pktdata_overload_t  *wqe_pktdata = NULL;

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
        switch(hfa_get_wqe_type(wqe)) {
            /* WQE is a search instruction response */
            case HFA_SEARCH_HWWQE:
                wqe_pktdata = (hfa_wqe_pktdata_overload_t *)wqe->packet_data;

                pflow = (hfaf_flow_t *)wqe_pktdata->unused1;

                (pflow->submitted)--;
                HFAUTILS_FAU_DEC(stats, pend_wqe);

                if(hfautils_likely(HFA_SUCCESS != 
                    hfa_searchctx_processwork(wqe, &psctx, &psparam))){
                    HFAUTILS_FAU_INC(stats, pdfail);
                    continue;
                } else {
                    if(hfautils_likely(HFA_SUCCESS != 
                        hfa_searchctx_getmatches(psctx, psparam, &pmatches))){
                        freeparam(wqe, 0);
                        HFAUTILS_FAU_INC(stats, pdfail);
                    } else {
                        HFAUTILS_FAU_INC(stats, pdsuccess);
                        freeparam(wqe, 1);
                    }
                    if(pflow->added)
                        __submitflow(pflow, pflow->flowid, &fstatus);
                }
                break;
            /* WQE is a packet wqe */
            case PACKET_WQE: 
                pflow = NULL;

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
                    dbgprintf("ERR: pflowid->flowid: %u, flowid: %u\n", 
                              pflow->flowid, flowid);
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
                if(HFA_SUCCESS != get_fparam(&pfparam, wqe, pflow)){
                    HFAUTILS_FAU_INC(stats, dropped);
                    send(wqe);
                    goto submit;
                }
                /*Add packet to the flow. If add failure then 
                 * continue to while loop*/
                if(HFA_SUCCESS != hfaf_addsparam(pflow, pfparam)){
                    dbgprintf("Add Failure %u\n", pflow->flowid);
                    HFAUTILS_FAU_INC(stats, adfail);
                    freeparam(pfparam->hwwqe, HFA_FALSE);
                } else {
                    if(HFAF_PARAM_ADDED != pfparam->status){
                        dbgprintf("Add Failure. Status: 0x%x\n", 
                                                pfparam->status);
                        HFAUTILS_FAU_INC(stats, adretry);
                        freeparam(pfparam->hwwqe, HFA_FALSE);
                    } else {
                        HFAUTILS_FAU_INC(stats, adsuccess);
                    }
                }
submit:
                /* Try to submit just received flow */
                if(pflow->submitted == 0) {
                    __submitflow(pflow, flowid, &fstatus);
                }
                break;
            default:
                break;
        }
    }
}
