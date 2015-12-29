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
 * Performance benchmarking application to illustrate HFA Engine performance.
 * It uses asynchronous mode of operation using poll mode. It does not report 
 * the pattern-matches found in the payload. Each core uses a single searchctx.
 * Once a packet is received, search parameter is created and submitted to HFA
 * engine on core's local searchctx. After search submission, parameter is 
 * added to the tail of searchctx param list. Each core then tries to poll 
 * search parameter at the head of searchctx param list. If the search 
 * corresponding to search paramater at head is completed, post processing is 
 * done and total matches are incremented. The application, therefore, does not
 * use any locks. This application supports searching of live network traffic.
 * The following lists the operational aspects of this application.
 * - Multicore - YES
 * - Type of API
 *       - Asynchronous OO API(search)
 *       - Synchronous OO API(memload and cacheload)
 * - Cluster resources - Managed by HFA API.
 * - Clusters shared among cores - YES
 * - Graph count - 1 (loaded by first core)
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - private to each core.
 * - Locks - NONE
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - The clusters are used in round-robin style by each
 *                         core.
 * - Buffer Payload - Supported. File is converted to local packets(WQE) and 
 *                    submitted to OCTEON SSO hardware. Incomig packets are 
 *                    received using cvmx_pow_get_work().
 * - Pcap Payload - Supported. Actual data from each packet in PCAP file is 
 *                  fetched and submitted locally as WQE to OCTEON SSO hardware. 
 *                  Incoming packets are received using cvmx_pow_get_work().
 * - Network traffic - Supported. Incoming packets from network interfaces are 
 *                     distributed among cores.
 * - Cross Packet Search - Disabled
 * - FSAVEBUF - Not Supported
 */
#include <cvm-hfa.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-search.h>
#include <pcap.h>
#include <app-utils.h>

#define RBUFSIZE                    2048
#define HFA_MAX_ALLOWED_PARAMS      10

#define HFA_SPARAM_FPA_POOL         7
#define HFA_SPARAM_FPA_POOL_SIZE    paramsz
        
#define HFA_RPTR_FPA_POOL           6
#define HFA_RPTR_FPA_POOL_SIZE      rptrsz

#define POOLCNT                     100000 

/*Application related structures*/
typedef hfa_return_t (*matchcb_t)(hfa_searchctx_t *, uint64_t *);
typedef hfa_return_t (*freecb_t)(void *, int);

typedef enum {
    WQE_DROP = 0,
    WQE_SUCCESS = 1,
    WQE_CLEANUP = 2
}wqe_status_t;

typedef enum {
    TRYAGAIN = 0,
    ADDED = 1,
    SUBMITTED =2,
    PROCESSED
}paramstatus_t;
typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    CTX_INIT = 3,
    PACKET_INIT = 4,
    SUCCESS
}error_stage_t;

/*Search Context*/
typedef struct {
    hfautils_lock_t         lock;
    hfautils_listhead_t     paramlist;
    hfa_searchctx_t         sctx;
    matchcb_t               matchcb;
    uint32_t                added;
    uint32_t                submitted;
}searchctx_t;

/*Search Parameters*/
typedef struct{
    hfautils_listhead_t     list;
    hfa_searchparams_t      sparam;
    paramstatus_t           status;
    cvmx_wqe_t              *pktwqe;
    void                    *rptr;
    hfa_iovec_t             input;
    freecb_t                cb;
    void                    *cba;
}searchparam_t;

/*Global and static variables*/
CVMX_SHARED hfa_dev_t                   hfa_dev;
CVMX_SHARED hfa_graph_t                 graph;
CVMX_SHARED hfautils_fau_perfcntrs_t    stats;
CVMX_SHARED void                        *graph_data=NULL;
CVMX_SHARED options_t                   options;
CVMX_SHARED uint64_t                    paramsz=0, rptrsz =0;
CVMX_SHARED uint32_t                    ncores = 0;
CVMX_SHARED uint32_t                    init_success=0;
CVMX_SHARED                             volatile int STOP=1;
uint64_t                                wqe_pool_cnt = 0, ibuf_pool_cnt = 0;
hfautils_payload_attr_t                 pattr;


/**One context per core*/
CVMX_SHARED searchctx_t                *gctx[32];

/**
 * Signal handler for CTRL+C(SIGINT) 
 */
#ifdef __linux__
void sigint_handler(int sig) {
    if (cvmx_is_init_core ()) {
        STOP=0;
        HFAUTILS_FAU_WR (stats, tot_bytes, 0ULL);
        if(options.networkpayload) 
            cvmx_helper_setup_red (ibuf_pool_cnt, ibuf_pool_cnt+8); 
        printf("\n\tCTRL-C detected \n");
        printf("\tProgram Exiting in a few moments...\n");
    }
}
static inline void 
cleanup_pendwqe(void)
{
    cvmx_wqe_t                  *wqe = NULL;

    if(!options.networkpayload){ 
        while(HFAUTILS_FAU_FETCH(stats.pend_wqe, 0ULL)){
            if(!hfautils_read_iqcomcnt())
                break;
            wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
            if(wqe == NULL)
                continue; 
            cvmx_helper_free_packet_data(wqe);
            cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
            HFAUTILS_FAU_DEC(stats, pend_wqe);
        }
    }
}
#endif
/**
 * Free Packet buffer and wqe to the corresponding fpa pools 
 */
static inline void 
freepktwqe(cvmx_wqe_t *wqe)
{
    if(hfautils_likely(wqe)){
        cvmx_helper_free_packet_data(wqe);
        cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
    }
}
static inline void 
send (cvmx_wqe_t *wqe)
{
    if(wqe){
#ifdef LOOPBACK
        hfautils_send_pkt(wqe);
#else                        
        freepktwqe(wqe);
#endif            
    }
}
/**
 * Resubmit WQE to HW
 */
static inline void 
resubmit(cvmx_wqe_t *wqe)
{
    if(hfautils_likely(wqe)){
        cvmx_pow_work_submit(wqe, cvmx_wqe_get_tag(wqe), cvmx_wqe_get_tt(wqe), 
                            cvmx_wqe_get_qos(wqe), cvmx_wqe_get_grp(wqe));
    }
}
/**
 * Send packet back or free packet data depending on wqe_status 
 */
static inline void 
sendpktwqe(cvmx_wqe_t *wqe, int wqe_status)
{
    if(options.networkpayload){
        switch(wqe_status) {
            case WQE_DROP:
                freepktwqe(wqe);
                HFAUTILS_FAU_INC(stats, dropped);
            break;
        
            case WQE_SUCCESS:
                HFAUTILS_FAU_INCBY(stats, tot_bytes, cvmx_wqe_get_len(wqe));
                send(wqe);
                HFAUTILS_FAU_INC(stats, out);
            break;
            
            case WQE_CLEANUP:
                send(wqe);
            break;
        
            default:
                /* Do nothing */
            break;
        }
    } else {
        switch(wqe_status) {
            case WQE_DROP:
                resubmit(wqe);
                HFAUTILS_FAU_INC(stats, dropped);
            break;
        
            case WQE_SUCCESS:
                HFAUTILS_FAU_INCBY(stats, tot_bytes, cvmx_wqe_get_len(wqe));
                HFAUTILS_FAU_INC(stats, out);
                resubmit(wqe);
            break;
        
            case WQE_CLEANUP:
                freepktwqe(wqe);
                HFAUTILS_FAU_DEC(stats, pend_wqe);
            break;

            default:
            break;
        }
    }
}
/**
 * Cleanup memory allocated for search parameters
 */
static inline hfa_return_t 
freeparam(void *cba, int wqe_status)
{
    searchparam_t   *param = (searchparam_t *)cba;

    if(hfautils_likely(param)){
        sendpktwqe((cvmx_wqe_t *)param->pktwqe, wqe_status);

        if(param->rptr){
            cvmx_fpa_free(param->rptr, HFA_RPTR_FPA_POOL, 0);
        }
        cvmx_fpa_free(param, HFA_SPARAM_FPA_POOL, 0);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Initialize search ctx 
 */
static inline hfa_return_t
createctx (searchctx_t **ppctx, uint64_t searchflags, matchcb_t cb)
{
    searchctx_t     *pctx = NULL;

    if(hfautils_likely(ppctx)){
        if(hfautils_unlikely(NULL == (pctx = 
            hfautils_memoryalloc(sizeof(searchctx_t), 8, 
                                 (hfa_searchctx_t *)NULL)))){
            ERR(" Failure in allocating pctx\n");
            return HFA_FAILURE;
        }
        memset(pctx, 0, sizeof(searchctx_t));
        hfautils_lockinit(&pctx->lock);
        HFA_OS_LISTHEAD_INIT(&pctx->paramlist);
        if(HFA_SUCCESS != hfa_dev_searchctx_init(&hfa_dev, &pctx->sctx)){
            ERR("error from searchctx_init\n");
            goto free_ctx;
        }
        if(HFA_SUCCESS != hfa_searchctx_setgraph(&pctx->sctx, &graph)){
            ERR("setgraph failure\n");
            goto free_ctx;
        }
        hfa_searchctx_setflags(&pctx->sctx, searchflags);
        *ppctx = pctx;

        return HFA_SUCCESS;
free_ctx:
        hfautils_memoryfree(pctx, sizeof(searchctx_t), (hfa_searchctx_t *)NULL);
    }
    return HFA_FAILURE;
}
/**
 * Counter part of createctx()
 */
static inline hfa_return_t
destroyctx(searchctx_t *pctx)
{
    hfautils_listhead_t *p1 = NULL, *p2 = NULL;
    searchparam_t       *param = NULL;
    uint32_t            searchstatus = 0;

    if(hfautils_likely(pctx)){
        hfautils_listforeachsafe(p1, p2, &pctx->paramlist){
            param = hfautils_listentry(p1, searchparam_t, list);
            
            /*remove from the list*/
            hfautils_listdel(&param->list);
            
            /*Free param list. If parameters are submitted 
             * poll for them first and then free*/
            switch(param->status){
                case ADDED:
                case TRYAGAIN:
                case PROCESSED:
                    freeparam(param, WQE_CLEANUP);
                break;

                case SUBMITTED:
                    searchstatus = HFA_SEARCH_SEAGAIN;
                    do{
                        hfa_searchctx_get_searchstatus(&pctx->sctx, 
                                      &param->sparam, &searchstatus);
                    }while(searchstatus == HFA_SEARCH_SEAGAIN);
                    freeparam(param, WQE_CLEANUP);
                break;

                default:
                    /*Do Nothing*/
                break;
            }
        }
        hfa_dev_searchctx_cleanup(&hfa_dev, &pctx->sctx);
        hfautils_lockdestroy(&pctx->sctx);
        hfautils_memoryfree(pctx, sizeof(searchctx_t), (hfa_searchctx_t *)NULL);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Add search param to the paramlist to process search later 
 */
static inline hfa_return_t
addsearchparam(searchctx_t *pctx,searchparam_t *psparam,freecb_t cb,void *cba){

    if(hfautils_unlikely((NULL == psparam) || (NULL == pctx))){
        LOG("pctx: %p, pspram: %p\n", pctx, psparam);
        return HFA_FAILURE;
    }
    psparam->status = TRYAGAIN;
    
    if(pctx->added >= HFA_MAX_ALLOWED_PARAMS){
        return HFA_FAILURE;
    }
    hfautils_listaddtail(&psparam->list, &pctx->paramlist);
    (pctx->added) += 1;
    psparam->status = ADDED;
    psparam->cb = cb;
    psparam->cba = cba;

    return HFA_SUCCESS;
}
/**
 * Submit search instruction to the HW by parsing through the paramlist 
 */
static inline hfa_return_t
submit(searchctx_t *pctx, paramstatus_t *pstatus)
{
    hfautils_listhead_t     *p1 = NULL, *p2 = NULL;
    searchparam_t           *psparam = NULL;

    if(hfautils_likely(pctx && pstatus)){
        *pstatus = TRYAGAIN;
        if(pctx->added){
            hfautils_listforeachsafe(p1, p2, &pctx->paramlist){
                psparam = hfautils_listentry(p1, searchparam_t, list);
            
                switch(psparam->status){
                    case ADDED:
                        /*Submit the ctx*/
                        if(HFA_SUCCESS==hfa_searchctx_search_async(&pctx->sctx,
                                         &psparam->sparam)){
                            HFAUTILS_FAU_INC(stats, sdsuccess); 
                            psparam->status = SUBMITTED;
                            (pctx->added)--;
                            (pctx->submitted)++;
                            return HFA_SUCCESS;
                        } else {
                            HFAUTILS_FAU_INC(stats, sdfail);
                        }
                    break;

                    default:
                    break;
                }
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Polls once for all submitted searches.If a search is completed 
 * the result is processed
 */
static inline hfa_return_t
poll_searchctx(searchctx_t *pctx, paramstatus_t *pstatus)
{
    hfautils_listhead_t     *p1 = NULL, *p2 = NULL;
    uint64_t                *pmatch = NULL;           
    hfa_reason_t            reason=0;
    searchparam_t           *psparam = NULL;
    hfa_searchstatus_t      status = HFA_SEARCH_SEAGAIN;

    if(hfautils_likely(pctx && pstatus)){
        *pstatus = TRYAGAIN;

        hfautils_listforeachsafe(p1, p2, &pctx->paramlist){
            psparam = hfautils_listentry(p1, searchparam_t, list);
        
            switch(psparam->status){
                case SUBMITTED:
                    if(HFA_SUCCESS == 
                        hfa_searchctx_get_searchstatus(&pctx->sctx,
                                               &psparam->sparam, &status)){
                        if(HFA_SEARCH_SEAGAIN == status){
                            continue;
                        }
                        *pstatus = PROCESSED;

                        /*Remove param from paramlist*/
                        hfautils_listdel(&psparam->list);

                        /*Update flow counters*/
                        (pctx->submitted)--;

                        /*Get HW reason and matches*/
                        hfa_searchparam_get_hwsearch_reason(&psparam->sparam,
                                                        &reason);
                        DBG("reason: %u\n", reason);
                        if(reason){
                            HFAUTILS_FAU_INC(stats, sdretry);
                            /*Call free cb*/
                            if(psparam->cb){
                                psparam->cb(psparam->cba, WQE_DROP);
                            }
                        } else {
                            DBG("Getting matches\n");
                            pmatch = NULL;
                            hfa_searchctx_getmatches(&pctx->sctx, 
                                                     &psparam->sparam, &pmatch);
                            /*Call matchcb*/
                            if(pctx->matchcb && pmatch){
                                pctx->matchcb(&pctx->sctx, pmatch);
                            }
                            if(psparam->cb){
                                psparam->cb(psparam->cba, WQE_SUCCESS);
                            }
                        }
                        return HFA_SUCCESS;
                    }
                break;

                default:
                /*Do Nothing*/
                break;
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Allocate and set parameters for search 
 */
static inline hfa_return_t
get_sparam(searchparam_t **pparam, cvmx_wqe_t *pktwqe)
{
    searchparam_t                *param = NULL;
    void                         *rptr = NULL;

    if(hfautils_likely(pparam && pktwqe)){
        *pparam = NULL;
        param = cvmx_fpa_alloc(HFA_SPARAM_FPA_POOL);
        rptr = cvmx_fpa_alloc(HFA_RPTR_FPA_POOL);

        if(param && rptr){
            memset(param, 0, HFA_SPARAM_FPA_POOL_SIZE);

            HFA_OS_LISTHEAD_INIT(&param->list);
            param->pktwqe = pktwqe;
            param->cb = freeparam;
            param->cba = param;
            param->rptr = rptr;

            hfa_searchparam_set_matchcb(&param->sparam,hfautils_matchcb,&stats);
            /*Create Iovec*/
            (param->input).ptr = 
                    cvmx_phys_to_ptr((pktwqe->packet_ptr).s.addr);

            (param->input).len = cvmx_wqe_get_len(pktwqe);
            
            /*Initialize Sparam*/
            hfa_searchparam_set_inputiovec(&param->sparam, &param->input, 1);
            hfa_searchparam_set_output(&param->sparam, rptr, 
                                       HFA_RPTR_FPA_POOL_SIZE);
            (param->sparam).clusterno = options.cluster;
            *pparam = param;
            return HFA_SUCCESS;
        } else {
            if(rptr){
                cvmx_fpa_free(rptr, HFA_RPTR_FPA_POOL,0);
            }
            if(param){
                cvmx_fpa_free(param, HFA_SPARAM_FPA_POOL,0);
            }
        }
    }
    return HFA_FAILURE;
}
/**
 * poll for all submitted searches.
 */
static inline hfa_return_t
poll(searchctx_t *pctx)
{
    paramstatus_t   status;

    if(hfautils_likely(pctx)){
        if(pctx->submitted){
            /*Try to poll local ctx*/
            if(HFA_SUCCESS != poll_searchctx(pctx, &status)){
                HFAUTILS_FAU_INC(stats, pdfail);
            } else {
                switch(status){
                    case PROCESSED:
                        HFAUTILS_FAU_INC(stats, pdsuccess);
                    break;

                    default:
                        HFAUTILS_FAU_INC(stats, pdretry);
                    break;
                }
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/** 
 * Process search on recieved packet wqe 
 */
static inline void
process_wqe(cvmx_wqe_t *wqe, searchctx_t *pctx)
{
    searchparam_t       *param = NULL;
    paramstatus_t       status;
    int                 addflag;
    
    HFAUTILS_FAU_INC(stats, in);
    
    if(cvmx_wqe_get_len(wqe) < 14){
        sendpktwqe(wqe, WQE_DROP);
    }
    addflag = HFA_FALSE;
    /*Get search parameters*/
    if(HFA_SUCCESS != get_sparam(&param, wqe)){
        sendpktwqe(wqe, WQE_DROP);
    } else { 
        if(HFA_SUCCESS !=addsearchparam(pctx, param, freeparam, param)){
            HFAUTILS_FAU_INC(stats, adfail);
            freeparam((void *)param, WQE_DROP);
        } else {
            if(ADDED != param->status){
                HFAUTILS_FAU_INC(stats, adretry);
                freeparam((void *)param, WQE_DROP);
            } else {
                HFAUTILS_FAU_INC(stats, adsuccess);
                addflag = HFA_TRUE;
            }
        }
    }
    if(addflag){
        /*Submit the ctx*/
        if(HFA_SUCCESS==hfa_searchctx_search_async(&pctx->sctx,
                    &param->sparam)){
            HFAUTILS_FAU_INC(stats, sdsuccess);
            param->status = SUBMITTED;
            (pctx->added)--;
            (pctx->submitted)++;
        } else {
            HFAUTILS_FAU_INC(stats, sdfail);
        }
        addflag = HFA_FALSE;
    } else {
        if(pctx->added){
            submit(pctx, &status);
        }
    }
    poll(pctx);
} 

/** 
 * Do asynchrounous get work operation then pre-fetch recieved wqe and 
 * process search on recieved packet wqe 
 */
void  
process_pkt()
{
    cvmx_wqe_t          *wqe = NULL, *prefetch_wqe = NULL;
    searchctx_t         *pctx = NULL;
     
    cvmx_pow_work_request_null_rd();
    pctx = gctx[cvmx_get_core_num()];

    cvmx_pow_work_request_async_nocheck(CVMX_SCR_SCRATCH, CVMX_POW_NO_WAIT);

    while(1){
        if(cvmx_is_init_core ()){
             hfautils_printstats(&stats, 0, 0, options.verbose, NULL);
        }
        prefetch_wqe = cvmx_pow_work_response_async(CVMX_SCR_SCRATCH);
        cvmx_pow_work_request_async_nocheck(CVMX_SCR_SCRATCH, CVMX_POW_NO_WAIT);
       
        if(prefetch_wqe){ 
           CVMX_PREFETCH(prefetch_wqe, 0);
        }
        if(wqe) {
            process_wqe(wqe, pctx);
        }
        wqe = prefetch_wqe;
        
#ifdef __linux__       
        if(!options.networkpayload) {
            if(!STOP){ 
                break;
            }
        }
#endif        
        if(wqe == NULL){
#ifdef __linux__       
            if(options.networkpayload) {
                if(!STOP){ 
                    break;
                }
            }
#endif        
            poll(pctx);
        } 
    }
}
/**
 * Cleanup will be done by this routine 
 */
static inline void 
cleanup(int stage) 
{
    switch(stage) {
        case SUCCESS:
        case PACKET_INIT:
            if(options.networkpayload){
                cvmx_helper_setup_red (256, 128); 
                cvmx_helper_shutdown_packet_io_global();
            }
            else {
                hfautils_cleanup_payload_attributes(&pattr, &options);
            }
        case CTX_INIT:
            if(!HFA_GET_GRAPHATTR(&graph, memonly)) {
                hfa_graph_cacheunload(&graph);
            }
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
        case DEV_INIT:
            hfa_dev_cleanup (&hfa_dev);        
        case OPTIONS_INIT:
            hfautils_memoryfree(graph_data, options.graphsize, 
                                     (hfa_searchctx_t *)NULL);
        default:
            hfautils_reset_octeon();
            break;
    }
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
    /* set the cluster on which this graph will be loaded*/
    if(HFA_SUCCESS != hfa_graph_setcluster (&graph, options.graph_clmsk)){
        ERR("Failure in hfa_graph_setcluster()\n");
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
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
            return HFA_FAILURE;
        }
    }
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;
}
/** 
 * Process command line options,
 * Read graph 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    hfautils_options_init(&options);
    options.networkpayload = 1;
    options.cluster = -1;
    options.pfflags = HFA_SEARCHCTX_FNOCROSS | HFA_SEARCHCTX_FSINGLEMATCH;
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return HFA_FAILURE;
    }
    if(!options.npkts){
        /* Number of local packets per core */ 
        options.npkts = 100; 
    } 
    /* Read graph and payload */
    if(HFA_SUCCESS != hfautils_read_file(options.graph, 
                &graph_data, options.graphsize)){
        ERR ("Error in reading graph \n");
        return HFA_FAILURE;
    }
    ncores = hfautils_get_number_of_cores();
    
    paramsz = sizeof(searchparam_t);
    rptrsz = RBUFSIZE;
    HFA_ALIGNED(paramsz, 128);
    HFA_ALIGNED(rptrsz, 128);
    
    return HFA_SUCCESS;
}
int 
main(int argc, char **argv)
{
    int                     i, msk = 0;
    hfa_return_t            retval = HFA_FAILURE;
    int                     stage = -1; 

#ifdef __linux__
    signal(SIGINT, sigint_handler);
#endif      
    cvmx_user_app_init ();
    if (cvmx_is_init_core ()) {

        /* Process command line options, read graph */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto error;
        }
        /*In case of 68xx we need more FPA pools to hit the max performance
         */
        if((OCTEON_HFA_ISCHIP(OCTEON_HFA_CN68XX_CID)) && 
            options.networkpayload){
            hfa_set_fpapools_cnt(60000, POOLCNT, 60000);
            wqe_pool_cnt = POOLCNT; 
            ibuf_pool_cnt = POOLCNT; 
        } else {
            wqe_pool_cnt = OCTEON_IBUFPOOL_COUNT; 
            ibuf_pool_cnt = OCTEON_IBUFPOOL_COUNT; 
        }
        /*Initialize HFA device*/
        if(HFA_SUCCESS != hfa_dev_init(&hfa_dev)){
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
        hfautils_init_perf_cntrs(&stats);

        /*Initialize per core context*/
        for(i=0; i < ncores; i++){
            if(HFA_SUCCESS != createctx(&(gctx[i]), options.pfflags, NULL)){
                ERR("FlowCtx creation error : %d\n", i);
                stage = CTX_INIT;
                goto error; 
            }
        }
        hfautils_initialize_wqepool(ibuf_pool_cnt, wqe_pool_cnt);
        if(options.networkpayload){
            /*Initialize FPA_WQE_POOL */
            hfa_prt_cfg_t               prt_cfg;
            memset(&prt_cfg, 0, sizeof(hfa_prt_cfg_t));

            hfautils_initinterfaces(&prt_cfg);
        } else {
            /*Create local packets if networkpayload is disabled*/
            pktwqe_attr_t       attr;
        
            memset(&attr, 0, sizeof(pktwqe_attr_t)); 
            memset(&pattr, 0, sizeof(hfautils_payload_attr_t));

            /* Initialize attributes for parsing the payload file */
            if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
                ERR ("Failure in hfautils_init_payload_attributes\n");
                stage = CTX_INIT;
                goto error;
            }
            attr.npkts = options.npkts * ncores;
            attr.pattr = &pattr;
            
            if(HFA_SUCCESS != hfautils_create_localpkts (&attr, &options)){ 
                ERR("Failure in creating localpkts\n");
                stage = PACKET_INIT;
                goto error;
            }
        }
        /*Parameter and Result buffer cnt should be equal to number of WQE and 
         * Packet data pool*/

        if (hfa_create_fpa_pool(HFA_RPTR_FPA_POOL, "Result buffers", 
                    HFA_RPTR_FPA_POOL_SIZE, ibuf_pool_cnt, &msk)){ 
            ERR("Unable to create fpa pool for result buffers\n");
            stage = PACKET_INIT;
            goto error;
        }
        if (hfa_create_fpa_pool(HFA_SPARAM_FPA_POOL, "SPARAM Nodes", 
                    HFA_SPARAM_FPA_POOL_SIZE, ibuf_pool_cnt, &msk)){ 
            ERR("Unable to create fap pool for search param\n");
            stage = PACKET_INIT;
            goto error;
        }
        HFAUTILS_FAU_WR(stats, pend_wqe, options.npkts * ncores);
        init_success = 1;
    }
error:        
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if(init_success == 1){
        cvmx_helper_initialize_packet_io_local ();
        
        process_pkt();
     
        retval = HFA_SUCCESS;
        stage = SUCCESS;
    } else {
        retval = HFA_FAILURE;
    }
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if((CTX_INIT == stage) || (SUCCESS == stage)){
        destroyctx(gctx[cvmx_get_core_num()]);
        gctx[cvmx_get_core_num()]=0;
    }
    cvmx_coremask_barrier_sync(&cvmx_sysinfo_get()->core_mask);
    if (cvmx_is_init_core ()) { 
#ifdef __linux__
        cleanup_pendwqe(); 
#endif        
        cleanup(stage);
    }
    
    return retval;
}
