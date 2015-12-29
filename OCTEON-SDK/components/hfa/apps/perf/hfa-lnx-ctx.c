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
 * This requires the Cavium OCTEON Ethernet driver, which should be configured
 * to use 60000 buffers(using num_packet_buffers module parameter). The ingress
 * ethernet interface which receives the network traffic may need to be set to
 * promiscuous mode to ensure that the packets are picked up by the OCTEON
 * Ethernet driver.
 *
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
 *                    submitted to OCTEON SSO hardware with WQE grp @b
 *                    hfa_pow_receive_group (@ref octeon_hfa_sdk_kernel_module_op)
 *                    These packets are picked by HFA SDK kernel module and
 *                    passed on to the application via process_pkt() thus
 *                    emulating the network traffic.
 * - Pcap Payload - Supported. Actual data from each packet in PCAP file is 
 *                  fetched and submitted locally as WQE to OCTEON SSO hardware 
 *                  with WQE grp @b hfa_pow_receive_group (@ref octeon_hfa_sdk_kernel_module_op)
 *                  These packets are picked by HFA SDK kernel module and passed
 *                  on to the application via process_pkt() thus emulating the
 *                  network traffic.
 * - Network traffic - Supported. Incoming packets are received from OCTEON Ethernet driver
 * - Cross Packet Search - Disabled
 * - FSAVEBUF - Not Supported
 */
#include <cvm-hfa.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-search.h>
#include <pcap.h>
#include <app-utils.h>

#define HFA_APP_LIB             "hfa-kernel-ctx"
#define RBUFSIZE                2048
#define HFA_MAX_ALLOWED_PARAMS  10

/*Module parameters*/
MODULE_AUTHOR("cavium networks");

static char     *graph = "graph";
module_param (graph, charp, 0444);
MODULE_PARM_DESC (graph, "graph file");

static char     *payload = "payload";
module_param (payload, charp, 0444);
MODULE_PARM_DESC (payload, "payload file");

static unsigned int chunksize = 65535;
module_param (chunksize, uint, 0444);
MODULE_PARM_DESC (chunksize, "chunk size");

static unsigned int npkts= 200;
module_param (npkts, uint, 0444);
MODULE_PARM_DESC (npkts, "Number of pkts");

static int cluster= -1;
module_param (cluster, int, 0444);
MODULE_PARM_DESC (cluster, "cluster number used to run HFA search");

static unsigned int gclmsk= 0;
module_param (gclmsk, uint, 0444);
MODULE_PARM_DESC (gclmsk, "Cluster Bitmask on which graph is loaded");

static int  matchacross=0;
module_param (matchacross, int, 0444);
MODULE_PARM_DESC (matchacross, "flags to enable or disable cross pkt search");

static int  singlematch=1;
module_param (singlematch, int, 0444);
MODULE_PARM_DESC (singlematch, "flags to enable or disable singlematch");

unsigned int network=1;
module_param (network, uint, 0444);
MODULE_PARM_DESC (network, "If network payload used");

static char    *port[20] = {"xaui0","xaui1","xaui2","xaui3"};
static int     count = 0;
module_param_array (port, charp, &count, 0444);
MODULE_PARM_DESC (port, "Incomming ports for packets");

static int  pcap=0;
module_param (pcap, int, 0444);
MODULE_PARM_DESC (pcap, "payload file is pcap file");

unsigned int nctx=1;
module_param (nctx, uint, 0444);
MODULE_PARM_DESC (nctx, "number of searchctx");

static int      verbose = 0;
module_param (verbose, int, 0444);
MODULE_PARM_DESC (verbose, "verbose option to print matches");

#define HFA_SPARAM_FPA_POOL         6
#define HFA_SPARAM_FPA_POOL_SIZE    paramsz
        
#define HFA_RPTR_FPA_POOL           7
#define HFA_RPTR_FPA_POOL_SIZE      rptrsz

/**
 * OCTEON MBOX messaging variable
 */
static int                          ipi_handle_mesg;

/*Application related structures*/
typedef hfa_return_t (*matchcb_t)(hfa_searchctx_t *, uint64_t *);
typedef hfa_return_t (*freecb_t)(void *, int);

void  core_exit(void);
/*Ethernet driver IBUFPOOL configuration*/
extern int                          hfa_pow_receive_group;
extern int                          hfa_distribute_load;
extern int                          hfa_napi_perf;

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
static struct net_device *input_device[20] = {NULL};

CVMX_SHARED hfa_dev_t                   dev;
CVMX_SHARED hfa_graph_t                 _graph;
CVMX_SHARED hfautils_fau_perfcntrs_t    stats;
CVMX_SHARED void                        *gbuf = NULL;
CVMX_SHARED hfa_size_t                  gsize=0, psize=0;
CVMX_SHARED options_t                   options;
CVMX_SHARED uint64_t                    paramsz=0, rptrsz =0;
CVMX_SHARED uint32_t                    ncores, bufcnt;
hfautils_payload_attr_t                 pattr;
char                                    *buf = NULL;
#ifdef USE_TIMER_FOR_STATS    
static struct timer_list                printresult_timer;
#endif
int                                     clno=0;
/**One context per core*/
CVMX_SHARED searchctx_t                *gctx[NR_CPUS];
atomic_t                                exitflag = ATOMIC_INIT(0);

cvm_oct_callback_result_t 
process_pkt(struct net_device *, void *, struct sk_buff *);

static inline void 
freepktwqe(cvmx_wqe_t *wqe)
{
    if(hfautils_likely(wqe)){
        hfa_napi_free_work(wqe);
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
static inline void 
resubmit(cvmx_wqe_t *wqe)
{
    if(hfautils_likely(wqe)){
        cvmx_pow_work_submit(wqe, cvmx_wqe_get_tag(wqe), cvmx_wqe_get_tt(wqe), 
                            cvmx_wqe_get_qos(wqe), cvmx_wqe_get_grp(wqe));
    }
}
static inline void 
sendpktwqe(cvmx_wqe_t *wqe, int wqe_status)
{
    if(network){
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
            break;

            default:
            break;
        }
    }
}
static inline hfa_return_t 
freeparam(void *cba, int wqe_status)
{
    searchparam_t   *param = (searchparam_t *)cba;

    if(hfautils_likely(param)){
        sendpktwqe((cvmx_wqe_t *)param->pktwqe, wqe_status);

        if(param->rptr){
            cvmx_fpa_free(param->rptr, HFA_RPTR_FPA_POOL, 0);
            param->rptr =0;
        }
        cvmx_fpa_free(param, HFA_SPARAM_FPA_POOL, 0);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}

/*static inline functions*/
static inline hfa_return_t
createctx (searchctx_t **ppctx, uint64_t searchflags, matchcb_t cb)
{
    searchctx_t     *pctx = NULL;

    if(hfautils_likely(ppctx)){
        if(hfautils_unlikely(NULL == (pctx = 
            hfautils_memoryalloc(sizeof(searchctx_t), 8, 
                                 (hfa_searchctx_t *)NULL)))){
            ERR("Memory allocation failed for pctx\n");
            return HFA_FAILURE;
        }
        memset(pctx, 0, sizeof(searchctx_t));
        hfautils_lockinit(&pctx->lock);
        HFA_OS_LISTHEAD_INIT(&pctx->paramlist);
        if(HFA_SUCCESS != hfa_dev_searchctx_init(&dev, &pctx->sctx)){
            ERR("error from searchctx_init\n");
            goto free_ctx;
        }
        if(HFA_SUCCESS != hfa_searchctx_setgraph(&pctx->sctx, &_graph)){
            ERR("setgraph failure\n");
            goto free_ctx;
        }
        hfa_searchctx_setflags(&pctx->sctx, searchflags);
        *ppctx = pctx;

        return HFA_SUCCESS;
free_ctx:
        hfautils_memoryfree(pctx, sizeof(searchctx_t),(hfa_searchctx_t *)NULL);
    }
    return HFA_FAILURE;
}
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
                    searchstatus = HFA_SEARCH_SDONE;
                    do{
                        hfa_searchctx_get_searchstatus(&pctx->sctx, 
                                          &param->sparam, &searchstatus);
                    }while(HFA_SEARCH_SEAGAIN == searchstatus);
                    freeparam(param, WQE_CLEANUP);
                break;

                default:
                    /*Do Nothing*/
                break;
            }
        }
        hfa_dev_searchctx_cleanup(&dev, &pctx->sctx);
        hfautils_lockdestroy(&pctx->sctx);
        hfautils_memoryfree(pctx, sizeof(searchctx_t), (hfa_searchctx_t *)NULL);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
static inline hfa_return_t
addsearchparam(searchctx_t *pctx,searchparam_t *psparam,freecb_t cb,void *cba){

    if(hfautils_unlikely((NULL == psparam) || (NULL == pctx))){
        DBG("pctx: %p, pspram: %p\n", pctx, psparam);
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
static inline hfa_return_t
poll_searchctx(searchctx_t *pctx, paramstatus_t *pstatus)
{
    hfautils_listhead_t     *p1 = NULL, *p2 = NULL;
    uint64_t                *pmatch = NULL;           
    hfa_reason_t            reason=0;
    searchparam_t           *psparam = NULL;
    hfa_searchstatus_t      status;

    if(hfautils_likely(pctx && pstatus)){
        *pstatus = TRYAGAIN;

        hfautils_listforeachsafe(p1, p2, &pctx->paramlist){
            psparam = hfautils_listentry(p1, searchparam_t, list);

            switch(psparam->status){
                case SUBMITTED:
                    status = HFA_SEARCH_SDONE;
                    if(HFA_SUCCESS == hfa_searchctx_get_searchstatus(&pctx->sctx,
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
                            /*Call free cb*/
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
static inline void 
printstats(unsigned long temp)
{
#ifdef USE_TIMER_FOR_STATS    
    del_timer(&printresult_timer);
    hfautils_printstats(&stats, 0, 0, 0, NULL);    
    add_timer(&printresult_timer);
#endif    
}

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
            (param->sparam).clusterno = cluster;
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
cvm_oct_callback_result_t 
process_pkt(struct net_device *dev, void *work, struct sk_buff *skb)
{
    searchparam_t       *param = NULL;
    cvmx_wqe_t          *wqe = (cvmx_wqe_t *) work;
    searchctx_t         *pctx = NULL;
    paramstatus_t       status= TRYAGAIN;
    int                 addflag;

    HFAUTILS_FAU_INC(stats, in);
    pctx = gctx[cvmx_get_core_num()];

    if(cvmx_wqe_get_len(wqe) < 14){
        HFAUTILS_FAU_INC(stats, dropped);
        return CVM_OCT_DROP;
    }
    addflag = HFA_FALSE;
    /*Get search parameters*/
    if(HFA_SUCCESS != get_sparam(&param, wqe)){
        sendpktwqe(wqe, WQE_DROP);
    } else { 
        if(HFA_SUCCESS != addsearchparam(pctx, param, freeparam, param)){
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
        if(HFA_SUCCESS == hfa_searchctx_search_async(&pctx->sctx,
                    &param->sparam)){
            HFAUTILS_FAU_INC(stats, sdsuccess);
            param->status = SUBMITTED;
            (pctx->added)--;
            (pctx->submitted)++;
        } else {
            HFAUTILS_FAU_INC(stats, sdfail);
        }
        addflag = HFA_FALSE;
    }else {
        if(pctx->added){
            submit(pctx, &status);
        }
    }
    poll(pctx);
    
    if(!cvmx_get_core_num()){
        hfautils_printstats(&stats, 0, 0, verbose, NULL); 
    }

    return CVM_OCT_TAKE_OWNERSHIP_WORK;
}
/** 
 * Process command line options,
 * Read graph and payload 
 */
static inline hfa_return_t 
process_options (void) 
{
    hfa_size_t              off=0;
    char                    *cwd = NULL;
    struct path             pwd, root;
    
    if(!(gclmsk) || gclmsk > hfa_get_max_clmsk()){
        gclmsk = hfa_get_max_clmsk();
    }
    if(!hfa_isethernetdrv_present()){
        ERR("Try after inserting OCTEON Ethernet driver\n");
        return HFA_FAILURE;
    }
    if(!network){
        if(!hfa_napi_perf || hfa_distribute_load){
            ERR("Reinsert HFA_LIB_MODULE with hfa_napi_perf=1 and "\
                "hfa_distribute_load=0\n" \
            "\t eg. insmod cvm-hfa-lib.ko hfa_distribute_load=0 hfa_napi_perf=1\n");
            return HFA_FAILURE;
        }
    }
    /*Request IPI handler for exiting of all cores */
    ipi_handle_mesg = octeon_request_ipi_handler(core_exit);
    if(ipi_handle_mesg < 0){
        panic("No IPI handler available\n");
    }
    hfautils_file_size(graph, &gsize);
    if(!network){
        hfautils_file_size(payload, &psize);
        if(HFA_SUCCESS != hfautils_validate_chunksize(&chunksize, psize)){
            return HFA_FAILURE;
        }
        options.payloadsize = psize;
        options.chunksize = chunksize;
        options.pcap = pcap;
        options.payload = payload;
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
                return HFA_FAILURE;
            } 
            cwd = d_path(&pwd, buf, 100 * sizeof(char));
            memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
            
            pattr.path = cwd;
            /* Initialize attributes for parsing the payload file */
            if(HFA_SUCCESS != 
                hfautils_init_payload_attributes (&pattr, &options)){
                ERR ("Failure in hfautils_init_payload_attributes\n");
                hfautils_memoryfree(buf, 100 * sizeof(char), 
                                        (hfa_searchctx_t *)NULL);
                return HFA_FAILURE;
            }
        }
    }
    /*Read Graph file*/
    if(HFA_SUCCESS != hfautils_read_file(graph, &gbuf, gsize, &off, HFA_TRUE)){
        ERR("failure in reading graph: %s\n", graph);
        goto pattr_cleanup;
    }
    ncores = hfautils_get_number_of_cores();
    
    paramsz = sizeof(searchparam_t);
    rptrsz = RBUFSIZE;
    HFA_ALIGNED(paramsz, 128);
    HFA_ALIGNED(rptrsz, 128);

    return HFA_SUCCESS;
pattr_cleanup:
    if(!network) {
        hfautils_cleanup_payload_attributes(&pattr, &options);
        hfautils_memoryfree(buf, 100 * sizeof(char), (hfa_searchctx_t *)NULL);
    }
    return HFA_FAILURE;
}

int 
entry(void)
{
    int                     i, msk;
    long unsigned int       sflags = HFA_SEARCHCTX_FNOCROSS | 
                                     HFA_SEARCHCTX_FSINGLEMATCH;
    
    /* Process command line options, read graph and payload */ 
    if(HFA_SUCCESS != process_options()) {
        ERR("failure in process_options\n");
        return HFA_FAILURE;
    }
    for_each_online_cpu(i){
        atomic_inc(&exitflag);
    }
    /*Initialize HFA device*/
    if(HFA_SUCCESS != hfa_dev_init((hfa_dev_t *)&dev)){
        ERR("Dev Init Failed\n");
        goto m_graph_free; 
    }
    /*Initialize graph*/
    hfa_dev_graph_init((hfa_dev_t *)&dev, &_graph);

    /*Set cluster mask*/
    if(HFA_SUCCESS != hfa_graph_setcluster(&_graph, gclmsk)){
        ERR("Failure returned from hfa_graph_setcluster\n");
        goto m_dev_cleanup;
    }
    /*Download Graph*/
    if(HFA_SUCCESS != hfautils_download_graph(&_graph, gbuf, gsize,
                                            GRAPHCHUNK, 0)){
        ERR("Failure in downloading the graph\n");
        goto m_dev_cleanup;
    }
    /*Cacheload Graph*/
    if(!HFA_GET_GRAPHATTR(&_graph, memonly)){
        if(HFA_SUCCESS != hfa_graph_cacheload(&_graph)){
            ERR("Failure in Graph Cache Load\n");
            goto m_graph_cleanup;
        }
    }
    /*Parameter and Result buffer cnt should be equal to number of WQE and 
     * Packet data pool setup by ethernet driver*/
    bufcnt = cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(OCTEON_IBUFPOOL));
    if (hfa_create_fpa_pool(HFA_SPARAM_FPA_POOL, "Search Param Nodes", 
               HFA_SPARAM_FPA_POOL_SIZE, bufcnt, &msk)){ 
        ERR("Unable to create search Param FPA\n");
        goto m_graph_cacheunload;
    }
     if (hfa_create_fpa_pool(HFA_RPTR_FPA_POOL, "Result buffers", 
                   HFA_RPTR_FPA_POOL_SIZE, bufcnt, &msk)){ 
        ERR("Unable to create Result buffers FPA\n");
        goto m_graph_cacheunload;
    }

    hfautils_init_perf_cntrs(&stats);
    
    /*Initialize per core searchctx*/

    if(matchacross){
         HFA_BITMSKCLR(sflags, HFA_SEARCHCTX_FNOCROSS);
    } else {
         HFA_BITMSKSET(sflags, HFA_SEARCHCTX_FNOCROSS);
    }
    if(singlematch){
       HFA_BITMSKSET(sflags, HFA_SEARCHCTX_FSINGLEMATCH);
    } else {
       HFA_BITMSKCLR(sflags, HFA_SEARCHCTX_FSINGLEMATCH);
    }
    LOG("Searchctx flags: 0x%lx\n", sflags);
    /*Initialize per core context*/
    for_each_online_cpu(i){
        if(HFA_SUCCESS != createctx(&(gctx[i]), sflags, NULL)){
            ERR("FlowCtx creation error : %d\n", i);
            goto m_destroy_ctx; 
        }
    }
    if(network){
        for(i=0; i<count; i++){
            input_device[i] = 
                cvm_oct_register_callback(port[i], process_pkt);
            if(NULL == input_device[i]){
                ERR("process pkt registration failed for port: %s\n", port[i]);
                goto m_deregister_reschedulecb;
            }
        }
    }
    else {
        /*Create local packets if network payload is disabled*/
        
        pktwqe_attr_t               attr;
        
        memset(&attr, 0, sizeof(pktwqe_attr_t)); 
        
        attr.npkts = npkts * ncores;
        attr.tt = CVMX_POW_TAG_TYPE_ORDERED;
        attr.grp = hfa_pow_receive_group;
        attr.pattr = &pattr;
        if(HFA_SUCCESS != hfa_register_packet_interceptcb(process_pkt)){
            ERR("Error in registering cb for Pkt WQE\n");
            goto m_deregister_reschedulecb;
        }
        if(HFA_SUCCESS != hfautils_create_localpkts (&attr, &options)){ 
            ERR("Failure in creating localpkts\n");
            goto m_deregister_pktcb;
        }
    }
#ifdef USE_TIMER_FOR_STATS    
    /*Insert timer*/
    init_timer(&printresult_timer);
    printresult_timer.function = printstats;
    printresult_timer.expires = jiffies;
    add_timer(&printresult_timer);
#endif    
    LOG("%s is inserted successfully\n", HFA_APP_LIB);
    if(network)
        LOG("Stats will be print once ethernet driver receives the packets\n");
    return 0;

m_deregister_pktcb:
    hfa_register_packet_interceptcb(NULL);
m_deregister_reschedulecb:
    if(network){
        for(i=0; i< count; i++){
            if(input_device[i]){
                cvm_oct_register_callback(port[i], NULL);
            }
        }
    }
m_destroy_ctx:
    for_each_online_cpu(i){
        destroyctx(gctx[i]);
        gctx[i]=0;
    }
m_graph_cacheunload:        
    if(!HFA_GET_GRAPHATTR(&_graph, memonly))
        hfa_graph_cacheunload(&_graph);
m_graph_cleanup:
    hfa_dev_graph_cleanup((hfa_dev_t *)&dev, &_graph);
m_dev_cleanup:
    hfa_dev_cleanup ((hfa_dev_t *)&dev);        
m_graph_free:
    hfautils_vmmemoryfree(gbuf, gsize, (hfa_searchctx_t *)NULL);
    if(!network) {
        hfautils_cleanup_payload_attributes(&pattr, &options);
        hfautils_memoryfree(buf, 100 * sizeof(char), (hfa_searchctx_t *)NULL);
    }
    return(-1);
}
void exit(void)
{
    int i;
   
    if(network){
        for(i=0; i< count; i++){
            if(input_device[i]){
                cvm_oct_register_callback(port[i], NULL);
            }
        }
    } else {
        hfautils_cleanup_payload_attributes(&pattr, &options);
        hfautils_memoryfree(buf, 100 * sizeof(char), (hfa_searchctx_t *)NULL);
    }
    hfa_register_packet_interceptcb(NULL);

#ifdef USE_TIMER_FOR_STATS    
    del_timer(&printresult_timer);
#endif  
    for_each_online_cpu(i){
        if(i == smp_processor_id()){
            core_exit();
        }else {
            octeon_send_ipi_single(i, ipi_handle_mesg);
        }
    }
    while(atomic_read(&exitflag)){
    }
    if(!HFA_GET_GRAPHATTR(&_graph, memonly)){
        hfa_graph_cacheunload (&_graph);
    }
    hfa_dev_graph_cleanup(&dev, &_graph);
    hfa_dev_cleanup (&dev);        
    hfautils_vmmemoryfree(gbuf, gsize, (hfa_searchctx_t *)NULL);
    LOG("%s is exited successfully\n", HFA_APP_LIB);
}
void core_exit(void)
{
    searchctx_t     *pctx = NULL;
   
    pctx = gctx[smp_processor_id()];
    destroyctx(pctx);
    
    atomic_dec(&exitflag);

    if(!atomic_read(&exitflag)){
        octeon_release_ipi_handler(ipi_handle_mesg);
    }
}

/* @cond APPINTERNAL */
module_init (entry);
module_exit (exit);
MODULE_LICENSE ("Cavium");
/* @endcond APPINTERNAL */
