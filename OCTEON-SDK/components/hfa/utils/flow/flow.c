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
 * Application interface to manage flow database and flows
 * - Create Flow Database, Flows
 * - Destroy Flow database, Flows
 * - Submit packet or poll packet to Flows
 *
 */
#include <flow.h>
#include <app-utils.h>

#define HFAF_APP_INVAL              -1

/**
 * Low level API to create a flow
 * Allocate Flow, Intialize searchctx, set graph and setflags,
 *
 * @param   pdev        Pointer to the device
 * @param   ppflow      Flow ptr after allocation set to this
 * @param   pgraph      Pointer to graph on which ctx/flow will work
 * @param   matchcb     Pointer to the matchcb application function
 * @param   searchflags Search Flags for the flow/ctx
 *
 * @return HFA_SUCCESS if flow created, HFA_FAILURE otherwise
 */
static inline hfa_return_t 
__hfaf_create_flow(hfa_dev_t *pdev, hfaf_flow_t **ppflow, hfa_graph_t *pgraph,
                 hfaf_matchcb_t matchcb, uint64_t searchflags)
{
    hfaf_flow_t     *pflow = NULL;

    if(hfa_os_likely(ppflow && pgraph && pdev)){
        if(hfa_os_unlikely(NULL == (*ppflow = 
                                hfaf_memoryalloc(sizeof(hfaf_flow_t), 8)))){
            ERR("memoryalloc failure\n");
            return HFA_FAILURE;
        }
        pflow = *ppflow;
        /*Initialize flow*/
        memset(pflow, 0 , sizeof(hfaf_flow_t));
        hfa_os_lockinit(&pflow->lock);
        pflow->matchcb = matchcb;
        HFA_OS_LISTHEAD_INIT(&pflow->paramlist);
        if(HFA_SUCCESS != hfa_dev_searchctx_init(pdev,&pflow->sctx)){
            ERR("error from searchctx_init\n");
            goto cleanup_flow;
        }
        if(HFA_SUCCESS != hfa_searchctx_setgraph(&pflow->sctx, pgraph)){
            ERR("setgraph failure\n");
            goto cleanup_ctx;
        }
        hfa_searchctx_setflags(&pflow->sctx, searchflags);

        return HFA_SUCCESS;
cleanup_ctx:
        hfa_dev_searchctx_cleanup(pdev, &pflow->sctx); 
cleanup_flow:
        hfaf_memoryfree((*ppflow), sizeof(hfaf_flow_t));
        *ppflow = NULL;
    }
    return HFA_FAILURE;
}
/**
 * Counterpart of __hfaf_create_flow. 
 * Low level API to Destroys ctx or flow
 *
 * @param   pdev    Pointer to the device
 * @param   pflow   Pointer to the flow
 *
 * @return  HFA_SUCCESS if flow destroyed, HFA_FAILURE otherwise
 */
static inline hfa_return_t
__hfaf_destroy_flow(hfa_dev_t *pdev, hfaf_flow_t *pflow)
{
    hfa_os_listhead_t   *p1 = NULL, *p2 = NULL;
    hfaf_sparam_t       *fparam = NULL;
#ifndef WQE_MODEL
    uint32_t            searchstatus = 0;
#endif
    
    if(hfa_os_likely(pdev && pflow)){
        hfa_os_listforeachsafe(p1, p2, &pflow->paramlist){
            fparam = hfa_os_listentry(p1, hfaf_sparam_t, list);

            /*remove from the list*/
            hfa_os_listdel(&fparam->list);

            /*Free param list. If parameters are submitted 
             * poll for them first and then free*/
            switch(fparam->status){
                case HFAF_PARAM_ADDED:
                case HFAF_PARAM_TRYAGAIN:
                case HFAF_PARAM_PROCESSED:
                    if(fparam->cb){
#ifdef WQE_MODEL
                        fparam->cb(((hfaf_sparam_t *)(fparam->cba))->hwwqe, HFA_FALSE);
#else 
                        fparam->cb(fparam->cba, HFA_FALSE);
#endif
                    }
                break;

                case HFAF_PARAM_SUBMITTED:
#ifndef WQE_MODEL
                    searchstatus = HFA_SEARCH_SEAGAIN;
                    do{
                        hfa_searchctx_get_searchstatus(&pflow->sctx, 
                                      &fparam->sparam, &searchstatus);
                    }while(searchstatus == HFA_SEARCH_SEAGAIN);
                    
                    if(fparam->cb){
                        fparam->cb(fparam->cba, HFA_FALSE);
                    }
#endif
                break;

                default:
                    /*Do Nothing*/
                break;
            }
        }
        hfa_dev_searchctx_cleanup(pdev, &pflow->sctx); 
        hfaf_memoryfree(pflow, sizeof(hfaf_flow_t));
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Low level API to submit search parameter to flow. Submit a search parameter from 
 * flow->paramlist. Paramlist of a flow is iterated from head and flow if found is 
 * submitted. Submit only one search parameter to maintain the flow. THis API is called 
 * from hfaf_submit_pktflow() and hfaf_process_pktflow()
 *
 * @param   pflow       POinter to the flow
 * @param   status      Submit Status
 *
 * @return  HFA_SUCCESS if submitted one, HFA_FAILURE otherwise
 */
static inline hfa_return_t
__hfaf_submit_pktflow(hfaf_flow_t *pflow, hfaf_paramstatus_t *status)
{
    hfa_os_listhead_t       *p1 = NULL, *p2 = NULL;
    hfaf_sparam_t           *fparam = NULL;

    /*Loop through Param List*/
    hfa_os_listforeachsafe(p1, p2, &pflow->paramlist){
        fparam = hfa_os_listentry(p1, hfaf_sparam_t, list);
        DBG("fparam %p\n", fparam);
        
        HFAF_OS_WLOCK(&fparam->lock);
        switch(fparam->status){
            case HFAF_PARAM_ADDED:
#if (defined WQE_MODEL) && (defined SHARED_FLOW)
                if(cvmx_get_core_num() < HFA_PKTDATA_WQE_GRP)
                    cvmx_wqe_set_grp((fparam->sparam).wqe, cvmx_get_core_num());
                else 
                    cvmx_wqe_set_grp((fparam->sparam).wqe,cvmx_get_core_num()+1);
#endif
                if(HFA_SUCCESS == hfa_searchctx_search_async(&pflow->sctx, 
                                                         &fparam->sparam)){
                    fparam->status = HFAF_PARAM_SUBMITTED;
                    *status = HFAF_PARAM_SUBMITTED;  
                    (pflow->added)--;
                    (pflow->submitted)++;
#ifdef WQE_MODEL
                    /*Remove param from paramlist*/
                    hfa_os_listdel(&fparam->list); 
#endif
                    goto out_of_loop;
                } else {
                    ERR("Submit Error\n");
                    HFAF_OS_WUNLOCK(&fparam->lock);
                    return HFA_FAILURE;
                }
            break;

            /*If already submitted wait for it*/
            case HFAF_PARAM_SUBMITTED:
                goto out_of_loop;
            break;

            default:
                HFAF_OS_WUNLOCK(&fparam->lock);
                return HFA_FAILURE;
            break;
        }
out_of_loop:    
        HFAF_OS_WUNLOCK(&fparam->lock);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Low level API to poll a flow. 
 * Paramlist of a flow is iterated and all submitted flows are polled
 * If one submitted flow once polled get success, matches are collected,
 * matchcb() is called and then API returns
 *
 * @param   pflow       Pointer to the flow
 * @param   fstatus     Poll status
 *
 * @return  HFA_SUCCESS
 */
static inline hfa_return_t
__hfaf_process_pktflow(hfaf_flow_t *pflow, hfaf_paramstatus_t *fstatus)
{
    hfa_os_listhead_t       *p1 = NULL, *p2 = NULL;
    uint64_t                *pmatch = NULL;           
    hfa_reason_t            reason=0;
    hfaf_sparam_t           *fparam = NULL;
    hfa_searchstatus_t      status = HFA_SEARCH_SEAGAIN;
    hfa_return_t            retval = HFA_SUCCESS;

    DBG("\n");
    *fstatus = HFAF_PARAM_TRYAGAIN;
    /*Loop through paramlist*/
    hfa_os_listforeachsafe(p1, p2, &pflow->paramlist){
        fparam = hfa_os_listentry(p1, hfaf_sparam_t, list);

        switch(fparam->status){
            case HFAF_PARAM_SUBMITTED:
                if(HFA_SUCCESS == hfa_searchctx_get_searchstatus(&pflow->sctx,
                                                   &fparam->sparam, &status)){
                    if(HFA_SEARCH_SEAGAIN == status){
                        DBG("EAGAIN\n");
                        return HFA_SUCCESS;
                    }
                    *fstatus = HFAF_PARAM_PROCESSED;

                    /*Remove param from paramlist*/
                    hfa_os_listdel(&fparam->list);

                    /*Update flow counters*/
                    (pflow->submitted)--;

                    /*Get HW reason and matches*/
                    hfa_searchparam_get_hwsearch_reason(&fparam->sparam,
                                                        &reason);
                    DBG("reason: %u\n", reason);
                    if(hfa_os_likely(!reason)){
                        DBG("Getting matches\n");
                        pmatch = NULL;
                        hfa_searchctx_getmatches(&pflow->sctx, &fparam->sparam,
                                                               &pmatch);
                        /*Call matchcb*/
                        if(pflow->matchcb && pmatch){
                            pflow->matchcb(&pflow->sctx, pmatch);
                        }
                    }

                    /*Call free cb*/
                    if(fparam->cb){
                        fparam->cb(fparam->cba, HFA_TRUE);
                    }
                    return retval;
              } else {
                  ERR("from get_searchstatus\n");
              }
            break;
            default:
                /*Do Nothing*/
            break;
        }
    }
    return retval;
}
/**
 * Initializes Flow database index. Called implicitly by hfaf_flowdb_init()
 *
 * @param   pfdb    Pointer to the flow
 * @param   cnt     Index of flowdb arrary where node has to be initialized
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfaf_flowdb_node_init(hfaf_flowdb_t *pfdb, uint32_t cnt)
{
    hfaf_flowdb_node_t *pfdb_node = NULL;

    DBG("cnt: %u\n", cnt);
    if(hfa_os_unlikely(NULL == pfdb)){
        ERR("pfdb found NULL\n");
        return HFA_FAILURE;
    }
    pfdb_node = (hfaf_flowdb_node_t *)&((pfdb->pnodes)[cnt]);
    DBG("pfdb_node: %p\n", pfdb_node);
    if(hfa_os_likely(pfdb_node)){
        hfa_os_lockinit(&pfdb_node->lock);
        HFA_OS_LISTHEAD_INIT(&pfdb_node->list);
        pfdb_node->ncnt=0;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Cleanup Flowdb Node (Per Index)
 *
 * @param   pfdb    Pointer to the Flow database
 * @param   cnt     Index of Flowdb array where node to be cleaned up
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfaf_flowdb_node_cleanup(hfaf_flowdb_t *pfdb, uint32_t cnt)
{
    hfaf_flowdb_node_t      *pfdb_node = NULL;
    hfa_os_listhead_t       *p1 = NULL, *p2 = NULL;
    hfaf_flowid_ptr_map_t   *pmap = NULL;

    DBG("\n");
    if(hfa_os_unlikely(NULL == pfdb)){
        ERR("pfdb found NULL\n");
        return HFA_FAILURE;
    }
    pfdb_node = (hfaf_flowdb_node_t *) &((pfdb->pnodes)[cnt]);

    if(hfa_os_likely(pfdb_node)){
        HFAF_OS_LOCK(&pfdb_node->lock);
        hfa_os_listforeachsafe(p1, p2, &pfdb_node->list){
            pmap = hfa_os_listentry(p1, hfaf_flowid_ptr_map_t, list);
            if(pmap){
                hfa_os_listdel(&pmap->list);
                (pfdb_node->ncnt)--;
                __hfaf_destroy_flow(pfdb->pdev, pmap->pflow);
                hfaf_memoryfree(pmap, sizeof(hfaf_flowid_ptr_map_t));
            }
        }
        HFAF_OS_UNLOCK(&pfdb_node->lock);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/** 
 * @cond INTERNAL
 *   Array   LinkedList of Flows per Array Index
 *   =====   ===================================
 *    ___     __    __    __
 *   |___|==>|__|->|__|->|__| 
 *   |___|==>|__|->|__|->|__|
 *   |___|==>|__|->|__|->|__| 
 *   |___|==>|__|->|__|->|__|
 *
 * Above figure depicts flow database. 
 * @endcond
 *
 * Initially a Array is created with maxflow indexes.Each index holds Linked List head. 
 * Each Linked List holds nodes having mapping of [FLOWID: PFLOW]. No memory allocated 
 * initially for any flow. The flow is created at run time, when the first packet is 
 * arrived for it. When the packet arrived for a flow, a index with in the above array is
 * calculated from the WQE tag using: 
 *                       (pfdb->bitmsk && tag)
 * and a map node is created [flowid, pflow] and added to the tail of the list of the
 * index node.
 *
 * If number of flows created == initially indexes created for flowdb. Each index will
 * have only one flow hence implementation will like hashing. However flow searching
 * complexity will increasing if flows per index increases and each time linked list has
 * to be iterated to get rewuired flow.
 *
 * This function tries to align maxflow count to number x (where x = 2^y -1) && 
 * (x > maxflows)
 *
 * @param   pdev        Pointer to device
 * @param   pfdb        Pointer to flow database
 * @param   pmaxflow    Pointer to number of initial flows
 *
 * @return  HFA_SUCCESS of flowdb created, HFA_FAILURE otherwise 
 */
hfa_return_t
hfaf_flowdb_init(hfa_dev_t *pdev, hfaf_flowdb_t  *pfdb, uint32_t *pmaxflow)
{
    uint32_t    cnt, tflows;

    if(hfa_os_likely(pfdb && (*pmaxflow) && pdev)){

        tflows=(*pmaxflow);

         /*Calculate at what max position bit is set in maxflow*/
        for(cnt=0; tflows; tflows >>= 1){
            cnt++;
        }
        /*If power of 2 then reduce one bit*/
        if(!((*pmaxflow) & ((*pmaxflow) -1))){
            cnt--;
            pfdb->maxflows = 1;
        }
        pfdb->maxflows += (~((HFAF_MAXFLOWS_ALLOWED) << cnt));
        pfdb->totflows = (*pmaxflow);
        pfdb->bitmsk = ~((HFAF_MAXFLOWS_ALLOWED) << cnt);
        pfdb->bitmsk <<= (pfdb->wqegrp_bits);
        hfa_os_rwlockinit(&pfdb->lock);
        HFA_ALIGNED(pfdb->maxflows, HFA_NBITS);
        
        /*Indicate application about increase in maxflows*/
        (*pmaxflow) = pfdb->maxflows;
        DBG("Actualflows: %u, Maxflows: %u, NBITS: %u, BitMsk: 0x%x\n", 
             pfdb->totflows, pfdb->maxflows, cnt, pfdb->bitmsk);
       
        if(NULL == (pfdb->pnodes = (hfaf_flowdb_node_t *)
           hfaf_memoryalloc((sizeof(hfaf_flowdb_node_t) * pfdb->maxflows), 8))){
            ERR("error in memoryalloc\n");
            return HFA_FAILURE;
        }
        pfdb->pdev = pdev;
        memset(pfdb->pnodes, 0, sizeof(hfaf_flowdb_node_t) * pfdb->maxflows);
        
        for(cnt=0; cnt < (pfdb->maxflows); cnt++){
          DBG("maxflows: 0x%lx, cnt: %u\n", pfdb->maxflows, cnt);
            if(HFA_SUCCESS != hfaf_flowdb_node_init(pfdb, cnt)){
                ERR("Failure from hfaf_flowdb_node_init\n");
                return HFA_FAILURE;
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Cleanups Flow database which was created in hfaf_flowdb_init()
 *
 * @param   pfdb        Pointer to Flow databsae
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfaf_flowdb_cleanup(hfaf_flowdb_t *pfdb)
{
    int cnt=0;
    DBG("\n");
    if(hfa_os_likely(pfdb && pfdb->pnodes)) {
        for(cnt=0; cnt < pfdb->maxflows; cnt++){
            hfaf_flowdb_node_cleanup(pfdb, cnt);
        }
        hfaf_memoryfree(pfdb->pnodes, 
                        sizeof(hfaf_flowdb_node_t) * (pfdb->maxflows));
        memset(pfdb, 0, sizeof(hfaf_flowdb_t));
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Create Packet Flow in Flowdb.
 * Allocate Flow, Intialize searchctx, set graph and setflags,
 * Create a map node, fill the node and add map node in the flowdb linked list
 *
 * @param   pfdb        Pointer to the flow
 * @param   flowid      Flowid or Tag value
 * @param   pgraph      Pointer to graph on which flow will search
 * @param   matchcb     Pointer to the matchcb application function
 * @param   searchflags Search Flags for the flow
 *
 * @return HFA_SUCCESS if flow created, HFA_FAILURE otherwise
 */
hfa_return_t
hfaf_create_pktflow (hfaf_flowdb_t *pfdb,flowid_t flowid,hfa_graph_t *pgraph,
                     hfaf_matchcb_t matchcb, uint64_t searchflags)
{
    uint64_t                flowidx;
    hfaf_flow_t             *pflow = NULL;
    hfaf_flowid_ptr_map_t   *pmap = NULL;
    hfaf_flowdb_node_t      *pfdbnode = NULL;

    DBG("\n");
    if(hfa_os_likely(pfdb && pgraph)){
        hfaf_get_flowidx(pfdb, flowid, &flowidx); 

        pfdbnode = (hfaf_flowdb_node_t *)&((pfdb->pnodes)[flowidx]);

        if(hfa_os_unlikely(NULL == pfdbnode)){
            ERR("pfdbnode at idx: %lu found NULL\n", 
                    (long unsigned int)flowidx);
            return HFA_FAILURE;
        }
        if(HFA_SUCCESS != __hfaf_create_flow(pfdb->pdev, &pflow, pgraph, 
                                           matchcb, searchflags)){
            ERR("Error from create_flow for flowid: %u\n", 
                     (unsigned int)flowid);
            return HFA_FAILURE;
        }
        if(NULL ==(pmap = hfaf_memoryalloc(sizeof(hfaf_flowid_ptr_map_t), 8))){
            ERR("alloc failure for flowid: %u\n", flowid);
            goto destroy_flow;
        }
        /*Initialize map*/
        pmap->flowid = flowid;
        pmap->pflow = pflow;
        HFA_OS_LISTHEAD_INIT(&pmap->list);
        pflow->flowid = flowid;

        /*Add to the list*/
        HFAF_OS_LOCK(&pfdbnode->lock);
        hfa_os_listaddtail(&pmap->list, &pfdbnode->list);
        (pfdbnode->ncnt)++;
        HFAF_OS_UNLOCK(&pfdbnode->lock);

        return HFA_SUCCESS;
    }
    return HFA_FAILURE;

destroy_flow:
    __hfaf_destroy_flow(pfdb->pdev, pflow);
    return HFA_FAILURE;    
}
/**
 * Counterpart of hfaf_create_pktflow(). Destroys flow
 * As per flowid a array index is selected and Linked list is iterated to get map node
 * of provided flowid. If found, node is deleted from the list and map node and flow
 * is freed
 *
 * @param   pfdb    Pointer to the flow db
 * @param   flowid  Flowid or Tag value
 *
 * @return  HFA_SUCCESS if flow destroyed, HFA_FAILURE otherwise
 */
hfa_return_t
hfaf_destroy_pktflow (hfaf_flowdb_t *pfdb, flowid_t flowid)
{
    uint64_t                flowidx;
    hfaf_flowid_ptr_map_t   *pmap = NULL;
    hfaf_flowdb_node_t      *pfdbnode = NULL;
    hfa_os_listhead_t       *p1 = NULL, *p2 = NULL;
    hfa_return_t            retval = HFA_FAILURE;

    DBG("\n");
    if(hfa_os_likely(pfdb && (pfdb->maxflows > flowid))){
        hfaf_get_flowidx(pfdb, flowid, &flowidx); 

        pfdbnode = (hfaf_flowdb_node_t *)&((pfdb->pnodes)[flowidx]);

        if(hfa_os_unlikely(NULL == pfdbnode)){
            ERR("pfdbnode at idx: %lu found NULL\n", 
                    (long unsigned int)flowidx);
            return HFA_FAILURE;
        }
        HFAF_OS_LOCK(&pfdbnode->lock);
        hfa_os_listforeachsafe(p1, p2, &pfdbnode->list){
            pmap = hfa_os_listentry(p1, hfaf_flowid_ptr_map_t, list);
            if(pmap->flowid == flowid){
                hfa_os_listdel(&pmap->list);
                (pfdbnode->ncnt)--;
                __hfaf_destroy_flow(pfdb->pdev, pmap->pflow);
                hfaf_memoryfree(pmap, sizeof(hfaf_flowid_ptr_map_t));
                retval = HFA_SUCCESS;
                break;
            }
        }
        HFAF_OS_UNLOCK(&pfdbnode->lock);
    }
    return retval;
}
/**
 * Add Search Parameter to a Flow
 * Search parameter is added to the flow->paramlist
 *
 * @param   pflow       Pointer to the flow
 * @param   fparam      Pointer to the search parameter
 *
 * @return HFA_SUCCESS if successfully added, HFA_FAILURE otherwise
 */
hfa_return_t
hfaf_addsparam(hfaf_flow_t *pflow, hfaf_sparam_t *fparam)
{

    DBG("\n");

    if(hfa_os_unlikely((NULL == fparam) || (NULL == pflow))){
        ERR("fparam NULL\n");
        return HFA_FAILURE;
    }
    fparam->status = HFAF_PARAM_TRYAGAIN;
    /*Take Lock*/
    DBG("param: %p added\n", fparam); 
    HFAF_OS_LOCK(&pflow->lock);
    hfa_os_listaddtail(&fparam->list, &pflow->paramlist);
    (pflow->added) += 1;
     HFAF_OS_UNLOCK(&pflow->lock);
    HFAF_OS_WLOCK(&fparam->lock);
    fparam->status = HFAF_PARAM_ADDED;
    HFAF_OS_WUNLOCK(&fparam->lock);

    return HFA_SUCCESS;
}
/**
 * High Level API to submit Search Parameter to a Flow.
 * THis API does the sanity to check is any search parameter is waiting to be submitted
 * or is any present and then call low level __hfaf_submit_pktflow()
 *
 * @param   pflow   Pointer to the flow
 * @param   status  Submit status
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfaf_submit_pktflow(hfaf_flow_t *pflow, hfaf_paramstatus_t *status)
{
    DBG("\n");

    if(hfa_os_unlikely((NULL == pflow) || (NULL == status))){
        return HFA_FAILURE;
    }
    *status = HFAF_PARAM_TRYAGAIN;
    
    /**Get lock, If already submitted return*/
    if(pflow->submitted){
        return HFA_SUCCESS;
    }
    /*Nothing to submit return*/
    if(!(pflow->added)){
        return HFA_SUCCESS;
    }
    return(__hfaf_submit_pktflow(pflow, status));
}
/**
 * All submitted search parameters in Paramlist of flow are polled
 * If low level API __hfaf_process_pktflow() indicates that one search parameter is 
 * successfully processed, an attempt is made to submit next search parameter (if present)
 * in the flow param list
 *
 * @param   pflow       Pointer to the flow
 * @param   fstatus     Process status
 *
 * @return HFA_SUCCESS/HFA_FAILURE
 */ 
hfa_return_t
hfaf_process_pktflow(hfaf_flow_t *pflow, hfaf_paramstatus_t *fstatus)
{
    DBG("\n");

    if(hfa_os_unlikely((NULL == pflow) || (NULL == fstatus))){
        ERR("pfdb, fstatus NULL\n");
        return HFA_FAILURE;
    }
    *fstatus = HFAF_PARAM_TRYAGAIN;
    if(HFA_SUCCESS != __hfaf_process_pktflow(pflow, fstatus)){
        ERR("Error from __hfaf_process_pktflow\n");
        return HFA_FAILURE;
    }

    switch(*fstatus){
        case HFAF_PARAM_PROCESSED:
            /*If one instruction is processed, submit another*/
            if((pflow->added) && !(pflow->submitted)){
               __hfaf_submit_pktflow(pflow, fstatus); 
            }
        break;

        default:
        break;
    }
    return HFA_SUCCESS;
}

