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
 * Header file to provide Flow based API interface
 */
#ifndef _HFA_APP_FLOW_H_
#define _HFA_APP_FLOW_H_
#include <cvm-hfa-common.h>
#include <cvm-hfa.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-search.h>
#include <app-utils.h>

#ifdef SHARED_FLOW
#define HFAF_OS_WLOCK(x)      hfa_os_wlock(x) 
#define HFAF_OS_WUNLOCK(x)    hfa_os_wunlock(x)   
#define HFAF_OS_LOCK(x)       hfa_os_lock(x)
#define HFAF_OS_UNLOCK(x)     hfa_os_unlock(x)
#define HFAF_OS_TRYLOCK(x)    hfa_os_trylock(x) 
#else
#define HFAF_OS_WLOCK(...)
#define HFAF_OS_WUNLOCK(...)
#define HFAF_OS_LOCK(...)
#define HFAF_OS_UNLOCK(...)
#define HFAF_OS_TRYLOCK(...)
#endif

#define hfaf_memoryalloc            hfa_os_memoryalloc
#define hfaf_memoryfree             hfa_os_memoryfree
#define HFAF_MAXFLOWS_ALLOWED       0xFFFFFFFF
#define HFAF_MAX_ALLOWED_PARAMS     20

typedef uint32_t            flowid_t;
typedef uint64_t            hfaf_bitmap_t;

typedef hfa_return_t (*hfaf_freecb_t)(void *, int);
typedef hfa_return_t (*hfaf_matchcb_t)(hfa_searchctx_t *, uint64_t *);

/**Flow Search Parmeter Status*/
typedef enum {
    HFAF_PARAM_TRYAGAIN = 0,
    HFAF_PARAM_ADDED = 1,
    HFAF_PARAM_SUBMITTED =2,
    HFAF_PARAM_PROCESSED
}hfaf_paramstatus_t;

/**strucutre holding match buffer and reason*/
typedef struct {
    uint64_t            *pmatch;
    hfa_reason_t        reason;
}hfaf_match_t;

/**Flow Search Parameter*/
typedef struct{
    hfa_os_listhead_t       list;
    hfa_os_rwlock_t         lock;
    hfa_searchparams_t      sparam;
    hfaf_paramstatus_t      status;
    cvmx_wqe_t              *pktwqe;
    cvmx_wqe_t              *hwwqe;
    hfa_iovec_t             input;
    hfaf_freecb_t           cb;
    void                    *cba;
}hfaf_sparam_t;

/**Flow structure*/
typedef struct {
    hfa_os_lock_t           lock;
    /*Ptr to flowid_ptr_map*/
    flowid_t                flowid;
    hfa_os_listhead_t       paramlist;
    hfa_searchctx_t         sctx;
    hfaf_matchcb_t          matchcb;
    uint32_t                added; 
    uint32_t                submitted; 
}hfaf_flow_t;
/**[Flowid: Ponter to Flow] map node, added to flowdb node list*/
typedef struct {
    hfa_os_listhead_t   list;
    hfaf_flow_t         *pflow;
    flowid_t            flowid;
}hfaf_flowid_ptr_map_t;

/*Each Flowdb node*/
typedef struct {
    /*Guarding this flowdb nodelist*/
    hfa_os_lock_t       lock;
    
    /*Per node flow list*/
    hfa_os_listhead_t   list;
    
    /*Number of flows in nodelist*/
    uint32_t            ncnt;
}hfaf_flowdb_node_t;

/*Flow DB such as HTTP, FTP*/
typedef struct {
    /*Base address to flow node array*/
    hfaf_flowdb_node_t  *pnodes;

    /*Dev*/
    hfa_dev_t           *pdev;

    /*Total umber of flows*/ 
    uint32_t            totflows;

    /*Total flows size aligned to next power of two value*/
    uint32_t            maxflows;

    /*Bitmsk to calculate index from 32 bit flowid*/
    uint32_t            bitmsk;
    
    /* Number of bits to calculate wqe group from tag value */
    int                 wqegrp_bits;

    hfa_os_rwlock_t     lock;
}hfaf_flowdb_t;
/**
 * Calculate Array index to which received flowid should be present or added
 * 
 * @param   pfdb        Pointer to the Flow db
 * @param   id          Flow id or Tag value
 * @param   pidx        Pointer to the Array Index
 *
 * @return void
 */
static inline void
hfaf_get_flowidx (hfaf_flowdb_t *pfdb, flowid_t id, uint64_t *pidx)
{
    uint32_t    mask = 0x0;
    
    mask = id & (pfdb->bitmsk);
    *pidx = mask >> (pfdb->wqegrp_bits);
}
/**
 * Search particular flowid or flow in Flow database and return 1 if present or 0 
 * otherwise. If found, return flow ptr in ppflow
 *
 * @param   pfdb        Pointe to the flowdb
 * @param   id          Flowid or Tag value
 * @param   ppflow      Pointer to pointer to flow 
 *
 * @return HFA_SUCCESS if id found otherwise HFA_FAILURE
 */
static inline hfa_return_t
hfaf_isflow_exist(hfaf_flowdb_t *pfdb, flowid_t id, hfaf_flow_t **ppflow)
{
    hfa_os_listhead_t       *p1 = NULL, *p2 = NULL;
    hfaf_flowdb_node_t      *pdbnode = NULL;
    hfaf_flowid_ptr_map_t   *pmap;
    uint64_t                idx;

    if(pfdb && ppflow){
        *ppflow = NULL;
        hfaf_get_flowidx(pfdb, id, &idx);

        pdbnode = (hfaf_flowdb_node_t *)&((pfdb->pnodes)[idx]);
        hfa_os_listforeachsafe(p1, p2, &pdbnode->list){
            pmap= hfa_os_listentry(p1,hfaf_flowid_ptr_map_t,list);
            if(id == pmap->flowid){
                *ppflow = pmap->pflow;
                goto flowexit;
            }
        }
flowexit:                
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}

/*Function declarations*/
hfa_return_t hfaf_flowdb_init(hfa_dev_t *, hfaf_flowdb_t  *, uint32_t *);
hfa_return_t hfaf_flowdb_cleanup(hfaf_flowdb_t *pflowdb);
hfa_return_t hfaf_destroy_pktflow (hfaf_flowdb_t *, flowid_t);
hfa_return_t hfaf_addsparam(hfaf_flow_t *, hfaf_sparam_t *);
hfa_return_t hfaf_submit_pktflow(hfaf_flow_t *, hfaf_paramstatus_t *);
hfa_return_t hfaf_process_pktflow(hfaf_flow_t *, hfaf_paramstatus_t *);
hfa_return_t hfautils_init_perf_cntrs(hfautils_fau_perfcntrs_t *);
hfa_return_t hfaf_create_pktflow (hfaf_flowdb_t *, flowid_t, hfa_graph_t *, 
                                  hfaf_matchcb_t, uint64_t);
#endif
