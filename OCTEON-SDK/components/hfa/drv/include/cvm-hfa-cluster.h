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
 * This is header file for cluster APIs
 *
 */
#ifndef _CVM_HFA_CLUSTERAPI_H_
#define _CVM_HFA_CLUSTERAPI_H_

#include "cvm-hfa-common.h"
#include "cvm-hfa.h"

/**@cond INTERNAL */
#define HFA_CLUSTER_INITDONE        0xA5A5
#define HFA_CLUSTER_MAX_NGRAPHS     64
/**@endcond */
/**Allocated Free memory/cache list*/
typedef struct {
    /**Lock guarding the structure*/
    hfa_os_rwlock_t     lock;

    /**Refcnt maintaining number of clusters sharing list*/
    int                 list_refcnt;

    /**Allocation List*/
    hfa_os_listhead_t   alist;

    /**Free List*/
    hfa_os_listhead_t   flist;
} hfa_memlist_t;
/**Menber of alist/flist of hfa_memlist_t*/
typedef struct {
    /**Memory List*/
    hfa_memlist_t       *pmemlist;

    /**List for each Cache*/
    hfa_memlist_t       *pclist[HFA_MAX_CACHE_PER_CLUSTER];
} hfa_mempool_t;

/**
 * @cond INTERNAL
 * Private data members of hfa_cluster_t
 */
typedef struct {
    /**Cluster Number*/
    uint32_t            clust_num;

    /*Future use*/
    hfa_size32_t        cacheshare_msk;

    /**Mask indicating memlist sharing*/
    hfa_size32_t        memshare_msk;

    /**Back Pointer to unit*/
    hfa_unit_t          *punit;
    
    /*Memaddr*/
    hfa_addr_t          memaddr;

    /*Memsize*/
    hfa_size_t          memsize;

    /**Back Pointer to cache load in unit*/
    hfa_os_rwlock_t     *pcload_lock;
} hfa_cluster_priv_t;
/**@endcond */
/**
 * Cluster object Data Structure
 */
typedef struct hfa_cluster {
    /**Private Data Structure*/
    hfa_cluster_priv_t  s;

    /**What all cores using this cluster*/
    hfa_coremask_t      coremask;

    /**Resource Pool*/
    hfa_mempool_t       pool;
} hfa_cluster_t;

/**@cond INTERNAL */
/****Function Prototypes***/
hfa_return_t hfa_cluster_init(hfa_dev_t*, hfa_cluster_t *, uint32_t);

hfa_return_t hfa_cluster_cleanup(hfa_cluster_t *);

hfa_return_t hfa_cluster_setmem (hfa_cluster_t*, hfa_addr_t , hfa_size_t);

hfa_return_t 
hfa_cluster_setcache(hfa_cluster_t*, hfa_size32_t , hfa_addr_t, hfa_size_t);

hfa_return_t hfa_cluster_cleanupmem(hfa_cluster_t *);

hfa_return_t hfa_cluster_cleanupcache(hfa_cluster_t *, hfa_size32_t);

hfa_return_t hfa_cluster_memalloc(hfa_cluster_t*, hfa_size_t, hfa_addr_t*);

hfa_return_t 
hfa_cluster_memcalloc(hfa_cluster_t*, hfa_size_t, hfa_addr_t*, uint32_t );

hfa_return_t
hfa_cluster_cachecalloc(hfa_cluster_t *, hfa_size32_t , hfa_size_t , 
                        hfa_addr_t *, uint32_t );
hfa_return_t hfa_cluster_memrealloc(hfa_cluster_t*, hfa_size_t, hfa_addr_t*);

hfa_return_t 
hfa_cluster_cachealloc(hfa_cluster_t*, hfa_size32_t, hfa_size_t, hfa_addr_t*);

hfa_return_t 
hfa_cluster_cacherealloc(hfa_cluster_t*, hfa_size32_t, hfa_size_t, hfa_addr_t*);

hfa_return_t hfa_cluster_memfree(hfa_cluster_t*, hfa_addr_t addr);

hfa_return_t 
hfa_cluster_cachefree(hfa_cluster_t*, hfa_size32_t, hfa_addr_t addr);

hfa_return_t hfa_cluster_share_mem(hfa_cluster_t *owner, hfa_cluster_t *sharer);

hfa_return_t hfa_get_cluster(hfa_dev_t *, hfa_cluster_t **, uint32_t clno);

hfa_return_t hfa_cluster_isinit (hfa_cluster_t *pclust);
/****Static Inline Functions******/

/**
 * Get Cluster Number for Cluster pointer
 *
 * @param   pclust      Pointer to Cluster
 * @param   pclus_num   Sets cluster number in *pclus_num
 *
 * @return  HFA_SUCCESS if successm FAILURE otherwise
 */
static inline hfa_return_t 
hfa_cluster_getnumber(hfa_cluster_t *pclust, hfa_size32_t *pclus_num)
{
    if(pclus_num && pclust){
        *pclus_num = pclust->s.clust_num;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Sets core mask to cluster structure
 *
 * @param   pclust      Pointer to the cluster
 * @param   mask        Coremask
 *
 * @return  Void
 */
static inline void
hfa_cluster_set_coremask(hfa_cluster_t *pclust, hfa_coremask_t mask)
{
    if(hfa_os_likely(pclust))
        pclust->coremask=mask;
}
/**
 * Sets Cluster Number to cluster data structure
 *
 * @param   pclust      Pointer to cluster
 * @param   cno         Cluster Num
 *
 * @return  Void
 */
static inline hfa_return_t
hfa_cluster_set_clustnum(hfa_cluster_t *pclust, uint32_t cno)
{
    if(hfa_os_likely(pclust)){
        HFA_SET(pclust, s, clust_num, cno);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Sets CLOAD Lock 
 *
 * @param   pdev        Pointer to Device
 * @param   pclust      Pointer to cluster
 *
 * @return  Void
 */
static inline hfa_return_t 
hfa_cluster_init_pcload_lock(hfa_dev_t *pdev, hfa_cluster_t *pclust)
{
    if(hfa_os_likely(pdev && pclust)){
       HFA_SET(pclust, s, pcload_lock, &(pdev->punit->s.cload_lock));
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**@endcond */
#endif
