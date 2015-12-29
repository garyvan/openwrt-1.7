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
 * This file contains APIs to Initialize, manage and cleanup cluster 
 * resources. cvm-hfa-cluster.h is the corresponding header file to be included
 * for prototypes and typedefs.
 *
 */
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-stats.h>

/**@cond INTERNAL*/
extern CVMX_SHARED uint64_t     hfa_isdevinit;
CVMX_SHARED uint64_t hfa_clust_init [HFA_MAX_NCLUSTERS];
CVMX_SHARED uint64_t hfa_isclustinit_byapi [HFA_MAX_NCLUSTERS];
extern int hfa_firstbit_setr [8];

static inline void
hfa_display_cluster_info(const char *str, hfa_unit_t *punit, uint32_t clno)
{
    hfa_cluster_t   *pclust = NULL;
    if(punit){
        pclust = punit->pclust[clno];
        if(NULL == pclust){
            hfa_log("Cluster: %d is freed\n", clno);
        } else {
            hfa_log("Cluster %d %s: MemMsk: 0x%x, Base: 0x%lx, Sz: %lu MB\n", 
                   clno, str, pclust->s.memshare_msk, pclust->s.memaddr, 
                   (pclust->s.memsize >> 20));
        }
    }
}
static inline hfa_return_t
__hfa_cluster_getnum (hfa_cluster_t *pclust, uint32_t *pclno)
{
    hfa_dev_t       *pdev = NULL;
    hfa_unit_t      *punit = NULL;
    hfa_cluster_t   *ppclust = NULL;
    int             cnt;

    if(hfa_os_unlikely(NULL == pclust)){
        hfa_err(CVM_HFA_EINVALARG, ("Null Cluster arg\n"));
        return (HFA_FAILURE);
    }
    punit = (pclust->s).punit;
    if(hfa_os_unlikely(NULL == punit)){
        hfa_err(CVM_HFA_EINVALARG, ("Unit found NULL in clust: %p\n", pclust));
        return (HFA_FAILURE);
    }
    pdev = punit->s.pdev;
    if(hfa_os_unlikely(NULL == pdev)){
        hfa_err(CVM_HFA_EINVALARG, ("Device found Null in unit\n"));
        return (HFA_FAILURE);
    }
    for(cnt=0; cnt <hfa_dev_get_nclusters(pdev); cnt++){
        hfa_get_cluster(pdev, &ppclust, cnt);
        if(pclust == ppclust){
            *pclno = cnt;
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/** 
 * @internal
 * Set Memory Share Mask
 *
 * @param   punit       Pointer to unit
 * @param   bitmsk      Resultant Bit Mask
 * @return  Void
 */
static inline void
hfa_cluster_set_memshare_msk (hfa_unit_t *punit, hfa_clmsk_t bitmsk)
{
    hfa_dev_t       *pdev = punit->s.pdev;
    hfa_cluster_t   *pclust = NULL;
    hfa_clmsk_t     r1,r2;
    int             _i, _cl;

    r1 = bitmsk;
    r2 = bitmsk;

#ifdef HFA_DEBUG
    hfa_dbg("punit: %p, bitmsk: 0x%x\n", punit, bitmsk);
    for(_i=0; _i<hfa_dev_get_nclusters(pdev); _i++){
        hfa_dbg("cl[%d] ptr: %p\n", _i, punit->pclust[_i]);
    }
#endif    

    HFA_FOREACHBIT_SET(r1){
        r2 = bitmsk;
        HFA_BITCLR(r2, _cl);
        hfa_get_cluster(pdev, &pclust, _cl);
        if(pclust){
            hfa_dbg("Setting cl:%d mem_msk: 0x%x", _cl, pclust->s.memshare_msk);
            pclust->s.memshare_msk = r2;
            dprintf(" to 0x%x\n", pclust->s.memshare_msk);
        }
    }
}
/** 
 * @internal
 * Unset memshare bit of given cluster to another cluster memshare_msk
 *
 * @param   punit       Pointer to unit
 * @param   clno        Cluster num
 *
 * @return  Void
 */
static inline void
hfa_cluster_unset_memshare_msk(hfa_unit_t *punit, uint32_t clno)
{
    int             cnt;
    hfa_cluster_t   *pclust = NULL;

    for(cnt=0; cnt < hfa_dev_get_nclusters(punit->s.pdev); cnt++){
        if(clno)
          continue;
        pclust = punit->pclust[cnt];
        if(pclust){
            HFA_BITCLR(pclust->s.memshare_msk, clno);
             hfa_dbg("ClusterDBG %d : MemMsk: 0x%x, Base: 0x%x, Sz: lu MB\n", 
                   clno, pclust->s.memshare_msk, pclust->s.memaddr, 
                   (pclust->s.memsize/(1024*1024)));
        }
    }
}
/**
 * @internal
 * Allocate and Initialise Memlist
 *
 * @param   ppmlist         Pointer to pointer to Memory List
 * @return  HFA_SUCCESS if successds, HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_memlist_init(hfa_memlist_t **ppmlist)
{
    /*ppmlist NULL validity done by caller
    */
    hfa_dbg("ppmlist: %p\n", ppmlist);
    *ppmlist = hfa_os_malloc(sizeof(hfa_memlist_t));
    memset(*ppmlist, 0, sizeof(hfa_memlist_t));
    HFA_OS_LISTHEAD_INIT(&((*ppmlist)->alist));
    HFA_OS_LISTHEAD_INIT(&((*ppmlist)->flist));    
    ((*ppmlist)->list_refcnt)++;
    hfa_os_rwlockinit(&((*ppmlist)->lock));
    return HFA_SUCCESS;
}
/**
 * @internal
 * Cleaning Memlist if Refcnt reaches Zero
 *
 * @param   ppmlist         Pointer to pointer to Memory List
 * @return  HFA_SUCCESS if successds, HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_memlist_cleanup(hfa_memlist_t **ppmlist)
{
    hfa_memlist_t       *pmlist = NULL;
    hfa_memnode_t       *pnode = NULL;
    hfa_os_listhead_t   *n1 = NULL;
    hfa_os_listhead_t   *n2 = NULL;

    if(hfa_os_unlikely(NULL == ppmlist)){
        hfa_err(CVM_HFA_EINVALARG, ("Null ppmlist pointer\n"));
        return HFA_FAILURE;
    }
    pmlist = *ppmlist;
    hfa_dbg("pmlist: %p, ppmlist: %p\n", pmlist, ppmlist);
    if(hfa_os_likely(pmlist)){
        hfa_os_wlock(&pmlist->lock);

        (pmlist->list_refcnt)--;
        /*Zero refcnt requires cleanup of memlist structure
        */
        hfa_dbg("list_refcnt: %d\n", pmlist->list_refcnt);
        if(pmlist->list_refcnt <= 0){
            /*Alist*/
            hfa_os_listforeachsafe(n1, n2, &(pmlist->alist)){
                pnode = hfa_os_listentry(n1, hfa_memnode_t, list);
                hfa_dbg("freeing node from alist: %p\n",pnode);
                hfa_os_free(pnode, sizeof *pnode);
            }
            /*Flist*/
            hfa_os_listforeachsafe(n1, n2, &(pmlist->flist)){
                pnode = hfa_os_listentry(n1, hfa_memnode_t, list);
                hfa_dbg("freeing node from flist: %p\n",pnode);
                hfa_os_free(pnode, sizeof *pnode);
            }
            /*Destroy Lock*/
            hfa_os_rwlockdestroy(&pmlist->lock);
            hfa_os_free(pmlist, sizeof *pmlist);
            /*
             *Initialise Memlist to NULL to allow reallocation
             */
            *ppmlist = NULL;
            goto label1;
        }
        /*Release Lock*/
        hfa_os_wunlock(&pmlist->lock);
label1:
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * @internal
 * Initializes Memlist with provided memory coordinates
 *
 * @param   ppmlist         Pointer to pointer to Memory List
 * @param   addr            Address of chunk
 * @param   sz              Size of chunk
 * @return  HFA_SUCCESS if successds, HFA_FAILURE otherwise
 */
static inline hfa_return_t
hfa_memlist_setup(hfa_memlist_t **ppmlist, hfa_addr_t addr, hfa_size_t sz)
{
    hfa_memnode_t *pnode = NULL;
    hfa_memlist_t *pmlist= NULL;

    hfa_dbg("ppmlist: %p, Addr: %lu, Sz: %lu\n", ppmlist, addr, sz);
    if(hfa_os_unlikely(NULL == ppmlist)){
        hfa_err(CVM_HFA_EINVALARG, ("ppmlist can't be NULL\n"));
        return HFA_FAILURE;
    }
    /*Allocate buffer for memlist when empty*/
    if(NULL == *ppmlist){
        if(hfa_os_unlikely(HFA_SUCCESS != hfa_memlist_init(ppmlist))){
           hfa_err(CVM_HFA_EMEMLISTINIT, ("ERROR: hfa_memlist_init failed\n"));
            return HFA_FAILURE;
        }
    }
    pnode = hfa_os_malloc(sizeof(hfa_memnode_t));
    hfa_dbg("pode: %p\n", pnode);
    if(hfa_os_unlikely(NULL == pnode)){
        hfa_err(CVM_HFA_ENOMEM, ("hfa_os_malloc() failed\n"));
        hfa_memlist_cleanup(ppmlist);
        return HFA_FAILURE;
    }
    memset(pnode, 0, sizeof(hfa_memnode_t));
    pnode->size = sz ;
    pnode->addr = addr;
    pmlist = *ppmlist;
    hfa_os_wlock(&pmlist->lock);
    hfa_os_listaddtail (&pnode->list, &pmlist->flist);
    hfa_os_wunlock(&pmlist->lock);
    return(HFA_SUCCESS);
}
/**
 * @internal
 * Frees the buffer which was allocated to application.
 * Moves provided buffer from alist to flist to make it available 
 * for future allocation. API also if needed adjust the flist to combine 
 * small chunk to bigger one.
 *
 * @param   pmemlist    Pointer to Memory list
 * @param   addr        uint64_t Memory address
 */
static inline hfa_return_t
__hfa_cluster_memfree(hfa_memlist_t *pmemlist, hfa_addr_t addr)
{
    hfa_memnode_t       *pnode = NULL;
    hfa_memnode_t       *ptnode = NULL;
    hfa_os_listhead_t   *n1 = NULL;
    hfa_os_listhead_t   *n2 = NULL;
    hfa_return_t        retval = HFA_FAILURE;
    int                 f = 0;

    /*Caller has to ensure that addr is not NULL
    */
    hfa_dbg("pmemlist: %p, Addr: 0x%lx\n", pmemlist, addr);
    if(hfa_os_likely(pmemlist)){
        hfa_os_wlock(&(pmemlist->lock));
        hfa_os_listforeachsafe (n1, n2, &pmemlist->alist) {
            ptnode = hfa_os_listentry (n1, hfa_memnode_t, list);
            if (ptnode->addr == addr) {
                ptnode->node_refcnt--;
                if (ptnode->node_refcnt <= 0){
                    hfa_dbg("deleting a node from alist ptnode: %p\n",ptnode);
                    hfa_os_listdel (&ptnode->list);
                }
                f = 1;
                break;
            }
        }
        if (!f) {
            hfa_dbg("Provided Address is not present in Alist\n");
            goto cmfree_ret;
        }
        f = 0;
        hfa_dbg("node_refcnt: %d\n", ptnode->node_refcnt);
        if (!ptnode->node_refcnt) {
            hfa_dbg("Moving node to flist: %p\n", ptnode);
            if(hfa_os_listempty(&pmemlist->flist)){
                hfa_os_listaddtail (&ptnode->list, &pmemlist->flist);
                retval = HFA_SUCCESS;
                goto cmfree_ret;
            }
            hfa_os_listforeachsafe (n1, n2, &pmemlist->flist) {
                pnode = hfa_os_listentry (n1, hfa_memnode_t, list);
                if (hfa_os_unlikely(ptnode->addr == pnode->addr)) {
                    hfa_dbg ("allocated entry is in free list!\n");
                    goto cmfree_ret;
                }
                if (ptnode->addr < pnode->addr) {
                    if ((ptnode->addr + ptnode->size) == pnode->addr) {
                        pnode->addr = ptnode->addr;
                        pnode->size += ptnode->size;
                        hfa_os_free (ptnode, sizeof *ptnode);
                    } else {
                        hfa_os_listaddtail(&ptnode->list, n1);
                    }
                    f = 1;
                    break;
                } else if ((pnode->addr + pnode->size) == ptnode->addr) {
                    pnode->size += ptnode->size;
                    hfa_os_free (ptnode, sizeof *ptnode);
                    if (n2 != &pnode->list) {
                        ptnode = hfa_os_listentry (n2, hfa_memnode_t, list);
                        if ((pnode->addr + pnode->size)== ptnode->addr) {
                            ptnode->addr = pnode->addr;
                            ptnode->size += pnode->size;
                            hfa_os_listdel (&pnode->list);
                            hfa_os_free (pnode, sizeof *pnode);
                        }
                    }
                    f = 1;
                    break;
                }
            }
            if (!f){
                hfa_os_listaddtail (&ptnode->list, &pmemlist->flist);
            }
        }
        retval = HFA_SUCCESS;
cmfree_ret:
        hfa_os_wunlock(&(pmemlist->lock));
    }
    return retval;
}
/**
 * @internal
 *
 * Provides buffer needed by application for graph load
 * If free memory exists, requested size of buffer is provided and
 * marked reserved by moving from flist to alist
 *
 * @param   pmemlist    Pointer to Memory list
 * @param   addr        uint64_t Memory address
 * @param   sz          uint64_t Size of buffer
 * @param   takelock    boolean to indicate API has to take lock or not
 * @param   refcnt      Initial refcnt for newly allocated node
 *                      If it is 0 then node->refcnt == list->ref_cnt
 *
 * @return  HFA_SUCCESS when success, HFA_FAILURE otherwise
 */
static inline hfa_return_t
__hfa_cluster_alloc(hfa_memlist_t *pmlist, hfa_addr_t *paddr, 
                    hfa_size_t sz, hfa_bool_t takelock, uint32_t refcnt)
{
    hfa_memnode_t     *pnode = NULL, *ptnode = NULL;
    hfa_os_listhead_t *n1    = NULL;
    hfa_os_listhead_t *n2    = NULL;
    uint32_t          retval = HFA_FAILURE;

    hfa_dbg("pmlist: %p, paddr: %p, sz: %lu\n", pmlist, paddr, sz);

    if(hfa_os_likely(pmlist)){
        if ((ptnode = hfa_os_malloc (sizeof *ptnode)) == NULL) {
            hfa_dbg("ptnode: %p\n",ptnode);
            hfa_err (CVM_HFA_ENOMEM, ("hfa_os_malloc failure\n"));
            return retval;
        }
        if(takelock){
            hfa_os_wlock (&pmlist->lock);
        }
        hfa_os_listforeachsafe(n1, n2, &(pmlist->flist)){
            pnode = hfa_os_listentry(n1, hfa_memnode_t, list);
            hfa_dbg("pnode: %p,pnode->size: %lu, req. sz: %lu\n", 
                    pnode, pnode->size, sz);
            /*First Fit*/
            if(pnode->size >= sz){
                ptnode->addr = *paddr = pnode->addr;
                ptnode->size = sz;
                hfa_dbg("refcnt: %d\n", refcnt);
                if(refcnt){
                    ptnode->node_refcnt = refcnt;  
                } else {
                    /*ptnode->node_refcnt == pmlist->list_refcnt
                    * helps to allocate node with valid initial refcnt*/
                    ptnode->node_refcnt = pmlist->list_refcnt;  
                }
                /*Add to Alist*/
                hfa_os_listaddtail(&(ptnode->list), &(pmlist->alist));
                ptnode = NULL;
                pnode->addr += sz;
                pnode->size -= sz;
               if (pnode->size == 0) {
               hfa_dbg("pnode->size is zero,deleting&freeing pnode:%p\n",pnode);
                    hfa_os_listdel (&pnode->list);
                    hfa_os_free (pnode, sizeof *pnode);
                }
                retval = HFA_SUCCESS;
                break;
            }
        }
        if(takelock){
            hfa_os_wunlock (&pmlist->lock);
        }
        if (ptnode != NULL) {
            hfa_os_free (ptnode, sizeof *ptnode);
            retval = HFA_FAILURE;
        }
    }
    hfa_dbg("Returned: %d\n", retval);
    return(retval);
}
/**
 * @internal
 *
 * Reallocation of buffer
 *
 * @param   pmemlist    Pointer to Memory list
 * @param   addr        uint64_t Memory address
 * @param   sz          uint64_t Size of buffer
 *
 * @return  HFA_SUCCESS when success, HFA_FAILURE otherwise
 */
static inline hfa_return_t
__hfa_cluster_realloc(hfa_memlist_t *pmemlist, hfa_addr_t *paddr, 
                                       hfa_size_t sz)
{
    hfa_memnode_t     *ptnode = NULL;
    hfa_os_listhead_t *n1 = NULL, *n2 = NULL;
    int                f = 0;
    hfa_return_t       retval = HFA_SUCCESS;

    hfa_dbg("pmemlist: %p, paddr: %p, sz: %lu\n", pmemlist, paddr, sz);
    if(hfa_os_likely(pmemlist)){
        hfa_os_wlock(&pmemlist->lock);
        hfa_os_listforeachsafe (n1, n2, &pmemlist->alist) {
            ptnode = hfa_os_listentry (n1, hfa_memnode_t, list);
            if (ptnode->addr == *paddr && ptnode->size == sz) {
                ptnode->node_refcnt++; 
                f = 1;
                break;
            }
        }
        if (!f) {
            retval = __hfa_cluster_alloc(pmemlist, paddr, sz, HFA_FALSE, 1); 
        }
        hfa_os_wunlock(&pmemlist->lock);
        return (retval);
    }
    return HFA_FAILURE;
}
/**@endcond*/
/**
 * @cond EXTERNAL_NOTYET
 * Extern Functions
 */
hfa_return_t
hfa_cluster_isinit (hfa_cluster_t *pclust)
{
    hfa_dev_t       *pdev = NULL;
    hfa_unit_t      *punit = NULL;
    hfa_cluster_t   *ppclust = NULL;
    int             cnt;

    if(hfa_os_unlikely(NULL == pclust)){
        hfa_err(CVM_HFA_EINVALARG, ("Null Cluster arg\n"));
        return (HFA_FAILURE);
    }
    punit = (pclust->s).punit;
    if(hfa_os_unlikely(NULL == punit)){
        hfa_err(CVM_HFA_EINVALARG, ("Unit found NULL in clust: %p\n", pclust));
        return (HFA_FAILURE);
    }
    pdev = punit->s.pdev;
    if(hfa_os_unlikely(NULL == pdev)){
        hfa_err(CVM_HFA_EINVALARG, ("Device found Null in unit\n"));
        return (HFA_FAILURE);
    }
    for(cnt=0; cnt < hfa_dev_get_nclusters(pdev); cnt++){
        hfa_get_cluster(pdev, &ppclust, cnt);
        if(pclust == ppclust){
            if(HFA_CLUSTER_INITDONE == hfa_clust_init[cnt]){
                return HFA_SUCCESS;
            }  else {
                hfa_err(CVM_HFA_ENOPERM, ("Cluster: %d is not init\n", cnt));
                return HFA_FAILURE;
            }
        }
    }
    return HFA_FAILURE;
}
/**@endcond*/
/**
 * Assigns a memory block to the cluster as HFA memory for the purpose of
 * loading graphs.
 *
 * See hfa_cluster_init() for more information. hfa_cluster_share_mem() should
 * be used to share a memory block already assigned to another cluster. This
 * routine should not be used to assign a memory block that is already assigned
 * to another cluster.
 * 
 * The corresponding cleanup routine is hfa_cluster_cleanupmem()
 * 
 * @param   pclust  Pointer to Cluster pointer
 * @param   addr    uint64_t Memory address
 * @param   sz      uint64_t Memory Size
 *
 * @return  HFA_FAILURE when failure and HFA_SUCCESS otherwise
 */
hfa_return_t
hfa_cluster_setmem(hfa_cluster_t *pclust, hfa_addr_t addr, hfa_size_t sz)
{
    hfa_return_t    retval;
    hfa_dbg("pclust: %p, addr:%lu, sz:%lu\n", pclust, addr, sz);

    if(hfa_os_unlikely(!sz)){
        hfa_err(CVM_HFA_EINVALARG, ("Input size can't be Zero\n"));
        return HFA_FAILURE;
    }
    if(HFA_IS_MEM_NOT_ALIGNED(addr)){
        hfa_err(CVM_HFA_EALIGNMENT, ("Input Memory address is not Aligned\n"));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
    if(pclust->pool.pmemlist){
        hfa_err(CVM_HFA_EMEMEXIST, 
            ("cl: %d memlist already setup\n", pclust->s.clust_num));
        return HFA_FAILURE;
    }
    retval = hfa_memlist_setup(&(pclust->pool.pmemlist), addr, sz);
    if(HFA_SUCCESS == retval){
        pclust->s.memsize = sz;
        pclust->s.memaddr = addr;
    }
    hfa_display_cluster_info("SetMem", pclust->s.punit, pclust->s.clust_num);

    return (retval);
}
/**
 * Each HFA cluster has predefined cache size and addresses
 * to be used by cluster for graph cache load
 * @b Implicitly called by hfa_cluster_init() during hfa_dev_init()
 *
 * @param   pclust  Pointer to Cluster pointer
 * @param   cacheno Cacheno {0, 1, 2}
 * @param   addr    uint64_t Cache memory address
 * @param   sz      uint64_t Cache Memory Size
 *
 * @return  HFA_SUCCESS if success and HFA_FAILURE otherwise 
 */
hfa_return_t
hfa_cluster_setcache(hfa_cluster_t *pclust, hfa_size32_t cacheno,
        hfa_addr_t addr, hfa_size_t sz)
{
    hfa_dbg("pclust: %p, cno: %d, addr:%lu, sz:%lu\n", 
                         pclust, cacheno, addr, sz);
    if(hfa_os_unlikely(!sz)){
        hfa_err(CVM_HFA_EINVALARG, ("Size can't be Zero\n"));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(cacheno >= HFA_MAX_CACHE_PER_CLUSTER)){
        hfa_err(CVM_HFA_EINVALARG, ("Invalid cacheno: %u\n", cacheno));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
    if(pclust->pool.pclist[cacheno]){
        hfa_err(CVM_HFA_ECEXIST, 
           ("cl: %d's clist %d already setup\n", pclust->s.clust_num, cacheno));
        return HFA_FAILURE;
    }
    return(hfa_memlist_setup(&(pclust->pool.pclist[cacheno]), addr, sz));
}
/**
 * Counterpart of hfa_cluster_setmem().
 * Frees Memory pool for cluster. Application can then free memory
 * provided in hfa_cluster_setmem().
 * This routine is called by hfa_cluster_cleanup().
 *
 * @param   pclust  Pointer to cluster
 * @return  HFA_SUCCESS when success and failure otherwise
 */
hfa_return_t
hfa_cluster_cleanupmem(hfa_cluster_t *pclust)
{
    hfa_dbg("pclust: %p\n", pclust);

    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
    return(hfa_memlist_cleanup(&((pclust->pool).pmemlist)));
}
/**
 * Frees Cache pool for cluster. @b Implicitly called by hfa_cluster_cleanup()
 * during hfa_dev_cleanup().
 *
 * @param   pclust      Pointer to Cluster 
 * @param   cacheno     Cache Number
 */
hfa_return_t
hfa_cluster_cleanupcache(hfa_cluster_t *pclust, hfa_size32_t cacheno)
{
    hfa_dbg("pclust: %p, cache_no: %d\n", pclust, cacheno);

    if(hfa_os_unlikely (cacheno >= HFA_MAX_CACHE_PER_CLUSTER)){
        hfa_err(CVM_HFA_EINVALARG, ("Invalid cacheno: %u\n", cacheno));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
    return(hfa_memlist_cleanup(&((pclust->pool).pclist[cacheno])));
}
/**
 * @cond EXTERNAL_NOTYET
 * Gets required size of memory from the memory pool setup by 
 * hfa_cluster_setmem() for the cluster
 *
 * @param   pclust  Pointer to Cluster 
 * @param   sz      Size of the buffer
 * @param   paddr   address of buffer (uint64_t)
 *
 * @return  HFA_SUCCESS if buffer provided, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_memalloc(hfa_cluster_t *pclust, hfa_size_t sz, hfa_addr_t *paddr)
{
    hfa_dbg("pclust: %p, paddr:%p, sz:%lu\n", pclust, paddr, sz);

#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely((NULL == paddr) || (!sz))){
        hfa_err(CVM_HFA_EINVALARG, ("Paddr :%p, sz:%lu\n", paddr, sz));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return (__hfa_cluster_alloc(pclust->pool.pmemlist, paddr, sz, HFA_TRUE, 1));
}
/**
 * Gets required size of buffer from the cache memory pool setup by 
 * hfa_cluster_setcache() for the cluster
 *
 * @param   pclust      Pointer to Cluster 
 * @param   cacheno     cache number
 * @param   sz          Size of the buffer
 * @param   paddr       address of buffer (uint64_t)
 *
 * @return  HFA_SUCCESS if buffer provided, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_cachealloc(hfa_cluster_t *pclust, hfa_size32_t cacheno, 
                                  hfa_size_t sz, hfa_addr_t *paddr)
{
    hfa_dbg("pclust: %p, cno: %d, paddr: %p, sz:%lu\n", 
                             pclust, cacheno, paddr, sz);
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely((NULL == paddr) || (!sz))){
        hfa_err(CVM_HFA_EINVALARG, ("Paddr :%p, sz:%lu\n", paddr, sz));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (cacheno >= HFA_MAX_CACHE_PER_CLUSTER)){
        hfa_err(CVM_HFA_EINVALARG, ("Invalid cacheno: %u\n", cacheno));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_cluster_alloc(pclust->pool.pclist[cacheno],paddr,sz,1, 1));
}
/**
 * Reallocation of memory buffer and mark refcnt > 1
 *
 * @param   pclust      Pointer to Cluster 
 * @param   sz          Size of the buffer
 * @param   paddr       address of buffer (uint64_t)
 * @param   refcnt      uint32_t Initial refcnt for memnode
 *
 * @return  HFA_SUCCESS if buffer provided, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_memcalloc(hfa_cluster_t *pclust, hfa_size_t sz, hfa_addr_t *paddr, 
                      uint32_t refcnt)
{
    hfa_dbg("pclust: %p, sz:%lu, paddr; %p\n", pclust, sz, paddr);

#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely((NULL == paddr) || (!sz) || (!refcnt) || 
                       (refcnt > hfa_get_max_clusters()))){
        hfa_err(CVM_HFA_EINVALARG, ("Paddr :%p, sz:%lu, refcnt:%d\n", 
                                    paddr, sz, refcnt));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_cluster_alloc(pclust->pool.pmemlist, paddr, sz, 1, refcnt));
}
/**
 * Allocation of cache buffer and initialize node with provided refcnt
 *
 * @param   pclust      Pointer to Cluster 
 * @param   cacheno     Cache Number 
 * @param   sz          Size of the buffer
 * @param   paddr       address of buffer (uint64_t)
 * @param   refcnt      uint32_t Initial refcnt for memnode
 *
 * @return  HFA_SUCCESS if buffer provided, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_cachecalloc(hfa_cluster_t *pclust, hfa_size32_t cacheno, 
                        hfa_size_t sz, hfa_addr_t *paddr, uint32_t refcnt)
{
    hfa_dbg("pclust: %p, cno: %d, paddr: %p, sz:%lu, refcnt: %d\n", 
                             pclust, cacheno, paddr, sz, refcnt);
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely((NULL == paddr) || (!sz)||  (!refcnt) ||
                       (refcnt > hfa_get_max_clusters()))){
        hfa_err(CVM_HFA_EINVALARG, ("Paddr :%p, sz: %lu, refcnt: %u\n", 
                                    paddr, sz, refcnt));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (cacheno >= HFA_MAX_CACHE_PER_CLUSTER)){
        hfa_err(CVM_HFA_EINVALARG, ("Invalid cacheno: %u\n", cacheno));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif
    return(__hfa_cluster_alloc(pclust->pool.pclist[cacheno],paddr,sz,1,refcnt));
}
/**
 * Reallocation of memory buffer
 *
 * @param   pclust      Pointer to Cluster 
 * @param   sz          Size of the buffer
 * @param   paddr       address of buffer (uint64_t)
 *
 * @return  HFA_SUCCESS if buffer provided, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_memrealloc(hfa_cluster_t *pclust, hfa_size_t sz, hfa_addr_t *paddr)
{
    hfa_dbg("pclust: %p, sz:%lu, paddr; %p\n", pclust, sz, paddr);

#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely((NULL == paddr) || (!sz))){
        hfa_err(CVM_HFA_EINVALARG, ("Paddr :%p, sz:%lu\n", paddr, sz));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_cluster_realloc(pclust->pool.pmemlist, paddr, sz));
}
/**
 * Reallocation of memory buffer
 *
 * @param   pclust      Pointer to Cluster 
 * @param   cacheno     cache number
 * @param   sz          Size of the buffer
 * @param   paddr       address of buffer (uint64_t)
 *
 * @return  HFA_SUCCESS if buffer provided, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_cacherealloc(hfa_cluster_t *pclust, hfa_size32_t cacheno, 
                                      hfa_size_t sz, hfa_addr_t *paddr)
{
    hfa_dbg("pclust: %p, cno: %d, sz:%lu, paddr; %p\n", 
                                 pclust, cacheno, sz, paddr);
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely((NULL == paddr) || (!sz))){
        hfa_err(CVM_HFA_EINVALARG, ("Paddr :%p, sz:%lu\n", paddr, sz));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely (cacheno >= HFA_MAX_CACHE_PER_CLUSTER)){
        hfa_err(CVM_HFA_EINVALARG, ("Invalid cacheno: %u\n", cacheno));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_cluster_realloc(pclust->pool.pclist[cacheno],paddr,sz));
}
/**
 * Returns memory buffer to cluster. Counterpart API of 
 * hfa_cluster_memalloc()
 *
 * @param   pclust      Pointer to Cluster 
 * @param   addr        address of buffer (uint64_t) to free
 *
 * @return  HFA_SUCCESS if buffer freed, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_memfree(hfa_cluster_t *pclust, hfa_addr_t addr)
{ 
    hfa_dbg("pclust: %p, addr; 0x%lx\n", pclust, addr);

    /*Note - addr can be Zero also*/
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_cluster_memfree(pclust->pool.pmemlist, addr));
}
/**
 * Returns memory buffer to cluster. Counterpart API of 
 * hfa_cluster_memalloc()
 *
 * @param   pclust      Pointer to Cluster 
 * @param   cno         cache number
 * @param   addr        address of buffer (uint64_t) to free
 *
 * @return  HFA_SUCCESS if buffer freed, HFA_FAILURE otherwise
 */
hfa_return_t
hfa_cluster_cachefree(hfa_cluster_t *pclust,hfa_size32_t cno, hfa_addr_t addr)
{
    hfa_dbg("pclust: %p, cno: %d, addr; 0x%lx\n", pclust, cno, addr);

    /*Note - addr can be Zero also*/
#ifdef HFA_STRICT_CHECK    
    if(hfa_os_unlikely (cno >= HFA_MAX_CACHE_PER_CLUSTER)){
        hfa_err(CVM_HFA_EINVALARG, ("Invalid cacheno: %u\n", cno));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(pclust))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Invalid cluster state\n"));
        return HFA_FAILURE;
    }
#endif    
    return(__hfa_cluster_memfree(pclust->pool.pclist[cno], addr));
}
/**@endcond*/
/**
 * This routine allows multiple clusters to share the same HFA memory block for
 * loading graphs. This facilitates sharing of graphs among clusters.
 * 
 * See hfa_cluster_init() and hfa_cluster_setmem() for more information.
 *
 * @param   powner  Cluster which already owns Memory pools
 * @param   psharer Cluster who needs to share resources with the owner
 *
 * @return  HFA_SUCCESS if sharing succeed, HFA_FAILURE otherwise
 */
hfa_return_t 
hfa_cluster_share_mem(hfa_cluster_t *powner, hfa_cluster_t *psharer)
{
    hfa_memlist_t   *pmlist = NULL;
    hfa_clmsk_t     bitmsk;
    hfa_size32_t    clno1=0, clno2=0;

    hfa_dbg("powner: %p, psharer: %p\n", powner, psharer);

    if(hfa_os_unlikely(powner == psharer)){
        hfa_err(CVM_HFA_ENOPERM, ("Cluster powner:%p, pshare:%p are same\n", 
                                                 powner, psharer));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(powner))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Inval. state of owner:%p\n", powner));
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely(HFA_SUCCESS != hfa_cluster_isinit(psharer))){
        hfa_err(CVM_HFA_EINVAL_CLSTATE, ("Inval. state of owner:%p\n",psharer));
        return HFA_FAILURE;
    }
    pmlist = powner->pool.pmemlist;

    if (hfa_os_unlikely(NULL == pmlist)){
        hfa_err(CVM_HFA_EINVALARG, ("Owner memlist is Empty\n"));
        return HFA_FAILURE;
    }
    if (hfa_os_unlikely(psharer->pool.pmemlist != NULL)){
        hfa_err(CVM_HFA_EMLOAD, ("Sharer already has Memlist\n")); 
        return HFA_FAILURE;
    }
    /*Memory can be shared during initial stage only
     * Sharing will fail if owner has done any graph load
     */
    if(!(hfa_os_listempty(&(pmlist->alist)))){
        hfa_err(CVM_HFA_ENOPERM, ("Sharing not allowed as Owner has" \
                                 " non-empty alist\n"));
        return (HFA_FAILURE);
    }
    hfa_os_wlock(&(pmlist->lock));
    psharer->pool.pmemlist = pmlist;
    (pmlist->list_refcnt)++;
    hfa_os_wunlock(&(pmlist->lock)); 

    /*Transitive share: If cluster 0 shared to cl1
     * and cl1 shared to cl2 then cl0 should share to cl2*/
    hfa_cluster_getnumber(powner, &clno1);
    hfa_cluster_getnumber(psharer, &clno2);
    bitmsk = (1 << clno1) | psharer->s.memshare_msk | powner->s.memshare_msk |
             (1 <<clno2);
    hfa_cluster_set_memshare_msk (powner->s.punit, bitmsk);
    psharer->s.memsize = powner->s.memsize;
    psharer->s.memaddr = powner->s.memaddr;
    hfa_display_cluster_info("Sharing", psharer->s.punit, 
                              psharer->s.clust_num);
    return HFA_SUCCESS;
}
/**
 * Returns a copy of a cluster of the HFA device. This can be used to obtain the
 * cluster initialized by hfa_dev_init() or subsequently by the application.
 * The cluster properties can be altered and reassigned the HFA device using
 * hfa_cluster_init().
 *
 * See hfa_cluster_init() for more information on cluster properties.
 * Reference applications hfa-se-async.c and hfa-lnx-async.c demonstrate usage
 * of this API.
 *
 * @param   pdev        Device pointer
 * @param   ppcluster   Variable where cluster pointer is written by API
 * @param   cl_no       Cluster number
 *
 * @return   HFA_SUCCESS, HFA_FAILURE
 */
hfa_return_t 
hfa_get_cluster(hfa_dev_t *pdev, hfa_cluster_t **ppcluster, uint32_t cl_no)
{
    if(hfa_os_unlikely((NULL == pdev) || NULL == ppcluster || 
                (cl_no >= hfa_get_max_clusters()))){
        hfa_err(CVM_HFA_EINVALARG,("Invalid arg: dev: %p, ppclus: %p, cl: %u\n",
                                   pdev, ppcluster, cl_no));
        return (HFA_FAILURE);
    }
    if(hfa_os_unlikely(HFA_DEV_INITDONE != hfa_isdevinit)){
        hfa_err(CVM_HFA_EDEVINITPEND,("hfa_dev_init() not performed\n"));
        return HFA_FAILURE;
    }
    *ppcluster = pdev->punit->pclust[cl_no];
    if(hfa_os_likely(*ppcluster)){
        return(HFA_SUCCESS);
    }
    return(HFA_FAILURE);
}
/**
 * The HFA device consists of one or more clusters. A Cluster is a work unit of
 * the HFA engine, which has access to the graph in HFA memory and has a
 * built-in cache for the frequently accessed graph-nodes. Every HFA Cluster
 * needs memory resources to load graphs. Clusters can point to independent or
 * shared HFA memory locations. Currently each Cluster comes with its own cache,
 * which cannot be shared with other clusters.
 *
 * CN63xx and CN66xx devices have designated HFA memory, while CN61xx and
 * CN68xx devices require DDR memory to be reserved for use as HFA memory.
 * CN68xx is the only device to have multiple clusters(3 clusters).
 *
 * hfa_dev_init() allocates and assigns memory resources to each available
 * cluster. Memory resources in 63xx/66xx are setup from designated memory.
 * The hfa_dev_get_memaddr() and hfa_dev_get_memsize() routines provide details
 * of these settings. 
 *
 * In case of CN68xx, hfa_dev_init() allocates one named block @ref
 * HFA_MEMORY_NB and shares it among all 3 clusters. This is done using
 * hfa_cluster_setmem() and hfa_cluster_share_mem() routines.
 *
 * Applications can alter the cluster memory resource assignment to point to
 * different memory blocks. Before doing this application should cleanup
 * existing resource allocations using hfa_cluster_cleanup(). In case of
 * CN61xx/CN68xx the application should also free or reuse @ref HFA_MEMORY_NB
 * named block. 
 *
 * After cleaning up the cluster resources, application will be responsible for
 * memory allocation, assigning it to cluster and subsequent deallocation of the
 * allocted memory.
 *
 * This routine initializes the cluster. It is called by hfa_dev_init() for all
 * clusters present in the device. This routine configures cache memory pool.
 * The HFA memory pool should be configured subsequently using
 * hfa_cluster_setmem(). 
 *
 * The clusters must be properly loaded before calling any HFA graph management
 * API.
 *
 * @param   pdev        Pointer to device
 * @param   pclust      Pointer to cluster
 * @param   clno        Cluster number
 *
 * @return HFA_SUCCESS if init successful, HFA_FAILURE otherwise 
 */
hfa_return_t 
hfa_cluster_init(hfa_dev_t *pdev, hfa_cluster_t *pclust, uint32_t clno)
{
    uint32_t                i;
    hfa_devinfo_t           *pdinfo = NULL;
    struct cvmx_sysinfo     *sysinfo ;
    uint32_t                retval=0;

    hfa_dbg("Pdev: %p, pclust: %p, clno:%d\n", pdev, pclust, clno);
    if(hfa_os_unlikely (HFA_DEV_INITDONE != hfa_isdevinit)){
        hfa_err(CVM_HFA_EDEVINITPEND, ("hfa_dev_init() not performed\n")); 
        return HFA_FAILURE;
    }
    if(hfa_os_unlikely((NULL == pdev) || (NULL == pclust)|| 
                        (clno >= hfa_get_max_clusters()))){ 
        hfa_err(CVM_HFA_EINVALARG,("Invalid arg dev: %p, clust: %p,clno: %u\n",
                                               pdev, pclust, clno));
        return (HFA_FAILURE);
    }
    /*Checkif cluster init is already done or not*/
    if(HFA_CLUSTER_INITDONE == hfa_clust_init[clno]){
        hfa_err(CVM_HFA_ECEXIST,
             ("Permission denied: Clust: %d already initialized\n", clno)); 
        return HFA_FAILURE;
    }
    /*Mark initialized to avoid further initializations*/
    hfa_clust_init[clno] = HFA_CLUSTER_INITDONE;

    memset(pclust, 0, sizeof(hfa_cluster_t));
    sysinfo = cvmx_sysinfo_get();
    pdinfo = &(pdev->devinfo);

    /*Link cluster to unit*/
    HFA_PSET(pdev, punit, pclust[clno], pclust);

    /*Initialize default data members*/
    HFA_SET(pclust, s, clust_num, clno);
    HFA_SET(pclust, s, punit, pdev->punit);
    HFA_SET(pclust, s, cacheshare_msk, 0);
    HFA_SET(pclust, s, memshare_msk, 0);
    hfa_cluster_init_pcload_lock(pdev, pclust);
    /*By default set all coremask*/
    hfa_cluster_set_coremask(pclust, sysinfo->core_mask);

    /*Initialize Cache Pool but MEM Pool to be initalized by 
     * user using hfa_cluster_set_mem() or hfa_cluster_share_mem()
     * */
    for(i = 0; i < HFA_MAX_CACHE_PER_CLUSTER; i++) {
        retval |= hfa_cluster_setcache(pclust, i, pdinfo->cinfo[i].addr,
                                                  pdinfo->cinfo[i].size); 
    }
    if(retval)
        return (HFA_FAILURE);
    else
        return HFA_SUCCESS;
}
/**
 * Cleanup Cluster. It is called by hfa_dev_cleanup() for all clusters
 * present in the device. It cleans up cache as well memory resources. This
 * routine is the counterpart of hfa_cluster_init().
 *
 * @param   pclust      Pointer to cluster
 *
 * @return HFA_SUCCESS if cleanup successful, HFA_FAILURE otherwise 
 */
hfa_return_t
hfa_cluster_cleanup(hfa_cluster_t *pclust)
{
    int             retval = 0;
    int             cnt;
    uint32_t        clno=0;

    hfa_dbg("%p\n", pclust);
    if (hfa_os_unlikely(HFA_SUCCESS != __hfa_cluster_getnum(pclust, &clno))){
        hfa_err(CVM_HFA_ENOPERM, ("__hfa_cluster_getnum error\n"));
        return HFA_FAILURE;
    }
    hfa_dbg("Cleaning up resources for Cl: %d\n", clno);
    /*Deallocate hfa_mempool_t*/
    retval |= hfa_cluster_cleanupmem(pclust);
    for(cnt=0; cnt<HFA_MAX_CACHE_PER_CLUSTER; cnt++){
        retval |= hfa_cluster_cleanupcache(pclust, cnt);
    }
    /* If cluster initialized by hfa_dev_init() then free it
     * otherwise application will take care of cluster pointer*/
    if(HFA_CLUSTER_INIT_BYAPI == hfa_isclustinit_byapi[clno]){
        hfa_os_free((pclust->s.punit)->pclust[clno], sizeof(hfa_cluster_t));
        hfa_isclustinit_byapi[clno]=0;
    }
    hfa_cluster_unset_memshare_msk(pclust->s.punit, clno);
    pclust->s.memsize = 0 ;
    pclust->s.memaddr = 0;
#ifdef HFA_DEBUG    
    hfa_display_cluster_info("Cleanup", pclust->s.punit, clno);
#endif    
    (pclust->s.punit)->pclust[clno] = NULL;
    /*Set unit pointer to NULL*/
    if(retval){
        return(HFA_FAILURE);
    }
    hfa_clust_init[clno]=0;
    return(HFA_SUCCESS);
}
/**@cond INTERNAL*/
#ifdef KERNEL
EXPORT_SYMBOL (hfa_cluster_init);
EXPORT_SYMBOL (hfa_cluster_cleanup);
EXPORT_SYMBOL (hfa_cluster_setmem);
EXPORT_SYMBOL (hfa_cluster_cleanupmem);
EXPORT_SYMBOL (hfa_cluster_setcache);
EXPORT_SYMBOL (hfa_cluster_cleanupcache);
EXPORT_SYMBOL (hfa_cluster_memalloc);
EXPORT_SYMBOL (hfa_cluster_memrealloc);
EXPORT_SYMBOL (hfa_cluster_memfree);
EXPORT_SYMBOL (hfa_cluster_cachealloc);
EXPORT_SYMBOL (hfa_cluster_cacherealloc);
EXPORT_SYMBOL (hfa_cluster_cachefree);
EXPORT_SYMBOL (hfa_cluster_share_mem);
EXPORT_SYMBOL (hfa_get_cluster);
#endif
/**@endcond*/
