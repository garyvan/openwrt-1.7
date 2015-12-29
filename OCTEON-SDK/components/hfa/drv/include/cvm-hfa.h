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
 * This is header file for device related macros and APIs
 *
 */
#ifndef _CVM_HFA_H_
#define _CVM_HFA_H_

#include "cvm-hfa-common.h"

/**HFA SDK version*/
#define HFA_VERSION                 "OCTEON-HFA-SDK-3.1.0-10"

/**HFA graph memory named block */
#define HFA_MEMORY_NB               "hfamemory"
/**HFA SDK arena memory named block */
#define HFA_ARENA_NB                "hfaarena"

/** @cond INTERNAL */
#define HFA_IS_MEM_NOT_ALIGNED(x)   _HFA_ISMEM_NOTALIGNED(x,hfa_get_mem_align())
#define HFA_CLUSTER_INIT_BYAPI      0xA5A5

struct hfa_cluster;
struct hfa_dev;
/** @endcond */

/**
 * Memory Chunk attributes
 */
typedef struct {
        /**Address of Chunk*/
        hfa_addr_t              addr;
        /**Size of Chunk*/
        hfa_size_t              size;
} hfa_memchunk_t;

/**
 * HFA Device Info
 */
typedef struct {
    /**Flag to indicate HFA block has its own memory or not*/
    hfa_bool_t              hwhasownmem;
 
    /**Device name*/
    char                    name[HFA_MAXNAMELEN];

    /**Number of Clusters*/
    hfa_size32_t            nclusters;

    /**Bitmask representing each cluster configured in device
     * Currently only 3 least significant bits valid**/
    hfa_clmsk_t             clmsk;
    /**Chip Id of processor*/
    octeon_chipid_t         chipid;

    /**Pass Version*/
    board_pass_t            pass;

    /**Memory attributes allocted to dev*/
    hfa_memchunk_t          minfo;

    /**Cache attributes to this device*/
    hfa_memchunk_t          cinfo[HFA_MAX_CACHE_PER_CLUSTER]; 
    
    /**Used to align mbase depending on OCTEON board */
    int                     mbasealignbits;
} hfa_devinfo_t;

/**
 * @cond INTERNAL 
 * Private data members of hfa_unit_t
 */
typedef struct {
    /**Back Pointer to Device*/
    struct hfa_dev    *pdev;
    /**Lock to guard Cache Load instruction*/
    hfa_os_rwlock_t   cload_lock; 
}hfa_unit_priv_t;
/**@endcond*/
/**
 * @cond INTERNAL  
 * One HFA device has unit and each unit
 * has one or more clusters
 */
typedef struct {
    /**Private Data Structure*/
    hfa_unit_priv_t      s;

    /**Pointer to each Cluster*/
    struct hfa_cluster   *pclust[HFA_MAX_NCLUSTERS]; 
} hfa_unit_t;
/**@endcond*/

/**
 * HFA Device Structure
 */
typedef struct hfa_dev {
    /**Pointer to HFA unit - maintained internally*/
    hfa_unit_t         *punit;

    /**HFA Devinfo*/
    hfa_devinfo_t      devinfo;
} hfa_dev_t;

/* Static Inline Functions */

/**
 * @cond INTERNAL
 * Tells whether OCTEON chip has HFA block
 *
 * @return Success if chip has HFA support, Failure otherwise
 */
static inline 
hfa_return_t hfa_is_supported(void)
{
    if(octeon_has_feature(OCTEON_FEATURE_HFA))
        return HFA_SUCCESS;
    else
        return HFA_FAILURE;
}
/**
 * Returns number of HTE in OCTEON CHIP
 *
 * @return  Number of HTEs
 */
static inline hfa_nhtes_t
hfa_get_max_htes(void)
{
    switch(OCTEON_HFA_CHIP()){
        case OCTEON_HFA_CN63XX_CID:
            return (HFA_CN63XX_HTES);
        break;
        case OCTEON_HFA_CN66XX_CID:
            return (HFA_CN66XX_HTES);
        break;
        case OCTEON_HFA_CN68XX_CID:
            return (HFA_CN68XX_HTES);
        break;
        case OCTEON_HFA_CN61XX_CID:
            return (HFA_CN61XX_HTES);
        break;
        case OCTEON_HFA_CN70XX_CID:
            return (HFA_CN70XX_HTES);
        break;
        default:
            return (HFA_ZERO_HTES);
    }
}
/**
 * Returns number of cluster supported in OCTEON
 *
 * @return  Number of clusters
 */
static inline hfa_clusters_t
hfa_get_max_clusters(void)
{
    switch(OCTEON_HFA_CHIP()){
        case OCTEON_HFA_CN63XX_CID:
            return (HFA_CN63XX_NCLUSTERS);
        break;
        case OCTEON_HFA_CN66XX_CID:
            return (HFA_CN66XX_NCLUSTERS);
        break;
        case OCTEON_HFA_CN68XX_CID:
            return (HFA_CN68XX_NCLUSTERS);
        break;
        case OCTEON_HFA_CN61XX_CID:
            return (HFA_CN61XX_NCLUSTERS);
        break;
        case OCTEON_HFA_CN70XX_CID:
            return (HFA_CN70XX_NCLUSTERS);
        break;
        default:
            return (HFA_ZERO_CLUSTERS);
    }
}
/**
 * Provided max cluster mask for HFA Unit
 *
 * clmsk[bit0]: Cluster 0
 * clmsk[bit1]: Cluster 1
 * clmsk[bit2]: Cluster 2
 *
 * @return  cluster mask for the chip
 */
static inline hfa_clusters_t
hfa_get_max_clmsk(void)
{
    switch(OCTEON_HFA_CHIP()){
        case OCTEON_HFA_CN68XX_CID:
            return HFA_68XX_MAX_CLMSK;
        break;

        default:
            return HFA_63XX_MAX_CLMSK;
    }
}
/** @endcond */
/**
 * Indicates whether device has its own HFA memory. hfa_dev_getdevinfo() should
 * be called before this routine.
 *
 * @param   pdev    Pointer to device
 * @return  1 if present, 0 otherwise
 */
static inline hfa_bool_t 
hfa_dev_haspvt_hfamemory (hfa_dev_t  *pdev)
{
    if(hfa_os_likely(pdev)){
        return (pdev->devinfo.hwhasownmem);
    } else {
        switch(OCTEON_HFA_CHIP()){
            case OCTEON_HFA_CN63XX_CID:
            case OCTEON_HFA_CN66XX_CID:
                return(HFA_TRUE);
            break;
            default:
                return(HFA_FALSE);
        }
    }
}
/**
 * Get Device Name. hfa_dev_getdevinfo() must be called before calling this
 * routine.
 *
 * @param   pdev    Pointer to device
 * @return  char *  String pointer
 */
static inline const char *
hfa_dev_getname(hfa_dev_t *pdev)
{
    if(hfa_os_likely(pdev)){
        char *name = (char *) pdev->devinfo.name;
        return (name);
    }
    return NULL;
}
/**
 * Returns number of clusters configured in device. hfa_dev_getdevinfo() should
 * be called before this routine.
 *
 * @param   pdev        Pointer to Device
 * @return  uint32_t    Number of clusters configured in dev
 */
static inline uint32_t 
hfa_dev_get_nclusters(hfa_dev_t *pdev)
{
    if(hfa_os_likely(pdev))
        return(pdev->devinfo.nclusters);
    else 
        return (hfa_get_max_clusters());
}
/**
 * Returns Cluster Bit Mask configured for device. hfa_dev_getdevinfo() should
 * be called before this routine.
 *
 * @param   pdev        Pointer to Device
 * @return  hfa_clmsk_t ClusterMask
 */
static inline hfa_clmsk_t
hfa_dev_get_clmsk(hfa_dev_t *pdev)
{
    if(hfa_os_likely(pdev))
        return(pdev->devinfo.clmsk);
    else
        return (hfa_get_max_clmsk()); 
}
/**
 * Returns configured memory address in device. hfa_dev_getdevinfo() should be
 * called before this routine.
 *
 * @param   pdev        Pointer to Device
 * @return  hfa_addr_t  64 bit long address
 */
static inline hfa_addr_t 
hfa_dev_get_memaddr(hfa_dev_t *pdev)
{
    hfa_devinfo_t *pdinfo = NULL;
    if(hfa_os_likely(pdev)){
        pdinfo = &(pdev->devinfo);
        return(pdinfo->minfo.addr);
    }
    return 0;
}
/**
 * Returns configured memory size in device. hfa_dev_getdevinfo() should be
 * called before this routine.
 *
 * @param   pdev        Pointer to Device
 * @return  hfa_size_t  64 bit long size
 */
static inline hfa_size_t 
hfa_dev_get_memsize(hfa_dev_t *pdev)
{
    hfa_devinfo_t *pdinfo = NULL;
    if(hfa_os_likely(pdev)){
        pdinfo = &(pdev->devinfo);
        return(pdinfo->minfo.size);
    }
    return 0;
}
/**
 * Returns configured cache address in device. hfa_dev_getdevinfo() should be
 * called before this routine.
 *
 * @param   pdev        Pointer to Device
 * @param   cno         Cacheno;
 * @return  hfa_addr_t  64 bit long address
 */
static inline hfa_addr_t 
hfa_dev_get_cacheaddr(hfa_dev_t *pdev, uint32_t cno)
{
    hfa_devinfo_t *pdinfo = NULL;
    if(hfa_os_likely(pdev)){
        pdinfo = &(pdev->devinfo);
        return(pdinfo->cinfo[cno].addr);
    }
    return 0;
}
/**
 * Returns configured cache size in dev. hfa_dev_getdevinfo() must be called
 * before calling this routine.
 *
 * @param   pdev        Pointer to Device
 * @param   cno         Cacheno;
 * @return  hfa_size_t  64 bit long size
 */
static inline hfa_size_t 
hfa_dev_get_cachesize(hfa_dev_t *pdev, uint32_t cno)
{
    hfa_devinfo_t *pdinfo = NULL;

    if(hfa_os_likely(pdev)){
        pdinfo = &(pdev->devinfo);
        return(pdinfo->cinfo[cno].size);
    }
    return 0;
}
/**
 * @cond INTERNAL
 * Returns memory alignment required for OCTEON HFA
 *
 * @return  hfa_size_t    Alignment
 */
static inline hfa_size_t 
hfa_get_mem_align(void)
{
    uint64_t    align;

    switch(OCTEON_HFA_CHIP()){
        case OCTEON_HFA_CN68XX_CID:
        case OCTEON_HFA_CN61XX_CID:
        case OCTEON_HFA_CN70XX_CID:
            align = HFA_68XX_MEM_ALIGNMENT;
        break;

        case OCTEON_HFA_CN63XX_CID:
        case OCTEON_HFA_CN66XX_CID:
            align   = HFA_63XX_MEM_ALIGNMENT;
        break;

        default:
            align = HFA_INVALID_ALIGNMENT;
    }
    return(align);
}

/*Function Prototypes*/
int cvm_hfa_set_fnp_ppalloc (hfa_fnp_ppalloc_cb_t);
int cvm_hfa_set_fnp_ppfree (hfa_fnp_ppfree_cb_t );
int cvm_hfa_set_fnp_ppsize (hfa_fnp_ppsize_cb_t );

int cvm_hfa_set_fnp_pptalloc (hfa_fnp_ppalloc_cb_t);
int cvm_hfa_set_fnp_pptfree (hfa_fnp_ppfree_cb_t );
int cvm_hfa_set_fnp_pptsize (hfa_fnp_ppsize_cb_t );

int cvm_hfa_set_fnp_ppmatchalloc (hfa_fnp_ppalloc_cb_t);
int cvm_hfa_set_fnp_ppmatchfree (hfa_fnp_ppfree_cb_t );
int cvm_hfa_set_fnp_ppmatchsize (hfa_fnp_ppsize_cb_t );

hfa_return_t hfa_dev_init (hfa_dev_t *pdev);
hfa_return_t hfa_dev_cleanup (hfa_dev_t *pdev);
void hfa_dev_getdevinfo(hfa_devinfo_t *pdevinfo);
int hfa_dev_submitasync (hfa_dev_t *pdev, hfa_instr_t *pinstr);
int hfa_dev_getasyncstatus (hfa_dev_t *pdev, volatile hfa_rmdata_t *rmdata);
int hfa_dev_submit (hfa_dev_t *pdev, hfa_instr_t *instr);
void hfa_dev_display_info(hfa_devinfo_t *pdinfo);
hfa_return_t
hfa_create_fpa_pool (hfa_size_t , const char *, hfa_size_t ,hfa_size_t ,int *);
/* defined in cvm-hfa-sim.h for simulator */
#ifndef HFA_SIM
hfa_return_t
hfa_find_named_block(const char *, void **, hfa_size_t *, uint64_t );
hfa_return_t hfa_free_named_block(const char *name);
#endif
hfa_return_t hfa_set_fpapools_cnt(uint64_t, uint64_t, uint64_t);

/** @endcond INTERNAL */
#endif /* _CVM_HFA_H_ */
