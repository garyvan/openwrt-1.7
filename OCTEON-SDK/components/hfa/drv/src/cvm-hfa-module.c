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
 * This file creates HFA kernel module to allow interface to HFA APIs
 */
#include <cvm-hfa-common.h>
#include <cvm-hfa-module.h>
#include <cvm-hfa.h>
#include <cvm-hfa-stats.h>

/**Name of the HFA Kernel module*/
#define HFA_LIB_MODULE             "cvm-hfa-lib"

MODULE_AUTHOR ("cavium networks");
MODULE_DESCRIPTION (HFA_LIB_MODULE "OCTEON-II/III HFA Library");
MODULE_LICENSE ("Cavium");

/** hfa_mem_nb_name */
char    * hfa_mem_nb_name = HFA_MEMORY_NB;
module_param (hfa_mem_nb_name, charp, 0444);
MODULE_PARM_DESC (hfa_mem_nb_name, "Named block reserving HFA memory");

/** HFA temp buffers count*/
int    hfa_tbuf_cnt = 60000;
module_param (hfa_tbuf_cnt, int, 0444);
MODULE_PARM_DESC (hfa_tbuf_cnt, "OCTEON HFA temp buffer pool count");

/**
 * If HFA_MEMORY_NB named block is not allocated at uboot interface
 * hfa_dev_init() will try to allocate namedblock of size hfa_mem_sz
 */
int    hfa_mem_sz = 128;
module_param (hfa_mem_sz, int , 0444);
MODULE_PARM_DESC(hfa_mem_sz,"OCTEON HFA Memory in MB(68xx/61xx)");


/** HFA command buffers count*/
int    hfa_cmdbuf_cnt = 60000;
module_param (hfa_cmdbuf_cnt, int, 0444);
MODULE_PARM_DESC (hfa_cmdbuf_cnt, "OCTEON HFA command buffer pool count");

/** HFA PP buffers count (this is same as hfa_cmdbuf_cnt (by default)*/
int    hfa_ppbuf_cnt = 60000;
module_param (hfa_ppbuf_cnt, int, 0444);
MODULE_PARM_DESC (hfa_ppbuf_cnt, "PP buffer pool count");

/**POW WQE grp on which HFA NAPI will run. Only valid if hfa_distribute_load=0*/
int hfa_pow_receive_group = 14;
module_param(hfa_pow_receive_group, int, 0444);
MODULE_PARM_DESC(hfa_pow_receive_group, "\n"
    "\tPOW group to receive packets from");

int octeon_ethernet_driver_pow_group = 15;
module_param(octeon_ethernet_driver_pow_group, int, 0444);
MODULE_PARM_DESC(octeon_ethernet_driver_pow_group, "\n"
    "\tPOW group on which ethernet driver running");


/*If hfa_distribute_load==0, only one core* runs NAPI on WQE grp 
 * hfa_pow_receive_group, If hfa_distribute_load==1, hfa_max_napi_grps takes
 * part in NAPI, hfa_pow_rcv_grp[cvmx_get_core_num()] will tell on which WQE
 * grp current core is running NAPI*/
int hfa_distribute_load = 0;
module_param(hfa_distribute_load, int, 0444);
MODULE_PARM_DESC(hfa_distribute_load, "\n"
    "\tdecides the load balancing");

/**If hfa_distribute_load==1 then this variable indicated how many cores will
 * run NAPI. The core range is [0-hfa_max_napi_grps). hfa_max_napi_grps == 32 as
 * there are 0-31 max cores on 68xx and WQE grp 15 is registered for OCTEON
 * ethernet driver*/
int hfa_max_napi_grps = 32;
module_param(hfa_max_napi_grps, int, 0444);
MODULE_PARM_DESC(hfa_max_napi_grps, "\n"
"\tNumber of SSO WQE grps [0-32] participate (when hfa_distribute_load=1)");

/**NAPI weight*/
int hfa_rx_napi_weight=32;
module_param(hfa_rx_napi_weight, int, 0444);
MODULE_PARM_DESC(hfa_rx_napi_weight, "The NAPI Weight parameter");

/**If hfa_napi_perf==0, NAPI interface will not be initialized, if 1 NAPI
 * interface will be initialized*/
int hfa_napi_perf=0;
module_param(hfa_napi_perf, int, 0444);
MODULE_PARM_DESC(hfa_napi_perf, "decides napi initialization");

/** Absolute path to hfa_set_irq_affinity.sh  */
char    *hfa_set_irq_affinity_path = NULL;
module_param (hfa_set_irq_affinity_path, charp, 0444);
MODULE_PARM_DESC (hfa_set_irq_affinity_path, "\n"
                  "\tAbsolute path of a shell script which sets irq affinity");

/*Global pp variables*/
int                             hfa_ppbuf_pool;
int                             hfa_ppbuf_sz;
extern hfa_napi_interceptcb_t  hfa_napi_hwwqe_interceptcb;
extern hfa_napi_interceptcb_t  hfa_napi_packet_interceptcb;

/**
 * Basis on processor ID returns whether target has HFAmemory
 *
 * @return  1 if present, 0 othertwise
 */
static inline hfa_bool_t 
hfa_drv_ishwmemory(void)
{
    switch(OCTEON_HFA_CHIP()){
        case OCTEON_HFA_CN63XX_CID:
        case OCTEON_HFA_CN66XX_CID:
            return(HFA_TRUE);
        break;
        default:
            return(HFA_FALSE);
    }
}
/**
 * Check if ethernet driver present
 *
 * @return 1 if ethernetdrv present or 0 otherwise
 */
int
hfa_isethernetdrv_present(void)
{
    cvmx_ipd_ctl_status_t ipd_reg;
            
    ipd_reg.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
    if(!ipd_reg.s.ipd_en)
        return 0;

    return 1;
}
/**
 *  Register intercept callback for HFA HW WQE
 *
 *  Any WQE having unused field == HFA_SEARCH_HWWQE_UNUSED_FIELD is treated as
 *  HFA HW WQE. If hfa_napi_hwwqe_interceptcb is registered, the intercept cb 
 *  will be called with received WQE as an argument, otherwise received WQE
 *  will be freed
 *  
 *  The @b cb function pointer must return cvm_oct_callback_result type
 *  If CVM_OCT_TAKE_OWNERSHIP_WORK is not returned, delievered WQE will be 
 *  freed in the NAPI interface
 *
 *  @param  cb          Application callback
 *
 *  @return 0 for success, -1 otherwise;
 */
int
hfa_register_hwwqe_interceptcb (hfa_napi_interceptcb_t cb)
{
    hfa_napi_hwwqe_interceptcb = cb;
    wmb();
    return 0;
}
/**
 *  Register intercept callback for Network Packets
 *
 *  Any WQE whose unused field != HFA_SEARCH_HWWQE_UNUSED_FIELD is treated as
 *  Network Packets. If intercept cb is registered, cb will be called with 
 *  received WQE as an argument, otherwise received WQE will be freed.
 *  
 *  The @b cb function pointer must return cvm_oct_callback_result type
 *  If CVM_OCT_TAKE_OWNERSHIP_WORK is not returned, delievered WQE will be 
 *  freed in the NAPI interface
 *
*
 *  @param  cb          Application callback
 *
 *  @return 0 for success, -1 otherwise
 */
int
hfa_register_packet_interceptcb (hfa_napi_interceptcb_t cb)
{
    hfa_napi_packet_interceptcb = cb;
    wmb();
    return 0;
}

 /**
 * hfa_oct_fill_hw_memory - fill a hardware pool with memory.
 *
 * @param   pool        Pool to populate
 * @param   size        Size of each buffer in the pool
 * @param   elements    Number of buffers to allocate
 *
 * @return actual number of buffers allocated.
 */
int hfa_oct_fill_hw_memory(int pool, int size, int elements)
{
    char *memory;
    char *fpa;
    int freed = elements;

    while (freed) {
        /*
         * FPA memory must be 128 byte aligned.  Since we are
         * aligning we need to save the original pointer so we
         * can feed it to kfree when the memory is returned to
         * the kernel.
         *
         * We allocate an extra 256 bytes to allow for
         * alignment and space for the original pointer saved
         * just before the block.
         */
        memory = kmalloc(size + 256, GFP_KERNEL);
    
        if (unlikely(memory == NULL)) {
            pr_warning("Unable to allocate %u bytes for FPA pool %d\n",
                   elements * size, pool);
            break;
        }
#ifdef HFA_STATS
        /* Increment the memory counter of system memory to the allocated size */
        if(hfa_stats) {
            hfa_core_mem_stats_inc(sysmem, size+256);
        }
#endif
        fpa = (char *)(((unsigned long)memory + 256) & ~0x7fUL);
        *((char **)fpa - 1) = memory;
        cvmx_fpa_free(fpa, pool, 0);
        freed--;
    }
    return elements - freed;
}

/**
 * hfa_oct_free_hw_memory - Free memory allocated by cvm_oct_fill_hw_memory
 *
 * @param pool          FPA pool to free
 * @param size          Size of each buffer in the pool
 * @param elements      Number of buffers that should be in the pool
 */
void hfa_oct_free_hw_memory(int pool, int size, int elements)
{
    char *memory;
    char *fpa;

    do {
        fpa = cvmx_fpa_alloc(pool);
        if (fpa) {
            elements--;
            fpa = (char *)phys_to_virt(cvmx_ptr_to_phys(fpa));
            memory = *((char **)fpa - 1);
            kfree(memory);
        }
    } while (fpa);

    if (elements < 0)
        pr_warning("Freeing of pool %u had too many buffers (%d)\n",
            pool, elements);
    else if (elements > 0)
        pr_warning("Warning: Freeing of pool %u is missing %d buffers\n",
            pool, elements);
}
/**
 * Initialize and allocate memory for the SSO. This api is for kernel 
 * applications when ethernet driver is not inserted. 
 *
 * @param   num_wqe   The maximum number of work queue entries to be supported
 
 * @return  HFA_SUCCESS/HFA_FAILURE.
 */ 
int hfa_oct_initialize_sso(int num_wqe)
{
   static struct kmem_cache    *cvm_oct_kmem_sso;
    cvmx_sso_cfg_t              sso_cfg;
    cvmx_fpa_fpfx_marks_t       fpa_marks;
    int                         i;
    int                         rwq_bufs;

    if (!OCTEON_IS_MODEL(OCTEON_CN68XX))
        return 0;

    rwq_bufs = 48 + DIV_ROUND_UP(num_wqe, 26);
    cvm_oct_kmem_sso = kmem_cache_create("octeon_sso", 256, 128, 0, NULL);
    
    if (cvm_oct_kmem_sso == NULL) {
        hfa_err (CVM_HFA_ENOMEM, 
                ("cannot allocate memory for octeon_sso\n"));
        return HFA_FAILURE;
    }

    /*
     * CN68XX-P1 may reset with the wrong values, put in
     * the correct values.
     */
    fpa_marks.u64 = 0;
    fpa_marks.s.fpf_wr = 0xa4;
    fpa_marks.s.fpf_rd = 0x40;
    cvmx_write_csr(CVMX_FPA_FPF8_MARKS, fpa_marks.u64);

    /* Make sure RWI/RWO is disabled. */
    sso_cfg.u64 = cvmx_read_csr(CVMX_SSO_CFG);
    sso_cfg.s.rwen = 0;
    cvmx_write_csr(CVMX_SSO_CFG, sso_cfg.u64);

    while (rwq_bufs) {
        union cvmx_sso_rwq_psh_fptr fptr;
        void *mem;

        mem = kmem_cache_alloc(cvm_oct_kmem_sso, GFP_KERNEL);
        if (mem == NULL) {
            hfa_err (CVM_HFA_ENOMEM, 
                    ("cannot allocate memory from octeon_sso\n"));
            return HFA_FAILURE;
        }
        for (;;) {
            fptr.u64 = cvmx_read_csr(CVMX_SSO_RWQ_PSH_FPTR);
            if (!fptr.s.full)
                break;
            __delay(1000);
        }
        fptr.s.fptr = virt_to_phys(mem) >> 7;
        cvmx_write_csr(CVMX_SSO_RWQ_PSH_FPTR, fptr.u64);
        rwq_bufs--;
    }
    for (i = 0; i < 8; i++) {
        union cvmx_sso_rwq_head_ptrx head_ptr;
        union cvmx_sso_rwq_tail_ptrx tail_ptr;
        void *mem;

        mem = kmem_cache_alloc(cvm_oct_kmem_sso, GFP_KERNEL);
        if (mem == NULL) {
            hfa_err (CVM_HFA_ENOMEM, 
                    ("cannot allocate memory from octeon_sso\n"));
            return HFA_FAILURE;
        }

        head_ptr.u64 = 0;
        tail_ptr.u64 = 0;
        head_ptr.s.ptr = virt_to_phys(mem) >> 7;
        tail_ptr.s.ptr = head_ptr.s.ptr;
        cvmx_write_csr(CVMX_SSO_RWQ_HEAD_PTRX(i), head_ptr.u64);
        cvmx_write_csr(CVMX_SSO_RWQ_TAIL_PTRX(i), tail_ptr.u64);
    }
    /* Now enable the SS0  RWI/RWO */
    sso_cfg.u64 = cvmx_read_csr(CVMX_SSO_CFG);
    sso_cfg.s.rwen = 1;
    sso_cfg.s.rwq_byp_dis = 0;
    sso_cfg.s.rwio_byp_dis = 0;
    cvmx_write_csr(CVMX_SSO_CFG, sso_cfg.u64);

    return HFA_SUCCESS;
}
static int
hfa_drv_lib_init (void)
{
    if(hfa_napi_perf == 1) {
        if(NULL == hfa_set_irq_affinity_path) {
            hfa_log("Reinsert HFA_LIB_MODULE with \n\thfa_set_irq_affinity_path = " 
                     "'absolute path to hfa_set_irq_affinity.sh'\n"\
                   "\t eg. insmod cvm-hfa-lib.ko hfa_napi_perf=1 "\
                   "hfa_set_irq_affinity_path=/bin/hfa_set_irq_affinity.sh\n");
            return HFA_FAILURE;
        }
        hfa_napi_rx_initialize();
    }
    hfa_log("\nHFA Lib module: " HFA_LIB_MODULE " inserted successfully\n");

    /*Dev Init and Set mem will be done by Application module*/
    return HFA_SUCCESS;
}
static void
hfa_drv_lib_exit (void)
{
    if(hfa_napi_perf == 1)
        hfa_napi_rx_shutdown();
    hfa_log("\nHFA Library module: " HFA_LIB_MODULE " exited successfully\n");
}
/**@cond INTERNAL*/
EXPORT_SYMBOL (hfa_napi_perf);
EXPORT_SYMBOL (hfa_distribute_load);
EXPORT_SYMBOL (hfa_pow_receive_group);
EXPORT_SYMBOL (octeon_ethernet_driver_pow_group);
EXPORT_SYMBOL (hfa_mem_nb_name);
EXPORT_SYMBOL (hfa_max_napi_grps);
EXPORT_SYMBOL (hfa_mem_sz);
EXPORT_SYMBOL (hfa_ppbuf_pool);
EXPORT_SYMBOL (hfa_ppbuf_sz);
EXPORT_SYMBOL (hfa_ppbuf_cnt);
EXPORT_SYMBOL (hfa_tbuf_cnt);
EXPORT_SYMBOL (hfa_cmdbuf_cnt);
EXPORT_SYMBOL (hfa_isethernetdrv_present);
EXPORT_SYMBOL (hfa_oct_fill_hw_memory);
EXPORT_SYMBOL (hfa_oct_free_hw_memory);
EXPORT_SYMBOL (hfa_register_hwwqe_interceptcb);
EXPORT_SYMBOL (hfa_register_packet_interceptcb);
EXPORT_SYMBOL (hfa_oct_initialize_sso);
/**@endcond*/
module_init (hfa_drv_lib_init);
module_exit (hfa_drv_lib_exit);
