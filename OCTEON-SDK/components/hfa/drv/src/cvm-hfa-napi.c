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
 * This file created the NAPI interface for linux kernel
 * app modules to receive either packet WQE or HFA HW WQE
 *
 */
#include <cvm-hfa-common.h>
#include <cvm-hfa-module.h>
#include <cvm-hfa.h>
#include <asm/octeon/octeon.h>
#include <linux/interrupt.h>

/**POW receive group array Each core index is filled with the
 * WQE grpno on which NAPI is running for that core Application can use current
 * WQE grpno using hfa_pow_rcv_grp[cvmx_get_core_num()]
 */
CVMX_SHARED int                 hfa_pow_rcv_grp[NR_CPUS];
/**Counter to track how many tomes NAPI is called on each core
 * Application print this count*/
CVMX_SHARED uint64_t            hfa_napi_cnt[NR_CPUS];

/**Intercept callback to be initialized using hfa_register_hwwqe_interceptcb()*/
hfa_napi_interceptcb_t  hfa_napi_hwwqe_interceptcb = NULL;

/**Intercept cb to be initialized using hfa_register_packet_interceptcb()*/
hfa_napi_interceptcb_t  hfa_napi_packet_interceptcb = NULL;

/**@cond INTERNAL*/
/**
 * Cache aligned Core state
 */
static struct hfa_core_state    core_state __cacheline_aligned_in_smp; 

/**
 * Structure having NAPI structure + core availabilty
 */
static struct hfa_napi_wrapper  hfa_napi[NR_CPUS] __cacheline_aligned_in_smp;

/**
 * OCTEON MBOX messaging variable
 */
static int                      hfa_ipi_handle_mesg;

/*Function pointer to call either hfa_enable_one_cpu or hfa_enable_all_cpu*/
void        (*fnp_hfa_napi_enable_cpu)(void);
void        (*fnp_hfa_napi_wakeup_more_cpu)(int);

extern int              hfa_pow_receive_group;
extern int              octeon_ethernet_driver_pow_group;
extern int              hfa_distribute_load;
extern int              hfa_max_napi_grps;
extern int              hfa_rx_napi_weight;
extern char             *hfa_set_irq_affinity_path;

/*Function definitions related to HFA NAPI*/
static inline void *
hfa_napi_get_buffer_ptr(union cvmx_buf_ptr ptr)
{
    return(cvmx_phys_to_ptr(((ptr.s.addr >>7)- ptr.s.back) <<7));
}

/*
 * Dummy function to be called if hfa_distribute_load==1
 * Corresponding function hfa_napi_wakeup_more_cpu 
 *
 * @param   budget
 *
 * @return void
 */
static inline void 
hfa_napi_wakeup_dummy(int budget)
{
}
/**
 * Free SKB fragments
 * 
 * @param   napi    Napi structure
 *
 * @return  void
 */
static inline void 
hfa_napi_free_frags(struct napi_struct *napi)
{
    kfree_skb(napi->skb);
    napi->skb = NULL;
}
/**
 * Free WQE packet data + WQE buffer from FPA
 *
 * @param   wqe     Work Queue entry
 *
 * @return  0 if success
 */
int 
hfa_napi_free_work(void *wqe)
{
    cvmx_wqe_t *work = (cvmx_wqe_t *)wqe;
    int segments = work->word2.s.bufs;
    union cvmx_buf_ptr segment_ptr = work->packet_ptr;

    while (segments--) {
        union cvmx_buf_ptr next_ptr = *(union cvmx_buf_ptr *)
                                     cvmx_phys_to_ptr(segment_ptr.s.addr - 8);
        if (unlikely(!segment_ptr.s.i))
            cvmx_fpa_free(hfa_napi_get_buffer_ptr(segment_ptr),
                    segment_ptr.s.pool,
                    DONT_WRITEBACK(CVMX_FPA_PACKET_POOL_SIZE / 128));
        segment_ptr = next_ptr;
    }
    cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, DONT_WRITEBACK(1));

    return 0;
}
/**Napi structure initializer*/
void hfa_netif_napi_add (struct net_device *dev, struct napi_struct *napi,
        int (*poll)(struct napi_struct *, int), int weight)
{
    napi->gro_count = 0;
    napi->gro_list = NULL;
    napi->skb = NULL;
    napi->poll = poll;
    napi->weight = weight;
    napi->dev = dev;
    set_bit(NAPI_STATE_SCHED, &napi->state);
}
/**
 * Delete Napi structure from KErnel
 *
 * @param   napi    Napi structure to be deleted
 *
 * @return void
 */
void hfa_netif_napi_del(struct napi_struct *napi)
{
    struct sk_buff *skb = NULL, *next = NULL;

    hfa_napi_free_frags(napi);
    for(skb = napi->gro_list; skb; skb=next){
        next = skb->next;
        skb->next = NULL;
        kfree_skb(skb);
    }
    napi->gro_list = NULL;
    napi->gro_count =0;
}
/**
 * Enable NAPI 'n' structure to be schedulable
 *
 * @param   n   Napi strucutre to be marked schedulable
 *
 * @return  void
 */
static inline void
hfa_napi_enable (struct napi_struct *n)
{
    BUG_ON(!test_bit(NAPI_STATE_SCHED, &n->state));
    smp_mb__before_clear_bit();
    clear_bit(NAPI_STATE_SCHED, &n->state);
}
/**
 * hfa_napi_schedule_prep - Check if NAPI schedulable
 *
 * @param   n   Napi structure to check
 *
 * @return 1 if schedulable and 0 otherwise
 *
 */
static inline int
hfa_napi_schedule_prep(struct napi_struct *n)
{
    /*Is NAPI disable*/
    int state = test_bit(NAPI_STATE_DISABLE, &n->state);
    /*Is NAPI already running*/
    int scheduled = test_and_set_bit(NAPI_STATE_SCHED, &n->state);

    return (!state && !scheduled);
}
/**
 * Schedules NAPI (if schedulable) on current core
 *
 * @return  void
 */
static void
hfa_napi_schedule(void)
{
    int cpu = smp_processor_id();

    struct napi_struct *napi = &(hfa_napi[cpu].napi);

    dprintf("Napi Scheduled on core: %d, smp_id: %d\n", cvmx_get_core_num(),
                                                       smp_processor_id());
    if(hfa_napi_schedule_prep(napi))
        __napi_schedule(napi);
}
/**
 * Schedule NAPI on all available cores. 
 * Should be called when hfa_distribute_load==1
 *
 * @return  void
 */
void hfa_napi_enable_all_cpu(void)
{
    int cpu;
    unsigned long flags;

    spin_lock_irqsave(&core_state.lock, flags);
    /* ... if a CPU is available, Turn on NAPI polling for that CPU.  */
    for(cpu=0; cpu < hfa_max_napi_grps; cpu++) {
        dprintf("Looping: Core%d. Avail:%d\n", cpu,
                hfa_napi[cpu].available);
        if (hfa_napi[cpu].available > 0) {
            hfa_napi[cpu].available--;
            core_state.active_cores++;
            if (cpu == cvmx_get_core_num()) {
                dprintf("Calling hfa_napi_Schedule for CPU:%d\n", cpu);
                hfa_napi_schedule();
            } else {
#ifdef CONFIG_SMP
                dprintf("IPI Handler for %d\n", cpu);
                octeon_send_ipi_single(cpu, hfa_ipi_handle_mesg);
#else
                BUG();
#endif
            }
        }
    }
    spin_unlock_irqrestore(&core_state.lock, flags);
    return;
}
/**
 * Schedule NAPI on one core among all available cores
 *
 * @return  void
 */
void hfa_napi_enable_one_cpu(void)
{
    int cpu;
    unsigned long flags;

    spin_lock_irqsave(&core_state.lock, flags);
    /* ... if a CPU is available, Turn on NAPI polling for that CPU.  */
    for_each_online_cpu(cpu) {
        if (hfa_napi[cpu].available > 0) {
            hfa_napi[cpu].available--;
            core_state.active_cores++;
            spin_unlock_irqrestore(&core_state.lock, flags);
            if (cpu == smp_processor_id()) {
                hfa_napi_schedule();
            } else {
#ifdef CONFIG_SMP
            octeon_send_ipi_single(cpu, hfa_ipi_handle_mesg);
#else
            BUG();
#endif
            }
            goto out;
        }
    }
    spin_unlock_irqrestore(&core_state.lock, flags);
out:
    return;

}
/**
 * As NAPI is already marked complete on this core so 
 * make this core available for further handling. 
 * Interrupts disabled in isr are enabled again
 *
 * @param   napi    Napi structure
 *
 * @return  void
 */
static void
hfa_napi_no_more_work(struct napi_struct *napi)
{
    int                     current_active_cores=0;
    unsigned long           flags;
    int                     grp = hfa_pow_rcv_grp[cvmx_get_core_num()]; 
    struct hfa_napi_wrapper *nr = container_of (napi, 
                                                struct hfa_napi_wrapper, napi);

    spin_lock_irqsave(&core_state.lock, flags);
    /*Reduce number of active cores running NAPI currently*/
    core_state.active_cores--;
    BUG_ON(core_state.active_cores < 0);
    current_active_cores = core_state.active_cores;

    (nr->available)++;
    BUG_ON(1 != nr->available);
    spin_unlock_irqrestore(&core_state.lock, flags);

    /*Enable interrupts if hfa_distribute_load or 
     * current_active_cores ==0*/
    if(hfa_distribute_load || !current_active_cores){
        /*Enable interrupt such that interrupt is raised when 
         * SSO has one packet for this grp*/
        if(OCTEON_IS_MODEL(OCTEON_CN68XX)){
            union cvmx_sso_wq_int_thrx  int_thr;
            int_thr.u64=0;
            int_thr.s.iq_thr=1;
            int_thr.s.ds_thr=1;
            cvmx_write_csr(CVMX_SSO_WQ_INT_THRX(grp), int_thr.u64);
        } else {
            union cvmx_pow_wq_int_thrx int_thr;
            int_thr.u64=0;
            int_thr.s.iq_thr=1;
            int_thr.s.ds_thr=1;
            cvmx_write_csr(CVMX_POW_WQ_INT_THRX(grp), int_thr.u64);
        }
    }
}
/**
 * Check if more cpu needed to wakeup at runtime
 * If hfa_distribute_load == 0 and amount of work > budget
 * then NAPI is scheduled on one more available cpu
 *
 * @param   budget      budget provided to NAPI
 *
 * @return  void
 */
static inline void
hfa_napi_wakeup_more_cpu(int budget)
{
    int backlog, cores_in_use = core_state.active_cores;
    int grp = hfa_pow_rcv_grp[cvmx_get_core_num()];

    /*Should always be called when hfa_distribute_load ==0*/
    BUG_ON(1 == hfa_distribute_load);

    if(OCTEON_IS_MODEL(OCTEON_CN68XX)){
        union cvmx_sso_wq_int_cntx  counts;
        counts.u64 = cvmx_read_csr(CVMX_SSO_WQ_INT_CNTX(grp));
        backlog = counts.s.iq_cnt + counts.s.ds_cnt;
    } else {
        union cvmx_pow_wq_int_cntx  counts;
        counts.u64 = cvmx_read_csr(CVMX_POW_WQ_INT_CNTX(grp));
        backlog = counts.s.iq_cnt + counts.s.ds_cnt;
    }

    if((backlog > (budget * cores_in_use)) &&
            (cores_in_use < core_state.baseline_cores)){
        hfa_napi_enable_one_cpu();
    }
}
/**
 *  Do get work to receive WQE and pass to the application
 *  through register callbacks. If no register callback found
 *  work will be freed here
 *
 *  @param      napi        Napi Structure
 *  @param      budget      Max 'budget' pkts to be served percore
 *  @param      cnt         Pointer to the packets served cnt
 *
 *  @return   void
 */
static inline void
hfa_napi_receive_and_handle_work (struct napi_struct *napi, 
                                  int budget, int *cnt)
{
    int             did_work_req=0;
    int             free_work=0;
    cvmx_wqe_t      *work = NULL;
#ifdef HFA_DEBUG
    int             flag=1;
#endif


    if(USE_ASYNC_IOBDMA){
        cvmx_pow_work_request_async(CVMX_SCR_SCRATCH, CVMX_POW_NO_WAIT);
        did_work_req=1;
    }

    *cnt=0;
    while(*cnt < budget){
        if(USE_ASYNC_IOBDMA && did_work_req){
            work = cvmx_pow_work_response_async(CVMX_SCR_SCRATCH);
        } else {
            work = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
        }
        prefetch(work);
        did_work_req=0;

        if(unlikely(NULL == work)){
            break;
        } 
#ifdef HFA_DEBUG
        else {
            if(flag){
                hfa_napi_cnt[cvmx_get_core_num()]++;
                flag=0;
            }
        }
#endif
        if(USE_ASYNC_IOBDMA && *cnt < (budget -1)){
            cvmx_pow_work_request_async_nocheck (CVMX_SCR_SCRATCH, 
                    CVMX_POW_NO_WAIT);
            did_work_req=1;
        }
        /*See if is there need to wakeup more cpus*/ 
        if(!(*cnt)){
            (*fnp_hfa_napi_wakeup_more_cpu)(budget);
        }
        free_work =1;
        switch(hfa_get_wqe_type(work)) {
            case HFA_SEARCH_HWWQE:
            case HFA_GRAPH_HWWQE:
                if(hfa_napi_hwwqe_interceptcb) {
                    free_work = !(CVM_OCT_TAKE_OWNERSHIP_WORK == 
                            hfa_napi_hwwqe_interceptcb(NULL, work, NULL));
                }
                break;
            case PACKET_WQE:
                if(hfa_napi_packet_interceptcb){
                    free_work = !(CVM_OCT_TAKE_OWNERSHIP_WORK == 
                            hfa_napi_packet_interceptcb(NULL, work, NULL));
                }
                break;
            default:
                break;
        }
        (*cnt)++;
        if(free_work){
            hfa_napi_free_work(work);
        }
    }
}
/*
 * NAPI poll function
 *
 * @param   napi        Napi structure
 * @param   budget      Maximum number of packets to receive
 *
 * @return  Number of rx_packets handled for napi
 * */
static int  
hfa_napi_poll(struct napi_struct *napi, int budget)
{
    uint64_t    old_scratch;
    uint64_t    old_grp_msk;
    int         coreno = cvmx_get_core_num();
    int         grp = hfa_pow_rcv_grp[coreno];
    int         rx_count=0;

    if(USE_ASYNC_IOBDMA){
        CVMX_SYNCIOBDMA;
        old_scratch = cvmx_scratch_read64(CVMX_SCR_SCRATCH);
    }
    /*Save old grp mask, Rewrite another one*/
    if (OCTEON_IS_MODEL(OCTEON_CN68XX)){
        old_grp_msk = cvmx_read_csr(CVMX_SSO_PPX_GRP_MSK(coreno));
        cvmx_write_csr(CVMX_SSO_PPX_GRP_MSK(coreno), 1ULL << grp);
        /*Read it again to take effect*/
        cvmx_read_csr(CVMX_SSO_PPX_GRP_MSK(coreno));
    } else {
        old_grp_msk = cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(coreno));
        cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreno), 
                ((old_grp_msk & (~0xFFFFull)) | (1ULL << grp)));
        cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(coreno));
    }
    hfa_napi_receive_and_handle_work(napi, budget, &rx_count);

    /*Restore original POW grp mask*/
    if (OCTEON_IS_MODEL(OCTEON_CN68XX)){
        cvmx_write_csr(CVMX_SSO_PPX_GRP_MSK(coreno), old_grp_msk);
        /*Read it again to take effect*/
        cvmx_read_csr(CVMX_SSO_PPX_GRP_MSK(coreno));
    } else {
        cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreno), old_grp_msk);
        cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(coreno));
    }
    /*Restore scratch pad*/
    if(USE_ASYNC_IOBDMA){
        cvmx_scratch_write64(CVMX_SCR_SCRATCH, old_scratch);
    }
    /*If all packets of core grp are handled. Deschedule NAPI
     * and Enable interrupts on this core*/
    if((rx_count < budget) && (NULL != napi)){
        napi_complete(napi);
        hfa_napi_no_more_work(napi);
    }
    return rx_count;
}
/**
 * SSO WQE grp interrupt handler
 *
 * @param    cpl         registers
 * @param   dev_id      Interrupt device id
 *
 * @return  IRQ_HANDLED if interrupt is handled
 */
static irqreturn_t 
hfa_napi_do_interrupt(int cpl, void *dev_id)
{
    int             cpu = smp_processor_id();
    int             grp = hfa_pow_rcv_grp[cvmx_get_core_num()];
    unsigned long   flags;

    /*Disable the IRQ*/
    if(OCTEON_IS_MODEL(OCTEON_CN68XX)){
        cvmx_write_csr(CVMX_SSO_WQ_INT_THRX(grp), 0);
        cvmx_write_csr(CVMX_SSO_WQ_INT, 1ULL << grp);
    } else {
        union cvmx_pow_wq_int wq_int;
        cvmx_write_csr (CVMX_POW_WQ_INT_THRX(grp), 0);
        wq_int.u64 =0;
        wq_int.s.wq_int = 1ULL << grp;
        cvmx_write_csr(CVMX_POW_WQ_INT, wq_int.u64);
    }

    spin_lock_irqsave(&core_state.lock, flags);

    BUG_ON (1 != hfa_napi[cpu].available);
    hfa_napi[cpu].available--;
    /*Increase number of active cores by 1*/
    (core_state.active_cores)++;
    BUG_ON(core_state.active_cores > core_state.baseline_cores);
    spin_unlock_irqrestore(&core_state.lock, flags);

    /*Schedule NAPI*/
    hfa_napi_schedule();

    return IRQ_HANDLED;
}
/**
 * Set the irq affinity of a given irq
 *
 * @param   irq		    Interrupt to set affinity
 * @param   cpumask     cpumask
 *
 */
static inline void
hfa_set_irq_affinity(unsigned int irqno, unsigned long int cpumask) 
{
    static char     *envp[] = { NULL};
    char            *argv[4];
    int             ret = 0;
    char            mask[20], irq[10];

    snprintf(mask, sizeof(mask)-1, "%lx", cpumask);
    snprintf(irq, sizeof(irq)-1, "%d", irqno);
    argv[0] = hfa_set_irq_affinity_path;
    argv[1] = mask;
    argv[2] = irq;
    argv[3] = NULL;
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if(ret == (-ENOENT)) {
        pr_crit("Unable to open file hfa_set_irq_affinity.sh\n");
    }
    return;
}
/**
 * NAPI init + SSO WQE GRP interrupt registeration
 *
 * @return  void
 */
void 
hfa_napi_rx_initialize(void)
{
    int             i, cnt,grp;
    unsigned int    irqno;
    uint64_t        cpumask;

    core_state.baseline_cores = num_online_cpus();

    /*Mark all cores/cpus as available and
     * initialize napi structure for them*/
    for_each_possible_cpu(i){
        hfa_napi[i].available = 1;
        hfa_netif_napi_add(NULL, &(hfa_napi[i].napi), 
                hfa_napi_poll, hfa_rx_napi_weight);
        hfa_napi_enable(&(hfa_napi[i].napi));
    }

    /*Initialize lock*/
    spin_lock_init(&core_state.lock);

#ifdef CONFIG_SMP
    /*Request IPI handler for running NAPI on other cores*/
    hfa_ipi_handle_mesg = octeon_request_ipi_handler(hfa_napi_schedule);

    if(hfa_ipi_handle_mesg < 0){
        panic("No IPI handler available\n");
    }
    /*If distribute_load == 1*/
    if(hfa_distribute_load){

        pr_crit("HFA DISTRIBUTE_LOAD among %d cores\n", 
                    core_state.baseline_cores);

        for(cnt=0; cnt< NR_CPUS; cnt++){
            hfa_pow_rcv_grp[cnt]=-1;
        }
        /*Register interrupt*/
        hfa_max_napi_grps =0;
        for_each_online_cpu(cnt){
            hfa_max_napi_grps++;
            i = octeon_ethernet_driver_pow_group - cnt;
            if(i > 0){
                /*From 0 to < octeon_pow_grp*/
                irqno = OCTEON_IRQ_WORKQ0 + cnt;
                grp=cnt;
            } else if (0 == i){
                /*if cnt == octeon_pow_grp*/
                irqno = OCTEON_IRQ_WORKQ0 + cnt +1;
                grp = cnt+1;
            } else if ((i < 0) && (i != 31)) {
                irqno = OCTEON_IRQ_WORKQ0 + cnt +1;
                grp = cnt+1;
            } else {
                pr_crit("Continue for cnt: %d\n", cnt);
                /*If cnt == 31*/
                continue;
            }
            if(irqno < OCTEON_IRQ_WORKQ0){
                panic("irqno: %d < less than OCTEON_IRQ_WORKQ0\n", irqno);
            }
            i = request_irq(irqno, hfa_napi_do_interrupt, 
                            IRQF_DISABLED, "hfa_napi", NULL);
            if(i){
                panic("Could not acquire IRQ: %d\n", irqno);
            }
            cpumask = 1ULL << cnt;
            hfa_set_irq_affinity(irqno, cpumask);
            pr_crit("[C%d]: Reg. IRQ for WQE grp: %d on core %d\n", 
              cvmx_get_core_num(), irqno - OCTEON_IRQ_WORKQ0, cnt);
            hfa_pow_rcv_grp[cnt] = grp;
            hfa_napi_cnt[cnt] = 0;
        }
        fnp_hfa_napi_enable_cpu = hfa_napi_enable_all_cpu;
        fnp_hfa_napi_wakeup_more_cpu = hfa_napi_wakeup_dummy;
    } else
#endif    
        /*Enable only one core for NAPI*/
    {
        hfa_max_napi_grps=1;
        irqno = OCTEON_IRQ_WORKQ0 + hfa_pow_receive_group;
        /* Setting to default irq affinity */
        cpumask = 0xffffffff; 
        hfa_set_irq_affinity(irqno, cpumask);
        /*Register interrupt for hfa_pow_receive_group*/
        i = request_irq(irqno, hfa_napi_do_interrupt, 0, "hfa_napi", NULL);
        if(i){
            panic("Could not acquire IRQ %d\n", irqno);
        }
        pr_crit("[C:%d] Scheduled one NAPI for WQE grp: %d\n", 
                cvmx_get_core_num(), hfa_pow_receive_group); 
        for_each_online_cpu(cnt){
            hfa_pow_rcv_grp[cnt] = hfa_pow_receive_group;
        }
        fnp_hfa_napi_enable_cpu = hfa_napi_enable_one_cpu;
        fnp_hfa_napi_wakeup_more_cpu = hfa_napi_wakeup_more_cpu;
    }
    for_each_online_cpu(cnt){
        hfa_dbg("hfa_pow_rcv_grp[%d]: %d\n", cnt, hfa_pow_rcv_grp[cnt]);
    }
    

    /*Schedule NAPI. This will run the NAPI loop once*/
    (*fnp_hfa_napi_enable_cpu)();
}
/**
 * Shutdown NAPI
 *
 * @return  void
 */
void 
hfa_napi_rx_shutdown(void)
{
    int cnt=0;

    for(cnt=0; cnt <hfa_max_napi_grps; cnt++){
        if(OCTEON_IS_MODEL(OCTEON_CN68XX)){
            cvmx_write_csr(CVMX_SSO_WQ_INT_THRX(hfa_pow_rcv_grp[cnt]), 0);
        } else {
            cvmx_write_csr(CVMX_POW_WQ_INT_THRX(hfa_pow_rcv_grp[cnt]), 0);
        }
        free_irq(OCTEON_IRQ_WORKQ0 + hfa_pow_rcv_grp[cnt], NULL);
    }
#ifdef CONFIG_SMP
    octeon_release_ipi_handler(hfa_ipi_handle_mesg);
#endif
}
EXPORT_SYMBOL (hfa_pow_rcv_grp);
EXPORT_SYMBOL (hfa_napi_cnt);
EXPORT_SYMBOL (hfa_napi_free_work);
/**@endcond*/
