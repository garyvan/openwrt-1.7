 	 	/***********************license start***************                              
* Copyright (c) 2008-2015 Cavium Inc. All rights reserved.
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
                                                                                  
*This Software,including technical data,may be subject to U.S. export control 
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

#include <cvmx-config.h>
#include <cvmx.h>
#include <cvmx-sysinfo.h>
#include <cvmx-coremask.h>
#include <cvmx-spinlock.h>
#include <cvmx-fpa.h>
#include <cvmx-ilk.h>
#include <cvmx-pip.h>
#include <cvmx-ipd.h>
#include <cvmx-pko.h>
#include <cvmx-pow.h>
#include <cvmx-bootmem.h>
#include <cvmx-wqe.h>
#include <cvmx-fau.h>
#include <cvmx-helper-cfg.h>
#include <cvmx-rwlock.h>
/* #define     ERR(_x, ...)    {                                                 \
    printf ("error: " _x, ## __VA_ARGS__);        \
    cvmx_reset_octeon ();                         \
} */
#include "misc_defs.h"
//#include "memfsmap.h"
#include "stats.h"
#include "exec_intf.h"

#ifndef UINT64_MAX
#define SIZEOF_UNSIGNED_LONG_INT 8
#  if SIZEOF_UNSIGNED_LONG_INT == 8
#    define UINT64_MAX (18446744073709551615UL)
#  else
#    define UINT64_MAX (18446744073709551615ULL)
#  endif  /* SIZEOF_UNSIGNED_LONG_INT == 8 */
#endif  /* UINT64_MAX */
CVMX_SHARED int used_port_sets = 0;
CVMX_SHARED unsigned long int port_set[MAX_PORT_SETS][2];
CVMX_SHARED volatile int core_counter = -1;
CVMX_SHARED cvmx_rwlock_wp_lock_t lock_wstats;

void (*func_processCtx_octeon)(int) = NULL;
void (*func_print_profile_stats)(void) = NULL;
void (*func_time_start)(void) = NULL;

int cav_oct_err_flag = 0;
static uint64_t pass_start_cycle = 0;
static uint64_t pass_all_cycle = 0;
static uint64_t pass_sso_cycle = 0;

#ifdef CAV_OCT_LINUX
volatile int cav_breakloop = 0;
#endif
int cav_cli = 0;
int profile = 0;
int cav_profile = 0;
int rcv_cores = 0;
#define QUOTE(x) #x
#define STRING(x) QUOTE(x)
#define MILLIES_DONE 40000  // stats wait time: 40 seconds
#define CYCLES_PER_MILLI 1500000 // assumption that the core is running at 1.5 Ghz
profile_stat_t profile_stats[MAX_METRICS];

CVMX_SHARED static int total_cores;

#define FROM_INPUT_PORT_GROUP 0

#define USE_ASYNC_IOBDMA 0  // define this value to 1 for Async Work mode
static int inc = 0;
#define is_my_turn() ((core_counter == cvmx_get_core_num())?1:0)
#ifdef CAV_OCT_SE

extern void cli_readline(void);
extern void cli_show_sysinfo(void);
extern void cli_init(void);
int memfs_setup(void * memfs_addr, void * (*memfs_alloc_rtn) (unsigned long)) {}
int memfs_init(void * (*memfs_alloc_rtn) (unsigned long)){}
extern void memfs_exit(void (*memfs_free_rtn) (void *));

//#define DUMP_PACKETS 1
#define BLOCK_NAME "memfs"
#define ULL unsigned long long


int init_named_block(void)
{
    void * addr = NULL;
    const cvmx_bootmem_named_block_desc_t *block_desc;

        block_desc = cvmx_bootmem_find_named_block(BLOCK_NAME);
        if(block_desc){
            addr = cvmx_phys_to_ptr((block_desc->base_addr));
		gz_fsinit(addr,malloc,(void(*)(const void *))free);
            }
        else{
            printf("BLOCK : %s is NULL\n",BLOCK_NAME);
        }

    return 0;
}
#endif


/* Snortxl: Initialize and check port set  argument given for octeon daq */
/* return 1 if success else return -1 for any error , printing error message */
int InitPortSets(char *intf)
{
    if(!intf)
    { 
        ERR("Null Interface Name");
        return -1;
    }

    char *endptr;
    char *tmp_str;
    char *tstr,*pair,*next_pair;
    int flag=0;
    unsigned long int port1, port2;

    tstr = strdup(intf);
    if(tstr == NULL)
    { 
        ERR("Strdup Failed \n");
        return -1;
    }


    while(1)
    {
        flag=0;
        
        // Handle case where single port is given like  -i 0 option or  -i 0:1::2 
        if(!strchr(tstr,':')) 
        { 
            port1   = strtoul(tstr,&endptr,0);
            if(!strncmp(STRING(OCTEON_MODEL),"OCTEON_CN70XX",13))
            {
                //check Condition when invalid port string
                if(port1 == 0 && ( strcmp(tstr,"0") != 0)) 
                {
                    ERR("Invalid port number \n");
                    return -1;           
                }
            }
            port2=port1;

            goto port_check;                      
        }

        if((strchr(tstr,':'))&&(next_pair=strstr(tstr,"::")))
        {   
            flag=1;
            if(!(pair=strdup(next_pair+2))){
                ERR("Strdup Failed \n");
                return -1;     }
        }

        tmp_str = strtok(tstr,":");
        port1   = strtoul(tmp_str,&endptr,0);
        
        tmp_str = strtok(NULL,":");
        port2 =   strtoul(tmp_str,&endptr,0);
        
        if(!strncmp(STRING(OCTEON_MODEL),"OCTEON_CN70XX",13))
        {
            //check Condition when invalid port string
            if(port1 == 0 && ( strcmp(tmp_str,"0") != 0)) 
            {
                ERR("Invalid port number \n");
                return -1;           
            }

            if(port2 == 0 && ( strcmp(tmp_str,"0") != 0)) //Condition when invalid port string
            {
                ERR("Invalid port Number \n");
                return -1;           
            }
        }  
port_check:  
        if(used_port_sets == MAX_PORT_SETS)
        {
            ERR("Ran out of ports \n");
            return -1;
        }
        if(!strncmp(STRING(OCTEON_MODEL),"OCTEON_CN70XX",13))
        {
       // Check for valid port Number ranges 
            if(!((port1 >=0 && port1 <=4 ) || ( port1 >=16 && port1 <=19 ) ))
            {
                ERR("Invalid Port Number please specify correct port number \n");
                return -1;
            }
            if(!((port2 >=0 && port2 <=4 ) || ( port2 >=16 && port2 <=19 ) ))
            {
                ERR("Invalid Port Number please specify correct port number \n");
                return -1;
            }
        }
        port_set[used_port_sets][0] = port1;
        port_set[used_port_sets][1] = port2;
        used_port_sets++;

        if(flag)
        {
            tstr=pair; //more ports left
        }
        else
            break;
    } 
    return 1;    
}

static int32_t cvmx_total_cores()
{
     uint8_t i=0;
     uint32_t tot_cores=0, scanned_bits, mask_size;
     uint64_t *mask_ptr, coremask_64;

     mask_size = 64;
     mask_ptr = (cvmx_sysinfo_get()->core_mask).coremask_bitmap;

     for(scanned_bits=0; scanned_bits < mask_size;scanned_bits+=64) 
     {
        coremask_64 = *mask_ptr;
        while(coremask_64)
        {
           tot_cores += 1;
           coremask_64 &= (coremask_64 - 1);
        }
        mask_ptr++;
     }
       
     return tot_cores;
}



static int application_init_simple_exec()
{
    int result;

    if (cvmx_helper_initialize_fpa(OCTEON_IBUFPOOL_COUNT, OCTEON_IBUFPOOL_COUNT, CVMX_PKO_MAX_OUTPUT_QUEUES * 4, 0, 0))
        return -1;

    /* Model check not done since its being done internally.
     * Required for 68xx only */
    if (cvmx_helper_initialize_sso(OCTEON_IBUFPOOL_COUNT))
        return -1;

/*
    if (octeon_has_feature(OCTEON_FEATURE_NO_WPTR))
    {
        cvmx_ipd_ctl_status_t ipd_ctl_status;
        ipd_ctl_status.u64 = cvmx_read_csr(CVMX_IPD_CTL_STATUS);
        ipd_ctl_status.s.no_wptr = 1;
#ifdef __LITTLE_ENDIAN_BITFIELD
        ipd_ctl_status.s.pkt_lend = 1;
        ipd_ctl_status.s.wqe_lend = 1;
#endif
        cvmx_write_csr(CVMX_IPD_CTL_STATUS, ipd_ctl_status.u64);
    }
*/

    cvmx_helper_cfg_opt_set(CVMX_HELPER_CFG_OPT_USE_DWB, 0);
    result = cvmx_helper_initialize_packet_io_global();

    /* Don't enable RED on simulator */
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
        cvmx_helper_setup_red(OCTEON_IBUFPOOL_COUNT/4, OCTEON_IBUFPOOL_COUNT/8);

    /* Leave 16 bytes space for the ethernet header */
    cvmx_write_csr(CVMX_PIP_IP_OFFSET, 2);
    cvmx_helper_cfg_set_jabber_and_frame_max();
    cvmx_helper_cfg_store_short_packets_in_wqe();
    
    int num_interfaces = cvmx_helper_get_number_of_interfaces();
    int interface;

    for (interface = 0; interface < num_interfaces; interface++) 
    {
        int num_ports, port;
        num_ports = cvmx_helper_ports_on_interface (interface);
        for(port = 0; port < num_ports; port++)
        {
            cvmx_pip_port_tag_cfg_t tag_cfg;
            int pknd;
            if (octeon_has_feature(OCTEON_FEATURE_PKND))
                pknd = cvmx_helper_get_pknd(interface, port);
            else
                pknd = cvmx_helper_get_ipd_port(interface, port);
            tag_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(pknd));
            if(!rcv_cores)
            {
                /* use tuple tag algorithm */
                tag_cfg.s.tag_mode = 0;
                /* compute the wqe group from the tag */
                tag_cfg.s.grptag = 1;
                /* offset that needs to be added to wqe group */
                tag_cfg.s.grptagbase = 0;

                if (total_cores > 16)
                {
                    /* (0,2,0) used to load on cores > 16 */
                    tag_cfg.s.grptagbase_msb = 0;
                    tag_cfg.s.grptagmask_msb = 2;
                    tag_cfg.s.grp_msb        = 0;
                    tag_cfg.s.grptagmask     = 0;
                }
                else
                {
                    /* (0,3,0) used to load on < 16 cores*/
                    tag_cfg.s.grptagbase_msb = 0;
                    tag_cfg.s.grptagmask_msb = 3;
                    tag_cfg.s.grp_msb        = 0;
                    tag_cfg.s.grptagmask     = 16-total_cores;
                }
            }
            else
            {
                /* dont compute the wqe group from the tag */
                tag_cfg.s.grptag = 0; 
                tag_cfg.u64 = cvmx_read_csr(CVMX_PIP_PRT_TAGX(pknd));
                tag_cfg.s.grp = FROM_INPUT_PORT_GROUP & 0xf;
                tag_cfg.s.grp_msb = (FROM_INPUT_PORT_GROUP >> 4) & 3;
                /*
                tag_cfg.s.grptagbase_msb = 0;
                tag_cfg.s.grptagmask_msb = 3;
                tag_cfg.s.grp_msb        = 0;
                tag_cfg.s.grptagmask     = 16;
                */
            }
            cvmx_write_csr(CVMX_PIP_PRT_TAGX(pknd), tag_cfg.u64);
        }
    }
    cvmx_write_csr (CVMX_PIP_TAG_SECRET, 0x44444444);

    return result;

}

void
initinterfaces ()
{
    int idx =0;
    uint64_t value = 0;
    if (octeon_has_feature(OCTEON_FEATURE_SRIO))
    {
        if (cvmx_helper_interface_get_mode(4) == CVMX_HELPER_INTERFACE_MODE_SRIO)
            cvmx_srio_initialize(0, 0);
        if (cvmx_helper_interface_get_mode(5) == CVMX_HELPER_INTERFACE_MODE_SRIO)
            cvmx_srio_initialize(1, 0);
    }

    /* 64 is the minimum number of buffers that are allocated to receive
       packets, but the real hardware, allocate above this minimal number. */
    if ((application_init_simple_exec()) != 0)
        ERR("Simple Executive initialization failed.\n");

    /* POW timeout Settings */
    cvmx_sso_nw_tim_t sso_tim;
    sso_tim.u64 = cvmx_read_csr(CVMX_SSO_NW_TIM);
    sso_tim.s.nw_tim = 100;
    cvmx_write_csr(CVMX_SSO_NW_TIM,sso_tim.u64);
    sso_tim.u64 = cvmx_read_csr(CVMX_SSO_NW_TIM);

    /* QOS setting */
    if(!strncmp(STRING(OCTEON_MODEL),"OCTEON_CN68XX",13))
    {
        int i;
        cvmx_sso_qos_thrx_t qos_sso_thrx[8];
        for (i=0;i<8; i++)
        {
            /* assuming single input QOS level */
            qos_sso_thrx[i].s.max_thr = 1950;
            qos_sso_thrx[i].s.min_thr = 10;
            cvmx_write_csr (CVMX_SSO_QOS_THRX(i),qos_sso_thrx[i].u64);
        }
    }
    /* Reset PIP received packet stats */
    for (idx=0; idx<=3; ++idx)
       cvmx_write_csr(CVMX_PIP_STAT_INB_PKTSX(idx),value);
    for (idx=16; idx<=19; ++idx)
       cvmx_write_csr(CVMX_PIP_STAT_INB_PKTSX(idx),value);

    return;    
}

void core_group_assignment (void)
{
    int core_id = 0;

    for (core_id = 0;core_id < total_cores;core_id++)
    {
        cvmx_pow_set_group_mask(core_id, 0x0); 
        cvmx_pow_set_group_mask(core_id, ((uint64_t)0x1<<core_id)); 
    }
    if(rcv_cores)
        for (core_id = 0;core_id < rcv_cores;core_id++)
            cvmx_pow_set_group_mask(core_id, ((uint64_t)0x1<<0));
}


int octeonSE_initialize()
{
    return 0;
}
#ifdef CAV_OCT_SE
static int isLastCore = 0;
static int lastCore(void){
        return (cvmx_coremask_get_last_core(&(cvmx_sysinfo_get()->core_mask)));

}
#endif

static inline unsigned long get_toggle_port(uint64_t port)
{
    int i;
    
    if (cvmx_unlikely(!used_port_sets))
       return port;

    for(i=0;i<used_port_sets;i++)
    {
       if (port == port_set[i][0])
           return (port_set[i][1]);
       if (port == port_set[i][1])
           return (port_set[i][0]);
     }

     return -1;
}

int octeon_initialize()
{
        int first_core;
        total_cores = cvmx_total_cores();
        first_core = cvmx_coremask_get_first_core (&(cvmx_sysinfo_get ()->core_mask));
        init_prof_stats();
        if (cvmx_get_core_num() == first_core) {
            initinterfaces();
            cvmx_rwlock_wp_init(&lock_wstats);
            core_group_assignment();
        }
#ifdef CAV_OCT_SE
        if(lastCore() == cvmx_get_core_num()){
            isLastCore = 1;
        if(cvmx_unlikely(cav_cli))
            cli_init();
        }
#endif
        cvmx_coremask_barrier_sync (&(cvmx_sysinfo_get ()->core_mask));
        cvmx_helper_initialize_packet_io_local ();
        cvmx_pow_work_request_null_rd ();
        if (cav_oct_is_first_core())
           inc = 1;

        return 0;
}


CVMX_SHARED volatile int printStats = 0;
void (*func_pStats)(void);
void (*func_show_preproc_profile)(void);
void (*func_show_rbuf_stat)(void);
void getStats(uint64_t * received,uint64_t *dropped);

static uint64_t unit_per_sec(uint64_t start, uint64_t end, uint64_t quantity)
{
   uint64_t time_in_millies = (end-start)/CYCLES_PER_MILLI;

   //printf("total_time %lu\n", (end-start));
   //printf("millies %lu\n", time_in_millies);
   //printf("qusntity %lu\n", quantity);

   if (time_in_millies)
      return (quantity*1000/time_in_millies);
   else
      return 0;
}


uint64_t total_packets=0;
uint64_t WrongPortPkts=0;
uint64_t total_bytes=0;
uint64_t total_cycles;
uint64_t useful_cycles;
static uint64_t flag = 0;
static uint64_t first_packet_seen=0, last_packet_seen;

static int did_work_request = 0;
CVMX_SHARED uint64_t total_perfmbps=0, total_hfaperfmbps=0;

void print_core_local_stats(uint64_t first_packet_seen, uint64_t last_packet_seen)
{
    uint64_t time_taken, local_mbps=0, local_hfa_mbps=0;
    if (!first_packet_seen) //Not seen a packet yet...!
       return;

    time_taken = last_packet_seen - first_packet_seen;
    local_mbps = unit_per_sec(first_packet_seen, last_packet_seen, total_bytes*8)/1000000;
    printf("Total cycles %lu     Utilization %d\n ", time_taken,((profile_stats[PASS_CYCLES].total)*100)/time_taken);
    printf("Mbps for the last burst: %lu\n", local_mbps);
    if (cav_profile)
    {
        local_hfa_mbps = unit_per_sec(first_packet_seen, last_packet_seen, ((profile_stats[HFA_LENGTH].total)*8))/1000000;
        printf("Pps for the last burst: %lu\n", unit_per_sec(first_packet_seen, last_packet_seen, total_packets));
        printf("HFA Mbps for the last burst: %lu\n", local_hfa_mbps);
        total_perfmbps += local_mbps; 
        total_hfaperfmbps += local_hfa_mbps; 
    }
    printf("Total Packets: %lu Total Bytes: %lu\n", total_packets, total_bytes);
    printf("Total Wrong Packets: %lu\n", WrongPortPkts);
}

void * octeonSE_acquire(uint32_t *len, uint64_t *addr,int timeout)
{
    cvmx_wqe_t    *work;
    static uint64_t current_cycle, prev_cycle;
    static uint64_t millies1=0;
    static uint64_t packets_last=0;
    static uint64_t bytes_last=0;
    /* millies:Time elapsed in wait loop */
    uint64_t millies = 0;
    uint64_t ret = 0;
    int my_core = cvmx_get_core_num();
    uint64_t        port;

    if (cvmx_likely(first_packet_seen))
        prev_cycle = cvmx_get_cycle();

    do {

#ifdef CAV_OCT_LINUX
        if (cav_breakloop)
        {
            /* We will be exiting, cleanup ur act */
            if(func_processCtx_octeon)
                (*func_processCtx_octeon)(1);
            return NULL;
        }
#endif
#if 0
#ifdef CAV_OCT_SE
        if(cvmx_unlikely(cav_cli))
        {
            if (isLastCore)
            {
                cli_readline();
            }

           if (isLastCore)
                getStats(NULL, NULL);

            if(printStats)
            {
                if(func_pStats)
                    (*func_pStats)();
                printStats = 0;
            }
        }
#endif
#endif
        if (cvmx_unlikely(is_my_turn()))
        {
           cvmx_rwlock_wp_write_lock(&lock_wstats);

           core_counter--;

           printf("*****************************************************************************\n");                       
           printf("Core %d Printing Stats\n",my_core);
           print_core_local_stats(first_packet_seen, last_packet_seen);
           (*func_print_profile_stats)();
           //following line i- stat SSO_Q doesnt take care of time after last_packet

           if (func_show_preproc_profile)    
               (*func_show_preproc_profile)();
#ifdef CAV_OCT_HFA
           if (func_show_rbuf_stat)    
              (*func_show_rbuf_stat)();
#endif
           millies1 = 0;

           if ((cvmx_get_core_num() == 0) && cav_profile) 
           {
              printf("______________________________________________________________________\n");
              printf("Total Perf:%llu Mbps   Total HFA Perf:%llu Mbps\n",total_perfmbps, total_hfaperfmbps);
              printf("______________________________________________________________________\n");
              total_perfmbps=0, total_hfaperfmbps=0;
           }

           cvmx_rwlock_wp_write_unlock(&lock_wstats);
           CVMX_SYNCW;

           if (func_pStats)
               (*func_pStats)();

        }

        if (cvmx_likely(first_packet_seen))
        {
            pass_all_cycle = cvmx_get_cycle();
            pass_sso_cycle = cvmx_get_cycle();
        }

        if (USE_ASYNC_IOBDMA && did_work_request)
            work = cvmx_pow_work_response_async(CVMX_SCR_SCRATCH);
        else
            work = cvmx_pow_work_request_sync (CVMX_POW_WAIT);
        did_work_request = 0;

        if (cvmx_unlikely(work == NULL)) 
        {
            if (cvmx_likely(first_packet_seen))
                if(cvmx_read_csr(CVMX_SSO_IQ_COM_CNT))
                    account_stats(cvmx_read_csr(CVMX_SSO_IQ_COM_CNT), SSO_Q);

            if (USE_ASYNC_IOBDMA) {
                if(cvmx_get_core_num())
                    cvmx_pow_work_request_async(CVMX_SCR_SCRATCH, CVMX_POW_NO_WAIT);
                else {
                    cvmx_pow_work_request_async(CVMX_SCR_SCRATCH, CVMX_POW_NO_WAIT);
                }
                did_work_request = 1;
            }

            if (func_processCtx_octeon)
                (*func_processCtx_octeon)(1);

            current_cycle = cvmx_get_cycle();

            if (cvmx_unlikely((current_cycle - prev_cycle) > CYCLES_PER_MILLI))
            {
                prev_cycle = current_cycle;
                millies  += 1; 
                millies1 += inc;//Only first core increments
            }

            if (cvmx_unlikely(millies1 > MILLIES_DONE))
            {

               //Only first core comes here  
               core_counter = total_cores - 1;

               millies1 = 0;
               CVMX_SYNCW;
            }
            /* Exit from the wait loop if time elapsed is more than end time */
            if(millies > timeout)
                return 0;
            continue;
        }

        if (cvmx_unlikely(!first_packet_seen))
            first_packet_seen = cvmx_get_cycle();
        else
            account_cycles(pass_sso_cycle, SSO_CYCLES);

        total_packets ++;
        total_bytes += cvmx_wqe_get_len(work);

        if(rcv_cores)
        {
            if(cvmx_get_core_num() < rcv_cores)
            {
                //frm wire
                uint32_t tag = cvmx_wqe_get_tag(work);
                //uint32_t grp_val = ((tag & 0xf)%14)+2 ;
                uint32_t grp_val = ((tag)%(total_cores - rcv_cores))+rcv_cores ;
                uint32_t tt = cvmx_wqe_get_tt(work);
                //printf("[%d] tag %d %d \n",0,tag, tt);
                cvmx_pow_tag_sw_desched_nocheck(tag,tt,grp_val ,0);
                work = NULL;
                continue;
            }
            else
            {	
                uint32_t tag = cvmx_wqe_get_tag(work);
            }
        }

        port = cvmx_wqe_get_port(work);

        /* Interlaken - fix port number */
        if (((port & 0xffe) == 0x480) || ((port & 0xffe) == 0x580))
            port &= ~0x80;
#if 1
		if(cvmx_unlikely(get_toggle_port(port) == -1))
        {
            cvmx_helper_free_packet_data(work);
            cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, 0);
            work = NULL;
            WrongPortPkts++;
            continue;
        }
#endif
        /* Check for errored packets, and drop.  If sender does not respond
        ** to backpressure or backpressure is not sent, packets may be truncated if
        ** the GMX fifo overflows */
        if (cvmx_unlikely(work->word2.snoip.rcv_error))
        {
            /* Work has error, so drop */
            cvmx_helper_free_packet_data(work);
		    cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, 0);
			work = NULL;
            continue;
        }
        else if (cvmx_unlikely(work->word2.s.IP_exc) && (work->word2.snoip.err_code == CVMX_PIP_IPV4_HDR_CHK))
        {
            cav_oct_err_flag = CAV_ERR_IP_CS;
        }
        else if (cvmx_unlikely(work->word2.s.L4_error) && (work->word2.snoip.err_code == CVMX_PIP_CHK_ERR))
        {
            cav_oct_err_flag = CAV_ERR_L4_CS;
        }
        else
        {
            cav_oct_err_flag = CAV_ERR_NONE;
        }

    } while (work == NULL);

    *len = cvmx_wqe_get_len(work);

    if (work->word2.s.bufs == 0)
    {
        *addr = cvmx_ptr_to_phys(work->packet_data);
        if (cvmx_likely(!work->word2.s.not_IP))
        {
            /* The beginning of the packet moves for IP packets */
            if (work->word2.s.is_v6)
                *addr += 2;
            else
                *addr += 6;
        }
        else
        {
            /* WARNING: This code assume that the packet is not RAW. If it was,
               we would use PIP_GBL_CFG[RAW_SHF] instead of
               PIP_GBL_CFG[NIP_SHF] */
            cvmx_pip_gbl_cfg_t pip_gbl_cfg;
            pip_gbl_cfg.u64 = cvmx_read_csr(CVMX_PIP_GBL_CFG);
            *addr += pip_gbl_cfg.s.nip_shf;
        }
    }
    else
    {
        *addr = work->packet_ptr.s.addr;
    }
#ifdef DUMP_PACKETS
    printf("Processing packet\n");
    cvmx_helper_dump_packet(work);
#endif
    *addr = (uint64_t)cvmx_phys_to_ptr(*addr);

    if (USE_ASYNC_IOBDMA) {
        if(cvmx_get_core_num())
            cvmx_pow_work_request_async_nocheck(CVMX_SCR_SCRATCH, CVMX_POW_WAIT);
        else {
            cvmx_pow_work_request_async_nocheck(CVMX_SCR_SCRATCH, CVMX_POW_WAIT);
        }
        did_work_request = 1;
    }

    return (void *)work;

}

int octeonSE_inject(void * work)
{
        cvmx_wqe_t *wqe;
        cvmx_pko_command_word0_t    pko_command;
        cvmx_buf_ptr_t                packet_ptr;
        uint64_t                    port;
        int queue, ret, pko_port, corenum;


        pko_port = -1;
        corenum = cvmx_get_core_num();

        
        wqe = (cvmx_wqe_t *)work;
        port = cvmx_wqe_get_port (wqe);
        
        port = get_toggle_port(port);

        if (port == -1)
        {
            printf("packet from unconfigured port \n");
            cvmx_helper_free_packet_data(work);
            cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, 0);
            goto endwithoutsend;
        }

#if 000	
        if(port1 != UINT64_MAX && port2 != UINT64_MAX)
        {
            if(port == port1)
                port = port2;
            else if(port == port2)
                port = port1;
			else {
					printf("packet from wrong port\n");
			    	cvmx_helper_free_packet_data(work);
                	cvmx_fpa_free(work, CVMX_FPA_WQE_POOL, 0);
					goto endwithoutsend;
			}
        }
#endif

    if (octeon_has_feature(OCTEON_FEATURE_PKND))
    {
        /* PKO internal port is different than IPD port */
        pko_port = cvmx_helper_cfg_ipd2pko_port_base(port);
        queue = cvmx_pko_get_base_queue_pkoid(pko_port);
        queue += (corenum % cvmx_pko_get_num_queues_pkoid(pko_port));
    }
    else
    {
        queue = cvmx_pko_get_base_queue (port);
        queue += (corenum % cvmx_pko_get_num_queues(port));
    }

        cvmx_pko_send_packet_prepare (port, queue, CVMX_PKO_LOCK_CMD_QUEUE);
        //cvmx_pko_send_packet_prepare (port, queue, CVMX_PKO_LOCK_ATOMIC_TAG);

#ifdef DUMP_PACKETS
       printf("Processing packet\n");
       cvmx_helper_dump_packet(wqe);
#endif
        pko_command.u64 = 0;
        if (wqe->word2.s.bufs == 0) {
            pko_command.s.total_bytes = cvmx_wqe_get_len (wqe);
            pko_command.s.segs = 1;
            packet_ptr.u64 = 0;
            packet_ptr.s.pool = CVMX_FPA_WQE_POOL;
            packet_ptr.s.size = CVMX_FPA_WQE_POOL_SIZE;
            packet_ptr.s.addr = cvmx_ptr_to_phys (wqe->packet_data);
            if (cvmx_likely (!wqe->word2.s.not_IP)) {
                if (wqe->word2.s.is_v6)
                    packet_ptr.s.addr += 2;
                else
                    packet_ptr.s.addr += 6;
            }
        }
        else {
            pko_command.s.total_bytes = cvmx_wqe_get_len (wqe);
            pko_command.s.segs = wqe->word2.s.bufs;
            packet_ptr = wqe->packet_ptr;
            cvmx_fpa_free (wqe, CVMX_FPA_WQE_POOL, 0);
        }
        
        if (cvmx_pko_send_packet_finish (port, queue, pko_command, packet_ptr,
                    CVMX_PKO_LOCK_CMD_QUEUE))
            printf ("failed to send packet\n");

endwithoutsend:

		if(flag)
            account_cycles(pass_all_cycle, PASS_CYCLES);
        else 
            flag = 1;
        last_packet_seen = cvmx_get_cycle();
        /* Crude solution to null tag explicitly
             * This may not be a permanent solution - review all tag issues
             * Bug #4327 & #4428 */
        //cvmx_pow_tag_sw_null ();
        return 0;
}

int octeonSE_shutdown(void)
{
    int first_core;
    cvmx_coremask_barrier_sync(&(cvmx_sysinfo_get()->core_mask));
    first_core = cvmx_coremask_get_first_core (&(cvmx_sysinfo_get ()->core_mask));
    if (cvmx_get_core_num() == first_core)
		cvmx_helper_shutdown_packet_io_global();
}

void getStats(uint64_t * received,uint64_t *dropped)
{
    int idx = 0;
    cvmx_pip_stat_inb_pktsx_t pip_stat_inb_pktsx;
    cvmx_pip_stat0_prtx_t stat0;
    int localPort, interface;
    uint64_t gmx_drop;
    static uint64_t rcvd, drpd;

    if (OCTEON_IS_MODEL(OCTEON_CN78XX))
    {
      int i;
      rcvd=0;drpd=0;
      cvmx_pip_port_status_t status;
      for(i=0;i<used_port_sets;i++)
      {
         cvmx_pip_get_port_status(port_set[i][0], 0, &status); //Stats will not get cleared after read in the API
         rcvd += (status.inb_packets+status.inb_errors); 
         drpd += status.dropped_packets;
         cvmx_pip_get_port_status(port_set[i][1], 0, &status);
         rcvd += (status.inb_packets+status.inb_errors); 
         drpd += status.dropped_packets;
      }
      cvmx_pki_statx_stat0_t pki_stat0;
    }
    else
    {
      if (octeon_has_feature(OCTEON_FEATURE_PKND))
      {
          for (idx=0; idx<=63; ++idx)
          {
              stat0.u64 = cvmx_read_csr(CVMX_PIP_STAT0_X(idx));
              pip_stat_inb_pktsx.u64 = cvmx_read_csr(CVMX_PIP_STAT_INB_PKTS_PKNDX(idx));
              drpd += stat0.s.drp_pkts;
              rcvd += pip_stat_inb_pktsx.s.pkts;
          }
      }
      else
      {
          for (idx=0; idx<=3; ++idx)
          {
              localPort = cvmx_helper_get_interface_index_num (idx);
              interface = cvmx_helper_get_interface_num (idx);
              gmx_drop  = cvmx_read_csr (CVMX_GMXX_RXX_STATS_PKTS_DRP (localPort, interface));
              stat0.u64 = cvmx_read_csr(CVMX_PIP_STAT0_PRTX(idx));
              pip_stat_inb_pktsx.u64 = cvmx_read_csr(CVMX_PIP_STAT_INB_PKTSX(idx));
              drpd += stat0.s.drp_pkts;
              drpd += gmx_drop;
              rcvd += pip_stat_inb_pktsx.s.pkts;
              gmx_drop = 0;
              cvmx_write_csr(CVMX_GMXX_RXX_STATS_PKTS_DRP (localPort, interface), gmx_drop);
          }
          for (idx=16; idx<=19; ++idx)
          {
              localPort = cvmx_helper_get_interface_index_num (idx);
              interface = cvmx_helper_get_interface_num (idx);
              gmx_drop  = cvmx_read_csr (CVMX_GMXX_RXX_STATS_PKTS_DRP (localPort, interface));
              stat0.u64 = cvmx_read_csr(CVMX_PIP_STAT0_PRTX(idx));
              pip_stat_inb_pktsx.u64 = cvmx_read_csr(CVMX_PIP_STAT_INB_PKTSX(idx));
              drpd += stat0.s.drp_pkts;
              drpd += gmx_drop;
              rcvd += pip_stat_inb_pktsx.s.pkts;
              gmx_drop = 0;
              cvmx_write_csr(CVMX_GMXX_RXX_STATS_PKTS_DRP (localPort, interface), gmx_drop);
          }

          // 70xx specific port 24 for AGL
          if (OCTEON_IS_MODEL(OCTEON_CN70XX))
          {   idx=24;
              stat0.u64 = cvmx_read_csr(CVMX_PIP_STAT0_PRTX(idx));
              pip_stat_inb_pktsx.u64 = cvmx_read_csr(CVMX_PIP_STAT_INB_PKTSX(idx));
              drpd += stat0.s.drp_pkts;
              rcvd += pip_stat_inb_pktsx.s.pkts;
          }

          for (idx=32; idx<=39; ++idx)
          {
              stat0.u64 = cvmx_read_csr(CVMX_PIP_STAT0_PRTX(idx));
              pip_stat_inb_pktsx.u64 = cvmx_read_csr(CVMX_PIP_STAT_INB_PKTSX(idx));
              drpd += stat0.s.drp_pkts;
              rcvd += pip_stat_inb_pktsx.s.pkts;
          }
      }
    }
    if (received)
        *received = rcvd;
    if (dropped)
        *dropped = drpd;
}

