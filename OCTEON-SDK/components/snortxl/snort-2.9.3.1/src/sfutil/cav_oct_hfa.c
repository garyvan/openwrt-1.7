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
        
#ifdef CAV_OCT_HFA
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include "util.h"
#include "snort_debug.h"
#include "fpcreate.h"
#include "snort.h"
#include <sys/queue.h>
#include <cav_oct_hfa.h>
#include "fpdetect.h"
#include <cvmx.h>
#include <cvmx-coremask.h>
#include <cvmx-rwlock.h>
#include <cvmx-fau.h>
#include <cvmx-bootmem.h>
#include <cvmx-utils.h>
#include <octeon-model.h>
#include "exec_intf.h"
#include "stats.h"
#include "encode.h"
#include "active.h"
#include "stream5_common.h"
#ifdef CAV_OCT_LINUX
#include "gzguts.h"
#endif
#include "sfcontrol_funcs.h"
#ifdef CAV_OCT_SE
#include "memfsmap.h"
#ifdef CAV_HFA_ENGINE_STATS
#include "hfa_pfc_cases.h"
#endif
#endif
#ifdef CAV_OCT_ASYNC
#include "stream_api.h"
#include "profiler.h"
extern int CheckTagging(Packet *);
#endif

uint32_t hfa_pipeline_depth = 4;
uint64_t alloc_fpa=0, free_fpa=0;

unsigned int pomdidx = 0;      /* Keeps track of pomdlist index */
OTNX_MATCH_DATA *pomdlist[40]; /* Store omd context for post process 
                                     if hfa_pipeline_depth is 0 */
/* defines */
#define CAV_OCT_HFADEV_CACHE_SIZE   16384 
#define CAV_OCT_HFA7XXX_CACHE_SIZE   4096 
#define PATTERN_ARRAY_ALLOC_SIZE 10
#define CAV_OCT_HFA_MAX_GRAPHS   2048 
#define MAX_GRAPH_LIST  100
#define CAV_GRAPH_ARRAY_SIZE (CAV_OCT_HFA_MAX_GRAPHS*sizeof(CAV_OCT_HFA_GRAPHS))
#define CAV_OCT_HFA_GRAPH_CACHE_SIZE 1000
#define XKPHYS(a) ((uint64_t)1 <<63 | a)
#define cavOctCore (cvmx_get_core_num())
/* fau reg for graph cache stats - hits/time etc */
#define FAU_GRAPH_USAGE(_x)     ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + (8*_x)))

#define dbgprintf(level, x...) if (level <= LOG_LEVEL) printf(x)
#define dbgl1(x...) dbgprintf(LVERBOSE, x)
#define dbgl2(x...) dbgprintf(LNOISY, x)
#define dbginfo(x...) dbgprintf(LINFO, x)
#define LNOISY 3
#define LVERBOSE 2
#define LINFO 1
#define LQUIET 0
#define BLK_SIZE  2048
#define LOG_LEVEL LINFO /* Modify for more verbose output */
#define ERROR printf

#define swap32(x)   \
(((x<<24)&0xff000000)|((x>>24)&0xff)|((x<<8)&0xff0000)|((x>>8)&0xff00))
/* Number of clusters. except cn68xx all devices have one each  */
CVMX_SHARED static unsigned int NCLUST = 1;
CVMX_SHARED CAV_OCT_HFA_GRAPHS *graph_array;  
CVMX_SHARED void *snort_pkt_pool_ptr; 
CVMX_SHARED void *sbufpool_2k_ptr , *sbufpool_128b_ptr ;
CVMX_SHARED void *pktpool_ptr; 

/* globals */
extern CVMX_SHARED unsigned int sf_cmask;
extern MG_DATA mg_list[12];
extern int profile;
extern int cav_profile, create_graphs, merge_graphs;
static int pending = 0, max_pending = -1, process_at_max_pending;
unsigned int process = 0;

typedef struct _mpse_struct {

    int    method;
    void * obj;
    int    verbose;
    uint64_t bcnt;
    char   inc_global_counter;

} MPSE;

CVMX_SHARED static int cacheEntry = 0;
CVMX_SHARED int global_cache_loads = 0;
CVMX_SHARED int global_cache_evicts = 0;
int global_memonly_packets = 0;
int global_cache_graphs = 0;
int rfull = 0,num_match = 0;
uint32_t num_partial = 0;

#ifdef CAV_OCT_SE
char graphpath[100]="graphs/";
#else
char graphpath[100]="./snortRuleDir/graphs/";
#endif
unsigned int exactProcessed = 0;
CAV_OCT_HFA_SBUF_NODE * sbufList = NULL;

CVMX_SHARED cvmx_rwlock_wp_lock_t lock;
CVMX_SHARED cvmx_rwlock_wp_lock_t usage_lock;
CVMX_SHARED OCT_HFA_GRAPHLIST glist[MAX_GRAPH_LIST]; 
CVMX_SHARED static hfa_dev_t hfa_dev;
CVMX_SHARED static int cavOctTotCtx=0;
CVMX_SHARED static int total_graphs = 0;

/* forward declarations */
unsigned int cav_oct_core;
static void cavOctHfaMatchCallback(int patno, int matchno, int startoffset, int endoffset, void *matchcba);

/* extern function handles */
extern void (*func_processCtx_octeon)(int);
extern void (*func_processCtx_pcap)(int);
#ifdef CAV_OCT_LINUX
extern void (*func_processCtx_lin)(int);
#endif
extern void (*func_print_profile_stats)(void);
extern void (*func_show_rbuf_stat)(void);
extern void (*func_time_start)(void);
extern int cavOctDaqFlag;
extern void Replace_ModifyPacket(Packet *p);
CVMX_SHARED cvmx_arena_list_t       cav_arena;
CVMX_SHARED cvmx_spinlock_t         cav_arena_lock;
CVMX_SHARED void*                   cav_arena_addr = NULL;
CVMX_SHARED int                     flag_dev_init=0;        // flag to be set in case hfa dev init failures
inline void *cav128BAlloc(void)
{
    void *tmp;
    tmp = cvmx_fpa_alloc(CAV_OCT_SNORT_128B_POOL);
    if(!tmp)
       ERROR("CORE %d: failed to allocate 128B pool\n", cavOctCore);
    return tmp;
}

inline void cav128BFree(void* ptr)
{
    cvmx_fpa_free(ptr, CAV_OCT_SNORT_128B_POOL, 0);
}

/* SnortXL - Move these to the profile file */ 
profile_stat_t profile_stats[MAX_METRICS];
static char *enum_to_string(int i)
{
    switch(i)
    {
       case HFA_CYCLES:
          return "HFA_CYCLES";
       case HFA_JUMBO_BUFFERS:
          return "HFA_JUMBO_BUFFERS";
       case HFA_LENGTH:
          return "HFA_SUBMIT";
       case PP_CYCLES:
          return "PP_CYCLES";
       case SNORT_LENGTH:
          return "SNORT_SUBMIT";
       case SNORT_DETECT_CYCLES:
          return "SNORT_DETECT_CYCLES";
       case SNORT_PP_CYCLES:
          return "SNORT_PP_CYCLES";
       case SNORT_TOTAL_CYCLES:
          return "TOTAL_CYCLES";
       case SNORT_PREPROC_CYCLES:
          return "MEMCPY CYCLES";
       case SUB_FAIL:
          return "MEMCPY BYTES";
       case SNORT_PROC_CYCLES:
          return "PROCESS_CYCLES";
       case PASS_CYCLES:
          return "PASS_CYCLES";
       case SSO_CYCLES:
          return "SSO_CYCLES";
       case SSO_Q:
          return "SSO USAGE";

       default:
          return "UNKNOWN";
    }
}

extern uint64_t total_packets;
void print_profile_stats(void)
{
  int i;
  int j = 0;
  uint64_t avg;
  if (cav_profile)
  {
      printf("\n=======================================================\n");
      printf("%20s|%15s|%10s|%10s|%10s|%10s|\n"," ","Total","Max","Min","Hits","Avg");
      for(i=0;i<MAX_METRICS;i++)
      {
          if (i != SNORT_TOTAL_CYCLES)
          {
              avg = 0;
              printf("%20s", enum_to_string(i));
              if (profile_stats[i].hits)
                  avg = profile_stats[i].total/profile_stats[i].hits;
              printf("|%15lu|%10lu|%10lu|%10lu|%10lu|\n", profile_stats[i].total, 
                      profile_stats[i].max, profile_stats[i].min, profile_stats[i].hits, avg);
          }
      }
      printf("\n=======================================================\n");
  }

  if (profile)
  {
      printf("Hits : ");
      for(i=0;i<MAX_METRICS;i++)
      {
          if (i != SNORT_TOTAL_CYCLES)
              printf("%8lu ",profile_stats[i].hits);
      }
      printf("\n");

      printf("Avg  : ");
      for(i=0;i<MAX_METRICS;i++)
      {
          if (i != SNORT_TOTAL_CYCLES)
          {
              if (profile_stats[i].hits)
                  printf("%8lu ",profile_stats[i].total/profile_stats[i].hits);
              else
              {
                  avg = 0;
                  printf("%8lu ",avg);
              }
          }
      }
      printf("\n");
  }
  if (cav_profile)
  {
      for(i=0;i<MAX_GRAPH_LIST;i++)
      {
          if(glist[i].graph_handle != NULL)
          {
              /* Code to print graph name and its count*/
              j = 0;
              while (graph_array[j].graph_handle != NULL)
              {
                  if(glist[i].graph_handle == graph_array[j].graph_handle)
                  {
                      if (cvmx_fau_fetch_and_add64(FAU_GRAPH_USAGE(i), 0))
                         printf("%d) graph: %s cached: %d count: %lu\n", i, graph_array[j].gname, glist[i].cached, 
                                cvmx_fau_fetch_and_add64(FAU_GRAPH_USAGE(i), 0));
                      break;
                  }
                  j++;
              }
          }
      }
  }
}

void show_rbuf_stat(void)
{
    if (cav_profile)
    {
        int i;
        for (i = 0; i < 8; i++) {
            printf("   POOL: %d, free pages: 0x%llu\n", 
                    i, CAST64(cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(i))));
        }

        printf("rfull: %d num_partial: %u num_match: %d hfa_submit ratio: %.02f\n", 
                rfull, num_partial, num_match, (float)profile_stats[HFA_LENGTH].total/profile_stats[SNORT_LENGTH].total);
        printf("cloads: %d cevicts: %u memonly_packets: %d\n", 
                global_cache_loads, global_cache_evicts, global_memonly_packets);
    }
    else
    {
        dbgl1("alloc fpa:%ld,free fpa:%ld\n",alloc_fpa,free_fpa);
        printf("rf: %d np: %u nm: %d cl: %d ce: %d mp: %d rt: %.02f\n", 
                rfull, num_partial, num_match, global_cache_loads, global_cache_evicts, global_memonly_packets, 
                (float)profile_stats[HFA_LENGTH].total/profile_stats[SNORT_LENGTH].total);
    }
}

int 
fd_read (gzFile gzf, void *buf, int size) 
{
    int totsize = 0, blocksize, items;
    
    while (!gzeof(gzf))
    {
        blocksize = (size - totsize) < BLK_SIZE ? (size - totsize) : BLK_SIZE;
        items = gzread(gzf, buf + totsize, blocksize);
        if (items != blocksize)
        {
            return items;
        }
        else if (blocksize == 0)
            break;
        else
            totsize += blocksize;
    }
    return totsize;
}

int get_size (char* graph, unsigned int *graph_len)
{
#ifdef CAV_OCT_LINUX
    int csize = 0,size = 0; 
    FILE *fd = NULL;
    gzFile gzf = NULL;
    if ((fd = fopen (graph, "rb")) == NULL) {
        printf ("unable to open file: %s\n",graphpath );
        return 1;
    }
    fseek (fd, 0, SEEK_END);
    csize = ftell(fd);
    if ((gzf = gzopen (graph, "rb")) == NULL) {
         printf ("unable to open file: %s\n", graph );
        return 1;
    }
    if(!gzdirect(gzf))
    {
        fseek(fd, csize - 4, SEEK_SET);
        fread(&size,4,1,fd);
        *graph_len = swap32(size);
    }
    else
       *graph_len = csize;
    fclose(fd);
    gzclose(gzf);
    return 0;
#else 
    gzFile gzf = NULL;
    if ((gzf = gzopen (graph, "rb")) == NULL) {
        printf ("unable to open file: %s\n", graph);
        return 1;
    }

    *graph_len = gz_get_size(gzf);
    gzclose(gzf);
    return 0;
#endif
}

static inline int
hfa_is_graph_cached(hfa_graph_t *graph_handle)
{
   return (HFA_GRAPHLOAD_FINISH == graph_handle->state);
}

static inline uint16_t
hfa_get_partial_matches(hfa_searchparams_t *psparam)
{
   hfa_rptr_overload_t     *rbuf = NULL;
   uint64_t                *ptr_odata = NULL;
   uint64_t                _rmdata;
   hfa_rmdata_t            *prmdata = NULL;

   rbuf = (hfa_rptr_overload_t *)(psparam->output.ptr);
   ptr_odata = &(rbuf->rptrbase); 
   _rmdata = (((uint64_t *) ptr_odata)[0]);
   prmdata = ((hfa_rmdata_t *) &_rmdata);

   return(prmdata->s.nument);
}

int cavOctHfaFindGraph(CAV_OCT_HFA_MPSE *cohm, char *gfname, int graph_data_len)
{
    int i = 0;
    FLAG_LIST *tmp;

    while(graph_array[i].graph_handle)
    {
        if (graph_array[i].size == graph_data_len)
        {
            dbgl2(" graph(%s) with handle %p"
                    " at index %d  %s\n", gfname, (void *)cohm->graph_handle, i,graph_array[i].gname);
            if(!strcmp(gfname,graph_array[i].gname))
            {
                cohm->graph_handle = graph_array[i].graph_handle;
                tmp = (FLAG_LIST *)SnortAlloc(sizeof(FLAG_LIST));
                tmp->cohm = cohm;
                if(graph_array[i].head[cavOctCore] == NULL)
                {
                    graph_array[i].head[cavOctCore]=tmp ;
                    tmp->next=NULL;
                }
                else
                {
                    if(!(cohm == graph_array[i].head[cavOctCore]->cohm))
                    {
                        tmp->next = graph_array[i].head[cavOctCore];
                        graph_array[i].head[cavOctCore]=tmp ;
                    }
                    else
                    {
                        free(tmp);
                    }
                }
                dbgl1("C%d: Found already loaded graph(%s) with handle %p" 
                        " at index %d \n", cavOctCore, gfname, (void *)cohm->graph_handle, i);
                return 0;
            }
        }
        i++;
    }
    dbgl1("ERROR: no match happened \n");
    return -1;
}

int cavOctHfaAddGraph(hfa_graph_t *graph_handle, char * gfname, int graph_data_len)
{
    int i = 0;
    static int total_graphs_size = 0;
    if (total_graphs >= CAV_OCT_HFA_MAX_GRAPHS)
    {
        dbginfo("Total graph count exceeded limit(%d)\n",
                CAV_OCT_HFA_MAX_GRAPHS);
        return -1;
    }
    i = total_graphs;
    graph_array[i].size = graph_data_len;
    strcpy(graph_array[i].gname, gfname);
    graph_array[i].graph_handle = graph_handle;
    total_graphs++;
    total_graphs_size += graph_data_len;
    dbgl1("cavOctHfaAddGraph: Added graph %s of size %d with handle %p"
            " at index %d. Total Graphs Size: %d\n", graph_array[i].gname,
            graph_array[i].size, (void *)graph_array[i].graph_handle, i,
            total_graphs_size);
    return 0;
}

int cavOctHfaGraphListInit(void)
{
    int i;
    for(i = 0; i < MAX_GRAPH_LIST ; i++)
    {
        glist[i].graph_handle = NULL ;
        glist[i].cached = 0;
        cvmx_fau_atomic_write64(FAU_GRAPH_USAGE(i), 0);
    }
    return 0;
}

/* SnortXL
 * Fuction for SnortXL HFA related initializations -
 * 1. Init Device
 * 2. Memory Pools
 * 3. Stats Init
 * 4. Graph structures Init
 */
int cavOctHfaInit (void)
{
    int ret = 0;
    int status = 0;
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM) 
    {   flag_dev_init=0;
        if(cav_oct_is_first_core())
        {
            if(HFA_SUCCESS != hfa_dev_init(&hfa_dev))  
            {   
                flag_dev_init=1;
                ERROR("hfa_dev_init failed....Initialization failed\n");
                goto dev_err;
            }
            if(cavOctHfaGraphListInit()) 
             {
                flag_dev_init=1;
                ERROR("cavOctHfaGraphListInit failed.....Initialization failed\n");
                goto dev_err;
             }
            cvmx_rwlock_wp_init(&lock);

            graph_array = cvmx_bootmem_alloc_named(CAV_GRAPH_ARRAY_SIZE, 128, "graph_array");
            if ( graph_array == NULL)
            {   
                flag_dev_init=1;
                ERROR("Error creating graph_array: Insufficient memory\n");
                goto dev_err;
            }
            dbgl1("graph_array allocated at: %p \n",graph_array); 
            memset((uint64_t *)graph_array, 0x00, CAV_GRAPH_ARRAY_SIZE);

            if (cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (CAV_OCT_SNORT_8K_POOL))) {
                if( (cvmx_fpa_get_block_size(CAV_OCT_SNORT_8K_POOL) )> 0)
                    status = cvmx_fpa_shutdown_pool(CAV_OCT_SNORT_8K_POOL);
            }
            if (status == 0)
            {
                snort_pkt_pool_ptr =  cvmx_bootmem_alloc_named(CAV_OCT_SNORT_8K_POOL_SIZE * CAV_OCT_SNORT_8K_POOL_COUNT, CAV_OCT_SNORT_8K_POOL_SIZE , "pkt_pool");
                if ( snort_pkt_pool_ptr == NULL)
                {
                    flag_dev_init=1;
                    ERROR("Error creating Pool, Insufficient memory...Initialization failed\n");
                    goto dev_err;
                }
                ret = cvmx_fpa_setup_pool (CAV_OCT_SNORT_8K_POOL, "snort_pkt_pool", snort_pkt_pool_ptr, CAV_OCT_SNORT_8K_POOL_SIZE ,CAV_OCT_SNORT_8K_POOL_COUNT);
                if ( ret < 0)
                {
                    flag_dev_init=1;
                    ERROR("Error creating Pool, fpa_setup_pool failed\n");
                    goto dev_err;
                }

                printf("FPA Pool %d (%s) created with %d buffers. Size: %dMB\n", CAV_OCT_SNORT_8K_POOL, 
                        "snort_pkt_pool", CAV_OCT_SNORT_8K_POOL_COUNT, (CAV_OCT_SNORT_8K_POOL_SIZE * CAV_OCT_SNORT_8K_POOL_COUNT) >> 20);
            }
            else {
                dbginfo("Warning!\t Pool for snort packets (pool %d) is already initialized.\n", CAV_OCT_SNORT_8K_POOL);
                status = 0.;
            }


            if (cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (CAV_OCT_SNORT_2K_POOL)) ) {
                if( (cvmx_fpa_get_block_size(CAV_OCT_SNORT_2K_POOL) )> 0)
                    status = cvmx_fpa_shutdown_pool(CAV_OCT_SNORT_2K_POOL);
            }
            if (status == 0)
            {
                sbufpool_2k_ptr =  cvmx_bootmem_alloc_named (CAV_OCT_SNORT_2K_POOL_SIZE * CAV_OCT_SNORT_2K_POOL_COUNT, CAV_OCT_SNORT_2K_POOL_SIZE , "sbuf_2k_pool");
                if ( sbufpool_2k_ptr == NULL)
                {
                    flag_dev_init=1;
                    ERROR("Error creating Pool, Insufficient memory...Initialization failed\n");
                    goto dev_err;

                }
                else
                    ret = cvmx_fpa_setup_pool (CAV_OCT_SNORT_2K_POOL, "snort_2k_pool", sbufpool_2k_ptr, CAV_OCT_SNORT_2K_POOL_SIZE, CAV_OCT_SNORT_2K_POOL_COUNT);
                if ( ret < 0)
                {
                    flag_dev_init=1;
                    ERROR("Error creating Pool, fpa_setup_pool failed\n");
                    goto dev_err;

                }
                printf("FPA Pool %d (%s) created with %d buffers. Size: %dMB\n", CAV_OCT_SNORT_2K_POOL, 
                        "snort_2k_sbuf_pool", CAV_OCT_SNORT_2K_POOL_COUNT, (CAV_OCT_SNORT_2K_POOL_SIZE * CAV_OCT_SNORT_2K_POOL_COUNT) >> 20);
            }
            else 
            {
                dbginfo("Warning!\t Pool for snort packets (pool %d) is already initialized.\n", CAV_OCT_SNORT_2K_POOL);
                status =0;
            }


#if (OCTEON_PPBUFPOOL != CAV_OCT_SNORT_128B_POOL)
            if (cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (CAV_OCT_SNORT_128B_POOL))) {
                if( (cvmx_fpa_get_block_size(CAV_OCT_SNORT_128B_POOL) )> 0)
                    status = cvmx_fpa_shutdown_pool(CAV_OCT_SNORT_128B_POOL);
            }
            if (status == 0)
            {
                sbufpool_128b_ptr = cvmx_bootmem_alloc_named (CAV_OCT_SNORT_128B_POOL_SIZE * CAV_OCT_SNORT_128B_POOL_COUNT, CAV_OCT_SNORT_128B_POOL_SIZE , "sbuf_128b_pool");
                if ( sbufpool_128b_ptr == NULL)
                {
                    flag_dev_init=1;
                    ERROR("Error creating Pool, Insufficient memory...Initialization failed\n");
                    goto dev_err;

                }
                ret = cvmx_fpa_setup_pool (CAV_OCT_SNORT_128B_POOL, "snort_128b_pool", sbufpool_128b_ptr, CAV_OCT_SNORT_128B_POOL_SIZE, CAV_OCT_SNORT_128B_POOL_COUNT);
                if ( ret < 0)
                {
                    flag_dev_init=1;
                    ERROR("Error creating Pool, fpa_setup_pool failed\n");
                    goto dev_err;

                }
                printf("FPA Pool %d (%s) created with %d buffers. Size: %dMB\n", CAV_OCT_SNORT_128B_POOL, 
                        "snort_128B_pool", CAV_OCT_SNORT_128B_POOL_COUNT, (CAV_OCT_SNORT_128B_POOL_SIZE * CAV_OCT_SNORT_128B_POOL_COUNT) >> 20);
            }
            else 
            {
                dbginfo("Warning!\t Pool for snort packets (pool %d) is already initialized.\n", CAV_OCT_SNORT_128B_POOL);
                status =0;
            }
#endif

            /* Arena for snort irregular/jumbo search buf allocations */
            cav_arena_addr = cvmx_bootmem_alloc_named (CAV_ARENA_SIZE, CVMX_CACHE_LINE_SIZE, "cav_arena");
                
            if ( cav_arena_addr == NULL)
            {
                 flag_dev_init=1;
                 ERROR("Error creating Pool, Insufficient memory...Initialization failed\n");
                 goto dev_err;

            }

            /* Initialize Arena */
            if (cvmx_add_arena(&cav_arena, cav_arena_addr,CAV_ARENA_SIZE) < 0) 
            {
                flag_dev_init=1;
                ERROR("Unable to add memory to HFA ARENA\n");
                goto dev_err;
            }
   
            printf("Shared Snort Arena allocated of size  %d\n", CAV_ARENA_SIZE >> 20);
            /* threadsafe cvmx_malloc spin lock initialization */
            cvmx_spinlock_init(&cav_arena_lock);
        
            printf("Result Buffer Size is %d \n", CAV_RBUF_SIZE);

        } /* End of Global Init by single core */

        func_processCtx_octeon = cavOctSbufPoll ;
        func_processCtx_pcap   = cavOctSbufPoll ;
#ifdef CAV_OCT_LINUX
        func_processCtx_lin    = cavOctSbufPoll ;
#endif

        func_time_start = TimeStart;
        func_print_profile_stats = print_profile_stats;
        func_show_rbuf_stat = show_rbuf_stat;
        func_cav128BAlloc   = cav128BAlloc; 
        func_cav128BFree    = cav128BFree; 
        if (!strcmp(STRING(HFAC_TARGET),"cn68xx"))
        { 
            /* 68xx has 3 clusters */ 
            NCLUST = 3;
            //max_tot_cache = CAV_OCT_HFADEV_CACHE_SIZE;
            dbgl1("NCLUST is set to %d for device cn68xx\n",NCLUST);
        }
        
        cav_oct_core = cvmx_get_core_num();

// any error in hfa dev initialization , jump  here and  for all cores call FatalError after all threads reach here 

dev_err:
       
        cav_oct_barrier_sync(0);
      if( flag_dev_init== 1)
         FatalError(" cavOctHfaInit() failed..");

    }

    if (search_type == SYNC)
        hfa_pipeline_depth = 0;
    else
        if(hfa_pipeline_depth > 20)
            hfa_pipeline_depth = 20;

    if(cav_oct_is_first_core())
        printf("HFA Pipeline Depth %d \n", hfa_pipeline_depth);
    init_prof_stats();
#ifdef CAV_HFA_ENGINE_STATS
    /* SnortXL : Incorporate this if HFA team willing to expose this option */
    hfa_busy_counters_init(0,15);
#endif 
    return 0;
}

/* SnortXL 
 * Copy search buffers and maintain it within cavium api
 */
#define CAV_SEARCHBUF_SIZE  CAV_OCT_SNORT_8K_POOL_SIZE
uint8_t * cav_search_prepare(int type, uint8_t *buffer, int *length)
{
    uint8_t *search_buf = NULL;
    
    if (cvmx_likely(*length < CAV_SEARCHBUF_SIZE))
        search_buf = cvmx_fpa_alloc(CAV_OCT_SNORT_8K_POOL);
    else 
    {
        search_buf = cav_arena_alloc( *length ,CVMX_CACHE_LINE_SIZE);
        account_stats(*length, HFA_JUMBO_BUFFERS);
    }

    if (search_buf == NULL)
        FatalError("Out of seach buffer POOL/arena memory \n");
    else
    {
        uint64_t start_prof_cycle = cvmx_get_cycle();
        memcpy(search_buf, buffer, *length);
        account_cycles(start_prof_cycle,SNORT_PREPROC_CYCLES);
        account_stats(*length, SUB_FAIL);
        return search_buf;

#if 000
/* SnortXL : Some buffers may be directly searchable - dont require to be copied Fix it */

struct cav_search_buf
{
    int type;
    void *buffer;
};

#define start_addr(ptr1, type1, member1) ((type1 *)((char *)(ptr1) - offsetof(type1, member1)))
#define CAV_SEARCHBUF_SIZE  (CAV_OCT_SNORT_8K_POOL_SIZE - offsetof(struct cav_search_buf, buffer))
        search_buf->type = type;

        if (type == 0) {
            search_buf->buffer = buffer;
        }
        else {
            if (*length > CAV_SEARCHBUF_SIZE)
            {
                printf("Length(%d) larger than mem pool(%d), curtailing!\n",*length, CAV_SEARCHBUF_SIZE); //a
                *length = CAV_SEARCHBUF_SIZE;
            }
            uint64_t strat_prof_cycle = cvmx_get_cycle();
            memcpy(&search_buf->buffer, buffer, *length);
            account_cycles(strat_prof_cycle,SNORT_PREPROC_CYCLES);
            account_stats(*length, SUB_FAIL);
        }

        return &search_buf->buffer;d
#endif
    }
    return NULL;
}

void cav_search_free(void *ptr, int length)
{
    if (length < CAV_SEARCHBUF_SIZE)
        cvmx_fpa_free(ptr, CAV_OCT_SNORT_8K_POOL, 0);
    else
        cav_arena_free(ptr);
#if 000
    /* SnortXL : see comments above */
    struct cav_search_buf *search_buf = (struct cav_search_buf *)start_addr(ptr, struct cav_search_buf, buffer);
#endif
    
}

/* Packet Allocation API 
 * Initialize sync specific flags
 * */
void* cavOctAlloc()
{
    int i;
    Packet *pkt = cvmx_fpa_alloc(CAV_OCT_SNORT_8K_POOL);
    
    if(pkt == NULL)
    {
        ERROR("CORE %d: failed to allocate packet\n", cavOctCore);
    }
    
    if (pkt != NULL)
    {
#ifdef CAV_OCT_ASYNC
        pkt->state_flag = CAV_STATE_NONE;
        pkt->omd_count = 0;
#endif
    }
    /*  SnortXL : Move to on-demand matchinfo allocation ??
	 *  But its ok/faster an less cluttered as long as hfa_pipeline depth is 
	 *  set to reasonable values
	 *  */

    pkt->matchInfo = (uint8_t*)cvmx_fpa_alloc(CAV_OCT_SNORT_8K_POOL);
   
    MATCH_INFO *matchInfo = (MATCH_INFO *)pkt->matchInfo;

    if(pkt->matchInfo == NULL)
    {
        printf("CORE %d:Unable to allocate matchinfo\n", cavOctCore);
    }
    
    pkt->iMatchInfoArraySize = 8;
    for(i = 0; i < pkt->iMatchInfoArraySize; i++)
    {
        matchInfo[i].iMatchCount  = 0;
        matchInfo[i].iMatchIndex  = 0;
        matchInfo[i].iMatchMaxLen = 0;
    }

    return pkt;
}

void cavOctFree(void *ptr)
{
    Packet *pkt = (Packet *)ptr;
    int retval = 0;
    int inject = 0;
    DAQ_PktHdr_t* daqhdr = (DAQ_PktHdr_t*)pkt->pkth;
    Stream5LWSession *lwssn;

#ifdef CAV_OCT_ASYNC

    if (((pkt->state_flag == CAV_STATE_FINAL) || (pkt->state_flag == CAV_STATE_PIPELINE)) && !(pkt->omd_count))
    {
        /* SnortXL  Async Postprocessing : 
         * 1. See eventq - right now its overlapping
         * 2. Fix duplicate matches
         * 3. Fix snort profiling opts 
         * */

        //PREPROC_PROFILE_START(eventqPerfStats);
        retval = SnortEventqLog(snort_conf->event_queue, pkt);
        SnortEventqReset();
        if(pkt->state_flag == CAV_STATE_PIPELINE)
            return;
        //PREPROC_PROFILE_END(eventqPerfStats);
        lwssn = (Stream5LWSession *)pkt->ssnptr;
        if (lwssn)
        {
            /* Got a packet on a session that was dropped (by a rule). */
            /* Drop this packet */
            if (((pkt->packet_flags & PKT_FROM_SERVER) &&
                 (lwssn->session_flags & SSNFLAG_DROP_SERVER)) ||
                ((pkt->packet_flags & PKT_FROM_CLIENT) &&
                 (lwssn->session_flags & SSNFLAG_DROP_CLIENT)))

                Active_DropPacket();
        }

        pkt->state_flag = CAV_STATE_CLEAN;
        if ( pkt->packet_flags & PKT_PSEUDO )
        {
            /* Only S5 packet is dynamically allocated,So free it before returning
             * Defragmented and Portscan packets are not yet handled */
            if(pkt->pseudo_type == PSEUDO_PKT_TCP)
            {
                cav_arena_free(pkt->pkt);
                func_cav128BFree((void*)pkt->pkth); 
                cvmx_fpa_free(pkt->matchInfo, CAV_OCT_SNORT_8K_POOL, 0);
                cvmx_fpa_free(pkt, CAV_OCT_SNORT_8K_POOL, 0);
            }
            return;
        }   
        /*
         ** By checking tagging here, we make sure that we log the
         ** tagged packet whether it generates an alert or not.
         */
        if (IPH_IS_VALID(pkt))
            CheckTagging(pkt);

        /*
         **  If we found events in this packet, let's flush
         **  the stream to make sure that we didn't miss any
         **  attacks before this packet.
         */
        if(retval && IsTCP(pkt) && stream_api)
            stream_api->alert_flush_stream(pkt);

        if(lwssn){
            lwssn->pending--;
            if(!lwssn->pending && (lwssn->flush_flags & CAV_FLUSH_ALL) )
            {
                cavSessionCleanup(lwssn);
            }
        }
        if ( Active_SessionWasDropped() )
        {
            Active_DropAction(pkt);

            if ( ScInlineMode() || Active_PacketForceDropped() )
                daqhdr->verdict = DAQ_VERDICT_BLACKLIST;
            else
                daqhdr->verdict = DAQ_VERDICT_IGNORE;
        }

#ifdef ACTIVE_RESPONSE
        if ( Active_ResponseQueued() )
        {
            Active_SendResponses(pkt);
        }
#endif
        if ( Active_PacketWasDropped() )
        {
            if ( daqhdr->verdict == DAQ_VERDICT_PASS )
                daqhdr->verdict = DAQ_VERDICT_BLOCK;
        }
        else
        {
            Replace_ModifyPacket(pkt);

            if ( pkt->packet_flags & PKT_MODIFIED )
            {
                // this packet was normalized and/or has replacements
                Encode_Update(pkt);
                daqhdr->verdict = DAQ_VERDICT_REPLACE;
            }

#ifdef NORMALIZER
            else if ( pkt->packet_flags & PKT_RESIZED )
            {
                // we never increase, only trim, but
                // daq doesn't support resizing wire packet
                if ( !DAQ_Inject(pkt->pkth, DAQ_INJECT, pkt->pkt, pkt->pkth->pktlen) )
                {
                    daqhdr->verdict = DAQ_VERDICT_BLOCK;
                    inject = 1;
                }
            }
#endif

            else
            {
                if ((pkt->packet_flags & PKT_IGNORE_PORT) ||
                        (stream_api && (stream_api->get_ignore_direction(pkt->ssnptr) == SSN_DIR_BOTH)))
                {
                    daqhdr->verdict = DAQ_VERDICT_WHITELIST;
                }
                else
                {
                    daqhdr->verdict = DAQ_VERDICT_PASS;
                }
            }
        }

        /* Collect some "on the wire" stats about packet size, etc */
        UpdateWireStats(&sfBase, daqhdr->caplen, Active_PacketWasDropped(), inject);
        Active_Reset();

        Encode_Reset();

        checkLWSessionTimeout(4, daqhdr->ts.tv_sec);
        ControlSocketDoWork(0);


        /* this pkt can be free - since all omds are processed and no new omds
         * will be associated with this pkt \
         */
#if 0
        /* SnortXL: the null checks can be removed - introduce strict checks */
        if (cvmx_unlikely(!pkt->pkth))
            FatalError("pkthdr null p %p pkth %p pkt %p  %x \n", pkt, pkt->pkth, pkt->pkt,pkt->packet_flags);
        if (cvmx_unlikely(!pkt->pkt))
            FatalError("pktbuf NULL?? p %p pkth %p pkt %p  %x\n", pkt, pkt->pkth, pkt->pkt,pkt->packet_flags);
#endif
        /* SnortXL : Here we send out the packet / Free pcap buf
         * Ensure all pkt actions are completed before this
         */ 
        DAQ_Inject(pkt->pkth, DAQ_SEND, pkt->pkt, pkt->pkth->pktlen);
        cvmx_fpa_free(pkt->matchInfo, CAV_OCT_SNORT_8K_POOL, 0);
        cvmx_fpa_free(pkt, CAV_OCT_SNORT_8K_POOL, 0);
    }
#else
    cvmx_fpa_free(pkt->matchInfo, CAV_OCT_SNORT_8K_POOL, 0);
    cvmx_fpa_free(pkt, CAV_OCT_SNORT_8K_POOL, 0);
#endif
}

#ifdef CAV_OCT_ASYNC
void cavPostProcess(OTNX_MATCH_DATA *omd)
{
    Stream5LWSession *lwssn;
    Packet *pkt = omd->p;
#ifdef BUGPRINTS
    printf("CF[%lu] fin %d pend %d ptr %p \n",pkt->omd_count, pkt->state_flag, omd->submit_cnt, pkt );
#endif
    if (cvmx_unlikely(!omd->p))
    {
        FatalError("C%d Null pkt %p \n",cvmx_get_core_num(), omd); 
        return; 
    }
    lwssn = (Stream5LWSession *)pkt->ssnptr;
    if (lwssn)
    {
        /* Got a packet on a session that was dropped (by a rule). */
        /* Drop this packet */
        if (((pkt->packet_flags & PKT_FROM_SERVER) &&
             (lwssn->session_flags & SSNFLAG_DROP_SERVER)) ||
            ((pkt->packet_flags & PKT_FROM_CLIENT) &&
             (lwssn->session_flags & SSNFLAG_DROP_CLIENT)))
        {
            if(!pkt->omd_count)
                Active_DropPacket();
        /* No need of handeling events for this since packet would be dropped */
            goto free_pkt;
        }
    }

	/* If this is the last omd associated with the packet
	 * Select event perform actions 
	 */
    if (((pkt->state_flag == CAV_STATE_FINAL) || (pkt->state_flag == CAV_STATE_PIPELINE)) && (pkt->omd_count==1))
        if (omd->final_flag == 1 && omd->submit_cnt == 0)
            cavfpFinalSelectEvent(omd,omd->p);
        
free_pkt:
    OtnxMatchDataFree(omd);
    
    cavOctFree(pkt);
}
#endif
/* Handles Post processing of omdlist and frees the Packet */
void cavProcessPkt (Packet *p)
{
    int idx=0;    
    if(pomdidx){
        for(idx = 0;idx < pomdidx; idx++)
        {
            pomdlist[idx]->pending = 0;
            cavPostProcess(pomdlist[idx]);
        }
    }
    pomdidx=0;
    memset(pomdlist,0,40*sizeof(OTNX_MATCH_DATA *));
    if(p)
        cavOctFree(p);
}
int octeon_shutdown(void)
{ 
    int result = 0,blksize=0;
    int status;
    int pool;

    //cvmx_helper_shutdown_packet_io_global();

    for (pool=0; pool<CVMX_FPA_NUM_POOLS; pool++)
    {
        if ((blksize = cvmx_fpa_get_block_size(pool) )> 0 && (pool == CAV_OCT_SNORT_2K_POOL 
            || pool == CAV_OCT_SNORT_8K_POOL || pool == CAV_OCT_SNORT_128B_POOL ))
        {
            status = cvmx_fpa_shutdown_pool(pool);
            result |= status;
        }
        printf("block size  for pool %d is %d \n",pool,blksize);
    }
    return result;
}

int cavOctHfaExit (void)
{
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM) {
        cav_oct_barrier_sync(0);
        cavOctHfaFreeGmdata();
        if (cav_oct_is_first_core())
        {
           /* Single Core Cleanups */
           //octeon_shutdown();
           cvmx_bootmem_free_named("cav_arena");
           cvmx_bootmem_free_named("sbuf_128b_pool");
           cvmx_bootmem_free_named("sbuf_2k_pool");
           cvmx_bootmem_free_named("pkt_pool");
           cvmx_bootmem_free_named("graph_array");
           print_profile_stats();
           show_rbuf_stat();
           hfa_dev_cleanup(&hfa_dev);
           dbgl1("cleanup done at cavOctHfaExit\n");
        }
    }
    return 0;
}

void * cavOctHfaNew
    (
     void (*sn_pat_free)(void *p),
     void (*sn_option_tree_free)(void **p),
     void (*sn_neg_list_free)(void **p)
    )
{
    CAV_OCT_HFA_MPSE *cohm = NULL;

    dbgl1("cavOctHfaNew: entered\n");

    cohm = (CAV_OCT_HFA_MPSE *)SnortAlloc(sizeof(*cohm));
    memset(cohm, 0, sizeof(*cohm));
    cohm->sn_pat_free = sn_pat_free;
    cohm->sn_option_tree_free = sn_option_tree_free;
    cohm->sn_neg_list_free = sn_neg_list_free;
    cohm->meta_data = (MDATA *)SnortAlloc(sizeof(MDATA)); 
    memset(cohm->meta_data,0,sizeof(MDATA));
    cohm->meta_data->min_len = 1000;

    dbgl1("cavOctHfaNew: returned %p\n", cohm);
    return (void *)cohm;
}

void free_graph_handle(hfa_graph_t *graph_handle)
{
    FLAG_LIST *tmp, *tmp1;
    int i;

    for (i=0 ; i < total_graphs ; i++)
        if(graph_array[i].graph_handle == graph_handle)
        {
            tmp=graph_array[i].head[cavOctCore];
            while(tmp != NULL)
            {
                tmp1=tmp->next;
                tmp->cohm->graph_handle = NULL;
                tmp=tmp1;
            }
            break;
        }
}

void cavOctHfaDelete(CAV_OCT_HFA_MPSE *cohm)
{
    int i = 0, ret = 0;
    static int gcnt = 0;
    dbgl1("cavOctHfaDelete: entered\n");
    dbgl1("cavOctHfaDelete: graph: %d\n", gcnt++);
    if (cohm == NULL)
        return;
    /* wait till all cores complete in case same graph is being used by multiple
     * cores */
    cav_oct_barrier_sync(sf_cmask);

    /* clean up ctx */
    if (cohm->graphCtx)
    {
        hfa_dev_searchctx_cleanup(&hfa_dev, cohm->graphCtx);
        //cvmx_fpa_free(cohm->graphCtx, CAV_OCT_SNORT_2K_POOL, 0);
        free(cohm->graphCtx);
        cohm->graphCtx = NULL;
    }

    /* clean up graphs */
    dbgl1("cavOctHfaDelete: cohm->graph_handle %p\n", cohm->graph_handle);
    if (cohm->graph_handle)
    {
        if (cav_oct_is_first_core())
        {
            for(i=0;i<MAX_GRAPH_LIST;i++)
                if(glist[i].graph_handle == cohm->graph_handle)
                {
                    if (glist[i].cached == 1)
                        ret = hfa_graph_cacheunload(glist[i].graph_handle);
                    uint64_t count = cvmx_fau_fetch_and_add64(FAU_GRAPH_USAGE(i), 0);

                    dbgl1("core%d cavOctHfaDelete: Unload Cache %p %lu [ret = %d]\n", cavOctCore, (uint64_t *)glist[i].graph_handle, count, ret );
                    ret = hfa_dev_graph_cleanup(&hfa_dev, glist[i].graph_handle);
                    if (HFA_SUCCESS != ret) 
                    {
                       ERROR("core %d : hfa_dev_graph_cleanup failed (%d) %p\n", cavOctCore, ret, glist[i].graph_handle);
                    }
                    //Free the graph
                    hfa_bootmem_free(glist[i].graph_handle, sizeof(hfa_graph_t));
                    dbgl1("core%d cavOctHfaDelete: Free Graph %p [ret = %d]\n", cavOctCore, (uint64_t *)glist[i].graph_handle, ret );
                    free_graph_handle(glist[i].graph_handle);
                    glist[i].graph_handle = NULL;
                    break;
                }
        }
        cohm->graph_handle = NULL;
    }

    /* clean up pattern info */
    dbgl1("cavOctHfaDelete: cohm->pattern_array %p[%d]\n", cohm->pattern_array,
            cohm->pattern_count);

    for (i = 0; i < cohm->pattern_count; i++)
    {
        CAV_OCT_HFA_PATTERN *pat = &cohm->pattern_array[i];
        dbgl2("cavOctHfaDelete: pattern_array[%d] cohm->sn_pat_free %p(%d)\n",
                i, cohm->sn_pat_free, *(int *)pat->sn_pat_data);
        if (cohm->sn_pat_free && pat->sn_pat_data)
            cohm->sn_pat_free(pat->sn_pat_data);
        if(pat->sn_pattern)
            free(pat->sn_pattern);
        if(pat->hex_pattern)
            free(pat->hex_pattern);
    }

    free(cohm->pattern_array);
    free(cohm->meta_data);

    /* cleanup up mpse */
    free(cohm);
    dbgl1("cavOctHfaDelete: returned\n");
}

int cavOctHfaAddPattern
(
 CAV_OCT_HFA_MPSE *cohm,
 unsigned char *pattern,
 int pat_len,
 unsigned int sn_no_case,
 unsigned int sn_negative,
 void *sn_pat_data,
 int sn_pat_id
 )
{
    CAV_OCT_HFA_PATTERN *pat;
    int i, offset = 0;
    dbgl2("cavOctHfaAddPattern: entered (cohm: %p)\n", cohm);
    if (cohm == NULL)
        return -1;

    dbgl2("cavOctHfaAddPattern: pattern_count %d, pattern_array_len %d \n", 
            cohm->pattern_count, cohm->pattern_array_len);
    if (cohm->pattern_count >= cohm->pattern_array_len)
    {
        int array_len = cohm->pattern_count + PATTERN_ARRAY_ALLOC_SIZE;
        pat = SnortAlloc(array_len*sizeof(*pat));
        memset(pat, 0, array_len*sizeof(*pat));
        memcpy(pat, cohm->pattern_array, cohm->pattern_count*sizeof(*pat));
        if (cohm->pattern_array)
            free(cohm->pattern_array);
        cohm->pattern_array = pat;
        cohm->pattern_array_len = array_len;
        dbgl2("cavOctHfaAddPattern: pattern_array %p[%d] \n", 
                cohm->pattern_array, cohm->pattern_array_len);
    }

    dbgl2("cavOctHfaAddPattern: sn_pattern %p of len %d \n", pattern, pat_len);
    pat = &cohm->pattern_array[cohm->pattern_count];
    pat->sn_pattern = (unsigned char *)SnortAlloc(pat_len);
    if (pat->sn_pattern == NULL)
        return -1;
    memcpy(pat->sn_pattern, pattern, pat_len);
    /* record each octet in the form "\xhh" to suit our pattern compiler */
    pat->pattern_len = pat_len*4;
    pat->sn_no_case = sn_no_case;
    pat->sn_negative = sn_negative;
    if (pat->sn_no_case)
        pat->pattern_len += 3; /* for {i} pattern prefix */
    if (pat->sn_negative)
        pat->pattern_len += 0; 
    pat->hex_pattern = (unsigned char *)SnortAlloc(pat->pattern_len+1);
    if (pat->hex_pattern == NULL)
        return -1;
    if (pat->sn_no_case)
        offset += sprintf((char *)pat->hex_pattern+offset, "{i}"); 
    //if (pat->sn_negative)
    //    offset += sprintf((char *)pat->hex_pattern+offset, ""); 
    for(i = 0; i < pat_len; i++)
        offset += sprintf((char *)pat->hex_pattern+offset, "\\x%02x",
                pattern[i]);
    pat->sn_pat_id = sn_pat_id;
    pat->sn_pat_data = sn_pat_data;
    pat->patternId = cohm->pattern_count++;
    dbgl2("cavOctHfaAddPattern: pattern[%d]' of len %d: '%s'\n", 
            cohm->pattern_count - 1, pat->pattern_len, pat->hex_pattern);

    if(sn_no_case)
        cohm->meta_data->ncase++;
    if(cohm->meta_data->min_len > pat_len)
        cohm->meta_data->min_len = pat_len;
    if(cohm->meta_data->max_len < pat_len)
        cohm->meta_data->max_len = pat_len;
    if(pat_len < MAX_SHORT_LENGTH)
        cohm->meta_data->nshort++;
    cohm->meta_data->tot_len += pat_len;
    dbgl2("cavOctHfaAddPattern: returned\n");
    return 0;
}

int cavOctHfaCompile
(
 CAV_OCT_HFA_MPSE *cohm,
 int (*sn_build_tree)(void *id, void **existing_tree),
 int (*sn_neg_list_func)(void *id, void **list)
 )
{
    char * pattern_list;
    int ret,i;
    unsigned int graph_data_len = 0;
    FILE * fp = NULL;
    char * pfname = "/tmp/pattern";
    char gfname[50];
    gzFile gzf = NULL;
    char graphpath_tmp[100];
    char buf[200];
    SHA_CTX c;
    unsigned char md[20];

    uint8_t *graph_read_ptr=NULL;
    uint32_t graph_read_len;
    static uint32_t gcnt = 0;

    dbgl2("cavOctHfaCompile: entered\n");
    if (cohm == NULL)
        return -1;

    cohm->meta_data->npat = cohm->pattern_count;
    cohm->meta_data->next = NULL;
    cohm->meta_data->gcount = 0;
    cohm->sn_build_tree = sn_build_tree;
    cohm->sn_neg_list_func = sn_neg_list_func;

    /* create iovec with all patterns */
    for (i = 0; i < cohm->pattern_count; i++)
    {
        CAV_OCT_HFA_PATTERN *pat = &cohm->pattern_array[i];
        graph_data_len += pat->pattern_len+1;
    }
    dbgl1("cavOctHfaCompile: pattern_array[%d] of total len %d bytes\n", 
            cohm->pattern_count, graph_data_len);
    pattern_list = SnortAlloc(graph_data_len);
    if (pattern_list == NULL)
    {
        FatalError("pattern_list = SnortAlloc(%d) failed\n", graph_data_len);
        goto error;
    }

    /* generate a SHA Digest of the pattern data */
    graph_data_len = 0;
    memset(md,0,20);
    SHA1_Init(&c);
    for (i = 0; i < cohm->pattern_count; i++)
    {
        CAV_OCT_HFA_PATTERN * pat = &cohm->pattern_array[i];
        SHA1_Update(&c,pat->sn_pattern,(pat->pattern_len)/4);
        memcpy(pattern_list+graph_data_len, pat->hex_pattern, pat->pattern_len);
        graph_data_len += pat->pattern_len;
        /* follow each pattern with a new-line */
        pattern_list[graph_data_len] = '\n';
        graph_data_len++;
        if (cohm->sn_neg_list_func && cohm->sn_build_tree)
        {
            if (pat->sn_negative)
                cohm->sn_neg_list_func(pat->sn_pat_data, &pat->sn_neg_list);
            else
                cohm->sn_build_tree(pat->sn_pat_data, &pat->sn_rule_option_tree);
            if (cohm->sn_build_tree)
                cohm->sn_build_tree(NULL, &pat->sn_rule_option_tree);
        }
        /* we no longer need sn_pattern and hex_pattern */
        if(pat->sn_pattern)
            free(pat->sn_pattern);
        pat->sn_pattern = 0;
        if(pat->hex_pattern)
            free(pat->hex_pattern);
        pat->hex_pattern = 0;
    }
    SHA1_Final(md,&c);
    dbgl2("cavOctHfaCompile: pattern_list of total len %d\n", graph_data_len);
    /* the SHA Digest will be used as the graph name when its generated later */
    snprintf(gfname, sizeof(gfname), "%016lx%016lx%08x", *(uint64_t *)md,
            *((uint64_t *)md+1), *(uint32_t *)((uint64_t *)md+2));
    memcpy(cohm->meta_data->gname, gfname, sizeof(gfname));
    snprintf(graphpath_tmp, sizeof(graphpath_tmp),"%s%s.gz",graphpath, gfname);
    dbgl2("cavOctHfaCompile: pattern file %s %s written\n", graphpath_tmp,gfname);

#ifdef CAV_OCT_LINUX
    /* compile list of patterns into graph */
    if (cav_oct_is_first_core())
    {
        /* 
         * save the patterns to a temporary pattern file for graph generation
         * using hfac
         */ 
        fp  = fopen(pfname, "w");
        if (fp == NULL)
        {
            ERROR("[%d]fopen(%s) == NULL : %s\n",__LINE__,pfname, strerror(errno));
            goto error;
        }
        ret = fwrite(pattern_list, 1, graph_data_len, fp);
        if (ret != graph_data_len)
        {
            ERROR("fwrite(%s, %d) != %d : %s\n", pfname, graph_data_len, ret,
                    strerror(errno));
            goto error;
        }
        fclose(fp);
        fp=NULL;
    }
#endif
    free(pattern_list);
    pattern_list = NULL;
    dbgl2("cavOctHfaCompile: pattern file %s written\n", pfname);

    if (!merge_graphs)
    {
        fp = fopen(graphpath_tmp,"r");
        if(fp!=NULL)
        {
            if(create_graphs == 1)
                ERROR("cavOctHfaCompile: graph %s already exists ...\n", graphpath_tmp);
            fclose(fp);
        }
        else
        {
            if (cav_oct_is_first_core())
            {
                snprintf(buf, sizeof(buf)-1, 
                        "hfac -out %s -input %s --hfacachelines=%d --hfaosmlines=0 --hnacachelines=0 --hnaosmlines=0 -rc -minlen 1", gfname, pfname,
                        CAV_OCT_HFA_GRAPH_CACHE_SIZE);
                ret = system(buf);
                dbgl1("cavOctHfaCompile: system(%s): %d\n", buf, ret);
            }
            cav_oct_barrier_sync(sf_cmask);
        }
        /* We're running in graph creation mode...so we are done with it*/
        if(create_graphs == 1)
            return 0;
        if(get_size(graphpath_tmp,&graph_data_len))
        {
            goto error;
        }    
        if ((gzf = (gzFile)gzopen (graphpath_tmp, "rb")) == NULL) 
        {
            FatalError("[%d]fopen(%s) == NULL : %s\n",__LINE__, graphpath_tmp, strerror(errno));
        }
        /* We're running in IDS mode...so we proceed to loading the graph */
        if (cav_oct_is_first_core())
        {
            /* some of snort's pattern files repeat, so we avoid reloading them */ 
            if(cavOctHfaFindGraph(cohm, gfname, graph_data_len))
            {
                /* ok, its a new a pattern file */
                graph_read_ptr = hfa_bootmem_alloc(graph_data_len, 128);
                if (graph_read_ptr == NULL)
                {
                    FatalError("graph_read_ptr = SnortAlloc(%d) failed\n",
                            graph_data_len);
                    goto error;
                }
             
                   /* read in the graph data from the graph file */
                ret = fd_read(gzf, graph_read_ptr , graph_data_len);
                if (ret != graph_data_len)
                {
                    FatalError("fdread(%s,%d)!=%d : %s\n", graphpath_tmp, graph_data_len,
                            ret, strerror(errno));
                    goto error;
                }
                graph_read_len = graph_data_len;
                dbgl2("cavOctHfaCompile: graph file %s read: %d bytes\n", graphpath_tmp,
                        graph_data_len);

                int clmsk;

                //Allocate graph handle
                cohm->graph_handle = cvmx_bootmem_alloc(sizeof(hfa_graph_t),128);

                /* Initialize the graph object */
                if (hfa_dev_graph_init (&hfa_dev, cohm->graph_handle) != HFA_SUCCESS)
                {
                    ERROR("hfa_dev_graph_init() failed: %d\n", ret);
                    goto error;
                }

                clmsk  = hfa_dev_get_clmsk(&hfa_dev);

                ret = hfa_graph_setcluster(cohm->graph_handle, clmsk);
                /** Set the cluster for each graph handle */
                if (HFA_SUCCESS != ret)
                {
                    ERROR("hfa_graph_setcluster() failed: %d\n", ret);
                    goto error;
                }

                /* lets load the graph data into HFA RAM */
                gcnt++;
                ret = hfa_graph_memload_data(cohm->graph_handle, graph_read_ptr, 
                        graph_read_len);
                if (HFA_SUCCESS != ret)
                {
                    ERROR("hfa_graph_memload_data() failed: %d gcnt: %d\n", ret, gcnt);
                    goto error;
                }
#if 0001
                /* SnortXL: Adjust cache variables, improve profiling - remove
                 * glist? 
                 */
                if (!(HFA_GET_GRAPHATTR(cohm->graph_handle, memonly)))
                {
                    int k;
                    ret = hfa_graph_cacheload(cohm->graph_handle);
                    if (ret != HFA_SUCCESS)
                    {
                        dbginfo("hfa_graph_cacheload() failed: %d %d %p\n", cvmx_get_core_num(), ret, cohm->graph_handle);
                        return -1;
                    }
                    global_cache_loads++;

                    for(k=0; k < MAX_GRAPH_LIST ; k++)
                    {
                        if(glist[k].graph_handle == NULL)
                        {
                            /* find first empty place in graph list and add */
                            glist[k].graph_handle = cohm->graph_handle;
                            glist[k].cached = 1;
                            cacheEntry++ ;
                            break;
                        }
                        dbgl1("CORE %u: cavOctHfaCacheLoad: loaded graph %p onto cache(%d) %d\n",
                                cavOctCore, cohm->graph_handle, k , cacheEntry);
                    }
                }
#endif

                hfa_bootmem_free(graph_read_ptr, graph_data_len);
                graph_read_ptr = NULL;

                /* 
                 * add graph handle to cohm and global graph array, so that
                 * other cores will update core-local cohm
                 */ 
                ret = cavOctHfaAddGraph(cohm->graph_handle, gfname, graph_data_len);
                if (ret)
                {
                    FatalError("cavOctHfaAddGraph(%s) failed: %d. "
                            "Too many graphs\n", gfname, ret);
                    goto error;
                }
            }
        }
        gzclose(gzf);
        fp = NULL;
        cav_oct_barrier_sync(sf_cmask);
        /* 
         * update core-local cohm structure on other cores with graph_handle.
         * All cores will use same graph_handle
         */
        if (!cav_oct_is_first_core())
        {
            if (cavOctHfaFindGraph(cohm, gfname, graph_data_len))
            {
                FatalError("cavOctHfaFindGraph(%s,%d) failed: on core %d\n",
                        gfname, graph_data_len, cavOctCore);
                goto error;
            }
        }
        dbgl1("cavOctHfaCompile: loaded graph %s into HFA engine: %p\n", gfname,
                cohm->graph_handle);
    }
    dbgl1("cavOctHfaCompile: returned\n");
    return 0;

error:
    if (cohm->graph_handle)
    {
        /* cleanup graphs loaded onto the HFA engine */
        if (cav_oct_is_first_core())
        {
            i = 0;
            while(graph_array[i].graph_handle != NULL)
            {
                hfa_dev_graph_cleanup(&hfa_dev, graph_array[i].graph_handle);
                free(graph_array[i].graph_handle);
                i++;
            }
            dbgl1("cavOctHfaCompile: Deleted %d Graphs\n",i);
            hfa_dev_graph_cleanup(&hfa_dev, cohm->graph_handle);
            free(cohm->graph_handle);
        }
        cav_oct_barrier_sync(sf_cmask);
        cohm->graph_handle = NULL;
    }
    if (gzf)
        gzclose(gzf);
    if (pattern_list)
        free(pattern_list);
    if (graph_read_ptr)
        free(graph_read_ptr);
    dbgl1("CORE %d: cavOctHfaCompile: returned error\n", cavOctCore);
    return -1;
}

void cavOctHfaGcompile()
{
    cavOctHfaParse();
#ifndef STATIC_CACHE
    cavOctHfaDump();
    if (cavOctHfaSort())
    {
        /* There are no fast patterns, dont call 
         * merge/compile/load graphs, just exit 
         */
        printf("No Fast Patterns\n");
        return;
    }
    cavOctHfaGraphMerge();
#endif
    if (merge_graphs)
    {
        char graphpath_tmp[100];
        char gfname[50];
        gzFile gzf = NULL;
        uint32_t graph_data_len;
        uint32_t graph_read_len;
        uint8_t *graph_read_ptr=NULL;
        int i,ret;
        int j, k = 0;
        CAV_OCT_HFA_MPSE *tmp_cohm;
        MDATA *tmp_mdata;
        rule_port_tables_t *ptables = snort_conf->port_tables;
        PortTable *tmp_pt;
        PortObject *tmp_po;

        while(k<8)
        {
            switch(k){
                case 0:
                    tmp_pt = ptables->tcp_src;
                    break;
                case 1:
                    tmp_pt = ptables->tcp_dst;
                    break;
                case 2:
                    tmp_pt = ptables->udp_src;
                    break;
                case 3:
                    tmp_pt = ptables->udp_dst;
                    break;
                case 4:
                    tmp_pt = ptables->icmp_src;
                    break;
                case 5:
                    tmp_pt = ptables->icmp_dst;
                    break;
                case 6:
                    tmp_pt = ptables->ip_src;
                    break;
                case 7:
                    tmp_pt = ptables->ip_dst;
                    break;
                default:
                    break;
            }

            for(i = 0;i < SFPO_MAX_PORTS; i++)
                for(j = 0; j < PM_TYPE__MAX; j++)
                {
                    if(((PortObject2 *)(tmp_pt->pt_port_object[i]) != NULL) 
                            && (((PORT_GROUP *)(((PortObject2 *)(tmp_pt->pt_port_object[i]))->data)) != NULL)
                            && ((MPSE *)(((PORT_GROUP *)(((PortObject2 *)(tmp_pt->pt_port_object[i]))->data))->pgPms[j]) != NULL))
                    {
                        tmp_cohm = ((CAV_OCT_HFA_MPSE *)(((MPSE *)((PORT_GROUP *)(tmp_pt->pt_port_object[i]->data))->pgPms[j])->obj));
                        tmp_mdata = tmp_cohm->meta_data;
                        if (strcmp(tmp_mdata->gname,tmp_mdata->gmptr->gname))
                            printf("2)tmp->gname:%s ,gtmp->gname:%s mg_graph: %d\n",tmp_mdata->gname,
                                    tmp_mdata->gmptr->gname,tmp_mdata->gmptr->mg_flag);
                        if(tmp_mdata->gmptr->mg_flag < 0)
                        {
                            snprintf(graphpath_tmp, sizeof(graphpath_tmp),"%s%s.gz", graphpath, tmp_mdata->gmptr->gname);
                            sprintf(gfname,"%s.gz",tmp_mdata->gmptr->gname);
                        }
                        else if (mg_list[tmp_mdata->gmptr->mg_flag].alive)
                        {
                            snprintf(graphpath_tmp, sizeof(graphpath_tmp),"%smg%d.gz", graphpath, tmp_mdata->gmptr->mg_flag);
                            sprintf(gfname,"mg%d.gz", tmp_mdata->gmptr->mg_flag);
                        }
                        else
                        {
                            FatalError("Error when linking merged graphs mglist[%d]\n", tmp_mdata->gmptr->mg_flag);
                        }
                         if(get_size(graphpath_tmp,&graph_data_len))
                        {
                            
                            FatalError("[%d]gzsizefailed for %s \n",__LINE__, graphpath_tmp);
                        }   
                        if ((gzf = (gzFile)gzopen (graphpath_tmp, "rb")) == NULL) 
                        {
                            FatalError("[%d]fopen(%s) == NULL : %s\n",__LINE__, graphpath_tmp, strerror(errno));
                        }

                        /* We're running in IDS mode...so we proceed to loading the graph */
                        if (cav_oct_is_first_core())
                        {
                            /* some of snort's pattern files repeat, so we avoid reloading them */ 
                            if(cavOctHfaFindGraph(tmp_cohm, gfname, graph_data_len))
                            {
                                /* ok, its a new a pattern file */
                                graph_read_ptr = hfa_bootmem_alloc(graph_data_len, 128);
                                if (graph_read_ptr == NULL)
                                {
                                    FatalError("graph_read_ptr = SnortAlloc(%d) failed\n",
                                            graph_data_len);
                                }
                                /* read in the graph data from the graph file */
                                ret = fd_read(gzf, graph_read_ptr , graph_data_len);
                                if (ret != graph_data_len)
                                {
                                    FatalError("fdread(%s,%d)!=%d : %s\n", graphpath_tmp, graph_data_len,
                                            ret, strerror(errno));
                                }
                                graph_read_len = graph_data_len;
                                dbgl2("cavOctHfaGCompile: graph file %s read: %d bytes\n", graphpath_tmp,
                                        graph_data_len);

                                int clmsk;

                                //Allocate graph handle
                                tmp_cohm->graph_handle = cvmx_bootmem_alloc(sizeof(hfa_graph_t),128);

                                /* Initialize the graph object */
                                if (hfa_dev_graph_init (&hfa_dev, tmp_cohm->graph_handle) != HFA_SUCCESS)
                                {
                                    FatalError("hfa_dev_graph_init() failed: %d\n", ret);
                                }

                                clmsk  = hfa_dev_get_clmsk(&hfa_dev);

                                ret = hfa_graph_setcluster(tmp_cohm->graph_handle, clmsk);
                                /** Set the cluster for each graph handle */
                                if (HFA_SUCCESS != ret)
                                {
                                    FatalError("hfa_graph_setcluster() failed: %d\n", ret);
                                }

                                /* lets load the graph data into HFA RAM */
                                ret = hfa_graph_memload_data(tmp_cohm->graph_handle, graph_read_ptr, 
                                        graph_read_len);
                                if (HFA_SUCCESS != ret)
                                {
                                    FatalError("hfa_graph_memload_data() failed: %d\n", ret);
                                }

                                hfa_bootmem_free(graph_read_ptr, graph_data_len);
                                graph_read_ptr = NULL;

                                if (!(HFA_GET_GRAPHATTR(tmp_cohm->graph_handle, memonly)))
                                {
                                    int kk;
                                    ret = hfa_graph_cacheload(tmp_cohm->graph_handle);
                                    if (ret != HFA_SUCCESS)
                                        ERROR("hfa_graph_cacheload() failed: %d %d %p\n", cvmx_get_core_num(), ret, tmp_cohm->graph_handle);
                                    global_cache_loads++;
 
                                    for(kk=0; kk < MAX_GRAPH_LIST ; kk++)
                                    {
                                        if(glist[kk].graph_handle == NULL)
                                        {
                                            /* find first empty place in graph list and add */
                                            glist[kk].graph_handle = tmp_cohm->graph_handle;
                                            glist[kk].cached = 1;
                                            cacheEntry++ ;
                                            break;
                                        }
                                        dbgl1("CORE %u: cavOctHfaCacheLoad: loaded graph %p onto cache(%d) %d\n",
                                                cavOctCore, tmp_cohm->graph_handle, kk , cacheEntry);
                                    }
                                }
                                /* 
                                 * add graph handle to cohm and global graph array, so that
                                 * other cores will update core-local cohm
                                 */ 
                                ret = cavOctHfaAddGraph(tmp_cohm->graph_handle, gfname, graph_data_len);
                                if (ret)
                                {
                                    FatalError("cavOctHfaAddGraph(%s) failed: %d. "
                                            "Too many graphs\n", gfname, ret);
                                }
                            }
                        }
                        gzclose(gzf);

                        cav_oct_barrier_sync(sf_cmask);
                        /* 
                         * update core-local cohm structure on other cores with graph_handle.
                         * All cores will use same graph_handle
                         */
                        if (!cav_oct_is_first_core())
                        {
                            if (cavOctHfaFindGraph(tmp_cohm, gfname, graph_data_len))
                            {
                                FatalError("cavOctHfaFindGraph(%s,%d) failed: on core %d\n",
                                        gfname, graph_data_len, cavOctCore);
                            }
                        }
                    }
                }
            k++;
        }

        k = 0;
        while(k<4)
        {
            switch(k){
                case 0:
                    tmp_po = ptables->tcp_anyany;
                    break;
                case 1:
                    tmp_po = ptables->udp_anyany;
                    break;
                case 2:
                    tmp_po = ptables->icmp_anyany;
                    break;
                case 3:
                    tmp_po = ptables->ip_anyany;
                    break;
                default:
                    break;
            }

            for(j = 0; j < PM_TYPE__MAX; j++)
            {
                if((((PORT_GROUP *)(tmp_po->data)) != NULL)
                        && ((MPSE *)(((PORT_GROUP *)(tmp_po->data))->pgPms[j]) != NULL))
                {
                    tmp_cohm = ((CAV_OCT_HFA_MPSE *)(((MPSE *)((PORT_GROUP *)(tmp_po->data))->pgPms[j])->obj));
                    tmp_mdata = tmp_cohm->meta_data;
                    if (strcmp(tmp_mdata->gname,tmp_mdata->gmptr->gname))
                        printf("2)tmp->gname:%s ,gtmp->gname:%s mg_graph: %d\n",tmp_mdata->gname,
                                tmp_mdata->gmptr->gname,tmp_mdata->gmptr->mg_flag);
                    if(tmp_mdata->gmptr->mg_flag < 0)
                    {
                        snprintf(graphpath_tmp, sizeof(graphpath_tmp),"%s%s.gz", graphpath, tmp_mdata->gmptr->gname);
                        sprintf(gfname,"%s.gz",tmp_mdata->gmptr->gname);
                    }
                    else if (mg_list[tmp_mdata->gmptr->mg_flag].alive)
                    {
                        snprintf(graphpath_tmp, sizeof(graphpath_tmp),"%smg%d.gz", graphpath, tmp_mdata->gmptr->mg_flag);
                        sprintf(gfname,"mg%d.gz", tmp_mdata->gmptr->mg_flag);
                    }
                    else
                    {
                        FatalError("Error when linking merged graphs mglist[%d]\n", tmp_mdata->gmptr->mg_flag);
                    }
                    if(get_size(graphpath_tmp,&graph_data_len))
                    {
                        FatalError("[%d]fopen(%s) == NULL : %s\n",__LINE__, graphpath_tmp, strerror(errno));
                    }
                    if ((gzf = (gzFile)gzopen (graphpath_tmp, "rb")) == NULL) 
                    {
                        FatalError("[%d]fopen(%s) == NULL : %s\n",__LINE__, graphpath_tmp, strerror(errno));
                    }

                    /* We're running in IDS mode...so we proceed to loading the graph */
                    if (cav_oct_is_first_core())
                    {
                        /* some of snort's pattern files repeat, so we avoid reloading them */ 
                        if(cavOctHfaFindGraph(tmp_cohm, gfname, graph_data_len))
                        {
                            /* ok, its a new a pattern file */
                            graph_read_ptr = hfa_bootmem_alloc(graph_data_len, 128);
                            if (graph_read_ptr == NULL)
                            {
                                FatalError("graph_read_ptr = SnortAlloc(%d) failed\n",
                                        graph_data_len);
                            }
                            /* read in the graph data from the graph file */
                            ret = fd_read(gzf, graph_read_ptr , graph_data_len);
                            if (ret != graph_data_len)
                            {
                                FatalError("fdread(%s,%d)!=%d : %s\n", graphpath_tmp, graph_data_len,
                                        ret, strerror(errno));
                            }
                            graph_read_len = graph_data_len;
                            dbgl2("cavOctHfaGCompile: graph file %s read: %d bytes\n", graphpath_tmp,
                                    graph_data_len);

                            int clmsk;

                            //Allocate graph handle
                            tmp_cohm->graph_handle = cvmx_bootmem_alloc(sizeof(hfa_graph_t),128);

                            /* Initialize the graph object */
                            if (hfa_dev_graph_init (&hfa_dev, tmp_cohm->graph_handle) != HFA_SUCCESS)
                            {
                                FatalError("hfa_dev_graph_init() failed: %d\n", ret);
                            }

                            clmsk  = hfa_dev_get_clmsk(&hfa_dev);

                            ret = hfa_graph_setcluster(tmp_cohm->graph_handle, clmsk);
                            /** Set the cluster for each graph handle */
                            if (HFA_SUCCESS != ret)
                            {
                                FatalError("hfa_graph_setcluster() failed: %d\n", ret);
                            }

                            /* lets load the graph data into HFA RAM */
                            ret = hfa_graph_memload_data(tmp_cohm->graph_handle, graph_read_ptr, 
                                    graph_read_len);
                            if (HFA_SUCCESS != ret)
                            {
                                FatalError("hfa_graph_memload_data() failed: %d \n", ret);
                            }

                            hfa_bootmem_free(graph_read_ptr, graph_data_len);
                            graph_read_ptr = NULL;

                            if (!(HFA_GET_GRAPHATTR(tmp_cohm->graph_handle, memonly)))
                            {
                                int kk;
                                ret = hfa_graph_cacheload(tmp_cohm->graph_handle);
                                if (ret != HFA_SUCCESS)
                                    ERROR("hfa_graph_cacheload() failed: %d %d %p\n", cvmx_get_core_num(), ret, tmp_cohm->graph_handle);
                                global_cache_loads++;
 
                                for(kk=0; kk < MAX_GRAPH_LIST ; kk++)
                                {
                                    if(glist[kk].graph_handle == NULL)
                                    {
                                        /* find first empty place in graph list and add */
                                        glist[kk].graph_handle = tmp_cohm->graph_handle;
                                        glist[kk].cached = 1;
                                        cacheEntry++ ;
                                        break;
                                    }
                                    dbgl1("CORE %u: cavOctHfaCacheLoad: loaded graph %p onto cache(%d) %d\n",
                                            cavOctCore, tmp_cohm->graph_handle, kk , cacheEntry);
                                }
                            }
                            /* 
                             * add graph handle to cohm and global graph array, so that
                             * other cores will update core-local cohm
                             */ 
                            ret = cavOctHfaAddGraph(tmp_cohm->graph_handle, gfname, graph_data_len);
                            if (ret)
                            {
                                FatalError("cavOctHfaAddGraph(%s) failed: %d. "
                                        "Too many graphs\n", gfname, ret);
                            }
                        }
                    }
                    gzclose(gzf);

                    cav_oct_barrier_sync(sf_cmask);
                    /* 
                     * update core-local cohm structure on other cores with graph_handle.
                     * All cores will use same graph_handle
                     */
                    if (!cav_oct_is_first_core())
                    {
                        if (cavOctHfaFindGraph(tmp_cohm, gfname, graph_data_len))
                        {
                            FatalError("cavOctHfaFindGraph(%s,%d) failed: on core %d\n",
                                    gfname, graph_data_len, cavOctCore);
                        }
                    }
                }
            }
            k++;
        }
    }
    return;
}


/* 
 * Callback function called for each fast pattern match 
 * In turn this calls snort match call back function to complete the rule
 * evaluation.
 */ 
static void
cavOctHfaMatchCallback(int patno, int matchno, int startoffset, int endoffset, void *matchcba)
{

    CAV_OCT_HFA_CB_ARG * cbarg = matchcba;
    CAV_OCT_HFA_MPSE * cohm    = cbarg->cohm;
    CAV_OCT_HFA_PATTERN * pat;

    int mg_flag = cohm->meta_data->gmptr->mg_flag;
    if(mg_flag < 0)
    {
        num_match++;
    }
    else if (mg_list[mg_flag].alive != 1)
    {
        FatalError("MCB: wrong merged graph %d !\n", cohm->meta_data->gmptr->mg_flag);
    }
    else
    {
        int common_pat_count = mg_list[mg_flag].common_pat_cnt;
        int act_pat_count = cohm->pattern_count - mg_list[mg_flag].common_pat_cnt;
        if (patno > (mg_list[mg_flag].npat - common_pat_count))
        {
            num_match ++;
            patno = cohm->pattern_count - (mg_list[mg_flag].npat - patno);
        }
        else
        {
            if ((patno >= (cohm->meta_data->gmptr->mg_offset + 1)) && (patno <= (cohm->meta_data->gmptr->mg_offset + act_pat_count)))
            {
                num_match++;
                patno = patno - cohm->meta_data->gmptr->mg_offset;
            }
            else
                return;
        }
    }

    uint64_t snort_pp_cycles;
    /* SnortXL - Verify the patno compatibility between snortXL and hfa */
    patno = patno - 1;
    if(patno == -1)
        patno = 0;
    dbgl1("MCB: matched patno: %d at endoffset %d \n", 
                 patno, endoffset);
    if (patno >= cohm->pattern_count)
    {
        ERROR("MCB Error: mresult patno(%d) > cohm->pattern_count(%d) - Report!\n",
                patno, cohm->pattern_count);
        return;
    }
    if (cohm->pattern_array[patno].patternId != patno)
    {
        ERROR("MCB Error: mresult patno(%d) != ""cohm->pattern_array[%d].patternId(%d) - Report!\n",
                patno, patno, cohm->pattern_array[patno].patternId);
        return;
    }
    pat = &cohm->pattern_array[patno];
    dbgl1("MCB: cbarg->sn_matchcb %p(%p, %p)",
            cbarg->sn_matchcb, pat->sn_pat_data, cbarg->sn_matchcb_arg);
    snort_pp_cycles = cvmx_get_cycle();
    int ret = cbarg->sn_matchcb(pat->sn_pat_data, pat->sn_rule_option_tree,
            0, cbarg->sn_matchcb_arg, pat->sn_neg_list);
    if (ret > 0)  // put unlikely for all errors
    {
        FatalError("MCB cbarg->sn_matchcb(%p): %d\n", cohm->sn_matchcb,ret);
    }
    account_cycles(snort_pp_cycles, SNORT_PP_CYCLES);
    dbgl1("MCB: returned\n");
}


void cavOctHfaSbufListAppend(CAV_OCT_HFA_SBUF_NODE * sbufnode)
{
    if (sbufList)
        sbufList->tail->next = sbufnode;
    else
    {
        sbufList = sbufnode;
    }
    sbufList->tail = sbufnode;
    sbufnode->next = NULL;
}

CAV_OCT_HFA_SBUF_NODE * cavOctHfaSbufListPop(void)
{
    CAV_OCT_HFA_SBUF_NODE * head = sbufList;
    if (sbufList)
    {
        if (sbufList->next)
            sbufList->next->tail = sbufList->tail;
        sbufList = sbufList->next;
    }
    return head;
}

/* 
 * SnortXL :
 * ReEntry code after search results are obtained
 * Actions:
 * Decode search results
 * Perform post-processing actions
 * Free all allocated buffers, pkt and omd
 * Send out packet
 *
 * hfa_pipeline_depth - Controls the max number of search that can be pending at
 * any given time - Helps Control memory requirements, number of pending packets
 * and latency. By default this is 4. Max limit is 20. A value below 5 should be
 * optimum for most cases. Higher values may even degrade performance.
 *
 */
void cavOctProcessSbufs(int hfa_pipeline_depth, int final)
{
    do
    {
        if (sbufList)
        {
            //SnortXL: review and optimize
            hfa_searchparams_t *poll_sparam = &(sbufList->sparam);
            hfa_searchctx_t *poll_ctx = ((CAV_OCT_HFA_CB_ARG *)(poll_sparam->cbarg))->cohm->graphCtx;
            hfa_searchstatus_t status;

            if (HFA_SUCCESS == hfa_searchctx_get_searchstatus(poll_ctx, poll_sparam, &status))
            {
                if (HFA_SEARCH_SEAGAIN != status)
                {
                    //void *piovec = NULL;
                    uint64_t *pmatches = NULL;
                    hfa_reason_t reason = 0;

                    CAV_OCT_HFA_SBUF_NODE *sbufnode_done = cavOctHfaSbufListPop(); 
                    hfa_searchparams_t *sparam_done = &(sbufnode_done->sparam);
                    hfa_iovec_t  *payload_data = &(sbufnode_done->iovec);
                    hfa_searchctx_t *ctx_done = ((CAV_OCT_HFA_CB_ARG *)sparam_done->cbarg)->cohm->graphCtx;

                    hfa_searchparam_get_hwsearch_reason(sparam_done, &reason);

                    num_partial += hfa_get_partial_matches(sparam_done);

                    /* RFULL is not being handled - only stats */
                    if(cvmx_unlikely(reason == HFA_REASON_RFULL))
                        rfull++;

                    OTNX_MATCH_DATA *pomd = ((CAV_OCT_HFA_CB_ARG *)sparam_done->cbarg)->sn_matchcb_arg;
                    
                    if (!pomd) printf("pomd NULL\n");
                    if (!pomd->p) printf("p NULL\n");

                    //Packet *pkt = pomd->p ;
                    //static int num = 0;
                    account_cycles(pomd->p->hfa_start_cycle, HFA_CYCLES);
                    pomd->p->pp_start_cycle = cvmx_get_cycle();
                    /* Parse Results */ 
                    if (HFA_SUCCESS != hfa_searchctx_getmatches(ctx_done, sparam_done, &pmatches))
                    {
                        dbgl1("Core:%d hfa_searchctx_getmatches Failed\n",cavOctCore);
                    }
                    cav_search_free(payload_data[0].ptr, payload_data[0].len);
                    hfa_matches_cleanup(&((ctx_done->savedctx).state), pmatches);
                    account_cycles(pomd->p->pp_start_cycle, PP_CYCLES);
                    account_cycles(pomd->p->detect_start_cycle, SNORT_DETECT_CYCLES);
                    account_cycles_latency(pomd->p->snort_start_cycle, &(pomd->p->snort_diff_cycle), SNORT_TOTAL_CYCLES);

#ifdef CAV_OCT_ASYNC
                    //cav_search_free(((CAV_OCT_HFA_CB_ARG *)sparam_done->cbarg)->buf, ((CAV_OCT_HFA_CB_ARG *)sparam_done->cbarg)->buf_len);
                    //cav_search_free(((CAV_OCT_HFA_CB_ARG *)sparam_done->cbarg)->buf);
                    
                    pomd->submit_cnt--;
                    if(cvmx_unlikely( final )) 
                        cavPostProcess(pomd);
                    else 
                    {
                        if(pomdidx){
                            if(pomdlist[pomdidx-1] != pomd)
                            {
                                pomdlist[pomdidx]=pomd;
                                pomdidx +=1;
                            }
                        }
                        else {
                            pomdlist[pomdidx]=pomd;
                            pomdidx +=1;
                        }
                        pomd->pending = 1;
                    }
                    
                  
#endif
                    /*free related stuff*/
                    //free(sparam_done->cbarg);
                    //piovec = (sparam_done->input_n).piovec;
                    cvmx_fpa_free(sbufnode_done, CAV_OCT_SNORT_8K_POOL, 0);
                    pending--;
                    process++;
                }
            }
        }
    } while (pending > hfa_pipeline_depth);
}

/* 
 * This API polls for completion of pending searches
 * Gets called if there are no new pending packets from wire (work == NULL).
 * Also called once complete pcap file is read, to ensure that there are no 
 * searches that stay in the pipe-line unpolled.
 * final:Gets set in above 2 cases,while session gets cleaned up
 * and for pipelined http request.
 * */
void cavOctSbufPoll(int final)
{
    cavOctProcessSbufs(0, final);
    dbgl1("All pending sbufs polled\n");
    return ;
}

/*
 * SnortXL :
 * Main Search API
 *
 * This API simulates an HFA search pipeline
 *
 * Tasks:
 * 1. Prepare and submit buffers for search
 * 2. Store requred info which will be required for postprocess
 * 3. Maintain list of pnding searches
 * 4. Submit buffer to HFA for search and add to list.
 * 5. Poll list for completion of search and if complete post-process.
 *
 * */
int cavOctHfaSearch
(
 CAV_OCT_HFA_MPSE * cohm,
 unsigned char * buffer,
 int buffer_len,
 SN_MATCH_CB sn_matchcb,
 void * sn_matchcb_arg
)
{
    int ret = 0,i = -1;
    CAV_OCT_HFA_CB_ARG * cbarg;
    CAV_OCT_HFA_SBUF_NODE * sbufnode=NULL;
    uint8_t *cavbuffer=NULL;

    //dbgl1("cavOctHfaSearch: entered\n");

    if (cohm == NULL)
        return -1;

    if(HFA_GET_GRAPHATTR(cohm->graph_handle, memonly))
    {
        global_memonly_packets++;
    }

    /* Increment usage for the relevant graph */  
    for(i=0;i<MAX_GRAPH_LIST;i++)
    {
        if(glist[i].graph_handle == cohm->graph_handle)
        {
            cvmx_fau_atomic_add64(FAU_GRAPH_USAGE(i), 1);
            break;
        }
        else if (cvmx_unlikely(glist[i].graph_handle == NULL))
        {
            /* find first empty place in graph list and add */
            glist[i].graph_handle = cohm->graph_handle;
            glist[i].cached = 0;
            cvmx_fau_atomic_add64(FAU_GRAPH_USAGE(i), 1);
            dbgl1("CORE %u: cavOctHfaSearch: loaded memonly graph %p onto %d\n",
                    cavOctCore, cohm->graph_handle, i);
            break;
        }
    }

    hfa_iovec_t  *payload_data = NULL;
    hfa_searchparams_t *sparam;

    /* Create search context if needed */
    if (cvmx_unlikely(cohm->graphCtx == NULL))
    {
       //cohm->graphCtx = (hfa_searchctx_t *)cvmx_fpa_alloc(CAV_OCT_SNORT_2K_POOL);
       cohm->graphCtx = (hfa_searchctx_t *)SnortAlloc(sizeof(hfa_searchctx_t));
       if (cohm->graphCtx == NULL)
       {
          ERROR("CORE %d: search context allocation failed. Total ctx(%d)\n",
                   cavOctCore, cavOctTotCtx);
          goto cavOctHfaSearchError;
       }

       if (HFA_SUCCESS != hfa_dev_searchctx_init(&hfa_dev, cohm->graphCtx))
       {
           ERROR("CORE %d: hfa_dev_searchctx_init failed. Total ctx(%d)\n",
                   cavOctCore, cavOctTotCtx);
           goto cavOctHfaSearchError;
       }

       if (HFA_SUCCESS != hfa_searchctx_setgraph(cohm->graphCtx, cohm->graph_handle))
       {
           ERROR("CORE %d: hfa_searchctx_setgraph(%lu) failed.\n",
                    cavOctCore, (long unsigned)cohm->graph_handle);
           goto cavOctHfaSearchError;
       }

       hfa_searchctx_setflags(cohm->graphCtx, HFA_SEARCHCTX_FNOCROSS);
    }

    /** Prepare the sparam/iovec/rbuf for HFA input parameters */
    if ((sbufnode = cvmx_fpa_alloc(CAV_OCT_SNORT_8K_POOL)) == NULL)
    {
        ERROR("CORE %d: failed to allocate sbufnode\n", cavOctCore);
        goto cavOctHfaSearchError;
    }

    cavbuffer = cav_search_prepare(1, buffer, &buffer_len);

    cbarg = &(sbufnode->cbarg);
    cbarg->sn_matchcb = sn_matchcb;
    cbarg->sn_matchcb_arg = sn_matchcb_arg;
    cbarg->cohm = cohm;


    /** Prepare payload_data */
    payload_data = &(sbufnode->iovec);
    payload_data[0].ptr = cavbuffer;
    payload_data[0].len = buffer_len;
    account_stats(buffer_len, HFA_LENGTH);

    sparam = &(sbufnode->sparam);
    memset(sparam, 0, sizeof(hfa_searchparams_t));
    /*set input parameters to search*/
    hfa_searchparam_set_inputiovec (sparam, payload_data, 1);
    /*set output parameters to search */
    hfa_searchparam_set_output(sparam, sbufnode->rbuf, CAV_RBUF_SIZE); 
    /*set the cluster*/
    sparam->clusterno = -1;
    /*set cb arg and MatchCallBack*/
    sparam->cbarg = cbarg;
    OTNX_MATCH_DATA *pomd = cbarg->sn_matchcb_arg;
    pomd->p->state_flag = CAV_STATE_SUBMIT;
    hfa_searchparam_set_matchcb(sparam, cavOctHfaMatchCallback, sparam->cbarg);

    do
    {
        dbgl1("cavOctHfaSearch: hfa_asyncsearch(%ld, %p, %d)\n", 
                    (long int)cohm->graphCtx, &cavbuffer, buffer_len);
        dbgl1("cavOctHfaSearch: hfa_asyncsearch '%s'\n",cavbuffer);
        dbgl1("cavOctHfaSearch: cohm->graph_handle %p\n", 
                (void *)cohm->graph_handle);

        pomd->p->hfa_start_cycle = cvmx_get_cycle();
        /* instruct HFA engine to scan the buffer */
        ret = hfa_searchctx_search_async (cohm->graphCtx, sparam);        

        /* append sbufnode to core-local list for status-polling later */
        if (cvmx_likely(HFA_SUCCESS == ret))
        {
#ifdef CAV_OCT_ASYNC
            pomd->submit_cnt++;
#endif
            cavOctHfaSbufListAppend(sbufnode);
            pending++;

            if (cvmx_unlikely(max_pending < pending))
            {
                max_pending = pending;
                process_at_max_pending = process;
            }
        }
        else
        {
            dbgl1("Core:%d cavOctHfaSearch: Out of memory[%d]\n",cavOctCore, ret);
            if (cvmx_unlikely(max_pending < pending))
            {
                max_pending = pending;
                process_at_max_pending = process;
                cavOctSbufPoll(0);
            }
        }
        
       /* Process pending submiited search Requests */
        cavOctProcessSbufs(hfa_pipeline_depth, 0);
    } while(ret != HFA_SUCCESS);
    
    dbgl1("cavOctHfaSearch: returned\n");
    return 0;

cavOctHfaSearchError:
    return -1;
}

int cavOctHfaGetPatternCount(CAV_OCT_HFA_MPSE *cohm)
{
    if (cohm == NULL)
        return 0;

    dbgl1("cavOctHfaGetPatternCount: %d\n", cohm->pattern_count);
    return cohm->pattern_count;
}

int cavOctHfaPrintInfo(CAV_OCT_HFA_MPSE *cohm)
{
    //int chip_id = cvmx_get_proc_id();
    //char * VERSION_NO = "2.0.0-09";
    return 0;
}

void cavOctHfaPrintSummary(void)
{
    dbgl1("cavOctHfaPrintSummary: show stats\n");
}

#endif
