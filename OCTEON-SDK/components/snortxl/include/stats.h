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



//#define DUMP_PKT_STATS //To dump Statistics for flow and search data
//#define DUMP_PKT_DATA  //To dump search buffer and sizes

typedef enum
{
  HFA_CYCLES,
  HFA_LENGTH,
  HFA_JUMBO_BUFFERS,
  PP_CYCLES,
  SNORT_LENGTH,
  SNORT_PP_CYCLES,
  SNORT_DETECT_CYCLES,
  SNORT_PREPROC_CYCLES,
  SUB_FAIL,
  SNORT_TOTAL_CYCLES,
  SNORT_PROC_CYCLES,  //All above metrics are broken for async - should work for sync
  PASS_CYCLES,
  SSO_CYCLES,
  SSO_Q,
  MAX_METRICS
}metric_t;

typedef struct profile_stat
{
  uint64_t total;
  uint64_t max;
  uint64_t min;
  uint64_t hits;
}profile_stat_t;

extern profile_stat_t profile_stats[];

#ifdef DUMP_PKT_STATS
int global_pkt_num;
#define NUM_DUMP_PACKETS 100
typedef struct pkt_stat
{
  uint64_t total;
  uint64_t hits;
  uint64_t avg;
}pkt_stat_t;

pkt_stat_t pkt_st[NUM_DUMP_PACKETS][MAX_METRICS];
#endif

static int init_prof_stats()
{
	int metric;
	for (metric=0; metric < MAX_METRICS; metric++)
	{
		profile_stats[metric].total = 0;
        profile_stats[metric].min = 0;
        profile_stats[metric].max = 0;
        profile_stats[metric].hits= 0;
	}

#ifdef DUMP_PKT_STATS
    int i;
    for (i=0;i<NUM_DUMP_PACKETS;i++)
	    for (metric=0; metric < MAX_METRICS; metric++)
        {
            pkt_st[i][metric].total = 0;
            pkt_st[i][metric].hits = 0;
            pkt_st[i][metric].avg = 0;
        }
#endif
    return 0;
}


static int account_stats(uint64_t stat, metric_t metric)
{

    profile_stats[metric].total +=  stat;
	
    if (cvmx_unlikely(!profile_stats[metric].min))
       profile_stats[metric].min = stat;

    else if (cvmx_unlikely(stat < profile_stats[metric].min))
       profile_stats[metric].min = stat;

    if (cvmx_unlikely(stat > profile_stats[metric].max))
       profile_stats[metric].max = stat;
   
    profile_stats[metric].hits ++;
    return 0;
}


static int account_cycles(uint64_t start_cycle, metric_t metric)
{
    uint64_t time_taken;

    time_taken = cvmx_get_cycle() - start_cycle;
    profile_stats[metric].total +=  time_taken;
	
#ifdef DUMP_PKT_STATS
    if(metric != 5)
        pkt_st[global_pkt_num][metric].total += time_taken;
    else
        pkt_st[global_pkt_num][metric].total = time_taken;
    pkt_st[global_pkt_num][metric].hits++;
    pkt_st[global_pkt_num][metric].avg = pkt_st[global_pkt_num][metric].total/pkt_st[global_pkt_num][metric].hits;
#endif

    if (cvmx_unlikely(!profile_stats[metric].min))
       profile_stats[metric].min = time_taken;
    else if (cvmx_unlikely(time_taken < profile_stats[metric].min))
       profile_stats[metric].min = time_taken;

    if (cvmx_unlikely(time_taken > profile_stats[metric].max))
       profile_stats[metric].max = time_taken;
   
    profile_stats[metric].hits ++;
    return 0;
}

static int account_cycles_latency(uint64_t start_cycle, uint64_t *difference, metric_t metric)
{
    uint64_t time_taken;
    uint64_t present_time = cvmx_get_cycle();

    time_taken = (present_time - start_cycle);
    profile_stats[metric].total +=  time_taken;
    profile_stats[metric].total -=  *difference;
    
	*difference = time_taken;
	
    if (cvmx_unlikely(!profile_stats[metric].min))
       profile_stats[metric].min = time_taken;
    else if (cvmx_unlikely(time_taken < profile_stats[metric].min))
       profile_stats[metric].min = time_taken;

    if (cvmx_unlikely(time_taken > profile_stats[metric].max))
       profile_stats[metric].max = time_taken;
   
    profile_stats[metric].hits ++;
    return 0;
}
