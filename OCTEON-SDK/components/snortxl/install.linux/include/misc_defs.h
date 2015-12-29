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


#ifndef _MISC_DEFS_H_
#define _MISC_DEFS_H_

#ifdef CAV_OCT_HFA
#include <cvmx.h>
#include <cvmx-bootmem.h>
#include <cvmx-coremask.h>
#include <cvmx-platform.h>
#endif
#include <string.h>
int octeon_initialize(void);
void (*func_pStats)(void);
int octeonSE_initialize();
void * octeonSE_acquire(uint32_t *len, uint64_t *addr, int);
int octeonSE_inject(void *work);
int octeonSE_shutdown();
int InitPortSets(char *intf);
#ifdef CAV_OCT_SE
#include "memfsmap.h"
#define waitpid(...) 0
inline void cav_wait(int wait);
inline int cav_board_type();
inline void cavreset();
void octeon_uart_init();
void memfs_exit(void (*memfs_free_rtn) (void *));
int init_named_block(void);
#endif

/* Enum for IP and L4 checksum Errors */
#ifndef CAV_OCT_HFA_GCOMPILE
enum 
{
	CAV_ERR_NONE = 0,
	CAV_ERR_IP_CS,
	CAV_ERR_L4_CS
};
#endif
extern int cav_oct_err_flag;
extern int merge_graphs;
#define NO_MERGE_GRAPHS "no-merge-graphs"
#define MAX_PORT_SETS 16
 
#if defined(CAV_OCT_HFA) || defined(CAV_OCT_HFA_GCOMPILE)

#define CREATE_GRAPHS "create-graphs"
#define GRAPH_PATH "graph-path"
extern int create_graphs;
extern char graphpath[100];
inline void cavgraphpath();
#endif

#ifdef CAV_OCT_HFA
#ifdef linux
#define ERR(_x, ...)    {                              \
                printf ("error: " _x, ## __VA_ARGS__);         \
            }
#else
#define ERR(_x, ...)    {                              \
                printf ("error: " _x, ## __VA_ARGS__);         \
                cvmx_reset_octeon();                  \
            }
#endif
#define HFA_SYNC "sync"
extern unsigned int cav_oct_core;
extern int cvm_hfap_flag;

inline void *cavSnortAlloc(unsigned long size);
inline void  cavfree(void *tmp, unsigned long size);
inline int   cavfirst_core();
inline int   cavlast_core();
inline void cavbarrier_sync();
inline void cav_user_app_init();
inline double cav_coremask();
#endif

#endif
