/***********************license start***************                              
* Copyright (c) 2003-2015  Cavium Inc. (support@cavium.com). All rights           
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
                                                                                  
*This Software,including technical data,may be subject to U.S. export control 
*laws, including the U.S. Export Administration Act and its  associated          
* regulations, and may be subject to export or import  regulations in other       
* countries.                                                                      
                                                                                  
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
*WARRANTIES,EITHER EXPRESS, IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO   
*THE SOFTWARE, INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR  
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
 * This is header file for pool and aura related macros
 *
 */
#ifndef _CVM_HFA_CONFIG_H_
#define _CVM_HFA_CONFIG_H_

#define CVMX_CACHE_LINE_SIZE			(128)
#define OCTEON_PPBUFPOOL_SIZE           (8 * CVMX_CACHE_LINE_SIZE)
#define OCTEON_PPBUFPOOL_COUNT			(120000)
#define OCTEON_TBUFPOOL_SIZE            (4 * CVMX_CACHE_LINE_SIZE)
#define OCTEON_TBUFPOOL_COUNT			(120000)
#define OCTEON_HFAPOOL_SIZE             OCTEON_PPBUFPOOL_SIZE
#define OCTEON_HFAPOOL_COUNT			OCTEON_PPBUFPOOL_COUNT
#define OCTEON_IBUFPOOL_SIZE            (16 * CVMX_CACHE_LINE_SIZE)
#define OCTEON_IBUFPOOL_COUNT           (120000)

#ifdef CN6XXX_HFA
#define OCTEON_IBUFPOOL              (0)
#define OCTEON_WQE_POOL              (1)
#define OCTEON_OUTPUT_BUFFER_POOL    (2)
#define OCTEON_PPBUFPOOL             (4)
#define OCTEON_TBUFPOOL              (5)
#define OCTEON_HFAPOOL               OCTEON_PPBUFPOOL
#else 
#define OCTEON_IBUFPOOL              (-1) /*Pool will be allocated dynamically*/
#define OCTEON_WQE_POOL              (-1) /*Pool will be allocated dynamically*/
#define OCTEON_OUTPUT_BUFFER_POOL    (-1) /*Pool will be allocated dynamically*/
#define OCTEON_HFAPOOL               (4)
#define OCTEON_PPBUFPOOL             OCTEON_HFAPOOL
#define OCTEON_TBUFPOOL              OCTEON_HFAPOOL
#endif

#define CAV_OCT_SNORT_8K_POOL           (7)
#define CAV_OCT_SNORT_8K_POOL_SIZE      (64 * CVMX_CACHE_LINE_SIZE)
#define CAV_OCT_SNORT_8K_POOL_COUNT     (12000)
#define CAV_OCT_SNORT_2K_POOL           (6)
#define CAV_OCT_SNORT_2K_POOL_SIZE      (16 * CVMX_CACHE_LINE_SIZE)
#define CAV_OCT_SNORT_2K_POOL_COUNT     (4000)

/* HFA arena size for graph in bytes */
#define OCTEON_HFA_ARENA_SIZE           (0x40000000)
/* HFA memory size in Mega Bytes */
#define OCTEON_HFA_MEMORY_SIZE          (0x400)

/*Resrving 64 OSM banks for HFA block*/
#define HFA_OSM_START_BANK          	0
#define HFA_OSM_NUMBANKS            	64 /*Minimum value is 2*/

#endif
