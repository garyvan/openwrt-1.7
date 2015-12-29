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
                                                                                  
* This Software, including technical data, may be subject to U.S. export 
* control laws, including the U.S. Export Administration Act and its 
* associated regulations, and may be subject to export or import  
* regulations in other countries.                                                                      
                                                                                  
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
* WARRANTIES,EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO   
* THE SOFTWARE, INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION
* OR DESCRIPTION,OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
***********************license end**************************************/         


/**
 * @file 
 * File containing configuration variables for HFA applications (SE and SE-UM mode
 */ 
#ifndef _OCTEON_DRV_CONFIG_H_
#define _OCTEON_DRV_CONFIG_H_

#ifdef CAVIUM_COMPONENT_REQUIREMENT
        cvmxconfig {
            fpa OCTEON_IBUFPOOL
                size = 12
                description = "input buffers for OCTEON hfa";
            fpa OCTEON_PPBUFPOOL
                size = 2
                pool = 4
                description = "match buffers for OCTEON hfa";
            fpa OCTEON_TBUFPOOL
                size = 3
                pool = 5
                description = "temp buffers for OCTEON hfa";
            fpa CAV_OCT_SNORT_8K_POOL
                size = 64
                pool = 7
                description = "Packet structure poll for OCTEON snort";
            fpa CAV_OCT_SNORT_2K_POOL
                size = 16
                pool = 6
                description = "Sbuf Poll for OCTEON snort";
            fpa CAV_OCT_SNORT_128B_POOL
                size = 1
                pool = 3
                description = "Snort 128B Pool";


            define OCTEON_IBUFPOOL_COUNT
                value = 30000;
    
            define OCTEON_HFAPOOL
                value = CVMX_FPA_DFA_POOL;
            define OCTEON_HFAPOOL_SIZE
                value = CVMX_FPA_DFA_POOL_SIZE;
            define OCTEON_HFAPOOL_COUNT
                value = 4800;
            define OCTEON_PPBUFPOOL_COUNT
                value = OCTEON_HFAPOOL_COUNT
                description = "thread buffer count for OCTEON hfa";
            define OCTEON_TBUFPOOL_COUNT
                value = 4800
                description = "temp buffer count for OCTEON hfa";
            define CAV_OCT_SNORT_2K_POOL_COUNT
                value = 4800
                description = "Sbuf pool for OCTEON snort";
            define CAV_OCT_SNORT_8K_POOL_COUNT
                value = 4800
                description = "Snort pkt pool for OCTEON snort";
            define CAV_OCT_SNORT_128B_POOL_COUNT
                value = 4800
                description = "Snort 128B Pool";
            define OCTEON_HFA_ARENA_SIZE
                value = 0x4000000
                description = "HFA arena size for graph in bytes 64 MB (default 1024 MB)";
            define OCTEON_HFA_MEMORY_SIZE
                value = 0x100
                description = "HFA Memory Size in Megabytes 256 MB (default 1024 MB)";

        }
#endif

#endif
