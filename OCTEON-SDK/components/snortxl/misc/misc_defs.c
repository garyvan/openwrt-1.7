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

#include <stdio.h>
#include <stdint.h>
#include "misc_defs.h"


inline void *cavSnortAlloc(unsigned long size)
{
 void *tmp;
 tmp = cvmx_bootmem_alloc(size, 128);
 if(!tmp)
		printf("cvmx_bootmem_alloc failed\n");
 return tmp;
}


inline void cavfree(void *tmp,unsigned long size)
{
	int ret = __cvmx_bootmem_phy_free(cvmx_ptr_to_phys(tmp),size,0);
	if(!ret)
		printf("cvmx_bootmem_phy_free failed \n");
    return;
}

inline int   cavfirst_core()
{
#ifdef SDK_3_1
    int ret = 0;
    ret = cvmx_coremask_get_first_core(&(cvmx_sysinfo_get()->core_mask));
    return ((unsigned)ret == cvmx_get_core_num());
#else
    return cvmx_coremask_first_core(cvmx_sysinfo_get()->core_mask);
#endif
}

inline int   cavlast_core()
{
#ifdef SDK_3_1
    int ret;
    ret = cvmx_coremask_get_last_core(&(cvmx_sysinfo_get()->core_mask));
    ret = ret-1;
    return ((unsigned)ret == cvmx_get_core_num());
#else
    return cvmx_coremask_is_member(cvmx_sysinfo_get()->core_mask)
        && (((cvmx_sysinfo_get()->core_mask) >> cvmx_get_core_num()) == 1);
#endif
}
        

inline void cavbarrier_sync()
{
#ifdef SDK_3_1
    cvmx_coremask_barrier_sync(&(cvmx_sysinfo_get()->core_mask));
#else
    cvmx_coremask_barrier_sync(cvmx_sysinfo_get()->core_mask);
#endif
    return;
}

inline void cavreset()
{
    cvmx_reset_octeon ();
    return;
}

inline void cav_user_app_init()
{
    cvmx_user_app_init();
    return;
}

inline void cav_wait(int wait)
{
    cvmx_wait(wait);
    return;
}

inline int cav_board_type()
{           
    if(cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
       return 1;
    else
       return 0;
} 

inline double cav_coremask()
{   
#ifdef SDK_3_1        
    return((double)cvmx_coremask_get_core_count(&(cvmx_sysinfo_get()->core_mask)));
#else
    return((double)cvmx_pop(cvmx_sysinfo_get()->core_mask));
#endif
}


#ifdef CAV_OCT_SE
inline int cav_umask(void * a)
{
  return 0;
}
#endif


#ifdef CAV_OCT_LINUX
inline void cavgraphpath()
{ 
    char buf[100];
    if(create_graphs == 1)
    {
        if(cavfirst_core())
        {
            snprintf(buf, sizeof(buf)-1, "rm -rf %s",graphpath);
            system(buf);
            snprintf(buf, sizeof(buf)-1, "mkdir -p %s",graphpath);
            system(buf);
        }
        cavbarrier_sync();
    }
    return;
}
#endif
