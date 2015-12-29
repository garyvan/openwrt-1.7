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



static inline int cav_oct_is_first_core(void)
{
#ifdef SDK_3_1
        int first_core;
        first_core = cvmx_coremask_get_first_core(&(cvmx_sysinfo_get()->core_mask));
        return (first_core == cvmx_get_core_num());
#else
        return (cvmx_coremask_first_core(cvmx_sysinfo_get()->core_mask));
#endif
}

static inline int cav_oct_is_first_core_from_mask(uint64_t mask)
{
#ifdef SDK_3_1
        int first_core, i;
        cvmx_coremask_t coremask_array;

        for(i=0;i < CVMX_COREMASK_BMPSZ;i++)
           coremask_array.coremask_bitmap[i] = 0;
        coremask_array.coremask_bitmap[0] = mask;
        first_core = cvmx_coremask_get_first_core(&coremask_array);
        return (first_core == cvmx_get_core_num());
#else
        return (cvmx_coremask_first_core(mask));
#endif
}


static inline void cav_oct_barrier_sync(uint64_t sf_cmask)
{
#ifdef SDK_3_1
   cvmx_coremask_t coremask_array;
   int i;

   for(i=0;i < CVMX_COREMASK_BMPSZ;i++)
      coremask_array.coremask_bitmap[i]=(cvmx_sysinfo_get()->core_mask).coremask_bitmap[i];

   coremask_array.coremask_bitmap[0] = (coremask_array.coremask_bitmap[0]) & (~sf_cmask);
   cvmx_coremask_barrier_sync(&coremask_array);
#else
   cvmx_coremask_barrier_sync((cvmx_sysinfo_get()->core_mask) & (~sf_cmask));
#endif
}

static inline uint64_t cav_oct_get_coremask(void)
{
#ifdef SDK_3_1
   return ((cvmx_sysinfo_get()->core_mask).coremask_bitmap[0]);
#else
   return (cvmx_sysinfo_get()->core_mask);
#endif
}


static inline int cav_oct_coremask_is_member(uint64_t mask)
{
#ifdef SDK_3_1
   cvmx_coremask_t coremask_array;
   int i;

   for(i=0;i < CVMX_COREMASK_BMPSZ;i++)
      coremask_array.coremask_bitmap[i] = 0;
   coremask_array.coremask_bitmap[0] = mask;
   return (cvmx_coremask_is_core_set(&coremask_array, cvmx_get_core_num()));
#else
   return(cvmx_coremask_is_member(mask));
#endif
}
