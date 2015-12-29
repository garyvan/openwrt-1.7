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
 * @INTERNAL
 * @file
 *
 * HFA toolchain versioning
 *
 */
#ifndef _HFA_TOOLS_VERSION_H_
#define _HFA_TOOLS_VERSION_H_

#ifdef KERNEL
#include <linux/types.h>
#include <asm/byteorder.h>
#ifndef __BYTE_ORDER
#if defined(__BIG_ENDIAN) && !defined(__LITTLE_ENDIAN)
#define __BYTE_ORDER __BIG_ENDIAN
#elif !defined(__BIG_ENDIAN) && defined(__LITTLE_ENDIAN)
#define __BYTE_ORDER __LITTLE_ENDIAN
#else
#error "couldn't determine endianness"
#endif
#endif
#else
#include <stdint.h>
#include <endian.h>
#endif
#ifdef HFA_SIM
#include <cvm-hfa-sim.h>
#endif

/*
 * @INTERNAL
 * Structure describing an HFA toolchain version. This may change in the future
 */
typedef struct {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t    releaseno;
	uint32_t    reserved1:16;
	uint32_t    reserved0:8;
	uint32_t    majorno:8;
#else
	uint32_t    majorno:8;
	uint32_t    reserved0:8;
	uint32_t    reserved1:16;
	uint32_t    releaseno;
#endif
} hfa_tools_version_t;

/**
 * @INTERNAL
 * Constructs a readable version string from the toolchain version structure
 *
 * @param   version   pointer to the version
 * @param   buf       char buffer for output
 * @param   size      size of buffer
 *
 * @return  number of bytes required for entire version string, including the
 *          terminating \0'
 */
static inline
size_t hfa_tools_version_to_string(const hfa_tools_version_t *version,
                                   char *buf, size_t size)
{
	return 1 + snprintf(buf, size, "%u-%u", (unsigned)version->majorno,
	                    (unsigned)version->releaseno);
}


/**
 * @INTERNAL
 * Compares two versions
 *
 * @param   version1   pointer to version1
 * @param   version2   pointer to version2
 *
 * @return  <0 if version1 <  version2
 *           0 if version1 == version2
 *          >0 if version1 >  version2
 */
static inline
int hfa_tools_compare_version(const hfa_tools_version_t *version1,
                              const hfa_tools_version_t *version2)
{
	if (version1->majorno != version2->majorno)
		return version1->majorno - version2->majorno;

	return version1->releaseno - version2->releaseno;
}


#endif
