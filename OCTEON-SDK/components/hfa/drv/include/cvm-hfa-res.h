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
 * Header file for creating Result buffer for Match callback)
 */
#ifndef _RES_H_
#define    _RES_H_

#include "ppdfa.h"

#define HFA_OS_PPBUFRALLOC(x)   ((*hfa_os_ppbuf_matchalloc)(x))
#define HFA_OS_PPBUFRFREE(x,y)  ((*hfa_os_ppbuf_matchfree)(x,y))
#define HFA_OS_PPBUFRSIZE(x)    ((*hfa_os_ppbuf_matchsize)(x))
/*
    Number of result entries that can fit in a single pp buffer
*/
#define    RMAX(uarg)  \
    (((HFA_OS_PPBUFRSIZE(uarg)) - sizeof (uint64_t)) / sizeof (uint64_t))

/*
    Returns a pointer to the next pp buffer in the list
    Rbuf pointer is a 64 bit pointer even for n32.

*/
#define    RNEXT(p, uarg)        \
 (*(uint64_t**)((uint8_t*)(p)+HFA_OS_PPBUFRSIZE(uarg)-sizeof(uint64_t)))

/*
    Initializes the result processing part of post-processing

        a    - arguments
*/
int
Rinit (arg_dfa_t *a);

/*
    Finish result processing part of post-processing

        a    - arguments
*/
uint64_t *
Rfinish (arg_dfa_t *a);

/*
    Adds a result word to the result buffer

        a    - arguments
        r    - result word
*/
int
Radd (arg_dfa_t *a, uint64_t r);

/*
    Reports a match

        a    - arguments
        patno    - pattern number
        matchno    - match number
        soff    - start offset of the match
        eoff    - end offset of the match
*/
void
Rreport1 (arg_dfa_t *a, int patno, int matchno, int soff, int eoff);

/*
    Frees the result buffer

        buf    - result buffer to free
        _state    - pp state
*/
void
Rfree (uint64_t *buf, state_dfa_t *_state);

#endif
