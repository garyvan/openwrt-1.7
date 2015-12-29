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
 * This file conains macros and definitions related to HFA API errors
 *
 */
#ifndef __CVM_HFA_ERROR_H__
#define __CVM_HFA_ERROR_H__

/** Max number of errors in uint64_t*/
#define CVM_HFA_MAX_ERR         64

/**16 bits for General errors*/
#define CVM_HFA_GENERR_IDX      1
#define CVM_HFA_GEN_ELEN        16

/**8 bits for Device errors*/
#define CVM_HFA_DEVERR_IDX      CVM_HFA_GENERR_IDX + CVM_HFA_GEN_ELEN /**17*/
#define CVM_HFA_DEV_ELEN        8 

/**8 bits for Cluster errors*/
#define CVM_HFA_CLUSERR_IDX     CVM_HFA_DEVERR_IDX + CVM_HFA_DEV_ELEN /**25*/ 
#define CVM_HFA_CLUS_ELEN       8 

/**8 bits for Graph errors*/
#define CVM_HFA_GRAPHERR_IDX    CVM_HFA_CLUSERR_IDX + CVM_HFA_CLUS_ELEN /**33*/
#define CVM_HFA_GRAPH_ELEN      8 

/**Remaining bits for Search errors*/
#define CVM_HFA_SRCHERR_IDX     CVM_HFA_GRAPHERR_IDX+ CVM_HFA_GRAPH_ELEN /**41*/
#define CVM_HFA_SRCH_ELEN       CVM_HFA_MAX_ERR - CVM_HFA_SRCHERR_IDX + 1

#ifdef KERNEL

#include <asm/errno.h>
#define assert(i)               BUG_ON(!(i))
extern  int                     errno;
#define hfa_err(ecode, _e)  ({                                              \
                                hfa_ecode |= 1ull<< (ecode -1);              \
                                printk ("ERR[%s,%d]: ",__func__,__LINE__);  \
                                printk _e ;                                 \
                            })
#define hfa_perror(_x)      {                                        \
                                printk ("Ecode: 0x%lx ", hfa_ecode); \
                                printk (_x "\n");                    \
                            }

#else
#include <errno.h>
#include <assert.h>

#define hfa_err(ecode, _e)  ({                                              \
                                hfa_ecode |= 1ull << (ecode -1);               \
                                printf ("ERR[%s,%d]: ",__func__,__LINE__);  \
                                printf _e ;                                 \
                            })
#define hfa_perror(_x)      {                                        \
                                printf ("Ecode: 0x%lx ", hfa_ecode); \
                                printf (_x "\n");                    \
                            }
#endif   
/**
 * Any HFA API failure will set this extern variable 
 * to contain valid error codes
 */
extern  uint64_t                hfa_ecode;
/**
 * HFA APIs error codes
 * API failure error codes can be known be reading extern variable
 * 'ecode'. Application needs to initialise it to 0 before calling
 * the API.
 */
typedef enum {
    CVM_HFA_NOERROR         = 0,
    /**General Errors*/
    CVM_HFA_ENOPERM         = CVM_HFA_GENERR_IDX,
    CVM_HFA_EGEN,
    CVM_HFA_ENOSUPP,           
    CVM_HFA_ENOMEM,           
    CVM_HFA_EMEMEXIST,           
    CVM_HFA_ENOCACHE,           
    CVM_HFA_EINVALARG,        
    CVM_HFA_EALIGNMENT,      
    CVM_HFA_E2BIG,          /*Unused*/
    CVM_HFA_E2SMALL, 
    CVM_HFA_EBADADDR, 
    CVM_HFA_EBADIIOV, 
    CVM_HFA_EBADOIOV, 
    CVM_HFA_EHWERROR,        /*Unused*/ 
    CVM_HFA_EHWBUSY,        /*Unused*/ 
    CVM_HFA_EAGAIN,         /**must be > HFA_REASON_GERR*/
    CVM_HFA_EFAULT, 
    CVM_HFA_EBADFILE, 
    
    /**Dev Errors*/
    CVM_HFA_EDEVINIT        = CVM_HFA_DEVERR_IDX,
    CVM_HFA_EDEVINITPEND,     
    CVM_HFA_EUNITINIT,
    CVM_HFA_EINVALDEVSTATE, 
    CVM_HFA_EDEVEXIST,
    CVM_HFA_EDEVEXIT,
    CVM_HFA_EINVALDEV,

    /**Cluster Errors*/
    CVM_HFA_ECLUSTERINIT    = CVM_HFA_CLUSERR_IDX,
    CVM_HFA_ECINITPEND,
    CVM_HFA_ECEXIST,
    CVM_HFA_EMEMLISTINIT,  
    CVM_HFA_EMEMLISTFULL,  
    CVM_HFA_EINVAL_CLSTATE, 
    CVM_HFA_ECLUSALLOC,
    CVM_HFA_ECLUSFREE,
    CVM_HFA_ECLUSREALLOC,

    /**Graph Errors*/
    CVM_HFA_EGRAPHINIT      = CVM_HFA_GRAPHERR_IDX,
    CVM_HFA_EGRAPH,
    CVM_HFA_EGRAPHVER,
    CVM_HFA_EGINITPEND,
    CVM_HFA_EGEXIST,
    CVM_HFA_ECLOAD, 
    CVM_HFA_EGFREE, 
    CVM_HFA_EMLOAD, 
    CVM_HFA_ECUNLOAD, 
    CVM_HFA_EMUNLOAD, 
    CVM_HFA_EGRAPHEXIST,  
    CVM_HFA_EGINVAL_STATE, 
    CVM_HFA_EGINVAL_STATUS, 
    CVM_HFA_EGINVAL_TYPE, 

    /**Search Errors*/
    CVM_HFA_ESEARCH         = CVM_HFA_SRCHERR_IDX, 
    CVM_HFA_EINVALSRCHSTATE,
    CVM_HFA_EPPINIT,
    CVM_HFA_EPPINITINFO,
    CVM_HFA_EPPCLEANUP,
    CVM_HFA_EPP,
    CVM_HFA_EPPDFA,
    CVM_HFA_EPPASSERT
}hfa_ecode_t;
#endif
