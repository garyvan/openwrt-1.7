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
 * This file contains common macros and definitions required by all APIs 
 * and applications
 * 
 */
#ifndef _CVM_HFA_COMMON_H_
#define _CVM_HFA_COMMON_H_

/*
 * This macro can be removed once code become
 * stable enough
 */
#define HFA_STRICT_CHECK

#ifndef HFA_SIM
#include <cvm-hfa-osapi.h>
#else
#include <cvm-hfa-sim.h>
#endif
#include <cvm-hfa-instr.h>
#include <cvm-hfa-error.h>
#include <pp.h>

#define HFA_DEV_INITDONE                0x5A5A
#define HFA_MAXNAMELEN                  32
#define HFA_MAX_OCTEON_CORE             32
#define HFADEV_PATHNAME                 "/dev/octeon-hfa" 

#define HFA_SET(TYPE, SUBTYPE, member, value)  ((TYPE)->SUBTYPE).member = value
#define HFA_PSET(TYPE, SUBTYPE, member, value) ((TYPE)->SUBTYPE)->member = value

#define HFA_BITSET(srcmsk, bitno)       (srcmsk |= (1ull << bitno))
#define HFA_BITCLR(srcmsk, bitno)       (srcmsk &= ~(1ull <<bitno))
#define HFA_ISBITSET(srcmsk, bitno)     ((srcmsk & (1ull << bitno))? 1: 0)
#define HFA_ISBITCLR(srcmsk, bitno)     ((srcmsk & (1ull << bitno))? 0: 1)

#define HFA_BITMSKSET(srcmsk, bitmsk)   (srcmsk |= (bitmsk))
#define HFA_BITMSKCLR(srcmsk, bitmsk)   (srcmsk &= ~(bitmsk))
#define HFA_ISBITMSKSET(srcmsk, bitmsk) ((bitmsk == (srcmsk & bitmsk)) ? 1:0)
#define HFA_ISBITMSKCLR(srcmsk, bitmsk) ((bitmsk != (srcmsk & bitmsk)) ? 1:0)

#define CVM_HFA_BUFSIZE             PPBUFSIZE

#define OCTEON_HFA_CID(x)           ((x >>8) & 0xff)
#define OCTEON_HFA_CHIP()           OCTEON_HFA_CID (cvmx_get_proc_id())
#define OCTEON_HFA_ISCHIP(id)       ((id == OCTEON_HFA_CHIP()) ? 1: 0)

#ifndef HFA_SIM
#define _HFA_ISMEM_NOTALIGNED(x, y) (x & (y-1))
#else
#define _HFA_ISMEM_NOTALIGNED(x, y) (0)
#endif

#define _HFA_ISMEM_ALIGNED(x, y)    (!_HFA_ISMEM_NOTALIGNED(x, y));
#define HFA_ALIGNED(x, y)            x += y- 1; x -= (x % y);
#define HFA_ROUND(x)                (x) - ((x) % hfa_get_mem_align())
#define HFA_RNDUP2(_x)              (((_x) >> 1) + ((_x) % 2))
#define HFA_ROUNDUP(_x,_y)          ((_x) + (_y - 1) - (((_x) + (_y -1)) % _y))
#define HFA_ROUNDUP8(_x)            ({                            \
                                        int a;                    \
                                        a = _x;                   \
                                        a += 7; a -= (a % 8);     \
                                        a;                        \
                                    })

/*Typedefs*/
typedef int                 hfa_devid_t;
typedef int                 hfa_clusters_t;
typedef int                 hfa_alignment_t;
typedef uint32_t            octeon_chipid_t;
typedef uint32_t            board_pass_t;
typedef uint64_t            hfa_graph_handle_t;
typedef uint32_t            hfa_graph_clmsk_t;
typedef uint32_t            hfa_flags_t;

typedef ppiovec_t           hfa_iovec_t;
typedef ppcb_t              hfa_matchcb_t;
typedef ppmeta_t            hfa_meta_t;
typedef ppcap_t             hfa_cap_t;
typedef ppmatch_t           hfa_match_t;
typedef ppstate_t           hfa_state_t;
typedef int                 hfa_ppiflags_t;
typedef int                 hfa_ppoflags_t;
typedef cvm_hfa_reason_t    hfa_reason_t;
typedef cvm_hfa_snode_t     hfa_snode_t;
typedef cvm_hfa_snode2_t    hfa_snode2_t;
typedef uint32_t            hfa_pdboff_t;
typedef cvmx_coremask_t     hfa_coremask_t;
typedef ppstats_t           hfa_ppstats_t;

#if defined(KERNEL) || defined(HFA_SIM)
typedef unsigned int        hfa_size32_t;
typedef unsigned long       hfa_size_t;
typedef unsigned long       hfa_addr_t;
#else
typedef uint32_t            hfa_size32_t;
typedef uint64_t            hfa_size_t;
typedef uint64_t            hfa_addr_t;
/* no arena concept in simulator */
#ifndef HFA_SIM
extern  CVMX_SHARED cvmx_arena_list_t   hfa_arena;
extern  CVMX_SHARED cvmx_spinlock_t     cvmx_malloc_lock;
#endif
#endif
/**
 * Return type for all HFA APIs
 */
typedef enum {
    HFA_SUCCESS = 0,
    HFA_FAILURE = -1
} hfa_return_t;

/**
 * OCTEON VALID TARGETS
 */
typedef enum {
    OCTEON_HFA_63XX_TARGET=3,
    OCTEON_HFA_68XX_TARGET=5,
    OCTEON_HFA_61XX_TARGET=6,
    OCTEON_HFA_66XX_TARGET=7,
    OCTEON_HFA_70XX_TARGET=9,
    OCTEON_HFA_MAX_TARGETS=10
}octeon_hfa_target_t;
/**
 * OCTEON CHIP Ids that supports HFA
 */
typedef enum {
    OCTEON_HFA_CN63XX_CID = 0x90,
    OCTEON_HFA_CN68XX_CID = 0x91,
    OCTEON_HFA_CN66XX_CID = 0x92,
    OCTEON_HFA_CN61XX_CID = 0x93,
    OCTEON_HFA_CN70XX_CID = 0x96
}octeon_hfa_cid_t;

/**
 * PP related flags
 */
typedef enum {
    CVM_HFA_FSUBMITALL  = 0x100,
    CVM_HFA_FBUFFER     = PPOFBUFFER,
    CVM_HFA_INVAL       = PPINVAL,
}hfa_pp_codes_t;

/**
 * HFA Cluster Numbering
 */
typedef enum {
    HFA_CLUSTER0 = 0,
    HFA_CLUSTER1 = 1,
    HFA_CLUSTER2 = 2,
    HFA_MAX_CACHE_PER_CLUSTER=3
}hfa_clusternum_t;
/**
 * Maximum no. of HTEs in each OCTEON
 */
typedef enum {
    HFA_ZERO_HTES=0,
    HFA_CN61XX_HTES=16,
    HFA_CN63XX_HTES=16,
    HFA_CN66XX_HTES=16,
    HFA_CN68XX_HTES=48, 
    HFA_CN70XX_HTES=16, 
} hfa_nhtes_t;
/**
 * Maximum no. of clusters supported in each OCTEON
 */
typedef enum {
    HFA_ZERO_CLUSTERS=0,
    HFA_CN61XX_NCLUSTERS=1,
    HFA_CN63XX_NCLUSTERS=1,
    HFA_CN66XX_NCLUSTERS=1,
    HFA_CN68XX_NCLUSTERS=3, 
    HFA_CN70XX_NCLUSTERS=1, 
    HFA_MAX_NCLUSTERS=3       /*Maximum cluster supported by any OCTEON chip*/
} hfa_nclusters_t;

/**
 * ClusterMask supported (0x1 - 0x7).
 */
typedef enum {
    HFA_68XX_MAX_CLMSK=0x7,
    HFA_63XX_MAX_CLMSK=0x1
} hfa_clmsk_t;

/**
 * HFA_RAM1 for Cache0 of cluster
 * HFA_RAM2 for Cache1 of cluster
 * HFA_RAM3 for Cache2 of cluster
 */
typedef enum {
    HFA_RAM1 = 0,
    HFA_RAM2 = 1,
    HFA_RAM3 = 2
} hfa_ramnum_t;

/**
 * Memory Alignement required as per OCTEONII/III
 */
typedef enum {
    HFA_68XX_MEM_ALIGNMENT = 0x10000,
    HFA_63XX_MEM_ALIGNMENT = 0x400,
    HFA_INVALID_ALIGNMENT = 0xffffffff
}hfa_mem_alignment_t;

/**Unused8 field value for different WQEs like
 * HFA WQE and PKT WQE*/
typedef enum {
    HFA_GRAPH_HWWQE_UNUSED_FIELD = 0x55,
    HFA_SEARCH_HWWQE_UNUSED_FIELD = 0x44
}hfa_wqe_unused_fieldval_t;

/**Different WQE types */
typedef enum {
    HFA_GRAPH_HWWQE,
    HFA_SEARCH_HWWQE,
    PACKET_WQE
}hfa_wqe_type_t;

/** 
 * Indicates whether recieved wqe is search instruction response.
 * 
 * @param   wqe         WQE pointer
 *
 * @return  1 if search response, 0 otherwise
 */ 
static inline hfa_bool_t 
hfa_search_response(cvmx_wqe_t *wqe) 
{
    if(HFA_SEARCH_HWWQE_UNUSED_FIELD == cvmx_wqe_get_unused8(wqe)) 
        return (HFA_TRUE);
    else 
        return (HFA_FALSE);
}
/** 
 * Indicates whether recieved wqe is graph load instruction response.
 * 
 * @param   wqe         WQE pointer
 *
 * @return  1 if search response, 0 otherwise
 */ 
static inline hfa_bool_t 
hfa_graph_load_response(cvmx_wqe_t *wqe) 
{
    if(HFA_GRAPH_HWWQE_UNUSED_FIELD == cvmx_wqe_get_unused8(wqe)) 
        return (HFA_TRUE);
    else 
        return (HFA_FALSE);
}
/** 
 * This routine is for getting WQE type.
 *
 * @param   wqe         WQE pointer
 *
 * @return  HFA_SEARCH_HWWQE, if wqe is a search instruction response
 *          HFA_GRAPH_HWWQE, if wqe is a graph load instruction response
 *          PACKET_WQE, if wqe is a packet wqe
 */ 
static inline hfa_wqe_type_t
hfa_get_wqe_type(cvmx_wqe_t *wqe) 
{
    switch(cvmx_wqe_get_unused8(wqe)) {
        case HFA_SEARCH_HWWQE_UNUSED_FIELD:
            return HFA_SEARCH_HWWQE;
        case HFA_GRAPH_HWWQE_UNUSED_FIELD:
            return HFA_GRAPH_HWWQE;
        default:
            return PACKET_WQE;
    }
}    
/**
 * Dump HFA related registers
 */
static inline void
hfa_dump_regs (void)
{
    int    i, j;
    struct {
        char        *name;
        uint64_t    addr;
    } regs[] = {
        { "DFA_CONFIG", 0x8001180037000000ULL },
        { "DFA_CONTROL", 0x8001180037000020ULL },
        { "DFA_ERROR", 0x8001180037000028ULL },
        { "DFA_INTMSK", 0x8001180037000030ULL },
        { "DFA_DEBUG0", 0x8001180037000040ULL },
        { "DFA_DEBUG1", 0x8001180037000048ULL },
        { "DFA_DEBUG2", 0x8001180037000050ULL },
        { "DFA_DEBUG3", 0x8001180037000058ULL },
        { "DFA_DTCFADR", 0x8001180037000060ULL },
        { "DFA_PFC_GCTL", 0x8001180037000080ULL },
        { "DFA_PFC0_CTL", 0x8001180037000088ULL },
        { "DFA_PFC0_CNT", 0x8001180037000090ULL },
        { "DFA_PFC1_CTL", 0x8001180037000098ULL },
        { "DFA_PFC1_CNT", 0x80011800370000A0ULL },
        { "DFA_PFC2_CTL", 0x80011800370000A8ULL },
        { "DFA_PFC2_CNT", 0x80011800370000B0ULL },
        { "DFA_PFC3_CTL", 0x80011800370000B8ULL },
        { "DFA_PFC3_CNT", 0x80011800370000C0ULL },
        { "DFA_BIST0", 0x80011800370007F0ULL },
        { "DFA_BIST1", 0x80011800370007F8ULL },
        { "DFA_DBELL", 0x8001370000000000ULL },
        { "DFA_DIFRDPTR", 0x8001370200000000ULL },
        { "DFA_DIFCTL", 0x8001370600000000ULL },
        { "DFA_MEMHIDAT", 0x8001370700000000ULL },
        { "DFM_DUAL_MEMCFG", 0x80011800D4000098ULL },
        { "DFM_RESET_CTL", 0x80011800D4000180ULL },
        { "DFM_CONFIG", 0x80011800D4000188ULL },
        { "DFM_CONTROL", 0x80011800D4000190ULL },
        { "DFM_TIMING_PARAMS0", 0x80011800D4000198ULL },
        { "DFM_TIMING_PARAMS1", 0x80011800D40001A0ULL },
        { "DFM_MODEREG_PARAMS0", 0x80011800D40001A8ULL },
        { "DFM_WODT_MASK", 0x80011800D40001B0ULL },
        { "DFM_COMP_CTL2", 0x80011800D40001B8ULL },
        { "DFM_DLL_CTL2", 0x80011800D40001C8ULL },
        { "DFM_IFB_CNT", 0x80011800D40001D0ULL },
        { "DFM_OPS_CNT", 0x80011800D40001D8ULL },
        { "DFM_FCLK_CNT", 0x80011800D40001E0ULL },
        { "DFM_INT_EN", 0x80011800D40001E8ULL },
        { "DFM_INT", 0x80011800D40001F0ULL },
        { "DFM_SLOT_CTL0", 0x80011800D40001F8ULL },
        { "DFM_SLOT_CTL1", 0x80011800D4000200ULL },
        { "DFM_SLOT_CTL2", 0x80011800D4000208ULL },
        { "DFM_PHY_CTL", 0x80011800D4000210ULL },
        { "DFM_DLL_CTL3", 0x80011800D4000218ULL },
        { "DFM_MODEREG_PARAMS1", 0x80011800D4000260ULL },
        { "DFM_RODT_MASK", 0x80011800D4000268ULL },
        { "DFM_RLEVEL_RANK0", 0x80011800D4000280ULL },
        { "DFM_RLEVEL_RANK1", 0x80011800D4000288ULL },
        { "DFM_RLEVEL_CTL", 0x80011800D40002A0ULL },
        { "DFM_RLEVEL_DBG", 0x80011800D40002A8ULL },
        { "DFM_WLEVEL_RANK0", 0x80011800D40002B0ULL },
        { "DFM_WLEVEL_RANK1", 0x80011800D40002B8ULL },
        { "DFM_WLEVEL_CTL", 0x80011800D4000300ULL },
        { "DFM_WLEVEL_DBG", 0x80011800D4000308ULL },
        { "DFM_FNT_CTL", 0x80011800D4000400ULL },
        { "DFM_FNT_STAT", 0x80011800D4000408ULL },
        { "DFM_FNT_IENA", 0x80011800D4000410ULL },
        { "DFM_FNT_SCLK", 0x80011800D4000418ULL },
        { "DFM_FNT_BIST", 0x80011800D40007F8ULL },
        { NULL, 0x0 }
    };
    union {
        uint8_t        u8[8];
        uint64_t    u64;
    } v;

    for (i = 0; regs[i].name != NULL; ++i) {
        printf ("%24s: 0x", regs[i].name);
        v.u64 = cvmx_read_csr (regs[i].addr);
        for (j = 0; j < 8; ++j)
            printf ("%02x", v.u8[j]);
        printf ("\n");
    }
}
#define WORDLEN 8
/**
 * Dump buffer pointed by "buf" in readable format
 *
 * @param   msg     String to identify dump
 * @param   buf     Pointer to the buffer
 * @param   count   Size of buffer
 *
 * @return  Void
 */
static inline void
hfa_dump_buf (const char *msg, uint64_t *buf, uint64_t count)
{
    unsigned long   i, base = 0;
    unsigned char *D = (unsigned char *)buf;
    hfa_log( "Dump: %s, Addr: %p\n", msg, buf);
    hfa_log( "-------- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- ----------------\n" );
    for( ; base+WORDLEN < count; base += WORDLEN )
    {
        hfa_log( "%08lX ", base );
        for( i=0; i<WORDLEN; i++ )
        {
            hfa_log( "%02X ", D[base+i] );
        }
        for( i=0; i<WORDLEN; i++ )
        {
            hfa_log( "%c", isprint(D[base+i])?D[base+i]:'.' );
        }
        hfa_log( "\n" );
     }
     hfa_log( "%08lX ", base );
     for( i=base; i<count; i++ )
     {
         hfa_log( "%02X ", D[i] );
     }
     for( ; i<base+WORDLEN; i++ )
     {
         hfa_log( "   " );
     }
     for( i=base; i<count; i++ )
     {
         hfa_log( "%c", isprint(D[i])?D[i]:'.' );
     }
     for( ; i<base+WORDLEN; i++ )
     {
         hfa_log( " ");
     }
     hfa_log( "\n" );
     hfa_log( "-------- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- ----------------\n" );
     hfa_log( "\n" );
 }
#endif
