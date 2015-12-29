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



#ifndef _CAV_OCT_HFA_H_
#define _CAV_OCT_HFA_H_

#include "snort_debug.h"
#ifdef CAV_OCT_HFA
#include "cvm-hfa.h"
#include "cvm-hfa-search.h"
#include "cvm-hfa-graph.h"
#include "cvmx-asm.h"
#endif

#ifdef CAV_OCT_HFA_GCOMPILE
typedef void hfa_searchctx_t;
typedef void hfa_graph_t;
typedef void *hfa_searchparams_t;
typedef void *hfa_iovec_t;
#endif

#define PATTERN_ARRAY_ALLOC_SIZE 10
#define QUOTE(x) #x
#define STRING(x) QUOTE(x)
#define MAX_SHORT_LENGTH 5
typedef struct gmdata
{
    char gname[41];
    char pgname[13];
    uint8_t pm_type;
    int gcount;
    int npat;
    int tot_len;
    int ncase;
    int min_len;
    int max_len;
    int nshort;
    struct gmdata *next;
    struct gmdata *prev;
    int mg_flag;
    int mg_offset;
    uint32_t cache;

} GMDATA;

/* SnortXL: Shared Arena for Jumbo Search buffers and stream5 packet 
 * - consider modifying this scheme - 
 * Multiple sized fpa pools can be used or software pre-allocated pools 
 * can be utilized
 *
 * Currently allocated 64 MB - Reduce for low-core-counts
 * This is excess - analyse and reduce on worst case reqirement.
 */

#define CAV_ARENA_SIZE 0x4000000

#define cav_arena_alloc(size, align) ({                                     \
            void *ptr = NULL, *newptr = NULL;                                  \
            cvmx_spinlock_lock(&cav_arena_lock);                    \
            if ((ptr = cvmx_malloc(cav_arena, size+align)) != NULL) {          \
                newptr = (void * )((((unsigned long)ptr)+align)&(~(align-1))); \
                ((unsigned char *)newptr)[-1] = (unsigned char)(newptr - ptr); \
            }                                                                  \
            cvmx_spinlock_unlock(&cav_arena_lock);                  \
            newptr;                                                            \
        })

#define cav_arena_free(ptr)    ({                             \
            unsigned char offset = ((unsigned char *)ptr)[-1];        \
            cvmx_spinlock_lock(&cav_arena_lock);                    \
            cvmx_free(((char *)ptr)-offset);                          \
            cvmx_spinlock_unlock(&cav_arena_lock);                  \
        })

typedef struct mdata
{
    char gname[41];
    char pgname[13];
    uint8_t pm_type;
    int gcount;
    int npat;
    int tot_len;
    int ncase;
    int min_len;
    int max_len;
    int nshort;
    struct mdata *next;
    GMDATA *gmptr;

} MDATA;

typedef struct mg_data
{
    int tot_graphs;
    int npat;
	int cache;
    int max_len;
    int common_pat_cnt;
    uint8_t alive;

} MG_DATA;

/* typedefs */
typedef struct cavOctHfaPattern
{
    unsigned char * hex_pattern;
    int pattern_len;
    uint32_t sn_pat_id;
    uint32_t patternId;

    unsigned char * sn_pattern;
    void * sn_pat_data;
    void * sn_rule_option_tree;
    void * sn_neg_list;
    unsigned int sn_no_case;
    unsigned int sn_negative;
} CAV_OCT_HFA_PATTERN;

#ifdef CAV_OCT_LINUX
void *hfa_bootmem_alloc (uint64_t, uint64_t);
int  hfa_bootmem_free (void *, uint64_t);
#endif
typedef int (*SN_MATCH_CB)(void * id, void *tree, int index, 
                           void * sn_matchcb_arg, void *neg_list);
typedef struct cavOctHfaMpse
{
    void (*sn_pat_free)(void *);
    void (*sn_option_tree_free)(void **);
    void (*sn_neg_list_free)(void **);
    int (*sn_build_tree)(void *, void **);
    int (*sn_neg_list_func)(void *, void **);
    int pattern_count;
    int pattern_array_len;
    hfa_searchctx_t *graphCtx; 
    hfa_graph_t *graph_handle;
    CAV_OCT_HFA_PATTERN * pattern_array;
    SN_MATCH_CB sn_matchcb;
    MDATA *meta_data;
} CAV_OCT_HFA_MPSE;

typedef struct flag_list
{
	struct cavOctHfaMpse *cohm;
	struct flag_list *next;
} FLAG_LIST;

typedef struct cavOctHfaGraphs
{
    int size;
    char gname[100];
    hfa_graph_t *graph_handle;
    struct flag_list *head[CVMX_MAX_CORES];
    struct cavOctHfaGraphs *prev;
} CAV_OCT_HFA_GRAPHS;

typedef struct OctHfaGraphlist
{
    hfa_graph_t *graph_handle;
    uint8_t cached;
} OCT_HFA_GRAPHLIST;

typedef struct cavOctHfaCbArg
{
    SN_MATCH_CB sn_matchcb;
    void * sn_matchcb_arg;
    CAV_OCT_HFA_MPSE * cohm;
} CAV_OCT_HFA_CB_ARG;

#define SBUF_PADDING  104  //  (256 - (16 + sizeof(hfa_searchparams_t) + sizeof(CAV_OCT_HFA_CB_ARG + sizeof(hfa_iovec_t))))
#define CAV_RBUF_SIZE 7936 // (CAV_OCT_SNORT_8K_POOL_SIZE - (SBUF_PADDING + 16 + sizeof(hfa_searchparams_t) + sizeof(hfa_iovec_t) + sizeof(CAV_OCT_HFA_CB_ARG)))

typedef struct cavOctHfaSbufNode
{
    struct cavOctHfaSbufNode * next;  //8
    struct cavOctHfaSbufNode * tail;  //8
    hfa_searchparams_t sparam;        //96
    hfa_iovec_t        iovec;         //16
    CAV_OCT_HFA_CB_ARG cbarg;         //24
    uint8_t unused[SBUF_PADDING];     //104
    uint8_t rbuf[CAV_RBUF_SIZE];
} CAV_OCT_HFA_SBUF_NODE;


/* forward declarations */
int cavOctHfaInit (void);
void * cavOctHfaNew (void (*sn_pat_free)(void *p),
void (*sn_option_tree_free)(void **p),
void (*sn_neg_list_free)(void **p));
void cavOctHfaDelete(CAV_OCT_HFA_MPSE *cohm);
int cavOctHfaAddPattern (CAV_OCT_HFA_MPSE *cohm, unsigned char *pattern,
    int pat_len, unsigned int sn_no_case, unsigned int sn_negative,
    void *sn_pat_data, int sn_pat_id);
int cavOctHfaCompile (CAV_OCT_HFA_MPSE *cohm,
int (*sn_build_tree)(void *id, void **existing_tree),
int (*sn_neg_list_func)(void *id, void **list));
void cavOctHfaFreeCallback(void *, unsigned short, void *);
int cavOctHfaSearch (CAV_OCT_HFA_MPSE * cohm, unsigned char * buffer,
    int buffer_len, SN_MATCH_CB sn_matchcb, void * sn_matchcb_arg);
void cavOctSbufPoll(int);
int cavOctHfaGetPatternCount(CAV_OCT_HFA_MPSE *cohm);
int cavOctHfaPrintInfo(CAV_OCT_HFA_MPSE *cohm);
void cavOctHfaPrintSummary(void);
int cavOctHfaExit (void);
void cavOctHfaGcompile(void);
void cavOctHfaParse(void);
void cavOctHfaDump(void);
int cavOctHfaSort(void);
void cavOctHfaFreeGmdata(void);
void cavOctHfaGraphMerge(void);
void* cavOctAlloc(void);
void cavOctFree(void *);
void show_rbuf_stat(void);
void show_hte_stat(void);
extern void* (*func_cav128BAlloc)(void);
extern void (*func_cav128BFree)(void*);

#ifdef CAV_OCT_ASYNC
void GetOmdStats(uint64_t *acount, uint64_t *fcount);
#endif
#endif  /* _CAV_OCT_HFA_H_ */
