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
 * This is header file for graph related APIs
 *
 */
#ifndef _CVM_HFA_GRAPH_H_
#define _CVM_HFA_GRAPH_H_

#include "cvm-hfa-common.h"
#include "cvm-hfa-cluster.h"
#include "cvm-hfa.h"
#include "ppdfa.h"

#define HFA_NONIOVEC_MAX_MEMLOADSZ  ((256<<20)-1) /*256 MB-1*/ 
/**@cond INTERNAL */
#define HFA_GRAPH_INITDONE          0xA5AE
#define HFA_IOVEC_MAX_MEMLOADSZ     ((16<<20)-1) /*16MB-1*/
#define HFA_MEM_TYPE                  2
#define HFA_RMDATA_SIZE               sizeof(hfa_mload_rmdata_overload_t)
/*Graph header related macros*/
#define HFA_GRESERVED_SIZE           20 /*Flag, savelen + graphattr*/

/*HFA_GPPINFO_SIZE should be pgraph->nirt * sizeof(ppinfo) but in case of
 * flags set CVM_HFA_SFUBMITALL then nirt =1 hence pgraph->ninfo
 * is valid to calculate size*/
#define HFA_GPPINFO_SIZE(pgraph)    ((pgraph)->ninfo * sizeof(ppinfo_t))
#define HFA_GINFO_SIZE(pgraph)      ((pgraph)->ninfo * sizeof(hfa_graphchunk_t))
#define HFA_GOBJ_SIZE(pgraph)       ((pgraph)->nobj * sizeof(hfa_graphobj_t))
#define HFA_GHDRLEN(pgraph)                     \
    HFA_GRAPHHDR_MINLEN + HFA_GOBJ_SIZE(pgraph) + HFA_GRESERVED_SIZE
#define HFA_GFLAG_OFF(pgraph)                   \
    HFA_GRAPHHDR_MINLEN + HFA_GOBJ_SIZE(pgraph)
#define HFA_GSAVELEN_OFF(pgraph)                \
    HFA_GRAPHHDR_MINLEN + HFA_GOBJ_SIZE(pgraph) + 4
#define HFA_GATTR_OFF(pgraph)                \
    HFA_GRAPHHDR_MINLEN + HFA_GOBJ_SIZE(pgraph) + 8

#define HFA_SET_GRAPHATTR(graph, field, val) ((graph)->info.attr).field = val
/**@endcond */
/** Get graph attributes. For available attributes see hfa_graphattr_t */
#define HFA_GET_GRAPHATTR(graph, field)      ((graph)->info.attr).field

#define HFA_GRAPH_PENDING_INSTR_INC(p, f)       p->f += 1;
#define HFA_GRAPH_PENDING_INSTR_DEC(p, f)       p->f -= 1;

/**@cond INTERNAL */
#define HFA_FOREACHBIT_SET(_msk)          _cl=hfa_firstbit_setr[_msk];    \
    for(_i=0;_msk; HFA_BITCLR(_msk, _cl), _cl = hfa_firstbit_setr[_msk], _i++)

/*Typedefs*/

typedef enum {
    HFA_GRAPHHDR_NOBJ_OFF=4,
    HFA_GRAPHHDR_MINLEN=8
}hfa_graphhdr_off_t;
/**
 * Graph type
 */
typedef enum {
    HFA_GRAPH_MEMONLY            = 0,
    HFA_GRAPH_MIXTYPE            = 1,
    HFA_GRAPH_LINKGRAPH          = 2,
    HFA_MAX_GRAPHTYPE            = 3,
    /*DFA graph not part of state machine*/
    HFA_GRAPH_DFA                = 4
}hfa_graphtype_t;
/**
 * Graph Status
 */
typedef enum {
    HFA_GRAPH_INITIAL            = 0,
    HFA_GRAPH_CLMSK_SET          = 1,
    HFA_GRAPH_CACHE_LOADING      = 2,
    HFA_GRAPH_MEM_LOADING        = 3,
    HFA_GRAPH_MEM_SKIPLEN        = 4,
    HFA_GRAPH_INFO_READING       = 5,
    HFA_GRAPH_CLOAD_PENDING      = 6,
    HFA_GRAPHLOAD_FINISH         = 7,
    HFA_MAX_GRAPHSTATES          = 8
} hfa_graphstate_t;
/**
 * Type of graph instruction pending
 */
typedef enum {
    HFA_GRAPH_LOAD_DONE         = 0x0,
    HFA_GRAPH_MEMLOAD_PENDING   = 0x100,
    HFA_GRAPH_CACHELOAD_PENDING = 0x200,
    HFA_GRAPH_GRAPHFREE_PENDING = 0x400
} hfa_graphstatus_t;

typedef enum {
    HFA_MLOAD_COPYING =0,
    HFA_MLOAD_READY2SUBMIT =1,
    HFA_MLOAD_SUBMITTED =2
}hfa_mloadstatus_t;
/**@endcond */

/**@cond INTERNAL */
typedef uint32_t    hfa_graphflags_t;
typedef uint32_t    hfa_graphsavelen_t;
typedef ppdfa_tstamp_t  hfa_tstamp_t;
typedef ppdfa_tstampopt_t  hfa_tstampopt_t;
typedef uint64_t    hfa_count_t;

/**
 * graph object size
 */
typedef struct {
    uint64_t           off;    /* beginning offset of file */
    uint32_t           size;   /* size of the file */
} __attribute__ ((packed)) hfa_graphobj_t;
/**
 * Memnode attributes which is a part of Memlist
 */
typedef struct hfa_memnode {
    /**List*/
    hfa_os_listhead_t       list;
    /**Memory address*/
    hfa_addr_t              addr;
    /**Memory size*/
    hfa_size_t              size;
    /**Reference count to track how many clusters using it*/
    int                     node_refcnt; /*Refcnt to be signed*/
} hfa_memnode_t;
/**@endcond */
typedef struct {
    /**Pending MLOAD instruction count*/
    hfa_count_t    mload;
    /**Pending CLOAD instruction count*/
    hfa_count_t    cload;    
    /**Pending GWALK instruction count*/
    hfa_count_t    gwalk;
    /**Pending GFREE instruction count*/
    hfa_count_t    gfree;
}hfa_graph_pending_instr_t;

/**@cond INTERNAL */
/**
 * Cluster resources allocated for graph
 */
typedef struct {
    uint32_t            clno;           /*Clusterno*/
    hfa_rmdata_t        *rmdata;        /*Result buffer*/
    hfa_addr_t          mbase;          /*Memory base*/
    hfa_addr_t          cbase;         
    hfa_addr_t          dbase;        
    hfa_size_t          pgid;         
    hfa_size32_t        vgid;
    cvmx_wqe_t          *wqe;
    hfa_graph_pending_instr_t   *pending_instr; 
} hfa_graph_clbuf_t;

typedef struct {
    uint64_t    rword0;
    uint64_t    rword1;
    uint64_t    ptr;
}hfa_mload_rmdata_overload_t;
/**
 * Cluster Info for graph
 */
typedef struct {
    /**Msk indicating for which clusters, 
     * pclustinfo->mbase is allocated (not shared)*/
    hfa_clmsk_t         mbase_alloc_msk;

    /**Pointer to cluster buffers allocated for each 
     * bit in pgraph->clmsk*/
    hfa_graph_clbuf_t   *pclustbuf;
}hfa_graph_clinfo_t;

typedef struct {
    hfa_os_listhead_t       list;
    void                    *ptr;
    hfa_mloadstatus_t       status;
    hfa_size_t              copypend;
}hfa_graph_mbufptr_t;

typedef struct {
    hfa_os_listhead_t       list;
    uint64_t                nbufs;
}hfa_graph_mloadinfo_t;
/**
 * Chunk size of memory/cache/portion
 */
typedef struct {
    /*Pointer to buffer*/
    void            *ptr;

    /*BufferSize submitted to hardware*/
    hfa_size32_t    submittedsz;

    /*Total size buffer*/
    hfa_size_t      size;
}hfa_graphchunk_t;
/**
 * Graph attributes/Properties
 */
typedef struct {
    hfa_tools_version_t     version;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t    dfa:1;
    uint32_t    strings: 1;
    uint32_t    rc: 1;
    uint32_t    sc: 1;
    uint32_t    memonly: 1;
    uint32_t    linkable: 1;
    uint32_t    linked: 1;
    uint32_t    target:8;
    uint32_t    submitall: 1;
    uint32_t    cachealgo: 4;
    uint32_t    dict: 1;
    uint32_t    compmulti: 1;
    uint32_t    rcprof: 1;
    uint32_t    appprof: 2;
    uint32_t    unused: 7;
#else
    uint32_t    unused: 7;
    uint32_t    appprof: 2;
    uint32_t    rcprof: 1;
    uint32_t    compmulti: 1;
    uint32_t    dict: 1;
    uint32_t    cachealgo: 4;
    uint32_t    submitall: 1;
    uint32_t    target:8;
    uint32_t    linked: 1;
    uint32_t    linkable: 1;
    uint32_t    memonly: 1;
    uint32_t    sc: 1;
    uint32_t    rc: 1;
    uint32_t    strings: 1;
    uint32_t    dfa:1;
#endif        
}__attribute ((packed)) hfa_graphattr_t;
/**
 * Graph file info
 */
typedef struct {
    hfa_graphflags_t        flags;
    hfa_graphsavelen_t      savelen;
    hfa_graphattr_t         attr;
}hfa_graphfile_info_t;
/**@endcond */
/**
 * Graph structure
 */
typedef struct {
    /**graph list + Lock*/
    hfa_os_listhead_t           list;
    hfa_os_rwlock_t             lock;

    /**Pointer to device and Track init variable*/
    hfa_dev_t                   *pdev;
    uint32_t                    isinit;

    /**Graph File Info*/
    hfa_graphfile_info_t        info;

    /** Graph State + Status + Graph type*/
    hfa_graphstate_t            state;        
    hfa_graphtype_t             gtype;

    /*current downloaded length of graph*/
    hfa_size_t                  curr_seek;
    hfa_size_t                  totlen;

    /**Cluster Mask on which graph is allowed to load*/
    hfa_clmsk_t                 clmsk;
    /**Cluster Mask on which any {CLOAD,MLOAD,GRAPHFREE} is submitted*/
    hfa_clmsk_t                 submittedinstr_clmsk;
    /**Cluster Mask on which graph is CACHELOADED currently*/
    hfa_clmsk_t                 cload_clmsk;

    /**Number of objs and pointer buffer*/
    uint32_t                    nobj;        
    hfa_graphobj_t              *obj;

    /**Number of graphs (irt) + ppinfo*/
    uint32_t                    nirt;
    ppinfo_t                    *irt;

    /**Number of info part*/
    uint32_t                    ninfo;
    
    /**Number of graphs > 1 in case of Linked Graph*/
    uint32_t                    ngraphs;

    /**buffer chunks for info+ memory + cache*/
    hfa_graphchunk_t            *pibuf;
    hfa_graphchunk_t            mbuf;
    hfa_graphchunk_t            cbuf;

    /*Structure used for loading memory portion for 
     * devices having designated memory*/
    hfa_graph_mloadinfo_t       mload;

    /**Cluster resource info for graph*/
    hfa_graph_clinfo_t          clinfo;

    /*Trigger size to submit instruction for memload*/
    hfa_size_t                  mload_triggersz;

    /*Skiplen for tstamp*/
    uint32_t                    skiplen;
} hfa_graph_t;

/**@cond INTERNAL */
/**
 * Function pointer declaration for state machine
 */
typedef hfa_return_t 
(*hfa_memload_event_hndlr)(hfa_graph_t *, uint8_t * pdata, 
        hfa_size_t currlen, hfa_size_t *consumedlen);

/**State machine decalaration*/
typedef struct {
    hfa_memload_event_hndlr     hndlr;
    hfa_graphstate_t            next_state;    
}hfa_graphload_sm_tbl_t;

/**Function declarations*/
hfa_return_t hfa_dev_graph_init(hfa_dev_t *, hfa_graph_t*);

hfa_return_t hfa_dev_graph_cleanup(hfa_dev_t *, hfa_graph_t*);

hfa_return_t hfa_graph_setcluster(hfa_graph_t*, uint32_t cluster_mask);

hfa_return_t 
hfa_graph_memload_data(hfa_graph_t*, uint8_t * data, hfa_size_t datalen);

hfa_return_t 
hfa_graph_memload_data_async(hfa_graph_t*, uint8_t * data, hfa_size_t datalen);

hfa_return_t hfa_graph_cacheload(hfa_graph_t*);

hfa_return_t hfa_graph_cacheload_async(hfa_graph_t*);

hfa_return_t hfa_graph_cacheunload(hfa_graph_t*);

hfa_return_t hfa_graph_cacheunload_async(hfa_graph_t*);

hfa_return_t hfa_graph_getstatus(hfa_graph_t*, uint32_t *status);

hfa_return_t
hfa_graph_setmemloadtrigger (hfa_graph_t *, hfa_size_t );

hfa_return_t hfa_graph_getsavelen (hfa_graph_t *pgraph, int *len);

hfa_return_t
hfa_graph_setwqe(hfa_graph_t *, int, cvmx_wqe_t *);

hfa_return_t
hfa_graph_processwork(cvmx_wqe_t *, hfa_graph_t **);

hfa_return_t 
hfa_graph_getgraph_count(hfa_graph_t *, uint32_t *);

hfa_return_t
hfa_graph_getsubgraph(hfa_graph_t *,hfa_graph_t *,uint32_t);

hfa_bool_t
hfa_graph_is_instr_pending(hfa_graph_t *, int, hfa_graph_pending_instr_t **);
/**@endcond */

#endif

