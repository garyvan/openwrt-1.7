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
 *  @file
 *  Header file for all common utility applications
 */
#ifndef _HFA_APPS_UTILS_H_
#define _HFA_APPS_UTILS_H_
#include <cvm-hfa-common.h>
#include <cvm-hfa.h>
#include <cvm-hfa-graph.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa-stats.h>
#include <gzguts.h>
#include <hfa-zlib.h>
#ifdef KERNEL
#include <asm/octeon/cvmx-fau.h>
#include <asm/octeon/cvmx-pip.h>
#include <asm/octeon/cvmx-pow.h>
#include <asm/octeon/octeon.h>
#include <linux/fs_struct.h>
#else
#ifndef HFA_SIM
#include <cvmx-fau.h>
#include <cvmx-pip.h>
#endif
#endif

/*Must be 8 byte aligned. Max value == 64*/
#define HFA_NBITS               64 
#undef  APP_DEBUG

#ifdef KERNEL

#ifdef APP_DEBUG
#define DBG(_x, ...)    {                                \
                    printk("(%s): ", __func__);          \
                    printk (_x, ## __VA_ARGS__);         \
                        }
#else
#define DBG(...)                        
#endif                                                
#define LOG(_x, ...)    {                                     \
                    printk("[C%d]: ", cvmx_get_core_num());   \
                    printk (_x, ## __VA_ARGS__);              \
                        }
#define ERR(_x, ...)    {                                           \
                    printk("[C%d] (%s, %d): ",                      \
                        cvmx_get_core_num(), __func__, __LINE__);   \
                    printk ("error: " _x, ## __VA_ARGS__);          \
                        }
#define hfautils_lock_t                spinlock_t
#define hfautils_lockinit(_x)          spin_lock_init (_x)
#define hfautils_lock(_x)              spin_lock_bh (_x)
#define hfautils_unlock(_x)            spin_unlock_bh (_x)
#define hfautils_trylock(_x)           ({                                \
                                            int r;                       \
                                            r = spin_trylock_bh(_x);     \
                                            r;                           \
                                        })
#define MAX_CORES                      32

#define hfautils_vmmemoryalloc(size, ctx)  ({              \
                            void *p = NULL;                \
                            p = vmalloc(size);             \
                            if(p && hfa_stats) {           \
                            hfa_core_mem_stats_inc(sysmem,size);\
                            if(ctx)                        \
                            hfa_searchctx_mem_stats_inc((ctx),sysmem,size);\
                            }                              \
                            p;                             \
                        })
#define hfautils_vmmemoryfree(ptr, size, ctx)  ({          \
                            vfree(ptr);                    \
                            if(hfa_stats) {                \
                            hfa_core_mem_stats_dec(sysmem,size);\
                            if(ctx)                        \
                            hfa_searchctx_mem_stats_dec((ctx),sysmem,size);\
                            }                              \
                        }) 
                            
#define hfautils_memoryalloc(size, align, ctx)  ({         \
                            void *p = NULL;                \
                            p = kmalloc(size, GFP_KERNEL); \
                            if(p && hfa_stats) {           \
                            hfa_core_mem_stats_inc(sysmem,size);\
                            if(ctx)                        \
                            hfa_searchctx_mem_stats_inc((ctx),sysmem,size);\
                            }                              \
                            p;                              \
                        })
#define hfautils_memoryfree(ptr, size, ctx)  ({            \
                            kfree(ptr);                    \
                            if(hfa_stats) {                \
                            hfa_core_mem_stats_dec(sysmem,size);\
                            if(ctx)                        \
                            hfa_searchctx_mem_stats_dec((ctx),sysmem,size);\
                            }                              \
                        }) 
#else /* Start of #ifndef KERNEL */
#ifdef APP_DEBUG                        
#define DBG(_x, ...)    {                                \
                    printf("(%s): ", __func__);   \
                    printf (_x, ## __VA_ARGS__);      \
                        }
#else
#define DBG(...)                        
#endif                                                

#define LOG(_x, ...)    {                                \
                    printf("[C%d]: ", cvmx_get_core_num());   \
                    printf (_x, ## __VA_ARGS__);      \
                        }
#define ERR(_x, ...)    {                                \
                    printf("[C%d] (%s): ", cvmx_get_core_num(), __func__);   \
                    printf ("error: " _x, ## __VA_ARGS__);      \
                        }

#define hfautils_lock_t                 cvmx_spinlock_t
#define hfautils_lockinit(_x)           cvmx_spinlock_init (_x)
#define hfautils_lock(_x)               cvmx_spinlock_lock (_x)
#define hfautils_unlock(_x)             cvmx_spinlock_unlock (_x)
#define hfautils_trylock(_x)            cvmx_spinlock_trylock(_x)
#define hfautils_memoryalloc(size, align, ctx)               \
                    ({                                       \
                        void *p = NULL;                      \
                        p = hfa_bootmem_alloc(size, align);  \
                        DBG("ALLOC:ptr = %p size = %u\n", p, size); \
                        if(p && hfa_stats) {                 \
                        hfa_core_mem_stats_inc(bootmem,size); \
                        if(ctx)                              \
                        hfa_searchctx_mem_stats_inc((ctx),bootmem,size);\
                        }                                    \
                        p;                                   \
                    })
#define hfautils_memoryfree(ptr, size, ctx)                  \
                    ({                                       \
                        hfa_bootmem_free(ptr, size);         \
                        DBG("FREE:ptr = %p size = %u\n", ptr, size); \
                        if(hfa_stats) {                      \
                        hfa_core_mem_stats_dec(bootmem,size);\
                        if(ctx)                              \
                        hfa_searchctx_mem_stats_dec((ctx),bootmem,size);\
                        }                                    \
                    })  
#endif /* Endof #define KERNEL */

#define GRAPHCHUNK                      65535
#define MAXRBUFSIZE                     65535*8
#define MAXIOVECS                       1000
#define BLK_SIZE                        2048
#define MAXSAVELEN                      1024
#define MAX_NAME_LENGTH                 50
#define HFA_PKTDATA_WQE_GRP             15

#define HFAUTILS_FAU_INCBY(t, f,n)      cvmx_fau_atomic_add64(t.f,n)
#define HFAUTILS_FAU_INC(t, f)          cvmx_fau_atomic_add64(t.f,1ULL)
#define HFAUTILS_FAU_DEC(t, f)          cvmx_fau_atomic_add64(t.f, -1)
#define HFAUTILS_FAU_WR(t, f, val)      cvmx_fau_atomic_write64(t.f, val)
#define HFAUTILS_FAU_FETCH(r, v)        cvmx_fau_fetch_and_add64(r, v)

#ifndef hfautils_lockdestroy
#define hfautils_lockdestroy(_x)
#endif
#define hfautils_rwlock_t               cvmx_rwlock_wp_lock_t
#define hfautils_rwlockinit(_x)         cvmx_rwlock_wp_init (_x)
#ifndef hfautils_rwlockdestroy
#define hfautils_rwlockdestroy(_x)
#endif
#define hfautils_rlock(_x)              cvmx_rwlock_wp_read_lock (_x)
#define hfautils_runlock(_x)            cvmx_rwlock_wp_read_unlock (_x)
#define hfautils_wlock(_x)              cvmx_rwlock_wp_write_lock (_x)
#define hfautils_wunlock(_x)            cvmx_rwlock_wp_write_unlock (_x)

#define hfautils_likely(_x)             cvmx_likely (_x)
#define hfautils_unlikely(_x)           cvmx_unlikely (_x)

#define HFAUTIS_LISTHEAD_INIT(_l)       do {                                  \
                                            (_l)->next = (_l);                \
                                            (_l)->prev = (_l);                \
                                        } while (0)

#define hfautils_listforeachsafe(_p, _n, _h)                                  \
               for (_p = (_h)->next, _n = _p->next;                           \
                  _p != (_h); _p = _n, _n = _p->next)

#define hfautils_listentry(_p, _t, _m)                                        \
               ((_t *) ((char *) (_p)-(unsigned long)                         \
                (&((_t *) 0)->_m)))
/**Linked list data structure*/               
typedef struct _hfautils_listhead_t  {
        hfautils_lock_t    lock;
        struct _hfautils_listhead_t *next, *prev;
} hfautils_listhead_t;

typedef void (*hfautils_printcb_t)(void);

/** Performance statistics */
typedef struct {
    /**total ingress packets*/
    cvmx_fau_reg_64_t   in;
    /**total egress packets*/
    cvmx_fau_reg_64_t   out;
    /**total pending instructions in HW*/
    cvmx_fau_reg_64_t   pend_wqe;
    /**total dropped packets*/
    cvmx_fau_reg_64_t   dropped;
    /**Added success packets*/
    cvmx_fau_reg_64_t   adsuccess;
    /**submitted success packets*/
    cvmx_fau_reg_64_t   sdsuccess;
    /**processed success packets*/
    cvmx_fau_reg_64_t   pdsuccess;
    /**added failed packets*/
    cvmx_fau_reg_64_t   adfail;
    /**submitted failed packets*/
    cvmx_fau_reg_64_t   sdfail;
    /**processed failed packets*/
    cvmx_fau_reg_64_t   pdfail;
    /**Retry in addition*/
    cvmx_fau_reg_64_t   adretry;
    /**submit retry*/
    cvmx_fau_reg_64_t   sdretry;
    /**processed retry*/
    cvmx_fau_reg_64_t   pdretry;
    /**Total no. of matches*/
    cvmx_fau_reg_64_t   nmatches;
    /**Total no. of input packet bytes*/
    cvmx_fau_reg_64_t   tot_bytes;
}hfautils_fau_perfcntrs_t;
/** Bit map data structure */
typedef struct {
    uint64_t            *bitmap;
    uint32_t            bits_prow; 
    uint32_t            nrows;
    uint32_t            totalbits;
    hfautils_rwlock_t   lock;
}hfautils_bitmap_t;
/** Recently cache used data structure*/
typedef struct {
    uint32_t            count;
    uint32_t            nonzerocnt;
    uint64_t            *ptrs;  
}hfautils_rcu_t;
/** Attributes needed for parsing payload */
typedef struct {
#ifdef KERNEL
    mm_segment_t            old_fs;
    char                    *path;
#endif
    gzFile                  gzf;                   
    struct pcap_file_header *phdr;
    uint8_t                 *payload;
    uint32_t                psize;
    int                     npkts;
    uint32_t                remain;
    uint64_t                nchunks;
}hfautils_payload_attr_t;
#ifdef KERNEL
/** Attributes needed for parsing payload for tasklets */
typedef struct task_attr {
    void           *data;
    unsigned long  size;
}task_attr_t;
typedef struct {
    hfa_coremask_t  tasks_coremask;
    hfa_coremask_t  threads_coremask;
    hfa_size_t      tasks_mask;
    hfa_size_t      threads_mask;
    int             task_cores;
    int             thread_cores;
}coremask_attr_t;
#endif
/** Attributes needed for creating local packets */
typedef struct {
    hfautils_payload_attr_t *pattr;
    uint8_t                 unused8;
    uint32_t                npkts;
    cvmx_pow_tag_type_t     tt;
    uint32_t                tag;
    uint64_t                qos;
    uint64_t                grp;
}pktwqe_attr_t;

/** Structure of command line arguments*/
typedef struct {
    int             verbose;
    /**Name of graph */
#ifndef KERNEL
    char            graph[MAX_NAME_LENGTH];
#else
    char            *graph;
#endif
    /**Name of payload */
#ifndef KERNEL
    char            payload[MAX_NAME_LENGTH];
#else
    char            *payload;
#endif
    /** Graph size*/
    hfa_size_t      graphsize;

    /* Payload size*/
    hfa_size_t      payloadsize;

    /**Chunk size*/
    hfa_size_t      chunksize;

    /**Cluster no on which search will happen*/
    int             cluster;

    /*clusters are used randomly for search*/
    uint32_t        israndom;

    /**Clusters on which graph to be loaded*/
    uint32_t        graph_clmsk;
    
    /**Number of search context*/
    uint64_t        nsearchctx;

    /**Number of searches per ctx**/
    uint64_t        nsearch;

    /**Number of packet flows*/
    uint64_t        nflows;

    /**Number of pkts*/
    uint64_t        npkts;

    /**Continue search on all possible clusters*/
    uint32_t        searchall;

    /**Search flags*/
    int             pfflags;

    /**If payload file is pcap*/
    int             pcap;

    /**If payload coming from network*/
    int             networkpayload;

#ifndef KERNEL
    /**Name of file system named block */
    char            fs[MAX_NAME_LENGTH];
#endif    
    /**Number of graphs */
    int             ngraphs;

} options_t;
/** Port configuration */
typedef struct {
    int          istagtypeset;
    uint8_t      isgrpset;
    uint64_t     wqegrp;
    uint8_t      grptag;
    uint8_t      tagmask_lsb;   
    uint8_t      tagmask_msb;   
    uint8_t      tag_type;
}hfa_prt_cfg_t;    

static inline void
__hfautils_listadd (hfautils_listhead_t *n, hfautils_listhead_t *prev, 
                  hfautils_listhead_t *next)
{
    next->prev = n;
    n->next = next;
    n->prev = prev;
    prev->next = n;
}

static inline void
hfautils_listadd (hfautils_listhead_t *n, hfautils_listhead_t *head)
{
    __hfautils_listadd (n, head, head->next);
}

static inline void
hfautils_listaddtail (hfautils_listhead_t *n, hfautils_listhead_t *head)
{
    __hfautils_listadd (n, head->prev, head);
}

static inline void
__hfautils_listdel (hfautils_listhead_t *prev, hfautils_listhead_t *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void
hfautils_listdel (hfautils_listhead_t *n)
{
    __hfautils_listdel (n->prev, n->next);
}

static inline int
hfautils_listempty (hfautils_listhead_t *h)
{
    return h->next == h;
}
/**
 * Return number of processing cores.
 *
 * @return  number of cores
 */
static inline 
int hfautils_get_number_of_cores(void) 
{
    hfa_coremask_t  *coremask;

    coremask = &cvmx_sysinfo_get()->core_mask;
    return cvmx_coremask_get_core_count(coremask);
}
/* no wqe support in simulator */
#ifndef HFA_SIM
/**
 * Return total pending WQE's in SSO.
 *
 * @return  total pending WQE's in SSO
 */
static inline uint64_t 
hfautils_read_iqcomcnt(void)
{
    if (octeon_has_feature(OCTEON_FEATURE_CN68XX_WQE))
        return cvmx_read_csr (CVMX_SSO_IQ_COM_CNT);
    else
        return cvmx_read_csr (CVMX_POW_IQ_COM_CNT);
}
/**
 * Return number of descheduled WQE's in SSO.
 *
 * @return  number of descheduled WQE's in SSO
 */
static inline uint64_t 
hfautils_read_dsdc(void)
{
    if (octeon_has_feature(OCTEON_FEATURE_CN68XX_WQE))
        return cvmx_read_csr (CVMX_SSO_DS_PC);
    else
        return cvmx_read_csr (CVMX_POW_DS_PC);
}
static inline 
void hfautils_write_dsdc(uint64_t val)
{
    if (octeon_has_feature(OCTEON_FEATURE_CN68XX_WQE))
        cvmx_write_csr (CVMX_SSO_DS_PC, 0x1ULL);
    else
        cvmx_write_csr (CVMX_POW_DS_PC, 0x1ULL);
}
/**
 * Return group mask of a core.
 *
 * @param   core_num        core number
 *
 * @return  group mask of given core
 */
static inline uint64_t 
hfautils_get_core_grpmsk(uint64_t core_num)
{
    if (octeon_has_feature(OCTEON_FEATURE_CN68XX_WQE)) {
        cvmx_sso_ppx_grp_msk_t grp_msk;
        grp_msk.u64 = cvmx_read_csr(CVMX_SSO_PPX_GRP_MSK(core_num));
        return(grp_msk.s.grp_msk);
    }  else     {
        cvmx_pow_pp_grp_mskx_t grp_msk;
        grp_msk.u64 = cvmx_read_csr(CVMX_SSO_PPX_GRP_MSK(core_num));
        return(grp_msk.s.grp_msk);
    }
}
/**
 * Prints group mask of all processing cores 
 */
static inline void
hfautils_show_grpmask(void)
{
    int cnt;
    int ncores = hfautils_get_number_of_cores();
    printf("CORE GROUP MASK\n");
    for(cnt=0; cnt < ncores; cnt++){
        printf("[%d]: 0x%lx", cnt, 
               (unsigned long int)hfautils_get_core_grpmsk(cnt));
        
        if((cnt) && (cnt %2)){
            printf("\n");
        } else {
            printf("  ");
        }
    }
}
/**
 * Prints performance statistics.
 *
 * @param   p               pointer to structure of statistics 
 * @param   start_port      start port
 * @param   nports          number of ports
 * @param   verbose         verbose option to print more statistics
 *
 */
static inline uint64_t
__hfautils_printstats(hfautils_fau_perfcntrs_t *p, int start_port,
                     int nports, int verbose)
{
    int                         i;
    static uint64_t             prev = 0;
    uint64_t                    hz= cvmx_sysinfo_get()->cpu_clock_hz;
#if defined(KERNEL) || defined(__linux__)
    uint64_t                    bits, time, perf;
#else        
    double                      bits, time, perf;
#endif    
    cvmx_pip_port_status_t      pip_reg;

#if defined(KERNEL) || defined(__linux__)
    time =  cvmx_get_cycle () - prev;
    prev = cvmx_get_cycle ();
    time /= hz;
    bits =  HFAUTILS_FAU_FETCH (p->tot_bytes, 0ULL);
#else
    time = (double) cvmx_get_cycle () - (double) prev;
    prev = cvmx_get_cycle ();
    time /= hz;
    bits = (double) HFAUTILS_FAU_FETCH (p->tot_bytes, 0ULL);
#endif                  
    HFAUTILS_FAU_WR ((*p), tot_bytes, 0ULL);
    bits *= 8;
    perf = bits / 1000000/ time;
    hfa_log("\n");

#if defined(KERNEL) || defined(__linux__)
    hfa_log("\n\n%lu Mbps (%lu matches/sec)\n", (unsigned long)perf,
        (unsigned long)(HFAUTILS_FAU_FETCH(p->nmatches, 0ULL)/time));
#else     
    hfa_log("\n\n%.2f Mbps (%.2f matches/sec)\n", perf,
            (double) HFAUTILS_FAU_FETCH(p->nmatches, 0ULL));
#endif
    hfa_log ("\t%15s: %lu\n", "matches found",
            (unsigned long) HFAUTILS_FAU_FETCH(p->nmatches, 0ULL));
    HFAUTILS_FAU_WR((*p), nmatches, 0ULL);
    if (verbose) {
        for(i=start_port; i < nports; i++){
            cvmx_pip_get_port_status(i, 1, &pip_reg);
            hfa_log("%s %d %s: [%s: %d], [%s: %d]\n",
                "Port", i, "stats", 
                "in", pip_reg.packets,
                "dropped", pip_reg.dropped_packets);
        }
        hfa_log ("%s: %lu, %s: %lu, %s: %lu)\n", "In",
            (unsigned long) HFAUTILS_FAU_FETCH(p->in, 0ULL), "Out",
            (unsigned long) HFAUTILS_FAU_FETCH(p->out, 0ULL),"Drop",
            (unsigned long) HFAUTILS_FAU_FETCH(p->dropped, 0ULL));
        HFAUTILS_FAU_WR ((*p), in, 0ULL);
        HFAUTILS_FAU_WR ((*p), out, 0ULL);
        HFAUTILS_FAU_WR ((*p), dropped, 0ULL);
       
        hfa_log ("%s: (%lu, %lu, %lu)\n", "Add (Succ, Fail, Retry)",
               (unsigned long) HFAUTILS_FAU_FETCH(p->adsuccess, 0ULL),
               (unsigned long) HFAUTILS_FAU_FETCH(p->adfail, 0ULL),
               (unsigned long) HFAUTILS_FAU_FETCH(p->adretry, 0ULL));
        HFAUTILS_FAU_WR ((*p), adsuccess, 0ULL);
        HFAUTILS_FAU_WR ((*p), adfail, 0ULL);
        HFAUTILS_FAU_WR ((*p), adretry, 0ULL);

        hfa_log ("%s: (%lu, %lu, %lu)\n", 
                "Submit(Succ, Fail, Retry)",
               (unsigned long) HFAUTILS_FAU_FETCH(p->sdsuccess, 0ULL),
               (unsigned long) HFAUTILS_FAU_FETCH(p->sdfail, 0ULL),
               (unsigned long) HFAUTILS_FAU_FETCH(p->sdretry, 0ULL));
        HFAUTILS_FAU_WR ((*p), sdsuccess, 0ULL);
        HFAUTILS_FAU_WR ((*p), sdfail, 0ULL);
        HFAUTILS_FAU_WR ((*p), sdretry, 0ULL);

        hfa_log ("%s: (%lu, %lu %lu)\n", 
                "Processed (Succ, Fail, Retry)",
               (unsigned long) HFAUTILS_FAU_FETCH(p->pdsuccess, 0ULL),
               (unsigned long) HFAUTILS_FAU_FETCH(p->pdfail, 0ULL),
               (unsigned long) HFAUTILS_FAU_FETCH(p->pdretry, 0ULL));
        HFAUTILS_FAU_WR ((*p), pdsuccess, 0ULL);
        HFAUTILS_FAU_WR ((*p), pdfail, 0ULL);
        HFAUTILS_FAU_WR ((*p), pdretry, 0ULL);
        hfa_log ("%s:\n%lu, %lu, %lu, %lu, %lu, %lu, "
                    "%lu %lu\n", "pools",
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (0)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (1)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (2)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (3)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (4)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (5)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (6)),
        (unsigned long)cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (7)));
        hfa_log ("%s: %lu %s: %lu\n", "SSO/POW IQ count",
                (unsigned long)hfautils_read_iqcomcnt(),
                "SSO/POW Desched",
                (unsigned long) hfautils_read_dsdc());
        hfautils_write_dsdc (0x1ULL);
    }
    return (prev);
}
#endif
/**
 * This routine is used to check if HFA_SEARCHCTX_FSAVEBUF is set in flags 
 * returned by post-processor. 
 *
 * @param   psparam     Pointer to search parameter
 * @param   fsbuf       If application supports FSAVEBUF it should send 
 *                      fsbuf as HFA_TRUE otherwise HFA_FALSE
 *
 * @return HFA_TRUE if FSAVEBUF sets in ppoflags, HFA_FALSE otherwise.
 */
static inline hfa_bool_t 
hfautils_is_fsavebuf_set (hfa_searchparams_t *psparam, hfa_bool_t fsbuf) 
{
    hfa_ppoflags_t          ppoflags = 0;
    
    hfa_searchparam_get_ppoflags (psparam, &ppoflags);
    if(HFA_ISBITMSKSET(ppoflags, HFA_PP_OFLAGS_FSAVEBUF)) {
        if(fsbuf)  {
            return HFA_TRUE;
        }
        else {
            LOG("WARNING: This application doesn't support FSAVEBUF "
                "(but it is set in ppoflags)\n. The application might " 
                "not find all the matches in the payload\n");
        }
    }
    return HFA_FALSE;
}
/**
 * Initialize recently cache used data structure.
 *
 * @param   pcache     pointer to cache 
 * @param   count      Cache entrys
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_rcu_init(hfautils_rcu_t *pcache, uint32_t count)
{
    if(pcache && count){
        memset(pcache, 0, sizeof(hfautils_rcu_t));
        pcache->ptrs = hfa_bootmem_alloc((count * sizeof(*pcache->ptrs)), 8);
        if(pcache->ptrs){
            pcache->count = count;
            memset(pcache->ptrs, 0, (sizeof(*pcache->ptrs) * count));
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/**
 * Cleanup recently cache used data structure.
 *
 * @param   pcache     pointer to cache
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_rcu_cleanup(hfautils_rcu_t *pcache)
{
    if(pcache){
        if(pcache->ptrs){
            hfa_bootmem_free(pcache->ptrs, (pcache->count * sizeof(*pcache->ptrs)));
            pcache->ptrs = NULL;
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/**
 * If cache entry is empty(i.e NULL) fill that entry with data.
 * Otherwise do nothing.
 *
 * @param   pcache     pointer to cache
 * @param   data       pointer to data to be fill in cache
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 * */
static inline hfa_return_t
hfautils_rcu_setatnull (hfautils_rcu_t *pcache, void *data)
{
    uint32_t        cnt;
    int             nullidx = -1;

    if(hfa_os_likely(pcache && data)){
        if(pcache->nonzerocnt >= pcache->count){
            return HFA_SUCCESS;
        }
        /*First check whether the flow is already present*/
        for(cnt=0; cnt < pcache->count; cnt++){

            /*Found first NUll value while looping*/
            if((0 == ((pcache->ptrs)[cnt])) && (nullidx < 0)){
                nullidx = cnt;
            }

            if((uint64_t)data == (uint64_t)((pcache->ptrs)[cnt])){
                return HFA_SUCCESS;
            }
        }
        /*Code reaches here if data is absent in cache
         * If there is any null idx present, add to it*/
        if(nullidx >=0){
            ((pcache->ptrs)[nullidx]) = (uint64_t)data;
            (pcache->nonzerocnt)++;
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/**Initialize index entry with data.
 *
 * @param   pcache      pointer to cache
 * @param   data        pointer to data to be fill
 * @param   idx         index at which data will be fill 
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 * */
static inline hfa_return_t
hfautils_rcu_set (hfautils_rcu_t *pcache, void *data, uint32_t idx)
{
    if(pcache && (idx < pcache->count)){
        if(data){
            (pcache->nonzerocnt)++;
        } else {
            if(pcache->nonzerocnt){
                (pcache->nonzerocnt)--;
            }
        }
        ((pcache->ptrs)[idx]) = (uint64_t)data;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Found entry in cache and if found remove it.
 *
 * @param   pcache      poniter to cache
 * @param   data        pointer to data to be remove
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 * */
static inline hfa_return_t
hfautils_rcu_removeentry (hfautils_rcu_t *pcache, void *data)
{
    int cnt;

    if(pcache && data){
        for(cnt=0; cnt < pcache->count; cnt++){
            if((uint64_t)data == (pcache->ptrs)[cnt]){
                (pcache->nonzerocnt)--;
                ((pcache->ptrs)[cnt]) = 0;
            }
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Return data at given index in the cache.
 *
 * @param   pcache      pointer to cache 
 * @param   idx         get data at this index 
 * @param   ppdata      pointer to data 
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_rcu_get(hfautils_rcu_t *pcache, uint32_t idx, uint64_t **ppdata)
{
    if(hfa_os_likely(pcache && ppdata && (idx < pcache->count))){
        *ppdata = (uint64_t *)((pcache->ptrs)[idx]);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/*
 * Find first bit set in word from right.
 *
 * @param   uint64_t    word
 */
static inline uint64_t
hfautils_ffb(uint64_t word)
{
	int num = 0;
#if 1 
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}
/**
 * Initialize bit map.
 *
 * @param   ptr        pointer to bit map structure
 * @param   totalbits  total bits in bitmap
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_bitmap_init(hfautils_bitmap_t *ptr, uint32_t totalbits)
{
    uint32_t    nrows, sz;

    if(ptr && totalbits){
        memset(ptr, 0, sizeof(hfautils_bitmap_t));
        nrows = (totalbits)/HFA_NBITS;
        /*If zero or floating point remainder*/
        if(!nrows || (totalbits != (nrows * HFA_NBITS))){
            nrows +=1;
        }
        sz = (HFA_NBITS * nrows)/8;
        DBG("Bitmap: Inputbits: %u, nrows: %u,sz: %u\n", totalbits,nrows,sz);
        ptr->bitmap = hfa_bootmem_alloc(sz, 64);
        if(ptr->bitmap){
            memset(ptr->bitmap, 0, sz);
            ptr->nrows = nrows;
            ptr->bits_prow = HFA_NBITS;
            ptr->totalbits = totalbits;
            hfautils_rwlockinit(&ptr->lock);
            return HFA_SUCCESS;
        } else {
            ERR("bootmem_alloc failed\n");
        }
    }
    return HFA_FAILURE;
}
/**
 * Clear bit map.
 *
 * @param   p         pointer to bit map structure
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_bitmap_cleanup(hfautils_bitmap_t *p)
{
    uint32_t    sz=0;
    if(p){
        if(p->bitmap){
            sz = (p->nrows * p->bits_prow)/8;
            hfa_bootmem_free(p->bitmap, sz);
            p->bitmap= NULL;
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/** 
 * Print bit map.
 *
 * @param   ptr        Pointer to bit map structure
 * @param   s          String to be printed 
 *
 */
static inline void
hfautils_showbitmap(hfautils_bitmap_t *ptr, char *s)
{
    uint32_t cnt=0;
    uint64_t l;
    printf("===============================================\n");
    printf("%s\n", s);
    for(;cnt < ptr->nrows; cnt++){
        l = (ptr->bitmap)[cnt];
        printf("[%u: 0x%lx]", cnt, (long unsigned int)l);
        if((cnt) && !(cnt %2)){
            printf("\n");
        }
    }
    printf("\n===============================================\n");
}
/**
 * Return set bit in bitmap index range [sidx: lidx].
 *
 * @param   p         pointer to bit map structure
 * @param   sidx      starting index in bitmap
 * @param   lidx      last index in bitmap
 * @param   pbit      *pbit contains value at which bit is set
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_getselective_bitset(hfautils_bitmap_t *p, uint32_t sidx, 
                             uint32_t lidx, long int *pbit)
{
    uint32_t    idx, cnt;
    uint64_t    u64;

    *pbit = -1;
    idx = (p->bits_prow) * sidx;
    if(sidx > (p->nrows -1)){
        return HFA_FAILURE;
    }
    if(lidx > (p->nrows -1)){
        lidx = (p->nrows -1);
    }

    for(cnt=sidx; cnt <= lidx; cnt++, idx += p->bits_prow){
        u64 = (p->bitmap)[cnt];
        if(u64){
            *pbit = (idx + hfautils_ffb(u64));
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/** 
 * Return First set bit in the given bit map.
 *
 * @param   p        pointer to bit map structure
 * @param   pbit     *pbit contains value at which bit is set
 *
 * @return  HFA_FAILURE/HFA_SUCCESS 
 */
static inline hfa_return_t
hfautils_getfirstbitset(hfautils_bitmap_t *p, long int *pbit)
{
    uint32_t    idx, cnt;
    uint64_t    u64;

    *pbit = -1; 
    for(cnt=0, idx=0; cnt < p->nrows; cnt++, idx += p->bits_prow){
        u64 = (p->bitmap)[cnt];
        if(u64){
            *pbit = (idx + hfautils_ffb(u64));
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/**
 * Return bit for given bit number in the given bit map.
 *
 * @param   p        pointer to bit map structure
 * @param   bitno    bit number  
 * @param   b        *b contains bit at bitno 
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_getbit(hfautils_bitmap_t *p, uint64_t bitno, int *b)
{
    uint32_t    tidx;
    uint64_t    *pidx = NULL, rem=0;

    if(bitno > (p->totalbits)){
        ERR("bitno: %lu > total: %u\n",(long unsigned int) bitno, p->totalbits);
        return HFA_FAILURE;
    }
    tidx = bitno/p->bits_prow;
    rem = bitno - (tidx * p->bits_prow);
    pidx = &(p->bitmap[tidx]);
    *b = HFA_ISBITSET ((*pidx), rem);
    return HFA_SUCCESS;
}
/**
 * Set bit with bit number in the given bit map.
 *
 * @param   p        pointer to bit map structure
 * @param   bitno    bit number to be set
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_setbit(hfautils_bitmap_t *p,  uint64_t bitno)
{
    uint32_t    tidx;
    uint64_t    *pidx = NULL, rem=0;

    if(bitno > (p->totalbits)){
        ERR("bitno: %lu > total: %u\n",(long unsigned int)bitno, p->totalbits);
        return HFA_FAILURE;
    }
    tidx = bitno/p->bits_prow;
    rem = bitno - (tidx * p->bits_prow);
    pidx = &(p->bitmap[tidx]);
    HFA_BITSET ((*pidx), rem);
    return HFA_SUCCESS;
}
/**
 * Clear bit with bit number in the given bit map.
 *
 * @param   p        pointer to bit map structure
 * @param   bitno    bit number to be clear
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_clearbit(hfautils_bitmap_t *p,  uint64_t bitno)
{
    uint32_t    tidx;
    uint64_t    *pidx = NULL, rem=0;

    if(bitno > (p->totalbits)){
        ERR("bitno: %lu > total: %u\n",(long unsigned int)bitno, p->totalbits);
        return HFA_FAILURE;
    }
    tidx = bitno/p->bits_prow;
    rem = bitno - (tidx * p->bits_prow);
    pidx = &(p->bitmap[tidx]);
    HFA_BITCLR ((*pidx), rem);
    return HFA_SUCCESS;
}

/*Function Declarations*/
#ifdef KERNEL
hfa_return_t 
hfautils_file_size(char *filename, hfa_size_t *psize);
hfa_return_t
hfautils_read_file(char *filename, void **, hfa_size_t , hfa_size_t *, int);
hfa_return_t
hfautils_read_payload(char *filename, void **, hfa_size_t *, task_attr_t *);
hfa_return_t 
hfautils_validate_chunksize(uint32_t *, uint32_t hfa_size_t);
hfa_return_t 
hfautils_launch_thread_and_tasklet(int (*thread_callback)(void *),
          void (*tasklet_callback)(unsigned long),coremask_attr_t *, char *);
void hfautils_kill_tasklets(coremask_attr_t *);
hfa_return_t 
hfautils_validate_threads_and_tasklets_coremask(coremask_attr_t *);

#else /*Endof #ifdef KERNEL, Start of #ifndef KERNEL*/

hfa_return_t 
hfautils_file_size(char *filename, hfa_size_t *pbufsize);
hfa_return_t
hfautils_read_file(char *, void **, hfa_size_t);
hfa_return_t 
hfautils_parse_arguments(int argc, char **argv, options_t *);
void hfautils_register_signalhandler(void);
void hfautils_reset_octeon(void);
char *hfautils_strnstr(const char *, const char *, uint64_t);
#endif /*End of #ifdef KERNEL*/

hfa_return_t 
hfautils_read_nb(char *namedblock, void **ppbuf);
hfa_return_t
hfautils_getnb_size (char *namedblock, hfa_size_t *psize);
hfa_return_t
hfautils_download_graph (hfa_graph_t *pgraph, void *gbuf, hfa_size_t gsize,
                         int chunk, hfa_bool_t isasync);
hfa_return_t 
hfautils_print_matches(hfa_searchctx_t *, uint64_t *, hfa_size_t *,int, int);
hfa_return_t
hfautils_initinterfaces (hfa_prt_cfg_t *);
hfa_return_t
hfautils_initialize_wqepool (uint64_t, uint64_t );
/*no print stats support in simulator */
#ifndef HFA_SIM
void
hfautils_printstats (hfautils_fau_perfcntrs_t *p, int start_port,
                     int nports, int verbose, hfautils_printcb_t);
void hfautils_print_fpapools_stats (void);
#endif
hfa_return_t
hfautils_init_perf_cntrs(hfautils_fau_perfcntrs_t *pstats);
hfa_return_t
hfautils_create_localpkts (pktwqe_attr_t *, options_t *);
void hfautils_send_pkt(cvmx_wqe_t *wqe);
hfa_return_t
hfautils_options_init (options_t *poptions);
void 
hfautils_matchcb(int, int, int, int, void *);
hfa_return_t
hfautils_init_payload_attributes(hfautils_payload_attr_t *, options_t *);
hfa_return_t
hfautils_parse_payload(hfautils_payload_attr_t *, options_t *);
void 
hfautils_cleanup_payload_attributes(hfautils_payload_attr_t *, options_t *);
hfa_size_t fd_read (gzFile, void *, hfa_size_t); 
#endif
