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
 * This file contains all os dependent APIs/macros. Includes header files 
 * from OCTEON-SDK/executive and standard gcc  header files
 *
 */
#ifndef _CVM_HFA_OSAPI_H_
#define _CVM_HFA_OSAPI_H_

#undef HFA_DEBUG
#define GLOBAL
#ifdef KERNEL
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#ifdef HFA_INCLUDE
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/version.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/div64.h>
#endif
#include <asm/octeon/cvmx.h>
#ifndef CVMX_DONT_INCLUDE_CONFIG
#include <asm/octeon/cvmx-config.h>
#endif
#include <asm/octeon/cvmx-bootmem.h>
#include <asm/octeon/cvmx-asm.h>
#include <asm/octeon/cvmx-helper.h>
#include <asm/octeon/cvmx-hfa.h>
#include <asm/octeon/cvmx-dfa-defs.h>
#include <asm/octeon/cvmx-dfm-defs.h>
#include <asm/octeon/cvmx-sso-defs.h>
#include <asm/octeon/cvmx-sysinfo.h>
#include <asm/octeon/cvmx-swap.h>
#include <asm/octeon/cvmx-spinlock.h>
#include <asm/octeon/cvmx-rwlock.h>
#include <asm/octeon/cvmx-fpa.h>
#include <asm/octeon/cvmx-fau.h>
#include <asm/octeon/cvmx-wqe.h>
#include <asm/octeon/cvmx-pko.h>
#include <asm/octeon/cvmx-pip.h>
#include <asm/octeon/cvmx-pow.h>
#include <asm/octeon/cvmx-l2c.h>
#include <asm/octeon/cvmx-gmxx-defs.h>
#include <cvm-hfa-module.h>
#define hfa_os_memoryalloc(_s, _a)  ({                                      \
                            void *p = NULL;                                 \
                            int order = get_order(_s);                      \
                            if (order <= 9){                                \
                                p = (void *) __get_free_pages (             \
                                        GFP_KERNEL |                        \
                                        GFP_ATOMIC, get_order(_s));         \
                                if(p && hfa_stats)                          \
                                    hfa_core_mem_stats_inc(sysmem,_s);      \
                            }                                               \
                            else {                                          \
                                p = hfa_bootmem_alloc (_s, _a);             \
                                if(p && hfa_stats)                          \
                                    hfa_core_mem_stats_inc(bootmem,_s);     \
                            }                                               \
                            p;                                              \
                        })
#define hfa_os_memoryfree(_p, _s)  ({                                       \
                            int order = get_order(_s);                      \
                            if (order <= 9) {                               \
                                free_pages ((unsigned long) _p,             \
                                    get_order (_s));                        \
                                if(hfa_stats)                               \
                                    hfa_core_mem_stats_dec(sysmem,_s);      \
                            }                                               \
                            else  {                                         \
                                hfa_bootmem_free (_p, _s);                  \
                                if(hfa_stats)                               \
                                    hfa_core_mem_stats_dec(bootmem,_s);     \
                            }                                               \
                        })

#define hfa_os_infoalloc(size, align)                                       \
                        ({                                                  \
                            void *p = NULL;                                 \
                            p = vmalloc(size);                              \
                            if(p && hfa_stats)                              \
                                hfa_core_mem_stats_inc(sysmem,size);        \
                            p;                                              \
                        })
#define hfa_os_infofree(ptr, size)                                          \
                        ({                                                  \
                            vfree(ptr);                                     \
                            if(hfa_stats)                                   \
                                hfa_core_mem_stats_dec(sysmem,size);        \
                        }) 
#define hfa_os_malloc(_s)                                                   \
                        ({                                                  \
                            void    *p = NULL;                              \
                            if ((_s)<=OCTEON_TBUFPOOL_SIZE){                \
                                p = cvmx_fpa_alloc (OCTEON_TBUFPOOL);       \
                                if(p && hfa_stats)                          \
                                    hfa_core_mem_stats_inc(tempbuf,1);      \
                            }                                               \
                            else  {                                         \
                                p = (void *) kmalloc (_s,                   \
                                        GFP_KERNEL | GFP_ATOMIC);           \
                                if(p && hfa_stats)                          \
                                    hfa_core_mem_stats_inc(sysmem,_s);      \
                            }                                               \
                            hfa_mdbg("TBUF: %p\n", p);                      \
                            p;                                              \
                         })
#define hfa_os_free(_x, _s)                                                 \
                         ({                                                 \
                            hfa_mdbg("\t\t\t\t\t\tTBuf: %p\n", _x);         \
                            if ((_s)<=OCTEON_TBUFPOOL_SIZE){                \
                                cvmx_fpa_free (_x, OCTEON_TBUFPOOL, 0);     \
                                if(hfa_stats)                               \
                                    hfa_core_mem_stats_dec(tempbuf,1);      \
                            }                                               \
                            else {                                          \
                                kfree (_x);                                 \
                                if(hfa_stats)                               \
                                    hfa_core_mem_stats_dec(sysmem,_s);      \
                            }                                               \
                          })
#define     hfa_log           printk
#define     hfa_logd          printk("[%s,%d]: ", __func__, __LINE__); printk
#define     printf            printk

#define hfa_os_trylock(_x)              ({                               \
                                            int r;                       \
                                            r=cvmx_spinlock_trylock(_x); \
                                            if(!r)local_bh_disable();    \
                                            r;                           \
                                        })
#ifdef HFA_DEBUG
#define     hfa_dbg     printk("[%s,%d]: ", __func__, __LINE__); printk 
#define     dprintf     printk
#else
#define     hfa_dbg(...)
#define     dprintf(...)
#endif
#ifdef HFA_MEM_DEBUG
#define     hfa_mdbg         printk("[%s,%d]: ", __func__, __LINE__); printk
#else
#define     hfa_mdbg(...)
#endif
extern  int                     hfa_ppbuf_pool;
extern  int                     hfa_ppbuf_sz;
extern  int                     hfa_ppbuf_cnt;

#else    /*Endof #ifdef KERNEL, Start of #ifndef KERNEL*/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <cvmx.h>
#include <cvmx-sysinfo.h>
#include <cvmx-spinlock.h>
#include <cvmx-coremask.h>

#ifndef CVMX_DONT_INCLUDE_CONFIG
#include <cvmx-config.h>
#endif

#include <cvmx-asm.h>
#include <cvmx-dfa-defs.h>
#include <cvmx-dfm-defs.h>
#include <cvmx-swap.h>
#include <cvmx-spinlock.h>
#include <cvmx-rwlock.h>
#include <cvmx-bootmem.h>
#include <cvmx-fpa.h>
#include <cvmx-hfa.h>
#include <cvmx-wqe.h>
#include <cvmx-pow.h>

#ifndef HFA_BUILD_FOR_LIBRARY
#include <cvmx-pko.h>
#include <cvmx-helper.h>
#endif

#ifdef CVMX_BUILD_FOR_LINUX_USER
#include <hfa-malloc.h>
#else
#include <cvmx-malloc.h>
#endif
#include <cvmx-l2c.h>

#define     hfa_os_malloc(_s)                                               \
                        ({                                                  \
                            void    *p = NULL;                              \
                            if ((_s)<=OCTEON_TBUFPOOL_SIZE){                \
                                p = cvmx_fpa_alloc (OCTEON_TBUFPOOL);       \
                                if(p && hfa_stats)                          \
                                    hfa_core_mem_stats_inc(tempbuf,1);      \
                            }                                               \
                            else {                                          \
                                p = hfa_bootmem_alloc(_s, 0);               \
                                if(p && hfa_stats)                          \
                                    hfa_core_mem_stats_inc(bootmem,_s);     \
                            }                                               \
                            hfa_mdbg("TBUF %p\n", p);                       \
                            p;                                              \
                        })

#define     hfa_os_free(_x, _s)                                             \
                        ({                                                  \
                            hfa_mdbg("\t\t\t\t\t\tTBUF %p\n", _x);          \
                            if ((_s)<=OCTEON_TBUFPOOL_SIZE) {               \
                                cvmx_fpa_free (_x, OCTEON_TBUFPOOL, 0);     \
                                if(hfa_stats)                               \
                                    hfa_core_mem_stats_dec(tempbuf,1);      \
                            }                                               \
                            else  {                                         \
                                hfa_bootmem_free(_x, _s);                   \
                                if(hfa_stats)                               \
                                    hfa_core_mem_stats_dec(bootmem,_s);     \
                            }                                               \
                        })
                                    
#define     hfa_log         printf
#define     hfa_logd        printf("[%s,%d]: ", __func__, __LINE__); printf 

#ifdef HFA_DEBUG
#define     hfa_dbg         printf("[%s,%d]: ", __func__, __LINE__); printf 
#define     dprintf         printf
#else
#define     hfa_dbg(...)
#define     dprintf(...)
#endif

#ifdef HFA_MEM_DEBUG
#define     hfa_mdbg         printf("[%s,%d]: ", __func__, __LINE__); printf
#else
#define     hfa_mdbg(...)
#endif

extern  CVMX_SHARED int     hfa_ppbuf_pool;
extern  CVMX_SHARED int     hfa_ppbuf_sz;
extern  CVMX_SHARED int     hfa_ppbuf_cnt;

#define hfa_os_memoryalloc(size, align) ({                                     \
            void *ptr = NULL, *newptr = NULL;                                  \
            cvmx_spinlock_lock(&cvmx_malloc_lock);                             \
            if ((ptr = cvmx_malloc(hfa_arena, size+align)) != NULL) {          \
                newptr = (void * )((((unsigned long)ptr)+align)&(~(align-1))); \
                ((unsigned char *)newptr)[-1] = (unsigned char)(newptr - ptr); \
                if(hfa_stats)                                                  \
                    hfa_core_mem_stats_inc(hfaarena,size);                     \
            }                                                                  \
            cvmx_spinlock_unlock(&cvmx_malloc_lock);                           \
            newptr;                                                            \
        })

#define hfa_os_memoryfree(ptr,size)    ({                             \
            unsigned char offset = ((unsigned char *)ptr)[-1];        \
            cvmx_spinlock_lock(&cvmx_malloc_lock);                    \
            cvmx_free(((char *)ptr)-offset);                          \
            if(hfa_stats)                                             \
                hfa_core_mem_stats_dec(hfaarena, size);               \
            cvmx_spinlock_unlock(&cvmx_malloc_lock);                  \
        })

#define hfa_os_infoalloc(size, align)  hfa_os_memoryalloc(size, align)
#define hfa_os_infofree(ptr, size)     hfa_os_memoryfree(ptr, size)
#define hfa_os_trylock(_x)                  cvmx_spinlock_trylock(_x)

#endif /*Endif #ifdef KERNEL*/

/*Common Macros*/
#define hfa_gptr_t                  cvm_hfa_gather_entry_t

#define HFA_FALSE                   CVMX_HFA_FALSE
#define HFA_TRUE                    CVMX_HFA_TRUE

/*************************PP memory allocators*******************/
/*Function ptr type for ppalloc/ppfree/ppsize*/
typedef void *  (*hfa_fnp_ppalloc_cb_t)(void *);
typedef void (*hfa_fnp_ppfree_cb_t)(void *, void *);
typedef uint64_t (*hfa_fnp_ppsize_cb_t)(void *);
typedef void (*hfa_fnp_pperr_cb_t)(uint32_t, void *);

/*extern declaration, defined and initialized in cvm-hfa.c*/
extern CVMX_SHARED hfa_fnp_ppalloc_cb_t     hfa_os_ppbuf_alloc;
extern CVMX_SHARED hfa_fnp_ppfree_cb_t      hfa_os_ppbuf_free;
extern CVMX_SHARED hfa_fnp_ppsize_cb_t      hfa_os_ppbuf_size;
extern CVMX_SHARED hfa_fnp_ppalloc_cb_t     hfa_os_ppbuf_talloc;
extern CVMX_SHARED hfa_fnp_ppfree_cb_t      hfa_os_ppbuf_tfree;
extern CVMX_SHARED hfa_fnp_ppsize_cb_t      hfa_os_ppbuf_tsize;
extern CVMX_SHARED hfa_fnp_ppalloc_cb_t     hfa_os_ppbuf_matchalloc;
extern CVMX_SHARED hfa_fnp_ppfree_cb_t      hfa_os_ppbuf_matchfree;
extern CVMX_SHARED hfa_fnp_ppsize_cb_t      hfa_os_ppbuf_matchsize;
extern CVMX_SHARED hfa_fnp_pperr_cb_t       hfa_os_pperr;

/***************************************************************/

#define hfa_os_likely(_x)           cvmx_likely (_x)
#define hfa_os_unlikely(_x)         cvmx_unlikely (_x)
#define hfa_os_htole64(_x)          ({                                      \
                                       uint64_t    r;                      \
                                       asm ("dsbh %[rd],%[rt]" : [rd]      \
                                            "=d" (r) : [rt] "d" (_x));     \
                                       asm ("dshd %[rd],%[rt]" : [rd]      \
                                            "=d" (r) : [rt] "d" (r));      \
                                       r;                                  \
                                    })
#define hfa_os_htole32(_x)         ({                                      \
                                       uint32_t    r;                      \
                                       asm ("wsbh %[rd],%[rt]" : [rd]      \
                                            "=d" (r) : [rt] "d" (_x));     \
                                       asm ("rotr %[rd],%[rs],16" :        \
                                            [rd] "=d" (r) : [rs] "d"       \
                                            (r));                          \
                                       r;                   \
                                   })
#define hfa_os_htole16(_x)         (((_x) >> 8) | ((_x) << 8))
#define hfa_os_le64toh(_x)         hfa_os_htole64 (_x)
#define hfa_os_le32toh(_x)         hfa_os_htole32 (_x)
#define hfa_os_le16toh(_x)         hfa_os_htole16 (_x)

#define hfa_likely(_x)             cvmx_likely (_x)
#define hfa_unlikely(_x)           cvmx_unlikely (_x)

#define hfa_os_lock_t              cvmx_spinlock_t
#define hfa_os_lockinit(_x)        cvmx_spinlock_init (_x)
#define hfa_os_lockdestroy(_x)
#define hfa_os_lock(_x)            cvmx_spinlock_lock (_x)
#define hfa_os_unlock(_x)          cvmx_spinlock_unlock (_x)
#define hfa_os_islocked(_x)        cvmx_spinlock_locked (_x)
#define hfa_os_rwlock_t            cvmx_rwlock_wp_lock_t
#define hfa_os_rwlockinit(_x)      cvmx_rwlock_wp_init (_x)
#define hfa_os_rwlockdestroy(_x)
#define hfa_os_rlock(_x)           cvmx_rwlock_wp_read_lock (_x)
#define hfa_os_runlock(_x)         cvmx_rwlock_wp_read_unlock (_x)
#define hfa_os_wlock(_x)           cvmx_rwlock_wp_write_lock (_x)
#define hfa_os_wunlock(_x)         cvmx_rwlock_wp_write_unlock (_x)
#define hfa_os_sleep(_x)           cvmx_wait (1000 * (_x))
#define hfa_os_sync()              CVMX_SYNCWS;
#define hfa_os_get_cycle()         cvmx_get_cycle ()

#define hfa_itype_t                cvm_hfa_itype_t
#define hfa_instr_t                cvmx_hfa_command_t
#define hfa_rmdata_t               cvm_hfa_rmdata_t
#define hfa_rword_t                cvm_hfa_rword_t
#define hfa_bool_t                 cvm_hfa_bool_t
#define ptr_to_phys(_x)            cvmx_ptr_to_phys(_x)
#define phys_to_ptr(_x)            cvmx_phys_to_ptr(_x)


#define hfa_os_compileassert(_x)        {                                     \
                                        char    __x[(_x)?1:-1]                \
                                            __attribute__ ((unused));         \
                                    }
#define OS_POP32(_x)                ({                                        \
                                        u32    v = (_x), c;                   \
                                        for (c = 0; v; c++)                   \
                                            v &= v - 1;                       \
                                        c;                                    \
                                    })
#define OS_POS32(_x)                ({                                        \
                                        int    i, v;                          \
                                        v = (_x);                             \
                                        for (i = 0;; i++, v >>= 1)            \
                                            if (v & 0x1)                      \
                                                break;                        \
                                        i;                                    \
                                    })
#define os_casttoptr(_x)            ((void *) (unsigned long) (_x))
#define os_casttolong(_x)           ((unsigned long) (_x))
#define HFA_OS_LISTHEAD_INIT(_l)    do {                                      \
                                        (_l)->next = (_l);                    \
                                        (_l)->prev = (_l);                    \
                                    } while (0)

#define hfa_os_listforeachsafe(_p, _n, _h)                                    \
               for (_p = (_h)->next, _n = _p->next;                           \
                  _p != (_h); _p = _n, _n = _p->next)

#define hfa_os_listentry(_p, _t, _m)                                          \
               ((_t *) ((char *) (_p)-(unsigned long)                         \
                (&((_t *) 0)->_m)))
/**Linked list data structure*/ 
/**@cond INTERNAL */
typedef struct _hfa_os_listhead_t  {
        struct _hfa_os_listhead_t *next, *prev;
} hfa_os_listhead_t;
/**@endcond */

static inline void
__hfa_os_listadd (hfa_os_listhead_t *n, hfa_os_listhead_t *prev,
                  hfa_os_listhead_t *next)
{
    next->prev = n;
    n->next = next;
    n->prev = prev;
    prev->next = n;
}

static inline void
hfa_os_listadd (hfa_os_listhead_t *n, hfa_os_listhead_t *head)
{
    __hfa_os_listadd (n, head, head->next);
}

static inline void
hfa_os_listaddtail (hfa_os_listhead_t *n, hfa_os_listhead_t *head)
{
    __hfa_os_listadd (n, head->prev, head);
}

static inline void
__hfa_os_listdel (hfa_os_listhead_t *prev, hfa_os_listhead_t *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void
hfa_os_listdel (hfa_os_listhead_t *n)
{
    __hfa_os_listdel (n->prev, n->next);
}

static inline int
hfa_os_listempty (hfa_os_listhead_t *h)
{
    return h->next == h;
}

static inline void
hfa_os_listchangehead (hfa_os_listhead_t *n, hfa_os_listhead_t *o)
{
    if (hfa_os_listempty (o))
        HFA_OS_LISTHEAD_INIT (n);
    else {
        n->next = o->next;
        n->prev = o->prev;
        o->next->prev = n;
        o->prev->next = n;
    }
}
#endif
