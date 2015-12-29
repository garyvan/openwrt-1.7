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



#ifndef MISC_DEFS_H
#define MISC_DEFS_H

#include "gzguts.h"
#include "hfa-zlib.h"
#if !(defined KERNEL) && !(defined HFA_SIM)
#include "cvmx-platform.h"
#endif
#ifdef HFA_SIM
#define CVMX_SHARED
#endif
#ifndef HFA_SIM
#define swap32(x)   \
(((x<<24)&0xff000000)|((x>>24)&0xff)|((x<<8)&0xff0000)|((x>>8)&0xff00))
#else
#define swap32(x)   (x)
#endif
#ifndef __linux__
#define malloc memfs_malloc
#define free memfs_free
#endif
#ifndef KERNEL
void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)(unsigned long), 
                                       void (*memfs_free_rtn)(const void *));

extern CVMX_SHARED void *(*memfs_malloc)(unsigned long);
extern CVMX_SHARED void (*memfs_free)(const void *);
#else 
void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)(unsigned long, gfp_t), 
                                       void (*memfs_free_rtn)(const void *));

extern void *(*memfs_malloc)(unsigned long, gfp_t);
extern void (*memfs_free)(const void *);
#endif

#ifndef KERNEL
#ifndef __linux__
#define open memfs_open
#define close memfs_close
#define read memfs_read
#undef LSEEK
#define LSEEK memfs_lseek
#endif
struct tar {
  char name[100];   char _unused[24];
  char size[12];    char _padding[376];
};
typedef struct flist_t
{
  long    fd;
  const char * fname;
  int    fsize;
  const char * data;
  int    fpos;
  struct flist_t  *next;
} FLIST;

FLIST *start;
unsigned long long gz_get_size(gzFile file);
int is_file_in_tar( struct tar *tar, char *name, char **start, int *length );
long memfs_open(const char * path, int flags, int mode);
int memfs_close(long fd);
int memfs_eof(FLIST * stream);
int memfs_lseek(long fd,long offset,int whence);
int memfs_getc(FLIST *tmp);
int memfs_read(long fd, void *buf, unsigned count);

#else
#include <vmalloc.h>
#include <slab.h>
#include <fs.h>
#include <linux/hardirq.h>

#define calloc(x,y,z) memfs_malloc(x*y,z)
#define open kopen
#define close kclose
#undef LSEEK
#define LSEEK klseek
#define read kread
#define write kread // just a dummy

typedef struct task_attr {
    void           *data;
    unsigned long  size;
}task_attr_t;

long  kopen(const char * path, int flags, int mode);
int klseek(long fd,long offset,int whence);
int kread(long fd, void *buf, unsigned count);
int kclose(long fd);
#endif
#endif
