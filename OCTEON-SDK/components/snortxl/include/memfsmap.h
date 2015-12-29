/* memfs_map.h -  */

/************************license start***************
 * Copyright (c) 2003-2015  Cavium Inc. (support@cavium.com). All rights
 * ither the name of Cavium Inc. nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.

 * This Software, increserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

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

/*
modification history
--------------------
01a,06apr11,rnp  written
*/

#ifndef _MEMFS_MAP_H_
#define _MEMFS_MAP_H_

#include "gzguts.h"
#ifdef CAV_OCT_SE
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
#define swap32(x)   (x)
#define open   memfs_open
#define close   memfs_close
#undef feof
#define feof   memfs_eof
#define read   memfs_read
#define LSEEK   memfs_lseek
//#define ftell   memfs_tell
#endif
void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)(unsigned long), 
                                       void (*memfs_free_rtn)(const void *));
#define fgets   getsgz
#define fread   readgz
unsigned long long gz_get_size(gzFile file);
inline int fclose(FILE *fp);
FILE *fopen(const char *path, const char *mode);
inline int cav_umask(void * a);
int memfs_eof(FILE * stream);
long memfs_tell(FILE * stream);
int memfs_getc(FILE * stream);
extern long memfs_open(const char * path, int flags, int mode);
int memfs_close(long fd);
int memfs_lseek(long fd,long offset,int whence);
int memfs_read(long fd, void *buf, unsigned count);
char * getsgz(char *s, int size, FILE *_stream);
int readgz(void *buf, int size, int nmemb, FILE * _stream);
#endif
