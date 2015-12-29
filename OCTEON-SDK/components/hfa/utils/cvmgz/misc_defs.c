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


#include "misc_defs.h"
/* 
 * These settings are common to all cores
 */
#ifndef KERNEL
CVMX_SHARED void *(*memfs_malloc)(unsigned long);
CVMX_SHARED void (*memfs_free)(const void *);
CVMX_SHARED struct tar *tar;
#else 
void *(*memfs_malloc)(unsigned long, gfp_t);
void (*memfs_free)(const void *);
struct tar *tar;
#endif

#ifdef KERNEL
void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)(unsigned long, gfp_t), void (*memfs_free_rtn)(const void *))
#else 
void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)(unsigned long), void (*memfs_free_rtn)(const void *))
#endif
{ 
#ifndef KERNEL
  tar= (struct tar *)nm_blk_addr;
#endif
  memfs_malloc = memfs_alloc_rtn;
  memfs_free   = memfs_free_rtn;
  return;
}

#ifndef KERNEL
int is_file_in_tar( struct tar *tar, char *name, char **start, int *length )
{
  for( ; tar->name[0]; tar+=1+(*length+511)/512 )
  {
    sscanf( tar->size, "%o", length);
    if( !strcmp(tar->name,name) )
    {
      *start = (char*)(tar+1);
      return 1;
    }
  }
  return 0;
}

long memfs_open(const char * path, int flags, int mode)
{
  static int j = 0;
  char *data; int length = 0;
  /* only read-only files supported */
  if (flags != O_RDONLY)
    return -1;

  if(path[0]=='.' && path[1]=='/')
    path=path+2;

  if(memcmp(((char *)tar + 257),"ustar",5))
  {
    printf("\n not a tar file\n");
    return -1;
  }
  if( is_file_in_tar((struct tar *)tar,(char *)path,&data,&length))
  {
    /*open the file for reading */
    FLIST * tmp_flist, *tmp;
#ifdef KERNEL
    tmp_flist=(FLIST *)memfs_malloc(sizeof(FLIST), GFP_KERNEL);
#else 
    tmp_flist=(FLIST *)memfs_malloc(sizeof(FLIST));
#endif
    tmp_flist->fd  = j;
    tmp_flist->fname = path;
    tmp_flist->fsize = length;
    tmp_flist->data  = data;
    tmp_flist->fpos  = 0;
    tmp_flist->next  = NULL;
    j++;
    if(start == NULL)
      start = tmp_flist;
    else
    {
      tmp = start;
      while(tmp->next != NULL)
        tmp= tmp->next;
      tmp->next = tmp_flist;
    }
    return tmp_flist->fd;
  }

  /* TODO: set errno...maybe */
  return -1;
}

unsigned long long gz_get_size(gzFile file)
{
  FLIST *tmp = start;
  unsigned long long csize = 0, usize = 0;
  while(tmp != NULL)
  {
    if(tmp->fd == ((gz_statep)file)->fd)
      break;
    tmp = tmp->next;
  }
  csize = tmp->fsize;
  if(gzdirect(file))
    usize = csize;
  else 
    usize = swap32(*(int *)(tmp->data + csize -4));
  //printf("\n csize: %d start offset: %p usize: %u \n",csize,tmp->data,usize);
  return usize;
}

int memfs_close(long fd)
{
  FLIST *tmp = start,*tmp1;
  if(start->fd == fd)
  {
    if(start->next == NULL)
    {
      memfs_free(start);
      start = NULL;
    }
    else
    {
      start = start->next;
      memfs_free(tmp);
    }
    return 0;
  }
  while(tmp != NULL)
  {
    if(tmp->fd == fd)
      break;
    tmp1=tmp;
    tmp = tmp->next;
  }
  tmp1->next = tmp->next;
  memfs_free(tmp);
  return 0;
}

int memfs_eof(FLIST * stream)
{
    if (stream->fpos >= stream->fsize)
        return 1;
    return 0;
}


int memfs_lseek(long fd,long offset,int whence)
{
  FLIST *tmp = start;
  while(tmp != NULL)
  {
    if(tmp->fd == fd)
      break;
    tmp = tmp->next;
  }
  switch(whence){
    case 0:
      if(offset > tmp->fsize){
        return -1;
      }
      tmp->fpos = offset;
      break;
    case 1:
      if(tmp->fpos+offset > tmp->fsize){
        return -1;
      }
      tmp->fpos += offset;
      break;
    case 2:
      if(tmp->fsize+offset > tmp->fsize){
        return -1;
      }
      tmp->fpos = tmp->fsize;
      break;
    default:;
  };
  return 0;
}

int memfs_getc(FLIST *tmp)
{
    if (memfs_eof(tmp))
        return -1;
    return tmp->data[tmp->fpos++];
}

int memfs_read(long fd, void *buf, unsigned count)
{
  int i = 0;
  unsigned sz = count;
  char * s = buf;
  FLIST *tmp = start;
  while(tmp != NULL)
  {
    if(tmp->fd == fd)
      break;
    tmp = tmp->next;
  }
  if(count == 0)
    printf("\n count cannot be zero");

  if(tmp == NULL)
  {
    printf("\n file not found for reading!! ");
    return -1;	
  }
  if(tmp->fpos+sz < tmp->fsize){
    memcpy(&s[i],tmp->data+tmp->fpos,sz);
    tmp->fpos+=sz;
    i+=sz;
  }else{
    while (1)
    {
      if (i >= sz)
        break;
      if (memfs_eof(tmp))
        break;
      s[i] = memfs_getc(tmp);
      i++;
    }
  }

  return i;
}

#else
long  kopen(const char * path, int flags, int mode)
{
  struct file     *file;
    
  if(in_softirq()) {
    return ((long)path);
  }
  file = filp_open(path, O_RDONLY, 0);
  if(IS_ERR(file)) {
    printk("flip_open failed %p\n", file);
    return -1;
  }
  return((long)file);
}

int klseek(long fd,long offset,int whence)
{
  if(in_softirq()) {
    task_attr_t *t_attr = (task_attr_t *)fd;
    int  off = (int)offset; 
   
    t_attr->size -= offset;  
    t_attr->data += off;
    return 0;
  } 
  return(vfs_llseek((struct file *)fd, offset, whence));
}

int kread(long fd, void *buf, unsigned count)
{
  if(in_softirq()) {
    task_attr_t *t_attr = (task_attr_t *)fd;

    count = count < t_attr->size ? count : t_attr->size;
    t_attr->size -= count;
    memcpy(buf, t_attr->data, count);
    t_attr->data += count;
    return count;
  } 
  return(vfs_read((struct file *)fd, buf, count, &(((struct file *)fd)->f_pos)));
}

int kclose(long fd)
{
  if(in_softirq()) {
    return 0;
  }
  filp_close((struct file *)fd, NULL);
  return 0;
}

#endif
