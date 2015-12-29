/* Copyright (C) 1992,94,1996-2000,2002,2004 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */
        

#ifndef __SHA1_H__
#define __SHA1_H__

#include <cvmx.h>
typedef  unsigned long int uint64_t ;
typedef  unsigned int      uint32_t ;
typedef  unsigned short    uint16_t ;
typedef  unsigned char     uint8_t  ;

#define SHA_LBLOCK	16
#define SHA_CBLOCK	(SHA_LBLOCK*4)  /* SHA treats input data as a
                                         * contiguous array of 32 bit
                                         * wide big-endian values. */
#define SHA_LONG unsigned long
#if 0
#define CVMX_TMP_STR(x) #x
#endif
#define CVMX_MT_HSH_IV(val,pos)     asm volatile ("dmtc2 %[rt],0x0048+" CVMX_TMP_STR(pos) :                 : [rt] "d" (val))
#define CVMX_MT_HSH_DAT(val,pos)    asm volatile ("dmtc2 %[rt],0x0040+" CVMX_TMP_STR(pos) :                 : [rt] "d" (val))
#if 0
#define CVMX_MT_HSH_STARTSHA(val)   asm volatile ("dmtc2 %[rt],0x4057"                   :                 : [rt] "d" (val))
#endif
#define CVMX_MT_HSH_DATZ(pos)       asm volatile ("dmtc2    $0,0x0040+" CVMX_TMP_STR(pos) :                 :               )
#define CVMX_MF_HSH_IV(val,pos)     asm volatile ("dmfc2 %[rt],0x0048+" CVMX_TMP_STR(pos) : [rt] "=d" (val) :               )

#define SHA1_DIGEST_LENGTH 20
#define BUFSIZE (1024*16)

  typedef struct SHAstate_st {
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    int num;
    uint64_t E, F, G;
  } SHA_CTX;

void do_fp(FILE *);

void pt(unsigned char *);

int SHA1_Init (SHA_CTX * );

int SHA1_Update (SHA_CTX * , const void *, unsigned long );

int SHA1_Final (unsigned char *, SHA_CTX * );

unsigned char *SHA1(const unsigned char *, int n, unsigned char *);
#endif
