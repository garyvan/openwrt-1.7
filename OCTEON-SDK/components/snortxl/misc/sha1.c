/* ====================================================================
 * Copyright (c) 1998-2008 The OpenSSL Project.  All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "sha1.h"

int
SHA1_Init (SHA_CTX * c)
{
  c->E = 0x67452301EFCDAB89ull;
  c->F = 0x98BADCFE10325476ull;
  c->G = 0xC3D2E1F000000000ull;
  c->num = 0;
  return 1;
}

int
SHA1_Update (SHA_CTX * c, const void *data, unsigned long n)
{
  unsigned long remaining = 0, totlen = 0, copied = 0;
  const uint64_t *ptr = (const uint64_t *) data;

  if(!n) 
    return -1;

  totlen = n;

  if (c->num) {
    totlen += remaining = c->num % 64;
    if (remaining) {
      memcpy ((void *) &(c->data) + remaining, data,
        SHA_CBLOCK - remaining);
      copied = 1;
    }
  }
  if (totlen >= 64) {
    /* Get the running IV loaded */
    CVMX_MT_HSH_IV (c->E, 0);
    CVMX_MT_HSH_IV (c->F, 1);
    CVMX_MT_HSH_IV (c->G, 2);

    /* Iterate through 64 bytes at a time */
    while (totlen >= 64) {
      if (copied)
        copied = 0;
      if (remaining)
        ptr = (uint64_t *) & c->data;
      CVMX_MT_HSH_DAT (*ptr++, 0);
      CVMX_MT_HSH_DAT (*ptr++, 1);
      CVMX_MT_HSH_DAT (*ptr++, 2);
      CVMX_MT_HSH_DAT (*ptr++, 3);
      CVMX_MT_HSH_DAT (*ptr++, 4);
      CVMX_MT_HSH_DAT (*ptr++, 5);
      CVMX_MT_HSH_DAT (*ptr++, 6);
      CVMX_MT_HSH_STARTSHA (*ptr++);
      totlen -= 64;
      /* remainig reset set ptr to input data */
      if (remaining) {
        ptr = data + (SHA_CBLOCK - remaining);
        remaining = 0;
      }
    }
    /* Update the IV */
    CVMX_MF_HSH_IV (c->E, 0);
    CVMX_MF_HSH_IV (c->F, 1);
    CVMX_MF_HSH_IV (c->G, 2);
  }                             /* end of if(totlen) */
  c->num += n;
  if (!copied)
    memcpy (&(c->data), ptr, totlen);
  return 1;
}

int
SHA1_Final (unsigned char *md, SHA_CTX * c)
{
  unsigned long len;
  uint8_t chunk[64];
  const uint64_t *ptr;
  uint64_t bits;

  len = c->num % 64;

  bits = (c->num * 8);          /* SHA1 expects big endian */
  /* The rest of the data will need to be copied into a chunk */
  if (len > 0)
    memcpy (chunk, c->data, len);
  chunk[len] = 0x80;
  memset (chunk + len + 1, 0, 64 - len - 1);
  /* Get the running IV loaded */
  CVMX_MT_HSH_IV (c->E, 0);
  CVMX_MT_HSH_IV (c->F, 1);
  CVMX_MT_HSH_IV (c->G, 2);

  ptr = (const uint64_t *) chunk;
  CVMX_MT_HSH_DAT (*ptr++, 0);
  CVMX_MT_HSH_DAT (*ptr++, 1);
  CVMX_MT_HSH_DAT (*ptr++, 2);
  CVMX_MT_HSH_DAT (*ptr++, 3);
  CVMX_MT_HSH_DAT (*ptr++, 4);
  CVMX_MT_HSH_DAT (*ptr++, 5);
  CVMX_MT_HSH_DAT (*ptr++, 6);

  /* Check to see if there is room for the bit count */
  if (len < 56)
    CVMX_MT_HSH_STARTSHA (bits);
  else {
    CVMX_MT_HSH_STARTSHA (*ptr);
    /* Another block was needed */
    CVMX_MT_HSH_DATZ (0);
    CVMX_MT_HSH_DATZ (1);
    CVMX_MT_HSH_DATZ (2);
    CVMX_MT_HSH_DATZ (3);
    CVMX_MT_HSH_DATZ (4);
    CVMX_MT_HSH_DATZ (5);
    CVMX_MT_HSH_DATZ (6);
    CVMX_MT_HSH_STARTSHA (bits);
  }
  /* Update the IV */
  CVMX_MF_HSH_IV (c->E, 0);
  CVMX_MF_HSH_IV (c->F, 1);
  CVMX_MF_HSH_IV (c->G, 2);
  memcpy (md, (void *) &c->E, 8);
  memcpy (md + 8, (void *) &c->F, 8);
  memcpy (md + 16, (void *) &c->G, 4);
  return 1;
}
unsigned char *SHA1(const unsigned char *d, int n, unsigned char *md)
{
								SHA_CTX c;
								SHA1_Init(&c);
								SHA1_Update(&c,d,n);
								SHA1_Final(md,&c);
								return(md);
}

void pt(unsigned char *md)
{
								int i;

								for (i=0; i<SHA1_DIGEST_LENGTH; i++)
																printf("%02x",md[i]);
								printf("\n");
}
void do_fp(FILE *f)
{
								SHA_CTX c;
								unsigned char md[SHA1_DIGEST_LENGTH];
								int fd;
								int i;
								unsigned char buf[BUFSIZE];

								fd=fileno(f);
								SHA1_Init(&c);
								for (;;)
								{
																i=read(fd,buf,BUFSIZE);
																if (i <= 0) break;
																SHA1_Update(&c,buf,(unsigned long)i);
								}
								SHA1_Final(&(md[0]),&c);
								pt(md);
}

