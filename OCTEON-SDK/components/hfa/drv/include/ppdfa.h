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
 * This file contains function declaration and macros for DFA Graph Post processing 
 */
#ifndef _PPDFA_H_
#define	_PPDFA_H_

#ifndef KERNEL
#include <stdint.h>
#endif

#ifndef HFA_SIM
#include <cvm-hfa-osapi.h>
#endif
#include "hfa-tools-version.h"
#include "pp.h"


#define	PPDFA_MSTRINGS		0x1		/* strings mode */
#define	PPDFA_MREGEX		0x2		/* regex mode */
#define	PPDFA_INVAL		(1 << 26)	/* invalid value */

#if defined(__i386__) || defined(__x86_64__)
#define	ppdfa_htole64(_x)	(_x)
#define	ppdfa_htole32(_x)	(_x)
#define	ppdfa_htole16(_x)	(_x)
#define	ppdfa_le64toh(_x)	ppdfa_htole64 (_x)
#define	ppdfa_le32toh(_x)	ppdfa_htole32 (_x)
#define	ppdfa_le16toh(_x)	ppdfa_htole16 (_x)
#elif defined(__OCTEON__)
#define	ppdfa_htole64(_x)	({					       \
					uint64_t r;			       \
					asm ("dsbh %[rd],%[rt]" : [rd]	       \
					    "=d" (r) : [rt] "d" (_x));	       \
					asm ("dshd %[rd],%[rt]" : [rd]	       \
					    "=d" (r) : [rt] "d" (r));	       \
					r;				       \
				})
#define	ppdfa_htole32(_x)	({					       \
					uint32_t r;			       \
					asm ("wsbh %[rd],%[rt]" : [rd]	       \
					    "=d" (r) : [rt] "d" (_x));	       \
					asm ("rotr %[rd],%[rs],16" :	       \
					    [rd] "=d" (r) : [rs] "d"	       \
					    (r));			       \
					r;				       \
				})
#define	ppdfa_htole16(_x)	(((_x) >> 8) | ((_x) << 8))
#define	ppdfa_le64toh(_x)	ppdfa_htole64 (_x)
#define	ppdfa_le32toh(_x)	ppdfa_htole32 (_x)
#define	ppdfa_le16toh(_x)	ppdfa_htole16 (_x)
#else
#error "unknown architecture for ppdfa"
#endif

/*
	ppdfa_cb_t is the callback to report matches

		arg0	- pattern number
		arg1	- match number with in pattern (always 0)
		arg2	- start offset
		arg3	- end offset
		arg4	- callback argument passed in by caller
*/
typedef void (*ppdfa_cb_t) (int, int, int, int, void *);

/*
	ppdfa_strnode_t holds the marked node info of a pattern compiled
	as string

		patno	- pattern number
		patlen	- length of the pattern
*/
typedef struct {
	uint32_t	patno;
	uint32_t	patlen;
	uint32_t	unused0;
	uint32_t	unused1;
} ppdfa_strnode_t;

/*
	ppdfa_strinfo_t holds the marked node info in strings mode

		nent	- no of ppdfa_strnode_t
		ent	- ppdfa_strnode_t[nent]
*/
typedef struct {
	uint32_t	nent;
	uint32_t	ent[];
} ppdfa_strinfo_t;

/*
	ppdfa_regexinfo_t holds the marked node info in regex mode

		nent	- no of pattern numbers
		ent	- pattern numbers
*/
typedef struct {
	uint32_t        unused;
	uint32_t	nent;
	uint32_t	ent[];
} ppdfa_regexinfo_t;

/*
	Hash table entry format

		bucket		- Is it a bucket? i.e, no of entries > 1
		present		- Are there any entries at this index?
		nnptr		- size of bucket if bucket is set,
				  else marked node
		off		- offset of bucket/marked node info in
				  info file
*/
typedef union {
	uint64_t	u64;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		uint64_t	off:32;
		uint64_t	nnptr:27;
		uint64_t	unused:3;
		uint64_t	present:1;
		uint64_t	bucket:1;
#else
		uint64_t	bucket:1;
		uint64_t	present:1;
		uint64_t	unused:3;
		uint64_t	nnptr:27;
		uint64_t	off:32;
#endif
	} s;
} ppdfa_hashent_t;

/*
	ppdfa_tstamp_t holds the compiler options part of a timestamp

		target		- target device
		cachesize	- cache size used
		strings		- compiled in strings mode
		dfa		- graph is a DFA
		cachealgo	- caching algorithm used
		memonly		- un-compressed graph
		linkable	- is the graph linkable?
		optlevel	- optimization level used
		linked		- is it a linked graph?
*/
typedef struct {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t	linkable:1;
	uint32_t	memonly:1;
	uint32_t	cachealgo:4;
	uint32_t	dfa:1;
	uint32_t	strings:1;
	uint32_t	cachesize:16;
	uint32_t	target:8;
	float		optlevel;
	uint32_t	unused1:1;
	uint32_t	linked:1;
	uint32_t	rsvd5:1;
	uint32_t	rsvd4:1;
	uint32_t	rsvd3:1;
	uint32_t	unused0:2;
	uint32_t	rsvd2:1;
	uint32_t	rsvd1:8;
	uint32_t	rsvd0:16;
#else
	uint32_t	target:8;
	uint32_t	cachesize:16;
	uint32_t	strings:1;
	uint32_t	dfa:1;
	uint32_t	cachealgo:4;
	uint32_t	memonly:1;
	uint32_t	linkable:1;
	float		optlevel;
	uint32_t	rsvd0:16;
	uint32_t	rsvd1:8;
	uint32_t	rsvd2:1;
	uint32_t	unused0:2;
	uint32_t	rsvd3:1;
	uint32_t	rsvd4:1;
	uint32_t	rsvd5:1;
	uint32_t	linked:1;
	uint32_t	unused1:1;
#endif
} ppdfa_tstampopt_t;

/*
	ppdfa_tstamp_t holds the actual timestamp

		version		- compiler version used
		options		- compiler options used
		uuid[16]	- Unique ID of this graph/info pair
*/
typedef struct {
	hfa_tools_version_t	version;
	ppdfa_tstampopt_t	options;
	uint8_t			uuid[16];
} ppdfa_tstamp_t;

/*
	ppdfa_infort_t holds info about the graph

		base		- base address of hfa.info data
		snode		- start node info
		snode2		- additional start node info
		strnodes	- strings info
		hasht[0..6]	- hash tables
		hashts[0..6]	- hash table sizes
		stamp		- timestamp
*/
typedef struct {
	void		*base;
	uint64_t	snode;
	uint64_t	snode2;
	ppdfa_strnode_t	*strnodes;
	void		*unused0;
	void		*unused1;
	void		*unused2;
	void		*unused3;
	ppdfa_hashent_t	*hasht0, *hasht1, *hasht2, *hasht3, *hasht4;
	ppdfa_hashent_t	*hasht5, *hasht6;
	uint32_t	mode, hashts0, hashts1, hashts2, hashts3;
	uint32_t	hashts4, hashts5, hashts6;
	ppdfa_tstamp_t	*stamp;
} ppdfa_infort_t;

/*
	Result word entry format

		pdboff	- packet data byte offset
		f3	- partial parse status
		f2	- partial parse status
		f1	- partial parse status
		u0	- user data
		nnptr	- next node pointer relative to graph
*/
typedef union {
	uint64_t	u64;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		uint64_t	pdboff:16;
		uint64_t	f3:9;
		uint64_t	f2:8;
		uint64_t	f1:3;
		uint64_t	u0:1;
		uint64_t	nnptr:27;
#else
		uint64_t	nnptr:27;
		uint64_t	u0:1;
		uint64_t	f1:3;
		uint64_t	f2:8;
		uint64_t	f3:9;
		uint64_t	pdboff:16;
#endif
	} s;
} ppdfa_rword1_t;

/*
	Result metadata format

		reas	- completion reason code
		f5	- partial parse status
		m	- last marked node
		d	- done processing
		rnum	- number of result words
*/
typedef union {
	uint64_t	u64;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		uint64_t	reas:3;
		uint64_t	rsvd:41;
		uint64_t	f5:2;
		uint64_t	m:1;
		uint64_t	d:1;
		uint64_t	rnum:16;
#else
		uint64_t	rnum:16;
		uint64_t	d:1;
		uint64_t	m:1;
		uint64_t	f5:2;
		uint64_t	rsvd:41;
		uint64_t	reas:3;
#endif
	} s;
} ppdfa_rword0_t;

/*
	state_dfa_t holds the mem allocation functions and postprocessing stats

		mcb	- User defined arguments
		stats	- holds pp progress statistics
*/
typedef struct {
	ppmemcb_t	mcb;
	ppstats_t	*stats;
} state_dfa_t;

/*
	arg_dfa_t holds the arguments for result buffer

		state		- ppdfa state to be operated on
		rptr		- pointer to the result buffer from hardware
		cb		- match callback to call for matches
		cbarg		- match callback argument
		rbuf		- result buffer to return
		radd		- pointer to current entry in the 'rbuf' list
		rcount		- number of results
		raddi		- index into the current result buffer where
				  the next entry is added
		rerr		- results buffer error count
*/
typedef struct {
	uint64_t	*rptr;
	ppdfa_cb_t		cb;
	void		*cbarg;
	uint64_t	*rbuf, *radd;
	uint32_t	rcount, raddi;
	uint32_t	unused0:2;
	uint32_t	rerr:1;
	uint32_t	unused:29;
	state_dfa_t		*state;
} arg_dfa_t;

/*
	ppdfa_snode_t holds start node info of the graph

		f4	- used in cache load instruction and '1' should be added
			  before filling it, i.e, for cache load,
			  iword3.f4 = f4 + 1
		dsize	- number of ram2 entries
		f3	- iword3.f3 for first walk instruction in a flow
		f2	- iword1.f2 for first walk instruction in a flow
		f1	- iword0.f1 for first walk instruction in a flow
		small	- global small memory flag
		snode	- snode for first walk instruction in a flow
*/
typedef union {
	uint64_t	u64;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		uint64_t	rsvd0:1;
		uint64_t	f4:6;
		uint64_t	dsize:9;
		uint64_t	f3:9;
		uint64_t	f2:8;
		uint64_t	f1:3;
		uint64_t	small:1;
		uint64_t	snode:27;
#else
		uint64_t	snode:27;
		uint64_t	small:1;
		uint64_t	f1:3;
		uint64_t	f2:8;
		uint64_t	f3:9;
		uint64_t	dsize:9;
		uint64_t	f4:6;
		uint64_t	rsvd0:1;
#endif
	} s;
} ppdfa_snode_t;

/*
	ppdfa_snode2_t holds start node info of the graph

		f5	- iword2.f5 for first walk instruction in a flow
*/
typedef union {
	uint64_t	u64;
	struct {
#if __BYTE_ORDER == __BIG_ENDIAN
		uint64_t	rsvd0:32;
		uint64_t	rsvd1:1;
		uint64_t	f5:2;
		uint64_t	rsvd2:14;
		uint64_t	rsvd3:9;
		uint64_t	rsvd4:6;
#else
		uint64_t	rsvd4:6;
		uint64_t	rsvd3:9;
		uint64_t	rsvd2:14;
		uint64_t	f5:2;
		uint64_t	rsvd1:1;
		uint64_t	rsvd0:32;
#endif
	} s;
} ppdfa_snode2_t;

int	ppdfa_initinfo (ppdfa_infort_t *, void *);
uint64_t *
pp(ppstate_t *state, ppdfa_infort_t *_irt, ppiovec_t *dptr, int dlen, int blen,
    uint64_t *rptr, ppdfa_cb_t cb, void *cbarg, int iflags, int *oflags);
int
ppinit (ppstate_t *_state, ppinfo_t *_irt, void *uarg);
void
ppcleanup (ppstate_t *_state, ppinfo_t *_irt);
void
ppassignstats (ppstate_t *, ppinfo_t *, ppstats_t *);
void 
ppcleanstats (ppstate_t *, ppinfo_t *);
ppstats_t * 
ppgetstats (ppstate_t *, ppinfo_t *);
#endif
