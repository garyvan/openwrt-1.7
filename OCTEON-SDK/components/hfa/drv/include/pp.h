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
 * This file contains Post-processing macros/function declaration for Post processing
 * of HFA Graph
 *
 */
#ifndef _PP_H_
#define	_PP_H_

#ifndef KERNEL
#include <stdint.h>
#endif
#include "hfa-tools-version.h"

#define	PPMAJORNO	0		/* major release no */
#define	PPMINORNO	9		/* minor release no */
#define	PPPATCHNO	4		/* patch no */

#define	PPIFNOCROSS	1		/* disable cross packet matching */
#define	PPIFSINGLEMATCH	2		/* report one match per call */

#define	PPOFBUFFER	1		/* buffer is needed later */

#define	PPINVAL		(1 << 26)	/* invalid value */

#define	PPBUFSIZE	 256 /* size of ppbuf(for hfaw)*/

/*
  ppcb_t is the callback to report matches
	arg0	- pattern number
	arg1	- match number with in pattern (for captured groups)
	arg2	- start offset
	arg3	- end offset
	arg4	- callback argument passed in by caller
*/
typedef void (*ppcb_t) (int, int, int, int, void *);

/*
ppmemcb_t holds the user defined argument used by pp to allocate/free. 
PP allocates/free memory using os_ppbufalloc(uarg)/os_ppbuffree(uarg)
respectively. os_ppbufalloc(uarg)/os_ppbuffree(uarg) are macros defined to
function pointers used by pp. By default HFA API sets default function pointers,
however application can override function pointer to any user-defined function.

@uarg	- User agument provided to os_ppbufalloc()/os_ppbufree() 
*/
typedef struct {
	void	*uarg;
} ppmemcb_t;

/*
  ppiovec_t is an io vector entry
	ptr	- pointer to the sg buffer
	len	- size of the sg buffer
*/
typedef struct {
	uint8_t		*ptr;
	uint32_t	len;
} ppiovec_t;

/*
	pp_tstampopt_t holds compiler options part of the timestamp

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
#ifdef __BIG_ENDIAN_BITFIELD
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
} pp_tstampopt_t;

/*
	pp_tstamp_t holds the timestamp

		version		- compiler version used
		options		- compiler options used
		uuid[16]	- Unique ID of this graph/info pair
*/
typedef struct {
	hfa_tools_version_t	version;
	pp_tstampopt_t		options;
	uint8_t			uuid[16];
} pp_tstamp_t;

/*
  ppinfo_t holds info about the graph
*/
typedef struct {
	void		*base;
	uint64_t	snode;
	uint64_t	snode2;
	uint8_t		info[12*sizeof(void*)+8*sizeof(uint32_t)];
	pp_tstamp_t	*stamp;
} ppinfo_t;

/*
  ppstate_t holds the post processing state of a flow
*/
typedef struct {
	uint8_t	state[ 6* sizeof (void *) + 4 * sizeof (int)];
} ppstate_t;

/*
  ppstats_t holds info about pp's progress
  	curr_rword	- current rword being processed
  	tot_rwords	- total number of rwords
  	rstack		- number of entries in rstack
  	sstack		- number of entries in sstack
	scycle		- cycle count at the beginning of pp
	ccycle		- current cycle count
*/
typedef struct {
	int curr_rword;
	int tot_rwords;
	int rstack;
	int sstack;
	uint64_t scycle;
	uint64_t ccycle;
} ppstats_t;

/*
  ppmeta_t holds the post processing results metadata
	nmatch		- no of pattern matches
	allocerr	- some memory allocation failed
			  Note: If this bit is set, nmatch may not be correct.
				The buffers should still be freed with
				ppfree ()
*/
typedef union {
	uint64_t	u64;
	struct {
		uint64_t	nmatch:32;
		uint64_t	allocerr:1;
		uint64_t	unused:31;
	} s;
} ppmeta_t;

/*
  ppmatch_t holds the post processing result
	patno	- pattern number
	ncap	- no of capture groups (atleast one)
*/
typedef union {
	uint64_t	u64;
	struct {
		uint64_t	patno:32;
		uint64_t	ncap:3;
		uint64_t	unused:29;
	} s;
} ppmatch_t;

/*
  ppcap_t holds the details of capture
	no	- capture number
	soff	- start offset of the capture
	eoff	- end offset of the capture
*/
typedef union {
	int64_t	u64;
	struct {
		uint64_t	no:3;
		int64_t		soff:32;
		int64_t		eoff:27;
		uint64_t	unused:2;
	} s;
} ppcap_t;

int	        pphfa_init (ppstate_t *, ppinfo_t *, void *);
void		pphfa_cleanup (ppstate_t *, ppinfo_t *);
uint64_t	*pphfa (ppstate_t *, ppinfo_t *, ppiovec_t *, int, int, uint64_t *,
		    ppcb_t, void *, int, int *);
void		ppinitinfo (ppinfo_t *, void *);
void		ppfree (ppstate_t *, uint64_t *);
ppstats_t * pphfa_getstats (ppstate_t *);
void		pphfa_assignstats (ppstate_t *, ppstats_t *);
void		pphfa_cleanstats (ppstate_t *_);

/**
 * Constructs a readable version string for the PP library
 *
 * @param   buf       char buffer for output
 * @param   size      size of buffer
 *
 * @return  number of bytes required for entire version string, including the
 *          terminating \0'
 */
size_t pp_get_version_string(char *buf, size_t size);

/**
 * Constructs a readable extended version string for the PP library
 *
 * @param   buf       char buffer for output
 * @param   size      size of buffer
 *
 * @return  number of bytes required for entire version string, including the
 *          terminating \0'
 */
size_t pp_get_version_string_ex(char *buf, size_t size);

/* Beginning of error defines and messages */

/*
 If we are adding a new assert/fatalerr/memerr in pp, 
 this macro's count should be incremented and that value 
 should be used as error id and corresponding entries should
 be made in the enum and message list
 This doesn't count the dummy error
*/

#define HFA_PPERROR_COUNT HFA_PPERR_STRINFO+1

/*Error types*/
#define HFA_PPERRASSERT		0
#define HFA_PPERRFATALERR	1
#define HFA_PPERRMEMERR		2

/*
 enum for error indices to index hfa_err_messages
 Self explanatory if you look at the array of messages
*/
enum hfa_err_enum {
	HFA_PPERR_DUMMY, HFA_PPERR_RWORD, 
	HFA_PPERR_INFO1, HFA_PPERR_INFO2, HFA_PPERR_INFO3, HFA_PPERR_INFO4, 
	HFA_PPERR_INFO5, HFA_PPERR_INFO6, HFA_PPERR_INFO7, HFA_PPERR_INFO8, 
	HFA_PPERR_INFO9, HFA_PPERR_INFO10, HFA_PPERR_INFO11, HFA_PPERR_INFO12, 
	HFA_PPERR_INFO13, 
	HFA_PPERR_INFOMODE1, HFA_PPERR_INFOMODE2, HFA_PPERR_INFOMODE3, 
	HFA_PPERR_INFOMODE4, HFA_PPERR_INFOMODE5, HFA_PPERR_INFOMODE6,
	HFA_PPERR_RCSTACK, HFA_PPERR_REGEXSTACK, HFA_PPERR_BADCAPNUM,
	HFA_PPERR_SCSTACK1, HFA_PPERR_SCSTACK2, HFA_PPERR_STRSTACK,
	HFA_PPERR_MEM1, HFA_PPERR_MEM2, HFA_PPERR_MEM3, HFA_PPERR_MEM4,
	HFA_PPERR_MEM5, HFA_PPERR_MEM6, HFA_PPERR_MEM7, HFA_PPERR_MEM8,
	HFA_PPERR_RCINFO, HFA_PPERR_SCINFO, HFA_PPERR_REGEXINFO, HFA_PPERR_STRINFO,
}__attribute__ ((unused));

static char *hfa_err_messages[HFA_PPERROR_COUNT] __attribute__ ((unused))= {
	[HFA_PPERR_DUMMY] = "This is a dummy error - invalid error code",
	[HFA_PPERR_RWORD] = "Result word returned by HFA hardware is corrupted before passing to pp()",
	[HFA_PPERR_INFO1] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO2] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO3] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO4] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO5] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO6] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO7] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO8] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO9] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO10] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO11] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO12] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFO13] = "Graph info passed to postprocessing, ie,  pp () is corrupted",
	[HFA_PPERR_INFOMODE1] = "Graph info is corrupted before initialization of postprocessing (ppinit)",
	[HFA_PPERR_INFOMODE2] = "Graph info is corrupted before cleanup of postprocessing (ppcleanup)",
	[HFA_PPERR_INFOMODE3] = "Graph info is corrupted before postprocessing (pp)",
	[HFA_PPERR_INFOMODE4] = "Graph info is detected to be corrupted as part of ppinitinfo",
	[HFA_PPERR_INFOMODE5] = "Graph info is detected to be corrupted as part of ppinitinfo",
	[HFA_PPERR_INFOMODE6] = "Graph info is detected to be corrupted as part of ppinitinfo",
	[HFA_PPERR_RCSTACK] = "RC mode - pp () stack may be corrupted",
	[HFA_PPERR_REGEXSTACK] = "Regex mode - pp () stack may be corrupted",
	[HFA_PPERR_BADCAPNUM] = "Bad capture number",
	[HFA_PPERR_SCSTACK1] = "SC mode - pp () stack may be corrupted",
	[HFA_PPERR_SCSTACK2] = "SC mode - pp () stack may be corrupted",
	[HFA_PPERR_STRSTACK] = "String mode - pp () stack may be corrupted",
	[HFA_PPERR_MEM1] = "Memory allocation failed",
	[HFA_PPERR_MEM2] = "Memory allocation failed",
	[HFA_PPERR_MEM3] = "Memory allocation failed",
	[HFA_PPERR_MEM4] = "Memory allocation failed",
	[HFA_PPERR_MEM5] = "Memory allocation failed",
	[HFA_PPERR_MEM6] = "Memory allocation failed",
	[HFA_PPERR_MEM7] = "Memory allocation failed",
	[HFA_PPERR_MEM8] = "Memory allocation failed",
	[HFA_PPERR_RCINFO] = "RC mode - Result word returned by HFA hardware is corrupted before passing to pp() or graph is corrupted",
	[HFA_PPERR_SCINFO] = "SC mode - Result word returned by HFA hardware is corrupted before passing to pp() or graph is corrupted",
	[HFA_PPERR_REGEXINFO] = "Regex mode - Result word returned by HFA hardware is corrupted before passing to pp() or graph is corrupted",
	[HFA_PPERR_STRINFO] = "String mode - Result word returned by HFA hardware is corrupted before passing to pp() or graph is corrupted"
};

static int hfa_err_type[HFA_PPERROR_COUNT] __attribute__ ((unused)) = 
{
	[HFA_PPERR_DUMMY] = -1, 
	[HFA_PPERR_RWORD ... HFA_PPERR_STRSTACK] = HFA_PPERRASSERT,
	[HFA_PPERR_MEM1 ... HFA_PPERR_MEM8] = HFA_PPERRMEMERR,
	[HFA_PPERR_RCINFO ... HFA_PPERR_STRINFO] = HFA_PPERRFATALERR
};


#endif
