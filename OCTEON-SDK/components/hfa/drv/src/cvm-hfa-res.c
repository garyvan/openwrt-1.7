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
 * This file contains APIs that are needed to create result buffer by 
 * post processing libraries
 *
 */
#include "cvm-hfa-res.h"
#include "cvm-hfa-stats.h"

/*
	Initializes the result processing part of post-processing

		a	- arguments
*/
int
Rinit (arg_dfa_t *a)
{
	/*Match buffer should be aligned*/
    if ((HFA_OS_PPBUFRSIZE(a->state->mcb.uarg) & 0x7) != 0)
        return -1;

	/*
		If a match callback is provided, skip creating result buffer
	*/
	if (a->cb != NULL)
		return 0;

	/*
		Match callback is not provided, create a result buffer to
		populate the matches with
	*/
	if ((a->rbuf = HFA_OS_PPBUFRALLOC (a->state->mcb.uarg)) == NULL)
		return -1;
	RNEXT (a->rbuf, a->state->mcb.uarg) = NULL;
	a->radd = a->rbuf;
	a->raddi = 1;
	a->rcount = 0;
	a->rerr = 0;
	return 0;
}

/*
	Finish result processing part of post-processing

		a	- arguments
*/
uint64_t *
Rfinish (arg_dfa_t *a)
{
	ppmeta_t	*meta;

	/*
		If match callback is provided, return NULL
	*/
	if (a->cb != NULL)
		return NULL;

	/*
		Fill-in the results metadata and return a pointer to it
	*/
	meta = (ppmeta_t *) a->rbuf;
	meta->u64 = 0;
	meta->s.nmatch = a->rcount;
	meta->s.allocerr = a->rerr;
	return a->rbuf;
}

/*
	Adds a result word to the result buffer

		a	- arguments
		r	- result word
*/
int
Radd (arg_dfa_t *a, uint64_t r)
{
	uint64_t	*t;
    void *uarg = a->state->mcb.uarg;


	/*
		If there is space in the current result buffer, add to it.
		Else, create a new pp buffer, link the current buffer to it
		and then add the new result word
	*/
	if (hfa_os_likely (a->raddi < RMAX(uarg)))
		a->radd[a->raddi++] = r;
	else {
		t = HFA_OS_PPBUFRALLOC (uarg);
		if (t != NULL) {
			RNEXT (t, uarg) = NULL;
			RNEXT (a->radd, uarg) = t;
			a->radd = t;
			a->radd[0] = r;
			a->raddi = 1;
		}
		else {
			a->rerr = 1;
			return -1;
		}
	}
	return 0;
}

/*
	Reports a match

		a	- arguments
		patno	- pattern number
		matchno	- match number
		soff	- start offset of the match
		eoff	- end offset of the match
*/
void
Rreport1 (arg_dfa_t *a, int patno, int matchno, int soff, int eoff)
{
	ppmatch_t	match;
	ppcap_t		cap;
    int flag=0;

	if(matchno)
		hfa_os_pperr(HFA_PPERR_BADCAPNUM, a->state->mcb.uarg);

	/*
		If the user provided a callback, use the callback to report
		the match and return
	*/
#ifdef HFA_STATS
        HFA_CORE_STATS_INC(nmatches, cvmx_get_core_num(), 1);
#endif
	if (a->cb != NULL) {
		(*a->cb) (patno, matchno, soff, eoff, a->cbarg);
		return;
	}

	/*
		Add the match to the result buffer
	*/
	match.u64 = 0;
	match.s.patno = patno;
	match.s.ncap = 1;
	flag |= Radd (a, match.u64);
	cap.u64 = 0;
	cap.s.soff = soff;
	cap.s.eoff = eoff;
	flag |= Radd (a, cap.u64);
    if(!flag){
		a->rcount++;
    }
}

/*
	Frees the result buffer

		buf	- result buffer to free
		_state	- ppdfa state
*/
void
Rfree (uint64_t *buf, state_dfa_t *_state)
{
	state_dfa_t		*state = _state;
	uint64_t	*t;

	while (buf != NULL) {
		t = RNEXT (buf, state->mcb.uarg);
		HFA_OS_PPBUFRFREE (buf, state->mcb.uarg);
		buf = t;
	}
}
