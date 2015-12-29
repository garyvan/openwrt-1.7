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
 * This file contains Post processing APIs
 */
#ifndef KERNEL
#include <stdio.h>
#include <assert.h>
#else
#define assert(i)   BUG_ON(!(i))
#endif
#include "ppdfa.h"
#include "cvm-hfa-res.h"

static void    *eswap (void *);
static void    *infoentry (ppdfa_infort_t *, ppdfa_rword1_t);
static uint32_t    hashidx (uint32_t, uint32_t);

/*
    Initializes the hfa.info from the compiler and creates an
    info runtime structure

        irt    - info runtime to create
        info    - pointer to hfa.info data
*/
int
ppdfa_initinfo (ppdfa_infort_t *irt, void *info)
{
    uint64_t    *pu64;
    uint32_t    i, *pu32, ncc, nstrn, len;

    hfa_os_compileassert(sizeof(ppdfa_infort_t) == sizeof(ppinfo_t));

    /*
        Endian swap the file, if needed
    */
    irt->stamp = (ppdfa_tstamp_t *) eswap (info);

    /*
        Get start nodes info
    */
    pu64 = (uint64_t *) info;
    irt->snode = pu64[0];
    irt->snode2 = pu64[1];
    pu64 += 2;
    pu32 = (uint32_t *) pu64;

    /*
        Get the mode (string/regex)
    */
    irt->mode = pu32[0];
    switch (irt->mode) {
    case PPDFA_MSTRINGS:

        /*
          Strings mode, get the no of string nodes
        */
        nstrn = pu32[1];
        pu32 += 2;
        irt->strnodes = (ppdfa_strnode_t *) pu32;
        for (i = len = 0; i < nstrn; ++i)
            len += irt->strnodes[i].unused1;

        /*
          Point to first hash table
        */
        pu32 = (uint32_t *) ((uint8_t *) pu32 + nstrn *
            sizeof *irt->strnodes + len);
        break;
    case PPDFA_MREGEX:

        /*
          Regular expressions mode, skip unused regex info
        */
        ncc = pu32[1];
        pu32 += 2;
        pu32 = (uint32_t *) ((char *) pu32 + ncc * 256);
        pu32++;

        /*
          Point to first hash table
        */
        pu32 = (uint32_t *) ((uint8_t *) pu32 + pu32[-1] * 10);
        break;
    default:
        assert (0);
    }

    /*
      Obtain pointers to all hash tables (one per node type)
    */
    irt->hasht0 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts0 = pu32[2];
    pu32 += 3;
    irt->hasht1 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts1 = pu32[2];
    pu32 += 3;
    irt->hasht2 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts2 = pu32[2];
    pu32 += 3;
    irt->hasht3 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts3 = pu32[2];
    pu32 += 3;
    irt->hasht4 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts4 = pu32[2];
    pu32 += 3;
    irt->hasht5 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts5 = pu32[2];
    pu32 += 3;
    irt->hasht6 = (ppdfa_hashent_t *) ((uint8_t *) info + pu32[0]);
    irt->hashts6 = pu32[2];
    pu32 += 3;
    return 0;
}

/*
    Initializes the post-processing state

        _state    - post-processing state to initialize
        _irt    - info runtime to use
        mcb    - memory alloc/free callbacks
*/
int
ppinit (ppstate_t *_state, ppinfo_t *_irt, void *uarg)
{
    if (!_irt->stamp)
        assert (0);

    if (!_irt->stamp->options.dfa) {
        return( pphfa_init(_state, _irt, uarg));
    }
    else
    {
        state_dfa_t        *state = (state_dfa_t *) _state;
        state->mcb.uarg = uarg;
        state->stats =NULL;
        return 0;
    }
}

/*
    Cleans up the post-processing state

        _state    - post-processing state to cleanup
        _irt    - info runtime to use
*/
void
ppcleanup (ppstate_t *_state, ppinfo_t *_irt)
{
    if (!_irt->stamp)
        assert (0);

    if (!_irt->stamp->options.dfa) {
        return( pphfa_cleanup(_state, _irt));
    }
}

/*
    Performs hardware retults to pattern numbers mapping

        irt    - info runtime to use
        rptr    - result buffer returned by hardware
        cb    - match callback
        cbarg    - match callback argument
*/
uint64_t *
pp(ppstate_t *state, ppdfa_infort_t *irt, ppiovec_t *dptr, int dlen, int blen,
    uint64_t *rptr, ppdfa_cb_t cb, void *cbarg, int iflags, int *oflags)
{

    if(!irt->stamp)
            assert (0);

    if (!irt->stamp->options.dfa) {
        return( pphfa(state, (ppinfo_t *)irt, dptr, dlen, blen, rptr, (ppcb_t)cb,
                   cbarg, iflags, oflags));
    }
    else
    {
        ppdfa_rword0_t        rmdata;
        ppdfa_rword1_t        rword;
        void            *infoent;
        ppdfa_strinfo_t        *si;
        ppdfa_strnode_t        *strn;
        ppdfa_regexinfo_t    *rin;
        int            i, ri, nr, soff, eoff;
        arg_dfa_t        a;
        a.state = (state_dfa_t *) state;
        a.rptr = rptr;
        a.cb = cb;
        a.cbarg = cbarg;
        if (Rinit (&a))
            return NULL;
    
        /*
            Process result words returned by hardware. Process only
            the first result word if '_1stonly' flag is set
        */
        rmdata.u64 = rptr[0];
        nr = (rmdata.s.rnum - (rmdata.s.m == 0)); 
        if (a.state->stats) {
            a.state->stats->scycle = hfa_os_get_cycle ();
            a.state->stats->tot_rwords = nr;
        }
        for (ri = 1; ri <= nr; ri++) {
            if (a.state->stats)
                a.state->stats->curr_rword = ri;
            rword.u64 = rptr[ri];
        
            /*
                Obtain the info entry for the given result word
            */
            if ((infoent = infoentry ((ppdfa_infort_t *)irt, rword)) == NULL) {
                /*
                    Fatal error. This should never happen
                */
                continue;
            }
        
            /*
                Report the pattern numbers of all the matches found
                at the current marked node
            */
            switch (((ppdfa_infort_t *)irt)->mode) {
            case PPDFA_MSTRINGS:
                si = infoent;
                for (i = 0; i < si->nent; ++i) {
                    strn = &((ppdfa_infort_t *)irt)->strnodes[si->ent[i]];
                    eoff = rword.s.pdboff;
                    soff = eoff - strn->patlen + 1;
                    Rreport1 (&a, strn->patno, 0, soff, eoff);
                }
                break;
            case PPDFA_MREGEX:
                rin = infoent;
                soff = PPDFA_INVAL;
                eoff = rword.s.pdboff;
                for (i = 0; i < rin->nent; ++i)
                    Rreport1 (&a, rin->ent[i], 0, soff, eoff);
                break;
            default:
                assert (0);
            }
        }
    return Rfinish (&a);
    }
}

/*
    Returns statistics that show pp progress
        state    - post-processing state whose stats are to be returned
*/
ppstats_t * 
ppgetstats (ppstate_t *_state, ppinfo_t *_irt)
{
    if (!_irt->stamp)
        assert (0);

    if (!_irt->stamp->options.dfa) {
        return (pphfa_getstats(_state));
    }
    else {
        state_dfa_t *state = (state_dfa_t *) _state;

        if (!state->stats)
            return NULL;

        state->stats->ccycle = hfa_os_get_cycle ();
        return state->stats;
    }
}

/*
      Assigns stats buffer to pp state and initialises it to zero. This should
      be called AFTER ppinit
*/
void 
ppassignstats (ppstate_t *_state, ppinfo_t *_irt, ppstats_t *stats)
{
    if (!_irt->stamp)
        assert (0);

    if (!_irt->stamp->options.dfa) {
        pphfa_assignstats(_state, stats);
    }
    else {
        state_dfa_t *state = (state_dfa_t *) _state;
        state->stats = stats;
        memset(stats, 0, sizeof(ppstats_t));
    }
}

/*
      Sets stats pointer in the state to NULL. This should be called BEFORE
      the stats buffer is freed.
*/
void 
ppcleanstats (ppstate_t *_state, ppinfo_t *_irt)
{
    if (!_irt->stamp)
        assert (0);

    if (!_irt->stamp->options.dfa) {
        pphfa_cleanstats(_state);
    }
    else {
        state_dfa_t *state = (state_dfa_t *) _state;
        state->stats = NULL;
    }
}

/*
    Converts the endianness of hfa.info to host endianness

        info    - pointer to hfa.info data
*/
void *
eswap (void *info)
{
    uint64_t    *u64p = (uint64_t *) info;
    uint32_t    *u32p, mode, ncc, nren, len, nent, nstrn;
    uint32_t    nt[7], st[7];
    uint16_t    *u16p;
    ppdfa_hashent_t    hent;
    int        i, j, noverflow;

    /*
      Endian swap start node info
    */
    u64p[0] = ppdfa_le64toh (u64p[0]);
    u64p[1] = ppdfa_le64toh (u64p[1]);
    u64p += 2;
    u32p = (uint32_t *) u64p;

    /*
      Endian swap mode
    */
    mode = u32p[0] = ppdfa_le32toh (u32p[0]);
    switch (mode) {
    case PPDFA_MSTRINGS:

        /*
          Endian swap strings info
        */
        nstrn = u32p[1] = ppdfa_le32toh (u32p[1]);
        u32p += 2;
        for (i = len = 0; i < nstrn; ++i) {

            /*
              Endian swap patno, patlen etc.
            */
            u32p[0] = ppdfa_le32toh (u32p[0]);
            u32p[1] = ppdfa_le32toh (u32p[1]);
            u32p[2] = ppdfa_le32toh (u32p[2]);
            u32p[3] = ppdfa_le32toh (u32p[3]);

            /*
              Skip trailing part
            */
            len += u32p[3];
            u32p += 4;
        }
        u32p = (uint32_t *) ((uint8_t *) u32p + len);
        break;
    case PPDFA_MREGEX:

        /*
          Endian swap regex info
        */
        ncc = u32p[1] = ppdfa_le32toh (u32p[1]);
        u32p += 2;
        u32p = (uint32_t *) ((char *) u32p + ncc * 256);
        nren = u32p[0] = ppdfa_le32toh (u32p[0]);
        u32p++;
        for (i = 0; i < nren; ++i) {
            u16p = (uint16_t *) u32p;
            u16p[0] = ppdfa_le16toh (u16p[0]);
            u16p++;
            u32p = (uint32_t *) u16p;
            u32p[0] = ppdfa_le32toh (u32p[0]);
            u32p[1] = ppdfa_le32toh (u32p[1]);
            u32p += 2;
        }
        break;
    default:
        assert (0);
    }

    /*
      Endian swap hash table offsets and no of entries
    */
    u32p[0] = ppdfa_le32toh (u32p[0]);
    nt[0] = u32p[1] = ppdfa_le32toh (u32p[1]);
    st[0] = u32p[2] = ppdfa_le32toh (u32p[2]);
    u32p[3] = ppdfa_le32toh (u32p[3]);
    nt[1] = u32p[4] = ppdfa_le32toh (u32p[4]);
    st[1] = u32p[5] = ppdfa_le32toh (u32p[5]);
    u32p[6] = ppdfa_le32toh (u32p[6]);
    nt[2] = u32p[7] = ppdfa_le32toh (u32p[7]);
    st[2] = u32p[8] = ppdfa_le32toh (u32p[8]);
    u32p[9] = ppdfa_le32toh (u32p[9]);
    nt[3] = u32p[10] = ppdfa_le32toh (u32p[10]);
    st[3] = u32p[11] = ppdfa_le32toh (u32p[11]);
    u32p[12] = ppdfa_le32toh (u32p[12]);
    nt[4] = u32p[13] = ppdfa_le32toh (u32p[13]);
    st[4] = u32p[14] = ppdfa_le32toh (u32p[14]);
    u32p[15] = ppdfa_le32toh (u32p[15]);
    nt[5] = u32p[16] = ppdfa_le32toh (u32p[16]);
    st[5] = u32p[17] = ppdfa_le32toh (u32p[17]);
    u32p[18] = ppdfa_le32toh (u32p[18]);
    nt[6] = u32p[19] = ppdfa_le32toh (u32p[19]);
    st[6] = u32p[20] = ppdfa_le32toh (u32p[20]);
    u32p += 21;

    /*
      Endian swap hash table entries
    */
    u64p = (uint64_t *) u32p;
    i = 0;
    noverflow = 0;
    for (i = 0; i < 7; ++i) {
        if (nt[i] == 0)
            continue;
        for (j = 0; j < st[i]; ++j) {
            hent.u64 = u64p[0] = ppdfa_le64toh (u64p[0]);
            u64p++;
            if (hent.s.bucket)
                noverflow += hent.s.nnptr;
        }
    }

    /*
      Endian swap overflown hash table entries
    */
    if (noverflow) {
        for (i = 0; i < noverflow; ++i) {
            u64p[0] = ppdfa_le64toh (u64p[0]);
            u64p++;
        }
    }

    /*
      Endian swap string/regex pattern numbers
    */
    u32p = (uint32_t *) u64p;
    while (1) {
        nent = u32p[0] = ppdfa_le32toh (u32p[0]);
        if (nent == ~0x0)
            break;
        switch (mode) {
        case PPDFA_MSTRINGS:
            u32p++;
            for (i = 0; i < nent; ++i)
                u32p[i] = ppdfa_le32toh (u32p[i]);
            u32p += nent;
            break;
        case PPDFA_MREGEX:
            nent = u32p[1] = ppdfa_le32toh (u32p[1]);
            u32p += 2;
            for (i = 0; i < nent; ++i)
                u32p[i] = ppdfa_le32toh (u32p[i]);
            u32p += nent;
            break;
        default:
            assert (0);
        }
    }

    /*
      Endian swap timestamp and return a pointer to it
    */
    u32p++;
    u32p[0] = ppdfa_le32toh (u32p[0]);
    u32p[1] = ppdfa_le32toh (u32p[1]);
    u32p[2] = ppdfa_le32toh (u32p[2]);
    u32p[3] = ppdfa_le32toh (u32p[3]);
    return u32p;
}

/*
    Returns a pointer to the info file entry of the given result word
    from hardware

        irt    - pointer to the info runtime
        rword    - hardware result word to lookup
*/
void *
infoentry (ppdfa_infort_t *irt, ppdfa_rword1_t rword)
{
    ppdfa_hashent_t    *hasht, *hashent;
    uint32_t    hashtsize;
    int        i, idx, found, nt;
    void        *entry;

    /*
        Select the hash table based on node type
    */
    switch (rword.s.f1) {
    case 0:
        hasht = irt->hasht0;
        hashtsize = irt->hashts0;
        break;
    case 1:
        hasht = irt->hasht1;
        hashtsize = irt->hashts1;
        break;
    case 2:
        hasht = irt->hasht2;
        hashtsize = irt->hashts2;
        break;
    case 3:
        hasht = irt->hasht3;
        hashtsize = irt->hashts3;
        break;
    case 4:
        hasht = irt->hasht4;
        hashtsize = irt->hashts4;
        break;
    case 5:
        hasht = irt->hasht5;
        hashtsize = irt->hashts5;
        break;
    case 6:
        hasht = irt->hasht6;
        hashtsize = irt->hashts6;
        break;
    default:
        assert (0);
    }
    found = 0;

    /*
        Hash the nnptr field and lookup into the hash table.
        If it is a bucket, search the bucket for requested entry
    */
    idx = hashidx (rword.s.nnptr, hashtsize - 1);
    if (hasht[idx].s.bucket) {
        hashent=(ppdfa_hashent_t*)((char*)irt->base+hasht[idx].s.off);
        nt = hasht[idx].s.nnptr;
        for (i = 0; i < nt; ++i) {
            if (hashent[i].s.nnptr == rword.s.nnptr) {
                entry = ((char*) irt->base + hashent[i].s.off);
                found = 1;
                break;
            }
        }
    }
    else if (hasht[idx].s.nnptr == rword.s.nnptr) {
        found = 1;
        entry = ((char *) irt->base + hasht[idx].s.off);
    }
    if (!found)
        return NULL;
    return entry;
}

/*
    Hashes the given value using the given mask

        value    - value to hash
        mask    - mask to use for hashing
*/
uint32_t
hashidx (uint32_t value, uint32_t mask)
{
    uint32_t    hash;

    hash = 0;
    hash = (hash << 4) ^ (hash >> 28) ^ ((value >> 24) & 0xff);
    hash = (hash << 4) ^ (hash >> 28) ^ ((value >> 16) & 0xff);
    hash = (hash << 4) ^ (hash >> 28) ^ ((value >> 8) & 0xff);
    hash = (hash << 4) ^ (hash >> 28) ^ (value & 0xff);
    return hash & mask;
}
