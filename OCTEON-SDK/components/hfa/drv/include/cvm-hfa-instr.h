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
 * This file contains APIs to create HFA instruction to be submitted to 
 * hardware
 *
 */
#ifndef __CVM_HFA_INSTR_H__
#define __CVM_HFA_INSTR_H__

/*Typedefs*/
/**Gather/Iovec Entry physical*/
typedef union {
   uint64_t u64;
   struct {
#ifdef __BIG_ENDIAN_BITFIELD
      uint64_t size:24;
      uint64_t addr:40;
#else
      uint64_t addr:40;
      uint64_t size:24;
#endif
   } s;
} cvm_hfa_gather_entry_t;

/**
 * Different types of instructions supported by HFA engine
 */ 
typedef enum {
    CVMX_HFA_ITYPE_MEMLOAD    = 0,
    CVMX_HFA_ITYPE_CACHELOAD  = 1,
    CVMX_HFA_ITYPE_GRAPHFREE  = 3,
    CVMX_HFA_ITYPE_GRAPHWALK  = 4
} cvm_hfa_itype_t;

/**
 * Type for boolean settings
 */ 
typedef enum {
        CVMX_HFA_FALSE   = 0,
        CVMX_HFA_TRUE    = 1
} cvm_hfa_bool_t;

/**
 * Different reason codes returned by HFA engine
 */ 
typedef enum {
        HFA_REASON_DDONE   = 0L,
        HFA_REASON_ERR     = 1L,
        HFA_REASON_RFULL   = 2L,
        HFA_REASON_TERM    = 3L,
        HFA_REASON_GDONE   = 4L,
        HFA_REASON_NOGRAPH = 5L,
        HFA_REASON_GERR    = 6L
} cvm_hfa_reason_t;

/**
 * Utility routine to convert HFA reason codes to strings
 */
#define CVM_HFA_REASON_STR(x)   (((x) == HFA_REASON_DDONE)   ? "DATA_GONE" : \
                                (((x) == HFA_REASON_RFULL)   ? "FULL"      : \
                                (((x) == HFA_REASON_ERR)     ? "PERR"      : \
                                (((x) == HFA_REASON_GDONE)   ? "GDONE"     : \
                                (((x) == HFA_REASON_NOGRAPH) ? "NOGRAPH"   : \
                                (((x) == HFA_REASON_TERM)    ? "TERM"      : \
                                                              "GERR"))))))

/**
 * Type for Result Words(other than RWORD0). The result buffer contains an array
 * of result words prefixed by cvm_hfa_rmdata_t
 *
 * Refer to HRM for field details
 */
typedef union {
    uint64_t    u64;
    struct {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t    offset:16;
        /** can be saved to cvm_hfa_snode_t::dnodeid */
        uint64_t    f3:9;
        /** can be saved to cvm_hfa_snode_t::hash */
        uint64_t    f2:8;
        /** can be saved to cvm_hfa_snode_t::ntype */
        uint64_t    f1:3;
        uint64_t    userdata:1;
        /** can be saved to cvm_hfa_snode_t::nextnode */
        uint64_t    nextnode:27;
#else
        uint64_t    nextnode:27;
        uint64_t    userdata:1;
        uint64_t    f1:3;
        uint64_t    f2:8;
        uint64_t    f3:9;
        uint64_t    offset:16;
#endif
    } s;
} cvm_hfa_rword_t;
/**
 * Type for Result Word metadata - RWORD0. The result buffer starts with RWORD0
 * followed by an array of cvm_hfa_rword_t
 *
 * Refer to HRM for field details
 */
typedef union {
    uint64_t    u64;
    struct {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t    reason:3;
        uint64_t    itype:3;
        uint64_t    rsvd:38;
        uint64_t    f5:2;
        uint64_t    lastmarked:1;
        uint64_t    done:1;
        uint64_t    nument:16;
#else
        uint64_t    nument:16;
        uint64_t    done:1;
        uint64_t    lastmarked:1;
        uint64_t    f5:2;
        uint64_t    rsvd:38;
        uint64_t    itype:3;
        uint64_t    reason:3;
#endif
    } s;
} cvm_hfa_rmdata_t;

/**
 * Type for saved node data(WORD0).
 * The HFA graph comes with the initial snode in the info section. A partial
 * search will return fields which should be saved from cvm_hfa_rword_t and
 * submitted back to the HFA on the next search to resume the partial search
 */ 
typedef union {
    uint64_t        u64;
    struct {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t        zerobdn:1;
        uint64_t        nbdnodes:6;
        uint64_t        ndnodes:9;
        /** 
         * saved from cvm_hfa_rword_t::f3 and set to corresponding field in
         * @ref cvmx_hfa_command_t
         */
        uint64_t        dnodeid:9;
        /** 
         * saved from cvm_hfa_rword_t::f2 and set to corresponding field in
         * @ref cvmx_hfa_command_t
         */
        uint64_t        hash:8;
        /** 
         * saved from cvm_hfa_rword_t::f1 and set to corresponding field in
         * @ref cvmx_hfa_command_t
         */
        uint64_t        ntype:3;
        uint64_t        smdtomtype:1;
        /** 
         * saved from cvm_hfa_rword_t::nextnode and set to corresponding field
         * in @ref cvmx_hfa_command_t
         */
        uint64_t        nextnode:27;
#else
        uint64_t        nextnode:27;
        uint64_t        smdtomtype:1;
        uint64_t        ntype:3;
        uint64_t        hash:8;
        uint64_t        dnodeid:9;
        uint64_t        ndnodes:9;
        uint64_t        nbdnodes:6;
        uint64_t        zerobdn:1;
#endif
    } s;
} cvm_hfa_snode_t;
/**
 * Type for saved node data(WORD1).
 * The HFA graph comes with the initial snode2 in the info section.
 */ 
typedef union {
        uint64_t            u64;
        struct {
#ifdef __BIG_ENDIAN_BITFIELD
            uint64_t        rsvd0:33;
            uint64_t        srepl:2;
            uint64_t        rsvd1:29;
#else
            uint64_t        rsvd1:29;
            uint64_t        srepl:2;
            uint64_t        rsvd0:33;
#endif
        } s;
} cvm_hfa_snode2_t;

/**
 * Initialize the HFA instruction.
 * Clears @b command to zero and sets its instruction type to @b itype
 *
 * @param command pointer to instruction
 * @param itype instruction type
 *
 * @return Zero on success, negative on failure
 */
static inline int cvm_hfa_instr_init(cvmx_hfa_command_t *command,
                                     cvm_hfa_itype_t itype)
{
        memset (command, 0, sizeof *command);
#ifdef HFA_STRICT_CHECK
        switch(itype){
            case CVMX_HFA_ITYPE_GRAPHWALK:
                hfa_dbg("InstrInit: Search\n");
            break;
            case CVMX_HFA_ITYPE_MEMLOAD:
                hfa_dbg("InstrInit: MemLoad\n");
            break;
            case CVMX_HFA_ITYPE_CACHELOAD:
                hfa_dbg("InstrInit: CacheLoad\n");
            break;
            case CVMX_HFA_ITYPE_GRAPHFREE:
                hfa_dbg("InstrInit: GraphFree\n");
            break;
            default:
                return (-1);
        }
#endif
        command->word0.itype = itype;
        return 0;
}

/**
 * Sets @b f1 in the GRAPHWALK instruction. @b f1 comes from the
 * cvm_hfa_snode_t::ntype in the graph info section.
 *
 * @param command pointer to instruction
 * @param f1 node type
 *
 * @return void
 */
static inline void cvm_hfa_instr_setf1(cvmx_hfa_command_t *command, uint32_t f1)
{
    command->word0.walk.f1 = f1;
    hfa_dbg("f1: 0x%x\n", f1);
}      

/**
 * Sets @b snode in the instruction. @b snode is the cvm_hfa_snode_t in the
 * graph info section.
 *
 * @param command pointer to instruction
 * @param snode saved node
 *
 * @return void
 */
static inline void cvm_hfa_instr_setsnode(cvmx_hfa_command_t *command, 
                                          uint64_t snode)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            break;
        default:
            hfa_dbg("snode: 0x%lx\n", snode);
            return ;
    }
#endif
    command->word0.walk.snode = snode;
}
        
/**
 * Sets @b dbase in the CACHELOAD instruction.
 *
 * @param command pointer to instruction
 * @param dbase RAM2 address
 *
 * @return void
 */
static inline void cvm_hfa_instr_setdbase(cvmx_hfa_command_t *command,
                                          uint64_t dbase) 
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_CACHELOAD:
            break;
        default:
            hfa_dbg("dbase: 0x%lx\n", dbase);
            return ;
    }
#endif
    command->word0.cload.dbase = dbase;
}

/**
 * Sets @b cbase in the CACHELOAD instruction.
 *
 * @param command pointer to instruction
 * @param cbase RAM1 address
 *
 * @return void
 */
static inline void cvm_hfa_instr_setcbase(cvmx_hfa_command_t *command,
                                          uint64_t cbase )
{
#ifdef  HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_CACHELOAD:
            break;
        default:
            hfa_dbg("cbase: 0x%lx\n", cbase);
            return ;
    }
#endif
    command->word0.cload.cbase = cbase;
}

/**
 * Sets @b gm in the instruction.
 *
 * @param command pointer to instruction
 * @param gm gather mode
 *
 * @return void
 */
static inline void cvm_hfa_instr_setgather(cvmx_hfa_command_t *command,
                                           cvm_hfa_bool_t gm)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word0.walk.gather_mode = gm;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word0.mload.gather_mode = gm;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word0.cload.gather_mode = gm;
            break;
        default: 
            break;
    }
    hfa_dbg("Gather Mode: %s\n", ((gm) ? "Yes": "No"));
}

/**
 * Sets @b le in the instruction.
 *
 * @param command pointer to instruction
 * @param le little-endian
 *
 * @return void
 */
static inline void cvm_hfa_instr_setle(cvmx_hfa_command_t *command, 
                                       cvm_hfa_bool_t le)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word0.walk.little_endian = le;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word0.mload.little_endian = le;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word0.cload.little_endian = le;
            break;
        default: 
            break;
    }
    hfa_dbg("Little Endian: %s\n", ((le) ? "Yes": "No"));
}

/**
 * Sets @b store_full in the instruction.
 * Can be used to improve writes to the result buffer.
 *
 * @param command pointer to instruction
 * @param store_full Enable STORE-FULL L2C operation usage.
 *
 * @return void
 */
static inline void cvm_hfa_instr_setstorefull(cvmx_hfa_command_t *command, 
                                              cvm_hfa_bool_t store_full)
{
    command->word0.store_full = store_full;
}

/**
 * Sets @b load_through in the instruction.
 *
 * @param command pointer to instruction
 * @param load_through Enable LOAD-THROUGH L2C operation usage.
 *
 * @return void
 */
static inline void cvm_hfa_instr_setloadthrough(cvmx_hfa_command_t *command,
                                                cvm_hfa_bool_t load_through)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word0.walk.load_through = load_through;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word0.mload.load_through = load_through;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word0.cload.load_through = load_through;
            break;
        default: 
            break;
    }
    hfa_dbg("Loadthrough: %s\n", ((load_through) ? "Yes": "No"));
}

/**
 * Sets @b smallmem in the GRAPHWALK instruction.
 *
 * @param command pointer to instruction
 * @param smallmem small memory nodes in graphs
 *
 * @return void
 */
static inline void cvm_hfa_instr_setsmallmem(cvmx_hfa_command_t *command,
                                             cvm_hfa_bool_t smallmem)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            break;
        default:
            hfa_dbg("smallmem: 0x%x\n", smallmem);
            return ;
    }
#endif
    command->word0.walk.small = smallmem;
}

/**
 * Sets @b mbase in the GRAPHWALK/MEMLOAD instruction.
 *
 * @param command pointer to instruction
 * @param mbase DDR address
 *
 * @return void
 */
static inline void cvm_hfa_instr_setmbase(cvmx_hfa_command_t *command, 
                                          uint64_t mbase)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word0.walk.mbase = mbase;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word0.mload.mbase = mbase;
            break;
        default: 
            break;
    }
    hfa_dbg("mbase: 0x%lx\n", mbase);
}

/**
 * Sets @b dsize in the CACHELOAD instruction.
 *
 * @param command pointer to instruction
 * @param dsize number of RAM2 entries
 *
 * @return void
 */
static inline void cvm_hfa_instr_setdsize(cvmx_hfa_command_t *command,
                                          uint32_t dsize)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_CACHELOAD:
            break;
        default:
            hfa_dbg("DSIZE: %d\n", dsize);
            return ;
    }
#endif
    command->word0.cload.dsize = dsize;
}

/**
 * Sets @b pgid in the CACHELOAD instruction.
 *
 * @param command pointer to instruction
 * @param pgid physical graph id
 *
 * @return void
 */
static inline void cvm_hfa_instr_setpgid(cvmx_hfa_command_t *command,
                                         uint32_t pgid)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_CACHELOAD:
            break;
        default:
            hfa_dbg("Pgid: %d\n", pgid);
            return ;
    }
#endif
    command->word0.cload.pgid = pgid;
}

/**
 * Sets @b rmax in the CACHELOAD instruction.
 *
 * @param command pointer to instruction
 * @param rmax max. result buffer words
 *
 * @return void
 */
static inline void cvm_hfa_instr_setrmax(cvmx_hfa_command_t *command,
                                         uint32_t rmax)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word1.walk.rmax = rmax;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word1.mload.rmax = rmax;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word1.cload.rmax = rmax;
            break;
        default: 
            break;
    }
    hfa_dbg("RMax: 0x%x\n", rmax);
}

/**
 * Sets @b f2 in the GRAPHWALK instruction. @b f2 comes from the
 * cvm_hfa_snode2_t::hash in the graph info section.
 *
 * @param command pointer to instruction
 * @param f2 hash
 *
 * @return void
 */
static inline void cvm_hfa_instr_setf2(cvmx_hfa_command_t *command, uint32_t f2)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            break;
        default:
            hfa_dbg("f2: 0x%x\n", f2);
            return ;
    }
#endif 
    command->word1.walk.f2 = f2;
}

/**
 * Sets @b rptr in the instruction.
 *
 * @param command pointer to instruction
 * @param rptr result pointer
 *
 * @return void
 */
static inline void cvm_hfa_instr_setrptr(cvmx_hfa_command_t *command, 
                                         uint64_t rptr)
{
        command->word1.rptr = rptr;
        hfa_dbg("Rptr: 0x%lx\n", rptr);
}

/**
 * Sets @b dlen in the instruction.
 *
 * @param command pointer to instruction
 * @param dlen input data length
 *
 * @return void
 */
static inline void cvm_hfa_instr_setdlen(cvmx_hfa_command_t *command, 
                                         uint32_t dlen)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word2.walk.dlen = dlen;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word2.mload.dlen = dlen;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word2.cload.dlen = dlen;
            break;
        default: 
            break;
    }
    hfa_dbg("dlen: %d\n", dlen);
}

/**
 * Sets @b f5 in GRAPHWALK instruction. @b f5 is the cvm_hfa_snode2_t::srepl
 * in the graph info section.
 *
 * @param command pointer to instruction
 * @param f5 replication setting 
 *
 * @return void
 */
static inline void cvm_hfa_instr_setf5(cvmx_hfa_command_t *command, uint32_t f5)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            break;
        default:
            hfa_dbg("f5: 0x%x\n", f5);
            return ;
    }
#endif
    command->word2.walk.f5 = f5;
}

/**
 * Sets @b clmsk in the instruction.
 *
 * @param command pointer to instruction
 * @param clmsk cluster mask
 *
 * @return void
 */
static inline void cvm_hfa_instr_setclmsk(cvmx_hfa_command_t *command,
                                          uint32_t clmsk)
{
        command->word2.clmsk = clmsk;
        hfa_dbg("clmsk: 0x%x\n", clmsk);
}

/**
 * Sets @b dptr in the instruction.
 *
 * @param command pointer to instruction
 * @param dptr input data pointer
 *
 * @return void
 */
static inline void cvm_hfa_instr_setdptr(cvmx_hfa_command_t *command,
                                         uint64_t dptr)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word2.walk.dptr = dptr;
            break;
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word2.mload.dptr = dptr;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word2.cload.dptr = dptr;
            break;
        default: 
            break;
    }
    hfa_dbg("Dptr: 0x%lx\n", dptr);
}

/**
 * Sets @b vgid in the instruction.
 *
 * @param command pointer to instruction
 * @param vgid virtual graph id
 *
 * @return void
 */
static inline void cvm_hfa_instr_setvgid(cvmx_hfa_command_t *command,
                                         uint32_t vgid)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            command->word3.walk.vgid = vgid;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word3.cload.vgid = vgid;
            break;
        case CVMX_HFA_ITYPE_GRAPHFREE:
            command->word3.free.vgid = vgid;
            break;
        default: 
            break;
    }
    hfa_dbg("vgid: %d\n", vgid);
}

/**
 * Sets @b f3 in the GRAPHWALK instruction. @b f3 comes from the
 * cvm_hfa_snode_t::dnodeid in the graph info section.
 *
 * @param command pointer to instruction
 * @param f3 dnodeid
 *
 * @return void
 */
static inline void cvm_hfa_instr_setf3(cvmx_hfa_command_t *command, uint32_t f3)
{
#ifdef HFA_STRICT_CHECK
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_GRAPHWALK:
            break;
        default:
            hfa_dbg("f3: 0x%x\n", f3);
            return ;
    }
#endif
    command->word3.walk.f3 = f3;
}

/**
 * Sets @b f4 in the MEMLOAD/CACHELOAD instruction. @b f4 is set to
 * cvm_hfa_snode_t::nbdnodes+1 if cvm_hfa_snode_t::zerobdn is set. @b f4 is zero
 * otherwise.
 *
 * @param command pointer to instruction
 * @param f4 number of bdn
 *
 * @return void
 */
static inline void cvm_hfa_instr_setf4(cvmx_hfa_command_t *command, uint32_t f4)
{
    switch(command->word0.itype) {
        case CVMX_HFA_ITYPE_MEMLOAD:
            command->word3.mload.f4 = f4;
            break;
        case CVMX_HFA_ITYPE_CACHELOAD:
            command->word3.cload.f4 = f4;
            break;
        default: 
            break;
    }
    hfa_dbg("f4: %d\n", f4);
}

/**
 * Sets @b wqptr instruction.
 *
 * @param command pointer to instruction
 * @param wqptr WQE pointer
 *
 * @return void
 */
static inline void cvm_hfa_instr_setwqptr(cvmx_hfa_command_t *command,
                                          uint64_t wqptr)
{
        command->word3.wqptr = wqptr;
}

/* API to get information from a result */
/**
 * Gets @b reason from RWORD0
 *
 * @param rmdata result word metadata
 * @param reason reason code to indicate success/failure of operation
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getreason(cvm_hfa_rmdata_t *rmdata, uint32_t *reason)
{
        *reason = rmdata->s.reason;
}

/**
 * Gets @b itype from RWORD0
 *
 * @param rmdata result word metadata
 * @param itype instruction type @ref cvm_hfa_itype_t
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getitype(cvm_hfa_rmdata_t *rmdata,
                                         uint32_t *itype)
{
        *itype = rmdata->s.itype;
}

/**
 * Gets @b f5 from RWORD0
 *
 * @param rmdata result word metadata
 * @param f5 get cvm_hfa_snode2_t::srepl setting of the graph
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getf5(cvm_hfa_rmdata_t *rmdata, uint32_t *f5)
{
        *f5 = rmdata->s.f5;
}

/**
 * Gets @b done from RWORD0
 *
 * @param rmdata result word metadata
 * @param done indicates whether the instruction is completed or still pending.
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getdone(volatile cvm_hfa_rmdata_t *rmdata,
                                        cvm_hfa_bool_t *done)
{
        *done = rmdata->s.done;
}
/**
 * Gets @b rnum from RWORD0
 *
 * @param rmdata result word metadata
 * @param rnum Number of cvm_hfa_rword_t entries
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getrnum(cvm_hfa_rmdata_t *rmdata,
                                        uint32_t *rnum)
{
        *rnum = rmdata->s.nument;
}
/**
 * Gets @b f3 from RWORD0
 *
 * @param rmdata result word metadata
 * @param f3 get cvm_hfa_snode_t::dnodeid
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getf3(cvm_hfa_rmdata_t *rmdata, uint32_t *f3)
{
        cvm_hfa_rword_t *rword = NULL;
        uint64_t         _rword = 0;

        _rword = (((uint64_t *) rmdata)[rmdata->s.nument]);
        rword = (cvm_hfa_rword_t *) &_rword;

        *f3   = rword->s.f3;
}
/**
 * Gets @b f2 from RWORD0
 *
 * @param rmdata result word metadata
 * @param f2 get cvm_hfa_snode_t::hash
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getf2(cvm_hfa_rmdata_t *rmdata, uint32_t *f2)
{
        cvm_hfa_rword_t *rword = NULL;
        uint64_t         _rword = 0;

        _rword = (((uint64_t *) rmdata)[rmdata->s.nument]);
        rword = (cvm_hfa_rword_t *) &_rword;

        *f2   = rword->s.f2;
}
/**
 * Gets @b f1 from RWORD0
 *
 * @param rmdata result word metadata
 * @param f1 get cvm_hfa_snode_t::ntype
 *
 * @return void
 */
static inline void cvm_hfa_rslt_getf1(cvm_hfa_rmdata_t *rmdata, uint32_t *f1)
{
        cvm_hfa_rword_t *rword = NULL;
        uint64_t         _rword = 0;

        _rword = (((uint64_t *) rmdata)[rmdata->s.nument]);
        rword = (cvm_hfa_rword_t *) &_rword;

        *f1   = rword->s.f1;
}

#endif /* __CVMX_HFA_H__ */
