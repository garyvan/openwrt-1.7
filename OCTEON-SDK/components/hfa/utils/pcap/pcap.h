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
 * PCAP interface to all applications
 */
#ifndef _HFA_PCAP_H_
#define _HFA_PCAP_H_

#include <cvm-hfa-common.h>
#include <app-utils.h>

#define ENDIAN_SWAP_2_BYTE(_i) \
    ((((uint16_t)(_i)) & 0xff00) >> 8) | \
    ((((uint16_t)(_i)) & 0x00ff) << 8) 

#define ENDIAN_SWAP_4_BYTE(_i) \
    ((((uint32_t)(_i)) & 0xff) << 24)  | \
    ((((uint32_t)(_i)) & 0xff00) << 8) | \
    (((uint32_t)(_i) >> 8) & 0xff00) | \
    (((uint32_t)(_i) >> 24) & 0xff)  

#define ET_IP           0x0800
#define IPP_TCP         0x6
#define IPP_UDP         0x11

#define PCAP_FILE_MAGIC             0xa1b2c3d4
#define PCAP_FILE_MAGIC_REV         0xd4c3b2a1
#define check_magic(magic)          (((magic) == PCAP_FILE_MAGIC) ? 0 :       \
                                      ((magic) == PCAP_FILE_MAGIC_REV)?1:-1)
#define PACKET_MIN_LENGTH           (14+20+8)
#define PACKET_MAX_LENGTH           1514



typedef int bpf_int32;

typedef struct pcap_file_header
{
        uint32_t        magic;          /* TCPDUMP_MAGIC = 0xa1b2c3d4 */
        uint16_t        version_major;  /* 2 */
        uint16_t        version_minor;  /* 4 */
        bpf_int32       thiszone;       /* gmt to local correction */
        uint32_t        sigfigs;        /* accuracy of timestamps */
        uint32_t        snaplen;        /*maxlen saved portion of each pkt */
        uint32_t        linktype;       /* data link type (LINKTYPE_ * ) */
} __attribute ((packed)) pcap_file_header_t;

typedef struct
{
        bpf_int32       ts1;            /* time stamp */
        bpf_int32       ts2;            /* time stamp */
        uint32_t        caplen;         /* length of portion present */
        uint32_t        len;            /* length this packet (off wire) */
} __attribute ((packed)) pcap_sf_pkthdr_t;

typedef struct {
        uint8_t         dst[6];
        uint8_t         src[6];
        uint16_t        type;
} __attribute ((packed)) ethhdr_t;

typedef struct {
#if __BYTE_ORDER == __BIG_ENDIAN
        uint8_t     version:4;
        uint8_t     ihl:4;
#else 
        uint8_t     ihl:4;
        uint8_t     version:4;
#endif
        uint8_t     tos;
        uint16_t    totlen;
        uint16_t    id;
        uint16_t    fragoff;
        uint8_t     ttl;
        uint8_t     protocol;
        uint16_t    check;
        uint32_t    saddr;
        uint32_t    daddr;
} __attribute ((packed)) ipv4hdr_t;

typedef struct {
        uint16_t    source;
        uint16_t    dest;
        uint16_t    len;
        uint16_t    check;
} __attribute ((packed)) udphdr_t;

typedef struct {
        uint16_t    source;
        uint16_t    dest;
        uint32_t    seq;
        uint32_t    ack_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
        uint8_t    doff:4;
        uint8_t    res1:4;
#else 
        uint16_t    res1:4;
        uint16_t    doff:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
        uint8_t    cwr:1;
        uint8_t    ece:1;
        uint8_t    urg:1;
        uint8_t    ack:1;
        uint8_t    psh:1;
        uint8_t    rst:1;
        uint8_t    syn:1;
        uint8_t    fin:1;
#else 
        uint16_t    fin:1;
        uint16_t    syn:1;
        uint16_t    rst:1;
        uint16_t    psh:1;
        uint16_t    ack:1;
        uint16_t    urg:1;
        uint16_t    ece:1;
        uint16_t    cwr:1;
#endif
        uint16_t    window;
        uint16_t    check;
        uint16_t    urg_ptr;
} __attribute ((packed)) tcphdr_t;

typedef struct {
#if __BYTE_ORDER == __BIG_ENDIAN
        uint32_t    version:3;
        uint32_t    ptype:1;
        uint32_t    rsvd:1;
        uint32_t    exthdrf:1;
        uint32_t    seqnof:1;
        uint32_t    npduf:1;
        uint32_t    msgtype:8;
        uint32_t    totlen:16;
#else 
        uint32_t    totlen:16;
        uint32_t    msgtype:8;
        uint32_t    npduf:1;
        uint32_t    seqnof:1;
        uint32_t    exthdrf:1;
        uint32_t    rsvd:1;
        uint32_t    ptype:1;
        uint32_t    version:3;
#endif
        uint32_t    teid;
} __attribute ((packed)) gtphdr_t;

typedef struct {
#if __BYTE_ORDER == __BIG_ENDIAN
        uint32_t    cont:1;
        uint32_t    pdutype:4;
        uint32_t    trailer:2;
        uint32_t    retr:1;
        uint32_t    tisresp:1;
        uint32_t    tid:15;
        uint32_t    seqno:8;
#else 
        uint32_t    seqno:8;
        uint32_t    tid:15;
        uint32_t    tisresp:1;
        uint32_t    retr:1;
        uint32_t    trailer:2;
        uint32_t    pdutype:4;
        uint32_t    cont:1;
#endif
} __attribute ((packed)) wtphdr_t;

typedef union {
    udphdr_t    *pudp;
    tcphdr_t    *ptcp; 
}l4hdr_t;

hfa_return_t
pcap_file_init(void *, hfautils_payload_attr_t *);

hfa_return_t 
pcap_count_vpackets(hfautils_payload_attr_t *, uint64_t *);

hfa_return_t
pcap_parse_file (hfautils_payload_attr_t *);
#endif
