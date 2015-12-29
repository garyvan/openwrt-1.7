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
 * @file: APIs to deal with PCAP files
 * HFA_apps directly uses these APIs.
 */
#include <pcap.h>

hfa_return_t
pcap_file_init(void *pheader, hfautils_payload_attr_t *pattr)
{
    uint8_t                 swap=0;
    pcap_file_header_t      *phdr = NULL;
    uint64_t                npkts = 0;

    if(pheader){
        phdr = (pcap_file_header_t *)pheader;

        if(PCAP_FILE_MAGIC== phdr->magic || PCAP_FILE_MAGIC_REV== phdr->magic){
            swap = (PCAP_FILE_MAGIC != phdr->magic);
       
            if(swap){
                phdr->version_major = ENDIAN_SWAP_2_BYTE(phdr->version_major);
                phdr->version_minor = ENDIAN_SWAP_2_BYTE(phdr->version_minor);
                phdr->snaplen = ENDIAN_SWAP_4_BYTE(phdr->snaplen);
            }
            LOG ("PCAP File Version: %d.%d. Snap Length=%d\n", 
                phdr->version_major, phdr->version_minor, phdr->snaplen);
            pattr->phdr = phdr;
        } else {
            hfa_err (CVM_HFA_EBADFILE, ("Unable to read PCAP file\n"));
            return HFA_FAILURE;
        }
        if(HFA_SUCCESS != pcap_count_vpackets(pattr, &npkts)) {
            return HFA_FAILURE;
        }
        if(!npkts){
            ERR("No TCP/UDP packets found in provided PCAP file\n");
            return HFA_FAILURE;
        }
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}

hfa_return_t 
pcap_count_vpackets(hfautils_payload_attr_t *pattr, uint64_t *valid_pkts)
{
    pcap_sf_pkthdr_t        sfhdr;
    ethhdr_t                eth;
    ipv4hdr_t               iph;
    udphdr_t                udph;
    tcphdr_t                tcph;
    uint16_t                pkt_len = 0, ip_hdr_len = 0, tcp_udp_hdr_len = 0;
    uint32_t                caplen = 0, offset = 0;
    uint8_t                 swap = 0;
     
    /**Parse hdr*/
    swap = (PCAP_FILE_MAGIC != pattr->phdr->magic);
    
    while (!gzeof(pattr->gzf)) {
        pkt_len = ip_hdr_len = tcp_udp_hdr_len = 0;

        if (fd_read (pattr->gzf, &sfhdr, sizeof(pcap_sf_pkthdr_t)) != 
                                         sizeof(pcap_sf_pkthdr_t)) {
            if(gzeof(pattr->gzf))
                break;
            ERR ("unable to read packet header in PCAP\n");
            return HFA_FAILURE;
        }
        if (swap) {
            caplen = ENDIAN_SWAP_4_BYTE(sfhdr.caplen);
        }
        else
            caplen = sfhdr.caplen;
        offset = caplen;
        DBG("caplen: %u\n", caplen);
        if (caplen < PACKET_MIN_LENGTH || caplen > PACKET_MAX_LENGTH){
            gzseek(pattr->gzf, offset, SEEK_CUR);
            continue;
        }
        if (fd_read (pattr->gzf, &eth, sizeof(ethhdr_t)) != sizeof(ethhdr_t)){
            if(gzeof(pattr->gzf))
                break;
            ERR ("unable to read ethernet header in PCAP\n");
            return HFA_FAILURE;
        }
        offset = caplen - sizeof(ethhdr_t);
#if defined(__i386__) || defined(__x86_64__)
        eth.type = ENDIAN_SWAP_2_BYTE(eth.type);
#endif
        if(eth.type != ET_IP) {
            DBG("continue\n");
            gzseek(pattr->gzf, offset, SEEK_CUR);
            continue;
        }
        if (fd_read (pattr->gzf, &iph, sizeof(ipv4hdr_t))!= sizeof(ipv4hdr_t)){
            if(gzeof(pattr->gzf))
                break;
            ERR ("unable to read ip header in PCAP\n");
            return HFA_FAILURE;
        }
        offset -= sizeof(ipv4hdr_t);
        pkt_len = iph.totlen;
#if defined(__i386__) || defined(__x86_64__)
        pkt_len = ENDIAN_SWAP_2_BYTE(pkt_len);
#endif
        DBG("pktlen = %u\n", pkt_len);
        ip_hdr_len = (iph.ihl)*4;
        gzseek(pattr->gzf, ip_hdr_len - sizeof(ipv4hdr_t), SEEK_CUR);
        offset -= (ip_hdr_len - sizeof(ipv4hdr_t));
        DBG("iphdrlen = %d\n", ip_hdr_len);
        switch (iph.protocol){
            case IPP_TCP: 
                if (fd_read (pattr->gzf, &tcph, sizeof(tcphdr_t)) != 
                        sizeof(tcphdr_t)) {
                    if(gzeof(pattr->gzf))
                        break;
                    ERR ("unable to read tcp header in PCAP\n");
                    return HFA_FAILURE;
                }
                offset -= sizeof(tcphdr_t);
                tcp_udp_hdr_len = (tcph.doff)*4;
                DBG("tcp hdr len %d\n", tcp_udp_hdr_len);
                gzseek(pattr->gzf, tcp_udp_hdr_len - sizeof(tcphdr_t),SEEK_CUR);
                offset -= (tcp_udp_hdr_len - sizeof(tcphdr_t));
                break;

            case IPP_UDP:
                if (fd_read (pattr->gzf, &udph, sizeof(udphdr_t)) != 
                        sizeof(udphdr_t)) {
                    if(gzeof(pattr->gzf))
                        break;
                    ERR ("unable to read udp header in PCAP\n");
                    return HFA_FAILURE;
                }
                tcp_udp_hdr_len = sizeof (udphdr_t);
                DBG("udp hdr len %d\n", tcp_udp_hdr_len);
                offset -= tcp_udp_hdr_len;
                break;
            default:
                gzseek(pattr->gzf, offset, SEEK_CUR);
                continue;
        }
        if ((pkt_len - (ip_hdr_len + tcp_udp_hdr_len)) <=0){
            gzseek(pattr->gzf, offset, SEEK_CUR);
            continue;
        }
        gzseek(pattr->gzf, offset, SEEK_CUR);
        (*valid_pkts)++;
    }
    gzseek(pattr->gzf, sizeof(pcap_file_header_t), SEEK_SET);
    return HFA_SUCCESS;
}
        
hfa_return_t
pcap_parse_file (hfautils_payload_attr_t *pattr)
{
    pcap_sf_pkthdr_t        sfhdr;
    ethhdr_t                eth;
    ipv4hdr_t               iph;
    udphdr_t                udph;
    tcphdr_t                tcph;
    uint16_t                pkt_len = 0, ip_hdr_len = 0, tcp_udp_hdr_len = 0;
    uint32_t                caplen = 0, offset = 0;
    int                     swap = 0;
     
    /**Parse hdr*/
    swap = (PCAP_FILE_MAGIC != pattr->phdr->magic);
    pattr->psize = 0;
    
    while (!gzeof(pattr->gzf)) {
        pkt_len = ip_hdr_len = tcp_udp_hdr_len = 0;

        if (fd_read (pattr->gzf, &sfhdr, sizeof(pcap_sf_pkthdr_t)) != 
                                        sizeof(pcap_sf_pkthdr_t)) {
            if(gzeof(pattr->gzf))
                break;
            ERR ("unable to read packet header in PCAP\n");
            return HFA_FAILURE;
        }
        if (swap) {
            caplen = ENDIAN_SWAP_4_BYTE(sfhdr.caplen);
        }
        else
            caplen = sfhdr.caplen;
        offset = caplen;
        DBG("caplen: %u\n", caplen);
        if (caplen < PACKET_MIN_LENGTH || caplen > PACKET_MAX_LENGTH){
            gzseek(pattr->gzf, offset, SEEK_CUR);
            continue;
        }
        if (fd_read (pattr->gzf, &eth, sizeof(ethhdr_t))!= sizeof(ethhdr_t)) {
            if(gzeof(pattr->gzf))
                break;
            ERR ("unable to read ethernet header in PCAP\n");
            return HFA_FAILURE;
        }
        offset = caplen - sizeof(ethhdr_t);
#if defined(__i386__) || defined(__x86_64__)
        eth.type = ENDIAN_SWAP_2_BYTE(eth.type);
#endif
        if(eth.type != ET_IP) {
            DBG("continue\n");
            gzseek(pattr->gzf, offset, SEEK_CUR);
            continue;
        }
        if (fd_read (pattr->gzf, &iph, sizeof(ipv4hdr_t))!= sizeof(ipv4hdr_t)) {
            if(gzeof(pattr->gzf))
                break;
            ERR ("unable to read ip header in PCAP\n");
            return HFA_FAILURE;
        }
        offset -= sizeof(ipv4hdr_t);
        pkt_len = iph.totlen;
#if defined(__i386__) || defined(__x86_64__)
        pkt_len = ENDIAN_SWAP_2_BYTE(pkt_len);
#endif
        DBG("pktlen = %u\n", pkt_len);
        ip_hdr_len = (iph.ihl)*4;
        gzseek(pattr->gzf, ip_hdr_len - sizeof(ipv4hdr_t), SEEK_CUR);
        offset -= (ip_hdr_len - sizeof(ipv4hdr_t));
        DBG("iphdrlen = %d\n", ip_hdr_len);
        switch (iph.protocol){
            case IPP_TCP: 
                if (fd_read (pattr->gzf, &tcph, sizeof(tcphdr_t)) != 
                        sizeof(tcphdr_t)) {
                    if(gzeof(pattr->gzf))
                        break;
                    ERR ("unable to read tcp header in PCAP\n");
                    return HFA_FAILURE;
                }
                offset -= sizeof(tcphdr_t);
                tcp_udp_hdr_len = (tcph.doff)*4;
                DBG("tcp hdr len %d\n", tcp_udp_hdr_len);
                gzseek(pattr->gzf, tcp_udp_hdr_len - sizeof(tcphdr_t),SEEK_CUR);
                offset -= (tcp_udp_hdr_len - sizeof(tcphdr_t));
                break;

            case IPP_UDP:
                if (fd_read (pattr->gzf, &udph, sizeof(udphdr_t)) != 
                        sizeof(udphdr_t)) {
                    if(gzeof(pattr->gzf))
                        break;
                    ERR ("unable to read udp header in PCAP\n");
                    return HFA_FAILURE;
                }
                tcp_udp_hdr_len = sizeof (udphdr_t);
                DBG("udp hdr len %d\n", tcp_udp_hdr_len);
                offset -= tcp_udp_hdr_len;
                break;
            default:
                gzseek(pattr->gzf, offset, SEEK_CUR);
                continue;
        }
        if ((pkt_len - (ip_hdr_len + tcp_udp_hdr_len)) <=0){
            gzseek(pattr->gzf, offset, SEEK_CUR);
            continue;
        }
        pattr->npkts++;
        pattr->psize = pkt_len - ip_hdr_len - tcp_udp_hdr_len;
        DBG("offset %u psize = %u\n", offset, pattr->psize);
        pattr->remain = offset - pattr->psize;
        break;
    }
#ifdef APP_DEBUG
    LOG("************\n");
    LOG("Pkt_Num: %lu Pkt_Caplen:%x\n", pattr->npkts, caplen);
    LOG("IP src=0x%04x ", iph.saddr);
    LOG(   "dst=0x%04x\n", iph.daddr);
    if (iph.protocol == IPP_TCP) {
        LOG("TCP Port src=%u dst=%u\n", tcph.source, tcph.dest);
    } 
    else if (iph.protocol == IPP_UDP) {
        LOG("UDP Port src=%u dst=%u\n", udph.source, udph.dest);
    }
#endif       
    return (HFA_SUCCESS); 
}

