 	 	/***********************license start***************                              
* Copyright (c) 2008-2015 Cavium Inc. All rights reserved.
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



#ifdef CAV_OCT_SE

/* Cavium Networks Inc */
#include <stdio.h>
#include <stdlib.h>
#ifndef SDK_3_1
#include <osapi.h>
#include <cvm-hfao.h>
#endif
#include <sha1.h>
#include "snort_debug.h"
#include "fpcreate.h"
#include <sys/queue.h>
#include <cav_oct_hfa.h>
#include <cvmx.h>
#include <cvmx-coremask.h>
#include <cvmx-bootmem.h>
#include <cvmx-mgmt-port.h>
#ifdef CAV_OCT_SE
#include "memfsmap.h"
#endif
#include <cvmx-pow.h>


#include<stdarg.h>
#include <time.h>
#include <string.h>
#include <util.h>
#include <syslog.h>

#define TBUF_LEN        2048
#define FMT_LEN         1024
#define INTERNALLOG     LOG_ERR|LOG_CONS|LOG_PERROR|LOG_PID

static int      LogStat = 0;            /* status bits, set by openlog() */
static char     *LogTag = NULL;       /* string to tag the entry with */
static int      LogFacility = LOG_USER; /* default facility code */
static int      LogMask = 0xff;         /* mask of priorities to be logged */


#define MGMT_PORT 0
/* #define MGMT_DEBUG */

#define LOCAL_UDP_PORT        2981

#define cav_ar_sha(ap)      (((caddr_t)((ap)+1)) +   0)
#define cav_ar_spa(ap)      (((caddr_t)((ap)+1)) +   (ap)->ar_hln)
#define cav_ar_tha(ap)      (((caddr_t)((ap)+1)) +   (ap)->ar_hln + (ap)->ar_pln)
#define cav_ar_tpa(ap)      (((caddr_t)((ap)+1)) + 2*(ap)->ar_hln + (ap)->ar_pln)

typedef struct _port_config
{
	uint8_t mac_addr[6];
	uint32_t ip_addrs;
} port_config_t;


typedef struct _remote_logging_config
{
	port_config_t local_addr;
	port_config_t remote_addr;
	uint16_t local_port;
	uint16_t remote_port;
	int rhost_present;
	int octeon_lport;
} remote_logging_config_t;

typedef struct _IPhdr
{
	uint32_t ip_v:4;            /* version */
	uint32_t ip_hl:4;           /* header length */
	uint32_t ip_tos:8;          /* type of service */
	uint32_t ip_len:16;         /* total length */
	uint32_t ip_id:16;          /* identification */
	uint32_t ip_off:16;         /* fragment offset field */
	uint32_t ip_ttl:8;          /* time to live */
	uint32_t ip_p:8;            /* protocol */
	uint32_t ip_sum:16;         /* checksum */
	uint32_t ip_src;            /* source address */
	uint32_t ip_dst;            /* dest address */
} IPhdr_t;


/****
 * UDP Header
 **/                                                                                                                                               

typedef struct _UDPhdr
{
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t chksum;
} UDPhdr_t;


typedef struct _eth_hdr                                                                                                                              
{   
	uint8_t ether_dst[6];
	uint8_t ether_src[6];
	uint16_t ether_type;

} eth_hdr_t;
   
typedef struct _eth_hdr ETHhdr_t;
#if 0
typedef struct _ARPHdr                                                                                                                               
{
	uint16_t ar_hrd;            /* format of hardware address   */
	uint16_t ar_pro;            /* format of protocol address   */
	uint8_t ar_hln;             /* length of hardware address   */
	uint8_t ar_pln;             /* length of protocol address   */
	uint16_t ar_op;             /* ARP opcode (command)         */
} ARPHdr;

#endif
typedef struct _ARPHdr ARPhdr_t;
#define ARPHRD_ETHER    1       /* ethernet hardware format     */  
/* using 4 local ethernet ports */
CVMX_SHARED port_config_t pcfg[6];

/* remote logging host information */
CVMX_SHARED remote_logging_config_t rlog_cfg;


int
CavIPaddrString (uint32_t ipaddr, char *ipaddr_str)
{
    if (ipaddr_str == NULL)
        return (1);

    sprintf (ipaddr_str, "%d.%d.%d.%d", (ipaddr >> 24) & 0xff,
             (ipaddr >> 16) & 0xff, (ipaddr >> 8) & 0xff, (ipaddr) & 0xff);

    return (0);
}


int
CavRemoteLogInit (uint32_t remote_host_ip_addr, int remote_udp_port)
{
        int first_core;

	if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM) 
	{
#ifdef SDK_3_1
                first_core = cvmx_coremask_get_first_core(&(cvmx_sysinfo_get()->core_mask));
                if (first_core == cvmx_get_core_num())
#else
		if (cvmx_coremask_first_core(cvmx_sysinfo_get()->core_mask))
#endif
		{
			uint8_t fmac[6];
			uint32_t fip = remote_host_ip_addr;
			int retval = 0;
			int i = 0;
			char ipaddr_string[32];
			uint64_t mac2;            /* Our MAC address */

			mac2 = cvmx_mgmt_port_get_mac(MGMT_PORT);	
#ifdef MGMT_DEBUG
			int err_init,err_enable;
			err_init = cvmx_mgmt_port_initialize(MGMT_PORT);	
			err_enable = cvmx_mgmt_port_enable(MGMT_PORT);	
			printf(" init= %d  %d\n",err_init,err_enable);	
			printf(" mac= %llu\n", mac2);	
#endif
			pcfg[4].mac_addr[0]=((mac2 >> 40) & 0xff);
			pcfg[4].mac_addr[1]=((mac2 >> 32) & 0xff);
			pcfg[4].mac_addr[2]=((mac2 >> 24) & 0xff);
			pcfg[4].mac_addr[3]=((mac2 >> 16) & 0xff);
			pcfg[4].mac_addr[4]=((mac2 >> 8) & 0xff);
			pcfg[4].mac_addr[5]=((mac2 >> 0) & 0xff);

#ifdef MGMT_DEBUG
			printf("\tLocal_test:  MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",pcfg[4].mac_addr[0], pcfg[4].mac_addr[1],pcfg[4].mac_addr[2],pcfg[4].mac_addr[3],pcfg[4].mac_addr[4], pcfg[4].mac_addr[5]);
#endif

			pcfg[4].ip_addrs= remote_host_ip_addr + 1;     
			i =4; 
			retval = CavGetRemoteIP (i, fip, (char *) fmac);
			if (!retval)
			{
				memcpy (rlog_cfg.local_addr.mac_addr, pcfg[i].mac_addr, 6);
				rlog_cfg.local_addr.ip_addrs = pcfg[i].ip_addrs;
				memcpy (rlog_cfg.remote_addr.mac_addr, fmac, 6);
				rlog_cfg.remote_addr.ip_addrs = remote_host_ip_addr;
				rlog_cfg.local_port = LOCAL_UDP_PORT;
				rlog_cfg.remote_port = remote_udp_port;
				rlog_cfg.rhost_present = 1;
				rlog_cfg.octeon_lport = 16 + i;     /* first RGMII is port 16 */
			}

			if (retval)
			{
				printf("Unable to find Remote Host! Remote logging will be disabled\n");

				unsigned a;
				for (a = 0; a < 10000; a++);
			}
			else
			{
				CavIPaddrString (remote_host_ip_addr, ipaddr_string);

				printf ("Remote Logging Init : \n");

				CavIPaddrString (rlog_cfg.local_addr.ip_addrs,
						ipaddr_string);

				printf
					("Local:  MAC=%02X:%02X:%02X:%02X:%02X:%02X; IP=%s; UDP port=%d\n",
					 rlog_cfg.local_addr.mac_addr[0], rlog_cfg.local_addr.mac_addr[1],
					 rlog_cfg.local_addr.mac_addr[2], rlog_cfg.local_addr.mac_addr[3],
					 rlog_cfg.local_addr.mac_addr[4], rlog_cfg.local_addr.mac_addr[5],
					 ipaddr_string, rlog_cfg.local_port);

				CavIPaddrString (rlog_cfg.remote_addr.ip_addrs,
						ipaddr_string);

				printf
					("Remote: MAC=%02X:%02X:%02X:%02X:%02X:%02X; IP=%s; UPD port=%d\n\n",
					 rlog_cfg.remote_addr.mac_addr[0],
					 rlog_cfg.remote_addr.mac_addr[1],
					 rlog_cfg.remote_addr.mac_addr[2],
					 rlog_cfg.remote_addr.mac_addr[3],
					 rlog_cfg.remote_addr.mac_addr[4],
					 rlog_cfg.remote_addr.mac_addr[5], ipaddr_string,
					 rlog_cfg.remote_port);
			}
			return (retval);
		}
	}
	return 0 ;
}



uint8_t CavCastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int
CavGetRemoteIP (int lport, uint32_t fip, char *fmac)
{
	void *ptr = NULL;
	cvmx_wqe_t *swp = NULL;
	ETHhdr_t *eth = NULL;
	ARPhdr_t *ah = NULL;
	cvmx_sysinfo_t *appinfo = cvmx_sysinfo_get ();
	uint64_t wait_cycles = (appinfo->cpu_clock_hz) * 2;
	uint64_t start_cycles = 0;
	ptr =  malloc(1024);
	if (ptr == NULL)
	{
		return (-1);
	}

	swp = (cvmx_wqe_t *) cvmx_fpa_alloc (CVMX_FPA_WQE_POOL);
	if (swp == NULL)
	{
		free (ptr);
		return (-1);
	}

	/* Fill in ethernet header */
	eth = (ETHhdr_t *) ptr;

	eth->ether_type = 0x0806;
	memcpy (eth->ether_dst, CavCastAddr, 6);
	memcpy (eth->ether_src, pcfg[lport].mac_addr, 6);


	/* Fill in ARP request header */
	ah = (ARPhdr_t *) ((char *) ptr + sizeof (ETHhdr_t));

	ah->ar_hrd = ARPHRD_ETHER;
	ah->ar_pro = 0x0800;
	ah->ar_hln = 6;
	ah->ar_pln = 4;
	ah->ar_op = ARPOP_REQUEST;

	memcpy (cav_ar_sha (ah), pcfg[lport].mac_addr, ah->ar_hln);
	memset (cav_ar_tha (ah), 0, ah->ar_hln);
	memcpy (cav_ar_spa (ah), &pcfg[lport].ip_addrs, ah->ar_pln);
	memcpy (cav_ar_tpa (ah), &fip, ah->ar_pln);


	swp->packet_ptr.u64 = 0;
	swp->packet_ptr.s.addr = (uint64_t) ptr;
	swp->word1.len = sizeof (ARPhdr_t) + 2 * 6 + 2 * 4 + 14;
	swp->packet_ptr.s.size = swp->word1.len;
	swp->word2.s.not_IP = 1;
	swp->word2.s.bufs = 1;
	cvmx_wqe_set_port(swp, lport) ;

#ifdef MGMT_DEBUG
	int length=swp->word1.len;
	if (length > 0)
	{
		/* Dump out packet contents */
		int i, j;
		unsigned char *up = ptr;
		for (i = 0; (i + 16) < length; i += 16)
		{
			printf("%04x ", i);
			for (j = 0; j < 16; ++j)
			{
				printf("%02x ", up[i+j]);
			}
			printf("    ");
			for (j = 0; j < 16; ++j)
			{
				printf("%c", ((up[i+j] >= ' ') && (up[i+j] <= '~')) ? up[i+j] : '.');
			}
			printf("\n");
		}
		printf("%04x ", i);
		for (j = 0; i+j < length; ++j)
		{
			printf("%02x ", up[i+j]);
		}
		for (; j < 16; ++j)
		{
			printf("   ");
		}
		printf("    ");
		for (j = 0; i+j < length; ++j)
		{
			printf("%c", ((up[i+j] >= ' ') && (up[i+j] <= '~')) ? up[i+j] : '.');
		}
		printf("\n");
	}

#endif

	/* using mgmt for remote logging */
	if(cvmx_mgmt_port_send(MGMT_PORT,swp->word1.len, (void *)ptr))
	{   ;
		/* printf("\nRemote logging Error (Send mgmt failed)\n"); */
	}

	/* free WQE */
	cvmx_fpa_free ((void *) swp, CVMX_FPA_WQE_POOL, 0);

	cvmx_pow_work_request_null_rd ();

	/* now wait for the response */
	start_cycles = cvmx_get_cycle ();

	while (1)
	{
		
		int k1= cvmx_mgmt_port_receive(MGMT_PORT,1024, (void *)ptr);
		if (k1 == 0)
		{
			if ((cvmx_get_cycle () - start_cycles) > wait_cycles)
				return (-1);
			continue;
		}
		/* GOT response */
		eth = (ETHhdr_t *) ((uint64_t) swp->packet_ptr.s.addr);

		if (memcmp (eth->ether_dst, pcfg[lport].mac_addr, 6))
			continue;
		if (eth->ether_type != 0x0806)
			continue;

		ah = (ARPhdr_t *) ((char *) ((uint64_t) swp->packet_ptr.s.addr) +
				sizeof (ETHhdr_t));

		if (ah->ar_pro != 0x0800)
			continue;
		if (ah->ar_op != ARPOP_REPLY)
			continue;

#ifdef MGMT_DEBUG
		int length=swp->word1.len;
		if (length > 0)
		{
			/* Dump out packet contents */
			int i, j;
			unsigned char *up = swp->packet_ptr.s.addr;
			for (i = 0; (i + 16) < length; i += 16)
			{
				printf("%04x ", i);
				for (j = 0; j < 16; ++j)
				{
					printf("%02x ", up[i+j]);
				}
				printf("    ");
				for (j = 0; j < 16; ++j)
				{
					printf("%c", ((up[i+j] >= ' ') && (up[i+j] <= '~')) ? up[i+j] : '.');
				}
				printf("\n");
			}
			printf("%04x ", i);
			for (j = 0; i+j < length; ++j)
			{
				printf("%02x ", up[i+j]);
			}
			for (; j < 16; ++j)
			{
				printf("   ");
			}
			printf("    ");
			for (j = 0; i+j < length; ++j)
			{
				printf("%c", ((up[i+j] >= ' ') && (up[i+j] <= '~')) ? up[i+j] : '.');
			}
			printf("\n");
		}

#endif

		memcpy (fmac, (char *) ah + sizeof (ARPhdr_t), ah->ar_hln);

		break;
	}

	return (0);
}

/*
 * IP header checksum calculation
 */
uint16_t
CavCalcChksum (IPhdr_t * ip)
{
    uint64_t sum;
    uint16_t *ptr = (uint16_t *) ip;
    uint8_t *bptr = (uint8_t *) ip;

    sum = ptr[0];
    sum += ptr[1];
    sum += ptr[2];
    sum += ptr[3];
    sum += ptr[4];

    /* Skip checksum field */
    sum += ptr[6];
    sum += ptr[7];
    sum += ptr[8];
    sum += ptr[9];

    /* Check for options */
    if (bptr[0] != 0x45)
        goto slow_cksum_calc;

  return_from_slow_cksum_calc:

    sum = (uint16_t) sum + (sum >> 16);
    sum = (uint16_t) sum + (sum >> 16);
    return ((uint16_t) (sum ^ 0xffff));

  slow_cksum_calc:
    /* Addes IPv4 options into the checksum (if present) */
    {
        uint64_t len = (bptr[0] & 0xf) - 5;
        ptr = &ptr[len << 1];

        while (len-- > 0)
        {
            sum += *ptr++;
            sum += *ptr++;
        }
    }

    goto return_from_slow_cksum_calc;
}


/*
 * Send UDP packet out
 */
int
CavSendUdpPkt (remote_logging_config_t * rlog, char *udp_payload,
                         int len)
{
    void *ptr = NULL;
    cvmx_wqe_t *swp = NULL;
    ETHhdr_t *eth = NULL;
    IPhdr_t *ih = NULL;
    UDPhdr_t *uh = NULL;
    static uint32_t ipid = 0;

    if (!rlog->rhost_present)
    {
        /* we don't have remote host configuration; exit */
		printf ("No Remote Host configuration present!\n");
        return (-1);
    }

    if ((len + sizeof (ETHhdr_t) + sizeof (IPhdr_t) + sizeof (UDPhdr_t)) >
        CVMX_FPA_PACKET_POOL_SIZE)
    {
        printf ("len too big..\n");
        return (-1);
    }

    ptr = cvmx_fpa_alloc(CVMX_FPA_PACKET_POOL);
    if (ptr == NULL)
    {
       
        printf ("Out of pkt pool buffers..\n");
	   	return (-1);
    }

    swp = (cvmx_wqe_t *) cvmx_fpa_alloc (CVMX_FPA_WQE_POOL);
    if (swp == NULL)
    {
        printf ("Out of WQE..\n");
        cvmx_fpa_free (ptr, CVMX_FPA_PACKET_POOL, 0);
        return (-1);
    }


    /* Fill in ethernet header */
    eth = (ETHhdr_t *) ptr;

    eth->ether_type = 0x0800;
    memcpy (eth->ether_dst, rlog->remote_addr.mac_addr, 6);
    memcpy (eth->ether_src, rlog->local_addr.mac_addr, 6);


    /* Fill in IP header */
    ih = (IPhdr_t *) ((char *) ptr + sizeof (ETHhdr_t));

    ih->ip_v = 4;
    ih->ip_hl = 5;
    ih->ip_tos = 0;
    ih->ip_len = sizeof (IPhdr_t) + sizeof (UDPhdr_t) + len;
    ih->ip_id = ipid++;
    ih->ip_off = 0;
    ih->ip_ttl = 64;
    ih->ip_p = 17;
    ih->ip_sum = 0;
    ih->ip_src = rlog->local_addr.ip_addrs;
    ih->ip_dst = rlog->remote_addr.ip_addrs;

    /* Fill in the UDP header */
    uh = (UDPhdr_t *) ((char *) ptr + sizeof (ETHhdr_t) + sizeof (IPhdr_t));

    uh->sport = rlog->local_port;
    uh->dport = rlog->remote_port;
    uh->len = sizeof (UDPhdr_t) + len;
    uh->chksum = 0;

    /* copy the data */
    memcpy (((char *) uh + sizeof (UDPhdr_t)), udp_payload, len);

    /* calculate IP checksum */
    ih->ip_sum = CavCalcChksum (ih);


    /* setup work queue entry */
    swp->packet_ptr.u64 = 0;
    swp->packet_ptr.s.addr = (uint64_t) ptr;
    swp->packet_ptr.s.pool = CVMX_FPA_PACKET_POOL;
    swp->word1.len = sizeof (ETHhdr_t) + sizeof (IPhdr_t) + sizeof (UDPhdr_t) + len;
    swp->packet_ptr.s.size = swp->word1.len;
    swp->word2.s.not_IP = 1;
    swp->word2.s.bufs = 1;

	/* using mgmt for remote logging */
	if(cvmx_mgmt_port_send(MGMT_PORT,swp->word1.len, (void *)ptr))
	{
		;
      /* comment for high rates.. or use limiter */
	  printf("\nRemote logging Error (Send mgmt failed)\n");  
	}

    /* free WQE */
    cvmx_fpa_free((void *) swp, CVMX_FPA_WQE_POOL, 0);
    cvmx_fpa_free (ptr, CVMX_FPA_PACKET_POOL, 0);
    
	return (0);
}

void syslog(int pri, char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
        vsyslog(pri, fmt, ap);
        va_end(ap);
}

void vsyslog(int pri, char *fmt, va_list ap){
	char *p, *t;
	register int cnt;
	int tbuf_left, fmt_left, prlen, saved_errno;
	char tbuf[TBUF_LEN], fmt_cpy[FMT_LEN];
    time_t now;
    char host_buf[256];

   	
    /* Check for invalid bits. */
    if (pri & ~(LOG_PRIMASK|LOG_FACMASK)) {
            syslog(INTERNALLOG,
                "syslog: unknown facility/priority: %x", pri);
            pri &= LOG_PRIMASK|LOG_FACMASK;
    }

    /* Check priority against setlogmask values. */
    if (!(LOG_MASK(LOG_PRI(pri)) & LogMask))
            return;

    saved_errno = errno;

    /* Set default facility if none specified. */
    if ((pri & LOG_FACMASK) == 0)
            pri |= LogFacility;

    /* Build the message. */

    /*
     * Although it's tempting, we can't ignore the possibility of
     * overflowing the buffer when assembling the "fixed" portion
     * of the message.  Strftime's "%h" directive expands to the
     * locale's abbreviated month name, but if the user has the
     * ability to construct to his own locale files, it may be
     * arbitrarily long.
     */
    (void)time(&now);

    p = tbuf;
    tbuf_left = TBUF_LEN;

#define DEC()   \
        do {                                    \
                if (prlen >= tbuf_left)         \
                        prlen = tbuf_left - 1;  \
                p += prlen;                     \
                tbuf_left -= prlen;             \
        } while (0)

    SnortSnprintf(p, tbuf_left, "<%d>", pri);
    prlen = SnortStrnlen(p, tbuf_left);
    DEC();

    prlen = strftime(p, tbuf_left, "%b %d %H:%M:%S ", localtime(&now));
    DEC();

/*  if (gethostname(host_buf, sizeof(host_buf)) == 0)  look at this */
    {
        SnortSnprintf(p, tbuf_left, "%s ", host_buf);
        prlen = SnortStrnlen(p, tbuf_left);
        DEC();
    }


    if (LogTag == NULL)
            LogTag = VERSION;
    if (LogTag != NULL) {
            SnortSnprintf(p, tbuf_left, "%s", LogTag);
            prlen = SnortStrnlen(p, tbuf_left);
            DEC();
    }
    if (LogStat & LOG_PID) {
            SnortSnprintf(p, tbuf_left, "[%d]", getpid());
            prlen = SnortStrnlen(p, tbuf_left);
            DEC();
    }
    if (LogTag != NULL) {
            if (tbuf_left > 1) {
                    *p++ = ':';
                    tbuf_left--;
            }
            if (tbuf_left > 1) {
                    *p++ = ' ';
                    tbuf_left--;
            }
    }

    /*
     * We wouldn't need this mess if printf handled %m, or if
     * strerror() had been invented before syslog().
     */
    for (t = fmt_cpy, fmt_left = FMT_LEN; *fmt != '\0' && fmt_left > 1; fmt++)
    {
        if (*fmt == '%' && *(fmt + 1) == 'm')
        {
            fmt++;
            SnortSnprintf(t, fmt_left, "%s", strerror(saved_errno));
            prlen = SnortStrnlen(t, fmt_left);
            if (prlen >= fmt_left)
                prlen = fmt_left - 1;

            t += prlen;
            fmt_left -= prlen;
        }
        else
        {
            if (fmt_left > 1)
            {
                *t++ = *fmt;
                fmt_left--;
            }
        }
    }

    *t = '\0';

    fmt_cpy[FMT_LEN - 1] = '\0';
    prlen = vsnprintf(p, tbuf_left, fmt_cpy, ap);
    p[tbuf_left - 1] = '\0';
    DEC();
    cnt = p - tbuf;

    CavSendUdpPkt (&rlog_cfg, tbuf, cnt);

}

#endif
