/*
** Copyright (C) 2010 Sourcefire, Inc.
** Author: Michael R. Altizer <maltizer@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#if 0
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "daq_api.h"
#include "sfbpf.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern int snprintf(char * buf, size_t size, const char *fmt, ...);
#ifdef CAV_OCT_HFA
#ifdef CAV_OCT_SE
extern char * strdup(const char *s);
#endif
extern int octeon_initialize();
extern void * octeonSE_acquire(uint32_t *len, uint64_t *addr, int timeout);
extern int octeonSE_inject(void *work);
extern int octeonSE_shutdown();
extern void* (*func_cav128BAlloc)(void);
extern void (*func_cav128BFree)(void*);
#endif

#if 0
#define FAU_PACKETS     ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 0))   /**< Fetch and add for counting packets processed */
#define FAU_ERRORS      ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 8))   /**< Fetch and add for counting detected errors */
#define FAU_OUTSTANDING ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 16))  /**< Fetch and add for counting outstanding packets */

#define FAU_PACKETS_RECEIVED    ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 24))   /**< Fetch and add for counting packets received */
#define FAU_PACKETS_INJECTED    ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 32))   /**< Fetch and add for counting packets injected */
#define FAU_PACKETS_DROPPED     ((cvmx_fau_reg_64_t)(CVMX_FAU_REG_AVAIL_BASE + 40))   /**< Fetch and add for counting packets dropped */
#endif

/* static unsigned int packet_termination_num; */
typedef struct _octeonSE_context

{
    char *device;
    //char *filter;
    int snaplen;
    int timeout;
    //uint32_t size;
    //int debug;
    uint32_t intf_count;
    //struct sfbpf_program fcode;
    volatile int break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
}Octeon_SE_Context_t;

/**
 * Setup the Cavium Simple Executive Libraries using defaults
 *
 * @param num_packet_buffers
 *               Number of outstanding packets to support
 * @return Zero on success
 */

static void update_hw_stats(Octeon_SE_Context_t *octContext)
{
#if 0
		octContext->stats.hw_packets_received = FAU_PACKETS_RECEIVED;
		octContext->stats.hw_packets_dropped = FAU_PACKETS_DROPPED;

		octContext->stats.packets_received = FAU_PACKETS_RECEIVED;
		//octContext->stats.packets_dropped = FAU_PACKETS_DROPPED;
		octContext->stats.packets_injected = FAU_PACKETS_INJECTED;
#endif
}

static void reset_stats(Octeon_SE_Context_t *octContext)
{
	//octeonSe_reset_stats();
    update_hw_stats(octContext);
}



static int octeonSE_close(Octeon_SE_Context_t *octContext)
{
	if(!octContext)
		return DAQ_ERROR;
	
    update_hw_stats(octContext);

    octContext->state = DAQ_STATE_STOPPED;

	return DAQ_SUCCESS;
}

static int octeonSE_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    Octeon_SE_Context_t *octContext;
	char *dev;
	int len;
    int rval = DAQ_ERROR;

    octContext = calloc(1, sizeof(Octeon_SE_Context_t));
    if (!octContext)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new OcteonSE context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    octContext->device = strdup(config->name);
    if (!octContext->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    octContext->snaplen = config->snaplen;
    octContext->timeout = (config->timeout > 0) ? (int) config->timeout : -1;

    dev = octContext->device;
    if (*dev == ':' || ((len = strlen(dev)) > 0 && *(dev + len - 1) == ':') || (config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::")))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, octContext->device);
        goto err;
    }

	if(!octeon_initialize()){
   		octContext->state = DAQ_STATE_INITIALIZED;
    	*ctxt_ptr = octContext;
    	return DAQ_SUCCESS;
	}
	else 
		goto err;

err:
    if (octContext)
    {
        octeonSE_close(octContext);
        if (octContext->device)
            free(octContext->device);
        free(octContext);
    }
    return rval;
}

static int octeonSE_daq_set_filter(void *handle, const char *filter)
{ 
	return 0;
}


static int octeonSE_daq_start(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    reset_stats(octContext);

    octContext->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static int octeonSE_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, void *user)
{ 
	uint64_t pkt;
	DAQ_PktHdr_t *pkthdr;
	void *work;
	int c=0;
	uint32_t len;

    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    while (cnt <= 0 || c < cnt)
	{
      	/* Has breakloop() been called? */
     	if (octContext->break_loop)
     	{
       		octContext->break_loop = 0;
       		return 0;
 		}

		work = octeonSE_acquire(&len, &pkt, octContext->timeout);
		if (work == NULL) { 
			/* This indicates that we have rcvd a SIGINT or have exceeded
             * timeout value and we need to break of get_work loop */
            break;
		}
 
 		pkthdr = (DAQ_PktHdr_t *)func_cav128BAlloc( );
		if(pkthdr == NULL)
		{
			printf("Out of heap mem for DAQ hdr\n");
			return DAQ_ERROR_NOMEM;
		}
 
		pkthdr->ts.tv_sec=0;
		pkthdr->ts.tv_usec=0;
		pkthdr->caplen = len;
		pkthdr->pktlen = len;
		pkthdr->device_index = -1;
		pkthdr->flags = 0;
		pkthdr->entry.work = work;

		callback(user,pkthdr,(uint8_t *)pkt);
		c++;

	}

	return 0;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int octeonSE_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{   
    Octeon_SE_Context_t * context = ( Octeon_SE_Context_t*) handle;
    DAQ_Verdict verdict;
    DAQ_Action action = reverse;

	/* SnortXL : both these are errors */
	if(hdr == NULL)
	{ 
		printf("NULL header\n"); 
		return 0;
	}	   
   
	if(hdr->entry.work == NULL)
	{ 
		printf("NULL work\n"); 
		return 0;
	}	   
    /*SnortXL:: Collect verdict stats for the packet with DAQ_SEND action and send the packet
     * out to the peer only if verdict is pass */
    if(action == DAQ_SEND)             
    {   
        verdict = hdr->verdict; 

        if(verdict >= MAX_DAQ_VERDICT)
            verdict = DAQ_VERDICT_PASS;

        context->stats.verdicts[verdict]++;

        verdict = verdict_translation_table[verdict];

        if(verdict == DAQ_VERDICT_PASS)
        {
            if(octeonSE_inject(hdr->entry.work) < 0)
                return DAQ_ERROR;
        }
    }
    else/* New Encoded Packets to be injected to the peer */
    {    
        if(octeonSE_inject(hdr->entry.work) < 0)
             return DAQ_ERROR;
        context->stats.packets_injected++;
    }

    func_cav128BFree((void*)hdr);

	return 0;
}


static int octeonSE_daq_breakloop(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    octContext->break_loop = 1; //no effect

    return DAQ_SUCCESS;
}

static int octeonSE_daq_stop(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    octeonSE_close(octContext);

    return DAQ_SUCCESS;
}

static void octeonSE_daq_shutdown(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    octeonSE_close(octContext);

	octeonSE_shutdown();

    if (octContext->device)
        free(octContext->device);
   // if (octContext->filter)
    //    free(octContext->filter);
    if (octContext)
        free(octContext);
}

static DAQ_State octeonSE_daq_check_status(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    return octContext->state;
}

static int octeonSE_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    update_hw_stats(octContext);
    memcpy(stats, &octContext->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void octeonSE_daq_reset_stats(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    reset_stats(octContext);
}

static int octeonSE_daq_get_snaplen(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    return octContext->snaplen;
}

static uint32_t octeonSE_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |  DAQ_CAPA_BREAKLOOP;
}

static int octeonSE_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *octeonSE_daq_get_errbuf(void *handle)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    return octContext->errbuf;
}

static void octeonSE_daq_set_errbuf(void *handle, const char *string)
{
    Octeon_SE_Context_t *octContext = (Octeon_SE_Context_t *) handle;

    if (!string)
        return;

    DPE(octContext->errbuf, "%s", string);
}

static int octeonSE_daq_get_device_index(void *handle, const char *string)
{
	return 0;
}

const DAQ_Module_t octeonSE_daq_module_data =
{
    .api_version = DAQ_API_VERSION,
    .module_version = 1,
    .name = "octeon",
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE, //| DAQ_TYPE_MULTI_INSTANCE,
    .initialize = octeonSE_daq_initialize,
    .set_filter = octeonSE_daq_set_filter,
    .start = octeonSE_daq_start,
    .acquire = octeonSE_daq_acquire,
    .inject = octeonSE_daq_inject,
    .breakloop = octeonSE_daq_breakloop,
    .stop = octeonSE_daq_stop,
    .shutdown = octeonSE_daq_shutdown,
    .check_status = octeonSE_daq_check_status,
    .get_stats = octeonSE_daq_get_stats,
    .reset_stats = octeonSE_daq_reset_stats,
    .get_snaplen = octeonSE_daq_get_snaplen,
    .get_capabilities = octeonSE_daq_get_capabilities,
    .get_datalink_type = octeonSE_daq_get_datalink_type,
    .get_errbuf = octeonSE_daq_get_errbuf,
    .set_errbuf = octeonSE_daq_set_errbuf,
    .get_device_index = octeonSE_daq_get_device_index
};
