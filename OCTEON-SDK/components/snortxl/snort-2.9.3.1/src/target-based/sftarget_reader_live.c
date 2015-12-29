/*
** Copyright (C) 2006-2012 Sourcefire, Inc.
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

/*
 * Author: Dilbagh Chahal
 * sftarget_reader_live.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef TARGET_BASED
#ifdef SUP_IP6

#include <stdio.h>
#include "string.h"
#include "mstring.h"
#include "util.h"
#include "parser.h"
#include "sftarget_reader.h"
#include "sftarget_protocol_reference.h"
#include "sfutil/sfrt.h"
#include "sfutil/sfxhash.h"
#include "sfutil/util_net.h"
#include "sftarget_hostentry.h"

#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "snort.h"

#include "snort_debug.h"
#include "sfPolicy.h"
#include "attribute_table_api.h"

typedef struct
{
    table_t *lookupTable;
    SFXHASH *mapTable;
} tTargetBasedConfig;

/**current configuration created by live feed, a separate table is created to make
 * verification easier when Snort starts using live feed and Snort attribute tables
 * together. The table can be dumped on cleanup, for comparison
 * with attribute table from DC.*/
tTargetBasedConfig currLiveTable;

static int addLiveHost(
        snort_ip_p ip
        );
static int updateLiveOs(
        snort_ip_p ip,
        char *os,
        char *vendor,
        char *version,
        char *fragPolicy,
        char *streamPolicy
        );
static int addLiveService(
        snort_ip_p ip,
        uint16_t port,
        const char *ipproto,
        char *protocol,
        char *application,
        char *version,
        uint32_t confidence
        );
static int delLiveService(
        snort_ip_p ip,
        uint16_t port
        );
static void cleanupCallback(
        void *host_attr_ent
        );

HostAttributeTableApi snortAttributeInterface = {
    addLiveHost,
    //delLiveHost,
    updateLiveOs,
    addLiveService,
    delLiveService,
    //addLiveClient,
    //delLiveClient,
};

HostAttributeTableApi *AttributeTableAPI;

/**Initializes live attribute table. Current attribute table if populated is discard
 */
void SFLAT_init(void)
{
    if (!currLiveTable.lookupTable)
    {
        /* Add 1 to max for table purposes */
        currLiveTable.lookupTable =
            sfrt_new(DIR_16x7_4x4, IPv6, ScMaxAttrHosts() + 1,
                    sizeof(HostAttributeEntry) * 200);
        if (!currLiveTable.lookupTable)
        {
            ErrorMessage("Failed to initialize memory for live attribute table\n");
        }
    }
    else
    {
        sfrt_cleanup(currLiveTable.lookupTable, cleanupCallback);
        sfrt_free(currLiveTable.lookupTable);
    }
    AttributeTableAPI = &snortAttributeInterface;
}

void SFLAT_fini(void)
{
    if (currLiveTable.lookupTable)
    {
        sfrt_cleanup(currLiveTable.lookupTable, cleanupCallback);
        sfrt_free(currLiveTable.lookupTable);
        currLiveTable.lookupTable = NULL;
    }
}

/**Host information may be streamed into Snort by external source. This
 * feature is hardcoded to be enabled.*/
int SFLAT_isEnabled(tSfPolicyId id, int parsing)
{
    return 1;
}


static void cleanupCallback(
        void *host_attr_ent
        )
{
    HostAttributeEntry *host_entry = (HostAttributeEntry*)host_attr_ent;
    FreeHostEntry(host_entry);
}
static void FreeApplicationEntry(ApplicationEntry *app)
{
    free(app);
}

#ifdef DEBUG_MSGS
static void printHostLiveAttributeEntry(void *hostentry)
{
    HostAttributeEntry *host = (HostAttributeEntry *)hostentry;
    ApplicationEntry *app;
    sfip_t host_addr;

    if (!host)
        return;

    sfip_set_ip(&host_addr, &host->ipAddr);
    host_addr.ip32[0] = ntohl(host_addr.ip32[0]);

    DebugMessage(DEBUG_ATTRIBUTE, "Host IP: %s/%d\n",
            inet_ntoa(&host_addr),
            host->ipAddr.bits
            );
    DebugMessage(DEBUG_ATTRIBUTE, "\tOS Information: %s; %s; %s\n",
            host->hostInfo.operatingSystem.value.s_value,
            host->hostInfo.vendor.value.s_value,
            host->hostInfo.version.value.s_value);
    DebugMessage(DEBUG_ATTRIBUTE, "\t\tfrag:%s stream: %s\n",
            host->hostInfo.fragPolicyName,
            host->hostInfo.streamPolicyName);
    for (app = host->services; app; app = app->next)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\tService: %d; %s; %s; %s; %s\n",
                app->port.value.l_value,
                app->ipproto.value.s_value,
                app->protocol.value.s_value,
                (app->fields & APPLICATION_ENTRY_APPLICATION)? app->application.value.s_value : "",
                (app->fields & APPLICATION_ENTRY_VERSION)? app->version.value.s_value : "");
    }

    for (app = host->clients; app; app = app->next)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\tClient: %s; %s; %s\n",
                app->protocol.value.s_value,
                (app->fields & APPLICATION_ENTRY_APPLICATION)? app->application.value.s_value : "",
                (app->fields & APPLICATION_ENTRY_VERSION)? app->version.value.s_value : "");
    }
}

void SFLAT_dump(void)
{
    sfrt_iterate(currLiveTable.lookupTable, printHostLiveAttributeEntry);

}
#endif

HostAttributeEntry* SFLAT_findHost(snort_ip_p ip)
{
    return sfrt_lookup(ip, currLiveTable.lookupTable);
}

/**add or update host to host table.*/
static int addLiveHost(
        snort_ip_p ip
        )
{
    int ret = RT_SUCCESS;
    HostAttributeEntry *host;

    host = SFLAT_findHost(ip);
    if (!host)
    {
        host = SnortAlloc(sizeof(HostAttributeEntry));
        if (!host)
        {
            return SFAT_ERROR;
        }

        sfip_set_ip(&host->ipAddr, ip);

        ret = sfrt_insert(ip, (unsigned char)ip->bits, host,
                        RT_FAVOR_SPECIFIC, currLiveTable.lookupTable);

        if (ret != RT_SUCCESS)
        {
            if (ret == RT_POLICY_TABLE_EXCEEDED)
            {
                ErrorMessage("Live AttributeTable insertion failed\n");
                ret = RT_SUCCESS;
            }
            else
            {
                ErrorMessage("AttributeTable insertion failed: %d '%s'\n",
                        ret, rt_error_messages[ret]);
            }

            FreeHostEntry(host);
        }
    }
    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

#if 0
//delete host operation is not supported yet. This requires extending Under current design, least recently used host will be deleted when
//lookup table is full.

/**deletes a host to live attribute table.*/
static int delLiveHost(snort_ip_p ip)
{
    int ret;
    HostAttributeEntry *host;

    host = SFLAT_findHost(ip);

    if (host)
    {
        FreeHostEntry(host);
    }
    else
    {
        DEBUG_WRAP( DebugMessage(DEBUG_ATTRIBUTE, "lookup failed: %x\n", ip->ip32[0]););
        ret = DIR_LOOKUP_FAILURE;
    }
    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}
#endif

/**Adds, Updates or deletes OS informatio. Existing info is overwritten. Delete is same as
 * empty strings. Newest information overwrites old information.
 */
static int updateLiveOs(
        snort_ip_p ip,
        char *os,
        char *vendor,
        char *version,
        char *fragPolicy,
        char *streamPolicy
        )
{
    int ret = RT_SUCCESS;
    HostAttributeEntry *host;

    host = SFLAT_findHost(ip);
    //inserting host data. Host gets created with just the IP address, os/service/clients
    //get added later.
    if (host)
    {
        //update the host
        SnortStrncpy (host->hostInfo.operatingSystem.value.s_value, os, STD_BUF);
        host->hostInfo.operatingSystem.value.s_value[STD_BUF-1] = 0;
        host->hostInfo.operatingSystem.confidence = 50 ;
        SnortStrncpy (host->hostInfo.vendor.value.s_value, vendor, STD_BUF);
        host->hostInfo.vendor.value.s_value[STD_BUF-1] = 0;
        host->hostInfo.vendor.confidence = 50 ;
        SnortStrncpy (host->hostInfo.version.value.s_value, version, STD_BUF);
        host->hostInfo.version.value.s_value[STD_BUF-1] = 0;
        host->hostInfo.version.confidence = 50 ;

        /* Set the policy IDs in the new table... */
        SnortStrncpy(host->hostInfo.fragPolicyName, fragPolicy, STD_BUF);
        host->hostInfo.fragPolicyName[STD_BUF-1] = 0;
        SnortStrncpy(host->hostInfo.streamPolicyName, streamPolicy, STD_BUF);
        host->hostInfo.streamPolicyName[STD_BUF-1] = 0;

        //existing hosts are not updated when host attribute is live updated.
    }
    else
    {
        DEBUG_WRAP( DebugMessage(DEBUG_ATTRIBUTE, "lookup failed: %x\n", ip->ip32[0]););
        ret = DIR_LOOKUP_FAILURE;
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

/**add or update service information.*/
static int addLiveService(
        snort_ip_p ip,
        uint16_t port,
        const char *ipproto,
        char *protocol,
        char *application,
        char *version,
        uint32_t confidence
        )
{
    int ret = RT_SUCCESS;
    HostAttributeEntry *host;
    ApplicationEntry *service;

    //inserting host data. Host gets created with just the IP address, os/service/clients
    //get added later.
    host = SFLAT_findHost(ip);
    if (host)
    {
        int16_t ipProtoOrdinal = AddProtocolReference(ipproto);
        int16_t protocolOrdinal = AddProtocolReference(protocol);

        //update the host
        for (service = host->services; service; service = service->next)
        {
            if ((service->port.value.l_value == port)
                    && ipProtoOrdinal && (service->ipproto.attributeOrdinal == ipProtoOrdinal))
            {
                //found matching service
                DEBUG_WRAP( DebugMessage(DEBUG_ATTRIBUTE, "Matched service : IP %x, protocol %s, port %d\n", ip->ip32[0], ipproto, port););
                break;
            }
        }
        if (!service)
        {
            //insert
            service = SnortAlloc(sizeof(ApplicationEntry));
            if (service)
            {
                DEBUG_WRAP( DebugMessage(DEBUG_ATTRIBUTE, "Added new service : IP %x, protocol %s, port %d\n", ip->ip32[0], ipproto, port););
                service->next = host->services;
                host->services = service;

                //port
                service->port.type = ATTRIBUTE_ID;
                service->port.value.l_value = port;
                service->port.confidence = 50;

                //ipproto
                service->ipproto.type = ATTRIBUTE_NAME;
                strncpy (service->ipproto.value.s_value, ipproto, STD_BUF);
                service->ipproto.value.s_value[STD_BUF-1] = 0;
                service->ipproto.attributeOrdinal = ipProtoOrdinal;
                service->ipproto.confidence = 50;

            }
        }

        if (service)
        {
            //protocol
            service->protocol.type = ATTRIBUTE_NAME;
            strncpy (service->protocol.value.s_value, protocol, STD_BUF);
            service->protocol.value.s_value[STD_BUF-1] = 0;
            service->protocol.attributeOrdinal = protocolOrdinal;
            service->protocol.confidence = 50;

            service->fields |= (APPLICATION_ENTRY_PORT | APPLICATION_ENTRY_IPPROTO | APPLICATION_ENTRY_PROTO);

            //application
            if (application)
            {
                service->application.type = ATTRIBUTE_NAME;
                strncpy (service->application.value.s_value, application, STD_BUF);
                service->application.value.s_value[STD_BUF-1] = 0;
                service->application.attributeOrdinal = 0;
                service->application.confidence = 50;
                service->fields |= APPLICATION_ENTRY_APPLICATION;

                //version
                if (version)
                {
                    service->version.type = ATTRIBUTE_NAME;
                    strncpy (service->version.value.s_value, version, STD_BUF);
                    service->version.value.s_value[STD_BUF-1] = 0;
                    service->version.confidence = 50;
                    service->fields |= APPLICATION_ENTRY_VERSION;
                }
            }
        }
    }
    else
    {
        DEBUG_WRAP( DebugMessage(DEBUG_ATTRIBUTE, "Host not found : IP %x\n", ip->ip32[0]););
        ret = DIR_LOOKUP_FAILURE;
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}
static int delLiveService(
        snort_ip_p ip,
        uint16_t port
        )
{
    int ret = RT_SUCCESS;
    HostAttributeEntry *host;
    ApplicationList *service = NULL;
    ApplicationList *prevService = NULL;

    //inserting host data. Host gets created with just the IP address, os/service/clients
    //get added later.
    host = SFLAT_findHost(ip);
    if (host)
    {
        //update the host
        for (service = host->services;
                service;
                prevService = service, service = service->next)
        {
            //only one service per port.
            if (service->port.value.l_value == port)
                    //&& ipProtoOrdinal && (service->ipproto.attributeOrdinal == ipProtoOrdinal))
            {
                //found matching service
                break;
            }
        }
    }
    if (service)
    {
        if (prevService)
        {
            prevService->next = service->next;
        }
        else
        {
            host->services = service->next;
        }

        FreeApplicationEntry(service);
    }
    else
    {
        ret = DIR_LOOKUP_FAILURE;
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

#if 0
static int addLiveClient(
        snort_ip_p ip,
        char *protocol,
        char *application,
        char *version,
        uint32_t confidence
        )
{
    int ret = RT_SUCCESS;
    HostAttributeEntry *host;
    ApplicationList *client;

    //inserting host data. Host gets created with just the IP address, os/service/clients
    //get added later.
    host = SFLAT_findHost(ip);
    if (host)
    {
        int16_t protocolOrdinal = AddProtocolReference(protocol);

        //search existing client app
        for (client = host->clients; client; client = client->next)
        {
            if (protocolOrdinal && (client->protocol.attributeOrdinal == protocolOrdinal)
                    && !strcasecmp(client->application.value.s_value, application))
            {
                break;
            }
        }

        if (!client)
        {
            //insert
            client = SnortAlloc(sizeof(ApplicationEntry));
            if (client)
            {
                client->next = host->clients;
                host->clients = client;
            }
        }

        if (client)
        {
            //protocol
            client->protocol.type = ATTRIBUTE_NAME;
            strncpy (client->protocol.value.s_value, protocol, STD_BUF);
            client->protocol.attributeOrdinal = protocolOrdinal;
            client->protocol.confidence = 50;
            client->fields |= (APPLICATION_ENTRY_PROTO);

            //application
            if (application)
            {
                client->application.type = ATTRIBUTE_NAME;
                strncpy (client->application.value.s_value, application, STD_BUF);
                client->application.attributeOrdinal = 0;
                client->application.confidence = 50;
                client->fields |= (APPLICATION_ENTRY_APPLICATION);

                //version
                if (version)
                {
                    client->version.type = ATTRIBUTE_NAME;
                    strncpy (client->version.value.s_value, version, STD_BUF);
                    client->version.confidence = 50;
                    client->fields |= (APPLICATION_ENTRY_VERSION);
                }
            }

        }
    }
    else
    {
        ret = DIR_LOOKUP_FAILURE;
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

/**delete a client entry from host.
 */
static int delLiveClient(
        snort_ip_p ip,
        char *protocol,
        char *application)
{
    int ret = RT_SUCCESS;
    HostAttributeEntry *host;
    ApplicationEntry *client;
    ApplicationEntry *prevClient = NULL;

    //get added later.
    host = SFLAT_findHost(ip);
    if (host)
    {
        int16_t protocolOrdinal = AddProtocolReference(protocol);

        //search existing client app
        for (client = host->clients;
                client;
                prevClient = client, client = client->next)
        {
            if (protocolOrdinal && (client->protocol.attributeOrdinal == protocolOrdinal)
                    && !strcasecmp(client->application.value.s_value,application))
            {
                break;
            }
        }
    }

    if (client)
    {
        if (prevClient)
        {
            prevClient->next = client->next;
        }
        else
        {
            host->clients = client->next;
        }

        FreeApplicationEntry(client);
    }
    else
    {
        ret = DIR_LOOKUP_FAILURE;
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}
#endif
#endif    //SUP_IP6
#endif    //TARGET_BASED

