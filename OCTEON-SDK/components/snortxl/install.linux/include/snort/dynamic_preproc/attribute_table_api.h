/* $Id$ */
/*
** Copyright (C) 2011-2012 Sourcefire, Inc.
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

#ifndef _SF_ATTRIBUTE_TABLE_API_H
#define _SF_ATTRIBUTE_TABLE_API_H
#ifdef TARGET_BASED

typedef struct
{
    int (*addHost)(snort_ip_p ip);
    //int (*delHost)(snort_ip_p ip);
    int (*updateOs)(snort_ip_p ip, char *os, char *vendor, char *version, char *fragPolicy, char *streamPolicy);
    int (*addService)(snort_ip_p ip, uint16_t port, const char *ipproto, char *protocol, char *application, char *version, uint32_t confidence);
    int (*delService)(snort_ip_p ip, uint16_t port);
    //int (*addClient)( snort_ip_p ip, char *ipproto, char *protocol, char *application, char *version, uint32_t confidence);
    //int (*delClient)( snort_ip_p ip, char *ipproto, char *protocol, char *application);

} HostAttributeTableApi;

extern HostAttributeTableApi *AttributeTableAPI;

#endif
#endif   // _SF_ATTRIBUTE_TABLE_API_H

