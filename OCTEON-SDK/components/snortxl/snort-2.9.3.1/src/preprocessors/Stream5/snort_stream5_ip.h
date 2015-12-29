/****************************************************************************
 *
 * Copyright (C) 2011-2012 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
/*
 * @file    snort_stream5_ip.h
 * @author  Russ Combs <rcombs@sourcefire.com>
 *
 */

#ifndef __STREAM5_IP_H__
#define __STREAM5_IP_H__

#include "stream5_common.h"
#include "sfPolicy.h"

void Stream5CleanIp(void);
void Stream5ResetIp(void);
void Stream5InitIp(Stream5GlobalConfig*);

void Stream5IpPolicyInit(Stream5IpConfig*, char*);
int Stream5VerifyIpConfig(Stream5IpConfig*, tSfPolicyId);
void Stream5IpConfigFree(Stream5IpConfig*);

int Stream5ProcessIp(Packet*);

uint32_t Stream5GetIpPrunes(void);
void Stream5ResetIpPrunes(void);

void IpSessionCleanup (Stream5LWSession* lws);

#endif
