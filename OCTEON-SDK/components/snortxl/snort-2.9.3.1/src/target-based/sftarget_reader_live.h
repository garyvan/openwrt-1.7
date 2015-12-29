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

#ifndef SF_TARGET_READER_LIVE_H_
#define SF_TARGET_READER_LIVE_H_
#ifdef TARGET_BASED

#include "snort.h"

void SFLAT_init(void);
void SFLAT_fini(void);
int SFLAT_isEnabled(tSfPolicyId id, int parsing);
void SFLAT_dump(void);
HostAttributeEntry* SFLAT_findHost(snort_ip_p ip);
#endif
#endif /* SF_TARGET_READER_LIVE_H_ */
