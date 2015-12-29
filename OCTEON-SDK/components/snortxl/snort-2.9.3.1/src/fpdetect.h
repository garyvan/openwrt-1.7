/*
** $Id$
**
** fpfuncs.h
**
** Copyright (C) 2002-2012 Sourcefire, Inc.
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** NOTES
** 5.15.02 - Initial Source Code. Norton/Roelker
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
**
*/

#ifndef __FPDETECT_H__
#define __FPDETECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fpcreate.h"
#include "snort_debug.h"
#include "decode.h"
#include "sflsq.h"
#include "event_queue.h"

#define REBUILD_FLAGS (PKT_REBUILT_FRAG | PKT_REBUILT_STREAM)

/*
**  This is the only function that is needed to do an
**  inspection on a packet.
*/
int fpEvalPacket(Packet *p);

int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p);
int fpEvalRTN(RuleTreeNode *rtn, Packet *p, int check_ports);

/*
**  This define is for the number of unique events
**  to match before choosing which event to log.
**  (Since we can only log one.) This define is the limit.
*/
#define MAX_EVENT_MATCH 100

/*
**  MATCH_INFO
**  The events that are matched get held in this structure,
**  and iMatchIndex gets set to the event that holds the
**  highest priority.
*/
typedef struct {

 OptTreeNode *MatchArray[MAX_EVENT_MATCH];
 int  iMatchCount;
 int  iMatchIndex;
 int  iMatchMaxLen;

}MATCH_INFO;

/*
**  OTNX_MATCH_DATA
**  This structure holds information that is
**  referenced during setwise pattern matches.
**  It also contains information regarding the
**  number of matches that have occurred and
**  the event to log based on the event comparison
**  function.
*/
typedef struct
{
    PORT_GROUP * pg;
    Packet * p;
    int check_ports;
#ifdef CAV_OCT_ASYNC
	/* SnortXL:
	 * submit_cnt : is th enumber of searches submitted for each omd 
	 * final_flag -s set after the point when no other submits using the same
	 * omd is possible 
	 */
	uint8_t submit_cnt;

    /* Gets set if omd gets added to omdlist.Tracks if post process for that 
     * particaular omd is pending */
	uint8_t pending;
	uint8_t final_flag;
#endif
    // SnortXL: Edit this sruct to incmude static matchinfo for ASYNC or move to
    // on demand matchinfo allocation
    int iMatchInfoArraySize;
    int pad;
    MATCH_INFO *matchInfo;
} OTNX_MATCH_DATA;

OTNX_MATCH_DATA * OtnXMatchDataNew(int);
void OtnxMatchDataFree(OTNX_MATCH_DATA *);

int fpAddMatch( OTNX_MATCH_DATA *omd_local, int pLen, OptTreeNode *otn);
void fpEvalIpProtoOnlyRules(SF_LIST **, Packet *);
#ifdef CAV_OCT_HFA
// Cavium: wrapper over fpFinalSelectEvent Called in case of async processing
int cavfpFinalSelectEvent(OTNX_MATCH_DATA *, Packet *);
#endif
OptTreeNode * GetOTN(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, char *);

#define TO_SERVER 1
#define TO_CLIENT 0

#endif
