/*
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
 * Copyright (C) 2011-2012 Sourcefire, Inc.
 *
 * Author: Ryan Jordan
 *
 * Protocol Aware Flushing (PAF) code for DNP3 preprocessor.
 *
 */

#ifndef DNP3_PAF__H
#define DNP3_PAF__H

#include "spp_dnp3.h"
#include "stream_api.h"

int DNP3AddPortsToPaf(dnp3_config_t *config, tSfPolicyId policy_id);

#endif /* DNP3_PAF__H */
