/***********************license start***************
 * Copyright (c) 2003-2010  Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

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
 * @file
 *
 * Resource management for PKI resources.
 */

#ifndef __CVMX_PKI_RESOURCES_H__
#define __CVMX_PKI_RESOURCES_H__

#ifdef CVMX_BUILD_FOR_LINUX_KERNEL
#include <asm/octeon/cvmx.h>
#endif

#ifdef	__cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

/**
 * This function allocates/reserves a style from pool of global styles per node.
 * @param node	 node to allocate style from.
 * @param style	 style to allocate, if -1 it will be allocated
                 first available style from style resource. If index is positive
		 number and in range, it will try to allocate specified style.
 * @return 	 style number on success, -1 on failure.
 */
int cvmx_pki_alloc_style(int node, int style);

/**
 * This function allocates/reserves a cluster group from per node
   cluster group resources.
 * @param node	 	node to allocate cluster group from.
   @param cl_grp	cluster group to allocate/reserve, if -1 ,
                        allocate any available cluster group.
 * @param num_clusters	number of clusters that will be attached to
			the cluster group.
 * @param parsing_mask  mask of parsing that will be enabled on the cluster gro.
 * @return 	 	cluster group number or -1 on failure
 */
int cvmx_pki_alloc_cluster_group(int node, int cl_grp, int num_clusters,
				 uint64_t parsing_mask, uint64_t *cluster_mask);

/**
 * This function allocates/reserves a pcam entry from node
 * @param node	 	node to allocate pcam entry from.
   @param index  	index of pacm entry (0-191), if -1 ,
                        allocate any available pcam entry.
 * @param bank		pcam bank where to allocate/reserve pcan entry from
 * @param cluster_mask  mask of clusters from which pcam entry is needed.
 * @return 	 	pcam entry of -1 on failure
 */
int cvmx_pki_pcam_alloc_entry(int node, int index, int bank, uint64_t cluster_mask);

/**
 * This function allocates/reserves QPG table entries per node.
 * @param node	 	node number.
 * @param base_offset	base_offset in qpg table. If -1, first available
			qpg base_offset will be allocated. If base_offset is positive
		 	number and in range, it will try to allocate specified base_offset.
   @param count		number of consecutive qpg entries to allocate. They will be consecutive
                        from base offset.
 * @return 	 	qpg table base offset number on success, -1 on failure.
 */
int cvmx_pki_alloc_qpg_entry(int node, int base_offset, int count );

#ifdef	__cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /*  __CVM_PKI_RESOURCES_H__ */