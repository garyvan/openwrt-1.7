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
 * PKI Support.
 */
#ifdef CVMX_BUILD_FOR_LINUX_KERNEL
#include <linux/module.h>
#include <asm/octeon/cvmx.h>
#include <asm/octeon/cvmx-pki-defs.h>
#include <asm/octeon/cvmx-pki.h>
#include "asm/octeon/cvmx-global-resources.h"
#include "asm/octeon/cvmx-range.h"
#else
#include "cvmx.h"
#include "cvmx-version.h"
#include "cvmx-error.h"
#include "cvmx-pki.h"
#include "cvmx-global-resources.h"
#include "cvmx-range.h"
#endif

/**
 * This function allocates/reserves a style from pool of global styles per node.
 * @param node	 node to allocate style from.
 * @param style	 style to allocate, if -1 it will be allocated
                 first available style from style resource. If index is positive
		 number and in range, it will try to allocate specified style.
 * @return 	 style number on success, -1 on failure.
 */
int cvmx_pki_alloc_style(int node, int style)
{
	if(cvmx_create_global_resource_range(CVMX_GR_TAG_STYLE(node),CVMX_PKI_NUM_INTERNAL_STYLES)) {
		cvmx_dprintf("\nERROR: Failed to create styles global resource\n");
		return -1;
	}
	if(style >= 0) {
		style = cvmx_reserve_global_resource_range(CVMX_GR_TAG_STYLE(node), style, style,1);
		if(style == -1){
			cvmx_dprintf("\nERROR: Failed to reserve style %d\n", (int)style);
			return -1;
		}
	}
	else {
		style = cvmx_allocate_global_resource_range(CVMX_GR_TAG_STYLE(node), style, 1,1);
		if(style == -1){
			cvmx_dprintf("ERROR: Failed to allocate style %d\n", (int)style);
			//vinita, define enum later
			return -1;
		}
	}
	return style;
}

/**
 * This function allocates/reserves a cluster group from per node
   cluster group resources.
 * @param node	 	node to allocate cluster group from.
   @param cl_grp	cluster group to allocate/reserve, if -1 ,
                        allocate any available cluster group.
 * @param num_clusters	number of clusters that will be attached to
			the cluster group.
 * @param parsing_mask  mask of parsing that will be enabled on the cluster group.
 * @return 	 	cluster group number or -1 on failure
 */
int cvmx_pki_alloc_cluster_group(int node, int cl_grp, int num_clusters,
				 uint64_t parsing_mask, uint64_t *cluster_mask)
{
	int cluster = 0;

	if(node >= CVMX_MAX_NODES) {
		cvmx_dprintf("Invalid node number %d",node);
		return -1;
	}

	if(cvmx_create_global_resource_range(CVMX_GR_TAG_CLUSTERS(node),CVMX_PKI_NUM_CLUSTERS)) {
		cvmx_dprintf("Failed to create Clusters global resource\n");
		return -1;
	}
	if(cvmx_create_global_resource_range(CVMX_GR_TAG_CLUSTER_GRP(node),CVMX_PKI_NUM_CLUSTER_GROUP)) {
		cvmx_dprintf("Failed to create Cluster group global resource\n");
		return -1;
	}

	if( cl_grp >=0 )
		cl_grp = cvmx_reserve_global_resource_range(CVMX_GR_TAG_CLUSTER_GRP(node),0,cl_grp,1);

	else {
		cl_grp = cvmx_allocate_global_resource_range(CVMX_GR_TAG_CLUSTER_GRP(node),0,1,1);

		if(cl_grp == -1) {
			cvmx_dprintf("Warning: Failed to alloc cluster grp %d\n", cl_grp);
			return -1;
		}
	}
	if(cl_grp >= CVMX_PKI_NUM_CLUSTER_GROUP) {
		cvmx_dprintf("ERROR: Invalid cluster group %d got allocated\n",cl_grp);
		return -1;
	}
	if(cl_grp == -1) {
		cvmx_dprintf("Warning: Failed to alloc cluster grp sharing the cluster grp\n");
		//vinita cl_grp = cvmx_find_global_resource_range_owner(CVMX_GR_TAG_CLUSTER_GRP(node), num_clusters);
		return -1; //vinita
	}
	else {
		cluster = cvmx_allocate_global_resource_range(CVMX_GR_TAG_CLUSTERS(node),
				cl_grp, num_clusters, 1);
		if(cluster >= CVMX_PKI_NUM_CLUSTERS) {
			cvmx_dprintf("ERROR: Invalid clusters %d got allocated\n", (int)cluster);
			return -1;
		}
		if(cluster == -1) {
			cvmx_dprintf("Warning: Failed to allocate clusters %d sharing the clusters \n", (int)num_clusters);
			//vinita cl_grp = cvmx_find_global_resource_range_owner(CVMX_GR_TAG_CLUSTERS(node), num_clusters);
			//to_do vinita cluster = cvmx_find_global_resource_owner_range(CVMX_GR_TAG_CLUSTERS(node), cl_grp);
			return -1; //vinita
		}
	}
	if(cl_grp == -1 || cluster == -1){
			cvmx_dprintf("Failed to allocate Cluster group global resource\n");
		return -1;
	}
	else {
		*cluster_mask = cvmx_build_mask((uint64_t)((num_clusters-(uint64_t)cluster+1) << cluster));
		return cl_grp;
	}
}

int cvmx_pki_free_cluster_group(int node, int grp_index)
{
	if(node >= CVMX_MAX_NODES) {
		cvmx_dprintf("Invalid node number %d",node);
		return -1;
	}

	//spinlock it
	if (--pki_config[node].cluster_cfg[grp_index].users) {
		cvmx_dprintf("ERROR: cluster group %d is in use, can't free it\n", (int)grp_index);
		return -1;
	}
	if (grp_index >= CVMX_PKI_NUM_CLUSTER_GROUP) {
		cvmx_dprintf("ERROR: Invalid cluster group %d in cvmx_pki_free_cluster_group\n", (int)grp_index);
		return -1;
	}
	if (cvmx_free_global_resource_range_with_owner(CVMX_GR_TAG_CLUSTER_GRP(node), grp_index) == -1) {
		cvmx_dprintf("ERROR Failed to release cluster group %d\n", (int)grp_index);
		return -1;
	}
	//spinlock it
	pki_config[node].cluster_cfg[grp_index].users--;
	return 0;
}

/**
 * This function allocates/reserves a pcam entry from node
 * @param node	 	node to allocate pcam entry from.
   @param index  	index of pacm entry (0-191), if -1 ,
                        allocate any available pcam entry.
 * @param bank		pcam bank where to allocate/reserve pcan entry from
 * @param cluster_mask  mask of clusters from which pcam entry is needed.
 * @return 	 	pcam entry of -1 on failure
 */
int cvmx_pki_pcam_alloc_entry(int node, int index, int bank, uint64_t cluster_mask)
{
	uint64_t cluster=0;

	while( cluster < CVMX_PKI_NUM_CLUSTERS) {
		if(cluster_mask & (0x01L << cluster)) {
			if (cvmx_create_global_resource_range(CVMX_GR_TAG_PCAM(node,cluster,bank),
			    	CVMX_PKI_TOTAL_PCAM_ENTRY)) {
				cvmx_dprintf("\nFailed to create pki pcam global resource");
				return -1;
			}
			if (index >= 0)
				index = cvmx_reserve_global_resource_range(CVMX_GR_TAG_PCAM(node,cluster,bank),
						cluster, index, 1);
			else
				index = cvmx_allocate_global_resource_range(CVMX_GR_TAG_PCAM(node,cluster,bank),
						cluster, 1, 1);
			if(index == -1) {
				cvmx_dprintf("Error:index %d not available in cluster %d bank %d",
						(int)index, (int)cluster, bank);
				return -1;
			}
			cluster++;
		}
	}
	//vinita to_do , implement cluster handle, for now assume
	//all clusters will have same base index
	return index;
}

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
int cvmx_pki_alloc_qpg_entry(int node, int base_offset, int count )
{
	if(cvmx_create_global_resource_range(CVMX_GR_TAG_QPG_ENTRY(node),CVMX_PKI_NUM_QPG_ENTRY)) {
		cvmx_dprintf("\nERROR: Failed to create qpg_entry global resource\n");
		return -1;
	}
	if(base_offset >= 0) {
		base_offset = cvmx_reserve_global_resource_range(CVMX_GR_TAG_QPG_ENTRY(node), base_offset, base_offset,count);
		if(base_offset == -1){
			cvmx_dprintf("\nERROR: Failed to reserve qpg entry %d\n", (int)base_offset);
			return -1;
		}
	}
	else {
		base_offset = cvmx_allocate_global_resource_range(CVMX_GR_TAG_QPG_ENTRY(node), base_offset, count,1);
		if(base_offset == -1){
			cvmx_dprintf("ERROR: Failed to allocate qpg entry %d\n", (int)base_offset);
			return -1;
		}
	}
	return base_offset;
}

/**
 * This function frees QPG table entries per node.
 * @param node	 	node number.
 * @param base_offset	base_offset in qpg table. If -1, first available
			qpg base_offset will be allocated. If base_offset is positive
		 	number and in range, it will try to allocate specified base_offset.
   @param count		number of consecutive qpg entries to allocate. They will be consecutive
                        from base offset.
 * @return 	 	qpg table base offset number on success, -1 on failure.
 */
int cvmx_pki_free_qpg_entry(int node, int base_offset, int count )
{
	return 0;
	//vinita_to_do
}
