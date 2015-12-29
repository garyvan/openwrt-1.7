/***********************license start***************
* Copyright (c) 2003-2015  Cavium Inc. (support@cavium.com). All rights
* ither the name of Cavium Inc. nor the names of
*     its contributors may be used to endorse or promote products
*     derived from this software without specific prior written
*     permission.

* This Software, increserved.
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

*This Software,including technical data,may be subject to U.S. export control
* laws, including the U.S. Export Administration Act and its  associated
* regulations, and may be subject to export or import  regulations in other
* countries.

* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR
* WARRANTIES,EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO
*THE SOFTWARE,INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR
* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
***********************license end**************************************/


/*
 * File version info: $Id: passthrough.c 87283 2013-08-23 18:13:43Z lrosenboim $
 *
 */

#include <stdio.h>
#include <string.h>
#include "cvmx.h"
#include "cvmx-helper.h"
#include "cvmx-pki.h"
#include "cvmx-helper-pki.h"
#include "cvmx-pki-resources.h"
#include "passthrough.h"


/* If this data needed to be shared between applications use CVMX_SHARED or bootmem_alloc
whichever is appropriate */
struct cvmx_pki_global_schd pki_gbl_schd;
struct cvmx_pki_intf_schd pki_intf_schd[PKI_SCHD_MAX_INTERFACE];
static int pass_qos_debug;

int application_init_packet_input(int node, int num_buffers)
{
    struct cvmx_pki_intf_schd *intf_schd;
    struct cvmx_pki_prt_schd *prtsch;
    struct cvmx_pki_qos_schd *qossch;
    struct cvmx_pki_global_config gbl_cfg;
    cvmx_helper_interface_mode_t imode;
    int intf;
    int port;
    int qos;
    int num_ports;
    int num_intf;
    int num_qos;

    /* To Modify any global pki parameters */
    cvmx_pki_read_global_config(node, &gbl_cfg);
    gbl_cfg.stat_mode = CVMX_PKI_STAT_MODE_PKIND;
    cvmx_pki_write_global_config(node, &gbl_cfg);

    /* If user wants to allocate resource on their own, pass the allocated value after allocating them*/
    /* setup global schedluing parametrs, pool, aura, & sso group */
#if PKI_SETUP_GLOBAL_POOL
    pki_gbl_schd.setup_pool = TRUE;
    pki_gbl_schd.pool_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
    if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
            pki_gbl_schd.pool_max_buff = num_buffers;
    else
        pki_gbl_schd.pool_max_buff = PKI_GBL_POOL_MAX_BUFF;
    pki_gbl_schd.pool_buff_size = PKI_GBL_POOL_BUFF_SIZE;
    pki_gbl_schd.pool_name = "pkigblpool";
#endif
#if PKI_SETUP_GLOBAL_AURA
    pki_gbl_schd.setup_aura = TRUE;
    pki_gbl_schd.aura_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
    if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
            pki_gbl_schd.aura_buff_cnt = num_buffers;
    else
        pki_gbl_schd.aura_buff_cnt = PKI_GBL_POOL_MAX_BUFF;
    pki_gbl_schd.aura_name = "pkigblaura";
#endif
#if PKI_SETUP_GLOBAL_SSO_GRP
    pki_gbl_schd.setup_sso_grp = TRUE;
    pki_gbl_schd.sso_grp = CVMX_PKI_FIND_AVAILABLE_RSRC;
#endif
    cvmx_helper_pki_set_gbl_schd(node, &pki_gbl_schd);

    /* Setup interface scheduling if ports on that interface will use shared resources*/
    /* Evaluation board supports numorous interfaces and port,
	customer can setup only for the interfaces and ports they are using */
    /* Evaluation board will intialize all sgmii interface, ilk interfaces same way*/
	/* If RED and backpressure is desired per port, setup auras for every port */
	/* If for GMX interfaces back pressure is desired per PFC, setup auras per port per
	PFC (per qos)*/
	/* Initialize all BGX interfaces */
    num_intf = cvmx_helper_get_number_of_interfaces();
    for (intf = 0; intf < num_intf; intf++) {
        intf_schd = &pki_intf_schd[intf];
        num_ports = cvmx_helper_ports_on_interface(intf);
        /*Skip invalid/disabled interfaces */
        if (num_ports <= 0)
                continue;
        imode = cvmx_helper_interface_get_mode(intf);

        if (imode == CVMX_HELPER_INTERFACE_MODE_XAUI ||
		 imode == CVMX_HELPER_INTERFACE_MODE_RXAUI ||
                 imode == CVMX_HELPER_INTERFACE_MODE_XFI ||
                 imode == CVMX_HELPER_INTERFACE_MODE_10G_KR ||
                 imode == CVMX_HELPER_INTERFACE_MODE_XLAUI ||
                 imode == CVMX_HELPER_INTERFACE_MODE_40G_KR4)
        {
            intf_schd->style_per_intf = PKI_STYLE_PER_INTF_FLAG_BGX_SMAC;
            intf_schd->pool_per_intf = PKI_POOL_PER_INTF_FLAG_BGX_SMAC;
            intf_schd->aura_per_intf = PKI_AURA_PER_INTF_FLAG_BGX_SMAC;
            intf_schd->sso_grp_per_intf = PKI_SSO_GRP_PER_INTF_FLAG_BGX_SMAC;
            intf_schd->qos_share_aura = PKI_SHARE_AURA_QOS_FLAG_BGX_SMAC;
            intf_schd->qos_share_grp = PKI_SHARE_SSO_GRP_QOS_FLAG_BGX_SMAC;
        }
        else if (imode == CVMX_HELPER_INTERFACE_MODE_ILK)
        {
            intf_schd->style_per_intf = PKI_STYLE_PER_INTF_FLAG_ILK;
            intf_schd->pool_per_intf = PKI_POOL_PER_INTF_FLAG_ILK;
            intf_schd->aura_per_intf = PKI_AURA_PER_INTF_FLAG_ILK;
            intf_schd->sso_grp_per_intf = PKI_SSO_GRP_PER_INTF_FLAG_ILK;
            intf_schd->qos_share_aura = PKI_SHARE_AURA_QOS_FLAG_ILK;
            intf_schd->qos_share_grp = PKI_SHARE_SSO_GRP_QOS_FLAG_ILK;
        }
        else if (imode == CVMX_HELPER_INTERFACE_MODE_NPI)
        {
            intf_schd->style_per_intf = PKI_STYLE_PER_INTF_FLAG_NPI;
            intf_schd->pool_per_intf = PKI_POOL_PER_INTF_FLAG_NPI;
            intf_schd->aura_per_intf = PKI_AURA_PER_INTF_FLAG_NPI;
            intf_schd->sso_grp_per_intf = PKI_SSO_GRP_PER_INTF_FLAG_NPI;
            intf_schd->qos_share_aura = PKI_SHARE_AURA_QOS_FLAG_NPI;
            intf_schd->qos_share_grp = PKI_SHARE_SSO_GRP_QOS_FLAG_NPI;
        }
        else if (imode == CVMX_HELPER_INTERFACE_MODE_LOOP)
        {
            intf_schd->style_per_intf = PKI_STYLE_PER_INTF_FLAG_LOOP;
            intf_schd->pool_per_intf = PKI_POOL_PER_INTF_FLAG_LOOP;
            intf_schd->aura_per_intf = PKI_AURA_PER_INTF_FLAG_LOOP;
            intf_schd->sso_grp_per_intf = PKI_SSO_GRP_PER_INTF_FLAG_LOOP;
            intf_schd->qos_share_aura = PKI_SHARE_AURA_QOS_FLAG_LOOP;
            intf_schd->qos_share_grp = PKI_SHARE_SSO_GRP_QOS_FLAG_LOOP;
        }
	else
	{
	    intf_schd->style_per_intf = PKI_STYLE_PER_INTF_FLAG_SGMII;
	    intf_schd->pool_per_intf = PKI_POOL_PER_INTF_FLAG_SGMII;
	    intf_schd->aura_per_intf = PKI_AURA_PER_INTF_FLAG_SGMII;
	    intf_schd->sso_grp_per_intf = PKI_SSO_GRP_PER_INTF_FLAG_SGMII;
	    intf_schd->qos_share_aura = PKI_SHARE_AURA_QOS_FLAG_SGMII;
	    intf_schd->qos_share_grp = PKI_SHARE_SSO_GRP_QOS_FLAG_SGMII;
	}
        if (intf_schd->style_per_intf) {
            intf_schd->style = CVMX_PKI_FIND_AVAILABLE_RSRC;
            intf_schd->qpg_base = CVMX_PKI_FIND_AVAILABLE_RSRC;
            if (intf_schd->pool_per_intf) {
                intf_schd->pool_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
                if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
                    intf_schd->pool_max_buff = num_buffers;
                else
                    intf_schd->pool_max_buff = PKI_INTF_POOL_MAX_BUFFERS;
                intf_schd->pool_buff_size = PKI_INTF_POOL_BUFFER_SIZE;
                intf_schd->pool_name = "pkiintfpool";
            }
            if (intf_schd->aura_per_intf) {
                intf_schd->aura_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
                if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM)
                        intf_schd->aura_buff_cnt = num_buffers;
                else
                    intf_schd->aura_buff_cnt = PKI_INTF_AURA_BUFFER_COUNT;
                intf_schd->aura_name = "pkiintfaura";
            }
            if (intf_schd->sso_grp_per_intf)
                intf_schd->sso_grp = CVMX_PKI_FIND_AVAILABLE_RSRC;
        }
	else { /* All ports will have their own styles*/
		for (port = 0; port < num_ports; port++)
			prtsch->style = CVMX_PKI_FIND_AVAILABLE_RSRC;
	}
	/* style per interface can still use pool/aura/grp per port or per qos*/
	/* if pools are sharing aura per qos they will have to use same pool and aura resources
	either from interface or from qos but not from per pool*/
        for (port = 0; port < num_ports; port++) {
            prtsch = &intf_schd->prt_s[port];
            if (imode == CVMX_HELPER_INTERFACE_MODE_XAUI ||
                imode == CVMX_HELPER_INTERFACE_MODE_RXAUI ||
                imode == CVMX_HELPER_INTERFACE_MODE_XFI ||
                imode == CVMX_HELPER_INTERFACE_MODE_10G_KR ||
                imode == CVMX_HELPER_INTERFACE_MODE_XLAUI ||
                imode == CVMX_HELPER_INTERFACE_MODE_40G_KR4)
            {
                prtsch->pool_per_prt = PKI_POOL_PER_PORT_FLAG_BGX_SMAC;
                prtsch->aura_per_prt = PKI_AURA_PER_PORT_FLAG_BGX_SMAC;
                prtsch->sso_grp_per_prt = PKI_SSO_GRP_PER_PORT_FLAG_BGX_SMAC;
                prtsch->qpg_qos =  PKI_QPG_QOS_BGX_SMAC;
            }
            else if (imode == CVMX_HELPER_INTERFACE_MODE_ILK)
            {
                prtsch->pool_per_prt = PKI_POOL_PER_PORT_FLAG_ILK;
                prtsch->aura_per_prt = PKI_AURA_PER_PORT_FLAG_ILK;
                prtsch->sso_grp_per_prt = PKI_SSO_GRP_PER_PORT_FLAG_ILK;
                prtsch->qpg_qos = PKI_QPG_QOS_ILK;
            }
            else if (imode == CVMX_HELPER_INTERFACE_MODE_NPI)
            {
                prtsch->pool_per_prt = PKI_POOL_PER_PORT_FLAG_NPI;
                prtsch->aura_per_prt = PKI_AURA_PER_PORT_FLAG_NPI;
                prtsch->sso_grp_per_prt = PKI_SSO_GRP_PER_PORT_FLAG_NPI;
                prtsch->qpg_qos = PKI_QPG_QOS_NPI;
            }
            else if (imode == CVMX_HELPER_INTERFACE_MODE_ILK)
            {
                prtsch->pool_per_prt = PKI_POOL_PER_PORT_FLAG_LOOP;
                prtsch->aura_per_prt = PKI_AURA_PER_PORT_FLAG_LOOP;
                prtsch->sso_grp_per_prt = PKI_SSO_GRP_PER_PORT_FLAG_LOOP;
                prtsch->qpg_qos = PKI_QPG_QOS_LOOP;
            }
            else
            {
                prtsch->pool_per_prt = PKI_POOL_PER_PORT_FLAG_SGMII;
                prtsch->aura_per_prt = PKI_AURA_PER_PORT_FLAG_SGMII;
                prtsch->sso_grp_per_prt = PKI_SSO_GRP_PER_PORT_FLAG_SGMII;
                prtsch->qpg_qos =  PKI_QPG_QOS_SGMII;
            }
            if (prtsch->qpg_qos && intf_schd->qos_share_aura && prtsch->pool_per_prt) {
                cvmx_dprintf("passthrough: port sharing aura qos can't have pool_per_port set\n");
                return -1;
            }
            if (prtsch->qpg_qos && intf_schd->qos_share_grp && prtsch->sso_grp_per_prt) {
                cvmx_dprintf("passthrough: port sharing aura grp can't have sso_grp_per_port set\n");
                return -1;
            }
            prtsch->qpg_base = CVMX_PKI_FIND_AVAILABLE_RSRC;
            if (prtsch->pool_per_prt) {
                prtsch->pool_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
                if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM) {
#ifdef SINGLE_PORT_SIM
                    prtsch->pool_max_buff = num_buffers;
#else
                    prtsch->pool_max_buff = num_buffers/4;
#endif
                }
                else
                    prtsch->pool_max_buff = PKI_PORT_POOL_MAX_BUFFERS;
                prtsch->pool_buff_size = PKI_PORT_POOL_BUFFER_SIZE;
                prtsch->pool_name = "pkiportpool";
            }
            if (prtsch->aura_per_prt) {
                prtsch->aura_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
                if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM) {
#ifdef SINGLE_PORT_SIM
                    prtsch->aura_buff_cnt = num_buffers;
#else
                    prtsch->aura_buff_cnt = num_buffers/4;
#endif
                }
                else
                    prtsch->aura_buff_cnt = PKI_PORT_AURA_BUFFER_COUNT;
                prtsch->aura_name = "pkiportaura";
            }
            if (prtsch->sso_grp_per_prt)
                prtsch->sso_grp = CVMX_PKI_FIND_AVAILABLE_RSRC;
            if (prtsch->qpg_qos) {
                num_qos = cvmx_helper_pki_get_num_qpg_entry(prtsch->qpg_qos);
                for (qos = 0; qos < num_qos; qos++) {
                    qossch = &prtsch->qos_s[qos];
                    if (imode == CVMX_HELPER_INTERFACE_MODE_XAUI ||
                        imode == CVMX_HELPER_INTERFACE_MODE_RXAUI ||
                        imode == CVMX_HELPER_INTERFACE_MODE_XFI ||
                        imode == CVMX_HELPER_INTERFACE_MODE_10G_KR ||
                        imode == CVMX_HELPER_INTERFACE_MODE_XLAUI ||
                        imode == CVMX_HELPER_INTERFACE_MODE_40G_KR4)
                    {
                        qossch->pool_per_qos = PKI_POOL_PER_QOS_FLAG_BGX_SMAC;
                        qossch->aura_per_qos = PKI_AURA_PER_QOS_FLAG_BGX_SMAC;
                        qossch->sso_grp_per_qos = PKI_SSO_GRP_PER_QOS_FLAG_BGX_SMAC;
                    }
                    else if (imode == CVMX_HELPER_INTERFACE_MODE_ILK)
                    {
                        qossch->pool_per_qos = PKI_POOL_PER_QOS_FLAG_ILK;
                        qossch->aura_per_qos = PKI_AURA_PER_QOS_FLAG_ILK;
                        qossch->sso_grp_per_qos = PKI_SSO_GRP_PER_QOS_FLAG_ILK;
                    }
                    else if (imode == CVMX_HELPER_INTERFACE_MODE_NPI)
                    {
                        qossch->pool_per_qos = PKI_POOL_PER_QOS_FLAG_NPI;
                        qossch->aura_per_qos = PKI_AURA_PER_QOS_FLAG_NPI;
                        qossch->sso_grp_per_qos = PKI_SSO_GRP_PER_QOS_FLAG_NPI;
                    }
                    else if (imode == CVMX_HELPER_INTERFACE_MODE_LOOP)
                    {
                        qossch->pool_per_qos = PKI_POOL_PER_QOS_FLAG_LOOP;
                        qossch->aura_per_qos = PKI_AURA_PER_QOS_FLAG_LOOP;
                        qossch->sso_grp_per_qos = PKI_SSO_GRP_PER_QOS_FLAG_LOOP;
                    }
                    else
                    {
                        qossch->pool_per_qos = PKI_POOL_PER_QOS_FLAG_SGMII;
                        qossch->aura_per_qos = PKI_AURA_PER_QOS_FLAG_SGMII;
                        qossch->sso_grp_per_qos = PKI_SSO_GRP_PER_QOS_FLAG_SGMII;
                    }
                    if (!pki_gbl_schd.setup_pool && !intf_schd->pool_per_intf &&
                         !prtsch->pool_per_prt && !qossch->pool_per_qos) {
                        cvmx_dprintf("passthrough: no pool config for pki\n");
                        return -1;
                    }
                    if (!pki_gbl_schd.setup_aura && !intf_schd->aura_per_intf &&
                         !prtsch->aura_per_prt && !qossch->aura_per_qos) {
                        cvmx_dprintf("passthrough: no aura config for pki\n");
                        return -1;
                    }
                    if (!pki_gbl_schd.setup_sso_grp && !intf_schd->sso_grp_per_intf &&
                         !prtsch->sso_grp_per_prt && !qossch->sso_grp_per_qos) {
                        cvmx_dprintf("passthrough: no sso grp config for pki\n");
                        return -1;
                    }
                    if (prtsch->pool_per_prt && qossch->pool_per_qos) {
                        cvmx_dprintf("Invalid Qos Pool configuration\n");
                        return -1;
                    }
                    qossch->port_add = PKI_QOS_PORT_ADD_INC * qos;
                    if (qossch->pool_per_qos) {
                        if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM) {
#ifdef SINGLE_PORT_SIM
                            qossch->pool_max_buff = num_buffers/num_qos;
#else
                            qossch->pool_max_buff = num_buffers;
#endif
                        }
                        else
                            qossch->pool_max_buff = PKI_QOS_POOL_MAX_BUFFERS;
                        qossch->pool_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
                        qossch->pool_buff_size = PKI_QOS_POOL_BUFFER_SIZE;
                        qossch->pool_name = "pkiqospool";
                    }
                    if (qossch->aura_per_qos) {
                        qossch->aura_num = CVMX_PKI_FIND_AVAILABLE_RSRC;
                        if (cvmx_sysinfo_get()->board_type == CVMX_BOARD_TYPE_SIM) {
                            if (prtsch->pool_per_prt)
                                qossch->aura_buff_cnt = prtsch->pool_max_buff/num_qos;
                            else if (qossch->pool_per_qos)
                                qossch->aura_buff_cnt = qossch->pool_max_buff/num_qos;
                            else
                                qossch->aura_buff_cnt = num_buffers/num_qos;
                        }
                        else
                            qossch->aura_buff_cnt = PKI_QOS_AURA_BUFFER_COUNT;
                        qossch->aura_name = "pkiqosaura";
                    }
                    if (qossch->sso_grp_per_qos) {
                        qossch->sso_grp = CVMX_PKI_FIND_AVAILABLE_RSRC;
                    }
                }
            }
        }
        /*convert to xiface*/
	cvmx_helper_pki_init_interface(cvmx_helper_node_interface_to_xiface(node, intf), intf_schd, &pki_gbl_schd);
    }
    return 0;
}

void application_setup_pki_ports(int node)
{
    struct cvmx_pki_style_config style_cfg;
    struct cvmx_pki_pkind_config pkind_cfg;
    struct cvmx_pki_intf_schd *intfsch;
    struct cvmx_pki_prt_schd *prtsch;
    struct cvmx_pki_qos_schd *qossch;
    cvmx_helper_interface_mode_t imode;
    int intf;
    int port;
    int pkind;
    int num_ports;
    int num_intf;
    uint16_t bpid;
    uint16_t bpid_q[64];
    uint16_t aura;
    bool ena_bp = 0, ena_red = 0, ena_drop = 0;
    uint16_t chl_map[CVMX_MAX_PORT_PER_INTERFACE];
    uint64_t pass_thresh = 0;
    uint64_t drop_thresh = 0;
    uint64_t bp_thresh = 0;
    uint8_t qos;
    uint8_t num_qos;

#if PKI_ENABLE_BACK_PRESSURE
    /* Enable bgx back pressure */
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
        ena_bp = 1;
#endif
#if PKI_ENABLE_RED
    if (cvmx_sysinfo_get()->board_type != CVMX_BOARD_TYPE_SIM)
    {
        ena_red = 1;
        ena_drop = 0;
    }
#else
    /* PKI_19103, if RED is not enabled make fpa_wait=1 */
    cvmx_helper_pki_errata(node);
#endif
    num_intf = cvmx_helper_get_number_of_interfaces();
    for (intf = 0; intf < num_intf; intf++)
    {
        num_ports = cvmx_helper_ports_on_interface(intf);
        if (num_ports <= 0)
            continue;
        intfsch = &pki_intf_schd[intf];
        /* Modify all port style related parameters */
        /* If all ports on particular interface are using same style then
        style related parameters needs to be modified only once */
        for (port = 0; port < num_ports; port++)
        {
            prtsch = &intfsch->prt_s[port];

            cvmx_pki_read_style_config(node, prtsch->style,
                                      CVMX_PKI_CLUSTER_ALL, &style_cfg);
            style_cfg.parm_cfg.dis_wq_dat = PKI_SEPARATE_WQE_BUFF;
#ifdef __LITTLE_ENDIAN_BITFIELD
            style_cfg.parm_cfg.pkt_lend = 1;
#endif
            imode = cvmx_helper_interface_get_mode(intf);
            if (imode == CVMX_HELPER_INTERFACE_MODE_NPI)
            {
                style_cfg.parm_cfg.lenerr_en = 0;
                style_cfg.parm_cfg.maxerr_en = 0;
                style_cfg.parm_cfg.minerr_en = 0;
            }
            else if (imode != CVMX_HELPER_INTERFACE_MODE_LOOP)
            {
                style_cfg.parm_cfg.lenerr_en = 1;
                style_cfg.parm_cfg.maxerr_en = 0;
                style_cfg.parm_cfg.minerr_en = 0;
            }
            cvmx_pki_write_style_config(node, prtsch->style,
                                        CVMX_PKI_CLUSTER_ALL, &style_cfg);
            /* port paramets*/
            pkind = cvmx_helper_get_pknd(intf, port);
            cvmx_pki_read_pkind_config(node, pkind, &pkind_cfg);
            pkind_cfg.parse_en.mpls_en = 1;
            cvmx_pki_write_pkind_config(node, pkind, &pkind_cfg);
        }
        if (intfsch->aura_per_intf)
        {
	    bpid = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);
            /* map aura to bpid */
            aura = intfsch->aura_num;
            if (pass_qos_debug)
            {
                cvmx_dprintf("aura %d assert bp on bpid %d\n", (int)aura, (int)bpid);
                cvmx_dprintf("bpid %d assert bp on channels:",bpid);
            }
            /*map bpid to all ports/channels */
            for (port = 0; port < num_ports; port++)
            {
                prtsch = &intfsch->prt_s[port];
		chl_map[port] = (uint16_t)cvmx_helper_get_ipd_port(intf, port) & (CVMX_PKI_NUM_CHANNEL-1);
                if (pass_qos_debug)
                    cvmx_dprintf("   %d", (int)chl_map[port]);
                    /* Add portadd for PFC */
            }
            if (pass_qos_debug)
                cvmx_dprintf("\n");
            /* If not all port or channel on that interface needs to back pressure then
            only map what is needed */
            cvmx_helper_pki_map_aura_chl_bpid(node, aura, bpid, chl_map, num_ports);
            /* configure aura thresholds and enable pki and aura for back pressure */
            /* Due to errata pki-19103 make sure that packet dropping is enabled at
            128 * (b+1), wher b is number of buffers required to fill the maximum packet size
            which is 32K pre Pass 2.0 */
            pass_thresh = (1 * intfsch->aura_buff_cnt)/3;
            drop_thresh = (3 * intfsch->aura_buff_cnt)/5;
            bp_thresh = (3 * intfsch->aura_buff_cnt)/4;
            cvmx_helper_setup_aura_qos(node, aura, ena_red, ena_drop,
                                       pass_thresh, drop_thresh, ena_bp, bp_thresh);
            if (pass_qos_debug)
            {
                cvmx_dprintf("aura %d fpa_cnt_levels 0x%llx\n",(int)aura,
                             (unsigned long long)cvmx_read_csr_node(node,CVMX_FPA_AURAX_CNT_LEVELS(aura)));
                cvmx_dprintf("aura %d pki_aura_cfg 0x%llx\n", (int)aura,
                             (unsigned long long) cvmx_read_csr_node(node, CVMX_PKI_AURAX_CFG(aura)));
            }
            for (port = 0; port < num_ports; port++)
            {
                if (pass_qos_debug)
                    cvmx_dprintf("channel %d pki_chan_cfg cfg = 0x%llx\n", chl_map[port],
                                         (unsigned long long)cvmx_read_csr_node(node,CVMX_PKI_CHANX_CFG(chl_map[port])));
            }
            if (pass_qos_debug)
                cvmx_dprintf("fpa_aura0_cnt %d\n", (int)cvmx_read_csr_node(0,CVMX_FPA_AURAX_CNT(0)));
        }
        else
        {
            /*map bpid to all ports/channels */
            for (port = 0; port < num_ports; port++)
            {
                prtsch = &intfsch->prt_s[port];
                if (prtsch->aura_per_prt)
                {
                    /* map aura to bpid */
                    aura = prtsch->aura_num;
		    bpid = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);//dont use bpid 0 which all channles are mapped to by default
		    chl_map[0] = (uint16_t)cvmx_helper_get_ipd_port(intf, port) & (CVMX_PKI_NUM_CHANNEL-1);
                    if (pass_qos_debug)
                    {
                        cvmx_dprintf("aura %d assert bp on bpid %d\n", (int)aura, (int)bpid);
                        cvmx_dprintf("bpid %d assert bp on channel %d\n",bpid, (int)chl_map[0]);
                        cvmx_helper_pki_map_aura_chl_bpid(node, aura, bpid, chl_map, 1);
                    }
                    /* configure aura thresholds and enable pki and aura for back pressure */
                    pass_thresh = (1 * prtsch->aura_buff_cnt)/3;
                    drop_thresh = (3 * prtsch->aura_buff_cnt)/5;
                    bp_thresh = (3 * prtsch->aura_buff_cnt)/4;
                    cvmx_helper_setup_aura_qos(node, aura, ena_red, ena_drop,
                                               pass_thresh, drop_thresh, ena_bp, bp_thresh);
                    if (pass_qos_debug)
                    {
                        cvmx_dprintf("aura %d fpa_cnt_levels 0x%llx\n",(int)aura,
                                        (unsigned long long)cvmx_read_csr_node(node, CVMX_FPA_AURAX_CNT_LEVELS(aura)));
                        cvmx_dprintf("aura %d pki_aura_cfg 0x%llx\n", (int)aura,
                                        (unsigned long long)cvmx_read_csr_node(node, CVMX_PKI_AURAX_CFG(aura)));
                        cvmx_dprintf("channel %d pki_chan_cfg cfg = 0x%llx\n", chl_map[0],
                                        (unsigned long long)cvmx_read_csr_node(node,CVMX_PKI_CHANX_CFG(chl_map[0])));
                        cvmx_dprintf("fpa_aura0_cnt %d\n", (int)cvmx_read_csr_node(0,CVMX_FPA_AURAX_CNT(0)));
                    }
                }
                else
                {
                    num_qos = cvmx_helper_pki_get_num_qpg_entry(prtsch->qpg_qos);
                    for (qos = 0; qos < num_qos; qos++)
                    {
                        qossch = &prtsch->qos_s[qos];
                        if (!qossch->aura_per_qos)
                        {
                            aura = pki_gbl_schd.aura_num;
			    bpid = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);
                            /* configure aura thresholds and enable pki and aura for back pressure */
                            pass_thresh = (1 * pki_gbl_schd.aura_buff_cnt)/3;
                            drop_thresh = (3 * pki_gbl_schd.aura_buff_cnt)/5;
                            bp_thresh = (3 * pki_gbl_schd.aura_buff_cnt)/4;
			    chl_map[0] = (uint16_t)cvmx_helper_get_ipd_port(intf, port) & (CVMX_PKI_NUM_CHANNEL-1);
                        }
                        else
                        {
                            aura = qossch->aura_num;
			    if (intfsch->qos_share_aura) {
				if (port == 0)
				    bpid_q[qos] =  cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);
				bpid = bpid_q[qos];
			    }
                            else
				bpid = cvmx_pki_bpid_alloc(node, CVMX_PKI_FIND_AVAL_ENTRY);
                            pass_thresh = (1 * qossch->aura_buff_cnt)/3;
                            drop_thresh = (3 * qossch->aura_buff_cnt)/5;
                            bp_thresh = (3 * qossch->aura_buff_cnt)/4;
			    chl_map[0] = ((uint16_t)cvmx_helper_get_ipd_port(intf, port) & (CVMX_PKI_NUM_CHANNEL-1))
					    + qossch->port_add;
                        }
                        if (pass_qos_debug)
                        {
                            cvmx_dprintf("aura %d assert bp on bpid %d\n", (int)aura, (int)bpid);
                            cvmx_dprintf("bpid %d assert bp on channel %d\n",bpid, (int)chl_map[0]);
                        }
                        cvmx_helper_pki_map_aura_chl_bpid(node, aura, bpid, chl_map, 1);
                        cvmx_helper_setup_aura_qos(node, aura, ena_red, ena_drop,
                                pass_thresh, drop_thresh, ena_bp, bp_thresh);
                        if (pass_qos_debug)
                        {
                            cvmx_dprintf("aura %d fpa_cnt_levels 0x%llx\n",(int)aura,
                                         (unsigned long long)cvmx_read_csr_node(node,CVMX_FPA_AURAX_CNT_LEVELS(aura)));
                            cvmx_dprintf("aura %d pki_aura_cfg 0x%llx\n", (int)aura,
                                         (unsigned long long)cvmx_read_csr_node(node, CVMX_PKI_AURAX_CFG(aura)));
                            cvmx_dprintf("channel %d pki_chan_cfg cfg = 0x%llx\n", chl_map[0],
                                         (unsigned long long)cvmx_read_csr_node(node,CVMX_PKI_CHANX_CFG(chl_map[0])));
                        }
                    }
                }
            }
        }
    }
}

