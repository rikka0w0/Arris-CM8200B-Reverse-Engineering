/*
    <:copyright-BRCM:2015:DUAL/GPL:standard
    
       Copyright (c) 2015 Broadcom 
       All Rights Reserved
    
    Unless you and Broadcom execute a separate written software license
    agreement governing use of this software, this software is licensed
    to you under the terms of the GNU General Public License version 2
    (the "GPL"), available at http://www.broadcom.com/licenses/GPLv2.php,
    with the following added to such license:
    
       As a special exception, the copyright holders of this software give
       you permission to link this software with independent modules, and
       to copy and distribute the resulting executable under terms of your
       choice, provided that you also meet, for each linked independent
       module, the terms and conditions of the license of that module.
       An independent module is a module which is not derived from this
       software.  The special exception does not apply to any modifications
       of the software.
    
    Not withstanding the above, under no circumstances may you combine
    this software in any way with any other Broadcom software provided
    under a license other than the GPL, without Broadcom's express prior
    written consent.
    
    :>
*/

#include "rdp_common.h"
#include "rdd_data_structures_auto.h"

#ifdef USE_BDMF_SHELL

struct bdmfmon_enum_val bbh_id_enum_table[] = {
    {"EMAC_0", BBH_ID_XLMAC0_0_10G},
    {"EMAC_1", BBH_ID_XLMAC0_1_2p5G},
    {"EMAC_2", BBH_ID_XLMAC0_2_1G},
    {"EMAC_3", BBH_ID_XLMAC0_3_1G},
    {"EMAC_4", BBH_ID_XLMAC1_0_RGMII},
    {"EMAC_5", BBH_ID_XLMAC1_1_RGMII},
    {"EMAC_6", BBH_ID_XLMAC1_2_RGMII},
    {"WAN",    BBH_ID_PON},
    {NULL, 0},
};

struct bdmfmon_enum_val rnr_id_enum_table[] = {
    {"RNR_0", RNR_CORE0_ID},
    {"RNR_1", RNR_CORE1_ID},
    {"RNR_2", RNR_CORE2_ID},
    {"RNR_3", RNR_CORE3_ID},
    {"RNR_4", RNR_CORE4_ID},
    {"RNR_5", RNR_CORE5_ID},
    {"RNR_6", RNR_CORE6_ID},
    {"RNR_7", RNR_CORE7_ID},
    {"RNR_8", RNR_CORE8_ID},
    {"RNR_9", RNR_CORE9_ID},
    {"RNR_10", RNR_CORE10_ID},
    {"RNR_11", RNR_CORE11_ID},
    {"RNR_12", RNR_CORE12_ID},
    {"RNR_13", RNR_CORE13_ID},
    {"RNR_14", RNR_CORE14_ID},
    {"RNR_15", RNR_CORE15_ID},
    {NULL, 0},
};

struct bdmfmon_enum_val quad_idx_enum_table[] = {
    {"RNR_QUAD_0", RNR_QUAD0_ID},
    {"RNR_QUAD_1", RNR_QUAD1_ID},
    {"RNR_QUAD_2", RNR_QUAD2_ID},
    {"RNR_QUAD_3", RNR_QUAD3_ID},
    {NULL, 0},
};

#endif
