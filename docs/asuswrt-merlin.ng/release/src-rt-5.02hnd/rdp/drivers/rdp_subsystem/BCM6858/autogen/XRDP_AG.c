/*
   Copyright (c) 2015 Broadcom
   All Rights Reserved

    <:label-BRCM:2015:DUAL/GPL:standard

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

#include "ru.h"

/******************************************************************************
 * Chip: XRDP_
 ******************************************************************************/
const ru_block_rec *RU_ALL_BLOCKS[] =
{
    &QM_BLOCK,
    &DQM_BLOCK,
    &RNR_MEM_BLOCK,
    &RNR_INST_BLOCK,
    &RNR_CNTXT_BLOCK,
    &RNR_PRED_BLOCK,
    &RNR_REGS_BLOCK,
    &RNR_QUAD_BLOCK,
    &PSRAM_BLOCK,
    &FPM_BLOCK,
    &DSPTCHR_BLOCK,
    &UBUS_MSTR_BLOCK,
    &UBUS_SLV_BLOCK,
    &XLIF_RX_IF_BLOCK,
    &XLIF_RX_FLOW_CONTROL_BLOCK,
    &XLIF_TX_IF_BLOCK,
    &XLIF_TX_FLOW_CONTROL_BLOCK,
    &DEBUG_BUS_BLOCK,
    &XLIF_EEE_BLOCK,
    &SBPM_BLOCK,
    &DMA_BLOCK,
    &TCAM_BLOCK,
    &HASH_BLOCK,
    &CNPL_BLOCK,
    &NATC_BLOCK,
    &NATC_ENG_BLOCK,
    &NATC_CFG_BLOCK,
    &NATC_CTRS_BLOCK,
    &NATC_INDIR_BLOCK,
    &BBH_TX_BLOCK,
    &BBH_RX_BLOCK,
    NULL
};

/* End of file XRDP_.c */
