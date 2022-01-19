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

#ifndef _XRDP_DRV_BBH_TX_AG_H_
#define _XRDP_DRV_BBH_TX_AG_H_

#include "access_macros.h"
#include "bdmf_interface.h"
#ifdef USE_BDMF_SHELL
#include "bdmf_shell.h"
#endif
#include "rdp_common.h"


/**************************************************************************************************/
/* fpmsrc: FPM_source_id - source id. This id is used to determine the route to the module.       */
/* sbpmsrc: SBPM_source_id - source id. This id is used to determine the route to the module.     */
/* stsrnrsrc: Status_Runner_source_id - source id. This id is used to determine the route to the  */
/*            Runner that is responsible for sending status messages (WAN only).                  */
/* msgrnrsrc: Message_Runner_source_id - source id. This id is used to determine the route to the */
/*             Runner which is responsible for sending DBR/Ghost messages (WAN only).             */
/**************************************************************************************************/
typedef struct
{
    uint8_t fpmsrc;
    uint8_t sbpmsrc;
    uint8_t stsrnrsrc;
    uint8_t msgrnrsrc;
} bbh_tx_cfg_src_id;


/**************************************************************************************************/
/* dmasrc: DMA_source_id - source id. This id is used to determine the route to the module.       */
/* descbase: Descriptor_FIFO_base - Defines the base address of the read request FIFO within the  */
/*           DMA address space.The value should be identical to the relevant configuration in the */
/*            DMA.                                                                                */
/* descsize: Descriptor_FIFO_size - The size of the BBH read requests FIFO inside the DMA         */
/**************************************************************************************************/
typedef struct
{
    uint8_t dmasrc;
    uint8_t descbase;
    uint8_t descsize;
} bbh_tx_bbh_dma_cfg;


/**************************************************************************************************/
/* sdmasrc: SDMA_source_id - source id. This id is used to determine the route to the module.     */
/* descbase: Descriptor_FIFO_base - Defines the base address of the read request FIFO within the  */
/*           DMA address space.The value should be identical to the relevant configuration in the */
/*            DMA.                                                                                */
/* descsize: Descriptor_FIFO_size - The size of the BBH read requests FIFO inside the DMA         */
/**************************************************************************************************/
typedef struct
{
    uint8_t sdmasrc;
    uint8_t descbase;
    uint8_t descsize;
} bbh_tx_bbh_sdma_cfg;


/**************************************************************************************************/
/* bufsize: DDR_buffer_size - The data is arranged in the DDR in a fixed size buffers.            */
/* byteresul: PO_bytes_resulotion - The packet offset byte resulotion.                            */
/* ddrtxoffset: DDR_tx_offset - Static offset in 8-bytes resolution for non aggregated packets in */
/*               DDR                                                                              */
/* hnsize0: HN_size_0 - The size of the HN (Header number) in bytes. The BBH decides between size */
/*           0 and size 1 according to a bit in the PD                                            */
/* hnsize1: HN_size_1 - The size of the HN (Header number) in bytes. The BBH decides between size */
/*           0 and size 1 according to a bit in the PD                                            */
/**************************************************************************************************/
typedef struct
{
    uint8_t bufsize;
    bdmf_boolean byteresul;
    uint16_t ddrtxoffset;
    uint8_t hnsize0;
    uint8_t hnsize1;
} bbh_tx_bbh_ddr_cfg;


/**************************************************************************************************/
/* srampd: SRAM_PD - This counter counts the number of packets which were transmitted from the SR */
/*         AM.                                                                                    */
/* ddrpd: DDR_PD - This counter counts the number of packets which were transmitted from the DDR. */
/* pddrop: PD_DROP - This counter counts the number of PDs which were dropped due to PD FIFO full */
/*         .                                                                                      */
/* stscnt: STS_CNT - This counter counts the number of received status messages.                  */
/* stsdrop: STS_DROP - This counter counts the number of STS which were dropped due to PD FIFO fu */
/*          ll.                                                                                   */
/* msgcnt: MSG_CNT - This counter counts the number of received DBR/ghost messages.               */
/* msgdrop: MSG_DROP - This counter counts the number of MSG which were dropped due to PD FIFO fu */
/*          ll.                                                                                   */
/* getnextnull: Get_next_is_null - This counter counts the number Get next responses with a null  */
/*              BN.                                                                               */
/* lenerr: LEN_ERR - This counter counts the number of times a length error occuered              */
/* aggrlenerr: AGGR_LEN_ERR - This counter counts the number of times an aggregation length error */
/*              occuered                                                                          */
/* srampkt: SRAM_PKT - This counter counts the number of packets which were transmitted from the  */
/*          SRAM.                                                                                 */
/* ddrpkt: DDR_PKT - This counter counts the number of packets which were transmitted from the DD */
/*         R.                                                                                     */
/* flshpkts: FLSH_PKTS - This counter counts the number of flushed packets                        */
/**************************************************************************************************/
typedef struct
{
    uint32_t srampd;
    uint32_t ddrpd;
    uint16_t pddrop;
    uint32_t stscnt;
    uint16_t stsdrop;
    uint32_t msgcnt;
    uint16_t msgdrop;
    uint16_t getnextnull;
    uint16_t lenerr;
    uint16_t aggrlenerr;
    uint32_t srampkt;
    uint32_t ddrpkt;
    uint16_t flshpkts;
} bbh_tx_debug_counters;


/**************************************************************************************************/
/* ddrtmbase: DDR_TM_BASE - DDR TM base.The address is in bytes resolution.The address should be  */
/*            aligned to 128 bytes.                                                               */
/**************************************************************************************************/
typedef struct
{
    uint32_t addr[2];
} bbh_tx_common_configurations_ddrtmbasel;


/**************************************************************************************************/
/* ddrtmbase: DDR_TM_BASE - MSB of DDR TM base.                                                   */
/**************************************************************************************************/
typedef struct
{
    uint32_t addr[2];
} bbh_tx_common_configurations_ddrtmbaseh;


/**************************************************************************************************/
/* cntxtrst: Context_reset - Writing 1 to this register will reset the segmentation context table */
/*           .The reset is done immediately. Reading this register will always return 0.          */
/* pdfiforst: PDs_FIFOs_reset - Writing 1 to this register will reset the PDs FIFOs.The reset is  */
/*            done immediately. Reading this register will always return 0.                       */
/* dmaptrrst: DMA_write_pointer_reset - Writing 1 to this register will reset the DMA write point */
/*            er.The reset is done immediately. Reading this register will always return 0.       */
/* sdmaptrrst: SDMA_write_pointer_reset - Writing 1 to this register will reset the SDMA write po */
/*             inter.The reset is done immediately. Reading this register will always return 0.Th */
/*             is register is relevalt only for Ethernet.                                         */
/* bpmfiforst: BPM_FIFO_reset - Writing 1 to this register will reset the BPM FIFO.The reset is d */
/*             one immediately. Reading this register will always return 0.                       */
/* sbpmfiforst: SBPM_FIFO_reset - Writing 1 to this register will reset the SBPM FIFO.The reset i */
/*              s done immediately. Reading this register will always return 0.This register is r */
/*              elevalt only for Ethernet.                                                        */
/* okfiforst: Order_Keeper_FIFO_reset - Writing 1 to this register will reset the order keeper FI */
/*            FO.The reset is done immediately. Reading this register will always return 0.This r */
/*            egister is relevalt only for Ethernet.                                              */
/* ddrfiforst: DDR_FIFO_reset - Writing 1 to this register will reset the DDR data FIFO.The reset */
/*              is done immediately. Reading this register will always return 0.This register is  */
/*             relevalt only for Ethernet.                                                        */
/* sramfiforst: SRAM_FIFO_reset - Writing 1 to this register will reset the SRAM data FIFO.The re */
/*              set is done immediately. Reading this register will always return 0.This register */
/*               is relevalt only for Ethernet.                                                   */
/* skbptrrst: SKB_PTR_reset - Writing 1 to this register will reset the SKB pointers.The reset is */
/*             done immediately. Reading this register will always return 0.                      */
/* stsfiforst: STS_FIFOs_reset - Writing 1 to this register will reset the EPON status FIFOs (per */
/*              queue 32 fifos).The reset is done immediately. Reading this register will always  */
/*             return 0.                                                                          */
/* reqfiforst: REQ_FIFO_reset - Writing 1 to this register will reset the EPON request FIFO (8 en */
/*             tries FIFO that holds the packet requests from the EPON MAC).The reset is done imm */
/*             ediately. Reading this register will always return 0.                              */
/* msgfiforst: MSG_FIFO_reset - Writing 1 to this register will reset the EPON/GPON MSG FIFOThe r */
/*             eset is done immediately. Reading this register will always return 0.              */
/* gnxtfiforst: GET_NXT_FIFO_reset - Writing 1 to this register will reset the GET NEXT FIFOsThe  */
/*              reset is done immediately. Reading this register will always return 0.            */
/* fbnfiforst: FIRST_BN_FIFO_reset - Writing 1 to this register will reset the FIRST BN FIFOsThe  */
/*             reset is done immediately. Reading this register will always return 0.             */
/**************************************************************************************************/
typedef struct
{
    bdmf_boolean cntxtrst;
    bdmf_boolean pdfiforst;
    bdmf_boolean dmaptrrst;
    bdmf_boolean sdmaptrrst;
    bdmf_boolean bpmfiforst;
    bdmf_boolean sbpmfiforst;
    bdmf_boolean okfiforst;
    bdmf_boolean ddrfiforst;
    bdmf_boolean sramfiforst;
    bdmf_boolean skbptrrst;
    bdmf_boolean stsfiforst;
    bdmf_boolean reqfiforst;
    bdmf_boolean msgfiforst;
    bdmf_boolean gnxtfiforst;
    bdmf_boolean fbnfiforst;
} bbh_tx_common_configurations_txrstcmd;


/**************************************************************************************************/
/* pdsel: pd_array_sel - rd from the PD FIFO                                                      */
/* pdvsel: pd_valid_array_sel - rd from the PD valid array                                        */
/* pdemptysel: pd_empty_array_sel - rd from the PD empty array                                    */
/* pdfullsel: pd_full_array_sel - rd from the PD Full array                                       */
/* pdbemptysel: pd_below_empty_array_sel - rd from the PD beliow empty array                      */
/* pdffwkpsel: pd_full_for_wakeup_array_sel - rd from the PD full for wakeup empty array          */
/* fbnsel: first_BN_array_sel - rd from the first BN array                                        */
/* fbnvsel: first_BN_valid_array_sel - rd from the first BN valid array                           */
/* fbnemptysel: first_BN_empty_array_sel - rd from the first BN empty array                       */
/* fbnfullsel: first_BN_full_array_sel - rd from the first BN full array                          */
/* getnextsel: get_next_array_sel - rd from the first Get Next array                              */
/* getnextvsel: get_next_valid_array_sel - rd from the get_next valid array                       */
/* getnextemptysel: get_next_empty_array_sel - rd from the get next empty array                   */
/* getnextfullsel: get_next_full_array_sel - rd from the get next full array                      */
/* gpncntxtsel: gpon_context_array_sel - rd from the gpon context array                           */
/* bpmsel: BPM_FIFO_sel - rd from the BPM FIFO                                                    */
/* bpmfsel: BPM_FLUSH_FIFO_sel - rd from the BPM FLUSH FIFO                                       */
/* sbpmsel: SBPM_FIFO_sel - rd from the SBPM FIFO                                                 */
/* sbpmfsel: SBPM_FLUSH_FIFO_sel - rd from the SBPM FLUSH FIFO                                    */
/* stssel: sts_array_sel - rd from the STS FIFO                                                   */
/* stsvsel: sts_valid_array_sel - rd from the STS valid array                                     */
/* stsemptysel: sts_empty_array_sel - rd from the STS empty array                                 */
/* stsfullsel: sts_full_array_sel - rd from the STS Full array                                    */
/* stsbemptysel: sts_below_empty_array_sel - rd from the STS beliow empty array                   */
/* stsffwkpsel: sts_full_for_wakeup_array_sel - rd from the STS full for wakeup empty array       */
/* msgsel: msg_array_sel - rd from the MSG FIFO                                                   */
/* msgvsel: msg_valid_array_sel - rd from the msg valid array                                     */
/* epnreqsel: epon_request_FIFO_sel - rd from the epon request FIFO                               */
/* datasel: DATA_FIFO_sel - rd from the DATA FIFO (SRAM and DDR)                                  */
/* reordersel: reorder_FIFO_sel - rd from the reorder FIFO                                        */
/* tsinfosel: Timestamp_info_FIFO_sel - rd from the Timestamp Info FIFO                           */
/* mactxsel: MAC_TX_FIFO_sel - rd from the MAC TX FIFO.                                           */
/**************************************************************************************************/
typedef struct
{
    bdmf_boolean pdsel;
    bdmf_boolean pdvsel;
    bdmf_boolean pdemptysel;
    bdmf_boolean pdfullsel;
    bdmf_boolean pdbemptysel;
    bdmf_boolean pdffwkpsel;
    bdmf_boolean fbnsel;
    bdmf_boolean fbnvsel;
    bdmf_boolean fbnemptysel;
    bdmf_boolean fbnfullsel;
    bdmf_boolean getnextsel;
    bdmf_boolean getnextvsel;
    bdmf_boolean getnextemptysel;
    bdmf_boolean getnextfullsel;
    bdmf_boolean gpncntxtsel;
    bdmf_boolean bpmsel;
    bdmf_boolean bpmfsel;
    bdmf_boolean sbpmsel;
    bdmf_boolean sbpmfsel;
    bdmf_boolean stssel;
    bdmf_boolean stsvsel;
    bdmf_boolean stsemptysel;
    bdmf_boolean stsfullsel;
    bdmf_boolean stsbemptysel;
    bdmf_boolean stsffwkpsel;
    bdmf_boolean msgsel;
    bdmf_boolean msgvsel;
    bdmf_boolean epnreqsel;
    bdmf_boolean datasel;
    bdmf_boolean reordersel;
    bdmf_boolean tsinfosel;
    bdmf_boolean mactxsel;
} bbh_tx_debug_counters_swrden;


/**************************************************************************************************/
/* dbgvec: Debug_vector - Selected debug vector.                                                  */
/**************************************************************************************************/
typedef struct
{
    uint32_t debug_out_reg[8];
} bbh_tx_debug_counters_dbgoutreg;

bdmf_error_t ag_drv_bbh_tx_mac_type_set(uint8_t bbh_id, uint8_t type);
bdmf_error_t ag_drv_bbh_tx_mac_type_get(uint8_t bbh_id, uint8_t *type);
bdmf_error_t ag_drv_bbh_tx_cfg_src_id_set(uint8_t bbh_id, const bbh_tx_cfg_src_id *cfg_src_id);
bdmf_error_t ag_drv_bbh_tx_cfg_src_id_get(uint8_t bbh_id, bbh_tx_cfg_src_id *cfg_src_id);
bdmf_error_t ag_drv_bbh_tx_rnr_src_id_set(uint8_t bbh_id, uint8_t pdrnr0src, uint8_t pdrnr1src);
bdmf_error_t ag_drv_bbh_tx_rnr_src_id_get(uint8_t bbh_id, uint8_t *pdrnr0src, uint8_t *pdrnr1src);
bdmf_error_t ag_drv_bbh_tx_bbh_dma_cfg_set(uint8_t bbh_id, const bbh_tx_bbh_dma_cfg *bbh_dma_cfg);
bdmf_error_t ag_drv_bbh_tx_bbh_dma_cfg_get(uint8_t bbh_id, bbh_tx_bbh_dma_cfg *bbh_dma_cfg);
bdmf_error_t ag_drv_bbh_tx_dma_max_otf_read_request_set(uint8_t bbh_id, uint8_t maxreq);
bdmf_error_t ag_drv_bbh_tx_dma_max_otf_read_request_get(uint8_t bbh_id, uint8_t *maxreq);
bdmf_error_t ag_drv_bbh_tx_dma_epon_urgent_set(uint8_t bbh_id, bdmf_boolean epnurgnt);
bdmf_error_t ag_drv_bbh_tx_dma_epon_urgent_get(uint8_t bbh_id, bdmf_boolean *epnurgnt);
bdmf_error_t ag_drv_bbh_tx_bbh_sdma_cfg_set(uint8_t bbh_id, const bbh_tx_bbh_sdma_cfg *bbh_sdma_cfg);
bdmf_error_t ag_drv_bbh_tx_bbh_sdma_cfg_get(uint8_t bbh_id, bbh_tx_bbh_sdma_cfg *bbh_sdma_cfg);
bdmf_error_t ag_drv_bbh_tx_sdma_max_otf_read_request_set(uint8_t bbh_id, uint8_t maxreq);
bdmf_error_t ag_drv_bbh_tx_sdma_max_otf_read_request_get(uint8_t bbh_id, uint8_t *maxreq);
bdmf_error_t ag_drv_bbh_tx_sdma_epon_urgent_set(uint8_t bbh_id, bdmf_boolean epnurgnt);
bdmf_error_t ag_drv_bbh_tx_sdma_epon_urgent_get(uint8_t bbh_id, bdmf_boolean *epnurgnt);
bdmf_error_t ag_drv_bbh_tx_bbh_ddr_cfg_set(uint8_t bbh_id, const bbh_tx_bbh_ddr_cfg *bbh_ddr_cfg);
bdmf_error_t ag_drv_bbh_tx_bbh_ddr_cfg_get(uint8_t bbh_id, bbh_tx_bbh_ddr_cfg *bbh_ddr_cfg);
bdmf_error_t ag_drv_bbh_tx_debug_counters_get(uint8_t bbh_id, bbh_tx_debug_counters *debug_counters);
bdmf_error_t ag_drv_bbh_tx_common_configurations_rnrcfg_1_set(uint8_t bbh_id, uint8_t rnr_cfg_index_1, uint16_t tcontaddr, uint16_t skbaddr);
bdmf_error_t ag_drv_bbh_tx_common_configurations_rnrcfg_1_get(uint8_t bbh_id, uint8_t rnr_cfg_index_1, uint16_t *tcontaddr, uint16_t *skbaddr);
bdmf_error_t ag_drv_bbh_tx_common_configurations_rnrcfg_2_set(uint8_t bbh_id, uint16_t rnr_cfg_index_2, uint16_t ptraddr, uint8_t task);
bdmf_error_t ag_drv_bbh_tx_common_configurations_rnrcfg_2_get(uint8_t bbh_id, uint16_t rnr_cfg_index_2, uint16_t *ptraddr, uint8_t *task);
bdmf_error_t ag_drv_bbh_tx_common_configurations_sbpmcfg_set(uint8_t bbh_id, bdmf_boolean freenocntxt, bdmf_boolean specialfree, uint8_t maxgn);
bdmf_error_t ag_drv_bbh_tx_common_configurations_sbpmcfg_get(uint8_t bbh_id, bdmf_boolean *freenocntxt, bdmf_boolean *specialfree, uint8_t *maxgn);
bdmf_error_t ag_drv_bbh_tx_common_configurations_ddrtmbasel_set(uint8_t bbh_id, uint8_t zero, const bbh_tx_common_configurations_ddrtmbasel *common_configurations_ddrtmbasel);
bdmf_error_t ag_drv_bbh_tx_common_configurations_ddrtmbasel_get(uint8_t bbh_id, uint8_t zero, bbh_tx_common_configurations_ddrtmbasel *common_configurations_ddrtmbasel);
bdmf_error_t ag_drv_bbh_tx_common_configurations_ddrtmbaseh_set(uint8_t bbh_id, uint8_t zero, const bbh_tx_common_configurations_ddrtmbaseh *common_configurations_ddrtmbaseh);
bdmf_error_t ag_drv_bbh_tx_common_configurations_ddrtmbaseh_get(uint8_t bbh_id, uint8_t zero, bbh_tx_common_configurations_ddrtmbaseh *common_configurations_ddrtmbaseh);
bdmf_error_t ag_drv_bbh_tx_common_configurations_dfifoctrl_set(uint8_t bbh_id, uint16_t psramsize, uint16_t ddrsize, uint16_t psrambase);
bdmf_error_t ag_drv_bbh_tx_common_configurations_dfifoctrl_get(uint8_t bbh_id, uint16_t *psramsize, uint16_t *ddrsize, uint16_t *psrambase);
bdmf_error_t ag_drv_bbh_tx_common_configurations_arb_cfg_set(uint8_t bbh_id, bdmf_boolean hightrxq);
bdmf_error_t ag_drv_bbh_tx_common_configurations_arb_cfg_get(uint8_t bbh_id, bdmf_boolean *hightrxq);
bdmf_error_t ag_drv_bbh_tx_common_configurations_bbroute_set(uint8_t bbh_id, uint16_t route, uint8_t dest, bdmf_boolean en);
bdmf_error_t ag_drv_bbh_tx_common_configurations_bbroute_get(uint8_t bbh_id, uint16_t *route, uint8_t *dest, bdmf_boolean *en);
bdmf_error_t ag_drv_bbh_tx_common_configurations_q2rnr_set(uint8_t bbh_id, uint8_t q_2_rnr_index, bdmf_boolean q0, bdmf_boolean q1);
bdmf_error_t ag_drv_bbh_tx_common_configurations_q2rnr_get(uint8_t bbh_id, uint8_t q_2_rnr_index, bdmf_boolean *q0, bdmf_boolean *q1);
bdmf_error_t ag_drv_bbh_tx_common_configurations_txrstcmd_set(uint8_t bbh_id, const bbh_tx_common_configurations_txrstcmd *common_configurations_txrstcmd);
bdmf_error_t ag_drv_bbh_tx_common_configurations_txrstcmd_get(uint8_t bbh_id, bbh_tx_common_configurations_txrstcmd *common_configurations_txrstcmd);
bdmf_error_t ag_drv_bbh_tx_common_configurations_dbgsel_set(uint8_t bbh_id, uint8_t dbgsel);
bdmf_error_t ag_drv_bbh_tx_common_configurations_dbgsel_get(uint8_t bbh_id, uint8_t *dbgsel);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdbase_set(uint8_t bbh_id, uint8_t wan_pd_base_index, uint16_t fifobase0, uint16_t fifobase1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdbase_get(uint8_t bbh_id, uint8_t wan_pd_base_index, uint16_t *fifobase0, uint16_t *fifobase1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdsize_set(uint8_t bbh_id, uint8_t wan_pd_size_index, uint16_t fifosize0, uint16_t fifosize1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdsize_get(uint8_t bbh_id, uint8_t wan_pd_size_index, uint16_t *fifosize0, uint16_t *fifosize1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdwkuph_set(uint8_t bbh_id, uint8_t wan_pd_wkup_index, uint8_t wkupthresh0, uint8_t wkupthresh1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdwkuph_get(uint8_t bbh_id, uint8_t wan_pd_wkup_index, uint8_t *wkupthresh0, uint8_t *wkupthresh1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pd_byte_th_set(uint8_t bbh_id, uint8_t wan_pd_byte_th_index, uint16_t pdlimit0, uint16_t pdlimit1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pd_byte_th_get(uint8_t bbh_id, uint8_t wan_pd_byte_th_index, uint16_t *pdlimit0, uint16_t *pdlimit1);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pd_byte_th_en_set(uint8_t bbh_id, bdmf_boolean pdlimiten);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pd_byte_th_en_get(uint8_t bbh_id, bdmf_boolean *pdlimiten);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdempty_set(uint8_t bbh_id, uint8_t empty);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_pdempty_get(uint8_t bbh_id, uint8_t *empty);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_stsrnrcfg_1_set(uint8_t bbh_id, uint8_t wan_sts_rnr_cfg_1_index, uint16_t tcontaddr);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_stsrnrcfg_1_get(uint8_t bbh_id, uint8_t wan_sts_rnr_cfg_1_index, uint16_t *tcontaddr);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_stsrnrcfg_2_set(uint8_t bbh_id, uint8_t wan_sts_rnr_cfg_2_index, uint16_t ptraddr, uint8_t task);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_stsrnrcfg_2_get(uint8_t bbh_id, uint8_t wan_sts_rnr_cfg_2_index, uint16_t *ptraddr, uint8_t *task);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_msgrnrcfg_1_set(uint8_t bbh_id, uint8_t wan_msg_rnr_cfg_1_index, uint16_t tcontaddr);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_msgrnrcfg_1_get(uint8_t bbh_id, uint8_t wan_msg_rnr_cfg_1_index, uint16_t *tcontaddr);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_msgrnrcfg_2_set(uint8_t bbh_id, uint8_t wan_msg_rnr_cfg_2_index, uint16_t ptraddr, uint8_t task);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_msgrnrcfg_2_get(uint8_t bbh_id, uint8_t wan_msg_rnr_cfg_2_index, uint16_t *ptraddr, uint8_t *task);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_epncfg_set(uint8_t bbh_id, bdmf_boolean stplenerr, bdmf_boolean cmp_width, bdmf_boolean considerfull, bdmf_boolean addcrc);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_epncfg_get(uint8_t bbh_id, bdmf_boolean *stplenerr, bdmf_boolean *cmp_width, bdmf_boolean *considerfull, bdmf_boolean *addcrc);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_flow2port_set(uint8_t bbh_id, uint32_t wdata, uint8_t a, bdmf_boolean cmd);
bdmf_error_t ag_drv_bbh_tx_wan_configurations_flow2port_get(uint8_t bbh_id, uint32_t *wdata, uint8_t *a, bdmf_boolean *cmd);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdbase_set(uint8_t bbh_id, uint16_t fifobase0, uint16_t fifobase1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdbase_get(uint8_t bbh_id, uint16_t *fifobase0, uint16_t *fifobase1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdsize_set(uint8_t bbh_id, uint16_t fifosize0, uint16_t fifosize1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdsize_get(uint8_t bbh_id, uint16_t *fifosize0, uint16_t *fifosize1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdwkuph_set(uint8_t bbh_id, uint8_t wkupthresh0, uint8_t wkupthresh1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdwkuph_get(uint8_t bbh_id, uint8_t *wkupthresh0, uint8_t *wkupthresh1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pd_byte_th_set(uint8_t bbh_id, uint16_t pdlimit0, uint16_t pdlimit1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pd_byte_th_get(uint8_t bbh_id, uint16_t *pdlimit0, uint16_t *pdlimit1);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pd_byte_th_en_set(uint8_t bbh_id, bdmf_boolean pdlimiten);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pd_byte_th_en_get(uint8_t bbh_id, bdmf_boolean *pdlimiten);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdempty_set(uint8_t bbh_id, uint8_t empty);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_pdempty_get(uint8_t bbh_id, uint8_t *empty);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_txthresh_set(uint8_t bbh_id, uint16_t ddrthresh, uint16_t sramthresh);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_txthresh_get(uint8_t bbh_id, uint16_t *ddrthresh, uint16_t *sramthresh);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_eee_set(uint8_t bbh_id, bdmf_boolean en);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_eee_get(uint8_t bbh_id, bdmf_boolean *en);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_ts_set(uint8_t bbh_id, bdmf_boolean en);
bdmf_error_t ag_drv_bbh_tx_lan_configurations_ts_get(uint8_t bbh_id, bdmf_boolean *en);
bdmf_error_t ag_drv_bbh_tx_debug_counters_srambyte_get(uint8_t bbh_id, uint32_t *srambyte);
bdmf_error_t ag_drv_bbh_tx_debug_counters_ddrbyte_get(uint8_t bbh_id, uint32_t *ddrbyte);
bdmf_error_t ag_drv_bbh_tx_debug_counters_swrden_set(uint8_t bbh_id, const bbh_tx_debug_counters_swrden *debug_counters_swrden);
bdmf_error_t ag_drv_bbh_tx_debug_counters_swrden_get(uint8_t bbh_id, bbh_tx_debug_counters_swrden *debug_counters_swrden);
bdmf_error_t ag_drv_bbh_tx_debug_counters_swrdaddr_set(uint8_t bbh_id, uint16_t rdaddr);
bdmf_error_t ag_drv_bbh_tx_debug_counters_swrdaddr_get(uint8_t bbh_id, uint16_t *rdaddr);
bdmf_error_t ag_drv_bbh_tx_debug_counters_swrddata_get(uint8_t bbh_id, uint32_t *data);
bdmf_error_t ag_drv_bbh_tx_debug_counters_dbgoutreg_get(uint8_t bbh_id, uint8_t zero, bbh_tx_debug_counters_dbgoutreg *debug_counters_dbgoutreg);

#ifdef USE_BDMF_SHELL
enum
{
    cli_bbh_tx_mac_type,
    cli_bbh_tx_cfg_src_id,
    cli_bbh_tx_rnr_src_id,
    cli_bbh_tx_bbh_dma_cfg,
    cli_bbh_tx_dma_max_otf_read_request,
    cli_bbh_tx_dma_epon_urgent,
    cli_bbh_tx_bbh_sdma_cfg,
    cli_bbh_tx_sdma_max_otf_read_request,
    cli_bbh_tx_sdma_epon_urgent,
    cli_bbh_tx_bbh_ddr_cfg,
    cli_bbh_tx_debug_counters,
    cli_bbh_tx_common_configurations_rnrcfg_1,
    cli_bbh_tx_common_configurations_rnrcfg_2,
    cli_bbh_tx_common_configurations_sbpmcfg,
    cli_bbh_tx_common_configurations_ddrtmbasel,
    cli_bbh_tx_common_configurations_ddrtmbaseh,
    cli_bbh_tx_common_configurations_dfifoctrl,
    cli_bbh_tx_common_configurations_arb_cfg,
    cli_bbh_tx_common_configurations_bbroute,
    cli_bbh_tx_common_configurations_q2rnr,
    cli_bbh_tx_common_configurations_txrstcmd,
    cli_bbh_tx_common_configurations_dbgsel,
    cli_bbh_tx_wan_configurations_pdbase,
    cli_bbh_tx_wan_configurations_pdsize,
    cli_bbh_tx_wan_configurations_pdwkuph,
    cli_bbh_tx_wan_configurations_pd_byte_th,
    cli_bbh_tx_wan_configurations_pd_byte_th_en,
    cli_bbh_tx_wan_configurations_pdempty,
    cli_bbh_tx_wan_configurations_stsrnrcfg_1,
    cli_bbh_tx_wan_configurations_stsrnrcfg_2,
    cli_bbh_tx_wan_configurations_msgrnrcfg_1,
    cli_bbh_tx_wan_configurations_msgrnrcfg_2,
    cli_bbh_tx_wan_configurations_epncfg,
    cli_bbh_tx_wan_configurations_flow2port,
    cli_bbh_tx_lan_configurations_pdbase,
    cli_bbh_tx_lan_configurations_pdsize,
    cli_bbh_tx_lan_configurations_pdwkuph,
    cli_bbh_tx_lan_configurations_pd_byte_th,
    cli_bbh_tx_lan_configurations_pd_byte_th_en,
    cli_bbh_tx_lan_configurations_pdempty,
    cli_bbh_tx_lan_configurations_txthresh,
    cli_bbh_tx_lan_configurations_eee,
    cli_bbh_tx_lan_configurations_ts,
    cli_bbh_tx_debug_counters_srambyte,
    cli_bbh_tx_debug_counters_ddrbyte,
    cli_bbh_tx_debug_counters_swrden,
    cli_bbh_tx_debug_counters_swrdaddr,
    cli_bbh_tx_debug_counters_swrddata,
    cli_bbh_tx_debug_counters_dbgoutreg,
};

int bcm_bbh_tx_cli_get(bdmf_session_handle session, const bdmfmon_cmd_parm_t parm[], uint16_t n_parms);
bdmfmon_handle_t ag_drv_bbh_tx_cli_init(bdmfmon_handle_t driver_dir);
#endif


#endif

