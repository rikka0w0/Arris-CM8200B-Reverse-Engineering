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

#include "rdp_common.h"
#include "xrdp_drv_drivers_common_ag.h"
#include "xrdp_drv_rnr_mem_ag.h"

#define BLOCK_ADDR_COUNT_BITS 3
#define BLOCK_ADDR_COUNT (1<<BLOCK_ADDR_COUNT_BITS)

bdmf_error_t ag_drv_rnr_mem_high_set(uint8_t rnr_id, uint32_t word_index, uint32_t data_mem)
{
    uint32_t reg_high=0;

#ifdef VALIDATE_PARMS
    if((rnr_id >= BLOCK_ADDR_COUNT) ||
       (word_index >= 2048))
    {
        bdmf_trace("ERROR driver %s:%u| err=%s (%d)\n", __FILE__, __LINE__, bdmf_strerror(BDMF_ERR_RANGE), BDMF_ERR_RANGE);
        return BDMF_ERR_RANGE;
    }
#endif

    reg_high = RU_FIELD_SET(rnr_id, RNR_MEM, HIGH, DATA_MEM, reg_high, data_mem);

    RU_REG_RAM_WRITE(rnr_id, word_index, RNR_MEM, HIGH, reg_high);

    return BDMF_ERR_OK;
}

bdmf_error_t ag_drv_rnr_mem_high_get(uint8_t rnr_id, uint32_t word_index, uint32_t *data_mem)
{
    uint32_t reg_high;

#ifdef VALIDATE_PARMS
    if(!data_mem)
    {
        bdmf_trace("ERROR driver %s:%u| err=%s (%d)\n", __FILE__, __LINE__, bdmf_strerror(BDMF_ERR_PARM), BDMF_ERR_PARM);
        return BDMF_ERR_PARM;
    }
    if((rnr_id >= BLOCK_ADDR_COUNT) ||
       (word_index >= 2048))
    {
        bdmf_trace("ERROR driver %s:%u| err=%s (%d)\n", __FILE__, __LINE__, bdmf_strerror(BDMF_ERR_RANGE), BDMF_ERR_RANGE);
        return BDMF_ERR_RANGE;
    }
#endif

    RU_REG_RAM_READ(rnr_id, word_index, RNR_MEM, HIGH, reg_high);

    *data_mem = RU_FIELD_GET(rnr_id, RNR_MEM, HIGH, DATA_MEM, reg_high);

    return BDMF_ERR_OK;
}

bdmf_error_t ag_drv_rnr_mem_low_set(uint8_t rnr_id, uint32_t word_index, uint32_t data_mem)
{
    uint32_t reg_low=0;

#ifdef VALIDATE_PARMS
    if((rnr_id >= BLOCK_ADDR_COUNT) ||
       (word_index >= 2048))
    {
        bdmf_trace("ERROR driver %s:%u| err=%s (%d)\n", __FILE__, __LINE__, bdmf_strerror(BDMF_ERR_RANGE), BDMF_ERR_RANGE);
        return BDMF_ERR_RANGE;
    }
#endif

    reg_low = RU_FIELD_SET(rnr_id, RNR_MEM, LOW, DATA_MEM, reg_low, data_mem);

    RU_REG_RAM_WRITE(rnr_id, word_index, RNR_MEM, LOW, reg_low);

    return BDMF_ERR_OK;
}

bdmf_error_t ag_drv_rnr_mem_low_get(uint8_t rnr_id, uint32_t word_index, uint32_t *data_mem)
{
    uint32_t reg_low;

#ifdef VALIDATE_PARMS
    if(!data_mem)
    {
        bdmf_trace("ERROR driver %s:%u| err=%s (%d)\n", __FILE__, __LINE__, bdmf_strerror(BDMF_ERR_PARM), BDMF_ERR_PARM);
        return BDMF_ERR_PARM;
    }
    if((rnr_id >= BLOCK_ADDR_COUNT) ||
       (word_index >= 2048))
    {
        bdmf_trace("ERROR driver %s:%u| err=%s (%d)\n", __FILE__, __LINE__, bdmf_strerror(BDMF_ERR_RANGE), BDMF_ERR_RANGE);
        return BDMF_ERR_RANGE;
    }
#endif

    RU_REG_RAM_READ(rnr_id, word_index, RNR_MEM, LOW, reg_low);

    *data_mem = RU_FIELD_GET(rnr_id, RNR_MEM, LOW, DATA_MEM, reg_low);

    return BDMF_ERR_OK;
}

#ifdef USE_BDMF_SHELL
typedef enum
{
    bdmf_address_high,
    bdmf_address_low,
}
bdmf_address;

static int bcm_rnr_mem_cli_set(bdmf_session_handle session, const bdmfmon_cmd_parm_t parm[], uint16_t n_parms)
{
    bdmf_error_t err = BDMF_ERR_OK;

    switch(parm[0].value.unumber)
    {
    case cli_rnr_mem_high:
        err = ag_drv_rnr_mem_high_set(parm[1].value.unumber, parm[2].value.unumber, parm[3].value.unumber);
        break;
    case cli_rnr_mem_low:
        err = ag_drv_rnr_mem_low_set(parm[1].value.unumber, parm[2].value.unumber, parm[3].value.unumber);
        break;
    default:
        err = BDMF_ERR_NOT_SUPPORTED;
        break;
    }
    return err;
}

int bcm_rnr_mem_cli_get(bdmf_session_handle session, const bdmfmon_cmd_parm_t parm[], uint16_t n_parms)
{
    bdmf_error_t err = BDMF_ERR_OK;

    switch(parm[0].value.unumber)
    {
    case cli_rnr_mem_high:
    {
        uint32_t data_mem;
        err = ag_drv_rnr_mem_high_get(parm[1].value.unumber, parm[2].value.unumber, &data_mem);
        bdmf_session_print(session, "data_mem = %u (0x%x)\n", data_mem, data_mem);
        break;
    }
    case cli_rnr_mem_low:
    {
        uint32_t data_mem;
        err = ag_drv_rnr_mem_low_get(parm[1].value.unumber, parm[2].value.unumber, &data_mem);
        bdmf_session_print(session, "data_mem = %u (0x%x)\n", data_mem, data_mem);
        break;
    }
    default:
        err = BDMF_ERR_NOT_SUPPORTED;
        break;
    }
    return err;
}

static int bcm_rnr_mem_cli_test(bdmf_session_handle session, const bdmfmon_cmd_parm_t parm[], uint16_t n_parms)
{
    bdmf_test_method m = parm[0].value.unumber;
    uint8_t rnr_id = parm[1].value.unumber;
    bdmf_error_t err = BDMF_ERR_OK;

    {
        uint32_t word_index=gtmv(m, 11);
        uint32_t data_mem=gtmv(m, 32);
        if(!err) bdmf_session_print(session, "ag_drv_rnr_mem_high_set(%u %u %u)\n", rnr_id, word_index, data_mem);
        if(!err) ag_drv_rnr_mem_high_set(rnr_id, word_index, data_mem);
        if(!err) ag_drv_rnr_mem_high_get( rnr_id, word_index, &data_mem);
        if(!err) bdmf_session_print(session, "ag_drv_rnr_mem_high_get(%u %u %u)\n", rnr_id, word_index, data_mem);
        if(err || data_mem!=gtmv(m, 32))
            return err ? err : BDMF_ERR_IO;
    }
    {
        uint32_t word_index=gtmv(m, 11);
        uint32_t data_mem=gtmv(m, 32);
        if(!err) bdmf_session_print(session, "ag_drv_rnr_mem_low_set(%u %u %u)\n", rnr_id, word_index, data_mem);
        if(!err) ag_drv_rnr_mem_low_set(rnr_id, word_index, data_mem);
        if(!err) ag_drv_rnr_mem_low_get( rnr_id, word_index, &data_mem);
        if(!err) bdmf_session_print(session, "ag_drv_rnr_mem_low_get(%u %u %u)\n", rnr_id, word_index, data_mem);
        if(err || data_mem!=gtmv(m, 32))
            return err ? err : BDMF_ERR_IO;
    }
    return err;
}

static int bcm_rnr_mem_cli_address(bdmf_session_handle session, const bdmfmon_cmd_parm_t parm[], uint16_t n_parms)
{
    uint32_t i;
    uint32_t j;
    uint32_t index1_start=0;
    uint32_t index1_stop;
    uint32_t index2_start=0;
    uint32_t index2_stop;
    bdmfmon_cmd_parm_t * bdmf_parm;
    const ru_reg_rec * reg;
    const ru_block_rec * blk;
    const char * enum_string = bdmfmon_enum_parm_stringval(session, 0, parm[0].value.unumber);

    if(!enum_string)
        return BDMF_ERR_INTERNAL;

    switch (parm[0].value.unumber)
    {
    case bdmf_address_high : reg = &RU_REG(RNR_MEM, HIGH); blk = &RU_BLK(RNR_MEM); break;
    case bdmf_address_low : reg = &RU_REG(RNR_MEM, LOW); blk = &RU_BLK(RNR_MEM); break;
    default :
        return BDMF_ERR_NOT_SUPPORTED;
        break;
    }
    if((bdmf_parm = bdmfmon_find_named_parm(session,"index1")))
    {
        index1_start = bdmf_parm->value.unumber;
        index1_stop = index1_start + 1;
    }
    else
        index1_stop = blk->addr_count;
    if((bdmf_parm = bdmfmon_find_named_parm(session,"index2")))
    {
        index2_start = bdmf_parm->value.unumber;
        index2_stop = index2_start + 1;
    }
    else
        index2_stop = reg->ram_count + 1;
    if(index1_stop > blk->addr_count)
    {
        bdmf_session_print(session, "index1 (%u) is out of range (%u).\n", index1_stop, blk->addr_count);
        return BDMF_ERR_RANGE;
    }
    if(index2_stop > (reg->ram_count + 1))
    {
        bdmf_session_print(session, "index2 (%u) is out of range (%u).\n", index2_stop, reg->ram_count + 1);
        return BDMF_ERR_RANGE;
    }
    if(reg->ram_count)
        for (i = index1_start; i < index1_stop; i++)
        {
            bdmf_session_print(session, "index1 = %u\n", i);
            for (j = index2_start; j < index2_stop; j++)
                bdmf_session_print(session, 	 "(%5u) 0x%lX\n", j, (blk->addr[i] + reg->addr + j));
        }
    else
        for (i = index1_start; i < index1_stop; i++)
            bdmf_session_print(session, "(%3u) 0x%lX\n", i, blk->addr[i]+reg->addr);
    return 0;
}

bdmfmon_handle_t ag_drv_rnr_mem_cli_init(bdmfmon_handle_t driver_dir)
{
    bdmfmon_handle_t dir;

    if ((dir = bdmfmon_dir_find(driver_dir, "rnr_mem"))!=NULL)
        return dir;
    dir = bdmfmon_dir_add(driver_dir, "rnr_mem", "rnr_mem", BDMF_ACCESS_ADMIN, NULL);

    {
        static bdmfmon_cmd_parm_t set_high[]={
            BDMFMON_MAKE_PARM_ENUM("rnr_id", "rnr_id", rnr_id_enum_table, 0),
            BDMFMON_MAKE_PARM("word_index", "word_index", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_MAKE_PARM("data_mem", "data_mem", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_PARM_LIST_TERMINATOR
        };
        static bdmfmon_cmd_parm_t set_low[]={
            BDMFMON_MAKE_PARM_ENUM("rnr_id", "rnr_id", rnr_id_enum_table, 0),
            BDMFMON_MAKE_PARM("word_index", "word_index", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_MAKE_PARM("data_mem", "data_mem", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_PARM_LIST_TERMINATOR
        };
        static bdmfmon_enum_val_t selector_table[] = {
            { .name="high", .val=cli_rnr_mem_high, .parms=set_high },
            { .name="low", .val=cli_rnr_mem_low, .parms=set_low },
            BDMFMON_ENUM_LAST
        };
        BDMFMON_MAKE_CMD(dir, "set", "set", bcm_rnr_mem_cli_set,
            BDMFMON_MAKE_PARM_SELECTOR("purpose", "purpose", selector_table, 0));
    }
    {
        static bdmfmon_cmd_parm_t set_high[]={
            BDMFMON_MAKE_PARM("rnr_id", "rnr_id", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_MAKE_PARM("word_index", "word_index", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_PARM_LIST_TERMINATOR
        };
        static bdmfmon_cmd_parm_t set_low[]={
            BDMFMON_MAKE_PARM("rnr_id", "rnr_id", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_MAKE_PARM("word_index", "word_index", BDMFMON_PARM_NUMBER, 0),
            BDMFMON_PARM_LIST_TERMINATOR
        };
        static bdmfmon_enum_val_t selector_table[] = {
            { .name="high", .val=cli_rnr_mem_high, .parms=set_high },
            { .name="low", .val=cli_rnr_mem_low, .parms=set_low },
            BDMFMON_ENUM_LAST
        };
        BDMFMON_MAKE_CMD(dir, "get", "get", bcm_rnr_mem_cli_get,
            BDMFMON_MAKE_PARM_SELECTOR("purpose", "purpose", selector_table, 0));
    }
    {
        static bdmfmon_enum_val_t enum_table_test_method[] = {
            { .name="low" , .val=bdmf_test_method_low },
            { .name="mid" , .val=bdmf_test_method_mid },
            { .name="high" , .val=bdmf_test_method_high },
            BDMFMON_ENUM_LAST
        };
        BDMFMON_MAKE_CMD(dir, "test", "test", bcm_rnr_mem_cli_test,
            BDMFMON_MAKE_PARM_ENUM("method", "low: 0000, mid: 1000, high: 1111", enum_table_test_method, 0),
            BDMFMON_MAKE_PARM_ENUM("rnr_id", "rnr_id", rnr_id_enum_table, 0));
    }
    {
        static bdmfmon_enum_val_t enum_table_address[] = {
            { .name="HIGH" , .val=bdmf_address_high },
            { .name="LOW" , .val=bdmf_address_low },
            BDMFMON_ENUM_LAST
        };
        BDMFMON_MAKE_CMD(dir, "address", "address", bcm_rnr_mem_cli_address,
            BDMFMON_MAKE_PARM_ENUM("method", "method", enum_table_address, 0),
            BDMFMON_MAKE_PARM_ENUM("index1", "rnr_id", rnr_id_enum_table, 0),
            BDMFMON_MAKE_PARM("index2", "onu_id/alloc_id/port_id/etc...", BDMFMON_PARM_NUMBER, BDMFMON_PARM_FLAG_OPTIONAL));
    }
    return dir;
}
#endif /* USE_BDMF_SHELL */

