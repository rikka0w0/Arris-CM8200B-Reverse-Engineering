/***********************************************************************
 * <:copyright-BRCM:2008-2013:proprietary:standard
 * 
 *    Copyright (c) 2008-2013 Broadcom 
 *    All Rights Reserved
 * 
 *  This program is the proprietary software of Broadcom and/or its
 *  licensors, and may only be used, duplicated, modified or distributed pursuant
 *  to the terms and conditions of a separate, written license agreement executed
 *  between you and Broadcom (an "Authorized License").  Except as set forth in
 *  an Authorized License, Broadcom grants no license (express or implied), right
 *  to use, or waiver of any kind with respect to the Software, and Broadcom
 *  expressly reserves all rights in and to the Software and all intellectual
 *  property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
 *  NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
 *  BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
 * 
 *  Except as expressly set forth in the Authorized License,
 * 
 *  1. This program, including its structure, sequence and organization,
 *     constitutes the valuable trade secrets of Broadcom, and you shall use
 *     all reasonable efforts to protect the confidentiality thereof, and to
 *     use this information only in connection with your use of Broadcom
 *     integrated circuit products.
 * 
 *  2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 *     AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
 *     WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 *     RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
 *     ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
 *     FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
 *     COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
 *     TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
 *     PERFORMANCE OF THE SOFTWARE.
 * 
 *  3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
 *     ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
 *     INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
 *     WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
 *     IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
 *     OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
 *     SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
 *     SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
 *     LIMITED REMEDY.
 * :> *
 * $Change: 121810 $
 ***********************************************************************/
/** \file apfw_hdr_cfg_param.h
 *
 * \brief APFW_HDR_CFG_PARAM primitive
 *  The following set of messages allow to read and write
 *  from/to Header Config Parameters
 **************************************************/


#ifndef APFW_HDR_CFG_PARAM_H_
#define APFW_HDR_CFG_PARAM_H_

/***************************************************
 *                 Include section
 ***************************************************/
#include "../base_types.h"
#include "definitions.h"

/***************************************************
 *                 Public Typedefs Section
 ***************************************************/

/** \brief Request to read one config parameter */
typedef struct
{
   TU32 offset;   //!< Parameter Header Config offset
   TU32 size;     //!< Parameter size 1,2,4
} tS_APFW_HDR_CFG_PARAM_GET_REQ;

/** \brief Request to write one config parameter */
typedef struct
{
   TU32 offset;   //!< Parameter Header Config offset
   TU32 size;     //!< Parameter size 1,2,4
   TU32 value;    //!< New parameter value
} tS_APFW_HDR_CFG_PARAM_SET_REQ;

/** \brief This is the struct to hold the APFW_HDR_CFG_PARAM_GET transaction
           response */
typedef struct
{
    tE_TransactionResult   result;     //!< Transaction result
    tS_APL2C_ERROR_CNF     err;        //!< APL2C_ERROR_CNF
    TU32                   cnf;        //!< Parameter read value
} tS_APFW_HDR_CFG_PARAM_GET_Result;

/** \brief This is the struct to hold the APFW_HDR_CFG_PARAM_SET transaction
          response */
typedef struct
{
    tE_TransactionResult  result;   //!< Transaction result
    tS_APL2C_ERROR_CNF    err;      //!< APL2C_ERROR_CNF
} tS_APFW_HDR_CFG_PARAM_SET_Result;

/***************************************************
 *         Public Function Prototypes Section
 ***************************************************/

/**
 * \brief            Execute APFW_HDR_CFG_PARAM_GET for Header Config Parameters
 *
 * \param req        (in)  REQ primitive
 * \param p_result   (out) Transaction result
*/
void Exec_APFW_HDR_CFG_PARAM_GET(
   const tS_APFW_HDR_CFG_PARAM_GET_REQ req,
   tS_APFW_HDR_CFG_PARAM_GET_Result* p_result);

/**
 * \brief            Execute APFW_HDR_CFG_PARAM_GET for Header Config Parameters
 *
 * \param req        (in)  REQ primitive
 * \param p_result   (out) Transaction result
*/
void Exec_APFW_HDR_CFG_PARAM_SET(
   const tS_APFW_HDR_CFG_PARAM_SET_REQ req,
   tS_APFW_HDR_CFG_PARAM_SET_Result* p_result);



#endif
