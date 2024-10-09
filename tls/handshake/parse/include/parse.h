/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef PARSE_H
#define PARSE_H

#include "hs_msg.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Parse handshake message header
 *
 * @param   ctx [IN] TLS context
 * @param   data [IN] Handshake message
 * @param   len [IN] Message length
 * @param   hsMsgInfo [OUT] Parsed handshake message header
 *
 * @return  HITLS_SUCCESS
 *          For other error codes, see hitls_error.h
 */
int32_t HS_ParseMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo);

/**
 * @brief   Parse the whole handshake message
 *          Used in pairs with HS_CleanMsg. After parsing, the data needs to be cleaned.
 *
 * @param   ctx [IN] TLS context
 * @param   hsMsgInfo [IN] Handshake message
 * @param   hsMsg [OUT] Parsed complete handshake message
 *
 * @return  HITLS_SUCCESS
 *          For other error codes, see hitls_error.h
 */
int32_t HS_ParseMsg(TLS_Ctx *ctx, const HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg);

/**
 * @brief   Clean handshake messages
 *          Used in pairs with HS_ParseMsg to release the memory allocated in hsMsg
 *
 * @param   hsMsg [IN] Handshake message
 */
void HS_CleanMsg(HS_Msg *hsMsg);


/**
 * @brief   Check whether the type of the handshake message is expected
 *
 * @param   ctx [IN] TLS context
 * @param   msgType [IN] Handshake message type
 *
 * @return  HITLS_SUCCESS
 *          For other error codes, see hitls_error.h
 */
int32_t CheckHsMsgType(TLS_Ctx *ctx, HS_MsgType msgType);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end PARSE_H */
