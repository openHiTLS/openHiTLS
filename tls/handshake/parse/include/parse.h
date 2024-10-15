/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
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
