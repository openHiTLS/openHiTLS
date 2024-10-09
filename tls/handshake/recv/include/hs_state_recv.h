/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HS_STATE_RECV_H
#define HS_STATE_RECV_H

#include <stdint.h>
#include "tls.h"
#include "hs_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Handshake layer state machine receiving messages processing
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MSG_HANDLE_UNSUPPORT_VERSION The TLS version is not supported
 * @retval  For details, see hitls_error.h
 */
int32_t HS_RecvMsgProcess(TLS_Ctx *ctx);

/**
 * @brief   key update message receiving processing
 *
 * @param   ctx [IN] TLS object
 * @param   hsMsgInfo [IN] Parsed message header
 * @param   hsMsg [OUT] Parsed message
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t HS_HandleRecvKeyUpdate(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg);

/**
 * @brief   Process renegotiation request
 *
 * @param   ctx [IN] TLS object
 * @param   hsMsgInfo [IN] Parsed message header
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t HS_HandleRecvRenegoReq(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo);

/**
 * @brief   Process TLS1.3 new session ticket
 *
 * @param   ctx [IN] TLS object
 * @param   hsMsgInfo [IN] Parsed message header
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t HS_HandleTLS13NewSessionTicket(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo);

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_STATE_RECV_H */