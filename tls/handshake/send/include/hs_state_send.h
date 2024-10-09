/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HS_STATE_SEND_H
#define HS_STATE_SEND_H

#include <stdint.h>
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Handshake layer state machine message sending processing
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MSG_HANDLE_UNSUPPORT_VERSION The TLS version is not supported
 * @retval  For details, see hitls_error.h
 */
int32_t HS_SendMsgProcess(TLS_Ctx *ctx);

/**
 * @brief   Key update message sending and processing
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t HS_HandleSendKeyUpdate(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_STATE_SEND_H */