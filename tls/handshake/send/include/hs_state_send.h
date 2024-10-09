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