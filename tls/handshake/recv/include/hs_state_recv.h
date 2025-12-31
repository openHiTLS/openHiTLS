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
 * @brief   Process HITLS_Listen recv ClientHello
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS
 * @retval  For details, see hitls_error.h
 */
int32_t HS_DtlsRecvClientHello(TLS_Ctx *ctx);

int32_t ReadHsMessage(TLS_Ctx *ctx, uint32_t length);
#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_STATE_RECV_H */