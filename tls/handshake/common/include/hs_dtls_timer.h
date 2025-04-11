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

#ifndef HS_DTLS_TIMER_H
#define HS_DTLS_TIMER_H

#include <stdint.h>
#include <stdbool.h>
#include "hs_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_TLS_PROTO_DTLS12

/**
 * @brief Start the 2MSL timer.
 *
 * @param ctx [IN] tls Context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MSG_HANDLE_SYS_TIME_FAIL The system time function fails to return.
 */
int32_t HS_Start2MslTimer(TLS_Ctx *ctx);

/**
 * @brief Start the timer.
 *
 * @param ctx [IN] tls Context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MSG_HANDLE_SYS_TIME_FAIL The system time function fails to return.
 */
int32_t HS_StartTimer(TLS_Ctx *ctx);

/**
 * @brief   Judge timer timeout
 *
 * @param   ctx [IN] tls Context
 * @param   isTimeout [OUT] Timeout or not
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MSG_HANDLE_SYS_TIME_FAIL The system time function fails to return.
 */
int32_t HS_IsTimeout(TLS_Ctx *ctx, bool *isTimeout);

/**
 * @brief DTLS receiving timeout timer processing
 *
 * @param ctx [IN] tls Context
 *
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_MSG_HANDLE_SYS_TIME_FAIL The system time function fails to return.
 * @retval HITLS_MSG_HANDLE_DTLS_CONNECT_TIMEOUT DTLS connection timeout
 */
int32_t HS_TimeoutProcess(TLS_Ctx *ctx);

#endif

#ifdef __cplusplus
}
#endif /* end __cplusplus */
#endif /* end HS_DTLS_TIMER_H */
