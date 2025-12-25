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

#ifndef CONN_COMMON_H
#define CONN_COMMON_H

#include <stdint.h>
#include "hitls_build.h"
#include "tls.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ALERT_COUNT 5u
#define GET_GROUPS_CNT (-1)

typedef int32_t (*ManageEventProcess)(HITLS_Ctx *ctx);

typedef int32_t (*WriteEventProcess)(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen);

typedef int32_t (*ReadEventProcess)(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen);

static inline CM_State GetConnState(const HITLS_Ctx *ctx)
{
    return ctx->state;
}
#ifdef HITLS_TLS_FEATURE_PHA
int32_t CommonCheckPostHandshakeAuth(TLS_Ctx *ctx);
#endif
/**
 * @ingroup hitls
 * @brief   General processing of all events in alerting state
 */
int32_t CommonEventInAlertingState(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   Processe of common events in hanshaking state, attempt to establish a connection
 */
int32_t CommonEventInHandshakingState(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   If the local end generates an Alert message when sending or receiving messages or processing handshake
 *          messages, or receives an Alert message from the peer end, the AlertEventProcess needs to be invoked to
 *          process the Alert status.
 */
int32_t AlertEventProcess(HITLS_Ctx *ctx);

void ChangeConnState(HITLS_Ctx *ctx, CM_State state);

void ConnCleanSensitiveData(TLS_Ctx *ctx);

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
/**
 * @ingroup hitls
 * @brief   In the renegotiation state, process the renegotiation event and attempt to establish a connection
 *
 * @param   ctx  [IN] TLS connection handle
 *
 * @retval  HITLS_SUCCESS succeeded
 * @retval  For other error codes, see hitls_error.h
 */
int32_t CommonEventInRenegotiationState(HITLS_Ctx *ctx);

/**
 * @ingroup hitls
 * @brief   In the renegotiation state, process no_renegotiation alert.
 *          Send a handshake_failure alert if no_renegotiation alert is received.
 *
 * @param   ctx  [IN] TLS connection handle
 *
 */
void InnerRenegotiationProcess(HITLS_Ctx *ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif
