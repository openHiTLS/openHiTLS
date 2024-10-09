/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CONN_COMMON_H
#define CONN_COMMON_H

#include <stdint.h>
#include "tls.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ALERT_COUNT 5u
#define GET_GROUPS_CNT (-1)

typedef int32_t (*ManageEventProcess)(HITLS_Ctx *ctx);

typedef int32_t (*WriteEventProcess)(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen);

typedef int32_t (*ReadEventProcess)(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen);
static inline CM_State GetConnState(const HITLS_Ctx *ctx)
{
    return ctx->state;
}

int32_t CommonCheckPostHandshakeAuth(TLS_Ctx *ctx);
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

typedef struct {
    HITLS_Ctx *ctx;
    uint8_t *buf;
    uint32_t bufSize;
    uint32_t *size;
    enum { READ_EVENT, WRITE_EVENT, MANAGER_EVENT } evenType;
    void *func;
} HITLSAsyncArgs;

int HITLS_EventProcWrapper(void *arg);

#ifdef __cplusplus
}
#endif

#endif
