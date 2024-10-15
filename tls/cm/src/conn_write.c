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

#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "bsl_log.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "tls.h"
#include "alert.h"
#include "app.h"
#include "conn_common.h"
#include "hs.h"

int32_t HITLS_GetMaxWriteSize(const HITLS_Ctx *ctx, uint32_t *len)
{
    if (ctx == NULL || len == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return APP_GetMaxWriteSize(ctx, len);
}

static int32_t WriteEventInIdleState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    (void)ctx;
    (void)data;
    (void)dataLen;
    BSL_ERR_PUSH_ERROR(HITLS_CM_LINK_UNESTABLISHED);
    return HITLS_CM_LINK_UNESTABLISHED;
}

static int32_t WriteEventInTransportingState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    int32_t ret;
    int32_t alertRet;
    uint32_t alertCount = 0;

    do {
        ret = APP_Write(ctx, data, dataLen);
        if (ret == HITLS_SUCCESS) {
            /* The message is sent successfully */
            break;
        }

        if (!ALERT_GetFlag(ctx)) {
            /* Failed to send a message but no alert is displayed */
            break;
        }

        alertCount++;
        if (alertCount >= MAX_ALERT_COUNT) {
            /* If multiple consecutive alerts exist, the link is abnormal and needs to be disconnected */
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }

        alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            /* If the alert fails to be sent, a response is returned to the user */
            return alertRet;
        }

        /* If fatal alert or close_notify has been processed, the link must be disconnected. */
        if (ctx->state == CM_STATE_ALERTED) {
            break;
        }
    } while (ret != HITLS_SUCCESS);

    return ret;
}

static int32_t WriteEventInHandshakingState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    // The link is being established. Therefore, the link establishment is triggered first. If the link is successfully
    // established, the message is directly sent.
    int32_t ret = CommonEventInHandshakingState(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return WriteEventInTransportingState(ctx, data, dataLen);
}

static int32_t WriteEventInRenegotiationState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    int32_t ret;
    do {
        /* If an unexpected message is received, the system ignores the return value and continues to establish a link.
         * Otherwise, the system returns the return value to the user for processing */
        ret = CommonEventInRenegotiationState(ctx);
    } while (ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG && ctx->state != CM_STATE_ALERTED);
    if (ret != HITLS_SUCCESS) {
        if (ctx->negotiatedInfo.isRenegotiation || (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
            /* If an error is returned during renegotiation, the error code must be sent to the user */
            return ret;
        }
        /* The scenario is that the HITLS server initiates renegotiation, but the peer end does not respond with the
         * client hello message. In this case,the app message needs to be sent to the peer end to prevent message
         * blocking
         */
    }

    ctx->userRenego = false;
    return WriteEventInTransportingState(ctx, data, dataLen);
}

static int32_t WriteEventInAlertedState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    (void)ctx;
    (void)data;
    (void)dataLen;
    // Directly return a message indicating that the link status is abnormal.
    BSL_ERR_PUSH_ERROR(HITLS_CM_LINK_FATAL_ALERTED);
    return HITLS_CM_LINK_FATAL_ALERTED;
}

static int32_t WriteEventInClosedState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    (void)ctx;
    (void)data;
    (void)dataLen;
    // Directly return a message indicating that the link status is abnormal.
    BSL_ERR_PUSH_ERROR(HITLS_CM_LINK_CLOSED);
    return HITLS_CM_LINK_CLOSED;
}

int32_t CommonCheckPostHandshakeAuth(TLS_Ctx *ctx)
{
    if (!ctx->isClient && ctx->phaState == PHA_PENDING && ctx->state == CM_STATE_TRANSPORTING) {
        ChangeConnState(ctx, CM_STATE_HANDSHAKING);
        return HS_CheckPostHandshakeAuth(ctx);
    }
    return HITLS_SUCCESS;
}

static int32_t HITLS_WritePreporcess(HITLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* Process the unsent alert message first, and then enter the corresponding state processing function based on the
     * processing result */
    if (GetConnState(ctx) == CM_STATE_ALERTING) {
        ret = CommonEventInAlertingState(ctx);
        if (ret != HITLS_SUCCESS) {
            /* If the alert message fails to be sent, the system returns the message to the user for processing */
            return ret;
        }
    }

    /* Process the key update message that is not sent, and then enter the corresponding state processing function
     * according to the processing resul */
    if (ctx->isKeyUpdateRequest) {
        ret = HS_CheckKeyUpdateState(ctx, ctx->keyUpdateType);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        ret = HS_SendKeyUpdate(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return CommonCheckPostHandshakeAuth(ctx);
}

int32_t HITLS_Write(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    int32_t ret;
    if (ctx == NULL || data == NULL || dataLen == 0) {
        return HITLS_NULL_INPUT;
    }

    ret = HITLS_WritePreporcess(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    WriteEventProcess writeEventProcess[CM_STATE_END] = {
        WriteEventInIdleState,
        WriteEventInHandshakingState,
        WriteEventInTransportingState,
        WriteEventInRenegotiationState,
        NULL,
        WriteEventInAlertedState,
        WriteEventInClosedState
    };

    if ((GetConnState(ctx) >= CM_STATE_END) || (GetConnState(ctx) == CM_STATE_ALERTING)) {
        /* If the alert message is sent successfully, the system switches to another state. Otherwise, an internal
         * exception occurs */
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    WriteEventProcess proc = writeEventProcess[GetConnState(ctx)];

    ret = proc(ctx, data, dataLen);
    return ret;
}
