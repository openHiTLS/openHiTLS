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

#include "hitls_build.h"
#include "bsl_log_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "tls.h"
#include "alert.h"
#include "app.h"
#include "conn_common.h"
#include "hs.h"
#include "hs_ctx.h"
#include "record.h"

int32_t HITLS_GetMaxWriteSize(const HITLS_Ctx *ctx, uint32_t *len)
{
    if (ctx == NULL || len == NULL) {
        return HITLS_NULL_INPUT;
    }

    return APP_GetMaxWriteSize(ctx, len);
}

static int32_t WriteEventInIdleState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    (void)ctx;
    (void)data;
    (void)dataLen;
    (void)writeLen;
    return HITLS_CM_LINK_UNESTABLISHED;
}

static int32_t WriteEventInTransportingState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    int32_t ret;
    int32_t alertRet;

    do {
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        /* In UDP scenarios, the 2MSL timer expires */
        ret = HS_CheckAndProcess2MslTimeout(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#endif
        ret = APP_Write(ctx, data, dataLen, writeLen);
        if (ret == HITLS_SUCCESS) {
            /* The message is sent successfully */
            break;
        }

        if (!ALERT_GetFlag(ctx)) {
            /* Failed to send a message but no alert is displayed */
            break;
        }

        if (ALERT_HaveExceeded(ctx, MAX_ALERT_COUNT)) {
            /* If multiple consecutive alerts exist, the link is abnormal and needs to be disconnected */
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }

        alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16546, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "AlertEventProcess fail", 0, 0, 0, 0);
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

static int32_t WriteEventInHandshakingState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    // The link is being established. Therefore, the link establishment is triggered first. If the link is successfully
    // established, the message is directly sent.
    int32_t ret = CommonEventInHandshakingState(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return WriteEventInTransportingState(ctx, data, dataLen, writeLen);
}

static int32_t WriteEventInRenegotiationState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    int32_t ret;
    if (ctx->recCtx->pendingData != NULL) {
        // Send the app data first.
        return WriteEventInTransportingState(ctx, data, dataLen, writeLen);
    }
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

    return WriteEventInTransportingState(ctx, data, dataLen, writeLen);
#else
    (void)ctx;
    (void)data;
    (void)dataLen;
    (void)writeLen;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15583, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
        "invalid conn states %d", CM_STATE_RENEGOTIATION, NULL, NULL, NULL);
    return HITLS_INTERNAL_EXCEPTION;
#endif
}

static int32_t WriteEventInAlertedState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    (void)ctx;
    (void)data;
    (void)dataLen;
    (void)writeLen;
    // Directly return a message indicating that the link status is abnormal.
    return HITLS_CM_LINK_FATAL_ALERTED;
}

static int32_t WriteEventInClosedState(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        ALERT_CleanInfo(ctx);
        int ret = APP_Write(ctx, data, dataLen, writeLen);
        if (ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_IO_BUSY) {
            return ret;
        }
        // There is no alert message to be processed.
        if (ALERT_GetFlag(ctx) == false) {
            return ret;
        }

        int32_t alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            return alertRet;
        }
        return ret;
    }
    // Directly return a message indicating that the link status is abnormal.
    return HITLS_CM_LINK_CLOSED;
}
#ifdef HITLS_TLS_FEATURE_PHA
int32_t CommonCheckPostHandshakeAuth(TLS_Ctx *ctx)
{
    if (!ctx->isClient && ctx->phaState == PHA_PENDING && ctx->state == CM_STATE_TRANSPORTING) {
        ChangeConnState(ctx, CM_STATE_HANDSHAKING);
        return HS_CheckPostHandshakeAuth(ctx);
    }
    return HITLS_SUCCESS;
}
#endif
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

#ifdef HITLS_TLS_FEATURE_PHA
    return CommonCheckPostHandshakeAuth(ctx);
#else
    return ret;
#endif
}

int32_t HITLS_Write(HITLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0 || writeLen == NULL) {
        return HITLS_NULL_INPUT;
    }
    ctx->allowAppOut = false;

    int32_t ret = HITLS_WritePreporcess(ctx);
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16548, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "internal exception occurs", 0, 0, 0, 0);
        /* If the alert message is sent successfully, the system switches to another state. Otherwise, an internal
         * exception occurs */
        return HITLS_INTERNAL_EXCEPTION;
    }

    WriteEventProcess proc = writeEventProcess[GetConnState(ctx)];

    ret = proc(ctx, data, dataLen, writeLen);
    if (ret != HITLS_SUCCESS) {
        *writeLen = 0;
    }
    return ret;
}
