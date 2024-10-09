/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "hitls_type.h"
#include "tls.h"
#include "rec.h"
#include "alert.h"
#include "app.h"
#include "conn_common.h"
#include "hs.h"

static int32_t ReadEventInIdleState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    (void)ctx;
    (void)data;
    (void)bufSize;
    (void)readLen;
    return HITLS_CM_LINK_UNESTABLISHED;
}

int32_t RecvUnexpectMsgInTransportingStateProcess(HITLS_Ctx *ctx)
{
    if (ctx->phaState == PHA_REQUESTED && ctx->hsCtx != NULL) {
        return CommonEventInHandshakingState(ctx);
    }
    /* Discard the unexpected message received but not the renegotiation request */
    if (!ctx->negotiatedInfo.isRenegotiation) {
        return HITLS_SUCCESS;
    }

    /* If the renegotiation request is received, perform renegotiation */
    int32_t ret = CommonEventInRenegotiationState(ctx);
    if (ret == HITLS_SUCCESS) {
        /* The renegotiation initiated by the peer end is processed and returned. */
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
    if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
        /* If an error is returned during renegotiation, the error code must be sent to the user */
        return ret;
    }
    if (ctx->state == CM_STATE_ALERTED) {
        /* If the alert message has been processed, the link must be disconnected */
        return ret;
    }
    /* The APP message received during the renegotiation process needs to be written into the user buffer */
    return HITLS_SUCCESS;
}

static int32_t ReadEventInTransportingState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int32_t ret;
    int32_t unexpectMsgRet;
    uint32_t alertCount = 0;

    do {
        ret = APP_Read(ctx, data, bufSize, readLen);
        if (ret == HITLS_SUCCESS) {
            /* An APP message is received */
            break;
        }

        if (ALERT_GetFlag(ctx)) {
            alertCount++;
            if (alertCount >= MAX_ALERT_COUNT) {
                /* If multiple consecutive alerts exist, the link is abnormal and needs to be disconnected */
                ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            }

            unexpectMsgRet = AlertEventProcess(ctx);
            if (unexpectMsgRet != HITLS_SUCCESS) {
                /* If the alert fails to be sent, a response is returned to the user for processing */
                return unexpectMsgRet;
            }

            /* If fatal alert or close_notify has been processed, the link must be disconnected */
            if (ctx->state == CM_STATE_ALERTED) {
                return ret;
            }
            continue;
        }

        if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
            return ret;
        }

        unexpectMsgRet = RecvUnexpectMsgInTransportingStateProcess(ctx);
        if (unexpectMsgRet != HITLS_SUCCESS) {
            return unexpectMsgRet;
        }
    } while (ret != HITLS_SUCCESS);

    return ret;
}

static int32_t ReadEventInHandshakingState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int32_t ret = CommonEventInHandshakingState(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ReadEventInTransportingState(ctx, data, bufSize, readLen);
}

static int32_t ReadEventInRenegotiationState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int32_t ret = CommonEventInRenegotiationState(ctx);
    if (ret != HITLS_SUCCESS) {
        if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
            /* If an error is returned during the renegotiation, the error code must be sent to the user */
            return ret;
        }
        /* The scenario is that the HITLS initiates renegotiation, but the peer end does not respond with a handshake
         *   message and continues to send the app message. In this case, you need to read the app message to prevent
         *   message blocking.
         */
        if (APP_GetReadPendingBytes(ctx) > 0u) {
            ret = APP_Read(ctx, data, bufSize, readLen);
        } else if (ctx->state != CM_STATE_ALERTED) {
            ret = HITLS_SUCCESS; /* If an empty APP message is received, a success message should be returned */
        }
        return ret;
    }

    if (!ctx->userRenego) {
        /* The renegotiation initiated by the peer end is processed and returned. */
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
    ctx->userRenego = false;
    return ReadEventInTransportingState(ctx, data, bufSize, readLen);
}

static int32_t ReadEventInAlertedState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    (void)ctx;
    (void)data;
    (void)bufSize;
    (void)readLen;
    // A message indicating that the link status is abnormal is displayed.
    return HITLS_CM_LINK_FATAL_ALERTED;
}

static int32_t ReadEventInClosedState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    // Non-closed state
    if ((ctx->shutdownState & HITLS_RECEIVED_SHUTDOWN) == 0) {
        ALERT_CleanInfo(ctx);
        int32_t ret = APP_Read(ctx, data, bufSize, readLen);
        if (ret == HITLS_SUCCESS) {
            return HITLS_SUCCESS;
        }
        // There is no alert message to be processed.
        if (ALERT_GetFlag(ctx) == false) {
            return ret;
        }

        int32_t alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            return alertRet;
        }
        /* Other warning alerts have been processed. */
        if ((ctx->shutdownState & HITLS_RECEIVED_SHUTDOWN) == 0) {
            return ret;
        }
    }
    // Directly return to link closed.
    return HITLS_CM_LINK_CLOSED;
}

int32_t HITLS_Read(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int32_t ret;
    if (ctx == NULL || data == NULL || readLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    /* Process the unsent alert message first, and then enter the corresponding state processing function based on the
     * processing result */
    if (GetConnState(ctx) == CM_STATE_ALERTING) {
        ret = CommonEventInAlertingState(ctx);
        if (ret != HITLS_SUCCESS) {
            /* If the alert message fails to be sent, the system returns the message to the user for processing */
            return ret;
        }
    }

    /* The unsent key update message is processed first, and the corresponding status processing function is entered
     * according to the processing result */
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

    ReadEventProcess readEventProcess[CM_STATE_END] = {
        ReadEventInIdleState,
        ReadEventInHandshakingState,
        ReadEventInTransportingState,
        ReadEventInRenegotiationState,
        NULL,
        ReadEventInAlertedState,
        ReadEventInClosedState
    };

    if ((GetConnState(ctx) >= CM_STATE_END) || (GetConnState(ctx) == CM_STATE_ALERTING)) {
        /* If the alert message is sent successfully, the system switches to another state. Otherwise, an internal
         * exception occurs */
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    ReadEventProcess proc = readEventProcess[GetConnState(ctx)];

    ret = proc(ctx, data, bufSize, readLen);
    return ret;
}

int32_t HITLS_ReadHasPending(const HITLS_Ctx *ctx, uint8_t *isPending)
{
    if (ctx == NULL || isPending == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    *isPending = 0;
    if (APP_GetReadPendingBytes(ctx) > 0 || REC_ReadHasPending(ctx)) {
        *isPending = 1;
    }

    return HITLS_SUCCESS;
}

uint32_t HITLS_GetReadPendingBytes(const HITLS_Ctx *ctx)
{
    return APP_GetReadPendingBytes(ctx);
}
