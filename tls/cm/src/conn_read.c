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
#include "hitls_error.h"
#include "sal_time.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "hitls_type.h"
#include "tls.h"
#include "rec.h"
#include "alert.h"
#include "app.h"
#include "conn_common.h"
#include "hs.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "hs_ctx.h"
#include "crypt.h"
#include "hs_dtls_timer.h"
#include "hs_state_recv.h"
#include "bsl_bytes.h"

#define HS_MESSAGE_LEN_FIELD 3u
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
// The HITLS protocol specifies the specification for the maximum timeout period, 3600 seconds.
#define DTLS_SPECIFY_MAX_TIMEOUT_VALUE  3600
#endif
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
    if (ctx->state == CM_STATE_HANDSHAKING) {
        return CommonEventInHandshakingState(ctx);
    }
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    if (ctx->state == CM_STATE_RENEGOTIATION) {
        int32_t ret = CommonEventInRenegotiationState(ctx);
        if (ret == HITLS_SUCCESS) {
            /* The renegotiation initiated by the peer is processed and returned. */
            return ret;
        }
        if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
            /* If an error is returned during renegotiation, the error code must be sent to the user */
            return ret;
        }
        if (ctx->state == CM_STATE_ALERTED) {
            /* If the alert message has been processed, the link must be disconnected */
            return ret;
        }
    }
#endif
    return HITLS_SUCCESS;
}
static int32_t RecvRenegoReqPreprocess(TLS_Ctx *ctx, uint8_t type)
{
    /* If the version is TLS1.3, ignore the message */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16514, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "tls13 not support Renegotiation", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    /* If the message is not a renegotiation request, ignore the message */
    if ((ctx->isClient && (type == CLIENT_HELLO)) ||
        (!ctx->isClient && (type == HELLO_REQUEST))) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16515, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ignore the message", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }
    /* if client renegotiate is not allowed, send no renegotiate alert, change state to CM_STATE_HANDSHAKING to
       finish this process */
    if (type == CLIENT_HELLO && !ctx->config.tlsConfig.allowClientRenegotiate && !ctx->userRenego) {
        ChangeConnState(ctx, CM_STATE_HANDSHAKING);
        (void)HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
        return HITLS_SUCCESS;
    }
    /* Renegotiation request is processed only after security renegotiation is negotiated. Otherwise, no renegotiation
     * alert is generated and the peer determines whether to disconnect the link */
    if (!ctx->negotiatedInfo.isSecureRenegotiation || !ctx->config.tlsConfig.isSupportRenegotiation) {
        if (type == HELLO_REQUEST) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16516, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "not support Renegotiation", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_WARNING, ALERT_NO_RENEGOTIATION);
            return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
        } else {
            ChangeConnState(ctx, CM_STATE_HANDSHAKING);
            (void)HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
            return HITLS_SUCCESS;
        }
    }

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    REC_RetransmitListClean(ctx->recCtx); /* dtls over udp scenario, the retransmission queue needs to be cleared */
#endif
    ChangeConnState(ctx, CM_STATE_RENEGOTIATION);
    if (type == CLIENT_HELLO) {
        // When the server start renegotiation, it sends a hello request message first, and the value of
        // nextSendSeq increases to 1. Then, the hsctx is released and the nextSendSeq is reset to 0.
        // Therefore, the value of nextSendSeq should return to 1 when sending server hello.
#ifdef HITLS_TLS_PROTO_DTLS12
        if (ctx->userRenego && IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
            ctx->hsCtx->nextSendSeq++;
        }
#endif
        (void)HS_ChangeState(ctx, TRY_RECV_CLIENT_HELLO);
    } else {
        (void)HS_ChangeState(ctx, TRY_RECV_HELLO_REQUEST);
    }
    return HITLS_SUCCESS;
}

static int32_t RecvKeyUpdatePreprocess(TLS_Ctx *ctx)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16517, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "negotiatedInfo version is not tls13", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    return HS_ChangeState(ctx, TRY_RECV_KEY_UPDATE);
}

static int32_t RecvCertReqPreprocess(TLS_Ctx *ctx)
{
    if (ctx->state != CM_STATE_TRANSPORTING || ctx->phaState != PHA_EXTENSION ||
        !ctx->isClient || ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16518, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx state err", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    };

    SAL_CRYPT_DigestFree(ctx->hsCtx->verifyCtx->hashCtx);
    ctx->hsCtx->verifyCtx->hashCtx = SAL_CRYPT_DigestCopy(ctx->phaHash);
    if (ctx->hsCtx->verifyCtx->hashCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16178, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pha hash copy error: digest copy fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    ctx->phaState = PHA_REQUESTED;
    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
}

static int32_t RecvCertPreprocess(TLS_Ctx *ctx)
{
    if (ctx->state != CM_STATE_TRANSPORTING || ctx->phaState != PHA_REQUESTED ||
        ctx->isClient || ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16519, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ctx state err", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }
    SAL_CRYPT_DigestFree(ctx->hsCtx->verifyCtx->hashCtx);
    ctx->hsCtx->verifyCtx->hashCtx = ctx->phaCurHash;
    ctx->phaCurHash = NULL;

    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
}

static int32_t RecvNSTPreprocess(TLS_Ctx *ctx)
{
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLS13 || ctx->isClient == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16520, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "version err or it is server", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
}

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
static int32_t RecvPostFinishPreprocess(TLS_Ctx *ctx)
{
    if (!IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID16131, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Unexpected %s handshake state message.", HS_GetMsgTypeStr(ctx->hsCtx->msgBuf[0]));
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }
    bool isTimeout = false;

    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16521, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetUioChainTransportType fail", 0, 0, 0, 0);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    if (HS_IsTimeout(ctx, &isTimeout) != HITLS_SUCCESS || isTimeout) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16522, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_IsTimeout fail or timeout", 0, 0, 0, 0);
        REC_RetransmitListClean(ctx->recCtx);
        HS_DeInit(ctx);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    if ((ctx->isClient && !ctx->negotiatedInfo.isResume) || (!ctx->isClient && ctx->negotiatedInfo.isResume)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16523, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "RecvPostFinishPreprocess fail", 0, 0, 0, 0);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }

    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    return HS_ChangeState(ctx, TRY_RECV_FINISH);
}
#endif

static int32_t PreprocessUnexpectHsMsg(HITLS_Ctx *ctx)
{
    if (ctx->hsCtx != NULL) {
        HS_DeInit(ctx);
    }
    int32_t ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15977, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when receive unexpected handshake message.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
    // get the handshake message type
    ret = ReadHsMessage(ctx, 1);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16524, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ReadHsMessage fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    HS_Ctx *hsCtx = ctx->hsCtx;
    switch (hsCtx->msgBuf[0]) {
        case HELLO_REQUEST:
        case CLIENT_HELLO:
            ret = RecvRenegoReqPreprocess(ctx, hsCtx->msgBuf[0]);
            break;
        case KEY_UPDATE:
            ret = RecvKeyUpdatePreprocess(ctx);
            break;
        case CERTIFICATE_REQUEST:
            ret = RecvCertReqPreprocess(ctx);
            break;
        case CERTIFICATE:
            ret = RecvCertPreprocess(ctx);
            break;
        case NEW_SESSION_TICKET:
            ret = RecvNSTPreprocess(ctx);
            break;
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        case FINISHED:
            ret = RecvPostFinishPreprocess(ctx);
            break;
#endif
        default:
            BSL_LOG_BINLOG_VARLEN(BINLOG_ID16529, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Unexpected %s handshake state message.", HS_GetMsgTypeStr(hsCtx->msgBuf[0]));
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            ret = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }
    return ret;
}

static void ConsumeHandshakeMessage(HITLS_Ctx *ctx)
{
    bool isDtls = IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask);
    uint32_t headerLen = isDtls ? DTLS_HS_MSG_HEADER_SIZE : HS_MSG_HEADER_SIZE;
    int32_t ret = ReadHsMessage(ctx, headerLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16525, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ReadHsMessage fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }
    uint32_t length = BSL_ByteToUint24(&ctx->hsCtx->msgBuf[headerLen - HS_MESSAGE_LEN_FIELD]);
    ret = ReadHsMessage(ctx, length + headerLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16526, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ReadHsMessage fail", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }
}

static int32_t ReadEventInTransportingState(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int32_t ret = 0;
    int32_t unexpectMsgRet = 0;

    do {
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        /* In UDP scenarios, the 2MSL timer expires */
        ret = HS_CheckAndProcess2MslTimeout(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#endif
        ret = APP_Read(ctx, data, bufSize, readLen);
        if (ret == HITLS_SUCCESS) {
            if ((!ctx->negotiatedInfo.isRenegotiation) && (ctx->hsCtx != NULL)) {
                /* In the UDP scenario, if an APP message is received, the peer end considers that the link
                 * establishment is complete. In this case, the hsCtx memory needs to be released */
                HS_DeInit(ctx);
            }
            /* An APP message is received */
            break;
        }

        /* The handshake message processing flow starts when an error code such as alarm, CCS,
            unknown type message, or decoding error is received. */
        if (ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG && REC_GetUnexpectedMsgType(ctx) == REC_TYPE_HANDSHAKE) {
            unexpectMsgRet = PreprocessUnexpectHsMsg(ctx);
            if (unexpectMsgRet != HITLS_SUCCESS) {
                ConsumeHandshakeMessage(ctx);
                HS_DeInit(ctx);
                ret = unexpectMsgRet;
            }
        }

        if (ALERT_GetFlag(ctx)) {
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
            /* After the server sends a hello request, the status changes to transporting. In this case, the read
             command is used to read the message. If the no_renegotiation alert is received, the connection
             needs to be disconnected. */
            if (ctx->userRenego) {
                InnerRenegotiationProcess(ctx);
            }
#endif
            if (ALERT_HaveExceeded(ctx, MAX_ALERT_COUNT)) {
                /* If multiple consecutive alerts exist, the link is abnormal and needs to be disconnected */
                ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            }

            unexpectMsgRet = AlertEventProcess(ctx);
            if (unexpectMsgRet != HITLS_SUCCESS) {
                /* If the alert fails to be sent, a response is returned to the user for processing */
                return unexpectMsgRet;
            }

            /* If fatal alert or close_notify has been processed, the link must be disconnected */
            if (ctx->state == CM_STATE_ALERTED || ctx->state == CM_STATE_CLOSED) {
                return ret;
            }
        }

        if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
            return ret;
        }

        unexpectMsgRet = RecvUnexpectMsgInTransportingStateProcess(ctx);
        if (unexpectMsgRet != HITLS_SUCCESS) {
            return unexpectMsgRet;
        }
#ifdef HITLS_TLS_FEATURE_MODE_AUTO_RETRY
        if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_AUTO_RETRY) == 0) {
            return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
        }
#endif
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
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    int32_t ret = CommonEventInRenegotiationState(ctx);
    if (ret != HITLS_SUCCESS) {
        if (ret != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG || ctx->state == CM_STATE_ALERTED) {
            /* If an error is returned during the renegotiation, the error code must be sent to the user */
            return ret;
        }
        /* The scenario is that the HITLS initiates renegotiation, but the peer end does not respond with a handshake
         *   message and continues to send the app message. In this case, you need to read the app message to prevent
         *   message blocking.
         */
        ret = APP_Read(ctx, data, bufSize, readLen);
        return ret;
    }

    return ReadEventInTransportingState(ctx, data, bufSize, readLen);
#else
    (void)ctx;
    (void)data;
    (void)bufSize;
    (void)readLen;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15407, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
        "invalid conn states %d", CM_STATE_RENEGOTIATION, NULL, NULL, NULL);
    return HITLS_INTERNAL_EXCEPTION;
#endif
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
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16531, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Read fail", 0, 0, 0, 0);
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
static int32_t ReadProcess(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16532, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "internal exception occurs", 0, 0, 0, 0);
        /* If the alert message is sent successfully, the system switches to another state. Otherwise, an internal
         * exception occurs */
        return HITLS_INTERNAL_EXCEPTION;
    }

    ReadEventProcess proc = readEventProcess[GetConnState(ctx)];
    return proc(ctx, data, bufSize, readLen);
}

int32_t HITLS_Read(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    int32_t ret;
    if (ctx == NULL || data == NULL || readLen == NULL) {
        return HITLS_NULL_INPUT;
    }
    ctx->allowAppOut = true;
    /* Process the unsent alert message first, and then enter the corresponding state processing function based on the
     * processing result */
    if (GetConnState(ctx) == CM_STATE_ALERTING) {
        ret = CommonEventInAlertingState(ctx);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16533, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Alerting fail", 0, 0, 0, 0);
            /* If the alert message fails to be sent, the system returns the message to the user for processing */
            return ret;
        }
    }

    return ReadProcess(ctx, data, bufSize, readLen);
}

int32_t HITLS_Peek(HITLS_Ctx *ctx, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    ctx->peekFlag = 1;
    int32_t ret = HITLS_Read(ctx, data, bufSize, readLen);
    ctx->peekFlag = 0;
    return ret;
}

int32_t HITLS_ReadHasPending(const HITLS_Ctx *ctx, bool *isPending)
{
    if (ctx == NULL || isPending == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isPending = (APP_GetReadPendingBytes(ctx) > 0 || REC_ReadHasPending(ctx));

    return HITLS_SUCCESS;
}

uint32_t HITLS_GetReadPendingBytes(const HITLS_Ctx *ctx)
{
    return APP_GetReadPendingBytes(ctx);
}

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t HITLS_DtlsProcessTimeout(HITLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL) {
        return HITLS_NULL_INPUT;
    }
    bool isTimeout = false;
    int32_t ret = HS_IsTimeout(ctx, &isTimeout);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17032, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_IsTimeout fail", 0, 0, 0, 0);
        return ret;
    }

    if (isTimeout) {
        ret = HS_TimeoutProcess(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        /* Receive the message of the last flight when the receiving times out */
        ret = REC_RetransmitListFlush(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        return HITLS_SUCCESS;
    }
    return HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT;
}

int32_t HITLS_DtlsGetTimeout(HITLS_Ctx *ctx, uint64_t *remainTimeOut)
{
    if (ctx == NULL || ctx->hsCtx == NULL || remainTimeOut == NULL) {
        return HITLS_NULL_INPUT;
    }

    *remainTimeOut = 0;
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP) || ctx->hsCtx->timeoutValue == 0) {
        return HITLS_MSG_HANDLE_ERR_WITHOUT_TIMEOUT_ACTION;
    }
    BSL_TIME curTime;
    int32_t ret = BSL_SAL_SysTimeGet(&curTime);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    BSL_TIME endTime = ctx->hsCtx->deadline;
    ret = BSL_SAL_DateTimeCompareByUs(&curTime, &endTime);
    if (ret == BSL_TIME_DATE_AFTER || ret == BSL_TIME_CMP_EQUAL) {
        return HITLS_SUCCESS;
    } else if (ret == BSL_TIME_CMP_ERROR) {
        return BSL_TIME_CMP_ERROR;
    }

    int64_t curUtcTime = 0;
    int64_t endUtcTime = 0;
    /* Convert the date into seconds. */
    ret = BSL_SAL_DateToUtcTimeConvert(&curTime, &curUtcTime);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_SAL_DateToUtcTimeConvert(&endTime, &endUtcTime);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint64_t remainSecTimeout = (uint64_t)(endUtcTime - curUtcTime);
    if (remainSecTimeout >= DTLS_SPECIFY_MAX_TIMEOUT_VALUE) {
        *remainTimeOut = DTLS_SPECIFY_MAX_TIMEOUT_VALUE * BSL_SECOND_TRANSFER_RATIO * BSL_SECOND_TRANSFER_RATIO;
        return HITLS_SUCCESS;
    }

    uint64_t endMicroSec = endTime.millSec * BSL_SECOND_TRANSFER_RATIO + endTime.microSec;
    uint64_t curMicroSec = curTime.millSec * BSL_SECOND_TRANSFER_RATIO + curTime.microSec;

    *remainTimeOut = remainSecTimeout * BSL_SECOND_TRANSFER_RATIO * BSL_SECOND_TRANSFER_RATIO +
        endMicroSec - curMicroSec;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
