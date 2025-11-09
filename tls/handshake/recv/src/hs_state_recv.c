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
#include "securec.h"
#include "hitls_build.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "tls_binlog_id.h"
#include "bsl_err_internal.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "rec.h"
#include "hs.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_verify.h"
#include "transcript_hash.h"
#include "hs_reass.h"
#include "parse.h"
#include "recv_process.h"
#include "bsl_uio.h"
#include "hs_kx.h"
#include "hs_dtls_timer.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */

static int32_t CheckHsMsg(TLS_Ctx *ctx, HS_Msg *hsMsg, int32_t ret)
{
    if (ret == HITLS_SUCCESS) {
        HS_CleanMsg(ctx->hsCtx->hsMsg);
        if (ctx->hsCtx->hsMsg != hsMsg) {
            BSL_SAL_FREE(ctx->hsCtx->hsMsg);
        }
        ctx->hsCtx->hsMsg = NULL;
    }
    if (ctx->hsCtx->hsMsg == hsMsg) {
        ctx->hsCtx->hsMsg = BSL_SAL_Dump(hsMsg, sizeof(HS_Msg));
        if (ctx->hsCtx->hsMsg == NULL) {
            HS_CleanMsg(hsMsg);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17357, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "hsMsg dump fail.", 0, 0,
                                  0, 0);
            return HITLS_MEMALLOC_FAIL;
        }
    }
    return ret;
}

#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
static int32_t Tls13RecvKeyUpdateProcess(TLS_Ctx *ctx, const HS_Msg *hsMsg)
{
    HITLS_KeyUpdateRequest requestUpdateType = hsMsg->body.keyUpdate.requestUpdate;
    if ((requestUpdateType != HITLS_UPDATE_NOT_REQUESTED) &&
        (requestUpdateType != HITLS_UPDATE_REQUESTED)) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15354, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.3 unexpected requestUpdateType(%u)", requestUpdateType, 0, 0, 0);
        return HITLS_MSG_HANDLE_ILLEGAL_KEY_UPDATE_TYPE;
    }

    /* Update and activate the app traffic secret used by the local after receiving the key update message */
    int32_t ret = HS_TLS13UpdateTrafficSecret(ctx, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15355, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.3 in key update fail", 0, 0, 0, 0);
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15980, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 recv key update success", 0, 0, 0, 0);

    if (hsMsg->body.keyUpdate.requestUpdate == HITLS_UPDATE_REQUESTED) {
        ctx->isKeyUpdateRequest = true;
        ctx->keyUpdateType = HITLS_UPDATE_NOT_REQUESTED;
        return HS_ChangeState(ctx, TRY_SEND_KEY_UPDATE);
    }
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static bool IsUnexpectedHandshaking(const TLS_Ctx *ctx)
{
    return (ctx->state == CM_STATE_HANDSHAKING && ctx->preState == CM_STATE_TRANSPORTING);
}
static int32_t ProcessHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    uint32_t version = HS_GetVersion(ctx);
    (void)version;
    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_SERVER
        case TRY_RECV_CLIENT_HELLO:
#ifdef HITLS_TLS_PROTO_DTLS12
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                return DtlsServerRecvClientHelloProcess(ctx, hsMsg);
            }
#endif /* HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
            return Tls12ServerRecvClientHelloProcess(ctx, hsMsg, true);
#else
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC only for tls13 */
        case TRY_RECV_CERTIFICATE_REQUEST:
            return ClientRecvCertRequestProcess(ctx);
        case TRY_RECV_CLIENT_KEY_EXCHANGE:
            return ServerRecvClientKxProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_VERIFY:
            return ServerRecvClientCertVerifyProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
#ifdef HITLS_TLS_PROTO_DTLS12
        case TRY_RECV_HELLO_VERIFY_REQUEST:
            return DtlsClientRecvHelloVerifyRequestProcess(ctx, hsMsg);
#endif
        case TRY_RECV_SERVER_HELLO:
            return ClientRecvServerHelloProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_KEY_EXCHANGE:
            return ClientRecvServerKxProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO_DONE:
            return ClientRecvServerHelloDoneProcess(ctx);
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case TRY_RECV_NEW_SESSION_TICKET:
            return Tls12ClientRecvNewSeesionTicketProcess(ctx, hsMsg);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_HOST_CLIENT */
        case TRY_RECV_CERTIFICATE:
            return RecvCertificateProcess(ctx, hsMsg);
        case TRY_RECV_FINISH:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
#ifdef HITLS_TLS_PROTO_DTLS12
                if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                    return DtlsClientRecvFinishedProcess(ctx, hsMsg);
                }
#endif /* HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
                return Tls12ClientRecvFinishedProcess(ctx, hsMsg);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_PROTO_DTLS12
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                return DtlsServerRecvFinishedProcess(ctx, hsMsg);
            }
#endif /* HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
            return Tls12ServerRecvFinishedProcess(ctx, hsMsg);
#else
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#endif /* HITLS_TLS_HOST_SERVER */
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15350, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state error: should recv msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}
static int32_t ProcessReceivedHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if (hsMsg->type == HELLO_REQUEST) {
        if (ctx->hsCtx->state == TRY_RECV_HELLO_REQUEST) {
            ctx->negotiatedInfo.isRenegotiation = true; /* Start renegotiation */
            ctx->negotiatedInfo.renegotiationNum++;
            return HS_ChangeState(ctx, TRY_SEND_CLIENT_HELLO);
        }
        /* The HelloRequest message should be ignored during the handshake. */
        return HITLS_SUCCESS;
    }
    if (hsMsg->type == CLIENT_HELLO && IsUnexpectedHandshaking(ctx)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17028, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "refuse Renegotiation request from client", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_WARNING, ALERT_NO_RENEGOTIATION);
        (void)HS_ChangeState(ctx, TLS_CONNECTED);
        return HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    }
    return ProcessHandshakeMsg(ctx, hsMsg);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13ProcessReceivedHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if ((hsMsg->type == HELLO_REQUEST) && (ctx->isClient)) {
        /* The HelloRequest message should be ignored during the handshake. */
        return HITLS_SUCCESS;
    }

    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_SERVER
        case TRY_RECV_CLIENT_HELLO:
            return Tls13ServerRecvClientHelloProcess(ctx, hsMsg);
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_RECV_CERTIFICATE_REQUEST:
            return Tls13ClientRecvCertRequestProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO:
            return Tls13ClientRecvServerHelloProcess(ctx, hsMsg);
        case TRY_RECV_ENCRYPTED_EXTENSIONS:
            return Tls13ClientRecvEncryptedExtensionsProcess(ctx, hsMsg);
#endif /* HITLS_TLS_HOST_CLIENT */
        case TRY_RECV_CERTIFICATE:
            return Tls13RecvCertificateProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_VERIFY:
            return Tls13RecvCertVerifyProcess(ctx);
        case TRY_RECV_FINISH:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
                return Tls13ClientRecvFinishedProcess(ctx, hsMsg);
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
            return Tls13ServerRecvFinishedProcess(ctx, hsMsg);
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case TRY_RECV_KEY_UPDATE:
            return Tls13RecvKeyUpdateProcess(ctx, hsMsg);
#endif
        case TRY_RECV_NEW_SESSION_TICKET:
            return Tls13ClientRecvNewSessionTicketProcess(ctx, hsMsg);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15343, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 handshake state error: should recv msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}
#endif /* HITLS_TLS_PROTO_TLS13 */

int32_t ReadHsMessage(TLS_Ctx *ctx, uint32_t length)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (hsCtx == NULL || hsCtx->msgBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17029, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    if (hsCtx->msgLen >= length) {
        return HITLS_SUCCESS;
    }
    int32_t ret = HS_GrowMsgBuf(ctx, length, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t readLen = 0;
    do {
        readLen = 0;
        ret = REC_Read(ctx, REC_TYPE_HANDSHAKE, &hsCtx->msgBuf[hsCtx->msgLen], &readLen, length - hsCtx->msgLen);
        hsCtx->msgLen += readLen;
        if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
            break;
        }
    } while (ret == HITLS_SUCCESS && hsCtx->msgLen < length && readLen != 0);
    if (ret == HITLS_SUCCESS && hsCtx->msgLen < length) {
        return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
    }
    return ret;
}

#ifdef HITLS_TLS_PROTO_TLS

static int32_t ReadThenParseTlsHsMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    int32_t ret = ReadHsMessage(ctx, HS_MSG_HEADER_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    HS_MsgInfo hsMsgInfo = {0};
    ret = HS_ParseMsgHeader(ctx, hsCtx->msgBuf, HS_MSG_HEADER_SIZE, &hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = ReadHsMessage(ctx, hsMsgInfo.headerAndBodyLen); // hsCtx->msgBuf always has enough buf
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HS_ParseMsg(ctx, &hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The HelloRequest message is not included. */
    if (hsMsgInfo.type != HELLO_REQUEST && hsMsgInfo.type != KEY_UPDATE &&
        !(HS_GetVersion(ctx) == HITLS_VERSION_TLS13 && hsMsgInfo.type == NEW_SESSION_TICKET)) {
        /* Session hash is needed to compute ems, the VERIFY_Append must be dealt with beforehand */
        ret = VERIFY_Append(hsCtx->verifyCtx, hsCtx->msgBuf, hsMsgInfo.headerAndBodyLen);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "VERIFY_Append fail", 0,
                                  0, 0, 0);
            HS_CleanMsg(hsMsg);
            return ret;
        }
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo.rawMsg, hsMsgInfo.headerAndBodyLen,
        ctx, ctx->config.tlsConfig.msgArg);
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    hsCtx->msgLen = 0;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
static int32_t Tls12TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    (void)memset_s(&hsMsg, sizeof(HS_Msg), 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        ret = ReadThenParseTlsHsMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(&hsMsg);
            return ret;
        }
        ctx->hsCtx->hsMsg = &hsMsg;
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }
    ret = ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    (void)memset_s(&hsMsg, sizeof(HS_Msg), 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        ret = ReadThenParseTlsHsMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(&hsMsg);
            return ret;
        }
        ctx->hsCtx->hsMsg = &hsMsg;
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }
    ret = Tls13ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_PROTO_TLS */
#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t DtlsCheckTimeoutAndProcess(TLS_Ctx *ctx, int32_t retValue)
{
    (void)ctx;
#ifdef HITLS_BSL_UIO_UDP
    int32_t ret = HITLS_DtlsProcessTimeout(ctx);
    if (ret != HITLS_SUCCESS && ret != HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT) {
        return ret;
    }
#endif
    /* HITLS_REC_NORMAL_RECV_BUF_EMPTY is returned here, and the choice is given to the user instead of the next read,
     * Prevents users from waiting for a long time due to long timeout. */
    return retValue;
}

int32_t DtlsDisorderMsgProcess(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* The SCTP scenario must be sequenced. */
    if (BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "msg with unmatched sequence, recv %u, expect %u.", hsMsgInfo->sequence, hsCtx->expectRecvSeq, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE;
    }
#ifdef HITLS_BSL_UIO_UDP
    /* In the renegotiation state, the FINISHED message of the previous handshake should be discarded. */
    if (ctx->hsCtx->expectRecvSeq == 0 && hsMsgInfo->type == FINISHED) {
        return HITLS_SUCCESS;
    }
    /* If the sequence number of the received message is greater than expected, the message is cached in the reassembly
     * queue. */
    if (hsMsgInfo->sequence > ctx->hsCtx->expectRecvSeq) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17033, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the message is need to cache in the reassembly queue", 0, 0, 0, 0);
        return HS_ReassAppend(ctx, hsMsgInfo);
    }

    return HITLS_SUCCESS;
#else
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17034, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "internal exception occurs", 0, 0, 0, 0);
    return HITLS_INTERNAL_EXCEPTION;
#endif /* HITLS_BSL_UIO_UDP */
}
static int32_t DtlsCheckAndParseMsg(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    int32_t ret = CheckHsMsgType(ctx, hsMsgInfo->type);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_ParseMsg(ctx, hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(hsMsg);
        return ret;
    }

    hsCtx->expectRecvSeq++; /* Auto-increment of the received message sequence number */
    return ret;
}

static int32_t ReadDtlsHsMessage(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;
    if (hsCtx == NULL || hsCtx->msgBuf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17035, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    uint8_t *buf = &hsCtx->msgBuf[hsCtx->msgLen];
    uint32_t readLen = 0;
    if (hsCtx->msgLen < DTLS_HS_MSG_HEADER_SIZE) {
        ret = REC_Read(ctx, REC_TYPE_HANDSHAKE, buf, &readLen, (uint32_t)(DTLS_HS_MSG_HEADER_SIZE - hsCtx->msgLen));
        if (ret != HITLS_SUCCESS) {
            if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
                return ret;
            }
            if (hsCtx->msgLen == 0) {
                return DtlsCheckTimeoutAndProcess(ctx, ret);
            }
        }
        hsCtx->msgLen += readLen;
    }
    ret = HS_ParseMsgHeader(ctx, hsCtx->msgBuf, hsCtx->msgLen, hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = ReadHsMessage(ctx, hsMsgInfo->fragmentLength + DTLS_HS_MSG_HEADER_SIZE);
    if ((hsMsgInfo->fragmentLength + DTLS_HS_MSG_HEADER_SIZE) != hsCtx->msgLen || ret != HITLS_SUCCESS) {
        hsCtx->msgLen = 0;
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15600, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS handshake msg length error, need to alert.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return ret;
}

static int32_t DtlsReadAndParseHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    HS_MsgInfo hsMsgInfo = {0};
    uint32_t dataLen = 0;
    int32_t ret = HS_GetReassMsg(ctx, &hsMsgInfo, &dataLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *buf = ctx->hsCtx->msgBuf;
    if (dataLen == 0) {
        ret = ReadDtlsHsMessage(ctx, &hsMsgInfo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        buf = ctx->hsCtx->msgBuf;
        dataLen = ctx->hsCtx->msgLen;
        ctx->hsCtx->msgLen = 0;
        /* when the hello verify request is lost and a clienthello with 0 message sequence is received again,
           the expect sequence is reset and dealt with same as receiving it for the first time. */
        if (hsMsgInfo.sequence == 0 && ctx->hsCtx->expectRecvSeq == 1 && ctx->hsCtx->state == TRY_RECV_CLIENT_HELLO &&
            hsMsgInfo.type == CLIENT_HELLO && !IsUnexpectedHandshaking(ctx) && ctx->state == CM_STATE_HANDSHAKING &&
            !BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_SCTP)) {
            ctx->hsCtx->expectRecvSeq = 0;
            ctx->hsCtx->nextSendSeq = 0;
        }

        /* SCTP messages are not out of order. Therefore, an alert message must be sent for the out-of-order messages */
        if (hsMsgInfo.sequence != ctx->hsCtx->expectRecvSeq && !IsUnexpectedHandshaking(ctx)) {
            return DtlsDisorderMsgProcess(ctx, &hsMsgInfo);
        }

        /* If the message is fragmented, the message needs to be reassembled. */
        if (hsMsgInfo.fragmentLength != hsMsgInfo.length) {
            return HS_ReassAppend(ctx, &hsMsgInfo);
        }
    }

    ret = DtlsCheckAndParseMsg(ctx, &hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The HelloRequest message is not included. */
    if (hsMsgInfo.type != HELLO_REQUEST) {
        /* Session hash is needed to compute ems, the VERIFY_Append must be dealt with beforehand */
        ret = VERIFY_Append(ctx->hsCtx->verifyCtx, buf, dataLen);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(hsMsg);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17036, "VERIFY_Append fail");
        }
    }
    ctx->hsCtx->hsMsg = hsMsg;
#ifdef HITLS_TLS_FEATURE_INDICATOR
    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo.rawMsg,
        hsMsgInfo.headerAndBodyLen, ctx, ctx->config.tlsConfig.msgArg);
    INDICATOR_StatusIndicate(ctx, ctx->isClient ? INDICATE_EVENT_STATE_CONNECT_LOOP : INDICATE_EVENT_STATE_ACCEPT_LOOP,
        INDICATE_VALUE_SUCCESS);
#endif /* HITLS_TLS_FEATURE_INDICATOR */
    return HITLS_SUCCESS;
}

static int32_t DtlsTryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    (void)memset_s(&hsMsg, sizeof(HS_Msg), 0, sizeof(HS_Msg));
    if (ctx->hsCtx->hsMsg == NULL) {
        ret = DtlsReadAndParseHandshakeMsg(ctx, &hsMsg);
        if (ret != HITLS_SUCCESS || ctx->hsCtx->hsMsg == NULL) {
            return ret;
        }
        ctx->hsCtx->readSubState = TLS_PROCESS_STATE_A;
    }

    ret = ProcessReceivedHandshakeMsg(ctx, ctx->hsCtx->hsMsg);
    return CheckHsMsg(ctx, &hsMsg, ret);
}
#endif

int32_t HandleResult(TLS_Ctx *ctx, int32_t ret)
{
    if (ret != HITLS_SUCCESS) {
        if (ctx->method.getAlertFlag(ctx)) {
            /* The alert has been processed. The handshake should be terminated. */
            return ret;
        }
        if (ret == HITLS_REC_NORMAL_RECV_DISORDER_MSG) {
            /* App messages and finished messages are out of order. The handshake proceeds. */
            return HITLS_SUCCESS;
        }
        if ((ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) &&
            REC_GetUnexpectedMsgType(ctx) == REC_TYPE_CHANGE_CIPHER_SPEC) {
            /* The CCS message is received. The handshake proceeds. */
            return HITLS_SUCCESS;
        }
        /* Other errors are returned */
    }
    return ret;
}

int32_t HS_RecvMsgProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /* If isFlightTransmitEnable is enabled, the handshake information stored in the bUio needs to be sent when the
     * receiving status is changed. */
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = REC_FlightTransmit(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_FLIGHT */
    uint32_t version = HS_GetVersion(ctx);

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS
        case HITLS_VERSION_TLS12:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#if defined(HITLS_TLS_PROTO_DTLS12)
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                ret = DtlsTryRecvHandShakeMsg(ctx);
                break;
            }
#endif
#endif /* HITLS_TLS_PROTO_TLCP11 */
#ifdef HITLS_TLS_PROTO_TLS_BASIC
            ret = Tls12TryRecvHandShakeMsg(ctx);
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
        case HITLS_VERSION_TLS13:
            ret = Tls13TryRecvHandShakeMsg(ctx);
            break;
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_PROTO_TLS */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            ret = DtlsTryRecvHandShakeMsg(ctx);
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15352, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Handshake state recv error: unsupport TLS version.", 0, 0, 0, 0);
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }
    return HandleResult(ctx, ret);
}
