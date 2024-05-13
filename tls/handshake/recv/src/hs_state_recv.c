/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
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
#include "transcript_hash.h"
#include "hs_reass.h"
#include "parse.h"
#include "recv_process.h"
#include "bsl_uio.h"
#include "hs_kx.h"
#include "indicator.h"
#include "securec.h"

static int32_t ProcessReceivedHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if (hsMsg->type == HELLO_REQUEST) {
        /* When the HelloRequest message appear at any time during the handshake, it should be ignored */
        return HITLS_SUCCESS;
    }
#ifndef HITLS_NO_DTLS12
    uint32_t version = HS_GetVersion(ctx);
#endif
    switch (ctx->hsCtx->state) {
        case TRY_RECV_CLIENT_HELLO:
#ifndef HITLS_NO_DTLS12
            if (version == HITLS_VERSION_DTLS12) {
                return DtlsServerRecvClientHelloProcess(ctx, hsMsg);
            }
#endif
            return Tls12ServerRecvClientHelloProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO:
            return ClientRecvServerHelloProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE:
            return RecvCertificateProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_KEY_EXCHANGE:
            return ClientRecvServerKxProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_REQUEST:
            return ClientRecvCertRequestProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO_DONE:
            return ClientRecvServerHelloDoneProcess(ctx);
        case TRY_RECV_CLIENT_KEY_EXCHANGE:
            return ServerRecvClientKxProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_VERIFY:
            return ServerRecvClientCertVerifyProcess(ctx);
        case TRY_RECV_NEW_SESSION_TICKET:
            return Tls12ClientRecvNewSeesionTicketProcess(ctx, hsMsg);
        case TRY_RECV_FINISH:
            if (ctx->isClient) {
#ifndef HITLS_NO_DTLS12
                if (version == HITLS_VERSION_DTLS12) {
                    return DtlsClientRecvFinishedProcess(ctx, hsMsg);
                }
#endif
                return Tls12ClientRecvFinishedProcess(ctx, hsMsg);
            }
#ifndef HITLS_NO_DTLS12
            if (version == HITLS_VERSION_DTLS12) {
                return DtlsServerRecvFinishedProcess(ctx, hsMsg);
            }
#endif
            return Tls12ServerRecvFinishedProcess(ctx, hsMsg);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15350, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state error: should recv msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}

int32_t Tls13TryRecvNewSeesionTicket(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if (!ctx->isClient) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID15329, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Unexpected msg: server recv new session ticket", HS_GetMsgTypeStr(hsMsg->type));
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }

    return Tls13ClientRecvNewSessionTicketProcess(ctx, hsMsg);
}
static int32_t Tls13ProcessReceivedHandshakeMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    if ((hsMsg->type == HELLO_REQUEST) && (ctx->isClient)) {
        /* The HelloRequest message may appear at any time during the handshake. The client should ignore this message
         */
        return HITLS_SUCCESS;
    }

    switch (ctx->hsCtx->state) {
        case TRY_RECV_CLIENT_HELLO:
            return Tls13ServerRecvClientHelloProcess(ctx, hsMsg);
        case TRY_RECV_SERVER_HELLO:
            return Tls13ClientRecvServerHelloProcess(ctx, hsMsg);
        case TRY_RECV_ENCRYPTED_EXTENSIONS:
            return Tls13ClientRecvEncryptedExtensionsProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_REQUEST:
            return Tls13ClientRecvCertRequestProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE:
            return Tls13RecvCertificateProcess(ctx, hsMsg);
        case TRY_RECV_CERTIFICATE_VERIFY:
            return Tls13RecvCertVerifyProcess(ctx);
        case TRY_RECV_FINISH:
            if (ctx->isClient) {
                return Tls13ClientRecvFinishedProcess(ctx, hsMsg);
            }
            return Tls13ServerRecvFinishedProcess(ctx, hsMsg);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_STATE_ILLEGAL);
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15343, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 handshake state error: should recv msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}

static int32_t ReadThenParseTlsHsMsg(TLS_Ctx *ctx, HS_Msg *hsMsg)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    int32_t ret = REC_TlsReadNbytes(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf, HS_MSG_HEADER_SIZE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    HS_MsgInfo hsMsgInfo = {0};
    ret = HS_ParseMsgHeader(ctx, hsCtx->msgBuf, HS_MSG_HEADER_SIZE, &hsMsgInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ctx->hasParsedHsMsgHeader = true;
    ret = REC_TlsReadNbytes(ctx, REC_TYPE_HANDSHAKE, hsCtx->msgBuf + HS_MSG_HEADER_SIZE, hsMsgInfo.length);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HS_ParseMsg(ctx, &hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The HelloRequest message is not included. */
    if (hsMsgInfo.type != HELLO_REQUEST) {
        /* Session hash is needed to compute ems, the VERIFY_Append must be dealt with beforehand */
        ret = VERIFY_Append(hsCtx->verifyCtx, hsCtx->msgBuf, hsMsgInfo.headerAndBodyLen);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(hsMsg);
            return ret;
        }
    }

    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo.rawMsg,
        hsMsgInfo.length, ctx, ctx->config.tlsConfig.msgArg);

    return HITLS_SUCCESS;
}

static int32_t Tls12TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    (void)memset_s(&hsMsg, sizeof(HS_Msg), 0, sizeof(HS_Msg));

    ret = ReadThenParseTlsHsMsg(ctx, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }

    ret = ProcessReceivedHandshakeMsg(ctx, &hsMsg);
    HS_CleanMsg(&hsMsg);

    return ret;
}

static int32_t Tls13TryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Msg hsMsg = {0};
    (void)memset_s(&hsMsg, sizeof(HS_Msg), 0, sizeof(HS_Msg));

    ret = ReadThenParseTlsHsMsg(ctx, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }

    ret = Tls13ProcessReceivedHandshakeMsg(ctx, &hsMsg);
    HS_CleanMsg(&hsMsg);

    return ret;
}

#ifndef HITLS_NO_DTLS12

int32_t DtlsDisorderMsgProcess(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    HS_Ctx *hsCtx = ctx->hsCtx;

    /* The SCTP scenario must be sequenced. */
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "msg with unmatched sequence, recv %u, expect %u.", hsMsgInfo->sequence, hsCtx->expectRecvSeq, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    return HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE;
}

static int32_t DtlsTryRecvHandShakeMsg(TLS_Ctx *ctx)
{
    HS_Ctx *hsCtx = ctx->hsCtx;
    uint8_t *buf = NULL;
    uint32_t dataLen = 0;
    HS_Msg hsMsg = {0};
    (void)memset_s(&hsMsg, sizeof(HS_Msg), 0, sizeof(HS_Msg));
    HS_MsgInfo hsMsgInfo = {0};

    /* Read the message with the expected sequence number from the reassembly queue. If no message exists, read the
     * message from the record layer */
    int32_t ret = HS_GetReassMsg(ctx, &hsMsgInfo, &dataLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    buf = hsCtx->msgBuf;
    if (dataLen == 0) {
        ret = REC_Read(ctx, REC_TYPE_HANDSHAKE, buf, &dataLen, hsCtx->bufferLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        ret = HS_ParseMsgHeader(ctx, buf, dataLen, &hsMsgInfo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }

        /* SCTP messages are not out of order. Therefore, an alert message must be sent for the out-of-order messages */
        if (hsMsgInfo.sequence != hsCtx->expectRecvSeq) {
            return DtlsDisorderMsgProcess(ctx, &hsMsgInfo);
        }

        /* If the message is fragmented, the message needs to be reassembled. */
        if (hsMsgInfo.fragmentLength != hsMsgInfo.length) {
            return HS_ReassAppend(ctx, &hsMsgInfo);
        }
    }

    ret = CheckHsMsgType(ctx, hsMsgInfo.type);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_ParseMsg(ctx, &hsMsgInfo, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }

    hsCtx->expectRecvSeq++; /* Auto-increment of the received message sequence number */

    /* The HelloRequest message is not included. */
    if (hsMsgInfo.type != HELLO_REQUEST) {
        /* Session hash is needed to compute ems, the VERIFY_Append must be dealt with beforehand */
        ret = VERIFY_Append(hsCtx->verifyCtx, buf, dataLen);
        if (ret != HITLS_SUCCESS) {
            HS_CleanMsg(&hsMsg);
            return ret;
        }
    }

    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo.rawMsg,
                              hsMsgInfo.length, ctx, ctx->config.tlsConfig.msgArg);

    if (hsMsgInfo.type == HELLO_REQUEST && hsMsgInfo.sequence != 0) {
        HS_CleanMsg(&hsMsg);
        return HITLS_SUCCESS;
    }
    ret = ProcessReceivedHandshakeMsg(ctx, &hsMsg);
    HS_CleanMsg(&hsMsg);
    return ret;
}
#endif

static int32_t FlightTransmit(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
    if (ret == BSL_UIO_IO_BUSY) {
        return HITLS_REC_NORMAL_IO_BUSY;
    }
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_REC_ERR_IO_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15777, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "fail to send handshake message in bUio.", 0, 0, 0, 0);
        return HITLS_REC_ERR_IO_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t HS_RecvMsgProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    /* If isFlightTransmitEnable is enabled, the handshake information stored in the bUio needs to be sent when the
     * receiving status is changed. */
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        ret = FlightTransmit(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    uint32_t version = HS_GetVersion(ctx);

    switch (version) {
        case HITLS_VERSION_TLS12:
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
#endif
            ret = Tls12TryRecvHandShakeMsg(ctx);
            break;
        case HITLS_VERSION_TLS13:
            ret = Tls13TryRecvHandShakeMsg(ctx);
            break;
#ifndef HITLS_NO_DTLS12
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

    if (ret != HITLS_SUCCESS) {
        if (ctx->method.getAlertFlag(ctx)) {
            /* The alert has been processed and the handshake cannot continue */
            return ret;
        }
        if (ret == HITLS_REC_NORMAL_RECV_DISORDER_MSG) {
            /* App messages and finished messages are out of order. Handshake can be continued */
            return HITLS_SUCCESS;
        }
        if ((ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) && (ctx->method.isRecvCCS(ctx))) {
            /* The CCS message is received, and the handshake can be continued. */
            return HITLS_SUCCESS;
        }
        /* return other errors */
    }
    return ret;
}

int32_t HS_HandleRecvKeyUpdate(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg)
{
    int32_t ret = HS_ParseMsg(ctx, hsMsgInfo, hsMsg);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15353, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse tls1.3 key update msg fail.", 0, 0, 0, 0);
        return ret;
    }

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
    ret = HS_TLS13UpdateTrafficSecret(ctx, false);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15355, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.3 in key update fail", 0, 0, 0, 0);
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15980, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 recv key update succ", 0, 0, 0, 0);
    return HITLS_SUCCESS;
}

static int32_t SelectVersionForHs(TLS_Ctx *ctx, uint16_t version, HS_Msg *hsMsg)
{
    int32_t ret = HITLS_SUCCESS;
    switch (version) {
        case HITLS_VERSION_TLS12:
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
#endif
            ret = Tls12ServerRecvClientHelloProcess(ctx, hsMsg);
            break;
#ifndef HITLS_NO_DTLS12
        case HITLS_VERSION_DTLS12:
            ret = DtlsServerRecvClientHelloProcess(ctx, hsMsg);
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15956, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Handshake state recv error: unsupport TLS version when recv renegotiation request.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            ret = HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
            break;
    }

    HS_CleanMsg(hsMsg);
    return ret;
}

int32_t HS_HandleRecvRenegoReq(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t version = HS_GetVersion(ctx);
    HS_Msg hsMsg = {0};
    HS_Ctx *hsCtx = ctx->hsCtx;
    uint32_t headerAndBodyLen = IS_DTLS_VERSION(version) ? (DTLS_HS_MSG_HEADER_SIZE + hsMsgInfo->length)
                                                         : (HS_MSG_HEADER_SIZE + hsMsgInfo->length);
    ret = HS_ParseMsg(ctx, hsMsgInfo, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }
#ifndef HITLS_NO_DTLS12
    hsCtx->expectRecvSeq++; /* Auto-increment of the received message sequence number */
#endif
    /* Because the HelloRequest message is empty, the message does not need to be processed and the hash of the message
     * does not need to be calculated. */
    if (hsMsgInfo->type == HELLO_REQUEST) {
        HS_CleanMsg(&hsMsg);
        return HITLS_SUCCESS;
    }

    ret = VERIFY_Append(hsCtx->verifyCtx, hsMsgInfo->rawMsg, headerAndBodyLen);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }

    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo->rawMsg,
                              hsMsgInfo->length, ctx, ctx->config.tlsConfig.msgArg);

    return SelectVersionForHs(ctx, version, &hsMsg);
}

int32_t HS_HandleTLS13NewSessionTicket(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    HS_Msg hsMsg = {0};
    int32_t ret = HS_ParseMsg(ctx, hsMsgInfo, &hsMsg);
    if (ret != HITLS_SUCCESS) {
        HS_CleanMsg(&hsMsg);
        return ret;
    }

    ret = Tls13TryRecvNewSeesionTicket(ctx, &hsMsg);

    HS_CleanMsg(&hsMsg);
    return ret;
}
