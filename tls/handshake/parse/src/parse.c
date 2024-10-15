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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "hs.h"
#include "hs_common.h"
#include "parse_msg.h"
#include "indicator.h"

#define TLS_PLAINTEXT_EXPANSION 2048u
#define TLS13_PLAINTEXT_EXPANSION 256u
typedef int32_t (*CheckHsMsgTypeFunc)(TLS_Ctx *ctx, const HS_MsgType msgType);

typedef struct {
    HS_MsgType msgType;
    CheckHsMsgTypeFunc checkCb;
} HsMsgTypeCheck;

static int32_t CheckServerKeyExchangeType(TLS_Ctx *ctx, const HS_MsgType msgType)
{
    /* When the PSK and RSA_PSK are used, whether the ServerKeyExchange message is received depends on whether the
     * server sends a PSK identity hint */
    if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_PSK ||
        ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_RSA_PSK) {
        if (msgType == CERTIFICATE_REQUEST) {
            HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
            return HITLS_SUCCESS;
        } else if (msgType == SERVER_HELLO_DONE) {
            HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO_DONE);
            return HITLS_SUCCESS;
        }
    }
    return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
}

static int32_t CheckCertificateRequestType(TLS_Ctx *ctx, const HS_MsgType msgType)
{
    uint32_t version = HS_GetVersion(ctx);
    if (version == HITLS_VERSION_TLS13) {
        if (msgType == CERTIFICATE) {
            HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
            return HITLS_SUCCESS;
        }
    } else {
        if (msgType == SERVER_HELLO_DONE) {
            HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO_DONE);
            return HITLS_SUCCESS;
        }
    }
    return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
}

static const HsMsgTypeCheck g_checkHsMsgTypeList[] = {
    [TRY_RECV_CLIENT_HELLO] = {.msgType = CLIENT_HELLO,
                               .checkCb = NULL},
    [TRY_RECV_SERVER_HELLO] = {.msgType = SERVER_HELLO,
                               .checkCb = NULL},
    [TRY_RECV_ENCRYPTED_EXTENSIONS] = {.msgType = ENCRYPTED_EXTENSIONS,
                                       .checkCb = NULL},
    [TRY_RECV_CERTIFICATE] = {.msgType = CERTIFICATE,
                              .checkCb = NULL},
    [TRY_RECV_SERVER_KEY_EXCHANGE] = {.msgType = SERVER_KEY_EXCHANGE,
                                      .checkCb = CheckServerKeyExchangeType},
    [TRY_RECV_CERTIFICATE_REQUEST] = {.msgType = CERTIFICATE_REQUEST,
                                      .checkCb = CheckCertificateRequestType},
    [TRY_RECV_SERVER_HELLO_DONE] = {.msgType = SERVER_HELLO_DONE,
                                    .checkCb = NULL},
    [TRY_RECV_CLIENT_KEY_EXCHANGE] = {.msgType = CLIENT_KEY_EXCHANGE,
                                      .checkCb = NULL},
    [TRY_RECV_CERTIFICATE_VERIFY] = {.msgType = CERTIFICATE_VERIFY,
                                     .checkCb = NULL},
    [TRY_RECV_NEW_SESSION_TICKET] = {.msgType = NEW_SESSION_TICKET,
                                     .checkCb = NULL},
    [TRY_RECV_FINISH] = {.msgType = FINISHED,
                         .checkCb = NULL},
};

int32_t CheckHsMsgType(TLS_Ctx *ctx, HS_MsgType msgType)
{
    if (ctx->state != CM_STATE_HANDSHAKING && ctx->state != CM_STATE_RENEGOTIATION) {
        return HITLS_SUCCESS;
    }

    if ((msgType == HELLO_REQUEST) && (ctx->isClient)) {
        /* The HelloRequest message may appear at any time during the handshake.
           The client should ignore this message */
        return HITLS_SUCCESS;
    }

    HS_Ctx *hsCtx = ctx->hsCtx;
    const char *expectedMsg = NULL;
    if (msgType != g_checkHsMsgTypeList[hsCtx->state].msgType) {
        if (g_checkHsMsgTypeList[hsCtx->state].checkCb == NULL ||
            g_checkHsMsgTypeList[hsCtx->state].checkCb(ctx, msgType) != HITLS_SUCCESS) {
            expectedMsg = HS_GetMsgTypeStr(g_checkHsMsgTypeList[hsCtx->state].msgType);
        }
    }

    if (msgType == FINISHED && HS_GetVersion(ctx) != HITLS_VERSION_TLS13) {
        bool isCcsRecv = ctx->method.isRecvCCS(ctx);
        if (isCcsRecv != true) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15349, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Handshake state expect finished, but recv ccs state(%d)", (int32_t)isCcsRecv, 0, 0, 0);
            expectedMsg = HS_GetMsgTypeStr(FINISHED);
        }
    }

    if (expectedMsg != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID15571, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Handshake state expect %s", expectedMsg);
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID15572, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            ", but got %s.", HS_GetMsgTypeStr(msgType));

        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    }
    return HITLS_SUCCESS;
}

#ifndef HITLS_NO_DTLS12
static int32_t DtlsParseHsMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    if (len < DTLS_HS_MSG_HEADER_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15599, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS handshake msg length error when parse msg header.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    hsMsgInfo->type = data[0]; /* The 0 byte is the handshake message type */
    if (hsMsgInfo->type >= HS_MSG_TYPE_END) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15936, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS invalid message type: %d.", hsMsgInfo->type, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
    }
    hsMsgInfo->length = BSL_ByteToUint24(&data[DTLS_HS_MSGLEN_ADDR]);
    hsMsgInfo->sequence = BSL_ByteToUint16(&data[DTLS_HS_MSGSEQ_ADDR]);
    hsMsgInfo->fragmentOffset = BSL_ByteToUint24(&data[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
    hsMsgInfo->fragmentLength = BSL_ByteToUint24(&data[DTLS_HS_FRAGMENT_LEN_ADDR]);
    hsMsgInfo->rawMsg = data;
    hsMsgInfo->isHsMsgComplete = true;

    if (((hsMsgInfo->fragmentLength + DTLS_HS_MSG_HEADER_SIZE) != len) ||
        ((hsMsgInfo->fragmentLength + hsMsgInfo->fragmentOffset) > hsMsgInfo->length) ||
        ((hsMsgInfo->length != 0) && (hsMsgInfo->fragmentLength == 0))) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15600, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS handshake msg length error, need to alert.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t maxMsgLen = HS_MaxMessageSize(ctx, hsMsgInfo->type);
    if (hsMsgInfo->length > maxMsgLen) {
        BSL_ERR_PUSH_ERROR(HTILS_PARSE_EXCESSIVE_MESSAGE_SIZE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15937, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS handshake msg parsed length: %u, max length: %u.", hsMsgInfo->length, maxMsgLen, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HTILS_PARSE_EXCESSIVE_MESSAGE_SIZE;
    }
    hsMsgInfo->headerAndBodyLen = hsMsgInfo->length + DTLS_HS_MSG_HEADER_SIZE;

    if (hsMsgInfo->type == HELLO_REQUEST && hsMsgInfo->length == 0) {
        INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, data, DTLS_HS_MSG_HEADER_SIZE,
                                  ctx, ctx->config.tlsConfig.msgArg);
    }

    return HITLS_SUCCESS;
}
#endif

static int32_t CheckHsMsgLen(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t hsMsgOfSpecificTypeMaxSize = HS_MaxMessageSize(ctx, hsMsgInfo->type);
    if (hsMsgInfo->length > hsMsgOfSpecificTypeMaxSize) {
        BSL_ERR_PUSH_ERROR(HTILS_PARSE_EXCESSIVE_MESSAGE_SIZE);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15800, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLS HS msg type: %d, parsed length: %u, max length: %u.", (int)hsMsgInfo->type, hsMsgInfo->length,
            hsMsgOfSpecificTypeMaxSize, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HTILS_PARSE_EXCESSIVE_MESSAGE_SIZE;
    }
    uint32_t hsPlaintextLen = HS_MSG_HEADER_SIZE + hsMsgInfo->length;
    uint32_t expansionLen =
        (HS_GetVersion(ctx) == HITLS_VERSION_TLS13) ? TLS13_PLAINTEXT_EXPANSION : TLS_PLAINTEXT_EXPANSION;
    if (hsPlaintextLen > REC_MAX_PLAIN_LENGTH) {
        // If this branch is entered, the hsCtx is guaranteed to exist
        hsMsgInfo->isHsMsgComplete = false;
        uint32_t cpyLen = (len < ctx->hsCtx->bufferLen) ? len : ctx->hsCtx->bufferLen;
        if (data != ctx->hsCtx->msgBuf) {
            (void)memcpy_s(ctx->hsCtx->msgBuf, ctx->hsCtx->bufferLen, data, cpyLen);
        }
        ret = HS_GrowMsgBuf(ctx, hsPlaintextLen + expansionLen, hsPlaintextLen + expansionLen, true);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        hsMsgInfo->rawMsg = ctx->hsCtx->msgBuf;
    }
    hsMsgInfo->headerAndBodyLen = hsPlaintextLen;

    if (hsMsgInfo->type == HELLO_REQUEST && hsMsgInfo->length == 0) {
        INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_HANDSHAKE, hsMsgInfo->rawMsg,
            HS_MSG_HEADER_SIZE, ctx, ctx->config.tlsConfig.msgArg);
    }

    return ret;
}

static int32_t TlsParseHsMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    if (len < HS_MSG_HEADER_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15601, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLS decode error: msg len = %u.", len, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    hsMsgInfo->type = data[0];

    if (hsMsgInfo->type >= HS_MSG_TYPE_END) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15801, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLS invalid message type: %d.", hsMsgInfo->type, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
    }

    int32_t ret = CheckHsMsgType(ctx, hsMsgInfo->type);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    hsMsgInfo->length = BSL_ByteToUint24(data + sizeof(uint8_t)); /* Parse handshake body length */
    hsMsgInfo->sequence = 0;                                      /* TLS does not have this field */
    hsMsgInfo->fragmentOffset = 0;                                /* TLS does not have this field */
    hsMsgInfo->fragmentLength = 0;                                /* TLS does not have this field */
    hsMsgInfo->rawMsg = data;
    hsMsgInfo->isHsMsgComplete = true;

    return CheckHsMsgLen(ctx, data, len, hsMsgInfo);
}

static int32_t ParseHandShakeMsg(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    switch (hsMsg->type) {
        case CLIENT_HELLO:
            return ParseClientHello(ctx, data, len, hsMsg);
        case SERVER_HELLO:
            return ParseServerHello(ctx, data, len, hsMsg);
        case CERTIFICATE:
            return ParseCertificate(ctx, data, len, hsMsg);
        case SERVER_KEY_EXCHANGE:
            return ParseServerKeyExchange(ctx, data, len, hsMsg);
        case CERTIFICATE_REQUEST:
            return ParseCertificateRequest(ctx, data, len, hsMsg);
        case CLIENT_KEY_EXCHANGE:
            return ParseClientKeyExchange(ctx, data, len, hsMsg);
        case CERTIFICATE_VERIFY:
            return ParseCertificateVerify(ctx, data, len, hsMsg);
        case NEW_SESSION_TICKET:
            return ParseNewSessionTicket(ctx, data, len, hsMsg);
        case FINISHED:
            return ParseFinished(ctx, data, len, hsMsg);
        case HELLO_REQUEST:
        case SERVER_HELLO_DONE:
            if (len != 0u) {
                    BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
                    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15603, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                        "msg %s", HS_GetMsgTypeStr(hsMsg->type));
                    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15611, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                        "msg length = %u", len, 0, 0, 0);
                    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
                    return HITLS_PARSE_INVALID_MSG_LEN;
                }
            return HITLS_SUCCESS;
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15604, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "dtls parse handshake msg error, unsupport type[%d].", hsMsg->type, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
}

int32_t Tls13ParseHandShakeMsg(TLS_Ctx *ctx, const uint8_t *hsBodyData, uint32_t hsBodyLen, HS_Msg *hsMsg)
{
    switch (hsMsg->type) {
        case CLIENT_HELLO:
            return ParseClientHello(ctx, hsBodyData, hsBodyLen, hsMsg);
        case SERVER_HELLO:
            return ParseServerHello(ctx, hsBodyData, hsBodyLen, hsMsg);
        case ENCRYPTED_EXTENSIONS:
            return ParseEncryptedExtensions(ctx, hsBodyData, hsBodyLen, hsMsg);
        case CERTIFICATE:
            return Tls13ParseCertificate(ctx, hsBodyData, hsBodyLen, hsMsg);
        case CERTIFICATE_REQUEST:
            return Tls13ParseCertificateRequest(ctx, hsBodyData, hsBodyLen, hsMsg);
        case CERTIFICATE_VERIFY:
            return ParseCertificateVerify(ctx, hsBodyData, hsBodyLen, hsMsg);
        case FINISHED:
            return ParseFinished(ctx, hsBodyData, hsBodyLen, hsMsg);
        case KEY_UPDATE:
            return ParseKeyUpdate(ctx, hsBodyData, hsBodyLen, hsMsg);
        case NEW_SESSION_TICKET:
            return ParseNewSessionTicket(ctx, hsBodyData, hsBodyLen, hsMsg);
        case HELLO_REQUEST:
            if (hsBodyLen != 0u) {
                BSL_ERR_PUSH_ERROR(HITLS_PARSE_INVALID_MSG_LEN);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15611, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "hello request length is not zero.", 0, 0, 0, 0);
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
                return HITLS_PARSE_INVALID_MSG_LEN;
            }
            return HITLS_SUCCESS;
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15605, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "parse TLS1.3 handshake msg error, unsupport type[%d].", hsMsg->type, 0, 0, 0);
    return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
}

int32_t HS_ParseMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    if ((ctx == NULL) || (ctx->method.sendAlert == NULL) || (data == NULL) || (hsMsgInfo == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15606, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the input parameter pointer is null.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t version = HS_GetVersion(ctx);

    switch (version) {
        case HITLS_VERSION_TLS12:
        case HITLS_VERSION_TLS13:
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
#endif
            return TlsParseHsMsgHeader(ctx, data, len, hsMsgInfo);
#ifndef HITLS_NO_DTLS12
        case HITLS_VERSION_DTLS12:
            return DtlsParseHsMsgHeader(ctx, data, len, hsMsgInfo);
#endif
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15607, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "parse msg header error, unsupport version[0x%x].", version, 0, 0, 0);
    return HITLS_PARSE_UNSUPPORT_VERSION;
}

int32_t HS_ParseMsg(TLS_Ctx *ctx, const HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg)
{
    if ((ctx == NULL) || (ctx->method.sendAlert == NULL) || (hsMsgInfo == NULL) || (hsMsgInfo->rawMsg == NULL) ||
        (hsMsg == NULL)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15608, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the input parameter pointer is null.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }
    hsMsg->type = hsMsgInfo->type;
    hsMsg->length = hsMsgInfo->length;
    hsMsg->sequence = hsMsgInfo->sequence;
    hsMsg->fragmentOffset = hsMsgInfo->fragmentOffset;
    hsMsg->fragmentLength = hsMsgInfo->fragmentLength;

    uint32_t version = HS_GetVersion(ctx);

    switch (version) {
        case HITLS_VERSION_TLS12:
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
#endif
            return ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
        case HITLS_VERSION_TLS13:
            return Tls13ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
#ifndef HITLS_NO_DTLS12
        case HITLS_VERSION_DTLS12:
            return ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[DTLS_HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15609, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "parse handshake msg error, unsupport version[0x%x].", version, 0, 0, 0);
    return HITLS_PARSE_UNSUPPORT_VERSION;
}

void HS_CleanMsg(HS_Msg *hsMsg)
{
    if (hsMsg == NULL) {
        return;
    }

    switch (hsMsg->type) {
        case CLIENT_HELLO:
            return CleanClientHello(&hsMsg->body.clientHello);
        case SERVER_HELLO:
            return CleanServerHello(&hsMsg->body.serverHello);
        case ENCRYPTED_EXTENSIONS:
            return CleanEncryptedExtensions(&hsMsg->body.encryptedExtensions);
        case CERTIFICATE:
            return CleanCertificate(&hsMsg->body.certificate);
        case SERVER_KEY_EXCHANGE:
            return CleanServerKeyExchange(&hsMsg->body.serverKeyExchange);
        case CERTIFICATE_REQUEST:
            return CleanCertificateRequest(&hsMsg->body.certificateReq);
        case CLIENT_KEY_EXCHANGE:
            return CleanClientKeyExchange(&hsMsg->body.clientKeyExchange);
        case CERTIFICATE_VERIFY:
            return CleanCertificateVerify(&hsMsg->body.certificateVerify);
        case NEW_SESSION_TICKET:
            return CleanNewSessionTicket(&hsMsg->body.newSessionTicket);
        case FINISHED:
            return CleanFinished(&hsMsg->body.finished);
        case KEY_UPDATE:
        case HELLO_REQUEST:
        case SERVER_HELLO_DONE:
            return;
        default:
            break;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15610, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "clean handshake msg error, unsupport type[%d].", hsMsg->type, 0, 0, 0);
    return;
}
