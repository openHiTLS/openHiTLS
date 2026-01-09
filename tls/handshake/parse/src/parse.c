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
#include "parse_common.h"
#include "hs_extensions.h"
#include "parse_extensions.h"
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif /* HITLS_TLS_FEATURE_INDICATOR */
typedef int32_t (*CheckHsMsgTypeFunc)(TLS_Ctx *ctx, const HS_MsgType msgType);

typedef struct {
    HS_MsgType msgType;
    CheckHsMsgTypeFunc checkCb;
} HsMsgTypeCheck;

#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t CheckHelloVerifyRequestType(TLS_Ctx *ctx, const HS_MsgType msgType)
{
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) && msgType == SERVER_HELLO) {
        (void)HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO);
        return HITLS_SUCCESS;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17022, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Check hvr Type fail", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
}
#endif

static int32_t CheckServerHelloType(TLS_Ctx *ctx, const HS_MsgType msgType)
{
    /* In DTLS, When client try to receive ServerHello message, it doesn't know if server enables
     * isSupportDtlsCookieExchange. If client receives HelloVerifyRequest message, also valid */
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) && msgType == HELLO_VERIFY_REQUEST) {
        (void)HS_ChangeState(ctx, TRY_RECV_HELLO_VERIFY_REQUEST);
        return HITLS_SUCCESS;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17331, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "CheckServerHelloType fail", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
}

static int32_t CheckServerKeyExchangeType(TLS_Ctx *ctx, const HS_MsgType msgType)
{
    /* When the PSK and RSA_PSK are used, whether the ServerKeyExchange message is received depends on whether the
     * server sends a PSK identity hint */
    if (ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_PSK ||
        ctx->hsCtx->kxCtx->keyExchAlgo == HITLS_KEY_EXCH_RSA_PSK) {
        if (msgType == CERTIFICATE_REQUEST) {
            (void)HS_ChangeState(ctx, TRY_RECV_CERTIFICATE_REQUEST);
            return HITLS_SUCCESS;
        } else if (msgType == SERVER_HELLO_DONE) {
            (void)HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO_DONE);
            return HITLS_SUCCESS;
        }
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17025, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "CheckServerKeyExchangeType fail", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
}

static int32_t CheckCertificateRequestType(TLS_Ctx *ctx, const HS_MsgType msgType)
{
#ifdef HITLS_TLS_PROTO_TLS13
    uint32_t version = GET_VERSION_FROM_CTX(ctx);
    if (version == HITLS_VERSION_TLS13) {
        if (msgType == CERTIFICATE) {
            (void)HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
            return HITLS_SUCCESS;
        }
    } else
#endif
    {
        if (msgType == SERVER_HELLO_DONE) {
            (void)HS_ChangeState(ctx, TRY_RECV_SERVER_HELLO_DONE);
            return HITLS_SUCCESS;
        }
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17026, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Check cert reqType fail", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
}

static const HsMsgTypeCheck g_checkHsMsgTypeList[] = {
    [TRY_RECV_CLIENT_HELLO] = {.msgType = CLIENT_HELLO,
                               .checkCb = NULL},
    [TRY_RECV_SERVER_HELLO] = {.msgType = SERVER_HELLO, .checkCb = CheckServerHelloType},
#ifdef HITLS_TLS_PROTO_DTLS12
    [TRY_RECV_HELLO_VERIFY_REQUEST] = {.msgType = HELLO_VERIFY_REQUEST, .checkCb = CheckHelloVerifyRequestType},
#endif
#ifdef HITLS_TLS_PROTO_TLS13
    [TRY_RECV_ENCRYPTED_EXTENSIONS] = {.msgType = ENCRYPTED_EXTENSIONS, .checkCb = NULL},
#endif
    [TRY_RECV_CERTIFICATE] = {.msgType = CERTIFICATE, .checkCb = NULL},
    [TRY_RECV_SERVER_KEY_EXCHANGE] = {.msgType = SERVER_KEY_EXCHANGE, .checkCb = CheckServerKeyExchangeType},
    [TRY_RECV_CERTIFICATE_REQUEST] = {.msgType = CERTIFICATE_REQUEST, .checkCb = CheckCertificateRequestType},
    [TRY_RECV_SERVER_HELLO_DONE] = {.msgType = SERVER_HELLO_DONE, .checkCb = NULL},
    [TRY_RECV_CLIENT_KEY_EXCHANGE] = {.msgType = CLIENT_KEY_EXCHANGE, .checkCb = NULL},
    [TRY_RECV_CERTIFICATE_VERIFY] = {.msgType = CERTIFICATE_VERIFY,  .checkCb = NULL},
    [TRY_RECV_NEW_SESSION_TICKET] = {.msgType = NEW_SESSION_TICKET, .checkCb = NULL},
    [TRY_RECV_FINISH] = {.msgType = FINISHED, .checkCb = NULL},
#ifdef HITLS_TLS_PROTO_TLS13
    [TRY_RECV_KEY_UPDATE] = {.msgType = KEY_UPDATE, .checkCb = NULL},
#endif
    [TRY_RECV_HELLO_REQUEST] = {.msgType = HELLO_REQUEST, .checkCb = NULL},
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
#ifdef HITLS_BSL_LOG
    const char *expectedMsg = NULL;
#endif
    bool isUnexpected = false;
    if (msgType != g_checkHsMsgTypeList[hsCtx->state].msgType) {
        if (g_checkHsMsgTypeList[hsCtx->state].checkCb == NULL ||
            g_checkHsMsgTypeList[hsCtx->state].checkCb(ctx, msgType) != HITLS_SUCCESS) {
#ifdef HITLS_BSL_LOG
            expectedMsg = HS_GetMsgTypeStr(g_checkHsMsgTypeList[hsCtx->state].msgType);
#endif
            isUnexpected = true;
        }
    }

    if (msgType == FINISHED && GET_VERSION_FROM_CTX(ctx) != HITLS_VERSION_TLS13 &&
            !(ctx->state == CM_STATE_HANDSHAKING && ctx->preState == CM_STATE_TRANSPORTING)) {
        bool isCcsRecv = ctx->method.isRecvCCS(ctx);
        if (isCcsRecv != true) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15349, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "recv finish but haven't recv ccs", 0, 0, 0, 0);
#ifdef HITLS_BSL_LOG
            expectedMsg = HS_GetMsgTypeStr(FINISHED);
#endif
            isUnexpected = true;
        }
    }

    if (isUnexpected) {
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID16148, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Handshake state expect %s", expectedMsg);
        BSL_LOG_BINLOG_VARLEN(BINLOG_ID16149, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            ", but got %s.", HS_GetMsgTypeStr(msgType));
        return ParseErrorProcess(ctx, HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE, 0,
            NULL, ALERT_UNEXPECTED_MESSAGE);
    }
    return HITLS_SUCCESS;
}

static int32_t CheckHsMsgLen(TLS_Ctx *ctx, HS_MsgInfo *hsMsgInfo)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t headerLen = IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) ?
        DTLS_HS_MSG_HEADER_SIZE : HS_MSG_HEADER_SIZE;
    uint32_t hsMsgOfSpecificTypeMaxSize = HS_MaxMessageSize(ctx, hsMsgInfo->type);
    hsMsgOfSpecificTypeMaxSize = hsMsgOfSpecificTypeMaxSize > HITLS_HS_BUFFER_SIZE_LIMIT - headerLen ?
        HITLS_HS_BUFFER_SIZE_LIMIT - headerLen : hsMsgOfSpecificTypeMaxSize;
    if (hsMsgInfo->length > hsMsgOfSpecificTypeMaxSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16161, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "(D)TLS HS msg type: %d, parsed length: %u, max length: %u.", (int)hsMsgInfo->type, hsMsgInfo->length,
            hsMsgOfSpecificTypeMaxSize, 0);
        return ParseErrorProcess(ctx, HITLS_PARSE_EXCESSIVE_MESSAGE_SIZE, 0,
            NULL, ALERT_ILLEGAL_PARAMETER);
    }
    ret = HS_GrowMsgBuf(ctx, headerLen + hsMsgInfo->length, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    hsMsgInfo->rawMsg = ctx->hsCtx->msgBuf;
    hsMsgInfo->headerAndBodyLen = headerLen + hsMsgInfo->length;
    return ret;
}

#ifdef HITLS_TLS_PROTO_DTLS12
static int32_t DtlsParseHsMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    const char *logStr = BINGLOG_STR("parse DTLS handshake msg header failed.");
    if (len < DTLS_HS_MSG_HEADER_SIZE) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15599,
            logStr, ALERT_DECODE_ERROR);
    }

    hsMsgInfo->type = data[0]; /* The 0 byte is the handshake message type */
    if (hsMsgInfo->type >= HS_MSG_TYPE_END) {
        BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16123, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DTLS invalid message type: %d.", hsMsgInfo->type, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
    }
    hsMsgInfo->length = BSL_ByteToUint24(&data[DTLS_HS_MSGLEN_ADDR]);
    hsMsgInfo->sequence = BSL_ByteToUint16(&data[DTLS_HS_MSGSEQ_ADDR]);
    hsMsgInfo->fragmentOffset = BSL_ByteToUint24(&data[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
    hsMsgInfo->fragmentLength = BSL_ByteToUint24(&data[DTLS_HS_FRAGMENT_LEN_ADDR]);

    if (((hsMsgInfo->fragmentLength + hsMsgInfo->fragmentOffset) > hsMsgInfo->length) ||
        ((hsMsgInfo->length != 0) && (hsMsgInfo->fragmentLength == 0))) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15600,
            logStr, ALERT_DECODE_ERROR);
    }

    return CheckHsMsgLen(ctx, hsMsgInfo);
}

#endif /* HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS
static int32_t TlsParseHsMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    const char *logStr = BINGLOG_STR("parse TLS handshake msg header failed.");
    if (len < HS_MSG_HEADER_SIZE) {
        return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15601,
            logStr, ALERT_DECODE_ERROR);
    }

    hsMsgInfo->type = data[0];

    if (hsMsgInfo->type >= HS_MSG_TYPE_END) {
        return ParseErrorProcess(ctx, HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG, BINLOG_ID16160,
            logStr, ALERT_UNEXPECTED_MESSAGE);
    }

    int32_t ret = CheckHsMsgType(ctx, hsMsgInfo->type);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    hsMsgInfo->length = BSL_ByteToUint24(data + sizeof(uint8_t)); /* Parse handshake body length */
    hsMsgInfo->sequence = 0;                                      /* TLS does not have this field */
    hsMsgInfo->fragmentOffset = 0;                                /* TLS does not have this field */
    hsMsgInfo->fragmentLength = 0;                                /* TLS does not have this field */

    return CheckHsMsgLen(ctx, hsMsgInfo);
}
#endif /* HITLS_TLS_PROTO_TLS */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t ParseHandShakeMsg(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_Msg *hsMsg)
{
    switch (hsMsg->type) {
        case CLIENT_HELLO:
            return ParseClientHello(ctx, data, len, hsMsg);
#ifdef HITLS_TLS_HOST_CLIENT
        case SERVER_HELLO:
            return ParseServerHello(ctx, data, len, hsMsg);
        case SERVER_KEY_EXCHANGE:
            return ParseServerKeyExchange(ctx, data, len, hsMsg);
        case CERTIFICATE_REQUEST:
            return ParseCertificateRequest(ctx, data, len, hsMsg);
#ifdef HITLS_TLS_PROTO_DTLS12
        case HELLO_VERIFY_REQUEST:
            return ParseHelloVerifyRequest(ctx, data, len, hsMsg);
#endif
#endif
        case CERTIFICATE:
            return ParseCertificate(ctx, data, len, hsMsg);
        case CLIENT_KEY_EXCHANGE:
            return ParseClientKeyExchange(ctx, data, len, hsMsg);
#if defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)
        case CERTIFICATE_VERIFY:
            return ParseCertificateVerify(ctx, data, len, hsMsg);
#endif
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case NEW_SESSION_TICKET:
            return ParseNewSessionTicket(ctx, data, len, hsMsg);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
        case FINISHED:
            return ParseFinished(ctx, data, len, hsMsg);
        case HELLO_REQUEST:
        case SERVER_HELLO_DONE:
            if (len != 0u) {
                    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15603, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                        "msg %s", HS_GetMsgTypeStr(hsMsg->type));
                    return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15611,
                        BINGLOG_STR("length is not zero"), ALERT_ILLEGAL_PARAMETER);
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
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13ParseHandShakeMsg(TLS_Ctx *ctx, const uint8_t *hsBodyData, uint32_t hsBodyLen, HS_Msg *hsMsg)
{
    switch (hsMsg->type) {
#ifdef HITLS_TLS_HOST_SERVER
        case CLIENT_HELLO:
            return ParseClientHello(ctx, hsBodyData, hsBodyLen, hsMsg);
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case SERVER_HELLO:
            return ParseServerHello(ctx, hsBodyData, hsBodyLen, hsMsg);
        case ENCRYPTED_EXTENSIONS:
            return ParseEncryptedExtensions(ctx, hsBodyData, hsBodyLen, hsMsg);
        case CERTIFICATE_REQUEST:
            return Tls13ParseCertificateRequest(ctx, hsBodyData, hsBodyLen, hsMsg);
        case NEW_SESSION_TICKET:
            return ParseNewSessionTicket(ctx, hsBodyData, hsBodyLen, hsMsg);
#endif /* HITLS_TLS_HOST_CLIENT */
        case CERTIFICATE:
            return Tls13ParseCertificate(ctx, hsBodyData, hsBodyLen, hsMsg);
        case CERTIFICATE_VERIFY:
            return ParseCertificateVerify(ctx, hsBodyData, hsBodyLen, hsMsg);
        case FINISHED:
            return ParseFinished(ctx, hsBodyData, hsBodyLen, hsMsg);
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case KEY_UPDATE:
            return ParseKeyUpdate(ctx, hsBodyData, hsBodyLen, hsMsg);
#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */
        case HELLO_REQUEST:
            if (hsBodyLen != 0u) {
                return ParseErrorProcess(ctx, HITLS_PARSE_INVALID_MSG_LEN, BINLOG_ID15611,
                    BINGLOG_STR("hello request length is not zero"), ALERT_DECODE_ERROR);
            }
            return HITLS_SUCCESS;
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15605, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "recv unsupport handshake msg type[%d].", hsMsg->type, 0, 0, 0);
    return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
int32_t HS_ParseMsgHeader(TLS_Ctx *ctx, const uint8_t *data, uint32_t len, HS_MsgInfo *hsMsgInfo)
{
    if ((ctx == NULL) || (ctx->method.sendAlert == NULL) || (data == NULL) || (hsMsgInfo == NULL)) {
        return ParseErrorProcess(ctx, HITLS_INTERNAL_EXCEPTION, BINLOG_ID15606,
            BINGLOG_STR("null input parameter"), ALERT_UNKNOWN);
    }

    uint32_t version = GET_VERSION_FROM_CTX(ctx);

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS
        case HITLS_VERSION_TLS12:
        case HITLS_VERSION_TLS13:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#if defined(HITLS_TLS_PROTO_DTLCP11)
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                return DtlsParseHsMsgHeader(ctx, data, len, hsMsgInfo);
            }
#endif
#endif
            return TlsParseHsMsgHeader(ctx, data, len, hsMsgInfo);
#endif /* HITLS_TLS_PROTO_TLS */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            return DtlsParseHsMsgHeader(ctx, data, len, hsMsgInfo);
#endif
        default:
            break;
    }

    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15607, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unsupport msg header version[0x%x].", version, 0, 0, 0);
    return HITLS_PARSE_UNSUPPORT_VERSION;
}

int32_t HS_ParseMsg(TLS_Ctx *ctx, const HS_MsgInfo *hsMsgInfo, HS_Msg *hsMsg)
{
    bool nullInput = (ctx == NULL) || (ctx->method.sendAlert == NULL) || (hsMsgInfo == NULL) ||
                     (hsMsgInfo->rawMsg == NULL) || (hsMsg == NULL);
    if (nullInput == true) {
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

    uint32_t version = GET_VERSION_FROM_CTX(ctx);

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS_BASIC
        case HITLS_VERSION_TLS12:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#if defined(HITLS_TLS_PROTO_DTLCP11)
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                return ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[DTLS_HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
            }
#endif
#endif
            return ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
        case HITLS_VERSION_TLS13:
            return Tls13ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            return ParseHandShakeMsg(ctx, &hsMsgInfo->rawMsg[DTLS_HS_MSG_HEADER_SIZE], hsMsgInfo->length, hsMsg);
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_PARSE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15609, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "unsupport handshake msg version[0x%x].", version, 0, 0, 0);
    return HITLS_PARSE_UNSUPPORT_VERSION;
}

void HS_CleanMsg(HS_Msg *hsMsg)
{
    if (hsMsg == NULL) {
        return;
    }

    switch (hsMsg->type) {
#ifdef HITLS_TLS_HOST_SERVER
        case CLIENT_HELLO:
            return CleanClientHello(&hsMsg->body.clientHello);
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
        case CLIENT_KEY_EXCHANGE:
            return CleanClientKeyExchange(&hsMsg->body.clientKeyExchange);
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case SERVER_HELLO:
            return CleanServerHello(&hsMsg->body.serverHello);
#ifdef HITLS_TLS_PROTO_DTLS12
        case HELLO_VERIFY_REQUEST:
            return CleanHelloVerifyRequest(&hsMsg->body.helloVerifyReq);
#endif
        case CERTIFICATE_REQUEST:
            return CleanCertificateRequest(&hsMsg->body.certificateReq);
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
        case SERVER_KEY_EXCHANGE:
            return CleanServerKeyExchange(&hsMsg->body.serverKeyExchange);
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
        case ENCRYPTED_EXTENSIONS:
            return CleanEncryptedExtensions(&hsMsg->body.encryptedExtensions);
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case NEW_SESSION_TICKET:
            return CleanNewSessionTicket(&hsMsg->body.newSessionTicket);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_HOST_CLIENT */
        case CERTIFICATE:
            return CleanCertificate(&hsMsg->body.certificate);
#if (defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)) || \
    defined(HITLS_TLS_PROTO_TLS13)    
        case CERTIFICATE_VERIFY:
            return CleanCertificateVerify(&hsMsg->body.certificateVerify);
#endif
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
        "clean unsupport handshake msg type[%d].", hsMsg->type, 0, 0, 0);
}
#ifdef HITLS_TLS_FEATURE_CLIENT_HELLO_CB
int32_t HITLS_ClientHelloGetLegacyVersion(HITLS_Ctx *ctx, uint16_t *version)
{
    if (ctx == NULL || version == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->hsCtx == NULL || ctx->hsCtx->hsMsg == NULL || ctx->hsCtx->hsMsg->type != CLIENT_HELLO) {
        return HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL;
    }
    *version = ctx->hsCtx->hsMsg->body.clientHello.version;
    return HITLS_SUCCESS;
}

int32_t HITLS_ClientHelloGetRandom(HITLS_Ctx *ctx, uint8_t **out, uint8_t *outlen)
{
    if (ctx == NULL || out == NULL || outlen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->hsCtx == NULL || ctx->hsCtx->hsMsg == NULL || ctx->hsCtx->hsMsg->type != CLIENT_HELLO) {
        return HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL;
    }
    *out = ctx->hsCtx->hsMsg->body.clientHello.randomValue;
    *outlen = RANDOM_SIZE;
    return HITLS_SUCCESS;
}

int32_t HITLS_ClientHelloGetSessionID(HITLS_Ctx *ctx, uint8_t **out, uint8_t *outlen)
{
    if (ctx == NULL || out == NULL || outlen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->hsCtx == NULL || ctx->hsCtx->hsMsg == NULL || ctx->hsCtx->hsMsg->type != CLIENT_HELLO) {
        return HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL;
    }
    *out = ctx->hsCtx->hsMsg->body.clientHello.sessionId;
    *outlen = ctx->hsCtx->hsMsg->body.clientHello.sessionIdSize;
    
    return HITLS_SUCCESS;
}

int32_t HITLS_ClientHelloGetCiphers(HITLS_Ctx *ctx, uint16_t **out, uint16_t *outlen)
{
    if (ctx == NULL || out == NULL || outlen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->hsCtx == NULL || ctx->hsCtx->hsMsg == NULL || ctx->hsCtx->hsMsg->type != CLIENT_HELLO) {
        return HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL;
    }
    *out = ctx->hsCtx->hsMsg->body.clientHello.cipherSuites;
    *outlen = ctx->hsCtx->hsMsg->body.clientHello.cipherSuitesSize;
    
    return HITLS_SUCCESS;
}

int32_t HITLS_ClientHelloGetExtensionsPresent(HITLS_Ctx *ctx, uint16_t **out, uint8_t *outlen)
{
    if (ctx == NULL || out == NULL || outlen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->hsCtx == NULL || ctx->hsCtx->hsMsg == NULL || ctx->hsCtx->hsMsg->type != CLIENT_HELLO) {
        return HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL;
    }
    uint32_t bufOffset = 0u;
    uint8_t *buf = ctx->hsCtx->hsMsg->body.clientHello.extensionBuff;
    uint32_t bufLen = ctx->hsCtx->hsMsg->body.clientHello.extensionBuffLen;
    uint16_t *extPresent = BSL_SAL_Malloc(ctx->hsCtx->hsMsg->body.clientHello.extensionCount * sizeof(uint16_t));
    if (extPresent == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17355, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc extPresent fail.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret;
    uint32_t extPresentCount = 0;
    while (bufOffset < bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            BSL_SAL_FREE(extPresent);
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;
        extPresent[extPresentCount++] = extMsgType;
        bufOffset += extMsgLen;
    }

    *out = extPresent;
    *outlen = ctx->hsCtx->hsMsg->body.clientHello.extensionCount;
    return HITLS_SUCCESS;
}

int32_t HITLS_ClientHelloGetExtension(HITLS_Ctx *ctx, uint16_t type, uint8_t **out, uint32_t *outlen)
{
    if (ctx == NULL || out == NULL || outlen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->hsCtx == NULL || ctx->hsCtx->hsMsg == NULL || ctx->hsCtx->hsMsg->type != CLIENT_HELLO) {
        return HITLS_CALLBACK_CLIENT_HELLO_INVALID_CALL;
    }
    uint32_t bufOffset = 0u;
    uint8_t *buf = ctx->hsCtx->hsMsg->body.clientHello.extensionBuff;
    uint32_t bufLen = ctx->hsCtx->hsMsg->body.clientHello.extensionBuffLen;
    int32_t ret;
    while (bufOffset < bufLen) {
        uint16_t extMsgType = HS_EX_TYPE_END;
        uint32_t extMsgLen = 0u;
        ret = ParseExHeader(ctx, &buf[bufOffset], bufLen - bufOffset, &extMsgType, &extMsgLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        bufOffset += HS_EX_HEADER_LEN;
        if (extMsgType != type) {
            /* If the extension type is not the one we are looking for, skip it */
            bufOffset += extMsgLen;
            continue;
        }
        *out = &buf[bufOffset];
        *outlen = extMsgLen;
        return HITLS_SUCCESS;
    }
    return HITLS_CALLBACK_CLIENT_HELLO_EXTENSION_NOT_FOUND;
}
#endif /* HITLS_TLS_FEATURE_CLIENT_HELLO_CB */