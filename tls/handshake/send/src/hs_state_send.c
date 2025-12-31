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
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs.h"
#include "hs_common.h"
#include "send_process.h"
#include "hs_kx.h"
#include "pack.h"
#include "bsl_uio.h"
#include "bsl_sal.h"

#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
static int32_t Tls13SendKeyUpdateProcess(TLS_Ctx *ctx)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = ctx->hsCtx;

    if (hsCtx->msgLen == 0) {
        ret = HS_PackMsg(ctx, KEY_UPDATE);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15791, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack tls1.3 key update msg fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    ret = HS_SendMsg(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15792, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 key update msg success.", 0, 0, 0, 0);
    /* After the key update message is sent, the local application traffic key is updated and activated. */
    ret = HS_TLS13UpdateTrafficSecret(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15793, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.3 out key update fail", 0, 0, 0, 0);
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15794, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 send key update success.", 0, 0, 0, 0);

    ctx->isKeyUpdateRequest = false;
    ctx->keyUpdateType = HITLS_KEY_UPDATE_REQ_END;
    return HS_ChangeState(ctx, TLS_CONNECTED);
}
#endif /* HITLS_TLS_FEATURE_KEY_UPDATE */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t SendFinishedProcess(TLS_Ctx *ctx)
{
#ifdef HITLS_TLS_HOST_CLIENT
    if (ctx->isClient) {
#ifdef HITLS_TLS_PROTO_DTLS12
        if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
            return DtlsClientSendFinishedProcess(ctx);
        }
#endif
#ifdef HITLS_TLS_PROTO_TLS_BASIC
        return Tls12ClientSendFinishedProcess(ctx);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
    }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        return DtlsServerSendFinishedProcess(ctx);
    }
#endif
#ifdef HITLS_TLS_PROTO_TLS_BASIC
    return Tls12ServerSendFinishedProcess(ctx);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#endif /* HITLS_TLS_HOST_SERVER */

    return HITLS_INTERNAL_EXCEPTION;
}
static int32_t ProcessSendHandshakeMsg(TLS_Ctx *ctx)
{
    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_SERVER
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
        case TRY_SEND_HELLO_REQUEST:
            return ServerSendHelloRequestProcess(ctx);
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        case TRY_SEND_HELLO_VERIFY_REQUEST:
            return DtlsServerSendHelloVerifyRequestProcess(ctx);
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */
        case TRY_SEND_SERVER_HELLO:
            return ServerSendServerHelloProcess(ctx);
        case TRY_SEND_SERVER_KEY_EXCHANGE:
            return ServerSendServerKeyExchangeProcess(ctx);
        case TRY_SEND_CERTIFICATE_REQUEST:
            return ServerSendCertRequestProcess(ctx);
        case TRY_SEND_SERVER_HELLO_DONE:
            return ServerSendServerHelloDoneProcess(ctx);
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case TRY_SEND_NEW_SESSION_TICKET:
            return SendNewSessionTicketProcess(ctx);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_SEND_CLIENT_HELLO:
            return ClientSendClientHelloProcess(ctx);
        case TRY_SEND_CLIENT_KEY_EXCHANGE:
            return ClientSendClientKeyExchangeProcess(ctx);
        case TRY_SEND_CERTIFICATE_VERIFY:
            return ClientSendCertVerifyProcess(ctx);
#endif /* HITLS_TLS_HOST_CLIENT */
        case TRY_SEND_CERTIFICATE:
            return SendCertificateProcess(ctx);
        case TRY_SEND_CHANGE_CIPHER_SPEC:
            return SendChangeCipherSpecProcess(ctx);
        case TRY_SEND_FINISH:
            return SendFinishedProcess(ctx);
        default:
            break;
    }
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID17100, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state err: should send msg, but current state is %s.", HS_GetStateStr(ctx->hsCtx->state));
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13SendChangeCipherSpecProcess(TLS_Ctx *ctx)
{
    int32_t ret;

    /* Sending message with changed cipher suites */
    ret = ctx->method.sendCCS(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HS_ChangeState(ctx, ctx->hsCtx->ccsNextState);
}

static int32_t Tls13ProcessSendHandshakeMsg(TLS_Ctx *ctx)
{
    switch (ctx->hsCtx->state) {
#ifdef HITLS_TLS_HOST_CLIENT
        case TRY_SEND_CLIENT_HELLO:
            return Tls13ClientSendClientHelloProcess(ctx);
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
        case TRY_SEND_HELLO_RETRY_REQUEST:
            return Tls13ServerSendHelloRetryRequestProcess(ctx);
        case TRY_SEND_SERVER_HELLO:
            return Tls13ServerSendServerHelloProcess(ctx);
        case TRY_SEND_ENCRYPTED_EXTENSIONS:
            return Tls13ServerSendEncryptedExtensionsProcess(ctx);
        case TRY_SEND_CERTIFICATE_REQUEST:
            return Tls13ServerSendCertRequestProcess(ctx);
        case TRY_SEND_NEW_SESSION_TICKET:
            return Tls13SendNewSessionTicketProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
        case TRY_SEND_CERTIFICATE:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
                return Tls13ClientSendCertificateProcess(ctx);
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
            return Tls13ServerSendCertificateProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
        case TRY_SEND_CERTIFICATE_VERIFY:
            return Tls13SendCertVerifyProcess(ctx);
        case TRY_SEND_FINISH:
#ifdef HITLS_TLS_HOST_CLIENT
            if (ctx->isClient) {
                return Tls13ClientSendFinishedProcess(ctx);
            }
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
            return Tls13ServerSendFinishedProcess(ctx);
#endif /* HITLS_TLS_HOST_SERVER */
        case TRY_SEND_CHANGE_CIPHER_SPEC:
            return Tls13SendChangeCipherSpecProcess(ctx);
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case TRY_SEND_KEY_UPDATE:
            return Tls13SendKeyUpdateProcess(ctx);
#endif
        default:
            break;
    }
    return RETURN_ERROR_NUMBER_PROCESS(HITLS_MSG_HANDLE_STATE_ILLEGAL, BINLOG_ID17101, "Handshake state error");
}
#endif /* HITLS_TLS_PROTO_TLS13 */
int32_t HS_SendMsgProcess(TLS_Ctx *ctx)
{
    uint32_t version = GET_VERSION_FROM_CTX(ctx);

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS_BASIC
        case HITLS_VERSION_TLS12:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#endif
            return ProcessSendHandshakeMsg(ctx);
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
        case HITLS_VERSION_TLS13:
            return Tls13ProcessSendHandshakeMsg(ctx);
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            return ProcessSendHandshakeMsg(ctx);
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15790, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "Handshake state send error: unsupport TLS version.", 0, 0, 0, 0);
    return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
}
