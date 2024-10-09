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


#define KEY_UPDATE_HS_MSG_MAX_LEN 16u   /* maximum length of key update message */

static int32_t ProcessSendHandshakeMsg(TLS_Ctx *ctx)
{
#ifndef HITLS_NO_DTLS12
    uint32_t version = HS_GetVersion(ctx);
#endif
    switch (ctx->hsCtx->state) {
        case TRY_SEND_HELLO_REQUEST:
            return ServerSendHelloRequestProcess(ctx);
        case TRY_SEND_CLIENT_HELLO:
            return ClientSendClientHelloProcess(ctx);
        case TRY_SEND_SERVER_HELLO:
            return ServerSendServerHelloProcess(ctx);
        case TRY_SEND_CERTIFICATE:
            return SendCertificateProcess(ctx);
        case TRY_SEND_SERVER_KEY_EXCHANGE:
            return ServerSendServerKeyExchangeProcess(ctx);
        case TRY_SEND_CERTIFICATE_REQUEST:
            return ServerSendCertRequestProcess(ctx);
        case TRY_SEND_SERVER_HELLO_DONE:
            return ServerSendServerHelloDoneProcess(ctx);
        case TRY_SEND_CLIENT_KEY_EXCHANGE:
            return ClientSendClientKeyExchangeProcess(ctx);
        case TRY_SEND_CERTIFICATE_VERIFY:
            return ClientSendCertVerifyProcess(ctx);
        case TRY_SEND_CHANGE_CIPHER_SPEC:
            return SendChangeCipherSpecProcess(ctx);
        case TRY_SEND_NEW_SESSION_TICKET:
            return SendNewSessionTicketProcess(ctx);
        case TRY_SEND_FINISH:
            if (ctx->isClient) {
#ifndef HITLS_NO_DTLS12
                if (version == HITLS_VERSION_DTLS12) {
                    return DtlsClientSendFinishedProcess(ctx);
                }
#endif
                return Tls12ClientSendFinishedProcess(ctx);
            } else {
#ifndef HITLS_NO_DTLS12
                if (version == HITLS_VERSION_DTLS12) {
                    return DtlsServerSendFinishedProcess(ctx);
                }
#endif
                return Tls12ServerSendFinishedProcess(ctx);
            }
        default:
            break;
    }
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}

int32_t Tls13SendChangeCipherSpecProcess(TLS_Ctx *ctx)
{
    int32_t ret;

    /** Sending message with changed cipher suites */
    ret = ctx->method.sendCCS(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HS_ChangeState(ctx, ctx->hsCtx->ccsNextState);
}

static int32_t Tls13ProcessSendHandshakeMsg(TLS_Ctx *ctx)
{
    switch (ctx->hsCtx->state) {
        case TRY_SEND_CLIENT_HELLO:
            return Tls13ClientSendClientHelloProcess(ctx);
        case TRY_SEND_HELLO_RETRY_REQUEST:
            return Tls13ServerSendHelloRetryRequestProcess(ctx);
        case TRY_SEND_SERVER_HELLO:
            return Tls13ServerSendServerHelloProcess(ctx);
        case TRY_SEND_ENCRYPTED_EXTENSIONS:
            return Tls13ServerSendEncryptedExtensionsProcess(ctx);
        case TRY_SEND_CERTIFICATE_REQUEST:
            return Tls13ServerSendCertRequestProcess(ctx);
        case TRY_SEND_CERTIFICATE:
            if (ctx->isClient) {
                return Tls13ClientSendCertificateProcess(ctx);
            } else {
                return Tls13ServerSendCertificateProcess(ctx);
            }
        case TRY_SEND_CERTIFICATE_VERIFY:
            return Tls13SendCertVerifyProcess(ctx);
        case TRY_SEND_FINISH:
            if (ctx->isClient) {
                return Tls13ClientSendFinishedProcess(ctx);
            } else {
                return Tls13ServerSendFinishedProcess(ctx);
            }
        case TRY_SEND_NEW_SESSION_TICKET:
            return Tls13SendNewSessionTicketProcess(ctx);

        case TRY_SEND_CHANGE_CIPHER_SPEC:
            return Tls13SendChangeCipherSpecProcess(ctx);
        default:
            break;
    }
    return HITLS_MSG_HANDLE_STATE_ILLEGAL;
}

int32_t HS_SendMsgProcess(TLS_Ctx *ctx)
{
    uint32_t version = HS_GetVersion(ctx);

    switch (version) {
        case HITLS_VERSION_TLS12:
#ifndef HITLS_NO_TLCP11
        case HITLS_VERSION_TLCP11:
#endif
            return ProcessSendHandshakeMsg(ctx);
        case HITLS_VERSION_TLS13:
            return Tls13ProcessSendHandshakeMsg(ctx);
#ifndef HITLS_NO_DTLS12
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

int32_t HS_HandleSendKeyUpdate(TLS_Ctx *ctx)
{
    uint8_t msgBuf[KEY_UPDATE_HS_MSG_MAX_LEN];
    uint32_t msgLen = 0;

    int32_t ret = HS_PackMsg(ctx, KEY_UPDATE, msgBuf, KEY_UPDATE_HS_MSG_MAX_LEN, &msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15791, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack tls1.3 key update msg fail.", 0, 0, 0, 0);
        return ret;
    }

    ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, msgBuf, msgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15792, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "send tls1.3 key update msg success.", 0, 0, 0, 0);

    /* After the key update message is sent, the app traffic secret used by the local is updated and activated. */
    ret = HS_TLS13UpdateTrafficSecret(ctx, true);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15793, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.3 out key update fail", 0, 0, 0, 0);
        return ret;
    }
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15794, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.3 send key update success.", 0, 0, 0, 0);

    return HITLS_SUCCESS;
}
