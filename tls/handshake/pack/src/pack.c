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

#include <stdlib.h>
#include <stdint.h>
#include "hitls_build.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs.h"
#include "pack_msg.h"
#include "alert.h"
#include "pack_common.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t PackHsMsgBody(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    switch (type) {
#ifdef HITLS_TLS_HOST_SERVER
        case SERVER_HELLO:
            ret = PackServerHello(ctx, buf, bufLen, usedLen);
            break;
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        case HELLO_VERIFY_REQUEST:
            ret = PackHelloVerifyRequest(ctx, buf, bufLen, usedLen);
            break;
#endif
        case SERVER_KEY_EXCHANGE:
            ret = PackServerKeyExchange(ctx, buf, bufLen, usedLen);
            break;
        case CERTIFICATE_REQUEST:
            ret = PackCertificateRequest(ctx, buf, bufLen, usedLen);
            break;
        case HELLO_REQUEST:
        case SERVER_HELLO_DONE:
            return HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        case NEW_SESSION_TICKET:
            ret = PackNewSessionTicket(ctx, buf, bufLen, usedLen);
            break;
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#endif /* HITLS_TLS_HOST_SERVER */
#ifdef HITLS_TLS_HOST_CLIENT
        case CLIENT_HELLO:
            ret = PackClientHello(ctx, buf, bufLen, usedLen);
            break;
        case CLIENT_KEY_EXCHANGE:
            ret = PackClientKeyExchange(ctx, buf, bufLen, usedLen);
            break;
        case CERTIFICATE_VERIFY:
            ret = PackCertificateVerify(ctx, buf, bufLen, usedLen);
            break;
#endif /* HITLS_TLS_HOST_CLIENT */
        case CERTIFICATE:
            ret = PackCertificate(ctx, buf, bufLen, usedLen);
            break;
        case FINISHED:
            ret = PackFinished(ctx, buf, bufLen, usedLen);
            break;
        default:
            ret = HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG;
            break;
    }

    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15812, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack handshake[%u] msg error.", type, 0, 0, 0);
    }
    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t PackTls13HsMsgBody(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    switch (type) {
#ifdef HITLS_TLS_HOST_CLIENT
        case CLIENT_HELLO:
            ret = PackClientHello(ctx, buf, bufLen, usedLen);
            break;
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
        case SERVER_HELLO:
            ret = PackServerHello(ctx, buf, bufLen, usedLen);
            break;
        case ENCRYPTED_EXTENSIONS:
            ret = PackEncryptedExtensions(ctx, buf, bufLen, usedLen);
            break;
        case CERTIFICATE_REQUEST:
            ret = Tls13PackCertificateRequest(ctx, buf, bufLen, usedLen);
            break;
        case NEW_SESSION_TICKET:
            ret = Tls13PackNewSessionTicket(ctx, buf, bufLen, usedLen);
            break;
#endif /* HITLS_TLS_HOST_SERVER */
        case CERTIFICATE:
            ret = Tls13PackCertificate(ctx, buf, bufLen, usedLen);
            break;
        case CERTIFICATE_VERIFY:
            ret = PackCertificateVerify(ctx, buf, bufLen, usedLen);
            break;
        case FINISHED:
            ret = PackFinished(ctx, buf, bufLen, usedLen);
            break;
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
        case KEY_UPDATE:
            ret = PackKeyUpdate(ctx, buf, bufLen, usedLen);
            break;
#endif
        default:
            ret = HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG;
            break;
    }

    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15813, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack handshake[%u] msg error.", type, 0, 0, 0);
    }
    return ret;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
int32_t Dtls12PackMsg(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint16_t sequence = 0;
    int32_t ret = HITLS_SUCCESS;
    uint32_t len = 0;

    ret = PackHsMsgBody(ctx, type, &buf[DTLS_HS_MSG_HEADER_SIZE], bufLen - DTLS_HS_MSG_HEADER_SIZE, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    sequence = ctx->hsCtx->nextSendSeq;
    PackDtlsMsgHeader(type, sequence, len, buf);

    *usedLen = len + DTLS_HS_MSG_HEADER_SIZE;

    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_PROTO_TLS_BASIC
int32_t Tls12PackMsg(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t len = 0;

    if (type > HS_MSG_TYPE_END) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16943, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "type err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG);
        return HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG;
    }
    ret = PackHsMsgBody(ctx, type, &buf[HS_MSG_HEADER_SIZE], bufLen - HS_MSG_HEADER_SIZE, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    buf[0] = (uint8_t)type & 0xffu;          /* Fill handshake message type */
    BSL_Uint24ToByte(len, &buf[1]); /* Fill handshake message body length */

    *usedLen = len + HS_MSG_HEADER_SIZE;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13PackMsg(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t len = 0;
    int32_t enumBorder = HS_MSG_TYPE_END;
    if ((int32_t)type > enumBorder) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16944, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "type err", 0, 0, 0, 0);
        return HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG;
    }
    ret = PackTls13HsMsgBody(ctx, type, &buf[HS_MSG_HEADER_SIZE], bufLen - HS_MSG_HEADER_SIZE, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    buf[0] = (uint8_t)type & 0xffu;          /* Fill handshake message type */
    BSL_Uint24ToByte(len, &buf[1]); /* Fill handshake message body length */

    *usedLen = len + HS_MSG_HEADER_SIZE;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
int32_t HS_PackMsg(TLS_Ctx *ctx, HS_MsgType type, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    if ((ctx == NULL) || (buf == NULL) || (usedLen == NULL) || (bufLen == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_INTERNAL_EXCEPTION, BINLOG_ID15814, "ctx is null");
    }

    uint32_t version = HS_GetVersion(ctx);
    int32_t ret = HITLS_SUCCESS;

    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS_BASIC
        case HITLS_VERSION_TLS12:
#ifdef HITLS_TLS_PROTO_TLCP11
        case HITLS_VERSION_TLCP_DTLCP11:
#if defined(HITLS_TLS_PROTO_DTLCP11)
            if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
                ret = Dtls12PackMsg(ctx, type, buf, bufLen, usedLen);
                break;
            }
#endif
#endif
            ret = Tls12PackMsg(ctx, type, buf, bufLen, usedLen);
            break;
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
#ifdef HITLS_TLS_PROTO_TLS13
        case HITLS_VERSION_TLS13:
            ret = Tls13PackMsg(ctx, type, buf, bufLen, usedLen);
            break;
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_PROTO_DTLS12
        case HITLS_VERSION_DTLS12:
            ret = Dtls12PackMsg(ctx, type, buf, bufLen, usedLen);
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSUPPORT_VERSION);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15815, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack handshake msg error, unsupport version[0x%x].", version, 0, 0, 0);
            return HITLS_PACK_UNSUPPORT_VERSION;
    }

    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
    }
    return ret;
}
