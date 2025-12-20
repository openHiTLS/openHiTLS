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
#ifdef HITLS_TLS_HOST_CLIENT
#include <stdint.h>
#include <stdbool.h>
#include "bsl_sal.h"
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_sni.h"
#include "hitls_security.h"
#include "tls.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "hs.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "hs_common.h"
#include "hs_extensions.h"
#include "hs_msg.h"
#include "record.h"
#include "transcript_hash.h"
#include "session_mgr.h"
#include "alpn.h"
#include "alert.h"
#include "hs_kx.h"
#include "config_type.h"
#include "config_check.h"

typedef int32_t (*CheckExtFunc)(TLS_Ctx *ctx, const ServerHelloMsg *serverHello);

static int32_t ClientCheckPointFormats(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.havePointFormats) && serverHello->havePointFormats) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15255, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get point formats.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* The key exchange algorithm is not ECDHE */
    if ((ctx->negotiatedInfo.cipherSuiteInfo.authAlg != HITLS_AUTH_ECDSA) &&
        (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg != HITLS_KEY_EXCH_ECDHE) &&
        (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg != HITLS_KEY_EXCH_ECDH) &&
        (ctx->negotiatedInfo.cipherSuiteInfo.kxAlg != HITLS_KEY_EXCH_ECDHE_PSK)) {
        return HITLS_SUCCESS;
    }

    if (!serverHello->havePointFormats) {
        return HITLS_SUCCESS;
    }

    for (uint8_t i = 0u; i < serverHello->pointFormatsSize; i++) {
        /* The point format list contains uncompressed (0) */
        if (serverHello->pointFormats[i] == 0u) {
            return HITLS_SUCCESS;
        }
    }

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15256, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "the point format extension in server hello is incorrect.", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_POINT_FORMAT);
    return HITLS_MSG_HANDLE_UNSUPPORT_POINT_FORMAT;
}
#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t ClientCheckNegotiatedAlpnOfServerHello(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    return ClientCheckNegotiatedAlpn(
        ctx, serverHello->haveSelectedAlpn, serverHello->alpnSelected, serverHello->alpnSelectedSize);
}
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_FEATURE_SNI
static int32_t ClientCheckServerName(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((ctx->hsCtx->extFlag.haveServerName == false) && (serverHello->haveServerName == true)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15263, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send server_name but get extended server_name .", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* Received null server_name extension for server hello message */
    if ((ctx->hsCtx->extFlag.haveServerName == true) && (serverHello->haveServerName == true)) {
        /* Not in session resumption, and the client has previously sent the server_name extension */
        if (ctx->session == NULL && ctx->config.tlsConfig.serverName != NULL &&
            ctx->config.tlsConfig.serverNameSize > 0) {
            /* The server negotiates the extension of the server_name of the client successfully */
            ctx->negotiatedInfo.isSniStateOK = true;
            ctx->negotiatedInfo.serverNameSize = ctx->config.tlsConfig.serverNameSize;

            BSL_SAL_FREE(ctx->negotiatedInfo.serverName);
            ctx->negotiatedInfo.serverName =
                (uint8_t *)BSL_SAL_Dump(ctx->config.tlsConfig.serverName,
                    ctx->negotiatedInfo.serverNameSize * sizeof(uint8_t));
            if (ctx->negotiatedInfo.serverName == NULL) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17082, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "Dump fail", 0, 0, 0, 0);
                BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
                return HITLS_MEMCPY_FAIL;
            }
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SNI */
static int32_t ClientCheckExtendedMasterSecret(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.haveExtendedMasterSecret) && serverHello->haveExtendedMasterSecret) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15264, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get extended master secret.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }
    /* tls1.3 Ignore Extended Master Secret */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 || (ctx->negotiatedInfo.version < HITLS_VERSION_TLS12 &&
        ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11)) {
        ctx->negotiatedInfo.isExtendedMasterSecret = false;
        return HITLS_SUCCESS;
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    /* rfc 7627 5.3 Client and Server Behavior: Abbreviated Handshake
        If a client receives a ServerHello that accepts an abbreviated
    handshake, it behaves as follows:
        o If the original session did not use the "extended_master_secret"
        extension but the new ServerHello contains the extension, the
        client MUST abort the handshake.
        o If the original session used the extension but the new ServerHello
        does not contain the extension, the client MUST abort the
        handshake.  */
    if (ctx->negotiatedInfo.isResume && ctx->session != NULL) {
        bool haveExtMasterSecret;
        HITLS_SESS_GetHaveExtMasterSecret(ctx->session, &haveExtMasterSecret);
        if (serverHello->haveExtendedMasterSecret != haveExtMasterSecret) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17083, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ExtendedMasterSecret err", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
            return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
        }
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    if (ctx->config.tlsConfig.isSupportExtendMasterSecret && !serverHello->haveExtendedMasterSecret) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ExtendedMasterSecret err", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
    }
    /* Configure the negotiation content to support the extended master secret */
    ctx->negotiatedInfo.isExtendedMasterSecret = (ctx->hsCtx->extFlag.haveExtendedMasterSecret &&
        serverHello->haveExtendedMasterSecret);
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t ClientCheckKeyShare(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.haveKeyShare) && serverHello->haveKeyShare) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15265, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get key share.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    return HITLS_SUCCESS;
}

static int32_t ClientCheckPreShareKey(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.havePreShareKey) && serverHello->haveSelectedIdentity) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15266, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get pre share key.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    return HITLS_SUCCESS;
}

static int32_t ClientCheckSupportedVersions(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.haveSupportedVers) && serverHello->haveSupportedVersion) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16133, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get supported versions.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t ClientCheckRenegoInfoDuringFirstHandshake(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* If the peer does not support the renegotiation, return */
    if (!serverHello->haveSecRenego) {
        /* Renegotiate info is not checked in tls13 protocol. */
        if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
            return HITLS_SUCCESS;
        }
        if (!ctx->config.tlsConfig.allowLegacyRenegotiate) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15899, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "Legacy Renegotiate is not allowed.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
            return HITLS_MSG_HANDLE_RENEGOTIATION_FAIL;
        }
        return HITLS_SUCCESS;
    }

    /* For the first handshake, if the security renegotiation information is not empty, a failure message is returned.
     */
    if (serverHello->secRenegoInfoSize != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15958, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "secRenegoInfoSize should be 0 in client initial handhsake.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
        return HITLS_MSG_HANDLE_RENEGOTIATION_FAIL;
    }

    /* Configure the security renegotiation function */
    ctx->negotiatedInfo.isSecureRenegotiation = true;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static int32_t ClientCheckRenegoInfoDuringRenegotiation(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* Verify the security renegotiation information */
    const uint8_t *clientData = ctx->negotiatedInfo.clientVerifyData;
    uint32_t clientDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
    const uint8_t *serverData = ctx->negotiatedInfo.serverVerifyData;
    uint32_t serverDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
    if (clientData == NULL || serverData == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17085, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "intput null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    if (serverHello->secRenegoInfoSize != (clientDataSize + serverDataSize)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15900, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "secRenegoInfoSize(%u) error, expect %u.", serverHello->secRenegoInfoSize,
            (clientDataSize + serverDataSize), 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
        return HITLS_MSG_HANDLE_RENEGOTIATION_FAIL;
    }
    if (memcmp(serverHello->secRenegoInfo, clientData, clientDataSize) != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15901, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check client secRenegoInfo verify data failed during renegotiation.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
        return HITLS_MSG_HANDLE_RENEGOTIATION_FAIL;
    }
    if (memcmp(&serverHello->secRenegoInfo[clientDataSize], serverData, serverDataSize) != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15902, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check server secRenegoInfo verify data failed during renegotiation.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
        return HITLS_MSG_HANDLE_RENEGOTIATION_FAIL;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
static int32_t ClientCheckAndProcessRenegoInfo(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* Not in the renegotiation state */
    if (!ctx->negotiatedInfo.isRenegotiation) {
        return ClientCheckRenegoInfoDuringFirstHandshake(ctx, serverHello);
    }
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    /* Renegotiation state */
    return ClientCheckRenegoInfoDuringRenegotiation(ctx, serverHello);
#else
    return HITLS_SUCCESS;
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
static int32_t ClientCheckTicketExternsion(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.haveTicket) && serverHello->haveTicket) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15972, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get ticket externsion.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 && serverHello->haveTicket) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15912, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TLS1.3 client get server hello ticket externsion.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* Set whether to support ticket extension */
    ctx->negotiatedInfo.isTicket = serverHello->haveTicket;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_ETM
static int32_t ClientCheckEncryptThenMac(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if (!ctx->hsCtx->extFlag.haveEncryptThenMac && serverHello->haveEncryptThenMac) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15920, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get encrypt then mac.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* The user does not support the EncryptThenMac extension, but receives the EncryptThenMac extension from the server
     */
    if (!ctx->config.tlsConfig.isEncryptThenMac && serverHello->haveEncryptThenMac) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15931, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client do not support encrypt then mac.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    /* During renegotiation, EncryptThenMac cannot be converted to MacThenEncrypt */
    if (ctx->negotiatedInfo.isRenegotiation && ctx->negotiatedInfo.isEncryptThenMac &&
        !serverHello->haveEncryptThenMac) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15934, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "regotiation should not change encrypt then mac to mac then encrypt.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ENCRYPT_THEN_MAC_ERR);
        return HITLS_MSG_HANDLE_ENCRYPT_THEN_MAC_ERR;
    }

    /* This extension does not need to be negotiated for tls1.3 */
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        return HITLS_SUCCESS;
    }

    /* Set the negotiated EncryptThenMac */
    if (serverHello->haveEncryptThenMac) {
        ctx->negotiatedInfo.isEncryptThenMac = true;
    } else {
        ctx->negotiatedInfo.isEncryptThenMac = false;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ETM */

static int32_t ClientCheckExtensionsFlag(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    static const CheckExtFunc extInfoList[] = {
        ClientCheckPointFormats,
#ifdef HITLS_TLS_FEATURE_SNI
        ClientCheckServerName,
#endif /* HITLS_TLS_FEATURE_SNI */
        ClientCheckExtendedMasterSecret,
#ifdef HITLS_TLS_FEATURE_ALPN
        ClientCheckNegotiatedAlpnOfServerHello,
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_PROTO_TLS13
        ClientCheckKeyShare,
        ClientCheckPreShareKey,
        ClientCheckSupportedVersions,
#endif /* HITLS_TLS_PROTO_TLS13 */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
        ClientCheckAndProcessRenegoInfo,
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        ClientCheckTicketExternsion,
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_ETM
        ClientCheckEncryptThenMac,
#endif /* HITLS_TLS_FEATURE_ETM */
    };

    int32_t ret;
    for (uint32_t i = 0; i < sizeof(extInfoList) / sizeof(extInfoList[0]); i++) {
        ret = extInfoList[i](ctx, serverHello);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

static bool IsCipherSuiteSupport(const TLS_Ctx *ctx, uint16_t cipherSuite)
{
    if (!IsCipherSuiteAllowed(ctx, cipherSuite, true)) {
        return false;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        for (uint32_t index = 0; index < ctx->config.tlsConfig.tls13cipherSuitesSize; index++) {
            if (cipherSuite == ctx->config.tlsConfig.tls13CipherSuites[index]) {
                return true;
            }
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    for (uint32_t index = 0; index < ctx->config.tlsConfig.cipherSuitesSize; index++) {
        if (cipherSuite == ctx->config.tlsConfig.cipherSuites[index]) {
            return true;
        }
    }
    return false;
}

static int32_t ClientCheckCipherSuite(TLS_Ctx *ctx, const ServerHelloMsg *serverHello, bool isHrr)
{
    int32_t ret = HITLS_SUCCESS;
    (void)isHrr;
    if (!IsCipherSuiteSupport(ctx, serverHello->cipherSuite)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15269, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "no supported cipher suites found.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
        return HITLS_MSG_HANDLE_CIPHER_SUITE_ERR;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    /* In TLS1.3, if the hello retry request message is received, ensure that the cipherSuite of the server hello
     * message is the same as the cipherSuite */
    if (!isHrr && ctx->hsCtx->haveHrr) {
        if (serverHello->cipherSuite != ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15270, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "cipherSuite in server hello (0x%02x) is defferent from hello retry request (0x%02x).",
                serverHello->cipherSuite, ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE);
            return HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE;
        }
        return HITLS_SUCCESS;
    }
#endif /* HITLS_TLS_PROTO_TLS13 */

    ret = CFG_GetCipherSuiteInfo(serverHello->cipherSuite, &ctx->negotiatedInfo.cipherSuiteInfo);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15271, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get cipher suite information fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_SECURITY
    /* Check the security of the cipher suite */
    ret = SECURITY_SslCheck((HITLS_Ctx *)ctx, HITLS_SECURITY_SECOP_CIPHER_SHARED, 0, 0,
        (void *)&ctx->negotiatedInfo.cipherSuiteInfo);
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17087, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SslCheck fail, ret %d", ret, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSECURE_CIPHER_SUITE);
        return HITLS_MSG_HANDLE_UNSECURE_CIPHER_SUITE;
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    /* Sets the key negotiation algorithm. */
    ctx->hsCtx->kxCtx->keyExchAlgo = ctx->negotiatedInfo.cipherSuiteInfo.kxAlg;

    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15272, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "ClientCheckCipherSuite: negotiated ciphersuite is [%s].",
        ctx->negotiatedInfo.cipherSuiteInfo.name);
    return HITLS_SUCCESS;
}

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t ClientCheckVersion(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    int32_t ret = HITLS_SUCCESS;
    (void)ret;
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    ret = CheckRenegotiatedVersion(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return RETURN_ALERT_PROCESS(ctx, ret, BINLOG_ID15072,
            "The client renegotiation version is inconsistent with the initial one", ALERT_PROTOCOL_VERSION);
    }
#endif
    uint16_t clientMinVersion = ctx->config.tlsConfig.minVersion;
    uint16_t clientMaxVersion = ctx->config.tlsConfig.maxVersion;
    uint16_t serverVersion = serverHello->version;

    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        if ((serverVersion > clientMinVersion) || (serverVersion < clientMaxVersion)) {
            /* The DTLS version selected by the server is too early and the negotiation cannot be continued */
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15267, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client support version is from %02x to %02x, server selected unsupported version %02x.",
                clientMinVersion, clientMaxVersion, serverVersion, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
        }
    } else {
        if ((serverVersion < clientMinVersion) || (serverVersion > clientMaxVersion)) {
            /* The TLS version selected by the server is too early and cannot be negotiated */
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15268, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client support version is from %02x to %02x, server selected unsupported version %02x.",
                clientMinVersion, clientMaxVersion, serverVersion, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
        }
    }
#ifdef HITLS_TLS_FEATURE_SECURITY
    ret = SECURITY_SslCheck((HITLS_Ctx *)ctx, HITLS_SECURITY_SECOP_VERSION, 0, serverHello->version, NULL);
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17088, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SslCheck fail, ret %d", ret, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSECURE_VERSION);
        return HITLS_MSG_HANDLE_UNSECURE_VERSION;
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    ctx->negotiatedInfo.version = serverVersion;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SESSION
static int32_t ClientCheckResumeServerHello(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    uint16_t version = 0;
    uint16_t cipherSuite = 0;
    bool haveExtMasterSecret = false;

    HITLS_SESS_GetProtocolVersion(ctx->session, &version);
    HITLS_SESS_GetCipherSuite(ctx->session, &cipherSuite);
    HITLS_SESS_GetHaveExtMasterSecret(ctx->session, &haveExtMasterSecret);

    /* Check the version information */
    if (serverHello->version != version) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15273, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the version of resume server hello is different from the pre connect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_VERSION);
        return HITLS_MSG_HANDLE_ILLEGAL_VERSION;
    }

    /* Check the cipher suite information */
    if (serverHello->cipherSuite != cipherSuite) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15274, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the cipher suite of resume server hello is different from the pre connect.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE);
        return HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE;
    }

    /* Check the extended master secret information */
    if (serverHello->haveExtendedMasterSecret != haveExtMasterSecret) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15275, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "session resume error:can not downgrade from extended master secret.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_EXTRENED_MASTER_SECRET);
        return HITLS_MSG_HANDLE_ILLEGAL_EXTRENED_MASTER_SECRET;
    }

    return HITLS_SUCCESS;
}

static bool SessionIdCmp(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    if ((hsCtx->sessionIdSize == 0u) || (serverHello->sessionIdSize == 0u)) {
        return false;
    }

    if (hsCtx->sessionIdSize != serverHello->sessionIdSize) {
        return false;
    }

    if (memcmp(hsCtx->sessionId, serverHello->sessionId, hsCtx->sessionIdSize) != 0) {
        return false;
    }

    return true;
}

static int32_t ClientCopySessionId(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    int32_t ret = HITLS_SUCCESS;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;

    BSL_SAL_FREE(hsCtx->sessionId);

    hsCtx->sessionId = (uint8_t *)BSL_SAL_Calloc(1u, HITLS_SESSION_ID_MAX_SIZE);
    if (hsCtx->sessionId == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15276, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "session Id malloc fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    ret = memcpy_s(hsCtx->sessionId, HITLS_SESSION_ID_MAX_SIZE, serverHello->sessionId, serverHello->sessionIdSize);
    if (ret != EOK) {
        BSL_SAL_FREE(hsCtx->sessionId);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15277, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "session Id memcpy fail.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    hsCtx->sessionIdSize = serverHello->sessionIdSize;
    return HITLS_SUCCESS;
}

static int32_t ClientCheckIfResumeFromSession(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    bool isResume = false;

    ctx->negotiatedInfo.isResume = false;

    if (ctx->session == NULL || serverHello->sessionIdSize == 0u) {
        return HITLS_SUCCESS;
    }

    isResume = SessionIdCmp(ctx, serverHello);
    if (isResume == true) {
        /* Resume the session */
        ctx->negotiatedInfo.isResume = true;
        /* Check whether the version number, cipher suite, and master key extension match */
        return ClientCheckResumeServerHello(ctx, serverHello);
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION */

static int32_t ClientCheckServerHello(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    int32_t ret = ClientCheckVersion(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = memcpy_s(ctx->hsCtx->serverRandom, HS_RANDOM_SIZE, serverHello->randomValue, HS_RANDOM_SIZE);
    if (ret != EOK) {
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    /* Check the session resumption. Check whether the session ID, version number, cipher suite, and master key
     * extension match */
    ret = ClientCheckIfResumeFromSession(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Save the session ID for complete handshake */
    if (ctx->negotiatedInfo.isResume == false && serverHello->sessionIdSize > 0) {
        ret = ClientCopySessionId(ctx, serverHello);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    ret = ClientCheckCipherSuite(ctx, serverHello, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_CheckReceivedExtension(ctx, SERVER_HELLO, serverHello->extensionTypeMask,
        HS_EX_TYPE_TLS1_2_ALLOWED_OF_SERVER_HELLO);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ClientCheckExtensionsFlag(ctx, serverHello);
}
// The client processes the Server Hello message
int32_t ClientRecvServerHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    const ServerHelloMsg *serverHello = &msg->body.serverHello;

    int32_t ret = ClientCheckServerHello(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = VERIFY_SetHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        ctx->hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID17089, "VERIFY_SetHash fail");
    }
#ifdef HITLS_TLS_FEATURE_SESSION
    if (ctx->negotiatedInfo.isResume == true) {
        ret = HS_ResumeKeyEstablish(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (ctx->negotiatedInfo.isTicket) {
            return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
        }
        /* Calculate the 'server verify data' for verifying the 'finished' message of the server. */
        ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            (void)memset_s(ctx->hsCtx->masterKey, sizeof(ctx->hsCtx->masterKey), 0, sizeof(ctx->hsCtx->masterKey));
            return RETURN_ALERT_PROCESS(ctx, ret, BINLOG_ID15278,
                "client Calculate server finished data error", ALERT_INTERNAL_ERROR);
        }
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }
#endif /* HITLS_TLS_FEATURE_SESSION */
    /* If the server rejects the session resume request, the system clears the ccs that may be received in disorder */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);

    /* Update the state machine. */
    /* If the PSK, DHE_PSK, ECDHE_PSK, or ANON_DH key negotiation is used, skip TRY_RECV_CERTIFICATIONATE */
#ifdef HITLS_TLS_FEATURE_PSK
    if (!IsNeedCertPrepare(&ctx->negotiatedInfo.cipherSuiteInfo)) {
        return HS_ChangeState(ctx, TRY_RECV_SERVER_KEY_EXCHANGE);
    }
#endif /* HITLS_TLS_FEATURE_PSK */
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t Tls13ClientCheckHelloRetryRequest(TLS_Ctx *ctx, const ServerHelloMsg *helloRetryRequest)
{
    /* If the second Hello Retry Request message is received over the same link, an alert message needs to be sent */
    if (ctx->hsCtx->haveHrr) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15279, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "duplicate hello retry request.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_DUPLICATE_HELLO_RETYR_REQUEST);
        return HITLS_MSG_HANDLE_DUPLICATE_HELLO_RETYR_REQUEST;
    }

    ctx->hsCtx->haveHrr = true; /* Update state: The hello retry request has been received */

    /* The supportedVersion is a mandatory extension */
    if (helloRetryRequest->haveSupportedVersion == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15280, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "missing supported version extension in server hello or hello retry request.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_MISSING_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_MISSING_EXTENSION);
        return HITLS_MSG_HANDLE_MISSING_EXTENSION;
    }

    /* If the hello retry request does not modify the client hello, an alert message is sent */
    if ((helloRetryRequest->haveCookie == false) &&
        (helloRetryRequest->haveKeyShare == false)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15281, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the hello retry reques would not result in any change in the client hello.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_MISSING_EXTENSION);
        return HITLS_MSG_HANDLE_MISSING_EXTENSION;
    }

    return HITLS_SUCCESS;
}

static int32_t Tls13ClientCheckSessionId(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* The legacy_session_id_echo field must be the same as the sent field */
    if (ctx->hsCtx->sessionIdSize != serverHello->sessionIdSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17090, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "sessionIdSize err", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID;
    }
    if (serverHello->sessionIdSize != 0) {
        if (memcmp(ctx->hsCtx->sessionId, serverHello->sessionId, serverHello->sessionIdSize) != 0) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17091, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "sessionId err", 0, 0, 0, 0);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
            return HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t Tls13ClientCheckServerHello(TLS_Ctx *ctx, const ServerHelloMsg *serverHello, bool isHrr)
{
    int32_t ret = HITLS_SUCCESS;

    ctx->negotiatedInfo.version = serverHello->supportedVersion;

    ret = memcpy_s(ctx->hsCtx->serverRandom, HS_RANDOM_SIZE, serverHello->randomValue, HS_RANDOM_SIZE);
    if (ret != EOK) {
        return ret;
    }

    ret = Tls13ClientCheckSessionId(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ClientCheckCipherSuite(ctx, serverHello, isHrr);
}

static int32_t ClientCheckHrrKeyShareExtension(TLS_Ctx *ctx, const ServerHelloMsg *helloRetryRequest)
{
    if (helloRetryRequest->haveKeyShare == false) {
        return HITLS_SUCCESS;
    }

    /* The keyshare extension of hrr contains only group and does not contain other fields */
    if (helloRetryRequest->keyShare.keyExchangeSize != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15282, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the keyshare keyExchangeSize is not 0 in hrr keyshare.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
        return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
    }

    uint16_t selectedGroup = helloRetryRequest->keyShare.group;
    const uint16_t *groups = ctx->config.tlsConfig.groups;
    uint32_t numOfGroups = ctx->config.tlsConfig.groupsSize;

    /* The selected group exist in the key share extension of the original client hello and no cookie exchange requested */
    if (ctx->negotiatedInfo.cookie == NULL && (selectedGroup == ctx->hsCtx->kxCtx->keyExchParam.share.group ||
            selectedGroup == ctx->hsCtx->kxCtx->keyExchParam.share.secondGroup)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15283, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the selected group extension is corresponded to a group in client hello key share.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
        return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
    }

    /* The selected group must exist in the supported groups extension of the original client hello */
    bool found = false;
    for (uint32_t i = 0; i < numOfGroups; i++) {
        if (selectedGroup == groups[i]) {
            found = true;
            break;
        }
    }
    if (found == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15284, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the selected group extension could not correspond to a group in client hello supported groups.",
            0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
        return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
    }
    if (selectedGroup == ctx->hsCtx->kxCtx->keyExchParam.share.secondGroup) {
        SAL_CRYPT_FreeEcdhKey(ctx->hsCtx->kxCtx->key);
        ctx->hsCtx->kxCtx->key = ctx->hsCtx->kxCtx->secondKey;
        ctx->hsCtx->kxCtx->secondKey = NULL;
        ctx->hsCtx->kxCtx->keyExchParam.share.group = selectedGroup;
        ctx->hsCtx->kxCtx->keyExchParam.share.secondGroup = HITLS_NAMED_GROUP_BUTT;
    }
    // Save the selected group
    ctx->negotiatedInfo.negotiatedGroup = selectedGroup;
    return HITLS_SUCCESS;
}

/* If an implementation receives an extension
 * which it recognizes and which is not specified for the message in
 * which it appears, it MUST abort the handshake with an
 * "illegal_parameter" alert. */
static int32_t ClientCheckHrrExtraExtension(TLS_Ctx *ctx, const ServerHelloMsg *helloRetryRequest)
{
    if (helloRetryRequest->haveServerName || helloRetryRequest->haveExtendedMasterSecret ||
        helloRetryRequest->havePointFormats || helloRetryRequest->haveSelectedAlpn ||
        helloRetryRequest->haveSelectedIdentity || helloRetryRequest->haveSecRenego || helloRetryRequest->haveTicket ||
        helloRetryRequest->haveEncryptThenMac) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17092, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "these extensions are not specified in the hrr message", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }
    return HITLS_SUCCESS;
}

static int32_t ClientCheckHrrCookieExtension(TLS_Ctx *ctx, const ServerHelloMsg *helloRetryRequest)
{
    if (helloRetryRequest->haveCookie == false) {
        return HITLS_SUCCESS;
    }

    BSL_SAL_FREE(ctx->negotiatedInfo.cookie); // Clearing Old Memory

    ctx->negotiatedInfo.cookie = BSL_SAL_Dump(helloRetryRequest->cookie, helloRetryRequest->cookieLen);
    if (ctx->negotiatedInfo.cookie == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15285, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cookie malloc fail when process hello retry request.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    ctx->negotiatedInfo.cookieSize = helloRetryRequest->cookieLen;

    return HITLS_SUCCESS;
}

static int32_t Tls13ClientCheckHrrExtension(TLS_Ctx *ctx, const ServerHelloMsg *helloRetryRequest)
{
    int32_t ret = HITLS_SUCCESS;

    ret = HS_CheckReceivedExtension(ctx, HELLO_RETRY_REQUEST, helloRetryRequest->extensionTypeMask,
        HS_EX_TYPE_TLS1_3_ALLOWED_OF_HELLO_RETRY_REQUEST);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check whether there are redundant extensions */
    ret = ClientCheckHrrExtraExtension(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check the key share extension */
    ret = ClientCheckHrrCookieExtension(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check the cookie extension */
    return ClientCheckHrrKeyShareExtension(ctx, helloRetryRequest);
}

int32_t Tls13ClientRecvHelloRetryRequestProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = HITLS_SUCCESS;
    const ServerHelloMsg *helloRetryRequest = &msg->body.serverHello;

    ret = Tls13ClientCheckHelloRetryRequest(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check whether the format of the Hello Retry Request message is the same as that of the Server Hello message
     * except the extended fields */
    ret = Tls13ClientCheckServerHello(ctx, helloRetryRequest, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = Tls13ClientCheckHrrExtension(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* According to RFC 8446 4.4.1, If the Hello Retry Request message is sent, special Transcript-Hash data needs to be
     * constructed */
    ret = VERIFY_HelloRetryRequestVerifyProcess(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HS_ChangeState(ctx, TRY_SEND_CLIENT_HELLO);
}
#ifdef HITLS_TLS_PROTO_TLS_BASIC
static int32_t CheckDowngradeRandom(TLS_Ctx *ctx, const ServerHelloMsg *serverHello, uint16_t *negotiatedVersion)
{
    const uint8_t *downgradeArr = NULL;
    uint32_t downgradeArrLen = 0;

    if (serverHello->version == HITLS_VERSION_TLS12) {
        /* The server that attempts to negotiate TLS1.2 should not send the server hello with the random */
        downgradeArr = HS_GetTls12DowngradeRandom(&downgradeArrLen);
        if (memcmp(&serverHello->randomValue[HS_RANDOM_SIZE - downgradeArrLen], downgradeArr, downgradeArrLen) != 0) {
            *negotiatedVersion = HITLS_VERSION_TLS12;
            return HITLS_SUCCESS;
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15286, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "tls1.2 server hello with downgrade random value.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
        return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC */
static int32_t GetNegotiatedVersion(TLS_Ctx *ctx, const ServerHelloMsg *serverHello, uint16_t *negotiatedVersion)
{
    /* As a client that supports TLS1.3, if the received server hello message does not contain the supported version
     * extension, the peer end wants to negotiate a version earlier than TLS1.3 */
    if (!serverHello->haveSupportedVersion) {
        if (serverHello->version < HITLS_VERSION_TLS12) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16169, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client cannot negotiate a version.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
        }
        return CheckDowngradeRandom(ctx, serverHello, negotiatedVersion);
    }

    /* If the serverHello of TLS1.3 is used, the version selected by the server must be earlier than TLS1.3, and the
     * legacy_version field must be TLS1.2 */
    if (serverHello->version != HITLS_VERSION_TLS12) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15288, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server version error, legacy version is 0x%02x.", serverHello->version, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
        return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }
    /* If the "supported_versions" extension in the ServerHello contains a version not offered by the client or
     * contains a version prior to TLS 1.3, the client MUST abort the handshake with an "illegal_parameter" alert. */
    if (serverHello->supportedVersion != HITLS_VERSION_TLS13) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17307, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server version error, selected version is 0x%02x.", serverHello->supportedVersion, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
        return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
    }

    *negotiatedVersion = HITLS_VERSION_TLS13;
    return HITLS_SUCCESS;
}

static int32_t ClientProcessKeyShare(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if (serverHello->haveKeyShare == false) {
        return HITLS_SUCCESS;
    }
    uint32_t keyshareLen = 0u;
    /* The keyshare extension of the server must contain the keyExchange field */
    if (serverHello->keyShare.keyExchangeSize == 0 || serverHello->keyShare.group == HITLS_NAMED_GROUP_BUTT ||
#ifdef HITLS_TLS_FEATURE_SM_TLS13
        (IS_SM_TLS13(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite)
         && serverHello->keyShare.group != HITLS_EC_GROUP_SM2) ||
#endif
        /* Check whether the sent support group is the same as the negotiated group */
        (serverHello->keyShare.group != ctx->hsCtx->kxCtx->keyExchParam.share.group &&
            serverHello->keyShare.group != ctx->hsCtx->kxCtx->keyExchParam.share.secondGroup)) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
        return RETURN_ALERT_PROCESS(ctx, HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP, BINLOG_ID15289,
            "the keyshare parameter is illegal.", ALERT_ILLEGAL_PARAMETER);
    }

    const KeyShare *keyShare = &serverHello->keyShare;
    if (keyShare->group == ctx->hsCtx->kxCtx->keyExchParam.share.secondGroup) {
        SAL_CRYPT_FreeEcdhKey(ctx->hsCtx->kxCtx->key);
        ctx->hsCtx->kxCtx->key = ctx->hsCtx->kxCtx->secondKey;
        ctx->hsCtx->kxCtx->secondKey = NULL;
        ctx->hsCtx->kxCtx->keyExchParam.share.group = keyShare->group;
        ctx->hsCtx->kxCtx->keyExchParam.share.secondGroup = HITLS_NAMED_GROUP_BUTT;
    }
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(&ctx->config.tlsConfig, keyShare->group);
    if (groupInfo == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_INVALID_INPUT, BINLOG_ID16247, "group info not found");
    }
    if (groupInfo->isKem) {
        keyshareLen = groupInfo->ciphertextLen;
    } else {
        keyshareLen = groupInfo->pubkeyLen;
    }
    if (keyshareLen == 0u || keyshareLen != keyShare->keyExchangeSize) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17326, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid keyShare length [%d]", keyShare->keyExchangeSize, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
    }
    uint8_t *peerPubkey = BSL_SAL_Dump(keyShare->keyExchange, keyshareLen);
    if (peerPubkey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return RETURN_ALERT_PROCESS(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID15290,
            "malloc peerPubkey fail when process server hello key share", ALERT_INTERNAL_ERROR);
    }

    BSL_SAL_FREE(ctx->hsCtx->kxCtx->peerPubkey);
    ctx->hsCtx->kxCtx->peerPubkey = peerPubkey;
    ctx->hsCtx->kxCtx->pubKeyLen = keyshareLen;
    ctx->negotiatedInfo.negotiatedGroup = serverHello->keyShare.group;

    return HITLS_SUCCESS;
}

static int32_t ClientProcessPreSharedKey(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if (serverHello->haveSelectedIdentity == false) {
        return HITLS_SUCCESS;
    }
    PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    HITLS_Session *pskSession = NULL;
    bool isResumePsk = false;
    BSL_SAL_FREE(pskInfo->psk);

    if (pskInfo->resumeSession != NULL && serverHello->selectedIdentity == 0) {
        pskSession = pskInfo->resumeSession;
        isResumePsk = true;
    } else if (pskInfo->userPskSess == NULL || serverHello->selectedIdentity != pskInfo->userPskSess->num) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_PSK_IDENTITY);
        return HITLS_MSG_HANDLE_ILLEGAL_PSK_IDENTITY;
    } else {
        pskSession = pskInfo->userPskSess->pskSession;
    }
    pskInfo->selectIndex = serverHello->selectedIdentity;

    uint8_t psk[HS_PSK_MAX_LEN] = {0};
    uint32_t pskLen = HS_PSK_MAX_LEN;

    uint16_t cipherSuite = 0;
    HITLS_SESS_GetCipherSuite(pskSession, &cipherSuite);
    CipherSuiteInfo cipherInfo = {0};
    int32_t ret = CFG_GetCipherSuiteInfo(cipherSuite, &cipherInfo);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ALERT_PROCESS(ctx, ret, BINLOG_ID17093, "GetCipherSuiteInfo fail", ALERT_INTERNAL_ERROR);
    }

    /* The hash algorithm used by the PSK must match the negotiated cipher suite */
    if (cipherInfo.hashAlg != ctx->negotiatedInfo.cipherSuiteInfo.hashAlg) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_PSK_SESSION_INVALID_CIPHER_SUITE);
        return HITLS_MSG_HANDLE_PSK_SESSION_INVALID_CIPHER_SUITE;
    }

    /* The session is available and the PSK is obtained */
    ret = HITLS_SESS_GetMasterKey(pskSession, psk, &pskLen);
    if (ret != HITLS_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return ret;
    }

    pskInfo->psk = BSL_SAL_Dump(psk, pskLen);
    BSL_SAL_CleanseData(psk, HS_PSK_MAX_LEN);
    if (pskInfo->psk == NULL) {
        (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
        return RETURN_ALERT_PROCESS(ctx, HITLS_MEMALLOC_FAIL, BINLOG_ID17094, "dump psk fail", ALERT_INTERNAL_ERROR);
    }
    pskInfo->pskLen = pskLen;
    ctx->negotiatedInfo.isResume = isResumePsk;
    return HITLS_SUCCESS;
}

static uint32_t GetServertls13AuthType(const ServerHelloMsg *serverHello)
{
    uint32_t tls13BasicKeyExMode = 0;
    if (serverHello->haveKeyShare && serverHello->haveSelectedIdentity) {
        tls13BasicKeyExMode = TLS13_KE_MODE_PSK_WITH_DHE;
    } else if (serverHello->haveSelectedIdentity) {
        tls13BasicKeyExMode = TLS13_KE_MODE_PSK_ONLY;
    } else if (serverHello->haveKeyShare) {
        tls13BasicKeyExMode = TLS13_CERT_AUTH_WITH_DHE;
    }
    return tls13BasicKeyExMode;
}

static int32_t Tls13ProcessServerHelloExtension(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    int32_t ret = 0;

    ret = HS_CheckReceivedExtension(ctx, SERVER_HELLO, serverHello->extensionTypeMask,
        HS_EX_TYPE_TLS1_3_ALLOWED_OF_SERVER_HELLO);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check whether the extension that is not sent is received */
    ret = ClientCheckExtensionsFlag(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t tls13BasicKeyExMode = GetServertls13AuthType(serverHello) & ctx->negotiatedInfo.tls13BasicKeyExMode;
    if (tls13BasicKeyExMode == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16141, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server selects the mode in which the client does not send.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_HANDSHAKE_FAILURE);
        return HITLS_MSG_HANDLE_HANDSHAKE_FAILURE;
    }
    ctx->negotiatedInfo.tls13BasicKeyExMode = tls13BasicKeyExMode;

    ret = ClientProcessKeyShare(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return ClientProcessPreSharedKey(ctx, serverHello);
}

int32_t Tls13ProcessServerHello(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = HITLS_SUCCESS;
    const ServerHelloMsg *serverHello = &msg->body.serverHello;

    /* Check all fields except the extended fields in the server hello message */
    ret = Tls13ClientCheckServerHello(ctx, serverHello, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = Tls13ProcessServerHelloExtension(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = VERIFY_SetHash(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        ctx->hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Client key derivation */
    ret = HS_TLS13CalcServerHelloProcessSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17095, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CalcServerHelloProcessSecret fail", 0, 0, 0, 0);
        return ret;
    }

    ret = HS_TLS13DeriveHandshakeTrafficSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17096, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DeriveHandshakeTrafficSecret fail", 0, 0, 0, 0);
        return ret;
    }

    /* The message after ServerHello is encrypted by ServerTrafficSecret and needs to be activated for decryption */
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (hashLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17097, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "DigestSize err", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_DIGEST;
    }
    ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->serverHsTrafficSecret, hashLen, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HS_ChangeState(ctx, TRY_RECV_ENCRYPTED_EXTENSIONS);
}

int32_t Tls13ClientRecvServerHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = HITLS_SUCCESS;
    const ServerHelloMsg *serverHello = &msg->body.serverHello;

    /* Obtain the intention of the server and determine the version to be negotiated by the server */
    uint16_t negotiatedVersion = 0;
    ret = GetNegotiatedVersion(ctx, serverHello, &negotiatedVersion);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_PROTO_TLS_BASIC
    if (negotiatedVersion < HITLS_VERSION_TLS13) {
        /* The keyshare is prepared when the TLS1.3 clientHello message is sent, so the old memory needs to be freed
         * here first */
        HS_KeyExchCtxFree(ctx->hsCtx->kxCtx);
        ctx->hsCtx->kxCtx = HS_KeyExchCtxNew();

        if (ctx->hsCtx->kxCtx == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17098, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "KeyExchCtxNew fail", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }

        return ClientRecvServerHelloProcess(ctx, msg);
    }
#endif /* only for tls13 */
    uint32_t hrrRandomSize = 0;
    const uint8_t *hrrRandom = HS_GetHrrRandom(&hrrRandomSize);

    /* Check the random number. If the message is a hello retry request message, update the client hello message */
    if (memcmp(serverHello->randomValue, hrrRandom, hrrRandomSize) == 0) {
        return Tls13ClientRecvHelloRetryRequestProcess(ctx, msg);
    }

    return Tls13ProcessServerHello(ctx, msg);
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_CLIENT */