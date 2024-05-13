/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

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
#include "security.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_verify.h"
#include "hs_common.h"
#include "hs_msg.h"
#include "transcript_hash.h"
#include "session_mgr.h"
#include "alpn.h"
#include "hs_kx.h"


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

static int32_t SelectProtocol(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    uint8_t *protoMatch = NULL;
    uint32_t protoMatchLen = 0;

    int32_t ret = ALPN_SelectProtocol(&protoMatch, &protoMatchLen, serverHello->alpnSelected,
        serverHello->alpnSelectedSize, ctx->config.tlsConfig.alpnList, ctx->config.tlsConfig.alpnListSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15258, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client check proposed protocol fail due to invalid params.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    } else if (protoMatch == NULL) {
        /* The RFC 7301 does not specify the behavior when the client selectedProto does not match the local
         * configuration list. The behavior is the same as that in OpenSSL. */
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15259, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server proposed protocol is not supported by client: %s.", serverHello->alpnSelected, 0, 0, 0);
    }

    return HITLS_SUCCESS;
}

static int32_t ClientCheckNegotiatedAlpn(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    if ((!ctx->hsCtx->extFlag.haveAlpn) && serverHello->haveSelectedAlpn) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15257, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get selected alpn protocol.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    if (serverHello->alpnSelectedSize == 0) {
        return HITLS_SUCCESS;
    }

    int32_t ret = SelectProtocol(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *alpnSelectedTmp = (uint8_t *)BSL_SAL_Calloc(1u, (serverHello->alpnSelectedSize + 1));
    if (alpnSelectedTmp == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15260, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client malloc selected alpn mem failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    if (memcpy_s(alpnSelectedTmp, serverHello->alpnSelectedSize + 1, serverHello->alpnSelected,
        serverHello->alpnSelectedSize) != EOK) {
        BSL_SAL_FREE(alpnSelectedTmp);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15261, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client copy selected alpn failed.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        return HITLS_MEMCPY_FAIL;
    }

    BSL_SAL_FREE(ctx->negotiatedInfo.alpnSelected);
    ctx->negotiatedInfo.alpnSelected = alpnSelectedTmp;
    ctx->negotiatedInfo.alpnSelectedSize = serverHello->alpnSelectedSize;

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15262, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "ALPN protocol: %s.", ctx->negotiatedInfo.alpnSelected, 0, 0, 0);

    return HITLS_SUCCESS;
}

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
            ctx->hsCtx->serverNameSize = ctx->config.tlsConfig.serverNameSize;

            ctx->hsCtx->serverName =
                (uint8_t *)BSL_SAL_Dump(ctx->config.tlsConfig.serverName, ctx->hsCtx->serverNameSize * sizeof(uint8_t));
            if (ctx->hsCtx->serverName == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
                return HITLS_MEMCPY_FAIL;
            }
        }
    }

    return HITLS_SUCCESS;
}

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
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 || ctx->negotiatedInfo.version < HITLS_VERSION_TLS12) {
        ctx->negotiatedInfo.isExtendedMasterSecret = false;
        return HITLS_SUCCESS;
    }
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
        uint8_t haveExtMasterSecret;
        HITLS_SESS_GetHaveExtMasterSecret(ctx->session, &haveExtMasterSecret);
        bool preEms = haveExtMasterSecret != 0;
        if (serverHello->haveExtendedMasterSecret != preEms) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
            return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
        }
    }
    if (ctx->config.tlsConfig.isSupportExtendMasterSecret && !serverHello->haveExtendedMasterSecret) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
        return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
    }
    /* Configure the negotiation content to support the extended master secret */
    ctx->negotiatedInfo.isExtendedMasterSecret = (ctx->hsCtx->extFlag.haveExtendedMasterSecret &&
        serverHello->haveExtendedMasterSecret);
    return HITLS_SUCCESS;
}

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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15853, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "client did not send but get supported versions.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_EXTENSION);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    return HITLS_SUCCESS;
}

static int32_t ClientCheckRenegoInfoDuringFirstHandshake(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* If the peer does not support the negotiation, return */
    if (!serverHello->haveSecRenego) {
        if (ctx->config.tlsConfig.noSecRenegotiationCb != NULL) {
            /* The user can determine whether to terminate when the peer does not support security renegotiation */
            int32_t ret = ctx->config.tlsConfig.noSecRenegotiationCb(ctx);
            if (ret != HITLS_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15899, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "noSecRenegotiationCb return fail when process server hello.", 0, 0, 0, 0);
                ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
        return HITLS_SUCCESS;
    }

    /* For the first handshake, if the security renegotiation information is not empty, return an error code.
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

static int32_t ClientCheckRenegoInfoDuringRenegotiation(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* Verify the security renegotiation information */
    const uint8_t *clientData = ctx->negotiatedInfo.clientVerifyData;
    uint32_t clientDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
    const uint8_t *serverData = ctx->negotiatedInfo.serverVerifyData;
    uint32_t serverDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
    if (clientData == NULL || serverData == NULL) {
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

static int32_t ClientCheckAndProcessRenegoInfo(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    /* Not in the renegotiation state */
    if (!ctx->negotiatedInfo.isRenegotiation) {
        return ClientCheckRenegoInfoDuringFirstHandshake(ctx, serverHello);
    }

    /* Renegotiation state */
    return ClientCheckRenegoInfoDuringRenegotiation(ctx, serverHello);
}

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

static int32_t ClientCheckExtensionsFlag(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    static const CheckExtFunc extInfoList[] = {
        ClientCheckServerName,
        ClientCheckExtendedMasterSecret,
        ClientCheckPointFormats,
        ClientCheckNegotiatedAlpn,
        ClientCheckKeyShare,
        ClientCheckPreShareKey,
        ClientCheckAndProcessRenegoInfo,
        ClientCheckTicketExternsion,
        ClientCheckEncryptThenMac,
        ClientCheckSupportedVersions,
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

static int32_t ClientCheckVersion(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    uint16_t clientMinVersion = ctx->config.tlsConfig.minVersion;
    uint16_t clientMaxVersion = ctx->config.tlsConfig.maxVersion;
    uint16_t serverVersion = serverHello->version;

    if (IS_DTLS_VERSION(serverVersion)) {
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

    int32_t  ret = SECURITY_SslCheck((HITLS_Ctx *)ctx, HITLS_SECURITY_SECOP_VERSION, 0, serverHello->version, NULL);
    if (ret != SECURITY_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSECURE_VERSION);
        return HITLS_MSG_HANDLE_UNSECURE_VERSION;
    }

    ctx->negotiatedInfo.version = serverVersion;
    return HITLS_SUCCESS;
}

static bool IsCipherSuiteSupport(const TLS_Ctx *ctx, uint16_t cipherSuite)
{
    if (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) {
        for (uint32_t index = 0; index < ctx->config.tlsConfig.tls13cipherSuitesSize; index++) {
            if (cipherSuite == ctx->config.tlsConfig.tls13CipherSuites[index]) {
                return true;
            }
        }
    }

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

    if (!IsCipherSuiteSupport(ctx, serverHello->cipherSuite)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15269, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "no supported cipher suites found.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
        return HITLS_MSG_HANDLE_CIPHER_SUITE_ERR;
    }

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

    ret = CFG_GetCipherSuiteInfo(serverHello->cipherSuite, &ctx->negotiatedInfo.cipherSuiteInfo);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15271, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get cipher suite information fail.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
    }

    /* Check the security of the cipher suite */
    ret = SECURITY_SslCheck((HITLS_Ctx *)ctx, HITLS_SECURITY_SECOP_CIPHER_SHARED, 0, 0,
        (void *)&ctx->negotiatedInfo.cipherSuiteInfo);
    if (ret != SECURITY_SUCCESS) {
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSECURE_CIPHER_SUITE);
        return HITLS_MSG_HANDLE_UNSECURE_CIPHER_SUITE;
    }

    /* Sets the key negotiation algorithm. */
    ctx->hsCtx->kxCtx->keyExchAlgo = ctx->negotiatedInfo.cipherSuiteInfo.kxAlg;

    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15272, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "ClientCheckCipherSuite: negotiated ciphersuite is [%s].",
        ctx->negotiatedInfo.cipherSuiteInfo.name);
    return HITLS_SUCCESS;
}

static int32_t ClientCheckResumeServerHello(TLS_Ctx *ctx, const ServerHelloMsg *serverHello)
{
    uint16_t version = 0;
    uint16_t cipherSuite = 0;
    uint8_t haveExtMasterSecret = 0;

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
    if (serverHello->haveExtendedMasterSecret != (bool)haveExtMasterSecret) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15275, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "session resume error:can not downgrade from extended master secret.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
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

    ret = ClientCheckCipherSuite(ctx, serverHello, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = ClientCheckExtensionsFlag(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

// The client processes the Server Hello message
int32_t ClientRecvServerHelloProcess(TLS_Ctx *ctx, const HS_Msg *msg)
{
    int32_t ret = HITLS_SUCCESS;
    const ServerHelloMsg *serverHello = &msg->body.serverHello;

    ret = ClientCheckServerHello(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = VERIFY_SetHash(ctx->hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (ctx->negotiatedInfo.isResume == true) {
        ret = HS_ResumeKeyEstablish(ctx);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (ctx->negotiatedInfo.isTicket) {
            return HS_ChangeState(ctx, TRY_RECV_NEW_SESSION_TICKET);
        }

        ret = VERIFY_CalcVerifyData(ctx, false, ctx->hsCtx->masterKey, MASTER_SECRET_LEN);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15278, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client Calculate server finished data error.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            return ret;
        }
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_READY);
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_ACTIVE_CIPHER_SPEC);
        return HS_ChangeState(ctx, TRY_RECV_FINISH);
    }

    /* If the server rejects the session resume request, the system clears the ccs that may be received in disorder */
    ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);

    /* Update the state machine. */
    /* If the PSK, DHE_PSK, ECDHE_PSK, or ANON_DH key negotiation is used, skip TRY_RECV_CERTIFICATIONATE */
    if (!IsNeedCertPrepare(&ctx->negotiatedInfo.cipherSuiteInfo)) {
        return HS_ChangeState(ctx, TRY_RECV_SERVER_KEY_EXCHANGE);
    }
    return HS_ChangeState(ctx, TRY_RECV_CERTIFICATE);
}

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
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        return HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID;
    }
    if (serverHello->sessionIdSize != 0) {
        if (memcmp(ctx->hsCtx->sessionId, serverHello->sessionId, serverHello->sessionIdSize) != 0) {
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

    ret = ClientCheckCipherSuite(ctx, serverHello, isHrr);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
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

    /* The selected group must not exist in the key share extension of the original client hello */
    if (selectedGroup == ctx->hsCtx->kxCtx->keyExchParam.share.group) {
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

    // Save the selected group
    ctx->hsCtx->kxCtx->keyExchParam.share.group = selectedGroup;
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
    /* Check whether there are redundant extensions */
    ret = ClientCheckHrrExtraExtension(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check the key share extension */
    ret = ClientCheckHrrKeyShareExtension(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check the cookie extension */
    ret = ClientCheckHrrCookieExtension(ctx, helloRetryRequest);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
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

    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15287, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "tls1.1 server hello with downgrade random value.", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
    BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
}

static int32_t GetNegotiatedVersion(TLS_Ctx *ctx, const ServerHelloMsg *serverHello, uint16_t *negotiatedVersion)
{
    /* As a client that supports TLS1.3, if the received server hello message does not contain the supported version
     * extension, the peer end wants to negotiate a version earlier than TLS1.3 */
    if (!serverHello->haveSupportedVersion) {
        if (serverHello->version < HITLS_VERSION_TLS12) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15846, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "client cannot negotiate a version.", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
            BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
            return HITLS_MSG_HANDLE_UNSUPPORT_VERSION;
        }
        return CheckDowngradeRandom(ctx, serverHello, negotiatedVersion);
    }

    /* If the serverHello of TLS1.3 is used, the version selected by the server must be earlier than TLS1.3, and the
     * legacy_version field must be TLS1.2 */
    if ((serverHello->supportedVersion != HITLS_VERSION_TLS13) || (serverHello->version != HITLS_VERSION_TLS12)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15288, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "server version error, selected version is 0x%02x, legacy version is 0x%02x.",
            serverHello->supportedVersion, serverHello->version, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
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

    /* The keyshare extension of the server must contain the keyExchange field */
    if (serverHello->keyShare.keyExchangeSize == 0 ||
        /* Check whether the sent support group is the same as the negotiated group */
        serverHello->keyShare.group != ctx->hsCtx->kxCtx->keyExchParam.share.group) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15289, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the keyshare parameter is illegal.", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
        return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
    }

    const KeyShare *keyShare = &serverHello->keyShare;
    uint8_t *peerPubkey = BSL_SAL_Dump(keyShare->keyExchange, keyShare->keyExchangeSize);
    if (peerPubkey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15290, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "malloc peerPubkey fail when process server hello key share.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t pubKeyLen = keyShare->keyExchangeSize;

    ctx->hsCtx->kxCtx->peerPubkey = peerPubkey;
    ctx->hsCtx->kxCtx->pubKeyLen = pubKeyLen;
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
    pskInfo->psk = NULL;

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
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return ret;
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
    if (pskInfo->psk == NULL) {
        (void)memset_s(psk, HS_PSK_MAX_LEN, 0, HS_PSK_MAX_LEN);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_MEMALLOC_FAIL;
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

    /* Check whether the extension that is not sent is received */
    ret = ClientCheckExtensionsFlag(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t tls13BasicKeyExMode = GetServertls13AuthType(serverHello) & ctx->negotiatedInfo.tls13BasicKeyExMode;
    if (tls13BasicKeyExMode == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15492, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
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

    ret = ClientProcessPreSharedKey(ctx, serverHello);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
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

    ret = VERIFY_SetHash(ctx->hsCtx->verifyCtx, ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Client key derivation */
    ret = HS_TLS13CalcServerHelloProcessSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HS_TLS13DeriveHandshakeTrafficSecret(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* The message after ServerHello is encrypted by ServerTrafficSecret and needs to be activated for decryption */
    uint32_t hashLen = SAL_CRYPT_DigestSize(ctx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    if (hashLen == 0) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    ret = HS_SwitchTrafficKey(ctx, ctx->hsCtx->serverHsTrafficSecret, hashLen, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* If there is an hrr message, the CCS has received the message before the serverhello message. If there is no hrr
     * message, the next message may be the ccs message */
    if (ctx->hsCtx->haveHrr && ctx->method.isRecvCCS(ctx)) {
        ctx->method.ctrlCCS(ctx, CCS_CMD_RECV_EXIT_READY);
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

    if (negotiatedVersion < HITLS_VERSION_TLS13) {
        /* The keyshare is prepared when the TLS1.3 clientHello message is sent, so the old memory needs to be freed
         * here first */
        HS_KeyExchCtxFree(ctx->hsCtx->kxCtx);
        ctx->hsCtx->kxCtx = HS_KeyExchCtxNew();

        if (ctx->hsCtx->kxCtx == NULL) {
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
            BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
            return HITLS_MEMALLOC_FAIL;
        }

        return ClientRecvServerHelloProcess(ctx, msg);
    }

    uint32_t hrrRandomSize = 0;
    const uint8_t *hrrRandom = HS_GetHrrRandom(&hrrRandomSize);

    /* Check the random number. If the message is a hello retry request message, update the client hello message */
    if (memcmp(serverHello->randomValue, hrrRandom, hrrRandomSize) == 0) {
        return Tls13ClientRecvHelloRetryRequestProcess(ctx, msg);
    }

    return Tls13ProcessServerHello(ctx, msg);
}
