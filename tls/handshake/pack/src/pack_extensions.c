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

#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "securec.h"
#include "cipher_suite.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_bytes.h"
#include "bsl_list.h"
#include "hitls_error.h"
#include "hitls_sni.h"
#include "hitls_cert_type.h"
#include "hitls_crypt_type.h"
#include "hitls_session.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "hs.h"
#include "hs_msg.h"
#include "hs_common.h"
#include "session.h"
#include "hs_verify.h"
#include "pack_common.h"
#include "custom_extensions.h"
#include "pack_extensions.h"
#include "config_type.h"


#define EXTENSION_MSG(exMsgT, needP, packF) \
    .exMsgType = (exMsgT), \
    .needPack = (needP), \
    .packFunc = (packF),    \

// Pack the extension header.
int32_t PackExtensionHeader(uint16_t exMsgType, uint16_t exMsgLen, PackPacket *pkt)
{
    int32_t ret = PackAppendUint16ToBuf(pkt, exMsgType);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackAppendUint16ToBuf(pkt, exMsgLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackReserveBytes(pkt, exMsgLen, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

static int32_t PackExtensions(const TLS_Ctx *ctx, PackPacket *pkt, PackExtInfo *extMsgList, uint32_t listSize)
{
    int32_t ret = HITLS_SUCCESS;
    for (uint32_t index = 0; index < listSize; index++) {
        if (extMsgList[index].needPack == false) {
            continue;
        }

        /* Empty expansion */
        if (extMsgList[index].packFunc == NULL) {
            ret = PackEmptyExtension(extMsgList[index].exMsgType, extMsgList[index].needPack, pkt);
        } else { /* Non-empty expansion */
            ret = extMsgList[index].packFunc(ctx, pkt);
        }

        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t PackExtensionEnd(PackPacket *pkt, uint32_t extensionLenPosition)
{
    uint32_t extensionLength = 0;
    int32_t ret = PackGetSubBuffer(pkt, extensionLenPosition, &extensionLength, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Update the packet length */
    if (extensionLength != sizeof(uint16_t)) {
        PackCloseUint16Field(pkt, extensionLenPosition);
    } else {
        *pkt->bufOffset -= sizeof(uint16_t);
    }

    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_TLS13

static bool IsNeedPreSharedKey(const TLS_Ctx *ctx)
{
    if (ctx->config.tlsConfig.maxVersion != HITLS_VERSION_TLS13) {
        return false;
    }

    if (ctx->hsCtx->state == TRY_SEND_HELLO_RETRY_REQUEST) {
        /* hello retry request does not contain the psk */
        return false;
    }

    return true;
}

bool Tls13NeedPack(const TLS_Ctx *ctx, uint32_t version)
{
    bool tls13NeedPack = false;
    if (IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        tls13NeedPack = false;
    } else {
        tls13NeedPack = (version >= HITLS_VERSION_TLS13) ? true : false;
    }
    return tls13NeedPack;
}
static int32_t PackCookie(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t exMsgDataLen = 0u;

    if (ctx->negotiatedInfo.cookie == NULL) {
        return HITLS_SUCCESS;
    }

    /* Calculate the extension length */
    exMsgDataLen = sizeof(uint16_t) + (ctx->negotiatedInfo.cookieSize);
    uint32_t cookieLen = ctx->negotiatedInfo.cookieSize;

    ret = PackExtensionHeader(HS_EX_TYPE_COOKIE, exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, cookieLen);

    /* Pack the cookie */
    (void)PackAppendDataToBuf(pkt, ctx->negotiatedInfo.cookie, cookieLen);

    ctx->hsCtx->extFlag.haveCookie = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
static int32_t PackPointFormats(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgHeaderLen = 0u;
    uint8_t exMsgDataLen = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if (config->pointFormatsSize == 0) {
        return HITLS_SUCCESS;
    }

    if (config->pointFormats == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15415, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack point formats extension error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Calculate the extension length */
    exMsgHeaderLen = sizeof(uint8_t);
    exMsgDataLen = (uint8_t)config->pointFormatsSize;

    ret = PackExtensionHeader(HS_EX_TYPE_POINT_FORMATS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the extension point format */
    (void)PackAppendUint8ToBuf(pkt, exMsgDataLen);

    for (uint32_t index = 0; index < config->pointFormatsSize; index++) {
        (void)PackAppendUint8ToBuf(pkt, config->pointFormats[index]);
    }

    /* Set the extension flag */
    ctx->hsCtx->extFlag.havePointFormats = true;

    return HITLS_SUCCESS;
}

int32_t PackEmptyExtension(uint16_t exMsgType, bool needPack, PackPacket *pkt)
{
    if (needPack) {
        int32_t ret = PackExtensionHeader(exMsgType, 0u, pkt);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_HOST_CLIENT
#ifdef HITLS_TLS_FEATURE_SNI
static int32_t PackServerName(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgDataLen = 0u;
    uint8_t *hostName = NULL;
    uint8_t *serverName = NULL;
    uint32_t hostNameSize, serverNameSize = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);
    bool isNotTls13 = (config->maxVersion < HITLS_VERSION_TLS13 || config->maxVersion == HITLS_VERSION_DTLS12);
    (void)isNotTls13;
    (void)hostNameSize;
    (void)hostName;
#ifdef HITLS_TLS_FEATURE_SESSION
    /* When a session whose protocol version is earlier than HITLS_VERSION_TLS13 is resumed, the servername extension
     * field is the hostname in the session */
    if (isNotTls13 && ctx->session != NULL) {
        /* Obtain the hostname in the session */
        SESS_GetHostName(ctx->session, &hostNameSize, &hostName);
        serverName = hostName;
    } else
#endif
    {
        /* Obtain the servername in the config */
        serverName = config->serverName;
    }

    if (serverName == NULL) {
        return HITLS_SUCCESS;
    }

    serverNameSize = (uint32_t)strlen((char *)serverName);
    /* Calculate the extension length */
    /* server Name list Length + server Name Type + Server Name Length + Server Name */
    exMsgDataLen = sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) * serverNameSize;

    ret = PackExtensionHeader(HS_EX_TYPE_SERVER_NAME, exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the extension Server Name Indication extension */
    /* server Name list Length */
    (void)PackAppendUint16ToBuf(pkt, exMsgDataLen - sizeof(uint16_t));

    /* server Name Type */
    (void)PackAppendUint8ToBuf(pkt, HITLS_SNI_HOSTNAME_TYPE);

    /* Server Name Length */
    (void)PackAppendUint16ToBuf(pkt, (uint16_t)serverNameSize);

    /* Server Name */
    (void)PackAppendDataToBuf(pkt, serverName, serverNameSize);

    /* Set the extension flag */
    ctx->hsCtx->extFlag.haveServerName = true;

    return HITLS_SUCCESS;
}

static bool IsNeedClientPackServerName(const TLS_Ctx *ctx)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);

    /* not in session resumption */
    if (ctx->session == NULL) {
        if (config->serverName == NULL) {
            return false;
        }
    }

    /* The session is being resumed */
    if (ctx->session != NULL) {
        if (config->maxVersion == HITLS_VERSION_TLS13 && config->serverName == NULL) {
            return false;
        }
    }

    return true;
}
#endif /* HITLS_TLS_FEATURE_SNI */
static int32_t PackClientSignatureAlgorithms(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgHeaderLen = 0u;
    uint16_t exMsgDataLen = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if (config->signAlgorithmsSize == 0) {
        return HITLS_SUCCESS;
    }

    if (config->signAlgorithms == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15413, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack signature algirithms extension error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t signAlgorithmsSize = 0;
    uint16_t *signAlgorithms = CheckSupportSignAlgorithms(ctx, config->signAlgorithms,
        config->signAlgorithmsSize, &signAlgorithmsSize);
    if (signAlgorithms == NULL || signAlgorithmsSize == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17309, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "no available signAlgorithms", 0, 0, 0, 0);
        BSL_SAL_FREE(signAlgorithms);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH;
    }

    /* Calculate the extension length */
    exMsgHeaderLen = sizeof(uint16_t);
    exMsgDataLen = sizeof(uint16_t) * (uint16_t)signAlgorithmsSize;

    /* Pack the extension header */
    ret = PackExtensionHeader(HS_EX_TYPE_SIGNATURE_ALGORITHMS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(signAlgorithms);
        return ret;
    }

    /* Pack the extended signature algorithm. */
    (void)PackAppendUint16ToBuf(pkt, exMsgDataLen);

    for (uint32_t index = 0; index < signAlgorithmsSize; index++) {
        (void)PackAppendUint16ToBuf(pkt, signAlgorithms[index]);
    }
    BSL_SAL_FREE(signAlgorithms);

    /* Set the extension flag */
    ctx->hsCtx->extFlag.haveSignatureAlgorithms = true;

    return HITLS_SUCCESS;
}

static int32_t PackClientSupportedGroups(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if (config->groupsSize == 0) {
        return HITLS_SUCCESS;
    }

    if (config->groups == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15414, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack supported groups extension error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    ret = PackAppendUint16ToBuf(pkt, HS_EX_TYPE_SUPPORTED_GROUPS);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t extensionLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t groupLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &groupLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    bool haveGroup = false;
    for (uint32_t i = 0; i < config->groupsSize; ++i) {
        const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(&ctx->config.tlsConfig, config->groups[i]);
        if (groupInfo == NULL || ((groupInfo->versionBits & config->version) == 0)) {
            continue;
        }
        haveGroup = true;
        ret = PackAppendUint16ToBuf(pkt, config->groups[i]);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
    if (!haveGroup) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15076, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack supported groups extension error, no available group.", 0, 0, 0, 0);
        return HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP;
    }
    PackCloseUint16Field(pkt, groupLenPosition);
    PackCloseUint16Field(pkt, extensionLenPosition);
    /* Set the extension flag */
    ctx->hsCtx->extFlag.haveSupportedGroups = true;

    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_FEATURE_ALPN
static int32_t PackClientAlpnList(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgHeaderLen = 0u;
    uint8_t exMsgDataLen = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if (config->alpnListSize == 0) {
        return HITLS_SUCCESS;
    }

    if (config->alpnList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15416, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack alpn list extension error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Calculate the extension length */
    exMsgHeaderLen = sizeof(uint16_t);
    exMsgDataLen = (uint8_t)config->alpnListSize;

    ret = PackExtensionHeader(HS_EX_TYPE_APP_LAYER_PROTOCOLS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, exMsgDataLen);

    (void)PackAppendDataToBuf(pkt, config->alpnList, config->alpnListSize);
    /* Set the extension flag */
    ctx->hsCtx->extFlag.haveAlpn = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
static int32_t PackClientTicket(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint8_t *ticket = NULL;
    uint32_t ticketSize = 0;
    uint16_t sessVersion = HITLS_VERSION_TLS13;
    if (ctx->session != NULL) {
        HITLS_SESS_GetProtocolVersion(ctx->session, &sessVersion);
    }

    /* Whether the ticket belongs to tls1.3 needs to be determined */
    if (sessVersion != HITLS_VERSION_TLS13) {
        SESS_GetTicket(ctx->session, &ticket, &ticketSize);
    }
#ifdef HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET
    if (ctx->config.tlsConfig.maxVersion >= HITLS_VERSION_TLS10) {
        if (ticket == NULL || ticketSize == 0) {
            ticket = ctx->config.tlsConfig.sessionTicketExt;
            ticketSize = ctx->config.tlsConfig.sessionTicketExtSize;
        }
    }
#endif /* HITLS_TLS_FEATURE_SESSION_CUSTOM_TICKET */
    ret = PackExtensionHeader(HS_EX_TYPE_SESSION_TICKET, (uint16_t)ticketSize, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendDataToBuf(pkt, ticket, ticketSize);

    /* Set the extension flag. */
    ctx->hsCtx->extFlag.haveTicket = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static int32_t PackClientSecRenegoInfo(const TLS_Ctx *ctx, PackPacket *pkt)
{
    if (!ctx->negotiatedInfo.isRenegotiation) {
        return HITLS_SUCCESS;
    }

    /* Calculate the extension length */
    const uint8_t *clientData = ctx->negotiatedInfo.clientVerifyData;
    uint32_t clientDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
    uint16_t exMsgHeaderLen = sizeof(uint8_t);
    uint16_t exMsgDataLen = (uint16_t)clientDataSize;

    /* Pack the extension header */
    int32_t ret = PackExtensionHeader(HS_EX_TYPE_RENEGOTIATION_INFO, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the length of secRenegoInfo */
    (void)PackAppendUint8ToBuf(pkt, (uint8_t)clientDataSize);

    /* Pack the secRenegoInfo content */
    (void)PackAppendDataToBuf(pkt, clientData, clientDataSize);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
static bool IsNeedPackEcExtension(const TLS_Ctx *ctx)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);
#ifdef HITLS_TLS_PROTO_TLS13
    if ((config->maxVersion == HITLS_VERSION_TLS13)) {
        uint32_t needKeyShareMode = TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_DHE;
        if ((ctx->negotiatedInfo.tls13BasicKeyExMode & needKeyShareMode) != 0) {
            return true;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    for (uint32_t index = 0; index < config->cipherSuitesSize; index++) {
        CipherSuiteInfo cipherInfo = {0};
        /* The returned value does not need to be checked. The validity of the cipher suite is checked when the cipher
         * suite is configured */
        (void)CFG_GetCipherSuiteInfo(config->cipherSuites[index], &cipherInfo);

        /* The ECC algorithm suite exists */
        if ((cipherInfo.authAlg == HITLS_AUTH_ECDSA) ||
            (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDHE) ||
            (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDH) ||
            (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDHE_PSK)) {
            return true;
        }
    }

    return false;
}
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t PackClientSupportedVersions(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgHeaderLen = 0u;
    uint8_t exMsgDataLen = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);
    uint16_t minVersion = config->minVersion;
    uint16_t maxVersion = config->maxVersion;

    if (config->minVersion < HITLS_VERSION_SSL30 || config->maxVersion > HITLS_VERSION_TLS13) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15418, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack supported version  extension error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Calculate the extension length */
    exMsgHeaderLen = sizeof(uint8_t);
    exMsgDataLen = sizeof(uint16_t) * (maxVersion - minVersion + 1);

    ret = PackExtensionHeader(HS_EX_TYPE_SUPPORTED_VERSIONS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the TLS version supported by the extension */
    (void)PackAppendUint8ToBuf(pkt, exMsgDataLen);

    for (uint16_t version = maxVersion; version >= minVersion; version--) {
        (void)PackAppendUint16ToBuf(pkt, version);
    }

    /* Set the extension flag */
    ctx->hsCtx->extFlag.haveSupportedVers = true;

    return HITLS_SUCCESS;
}

static int32_t PackClientPskKeyExModes(const TLS_Ctx *ctx, PackPacket *pkt)
{
    bool allowOnly = false;
    bool allowDhe = false;
    const uint32_t configKxMode = ctx->config.tlsConfig.keyExchMode;
    uint16_t exMsgHeaderLen = sizeof(uint8_t);
    uint16_t exMsgDataLen = 0;

    if ((bool)(configKxMode & TLS13_KE_MODE_PSK_WITH_DHE)) {
        exMsgDataLen++;
        allowDhe = true;
    }
    if ((bool)(configKxMode & TLS13_KE_MODE_PSK_ONLY)) {
        exMsgDataLen++;
        allowOnly = true;
    }

    int32_t ret = PackExtensionHeader(HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the length of the key exchange pattern extension */
    (void)PackAppendUint8ToBuf(pkt, (uint8_t)exMsgDataLen);

    if (allowDhe) {
        (void)PackAppendUint8ToBuf(pkt, PSK_DHE_KE);
    }
    if (allowOnly) {
        (void)PackAppendUint8ToBuf(pkt, PSK_KE);
    }

    ctx->hsCtx->extFlag.havePskExMode = true;

    return HITLS_SUCCESS;
}

static int32_t PackClientKeyShare(const TLS_Ctx *ctx, PackPacket *pkt)
{
    uint32_t needKeyShareMode = TLS13_KE_MODE_PSK_WITH_DHE | TLS13_CERT_AUTH_WITH_DHE;
    if ((ctx->negotiatedInfo.tls13BasicKeyExMode & needKeyShareMode) == 0) {
        return HITLS_SUCCESS;
    }

    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;
    if (kxCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16939, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "kxCtx is null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    uint16_t keyShareLen = 0;

    KeyShareParam *keyShare = &(kxCtx->keyExchParam.share);
    uint32_t secondPubKeyLen = 0u;
    uint32_t pubKeyLen = SAL_CRYPT_GetCryptLength(ctx, HITLS_CRYPT_INFO_CMD_GET_PUBLIC_KEY_LEN, keyShare->group);
    if (pubKeyLen == 0u) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15422, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid keyShare length.", 0, 0, 0, 0);
        return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
    }

    keyShareLen += sizeof(uint16_t) + sizeof(uint16_t) + pubKeyLen;
    if (keyShare->secondGroup != HITLS_NAMED_GROUP_BUTT) {
        secondPubKeyLen = SAL_CRYPT_GetCryptLength(ctx, HITLS_CRYPT_INFO_CMD_GET_PUBLIC_KEY_LEN, keyShare->secondGroup);
        if (secondPubKeyLen == 0u) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15422, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "invalid keyShare length.", 0, 0, 0, 0);
            return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
        }
        keyShareLen += sizeof(uint16_t) + sizeof(uint16_t) + secondPubKeyLen;
    }

    int32_t ret = PackExtensionHeader(HS_EX_TYPE_KEY_SHARE, sizeof(uint16_t) + keyShareLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the total length of client_keyShare */
    (void)PackAppendUint16ToBuf(pkt, keyShareLen);

    /* Pack a group */
    (void)PackAppendUint16ToBuf(pkt, (uint16_t)keyShare->group);

    /* Length of the Pack KeyExChange */
    (void)PackAppendUint16ToBuf(pkt, (uint16_t)pubKeyLen);

    uint32_t pubKeyUsedLen = 0;
    uint8_t *pubKeyBuf = NULL;
    (void)PackReserveBytes(pkt, pubKeyLen, &pubKeyBuf);
    /* Pack KeyExChange */
    ret = SAL_CRYPT_EncodeEcdhPubKey(kxCtx->key, pubKeyBuf, pubKeyLen, &pubKeyUsedLen);
    if (ret != HITLS_SUCCESS || pubKeyUsedLen != pubKeyLen) {
        BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15423, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode client keyShare key fail.", 0, 0, 0, 0);
        return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
    }

    (void)PackSkipBytes(pkt, pubKeyUsedLen);

    if (keyShare->secondGroup != HITLS_NAMED_GROUP_BUTT) {
        (void)PackAppendUint16ToBuf(pkt, (uint16_t)keyShare->secondGroup);
        (void)PackAppendUint16ToBuf(pkt, (uint16_t)secondPubKeyLen);
        uint8_t *secondPubKeyBuf = NULL;
        (void)PackReserveBytes(pkt, secondPubKeyLen, &secondPubKeyBuf);
        ret = SAL_CRYPT_EncodeEcdhPubKey(kxCtx->secondKey, secondPubKeyBuf, secondPubKeyLen, &pubKeyUsedLen);
        if (ret != HITLS_SUCCESS || pubKeyUsedLen != secondPubKeyLen) {
            BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15423, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "encode client keyShare key fail.", 0, 0, 0, 0);
            return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
        }
        (void)PackSkipBytes(pkt, pubKeyUsedLen);
    }
    ctx->hsCtx->extFlag.haveKeyShare = true;
    return HITLS_SUCCESS;
}

static uint32_t GetPreSharedKeyExtLen(const PskInfo13 *pskInfo)
{
    uint32_t extLen =  HS_EX_HEADER_LEN;
    uint32_t binderLen = 0;
    if (pskInfo->resumeSession != NULL) {
        HITLS_HashAlgo hashAlg = HITLS_HASH_BUTT;
        binderLen = HS_GetBinderLen(pskInfo->resumeSession, &hashAlg);
        if (binderLen == 0) {
            return 0;
        }
        uint8_t *ticket = NULL;
        uint32_t ticketSize = 0;
        SESS_GetTicket(pskInfo->resumeSession, &ticket, &ticketSize);
        extLen += sizeof(uint16_t) + ticketSize + sizeof(uint32_t) + sizeof(uint8_t) + binderLen;
    }

    if (pskInfo->userPskSess != NULL) {
        HITLS_HashAlgo hashAlg = HITLS_HASH_BUTT;
        binderLen = HS_GetBinderLen(pskInfo->userPskSess->pskSession, &hashAlg);
        if (binderLen == 0) {
            return 0;
        }
        extLen += sizeof(uint16_t) + pskInfo->userPskSess->identityLen + sizeof(uint32_t) + sizeof(uint8_t) + binderLen;
    }
    extLen += sizeof(uint16_t) + sizeof(uint16_t);
    return extLen;
}

static void PackClientPreSharedKeyIdentity(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen)
{
    PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    uint32_t offset = 0;
    uint32_t offsetStamp = offset;
    offset += sizeof(uint16_t); // skip identities len
    if (pskInfo->resumeSession != NULL) {
        uint8_t *ticket = NULL;
        uint32_t ticketSize = 0;
        SESS_GetTicket(pskInfo->resumeSession, &ticket, &ticketSize);
        BSL_Uint16ToByte((uint16_t)ticketSize, &buf[offset]);
        offset += sizeof(uint16_t);
        // has passed the verification above, and it must be successful here.
        (void)memcpy_s(&buf[offset], bufLen - offset, ticket, ticketSize);
        offset += ticketSize;
        uint32_t ageSec = (uint32_t)((uint64_t)BSL_SAL_CurrentSysTimeGet() - SESS_GetStartTime(pskInfo->resumeSession));

        uint32_t agemSec = ageSec * 1000 + (uint32_t)SESS_GetTicketAgeAdd(pskInfo->resumeSession);       /* unit: ms */
        BSL_Uint32ToByte(agemSec, &buf[offset]);
        offset += sizeof(uint32_t);
    }

    if (pskInfo->userPskSess != NULL) {
        BSL_Uint16ToByte((uint16_t)pskInfo->userPskSess->identityLen, &buf[offset]);
        offset += sizeof(uint16_t);
        (void)memcpy_s(&buf[offset], bufLen - offset,
            // has passed the verification above, and it must be successful here
            pskInfo->userPskSess->identity, pskInfo->userPskSess->identityLen);
        offset += pskInfo->userPskSess->identityLen;
        BSL_Uint32ToByte(0, &buf[offset]);
        offset += sizeof(uint32_t);
    }
    BSL_Uint16ToByte((uint16_t)(offset - offsetStamp - sizeof(uint16_t)), &buf[offsetStamp]);
}

// ClientPreSharedKey: pskid, binder, see rfc 8446 section 4.2.11, currently support one pskid and one binder
static int32_t PackClientPreSharedKey(const TLS_Ctx *ctx, PackPacket *pkt)
{
    PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    if (pskInfo->resumeSession == NULL && pskInfo->userPskSess == NULL) {
        return HITLS_SUCCESS;
    }
    uint32_t minLen = GetPreSharedKeyExtLen(pskInfo);
    if (minLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_PRE_SHARED_KEY_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15939, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Binder size is zero when PackClientPreSharedKey", 0, 0, 0, 0);
        return HITLS_PACK_PRE_SHARED_KEY_ERR;
    }
    int32_t ret = PackExtensionHeader(HS_EX_TYPE_PRE_SHARED_KEY, (uint16_t)(minLen - HS_EX_HEADER_LEN), pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t *pskBuf = NULL;
    ret = PackReserveBytes(pkt, minLen - HS_EX_HEADER_LEN, &pskBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = PackSkipBytes(pkt, minLen - HS_EX_HEADER_LEN);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    PackClientPreSharedKeyIdentity(ctx, pskBuf, minLen - HS_EX_HEADER_LEN);

    // pack binder after fills in the packet header and extension length. call PackClientPreSharedKeyBinders
    ctx->hsCtx->extFlag.havePreShareKey = true;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
int32_t PackClientCAList(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);
    int32_t ret = PackAppendUint16ToBuf(pkt, HS_EX_TYPE_CERTIFICATE_AUTHORITIES);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint32_t extensionLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t caLenPosition = 0u;
    ret = PackStartLengthField(pkt, sizeof(uint16_t), &caLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackTrustedCAList(config->caList, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    PackCloseUint16Field(pkt, caLenPosition);
    PackCloseUint16Field(pkt, extensionLenPosition);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */

#ifdef HITLS_TLS_FEATURE_PHA
static bool IsNeedPackPha(const TLS_Ctx *ctx)
{
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    if (tlsConfig->maxVersion != HITLS_VERSION_TLS13) {
        return false;
    }
    return tlsConfig->isSupportPostHandshakeAuth;
}
#endif /* HITLS_TLS_FEATURE_PHA */
#endif /* HITLS_TLS_PROTO_TLS13 */

// Pack the non-null extension of client hello.
static int32_t PackClientExtensions(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    (void)tlsConfig;
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    const TLS_NegotiatedInfo *negoInfo = &ctx->negotiatedInfo;
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
#ifdef HITLS_TLS_PROTO_TLS13
    bool isTls13 = (tlsConfig->maxVersion == HITLS_VERSION_TLS13);
#endif /* HITLS_TLS_PROTO_TLS13 */
    /* Check whether EC extensions need to be filled */
    bool isEcNeed = IsNeedPackEcExtension(ctx);

    /* If the version is earlier than tls1.2, the signature extension cannot be sent */
    bool isSignAlgNeed = (ctx->config.tlsConfig.maxVersion >= HITLS_VERSION_TLS12);
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
    /* Do not send the sessionticket in the PTO scenario */
    bool isSessionTicketNeed = IsTicketSupport(ctx);
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_PHA
    bool isNeedPha = IsNeedPackPha(ctx);
#endif /* HITLS_TLS_FEATURE_PHA */
    PackExtInfo extMsgList[] = {
#ifdef HITLS_TLS_FEATURE_SNI
        { EXTENSION_MSG(HS_EX_TYPE_SERVER_NAME, IsNeedClientPackServerName(ctx), PackServerName) },
#endif /* HITLS_TLS_FEATURE_SNI */
        { EXTENSION_MSG(HS_EX_TYPE_SIGNATURE_ALGORITHMS, isSignAlgNeed, PackClientSignatureAlgorithms) },
        { EXTENSION_MSG(HS_EX_TYPE_SUPPORTED_GROUPS, isEcNeed, PackClientSupportedGroups) },
        { EXTENSION_MSG(HS_EX_TYPE_POINT_FORMATS, isEcNeed, PackPointFormats) },
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_SUPPORTED_VERSIONS, isTls13, PackClientSupportedVersions) },
#endif /* HITLS_TLS_PROTO_TLS13 */
        { EXTENSION_MSG(HS_EX_TYPE_EARLY_DATA, false, NULL) },
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_COOKIE, isTls13, PackCookie) },
#ifdef HITLS_TLS_FEATURE_PHA
        { EXTENSION_MSG(HS_EX_TYPE_POST_HS_AUTH, isNeedPha, NULL) },
#endif /* HITLS_TLS_FEATURE_PHA */
#endif /* HITLS_TLS_PROTO_TLS13 */
        { EXTENSION_MSG(HS_EX_TYPE_EXTENDED_MASTER_SECRET, true, NULL) },
#ifdef HITLS_TLS_FEATURE_ALPN
        { EXTENSION_MSG(HS_EX_TYPE_APP_LAYER_PROTOCOLS, (tlsConfig->alpnList != NULL &&
            ctx->state == CM_STATE_HANDSHAKING), PackClientAlpnList) },
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES, isTls13, PackClientPskKeyExModes) },
        { EXTENSION_MSG(HS_EX_TYPE_KEY_SHARE, isTls13, PackClientKeyShare) },
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
        { EXTENSION_MSG(HS_EX_TYPE_CERTIFICATE_AUTHORITIES, isTls13 && tlsConfig->caList != NULL, PackClientCAList) },
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
        { EXTENSION_MSG(HS_EX_TYPE_RENEGOTIATION_INFO, negoInfo->isSecureRenegotiation, PackClientSecRenegoInfo) },
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        { EXTENSION_MSG(HS_EX_TYPE_SESSION_TICKET, isSessionTicketNeed, PackClientTicket) },
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
#ifdef HITLS_TLS_FEATURE_ETM
        { EXTENSION_MSG(HS_EX_TYPE_ENCRYPT_THEN_MAC, tlsConfig->isEncryptThenMac, NULL) },
#endif /* HITLS_TLS_FEATURE_ETM */
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_PRE_SHARED_KEY, IsNeedPreSharedKey(ctx), PackClientPreSharedKey) },
#endif /* HITLS_TLS_PROTO_TLS13 */
    };

#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsPackNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), HITLS_EX_TYPE_CLIENT_HELLO)) {
        ret = PackCustomExtensions(ctx, pkt, HITLS_EX_TYPE_CLIENT_HELLO, NULL, 0);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */

    ret = PackExtensions(ctx, pkt, extMsgList, sizeof(extMsgList) / sizeof(extMsgList[0]));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_PHA
    ctx->hsCtx->extFlag.havePostHsAuth = isNeedPha;
#endif /* HITLS_TLS_FEATURE_PHA */
    ctx->hsCtx->extFlag.haveExtendedMasterSecret = true;
#ifdef HITLS_TLS_FEATURE_ETM
    ctx->hsCtx->extFlag.haveEncryptThenMac = ctx->config.tlsConfig.isEncryptThenMac;
#endif /* HITLS_TLS_FEATURE_ETM */
    return HITLS_SUCCESS;
}

// Pack the Client Hello extension
int32_t PackClientExtension(const TLS_Ctx *ctx, PackPacket *pkt)
{
    uint32_t extensionLenPosition = 0u;
    int32_t ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the client hello extension content */
    ret = PackClientExtensions(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return PackExtensionEnd(pkt, extensionLenPosition);
}
#endif /* HITLS_TLS_HOST_CLIENT */
#ifdef HITLS_TLS_HOST_SERVER
static bool IsServerNeedPackEcExtension(const TLS_Ctx *ctx)
{
    const TLS_NegotiatedInfo *negotiatedInfo = &(ctx->negotiatedInfo);
    CipherSuiteInfo cipherInfo = negotiatedInfo->cipherSuiteInfo;

    /* The negotiated algorithm suite is the ECC cipher suite */
    if (((cipherInfo.authAlg == HITLS_AUTH_ECDSA) || (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDHE) ||
        (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDH) || (cipherInfo.kxAlg == HITLS_KEY_EXCH_ECDHE_PSK)) &&
        ctx->haveClientPointFormats == true) {
        return true;
    }

    return false;
}
#ifdef HITLS_TLS_FEATURE_ALPN
int32_t PackServerSelectAlpnProto(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgHeaderLen = 0u;
    uint8_t exMsgDataLen = 0u;

    if (ctx->negotiatedInfo.alpnSelectedSize == 0) {
        return HITLS_SUCCESS;
    }

    /* Calculate the extension length */
    exMsgHeaderLen = sizeof(uint16_t);
    exMsgDataLen = (uint8_t)ctx->negotiatedInfo.alpnSelectedSize + sizeof(uint8_t);

    /* Pack the extension header */
    ret = PackExtensionHeader(HS_EX_TYPE_APP_LAYER_PROTOCOLS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, (uint16_t)exMsgDataLen);

    (void)PackAppendUint8ToBuf(pkt, exMsgDataLen - sizeof(uint8_t));

    (void)PackAppendDataToBuf(pkt, ctx->negotiatedInfo.alpnSelected, ctx->negotiatedInfo.alpnSelectedSize);

    /* Set the extension flag */
    ctx->hsCtx->extFlag.haveAlpn = true;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t PackHrrKeyShare(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgDataLen = 0u;
    KeyShareParam *keyShare = &(ctx->hsCtx->kxCtx->keyExchParam.share);

    /* Message length = group length */
    exMsgDataLen = sizeof(uint16_t);

    ret = PackExtensionHeader(HS_EX_TYPE_KEY_SHARE, exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack a group */
    (void)PackAppendUint16ToBuf(pkt, (uint16_t)keyShare->group);

    ctx->hsCtx->extFlag.haveKeyShare = true;
    return HITLS_SUCCESS;
}

static int32_t PackServerKeyShare(const TLS_Ctx *ctx, PackPacket *pkt)
{
    KeyShareParam *keyShare = &(ctx->hsCtx->kxCtx->keyExchParam.share);
    KeyExchCtx *kxCtx = ctx->hsCtx->kxCtx;

    /* If the peer public key does not exist, the psk_only mode is used. In this case, the key share does not need to be
     * sent */
    if (kxCtx->peerPubkey == NULL) {
        return HITLS_SUCCESS;
    }
    const TLS_GroupInfo *groupInfo = ConfigGetGroupInfo(&ctx->config.tlsConfig, ctx->negotiatedInfo.negotiatedGroup);
    if (groupInfo == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16246, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "group info not found", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    uint32_t pubKeyLen = groupInfo->isKem ? groupInfo->ciphertextLen : groupInfo->pubkeyLen;
    if (pubKeyLen == 0u || (groupInfo->isKem && pubKeyLen != kxCtx->ciphertextLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_INVALID_KX_PUBKEY_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15428, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "invalid keyShare length.", 0, 0, 0, 0);
        return HITLS_PACK_INVALID_KX_PUBKEY_LENGTH;
    }

    /* Length of group + Length of KeyExChange + KeyExChange */
    uint16_t exMsgDataLen = sizeof(uint16_t) + sizeof(uint16_t) + (uint16_t)pubKeyLen;
    int32_t ret = PackReserveBytes(pkt, exMsgDataLen + HS_EX_HEADER_LEN, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackExtensionHeader(HS_EX_TYPE_KEY_SHARE, exMsgDataLen, pkt);

    /* Pack a group */
    (void)PackAppendUint16ToBuf(pkt, (uint16_t)keyShare->group);

    /* Length of the paced KeyExChange */
    (void)PackAppendUint16ToBuf(pkt, (uint16_t)pubKeyLen);

    if (groupInfo->isKem) {
        ret = PackAppendDataToBuf(pkt, kxCtx->ciphertext, kxCtx->ciphertextLen);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    } else {
        uint8_t *pubKeyBuf = NULL;
        uint32_t pubKeyUsedLen = 0;
        (void)PackReserveBytes(pkt, pubKeyLen, &pubKeyBuf);

        ret = SAL_CRYPT_EncodeEcdhPubKey(kxCtx->key, pubKeyBuf, pubKeyLen, &pubKeyUsedLen);
        if (ret != HITLS_SUCCESS || pubKeyLen != pubKeyUsedLen) {
            BSL_ERR_PUSH_ERROR(HITLS_CRYPT_ERR_ENCODE_ECDH_KEY);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15429, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "encode server keyShare key fail.", 0, 0, 0, 0);
            return HITLS_CRYPT_ERR_ENCODE_ECDH_KEY;
        }
        (void)PackSkipBytes(pkt, pubKeyUsedLen);
    }

    ctx->hsCtx->extFlag.haveKeyShare = true;
    return HITLS_SUCCESS;
}

static int32_t PackServerSupportedVersion(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t exMsgDataLen = 0u;
    const uint16_t supportedVersion = ctx->negotiatedInfo.version;

    if (supportedVersion <= 0) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15430, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack supported version extension error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Calculate the extension length */
    exMsgDataLen = sizeof(uint16_t);

    ret = PackExtensionHeader(HS_EX_TYPE_SUPPORTED_VERSIONS, exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, supportedVersion);

    ctx->hsCtx->extFlag.haveSupportedVers = true;

    return HITLS_SUCCESS;
}

static int32_t IsHrrKeyShare(const TLS_Ctx *ctx)
{
    bool haveHrr = ctx->hsCtx->haveHrr; /* Sent or in the process of sending hrr */
    bool haveKeyShare = ctx->hsCtx->extFlag.haveKeyShare; /* has packed the keyshare */

    if (haveHrr && !haveKeyShare) {
        return true;
    }
    return false;
}

static int32_t PackServerPreSharedKey(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const PskInfo13 *pskInfo = &ctx->hsCtx->kxCtx->pskInfo13;
    if (pskInfo->psk == NULL) {
        return HITLS_SUCCESS;
    }
    int32_t ret = PackExtensionHeader(HS_EX_TYPE_PRE_SHARED_KEY, sizeof(uint16_t), pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, (uint16_t)pskInfo->selectIndex);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t PackServerSecRenegoInfo(const TLS_Ctx *ctx, PackPacket *pkt)
{
    bool isRenegotiation = ctx->negotiatedInfo.isRenegotiation;
    const uint8_t *clientData = ctx->negotiatedInfo.clientVerifyData;
    uint32_t clientDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
    const uint8_t *serverData = ctx->negotiatedInfo.serverVerifyData;
    uint32_t serverDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
    /* Calculate the extension length */
    uint16_t exMsgHeaderLen = sizeof(uint8_t);
    /* For renegotiation, the verify data (client data + server data) must be assembled */
    uint16_t exMsgDataLen = (uint16_t)(isRenegotiation ? (clientDataSize + serverDataSize) : 0);

    int32_t ret = PackExtensionHeader(HS_EX_TYPE_RENEGOTIATION_INFO, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (!isRenegotiation) {
        (void)PackAppendUint8ToBuf(pkt, 0);
        return HITLS_SUCCESS;
    }

    /* Pack the length of secRenegoInfo */
    (void)PackAppendUint8ToBuf(pkt, (uint8_t)(clientDataSize + serverDataSize));

    /* Pack the secRenegoInfo content */
    (void)PackAppendDataToBuf(pkt, clientData, clientDataSize);

    (void)PackAppendDataToBuf(pkt, serverData, serverDataSize);

    return HITLS_SUCCESS;
}
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_SNI
static bool IsNeedServerPackServerName(const TLS_Ctx *ctx)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);
    const TLS_NegotiatedInfo *negoInfo = &ctx->negotiatedInfo;

    /* The protocol version is earlier than tls1.3 and the server accepts the server name. The server hello message sent
     * by the server contains an empty server name extension */
    if (negoInfo->isSniStateOK &&
        (config->maxVersion < HITLS_VERSION_TLS13 || config->maxVersion == HITLS_VERSION_DTLS12)) {
        return true;
    }
    return false;
}
#endif /* HITLS_TLS_FEATURE_SNI */
#ifdef HITLS_TLS_FEATURE_ETM
static bool IsNeedServerPackEncryptThenMac(const TLS_Ctx *ctx)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);
    const TLS_NegotiatedInfo *negoInfo = &ctx->negotiatedInfo;
    if (config->isEncryptThenMac && negoInfo->isEncryptThenMac) {
        return true;
    }
    return false;
}
#endif /* HITLS_TLS_FEATURE_ETM */
// Pack the empty extension of Server Hello
static int32_t PackServerExtensions(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_PROTO_TLS13
    uint32_t version = HS_GetVersion(ctx);
    bool isHrrKeyshare = IsHrrKeyShare(ctx);
    bool isTls13 = Tls13NeedPack(ctx, version);
#endif /* HITLS_TLS_PROTO_TLS13 */
    const TLS_NegotiatedInfo *negoInfo = &ctx->negotiatedInfo;
    (void)negoInfo;
    PackExtInfo extMsgList[] = {
#ifdef HITLS_TLS_FEATURE_SNI
        { EXTENSION_MSG(HS_EX_TYPE_SERVER_NAME, IsNeedServerPackServerName(ctx), NULL) },
#endif /* HITLS_TLS_FEATURE_SNI */
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_COOKIE, isTls13, PackCookie) },
#endif /* HITLS_TLS_PROTO_TLS13 */
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
        { EXTENSION_MSG(HS_EX_TYPE_SESSION_TICKET, negoInfo->isTicket, NULL) },
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */
        { EXTENSION_MSG(HS_EX_TYPE_POINT_FORMATS, IsServerNeedPackEcExtension(ctx), PackPointFormats) },
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_SUPPORTED_VERSIONS, isTls13, PackServerSupportedVersion) },
#endif /* HITLS_TLS_PROTO_TLS13 */
        { EXTENSION_MSG(HS_EX_TYPE_EXTENDED_MASTER_SECRET, negoInfo->isExtendedMasterSecret, NULL) },
#ifdef HITLS_TLS_FEATURE_ALPN
        { .exMsgType = HS_EX_TYPE_APP_LAYER_PROTOCOLS,
          .needPack = (negoInfo->alpnSelected != NULL
#ifdef HITLS_TLS_PROTO_TLS13
            && !isTls13
#endif
            ),
          .packFunc = PackServerSelectAlpnProto },
#endif /* HITLS_TLS_FEATURE_ALPN */
#ifdef HITLS_TLS_PROTO_TLS13
        { EXTENSION_MSG(HS_EX_TYPE_KEY_SHARE, (isTls13 && !isHrrKeyshare), PackServerKeyShare) },
        { EXTENSION_MSG(HS_EX_TYPE_KEY_SHARE, (isTls13 && isHrrKeyshare), PackHrrKeyShare) },
#endif /* HITLS_TLS_PROTO_TLS13 */
#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
        { EXTENSION_MSG(HS_EX_TYPE_RENEGOTIATION_INFO, negoInfo->isSecureRenegotiation, PackServerSecRenegoInfo) },
#endif /* defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12) */
#ifdef HITLS_TLS_FEATURE_ETM
        { EXTENSION_MSG(HS_EX_TYPE_ENCRYPT_THEN_MAC, IsNeedServerPackEncryptThenMac(ctx), NULL) },
#endif /* HITLS_TLS_FEATURE_ETM */
#ifdef HITLS_TLS_PROTO_TLS13
        /* The preshare key must be the last extension */
        { EXTENSION_MSG(HS_EX_TYPE_PRE_SHARED_KEY, IsNeedPreSharedKey(ctx), PackServerPreSharedKey) },
#endif /* HITLS_TLS_PROTO_TLS13 */
    };
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    uint32_t context = 0;
#ifdef HITLS_TLS_PROTO_TLS13
    if (isTls13) {
        if (isHrrKeyshare) {
            context = HITLS_EX_TYPE_HELLO_RETRY_REQUEST;
        } else {
            context = HITLS_EX_TYPE_TLS1_3_SERVER_HELLO;
        }
    } else
#endif
    {
        context = HITLS_EX_TYPE_TLS1_2_SERVER_HELLO;
    }

    if (IsPackNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), context)) {
        ret = PackCustomExtensions(ctx, pkt, context, NULL, 0);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */

    ret = PackExtensions(ctx, pkt, extMsgList, sizeof(extMsgList) / sizeof(extMsgList[0]));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_SUCCESS;
}

// Pack the Server Hello extension
int32_t PackServerExtension(const TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Obtain the packet header length */
    uint32_t extensionLenPosition = 0u;
    int32_t ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the server hello extension content */
    ret = PackServerExtensions(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return PackExtensionEnd(pkt, extensionLenPosition);
}
#endif /* HITLS_TLS_HOST_SERVER */
