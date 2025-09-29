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
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "tls.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_security.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "cipher_suite.h"
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack_extensions.h"
#include "hs_common.h"

#define SINGLE_CIPHER_SUITE_SIZE 2u
#define CIPHER_SUITES_LEN_SIZE   2u

// Pack the version content of the client Hello message.
static int32_t PackClientVersion(const TLS_Ctx *ctx, uint16_t version, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    (void)bufLen;
    (void)ctx;
    uint32_t offset = 0u;
#ifdef HITLS_TLS_FEATURE_SECURITY
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    int32_t ret = SECURITY_CfgCheck((const HITLS_Config *)tlsConfig, HITLS_SECURITY_SECOP_VERSION, 0, version, NULL);
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16924, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CfgCheck fail, ret %d", ret, 0, 0, 0);
        ctx->method.sendAlert((TLS_Ctx *)(uintptr_t)ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSECURE_VERSION);
        return HITLS_PACK_UNSECURE_VERSION;
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    BSL_Uint16ToByte(version, &buf[offset]);
    offset += sizeof(uint16_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_PROTO_DTLS12
// Pack the cookie content of the client Hello message.
static int32_t PackClientCookie(const uint8_t *cookie, uint8_t cookieLen,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;

    if (bufLen < (sizeof(uint8_t) + cookieLen)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_COOKIE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15730, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of cookie is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_COOKIE_ERR;
    }

    buf[offset] = cookieLen;
    offset += sizeof(uint8_t);
    if (cookieLen == 0u) {
        *usedLen = offset;
        return HITLS_SUCCESS;
    }

    (void)memcpy_s(&buf[offset], bufLen - offset, cookie, cookieLen);
    offset += cookieLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 */
static int32_t PackCipherSuites(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *offset, bool isTls13)
{
    uint16_t *cipherSuites = NULL;
    uint32_t cipherSuitesSize = 0;
    uint32_t tmpOffset = *offset;
#ifdef HITLS_TLS_PROTO_TLS13
    if (isTls13) {
        cipherSuites = ctx->config.tlsConfig.tls13CipherSuites;
        cipherSuitesSize = ctx->config.tlsConfig.tls13cipherSuitesSize;
    } else {
        cipherSuites = ctx->config.tlsConfig.cipherSuites;
        cipherSuitesSize = ctx->config.tlsConfig.cipherSuitesSize;
    }
#else
    (void)isTls13;
    cipherSuites = ctx->config.tlsConfig.cipherSuites;
    cipherSuitesSize = ctx->config.tlsConfig.cipherSuitesSize;
#endif /* HITLS_TLS_PROTO_TLS13 */

    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        if (!IsCipherSuiteAllowed(ctx, cipherSuites[i], false)) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15845, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                "The cipher suite [0x%04x] is NOT supported, index=[%u].", cipherSuites[i], i, 0, 0);
            continue;
        }
        if (tmpOffset + sizeof(uint16_t) > bufLen) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15733, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack cipher suite error, the buffer length is not enough.", 0, 0, 0, 0);
            return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
        }
        BSL_Uint16ToByte(cipherSuites[i], &buf[tmpOffset]);
        tmpOffset += sizeof(uint16_t);
    }

    *offset = tmpOffset;
    return HITLS_SUCCESS;
}

static int32_t PackScsvCipherSuites(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t tmpOffset = *offset;
    /* If the local is not in the renegotiation state, the SCSV algorithm set needs to be packed. */
    if (!ctx->negotiatedInfo.isRenegotiation) {
        if (tmpOffset + sizeof(uint16_t) > bufLen) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15338, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack cipher suite error, the buffer length is not enough.", 0, 0, 0, 0);
            return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
        }
        BSL_Uint16ToByte(TLS_EMPTY_RENEGOTIATION_INFO_SCSV, &buf[tmpOffset]);
        tmpOffset += sizeof(uint16_t);
    }
#ifdef HITLS_TLS_FEATURE_MODE_FALL_BACK_SCSV
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_SEND_FALLBACK_SCSV) != 0) {
        if (tmpOffset + sizeof(uint16_t) > bufLen) {
            BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15337, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack cipher suite error, the buffer length is not enough.", 0, 0, 0, 0);
            return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
        }
        BSL_Uint16ToByte(TLS_FALLBACK_SCSV, &buf[tmpOffset]);
        tmpOffset += sizeof(uint16_t);
    }
#endif
    *offset = tmpOffset;
    return HITLS_SUCCESS;
}

// Pack the cipher suites content of the client hello message.
static int32_t PackClientCipherSuites(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint16_t cipherSuitesLen = 0u;
    /* Finally fill in the length of the cipher suites */
    uint32_t offset = CIPHER_SUITES_LEN_SIZE;
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) {
        ret = PackCipherSuites(ctx, buf, bufLen, &offset, 1);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16925, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PackCipherSuites fail", 0, 0, 0, 0);
            return ret;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    if (ctx->config.tlsConfig.minVersion != HITLS_VERSION_TLS13) {
        ret = PackCipherSuites(ctx, buf, bufLen, &offset, 0);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16926, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PackCipherSuites fail", 0, 0, 0, 0);
            return ret;
        }
    }

    if (offset == SINGLE_CIPHER_SUITE_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15732, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack cipher suite error, no cipher suite.", 0, 0, 0, 0);
        return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
    }

    ret = PackScsvCipherSuites(ctx, buf, bufLen, &offset);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* The cipher suite has been filled. Each cipher suite takes two bytes, so the length of the filled cipher suite can
     * be calculated according to offset */
    cipherSuitesLen = (uint16_t)(offset - CIPHER_SUITES_LEN_SIZE);
    BSL_Uint16ToByte(cipherSuitesLen, &buf[0]);
    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the content of the method for compressing the client Hello message.
static int32_t PackClientCompressionMethod(uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;

    if (bufLen < sizeof(uint8_t) + sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15734, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack compression method error, the buffer length is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    buf[offset] = 1;
    offset += sizeof(uint8_t);
    buf[offset] = 0;           /* Compression methods Currently support uncompressed */
    offset += sizeof(uint8_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the session and cookie content of the client hello message.
static int32_t PackSessionAndCookie(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t len = 0;
    (void)len;
    (void)ret;
    (void)ctx;
    (void)bufLen;
#if defined(HITLS_TLS_FEATURE_SESSION_ID) || defined(HITLS_TLS_PROTO_TLS13)
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    len = 0u;
    ret = PackSessionId(hsCtx->sessionId, hsCtx->sessionIdSize, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        (void)memset_s(hsCtx->sessionId, hsCtx->sessionIdSize, 0, hsCtx->sessionIdSize);
        return ret;
    }
    offset += len;
#else // Session recovery is not supported.
    /* SessionId (Session is not supported yet and the length field is initialized with a value of 0) */
    buf[offset] = 0;
    offset += sizeof(uint8_t);
#endif

#ifdef HITLS_TLS_PROTO_DTLS12
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    if (IS_SUPPORT_DATAGRAM(tlsConfig->originVersionMask)) {
        len = 0u;
        ret = PackClientCookie(ctx->negotiatedInfo.cookie, (uint8_t)ctx->negotiatedInfo.cookieSize,
            &buf[offset], bufLen - offset, &len);
        if (ret != HITLS_SUCCESS) {
            (void)memset_s(ctx->negotiatedInfo.cookie, ctx->negotiatedInfo.cookieSize,
                           0, ctx->negotiatedInfo.cookieSize);
            return ret;
        }
        offset += len;
    }
#endif

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the mandatory content of the ClientHello message.
static int32_t PackClientHelloMandatoryField(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    /* The bufLen must be able to assemble at least the version number (2 bytes),
       random number (32 bytes), and session ID (1 byte) */
    if (bufLen < (sizeof(uint16_t) + HS_RANDOM_SIZE + sizeof(uint8_t))) {
        return PackBufLenError(BINLOG_ID16078, BINGLOG_STR("client hello"));
    }
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t len = 0u;
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    if (ctx->hsCtx->clientRandom == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16927, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "clientRandom null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    uint16_t version =
#ifdef HITLS_TLS_PROTO_TLS13
    (tlsConfig->maxVersion == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 :
#endif
     tlsConfig->maxVersion;
    ret = PackClientVersion(ctx, version, buf, bufLen, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    (void)memcpy_s(&buf[offset], bufLen - offset, ctx->hsCtx->clientRandom, HS_RANDOM_SIZE);
    offset += HS_RANDOM_SIZE;

    len = 0u;
    ret = PackSessionAndCookie(ctx, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    len = 0u;
    ret = PackClientCipherSuites(ctx, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    len = 0u;
    ret = PackClientCompressionMethod(&buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the ClientHello message to form the Handshake body.
int32_t PackClientHello(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t msgLen = 0u;
    uint32_t exMsgLen = 0u;

    ret = PackClientHelloMandatoryField(ctx, buf, bufLen, &msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15735, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += msgLen;
    exMsgLen = 0u;
    ret = PackClientExtension(ctx, &buf[offset], bufLen - offset, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15736, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello extension content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += exMsgLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}

#endif /* HITLS_TLS_HOST_CLIENT */