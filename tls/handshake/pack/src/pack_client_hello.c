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
#include "hitls_error.h"
#include "hitls_security.h"
#include "cipher_suite.h"
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack_extensions.h"
#include "hs_common.h"

#define CIPHER_SUITES_LEN_SIZE   2u

#ifdef HITLS_TLS_PROTO_DTLS12
// Pack the cookie content of the client Hello message.
static int32_t PackClientCookie(PackPacket *pkt, const uint8_t *cookie, uint8_t cookieLen)
{
    int32_t ret = PackAppendUint8ToBuf(pkt, cookieLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (cookieLen == 0u) {
        return HITLS_SUCCESS;
    }
    return PackAppendDataToBuf(pkt, cookie, cookieLen);
}
#endif /* HITLS_TLS_PROTO_DTLS12 */
static int32_t PackCipherSuites(const TLS_Ctx *ctx, PackPacket *pkt, bool isTls13)
{
    uint16_t *cipherSuites = NULL;
    uint32_t cipherSuitesSize = 0;
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

    int32_t ret = HITLS_SUCCESS;
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        if (!IsCipherSuiteAllowed(ctx, cipherSuites[i], false)) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15845, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
                "The cipher suite [0x%04x] is NOT supported, index=[%u].", cipherSuites[i], i, 0, 0);
            continue;
        }
        ret = PackAppendUint16ToBuf(pkt, cipherSuites[i]);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

static int32_t PackScsvCipherSuites(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    /* If the local is not in the renegotiation state, the SCSV algorithm set needs to be packed. */
    if (!ctx->negotiatedInfo.isRenegotiation) {
        ret = PackAppendUint16ToBuf(pkt, TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#ifdef HITLS_TLS_FEATURE_MODE_FALL_BACK_SCSV
    if ((ctx->config.tlsConfig.modeSupport & HITLS_MODE_SEND_FALLBACK_SCSV) != 0) {
        ret = PackAppendUint16ToBuf(pkt, TLS_FALLBACK_SCSV);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif
    return HITLS_SUCCESS;
}

// Pack the cipher suites content of the client hello message.
static int32_t PackClientCipherSuites(const TLS_Ctx *ctx, PackPacket *pkt)
{
    uint32_t cipherLenPosition = 0u;
    /* Finally fill in the length of the cipher suites */
    int32_t ret = PackStartLengthField(pkt, CIPHER_SUITES_LEN_SIZE, &cipherLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) {
        ret = PackCipherSuites(ctx, pkt, 1);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16925, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PackCipherSuites fail", 0, 0, 0, 0);
            return ret;
        }
    }
#endif /* HITLS_TLS_PROTO_TLS13 */
    if (ctx->config.tlsConfig.minVersion != HITLS_VERSION_TLS13) {
        ret = PackCipherSuites(ctx, pkt, 0);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16926, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "PackCipherSuites fail", 0, 0, 0, 0);
            return ret;
        }
    }

    uint32_t suitesLength = 0;
    ret = PackGetSubBuffer(pkt, cipherLenPosition, &suitesLength, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (suitesLength == CIPHER_SUITES_LEN_SIZE) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15732, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack cipher suite error, no cipher suite.", 0, 0, 0, 0);
        return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR;
    }

    ret = PackScsvCipherSuites(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* The cipher suite has been filled. Each cipher suite takes two bytes, so the length of the filled cipher suite can
     * be calculated according to offset */
    PackCloseUint16Field(pkt, cipherLenPosition);
    return HITLS_SUCCESS;
}

// Pack the content of the method for compressing the client Hello message.
static int32_t PackClientCompressionMethod(PackPacket *pkt)
{
    int32_t ret = PackAppendUint8ToBuf(pkt, 1);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Compression methods Currently support uncompressed */
    return PackAppendUint8ToBuf(pkt, 0);
}

// Pack the mandatory content of the ClientHello message.
static int32_t PackClientHelloMandatoryField(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
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
    ret = PackHelloCommonField(ctx, pkt, version, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_PROTO_DTLS12
    if (IS_SUPPORT_DATAGRAM(tlsConfig->originVersionMask)) {
        ret = PackClientCookie(pkt, ctx->negotiatedInfo.cookie, (uint8_t)ctx->negotiatedInfo.cookieSize);
        if (ret != HITLS_SUCCESS) {
            (void)memset_s(ctx->negotiatedInfo.cookie, ctx->negotiatedInfo.cookieSize,
                           0, ctx->negotiatedInfo.cookieSize);
            return ret;
        }
    }
#endif

    ret = PackClientCipherSuites(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return PackClientCompressionMethod(pkt);
}

// Pack the ClientHello message to form the Handshake body.
int32_t PackClientHello(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = PackClientHelloMandatoryField(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15735, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }

    ret = PackClientExtension(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15736, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack client hello extension content fail.", 0, 0, 0, 0);
        return ret;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_CLIENT */