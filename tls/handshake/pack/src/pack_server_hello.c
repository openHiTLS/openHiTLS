/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_security.h"
#include "tls.h"
#include "security.h"
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack_extensions.h"

// Pack the mandatory content of the ServerHello message
static int32_t PackServerHelloMandatoryField(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    /* The bufLen must be able to pack at least the version number (2 bytes) + random number (32 bytes) + session ID
     * (1 byte length field) + algorithm suite (2 bytes) + compression method (1 byte) */
    if (bufLen < (sizeof(uint16_t) + HS_RANDOM_SIZE + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t))) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15461, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello mandatory field error, the bufLen(%u) is not enough.", bufLen, NULL, NULL, NULL);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t len = 0u;
    HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
    uint16_t negotiatedVersion = ctx->negotiatedInfo.version;

    uint16_t version = (negotiatedVersion == HITLS_VERSION_TLS13) ? HITLS_VERSION_TLS12 : negotiatedVersion;
    ret = SECURITY_CfgCheck((HITLS_Config *)&ctx->config.tlsConfig, HITLS_SECURITY_SECOP_VERSION, 0, version, NULL);
    if (ret != SECURITY_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSECURE_VERSION);
        ctx->method.sendAlert((TLS_Ctx *)ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        return HITLS_PACK_UNSECURE_VERSION;
    }
    BSL_Uint16ToByte(version, &buf[offset]);    // version number
    offset += sizeof(uint16_t);
    (void)memcpy_s(&buf[offset], bufLen - offset, ctx->hsCtx->serverRandom, HS_RANDOM_SIZE);    // server random number
    offset += HS_RANDOM_SIZE;

    len = 0u;
    ret = PackSessionId(hsCtx->sessionId, hsCtx->sessionIdSize, &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        (void)memset_s(hsCtx->sessionId, hsCtx->sessionIdSize, 0, hsCtx->sessionIdSize);
        return ret;
    }
    offset += len;

    BSL_Uint16ToByte(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite, &buf[offset]);    // cipher suite
    offset += sizeof(uint16_t);

    buf[offset] = 0;    // Compression method, currently supports uncompression
    offset += sizeof(uint8_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the ServertHello message.
int32_t PackServerHello(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t msgLen = 0u;
    uint32_t exMsgLen = 0u;

    ret = PackServerHelloMandatoryField(ctx, buf, bufLen, &msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15863, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += msgLen;

    exMsgLen = 0u;
    ret = PackServerExtension(ctx, &buf[offset], bufLen - offset, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15864, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello extension content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += exMsgLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
