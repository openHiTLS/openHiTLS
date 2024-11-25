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
#ifdef HITLS_TLS_HOST_SERVER
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
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "hs_ctx.h"
#include "pack_common.h"
#include "pack_extensions.h"

extern int32_t PackClientCookie(const uint8_t *cookie, uint8_t cookieLen,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen);

// Pack the mandatory content of the HelloVerifyRequest message
static int32_t PackHelloVerifyReqMandatoryField(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    /* The bufLen must be able to pack at least the version number (2 bytes) + cookie (xx bytes)*/
    if (bufLen < (sizeof(uint16_t) + ctx->negotiatedInfo.cookieSize)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15461, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello mandatory field error, the bufLen(%u) is not enough.", bufLen, NULL, NULL, NULL);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    uint32_t offset = 0u;
    uint32_t len = 0u;
    int32_t ret = 0;

    uint16_t version = HITLS_DTLS_ANY_VERSION;
#ifdef HITLS_TLS_FEATURE_SECURITY
    const TLS_Config *tlsConfig = &ctx->config.tlsConfig;
    ret = SECURITY_CfgCheck((const HITLS_Config *)tlsConfig, HITLS_SECURITY_SECOP_VERSION, 0, version, NULL);
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16924, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CfgCheck fail, ret %d", ret, 0, 0, 0);
        ctx->method.sendAlert((TLS_Ctx *)(uintptr_t)ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        BSL_ERR_PUSH_ERROR(HITLS_PACK_UNSECURE_VERSION);
        return HITLS_PACK_UNSECURE_VERSION;
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */    
    BSL_Uint16ToByte(version, &buf[offset]);    // version number
    offset += sizeof(uint16_t);
    ret = PackClientCookie(ctx->negotiatedInfo.cookie, (uint8_t)ctx->negotiatedInfo.cookieSize,
            &buf[offset], bufLen - offset, &len);
    if (ret != HITLS_SUCCESS) {
        (void)memset_s(ctx->negotiatedInfo.cookie, ctx->negotiatedInfo.cookieSize,
                        0, ctx->negotiatedInfo.cookieSize);
        return ret;
    }
    offset += len;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the HelloVerifyRequest message.
int32_t PackHelloVerifyRequest(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t msgLen = 0u;
    
    ret = PackHelloVerifyReqMandatoryField(ctx, buf, bufLen, &msgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15863, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack server hello mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += msgLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_HOST_SERVER */