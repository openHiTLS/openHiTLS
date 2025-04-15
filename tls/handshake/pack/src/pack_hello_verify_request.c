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
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_HOST_SERVER)
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

// Pack the mandatory content of the HelloVerifyRequest message
static int32_t PackHelloVerifyReqMandatoryField(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    const TLS_NegotiatedInfo *negotiatedInfo = &ctx->negotiatedInfo;
    /* The bufLen must be able to pack at least the version number (2 bytes) + cookiesize (1 byte) + cookie (xx bytes) */
    if (bufLen < (sizeof(uint16_t) + sizeof(uint8_t) + negotiatedInfo->cookieSize)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17329, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack hello verify request mandatory field error, the bufLen(%u) is not enough.", bufLen, NULL, NULL, NULL);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    uint32_t offset = 0u;
    uint16_t version = HITLS_VERSION_DTLS10;
    if (IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask)) {
        version = HITLS_VERSION_TLCP_DTLCP11;
    }

    BSL_Uint16ToByte(version, &buf[offset]); // version number
    offset += sizeof(uint16_t);

    buf[offset] = (uint8_t)negotiatedInfo->cookieSize;
    offset++;
        /* According to rfc6347 4.2.1, message with the cookie length of 0 can be sent,
       but it is meaningless and will be trapped in an infinite loop.
       Therefore, cannot sent cookies with the length of 0 here. */
    if (negotiatedInfo->cookieSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_COOKIE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15828, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cookieSize is 0.", 0, 0, 0, 0);
        return HITLS_PACK_COOKIE_ERR;
    }
    /* assemble the cookie */
    (void)memcpy_s(&buf[offset], bufLen - offset, negotiatedInfo->cookie, negotiatedInfo->cookieSize);
    offset += negotiatedInfo->cookieSize;
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17330, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack hello verify request mandatory content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += msgLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP && HITLS_TLS_HOST_SERVER */