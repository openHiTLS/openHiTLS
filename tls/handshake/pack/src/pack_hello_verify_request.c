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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack_common.h"

// Pack the HelloVerifyRequest message.
int32_t PackHelloVerifyRequest(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const TLS_NegotiatedInfo *negotiatedInfo = &ctx->negotiatedInfo;
    /* According to rfc6347 4.2.1, message with the cookie length of 0 can be sent,
       but it is meaningless and will be trapped in an infinite loop.
       Therefore, cannot sent cookies with the length of 0 here. */
    if (negotiatedInfo->cookieSize == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_COOKIE_ERR);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15828, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cookieSize is 0.", 0, 0, 0, 0);
        return HITLS_PACK_COOKIE_ERR;
    }

    /* assemble the version, the version is fixed to dtls1.0 */
    uint16_t version = HITLS_VERSION_DTLS10;
    if (IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask)) {
        version = HITLS_VERSION_TLCP_DTLCP11;
    }

    int32_t ret = PackReserveBytes(pkt, sizeof(uint16_t) + sizeof(uint8_t) + negotiatedInfo->cookieSize, NULL);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, version);

    /* assenmble cookie length */
    (void)PackAppendUint8ToBuf(pkt, (uint8_t)negotiatedInfo->cookieSize);

    (void)PackAppendDataToBuf(pkt, negotiatedInfo->cookie, negotiatedInfo->cookieSize);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP && HITLS_TLS_HOST_SERVER */