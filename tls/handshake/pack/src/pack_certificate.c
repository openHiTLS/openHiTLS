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
#include "hitls_build.h"
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "cert.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_extensions.h"
#include "pack_common.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t PackCertificate(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;

    if (bufLen < CERT_LEN_TAG_SIZE) {
        return PackBufLenError(BINLOG_ID15808, BINGLOG_STR("cert"));
    }

    /* Certificate content */
    ret = SAL_CERT_EncodeCertChain(ctx, &buf[CERT_LEN_TAG_SIZE], bufLen - CERT_LEN_TAG_SIZE, usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15809, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode cert list fail.", 0, 0, 0, 0);
        return ret;
    }

    /* Certificate length */
    BSL_Uint24ToByte(*usedLen, buf);
    *usedLen += CERT_LEN_TAG_SIZE;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13PackCertificate(TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0;

    if (bufLen < (CERT_LEN_TAG_SIZE + ctx->certificateReqCtxSize + sizeof(uint16_t))) {
        return PackBufLenError(BINLOG_ID15810, BINGLOG_STR("cert"));
    }
    /* Pack the length of certificate_request_context */
    buf[offset] = (uint8_t)ctx->certificateReqCtxSize;
    offset++;

    /* Pack the content of certificate_request_context */
    if (ctx->certificateReqCtxSize > 0) {
        (void)memcpy_s(&buf[offset], bufLen - offset, ctx->certificateReqCtx, ctx->certificateReqCtxSize);
        offset += ctx->certificateReqCtxSize;
    }

    uint32_t certLenFieldOffset = offset;
    offset += CERT_LEN_TAG_SIZE;

    /* Certificate content */
    ret = SAL_CERT_EncodeCertChain(ctx, &buf[offset], bufLen - offset, usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15811, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode cert list fail when pack certificate msg.", 0, 0, 0, 0);
        return ret;
    }

    /* Certificate length */
    BSL_Uint24ToByte(*usedLen, &buf[certLenFieldOffset]);
    *usedLen += offset;
    return HITLS_SUCCESS;
}
#endif