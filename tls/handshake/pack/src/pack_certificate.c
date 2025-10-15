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
int32_t PackCertificate(TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Start packing certificate list length */
    uint32_t certListLenPosition = 0u;
    int32_t ret = PackStartLengthField(pkt, CERT_LEN_TAG_SIZE, &certListLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Certificate content using callback */
    ret = SAL_CERT_EncodeCertChain(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15809, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode cert list fail.", 0, 0, 0, 0);
        return ret;
    }

    /* Close certificate list length field */
    PackCloseUint24Field(pkt, certListLenPosition);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
int32_t Tls13PackCertificate(TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Pack the length of certificate_request_context */
    int32_t ret = PackAppendUint8ToBuf(pkt, (uint8_t)ctx->certificateReqCtxSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the content of certificate_request_context */
    if (ctx->certificateReqCtxSize > 0) {
        ret = PackAppendDataToBuf(pkt, ctx->certificateReqCtx, ctx->certificateReqCtxSize);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    /* Start packing certificate list length */
    uint32_t certListLenPosition = 0u;
    ret = PackStartLengthField(pkt, CERT_LEN_TAG_SIZE, &certListLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Certificate content using callback */
    ret = SAL_CERT_EncodeCertChain(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15811, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode cert list fail when pack certificate msg.", 0, 0, 0, 0);
        return ret;
    }

    /* Close certificate list length field */
    PackCloseUint24Field(pkt, certListLenPosition);
    return HITLS_SUCCESS;
}
#endif