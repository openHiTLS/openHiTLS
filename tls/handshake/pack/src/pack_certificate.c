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
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "cert.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "hs_extensions.h"
#include "pack_common.h"
#include "pack_msg.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t PackCertificate(TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Start packing certificate list length */
    uint32_t certListLenPosition = 0u;
    int32_t ret = PackStartLengthField(pkt, CERT_LEN_TAG_SIZE, &certListLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Certificate content */
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
static int32_t BuildTls13CertificateBody(TLS_Ctx *ctx, uint8_t **body, uint32_t *bodyLen)
{
    uint8_t *tmpBuf = NULL;
    uint32_t tmpBufLen = 0;
    uint32_t tmpOffset = 0;
    PackPacket tmpPkt = {.buf = &tmpBuf, .bufLen = &tmpBufLen, .bufOffset = &tmpOffset};
    int32_t ret = Tls13PackCertificate(ctx, &tmpPkt);

    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(tmpBuf);
        return ret;
    }
    *body = tmpBuf;
    *bodyLen = tmpOffset;
    return HITLS_SUCCESS;
}

int32_t Tls13PackCertificate(TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = PackCertificateReqCtx(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
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

int32_t Tls13PackCompressedCertificate(TLS_Ctx *ctx, PackPacket *pkt)
{
    uint8_t *certBody = NULL;
    uint8_t *compressed = NULL;
    uint32_t certBodyLen = 0;
    uint32_t compressedLen = 0;
    int32_t ret = BuildTls13CertificateBody(ctx, &certBody, &certBodyLen);

    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (certBodyLen > ctx->config.tlsConfig.certCompressionMaxUncompLen) {
        BSL_SAL_FREE(certBody);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }

    compressedLen = HS_GetCertCompressionBound(ctx->negotiatedInfo.certCompressionAlg, certBodyLen);
    if (compressedLen == 0) {
        BSL_SAL_FREE(certBody);
        return HITLS_CONFIG_INVALID_SET;
    }
    compressed = (uint8_t *)BSL_SAL_Malloc(compressedLen);
    if (compressed == NULL) {
        BSL_SAL_FREE(certBody);
        return HITLS_MEMALLOC_FAIL;
    }

    ret = HS_CompressCertificate(ctx, ctx->negotiatedInfo.certCompressionAlg, certBody, certBodyLen,
        compressed, &compressedLen);
    if (ret == HITLS_SUCCESS) {
        ret = PackAppendUint16ToBuf(pkt, ctx->negotiatedInfo.certCompressionAlg);
    }
    if (ret == HITLS_SUCCESS) {
        ret = PackAppendUint24ToBuf(pkt, certBodyLen);
    }
    if (ret == HITLS_SUCCESS) {
        ret = PackAppendUint24ToBuf(pkt, compressedLen);
    }
    if (ret == HITLS_SUCCESS) {
        ret = PackAppendDataToBuf(pkt, compressed, compressedLen);
    }

    BSL_SAL_FREE(compressed);
    BSL_SAL_FREE(certBody);
    return ret;
}
#endif
