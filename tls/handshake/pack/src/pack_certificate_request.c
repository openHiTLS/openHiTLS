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
#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_common.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "pack_common.h"
#include "pack_extensions.h"
#include "cert_mgr_ctx.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
typedef struct {
    uint8_t certType;
    bool isSupported;
} PackCertTypesInfo;
static int32_t PackCertificateTypes(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if ((config->cipherSuites == NULL) || (config->cipherSuitesSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15682, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack certificate types error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    PackCertTypesInfo certTypeLists[] = {
        {CERT_TYPE_RSA_SIGN, false},
        {CERT_TYPE_ECDSA_SIGN, false},
        {CERT_TYPE_DSS_SIGN, false},
#ifdef HITLS_TLS_PROTO_TLCP11
        {CERT_TYPE_SM2_SIGN, false},
#endif
    };

    uint8_t certTypeListsSize = (uint8_t)(sizeof(certTypeLists) / sizeof(certTypeLists[0]));
    uint8_t supportedCertTypesSize = 0;
    uint32_t baseSignAlgorithmsSize = config->signAlgorithmsSize;
    const uint16_t *baseSignAlgorithms = config->signAlgorithms;
    for (uint32_t i = 0; i < baseSignAlgorithmsSize; i++) {
        HITLS_CERT_KeyType keyType = SAL_CERT_SignScheme2CertKeyType(ctx, baseSignAlgorithms[i]);
        CERT_Type certType = CertKeyType2CertType(keyType);
        for (uint32_t j = 0; j < certTypeListsSize; j++) {
            if ((certTypeLists[j].certType == certType) && (certTypeLists[j].isSupported == false)) {
                certTypeLists[j].isSupported = true;
                supportedCertTypesSize++;
                break;
            }
        }
    }

    if (bufLen < (sizeof(uint8_t) + supportedCertTypesSize)) {
        return PackBufLenError(BINLOG_ID17119, BINGLOG_STR("certificate type"));
    }

    buf[offset] = supportedCertTypesSize;
    offset += sizeof(uint8_t);
    for (uint32_t i = 0; i < certTypeListsSize; i++) {
        if (certTypeLists[i].isSupported == true) {
            buf[offset] = certTypeLists[i].certType;
            offset += sizeof(uint8_t);
        }
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t PackSignAlgorithms(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if ((config->signAlgorithms == NULL) || (config->signAlgorithmsSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15684, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack signature algorithms error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint16_t signAlgorithmsSize = (uint16_t)config->signAlgorithmsSize * sizeof(uint16_t);
    if (bufLen < (sizeof(uint16_t) + signAlgorithmsSize)) {
        return PackBufLenError(BINLOG_ID15683, BINGLOG_STR("sign algorithms"));
    }

    BSL_Uint16ToByte(signAlgorithmsSize, &buf[offset]);
    offset += sizeof(uint16_t);
    for (uint32_t index = 0; index < config->signAlgorithmsSize; index++) {
        BSL_Uint16ToByte(config->signAlgorithms[index], &buf[offset]);
        offset += sizeof(uint16_t);
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS12 || HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t PackCertificateRequest(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;
    uint32_t len = 0u;

    int32_t ret = PackCertificateTypes(ctx, buf, bufLen, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12)
    /* TLCP does not have the signature algorithm field */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11) {
        len = 0u;
        ret = PackSignAlgorithms(ctx, &buf[offset], bufLen - offset, &len);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        offset += len;
    }
#endif
    /* The distinguishable name of the certificate authorization list. The currently supported certificate authorization
     * list is empty */
    BSL_Uint16ToByte(0, &buf[offset]);
    offset += sizeof(uint16_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t PackSignAlgorithmsExtension(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if ((config->signAlgorithms == NULL) || (config->signAlgorithmsSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15686, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack signature algorithms error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t signAlgorithmsSize = 0;
    uint16_t *signAlgorithms = CheckSupportSignAlgorithms(ctx, config->signAlgorithms,
        config->signAlgorithmsSize, &signAlgorithmsSize);
    if (signAlgorithms == NULL || signAlgorithmsSize == 0) {
        BSL_SAL_FREE(signAlgorithms);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17310, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "no available signAlgo", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
        return HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH;
    }

    uint16_t exMsgHeaderLen = sizeof(uint16_t);
    uint16_t exMsgDataLen = sizeof(uint16_t) * (uint16_t)signAlgorithmsSize;

    int32_t ret = PackExtensionHeader(HS_EX_TYPE_SIGNATURE_ALGORITHMS, exMsgHeaderLen + exMsgDataLen, buf, bufLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(signAlgorithms);
        return ret;
    }
    offset += HS_EX_HEADER_LEN;

    if (bufLen < sizeof(uint16_t) + offset) {
        BSL_SAL_FREE(signAlgorithms);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16920, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "buflen err", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    BSL_Uint16ToByte(exMsgDataLen, &buf[offset]);
    offset += sizeof(uint16_t);

    if (bufLen < exMsgDataLen + offset) {
        BSL_SAL_FREE(signAlgorithms);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16921, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "buflen err", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    for (uint32_t index = 0; index < signAlgorithmsSize; index++) {
        BSL_Uint16ToByte(signAlgorithms[index], &buf[offset]);
        offset += sizeof(uint16_t);
    }
    BSL_SAL_FREE(signAlgorithms);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the extension of the Tls1.3 Certificate Request
static int32_t PackCertReqExtensions(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t listSize;
    uint32_t exLen = 0u;
    uint32_t offset = 0u;

    const PackExtInfo extMsgList[] = {
        {.exMsgType = HS_EX_TYPE_SIGNATURE_ALGORITHMS,
         .needPack = true,
         .packFunc = PackSignAlgorithmsExtension},
        {.exMsgType = HS_EX_TYPE_SIGNATURE_ALGORITHMS_CERT,
            /* We do not generate signature_algorithms_cert at present. */
         .needPack = false,
         .packFunc = NULL},
    };

    listSize = sizeof(extMsgList) / sizeof(extMsgList[0]);

    for (uint32_t index = 0; index < listSize; index++) {
        if (extMsgList[index].packFunc == NULL) {
            exLen = 0u;
            ret = PackEmptyExtension(extMsgList[index].exMsgType, extMsgList[index].needPack,
                &buf[offset], bufLen - offset, &exLen);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            offset += exLen;
        }
        if (extMsgList[index].packFunc != NULL && extMsgList[index].needPack) {
            exLen = 0u;
            ret = extMsgList[index].packFunc(ctx, &buf[offset], bufLen - offset, &exLen);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            offset += exLen;
        }
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}

// Pack the Tls1.3 Certificate Request extension.
int32_t Tls13PackCertReqExtensions(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t headerLen;
    uint32_t exLen = 0u;

    headerLen = sizeof(uint16_t);
    if (bufLen < headerLen) {
        return PackBufLenError(BINLOG_ID15687, BINGLOG_STR("certReq extension"));
    }

    /* Pack the extended content of the Tls1.3 Certificate Request */
    ret = PackCertReqExtensions(ctx, &buf[headerLen], bufLen - headerLen, &exLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (exLen > 0u) {
        BSL_Uint16ToByte((uint16_t)exLen, buf);
        *len = exLen + headerLen;
    } else {
        BSL_Uint16ToByte((uint16_t) 0, buf);
        *len = 0u + headerLen;
    }

    return HITLS_SUCCESS;
}

// Pack the Tls1.3 CertificateRequest message.
int32_t Tls13PackCertificateRequest(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t offset = 0u;
    uint32_t exMsgLen = 0u;

    if (bufLen < sizeof(uint8_t) + ctx->certificateReqCtxSize) {
        return PackBufLenError(BINLOG_ID15688, BINGLOG_STR("tls1.3 certReq"));
    }
    /* Pack certificate_request_context */
    buf[offset] = (uint8_t)ctx->certificateReqCtxSize;
    offset++;

    if (ctx->certificateReqCtxSize > 0) {
        (void)memcpy_s(&buf[offset], bufLen - offset, ctx->certificateReqCtx, ctx->certificateReqCtxSize);
        offset += ctx->certificateReqCtxSize;
    }

    ret = Tls13PackCertReqExtensions(ctx, &buf[offset], bufLen - offset, &exMsgLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15690, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack tls1.3 certificate request msg extension content fail.", 0, 0, 0, 0);
        return ret;
    }
    offset += exMsgLen;
    *usedLen = offset;

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */

#endif /* HITLS_TLS_HOST_SERVER */