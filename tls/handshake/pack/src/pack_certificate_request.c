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
#if defined(HITLS_TLS_HOST_SERVER) && defined(HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY)
#include <stdint.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "tls.h"
#include "hs_common.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "pack_common.h"
#include "pack_extensions.h"
#include "hs_cert.h"
#include "custom_extensions.h"

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
typedef struct {
    uint8_t certType;
    bool isSupported;
} PackCertTypesInfo;
static int32_t PackCertificateTypes(const TLS_Ctx *ctx, PackPacket *pkt)
{
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
        {CERT_TYPE_DSS_SIGN, false}
    };

    uint8_t certTypeListsSize = (uint8_t)(sizeof(certTypeLists) / sizeof(certTypeLists[0]));
    uint8_t supportedCertTypesSize = 0;
    uint32_t baseSignAlgorithmsSize = config->signAlgorithmsSize;
    const uint16_t *baseSignAlgorithms = config->signAlgorithms;
    for (uint32_t i = 0; i < baseSignAlgorithmsSize; i++) {
        HITLS_CERT_KeyType keyType = HS_SignScheme2CertKeyType(ctx, baseSignAlgorithms[i]);
        CERT_Type certType = CertKeyType2CertType(keyType);
        for (uint32_t j = 0; j < certTypeListsSize; j++) {
            if ((certTypeLists[j].certType == certType) && (certTypeLists[j].isSupported == false)) {
                certTypeLists[j].isSupported = true;
                supportedCertTypesSize++;
                break;
            }
        }
    }

    int32_t ret = PackAppendUint8ToBuf(pkt, supportedCertTypesSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    for (uint32_t i = 0; i < certTypeListsSize; i++) {
        if (certTypeLists[i].isSupported == true) {
            ret = PackAppendUint8ToBuf(pkt, certTypeLists[i].certType);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12)
static int32_t PackSignAlgorithms(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);

    if ((config->signAlgorithms == NULL) || (config->signAlgorithmsSize == 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15684, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack signature algorithms error, invalid input parameter.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint16_t signAlgorithmsSize = (uint16_t)config->signAlgorithmsSize * sizeof(uint16_t);
    int32_t ret = PackAppendUint16ToBuf(pkt, signAlgorithmsSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    for (uint32_t index = 0; index < config->signAlgorithmsSize; index++) {
        ret = PackAppendUint16ToBuf(pkt, config->signAlgorithms[index]);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS12 || HITLS_TLS_PROTO_DTLS12 */

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
static int32_t PackCALists(const TLS_Ctx *ctx, PackPacket *pkt)
{
    const TLS_Config *config = &(ctx->config.tlsConfig);
    
    if (config->caList == NULL) {
        return PackAppendUint16ToBuf(pkt, 0);
    }

    uint32_t caListLenPosition = 0u;
    int32_t ret = PackStartLengthField(pkt, sizeof(uint16_t), &caListLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = PackTrustedCAList(config->caList, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17370, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack CA list error", 0, 0, 0, 0);
        return ret;
    }

    PackCloseUint16Field(pkt, caListLenPosition);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */

int32_t PackCertificateRequest(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = PackCertificateTypes(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#if defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_DTLS12)
    /* TLCP does not have the signature algorithm field */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP_DTLCP11) {
        ret = PackSignAlgorithms(ctx, pkt);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
    ret = PackCALists(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_SUCCESS;
#else
    return PackAppendUint16ToBuf(pkt, 0);
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */
}
#endif /* HITLS_TLS_PROTO_TLS_BASIC || HITLS_TLS_PROTO_DTLS12 */
#ifdef HITLS_TLS_PROTO_TLS13
static int32_t PackSignAlgorithmsExtension(const TLS_Ctx *ctx, PackPacket *pkt)
{
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
#ifdef HITLS_TLS_FEATURE_SM_TLS13
    if (IS_SM_TLS13(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite)) {
        signAlgorithmsSize = 1;
        signAlgorithms[0] = CERT_SIG_SCHEME_SM2_SM3;
    }
#endif
    uint16_t exMsgHeaderLen = sizeof(uint16_t);
    uint16_t exMsgDataLen = sizeof(uint16_t) * (uint16_t)signAlgorithmsSize;

    int32_t ret = PackExtensionHeader(HS_EX_TYPE_SIGNATURE_ALGORITHMS, exMsgHeaderLen + exMsgDataLen, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(signAlgorithms);
        return ret;
    }

    (void)PackAppendUint16ToBuf(pkt, exMsgDataLen);

    for (uint32_t index = 0; index < signAlgorithmsSize; index++) {
        (void)PackAppendUint16ToBuf(pkt, signAlgorithms[index]);
    }
    BSL_SAL_FREE(signAlgorithms);

    return HITLS_SUCCESS;
}

// Pack the extension of the Tls1.3 Certificate Request
static int32_t PackCertReqExtensions(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = HITLS_SUCCESS;
    const PackExtInfo extMsgList[] = {
        {.exMsgType = HS_EX_TYPE_SIGNATURE_ALGORITHMS,
         .needPack = true,
         .packFunc = PackSignAlgorithmsExtension},
        {.exMsgType = HS_EX_TYPE_SIGNATURE_ALGORITHMS_CERT,
         .needPack = false,
         .packFunc = NULL},
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
        {.exMsgType = HS_EX_TYPE_CERTIFICATE_AUTHORITIES,
         .needPack = ctx->config.tlsConfig.caList != NULL,
         .packFunc = PackClientCAList},
#endif /* HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES */
    };

    uint32_t listSize = sizeof(extMsgList) / sizeof(extMsgList[0]);
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
    if (IsPackNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST)) {
        ret = PackCustomExtensions(ctx, pkt, HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST, NULL, 0);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */

    for (uint32_t index = 0; index < listSize; index++) {
        if (extMsgList[index].packFunc == NULL) {
            ret = PackEmptyExtension(extMsgList[index].exMsgType, extMsgList[index].needPack, pkt);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
        if (extMsgList[index].packFunc != NULL && extMsgList[index].needPack) {
            ret = extMsgList[index].packFunc(ctx, pkt);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
    }

    return HITLS_SUCCESS;
}

static int32_t Tls13PackCertReqExtensions(const TLS_Ctx *ctx, PackPacket *pkt)
{
    /* Start packing extensions length */
    uint32_t extensionsLenPosition = 0u;
    int32_t ret = PackStartLengthField(pkt, sizeof(uint16_t), &extensionsLenPosition);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Pack the extended content of the Tls1.3 Certificate Request */
    ret = PackCertReqExtensions(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Close extensions length field */
    PackCloseUint16Field(pkt, extensionsLenPosition);
    
    return HITLS_SUCCESS;
}

int32_t Tls13PackCertificateRequest(const TLS_Ctx *ctx, PackPacket *pkt)
{
    int32_t ret = PackCertificateReqCtx(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = Tls13PackCertReqExtensions(ctx, pkt);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15690, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pack tls1.3 certificate request msg extension content fail.", 0, 0, 0, 0);
        return ret;
    }

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_PROTO_TLS13 */
#endif /* HITLS_TLS_HOST_SERVER && HITLS_TLS_FEATURE_CERT_MODE_CLIENT_VERIFY */