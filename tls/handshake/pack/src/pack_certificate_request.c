/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

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
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "pack_extensions.h"

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
        {CERT_TYPE_SM2_SIGN, false},
    };

    uint32_t cipherSuitesSize = config->cipherSuitesSize;
    uint8_t certTypeListsSize = (uint8_t)(sizeof(certTypeLists) / sizeof(certTypeLists[0]));
    uint8_t supportedCertTypesSize = 0;
    for (uint32_t i = 0; i < cipherSuitesSize; i++) {
        uint8_t type = CFG_GetCertTypeByCipherSuite(config->cipherSuites[i]);
        for (uint32_t j = 0; j < certTypeListsSize; j++) {
            if ((certTypeLists[j].certType == type) && (certTypeLists[j].isSupported == false)) {
                certTypeLists[j].isSupported = true;
                supportedCertTypesSize++;
                break;
            }
        }
    }

    if (bufLen < (sizeof(uint8_t) + supportedCertTypesSize)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15683, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of certificate types message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
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
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15685, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of sign algorithms message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
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

int32_t PackCertificateRequest(const TLS_Ctx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0u;
    uint32_t len = 0u;

    int32_t ret = PackCertificateTypes(ctx, buf, bufLen, &len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += len;

    /* TLCP does not have the signature algorithm field */
    if (ctx->negotiatedInfo.version != HITLS_VERSION_TLCP11) {
        len = 0u;
        ret = PackSignAlgorithms(ctx, &buf[offset], bufLen - offset, &len);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        offset += len;
    }

    /* The distinguishable name of the certificate authorization list. The currently supported certificate authorization
     * list is empty */
    BSL_Uint16ToByte(0, &buf[offset]);
    offset += sizeof(uint16_t);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

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

    uint16_t exMsgHeaderLen = sizeof(uint16_t);
    uint16_t exMsgDataLen = sizeof(uint16_t) * (uint16_t)config->signAlgorithmsSize;

    int32_t ret = PackExtensionHeader(HS_EX_TYPE_SIGNATURE_ALGORITHMS, exMsgHeaderLen + exMsgDataLen, buf, bufLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    offset += HS_EX_HEADER_LEN;

    if (bufLen < sizeof(uint16_t) + offset) {
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    BSL_Uint16ToByte(exMsgDataLen, &buf[offset]);
    offset += sizeof(uint16_t);

    if (bufLen < exMsgDataLen + offset) {
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    for (uint32_t index = 0; index < config->signAlgorithmsSize; index++) {
        BSL_Uint16ToByte(config->signAlgorithms[index], &buf[offset]);
        offset += sizeof(uint16_t);
    }

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
        {.exMsgType = HS_EX_TYPE_OID_FILTERS,
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
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15687, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer length of tls1.3 certificate Request extension message is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
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

    if (bufLen < sizeof(uint8_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_PACK_NOT_ENOUGH_BUF_LENGTH);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15688, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "the buffer len of tls1.3 cert request msg is not enough.", 0, 0, 0, 0);
        return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
    }
    /* Pack certificate_request_context */
    buf[offset] = (uint8_t)ctx->certificateReqCtxSize;
    offset++;

    if (ctx->certificateReqCtxSize > 0) {
        if (memcpy_s(&buf[offset], bufLen - offset, ctx->certificateReqCtx, ctx->certificateReqCtxSize) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15689, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "pack certificateReqCtx fail when pack cert request.", 0, 0, 0, 0);
            return HITLS_MEMCPY_FAIL;
        }
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
