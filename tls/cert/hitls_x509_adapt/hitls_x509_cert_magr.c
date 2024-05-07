/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include "securec.h"
#include "crypt_eal_pkey.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_x509.h"
#include "hitls_cert_local.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"

int32_t HITLS_X509_Adapt_CertEncode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len,
    uint32_t *usedLen)
{
    (void)ctx;
    *usedLen = 0;
    uint32_t encodeLen = 0;
    int32_t ret = HITLS_X509_CtrlCert((HITLS_X509_Cert *)cert, HITLS_X509_CERT_GET_ENCODELEN, &encodeLen,
        (int32_t)sizeof(uint32_t));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len < encodeLen) {
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    uint8_t *encodedBuff = NULL;
    ret = HITLS_X509_CtrlCert((HITLS_X509_Cert *)cert, HITLS_X509_CERT_ENCODE, (void *)&encodedBuff, 0);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)memcpy_s(buf, len, encodedBuff, encodeLen);
    *usedLen = encodeLen;
    return ret;
}

static BSL_ParseFormat GetBslParseFormat(HITLS_ParseFormat format)
{
    typedef struct {
       HITLS_ParseFormat hitlsFormat;
       BSL_ParseFormat bslFormat;
    } ParseFormatMap;
    static ParseFormatMap formatMap[]= {
        {TLS_PARSE_FORMAT_PEM, BSL_PARSE_FORMAT_PEM},
        {TLS_PARSE_FORMAT_ASN1, BSL_PARSE_FORMAT_ASN1}
    };
    for (size_t i = 0; i < sizeof(formatMap) / sizeof(formatMap[0]); i++) {
        if (formatMap[i].hitlsFormat == format) {
            return formatMap[i].bslFormat;
        }
    }

    return BSL_PARSE_FORMAT_UNKNOWN;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    (void)config;
    BSL_Buffer encodedCert = { NULL, 0 };
    BSL_ParseFormat bslFormat = GetBslParseFormat(format);
    int ret = HITLS_X509_ADAPT_ERR;
    HITLS_X509_Cert *cert = HITLS_X509_NewCert();
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return NULL;
    }
    switch (type) {
        case TLS_PARSE_TYPE_FILE:
            ret = HITLS_X509_ParseFileCert(bslFormat, (const char *)buf, cert);
            break;
        case TLS_PARSE_TYPE_BUFF:
            encodedCert.data = (uint8_t *)BSL_SAL_Calloc(len, (uint32_t)sizeof(uint8_t));
            if (encodedCert.data == NULL) {
                ret = HITLS_MEMALLOC_FAIL;
                break;
            }
            (void)memcpy_s(encodedCert.data, len, buf, len);
            encodedCert.dataLen = len;
            ret = HITLS_X509_ParseBuffCert(true, bslFormat, &encodedCert, cert);
            break;
        default:
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_X509_FreeCert(cert);
        BSL_SAL_FREE(encodedCert.data);
        return NULL;
    }

    BSL_SAL_FREE(encodedCert.data);
    return cert;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertDup(HITLS_CERT_X509 *cert)
{
    HITLS_X509_Cert *dest = NULL;
    int32_t ret = HITLS_X509_DupCert(cert, &dest);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return dest;
}

void HITLS_X509_Adapt_CertFree(HITLS_CERT_X509 *cert)
{
    HITLS_X509_FreeCert(cert);
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertRef(HITLS_CERT_X509 *cert)
{
    int ref = 0;
    int ret = HITLS_X509_CtrlCert(cert, HITLS_X509_CERT_REF_UP, (void *)&ref, (int32_t)sizeof(int));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return cert;
}

int32_t HITLS_X509_Adapt_CertCtrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output)
{
    (void)config;
    (void)input;
    int32_t valLen = sizeof(int32_t);
    int32_t x509Cmd = 0;
    switch (cmd) {
        case CERT_CTRL_GET_ENCODE_LEN:
            x509Cmd = HITLS_X509_CERT_GET_ENCODELEN;
            break;
        case CERT_CTRL_GET_PUB_KEY:
            valLen = (int32_t)sizeof(CRYPT_EAL_PkeyPub *);
            x509Cmd = HITLS_X509_CERT_GET_PUBKEY;
            break;
        case CERT_CTRL_GET_SIGN_ALGO:
            valLen = (int32_t)sizeof(int32_t);
            x509Cmd = HITLS_X509_CERT_GET_SIGNALG;
            break;
        case CERT_KEY_CTRL_IS_KEYENC_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_CERT_EXT_KU_KEYENC;
            break;
        case CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_CERT_EXT_KU_DIGITALSIGN;
            break;
        case CERT_KEY_CTRL_IS_KEY_CERT_SIGN_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_CERT_EXT_KU_CERTSIGN;
            break;
        case CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_CERT_EXT_KU_KEYAGREEMENT;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_ERR);
            return HITLS_X509_ADAPT_ERR;
    }
    int32_t ret = HITLS_X509_CtrlCert(cert, x509Cmd, output, valLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
