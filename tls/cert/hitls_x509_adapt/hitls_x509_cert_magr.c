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
#if defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER)
#include <stdint.h>
#include "securec.h"
#include "crypt_eal_pkey.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_pki_cert.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"
#include "tls_config.h"
#include "cert_mgr_ctx.h"
#include "config_type.h"

int32_t HITLS_X509_Adapt_CertEncode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len,
    uint32_t *usedLen)
{
    (void)ctx;
    *usedLen = 0;
    uint32_t encodeLen = 0;
    int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)cert, HITLS_X509_GET_ENCODELEN, &encodeLen,
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
    ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)cert, HITLS_X509_GET_ENCODE, (void *)&encodedBuff, 0);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    (void)memcpy_s(buf, len, encodedBuff, encodeLen);
    *usedLen = encodeLen;
    return ret;
}

#ifdef HITLS_TLS_FEATURE_PROVIDER
HITLS_CERT_X509 *HITLS_CERT_ProviderCertParse(HITLS_Lib_Ctx *libCtx, const char *attrName, const uint8_t *buf,
    uint32_t len, HITLS_ParseType type, const char *format)
{
    BSL_Buffer encodedCert = { NULL, 0 };
    int ret = HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT;
    HITLS_X509_Cert *cert = NULL;
#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
    if (type == TLS_PARSE_TYPE_FILE) {
        ret = HITLS_X509_ProviderCertParseFile(libCtx, attrName, format, (const char *)buf, &cert);
    } else
#endif
    if (type == TLS_PARSE_TYPE_BUFF) {
        encodedCert.data = (uint8_t *)(uintptr_t)buf;
        encodedCert.dataLen = len;
        ret = HITLS_X509_ProviderCertParseBuff(libCtx, attrName, format, &encodedCert, &cert);
    }

    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return cert;
}
#else
HITLS_CERT_X509 *HITLS_X509_Adapt_CertParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    (void)config;
    BSL_Buffer encodedCert = { NULL, 0 };
    int ret = HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT;
    HITLS_X509_Cert *cert = NULL;
#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
    if (type == TLS_PARSE_TYPE_FILE) {
        ret = HITLS_X509_CertParseFile(format, (const char *)buf, &cert);
    } else
#endif
    if (type == TLS_PARSE_TYPE_BUFF) {
        encodedCert.data = (uint8_t *)(uintptr_t)buf;
        encodedCert.dataLen = len;
        ret = HITLS_X509_CertParseBuff(format, &encodedCert, &cert);
    }

    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return cert;
}
#endif

HITLS_CERT_Chain *HITLS_X509_Adapt_BundleCertParse(HITLS_Lib_Ctx *libCtx, const char *attrName, const uint8_t *buf,
    uint32_t len, HITLS_ParseType type, const char *format)
{
    BSL_Buffer encodedCert = { NULL, 0 };
    int ret;
    HITLS_X509_List *certlist = NULL;
    switch (type) {
        case TLS_PARSE_TYPE_FILE:
            ret = HITLS_X509_ProviderCertParseBundleFile(libCtx, attrName, format, (const char *)buf, &certlist);
            break;
        case TLS_PARSE_TYPE_BUFF:
            encodedCert.data = (uint8_t *)(uintptr_t)buf;
            encodedCert.dataLen = len;
            ret = HITLS_X509_ProviderCertParseBundleBuff(libCtx, attrName, format, &encodedCert, &certlist);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT);
            return NULL;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return certlist;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertRef(HITLS_CERT_X509 *cert)
{
    int ref = 0;
    int ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, (void *)&ref, (int32_t)sizeof(int));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return cert;
}

static HITLS_SignHashAlgo BslCid2SignHashAlgo(HITLS_Config *config, BslCid signAlgId, BslCid hashAlgId)
{
    uint32_t size = 0;
    const TLS_SigSchemeInfo *sigSchemeInfoList = ConfigGetSignatureSchemeInfoList(config, &size);
    for (size_t i = 0; i < size; i++) {
        if (sigSchemeInfoList[i].signHashAlgId == (int32_t)signAlgId &&
            sigSchemeInfoList[i].hashAlgId == (int32_t)hashAlgId) {
            return sigSchemeInfoList[i].signatureScheme;
        }
    }

    return CERT_SIG_SCHEME_UNKNOWN;
}

static int32_t CertCtrlGetSignAlgo(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_SignHashAlgo *algSign)
{
    BslCid signAlgCid = 0;
    BslCid hashCid = 0;
    *algSign = CERT_SIG_SCHEME_UNKNOWN;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGNALG, &signAlgCid, sizeof(BslCid));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGN_MDALG, &hashCid, sizeof(BslCid));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *algSign = BslCid2SignHashAlgo(config, signAlgCid, hashCid);
    return HITLS_SUCCESS;
}
#if defined(HITLS_TLS_PROTO_TLCP11) || defined(HITLS_TLS_CONFIG_KEY_USAGE)
static int32_t CertCheckKeyUsage(HITLS_Config *config, HITLS_CERT_X509 *cert, uint32_t inKeyUsage, bool *res)
{
    (void)config;
    uint32_t keyUsage = 0;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_KUSAGE, &keyUsage, sizeof(uint32_t));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (keyUsage == HITLS_X509_EXT_KU_NONE) {
#ifdef HITLS_TLS_PROTO_TLCP11
        // Key usage must be present, otherwise the chain is broken.
        if (config == NULL) {
            return HITLS_INVALID_INPUT;
        }
        if (config->maxVersion == HITLS_VERSION_TLCP_DTLCP11) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_NO_KEYUSAGE);
            return HITLS_CERT_ERR_NO_KEYUSAGE;
        }
#endif
        *res = true;
        return HITLS_SUCCESS;
    }
    *res = (keyUsage & inKeyUsage) != 0;
    return HITLS_SUCCESS;
}
#endif
int32_t HITLS_X509_Adapt_CertCtrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output)
{
    (void)input;
    int32_t ret = HITLS_SUCCESS;
    switch (cmd) {
        case CERT_CTRL_GET_ENCODE_LEN:
            ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODELEN, output, (uint32_t)sizeof(int32_t));
            break;
        case CERT_CTRL_GET_PUB_KEY:
            ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, output, (uint32_t)sizeof(CRYPT_EAL_PkeyPub *));
            break;
        case CERT_CTRL_GET_SIGN_ALGO:
            return CertCtrlGetSignAlgo(config, cert, (HITLS_SignHashAlgo *)output);
#if defined(HITLS_TLS_PROTO_TLCP11) || defined(HITLS_TLS_CONFIG_KEY_USAGE)
        case CERT_KEY_CTRL_IS_KEYENC_USAGE:
            return CertCheckKeyUsage(config, cert, HITLS_X509_EXT_KU_KEY_ENCIPHERMENT, (bool *)output);
        case CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE:
            return CertCheckKeyUsage(config, cert, HITLS_X509_EXT_KU_DIGITAL_SIGN, (bool *)output);
        case CERT_KEY_CTRL_IS_KEY_CERT_SIGN_USAGE:
            return CertCheckKeyUsage(config, cert, HITLS_X509_EXT_KU_KEY_CERT_SIGN, (bool *)output);
        case CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE:
            return CertCheckKeyUsage(config, cert, HITLS_X509_EXT_KU_KEY_AGREEMENT, (bool *)output);
        case CERT_KEY_CTRL_IS_DATA_ENC_USAGE:
            return CertCheckKeyUsage(config, cert, HITLS_X509_EXT_KU_DATA_ENCIPHERMENT, (bool *)output);
        case CERT_KEY_CTRL_IS_NON_REPUDIATION_USAGE:
            return CertCheckKeyUsage(config, cert, HITLS_X509_EXT_KU_NON_REPUDIATION, (bool *)output);
#endif
#ifdef HITLS_TLS_FEATURE_CERTIFICATE_AUTHORITIES
        case CERT_CTRL_GET_ENCODE_SUBJECT_DN:
            ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE_SUBJECT_DN, output, sizeof(BSL_Buffer *));
            break;
#endif
#ifdef HITLS_TLS_CONFIG_CERT_BUILD_CHAIN
        case CERT_CTRL_IS_SELF_SIGNED:
            return HITLS_X509_CertCtrl(cert, HITLS_X509_IS_SELF_SIGNED, (bool *)output, (uint32_t)sizeof(bool));
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_ERR);
            return HITLS_CERT_SELF_ADAPT_ERR;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif /* defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER) */
