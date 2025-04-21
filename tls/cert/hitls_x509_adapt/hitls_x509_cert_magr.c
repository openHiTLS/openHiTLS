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

HITLS_CERT_X509 *HITLS_CERT_ProviderCertParse(HITLS_Lib_Ctx *libCtx, const char *attrName, const uint8_t *buf,
    uint32_t len, HITLS_ParseType type, HITLS_ParseFormat format)
{
    BSL_Buffer encodedCert = { NULL, 0 };
    int ret;
    HITLS_X509_Cert *cert = NULL;
    switch (type) {
        case TLS_PARSE_TYPE_FILE:
            ret = HITLS_X509_ProviderCertParseFile(libCtx, attrName, format, (const char *)buf, &cert);
            break;
        case TLS_PARSE_TYPE_BUFF:
            encodedCert.data = (uint8_t *)(uintptr_t)buf;
            encodedCert.dataLen = len;
            ret = HITLS_X509_ProviderCertParseBuff(libCtx, attrName, format, &encodedCert, &cert);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT);
            ret = HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT;
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return cert;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    HITLS_Lib_Ctx *libCtx = LIBCTX_FROM_CONFIG(config);
    const char *attrName = ATTRIBUTE_FROM_CONFIG(config);

    HITLS_CERT_X509 *cert = HITLS_CERT_ProviderCertParse(libCtx, attrName, buf, len, type, format);
    if (cert == NULL) {
        return NULL;
    }

    return cert;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertDup(HITLS_CERT_X509 *cert)
{
    return HITLS_X509_CertDup(cert);
}

void HITLS_X509_Adapt_CertFree(HITLS_CERT_X509 *cert)
{
    HITLS_X509_CertFree(cert);
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

int32_t HITLS_X509_Adapt_CertCtrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output)
{
    (void)input;
    uint32_t valLen = (uint32_t)sizeof(int32_t);
    int32_t x509Cmd = 0;
    switch (cmd) {
        case CERT_CTRL_GET_ENCODE_LEN:
            x509Cmd = HITLS_X509_GET_ENCODELEN;
            break;
        case CERT_CTRL_GET_PUB_KEY:
            valLen = (uint32_t)sizeof(CRYPT_EAL_PkeyPub *);
            x509Cmd = HITLS_X509_GET_PUBKEY;
            break;
        case CERT_CTRL_GET_SIGN_ALGO:
            return CertCtrlGetSignAlgo(config, cert, (HITLS_SignHashAlgo *)output);
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
        case CERT_KEY_CTRL_IS_KEYENC_USAGE:
            valLen = (uint32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_KEYENC;
            break;
        case CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE:
            valLen = (uint32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_DIGITALSIGN;
            break;
        case CERT_KEY_CTRL_IS_KEY_CERT_SIGN_USAGE:
            valLen = (uint32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_CERTSIGN;
            break;
        case CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE:
            valLen = (uint32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_KEYAGREEMENT;
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_ERR);
            return HITLS_CERT_SELF_ADAPT_ERR;
    }
    int32_t ret = HITLS_X509_CertCtrl(cert, x509Cmd, output, valLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif /* defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER) */
