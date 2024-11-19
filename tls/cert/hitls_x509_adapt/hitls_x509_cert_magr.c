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
#ifdef HITLS_TLS_CALLBACK_CERT
#include <stdint.h>
#include "securec.h"
#include "crypt_eal_pkey.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_pki.h"
#include "hitls_cert_local.h"
#include "hitls_error.h"
#include "bsl_err_internal.h"

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

static BSL_ParseFormat GetBslParseFormat(HITLS_ParseFormat format)
{
    typedef struct {
       HITLS_ParseFormat hitlsFormat;
       BSL_ParseFormat bslFormat;
    } ParseFormatMap;
    static ParseFormatMap formatMap[]= {
        {TLS_PARSE_FORMAT_PEM, BSL_FORMAT_PEM},
        {TLS_PARSE_FORMAT_ASN1, BSL_FORMAT_ASN1}
    };
    for (size_t i = 0; i < sizeof(formatMap) / sizeof(formatMap[0]); i++) {
        if (formatMap[i].hitlsFormat == format) {
            return formatMap[i].bslFormat;
        }
    }

    return BSL_FORMAT_UNKNOWN;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    (void)config;
    BSL_Buffer encodedCert = { NULL, 0 };
    BSL_ParseFormat bslFormat = GetBslParseFormat(format);
    int ret = HITLS_X509_ADAPT_ERR;
    HITLS_X509_Cert *cert = NULL;
    switch (type) {
        case TLS_PARSE_TYPE_FILE:
            ret = HITLS_X509_CertParseFile(bslFormat, (const char *)buf, &cert);
            break;
        case TLS_PARSE_TYPE_BUFF:
            encodedCert.data = (uint8_t *)BSL_SAL_Calloc(len, (uint32_t)sizeof(uint8_t));
            if (encodedCert.data == NULL) {
                ret = HITLS_MEMALLOC_FAIL;
                break;
            }
            (void)memcpy_s(encodedCert.data, len, buf, len);
            encodedCert.dataLen = len;
            ret = HITLS_X509_CertParseBuff(bslFormat, &encodedCert, &cert);
            break;
        default:
            break;
    }
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(encodedCert.data);
        return NULL;
    }

    BSL_SAL_FREE(encodedCert.data);
    return cert;
}

HITLS_CERT_X509 *HITLS_X509_Adapt_CertDup(HITLS_CERT_X509 *cert)
{
    HITLS_X509_Cert *dest = NULL;
    int32_t ret = HITLS_X509_CertDup(cert, &dest);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return dest;
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

static HITLS_SignHashAlgo BslCid2SignHashAlgo(BslCid cid)
{
    typedef struct {
        BslCid cid;
        HITLS_SignHashAlgo signHashAlg;
    } SignHashMap;
    static SignHashMap signMap[] = {
        { BSL_CID_SHA1WITHRSA, CERT_SIG_SCHEME_RSA_PKCS1_SHA1 },
        { BSL_CID_SHA224WITHRSAENCRYPTION, CERT_SIG_SCHEME_RSA_PKCS1_SHA224 },
        { BSL_CID_SHA256WITHRSAENCRYPTION, CERT_SIG_SCHEME_RSA_PKCS1_SHA256 },
        { BSL_CID_SHA384WITHRSAENCRYPTION, CERT_SIG_SCHEME_RSA_PKCS1_SHA384 },
        { BSL_CID_SHA512WITHRSAENCRYPTION, CERT_SIG_SCHEME_RSA_PKCS1_SHA512 },
        { BSL_CID_RSASSAPSS, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256 },
        { BSL_CID_ECDSAWITHSHA1, CERT_SIG_SCHEME_ECDSA_SHA1 },
        { BSL_CID_ECDSAWITHSHA224, CERT_SIG_SCHEME_ECDSA_SHA224 },
        { BSL_CID_ECDSAWITHSHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256 },
        { BSL_CID_ECDSAWITHSHA384, CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384 },
        { BSL_CID_ECDSAWITHSHA512, CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512 },
#ifndef HITLS_NO_TLCP11
        { BSL_CID_SM2DSAWITHSM3, CERT_SIG_SCHEME_SM2_SM3 },
#endif
        { BSL_CID_ED25519, CERT_SIG_SCHEME_ED25519 },
        { BSL_CID_DSAWITHSHA1, CERT_SIG_SCHEME_DSA_SHA1 },
        { BSL_CID_DSAWITHSHA224, CERT_SIG_SCHEME_DSA_SHA224 },
        { BSL_CID_DSAWITHSHA256, CERT_SIG_SCHEME_DSA_SHA256 },
        { BSL_CID_DSAWITHSHA384, CERT_SIG_SCHEME_DSA_SHA384 },
        { BSL_CID_DSAWITHSHA512, CERT_SIG_SCHEME_DSA_SHA512 },
    };
    for (size_t i = 0; i < sizeof(signMap) / sizeof(signMap[0]); i++) {
        if (signMap[i].cid == cid) {
            return signMap[i].signHashAlg;
        }
    }

    return CERT_SIG_SCHEME_UNKNOWN;
    
}

static int32_t CertCtrlGetSignAlgo(HITLS_CERT_X509 *cert, HITLS_SignHashAlgo *algSign)
{
    BslCid tmpCid = 0;
    *algSign = CERT_SIG_SCHEME_UNKNOWN;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SIGNALG, &tmpCid, sizeof(BslCid));
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *algSign = BslCid2SignHashAlgo(tmpCid);
    return HITLS_SUCCESS;
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
            x509Cmd = HITLS_X509_GET_ENCODELEN;
            break;
        case CERT_CTRL_GET_PUB_KEY:
            valLen = (int32_t)sizeof(CRYPT_EAL_PkeyPub *);
            x509Cmd = HITLS_X509_GET_PUBKEY;
            break;
        case CERT_CTRL_GET_SIGN_ALGO:
            return CertCtrlGetSignAlgo(cert, (HITLS_SignHashAlgo *)output);
        case CERT_KEY_CTRL_IS_KEYENC_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_KEYENC;
            break;
        case CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_DIGITALSIGN;
            break;
        case CERT_KEY_CTRL_IS_KEY_CERT_SIGN_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_CERTSIGN;
            break;
        case CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE:
            valLen = (int32_t)sizeof(uint8_t);
            x509Cmd = HITLS_X509_EXT_KU_KEYAGREEMENT;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_ERR);
            return HITLS_X509_ADAPT_ERR;
    }
    int32_t ret = HITLS_X509_CertCtrl(cert, x509Cmd, output, valLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif /* HITLS_TLS_CALLBACK_CERT */
