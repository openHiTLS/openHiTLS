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
#include "bsl_sal.h"
#include "bsl_type.h"
#include "bsl_err_internal.h"
#include "hitls_x509_adapt_local.h"
#include "crypt_eal_encode.h"
#include "crypt_errno.h"
#include "hitls_cert.h"
#include "hitls_cert_type.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "crypt_eal_pkey.h"
#include "hitls_crypt_type.h"

static int32_t g_tryTypes[] = { CRYPT_PRIKEY_PKCS8_UNENCRYPT, CRYPT_PRIKEY_PKCS8_ENCRYPT, CRYPT_PRIKEY_RSA,
    CRYPT_PRIKEY_ECC };

static int32_t GetPassByCb(HITLS_PasswordCb passWordCb, void *passWordCbUserData, char *pass, int32_t *passLen)
{
    if (pass == NULL || passLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int32_t len = 0;
    if (passWordCb != NULL) {
        len = passWordCb(pass, *passLen, 0, passWordCbUserData);
        if (len < 0) {
            BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_ERR);
            return HITLS_X509_ADAPT_ERR;
        }
    } else {
        if (passWordCbUserData != NULL) {
            uint32_t userDataLen = BSL_SAL_Strnlen((const char *)passWordCbUserData, *passLen);
            if (userDataLen == 0) {
                BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_ERR);
                return HITLS_X509_ADAPT_ERR;
            }
            (void)memcpy_s(pass, *passLen, (char *)passWordCbUserData, userDataLen + 1);
            len = userDataLen;
        }
    }
    
    *passLen = len;
    return HITLS_SUCCESS;
}

static int32_t GetPrivKeyPassword(HITLS_Config *config, uint8_t *pwd, int32_t *pwdLen)
{
    HITLS_PasswordCb pwCb = HITLS_CFG_GetDefaultPasswordCb(config);
    void *userData = HITLS_CFG_GetDefaultPasswordCbUserdata(config);
    int32_t len = *pwdLen;
    int32_t ret = GetPassByCb(pwCb, userData, (char *)pwd, pwdLen);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        (void)memset_s(pwd, len, 0, len);
        return ret;
    }
    return HITLS_SUCCESS;
}

static HITLS_CERT_Key *HitlsPrivKeyBuffAsn1Parse(HITLS_Config *config, BSL_Buffer *encode)
{
    HITLS_CERT_Key *ealPriKey = NULL;
    uint8_t pwd[MAX_PASS_LEN] = { 0 };
    uint32_t pwdLen = MAX_PASS_LEN;
    int32_t ret;
    for (size_t i = 0; i < sizeof(g_tryTypes) / sizeof(g_tryTypes[0]); i++) {
        if (g_tryTypes[i] == CRYPT_PRIKEY_PKCS8_ENCRYPT) {
            if (GetPrivKeyPassword(config, pwd, (int32_t *)&pwdLen) != HITLS_SUCCESS) {
                continue;
            }
        }
        ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, g_tryTypes[i], encode, pwd, pwdLen,
            (CRYPT_EAL_PkeyCtx **)&ealPriKey);
        if (ret == HITLS_SUCCESS) {
            (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
            return ealPriKey;
        }
    }
    (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
    return NULL;
}

static HITLS_CERT_Key *HitlsPrivKeyBuffPemParse(HITLS_Config *config, BSL_Buffer *encode)
{
    HITLS_CERT_Key *ealPriKey = NULL;
    uint8_t pwd[MAX_PASS_LEN] = { 0 };
    uint32_t pwdLen = MAX_PASS_LEN;
    int32_t ret;
    for (size_t i = 0; i < sizeof(g_tryTypes) / sizeof(g_tryTypes[0]); i++) {
        if (g_tryTypes[i] == CRYPT_PRIKEY_PKCS8_ENCRYPT) {
            if (GetPrivKeyPassword(config, pwd, (int32_t *)&pwdLen) != HITLS_SUCCESS) {
                continue;
            }
        }
        ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_PEM, g_tryTypes[i], encode, pwd, pwdLen,
            (CRYPT_EAL_PkeyCtx **)&ealPriKey);
        if (ret == HITLS_SUCCESS) {
            (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
            return ealPriKey;
        }
    }
    (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
    return NULL;
}

static HITLS_CERT_Key *HitlsPrivKeyFileAsn1Parse(HITLS_Config *config, const uint8_t *buf)
{
    HITLS_CERT_Key *ealPriKey = NULL;
    uint8_t pwd[MAX_PASS_LEN] = { 0 };
    uint32_t pwdLen = MAX_PASS_LEN;
    for (size_t i = 0; i < sizeof(g_tryTypes) / sizeof(g_tryTypes[0]); i++) {
        if (g_tryTypes[i] == CRYPT_PRIKEY_PKCS8_ENCRYPT) {
            if (GetPrivKeyPassword(config, pwd, (int32_t *)&pwdLen) != HITLS_SUCCESS) {
                continue;
            }
        }
        int ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, g_tryTypes[i], (const char *)buf, pwd, pwdLen,
            (CRYPT_EAL_PkeyCtx **)&ealPriKey);
        if (ret == HITLS_SUCCESS) {
            (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
            return ealPriKey;
        }
    }
    (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
    return NULL;
}

static HITLS_CERT_Key *HitlsPrivKeyFilePemParse(HITLS_Config *config, const uint8_t *buf)
{
    HITLS_CERT_Key *ealPriKey = NULL;
    uint8_t pwd[MAX_PASS_LEN] = { 0 };
    uint32_t pwdLen = MAX_PASS_LEN;
    for (size_t i = 0; i < sizeof(g_tryTypes) / sizeof(g_tryTypes[0]); i++) {
        if (g_tryTypes[i] == CRYPT_PRIKEY_PKCS8_ENCRYPT) {
            if (GetPrivKeyPassword(config, pwd, (int32_t *)&pwdLen) != HITLS_SUCCESS) {
                continue;
            }
        }
        int ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, g_tryTypes[i], (const char *)buf, pwd, pwdLen,
            (CRYPT_EAL_PkeyCtx **)&ealPriKey);
        if (ret == HITLS_SUCCESS) {
            (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
            return ealPriKey;
        }
    }
    (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
    return NULL;
}

static HITLS_CERT_Key *HitlsPrivKeyBuffParse(HITLS_Config *config, int32_t format, BSL_Buffer *encode)
{
    switch (format) {
        case TLS_PARSE_FORMAT_PEM:
            return HitlsPrivKeyBuffPemParse(config, encode);
        case TLS_PARSE_FORMAT_ASN1:
            return HitlsPrivKeyBuffAsn1Parse(config, encode);
        default:
            return NULL;
    }
}

static HITLS_CERT_Key *HitlsPrivKeyFileParse(HITLS_Config *config, int32_t format, const uint8_t *buf)
{
    switch (format) {
        case TLS_PARSE_FORMAT_PEM:
            return HitlsPrivKeyFilePemParse(config, buf);
        case TLS_PARSE_FORMAT_ASN1:
            return HitlsPrivKeyFileAsn1Parse(config, buf);
        default:
            return NULL;
    }
}

HITLS_CERT_Key *HITLS_X509_Adapt_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    BSL_Buffer encode = {};
    HITLS_CERT_Key *certKey = NULL;
    encode.data = (uint8_t *)BSL_SAL_Calloc(len, sizeof(uint8_t));
    if (encode.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return NULL;
    }
    (void)memcpy_s(encode.data, len, buf, len);
    encode.dataLen = len;
    switch (type) {
        case TLS_PARSE_TYPE_FILE:
            certKey = HitlsPrivKeyFileParse(config, format, buf);
            break;
        case TLS_PARSE_TYPE_BUFF:
            certKey = HitlsPrivKeyBuffParse(config, format, &encode);
            break;
        default:
            break;;
    }
    BSL_SAL_FREE(encode.data);
    return certKey;
}

HITLS_CERT_Key *HITLS_X509_Adapt_KeyDup(HITLS_CERT_Key *key)
{
    return (HITLS_CERT_Key *)CRYPT_EAL_PkeyDupCtx(key);
}

void HITLS_X509_Adapt_KeyFree(HITLS_CERT_Key *key)
{
    CRYPT_EAL_PkeyFreeCtx(key);
}

static HITLS_NamedGroup GetCurveNameByParaId(CRYPT_PKEY_ParaId paraId)
{
    typedef struct {
        CRYPT_PKEY_ParaId paraId;
        HITLS_NamedGroup curveName;
    } CertKeyCurveNameMap;
    static CertKeyCurveNameMap curveNameMap[] = {
        { CRYPT_ECC_NISTP256, HITLS_EC_GROUP_SECP256R1 },
        { CRYPT_ECC_NISTP384, HITLS_EC_GROUP_SECP384R1 },
        { CRYPT_ECC_NISTP521, HITLS_EC_GROUP_SECP521R1 },
        { CRYPT_ECC_BRAINPOOLP256R1, HITLS_EC_GROUP_BRAINPOOLP256R1 },
        { CRYPT_ECC_BRAINPOOLP384R1, HITLS_EC_GROUP_BRAINPOOLP384R1 },
        { CRYPT_ECC_BRAINPOOLP512R1, HITLS_EC_GROUP_BRAINPOOLP512R1 },
    };
    for (size_t i = 0; i < sizeof(curveNameMap) / sizeof(curveNameMap[0]); i++) {
        if (curveNameMap[i].paraId == paraId) {
            return curveNameMap[i].curveName;
        }
    }
    return HITLS_NAMED_GROUP_BUTT;
}

static HITLS_NamedGroup GetCurveNameByKey(const CRYPT_EAL_PkeyCtx *key)
{
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(key);
    if (cid == CRYPT_PKEY_X25519) {
        return HITLS_EC_GROUP_CURVE25519;
    }
    if (cid != CRYPT_PKEY_ECDSA && cid != CRYPT_PKEY_ECDH) {
        return HITLS_NAMED_GROUP_BUTT;
    }
    CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(key);
    return GetCurveNameByParaId(paraId);
}

typedef struct {
    CRYPT_PKEY_AlgId cid;
    HITLS_CERT_KeyType keyType;
} CertKeyTypeMap;

static HITLS_CERT_KeyType CertKeyAlgId2KeyType(CRYPT_EAL_PkeyCtx *pkey)
{
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(pkey);
    if (cid == CRYPT_PKEY_RSA) {
        CRYPT_RsaPadType padType = 0;
        if (CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(CRYPT_RsaPadType)) != CRYPT_SUCCESS) {
            return TLS_CERT_KEY_TYPE_UNKNOWN;
        }
        if (padType == CRYPT_PKEY_EMSA_PSS) {
            return TLS_CERT_KEY_TYPE_RSA_PSS;
        }
    }
    static CertKeyTypeMap signMap[] = {
        {CRYPT_PKEY_RSA, TLS_CERT_KEY_TYPE_RSA},
        {CRYPT_PKEY_DSA, TLS_CERT_KEY_TYPE_DSA},
        {CRYPT_PKEY_ECDSA, TLS_CERT_KEY_TYPE_ECDSA},
        {CRYPT_PKEY_ED25519, TLS_CERT_KEY_TYPE_ED25519},
    #ifndef HITLS_NO_TLCP11
        {CRYPT_PKEY_SM2, TLS_CERT_KEY_TYPE_SM2},
    #endif
    };
    for (size_t i = 0; i < sizeof(signMap) / sizeof(signMap[0]); i++) {
        if (signMap[i].cid == cid) {
            return signMap[i].keyType;
        }
    }
    return TLS_CERT_KEY_TYPE_UNKNOWN;
}

int32_t HITLS_X509_Adapt_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output)
{
    (void)config;
    (void)input;
    int32_t ret = HITLS_SUCCESS;
    switch (cmd) {
        case CERT_KEY_CTRL_GET_SIGN_LEN:
            *(uint32_t *)output = CRYPT_EAL_PkeyGetSignLen((const CRYPT_EAL_PkeyCtx *)key);
            break;
        case CERT_KEY_CTRL_GET_TYPE:
            *(HITLS_CERT_KeyType *)output = CertKeyAlgId2KeyType(key);
            break;
        case CERT_KEY_CTRL_GET_CURVE_NAME:
            *(HITLS_NamedGroup *)output = GetCurveNameByKey(key);
            break;
        case CERT_KEY_CTRL_GET_POINT_FORMAT:
            /* Currently only uncompressed is used */
            *(HITLS_ECPointFormat *)output = HITLS_POINT_FORMAT_UNCOMPRESSED;
            break;
        case CERT_KEY_CTRL_GET_SECBITS:
            *(int32_t *)output = CRYPT_EAL_PkeyGetSecurityBits(key);
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_X509_ADAPT_ERR);
            ret = HITLS_X509_ADAPT_ERR;
            break;
    }

    return ret;
}

#endif /* HITLS_TLS_CALLBACK_CERT */