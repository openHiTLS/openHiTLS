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
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_err_internal.h"
#include "hitls_x509_adapt.h"
#include "crypt_eal_codecs.h"
#include "crypt_errno.h"
#include "hitls_cert.h"
#include "hitls_cert_type.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "crypt_eal_pkey.h"
#include "hitls_crypt_type.h"
#include "cert.h"
#include "config_type.h"
#include "tls_config.h"

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
            BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_ERR);
            return HITLS_CERT_SELF_ADAPT_ERR;
        }
    } else {
        if (passWordCbUserData != NULL) {
            uint32_t userDataLen = BSL_SAL_Strnlen((const char *)passWordCbUserData, *passLen);
            if (userDataLen == 0 || userDataLen == (uint32_t)*passLen) {
                BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_ERR);
                return HITLS_CERT_SELF_ADAPT_ERR;
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
    }
    return ret;
}

#ifdef HITLS_TLS_FEATURE_PROVIDER
HITLS_CERT_Key *HITLS_X509_Adapt_ProviderKeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, const char *format, const char *encodeType)
{
    HITLS_Lib_Ctx *libCtx = LIBCTX_FROM_CONFIG(config);
    const char *attrName = ATTRIBUTE_FROM_CONFIG(config);
    int32_t ret = HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT;
    BSL_Buffer encode = {0};
    HITLS_CERT_Key *ealPriKey = NULL;
    uint8_t pwd[MAX_PASS_LEN] = { 0 };
    BSL_Buffer pwdBuff = {pwd, sizeof(pwd)};
    (void)GetPrivKeyPassword(config, pwdBuff.data, (int32_t *)&pwdBuff.dataLen);
#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
    if (type == TLS_PARSE_TYPE_FILE) {
        ret = CRYPT_EAL_ProviderDecodeFileKey(libCtx, attrName, BSL_CID_UNKNOWN, format, encodeType,
            (const char *)buf, &pwdBuff, (CRYPT_EAL_PkeyCtx **)&ealPriKey);
    } else
#endif
    if (type == TLS_PARSE_TYPE_BUFF) {
        encode.data = (uint8_t *)(uintptr_t)buf;
        encode.dataLen = len;
        ret = CRYPT_EAL_ProviderDecodeBuffKey(libCtx, attrName, BSL_CID_UNKNOWN, format, encodeType,
            &encode, &pwdBuff, (CRYPT_EAL_PkeyCtx **)&ealPriKey);
    }

    (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return ealPriKey;
}

#else
HITLS_CERT_Key *HITLS_X509_Adapt_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    (void)config;
    int32_t ret = HITLS_CERT_SELF_ADAPT_UNSUPPORT_FORMAT;
    BSL_Buffer encode = {0};
    HITLS_CERT_Key *ealPriKey = NULL;
    uint8_t pwd[MAX_PASS_LEN] = { 0 };
    int32_t pwdLen = (int32_t)sizeof(pwd);
    (void)GetPrivKeyPassword(config, pwd, &pwdLen);
#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
    if (type == TLS_PARSE_TYPE_FILE) {
        ret = CRYPT_EAL_DecodeFileKey(format, CRYPT_ENCDEC_UNKNOW, (const char *)buf, pwd, pwdLen,
            (CRYPT_EAL_PkeyCtx **)&ealPriKey);
    } else
#endif
    if (type == TLS_PARSE_TYPE_BUFF) {
        encode.data = (uint8_t *)(uintptr_t)buf;
        encode.dataLen = len;
        ret = CRYPT_EAL_DecodeBuffKey(format, CRYPT_ENCDEC_UNKNOW, &encode, pwd, pwdLen,
            (CRYPT_EAL_PkeyCtx **)&ealPriKey);
    }

    (void)memset_s(pwd, MAX_PASS_LEN, 0, MAX_PASS_LEN);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return ealPriKey;
}
#endif

HITLS_CERT_Key *HITLS_X509_Adapt_KeyDup(HITLS_CERT_Key *key)
{
    return (HITLS_CERT_Key *)CRYPT_EAL_PkeyDupCtx(key);
}

void HITLS_X509_Adapt_KeyFree(HITLS_CERT_Key *key)
{
    CRYPT_EAL_PkeyFreeCtx(key);
}

static HITLS_NamedGroup GetCurveNameByKey(HITLS_Config *config, const CRYPT_EAL_PkeyCtx *key)
{
    CRYPT_PKEY_ParaId paraId = CRYPT_EAL_PkeyGetParaId(key);
    if (paraId == CRYPT_PKEY_PARAID_MAX) {
        return HITLS_NAMED_GROUP_BUTT;
    }
    uint32_t size = 0;
    const TLS_GroupInfo *groupInfoList = ConfigGetGroupInfoList(config, &size);
    for (size_t i = 0; i < size; i++) {
        if (groupInfoList[i].paraId == (int32_t)paraId) {
            return groupInfoList[i].groupId;
        }
    }
    return HITLS_NAMED_GROUP_BUTT;
}

static HITLS_CERT_KeyType CertKeyAlgId2KeyType(CRYPT_EAL_PkeyCtx *pkey)
{
    CRYPT_PKEY_AlgId cid = CRYPT_EAL_PkeyGetId(pkey);
    if (cid == CRYPT_PKEY_RSA) {
        int32_t padType = 0;
        if (CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(padType)) != CRYPT_SUCCESS) {
            return TLS_CERT_KEY_TYPE_UNKNOWN;
        }
        if (padType == CRYPT_EMSA_PSS) {
            return TLS_CERT_KEY_TYPE_RSA_PSS;
        }
    }
    return (HITLS_CERT_KeyType)cid;
}

int32_t HITLS_X509_Adapt_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output)
{
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
            *(HITLS_NamedGroup *)output = GetCurveNameByKey(config, key);
            break;
        case CERT_KEY_CTRL_GET_POINT_FORMAT:
            /* Currently only uncompressed is used */
            *(HITLS_ECPointFormat *)output = HITLS_POINT_FORMAT_UNCOMPRESSED;
            break;
        case CERT_KEY_CTRL_GET_SECBITS:
            *(int32_t *)output = CRYPT_EAL_PkeyGetSecurityBits(key);
            break;
        case CERT_KEY_CTRL_GET_PARAM_ID:
            *(int32_t *)output = CRYPT_EAL_PkeyGetParaId(key);
            break;
        case CERT_KEY_CTRL_GET_PSS_MD:
            (void)CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_GET_RSA_MD, output, sizeof(int32_t));
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_CERT_SELF_ADAPT_ERR);
            ret = HITLS_CERT_SELF_ADAPT_ERR;
            break;
    }

    return ret;
}

#endif /* defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER) */
