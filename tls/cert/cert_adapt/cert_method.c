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
#include <stddef.h>
#include "hitls_build.h"
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_x509_adapt.h"
#include "hitls_pki_x509.h"
#include "tls_config.h"
#include "tls.h"
#include "cert_mgr_ctx.h"
#include "cert_method.h"
#ifndef HITLS_TLS_FEATURE_PROVIDER
HITLS_CERT_MgrMethod g_certMgrMethod = {0};
static bool IsMethodValid(const HITLS_CERT_MgrMethod *method)
{
    if (method == NULL ||
        method->certStoreNew == NULL ||
        method->certStoreDup == NULL ||
        method->certStoreFree == NULL ||
        method->certStoreCtrl == NULL ||
        method->buildCertChain == NULL ||
        method->verifyCertChain == NULL ||
        method->certEncode == NULL ||
        method->certParse == NULL ||
        method->certDup == NULL ||
        method->certFree == NULL ||
        method->certCtrl == NULL ||
        method->keyParse == NULL ||
        method->keyDup == NULL ||
        method->keyFree == NULL ||
        method->keyCtrl == NULL ||
        method->createSign == NULL ||
        method->verifySign == NULL ||
        method->checkPrivateKey == NULL) {
        return false;
    }
    return true;
}

int32_t HITLS_CERT_RegisterMgrMethod(HITLS_CERT_MgrMethod *method)
{
    /* check the callbacks that must be set */
    if (IsMethodValid(method) == false) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID16108, "input NULL");
    }

    if (memcpy_s(&g_certMgrMethod, sizeof(HITLS_CERT_MgrMethod), method, sizeof(HITLS_CERT_MgrMethod)) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}

void HITLS_CERT_DeinitMgrMethod(void)
{
    HITLS_CERT_MgrMethod mgr = {0};
    (void)memcpy_s(&g_certMgrMethod, sizeof(HITLS_CERT_MgrMethod), &mgr, sizeof(HITLS_CERT_MgrMethod));
}

HITLS_CERT_MgrMethod *SAL_CERT_GetMgrMethod(void)
{
    return &g_certMgrMethod;
}

HITLS_CERT_MgrMethod *HITLS_CERT_GetMgrMethod(void)
{
    return SAL_CERT_GetMgrMethod();
}

#endif /* HITLS_TLS_FEATURE_PROVIDER */

const char *g_certCallBackStr[] = {
    [HITLS_CERT_CALLBACK_STORE_NEW] = "cert store new",
    [HITLS_CERT_CALLBACK_STORE_DUP] = "cert store dup",
    [HITLS_CERT_CALLBACK_STORE_FREE] = "cert store free",
    [HITLS_CERT_CALLBACK_STORE_CTRL] = "cert store ctrl",
    [HITLS_CERT_CALLBACK_BUILD_CERT_CHAIN] = "cert store build chain by cert",
    [HITLS_CERT_CALLBACK_VERIFY_CERT_CHAIN] = "cert store verify chain",
    [HITLS_CERT_CALLBACK_CERT_ENCODE] = "encode cert",
    [HITLS_CERT_CALLBACK_CERT_PARSE] = "parse cert",
    [HITLS_CERT_CALLBACK_CERT_DUP] = "dup cert",
    [HITLS_CERT_CALLBACK_CERT_REF] = "ref cert",
    [HITLS_CERT_CALLBACK_CERT_FREE] = "free certs",
    [HITLS_CERT_CALLBACK_CERT_CTRL] = "cert ctrl",
    [HITLS_CERT_CALLBACK_KEY_PARSE] = "parse key",
    [HITLS_CERT_CALLBACK_KEY_DUP] = "dup key",
    [HITLS_CERT_CALLBACK_KEY_CTRL] = "key ctrl",
    [HITLS_CERT_CALLBACK_CREATE_SIGN] = "create signature",
    [HITLS_CERT_CALLBACK_VERIFY_SIGN] = "verify signature",
    [HITLS_CERT_CALLBACK_ENCRYPT] = "pubkey encrypt",
    [HITLS_CERT_CALLBACK_DECRYPT] = "private key decrypt",
    [HITLS_CERT_CALLBACK_CHECK_PRIVATE_KEY] = "check cert and private key",
};

int32_t CheckCertCallBackRetVal(int32_t cmd, int32_t callBackRet, uint32_t bingLogId, uint32_t hitlsRet)
{
    if (callBackRet != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(bingLogId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "%s error: callback ret = 0x%x.", g_certCallBackStr[cmd], callBackRet, 0, 0);
        BSL_ERR_PUSH_ERROR((int32_t)hitlsRet);
        return (int32_t)hitlsRet;
    }
    return HITLS_SUCCESS;
}

HITLS_CERT_Store *SAL_CERT_StoreNew(const CERT_MgrCtx *mgrCtx)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return HITLS_X509_ProviderStoreCtxNew(LIBCTX_FROM_CERT_MGR_CTX(mgrCtx), ATTRIBUTE_FROM_CERT_MGR_CTX(mgrCtx));
#else
    return mgrCtx->method.certStoreNew();
#endif
}

HITLS_CERT_Store *SAL_CERT_StoreDup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)mgrCtx;
    return HITLS_X509_Adapt_StoreDup(store);
#else
    return mgrCtx->method.certStoreDup(store);
#endif
}

void SAL_CERT_StoreFree(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)mgrCtx;
    return HITLS_X509_StoreCtxFree(store);
#else
    mgrCtx->method.certStoreFree(store);
#endif
}

int32_t SAL_CERT_BuildChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **certList, uint32_t *num)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_BuildCertChain(config, store, cert, certList, num);
#else
    ret = config->certMgrCtx->method.buildCertChain(config, store, cert, certList, num);
#endif
    return CheckCertCallBackRetVal(
        HITLS_CERT_CALLBACK_BUILD_CERT_CHAIN, ret, BINLOG_ID16083, HITLS_CERT_ERR_BUILD_CHAIN);
}

int32_t SAL_CERT_VerifyChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **certList, uint32_t num)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_VerifyCertChain(ctx, store, certList, num);
#else
    ret = ctx->config.tlsConfig.certMgrCtx->method.verifyCertChain(ctx, store, certList, num);
#endif
    return CheckCertCallBackRetVal(
        HITLS_CERT_CALLBACK_VERIFY_CERT_CHAIN, ret, BINLOG_ID16084, HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
}

int32_t SAL_CERT_X509Encode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len, uint32_t *usedLen)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_CertEncode(ctx, cert, buf, len, usedLen);
#else
    ret = ctx->config.tlsConfig.certMgrCtx->method.certEncode(ctx, cert, buf, len, usedLen);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_CERT_ENCODE, ret, BINLOG_ID16086,
        HITLS_CERT_ERR_ENCODE_CERT);
}

HITLS_CERT_X509 *SAL_CERT_X509Parse(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)config;
    return HITLS_CERT_ProviderCertParse(libCtx, attrName, buf, len, type, format);
#else
    (void)libCtx;
    (void)attrName;
    return config->certMgrCtx->method.certParse(config, buf, len, type, format);
#endif
}

HITLS_CERT_X509 *SAL_CERT_X509Dup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)mgrCtx;
    return (HITLS_CERT_X509 *)HITLS_X509_CertDup(cert);
#else
    return mgrCtx->method.certDup(cert);
#endif
}

void SAL_CERT_X509Free(HITLS_CERT_X509 *cert)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    HITLS_X509_CertFree(cert);
#else
    if (cert == NULL) {
        return;
    }
    g_certMgrMethod.certFree(cert);
#endif
}

HITLS_CERT_X509 *SAL_CERT_X509Ref(const CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)mgrCtx;
    return HITLS_X509_Adapt_CertRef(cert);
#else
    return mgrCtx->method.certRef(cert);
#endif
}

HITLS_CERT_Key *SAL_CERT_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return HITLS_X509_Adapt_KeyParse(config, buf, len, type, format);
#else
    return config->certMgrCtx->method.keyParse(config, buf, len, type, format);
#endif
}

HITLS_CERT_Key *SAL_CERT_KeyDup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Key *key)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)mgrCtx;
    return (HITLS_CERT_Key *)CRYPT_EAL_PkeyDupCtx(key);
#else
    return mgrCtx->method.keyDup(key);
#endif
}

void SAL_CERT_KeyFree(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Key *key)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)mgrCtx;
    CRYPT_EAL_PkeyFreeCtx(key);
#else
    if (key == NULL) {
        return;
    }
    mgrCtx->method.keyFree(key);
#endif
}

/* change the error code when modifying the ctrl command */
uint32_t g_tlsCertCtrlErrorCode[] = {
    HITLS_CERT_STORE_CTRL_ERR_SET_VERIFY_DEPTH,
    HITLS_CERT_STORE_CTRL_ERR_ADD_CERT_LIST,
    HITLS_CERT_CTRL_ERR_GET_ENCODE_LEN,
    HITLS_CERT_CTRL_ERR_GET_PUB_KEY,
    HITLS_CERT_CTRL_ERR_GET_SIGN_ALGO,
    HITLS_CERT_KEY_CTRL_ERR_GET_SIGN_LEN,
    HITLS_CERT_KEY_CTRL_ERR_GET_TYPE,
    HITLS_CERT_KEY_CTRL_ERR_GET_CURVE_NAME,
    HITLS_CERT_KEY_CTRL_ERR_GET_POINT_FORMAT,
    HITLS_CERT_KEY_CTRL_ERR_GET_SECBITS,
    HITLS_CERT_KEY_CTRL_ERR_IS_ENC_USAGE,
    HITLS_CERT_KEY_CTRL_ERR_IS_DIGITAL_SIGN_USAGE,
    HITLS_CERT_KEY_CTRL_ERR_IS_KEY_CERT_SIGN_USAGE,
    HITLS_CERT_KEY_CTRL_ERR_IS_KEY_AGREEMENT_USAGE,
    HITLS_CERT_KEY_CTRL_ERR_GET_PARAM_ID,
};

int32_t SAL_CERT_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_StoreCtrl(config, store, cmd, in, out);
#else
    ret = config->certMgrCtx->method.certStoreCtrl(config, store, cmd, in, out);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_STORE_CTRL, ret, BINLOG_ID16094,
        g_tlsCertCtrlErrorCode[cmd]);
}

int32_t SAL_CERT_X509Ctrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16279, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_CertCtrl(config, cert, cmd, in, out);
#else
    ret = config->certMgrCtx->method.certCtrl(config, cert, cmd, in, out);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_CERT_CTRL, ret, BINLOG_ID16096,
        g_tlsCertCtrlErrorCode[cmd]);
}

int32_t SAL_CERT_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (key == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16280, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_KeyCtrl(config, key, cmd, in, out);
#else
    ret = config->certMgrCtx->method.keyCtrl(config, key, cmd, in, out);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_KEY_CTRL, ret, BINLOG_ID16098,
        g_tlsCertCtrlErrorCode[cmd]);
}

int32_t SAL_CERT_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, CERT_SignParam *signParam)
{
    if (key == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16281, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_CreateSign(ctx, key, signParam->signAlgo, signParam->hashAlgo, signParam->data,
        signParam->dataLen, signParam->sign, &signParam->signLen);
#else
    ret = ctx->config.tlsConfig.certMgrCtx->method.createSign(ctx, key, signParam->signAlgo,
        signParam->hashAlgo, signParam->data, signParam->dataLen, signParam->sign, &signParam->signLen);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_CREATE_SIGN, ret, BINLOG_ID16103,
        HITLS_CERT_ERR_CREATE_SIGN);
}

int32_t SAL_CERT_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, CERT_SignParam *signParam)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_VerifySign(ctx, key, signParam->signAlgo,
        signParam->hashAlgo, signParam->data, signParam->dataLen, signParam->sign, signParam->signLen);
#else
    ret = ctx->config.tlsConfig.certMgrCtx->method.verifySign(ctx, key, signParam->signAlgo,
        signParam->hashAlgo, signParam->data, signParam->dataLen, signParam->sign, signParam->signLen);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_VERIFY_SIGN, ret, BINLOG_ID16101,
        HITLS_CERT_ERR_VERIFY_SIGN);
}

#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
int32_t SAL_CERT_KeyEncrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_Encrypt(ctx, key, in, inLen, out, outLen);
#else
    ret = ctx->config.tlsConfig.certMgrCtx->method.encrypt(ctx, key, in, inLen, out, outLen);
#endif
    return CheckCertCallBackRetVal(HITLS_CERT_CALLBACK_ENCRYPT, ret, BINLOG_ID15059, HITLS_CERT_ERR_ENCRYPT);
}

int32_t SAL_CERT_KeyDecrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return HITLS_X509_Adapt_Decrypt(ctx, key, in, inLen, out, outLen);
#else
    return ctx->config.tlsConfig.certMgrCtx->method.decrypt(ctx, key, in, inLen, out, outLen);
#endif
}
#endif /* HITLS_TLS_SUITE_KX_RSA || HITLS_TLS_PROTO_TLCP11 */

int32_t SAL_CERT_CheckPrivateKey(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_CheckPrivateKey(config, cert, key);
#else
    ret = config->certMgrCtx->method.checkPrivateKey(config, cert, key);
#endif
    return CheckCertCallBackRetVal(
        HITLS_CERT_CALLBACK_CHECK_PRIVATE_KEY, ret, BINLOG_ID15538, HITLS_CERT_ERR_CHECK_CERT_AND_KEY);
}
