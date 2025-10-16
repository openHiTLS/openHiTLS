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
#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "hitls_pki_x509.h"
#endif /* HITLS_TLS_FEATURE_PROVIDER */
#include "tls_config.h"
#include "tls.h"
#include "cert_mgr_ctx.h"
#include "cert_method.h"
#ifndef HITLS_TLS_FEATURE_PROVIDER
HITLS_CERT_MgrMethod g_certMgrMethod = {0};
static bool IsMethodValid(const HITLS_CERT_MgrMethod *method)
{
    bool valid = method == NULL ||
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
        method->checkPrivateKey == NULL;
    if (valid) {
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

int32_t CheckCertCallBackRetVal(
    const char *logStr, int32_t callBackRet, uint32_t bingLogId, int32_t hitlsRet, int32_t cmd)
{
#ifndef HITLS_BSL_LOG
    (void)logStr;
    (void)bingLogId;
#endif
    if (callBackRet != HITLS_SUCCESS) {
        if (cmd == CERT_KEY_CTRL_IS_KEYENC_USAGE || cmd == CERT_KEY_CTRL_IS_DATA_ENC_USAGE ||
            cmd == CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE) {
            return hitlsRet;
        }
        BSL_LOG_BINLOG_FIXLEN(bingLogId, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "%s cmd %d error: callback ret = 0x%x.", logStr, cmd, callBackRet, 0);
        BSL_ERR_PUSH_ERROR(hitlsRet);
        return hitlsRet;
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
        "cert store build chain by cert", ret, BINLOG_ID16083, HITLS_CERT_ERR_BUILD_CHAIN, CERT_CTRL_BUTT);
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
        "cert store verify chain", ret, BINLOG_ID16084, HITLS_CERT_ERR_VERIFY_CERT_CHAIN, CERT_CTRL_BUTT);
}

int32_t SAL_CERT_X509Encode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len, uint32_t *usedLen)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_CertEncode(ctx, cert, buf, len, usedLen);
#else
    ret = ctx->config.tlsConfig.certMgrCtx->method.certEncode(ctx, cert, buf, len, usedLen);
#endif
    return CheckCertCallBackRetVal("encode cert", ret, BINLOG_ID16086, HITLS_CERT_ERR_ENCODE_CERT, CERT_CTRL_BUTT);
}

HITLS_CERT_Chain *SAL_CERT_X509ParseBundleFile(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    return HITLS_X509_Adapt_BundleCertParse(LIBCTX_FROM_CONFIG(config),
        ATTRIBUTE_FROM_CONFIG(config), buf, len, type, SAL_CERT_GetParseFormatStr(format));
}

HITLS_CERT_X509 *SAL_CERT_X509Parse(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    (void)config;
    return HITLS_CERT_ProviderCertParse(libCtx, attrName, buf, len, type, SAL_CERT_GetParseFormatStr(format));
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
    return (HITLS_CERT_X509 *)HITLS_X509_Adapt_CertDup(cert);
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
    if (mgrCtx->method.certRef == NULL) {
        return NULL;
    }
    return mgrCtx->method.certRef(cert);
#endif
}

typedef struct {
    const char *name;
    HITLS_ParseFormat format;
} ParseFormatMap;

static const ParseFormatMap g_parseFormatMap[] = {
    {"PEM", TLS_PARSE_FORMAT_PEM},
    {"ASN1", TLS_PARSE_FORMAT_ASN1},
    {"PFX_COM", TLS_PARSE_FORMAT_PFX_COM},
    {"PKCS12", TLS_PARSE_FORMAT_PKCS12}
};

const char *SAL_CERT_GetParseFormatStr(HITLS_ParseFormat format)
{
    for (size_t i = 0; i < sizeof(g_parseFormatMap) / sizeof(g_parseFormatMap[0]); i++) {
        if (g_parseFormatMap[i].format == format) {
            return g_parseFormatMap[i].name;
        }
    }
    return NULL;
}

#ifndef HITLS_TLS_FEATURE_PROVIDER
static HITLS_ParseFormat GetTlsParseFormat(const char *format)
{
    if (format == NULL) {
        return TLS_PARSE_FORMAT_BUTT;
    }
    for (size_t i = 0; i < sizeof(g_parseFormatMap) / sizeof(g_parseFormatMap[0]); i++) {
        if (BSL_SAL_StrcaseCmp(format, g_parseFormatMap[i].name) == 0) {
            return g_parseFormatMap[i].format;
        }
    }
    return TLS_PARSE_FORMAT_BUTT;
}
#endif

HITLS_CERT_Key *SAL_CERT_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, const char *format, const char *encodeType)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return HITLS_X509_Adapt_ProviderKeyParse(config, buf, len, type, format, encodeType);
#else
    (void)encodeType;
    return config->certMgrCtx->method.keyParse(config, buf, len, type, GetTlsParseFormat(format));
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

int32_t SAL_CERT_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    int32_t ret;
    if (cmd > CERT_CTRL_BUTT - 1) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_CTRL_ERR_INVALID_CMD);
        return HITLS_CERT_CTRL_ERR_INVALID_CMD;
    }
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_StoreCtrl(config, store, cmd, in, out);
#else
    ret = config->certMgrCtx->method.certStoreCtrl(config, store, cmd, in, out);
#endif
    return CheckCertCallBackRetVal("cert store ctrl", ret, BINLOG_ID16094, ret, cmd);
}

int32_t SAL_CERT_X509Ctrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16279, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    if (cmd > CERT_CTRL_BUTT - 1) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_CTRL_ERR_INVALID_CMD);
        return HITLS_CERT_CTRL_ERR_INVALID_CMD;
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_CertCtrl(config, cert, cmd, in, out);
#else
    ret = config->certMgrCtx->method.certCtrl(config, cert, cmd, in, out);
#endif
    return CheckCertCallBackRetVal("cert ctrl", ret, BINLOG_ID16096, ret, cmd);
}

int32_t SAL_CERT_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (key == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16280, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    if (cmd > CERT_CTRL_BUTT - 1) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_CTRL_ERR_INVALID_CMD);
        return HITLS_CERT_CTRL_ERR_INVALID_CMD;
    }
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_KeyCtrl(config, key, cmd, in, out);
#else
    ret = config->certMgrCtx->method.keyCtrl(config, key, cmd, in, out);
#endif
    return CheckCertCallBackRetVal("key ctrl", ret, BINLOG_ID16098, ret, cmd);
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
    return CheckCertCallBackRetVal("create signature", ret, BINLOG_ID16103, HITLS_CERT_ERR_CREATE_SIGN, CERT_CTRL_BUTT);
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
    return CheckCertCallBackRetVal("verify signature", ret, BINLOG_ID16101, HITLS_CERT_ERR_VERIFY_SIGN, CERT_CTRL_BUTT);
}

#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
int32_t SAL_CERT_KeyEncrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ret = HITLS_X509_Adapt_Encrypt(ctx, key, in, inLen, out, outLen);
#else
    if (ctx->config.tlsConfig.certMgrCtx->method.encrypt == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID15333, "unregistered encrypt");
    }
    ret = ctx->config.tlsConfig.certMgrCtx->method.encrypt(ctx, key, in, inLen, out, outLen);
#endif
    return CheckCertCallBackRetVal("pubkey encrypt", ret, BINLOG_ID15059, HITLS_CERT_ERR_ENCRYPT, CERT_CTRL_BUTT);
}

int32_t SAL_CERT_KeyDecrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
#ifdef HITLS_TLS_FEATURE_PROVIDER
    return HITLS_X509_Adapt_Decrypt(ctx, key, in, inLen, out, outLen);
#else
    if (ctx->config.tlsConfig.certMgrCtx->method.decrypt == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID15334, "unregistered decrypt");
    }
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
        "check cert and private key", ret, BINLOG_ID15538, HITLS_CERT_ERR_CHECK_CERT_AND_KEY, CERT_CTRL_BUTT);
}

HITLS_CERT_CRLList *SAL_CERT_CrlParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    return HITLS_X509_Adapt_CrlParse(config, buf, len, type, format);
}

void SAL_CERT_CrlFree(HITLS_CERT_CRLList *crlList)
{
    HITLS_X509_Adapt_CrlFree(crlList);
}
