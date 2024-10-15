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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "tls_config.h"
#include "tls.h"
#include "cert_mgr_ctx.h"
#include "cert_method.h"

HITLS_CERT_MgrMethod g_certMgrMethod = {0};

HITLS_CERT_UserKeyMgrMethod g_certUserKeyMgrMethod = {0};

static int32_t IsMethodValid(const HITLS_CERT_MgrMethod *method)
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
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15003, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HITLS_CERT_RegisterMgrMethod error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    (void)memcpy_s(&g_certMgrMethod, sizeof(HITLS_CERT_MgrMethod), method, sizeof(HITLS_CERT_MgrMethod));
    return HITLS_SUCCESS;
}

void HITLS_CERT_DeinitMgrMethod(void)
{
    HITLS_CERT_MgrMethod mgr = {0};
    (void)memcpy_s(&g_certMgrMethod, sizeof(HITLS_CERT_MgrMethod), &mgr, sizeof(HITLS_CERT_MgrMethod));
}

int32_t HITLS_CERT_RegisterUserKeyMgrMethod(HITLS_CERT_UserKeyMgrMethod *method)
{
    /* the usage of HITLS_CERT_UserKeyMgrMethod depends on HITLS_CERT_MgrMethod,
       therefore there is the judgment of registration of HITLS_CERT_MgrMethod */
    HITLS_CERT_MgrMethod *certMgrMethod = SAL_CERT_GetMgrMethod();
    if (IsMethodValid(certMgrMethod) == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16018, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HITLS_CERT_RegisterMgrMethod is not registed", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (method == NULL ||
        method->keyToUserKey == NULL ||
        method->keyFormUserKey == NULL ||
        method->userKeyFree == NULL ||
        method->userKeyDup == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15007, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HITLS_CERT_RegisterUserKeyMgrMethod error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    if (memcpy_s(&g_certUserKeyMgrMethod,
        sizeof(HITLS_CERT_UserKeyMgrMethod),
        method,
        sizeof(HITLS_CERT_UserKeyMgrMethod)) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    return HITLS_SUCCESS;
}

void HITLS_CERT_DeinitUserKeyMgrMethod(void)
{
    HITLS_CERT_UserKeyMgrMethod mgr = {0};
    (void)memcpy_s(
        &g_certUserKeyMgrMethod, sizeof(HITLS_CERT_UserKeyMgrMethod), &mgr, sizeof(HITLS_CERT_UserKeyMgrMethod));
    return;
}

HITLS_CERT_MgrMethod *SAL_CERT_GetMgrMethod(void)
{
    return &g_certMgrMethod;
}

HITLS_CERT_UserKeyMgrMethod *SAL_CERT_GetUserKeyMgrMethod(void)
{
    return &g_certUserKeyMgrMethod;
}

HITLS_CERT_Store *SAL_CERT_StoreNew(const CERT_MgrCtx *mgrCtx)
{
    if (mgrCtx == NULL || mgrCtx->method.certStoreNew == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15006, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store new error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    HITLS_CERT_Store *store = mgrCtx->method.certStoreNew();
    if (store == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15009, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store new error: callback return NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_STORE_ERR_NEW);
        return NULL;
    }

    return store;
}

HITLS_CERT_Store *SAL_CERT_StoreDup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
    if (mgrCtx == NULL || store == NULL || mgrCtx->method.certStoreDup == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15008, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store dup error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    HITLS_CERT_Store *newStore = mgrCtx->method.certStoreDup(store);
    if (newStore == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15062, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store dup error: callback return NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_STORE_DUP);
        return NULL;
    }

    return newStore;
}

void SAL_CERT_StoreFree(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Store *store)
{
    if (mgrCtx == NULL || store == NULL || mgrCtx->method.certStoreFree == NULL) {
        return;
    }

    mgrCtx->method.certStoreFree(store);
    return;
}

int32_t SAL_CERT_BuildChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **certList, uint32_t *num)
{
    if (config == NULL || store == NULL || cert == NULL || certList == NULL || num == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.buildCertChain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.buildCertChain(config, store, cert, certList, num);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15464, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store build chain by cert error: ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_BUILD_CHAIN);
        return HITLS_CERT_ERR_BUILD_CHAIN;
    }

    return HITLS_SUCCESS;
}

int32_t SAL_CERT_VerifyChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **certList, uint32_t num)
{
    if (ctx == NULL || store == NULL || certList == NULL || num == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.verifyCertChain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.verifyCertChain(ctx, store, certList, num);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15465, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store verify chain error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
        return HITLS_CERT_ERR_VERIFY_CERT_CHAIN;
    }

    return HITLS_SUCCESS;
}

int32_t SAL_CERT_X509Encode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len, uint32_t *usedLen)
{
    if (ctx == NULL || cert == NULL || buf == NULL || len == 0 || usedLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.certEncode == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.certEncode(ctx, cert, buf, len, usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15466, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode cert error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_ENCODE_CERT);
        return HITLS_CERT_ERR_ENCODE_CERT;
    }

    return HITLS_SUCCESS;
}

HITLS_CERT_X509 *SAL_CERT_X509Parse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || len == 0) {
        return NULL;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.certParse == NULL) {
        return NULL;
    }

    HITLS_CERT_X509 *cert = mgrCtx->method.certParse(config, buf, len, type, format);
    if (cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15467, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse cert error: len = %u, type = %u, format = %u.", len, type, format, 0);
        return NULL;
    }

    return cert;
}

HITLS_CERT_X509 *SAL_CERT_X509Dup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert)
{
    if (mgrCtx == NULL || cert == NULL || mgrCtx->method.certDup == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15002, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup cert error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    HITLS_CERT_X509 *newCert = mgrCtx->method.certDup(cert);
    if (newCert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15181, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup cert error: callback return NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_X509_DUP);
        return NULL;
    }

    return newCert;
}

void SAL_CERT_X509Free(HITLS_CERT_X509 *cert)
{
    if (cert == NULL || g_certMgrMethod.certFree == NULL) {
        return;
    }

    g_certMgrMethod.certFree(cert);
    return;
}

HITLS_CERT_X509 *SAL_CERT_X509Ref(const CERT_MgrCtx *mgrCtx, HITLS_CERT_X509 *cert)
{
    if (mgrCtx == NULL || cert == NULL || mgrCtx->method.certRef == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15335, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ref cert error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    HITLS_CERT_X509 *newCert = mgrCtx->method.certRef(cert);
    if (newCert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15336, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ref cert error: callback return NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_X509_REF);
        return NULL;
    }

    return newCert;
}

HITLS_CERT_Key *SAL_CERT_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || len == 0) {
        return NULL;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.keyParse == NULL) {
        return NULL;
    }

    HITLS_CERT_Key *key = mgrCtx->method.keyParse(config, buf, len, type, format);
    if (key == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15180, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "parse key error: len = %u, type = %u, format = %u.", len, type, format, 0);
        return NULL;
    }

    return key;
}

HITLS_CERT_Key *SAL_CERT_KeyDup(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Key *key)
{
    if (mgrCtx == NULL || key == NULL || mgrCtx->method.keyDup == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15004, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup key error: input NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }

    HITLS_CERT_Key *newKey = mgrCtx->method.keyDup(key);
    if (newKey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15005, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "dup key error: callback return NULL.", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_KEY_DUP);
        return NULL;
    }

    return newKey;
}

void SAL_CERT_KeyFree(const CERT_MgrCtx *mgrCtx, HITLS_CERT_Key *key)
{
    if (mgrCtx == NULL || key == NULL || mgrCtx->method.keyFree == NULL) {
        return;
    }

    // use the EVP type to release data
    HITLS_CERT_UserKeyMgrMethod *method = SAL_CERT_GetUserKeyMgrMethod();
    if (method->userKeyFree != NULL) {
        method->userKeyFree(key);
        return;
    }

    mgrCtx->method.keyFree(key);
    return;
}

/* change the error code when modifying the ctrl command */
int32_t g_tlsCertCtrlErrorCode[] = {
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
};

int32_t SAL_CERT_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (config == NULL || store == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.certStoreCtrl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.certStoreCtrl(config, store, cmd, in, out);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15174, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert store ctrl callback error: ret = 0x%x, cmd = %u.", ret, cmd, 0, 0);
        BSL_ERR_PUSH_ERROR(g_tlsCertCtrlErrorCode[cmd]);
        return g_tlsCertCtrlErrorCode[cmd];
    }

    return HITLS_SUCCESS;
}

int32_t SAL_CERT_X509Ctrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.certCtrl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.certCtrl(config, cert, cmd, in, out);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15173, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert ctrl callback error: ret = 0x%x, cmd = %u.", ret, cmd, 0, 0);
        BSL_ERR_PUSH_ERROR(g_tlsCertCtrlErrorCode[cmd]);
        return g_tlsCertCtrlErrorCode[cmd];
    }

    return HITLS_SUCCESS;
}

int32_t SAL_CERT_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd, void *in, void *out)
{
    if (config == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.keyCtrl == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.keyCtrl(config, key, cmd, in, out);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15172, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "key ctrl callback error: ret = 0x%x, cmd = %u.", ret, cmd, 0, 0);
        BSL_ERR_PUSH_ERROR(g_tlsCertCtrlErrorCode[cmd]);
        return g_tlsCertCtrlErrorCode[cmd];
    }

    return HITLS_SUCCESS;
}

int32_t SAL_CERT_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, CERT_SignParam *signParam)
{
    if (ctx == NULL || key == NULL || signParam == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.createSign == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.createSign(ctx, key, signParam->signAlgo, signParam->hashAlgo,
        signParam->data, signParam->dataLen, signParam->sign, &signParam->signLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15536, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "create signature error: sign algo = %u, hash algo = %u, dataLen = %u, signLen = %u",
            signParam->signAlgo, signParam->hashAlgo, signParam->dataLen, signParam->signLen);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15962, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "callback ret = 0x%x", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_CREATE_SIGN);
        return HITLS_CERT_ERR_CREATE_SIGN;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, CERT_SignParam *signParam)
{
    if (key == NULL || ctx == NULL || signParam == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.verifySign == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.verifySign(ctx, key, signParam->signAlgo, signParam->hashAlgo,
        signParam->data, signParam->dataLen, signParam->sign, signParam->signLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15964, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "verify signature error: sign algo = %u, hash algo = %u, dataLen = %u, signLen = %u",
            signParam->signAlgo, signParam->hashAlgo, signParam->dataLen, signParam->signLen);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15969, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "callback ret = 0x%x", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_VERIFY_SIGN);
        return HITLS_CERT_ERR_VERIFY_SIGN;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_KeyEncrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.encrypt == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.encrypt(ctx, key, in, inLen, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15059, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "pubkey encrypt error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_ENCRYPT);
        return HITLS_CERT_ERR_ENCRYPT;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_KeyDecrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.decrypt == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.decrypt(ctx, key, in, inLen, out, outLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15060, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "private key decrypt error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_DECRYPT);
        return HITLS_CERT_ERR_DECRYPT;
    }
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_CheckPrivateKey(const HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key)
{
    if (config == NULL || cert == NULL || key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL || mgrCtx->method.checkPrivateKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    int32_t ret = mgrCtx->method.checkPrivateKey(config, cert, key);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15061, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "check cert and private key error: callback ret = 0x%x.", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_CHECK_CERT_AND_KEY);
        return HITLS_CERT_ERR_CHECK_CERT_AND_KEY;
    }
    return HITLS_SUCCESS;
}
