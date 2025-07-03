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
#ifdef HITLS_CRYPTO_CMVP

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "crypt_cmvp.h"
#include "cmvp_common.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_entropy.h"
#include "bsl_sal.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_cmvp.h"
#include "crypt_cmvp.h"
#include "bsl_errno.h"

bool CMVP_MlKemPct(CRYPT_EAL_PkeyCtx *pkey)
{
    uint32_t cipherLen = 0;
    uint8_t *ciphertext = NULL;
    uint8_t sharedKey[32] = {0};
    uint32_t sharedLen = sizeof(sharedKey);
    uint8_t sharedKey2[32] = {0};
    uint32_t sharedLen2 = sizeof(sharedKey2);

    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    if (ret != CRYPT_SUCCESS) {
        return false;
    }

    ciphertext = BSL_SAL_Malloc(cipherLen);
    if (ciphertext == NULL) {
        return false;
    }

    ret = CRYPT_EAL_PkeyEncaps(pkey, ciphertext, &cipherLen, sharedKey, &sharedLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(ciphertext);
        return false;
    }

    ret = CRYPT_EAL_PkeyDecaps(pkey, ciphertext, cipherLen, sharedKey2, &sharedLen2);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(ciphertext);
        return false;
    }

    BSL_SAL_FREE(ciphertext);
    if (sharedLen != sharedLen2 || memcmp(sharedKey, sharedKey2, sharedLen) != 0) {
        return false;
    }
    return true;
}

bool CMVP_Pct(CRYPT_EAL_PkeyCtx *pkey)
{
    CRYPT_PKEY_AlgId id = CRYPT_EAL_PkeyGetId(pkey);
    if (id == CRYPT_PKEY_DH || id == CRYPT_PKEY_X25519 || id == CRYPT_PKEY_ECDH) {
        return true;
    }
    if (id == CRYPT_PKEY_ML_KEM) {
        return CMVP_MlKemPct(pkey);
    }
    bool ret = false;
    uint8_t *sign = NULL;
    uint32_t signLen;
    const uint8_t msg[] = { 0x01, 0x02, 0x03, 0x04 };
    uint32_t mdId = CRYPT_MD_SHA512;

    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(signLen);
    GOTO_EXIT_IF(sign == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (id == CRYPT_PKEY_RSA) {
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId,
            sizeof(mdId)) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_EXIT_IF(CRYPT_EAL_PkeySign(pkey, id == CRYPT_PKEY_SM2 ? CRYPT_MD_SM3 : CRYPT_MD_SHA512,
        msg, sizeof(msg), sign, &signLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_PkeyVerify(pkey, id == CRYPT_PKEY_SM2 ? CRYPT_MD_SM3 : CRYPT_MD_SHA512,
        msg, sizeof(msg), sign, signLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
EXIT:
    BSL_SAL_FREE(sign);
    return ret;
}


#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_EAL_SetCmvpSelftestMethod(CRYPT_SelftestCtx *ctx, const CRYPT_EAL_Func *funcs)
{
    int32_t index = 0;
    EAL_CmvpSelftestMethod *method = BSL_SAL_Calloc(1, sizeof(EAL_CmvpSelftestMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLSELFTEST_NEWCTX:
                method->provNewCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLSELFTEST_GETVERSION:
                method->getVersion = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLSELFTEST_SELFTEST:
                method->selftest = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLSELFTEST_FREECTX:
                method->freeCtx = funcs[index].func;
                break;
            default:
                BSL_SAL_FREE(method);
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    ctx->method = method;
    return CRYPT_SUCCESS;
}

static CRYPT_SelftestCtx *CRYPT_CMVP_SelftestNewCtxInner(CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
    const CRYPT_EAL_Func *funcs = NULL;
    void *provCtx = NULL;
    int32_t algId = CRYPT_CMVP_PROVIDER_SELFTEST;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_SELFTEST, algId, attrName,
        &funcs, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    CRYPT_SelftestCtx *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_SelftestCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret = CRYPT_EAL_SetCmvpSelftestMethod(ctx, funcs);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    if (ctx->method->provNewCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_IMPL_NULL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->data = ctx->method->provNewCtx(provCtx);
    if (ctx->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->id = algId;
    ctx->isProvider = true;
    return ctx;
}
#endif // HITLS_CRYPTO_PROVIDER

CRYPT_SelftestCtx *CRYPT_CMVP_SelftestNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_CMVP_SelftestNewCtxInner(libCtx, attrName);
#else
    (void)libCtx;
    (void)attrName;
    return NULL;
#endif
}

const char *CRYPT_CMVP_GetVersion(CRYPT_SelftestCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    if (ctx->method == NULL || ctx->method->getVersion == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return NULL;
    }

    return ctx->method->getVersion(ctx->data);
}

int32_t CRYPT_CMVP_Selftest(CRYPT_SelftestCtx *ctx, CRYPT_CMVP_SELFTEST_TYPE type)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->selftest == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    return ctx->method->selftest(ctx->data, type);
}

void CRYPT_CMVP_SelftestFreeCtx(CRYPT_SelftestCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->method != NULL && ctx->method->freeCtx != NULL) {
        ctx->method->freeCtx(ctx->data);
    }

    BSL_SAL_FREE(ctx->method);
    BSL_SAL_FREE(ctx);
}

#endif
