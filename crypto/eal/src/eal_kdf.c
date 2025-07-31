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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_KDF)

#include <stdint.h>
#include "crypt_eal_kdf.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_local_types.h"
#include "crypt_eal_mac.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#endif
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "eal_mac_local.h"
#include "eal_kdf_local.h"
#ifdef HITLS_CRYPTO_HMAC
#include "crypt_hmac.h"
#endif
#ifdef HITLS_CRYPTO_PBKDF2
#include "crypt_pbkdf2.h"
#endif
#ifdef HITLS_CRYPTO_HKDF
#include "crypt_hkdf.h"
#endif
#ifdef HITLS_CRYPTO_KDFTLS12
#include "crypt_kdf_tls12.h"
#endif
#ifdef HITLS_CRYPTO_SCRYPT
#include "crypt_scrypt.h"
#endif
#include "eal_common.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

static CRYPT_EAL_KdfCTX *KdfAllocCtx(CRYPT_KDF_AlgId id, EAL_KdfUnitaryMethod *method)
{
    CRYPT_EAL_KdfCTX *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_KdfCTX));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    void *data = method->newCtx();
    if (data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, id, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->data = data;
    return ctx;
}

static void EalKdfCopyMethod(const EAL_KdfMethod *method, EAL_KdfUnitaryMethod *dest)
{
    dest->newCtx = method->newCtx;
    dest->setParam = method->setParam;
    dest->derive = method->derive;
    dest->deinit = method->deinit;
    dest->freeCtx = method->freeCtx;
    dest->ctrl = method->ctrl;
}

#ifdef HITLS_CRYPTO_PROVIDER
static int32_t CRYPT_EAL_SetKdfMethod(CRYPT_EAL_KdfCTX *ctx, const CRYPT_EAL_Func *funcs)
{
    int32_t index = 0;
    EAL_KdfUnitaryMethod *method = BSL_SAL_Calloc(1, sizeof(EAL_KdfUnitaryMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLKDF_NEWCTX:
                method->provNewCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_SETPARAM:
                method->setParam = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_DERIVE:
                method->derive = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_DEINITCTX:
                method->deinit = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_CTRL:
                method->ctrl = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLKDF_FREECTX:
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

CRYPT_EAL_KdfCTX *CRYPT_EAL_ProviderKdfNewCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
    const CRYPT_EAL_Func *funcs = NULL;
    void *provCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_KDF, algId, attrName,
        &funcs, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, ret);
        return NULL;
    }
    CRYPT_EAL_KdfCTX *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_KdfCTX));
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ret = CRYPT_EAL_SetKdfMethod(ctx, funcs);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    if (ctx->method->provNewCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, CRYPT_PROVIDER_ERR_IMPL_NULL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->data = ctx->method->provNewCtx(provCtx, algId);
    if (ctx->data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
    ctx->id = algId;
    ctx->isProvider = true;
    return ctx;
}
#endif // HITLS_CRYPTO_PROVIDER

bool CRYPT_EAL_KdfIsValidAlgId(CRYPT_KDF_AlgId id)
{
    const EAL_KdfMethod *method = EAL_KdfFindMethod(id);
    if (method == NULL) {
        return false;
    } else {
        return true;
    }
}

CRYPT_EAL_KdfCTX *CRYPT_EAL_ProviderKdfNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderKdfNewCtxInner(libCtx, algId, attrName);
#else
    (void)libCtx;
    (void)attrName;
    return CRYPT_EAL_KdfNewCtx(algId);
    return NULL;
#endif
}

CRYPT_EAL_KdfCTX *CRYPT_EAL_KdfNewCtx(CRYPT_KDF_AlgId algId)
{
    const EAL_KdfMethod *method = EAL_KdfFindMethod(algId);
    if (method == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    EAL_KdfUnitaryMethod *temp = BSL_SAL_Calloc(1, sizeof(EAL_KdfUnitaryMethod));
    if (temp == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, BSL_MALLOC_FAIL);
        return NULL;
    }
    EalKdfCopyMethod(method, temp);
    CRYPT_EAL_KdfCTX *ctx = KdfAllocCtx(algId, temp);
    if (ctx == NULL) {
        BSL_SAL_FREE(temp);
        return NULL;
    }

    ctx->id = algId;
    ctx->method = temp;
    return ctx;
}

int32_t CRYPT_EAL_KdfSetParam(CRYPT_EAL_KdfCTX *ctx, const BSL_Param *param)
{
    int32_t ret;
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->setParam == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    ret = ctx->method->setParam(ctx->data, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, ret);
    }
    return ret;
}

int32_t CRYPT_EAL_KdfDerive(CRYPT_EAL_KdfCTX *ctx, uint8_t *key, uint32_t keyLen)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method == NULL || ctx->method->derive == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->method->derive(ctx->data, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_KdfDeInitCtx(CRYPT_EAL_KdfCTX *ctx)
{
    if (ctx == NULL || ctx->method == NULL || ctx->method->deinit == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->method->deinit(ctx->data);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_KdfCtrl(CRYPT_EAL_KdfCTX *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || ctx->method == NULL || ctx->method->ctrl== NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = ctx->method->ctrl(ctx->data, cmd, val, valLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, ret);
    }

    return ret;
}

void CRYPT_EAL_KdfFreeCtx(CRYPT_EAL_KdfCTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->method == NULL || ctx->method->freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        BSL_SAL_FREE(ctx->method);
        BSL_SAL_FREE(ctx);
        return;
    }
    ctx->method->freeCtx(ctx->data);
    BSL_SAL_FREE(ctx->method);
    BSL_SAL_FREE(ctx);
    return;
}

#endif
