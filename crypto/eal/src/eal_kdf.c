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

bool CRYPT_EAL_KdfIsValidAlgId(CRYPT_KDF_AlgId id)
{
    return EAL_KdfFindMethod(id, NULL) == CRYPT_SUCCESS;
}

CRYPT_EAL_KdfCTX *KdfNewCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName, bool isProvider)
{
    (void)libCtx;
    (void)attrName;
    (void)isProvider;
    CRYPT_EAL_KdfCTX *ctx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_KdfCTX));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    void *provCtx = NULL;
    int32_t ret;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == true) {
        ret = EAL_ProviderKdfFindMethod(algId, libCtx, attrName, &ctx->method, &provCtx);
    } else
#endif
    {
        ret = EAL_KdfFindMethod(algId, &ctx->method);
    }
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, ret);
        goto ERR;
    }

    if (ctx->method.newCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, CRYPT_PROVIDER_ERR_IMPL_NULL);
        goto ERR;
    }
    ctx->data = ctx->method.newCtx(provCtx, algId);
    if (ctx->data == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, algId, CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }

    ctx->id = algId;
    return ctx;
ERR:
    BSL_SAL_Free(ctx);
    return NULL;
}

CRYPT_EAL_KdfCTX *CRYPT_EAL_ProviderKdfNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName)
{
    return KdfNewCtxInner(libCtx, algId, attrName, true);
}

CRYPT_EAL_KdfCTX *CRYPT_EAL_KdfNewCtx(CRYPT_KDF_AlgId algId)
{
    return KdfNewCtxInner(NULL, algId, NULL, false);
}

int32_t CRYPT_EAL_KdfSetParam(CRYPT_EAL_KdfCTX *ctx, const BSL_Param *param)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->method.setParam == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->method.setParam(ctx->data, param);
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
    if (ctx->method.derive == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
        return CRYPT_EAL_ALG_NOT_SUPPORT;
    }

    int32_t ret = ctx->method.derive(ctx->data, key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_KdfDeInitCtx(CRYPT_EAL_KdfCTX *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, CRYPT_KDF_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->method.deinit(ctx->data);
    return CRYPT_SUCCESS;
}

void CRYPT_EAL_KdfFreeCtx(CRYPT_EAL_KdfCTX *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->method.freeCtx != NULL) {
        ctx->method.freeCtx(ctx->data);
        EAL_EVENT_REPORT(CRYPT_EVENT_ZERO, CRYPT_ALGO_KDF, ctx->id, CRYPT_SUCCESS);
    } else {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_KDF, ctx->id, CRYPT_EAL_ALG_NOT_SUPPORT);
    }
    BSL_SAL_Free(ctx);
}

#endif
