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
#ifdef HITLS_CRYPTO_HSS_LMS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "hss_local.h"

CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void)
{
    return (CRYPT_HSS_Ctx *)BSL_SAL_Calloc(1, sizeof(CRYPT_HSS_Ctx));
}

CRYPT_HSS_Ctx *CRYPT_HSS_NewCtxEx(void *libCtx)
{
    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

void CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ClearFree(ctx->privateKey, HSS_PRVKEY_LEN);
    BSL_SAL_ClearFree(ctx->publicKey, ctx->publicLen);
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        BSL_SAL_ClearFree(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
    }
    BSL_SAL_ClearFree(ctx, sizeof(CRYPT_HSS_Ctx));
}

CRYPT_HSS_Ctx *CRYPT_HSS_DupCtx(CRYPT_HSS_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_HSS_Ctx *newCtx = (CRYPT_HSS_Ctx *)CRYPT_HSS_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    memcpy(&newCtx->para, &srcCtx->para, sizeof(HSS_Para));
    if (srcCtx->publicKey != NULL && srcCtx->publicLen > 0) {
        newCtx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, srcCtx->publicLen);
        if (newCtx->publicKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            CRYPT_HSS_FreeCtx(newCtx);
            return NULL;
        }
        newCtx->publicLen = srcCtx->publicLen;
        memcpy(newCtx->publicKey, srcCtx->publicKey, newCtx->publicLen);
    }

    newCtx->signatureIndex = 0;
    return newCtx;
}

int32_t CRYPT_HSS_Cmp(CRYPT_HSS_Ctx *ctx1, CRYPT_HSS_Ctx *ctx2)
{
    if (ctx1 == NULL || ctx2 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }

    // Compare parameters
    if (ctx1->para.levels != ctx2->para.levels) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }
    for (uint32_t i = 0; i < ctx1->para.levels; i++) {
        if (ctx1->para.lmsType[i] != ctx2->para.lmsType[i] || ctx1->para.otsType[i] != ctx2->para.otsType[i]) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
    }

    // Compare public keys
    if ((ctx1->publicKey == NULL) != (ctx2->publicKey == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }
    if (ctx1->publicKey != NULL) {
        if (ctx1->publicLen != ctx2->publicLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
        if (ConstTimeMemcmp(ctx1->publicKey, ctx2->publicKey, ctx1->publicLen) == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
    }

    // Compare private keys -- constant-time to prevent timing side-channel leakage
    if ((ctx1->privateKey == NULL) != (ctx2->privateKey == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
        return CRYPT_HSS_CMP_FALSE;
    }
    if (ctx1->privateKey != NULL) {
        if (ConstTimeMemcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_LEN) == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_CMP_FALSE);
            return CRYPT_HSS_CMP_FALSE;
        }
    }

    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_HSS_LMS */
