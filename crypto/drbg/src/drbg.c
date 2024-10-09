/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_DRBG

#include <stdlib.h>
#include <securec.h>
#include "crypt_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "drbg_local.h"


#define DRBG_NONCE_FROM_ENTROPY (2)

// According to the definition of DRBG_Ctx, ctx->seedMeth is not NULL
static void DRBG_CleanEntropy(DRBG_Ctx *ctx, CRYPT_Data *entropy)
{
    CRYPT_RandSeedMethod *seedMeth = NULL;

    if (ctx == NULL || CRYPT_IsDataNull(entropy)) {
        return;
    }

    seedMeth = &ctx->seedMeth;

    if (seedMeth->cleanEntropy != NULL) {
        seedMeth->cleanEntropy(ctx->seedCtx, entropy);
    }

    entropy->data = NULL;
    entropy->len = 0;

    return;
}

// According to the definition of DRBG_Ctx, ctx->seedMeth is not NULL
static int32_t DRBG_GetEntropy(DRBG_Ctx *ctx, CRYPT_Data *entropy, bool addEntropy)
{
    int32_t ret;
    CRYPT_RandSeedMethod *seedMeth = NULL;
    CRYPT_Range entropyRange = ctx->entropyRange;
    uint32_t strength = ctx->strength;

    seedMeth = &ctx->seedMeth;

    if (addEntropy) {
        strength += strength / DRBG_NONCE_FROM_ENTROPY;
        entropyRange.min += ctx->nonceRange.min;
        entropyRange.max += ctx->nonceRange.max;
    }

    if (seedMeth->getEntropy == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }

    // CPRNG is implemented by hooks, in DRBG, the CPRNG is not verified,
    // but only the entropy source pointer and its length are verified.
    ret = seedMeth->getEntropy(ctx->seedCtx, entropy, strength, &entropyRange);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }

    if (CRYPT_CHECK_DATA_INVALID(entropy)) {
        goto ERR;
    }

    if (!CRYPT_IN_RANGE(entropy->len, &entropyRange)) {
        goto ERR;
    }
    return CRYPT_SUCCESS;

ERR:
    DRBG_CleanEntropy(ctx, entropy);
    BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
    return CRYPT_DRBG_FAIL_GET_ENTROPY;
}

// According to the definition of DRBG_Ctx, ctx->seedMeth is not NULL
static void DRBG_CleanNonce(DRBG_Ctx *ctx, CRYPT_Data *nonce)
{
    CRYPT_RandSeedMethod *seedMeth = NULL;

    if (ctx == NULL || CRYPT_IsDataNull(nonce)) {
        return;
    }

    seedMeth = &ctx->seedMeth;

    if (seedMeth->cleanNonce != NULL) {
        seedMeth->cleanNonce(ctx->seedCtx, nonce);
    }
    nonce->data = NULL;
    nonce->len = 0;
    return;
}

// According to the definition of DRBG_Ctx, ctx->seedMeth is not NULL
static int32_t DRBG_GetNonce(DRBG_Ctx *ctx, CRYPT_Data *nonce, bool *addEntropy)
{
    int32_t ret;
    CRYPT_RandSeedMethod *seedMeth = NULL;

    seedMeth = &ctx->seedMeth;

    // Allowed nonce which entered by the user can be NULL.
    // In this case, set *addEntropy to true to obtain the nonce from the entropy.
    if (seedMeth->getNonce == NULL || ctx->nonceRange.max == 0) {
        if (ctx->nonceRange.min > 0) {
            *addEntropy = true;
        }
        return CRYPT_SUCCESS;
    }

    ret = seedMeth->getNonce(ctx->seedCtx, nonce, ctx->strength, &ctx->nonceRange);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_NONCE);
        return CRYPT_DRBG_FAIL_GET_NONCE;
    }

    if (CRYPT_CHECK_DATA_INVALID(nonce)) {
        goto ERR;
    }

    if (!CRYPT_IN_RANGE(nonce->len, &ctx->nonceRange)) {
        goto ERR;
    }

    return CRYPT_SUCCESS;

ERR:
    DRBG_CleanNonce(ctx, nonce);
    BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_NONCE);
    return CRYPT_DRBG_FAIL_GET_NONCE;
}

void DRBG_Free(DRBG_Ctx *ctx)
{
    if (ctx == NULL || ctx->meth == NULL || ctx->meth->free == NULL) {
        return;
    }

    void (*ctxFree)(DRBG_Ctx *ctx) = ctx->meth->free;

    DRBG_Uninstantiate(ctx);
    ctxFree(ctx);

    return;
}

int32_t DRBG_Instantiate(DRBG_Ctx *ctx, const uint8_t *person, uint32_t persLen)
{
    int32_t ret;
    CRYPT_Data entropy = {NULL, 0};
    CRYPT_Data nonce = {NULL, 0};
    CRYPT_Data pers = {(uint8_t *)(uintptr_t)person, persLen};
    bool addEntropy = false;

    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (CRYPT_CHECK_DATA_INVALID(&pers)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (persLen > ctx->maxPersLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_INVALID_LEN);
        return CRYPT_DRBG_INVALID_LEN;
    }

    if (ctx->state != DRBG_STATE_UNINITIALISED) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ERR_STATE);
        return CRYPT_DRBG_ERR_STATE;
    }

    ctx->state = DRBG_STATE_ERROR;

    ret = DRBG_GetNonce(ctx, &nonce, &addEntropy);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_NONCE;
    }

    ret = DRBG_GetEntropy(ctx, &entropy, addEntropy);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_ENTROPY;
    }

    ret = ctx->meth->instantiate(ctx, &entropy, &nonce, &pers);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_ENTROPY;
    }

    ctx->state = DRBG_STATE_READY;
    ctx->reseedCtr = 1;

ERR_ENTROPY:
    DRBG_CleanEntropy(ctx, &entropy);
ERR_NONCE:
    DRBG_CleanNonce(ctx, &nonce);

    return ret;
}

static inline bool DRBG_IsNeedReseed(const DRBG_Ctx *ctx, bool pr)
{
    if (pr) {
        return true;
    }

    if (ctx->reseedCtr > ctx->reseedInterval) {
        return true;
    }
    return false;
}

int32_t DRBG_Reseed(DRBG_Ctx *ctx, const uint8_t *adin, uint32_t adinLen)
{
    int32_t ret;
    CRYPT_Data entropy = {NULL, 0};
    CRYPT_Data adinData = {(uint8_t*)(uintptr_t)adin, adinLen};

    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (CRYPT_CHECK_BUF_INVALID(adin, adinLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (adinLen > ctx->maxAdinLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_INVALID_LEN);
        return CRYPT_DRBG_INVALID_LEN;
    }

    if (ctx->state != DRBG_STATE_READY) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ERR_STATE);
        return CRYPT_DRBG_ERR_STATE;
    }

    ctx->state = DRBG_STATE_ERROR;

    ret = DRBG_GetEntropy(ctx, &entropy, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = ctx->meth->reseed(ctx, &entropy, &adinData);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ctx->reseedCtr = 1;
    ctx->state = DRBG_STATE_READY;

ERR:
    DRBG_CleanEntropy(ctx, &entropy);

    return ret;
}

int32_t DRBG_Generate(DRBG_Ctx *ctx,
                      uint8_t *out, uint32_t outLen,
                      const uint8_t *adin, uint32_t adinLen,
                      bool pr)
{
    int32_t ret;
    CRYPT_Data adinData = {(uint8_t*)(uintptr_t)adin, adinLen};

    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (out == NULL || outLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (CRYPT_CHECK_BUF_INVALID(adin, adinLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (outLen > ctx->maxRequest || adinLen > ctx->maxAdinLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_INVALID_LEN);
        return CRYPT_DRBG_INVALID_LEN;
    }

    if (ctx->state != DRBG_STATE_READY) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ERR_STATE);
        return CRYPT_DRBG_ERR_STATE;
    }

    if (DRBG_IsNeedReseed(ctx, pr)) {
        ret = DRBG_Reseed(ctx, adin, adinLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        adinData.data = NULL;
        adinData.len = 0;
    }

    ret = ctx->meth->generate(ctx, out, outLen, &adinData);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->reseedCtr++;

    return ret;
}

int32_t DRBG_Uninstantiate(DRBG_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ctx->meth->uninstantiate(ctx);

    ctx->reseedCtr = 0;
    ctx->state = DRBG_STATE_UNINITIALISED;

    return CRYPT_SUCCESS;
}
#endif /* HITLS_CRYPTO_DRBG */
