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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_ENTROPY)
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "eal_entropy.h"

#define EAL_MAX_ENTROPY_EVERY_BYTE 8

static uint32_t GetMinLen(void *pool, uint32_t entropy, uint32_t minLen)
{
    uint32_t minEntropy = ENTROPY_SeedPoolGetMinEntropy(pool);
    if (minEntropy == 0) {
        return 0;
    }
    uint32_t len = (uint32_t)(((uint64_t)entropy + (uint64_t)minEntropy - 1) / (uint64_t)minEntropy);
    /* '<' indicates that the data with a length of len can provide sufficient bit entropy. */
    if (len < minLen) {
        len = minLen;
    }
    return len;
}

EAL_EntropyCtx *EAL_EntropyNewCtx(CRYPT_EAL_SeedPoolCtx *seedPool, uint8_t isNpesUsed, uint32_t minLen,
    uint32_t maxLen, uint32_t entropy)
{
    if (minLen > maxLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return NULL;
    }
    if (!ENTROPY_SeedPoolCheckState(seedPool->pool, isNpesUsed)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_STATE_ERROR);
        return NULL;
    }
    if (entropy > maxLen * EAL_MAX_ENTROPY_EVERY_BYTE) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_RANGE_ERROR);
        return NULL;
    }
    EAL_EntropyCtx *ctx = BSL_SAL_Malloc(sizeof(EAL_EntropyCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(EAL_EntropyCtx), 0, sizeof(EAL_EntropyCtx));
    ctx->minLen = minLen;
    ctx->maxLen = maxLen;
    ctx->isNpesUsed = isNpesUsed;
    ctx->requestEntropy = entropy;
    ctx->isNeedFe = (minLen == maxLen) ? true : false;
    uint32_t needLen;
    if (ctx->isNeedFe) {
#ifdef HITLS_CRYPTO_DRBG_GM
        ctx->ecfuncId = CRYPT_MAC_HMAC_SM3;
#else
        ctx->ecfuncId = CRYPT_MAC_HMAC_SHA256;
#endif
        ctx->ecfunc = EAL_EntropyGetECF(ctx->ecfuncId);
        needLen = minLen;
    } else {
        needLen = GetMinLen(seedPool->pool, entropy, minLen);
    }
    ctx->buf = BSL_SAL_Malloc(needLen);
    if (ctx->buf == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->bufLen = needLen;
    return ctx;
}

void EAL_EntropyFreeCtx(EAL_EntropyCtx *ctx)
{
    if (ctx->buf != NULL) {
        (void)memset_s(ctx->buf, ctx->bufLen, 0, ctx->bufLen);
        BSL_SAL_FREE(ctx->buf);
    }
    BSL_SAL_Free(ctx);
}

static int32_t EAL_EntropyObtain(void *seedPool, EAL_EntropyCtx *ctx)
{
    while (ctx->curEntropy < ctx->requestEntropy) {
        uint32_t needEntropy = ctx->requestEntropy - ctx->curEntropy;
        uint8_t *buff = ctx->buf + ctx->curLen;
        uint32_t len = ctx->bufLen - ctx->curLen;
        uint32_t entropy = ENTROPY_SeedPoolCollect(seedPool, ctx->isNpesUsed, needEntropy, buff, &len);
        if (entropy == 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED);
            return CRYPT_SEED_POOL_NO_ENTROPY_OBTAINED;
        }

        ctx->curEntropy += entropy;
        ctx->curLen += len;
    }
    /*
     * If the entropy data length is greater than the upper limit, the entropy source quality cannot meet the
     * requirements and an error is reported.
     */
    if (ctx->curLen > ctx->maxLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT);
        return CRYPT_SEED_POOL_NOT_MEET_REQUIREMENT;
    }
    if (ctx->curLen < ctx->minLen) {
        /*
         * If the length of the entropy data is less than the lower limit of the required length,
         * the entropy data that meets the length requirement is read without considering the entropy.
         */
        uint32_t len = ctx->minLen - ctx->curLen;
        uint32_t ent = ENTROPY_SeedPoolCollect(seedPool, true, 0, ctx->buf + ctx->curLen, &len);
        if (ent == 0 || len != ctx->minLen - ctx->curLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NO_SUFFICIENT_ENTROPY);
            return CRYPT_SEED_POOL_NO_SUFFICIENT_ENTROPY;
        }
        ctx->curLen = ctx->minLen;
    }
    return CRYPT_SUCCESS;
}

static int32_t EAL_EntropyFesObtain(void *seedPool, EAL_EntropyCtx *ctx)
{
    ENTROPY_ECFCtx seedCtx = {ctx->ecfuncId, ctx->ecfunc};
    int32_t ret = ENTROPY_GetFullEntropyInput(&seedCtx, seedPool, ctx->isNpesUsed, ctx->requestEntropy, ctx->buf,
        ctx->bufLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->curEntropy = ctx->requestEntropy;
    ctx->curLen = ctx->bufLen;
    return ret;
}

int32_t EAL_EntropyCollection(CRYPT_EAL_SeedPoolCtx *seedPool, EAL_EntropyCtx *ctx)
{
    if (!ENTROPY_SeedPoolCheckState(seedPool->pool, true)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_STATE_ERROR);
        return CRYPT_SEED_POOL_STATE_ERROR;
    }
    if (!ctx->isNeedFe) {
        return EAL_EntropyObtain(seedPool->pool, ctx);
    } else {
        return EAL_EntropyFesObtain(seedPool->pool, ctx);
    }
}

uint8_t *EAL_EntropyDetachBuf(EAL_EntropyCtx *ctx, uint32_t *len)
{
    if (ctx->curEntropy < ctx->requestEntropy) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return NULL;
    }
    uint8_t *data = ctx->buf;
    *len = ctx->curLen;
    ctx->buf = NULL;
    ctx->bufLen = 0;
    ctx->curLen = 0;
    ctx->curEntropy = 0;
    return data;
}

static int32_t GetEntropy(void *seedCtx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    return CRYPT_EAL_SeedPoolGetEntropy(seedCtx, entropy, strength, lenRange);
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_CleanseData(entropy->data, entropy->len);
    BSL_SAL_FREE(entropy->data);
}

static int32_t GetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    return GetEntropy(ctx, nonce, strength, lenRange);
}

static void CleanNonce(void *ctx, CRYPT_Data *nonce)
{
    CleanEntropy(ctx, nonce);
}

int32_t EAL_SetDefaultEntropyMeth(CRYPT_RandSeedMethod *meth)
{
    if (meth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    meth->getEntropy = GetEntropy;
    meth->cleanEntropy = CleanEntropy;
    meth->cleanNonce = CleanNonce;
    meth->getNonce = GetNonce;
    return CRYPT_SUCCESS;
}

#endif
