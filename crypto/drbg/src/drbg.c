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
#ifdef HITLS_CRYPTO_DRBG

#include <stdlib.h>
#include <stdbool.h>
#include <securec.h>
#include "crypt_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_ealinit.h"
#include "eal_entropy.h"
#include "bsl_err_internal.h"
#include "drbg_local.h"
#include "crypt_drbg_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "bsl_sal.h"

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

#ifdef HITLS_CRYPTO_DRBG_CTR
#define RAND_AES128_KEYLEN  16
#define RAND_AES192_KEYLEN  24
#define RAND_AES256_KEYLEN  32
#define RAND_SM4_KEYLEN     16

static int32_t GetCipherKeyLen(int32_t id, uint32_t *keyLen)
{
    switch (id) {
        case CRYPT_CIPHER_AES128_CTR:
            *keyLen = RAND_AES128_KEYLEN;
            break;
        case CRYPT_CIPHER_AES192_CTR:
            *keyLen = RAND_AES192_KEYLEN;
            break;
        case CRYPT_CIPHER_AES256_CTR:
            *keyLen = RAND_AES256_KEYLEN;
            break;
        case CRYPT_CIPHER_SM4_CTR:
            *keyLen = RAND_SM4_KEYLEN;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}
#endif

static int32_t DRBG_Restart(DRBG_Ctx *ctx)
{
    if (ctx->state == DRBG_STATE_ERROR) {
        (void)DRBG_Uninstantiate(ctx);
    }
    if (ctx->state == DRBG_STATE_UNINITIALISED) {
        int32_t ret = DRBG_Instantiate(ctx, NULL, 0, NULL);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

DRBG_Ctx *DRBG_New(int32_t algId, BSL_Param *param)
{
    int32_t ret;

    CRYPT_RandSeedMethod seedMethArray = {0};
    CRYPT_RandSeedMethod *seedMeth = &seedMethArray;
    void *seedCtx = NULL;

    const BSL_Param *temp = NULL;
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_GETENTROPY)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
            (void **)&(seedMethArray.getEntropy), NULL), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_CLEANENTROPY)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
            (void **)&(seedMethArray.cleanEntropy), NULL), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_GETNONCE)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR,
            (void **)&(seedMethArray.getNonce), NULL), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_CLEANNONCE)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR,
            (void **)&(seedMethArray.cleanNonce), NULL), ret);
    }

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEEDCTX)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, &seedCtx, NULL), ret);
    }

    DRBG_Ctx *drbg = NULL;
    EAL_RandMethLookup lu = { 0 };
    if (EAL_RandFindMethod(algId, &lu) != CRYPT_SUCCESS) {
        return NULL;
    }
    switch (lu.type) {
#ifdef HITLS_CRYPTO_DRBG_HASH
        case RAND_TYPE_MD:
            drbg = DRBG_NewHashCtx((const EAL_MdMethod *)(lu.method), algId == CRYPT_RAND_SM3, seedMeth, seedCtx);
            break;
#endif
#ifdef HITLS_CRYPTO_DRBG_HMAC
        case RAND_TYPE_MAC:
            drbg = DRBG_NewHmacCtx((const EAL_MacMethod *)(lu.method), lu.methodId, seedMeth, seedCtx);
            break;
#endif
#ifdef HITLS_CRYPTO_DRBG_CTR
        case RAND_TYPE_SM4_DF:
        case RAND_TYPE_AES:
        case RAND_TYPE_AES_DF: {
            bool isUsedDF = (lu.type == RAND_TYPE_AES_DF || lu.type == RAND_TYPE_SM4_DF) ? true : false;
            uint32_t keyLen;
            if (GetCipherKeyLen(lu.methodId, &keyLen) != CRYPT_SUCCESS) {
                return NULL;
            }
            drbg = DRBG_NewCtrCtx((const EAL_SymMethod *)(lu.method), keyLen, algId == CRYPT_RAND_SM4_CTR_DF, isUsedDF,
                seedMeth, seedCtx);
            break;
        }
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
            return NULL;
    }
    return drbg;

ERR:
    return NULL;
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

int32_t DRBG_Instantiate(DRBG_Ctx *ctx, const uint8_t *person, uint32_t persLen, BSL_Param *param)
{
    (void) param;
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
        goto ERR_NONCE;
    }

    ret = DRBG_GetEntropy(ctx, &entropy, addEntropy);
    if (ret != CRYPT_SUCCESS) {
        goto ERR_ENTROPY;
    }

    ret = ctx->meth->instantiate(ctx, &entropy, &nonce, &pers);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR_ENTROPY;
    }

    ctx->state = DRBG_STATE_READY;
    ctx->reseedCtr = 1;
#if defined(HITLS_CRYPTO_DRBG_GM)
    if (ctx->reseedIntervalTime != 0) {
        ctx->lastReseedTime = BSL_SAL_CurrentSysTimeGet();
    }
#endif
ERR_ENTROPY:
    DRBG_CleanEntropy(ctx, &entropy);
ERR_NONCE:
    DRBG_CleanNonce(ctx, &nonce);

    return ret;
}

static inline bool DRBG_IsNeedReseed(DRBG_Ctx *ctx, bool pr)
{
    int32_t forkId = BSL_SAL_GetPid();
    if (ctx->forkId != forkId) {
        ctx->forkId = forkId;
        return true;
    }
    if (pr) {
        return true;
    }

    if (ctx->reseedCtr > ctx->reseedInterval) {
        return true;
    }
#if defined(HITLS_CRYPTO_DRBG_GM)
    if (ctx->reseedIntervalTime != 0) {
        int64_t time = BSL_SAL_CurrentSysTimeGet();
        return ((time - ctx->lastReseedTime) > ctx->reseedIntervalTime) ? true : false;
    }
#endif
    return false;
}

int32_t DRBG_Reseed(DRBG_Ctx *ctx, const uint8_t *adin, uint32_t adinLen, BSL_Param *param)
{
    (void) param;
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
        if (DRBG_Restart(ctx) != CRYPT_SUCCESS) {
            return CRYPT_DRBG_ERR_STATE;
        }
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
#if defined(HITLS_CRYPTO_DRBG_GM)
    if (ctx->reseedIntervalTime != 0) {
        ctx->lastReseedTime = BSL_SAL_CurrentSysTimeGet();
    }
#endif
    ctx->state = DRBG_STATE_READY;

ERR:
    DRBG_CleanEntropy(ctx, &entropy);

    return ret;
}

int32_t DRBG_Generate(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen,  bool pr)
{
    int32_t ret;
    CRYPT_Data adinData = {(uint8_t*)(uintptr_t)adin, adinLen};
    if (CRYPT_CHECK_BUF_INVALID(adin, adinLen)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (outLen > ctx->maxRequest || adinLen > ctx->maxAdinLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_INVALID_LEN);
        return CRYPT_DRBG_INVALID_LEN;
    }

    if (ctx->state != DRBG_STATE_READY) {
        if (DRBG_Restart(ctx) != CRYPT_SUCCESS) {
            return CRYPT_DRBG_ERR_STATE;
        }
    }

    if (DRBG_IsNeedReseed(ctx, pr)) {
        ret = DRBG_Reseed(ctx, adin, adinLen, NULL);
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

int32_t DRBG_GenerateBytes(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen,  BSL_Param *param)
{
    if (ctx == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    bool pr = false;
    const BSL_Param *temp = NULL;
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_PR)) != NULL) {
        uint32_t boolSize = sizeof(bool);
        ret = BSL_PARAM_GetValue(temp, CRYPT_PARAM_RAND_PR, BSL_PARAM_TYPE_BOOL, (void *)&pr, &boolSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    uint32_t block = ctx->maxRequest;
    if (block == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    for (uint32_t leftLen = outLen; leftLen > 0; leftLen -= block, out += block) {
        block = leftLen > block ? block : leftLen;
        ret = DRBG_Generate(ctx, out, block, adin, adinLen, pr);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
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

#if defined(HITLS_CRYPTO_DRBG_GM)
static int32_t DRBG_SetGmlevel(DRBG_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (*(const uint32_t *)val == 1) {
        ctx->reseedInterval = DRBG_RESEED_INTERVAL_GM1;
        ctx->reseedIntervalTime = DRBG_RESEED_TIME_GM1;
    } else {
        ctx->reseedInterval = DRBG_RESEED_INTERVAL_GM2;
        ctx->reseedIntervalTime = DRBG_RESEED_TIME_GM2;
    }
    return CRYPT_SUCCESS;
}

static int32_t DRBG_SetReseedIntervalTime(DRBG_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->reseedIntervalTime = *(const uint64_t *)val;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_DRBG_GM

static int32_t DRBG_SetReseedInterval(DRBG_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    ctx->reseedInterval = *(const uint32_t *)val;
    return CRYPT_SUCCESS;
}

int32_t DRBG_Ctrl(DRBG_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
#if defined(HITLS_CRYPTO_DRBG_GM)
        case CRYPT_CTRL_SET_GM_LEVEL:
            return DRBG_SetGmlevel(ctx, val, len);
        case CRYPT_CTRL_SET_RESEED_TIME:
            return DRBG_SetReseedIntervalTime(ctx, val, len);
#endif // HITLS_CRYPTO_DRBG_GM
        case CRYPT_CTRL_SET_RESEED_INTERVAL:
            return DRBG_SetReseedInterval(ctx, val, len);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}

static const DrbgIdMap DRBG_METHOD_MAP[] = {
#if defined(HITLS_CRYPTO_DRBG_HASH)
    { CRYPT_RAND_SHA1, CRYPT_MD_SHA1, RAND_TYPE_MD },
    { CRYPT_RAND_SHA224, CRYPT_MD_SHA224, RAND_TYPE_MD },
    { CRYPT_RAND_SHA256, CRYPT_MD_SHA256, RAND_TYPE_MD },
    { CRYPT_RAND_SHA384, CRYPT_MD_SHA384, RAND_TYPE_MD },
    { CRYPT_RAND_SHA512, CRYPT_MD_SHA512, RAND_TYPE_MD },
#ifdef HITLS_CRYPTO_DRBG_GM
    { CRYPT_RAND_SM3, CRYPT_MD_SM3, RAND_TYPE_MD },
#endif
#endif
#if defined(HITLS_CRYPTO_DRBG_HMAC)
    { CRYPT_RAND_HMAC_SHA1, CRYPT_MAC_HMAC_SHA1, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA224, CRYPT_MAC_HMAC_SHA224, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA256, CRYPT_MAC_HMAC_SHA256, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA384, CRYPT_MAC_HMAC_SHA384, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA512, CRYPT_MAC_HMAC_SHA512, RAND_TYPE_MAC },
#endif
#if defined(HITLS_CRYPTO_DRBG_CTR)
    { CRYPT_RAND_AES128_CTR, CRYPT_CIPHER_AES128_CTR, RAND_TYPE_AES },
    { CRYPT_RAND_AES192_CTR, CRYPT_CIPHER_AES192_CTR, RAND_TYPE_AES },
    { CRYPT_RAND_AES256_CTR, CRYPT_CIPHER_AES256_CTR, RAND_TYPE_AES },
    { CRYPT_RAND_AES128_CTR_DF, CRYPT_CIPHER_AES128_CTR, RAND_TYPE_AES_DF },
    { CRYPT_RAND_AES192_CTR_DF, CRYPT_CIPHER_AES192_CTR, RAND_TYPE_AES_DF },
    { CRYPT_RAND_AES256_CTR_DF, CRYPT_CIPHER_AES256_CTR, RAND_TYPE_AES_DF },
#ifdef HITLS_CRYPTO_DRBG_GM
    { CRYPT_RAND_SM4_CTR_DF, CRYPT_CIPHER_SM4_CTR, RAND_TYPE_SM4_DF }
#endif
#endif
};

const DrbgIdMap *DRBG_GetIdMap(CRYPT_RAND_AlgId id)
{
    uint32_t num = sizeof(DRBG_METHOD_MAP) / sizeof(DRBG_METHOD_MAP[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (DRBG_METHOD_MAP[i].drbgId == id) {
            return &DRBG_METHOD_MAP[i];
        }
    }
    return NULL;
}

#endif /* HITLS_CRYPTO_DRBG */
