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
#include "crypt_entropy.h"
#include "bsl_err_internal.h"
#include "drbg_local.h"
#include "eal_drbg_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"


#define DRBG_NONCE_FROM_ENTROPY (2)

typedef enum {
    RAND_AES128_KEYLEN = 16,
    RAND_AES192_KEYLEN = 24,
    RAND_AES256_KEYLEN = 32,
} RAND_AES_KeyLen;

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
static int32_t GetAesKeyLen(int32_t id, uint32_t *keyLen)
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
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}
#endif

static int32_t DrbgParaIsValid(CRYPT_RAND_AlgId id, const CRYPT_RandSeedMethod *seedMeth, const void *seedCtx,
    const uint8_t *pers, const uint32_t persLen)
{
    if (GetDrbgIdMap(id) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    if (seedMeth == NULL && seedCtx != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pers == NULL && persLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

static int32_t RandInitCheck(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod **seedMethPoint,
    void **seedCtxPoint, CRYPT_RandSeedMethod *seedMethTmp)
{
    CRYPT_RandSeedMethod *seedMeth = *seedMethPoint;
    void *seedCtx = *seedCtxPoint;

#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Drbg(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return CRYPT_EAL_ALG_ASM_NOT_SUPPORT;
    }
#endif
    CRYPT_RandSeedMethod *seedMethond = seedMeth;
    int32_t ret = DrbgParaIsValid(id, seedMeth, seedCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (seedMeth == NULL) {
#ifdef HITLS_CRYPTO_ENTROPY
        ret = EAL_SetDefaultEntropyMeth(seedMethTmp, seedCtxPoint);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        seedMethond = seedMethTmp;
#else
        (void) seedMethTmp;
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
#endif
    }
    *seedMethPoint = seedMethond;
    return CRYPT_SUCCESS;
}

DRBG_Ctx *DRBG_New(int32_t algId, BSL_Param *param)
{
    int32_t ret;
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_PARAM_ERROR);
        return NULL;
    }
    CRYPT_RandSeedMethod seedMethArray = {0};
    CRYPT_RandSeedMethod *seedMeth = &seedMethArray;
    void *seedCtx = NULL;

    const BSL_Param *temp = NULL;
    bool seedMethFlag = false;
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_GETENTROPY)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, (void **)&(seedMethArray.getEntropy), NULL), ret);
        seedMethFlag = true;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_CLEANENTROPY)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, (void **)&(seedMethArray.cleanEntropy), NULL), ret);
        seedMethFlag = true;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_GETNONCE)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, (void **)&(seedMethArray.getNonce), NULL), ret);
        seedMethFlag = true;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEED_CLEANNONCE)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, (void **)&(seedMethArray.cleanNonce), NULL), ret);
        seedMethFlag = true;
    }
    if (!seedMethFlag) {
        seedMeth = NULL;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RAND_SEEDCTX)) != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(temp, CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, &seedCtx, NULL), ret);
    }
    CRYPT_RandSeedMethod seedMethTmp = {0};
    ret = RandInitCheck(algId, &seedMeth, &seedCtx, &seedMethTmp);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    DRBG_Ctx *drbg = NULL;
    EAL_RandMethLookup lu;
    if (EAL_RandFindMethod(algId, &lu) != CRYPT_SUCCESS) {
        return NULL;
    }
    switch (lu.type) {
#ifdef HITLS_CRYPTO_DRBG_HASH
        case RAND_TYPE_MD:
            drbg = DRBG_NewHashCtx((const EAL_MdMethod *)(lu.method), seedMeth, seedCtx);
            break;
#endif
#ifdef HITLS_CRYPTO_DRBG_HMAC
        case RAND_TYPE_MAC:
            drbg = DRBG_NewHmacCtx((const EAL_MacMethod *)(lu.method), lu.methodId, seedMeth, seedCtx);
            break;
#endif
#ifdef HITLS_CRYPTO_DRBG_CTR
        case RAND_TYPE_AES:
        case RAND_TYPE_AES_DF: {
            bool isUsedDF = (lu.type == RAND_TYPE_AES_DF) ? true : false;
            uint32_t keyLen;
            if (GetAesKeyLen(lu.methodId, &keyLen) != CRYPT_SUCCESS) {
                return NULL;
            }
            drbg = DRBG_NewCtrCtx((const EAL_SymMethod *)(lu.method), keyLen, isUsedDF, seedMeth, seedCtx);
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

int32_t DRBG_Generate(DRBG_Ctx *ctx, uint8_t *out, uint32_t outLen,
    const uint8_t *adin, uint32_t adinLen,  BSL_Param *param)
{
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
        ret = DRBG_Reseed(ctx, adin, adinLen, param);
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

int32_t DRBG_Ctrl(void *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) ctx;
    (void) cmd;
    (void) val;
    (void) valLen;
    BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
    return CRYPT_NOT_SUPPORT;
}

#endif /* HITLS_CRYPTO_DRBG */
