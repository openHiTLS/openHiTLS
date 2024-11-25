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
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_DRBG)

#include <stdbool.h>
#include <securec.h>
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_ealinit.h"
#include "eal_drbg_local.h"
#include "bsl_err_internal.h"
#include "crypt_types.h"
#include "crypt_local_types.h"
#include "crypt_util_rand.h"
#include "eal_common.h"
#include "crypt_entropy.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_modes.h"

static CRYPT_EAL_RndCtx *g_globalRndCtx = NULL;

#define RETURN_RAND_LOCK(ctx, ret)                              \
    do {                                                        \
        (ret) = BSL_SAL_ThreadWriteLock(((ctx)->lock));         \
        if ((ret) != BSL_SUCCESS) {                             \
            EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, (ret));      \
            return (ret);                                       \
        }                                                       \
    } while (0)

#define RAND_UNLOCK(ctx) (void)BSL_SAL_ThreadUnlock(((ctx)->lock))

static void MethFreeCtx(CRYPT_EAL_RndCtx *ctx)
{
    if (ctx == NULL || ctx->meth == NULL || ctx->meth->freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return;
    }
    ctx->meth->freeCtx(ctx->ctx);
    return;
}

int32_t EAL_RandSetMeth(EAL_RandUnitaryMethod *meth, CRYPT_EAL_RndCtx *ctx)
{
    if (meth == NULL || ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (meth->gen == NULL || meth->reSeed == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    if (meth->newCtx != NULL && meth->freeCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    if (ctx->working == true) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_RAND_WORKING);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }

    EAL_RandUnitaryMethod *temp = BSL_SAL_Calloc(1, sizeof(EAL_RandUnitaryMethod));
    if (temp == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy_s(temp, sizeof(EAL_RandUnitaryMethod), meth, sizeof(EAL_RandUnitaryMethod));
    ctx->meth = temp;

    return CRYPT_SUCCESS;
}


static int32_t CRYPT_EAL_SetRandMethod(CRYPT_EAL_RndCtx *ctx, const CRYPT_EAL_Func *funcs)
{
    int32_t index = 0;
    EAL_RandUnitaryMethod *method = BSL_SAL_Calloc(1, sizeof(EAL_RandUnitaryMethod));
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    while (funcs[index].id != 0) {
        switch (funcs[index].id) {
            case CRYPT_EAL_IMPLRAND_DRBGNEWCTX:
                method->provNewCtx = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLRAND_DRBGINST:
                method->inst = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLRAND_DRBGUNINST:
                method->unInst = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLRAND_DRBGGEN:
                method->gen = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLRAND_DRBGRESEED:
                method->reSeed = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLRAND_DRBGCTRL:
                method->ctrl = funcs[index].func;
                break;
            case CRYPT_EAL_IMPLRAND_DRBGFREECTX:
                method->freeCtx = funcs[index].func;
                break;
            default:
                BSL_SAL_Free(method);
                BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL);
                return CRYPT_PROVIDER_ERR_UNEXPECTED_IMPL;
        }
        index++;
    }
    ctx->meth = method;
    return CRYPT_SUCCESS;
}

/* Initialize the global DRBG. */
int32_t EAL_RandInit(CRYPT_RAND_AlgId id, BSL_Param *param, CRYPT_EAL_RndCtx *ctx, void *provCtx)
{
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->working == true) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_RAND_WORKING);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }

    EAL_RandUnitaryMethod *meth = ctx->meth;
    if (meth->gen == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((ctx->isProvider) ? (meth->provNewCtx == NULL) : (meth->newCtx == NULL)) {
        ctx->working = true;
        ctx->ctx = NULL;
        return CRYPT_SUCCESS;
    }

    ctx->ctx = (ctx->isProvider) ? meth->provNewCtx(provCtx, id, param) : meth->newCtx(id, param);
    if (ctx->ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_DrbgInstantiate(CRYPT_EAL_RndCtx *ctx, const uint8_t *pers, uint32_t persLen)
{
    if (ctx == NULL || ctx->meth == NULL || ctx->meth->inst == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    RETURN_RAND_LOCK(ctx, ret); // write lock
    if (ctx->working == true) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_RAND_WORKING);
        RAND_UNLOCK(ctx);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }
    ret = ctx->meth->inst(ctx->ctx, pers, persLen, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, ret);
        RAND_UNLOCK(ctx);
        return ret;
    }
    ctx->working = true;
    RAND_UNLOCK(ctx);
    return ret;
}

void CRYPT_RandDeinit(CRYPT_EAL_RndCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ThreadLockHandle lock = ctx->lock;
    ctx->lock = NULL;

    if (BSL_SAL_ThreadWriteLock(lock) != CRYPT_SUCCESS) { // write lock
        MethFreeCtx(ctx);
        BSL_SAL_ThreadLockFree(lock);
        BSL_SAL_FREE(ctx->meth);
        BSL_SAL_FREE(ctx);
        return;
    }

    ctx->working = false;
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_RAND, ctx->id, CRYPT_SUCCESS);
    MethFreeCtx(ctx);
    (void)BSL_SAL_ThreadUnlock(lock);
    BSL_SAL_ThreadLockFree(lock); // free the lock resource
    BSL_SAL_FREE(ctx->meth);
    BSL_SAL_FREE(ctx);
    return;
}

// Check whether the state of CTX is available.
static int32_t CheckRndCtxState(CRYPT_EAL_RndCtx *ctx)
{
    if (ctx->working == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_RAND_NO_WORKING);
        return CRYPT_EAL_ERR_RAND_NO_WORKING;
    }

    return CRYPT_SUCCESS;
}

int32_t EAL_RandDrbgGenerate(CRYPT_EAL_RndCtx *drbgCtx, uint8_t *bytes, uint32_t len,
    const uint8_t *adin, uint32_t adinLen)
{
    if (drbgCtx == NULL || drbgCtx->meth == NULL || drbgCtx->meth->gen == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    bool pr = false;
    BSL_Param param[2] = {
        {CRYPT_PARAM_RAND_PR, BSL_PARAM_TYPE_BOOL, &pr, sizeof(bool), 0},
        BSL_PARAM_END};

    int32_t ret = drbgCtx->meth->gen(drbgCtx->ctx, bytes, len, adin, adinLen, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, drbgCtx->id, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t EAL_RandDrbgReseed(CRYPT_EAL_RndCtx *drbgCtx, const uint8_t *adin, uint32_t adinLen)
{
    if (drbgCtx == NULL || drbgCtx->meth == NULL || drbgCtx->meth->reSeed == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = drbgCtx->meth->reSeed(drbgCtx->ctx, adin, adinLen, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, drbgCtx->id, ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static CRYPT_EAL_RndCtx *EAL_RandInitDrbg(CRYPT_RAND_AlgId id, BSL_Param *param)
{
    EAL_RandUnitaryMethod *meth = EAL_RandGetMethod();

    CRYPT_EAL_RndCtx *randCtx = BSL_SAL_Malloc(sizeof(CRYPT_EAL_RndCtx));
    if (randCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    // Apply for lock resources.
    int32_t ret = BSL_SAL_ThreadLockNew(&(randCtx->lock));
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, ret);
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    randCtx->isProvider = false;
    randCtx->working = false;
    randCtx->id = id;

    ret = EAL_RandSetMeth(meth, randCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    ret = EAL_RandInit(id, param, randCtx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
        BSL_SAL_FREE(randCtx->meth);
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    return randCtx;
}

int32_t CRYPT_EAL_RandInit(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx,
                           const uint8_t *pers, uint32_t persLen)
{
    CRYPT_EAL_RndCtx *ctx = NULL;
    if (g_globalRndCtx != NULL) { // Prevent DRBG repeated Init
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_EAL_ERR_DRBG_REPEAT_INIT);
        return CRYPT_EAL_ERR_DRBG_REPEAT_INIT;
    }

    BSL_Param param[6] = {0};
    param[0] = (BSL_Param){CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, seedCtx, 0, 0};
    if (seedMeth != NULL) {
        param[1] = (BSL_Param){CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->getEntropy, 0, 0};
        param[2] = (BSL_Param){CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->cleanEntropy, 0, 0};
        param[3] = (BSL_Param){CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->getNonce, 0, 0};
        param[4] = (BSL_Param){CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->cleanNonce, 0, 0};
    }

    ctx = EAL_RandInitDrbg(id, param);
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, pers, persLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_RandDeinit(ctx);
        return ret;
    }
    CRYPT_RandRegist(CRYPT_EAL_Randbytes); // provide a random number generation function for BigNum.
    g_globalRndCtx = ctx;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_RndCtx *CRYPT_EAL_DrbgNew(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx)
{
    BSL_Param param[6] = {0};
    param[0] = (BSL_Param){CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR, seedCtx, 0, 0};
    if (seedMeth != NULL) {
        param[1] = (BSL_Param){CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->getEntropy, 0, 0};
        param[2] = (BSL_Param){CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->cleanEntropy, 0, 0};
        param[3] = (BSL_Param){CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->getNonce, 0, 0};
        param[4] = (BSL_Param){CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR, seedMeth->cleanNonce, 0, 0};
    }

    return EAL_RandInitDrbg(id, param);
}

static CRYPT_EAL_RndCtx *EAL_ProvRandInitDrbg(CRYPT_EAL_LibCtx *libCtx, CRYPT_RAND_AlgId id,
    const char *attrName, BSL_Param *param)
{
    const CRYPT_EAL_Func *funcs = NULL;
    void *provCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncsFrom(libCtx, CRYPT_EAL_OPERAID_RAND, id, attrName,
        &funcs, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, ret);
        return NULL;
    }
    CRYPT_EAL_RndCtx *randCtx = BSL_SAL_Malloc(sizeof(CRYPT_EAL_RndCtx));
    if (randCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    // Apply for lock resources.
    ret = BSL_SAL_ThreadLockNew(&(randCtx->lock));
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, ret);
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    randCtx->isProvider = true;
    randCtx->working = false;
    randCtx->id = id;

    ret = CRYPT_EAL_SetRandMethod(randCtx, funcs);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
        BSL_SAL_FREE(randCtx);
        return NULL;
    }
    ret = EAL_RandInit(id, param, randCtx, provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
        BSL_SAL_FREE(randCtx->meth);
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    return randCtx;
}

int32_t CRYPT_EAL_ProviderRandInitCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
    CRYPT_EAL_RndCtx *ctx = NULL;
    if (g_globalRndCtx != NULL) { // Prevent DRBG repeated Init
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, algId, CRYPT_EAL_ERR_DRBG_REPEAT_INIT);
        return CRYPT_EAL_ERR_DRBG_REPEAT_INIT;
    }
 
    ctx = EAL_ProvRandInitDrbg(libCtx, algId, attrName, param);
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, algId, CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    if (ctx->meth->inst == NULL) {
        CRYPT_RandDeinit(ctx);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    int32_t ret = ctx->meth->inst(ctx->ctx, pers, persLen, param);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_RandDeinit(ctx);
        return ret;
    }
    ctx->working = true;
    CRYPT_RandRegist(CRYPT_EAL_Randbytes); // provide a random number generation function for BigNum.
    g_globalRndCtx = ctx;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_RndCtx *CRYPT_EAL_ProviderDrbgInitCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    BSL_Param *param)
{
    return EAL_ProvRandInitDrbg(libCtx, algId, attrName, param);
}

void CRYPT_EAL_RandDeinit(void)
{
    CRYPT_RandDeinit(g_globalRndCtx);
    g_globalRndCtx = NULL;
    return;
}

void CRYPT_EAL_DrbgDeinit(CRYPT_EAL_RndCtx *ctx)
{
    CRYPT_RandDeinit(ctx);
    return;
}

int32_t CRYPT_EAL_RandbytesWithAdin(uint8_t *byte, uint32_t len, uint8_t *addin, uint32_t addinLen)
{
    if (g_globalRndCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
        return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL;
    }
    return CRYPT_EAL_DrbgbytesWithAdin(g_globalRndCtx, byte, len, addin, addinLen);
}

int32_t CRYPT_EAL_Randbytes(uint8_t *byte, uint32_t len)
{
    return CRYPT_EAL_RandbytesWithAdin(byte, len, NULL, 0);
}

int32_t CRYPT_EAL_RandSeedWithAdin(uint8_t *addin, uint32_t addinLen)
{
    if (g_globalRndCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
        return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL;
    }
    return CRYPT_EAL_DrbgSeedWithAdin(g_globalRndCtx, addin, addinLen);
}

int32_t CRYPT_EAL_RandSeed(void)
{
    return CRYPT_EAL_RandSeedWithAdin(NULL, 0);
}

int32_t CRYPT_EAL_DrbgbytesWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len, uint8_t *addin,
    uint32_t addinLen)
{
    int32_t ret;
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    RETURN_RAND_LOCK(ctx, ret); // write lock
    ret = CheckRndCtxState(ctx);
    if (ret != CRYPT_SUCCESS) {
        RAND_UNLOCK(ctx);
        return ret;
    }

    ret = EAL_RandDrbgGenerate(ctx, byte, len, addin, addinLen);
    EAL_EventReport((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_RANDGEN : CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, ret);
    RAND_UNLOCK(ctx);
    return ret;
}

int32_t CRYPT_EAL_Drbgbytes(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len)
{
    return CRYPT_EAL_DrbgbytesWithAdin(ctx, byte, len, NULL, 0);
}

int32_t CRYPT_EAL_DrbgSeedWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *addin, uint32_t addinLen)
{
    int32_t ret;
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    RETURN_RAND_LOCK(ctx, ret); // write lock
    ret = CheckRndCtxState(ctx);
    if (ret != CRYPT_SUCCESS) {
        RAND_UNLOCK(ctx);
        return ret;
    }

    ret = EAL_RandDrbgReseed(ctx, addin, addinLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, ret);
    }
    RAND_UNLOCK(ctx);
    return ret;
}

int32_t CRYPT_EAL_DrbgSeed(CRYPT_EAL_RndCtx *ctx)
{
    return CRYPT_EAL_DrbgSeedWithAdin(ctx, NULL, 0);
}

bool CRYPT_EAL_RandIsValidAlgId(CRYPT_RAND_AlgId id)
{
    return (GetDrbgIdMap(id) != NULL);
}

int32_t CRYPT_EAL_DrbgCtrl(CRYPT_EAL_RndCtx *ctx, int32_t cmd, void *val, uint32_t valLen)
{
    if (ctx == NULL || ctx->meth == NULL || ctx->meth->ctrl== NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return ctx->meth->ctrl(ctx->ctx, cmd, val, valLen);
}
#endif
