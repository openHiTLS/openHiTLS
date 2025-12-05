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
#include "crypt_drbg.h"

#ifdef HITLS_CRYPTO_MD
#include "eal_md_local.h"
#endif
#ifdef HITLS_CRYPTO_MAC
#include "eal_mac_local.h"
#endif
#ifdef HITLS_CRYPTO_CIPHER
#include "eal_cipher_local.h"
#endif
#include "eal_drbg_local.h"
#include "bsl_err_internal.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "crypt_entropy.h"
#include "eal_common.h"
#include "eal_entropy.h"
#include "sal_atomic.h"
#include "crypt_ealinit.h"
#ifdef HITLS_CRYPTO_PROVIDER
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_provider.h"
#endif
#include "bsl_params.h"
#include "crypt_params_key.h"

#ifdef HITLS_CRYPTO_ENTROPY
static EAL_SeedDrbg g_seedDrbg = {HITLS_SEED_DRBG_INIT_RAND_ALG, NULL, NULL, {0}, {0}};
static BSL_SAL_ThreadLockHandle g_seedLock = NULL;
#endif

static CRYPT_EAL_RndCtx *EAL_RandNewDrbg(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx);

#define RETURN_RAND_LOCK(ctx, ret)                              \
    do {                                                        \
        (ret) = BSL_SAL_ThreadWriteLock(((ctx)->lock));         \
        if ((ret) != BSL_SUCCESS) {                             \
            BSL_ERR_PUSH_ERROR((ret));                          \
            return (ret);                                       \
        }                                                       \
    } while (0)

#define RAND_UNLOCK(ctx) (void)BSL_SAL_ThreadUnlock(((ctx)->lock))

#if defined(HITLS_CRYPTO_RAND_CB)
static CRYPT_EAL_RandFunc g_rndFunc = NULL;
static CRYPT_EAL_RandFuncEx g_rndFuncEx = NULL;
#endif

static int32_t EAL_RandSetMeth(EAL_RandUnitaryMethod *meth, CRYPT_EAL_RndCtx *ctx)
{
    EAL_RandUnitaryMethod *temp = BSL_SAL_Dump(meth, sizeof(EAL_RandUnitaryMethod));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->meth = temp;
    return CRYPT_SUCCESS;
}

/* Initialize the global DRBG. */
static int32_t EAL_RandNew(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx, CRYPT_EAL_RndCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->working == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_RAND_WORKING);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }

    EAL_RandUnitaryMethod *meth = ctx->meth;
    ctx->ctx = meth->newCtx(NULL, id, seedMeth, seedCtx);
    if (ctx->ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }

    return CRYPT_SUCCESS;
}

static void MethFreeCtx(CRYPT_EAL_RndCtx *ctx)
{
    EAL_RandUnitaryMethod *meth = ctx->meth;
    if (meth != NULL && meth->freeCtx != NULL) {
        meth->freeCtx(ctx->ctx);
    }
    BSL_SAL_FREE(ctx->meth);
    return;
}

#ifdef HITLS_CRYPTO_ENTROPY
int32_t EAL_SeedDrbgLockInit(void)
{
    if (g_seedLock != NULL) {
        return BSL_SUCCESS;
    }
    return BSL_SAL_ThreadLockNew(&g_seedLock);
}

void EAL_SeedDrbgLockDeInit(void)
{
    if (g_seedLock == NULL) {
        return;
    }
    BSL_SAL_ThreadLockFree(g_seedLock);
    g_seedLock = NULL;
}

void EAL_SeedDrbgRandDeinit(CRYPT_EAL_RndCtx *rndCtx)
{
    if (rndCtx == NULL) {
        return;
    }
    rndCtx->working = false;
    MethFreeCtx(rndCtx);
    BSL_SAL_ThreadLockFree(rndCtx->lock);
    BSL_SAL_FREE(rndCtx);
}

void EAL_SeedDrbgDeinit(bool isDefaultSeed)
{
    if (!isDefaultSeed) {
        return;
    }
    (void)BSL_SAL_ThreadWriteLock(g_seedLock);
    int val = 0;
    BSL_SAL_AtomicDownReferences(&(g_seedDrbg.references), &val);
    if (val > 0) {
        (void)BSL_SAL_ThreadUnlock(g_seedLock);
        return;
    }

    if (g_seedDrbg.seed != NULL) {
        EAL_SeedDrbgRandDeinit(g_seedDrbg.seed);
        g_seedDrbg.seed = NULL;
        CRYPT_EAL_SeedPoolFree(g_seedDrbg.seedCtx);
        g_seedDrbg.seedCtx = NULL;
        (void)memset_s(&(g_seedDrbg.seedMeth), sizeof(g_seedDrbg.seedMeth), 0, sizeof(g_seedDrbg.seedMeth));
        BSL_SAL_ReferencesFree(&(g_seedDrbg.references));
    }
    (void)BSL_SAL_ThreadUnlock(g_seedLock);
}
#endif

void EAL_RandDeinit(CRYPT_EAL_RndCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    BSL_SAL_ThreadLockHandle lock = ctx->lock;
    ctx->lock = NULL;

    if (BSL_SAL_ThreadWriteLock(lock) != BSL_SUCCESS) { // write lock
        MethFreeCtx(ctx);
        BSL_SAL_ThreadLockFree(lock);
#ifdef HITLS_CRYPTO_ENTROPY
        EAL_SeedDrbgDeinit(ctx->isDefaultSeed);
#endif
        BSL_SAL_FREE(ctx);
        return;
    }

    ctx->working = false;
    EAL_EVENT_REPORT(CRYPT_EVENT_ZERO, CRYPT_ALGO_RAND, ctx->id, CRYPT_SUCCESS);
    MethFreeCtx(ctx);
    (void)BSL_SAL_ThreadUnlock(lock);
    BSL_SAL_ThreadLockFree(lock); // free the lock resource
#ifdef HITLS_CRYPTO_ENTROPY
    EAL_SeedDrbgDeinit(ctx->isDefaultSeed);
#endif
    BSL_SAL_FREE(ctx);
    return;
}

// Check whether the state of CTX is available.
static int32_t CheckRndCtxState(CRYPT_EAL_RndCtx *ctx)
{
    if (ctx->working == false) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, CRYPT_EAL_ERR_RAND_NO_WORKING);
        return CRYPT_EAL_ERR_RAND_NO_WORKING;
    }

    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_RAND_CB)
void CRYPT_EAL_SetRandCallBack(CRYPT_EAL_RandFunc func)
{
    g_rndFunc = func;
    CRYPT_RandRegist(func);
    return;
}

void CRYPT_EAL_SetRandCallBackEx(CRYPT_EAL_RandFuncEx func)
{
    g_rndFuncEx = func;
    CRYPT_RandRegistEx(func);
    return;
}
#endif

int32_t EAL_DrbgbytesWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len, uint8_t *addin,
    uint32_t addinLen)
{
    if (ctx == NULL || ctx->meth == NULL || ctx->meth->gen == NULL || byte == NULL || len == 0) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = BSL_SAL_ThreadWriteLock(ctx->lock);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CheckRndCtxState(ctx);
    if (ret != CRYPT_SUCCESS) {
        RAND_UNLOCK(ctx);
        return ret;
    }

    ret = ctx->meth->gen(ctx->ctx, byte, len, addin, addinLen, NULL);
    EAL_EVENT_REPORT((ret == CRYPT_SUCCESS) ? CRYPT_EVENT_RANDGEN : CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, ret);
    RAND_UNLOCK(ctx);

    return ret;
}

int32_t EAL_DrbgSeedWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *addin, uint32_t addinLen)
{
    if (ctx == NULL || ctx->meth == NULL || ctx->meth->reSeed == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = BSL_SAL_ThreadWriteLock(ctx->lock);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CheckRndCtxState(ctx);
    if (ret != CRYPT_SUCCESS) {
        RAND_UNLOCK(ctx);
        return ret;
    }

    ret = ctx->meth->reSeed(ctx->ctx, addin, addinLen, NULL);
    if (ret != CRYPT_SUCCESS) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, ctx->id, ret);
    }
    RAND_UNLOCK(ctx);

    return ret;
}

void EAL_RandDrbgFree(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    DRBG_Ctx *drbg = (DRBG_Ctx *)ctx;

    DRBG_Free(drbg);
    return;
}

#ifdef HITLS_CRYPTO_ENTROPY
static int32_t GetSeedDrbgEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    CRYPT_EAL_RndCtx *seed = (CRYPT_EAL_RndCtx *)ctx;
    uint32_t strengthBytes = (strength + 7) / 8; // Figure out how many bytes needed.
    entropy->len = ((strengthBytes > lenRange->min) ? strengthBytes : lenRange->min);
    if (entropy->len > lenRange->max) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_RANGE_ERROR);
        return CRYPT_ENTROPY_RANGE_ERROR;
    }
    entropy->data = BSL_SAL_Malloc(entropy->len);
    if (entropy->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = EAL_DrbgbytesWithAdin(seed, entropy->data, entropy->len, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(entropy->data);
    }
    return ret;
}

static void CleanSeedDrbgEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_CleanseData(entropy->data, entropy->len);
    BSL_SAL_FREE(entropy->data);
}

void EAL_SeedDrbgEntropyMeth(CRYPT_RandSeedMethod *meth)
{
    meth->getEntropy = GetSeedDrbgEntropy;
    meth->cleanEntropy = CleanSeedDrbgEntropy;
    meth->cleanNonce = CleanSeedDrbgEntropy;
    meth->getNonce = GetSeedDrbgEntropy;
}

static int32_t SetSeedDrbgReseedInfo(CRYPT_EAL_RndCtx *rndCtx)
{
    int32_t ret;
#if defined(HITLS_CRYPTO_DRBG_GM)
    if (g_seedDrbg.id == CRYPT_RAND_SM3 || g_seedDrbg.id == CRYPT_RAND_SM4_CTR_DF) {
        uint32_t gmLevel = 2; // Set gm level 2
        ret = rndCtx->meth->ctrl(rndCtx->ctx, CRYPT_CTRL_SET_GM_LEVEL, &gmLevel, sizeof(uint32_t));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        return ret;
    }
#endif
    uint32_t reseedInterval = DRBG_RESEED_INTERVAL;
    ret = rndCtx->meth->ctrl(rndCtx->ctx, CRYPT_CTRL_SET_RESEED_INTERVAL, &reseedInterval, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t EAL_SeedDrbgInit(EAL_SeedDrbg *seedDrbg)
{
    CRYPT_RandSeedMethod seedMethond = {0};
    int32_t ret = EAL_SetDefaultEntropyMeth(&seedMethond);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CRYPT_EAL_SeedPoolCtx *seedPoolCtx = CRYPT_EAL_SeedPoolNew(false);
    if (seedPoolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NEW_ERROR);
        return CRYPT_SEED_POOL_NEW_ERROR;
    }

    CRYPT_EAL_RndCtx *rndCtx = EAL_RandNewDrbg(seedDrbg->id, &seedMethond, seedPoolCtx);
    if (rndCtx == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = SetSeedDrbgReseedInfo(rndCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = rndCtx->meth->inst(rndCtx->ctx, NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    rndCtx->working = true;

    seedDrbg->seed = rndCtx;
    seedDrbg->seedMeth = seedMethond;
    seedDrbg->seedCtx = seedPoolCtx;
    BSL_SAL_ReferencesInit(&(seedDrbg->references));
    return CRYPT_SUCCESS;

EXIT:
    CRYPT_EAL_SeedPoolFree(seedPoolCtx);
    EAL_RandDeinit(rndCtx);
    return ret;
}

int32_t EAL_GetDefaultSeed(CRYPT_RandSeedMethod *seedMeth, void **seedCtx)
{
    EAL_SeedDrbgEntropyMeth(seedMeth);

    (void)BSL_SAL_ThreadWriteLock(g_seedLock);
    if (g_seedDrbg.seed != NULL) {
        *seedCtx = g_seedDrbg.seed;
        int val = 0;
        BSL_SAL_AtomicUpReferences(&(g_seedDrbg.references), &val);
        (void)BSL_SAL_ThreadUnlock(g_seedLock);
        return CRYPT_SUCCESS;
    }
    int32_t ret = EAL_SeedDrbgInit(&g_seedDrbg);
    if (ret != CRYPT_SUCCESS) {
        (void)BSL_SAL_ThreadUnlock(g_seedLock);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    *seedCtx = g_seedDrbg.seed;
    (void)BSL_SAL_ThreadUnlock(g_seedLock);
    return CRYPT_SUCCESS;
}
#endif

static CRYPT_EAL_RndCtx *EAL_RandNewDrbg(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth,
    void *seedCtx)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Drbg(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    CRYPT_RandSeedMethod seedMethTmp = {0};
    CRYPT_RandSeedMethod *seedMethond = seedMeth;
    EAL_RandUnitaryMethod *meth = NULL;
    void *seedTmp = NULL;
    int32_t ret;

    CRYPT_EAL_RndCtx *randCtx = (CRYPT_EAL_RndCtx *)BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_RndCtx));
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    randCtx->isDefaultSeed = false;

    if (seedMeth == NULL || seedMeth->getEntropy == NULL) {
#ifdef HITLS_CRYPTO_ENTROPY
        ret = EAL_GetDefaultSeed(&seedMethTmp, &seedTmp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        seedCtx = seedTmp;
        seedMethond = &seedMethTmp;
        randCtx->isDefaultSeed = true;
#else
        (void)seedMethTmp;
        (void)seedTmp;
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        goto ERR;
#endif
    }
    meth = EAL_RandGetMethod();
    // Apply for lock resources.
    ret = BSL_SAL_ThreadLockNew(&(randCtx->lock));
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    randCtx->isProvider = false;
    randCtx->working = false;
    randCtx->id = id;

    ret = EAL_RandSetMeth(meth, randCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    ret = EAL_RandNew(id, seedMethond, seedCtx, randCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    return randCtx;
ERR:
    EAL_RandDeinit(randCtx);
    return NULL;
}

#ifdef HITLS_CRYPTO_DRBG
static CRYPT_EAL_RndCtx *g_globalRndCtx = NULL;

static int32_t DrbgParaIsValid(CRYPT_RAND_AlgId id, const CRYPT_RandSeedMethod *seedMeth, const void *seedCtx,
    const uint8_t *pers, uint32_t persLen)
{
    if (DRBG_GetIdMap(id) == NULL) {
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
    if (seedMeth != NULL && seedMeth->getEntropy == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_RandInit(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx,
                           const uint8_t *pers, uint32_t persLen)
{
    CRYPT_EAL_RndCtx *ctx = NULL;
    if (g_globalRndCtx != NULL) { // Prevent DRBG repeated Init
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_DRBG_REPEAT_INIT);
        return CRYPT_EAL_ERR_DRBG_REPEAT_INIT;
    }
    int32_t ret = DrbgParaIsValid(id, seedMeth, seedCtx, pers, persLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx = EAL_RandNewDrbg(id, seedMeth, seedCtx);
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    ret = CRYPT_EAL_DrbgInstantiate(ctx, pers, persLen);
    if (ret != CRYPT_SUCCESS) {
        EAL_RandDeinit(ctx);
        return ret;
    }
    CRYPT_RandRegist(CRYPT_EAL_Randbytes); // provide a random number generation function for BigNum.
    g_globalRndCtx = ctx;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_RandbytesWithAdin(uint8_t *byte, uint32_t len, uint8_t *addin, uint32_t addinLen)
{
    if (g_globalRndCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
        return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL;
    }
    return EAL_DrbgbytesWithAdin(g_globalRndCtx, byte, len, addin, addinLen);
}

int32_t CRYPT_EAL_Randbytes(uint8_t *byte, uint32_t len)
{
#if defined(HITLS_CRYPTO_RAND_CB)
    if (g_rndFunc != NULL) {
        return g_rndFunc(byte, len);
    }
#endif
    return CRYPT_EAL_RandbytesWithAdin(byte, len, NULL, 0);
}

int32_t CRYPT_EAL_RandSeedWithAdin(uint8_t *addin, uint32_t addinLen)
{
    if (g_globalRndCtx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, CRYPT_RAND_ALGID_MAX, CRYPT_EAL_ERR_GLOBAL_DRBG_NULL);
        return CRYPT_EAL_ERR_GLOBAL_DRBG_NULL;
    }
    return EAL_DrbgSeedWithAdin(g_globalRndCtx, addin, addinLen);
}

int32_t CRYPT_EAL_RandSeed(void)
{
    return CRYPT_EAL_RandSeedWithAdin(NULL, 0);
}

bool CRYPT_EAL_RandIsValidAlgId(CRYPT_RAND_AlgId id)
{
    return (DRBG_GetIdMap(id) != NULL);
}
#endif // end of HITLS_CRYPTO_DRBG

int32_t CRYPT_EAL_DrbgInstantiate(CRYPT_EAL_RndCtx *rndCtx, const uint8_t *pers, uint32_t persLen)
{
    int32_t ret;
    if (rndCtx == NULL || rndCtx->meth == NULL || rndCtx->meth->inst == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    RETURN_RAND_LOCK(rndCtx, ret);
    ret = rndCtx->meth->inst(rndCtx->ctx, pers, persLen, NULL);
    if (ret != CRYPT_SUCCESS) {
        RAND_UNLOCK(rndCtx);
        return ret;
    }
    rndCtx->working = true;
    RAND_UNLOCK(rndCtx);
    return ret;
}

CRYPT_EAL_RndCtx *CRYPT_EAL_DrbgNew(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx)
{
    if (seedMeth == NULL && seedCtx != NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_NULL_INPUT);
        return NULL;
    }

    return EAL_RandNewDrbg(id, seedMeth, seedCtx);
}

int32_t CRYPT_EAL_DrbgSeedWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *addin, uint32_t addinLen)
{
    return EAL_DrbgSeedWithAdin(ctx, addin, addinLen);
}

int32_t CRYPT_EAL_DrbgSeed(CRYPT_EAL_RndCtx *ctx)
{
    return CRYPT_EAL_DrbgSeedWithAdin(ctx, NULL, 0);
}

int32_t CRYPT_EAL_DrbgbytesWithAdin(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len, uint8_t *addin,
    uint32_t addinLen)
{
    return EAL_DrbgbytesWithAdin(ctx, byte, len, addin, addinLen);
}

int32_t CRYPT_EAL_Drbgbytes(CRYPT_EAL_RndCtx *ctx, uint8_t *byte, uint32_t len)
{
    return CRYPT_EAL_DrbgbytesWithAdin(ctx, byte, len, NULL, 0);
}

void CRYPT_EAL_DrbgDeinit(CRYPT_EAL_RndCtx *ctx)
{
    EAL_RandDeinit(ctx);
    return;
}

CRYPT_EAL_RndCtx *CRYPT_EAL_GetSeedCtx(bool isParentEntropy)
{
    if (isParentEntropy) {
#ifdef HITLS_CRYPTO_ENTROPY
        return g_seedDrbg.seed;
#else
        return NULL;
#endif
    }
    return g_globalRndCtx;
}

static int32_t GetDRBGWorkingStatus(CRYPT_EAL_RndCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    *(uint32_t *)val = (uint32_t)(ctx->working);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_DrbgCtrl(CRYPT_EAL_RndCtx *rndCtx, int32_t opt, void *val, uint32_t len)
{
    if (rndCtx == NULL || rndCtx->meth == NULL || rndCtx->meth->ctrl == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (opt == CRYPT_CTRL_GET_WORKING_STATUS) {
        return GetDRBGWorkingStatus(rndCtx, val, len);
    }

    int32_t ret;
    RETURN_RAND_LOCK(rndCtx, ret);
    if (rndCtx->working == true) {
        RAND_UNLOCK(rndCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_RAND_WORKING);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }
    ret = rndCtx->meth->ctrl(rndCtx->ctx, opt, val, len);
    RAND_UNLOCK(rndCtx);
    return ret;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_EAL_SetRandMethod(CRYPT_EAL_RndCtx *ctx, const CRYPT_EAL_Func *funcs)
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

static CRYPT_EAL_RndCtx *EAL_ProvRandInitDrbg(CRYPT_EAL_LibCtx *libCtx, CRYPT_RAND_AlgId id,
    const char *attrName, BSL_Param *param)
{
    const CRYPT_EAL_Func *funcs = NULL;
    void *provCtx = NULL;
    int32_t ret = CRYPT_EAL_ProviderGetFuncs(libCtx, CRYPT_EAL_OPERAID_RAND, id, attrName,
        &funcs, &provCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    CRYPT_EAL_RndCtx *randCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_RndCtx));
    if (randCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    // Apply for lock resources.
    ret = BSL_SAL_ThreadLockNew(&(randCtx->lock));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    randCtx->isDefaultSeed = false;
    randCtx->isProvider = true;
    randCtx->working = false;
    randCtx->id = id;

    ret = CRYPT_EAL_SetRandMethod(randCtx, funcs);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }
    if (randCtx->meth->provNewCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        goto ERR;
    }

    randCtx->ctx = randCtx->meth->provNewCtx(provCtx, id, param);
    if (randCtx->ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        goto ERR;
    }
    return randCtx;
ERR:
    BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
    BSL_SAL_FREE(randCtx->meth);
    BSL_SAL_FREE(randCtx);
    return NULL;
}

CRYPT_EAL_RndCtx *CRYPT_EAL_ProviderDrbgNewCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    BSL_Param *param)
{
    return EAL_ProvRandInitDrbg(libCtx, algId, attrName, param);
}

int32_t CRYPT_EAL_ProviderRandInitCtxInner(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
    CRYPT_EAL_RndCtx *ctx = NULL;
    CRYPT_EAL_LibCtx *localLibCtx = GetCurrentProviderLibCtx(libCtx);
    if (localLibCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    if (localLibCtx->drbg != NULL) { // Prevent DRBG repeated Init
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_DRBG_REPEAT_INIT);
        return CRYPT_EAL_ERR_DRBG_REPEAT_INIT;
    }
 
    ctx = EAL_ProvRandInitDrbg(libCtx, algId, attrName, param);
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, algId, CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    if (ctx->meth->inst == NULL) {
        EAL_RandDeinit(ctx);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    int32_t ret = ctx->meth->inst(ctx->ctx, pers, persLen, param);
    if (ret != CRYPT_SUCCESS) {
        EAL_RandDeinit(ctx);
        return ret;
    }
    ctx->working = true;
    CRYPT_RandRegist(CRYPT_EAL_Randbytes);
    // provide a random number generation function for BigNum.
    CRYPT_RandRegistEx((CRYPT_EAL_RandFuncEx)CRYPT_EAL_RandbytesEx);
    localLibCtx->drbg = ctx;
    return CRYPT_SUCCESS;
}
#endif // end of HITLS_CRYPTO_PROVIDER

int32_t CRYPT_EAL_NoProviderRandInitCtxInner(int32_t algId,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
    CRYPT_RandSeedMethod seedMeth = {0};
    void *seedCtx = NULL;
    const BSL_Param *temp = NULL;
    int32_t ret;
    bool hasEnt = false;
    
    if ((temp = EAL_FindParam(param, CRYPT_PARAM_RAND_SEED_GETENTROPY)) != NULL) {
        seedMeth.getEntropy = temp->value;
        hasEnt = true;
    }
    if ((temp = EAL_FindParam(param, CRYPT_PARAM_RAND_SEED_CLEANENTROPY)) != NULL) {
        seedMeth.cleanEntropy = temp->value;
        hasEnt = true;
    }
    if ((temp = EAL_FindParam(param, CRYPT_PARAM_RAND_SEED_GETNONCE)) != NULL) {
        seedMeth.getNonce = temp->value;
        hasEnt = true;
    }
    if ((temp = EAL_FindParam(param, CRYPT_PARAM_RAND_SEED_CLEANNONCE)) != NULL) {
        seedMeth.cleanNonce = temp->value;
        hasEnt = true;
    }
    if ((temp = EAL_FindParam(param, CRYPT_PARAM_RAND_SEEDCTX)) != NULL) {
        seedCtx = temp->value;
    }
    if (hasEnt) {
        ret = CRYPT_EAL_RandInit(algId, &seedMeth, seedCtx, pers, persLen);
    } else {
        ret = CRYPT_EAL_RandInit(algId, NULL, seedCtx, pers, persLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_EAL_ProviderRandInitCtx(CRYPT_EAL_LibCtx *libCtx, int32_t algId, const char *attrName,
    const uint8_t *pers, uint32_t persLen, BSL_Param *param)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderRandInitCtxInner(libCtx, algId, attrName, pers, persLen, param);
#else
    (void) libCtx;
    (void) attrName;
    return CRYPT_EAL_NoProviderRandInitCtxInner(algId, pers, persLen, param);
#endif
}

void CRYPT_EAL_RandDeinitEx(CRYPT_EAL_LibCtx *libCtx)
{
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_LibCtx *localLibCtx = libCtx;
    if (localLibCtx == NULL) {
        localLibCtx = CRYPT_EAL_GetGlobalLibCtx();
    }
    if (localLibCtx == NULL) {
        return;
    }
    EAL_RandDeinit(localLibCtx->drbg);
    localLibCtx->drbg = NULL;
    CRYPT_RandRegistEx(NULL);
    return;
#else
    (void) libCtx;
    CRYPT_EAL_RandDeinit();
    return;
#endif
}

void CRYPT_EAL_RandDeinit(void)
{
    EAL_RandDeinit(g_globalRndCtx);
    g_globalRndCtx = NULL;
    CRYPT_RandRegist(NULL);
    return;
}

#ifdef HITLS_CRYPTO_PROVIDER
int32_t CRYPT_EAL_RandbytesWithAdinEx(CRYPT_EAL_LibCtx *libCtx,
    uint8_t *byte, uint32_t len, uint8_t *addin, uint32_t addinLen)
{
    CRYPT_EAL_LibCtx *localCtx = libCtx;
    if (localCtx == NULL) {
        localCtx = CRYPT_EAL_GetGlobalLibCtx();
    }

    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    return EAL_DrbgbytesWithAdin((CRYPT_EAL_RndCtx *)localCtx->drbg, byte, len, addin, addinLen);
}
#endif

int32_t CRYPT_EAL_RandbytesEx(CRYPT_EAL_LibCtx *libCtx, uint8_t *byte, uint32_t len)
{
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_LibCtx *localCtx = libCtx;
    if (localCtx == NULL) {
        localCtx = CRYPT_EAL_GetGlobalLibCtx();
    }
    if (localCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    return EAL_DrbgbytesWithAdin((CRYPT_EAL_RndCtx *)localCtx->drbg, byte, len, NULL, 0);
#else
    (void) libCtx;
    return CRYPT_EAL_Randbytes(byte, len);
#endif
}

int32_t CRYPT_EAL_RandSeedEx(CRYPT_EAL_LibCtx *libCtx)
{
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_LibCtx *tempLibCtx = libCtx;
    if (tempLibCtx == NULL) {
        tempLibCtx = CRYPT_EAL_GetGlobalLibCtx();
    }

    if (tempLibCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_INVALID_LIB_CTX);
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    return EAL_DrbgSeedWithAdin((CRYPT_EAL_RndCtx *)tempLibCtx->drbg, NULL, 0);
#else
    (void) libCtx;
    return CRYPT_EAL_RandSeed();
#endif
}

#endif // end of HITLS_CRYPTO_EAL && HITLS_CRYPTO_DRBG
