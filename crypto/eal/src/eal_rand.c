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
#include "crypt_util_rand.h"
#include "eal_common.h"
#include "eal_entropy.h"

typedef enum {
    RAND_AES128_KEYLEN = 16,
    RAND_AES192_KEYLEN = 24,
    RAND_AES256_KEYLEN = 32,
} RAND_AES_KeyLen;

typedef struct {
    CRYPT_RAND_AlgId id;
    CRYPT_RandSeedMethod *seedMeth;
    void *seedCtx;
    const uint8_t *pers;
    uint32_t persLen;
} CRYPT_RAND_DrbgParam;

static CRYPT_EAL_RndCtx *g_globalRndCtx = NULL;

#define RETURN_RAND_LOCK(ctx, ret)                              \
    do {                                                        \
        (ret) = BSL_SAL_ThreadWriteLock(((ctx)->lock));             \
        if ((ret) != BSL_SUCCESS) {                             \
            BSL_ERR_PUSH_ERROR((ret));                          \
            return (ret);                                       \
        }                                                       \
    } while (0)

#define RAND_UNLOCK(ctx) (void)BSL_SAL_ThreadUnlock(((ctx)->lock))


int32_t EAL_RandSetMeth(EalRndMeth *meth, CRYPT_EAL_RndCtx *ctx)
{
    if (meth == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (meth->rand == NULL || meth->seed == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    if (meth->newCtx != NULL && meth->freeCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }

    if (ctx->working == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_RAND_WORKING);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }

    (void)memcpy_s(&ctx->meth, sizeof(EalRndMeth), meth, sizeof(EalRndMeth));

    return CRYPT_SUCCESS;
}

/* Initialize the global DRBG. */
int32_t EAL_RandInit(CRYPT_RndParam *param, CRYPT_EAL_RndCtx *ctx)
{
    if (param == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->working == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_RAND_WORKING);
        return CRYPT_EAL_ERR_RAND_WORKING;
    }

    EalRndMeth *meth = &ctx->meth;
    if (meth->rand == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (meth->newCtx == NULL) {
        ctx->working = true;
        ctx->ctx = NULL;
        return CRYPT_SUCCESS;
    }

    ctx->ctx = meth->newCtx(param);
    if (ctx->ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }

    ctx->working = true;

    return CRYPT_SUCCESS;
}

static void MethFreeCtx(CRYPT_EAL_RndCtx *ctx)
{
    EalRndMeth *meth = &ctx->meth;
    if (ctx->ctx != NULL && meth->freeCtx != NULL) {
        meth->freeCtx(ctx->ctx);
    }
    return;
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
        BSL_SAL_FREE(ctx);
        return;
    }

    ctx->working = false;
    EAL_EventReport(CRYPT_EVENT_ZERO, CRYPT_ALGO_RAND, ctx->id, CRYPT_SUCCESS);
    MethFreeCtx(ctx);
    (void)BSL_SAL_ThreadUnlock(lock);
    BSL_SAL_ThreadLockFree(lock); // free the lock resource
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

    EalRndMeth *meth = &ctx->meth;
    ret = meth->rand(ctx->ctx, byte, len, addin, addinLen);
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

    EalRndMeth *meth = &ctx->meth;
    ret = meth->seed(ctx->ctx, addin, addinLen);
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

void EAL_RandDrbgFree(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    DRBG_Ctx *drbg = (DRBG_Ctx *)ctx;

    DRBG_Free(drbg);
    return;
}

#define RAND_TYPE_MD 1
#define RAND_TYPE_MAC 2
#define RAND_TYPE_AES 3
#define RAND_TYPE_AES_DF 4

typedef struct {
    CRYPT_RAND_AlgId  drbgId;
    uint32_t depId;
    uint32_t type;
} DrbgIdMap;

/* Mapping between RAND and specific random number generation algorithms */
static const DrbgIdMap DRBG_METHOD_MAP[] = {
#ifdef HITLS_CRYPTO_DRBG_HASH
    { CRYPT_RAND_SHA1, CRYPT_MD_SHA1, RAND_TYPE_MD },
    { CRYPT_RAND_SHA224, CRYPT_MD_SHA224, RAND_TYPE_MD },
    { CRYPT_RAND_SHA256, CRYPT_MD_SHA256, RAND_TYPE_MD },
    { CRYPT_RAND_SHA384, CRYPT_MD_SHA384, RAND_TYPE_MD },
    { CRYPT_RAND_SHA512, CRYPT_MD_SHA512, RAND_TYPE_MD },
#endif
#ifdef HITLS_CRYPTO_DRBG_HMAC
    { CRYPT_RAND_HMAC_SHA1, CRYPT_MAC_HMAC_SHA1, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA224, CRYPT_MAC_HMAC_SHA224, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA256, CRYPT_MAC_HMAC_SHA256, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA384, CRYPT_MAC_HMAC_SHA384, RAND_TYPE_MAC },
    { CRYPT_RAND_HMAC_SHA512, CRYPT_MAC_HMAC_SHA512, RAND_TYPE_MAC },
#endif
#ifdef HITLS_CRYPTO_DRBG_CTR
    { CRYPT_RAND_AES128_CTR, CRYPT_SYM_AES128, RAND_TYPE_AES },
    { CRYPT_RAND_AES192_CTR, CRYPT_SYM_AES192, RAND_TYPE_AES },
    { CRYPT_RAND_AES256_CTR, CRYPT_SYM_AES256, RAND_TYPE_AES },
    { CRYPT_RAND_AES128_CTR_DF, CRYPT_SYM_AES128, RAND_TYPE_AES_DF },
    { CRYPT_RAND_AES192_CTR_DF, CRYPT_SYM_AES192, RAND_TYPE_AES_DF },
    { CRYPT_RAND_AES256_CTR_DF, CRYPT_SYM_AES256, RAND_TYPE_AES_DF }
#endif
};

#ifdef HITLS_CRYPTO_DRBG_CTR
static uint32_t GetAesKeyLen(CRYPT_SYM_AlgId id, uint32_t *keyLen)
{
    switch (id) {
        case CRYPT_SYM_AES128:
            *keyLen = RAND_AES128_KEYLEN;
            break;
        case CRYPT_SYM_AES192:
            *keyLen = RAND_AES192_KEYLEN;
            break;
        case CRYPT_SYM_AES256:
            *keyLen = RAND_AES256_KEYLEN;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_DRBG_ALG_NOT_SUPPORT);
            return CRYPT_DRBG_ALG_NOT_SUPPORT;
    }
    return CRYPT_SUCCESS;
}
#endif

static const DrbgIdMap *GetDrbgIdMap(CRYPT_RAND_AlgId id)
{
    uint32_t num = sizeof(DRBG_METHOD_MAP) / sizeof(DRBG_METHOD_MAP[0]);
    for (uint32_t i = 0; i < num; i++) {
        if (DRBG_METHOD_MAP[i].drbgId == id) {
            return &DRBG_METHOD_MAP[i];
        }
    }

    return NULL;
}

void* EAL_RandDrbgNew(CRYPT_RndParam *param)
{
    if (param == NULL) {
        return NULL;
    }
    CRYPT_RAND_DrbgParam *p = (CRYPT_RAND_DrbgParam*)(param->ptr);
    DRBG_Ctx *drbg = NULL;

    const DrbgIdMap *map = GetDrbgIdMap(p->id);
    if (map == NULL) {
        return NULL;
    }
#ifdef HITLS_CRYPTO_DRBG_HASH
    if (map->type == RAND_TYPE_MD) {
        const EAL_MdMethod *md = EAL_MdFindMethod(map->depId);
        if (md == NULL) {
            return NULL;
        }
        drbg = DRBG_NewHashCtx(md, p->seedMeth, p->seedCtx);
    }
#endif
#ifdef HITLS_CRYPTO_DRBG_HMAC
    if (map->type == RAND_TYPE_MAC) {
        EAL_MacMethLookup hmac;
        if (EAL_MacFindMethod(map->depId, &hmac) != CRYPT_SUCCESS) {
            return NULL;
        }
        drbg = DRBG_NewHmacCtx(hmac.macMethod, hmac.md, p->seedMeth, p->seedCtx);
    }
#endif
#ifdef HITLS_CRYPTO_DRBG_CTR
    if (map->type == RAND_TYPE_AES || map->type == RAND_TYPE_AES_DF) {
        bool isUsedDF = (map->type == RAND_TYPE_AES_DF) ? true : false;
        uint32_t keyLen;
        if (GetAesKeyLen(map->depId, &keyLen) != CRYPT_SUCCESS) {
            return NULL;
        }
        const EAL_CipherMethod *ciphMeth = EAL_FindSymMethod(map->depId);
        if (ciphMeth == NULL) {
            return NULL;
        }
        drbg = DRBG_NewCtrCtx(ciphMeth, keyLen, isUsedDF, p->seedMeth, p->seedCtx);
    }
#endif
    if (DRBG_Instantiate(drbg, p->pers, p->persLen) != CRYPT_SUCCESS) {
        EAL_RandDrbgFree(drbg);
        return NULL;
    }
    return drbg;
}

int32_t EAL_RandDrbgGenerate(void *ctx, uint8_t *bytes, uint32_t len, const uint8_t *adin, uint32_t adinLen)
{
    return DRBG_Generate((DRBG_Ctx *)ctx, bytes, len, adin, adinLen, false);
}

int32_t EAL_RandDrbgReseed(void *ctx, const uint8_t *adin, uint32_t adinLen)
{
    return DRBG_Reseed((DRBG_Ctx *)ctx, adin, adinLen);
}

static int32_t DrbgParaIsValid(CRYPT_RAND_AlgId id, const CRYPT_RandSeedMethod *seedMeth, const void *seedCtx,
    const uint8_t *pers, const uint32_t persLen)
{
    if (GetDrbgIdMap(id) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }

    if (seedMeth == NULL && seedCtx != NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (pers == NULL && persLen != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

static CRYPT_EAL_RndCtx *EAL_RandInitDrbg(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth,
                                          void *seedCtx, const uint8_t *pers, uint32_t persLen)
{
#ifdef HITLS_CRYPTO_ASM_CHECK
    if (CRYPT_ASMCAP_Drbg(id) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_ASM_NOT_SUPPORT);
        return NULL;
    }
#endif
    CRYPT_RandSeedMethod seedMethTmp = {0};
    CRYPT_RandSeedMethod *seedMethond = seedMeth;
    int32_t ret = DrbgParaIsValid(id, seedMeth, seedCtx, pers, persLen);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    if (seedMeth == NULL) {
#ifdef HITLS_CRYPTO_ENTROPY
        ret = EAL_SetDefaultEntropyMeth(&seedMethTmp, &seedCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return NULL;
        }
        seedMethond = &seedMethTmp;
#else
        (void) seedMethTmp;
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
#endif
    }
    CRYPT_EAL_RndCtx *randCtx = BSL_SAL_Malloc(sizeof(CRYPT_EAL_RndCtx));
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

    randCtx->working = false;
    randCtx->id = id;

    EalRndMeth meth = {
        .newCtx = EAL_RandDrbgNew,
        .freeCtx = EAL_RandDrbgFree,
        .rand = EAL_RandDrbgGenerate,
        .seed = EAL_RandDrbgReseed
    };
    CRYPT_RAND_DrbgParam drbgParam = {
        .id = id,
        .seedMeth = seedMethond,
        .seedCtx = seedCtx,
        .pers = pers,
        .persLen = persLen
    };
    CRYPT_RndParam param;
    param.ptr = (uintptr_t)&drbgParam;

    ret = EAL_RandSetMeth(&meth, randCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
        BSL_SAL_FREE(randCtx);
        return NULL;
    }

    ret = EAL_RandInit(&param, randCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadLockFree(randCtx->lock); // free the lock resource
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
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_DRBG_REPEAT_INIT);
        return CRYPT_EAL_ERR_DRBG_REPEAT_INIT;
    }

    ctx = EAL_RandInitDrbg(id, seedMeth, seedCtx, pers, persLen);
    if (ctx == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_RAND, id, CRYPT_EAL_ERR_DRBG_INIT_FAIL);
        return CRYPT_EAL_ERR_DRBG_INIT_FAIL;
    }
    CRYPT_RandRegist(CRYPT_EAL_Randbytes); // provide a random number generation function for BigNum.
    g_globalRndCtx = ctx;
    return CRYPT_SUCCESS;
}

CRYPT_EAL_RndCtx *CRYPT_EAL_DrbgInit(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx,
    const uint8_t *pers, uint32_t persLen)
{
    return EAL_RandInitDrbg(id, seedMeth, seedCtx, pers, persLen);
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

bool CRYPT_EAL_RandIsValidAlgId(CRYPT_RAND_AlgId id)
{
    return (GetDrbgIdMap(id) != NULL);
}
#endif
