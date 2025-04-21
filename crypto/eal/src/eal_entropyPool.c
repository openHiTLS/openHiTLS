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
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "eal_entropy.h"
#include "eal_common.h"
#ifdef HITLS_CRYPTO_ENTROPY_SYS
#include "eal_md_local.h"
#endif
#include "crypt_eal_entropy.h"

#define CRYPT_ENTROPY_SOURCE_FULL_ENTROPY 8

#ifdef HITLS_CRYPTO_ENTROPY_SYS
CRYPT_EAL_Es *CRYPT_EAL_EsNew(void)
{
    CRYPT_EAL_Es *esCtx = BSL_SAL_Malloc(sizeof(CRYPT_EAL_Es));
    if (esCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(esCtx, sizeof(CRYPT_EAL_Es), 0, sizeof(CRYPT_EAL_Es));
    esCtx->es = ENTROPY_EsNew();
    if (esCtx->es == NULL) {
        BSL_SAL_Free(esCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CREATE_ERROR);
        return NULL;
    }
    int32_t ret = BSL_SAL_ThreadLockNew(&esCtx->lock);
    if (ret != CRYPT_SUCCESS) {
        ENTROPY_EsFree(esCtx->es);
        BSL_SAL_FREE(esCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return esCtx;
}

void CRYPT_EAL_EsFree(CRYPT_EAL_Es *esCtx)
{
    if (esCtx == NULL) {
        return;
    }
    BSL_SAL_ThreadLockHandle lock = esCtx->lock;
    esCtx->lock = NULL;
    if (BSL_SAL_ThreadWriteLock(lock) != BSL_SUCCESS) {
        ENTROPY_EsFree(esCtx->es);
        BSL_SAL_ThreadLockFree(lock);
        BSL_SAL_Free(esCtx);
        return;
    }
    ENTROPY_EsFree(esCtx->es);
    (void)BSL_SAL_ThreadUnlock(lock);
    BSL_SAL_ThreadLockFree(lock);
    BSL_SAL_Free(esCtx);
    return;
}

int32_t CRYPT_EAL_EsInit(CRYPT_EAL_Es *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(ctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ENTROPY_EsInit(ctx->es);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    (void)BSL_SAL_ThreadUnlock(ctx->lock);
    return ret;
}

uint32_t CRYPT_EAL_EsEntropyGet(CRYPT_EAL_Es *esCtx, uint8_t *data, uint32_t len)
{
    if (esCtx == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock((esCtx->lock));
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR((ret));
        return 0;
    }

    uint32_t resLen = ENTROPY_EsEntropyGet(esCtx->es, data, len);
    (void)BSL_SAL_ThreadUnlock(esCtx->lock);
    return resLen;
}


static uint32_t EAL_CfGetAlgId(const char *name)
{
    if (strcmp(name, "sm3_df") == 0) {
        return CRYPT_MD_SM3;
    }
    if (strcmp(name, "sha224_df") == 0) {
        return CRYPT_MD_SHA224;
    }
    if (strcmp(name, "sha256_df") == 0) {
        return CRYPT_MD_SHA256;
    }
    if (strcmp(name, "sha384_df") == 0) {
        return CRYPT_MD_SHA384;
    }
    if (strcmp(name, "sha512_df") == 0) {
        return CRYPT_MD_SHA512;
    }
    return CRYPT_MD_MAX;
}

static int32_t EAL_CFSetDfMethod(CRYPT_EAL_Es *esCtx, const char *name)
{
    CRYPT_MD_AlgId alg = EAL_CfGetAlgId(name);
    if (alg == CRYPT_MD_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_ALG_ERROR);
        return CRYPT_ENTROPY_ECF_ALG_ERROR;
    }
    const EAL_MdMethod *md = EAL_MdFindMethod(alg);
    if (md == NULL) {
        EAL_ERR_REPORT(CRYPT_EVENT_ERR, CRYPT_ALGO_MD, alg, CRYPT_EAL_ERR_ALGID);
        return CRYPT_ENTROPY_ECF_ALG_ERROR;
    }
    ENTROPY_CFPara para = {alg, (void *)(uintptr_t)md};
    return ENTROPY_EsCtrl(esCtx->es, CRYPT_ENTROPY_SET_CF, (void *)&para, sizeof(ENTROPY_CFPara));
}

static int32_t EAL_EsPoolCfSet(CRYPT_EAL_Es *esCtx, void *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (strstr(data, "df") != NULL) {
        return EAL_CFSetDfMethod(esCtx, data);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_ALG_ERROR);
    return CRYPT_ENTROPY_ECF_ALG_ERROR;
}

static int32_t EAL_EsCtrl(CRYPT_EAL_Es *esCtx, int32_t cmd, void *data, uint32_t len)
{
    switch (cmd) {
        case CRYPT_ENTROPY_SET_CF:
            return EAL_EsPoolCfSet(esCtx, data, len);
        case CRYPT_ENTROPY_GATHER_ENTROPY:
            return ENTROPY_EsEntropyGather(esCtx->es);
        default:
            return ENTROPY_EsCtrl(esCtx->es, cmd, data, len);
    }
}


int32_t CRYPT_EAL_EsCtrl(CRYPT_EAL_Es *esCtx, int32_t type, void *data, uint32_t len)
{
    if (esCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (type < CRYPT_ENTROPY_SET_POOL_SIZE || type >= CRYPT_ENTROPY_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ES_CTRL_ERROR);
        return CRYPT_ENTROPY_ES_CTRL_ERROR;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(esCtx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = EAL_EsCtrl(esCtx, type, data, len);
    (void)BSL_SAL_ThreadUnlock(esCtx->lock);
    return ret;
}

static CRYPT_EAL_Es *EsDefaultCreate(void)
{
    CRYPT_EAL_Es *es = CRYPT_EAL_EsNew();
    if (es == NULL) {
        return NULL;
    }
    char *data = "sha256_df";
    int32_t ret = CRYPT_EAL_EsCtrl(es, CRYPT_ENTROPY_SET_CF, data, strlen(data));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    ret = ENTROPY_EsInit(es->es);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_EsFree(es);
        return NULL;
    }
    return es;
}
#endif

CRYPT_EAL_SeedPoolCtx *CRYPT_EAL_SeedPoolNew(bool isCreateNullPool)
{
    CRYPT_EAL_SeedPoolCtx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_EAL_SeedPoolCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_EAL_SeedPoolCtx), 0, sizeof(CRYPT_EAL_SeedPoolCtx));
    int32_t ret = BSL_SAL_ThreadLockNew(&ctx->lock);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(ctx);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    ctx->pool = ENTROPY_SeedPoolNew(isCreateNullPool);
    if (ctx->pool == NULL) {
        CRYPT_EAL_SeedPoolFree(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NEW_ERROR);
        return NULL;
    }
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    if (isCreateNullPool) {
        ctx->es = NULL;
        return ctx;
    }
    ctx->es = EsDefaultCreate();
    if (ctx->es == NULL) {
        CRYPT_EAL_SeedPoolFree(ctx);
        return NULL;
    }
    CRYPT_EAL_EsPara para = {false, CRYPT_ENTROPY_SOURCE_FULL_ENTROPY, ctx->es,
        (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ret = ENTROPY_SeedPoolAddEs(ctx->pool, &para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_SeedPoolFree(ctx);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
#endif
    return ctx;
}

int32_t CRYPT_EAL_SeedPoolAddEs(CRYPT_EAL_SeedPoolCtx *ctx, const CRYPT_EAL_EsPara *para)
{
    if (ctx == NULL || para == NULL || para->minEntropy == 0 || para->minEntropy > CRYPT_ENTROPY_SOURCE_FULL_ENTROPY ||
        para->entropyGet == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(ctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ENTROPY_SeedPoolAddEs(ctx->pool, para);
    (void)BSL_SAL_ThreadUnlock(ctx->lock);
    return ret;
}

void CRYPT_EAL_SeedPoolFree(CRYPT_EAL_SeedPoolCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    (void)BSL_SAL_ThreadWriteLock(ctx->lock);
    if (ctx->pool != NULL) {
        ENTROPY_SeedPoolFree(ctx->pool);
        ctx->pool = NULL;
    }
#ifdef HITLS_CRYPTO_ENTROPY_SYS
    if (ctx->es != NULL) {
        CRYPT_EAL_EsFree(ctx->es);
        ctx->es = NULL;
    }
#endif
    (void)BSL_SAL_ThreadUnlock(ctx->lock);
    BSL_SAL_ThreadLockFree(ctx->lock);
    BSL_SAL_FREE(ctx);
    return;
}

static int32_t SeedPoolGetEntropy(CRYPT_EAL_SeedPoolCtx *poolCtx, CRYPT_Data *entropy, uint32_t strength,
    const CRYPT_Range *lenRange)
{
    EAL_EntropyCtx *ctx = EAL_EntropyNewCtx(poolCtx, true, lenRange->min, lenRange->max, strength);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_CTX_CREATE_FAILED);
        return CRYPT_ENTROPY_CTX_CREATE_FAILED;
    }
    int32_t ret = EAL_EntropyCollection(poolCtx, ctx);
    if (ret != CRYPT_SUCCESS) {
        EAL_EntropyFreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    entropy->data = EAL_EntropyDetachBuf(ctx, &entropy->len);
    EAL_EntropyFreeCtx(ctx);
    if (entropy->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_SeedPoolGetEntropy(CRYPT_EAL_SeedPoolCtx *ctx, CRYPT_Data *entropy, uint32_t strength,
    const CRYPT_Range *lenRange)
{
    if (ctx == NULL || entropy == NULL || lenRange == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(ctx->lock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = SeedPoolGetEntropy(ctx, entropy, strength, lenRange);
    (void)BSL_SAL_ThreadUnlock(ctx->lock);
    return ret;
}
#endif