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
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "entropy_seed_pool.h"

#define SEEDPOOL_ES_MAX_SIZE 16
#define SEEDPOOL_ES_INIT_MINENTROPY 9
#define SEEDPOOL_ES_FULL_MINENTROPY 8
#define SEEDPOOL_ES_SYS_MINENTROPY 7

#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
#define ENTROPY_SEEDPOOL_HAVE_SYS_BACKEND
#endif

#if defined(HITLS_CRYPTO_ENTROPY_HARDWARE) && \
    (defined(__x86_64__) || (defined(__aarch64__) && defined(__linux__)))
#define ENTROPY_SEEDPOOL_HAVE_HW_BACKEND
#endif

static int32_t SeedPoolAddDefaultSys(ENTROPY_SeedPool *pool)
{
#ifdef ENTROPY_SEEDPOOL_HAVE_SYS_BACKEND
    CRYPT_EAL_EsPara para = {false, SEEDPOOL_ES_SYS_MINENTROPY, NULL, ENTROPY_SysEntropyGet};
    return ENTROPY_SeedPoolAddEs(pool, &para);
#else
    (void)pool;
    return CRYPT_SUCCESS;
#endif
}

static int32_t SeedPoolAddDefaultHw(ENTROPY_SeedPool *pool)
{
#ifdef ENTROPY_SEEDPOOL_HAVE_HW_BACKEND
    CRYPT_EAL_EsPara para = {true, SEEDPOOL_ES_FULL_MINENTROPY, NULL, ENTROPY_HWEntropyGet};
    return ENTROPY_SeedPoolAddEs(pool, &para);
#else
    (void)pool;
    return CRYPT_SUCCESS;
#endif
}

ENTROPY_SeedPool *ENTROPY_SeedPoolNew(bool isCreateNullPool)
{
    ENTROPY_SeedPool *poolCtx = BSL_SAL_Malloc(sizeof(ENTROPY_SeedPool));
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    memset(poolCtx, 0, sizeof(ENTROPY_SeedPool));
    poolCtx->esList = BSL_LIST_New(sizeof(ENTROPY_Source));
    if (poolCtx->esList == NULL) {
        BSL_SAL_Free(poolCtx);
        BSL_ERR_PUSH_ERROR(BSL_LIST_MALLOC_FAIL);
        return NULL;
    }
    poolCtx->minEntropy = SEEDPOOL_ES_INIT_MINENTROPY;
    if (isCreateNullPool) {
        return poolCtx;
    }

    int32_t ret = SeedPoolAddDefaultSys(poolCtx);
    if (ret != CRYPT_SUCCESS) {
        ENTROPY_SeedPoolFree(poolCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    ret = SeedPoolAddDefaultHw(poolCtx);
    if (ret != CRYPT_SUCCESS) {
        ENTROPY_SeedPoolFree(poolCtx);
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }
    return poolCtx;
}

static ENTROPY_Source *SeedPoolEsNew(const CRYPT_EAL_EsPara *para)
{
    ENTROPY_Source *es = BSL_SAL_Malloc(sizeof(ENTROPY_Source));
    if (es == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    es->isPhysical = para->isPhysical;
    es->minEntropy = para->minEntropy;
    es->ctx = para->entropyCtx;
    es->entropyGet = (EntropyGet)(para->entropyGet);
    return es;
}

int32_t ENTROPY_SeedPoolAddEs(ENTROPY_SeedPool *pool, const CRYPT_EAL_EsPara *para)
{
    if (pool == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (BSL_LIST_COUNT(pool->esList) >= SEEDPOOL_ES_MAX_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_ES_LIST_FULL);
        return CRYPT_SEED_POOL_ES_LIST_FULL;
    }
    ENTROPY_Source *es = SeedPoolEsNew(para);
    if (es == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NEW_ERROR);
        return CRYPT_SEED_POOL_NEW_ERROR;
    }
    /*
     * The header insertion method is used to add an entropy source to ensure that the entropy source added by the
     * invoker is used first when the entropy data is obtained.
     */
    int32_t ret = BSL_LIST_AddElement(pool->esList, es, BSL_LIST_POS_BEGIN);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(es);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pool->minEntropy = (pool->minEntropy < para->minEntropy) ? pool->minEntropy : para->minEntropy;
    pool->isContainFes = pool->isContainFes || (para->minEntropy == SEEDPOOL_ES_FULL_MINENTROPY);
    pool->isContainPes = pool->isContainPes || para->isPhysical;
    return CRYPT_SUCCESS;
}

void ENTROPY_SeedPoolFree(ENTROPY_SeedPool *pool)
{
    if (pool == NULL) {
        return;
    }

    if (pool->esList != NULL) {
        BSL_LIST_FREE(pool->esList, BSL_SAL_Free);
    }
    BSL_SAL_Free(pool);
    return;
}

static uint32_t GetMinLen(uint32_t needEntropy, uint32_t currEntropy, uint32_t minEntropy, uint32_t bufLen)
{
    if (needEntropy == 0) {
        return bufLen;
    }
    uint32_t len =
        (uint32_t)(((uint64_t)(needEntropy - currEntropy) + (uint64_t)minEntropy - 1) / (uint64_t)minEntropy);
    return bufLen >= len ? len : bufLen;
}

static uint32_t SeedPoolCreditAdd(uint32_t curEntropy, uint32_t minEntropy, uint32_t readLen)
{
    uint64_t total = (uint64_t)curEntropy + (uint64_t)minEntropy * readLen;
    return total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
}

uint32_t ENTROPY_SeedPoolCollect(ENTROPY_SeedPool *pool, bool isNpesUsed, uint32_t needEntropy, uint8_t *data,
    uint32_t *len)
{
    if (data == NULL || len == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (!ENTROPY_SeedPoolCheckState(pool, isNpesUsed)) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_STATE_ERROR);
        return 0;
    }
    uint32_t bufLen = *len;
    uint8_t *buf = data;
    uint32_t curEntropy = 0;
    for (BslListNode *node = BSL_LIST_FirstNode(pool->esList); node != NULL;
        node = BSL_LIST_GetNextNode(pool->esList, node)) {
        ENTROPY_Source *es = BSL_LIST_GetData(node);
        if (!isNpesUsed && !es->isPhysical) {
            continue;
        }
        uint32_t tmpLen = GetMinLen(needEntropy, curEntropy, es->minEntropy, bufLen);
        uint32_t readLen = es->entropyGet(es->ctx, buf, tmpLen);
        if (readLen > tmpLen) {
            *len = 0;
            BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_STATE_ERROR);
            return 0;
        }
        if (readLen > 0) {
            bufLen -= readLen;
            buf += readLen;
            curEntropy = SeedPoolCreditAdd(curEntropy, es->minEntropy, readLen);
        }
        bool flag = (needEntropy == 0) ? (bufLen == 0) : (curEntropy >= needEntropy);
        if (flag) {
            break;
        }
    }
    *len = buf - data;
    return curEntropy;
}

bool ENTROPY_SeedPoolCheckState(ENTROPY_SeedPool *seedPool, bool isNpesUsed)
{
    if (seedPool == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return false;
    }
    if (BSL_LIST_COUNT(seedPool->esList) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NO_ENTROPY_SOURCE);
        return false;
    }
    if (!isNpesUsed && !seedPool->isContainPes) {
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NO_ENTROPY_SOURCE);
        return false;
    }
    return true;
}

uint32_t ENTROPY_SeedPoolGetMinEntropy(ENTROPY_SeedPool *seedPool)
{
    if (seedPool == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return seedPool->minEntropy;
}
#endif
