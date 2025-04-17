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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "es_entropy_pool.h"

ES_EntropyPool *ES_EntropyPoolInit(uint32_t size)
{
    ES_EntropyPool *pool = NULL;
    uint32_t maxSize = size + 1;
    if (size == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    pool = (ES_EntropyPool *)BSL_SAL_Malloc(sizeof(ES_EntropyPool));
    if (pool == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    pool->buf = (uint8_t *)BSL_SAL_Malloc(maxSize);
    if (pool->buf == NULL) {
        BSL_SAL_FREE(pool);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    pool->front = 0;
    pool->rear = 0;
    pool->maxSize = maxSize;
    return pool;
}

void ES_EntropyPoolDeInit(ES_EntropyPool *pool)
{
    if (pool == NULL) {
        return;
    }

    (void)memset_s(pool->buf, pool->maxSize, 0, pool->maxSize);
    BSL_SAL_FREE(pool->buf);
    BSL_SAL_Free(pool);
    return;
}

int32_t ES_EntropyPoolGetMaxSize(ES_EntropyPool *pool)
{
    return pool->maxSize - 1;
}

uint32_t ES_EntropyPoolGetCurSize(ES_EntropyPool *pool)
{
    return (pool->rear - pool->front + pool->maxSize) % pool->maxSize;
}

int32_t ES_EntropyPoolPushBytes(ES_EntropyPool *pool, uint8_t *buf, uint32_t bufLen)
{
    uint32_t partA, partB;
    partA = (bufLen > (pool->maxSize - pool->rear)) ? pool->maxSize - pool->rear : bufLen;
    (void)memcpy_s(&pool->buf[pool->rear], pool->maxSize - pool->rear, buf, partA);
    pool->rear = (pool->rear + partA) % pool->maxSize;
    if (partA < bufLen) {
        partB = bufLen - partA;
        (void)memcpy_s(&pool->buf[pool->rear], pool->maxSize - pool->rear, buf + partA, partB);
        pool->rear = (pool->rear + partB) % pool->maxSize;
    }
    return CRYPT_SUCCESS;
}

uint32_t ES_EntropyPoolPopBytes(ES_EntropyPool *pool, uint8_t *data, uint32_t size)
{
    uint32_t bufLen, partA, partB;
    if (ES_EntropyPoolGetMaxSize(pool) == 0 || size == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }

    bufLen = (ES_EntropyPoolGetCurSize(pool) < size) ? ES_EntropyPoolGetCurSize(pool) : size;

    partA = (bufLen <= pool->maxSize - pool->front) ? bufLen : pool->maxSize - pool->front;
    (void)memcpy_s(data, bufLen, &pool->buf[pool->front], partA);
    pool->front = (pool->front + partA) % pool->maxSize;
    partB = bufLen - partA;
    if (partB != 0) {
        (void)memcpy_s(data + partA, bufLen - partA, &pool->buf[pool->front], partB);
        pool->front = (pool->front + partB) % pool->maxSize;
    }

    return bufLen;
}

#endif