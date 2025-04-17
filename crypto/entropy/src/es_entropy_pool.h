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

#ifndef ES_ENTROPY_POOL_H
#define ES_ENTROPY_POOL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint8_t *buf; // queue data
    uint32_t front; // queue head
    uint32_t rear; // queue tail
    uint32_t maxSize; // queue capacity + 1
} ES_EntropyPool;

/* Entropy pool initialization. */
ES_EntropyPool *ES_EntropyPoolInit(uint32_t size);

/* Entropy pool deinitialization. */
void ES_EntropyPoolDeInit(ES_EntropyPool *pool);

/* Obtains the maximum capacity of the entropy pool. */
int32_t ES_EntropyPoolGetMaxSize(ES_EntropyPool *pool);

/* Obtains the current data volume of the entropy pool. */
uint32_t ES_EntropyPoolGetCurSize(ES_EntropyPool *pool);

/* Obtains entropy data from the entropy pool. */
int32_t ES_EntropyPoolPushBytes(ES_EntropyPool *pool, uint8_t *buf, uint32_t bufLen);

/* Compress entropy data into the entropy pool. */
uint32_t ES_EntropyPoolPopBytes(ES_EntropyPool *pool, uint8_t *data, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif

#endif