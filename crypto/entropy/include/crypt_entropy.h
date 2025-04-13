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

#ifndef CRYPT_ENTROPY_H
#define CRYPT_ENTROPY_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * drbg1         drbg2         drbg3         drbgi
 *   *             *             *             *
 *         *         *         *        *
 *                 *   *     *   *
 *                        *
 *                        *
 *                   get-entropy
 *                        *
 *                   parent-drbg
 *                        *
 *                   get-entropy
 *                        *
 *                    seed-pool
 *                        *
 *                        *
 *                 *   *    *    *      
 *           *       *        *         *
 *     *          *             *             *
 * hard-ES     sys-ES        hitls-ES      ES(add-in)
 *                               *
 *                          entropy-pool
 *                               *
 *                            CF/LFST
 *                               *
 *                               *
 *                        *    *   *    *    
 *                 *         *       *         *
 *          *             *             *             *
 *     timestamp-NS   jitter-NS    interrup-NS     NS(add-in)
 */
#ifdef HITLS_CRYPTO_ENTROPY_SYS
typedef struct ES_Entropy ENTROPY_EntropySource;

typedef struct {
    uint32_t algId;
    void *md;
} ENTROPY_CFPara;

/* Entropy source model APIs provided by HiTLS. */

/* Creating an entropy source. */
ENTROPY_EntropySource *ENTROPY_EsNew(void);

/* release entropy source. */
void ENTROPY_EsFree(ENTROPY_EntropySource *ctx);

/* Initialize Entropy Source. */
int32_t ENTROPY_EsInit(ENTROPY_EntropySource *ctx);

/* Deinitialize the entropy source. */
void ENTROPY_EsDeinit(ENTROPY_EntropySource *ctx);

/* Interface for Setting the Entropy Source. */
int32_t ENTROPY_EsCtrl(ENTROPY_EntropySource *ctx, int32_t cmd, void *data, uint32_t len);

/* Obtaining Entropy Data. */
uint32_t ENTROPY_EsEntropyGet(ENTROPY_EntropySource *ctx, uint8_t *data, uint32_t len);

/* Collect entropy data. */
int32_t ENTROPY_EsEntropyGather(ENTROPY_EntropySource *es);
#endif

typedef struct EntropySeedPool ENTROPY_SeedPool;


typedef uint32_t (*EntropyGet)(void *ctx, uint8_t *buf, uint32_t bufLen);

/* create seed-pool handles */
ENTROPY_SeedPool *ENTROPY_SeedPoolNew(bool isCreateNullPool);

/* Adding an entropy source */
int32_t ENTROPY_SeedPoolAddEs(ENTROPY_SeedPool *pool, const CRYPT_EAL_EsPara *para);

/* Interface for releasing the seed pool */
void ENTROPY_SeedPoolFree(ENTROPY_SeedPool *pool);

/* Interface for collecting entropy data */
uint32_t ENTROPY_SeedPoolCollect(ENTROPY_SeedPool *pool, bool isNpesUsed, uint32_t needEntropy,
    uint8_t *data, uint32_t *len);

/* Check whether the seed pool contains physical or non-physical entropy sources. */
bool ENTROPY_SeedPoolCheckState(ENTROPY_SeedPool *seedPool, bool isNpesUsed);

/* Obtains the minimum entropy of the entropy source. */
uint32_t ENTROPY_SeedPoolGetMinEntropy(ENTROPY_SeedPool *seedPool);

typedef int32_t (*ExternalConditioningFunction)(uint32_t algId, uint8_t *in, uint32_t inLen, uint8_t *out,
    uint32_t *outLen);

typedef struct EcfCtx {
    uint32_t algId;
    ExternalConditioningFunction conFunc;
} ENTROPY_ECFCtx;

/**
 * @brief Obtain full entropy bits
 *
 * @param ctx[IN] ecfCtx
 * @param pool[IN] seed pool
 * @param isNpesUsed[IN] whether the npes is available
 * @param needEntropy[IN] the amount of entropy required
 * @param data[OUT] data
 * @param len[IN]  length
 * @return  Success: CRYPT_SUCCESS
 */
int32_t ENTROPY_GetFullEntropyInput(void *ctx, ENTROPY_SeedPool *pool, bool isNpesUsed, uint32_t needEntropy,
    uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ENTROPY

#endif // CRYPT_ENTROPY_H
