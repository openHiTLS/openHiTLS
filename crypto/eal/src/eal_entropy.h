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

#ifndef EAL_ENTROPY_H
#define EAL_ENTROPY_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_ENTROPY)

#include "crypt_eal_entropy.h"
#include "bsl_sal.h"
#include "crypt_entropy.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef HITLS_CRYPTO_ENTROPY_SYS
struct CryptEalEntropySource {
    ENTROPY_EntropySource *es;
    BSL_SAL_ThreadLockHandle lock; // thread lock
};
#endif

typedef struct {
    /* whether non-physical entropy sources are allowed. */
    bool isNpesUsed;
    /* whether a full-entropy bit string is required. */
    bool isNeedFe;
    /* the minimum length of entropy data. */
    uint32_t minLen;
    /* the maximum length of entropy data. */
    uint32_t maxLen;
    /* the amount of entropy required. */
    uint32_t requestEntropy;
    /* the current amount of entropy. */
    uint32_t curEntropy;
    /* external conditioning function algorithm */
    uint32_t ecfuncId;
    uint32_t ecfOutLen;
    /* external conditioning function */
    ExternalConditioningFunction ecfunc;
    /* the length of the existing entropy data */
    uint32_t curLen;
    /* the length of entropy buffer. */
    uint32_t bufLen;
    /* the buffer of entropy buffer. */
    uint8_t *buf;
} EAL_EntropyCtx;

struct EAL_SeedPool {
    CRYPT_EAL_Es *es;
    void *pool;
    BSL_SAL_ThreadLockHandle lock; // thread lock
};

/*
 * @brief Creating an Entropy Source Application Handle.
 *
 * @param  seedPool[IN] seed pool handle
 * @param  isNpesUsed[IN] whether non-physical entropy sources are allowed
 * @param  minLen[IN] the minimum length of entropy data
 * @param  maxLen[IN] the maximum length of entropy data
 * @param  entropy[IN] the amount of entropy required
 * @return entropy context
 */
EAL_EntropyCtx *EAL_EntropyNewCtx(CRYPT_EAL_SeedPoolCtx *seedPool, uint8_t isNpesUsed, uint32_t minLen,
    uint32_t maxLen, uint32_t entropy);

/*
 * @brief Release an Entropy Source Application Handle.
 *
 * @param  ctx[IN] seed pool handle
 * @return void
 */
void EAL_EntropyFreeCtx(EAL_EntropyCtx *ctx);

/*
 * @brief collect entropy data.
 *
 * @param  seedPool[IN] seed pool handle
 * @param  ctx[IN] entropy source application Handle
 * @return success: CRYPT_SUCCESS
 *         failed: other error codes
 */
int32_t EAL_EntropyCollection(CRYPT_EAL_SeedPoolCtx *seedPool, EAL_EntropyCtx *ctx);

/*
 * @brief pop entropy data.
 *
 * @param  seedPool[IN] seed pool handle
 * @param  ctx[IN] entropy source application Handle
 * @param  len[OUT] entropy buf length
 * @return success: buffer
 *         failed: NULL
 */
uint8_t *EAL_EntropyDetachBuf(EAL_EntropyCtx *ctx, uint32_t *len);

/**
 * @brief Set the random number method that uses the default system entropy source.
 *
 * @param meth    meth method
 * @return Success: CRYPT_SUCCESS
 */
int32_t EAL_SetDefaultEntropyMeth(CRYPT_RandSeedMethod *meth);

/**
 * @brief Obtain the conditioning function of the corresponding algorithm.
 *
 * @param  algId algId
 * @return ExternalConditioningFunction
 */
ExternalConditioningFunction EAL_EntropyGetECF(uint32_t algId);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif

#endif
