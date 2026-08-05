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

#ifndef HBS_WOTS_H
#define HBS_WOTS_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>
#include "hbs_common.h"
#include "hbs_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HBS WOTS+ Context
 */
typedef struct {
    const void *coreCtx;
    uint32_t n;
    uint32_t otsLen; /**< Number of WOTS+ chain elements */
    const HbsHashFuncs *hashFuncs; /**< Hash function interface */
    const HbsAdrsOps *adrsOps; /**< Address operation interface */
    const uint8_t *pubSeed;
    const uint8_t *skSeed;
    HbsAlgoType algoType; /**< Algorithm type (XMSS or SLH-DSA) */
} HbsWotsCtx;

/**
 * @ingroup hbs
 * @brief WOTS+ chain iteration (F function applied 'steps' times)
 *
 * @param x       [IN]  Starting value (n bytes)
 * @param xLen    [IN]  Length of x (must equal n)
 * @param start   [IN]  Starting chain position
 * @param steps   [IN]  Number of iterations
 * @param pubSeed [IN]  Public seed (kept for API compatibility)
 * @param adrs    [IN/OUT] Address structure (hash address will be modified)
 * @param ctx     [IN]  WOTS+ context
 * @param output  [OUT] Result after 'steps' iterations (n bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HbsWots_Chain(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
                      void *adrs, const HbsWotsCtx *ctx, uint8_t *output);

/**
 * @ingroup hbs
 * @brief Generate WOTS+ public key from secret seed
 *
 * @param pub  [OUT] Output public key (compressed via L-tree, n bytes)
 * @param adrs [IN/OUT] Address structure
 * @param ctx  [IN]  WOTS+ context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HbsWots_GeneratePublicKey(uint8_t *pub, void *adrs, const HbsWotsCtx *ctx);

/**
 * @ingroup hbs
 * @brief Generate WOTS+ signature
 *
 * @param sig    [OUT] Output signature buffer (otsLen * n bytes)
 * @param sigLen [IN/OUT] In: buffer size, Out: actual signature length
 * @param msg    [IN]  Message to sign (n bytes)
 * @param msgLen [IN]  Message length (must equal n)
 * @param adrs   [IN/OUT] Address structure
 * @param ctx    [IN]  WOTS+ context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HbsWots_Sign(uint8_t *sig, uint32_t *sigLen, const uint8_t *msg, uint32_t msgLen, void *adrs,
                     const HbsWotsCtx *ctx);

/**
 * @ingroup hbs
 * @brief Recover WOTS+ public key from signature
 *
 * @param msg    [IN]  Message that was signed (n bytes)
 * @param msgLen [IN]  Message length (must equal n)
 * @param sig    [IN]  Signature (otsLen * n bytes)
 * @param sigLen [IN]  Signature length
 * @param adrs   [IN/OUT] Address structure
 * @param ctx    [IN]  WOTS+ context
 * @param pub    [OUT] Recovered public key (compressed, n bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HbsWots_PkFromSig(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, void *adrs,
                          const HbsWotsCtx *ctx, uint8_t *pub);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_XMSSMT || HITLS_CRYPTO_SLH_DSA */
#endif /* HBS_WOTS_H */
