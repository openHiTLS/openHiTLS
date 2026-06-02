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
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>
#include "hbs_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XMSS/SLH-DSA Hash Functions Interface
 */
typedef struct XmssFamilyHashFuncs {
    /* Private key derivation: PRF(skSeed, adrs) */
    int32_t (*skDerive)(const void *ctx, const void *adrs, uint8_t *out);

    /* Chain iteration hash: F(pubSeed, adrs, msg) */
    int32_t (*chainHash)(const void *ctx, const void *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out);

    /* Tree node merge hash: H(pubSeed, adrs, left||right) */
    int32_t (*nodeHash)(const void *ctx, const void *adrs, const uint8_t *in, uint32_t inLen, uint8_t *out);

    /* Message hash: H_msg(r, root, idx, msg) */
    int32_t (*msgHash)(const void *ctx, const uint8_t *r, const uint8_t *msg, uint32_t msgLen, const uint8_t *idx,
                       uint8_t *out);

    /* L-tree public key compression: T_l(pubSeed, adrs, wotsPk) */
    int32_t (*pkCompress)(const void *ctx, const void *adrs, const uint8_t *msg, uint32_t msgLen, uint8_t *out);

    /* Signature randomness generation: PRF_msg(skPrf, optRand, msg) */
    int32_t (*sigRandGen)(const void *ctx, const uint8_t *key, const uint8_t *msg, uint32_t msgLen, uint8_t *out);

    /* Optional optimized multi-step chain iteration.
     * When non-NULL, HbsWots_Chain delegates to this instead of the generic chainHash loop.
     * Intended for algorithms (e.g. SLH-DSA) that can reuse pre-computed hash state
     * across iterations for performance (ChainSha256 / ChainShake256).
     * Set to NULL to use the generic fallback in HbsWots_Chain. */
    int32_t (*chain)(const uint8_t *x, uint32_t xLen, uint32_t start, uint32_t steps, const uint8_t *pubSeed,
                     void *adrs, const void *ctx, uint8_t *output);
} XmssFamilyHashFuncs;

/*
 * XMSS/SLH-DSA Address Operations Interface
 */
typedef struct XmssFamilyAdrsOps {
    void (*setLayerAddr)(void *adrs, uint32_t layer);
    void (*setTreeAddr)(void *adrs, uint64_t tree);
    void (*setType)(void *adrs, uint32_t type);
    void (*setKeyPairAddr)(void *adrs, uint32_t keyPair);
    void (*setChainAddr)(void *adrs, uint32_t chain);
    void (*setTreeHeight)(void *adrs, uint32_t height);
    void (*setHashAddr)(void *adrs, uint32_t hash);
    void (*setTreeIndex)(void *adrs, uint32_t index);
    uint32_t (*getTreeIndex)(const void *adrs);
    void (*copyKeyPairAddr)(void *dest, const void *src);
    uint32_t (*getAdrsLen)(void);
} XmssFamilyAdrsOps;

/*
 * HBS WOTS+ Context
 */
typedef struct {
    const void *coreCtx;
    uint32_t n;
    uint32_t otsLen; /**< Number of WOTS+ chain elements */
    const XmssFamilyHashFuncs *hashFuncs; /**< Hash function interface */
    const XmssFamilyAdrsOps *adrsOps; /**< Address operation interface */
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

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_SLH_DSA */
#endif /* HBS_WOTS_H */
