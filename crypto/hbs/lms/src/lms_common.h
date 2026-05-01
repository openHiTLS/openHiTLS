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

#ifndef LMS_COMMON_H
#define LMS_COMMON_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "lms_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup lms_common LMS Common Infrastructure
 * @brief Shared interfaces and structures for LMS/HSS operations
 *
 * This module provides common abstractions following the XMSS/SLH-DSA pattern:
 * - Generic address operations interface (LmsAdrsOps)
 * - Context-based OTS operations (LmsOtsCtx)
 * - Context-based tree operations (LmsTreeCtx)
 * - Shared utilities and constants
 *
 * Design Philosophy:
 * - Reduce code duplication between LMS and HSS
 * - Enable context-based operations (reduce parameter passing)
 * - Provide clear separation between algorithm-specific and reusable code
 * - Maintain RFC 8554 compliance
 */

/* Forward declarations */
typedef struct LmsOtsCtx LmsOtsCtx;
typedef struct LmsTreeCtx LmsTreeCtx;
typedef struct LmsFamilyAdrsOps LmsFamilyAdrsOps;

/**
 * @ingroup lms_common
 * @brief LMS Address Operations Interface
 *
 * Unlike XMSS which uses structured addresses, LMS uses domain-separated
 * hash inputs (I || q || D || data). This interface abstracts buffer
 * construction for different operations while respecting RFC 8554's
 * domain separation approach.
 *
 * Buffer formats:
 * - OTS iteration:  I(16) || q(4) || k(2) || j(1) || prev(n)
 * - Leaf node:      I(16) || r(4) || D(2) || pk(n)
 * - Internal node:  I(16) || r(4) || D(2) || left(n) || right(n)
 * - Message hash:   I(16) || q(4) || D(2) || C(n)
 * - OTS public key: I(16) || q(4) || D(2) || chains(p*n)
 */
struct LmsFamilyAdrsOps {
    /**
     * Build OTS iteration buffer (I || q || k || j || prev)
     * @param buffer [OUT] Output buffer (must be at least LMS_ITER_LEN(n) bytes)
     * @param I      [IN]  Tree identifier (16 bytes)
     * @param q      [IN]  Leaf index
     * @param k      [IN]  Chain index
     * @param j      [IN]  Iteration index
     * @param prev   [IN]  Previous hash value (n bytes)
     * @param n      [IN]  Hash output length
     */
    void (*buildOtsIterInput)(uint8_t *buffer, const uint8_t *I, uint32_t q, uint32_t k, uint32_t j,
                              const uint8_t *prev, uint32_t n);

    /**
     * Build leaf node buffer (I || r || D || pk)
     * @param buffer [OUT] Output buffer (must be at least LMS_LEAF_LEN(n) bytes)
     * @param I      [IN]  Tree identifier (16 bytes)
     * @param r      [IN]  Node index
     * @param pk     [IN]  OTS public key (n bytes)
     * @param n      [IN]  Hash output length
     */
    void (*buildLeafInput)(uint8_t *buffer, const uint8_t *I, uint32_t r, const uint8_t *pk, uint32_t n);

    /**
     * Build internal node buffer (I || r || D || left || right)
     * @param buffer [OUT] Output buffer (must be at least LMS_INTR_LEN(n) bytes)
     * @param I      [IN]  Tree identifier (16 bytes)
     * @param r      [IN]  Node index
     * @param left   [IN]  Left child hash (n bytes)
     * @param right  [IN]  Right child hash (n bytes)
     * @param n      [IN]  Hash output length
     */
    void (*buildInternalInput)(uint8_t *buffer, const uint8_t *I, uint32_t r, const uint8_t *left, const uint8_t *right,
                               uint32_t n);

    /**
     * Build message hash buffer (I || q || D || C)
     * @param buffer [OUT] Output buffer (must be at least LMS_MESG_PREFIX_LEN(n) bytes)
     * @param I      [IN]  Tree identifier (16 bytes)
     * @param q      [IN]  Leaf index
     * @param C      [IN]  Randomizer (n bytes)
     * @param n      [IN]  Hash output length
     */
    void (*buildMsgInput)(uint8_t *buffer, const uint8_t *I, uint32_t q, const uint8_t *C, uint32_t n);

    /**
     * Build OTS public key buffer (I || q || D || chains)
     * @param buffer [OUT] Output buffer (must be at least LMS_PBLC_PREFIX_LEN + p*n bytes)
     * @param I      [IN]  Tree identifier (16 bytes)
     * @param q      [IN]  Leaf index
     * @param chains [IN]  Chain values (p * n bytes)
     * @param p      [IN]  Number of chains
     * @param n      [IN]  Hash output length
     */
    void (*buildOtsPubKeyInput)(uint8_t *buffer, const uint8_t *I, uint32_t q, const uint8_t *chains, uint32_t p,
                                uint32_t n);
};

/**
 * @ingroup lms_common
 * @brief LMS OTS Context
 *
 * Encapsulates parameters for LM-OTS operations, reducing parameter passing
 * and improving code organization. Analogous to XMSS XmssWotsCtx.
 */
struct LmsOtsCtx {
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    uint32_t q; /**< Leaf index */
    uint32_t n; /**< Hash output length */
    uint32_t w; /**< Winternitz parameter */
    uint32_t p; /**< Number of n-byte string elements */
    uint32_t ls; /**< Checksum left shift */
    const LmsFamilyHashFuncs *hashFuncs; /**< Hash function pointers */
    const LmsFamilyAdrsOps *adrsOps; /**< Address operations (optional, can be NULL) */
    void *seedDerive; /**< Seed derivation context (optional, opaque pointer) */
};

/**
 * @ingroup lms_common
 * @brief LMS Tree Context
 *
 * Encapsulates parameters for Merkle tree operations, enabling code reuse
 * and reducing parameter passing. Analogous to XMSS TreeCtx.
 */
struct LmsTreeCtx {
    const LMS_Para *para; /**< LMS parameters */
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    const uint8_t *seed; /**< Master seed (32 bytes) */
    uint32_t height; /**< Tree height */
    uint32_t n; /**< Hash output length */
    const LmsFamilyHashFuncs *hashFuncs; /**< Hash function pointers */
    const LmsFamilyAdrsOps *adrsOps; /**< Address operations (optional) */

    /* Tree caching support (for performance optimization) */
    uint8_t **cachedTree; /**< Pointer to cached tree array */
    size_t *cachedTreeSize; /**< Pointer to cached tree size */
    bool *treeCacheValid; /**< Pointer to cache validity flag */
};

/**
 * @ingroup lms_common
 * @brief Initialize LMS address operations
 *
 * Returns a pointer to the global LMS address operations table.
 * This table provides functions for building domain-separated hash inputs.
 *
 * @return Pointer to LmsAdrsOps structure (never NULL)
 */
const LmsFamilyAdrsOps *LmsAdrsOps_Init(void);

/**
 * @ingroup lms_common
 * @brief Initialize LMS tree context
 *
 * @param ctx       [OUT] Tree context to initialize
 * @param para      [IN]  LMS parameters
 * @param I         [IN]  Tree identifier (16 bytes)
 * @param seed      [IN]  Master seed (32 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsTree_InitContext(LmsTreeCtx *ctx, const LMS_Para *para, const uint8_t *I, const uint8_t *seed);

/**
 * @ingroup lms_common
 * @brief Set tree cache in tree context
 *
 * Enables tree caching optimization for repeated operations.
 *
 * @param ctx            [IN/OUT] Tree context
 * @param cachedTree     [IN]     Pointer to cached tree pointer
 * @param cachedTreeSize [IN]     Pointer to cached tree size
 * @param treeCacheValid [IN]     Pointer to cache validity flag
 */
void LmsTree_SetCache(LmsTreeCtx *ctx, uint8_t **cachedTree, size_t *cachedTreeSize, bool *treeCacheValid);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_LMS */
#endif /* LMS_COMMON_H */
