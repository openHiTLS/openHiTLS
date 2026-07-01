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
#ifdef HITLS_CRYPTO_HSS_LMS

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

    /* Tree caching support (for performance optimization) */
    uint8_t **cachedTree; /**< Pointer to cached tree array */
    size_t *cachedTreeSize; /**< Pointer to cached tree size */
    bool *treeCacheValid; /**< Pointer to cache validity flag */
};

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
int32_t LmsTreeInitContext(LmsTreeCtx *ctx, const LMS_Para *para, const uint8_t *I, const uint8_t *seed);

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
void LmsTreeSetCache(LmsTreeCtx *ctx, uint8_t **cachedTree, size_t *cachedTreeSize, bool *treeCacheValid);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* LMS_COMMON_H */
