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

#ifndef HSS_TREE_H
#define HSS_TREE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS_LMS

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hbs_common.h"
#include "lms_internal.h"
#include "hss_local.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup hss_tree HSS Multi-Tree Operations
 * @brief Hierarchical tree management for HSS
 *
 * This module provides multi-tree operations for HSS (Hierarchical Signature System):
 * - Multi-level tree context management
 * - Signed public key generation (parent signs child)
 * - Tree index calculation
 * - Multi-tree signing and verification
 */

/**
 * @ingroup hss_tree
 * @brief HSS Multi-Tree Context
 *
 * Manages the hierarchical structure of multiple LMS trees.
 * Stores actual I and seed data for each level to avoid pointer lifetime issues.
 *
 * Design note (HBS refactoring §6.4):
 *   lmsTrees[i]  — per-level LMS-specific storage (LmsTreeCtx) that holds cache
 *                  pointers and LMS hash/adrs-ops. trees[i].originalCtx points
 *                  here so hbs_tree.c can reach LMS internals via the unified
 *                  HbsTreeCtx interface.  This is the legitimate internal boundary
 *                  between HSS and LMS; hss_local.h includes lms_internal.h
 *                  (not lms_local.h) to keep the boundary explicit.
 *   trees[i]     — unified HBS tree context (algoType=HBS_ALGO_LMS, adrsOps=NULL,
 *                  hashFuncs.lms from levelPara, originalCtx=&lmsTrees[i]).
 *                  Used by the common hbs_tree.c layer.
 */
typedef struct {
    uint32_t levels; /**< Number of levels in hierarchy */
    uint64_t globalIndex; /**< Global signature index */
    uint64_t treeIndices[HSS_LEVELS_ARRAY_SIZE]; /**< Tree index at each level */
    uint32_t leafIndices[HSS_LEVELS_ARRAY_SIZE]; /**< Leaf index at each level */
    const HSS_Para *para; /**< HSS parameters */

    /* Actual data storage for each level */
    uint8_t levelI[HSS_LEVELS_ARRAY_SIZE][LMS_I_LEN]; /**< Tree identifiers */
    uint8_t levelSeed[HSS_LEVELS_ARRAY_SIZE][LMS_SEED_LEN]; /**< Tree seeds */

    /* Per-level LMS tree contexts: serve as the originalCtx targets for trees[].
     * They also carry the tree-cache pointers used by HssTreeSign.
     * Access via lms_internal.h boundary (not lms_local.h). */
    LmsTreeCtx lmsTrees[HSS_LEVELS_ARRAY_SIZE]; /**< LMS tree contexts (originalCtx targets) */
} HssMultiTreeCtx;

/**
 * @ingroup hss_tree
 * @brief Initialize HSS multi-tree context
 *
 * @param ctx          [OUT] Multi-tree context to initialize
 * @param para         [IN]  HSS parameters
 * @param globalIndex  [IN]  Global signature index
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssTreeInitContext(HssMultiTreeCtx *ctx, const HSS_Para *para, uint64_t globalIndex);

/**
 * @ingroup hss_tree
 * @brief Initialize HSS multi-tree context with seeds
 *
 * Initializes the context and generates all level seeds from the master seed.
 *
 * @param ctx          [OUT] Multi-tree context to initialize
 * @param para         [IN]  HSS parameters
 * @param masterSeed   [IN]  Master seed (32 bytes)
 * @param globalIndex  [IN]  Global signature index
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssTreeInitContextWithSeeds(HssMultiTreeCtx *ctx, const HSS_Para *para, const uint8_t masterSeed[LMS_SEED_LEN],
    uint64_t globalIndex);

/**
 * @ingroup hss_tree
 * @brief Calculate tree and leaf indices from global index
 *
 * Decomposes the global signature index into per-level tree and leaf indices.
 *
 * @param treeIndices [OUT] Tree indices for each level
 * @param leafIndices [OUT] Leaf indices for each level
 * @param globalIndex [IN]  Global signature index
 * @param para        [IN]  HSS parameters
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssTreeCalculateIndices(uint64_t treeIndices[HSS_LEVELS_ARRAY_SIZE],
    uint32_t leafIndices[HSS_LEVELS_ARRAY_SIZE], uint64_t globalIndex, const HSS_Para *para);

/**
 * @ingroup hss_tree
 * @brief Generate signed public key (parent signs child)
 *
 * Creates a signed public key where the parent tree signs the child tree's public key.
 * This is used to link levels in the HSS hierarchy.
 *
 * @param output  [OUT]    Output buffer for signed public key
 * @param signCtx [IN]     Signing context
 * @param parent  [IN]     Parent tree context
 * @param child   [IN]     Child tree context
 * @param cache   [IN/OUT] Tree cache for parent level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssTreeGenerateSignedPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx,
    const HssTreeContext *parent, const HssTreeContext *child, LMS_TreeCache *cache);

/**
 * @ingroup hss_tree
 * @brief Sign message with HSS multi-tree
 *
 * Generates a complete HSS signature including all signed public keys and the bottom-level signature.
 *
 * @param signature    [OUT]    Output signature buffer
 * @param signatureLen [IN/OUT] In: buffer size, Out: actual signature length
 * @param message      [IN]     Message to sign
 * @param messageLen   [IN]     Message length
 * @param ctx          [IN]     Multi-tree context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssTreeSign(uint8_t *signature, size_t *signatureLen, const uint8_t *message, size_t messageLen,
    const HssMultiTreeCtx *ctx);

/**
 * @ingroup hss_tree
 * @brief Verify HSS signature
 *
 * Verifies an HSS signature by validating all signed public keys and the bottom-level signature.
 *
 * @param para         [IN] HSS parameters
 * @param publicKey    [IN] Public key (60 bytes)
 * @param message      [IN] Message that was signed
 * @param messageLen   [IN] Message length
 * @param signature    [IN] Signature to verify
 * @param signatureLen [IN] Signature length
 * @return CRYPT_SUCCESS if valid, error code otherwise
 */
int32_t HssTreeVerify(const HSS_Para *para, const uint8_t *publicKey, const uint8_t *message, size_t messageLen,
    const uint8_t *signature, size_t signatureLen);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* HSS_TREE_H */
