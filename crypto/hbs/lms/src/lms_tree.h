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

#ifndef LMS_TREE_H
#define LMS_TREE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_HSS_LMS

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "lms_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup lms_tree LMS Tree Operations
 * @brief Merkle tree operations for LMS
 *
 * This module provides tree operations following the XMSS pattern:
 * - Context-based tree operations
 * - Tree node computation
 * - Authentication path generation
 * - Tree caching support
 */

/**
 * @ingroup lms_tree
 * @brief Compute Merkle tree root hash
 *
 * Computes the root hash of the entire Merkle tree.
 * This is used during key generation.
 *
 * @param root [OUT] Output root hash (n bytes)
 * @param ctx  [IN]  Tree context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsTreeComputeRoot(uint8_t *root, const LmsTreeCtx *ctx);

/**
 * @ingroup lms_tree
 * @brief Generate authentication path for leaf node
 *
 * Generates the authentication path (sibling hashes) needed to verify
 * a signature for the given leaf index.
 *
 * @param authPath [OUT] Output authentication path (h * n bytes)
 * @param ctx      [IN]  Tree context
 * @param q        [IN]  Leaf index
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsTreeGenerateAuthPath(uint8_t *authPath, const LmsTreeCtx *ctx, uint32_t q);

/**
 * @ingroup lms_tree
 * @brief Generate authentication path with tree caching
 *
 * Generates the authentication path using a cached tree if available.
 * This significantly improves performance for repeated signing operations.
 *
 * The cache must be set in the context using LmsTreeSetCache() before calling.
 *
 * @param authPath [OUT] Output authentication path (h * n bytes)
 * @param ctx      [IN]  Tree context (with cache configured)
 * @param q        [IN]  Leaf index
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmsTreeGenerateAuthPathCached(uint8_t *authPath, const LmsTreeCtx *ctx, uint32_t q);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_HSS_LMS */
#endif /* LMS_TREE_H */
