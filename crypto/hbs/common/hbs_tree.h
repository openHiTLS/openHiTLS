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

#ifndef HBS_TREE_H
#define HBS_TREE_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>
#include "hbs_common.h"
#include "hbs_wots.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hbs
 * @brief Compute an internal tree node (recursive)
 */
int32_t HbsTree_ComputeNode(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const HbsTreeCtx *ctx,
                            uint8_t *authPath, uint32_t leafIdx);

/**
 * @ingroup hbs
 * @brief Generate a single-layer tree signature (WOTS+ sig + auth path)
 */
int32_t HbsTree_Sign(const uint8_t *msg, uint32_t msgLen, uint32_t idx, void *adrs, const HbsTreeCtx *ctx, uint8_t *sig,
                     uint32_t *sigLen, uint8_t *root);

/**
 * @ingroup hbs
 * @brief Verify a single-layer tree signature and compute the root
 */
int32_t HbsTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint32_t idx,
                       void *adrs, const HbsTreeCtx *ctx, uint8_t *pk);

/**
 * @ingroup hbs
 * @brief Verify a hypertree signature (multi-layer)
 */
int32_t HbsHyperTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                            uint32_t leafIdx, const HbsTreeCtx *ctx);

/**
 * @ingroup hbs
 * @brief Generate a hypertree signature (multi-layer)
 */
int32_t HbsHyperTree_Sign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx,
                          const HbsTreeCtx *ctx, uint8_t *sig, uint32_t *sigLen);

/* -----------------------------------------------------------------------
 * Unified tree context initializers (canonical names per design §3.6)
 *
 * Each initializer is declared in its own module header alongside the
 * implementation, since they depend on algorithm-specific context types:
 *   HbsTreeCtx_InitForXmss    -> xmss/src/xmss_local.h
 *   HbsTreeCtx_InitForXmssmt  -> xmss/src/xmss_local.h
 *   HbsTreeCtx_InitFromSlhDsa -> slh_dsa/src/slh_dsa_local.h
 *   HbsTreeCtx_InitFromHss    -> hss/src/hss_tree.h
 * ----------------------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_XMSSMT || HITLS_CRYPTO_SLH_DSA */
#endif /* HBS_TREE_H */
