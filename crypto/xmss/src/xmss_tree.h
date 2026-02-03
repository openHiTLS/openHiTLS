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

#ifndef XMSS_TREE_H
#define XMSS_TREE_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>
#include "xmss_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic Tree Context
 * This structure encapsulates the parameters needed for tree operations
 * Used by both XMSS and SLH-DSA for common tree operations
 */
typedef struct {
    /* Algorithm parameters */
    uint32_t n; // Hash output length
    uint32_t hp; // Tree height per layer
    uint32_t d; // Number of layers
    uint32_t wotsLen; // WOTS+ chain length

    /* Key material */
    const uint8_t *pubSeed; // Public seed
    const uint8_t *skSeed; // Private seed
    const uint8_t *root; // Tree root (used for verification)

    /* Generic hash function table */
    const CryptHashFuncs *hashFuncs;

    /* Generic address operation table */
    const CryptAdrsOps *adrsOps;

    /* Original context (for hash function callbacks) */
    void *originalCtx;
    bool isXmss;
} TreeCtx;

/*
 * Compute an internal tree node
 *
 * Recursively computes a node in the XMSS Merkle tree.
 * - If height == 0: computes WOTS+ public key (leaf node)
 * - Otherwise: recursively computes children and hashes them
 *
 * @param node      Output node (n bytes)
 * @param idx       Node index at the given height
 * @param height    Node height in the tree (0 = leaf)
 * @param adrs      Address for domain separation
 * @param ctx       Tree context
 * @param authPath  Output authentication path (optional, can be NULL)
 * @param leafIdx   Leaf index for which to build auth path
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssTree_ComputeNode(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const TreeCtx *ctx,
                             uint8_t *authPath, uint32_t leafIdx);

/*
 * Generate XMSS signature
 *
 * Generates a WOTS+ signature plus authentication path for a message.
 *
 * @param msg      Message to sign (n bytes - already hashed)
 * @param msgLen   Length of message (must be n)
 * @param idx      Leaf index to sign
 * @param adrs     Address for domain separation (void* for polymorphism)
 * @param ctx      Tree context
 * @param sig      Output signature (WOTS+ sig + auth path)
 * @param sigLen   Input: buffer size, Output: actual signature length
 * @param root     Output tree root (n bytes)
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssTree_Sign(const uint8_t *msg, uint32_t msgLen, uint32_t idx, void *adrs, const TreeCtx *ctx, uint8_t *sig,
                      uint32_t *sigLen, uint8_t *root);

/*
 * Compute public key from XMSS signature
 *
 * Verifies an XMSS signature and computes the resulting tree root.
 *
 * @param msg      Message that was signed (n bytes)
 * @param msgLen   Length of message (must be n)
 * @param sig      XMSS signature (WOTS+ sig + auth path)
 * @param sigLen   Length of signature
 * @param idx      Leaf index that was signed
 * @param adrs     Address for domain separation (void* for polymorphism)
 * @param ctx      Tree context
 * @param pk       Output public key / tree root (n bytes)
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t XmssTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint32_t idx,
                        void *adrs, const TreeCtx *ctx, uint8_t *pk);

/*
 * Verify XMSS Hypertree signature (internal)
 *
 * Verifies a hypertree signature by iterating through all layers.
 * For XMSS (d=1), this is just a single tree verification.
 * For XMSSMT or SLH-DSA (d>1), this traverses the multi-layer tree structure.
 *
 * Execution flow:
 * 1. Validates input parameters and signature length
 * 2. Iterates through each layer (0 to d-1):
 *    a. For layer > 0: extract tree and leaf indices from treeIdx
 *    b. Set layer address and tree address in ADRS
 *    c. Verify current layer using XmssTree_Verify
 *    d. Use computed root as message for next layer
 * 3. Compare final computed root with ctx->root
 *
 * @param msg        Message digest to verify (n bytes)
 * @param msgLen     Length of message (n bytes)
 * @param sig        Signature buffer (contains auth paths for all layers)
 * @param sigLen     Length of signature
 * @param treeIdx    Tree index (for layer > 0)
 * @param leafIdx    Leaf index in the current layer
 * @param ctx        Tree context (contains expected root in ctx->root)
 *
 * @return CRYPT_SUCCESS on success
 *         CRYPT_XMSS_ERR_VERIFY_FAIL on verification failure
 */
int32_t HyperTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                         uint32_t leafIdx, const TreeCtx *ctx);

/*
 * Sign using XMSS Hypertree (internal)
 *
 * Generates a signature for a hypertree structure by iterating through all layers.
 * For XMSS (d=1), this is just a single tree signature.
 * For XMSSMT (d>1), this traverses the multi-layer tree structure.
 *
 * This function encapsulates the multi-layer signing logic that is common
 * to both XMSS and XMSSMT, making the code more maintainable and reusable.
 *
 * Execution flow:
 * 1. Validates input parameters
 * 2. Iterates through each layer (0 to d-1):
 *    a. For layer > 0: extract tree and leaf indices from treeIdx
 *    b. Set layer address and tree address in ADRS
 *    c. Sign current layer using XmssTree_Sign
 *    d. Use computed root as message for next layer
 * 3. Returns the final signature containing all layer signatures
 *
 * @param msg        Message digest to sign (n bytes)
 * @param msgLen     Length of message (n bytes)
 * @param treeIdx    Tree index (for layer > 0)
 * @param leafIdx    Leaf index in the current layer
 * @param ctx        Tree context (generic, works with both XMSS and SLH-DSA)
 * @param sig        Output signature buffer
 * @param sigLen     Input: buffer size, Output: actual signature length
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t HyperTree_Sign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx, const TreeCtx *ctx,
                       uint8_t *sig, uint32_t *sigLen);
#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_XMSS || HITLS_CRYPTO_SLH_DSA
#endif // XMSS_TREE_H
