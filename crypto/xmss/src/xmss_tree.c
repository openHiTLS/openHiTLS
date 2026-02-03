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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_XMSS

#include <stdint.h>
#include <stddef.h>
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "xmss_params.h"
#include "xmss_tree.h"
#include "xmss_wots.h"

static void BuildWotsCtxFromTreeCtx(XmssWotsCtx *wotsCtx, const TreeCtx *treeCtx)
{
    wotsCtx->coreCtx = treeCtx->originalCtx;
    wotsCtx->n = treeCtx->n;
    wotsCtx->wotsLen = treeCtx->wotsLen;
    wotsCtx->hashFuncs = treeCtx->hashFuncs;
    wotsCtx->adrsOps = treeCtx->adrsOps;
    wotsCtx->pubSeed = treeCtx->pubSeed;
    wotsCtx->skSeed = treeCtx->skSeed;
    wotsCtx->isXmss = treeCtx->isXmss;
}

/*
 * Recursively compute a node in the XMSS Merkle tree and collect authentication path
 *
 * This is the core tree computation function that builds the Merkle tree from bottom (leaves)
 * to top (root) using post-order traversal. It serves two purposes:
 * 1. Compute the hash value of a specific node at a given height and index
 * 2. Collect sibling nodes along the authentication path for signature generation
 *
 * Tree Structure
 * - Height 0: Leaf nodes (WOTS+ public keys compressed via L-tree)
 * - Height 1..hp-1: Internal nodes (hashes of child pairs)
 * - Height hp: Root node (final tree root)
 *
 * Authentication Path Collection:
 * When authPath is non-NULL and leafIdx is specified, this function collects the sibling
 * nodes required to verify a signature at leaf index leafIdx. For each height h (0 to hp-1),
 * it saves the sibling of the node on the path from leafIdx to root.
 *
 * Index Calculation:
 * - At each height h, the sibling of node at position (leafIdx >> h) is at position
 *   (leafIdx >> h) XOR 1, which is computed as ((leafIdx >> h) ^ 0x01)
 * - During recursion, we compute node at index 'idx', and check if it's the sibling
 *
 * @param node     [out]    Output buffer for the computed node hash (n bytes)
 * @param idx      [in]     Node index at current height (0-based, left-to-right)
 * @param height   [in]     Height in tree (0=leaf, hp=root)
 * @param adrs     [in]     Base XMSS address (layer and tree address pre-set by caller)
 * @param ctx      [in]     Tree context with parameters, hash functions, and seeds
 * @param authPath [out]    Buffer to store authentication path nodes (hp * n bytes), or NULL
 * @param leafIdx  [in]     Leaf index for which to collect authentication path (ignored if authPath is NULL)
 *
 * @return CRYPT_SUCCESS on success
 *         CRYPT_NULL_INPUT if required parameters are NULL
 *         Other error codes on hash or WOTS+ operation failure
 */
int32_t XmssTree_ComputeNode(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const TreeCtx *ctx,
                             uint8_t *authPath, uint32_t leafIdx)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;

    if (node == NULL || adrs == NULL || ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Base case: height is 0, compute WOTS+ public key (leaf node)
     * Each leaf is the L-tree compression of a WOTS+ public key */
    if (height == 0) {
        uint8_t adrsBuffer[MAX_ADRS_SIZE] = {0};
        void *leafAdrs = adrsBuffer;
        (void)memcpy_s(leafAdrs, sizeof(adrsBuffer), adrs, sizeof(adrsBuffer));

        ctx->adrsOps->setType(leafAdrs, XMSS_ADRS_TYPE_OTS);
        ctx->adrsOps->setKeyPairAddr(leafAdrs, idx); /* Set OTS key pair index */

        /* Create WOTS+ context for leaf computation */
        XmssWotsCtx wotsCtx;
        BuildWotsCtxFromTreeCtx(&wotsCtx, ctx);

        /* Generate WOTS+ public key (internally applies L-tree compression) */
        ret = XmssWots_GeneratePublicKey(node, leafAdrs, &wotsCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        /* Check if this leaf is the sibling of the target leaf in authentication path
         * At height 0, sibling of leafIdx is at index (leafIdx ^ 1) */
        if (authPath && (idx == ((leafIdx >> height) ^ 0x01))) {
            (void)memcpy_s(authPath + (height * n), n, node, n);
        }
        return CRYPT_SUCCESS;
    }

    /* Recursive case: compute internal node by hashing its two children
     * Binary tree: node[idx] at height h has children:
     *   - Left child:  node[2*idx] at height h-1
     *   - Right child: node[2*idx+1] at height h-1 */
    uint8_t leftNode[XMSS_MAX_MDSIZE] = {0};
    uint8_t rightNode[XMSS_MAX_MDSIZE] = {0};

    /* Recursively compute left child (index = 2*idx at height-1) */
    ret = XmssTree_ComputeNode(leftNode, 2 * idx, height - 1, adrs, ctx, authPath, leafIdx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Recursively compute right child (index = 2*idx+1 at height-1) */
    ret = XmssTree_ComputeNode(rightNode, 2 * idx + 1, height - 1, adrs, ctx, authPath, leafIdx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Hash children to get parent node
    uint8_t adrsBuffer[MAX_ADRS_SIZE] = {0};
    void *treeAdrs = adrsBuffer;
    (void)memcpy_s(treeAdrs, sizeof(adrsBuffer), adrs, sizeof(adrsBuffer));

    ctx->adrsOps->setType(treeAdrs, XMSS_ADRS_TYPE_HASH); // slh-dsa is also tree of value 2
    if (ctx->isXmss) {
        ctx->adrsOps->setTreeHeight(treeAdrs, height - 1);
    } else {
        ctx->adrsOps->setTreeHeight(treeAdrs, height);
    }
    ctx->adrsOps->setTreeIndex(treeAdrs, idx);
    uint8_t tmp[XMSS_MAX_MDSIZE * 2];
    (void)memcpy_s(tmp, XMSS_MAX_MDSIZE * 2, leftNode, n);
    (void)memcpy_s(tmp + n, XMSS_MAX_MDSIZE * 2 - n, rightNode, n);

    ret = ctx->hashFuncs->h(ctx->originalCtx, treeAdrs, tmp, 2 * n, node);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Save this node to authentication path if it's the sibling of the path node
     * Skip saving at height hp (root level has no sibling)
     * At height h, the node on the path from leafIdx to root is at index (leafIdx >> h),
     * so its sibling is at index ((leafIdx >> h) ^ 1) */
    if ((height != hp) && authPath && (idx == ((leafIdx >> height) ^ 0x01))) {
        (void)memcpy_s(authPath + (height * n), n, node, n);
    }

    return CRYPT_SUCCESS;
}

/*
 * Generate XMSS tree signature for a single layer
 *
 * This function generates a signature for one layer of the XMSS/XMSSMT tree structure.
 * The signature consists of two parts:
 * 1. WOTS+ signature (wotsLen * n bytes)
 * 2. Authentication path (hp * n bytes)
 *
 * Note: This function handles only the tree-layer signature, not the complete XMSS signature.
 * The complete XMSS/XMSSMT signature structure (assembled in XmssCore_Sign) is:
 * - XMSS (d=1):   sig = idx (4 bytes) || R (n bytes) || WOTS+sig || auth_path
 * - XMSSMT (d>1): sig = idx ((h+7)/8 bytes) || R (n bytes) || d layers of (WOTS+sig || auth_path)
 *
 * @param msg      [in]     Message digest to sign (typically n bytes from H_msg or previous layer root)
 * @param msgLen   [in]     Length of message digest
 * @param idx      [in]     Leaf index in this tree layer
 * @param adrs     [in]     XMSS address structure (layer and tree address should be pre-set)
 * @param ctx      [in]     Tree context containing parameters, hash functions, and seeds
 * @param sig      [out]    Buffer to store tree signature (WOTS+ sig || authentication path)
 * @param sigLen   [in/out] Input: buffer size; Output: actual signature length
 * @param root     [out]    Computed tree root (n bytes)
 *
 * @return CRYPT_SUCCESS on success
 *         CRYPT_BN_BUFF_LEN_NOT_ENOUGH if buffer is too small
 *         Other error codes on failure
 */
int32_t XmssTree_Sign(const uint8_t *msg, uint32_t msgLen, uint32_t idx, void *adrs, const TreeCtx *ctx, uint8_t *sig,
                      uint32_t *sigLen, uint8_t *root)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t len = ctx->wotsLen;

    /* Check buffer size: need space for WOTS+ signature (len*n) + authentication path (hp*n) */
    if (*sigLen < (len + hp) * n) {
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }

    /* Generate WOTS+ signature on the message digest
     * Output: sig[0 .. len*n-1] contains WOTS+ signature */
    /* Make a copy of the address to avoid modifying the original */
    uint8_t adrsBuffer[MAX_ADRS_SIZE] = {0};
    void *wotsAdrs = adrsBuffer;
    (void)memcpy_s(wotsAdrs, sizeof(adrsBuffer), adrs, sizeof(adrsBuffer));

    ctx->adrsOps->setType(wotsAdrs, XMSS_ADRS_TYPE_OTS); // for slh-dsa case, WOTS_HASH is also 0
    ctx->adrsOps->setKeyPairAddr(wotsAdrs, idx);

    uint32_t wotsSigLen = len * n;
    XmssWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, ctx);
    ret = XmssWots_Sign(sig, &wotsSigLen, msg, msgLen, wotsAdrs, &wotsCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Compute tree root and collect authentication path
     * - root: output parameter receiving the computed tree root
     * - sig + (len * n): authentication path written to sig[len*n .. (len+hp)*n-1]
     * - idx: leaf index to compute authentication path for
     *
     * The ComputeNode function recursively builds the tree from leaves to root,
     * and collects sibling nodes along the path from leaf[idx] to root */
    ret = XmssTree_ComputeNode(root, 0, hp, adrs, ctx, sig + (len * n), idx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Set actual signature length: WOTS+ signature + authentication path */
    *sigLen = (len + hp) * n;
    return CRYPT_SUCCESS;
}

/*
 * Verify XMSS tree signature for a single layer, compute pk from sig
 *
 * This function verifies a tree-layer signature by reconstructing the tree root from:
 * 1. The WOTS+ signature (used to recover the WOTS+ public key / leaf node)
 * 2. The authentication path (sibling nodes from leaf to root)
 *
 * Verification Process
 * Step 1: Recover the WOTS+ public key (leaf node) from the WOTS+ signature and message
 * Step 2: Use the authentication path to compute the tree root:
 *         - Start with the recovered leaf node
 *         - For each level from 0 to hp-1, hash current node with its sibling from auth path
 *         - The sibling position (left or right) is determined by the leaf index bits
 * Step 3: Compare the computed root with the expected public key (passed by caller)
 *
 * Authentication Path Usage:
 * The authentication path contains hp sibling nodes (one per tree level).
 * At level k (0 ≤ k < hp):
 * - If bit k of idx is 0: current node is left child, sibling is right child
 * - If bit k of idx is 1: current node is right child, sibling is left child
 * - Hash: parent = H(left_child || right_child)
 *
 * @param msg      [in]  Message digest that was signed (n bytes)
 * @param msgLen   [in]  Length of message digest
 * @param sig      [in]  Tree signature buffer (WOTS+ sig || authentication path)
 * @param sigLen   [in]  Length of signature buffer
 * @param idx      [in]  Leaf index that was used for signing
 * @param adrs     [in]  address structure (layer and tree address pre-set by caller)
 * @param ctx      [in]  Tree context with parameters, hash functions, and public seed
 * @param pk       [out] Computed tree root (n bytes), to be compared with expected root
 *
 * @return CRYPT_SUCCESS on success (note: caller must compare pk with expected root)
 *         CRYPT_XMSS_ERR_INVALID_SIG_LEN if signature is too short
 *         Other error codes on WOTS+ or hash operation failure
 */
int32_t XmssTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint32_t idx,
                        void *adrs, const TreeCtx *ctx, uint8_t *pk)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t len = ctx->wotsLen;

    /* Check signature length: must contain WOTS+ sig (len*n) + auth path (hp*n) */
    if (sigLen < (len + hp) * n) {
        return ctx->isXmss ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }

    /* Step 1: Recover WOTS+ public key (leaf node) from signature
     * Input:  msg (message digest), sig[0..len*n-1] (WOTS+ signature)
     * Output: node0 (recovered WOTS+ public key = leaf node) */
    uint8_t wotsAdrsBuffer[MAX_ADRS_SIZE];
    void *wotsAdrs = wotsAdrsBuffer;
    (void)memcpy_s(wotsAdrs, sizeof(wotsAdrsBuffer), adrs, sizeof(wotsAdrsBuffer));

    ctx->adrsOps->setType(wotsAdrs, XMSS_ADRS_TYPE_OTS);
    ctx->adrsOps->setKeyPairAddr(wotsAdrs, idx);

    uint8_t node0[XMSS_MAX_MDSIZE] = {0};
    uint8_t node1[XMSS_MAX_MDSIZE] = {0};
    XmssWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, ctx);
    ret = XmssWots_PkFromSig(msg, msgLen, sig, len * n, wotsAdrs, &wotsCtx, node0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Step 2: Compute tree root from leaf node using authentication path
     * The authentication path contains hp sibling nodes: sig[len*n + k*n] for k=0..hp-1
     * We climb from leaf (height 0) to root (height hp-1) */
    ctx->adrsOps->setType(adrs, XMSS_ADRS_TYPE_HASH); // slh-dsa TREE type is also 2
    ctx->adrsOps->setTreeIndex(adrs, idx); // Set tree index before climbing
    for (uint32_t k = 0; k < hp; k++) {
        if (ctx->isXmss) {
            ctx->adrsOps->setTreeHeight(adrs, k);
        } else {
            ctx->adrsOps->setTreeHeight(adrs, k + 1);
        }
        /* Determine hash order based on whether current node is left or right child
         * Bit k of idx determines the position:
         * - If bit k is 0: node0 is left child, sibling (from auth path) is right child
         * - If bit k is 1: node0 is right child, sibling (from auth path) is left child */
        uint8_t tmp[XMSS_MAX_MDSIZE * 2];
        if (((idx >> k) & 1) != 0) {
            /* Current node is right child: hash(sibling || node0) */
            (void)memcpy_s(tmp, sizeof(tmp), sig + (len + k) * n, n); /* Left: sibling from auth path */
            (void)memcpy_s(tmp + n, sizeof(tmp) - n, node0, n); /* Right: current node */
            ctx->adrsOps->setTreeIndex(adrs, (ctx->adrsOps->getTreeIndex(adrs) - 1) >> 1);
        } else {
            /* Current node is left child: hash(node0 || sibling) */
            (void)memcpy_s(tmp, sizeof(tmp), node0, n); /* Left: current node */
            (void)memcpy_s(tmp + n, sizeof(tmp) - n, sig + (len + k) * n, n); /* Right: sibling from auth path */
            ctx->adrsOps->setTreeIndex(adrs, ctx->adrsOps->getTreeIndex(adrs) >> 1);
        }

        /* Compute parent node: node1 = H(SEED, ADRS, left || right) */
        ret = ctx->hashFuncs->h(ctx->originalCtx, adrs, tmp, 2 * n, node1);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        /* Move up one level: the computed parent becomes the current node for next iteration */
        (void)memcpy_s(node0, sizeof(node0), node1, sizeof(node1));
    }

    /* Step 3: Output the computed root
     * Caller must compare this with the expected root from public key */
    (void)memcpy_s(pk, n, node0, n);
    return CRYPT_SUCCESS;
}

int32_t HyperTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                         uint32_t leafIdx, const TreeCtx *ctx)
{
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t d = ctx->d;
    uint32_t wotsLen = ctx->wotsLen;
    const uint8_t *root = ctx->root;
    /* Calculate expected signature length for a single layer */
    uint32_t expectedLayerSigLen = (wotsLen + hp) * n;
    if (sigLen < expectedLayerSigLen * d) {
        return ctx->isXmss ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }
    const uint8_t *sigPtr = sig;
    uint8_t node[XMSS_MAX_MDSIZE] = {0};
    (void)memcpy_s(node, sizeof(node), msg, msgLen);
    uint64_t treeIdxTmp = treeIdx;
    uint32_t leafIdxTmp = leafIdx;

    /* Initialize address buffer once and reuse across layers */
    uint8_t adrsBuffer[MAX_ADRS_SIZE] = {0};
    void *verifyAdrs = adrsBuffer;
    for (uint32_t layer = 0; layer < d; layer++) {
        /* For layer > 0, extract indices from treeIdx */
        if (layer != 0) {
            leafIdxTmp = (uint32_t)(treeIdxTmp & ((1UL << hp) - 1));
            treeIdxTmp = treeIdxTmp >> hp;
            ctx->adrsOps->setLayerAddr(verifyAdrs, layer);
        }
        ctx->adrsOps->setTreeAddr(verifyAdrs, treeIdxTmp);
        int32_t ret = XmssTree_Verify(node, n, sigPtr, expectedLayerSigLen, leafIdxTmp, verifyAdrs, ctx, node);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        /* Move to next layer's signature */
        sigPtr += expectedLayerSigLen;
    }
    if (memcmp(node, root, n) != 0) {
        return ctx->isXmss ? CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH : CRYPT_SLHDSA_ERR_HYPERTREE_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t HyperTree_Sign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx, const TreeCtx *ctx,
                       uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t d = ctx->d;
    uint32_t wotsLen = ctx->wotsLen;
    uint8_t *sigPtr = sig;
    uint32_t offset = 0;
    if (*sigLen < (wotsLen + hp) * n * d) {
        return ctx->isXmss ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }
    uint8_t root[XMSS_MAX_MDSIZE] = {0};
    (void)memcpy_s(root, n, msg, msgLen);
    const uint8_t *currentMsg = root;
    for (uint32_t j = 0; j < d; j++) {
        /* Create a fresh address buffer for each iteration to avoid corruption */
        uint8_t adrsBuffer[MAX_ADRS_SIZE] = {0};
        void *signAdrs = adrsBuffer;

        /* Only set layer address for j > 0 */
        if (j != 0) {
            leafIdx = (uint32_t)(treeIdx & (((uint64_t)1 << hp) - 1));
            treeIdx = treeIdx >> hp;
            ctx->adrsOps->setLayerAddr(signAdrs, j);
        }

        ctx->adrsOps->setTreeAddr(signAdrs, treeIdx);

        uint32_t layerSigLen = wotsLen * n + hp * n;

        /* XmssTree_Sign result stored in root (n bytes) and signature (layerSigLen bytes) */
        ret = XmssTree_Sign(currentMsg, n, leafIdx, signAdrs, ctx, sigPtr, &layerSigLen, root);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        /* Move to next layer's signature */
        sigPtr += layerSigLen;
        offset += layerSigLen;

        /* Use computed root as message for next layer */
        currentMsg = root;
    }
    *sigLen = offset;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_XMSS
