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
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_SLH_DSA)

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "hbs_address.h"
#include "hbs_common.h"
#include "hbs_tree.h"

/* HbsWots_* functions are declared in hbs_wots.h and implemented in hbs_wots.c */

/* Populate a WOTS+ context from the enclosing tree context. */
static void BuildWotsCtxFromTreeCtx(HbsWotsCtx *wotsCtx, const HbsTreeCtx *treeCtx)
{
    wotsCtx->coreCtx = treeCtx->originalCtx;
    wotsCtx->n = treeCtx->n;
    wotsCtx->otsLen = treeCtx->otsLen;
    wotsCtx->hashFuncs = treeCtx->hashFuncs.xmss;
    wotsCtx->adrsOps = treeCtx->adrsOps;
    wotsCtx->pubSeed = treeCtx->pubSeed;
    wotsCtx->skSeed = treeCtx->skSeed;
    wotsCtx->algoType = treeCtx->algoType;
}

/* Compute a leaf node: generate the WOTS+ public key for the given leaf index. */
static int32_t ComputeLeafNode(uint8_t *node, uint32_t idx, void *adrs, const HbsTreeCtx *ctx)
{
    uint8_t adrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *leafAdrs = adrsBuffer;
    memcpy(leafAdrs, adrs, sizeof(adrsBuffer));

    ctx->adrsOps->setType(leafAdrs, HBS_ADRS_TYPE_OTS);
    ctx->adrsOps->setKeyPairAddr(leafAdrs, idx);

    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, ctx);
    return HbsWots_GeneratePublicKey(node, leafAdrs, &wotsCtx);
}

/* Hash two child nodes into their parent internal node. */
static int32_t HashInternalNode(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const uint8_t *leftNode,
                                const uint8_t *rightNode, const HbsTreeCtx *ctx)
{
    uint32_t n = ctx->n;
    uint8_t adrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *treeAdrs = adrsBuffer;
    memcpy(treeAdrs, adrs, sizeof(adrsBuffer));

    ctx->adrsOps->setType(treeAdrs, HBS_ADRS_TYPE_HASH);
    /* XMSS uses height-1 for the tree-height field; SLH-DSA uses height */
    ctx->adrsOps->setTreeHeight(treeAdrs, HBS_IS_XMSS(ctx) ? (height - 1) : height);
    ctx->adrsOps->setTreeIndex(treeAdrs, idx);

    uint8_t tmp[HBS_MAX_MDSIZE * 2];
    memcpy(tmp, leftNode, n);
    memcpy(tmp + n, rightNode, n);

    return ctx->hashFuncs.xmss->nodeHash(ctx->originalCtx, treeAdrs, tmp, 2 * n, node);
}

/* Store the node into the authentication path if it is the sibling on the path to leafIdx. */
static void CollectAuthPathNode(uint8_t *authPath, uint32_t idx, uint32_t height, uint32_t hp, uint32_t leafIdx,
                                const uint8_t *node, uint32_t n)
{
    if (authPath == NULL || (height == hp)) {
        return;
    }
    if (idx == ((leafIdx >> height) ^ 0x01)) {
        memcpy(authPath + (height * n), node, n);
    }
}

/* Internal recursive worker — no input validation (already done by the public entry). */
static int32_t ComputeNodeRecursive(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const HbsTreeCtx *ctx,
                                    uint8_t *authPath, uint32_t leafIdx)
{
    int32_t ret;
    if (height == 0) {
        ret = ComputeLeafNode(node, idx, adrs, ctx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        CollectAuthPathNode(authPath, idx, 0, ctx->hp, leafIdx, node, ctx->n);
        return CRYPT_SUCCESS;
    }

    uint8_t leftNode[HBS_MAX_MDSIZE] = {0};
    uint8_t rightNode[HBS_MAX_MDSIZE] = {0};

    ret = ComputeNodeRecursive(leftNode, 2 * idx, height - 1, adrs, ctx, authPath, leafIdx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = ComputeNodeRecursive(rightNode, 2 * idx + 1, height - 1, adrs, ctx, authPath, leafIdx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HashInternalNode(node, idx, height, adrs, leftNode, rightNode, ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CollectAuthPathNode(authPath, idx, height, ctx->hp, leafIdx, node, ctx->n);
    return CRYPT_SUCCESS;
}

/* Compute the Merkle tree node at (idx, height).
 * If authPath is non-NULL, the sibling nodes along the path to leafIdx are stored in it. */
int32_t HbsTree_ComputeNode(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const HbsTreeCtx *ctx,
                            uint8_t *authPath, uint32_t leafIdx)
{
    if (ctx->hashFuncs.xmss == NULL || ctx->hashFuncs.xmss->nodeHash == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->n == 0 || ctx->n > HBS_MAX_MDSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    return ComputeNodeRecursive(node, idx, height, adrs, ctx, authPath, leafIdx);
}

/* Sign a message within a single Merkle tree layer.
 * Produces a WOTS+ signature and the authentication path; also returns the tree root. */
int32_t HbsTree_Sign(const uint8_t *msg, uint32_t msgLen, uint32_t idx, void *adrs, const HbsTreeCtx *ctx, uint8_t *sig,
                     uint32_t *sigLen, uint8_t *root)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t len = ctx->otsLen;

    if (*sigLen < (len + hp) * n) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_BN_BUFF_LEN_NOT_ENOUGH;
    }

    uint8_t adrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *wotsAdrs = adrsBuffer;
    memcpy(wotsAdrs, adrs, sizeof(adrsBuffer));

    ctx->adrsOps->setType(wotsAdrs, HBS_ADRS_TYPE_OTS);
    ctx->adrsOps->setKeyPairAddr(wotsAdrs, idx);

    uint32_t wotsSigLen = len * n;
    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, ctx);
    ret = HbsWots_Sign(sig, &wotsSigLen, msg, msgLen, wotsAdrs, &wotsCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HbsTree_ComputeNode(root, 0, hp, adrs, ctx, sig + (len * n), idx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *sigLen = (len + hp) * n;
    return CRYPT_SUCCESS;
}

/* Verify a single-layer Merkle tree signature.
 * Reconstructs the root from the WOTS+ signature and authentication path, writing it to pk. */
int32_t HbsTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint32_t idx,
                       void *adrs, const HbsTreeCtx *ctx, uint8_t *pk)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t len = ctx->otsLen;

    if (sigLen < (len + hp) * n) {
        int32_t err = HBS_IS_XMSS(ctx) ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
        BSL_ERR_PUSH_ERROR(err);
        return err;
    }

    uint8_t wotsAdrsBuffer[HBS_MAX_ADRS_SIZE];
    void *wotsAdrs = wotsAdrsBuffer;
    memcpy(wotsAdrs, adrs, sizeof(wotsAdrsBuffer));

    ctx->adrsOps->setType(wotsAdrs, HBS_ADRS_TYPE_OTS);
    ctx->adrsOps->setKeyPairAddr(wotsAdrs, idx);

    uint8_t node0[HBS_MAX_MDSIZE] = {0};
    HbsWotsCtx wotsCtx;
    BuildWotsCtxFromTreeCtx(&wotsCtx, ctx);
    ret = HbsWots_PkFromSig(msg, msgLen, sig, len * n, wotsAdrs, &wotsCtx, node0);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->adrsOps->setType(adrs, HBS_ADRS_TYPE_HASH);
    ctx->adrsOps->setTreeIndex(adrs, idx);
    for (uint32_t k = 0; k < hp; k++) {
        if (HBS_IS_XMSS(ctx)) {
            ctx->adrsOps->setTreeHeight(adrs, k);
        } else {
            ctx->adrsOps->setTreeHeight(adrs, k + 1);
        }

        uint8_t tmp[HBS_MAX_MDSIZE * 2];
        if (((idx >> k) & 1) != 0) {
            memcpy(tmp, sig + (len + k) * n, n);
            memcpy(tmp + n, node0, n);
            ctx->adrsOps->setTreeIndex(adrs, (ctx->adrsOps->getTreeIndex(adrs) - 1) >> 1);
        } else {
            memcpy(tmp, node0, n);
            memcpy(tmp + n, sig + (len + k) * n, n);
            ctx->adrsOps->setTreeIndex(adrs, ctx->adrsOps->getTreeIndex(adrs) >> 1);
        }

        uint8_t node1[HBS_MAX_MDSIZE] = {0};
        ret = ctx->hashFuncs.xmss->nodeHash(ctx->originalCtx, adrs, tmp, 2 * n, node1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        memcpy(node0, node1, sizeof(node1));
    }

    memcpy(pk, node0, n);
    return CRYPT_SUCCESS;
}

/* Verify a hyper-tree signature by walking through all d layers
 * and comparing the final reconstructed root against ctx->root. */
int32_t HbsHyperTree_Verify(const uint8_t *msg, uint32_t msgLen, const uint8_t *sig, uint32_t sigLen, uint64_t treeIdx,
                            uint32_t leafIdx, const HbsTreeCtx *ctx)
{
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t d = ctx->d;
    uint32_t otsLen = ctx->otsLen;
    const uint8_t *root = ctx->root;

    if (n == 0 || n > HBS_MAX_MDSIZE || msgLen > n || root == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    uint32_t layerSigLen = (otsLen + hp) * n;
    if (d == 0 || sigLen / d < layerSigLen) {
        int32_t err = HBS_IS_XMSS(ctx) ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
        BSL_ERR_PUSH_ERROR(err);
        return err;
    }

    const uint8_t *sigPtr = sig;
    uint8_t node[HBS_MAX_MDSIZE] = {0};
    memcpy(node, msg, msgLen);
    uint64_t treeIdxTmp = treeIdx;
    uint32_t leafIdxTmp = leafIdx;

    uint8_t adrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
    void *verifyAdrs = adrsBuffer;
    for (uint32_t layer = 0; layer < d; layer++) {
        if (layer != 0) {
            leafIdxTmp = (uint32_t)(treeIdxTmp & ((1UL << hp) - 1));
            treeIdxTmp = treeIdxTmp >> hp;
            ctx->adrsOps->setLayerAddr(verifyAdrs, layer);
        }
        ctx->adrsOps->setTreeAddr(verifyAdrs, treeIdxTmp);
        int32_t ret = HbsTree_Verify(node, n, sigPtr, layerSigLen, leafIdxTmp, verifyAdrs, ctx, node);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        sigPtr += layerSigLen;
    }

    uint8_t diff = 0;
    for (uint32_t i = 0; i < n; i++) {
        diff |= node[i] ^ root[i];
    }
    if (diff != 0) {
        int32_t err =
            HBS_IS_XMSS(ctx) ? CRYPT_XMSS_ERR_MERKLETREE_ROOT_MISMATCH : CRYPT_SLHDSA_ERR_HYPERTREE_VERIFY_FAIL;
        BSL_ERR_PUSH_ERROR(err);
        return err;
    }
    return CRYPT_SUCCESS;
}

/* Produce a hyper-tree signature over msg by signing through all d layers. */
int32_t HbsHyperTree_Sign(const uint8_t *msg, uint32_t msgLen, uint64_t treeIdx, uint32_t leafIdx,
                          const HbsTreeCtx *ctx, uint8_t *sig, uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;
    uint32_t d = ctx->d;
    uint32_t otsLen = ctx->otsLen;
    uint8_t *sigPtr = sig;
    uint32_t offset = 0;

    if (n == 0 || n > HBS_MAX_MDSIZE || msgLen > n) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    size_t totalSigLen = (size_t)(otsLen + hp) * n * d;
    if (*sigLen < totalSigLen) {
        int32_t err = HBS_IS_XMSS(ctx) ? CRYPT_XMSS_ERR_INVALID_SIG_LEN : CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
        BSL_ERR_PUSH_ERROR(err);
        return err;
    }

    uint8_t root[HBS_MAX_MDSIZE] = {0};
    memcpy(root, msg, msgLen);
    const uint8_t *currentMsg = root;

    for (uint32_t j = 0; j < d; j++) {
        uint8_t adrsBuffer[HBS_MAX_ADRS_SIZE] = {0};
        void *signAdrs = adrsBuffer;

        if (j != 0) {
            leafIdx = (uint32_t)(treeIdx & (((uint64_t)1 << hp) - 1));
            treeIdx = treeIdx >> hp;
            ctx->adrsOps->setLayerAddr(signAdrs, j);
        }
        ctx->adrsOps->setTreeAddr(signAdrs, treeIdx);

        uint32_t layerSigLen = otsLen * n + hp * n;
        ret = HbsTree_Sign(currentMsg, n, leafIdx, signAdrs, ctx, sigPtr, &layerSigLen, root);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        sigPtr += layerSigLen;
        offset += layerSigLen;
        currentMsg = root;
    }
    *sigLen = offset;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_XMSS || HITLS_CRYPTO_SLH_DSA */
