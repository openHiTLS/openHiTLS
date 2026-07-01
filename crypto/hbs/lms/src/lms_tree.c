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
#if defined(HITLS_CRYPTO_HSS_LMS) && (defined(HITLS_CRYPTO_HSS_KEYGEN) || defined(HITLS_CRYPTO_HSS_SIGN))

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "lms_tree.h"
#include "lms_local.h"
#include "lms_hash.h"

/**
 * @ingroup lms_common
 * @brief Initialize LMS tree context
 */
int32_t LmsTreeInitContext(LmsTreeCtx *ctx, const LMS_Para *para, const uint8_t *I, const uint8_t *seed)
{
    ctx->para = para;
    ctx->I = I;
    ctx->seed = seed;
    ctx->height = para->height;
    ctx->n = para->n;
    ctx->hashFuncs = &para->hashFuncs;
    ctx->cachedTree = NULL;
    ctx->cachedTreeSize = NULL;
    ctx->treeCacheValid = NULL;

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_common
 * @brief Set tree cache in tree context
 */
void LmsTreeSetCache(LmsTreeCtx *ctx, uint8_t **cachedTree, size_t *cachedTreeSize, bool *treeCacheValid)
{
    ctx->cachedTree = cachedTree;
    ctx->cachedTreeSize = cachedTreeSize;
    ctx->treeCacheValid = treeCacheValid;
}

/**
 * @ingroup lms_tree
 * @brief Compute leaf node hash
 */
static int32_t LmsTreeComputeLeafHash(uint8_t *leafHash, const LmsTreeCtx *ctx, uint32_t r, const uint8_t *otsPubKey)
{
    int32_t ret = ctx->hashFuncs->leafHash(ctx, r, otsPubKey, leafHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_tree
 * @brief Compute internal node hash
 */
static int32_t LmsTreeComputeInternalHash(uint8_t *nodeHash, const LmsTreeCtx *ctx, uint32_t r,
    const uint8_t *leftChild, const uint8_t *rightChild)
{
    int32_t ret = ctx->hashFuncs->nodeHash(ctx, r, leftChild, rightChild, nodeHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_tree
 * @brief Compute all leaf nodes of Merkle tree
 */
static int32_t LmsTreeComputeLeafNodes(uint8_t *tree, const LmsTreeCtx *ctx, uint32_t numLeaves)
{
    uint8_t otsPubKey[LMS_MAX_HASH];
    LMS_SeedDerive derive;

    int32_t ret = LmsSeedDeriveInit(&derive, ctx->I, ctx->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (uint32_t q = 0; q < numLeaves; q++) {
        LmsSeedDeriveSetQ(&derive, q);

        ret = LmOtsGeneratePublicKey(ctx->para->otsType, &derive, ctx->hashFuncs, otsPubKey, ctx->n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        uint32_t r = numLeaves + q;
        ret = LmsTreeComputeLeafHash(&tree[r * ctx->n], ctx, r, otsPubKey);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    BSL_SAL_CleanseData(otsPubKey, sizeof(otsPubKey));
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_tree
 * @brief Compute all internal nodes of Merkle tree
 */
static int32_t LmsTreeComputeInternalNodes(uint8_t *tree, const LmsTreeCtx *ctx, uint32_t numLeaves)
{
    if (numLeaves < 2) {
        return CRYPT_SUCCESS;
    }
    for (uint32_t r = numLeaves - LMS_ROOT_NODE_INDEX; r >= LMS_ROOT_NODE_INDEX; r--) {
        uint32_t leftChild = LMS_LEFT_CHILD_MULTIPLIER * r;
        uint32_t rightChild = LMS_LEFT_CHILD_MULTIPLIER * r + LMS_RIGHT_CHILD_OFFSET;

        int32_t ret = LmsTreeComputeInternalHash(&tree[r * ctx->n], ctx, r, &tree[leftChild * ctx->n],
                                                  &tree[rightChild * ctx->n]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_tree
 * @brief Compute Merkle tree root hash
 */
int32_t LmsTreeComputeRoot(uint8_t *root, const LmsTreeCtx *ctx)
{
    if (ctx->height > LMS_MAX_HEIGHT) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint32_t numLeaves = (uint32_t)(1ULL << ctx->height);
    if (ctx->n == 0 || numLeaves > SIZE_MAX / ((size_t)2u * ctx->n)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    size_t treeSize = (size_t)2u * numLeaves * ctx->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
    if (tree == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = LmsTreeComputeLeafNodes(tree, ctx, numLeaves);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(tree, treeSize);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsTreeComputeInternalNodes(tree, ctx, numLeaves);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(tree, treeSize);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    memcpy(root, &tree[LMS_ROOT_NODE_INDEX * ctx->n], ctx->n);

    BSL_SAL_ClearFree(tree, treeSize);

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_tree
 * @brief Extract authentication path from computed tree
 */
static void LmsTreeExtractAuthPath(uint8_t *authPath, const uint8_t *tree, uint32_t q, uint32_t height, uint32_t n)
{
    uint32_t numLeaves = (uint32_t)(1ULL << height);
    uint32_t nodeNum = numLeaves + q;

    for (uint32_t level = 0; level < height; level++) {
        uint32_t sibling;
        if (nodeNum % LMS_LEFT_CHILD_MULTIPLIER == 0) {
            sibling = nodeNum + LMS_RIGHT_CHILD_OFFSET;
        } else {
            sibling = nodeNum - LMS_RIGHT_CHILD_OFFSET;
        }
        memcpy(authPath + level * n, &tree[sibling * n], n);
        nodeNum /= LMS_LEFT_CHILD_MULTIPLIER;
    }
}

/**
 * @ingroup lms_tree
 * @brief Generate authentication path for leaf node
 */
int32_t LmsTreeGenerateAuthPath(uint8_t *authPath, const LmsTreeCtx *ctx, uint32_t q)
{
    if (ctx->height > LMS_MAX_HEIGHT) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint32_t numLeaves = (uint32_t)(1ULL << ctx->height);

    if (q >= numLeaves) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_LEAF_INDEX);
        return CRYPT_LMS_INVALID_LEAF_INDEX;
    }

    if (ctx->n == 0 || numLeaves > SIZE_MAX / ((size_t)2u * ctx->n)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    size_t treeSize = (size_t)2u * numLeaves * ctx->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
    if (tree == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = LmsTreeComputeLeafNodes(tree, ctx, numLeaves);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(tree, treeSize);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsTreeComputeInternalNodes(tree, ctx, numLeaves);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(tree, treeSize);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    LmsTreeExtractAuthPath(authPath, tree, q, ctx->height, ctx->n);

    BSL_SAL_ClearFree(tree, treeSize);
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms_tree
 * @brief Generate authentication path with tree caching
 */
/* Ensure the cached tree buffer is allocated and matches the required size. */
static int32_t EnsureTreeCacheAllocated(const LmsTreeCtx *ctx, size_t treeSize)
{
    if (*ctx->cachedTree == NULL || *ctx->cachedTreeSize != treeSize) {
        if (*ctx->cachedTree != NULL) {
            BSL_SAL_ClearFree(*ctx->cachedTree, *ctx->cachedTreeSize);
        }
        *ctx->cachedTree = BSL_SAL_Calloc(treeSize, 1);
        if (*ctx->cachedTree == NULL) {
            *ctx->cachedTreeSize = 0;
            *ctx->treeCacheValid = false;
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        *ctx->cachedTreeSize = treeSize;
    }
    return CRYPT_SUCCESS;
}

/* Build the cached tree if it is not already valid. */
static int32_t BuildCachedTree(const LmsTreeCtx *ctx, size_t treeSize, uint32_t numLeaves, uint8_t **treeOut)
{
    if (*ctx->treeCacheValid && *ctx->cachedTree != NULL && *ctx->cachedTreeSize == treeSize) {
        *treeOut = *ctx->cachedTree;
        return CRYPT_SUCCESS;
    }
    int32_t ret = EnsureTreeCacheAllocated(ctx, treeSize);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *treeOut = *ctx->cachedTree;
    ret = LmsTreeComputeLeafNodes(*treeOut, ctx, numLeaves);
    if (ret != CRYPT_SUCCESS) {
        *ctx->treeCacheValid = false;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = LmsTreeComputeInternalNodes(*treeOut, ctx, numLeaves);
    if (ret != CRYPT_SUCCESS) {
        *ctx->treeCacheValid = false;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *ctx->treeCacheValid = true;
    return CRYPT_SUCCESS;
}

int32_t LmsTreeGenerateAuthPathCached(uint8_t *authPath, const LmsTreeCtx *ctx, uint32_t q)
{
    if (ctx->cachedTree == NULL || ctx->cachedTreeSize == NULL || ctx->treeCacheValid == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    if (ctx->height > LMS_MAX_HEIGHT) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint32_t numLeaves = (uint32_t)(1ULL << ctx->height);
    if (q >= numLeaves || ctx->n == 0 || numLeaves > SIZE_MAX / ((size_t)2u * ctx->n)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    size_t treeSize = (size_t)2u * numLeaves * ctx->n;
    uint8_t *tree = NULL;
    int32_t ret = BuildCachedTree(ctx, treeSize, numLeaves, &tree);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    LmsTreeExtractAuthPath(authPath, tree, q, ctx->height, ctx->n);
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_HSS_LMS */
