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
#if defined(HITLS_CRYPTO_HSS_LMS)

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "lms_internal.h"
#include "lms_hash.h"
#include "hss_local.h"
#include "crypt_params_key.h"
#include "crypt_local_types.h"

/* Test-only (moved from production headers) */
#define LMS_TREE_INDEX_BYTES           8
#define LMS_LEVEL_INDEX_BYTES          4
#define LMS_RIGHT_CHILD_OFFSET         1

#define LMS_PRVKEY_INDEX_OFFSET    0
#define LMS_PRVKEY_INDEX_LEN       8
#define LMS_PRVKEY_LMS_TYPE_OFFSET 8
#define LMS_PRVKEY_OTS_TYPE_OFFSET 12
#define LMS_PRVKEY_I_OFFSET        16
#define LMS_PRVKEY_SEED_OFFSET     32
#define LMS_PRVKEY_MAX_LEN         (32 + LMS_SEED_LEN)

#define LMS_MAX_HEIGHT 25
#define LMS_SEED_RANDOMIZER_INDEX 0xFFFFFFFE
#define LMS_PRG_FF_VALUE 0xff
#define LMS_ZERO_INIT_VALUE 0
#define LMS_SIGNATURE_INDEX_INCREMENT 1
#define LMS_PRG_LEN (23 + LMS_SEED_LEN)
#define LMS_PRG_I_OFFSET 0
#define LMS_PRG_Q_OFFSET 16
#define LMS_PRG_J_OFFSET 20
#define LMS_PRG_FF_OFFSET 22
#define LMS_PRG_SEED_OFFSET 23

#define HSS_PRVKEY_COUNTER_OFFSET 0
#define HSS_PRVKEY_PARAMS_OFFSET 8
#define HSS_PRVKEY_PARAMS_LEN 8
#define HSS_PRVKEY_SEED_OFFSET 16
#define HSS_PRVKEY_SEED_LEN 32
#define HSS_PUBKEY_I_OFFSET 12
#define HSS_SEED_ROOT_I 0x00
#define HSS_SEED_ROOT_SEED 0x01
#define HSS_SEED_CHILD_SUFFIX 0x01
#define HSS_COMPRESSED_PARAMS_LEN (1 + 2 * HSS_MAX_LEVELS + 1)
#define HSS_ROOT_SEED_DERIVE_BUF_LEN 34
#define HSS_CHILD_SEED_DERIVE_BUF_LEN 60
#define HSS_CHILD_SEED_SUFFIX_BUF_LEN 61
#define HSS_COMPRESSED_LEVEL_FIELD_SIZE 1
#define HSS_COMPRESSED_PARAM_PAIR_SIZE 2

typedef struct {
    const uint8_t *I;
    const uint8_t *masterSeed;
    uint32_t q;
    uint32_t j;
} LMS_SeedDerive;

typedef struct {
    uint8_t **tree;
    uint32_t *size;
    bool *valid;
} LMS_TreeCache;

typedef struct {
    const uint8_t *I;
    const uint8_t *seed;
} LMS_TreeParams;

static int32_t LmsTreeInitContext(LmsTreeCtx *ctx, const LMS_Para *para, const uint8_t *I, const uint8_t *seed);
static void LmsTreeSetCache(LmsTreeCtx *ctx, uint8_t **cachedTree, uint32_t *cachedTreeSize, bool *treeCacheValid);
int32_t LmOtsSign(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
    const CRYPT_ConstData *message, CRYPT_Data *signature);
int32_t LmOtsGeneratePublicKey(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
    uint8_t *publicKey, uint32_t publicKeyLen);

typedef struct {
    uint8_t *signature;
    uint32_t *signatureLen;
    const LMS_Para *para;
    const uint8_t *I;
    const uint8_t *seed;
    uint32_t q;
    const uint8_t *message;
    uint32_t messageLen;
} LmsSignWriteCtx;

typedef struct {
    uint8_t *data;
    uint32_t *len;
} LMS_SignatureBuffer;

/* Forward declarations for tree functions (merged from lms_tree.c) */
static int32_t LmsTreeComputeRoot(uint8_t *root, const LmsTreeCtx *ctx);
static int32_t LmsTreeGenerateAuthPathCached(uint8_t *authPath, const LmsTreeCtx *ctx, uint32_t q);

int32_t LmsSeedDeriveInit(LMS_SeedDerive *derive, const uint8_t *I, const uint8_t *seed)
{
    derive->I = I;
    derive->masterSeed = seed;
    derive->q = LMS_ZERO_INIT_VALUE;
    derive->j = LMS_ZERO_INIT_VALUE;
    return CRYPT_SUCCESS;
}

int32_t LmsSeedDeriveSetQ(LMS_SeedDerive *derive, uint32_t q)
{
    derive->q = q;
    return CRYPT_SUCCESS;
}

int32_t LmsSeedDeriveSetJ(LMS_SeedDerive *derive, uint32_t j)
{
    derive->j = j;
    return CRYPT_SUCCESS;
}

int32_t LmsSeedDerive(uint8_t *seed, LMS_SeedDerive *derive, bool incrementJ)
{
    uint8_t buffer[LMS_PRG_LEN];

    memcpy(buffer + LMS_PRG_I_OFFSET, derive->I, LMS_I_LEN);
    BSL_Uint32ToByte(derive->q, buffer + LMS_PRG_Q_OFFSET);
    BSL_Uint16ToByte((uint16_t)derive->j, buffer + LMS_PRG_J_OFFSET);
    buffer[LMS_PRG_FF_OFFSET] = LMS_PRG_FF_VALUE;
    memcpy(buffer + LMS_PRG_SEED_OFFSET, derive->masterSeed, LMS_SEED_LEN);

    int32_t ret = LmsHash(seed, buffer, LMS_PRG_LEN);
    BSL_SAL_CleanseData(buffer, LMS_PRG_LEN);
    if (ret != CRYPT_SUCCESS) {
        memset(seed, 0, LMS_SEED_LEN);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (incrementJ) {
        derive->j += 1;
    }
    return CRYPT_SUCCESS;
}

int32_t LmsComputeRoot(uint8_t *root, const LMS_Para *para, const uint8_t *I, const uint8_t *seed)
{
    LmsTreeCtx treeCtx;
    int32_t ret = LmsTreeInitContext(&treeCtx, para, I, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsTreeComputeRoot(root, &treeCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t LmsGenerateAuthPathCached(uint8_t *authPath, const LMS_Para *para, const LMS_TreeParams *treeParams, uint32_t q,
    LMS_TreeCache *cache)
{
    LmsTreeCtx treeCtx;
    int32_t ret = LmsTreeInitContext(&treeCtx, para, treeParams->I, treeParams->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    LmsTreeSetCache(&treeCtx, cache->tree, cache->size, cache->valid);

    ret = LmsTreeGenerateAuthPathCached(authPath, &treeCtx, q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t LmsSignValidate(const LMS_Para *para, const uint8_t *privateKey, uint32_t *signatureLen)
{
    if (*signatureLen < para->sigLen) {
        *signatureLen = para->sigLen;
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    if (para->height > LMS_MAX_HEIGHT) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint64_t q = BSL_ByteToUint64(privateKey + LMS_PRVKEY_INDEX_OFFSET);
    uint64_t numLeaves = 1ULL << para->height;

    if (q >= numLeaves) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_KEY_EXHAUSTED);
        return CRYPT_LMS_KEY_EXHAUSTED;
    }
    return CRYPT_SUCCESS;
}

static int32_t LmsSignWriteSignatureCached(const LmsSignWriteCtx *ctx, LMS_TreeCache *cache)
{
    LMS_SeedDerive derive;
    int32_t ret = LmsSeedDeriveInit(&derive, ctx->I, ctx->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    LmsSeedDeriveSetQ(&derive, ctx->q);

    uint32_t offset = 0;
    BSL_Uint32ToByte(ctx->q, ctx->signature + offset);
    offset += LMS_Q_LEN;

    uint32_t otsSigLen = LmOtsGetSigLen(ctx->para->otsType);
    CRYPT_Data sigBuf = {ctx->signature + offset, otsSigLen};
    CRYPT_ConstData msgBuf = {ctx->message, ctx->messageLen};
    ret = LmOtsSign(ctx->para->otsType, &derive, &ctx->para->hashFuncs, &msgBuf, &sigBuf);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += otsSigLen;

    BSL_Uint32ToByte(ctx->para->lmsType, ctx->signature + offset);
    offset += LMS_TYPE_LEN;

    LMS_TreeParams treeParams = {ctx->I, ctx->seed};
    ret = LmsGenerateAuthPathCached(ctx->signature + offset, ctx->para, &treeParams, ctx->q, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += ctx->para->height * ctx->para->n;

    *ctx->signatureLen = offset;
    return CRYPT_SUCCESS;
}

int32_t LmsSignCached(const LMS_Para *para, uint8_t *privateKey, const CRYPT_ConstData *message,
    LMS_SignatureBuffer *signature, LMS_TreeCache *cache)
{
    int32_t ret = LmsSignValidate(para, privateKey, signature->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint64_t q = BSL_ByteToUint64(privateKey + LMS_PRVKEY_INDEX_OFFSET);
    const uint8_t *I = privateKey + LMS_PRVKEY_I_OFFSET;
    const uint8_t *seed = privateKey + LMS_PRVKEY_SEED_OFFSET;

    BSL_Uint64ToByte(q + LMS_SIGNATURE_INDEX_INCREMENT, privateKey + LMS_PRVKEY_INDEX_OFFSET);

    LmsSignWriteCtx ctx = {signature->data, signature->len, para, I, seed, (uint32_t)q, message->data, message->len};
    ret = LmsSignWriteSignatureCached(&ctx, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

static int32_t LmsTreeInitContext(LmsTreeCtx *ctx, const LMS_Para *para, const uint8_t *I, const uint8_t *seed)
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

static void LmsTreeSetCache(LmsTreeCtx *ctx, uint8_t **cachedTree, uint32_t *cachedTreeSize, bool *treeCacheValid)
{
    ctx->cachedTree = cachedTree;
    ctx->cachedTreeSize = cachedTreeSize;
    ctx->treeCacheValid = treeCacheValid;
}

static int32_t LmsTreeComputeLeafHash(uint8_t *leafHash, const LmsTreeCtx *ctx, uint32_t r, const uint8_t *otsPubKey)
{
    int32_t ret = ctx->hashFuncs->leafHash(ctx, r, otsPubKey, leafHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

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

static int32_t LmsTreeComputeRoot(uint8_t *root, const LmsTreeCtx *ctx)
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
    uint32_t treeSize = 2u * numLeaves * ctx->n;
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

static int32_t EnsureTreeCacheAllocated(const LmsTreeCtx *ctx, uint32_t treeSize)
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

static int32_t BuildCachedTree(const LmsTreeCtx *ctx, uint32_t treeSize, uint32_t numLeaves, uint8_t **treeOut)
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

static int32_t LmsTreeGenerateAuthPathCached(uint8_t *authPath, const LmsTreeCtx *ctx, uint32_t q)
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
    if (q >= numLeaves || ctx->n == 0 || numLeaves > SIZE_MAX / (2u * ctx->n)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint32_t treeSize = 2u * numLeaves * ctx->n;
    uint8_t *tree = NULL;
    int32_t ret = BuildCachedTree(ctx, treeSize, numLeaves, &tree);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    LmsTreeExtractAuthPath(authPath, tree, q, ctx->height, ctx->n);
    return CRYPT_SUCCESS;
}

static int32_t LmOtsGenerateChains(uint8_t *chains, const LmsOtsCtx *ctx, LMS_SeedDerive *seed)
{
    uint8_t tmp[LMS_MAX_HASH];

    LmsSeedDeriveSetJ(seed, LMS_ZERO_INIT_VALUE);

    for (uint32_t i = 0; i < ctx->p; i++) {
        int32_t ret = LmsSeedDerive(tmp, seed, (i < ctx->p - 1));
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        uint32_t maxSteps = (1 << ctx->w) - 1;
        ret = LmOtsChain(tmp, 0, maxSteps, ctx, i);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        memcpy(chains + i * ctx->n, tmp, ctx->n);
    }

    BSL_SAL_CleanseData(tmp, sizeof(tmp));
    return CRYPT_SUCCESS;
}

int32_t LmOtsGeneratePublicKey(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
    uint8_t *publicKey, uint32_t publicKeyLen)
{
    LmOtsParams params;
    int32_t ret = LmOtsLookupParamSet(otsType, &params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (publicKeyLen < params.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    LmsOtsCtx ctx = {seed->I, seed->q, params.n, params.w, params.p, params.ls, hashFuncs};

    uint32_t chainsLen = params.p * params.n;
    uint8_t *chains = BSL_SAL_Malloc(chainsLen);
    if (chains == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmOtsGenerateChains(chains, &ctx, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(chains, chainsLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = hashFuncs->pkCompress(&ctx, chains, publicKey);
    BSL_SAL_ClearFree(chains, chainsLen);

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t LmOtsGenerateRandomizer(uint8_t *c, uint32_t n, LMS_SeedDerive *seed)
{
    uint8_t randomizer[LMS_SEED_LEN];

    LmsSeedDeriveSetJ(seed, LMS_SEED_RANDOMIZER_INDEX);
    int32_t ret = LmsSeedDerive(randomizer, seed, false);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(randomizer, sizeof(randomizer));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    memcpy(c, randomizer, n);
    BSL_SAL_CleanseData(randomizer, sizeof(randomizer));
    return CRYPT_SUCCESS;
}

static int32_t LmOtsSignChains(uint8_t *signature, const LmsOtsCtx *ctx, const uint8_t *Q, LMS_SeedDerive *seed)
{
    uint8_t tmp[LMS_MAX_HASH];

    LmsSeedDeriveSetJ(seed, LMS_ZERO_INIT_VALUE);

    for (uint32_t i = 0; i < ctx->p; i++) {
        int32_t ret = LmsSeedDerive(tmp, seed, (i < ctx->p - 1));
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        uint32_t a = LmOtsCoef(Q, i, ctx->w);
        ret = LmOtsChain(tmp, 0, a, ctx, i);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        memcpy(&signature[LMS_TYPE_LEN + ctx->n + ctx->n * i], tmp, ctx->n);
    }

    BSL_SAL_CleanseData(tmp, sizeof(tmp));
    return CRYPT_SUCCESS;
}

int32_t LmOtsSign(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
    const CRYPT_ConstData *message, CRYPT_Data *signature)
{
    LmOtsParams params;
    int32_t ret = LmOtsLookupParamSet(otsType, &params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (signature->len < LMS_TYPE_LEN + params.n + params.p * params.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    BSL_Uint32ToByte(otsType, signature->data);
    ret = LmOtsGenerateRandomizer(signature->data + LMS_TYPE_LEN, params.n, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t Q[LMS_MAX_HASH + LMS_CHECKSUM_LEN];
    LmsOtsCtx ctx = {seed->I, seed->q, params.n, params.w, params.p, params.ls, hashFuncs};
    ret = LmOtsComputeQ(Q, &ctx, signature->data + LMS_TYPE_LEN, message->data, message->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmOtsSignChains(signature->data, &ctx, Q, seed);
    BSL_SAL_CleanseData(Q, sizeof(Q));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

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

typedef struct {
    uint64_t treeIndex;
    uint32_t level;
} HssChildPosition;

typedef struct {
    uint8_t *data;
    uint32_t *len;
} HSS_OutputBuffer;

typedef struct {
    const uint8_t *I;
    const uint8_t *seed;
    uint32_t leafIndex;
} HssTreeContext;

typedef struct {
    uint32_t parentLevel;
    uint32_t childLevel;
    const HSS_Para *para;
} HssSignContext;

static int32_t HssCompressLmsType(uint32_t lmsType, uint8_t *lmsComp)
{
    switch (lmsType) {
        case LMS_SHA256_M32_H5:
            *lmsComp = 5;
            break;
        case LMS_SHA256_M32_H10:
            *lmsComp = 10;
            break;
        case LMS_SHA256_M32_H15:
            *lmsComp = 15;
            break;
        case LMS_SHA256_M32_H20:
            *lmsComp = 20;
            break;
        case LMS_SHA256_M32_H25:
            *lmsComp = 25;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

static int32_t HssCompressOtsType(uint32_t otsType, uint8_t *otsComp)
{
    switch (otsType) {
        case LMOTS_SHA256_N32_W1:
            *otsComp = 1;
            break;
        case LMOTS_SHA256_N32_W2:
            *otsComp = 2;
            break;
        case LMOTS_SHA256_N32_W4:
            *otsComp = 4;
            break;
        case LMOTS_SHA256_N32_W8:
            *otsComp = 8;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

static int32_t HssCompressParamSet(uint8_t compressed[8], const HSS_Para *para)
{
    if (para->levels < HSS_MIN_LEVELS || para->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    memset(compressed, 0, HSS_COMPRESSED_PARAMS_LEN);
    compressed[0] = (uint8_t)para->levels;

    for (uint32_t i = 0; i < para->levels && i < HSS_MAX_LEVELS; i++) {
        uint8_t lmsComp;
        uint8_t otsComp;
        int32_t ret = HssCompressLmsType(para->lmsType[i], &lmsComp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = HssCompressOtsType(para->otsType[i], &otsComp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE] = lmsComp;
        compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE + 1] = otsComp;
    }

    return CRYPT_SUCCESS;
}

static int32_t HssDecompressLmsType(uint8_t lmsComp, uint32_t *lmsType)
{
    switch (lmsComp) {
        case 5:
            *lmsType = LMS_SHA256_M32_H5;
            break;
        case 10:
            *lmsType = LMS_SHA256_M32_H10;
            break;
        case 15:
            *lmsType = LMS_SHA256_M32_H15;
            break;
        case 20:
            *lmsType = LMS_SHA256_M32_H20;
            break;
        case 25:
            *lmsType = LMS_SHA256_M32_H25;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

static int32_t HssDecompressOtsType(uint8_t otsComp, uint32_t *otsType)
{
    switch (otsComp) {
        case 1:
            *otsType = LMOTS_SHA256_N32_W1;
            break;
        case 2:
            *otsType = LMOTS_SHA256_N32_W2;
            break;
        case 4:
            *otsType = LMOTS_SHA256_N32_W4;
            break;
        case 8:
            *otsType = LMOTS_SHA256_N32_W8;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
    }
    return CRYPT_SUCCESS;
}

static int32_t HssDecompressParamSet(HSS_Para *para, const uint8_t compressed[8])
{
    uint32_t levels = compressed[0];
    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    uint32_t lmsTypes[HSS_LEVELS_ARRAY_SIZE];
    uint32_t otsTypes[HSS_LEVELS_ARRAY_SIZE];

    for (uint32_t i = 0; i < levels; i++) {
        uint8_t lmsComp = compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE];
        uint8_t otsComp = compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE + 1];

        int32_t ret = HssDecompressLmsType(lmsComp, &lmsTypes[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        ret = HssDecompressOtsType(otsComp, &otsTypes[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    int32_t initRet = HssParaInit(para, levels, lmsTypes, otsTypes);
    if (initRet != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(initRet);
    }
    return initRet;
}

static int32_t HssGenerateRootSeed(uint8_t rootI[LMS_I_LEN], uint8_t rootSeed[LMS_SEED_LEN],
    const uint8_t masterSeed[LMS_SEED_LEN])
{
    uint8_t buffer[HSS_ROOT_SEED_DERIVE_BUF_LEN];
    memcpy(buffer, masterSeed, LMS_SEED_LEN);
    buffer[LMS_SEED_LEN] = HSS_SEED_ROOT_I;
    buffer[LMS_SEED_LEN + 1] = 0x00;

    uint8_t hash[LMS_SHA256_N];
    int32_t ret = LmsHash(hash, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }
    memcpy(rootI, hash, LMS_I_LEN);

    buffer[LMS_SEED_LEN] = HSS_SEED_ROOT_SEED;
    buffer[LMS_SEED_LEN + 1] = 0x00;

    ret = LmsHash(rootSeed, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }

    BSL_SAL_CleanseData(buffer, sizeof(buffer));
    return CRYPT_SUCCESS;
}

static int32_t HssGenerateChildSeed(uint8_t childI[LMS_I_LEN], uint8_t childSeed[LMS_SEED_LEN],
    const uint8_t parentI[LMS_I_LEN], const uint8_t parentSeed[LMS_SEED_LEN], const HssChildPosition *position)
{
    uint8_t buffer[HSS_CHILD_SEED_DERIVE_BUF_LEN];
    memcpy(buffer, parentSeed, LMS_SEED_LEN);
    memcpy(buffer + LMS_SEED_LEN, parentI, LMS_I_LEN);
    BSL_Uint64ToByte(position->treeIndex, buffer + LMS_SEED_LEN + LMS_I_LEN);
    BSL_Uint32ToByte(position->level, buffer + LMS_SEED_LEN + LMS_I_LEN + LMS_TREE_INDEX_BYTES);

    uint8_t hash[LMS_SHA256_N];
    int32_t ret = LmsHash(hash, buffer, HSS_CHILD_SEED_DERIVE_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(buffer, sizeof(buffer));
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }
    memcpy(childI, hash, LMS_I_LEN);

    uint8_t bufferWithSuffix[HSS_CHILD_SEED_SUFFIX_BUF_LEN];
    memcpy(bufferWithSuffix, buffer, HSS_CHILD_SEED_DERIVE_BUF_LEN);
    bufferWithSuffix[HSS_CHILD_SEED_DERIVE_BUF_LEN] = HSS_SEED_CHILD_SUFFIX;

    ret = LmsHash(childSeed, bufferWithSuffix, HSS_CHILD_SEED_SUFFIX_BUF_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(buffer, sizeof(buffer));
        BSL_SAL_CleanseData(bufferWithSuffix, sizeof(bufferWithSuffix));
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SEED_DERIVE_FAIL);
        return CRYPT_HSS_SEED_DERIVE_FAIL;
    }

    BSL_SAL_CleanseData(buffer, sizeof(buffer));
    BSL_SAL_CleanseData(bufferWithSuffix, sizeof(bufferWithSuffix));
    return CRYPT_SUCCESS;
}

static int32_t HssCalculateTreeIndices(const HSS_Para *para, uint64_t globalIndex, uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE],
                                uint32_t leafIndex[HSS_LEVELS_ARRAY_SIZE])
{
    if (para->levels == 0 || para->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_LEVEL);
        return CRYPT_HSS_INVALID_LEVEL;
    }

    uint64_t sigsPerTree[HSS_LEVELS_ARRAY_SIZE];
    sigsPerTree[para->levels - 1] = 1ULL << para->levelPara[para->levels - 1].height;

    for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
        uint32_t currentHeight = para->levelPara[i].height;
        sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << currentHeight);
    }

    for (uint32_t i = 0; i < para->levels; i++) {
        treeIndex[i] = globalIndex / sigsPerTree[i];

        uint32_t height = para->levelPara[i].height;
        uint64_t maxLeaves = 1ULL << height;

        if (i == para->levels - 1) {
            leafIndex[i] = (uint32_t)(globalIndex % maxLeaves);
        } else {
            leafIndex[i] = (uint32_t)((globalIndex / sigsPerTree[i + 1]) % maxLeaves);
        }
    }

    return CRYPT_SUCCESS;
}

static void HssInvalidateAllTreeCaches(CRYPT_HSS_Ctx *ctx)
{
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        BSL_SAL_ClearFree(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
        ctx->cachedTrees[i] = NULL;
        ctx->cachedTreeSizes[i] = 0;
        ctx->treeCacheValid[i] = false;
        ctx->cachedTreeIndex[i] = 0;
    }
}

int32_t CRYPT_HSS_SetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para.prvKeyLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    const BSL_Param *prvKeyParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_PRVKEY);
    if (prvKeyParam == NULL || prvKeyParam->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }
    if (prvKeyParam->valueLen != HSS_PRVKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    uint8_t compressed[HSS_COMPRESSED_PARAMS_LEN];
    memcpy(compressed, (const uint8_t *)prvKeyParam->value + HSS_PRVKEY_PARAMS_OFFSET, HSS_PRVKEY_PARAMS_LEN);
    HSS_Para newPara = {0};
    int32_t ret = HssDecompressParamSet(&newPara, compressed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (newPara.levels != ctx->para.levels) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < newPara.levels; i++) {
        if (newPara.lmsType[i] != ctx->para.lmsType[i] || newPara.otsType[i] != ctx->para.otsType[i]) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return CRYPT_HSS_INVALID_PARAM;
        }
    }

    if (ctx->privateKey == NULL) {
        ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);
        if (ctx->privateKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    memcpy(ctx->privateKey, prvKeyParam->value, HSS_PRVKEY_LEN);

    HssInvalidateAllTreeCaches(ctx);
    ctx->signatureIndex = BSL_ByteToUint64(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_GetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (prv->valueLen < HSS_PRVKEY_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_KEY_LEN);
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    memcpy(prv->value, ctx->privateKey, HSS_PRVKEY_LEN);
    prv->useLen = HSS_PRVKEY_LEN;
    return CRYPT_SUCCESS;
}

int32_t HssCtrlGetPrvKeyLen(void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    *(uint32_t *)val = HSS_PRVKEY_LEN;
    return CRYPT_SUCCESS;
}

int32_t HssCtrlGetRemaining(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen != sizeof(uint64_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para.levels == 0 || ctx->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    if (ctx->para.pubKeyLen == 0) {
        int32_t ret = HssParaInit(&ctx->para, ctx->para.levels, ctx->para.lmsType, ctx->para.otsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    uint64_t maxSigs = HssGetMaxSignatures(&ctx->para);
    uint64_t counter = BSL_ByteToUint64(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET);
    uint64_t remaining = (maxSigs > 0 && counter < maxSigs) ? (maxSigs - counter) : 0;
    *(uint64_t *)val = remaining;
    return CRYPT_SUCCESS;
}

static int32_t HssGenerateKeys(void *libCtx, uint8_t rootI[LMS_I_LEN], uint8_t rootHash[LMS_SHA256_N],
    uint8_t masterSeed[LMS_SEED_LEN], const LMS_Para *levelPara)
{
    int32_t ret = CRYPT_RandEx(libCtx, masterSeed, LMS_SEED_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_KEYGEN_FAIL);
        return CRYPT_HSS_KEYGEN_FAIL;
    }
    uint8_t rootSeed[LMS_SEED_LEN];
    ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsComputeRoot(rootHash, levelPara, rootI, rootSeed);
    BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_KEYGEN_FAIL);
        return CRYPT_HSS_KEYGEN_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t HssFormatPublicKey(uint8_t *publicKey, const HSS_Para *para, const uint8_t *rootI,
    const uint8_t *rootHash)
{
    BSL_Uint32ToByte(para->levels, publicKey + HSS_PUBKEY_LEVELS_OFFSET);
    BSL_Uint32ToByte(para->lmsType[0], publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET);
    BSL_Uint32ToByte(para->otsType[0], publicKey + HSS_PUBKEY_OTS_TYPE_OFFSET);
    memcpy(publicKey + HSS_PUBKEY_I_OFFSET, rootI, LMS_I_LEN);
    memcpy(publicKey + HSS_PUBKEY_ROOT_OFFSET, rootHash, LMS_SHA256_N);
    return CRYPT_SUCCESS;
}

static int32_t HssFormatPrivateKey(uint8_t *privateKey, const HSS_Para *para, const uint8_t *masterSeed)
{
    BSL_Uint64ToByte(0, privateKey + HSS_PRVKEY_COUNTER_OFFSET);

    uint8_t compressed[HSS_COMPRESSED_PARAMS_LEN];
    int32_t ret = HssCompressParamSet(compressed, para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memcpy(privateKey + HSS_PRVKEY_PARAMS_OFFSET, compressed, HSS_PRVKEY_PARAMS_LEN);
    memcpy(privateKey + HSS_PRVKEY_SEED_OFFSET, masterSeed, HSS_PRVKEY_SEED_LEN);
    BSL_SAL_CleanseData(compressed, sizeof(compressed));
    return CRYPT_SUCCESS;
}

static int32_t HssAllocKeyBuffers(CRYPT_HSS_Ctx *ctx)
{
    uint8_t *newPublicKey = BSL_SAL_Calloc(1, ctx->para.pubKeyLen);
    if (newPublicKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (ctx->privateKey == NULL) {
        ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);
        if (ctx->privateKey == NULL) {
            BSL_SAL_Free(newPublicKey);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    if (ctx->publicKey != NULL) {
        BSL_SAL_Free(ctx->publicKey);
    }
    ctx->publicKey = newPublicKey;
    ctx->publicLen = ctx->para.pubKeyLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Gen(CRYPT_HSS_Ctx *ctx)
{
    int32_t ret;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para.pubKeyLen == 0) {
        ret = HssParaInit(&ctx->para, ctx->para.levels, ctx->para.lmsType, ctx->para.otsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    uint8_t masterSeed[LMS_SEED_LEN];
    uint8_t rootI[LMS_I_LEN];
    uint8_t rootHash[LMS_SHA256_N];
    ret = HssGenerateKeys(ctx->libCtx, rootI, rootHash, masterSeed, &ctx->para.levelPara[0]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto CLEANUP;
    }

    ret = HssAllocKeyBuffers(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto CLEANUP;
    }

    HssFormatPublicKey(ctx->publicKey, &ctx->para, rootI, rootHash);
    ret = HssFormatPrivateKey(ctx->privateKey, &ctx->para, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto CLEANUP;
    }

    ctx->signatureIndex = 0;
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        ctx->treeCacheValid[i] = false;
        ctx->cachedTreeIndex[i] = 0;
    }

CLEANUP:
    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
    BSL_SAL_CleanseData(rootI, sizeof(rootI));
    BSL_SAL_CleanseData(rootHash, sizeof(rootHash));
    return ret;
}

static int32_t HssCreateChildPubKey(uint8_t childPubKey[LMS_PUBKEY_MAX_LEN], const HssSignContext *signCtx,
    const HssTreeContext *child)
{
    uint8_t childRoot[32];
    int32_t ret = LmsComputeRoot(childRoot, &signCtx->para->levelPara[signCtx->childLevel], child->I, child->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BSL_Uint32ToByte(signCtx->para->lmsType[signCtx->childLevel], childPubKey + LMS_PUBKEY_LMS_TYPE_OFFSET);
    BSL_Uint32ToByte(signCtx->para->otsType[signCtx->childLevel], childPubKey + LMS_PUBKEY_OTS_TYPE_OFFSET);
    memcpy(childPubKey + LMS_PUBKEY_I_OFFSET, child->I, LMS_I_LEN);
    memcpy(childPubKey + LMS_PUBKEY_ROOT_OFFSET, childRoot, LMS_SHA256_N);
    BSL_SAL_CleanseData(childRoot, sizeof(childRoot));
    return CRYPT_SUCCESS;
}

static int32_t HssSignChildPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx, const HssTreeContext *parent,
    const uint8_t childPubKey[LMS_PUBKEY_MAX_LEN], LMS_TreeCache *cache)
{
    uint8_t parentPrivKey[LMS_PRVKEY_MAX_LEN];
    BSL_Uint64ToByte(parent->leafIndex, parentPrivKey + LMS_PRVKEY_INDEX_OFFSET);
    BSL_Uint32ToByte(signCtx->para->lmsType[signCtx->parentLevel], parentPrivKey + LMS_PRVKEY_LMS_TYPE_OFFSET);
    BSL_Uint32ToByte(signCtx->para->otsType[signCtx->parentLevel], parentPrivKey + LMS_PRVKEY_OTS_TYPE_OFFSET);
    memcpy(parentPrivKey + LMS_PRVKEY_I_OFFSET, parent->I, LMS_I_LEN);
    memcpy(parentPrivKey + LMS_PRVKEY_SEED_OFFSET, parent->seed, LMS_SEED_LEN);

    uint32_t childPubKeyLen = signCtx->para->levelPara[signCtx->childLevel].pubKeyLen;
    CRYPT_ConstData msgBuf = {childPubKey, childPubKeyLen};
    LMS_SignatureBuffer sigBuf = {output->data, output->len};
    int32_t ret =
        LmsSignCached(&signCtx->para->levelPara[signCtx->parentLevel], parentPrivKey, &msgBuf, &sigBuf, cache);
    BSL_SAL_CleanseData(parentPrivKey, sizeof(parentPrivKey));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HssGenerateSignedPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx, const HssTreeContext *parent,
    const HssTreeContext *child, LMS_TreeCache *cache)
{
    uint8_t childPubKey[LMS_PUBKEY_MAX_LEN];
    int32_t ret = HssCreateChildPubKey(childPubKey, signCtx, child);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t parentSigLen = signCtx->para->levelPara[signCtx->parentLevel].sigLen;
    uint32_t childPubKeyLen = signCtx->para->levelPara[signCtx->childLevel].pubKeyLen;
    if (*output->len < parentSigLen + childPubKeyLen) {
        BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    HSS_OutputBuffer sigOutput = {output->data, &parentSigLen};
    ret = HssSignChildPubKey(&sigOutput, signCtx, parent, childPubKey, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    memcpy(output->data + parentSigLen, childPubKey, childPubKeyLen);
    *output->len = parentSigLen + childPubKeyLen;
    BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
    return CRYPT_SUCCESS;
}

typedef struct {
    const uint8_t *data;
    uint32_t len;
} HssMessage;

static int32_t HssGenerateAllSeeds(uint8_t levelI[HSS_LEVELS_ARRAY_SIZE][LMS_I_LEN],
    uint8_t levelSeed[HSS_LEVELS_ARRAY_SIZE][LMS_SEED_LEN], const uint8_t masterSeed[LMS_SEED_LEN],
    const uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE], uint32_t levels)
{
    int32_t ret = HssGenerateRootSeed(levelI[0], levelSeed[0], masterSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (uint32_t i = 1; i < levels; i++) {
        HssChildPosition position = {treeIndex[i], i};
        ret = HssGenerateChildSeed(levelI[i], levelSeed[i], levelI[i - 1], levelSeed[i - 1], &position);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t HssSignValidateAndSetup(CRYPT_HSS_Ctx *ctx, uint32_t sigLen, uint64_t *counter,
    uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE], uint32_t leafIndex[HSS_LEVELS_ARRAY_SIZE])
{
    if (ctx->privateKey == NULL || ctx->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    if (sigLen < HssGetSignatureLen(&ctx->para)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    *counter = BSL_ByteToUint64(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET);
    uint64_t maxSigs = HssGetMaxSignatures(&ctx->para);
    if (maxSigs == 0 || *counter >= maxSigs) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_KEY_EXHAUSTED);
        return CRYPT_HSS_KEY_EXHAUSTED;
    }

    int32_t idxRet = HssCalculateTreeIndices(&ctx->para, *counter, treeIndex, leafIndex);
    if (idxRet != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(idxRet);
    }
    return idxRet;
}

int32_t HssTreeCalculateIndices(uint64_t treeIndices[HSS_LEVELS_ARRAY_SIZE],
    uint32_t leafIndices[HSS_LEVELS_ARRAY_SIZE], uint64_t globalIndex, const HSS_Para *para)
{
    if (para->levels == 0 || para->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    uint64_t remaining = globalIndex;

    for (int32_t level = para->levels - 1; level >= 0; level--) {
        uint64_t numLeaves = 1ULL << para->levelPara[level].height;
        leafIndices[level] = (uint32_t)(remaining % numLeaves);
        remaining /= numLeaves;
        treeIndices[level] = remaining;
    }

    return CRYPT_SUCCESS;
}

int32_t HssTreeInitContext(HssMultiTreeCtx *ctx, const HSS_Para *para, uint64_t globalIndex)
{
    ctx->levels = para->levels;
    ctx->globalIndex = globalIndex;
    ctx->para = para;

    int32_t ret = HssTreeCalculateIndices(ctx->treeIndices, ctx->leafIndices, globalIndex, para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t HssTreeInitContextWithSeeds(HssMultiTreeCtx *ctx, const HSS_Para *para, const uint8_t masterSeed[LMS_SEED_LEN],
    uint64_t globalIndex)
{
    int32_t ret = HssTreeInitContext(ctx, para, globalIndex);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HssGenerateAllSeeds(ctx->levelI, ctx->levelSeed, masterSeed, ctx->treeIndices, para->levels);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (uint32_t i = 0; i < para->levels; i++) {
        ctx->lmsTrees[i].para = &para->levelPara[i];
        ctx->lmsTrees[i].I = ctx->levelI[i];
        ctx->lmsTrees[i].seed = ctx->levelSeed[i];
        ctx->lmsTrees[i].height = para->levelPara[i].height;
        ctx->lmsTrees[i].n = para->levelPara[i].n;
        ctx->lmsTrees[i].hashFuncs = &para->levelPara[i].hashFuncs;
        ctx->lmsTrees[i].cachedTree = NULL;
        ctx->lmsTrees[i].cachedTreeSize = NULL;
        ctx->lmsTrees[i].treeCacheValid = NULL;
    }

    return CRYPT_SUCCESS;
}

int32_t HssTreeGenerateSignedPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx,
    const HssTreeContext *parent, const HssTreeContext *child, LMS_TreeCache *cache)
{
    return HssGenerateSignedPubKey(output, signCtx, parent, child, cache);
}

static int32_t HssSignIntermediateLayers(uint8_t *signature, uint8_t **sigPtrInOut, const uint32_t *signatureLen,
    const HssMultiTreeCtx *ctx, uint32_t nspk)
{
    uint8_t *sigPtr = *sigPtrInOut;
    for (uint32_t i = 0; i < nspk; i++) {
        HssTreeContext parent = {ctx->levelI[i], ctx->levelSeed[i], ctx->leafIndices[i]};
        HssTreeContext child = {ctx->levelI[i + 1], ctx->levelSeed[i + 1], 0};
        HssSignContext signCtx = {i, i + 1, ctx->para};
        LMS_TreeCache cache = {ctx->lmsTrees[i].cachedTree, ctx->lmsTrees[i].cachedTreeSize,
                               ctx->lmsTrees[i].treeCacheValid};

        uint32_t remainingLen = (uint32_t)(*signatureLen - (size_t)(sigPtr - signature));
        HSS_OutputBuffer output = {sigPtr, &remainingLen};

        int32_t ret = HssTreeGenerateSignedPubKey(&output, &signCtx, &parent, &child, &cache);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        sigPtr += remainingLen;
    }
    *sigPtrInOut = sigPtr;
    return CRYPT_SUCCESS;
}

static int32_t HssSignBottomLayer(uint8_t *signature, uint8_t **sigPtrInOut, const uint32_t *signatureLen,
    const uint8_t *message, uint32_t messageLen, const HssMultiTreeCtx *ctx)
{
    uint32_t bottomLevel = ctx->levels - 1;
    uint8_t bottomPrivKey[LMS_PRVKEY_MAX_LEN];

    BSL_Uint64ToByte(ctx->leafIndices[bottomLevel], bottomPrivKey + LMS_PRVKEY_INDEX_OFFSET);
    BSL_Uint32ToByte(ctx->para->lmsType[bottomLevel], bottomPrivKey + LMS_PRVKEY_LMS_TYPE_OFFSET);
    BSL_Uint32ToByte(ctx->para->otsType[bottomLevel], bottomPrivKey + LMS_PRVKEY_OTS_TYPE_OFFSET);
    memcpy(bottomPrivKey + LMS_PRVKEY_I_OFFSET, ctx->levelI[bottomLevel], LMS_I_LEN);
    memcpy(bottomPrivKey + LMS_PRVKEY_SEED_OFFSET, ctx->levelSeed[bottomLevel], LMS_SEED_LEN);

    uint8_t *sigPtr = *sigPtrInOut;
    CRYPT_ConstData msgBuf = {message, messageLen};
    uint32_t bottomSigLen = (uint32_t)(*signatureLen - (size_t)(sigPtr - signature));
    LMS_SignatureBuffer sigBuf = {sigPtr, &bottomSigLen};
    LMS_TreeCache bottomCache = {ctx->lmsTrees[bottomLevel].cachedTree, ctx->lmsTrees[bottomLevel].cachedTreeSize,
                                 ctx->lmsTrees[bottomLevel].treeCacheValid};

    int32_t ret = LmsSignCached(&ctx->para->levelPara[bottomLevel], bottomPrivKey, &msgBuf, &sigBuf, &bottomCache);
    BSL_SAL_CleanseData(bottomPrivKey, sizeof(bottomPrivKey));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGN_FAIL);
        return CRYPT_HSS_SIGN_FAIL;
    }
    *sigPtrInOut = sigPtr + bottomSigLen;
    return CRYPT_SUCCESS;
}

int32_t HssTreeSign(uint8_t *signature, uint32_t *signatureLen, const uint8_t *message, uint32_t messageLen,
    const HssMultiTreeCtx *ctx)
{
    if (ctx->levels == 0 || ctx->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (*signatureLen < ctx->para->sigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    uint8_t *sigPtr = signature;
    uint32_t nspk = ctx->levels - 1;
    BSL_Uint32ToByte(nspk, sigPtr);
    sigPtr += HSS_SIG_NSPK_LEN;

    int32_t ret = HssSignIntermediateLayers(signature, &sigPtr, signatureLen, ctx, nspk);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = HssSignBottomLayer(signature, &sigPtr, signatureLen, message, messageLen, ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *signatureLen = (size_t)(sigPtr - signature);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Sign(CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
    uint32_t *sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint64_t counter;
    uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE];
    uint32_t leafIndex[HSS_LEVELS_ARRAY_SIZE];
    int32_t ret = HssSignValidateAndSetup(ctx, *sigLen, &counter, treeIndex, leafIndex);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t masterSeed[LMS_SEED_LEN];
    memcpy(masterSeed, ctx->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

    HssMultiTreeCtx treeCtx;
    ret = HssTreeInitContextWithSeeds(&treeCtx, &ctx->para, masterSeed, counter);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (uint32_t i = 0; i < ctx->para.levels; i++) {
        if (ctx->cachedTreeIndex[i] != treeCtx.treeIndices[i]) {
            ctx->treeCacheValid[i] = false;
            ctx->cachedTreeIndex[i] = treeCtx.treeIndices[i];
        }
        treeCtx.lmsTrees[i].cachedTree = &ctx->cachedTrees[i];
        treeCtx.lmsTrees[i].cachedTreeSize = &ctx->cachedTreeSizes[i];
        treeCtx.lmsTrees[i].treeCacheValid = &ctx->treeCacheValid[i];
    }

    BSL_Uint64ToByte(counter + 1, ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET);
    ctx->signatureIndex = counter + 1;

    uint32_t actualSigLen = *sigLen;
    ret = HssTreeSign(sig, &actualSigLen, msg, msgLen, &treeCtx);

    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
    BSL_SAL_CleanseData(treeCtx.levelSeed, sizeof(treeCtx.levelSeed));

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *sigLen = (uint32_t)actualSigLen;
    return CRYPT_SUCCESS;
}

static int32_t HSSCheckBasicParams(const CRYPT_HSS_Ctx *pubKey, const CRYPT_HSS_Ctx *prvKey)
{
    uint32_t pubLevels = BSL_ByteToUint32(pubKey->publicKey + HSS_PUBKEY_LEVELS_OFFSET);
    if (pubLevels != prvKey->para.levels) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    uint32_t pubLmsType = BSL_ByteToUint32(pubKey->publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET);
    uint32_t pubOtsType = BSL_ByteToUint32(pubKey->publicKey + HSS_PUBKEY_OTS_TYPE_OFFSET);
    if (pubLmsType != prvKey->para.lmsType[0] || pubOtsType != prvKey->para.otsType[0]) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t HSSVerifyRootHash(const CRYPT_HSS_Ctx *pubKey, const CRYPT_HSS_Ctx *prvKey, const uint8_t *rootI,
                                 const uint8_t *rootSeed)
{
    if (ConstTimeMemcmp(rootI, pubKey->publicKey + HSS_PUBKEY_I_OFFSET, LMS_I_LEN) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    LMS_Para lmsPara;
    int32_t ret = LmsParaInit(&lmsPara, prvKey->para.lmsType[0], prvKey->para.otsType[0]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t computedRoot[LMS_SHA256_N];
    ret = LmsComputeRoot(computedRoot, &lmsPara, rootI, rootSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    int32_t cmpRet = ConstTimeMemcmp(computedRoot, pubKey->publicKey + HSS_PUBKEY_ROOT_OFFSET, LMS_SHA256_N);
    BSL_SAL_CleanseData(computedRoot, sizeof(computedRoot));
    if (cmpRet == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_PAIRWISE_CHECK_FAIL);
        return CRYPT_HSS_PAIRWISE_CHECK_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t HSSKeyPairCheck(const CRYPT_HSS_Ctx *pubKey, const CRYPT_HSS_Ctx *prvKey)
{
    if (pubKey == NULL || prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->para.levels == 0 || prvKey->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pubKey->publicKey == NULL || prvKey->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    int32_t ret = HSSCheckBasicParams(pubKey, prvKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t masterSeed[LMS_SEED_LEN];
    memcpy(masterSeed, prvKey->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

    uint8_t rootI[LMS_I_LEN];
    uint8_t rootSeed[LMS_SEED_LEN];
    ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = HSSVerifyRootHash(pubKey, prvKey, rootI, rootSeed);
    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
    BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));
    BSL_SAL_CleanseData(rootI, sizeof(rootI));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t HSSPrvKeyCheck(const CRYPT_HSS_Ctx *prvKey)
{
    if (prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prvKey->privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Check(uint32_t checkType, const CRYPT_HSS_Ctx *pkey1, const CRYPT_HSS_Ctx *pkey2)
{
    switch (checkType) {
        case CRYPT_PKEY_CHECK_KEYPAIR:
            return HSSKeyPairCheck(pkey1, pkey2);
        case CRYPT_PKEY_CHECK_PRVKEY:
            return HSSPrvKeyCheck(pkey1);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

#endif /* HITLS_CRYPTO_HSS_LMS */
