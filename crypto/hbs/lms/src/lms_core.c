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
#ifdef HITLS_CRYPTO_LMS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "lms_local.h"
#include "lms_common.h"
#include "lms_tree.h"

/**
 * @ingroup lms
 * @brief Context for computing leaf node hash
 */
typedef struct {
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    uint32_t n; /**< Hash output length */
    const LmsFamilyHashFuncs *hashFuncs; /**< Hash function pointers */
} LmsLeafHashCtx;

/**
 * @ingroup lms
 * @brief Compute leaf node hash (RFC 8554 Algorithm 1)
 * @param leafHash [OUT] Output leaf hash
 * @param ctx      [IN]  Leaf hash context
 * @param r        [IN]  Node index
 * @param otsPubKey [IN] OTS public key
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsComputeLeafHash(uint8_t *leafHash, const LmsLeafHashCtx *ctx, uint32_t r, const uint8_t *otsPubKey)
{
    /* Create a temporary tree context for hLeaf function */
    LmsTreeCtx treeCtx = {.I = ctx->I, .n = ctx->n, .hashFuncs = ctx->hashFuncs};

    int32_t ret = ctx->hashFuncs->leafHash(&treeCtx, r, otsPubKey, leafHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Context for computing internal node hash
 */
typedef struct {
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    uint32_t r; /**< Node index */
    const uint8_t *leftChild; /**< Left child hash */
    const uint8_t *rightChild; /**< Right child hash */
    uint32_t n; /**< Hash output length */
    const LmsFamilyHashFuncs *hashFuncs; /**< Hash function pointers */
} LmsInternalHashCtx;

/**
 * @ingroup lms
 * @brief Context for writing LMS signature
 */
typedef struct {
    uint8_t *signature; /**< Output signature buffer */
    size_t *signatureLen; /**< Signature length pointer */
    const LMS_Para *para; /**< LMS parameters */
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    const uint8_t *seed; /**< Tree seed (32 bytes) */
    uint32_t q; /**< Leaf index */
    const uint8_t *message; /**< Message to sign */
    size_t messageLen; /**< Message length */
} LmsSignWriteCtx;

/**
 * @ingroup lms
 * @brief Parsed LMS signature information
 */
typedef struct {
    uint32_t lmsType; /**< LMS parameter set identifier */
    uint32_t otsType; /**< OTS parameter set identifier */
    uint32_t h; /**< Hash type */
    uint32_t n; /**< Hash output length */
    uint32_t height; /**< Tree height */
    uint32_t q; /**< Leaf index */
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    const uint8_t *expectedRoot; /**< Expected root hash from public key */
    const uint8_t *otsSig; /**< OTS signature portion */
    const uint8_t *authPath; /**< Authentication path */
} LmsSignatureInfo;

/**
 * @ingroup lms
 * @brief Context for validating authentication path
 */
typedef struct {
    uint8_t *currentHash; /**< Current hash being computed */
    const uint8_t *I; /**< Tree identifier (16 bytes) */
    uint32_t q; /**< Leaf index */
    const uint8_t *authPath; /**< Authentication path */
    uint32_t height; /**< Tree height */
    uint32_t n; /**< Hash output length */
    uint32_t numLeaves; /**< Number of leaves in tree */
    const LmsFamilyHashFuncs *hashFuncs; /**< Hash function pointers */
} LmsValidateAuthPathCtx;

/**
 * @ingroup lms
 * @brief Compute internal node hash (RFC 8554)
 * @param nodeHash [OUT] Output node hash
 * @param ctx      [IN]  Internal hash context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsComputeInternalHash(uint8_t *nodeHash, const LmsInternalHashCtx *ctx)
{
    /* Create a temporary tree context for hIntr function */
    LmsTreeCtx treeCtx = {.I = ctx->I, .n = ctx->n, .hashFuncs = ctx->hashFuncs};

    int32_t ret = ctx->hashFuncs->nodeHash(&treeCtx, ctx->r, ctx->leftChild, ctx->rightChild, nodeHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t LmsComputeRoot(uint8_t *root, const LMS_Para *para, const uint8_t *I, const uint8_t *seed)
{
    /* Wrapper function - use new tree operations */
    LmsTreeCtx treeCtx;
    int32_t ret = LmsTree_InitContext(&treeCtx, para, I, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsTree_ComputeRoot(root, &treeCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t LmsGenerateAuthPath(uint8_t *authPath, const LMS_Para *para, const uint8_t *I, const uint8_t *seed, uint32_t q)
{
    /* Wrapper function - use new tree operations */
    LmsTreeCtx treeCtx;
    int32_t ret = LmsTree_InitContext(&treeCtx, para, I, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsTree_GenerateAuthPath(authPath, &treeCtx, q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t LmsGenerateAuthPathCached(uint8_t *authPath, const LMS_Para *para, const LMS_TreeParams *treeParams, uint32_t q,
                                  LMS_TreeCache *cache)
{
    /* Wrapper function - use new tree operations */
    LmsTreeCtx treeCtx;
    int32_t ret = LmsTree_InitContext(&treeCtx, para, treeParams->I, treeParams->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Set cache in tree context */
    LmsTree_SetCache(&treeCtx, cache->tree, cache->size, cache->valid);

    ret = LmsTree_GenerateAuthPathCached(authPath, &treeCtx, q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t LmsKeyGen(void *libCtx, LMS_Para *para, uint8_t *publicKey, uint8_t *privateKey)
{
    uint8_t seed[LMS_SEED_LEN];
    uint8_t I[LMS_I_LEN];

    int32_t ret = CRYPT_RandEx(libCtx, seed, LMS_SEED_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_KEYGEN_FAIL);
        return CRYPT_LMS_KEYGEN_FAIL;
    }

    ret = CRYPT_RandEx(libCtx, I, LMS_I_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(seed, LMS_SEED_LEN);
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_KEYGEN_FAIL);
        return CRYPT_LMS_KEYGEN_FAIL;
    }

    uint8_t root[LMS_MAX_HASH];
    ret = LmsComputeRoot(root, para, I, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(seed, LMS_SEED_LEN);
        BSL_SAL_CleanseData(I, LMS_I_LEN);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // Format public key
    LmsPutBigendian(publicKey + LMS_PUBKEY_LMS_TYPE_OFFSET, para->lmsType, LMS_TYPE_LEN); // 4 bytes
    LmsPutBigendian(publicKey + LMS_PUBKEY_OTS_TYPE_OFFSET, para->otsType, LMS_TYPE_LEN); // 4 bytes
    memcpy(publicKey + LMS_PUBKEY_I_OFFSET, I, LMS_I_LEN);
    memcpy(publicKey + LMS_PUBKEY_ROOT_OFFSET, root, para->n);

    // Format private key
    LmsPutBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, 0, LMS_PRVKEY_INDEX_LEN); // 8 bytes
    LmsPutBigendian(privateKey + LMS_PRVKEY_LMS_TYPE_OFFSET, para->lmsType, LMS_TYPE_LEN); // 4 bytes
    LmsPutBigendian(privateKey + LMS_PRVKEY_OTS_TYPE_OFFSET, para->otsType, LMS_TYPE_LEN); // 4 bytes
    memcpy(privateKey + LMS_PRVKEY_I_OFFSET, I, LMS_I_LEN);
    memcpy(privateKey + LMS_PRVKEY_SEED_OFFSET, seed, LMS_SEED_LEN);

    BSL_SAL_CleanseData(seed, LMS_SEED_LEN);
    BSL_SAL_CleanseData(I, LMS_I_LEN);
    BSL_SAL_CleanseData(root, sizeof(root));

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Validate signing preconditions
 * @param para         [IN]     LMS parameters
 * @param privateKey   [IN]     Private key
 * @param signatureLen [IN/OUT] Signature length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsSignValidate(const LMS_Para *para, const uint8_t *privateKey, size_t *signatureLen)
{
    if (*signatureLen < para->sigLen) {
        *signatureLen = para->sigLen;
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    /* Guard the shift below: height >= 32 would otherwise invoke undefined behavior. */
    if (para->height > LMS_MAX_HEIGHT) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint64_t q = LmsGetBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, LMS_PRVKEY_INDEX_LEN);
    uint64_t numLeaves = 1ULL << para->height;

    if (q >= numLeaves) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_KEY_EXHAUSTED);
        return CRYPT_LMS_KEY_EXHAUSTED;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Write LMS signature to buffer
 * @param ctx [IN] Signature write context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsSignWriteSignature(const LmsSignWriteCtx *ctx)
{
    LMS_SeedDerive derive;
    int32_t ret = LmsSeedDeriveInit(&derive, ctx->I, ctx->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    LmsSeedDeriveSetQ(&derive, ctx->q);

    size_t offset = 0;
    LmsPutBigendian(ctx->signature + offset, ctx->q, LMS_Q_LEN);
    offset += LMS_Q_LEN;

    size_t otsSigLen = LmOtsGetSigLen(ctx->para->otsType);
    LMS_OutputBuffer sigBuf = {ctx->signature + offset, otsSigLen};
    LMS_InputBuffer msgBuf = {ctx->message, ctx->messageLen};
    ret = LmOtsSign(ctx->para->otsType, &derive, &ctx->para->hashFuncs, &msgBuf, &sigBuf);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += otsSigLen;

    LmsPutBigendian(ctx->signature + offset, ctx->para->lmsType, LMS_TYPE_LEN);
    offset += LMS_TYPE_LEN;

    ret = LmsGenerateAuthPath(ctx->signature + offset, ctx->para, ctx->I, ctx->seed, ctx->q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += ctx->para->height * ctx->para->n;

    *ctx->signatureLen = offset;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Write LMS signature to buffer with tree caching
 * @param ctx   [IN]     Signature write context
 * @param cache [IN/OUT] Tree cache structure
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsSignWriteSignatureCached(const LmsSignWriteCtx *ctx, LMS_TreeCache *cache)
{
    LMS_SeedDerive derive;
    int32_t ret = LmsSeedDeriveInit(&derive, ctx->I, ctx->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    LmsSeedDeriveSetQ(&derive, ctx->q);

    size_t offset = 0;
    LmsPutBigendian(ctx->signature + offset, ctx->q, LMS_Q_LEN);
    offset += LMS_Q_LEN;

    size_t otsSigLen = LmOtsGetSigLen(ctx->para->otsType);
    LMS_OutputBuffer sigBuf = {ctx->signature + offset, otsSigLen};
    LMS_InputBuffer msgBuf = {ctx->message, ctx->messageLen};
    ret = LmOtsSign(ctx->para->otsType, &derive, &ctx->para->hashFuncs, &msgBuf, &sigBuf);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += otsSigLen;

    LmsPutBigendian(ctx->signature + offset, ctx->para->lmsType, LMS_TYPE_LEN);
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

int32_t LmsSign(const LMS_Para *para, uint8_t *privateKey, const LMS_InputBuffer *message,
                LMS_SignatureBuffer *signature)
{
    int32_t ret = LmsSignValidate(para, privateKey, signature->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint64_t q = LmsGetBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, LMS_PRVKEY_INDEX_LEN);
    const uint8_t *I = privateKey + LMS_PRVKEY_I_OFFSET;
    const uint8_t *seed = privateKey + LMS_PRVKEY_SEED_OFFSET;

    /* Advance q in the private key BEFORE writing the signature.  If the OTS
     * sign or auth-path generation below fails, the caller might retry; a retry
     * that reused the same q with a different message would let an attacker
     * recover the LM-OTS private key.  Consume the index first (fail-closed). */
    LmsPutBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, q + LMS_SIGNATURE_INDEX_INCREMENT, LMS_PRVKEY_INDEX_LEN);

    LmsSignWriteCtx ctx = {signature->data, signature->len, para, I, seed, (uint32_t)q, message->data, message->len};
    ret = LmsSignWriteSignature(&ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

int32_t LmsSignCached(const LMS_Para *para, uint8_t *privateKey, const LMS_InputBuffer *message,
                      LMS_SignatureBuffer *signature, LMS_TreeCache *cache)
{
    int32_t ret = LmsSignValidate(para, privateKey, signature->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint64_t q = LmsGetBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, LMS_PRVKEY_INDEX_LEN);
    const uint8_t *I = privateKey + LMS_PRVKEY_I_OFFSET;
    const uint8_t *seed = privateKey + LMS_PRVKEY_SEED_OFFSET;

    /* See LmsSign: advance q before signing so a retry after partial failure
     * cannot reuse the same one-time index. */
    LmsPutBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, q + LMS_SIGNATURE_INDEX_INCREMENT, LMS_PRVKEY_INDEX_LEN);

    LmsSignWriteCtx ctx = {signature->data, signature->len, para, I, seed, (uint32_t)q, message->data, message->len};
    ret = LmsSignWriteSignatureCached(&ctx, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Parse and validate signature format
 * @param publicKey    [IN]  Public key
 * @param signature    [IN]  Signature to parse
 * @param signatureLen [IN]  Signature length
 * @param info         [OUT] Parsed signature information
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsValidateParseSignature(const uint8_t *publicKey, const uint8_t *signature, size_t signatureLen,
                                         LmsSignatureInfo *info)
{
    info->lmsType = (uint32_t)LmsGetBigendian(publicKey + LMS_PUBKEY_LMS_TYPE_OFFSET, LMS_TYPE_LEN);
    info->otsType = (uint32_t)LmsGetBigendian(publicKey + LMS_PUBKEY_OTS_TYPE_OFFSET, LMS_TYPE_LEN);
    info->I = publicKey + LMS_PUBKEY_I_OFFSET;
    info->expectedRoot = publicKey + LMS_PUBKEY_ROOT_OFFSET;

    int32_t ret = LmsLookupParamSet(info->lmsType, &info->h, &info->n, &info->height);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (info->n == 0 || info->n > LMS_MAX_HASH) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    size_t otsSigLen = LmOtsGetSigLen(info->otsType);
    if (otsSigLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    size_t expectedSigLen = LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN + info->height * info->n;

    if (signatureLen != expectedSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    size_t offset = 0;
    info->q = (uint32_t)LmsGetBigendian(signature + offset, LMS_Q_LEN);
    offset += LMS_Q_LEN;

    info->otsSig = signature + offset;
    offset += otsSigLen;

    uint32_t sigLmsType = (uint32_t)LmsGetBigendian(signature + offset, LMS_TYPE_LEN);
    offset += LMS_TYPE_LEN;

    if (sigLmsType != info->lmsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }

    info->authPath = signature + offset;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Validate authentication path and compute root
 * @param ctx [IN] Validation context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsValidateAuthPath(const LmsValidateAuthPathCtx *ctx)
{
    uint8_t leftChild[LMS_MAX_HASH];
    uint8_t rightChild[LMS_MAX_HASH];
    uint32_t nodeNum = ctx->numLeaves + ctx->q;

    for (uint32_t level = 0; level < ctx->height; level++) {
        uint32_t parentNode = nodeNum / LMS_LEFT_CHILD_MULTIPLIER;

        if (nodeNum % LMS_LEFT_CHILD_MULTIPLIER == LMS_ROOT_NODE_INDEX) {
            memcpy(leftChild, ctx->authPath + level * ctx->n, ctx->n);
            memcpy(rightChild, ctx->currentHash, ctx->n);
        } else {
            memcpy(leftChild, ctx->currentHash, ctx->n);
            memcpy(rightChild, ctx->authPath + level * ctx->n, ctx->n);
        }

        LmsInternalHashCtx hashCtx = {ctx->I, parentNode, leftChild, rightChild, ctx->n, ctx->hashFuncs};
        int32_t ret = LmsComputeInternalHash(ctx->currentHash, &hashCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        nodeNum = parentNode;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Verify OTS signature and compute leaf hash
 * @param currentHash [OUT] Output leaf hash
 * @param info        [IN]  Signature information
 * @param message     [IN]  Message that was signed
 * @param messageLen  [IN]  Message length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsVerifyOtsAndComputeLeaf(uint8_t *currentHash, const LmsSignatureInfo *info, const uint8_t *message,
                                          size_t messageLen)
{
    /* info->height is guaranteed valid by LmsLookupParamSet (returns only {5,10,15,20,25}) */
    uint32_t numLeaves = (uint32_t)(1ULL << info->height);
    if (info->q >= numLeaves) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_LEAF_INDEX);
        return CRYPT_LMS_INVALID_LEAF_INDEX;
    }

    uint8_t computedOtsPubKey[LMS_MAX_HASH];
    size_t otsSigLen = LmOtsGetSigLen(info->otsType);
    LMS_OtsValidateCtx validateCtx = {info->I, info->q, info->otsType};
    LMS_InputBuffer msgBuf = {message, messageLen};
    LMS_InputBuffer sigBuf = {info->otsSig, otsSigLen};

    const LmsFamilyHashFuncs *hashFuncs = LmsGetHashFuncs(info->lmsType);
    if (hashFuncs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }
    int32_t ret = LmOtsValidateSignature(computedOtsPubKey, &validateCtx, hashFuncs, &msgBuf, &sigBuf);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }

    uint32_t nodeNum = numLeaves + info->q;
    LmsLeafHashCtx leafCtx = {info->I, info->n, hashFuncs};
    return LmsComputeLeafHash(currentHash, &leafCtx, nodeNum, computedOtsPubKey);
}

int32_t LmsValidateSignature(const uint8_t *publicKey, const uint8_t *message, size_t messageLen,
                             const uint8_t *signature, size_t signatureLen)
{
    LmsSignatureInfo info;
    int32_t ret = LmsValidateParseSignature(publicKey, signature, signatureLen, &info);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t currentHash[LMS_MAX_HASH];
    ret = LmsVerifyOtsAndComputeLeaf(currentHash, &info, message, messageLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* info.height already validated by LmsLookupParamSet in LmsValidateParseSignature */
    uint32_t numLeaves = (uint32_t)(1ULL << info.height);
    const LmsFamilyHashFuncs *hashFuncs = LmsGetHashFuncs(info.lmsType);
    if (hashFuncs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }
    LmsValidateAuthPathCtx ctx = {currentHash, info.I, info.q,    info.authPath,
                                  info.height, info.n, numLeaves, hashFuncs};
    ret = LmsValidateAuthPath(&ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t diff = 0;
    for (uint32_t i = 0; i < info.n; i++) {
        diff |= currentHash[i] ^ info.expectedRoot[i];
    }
    if (diff != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

uint64_t LmsGetRemainingSignatures(const uint8_t *privateKey, uint32_t height)
{
    if (height > LMS_MAX_HEIGHT) {
        return 0;
    }

    uint64_t currentIndex = LmsGetBigendian(privateKey + LMS_PRVKEY_INDEX_OFFSET, LMS_PRVKEY_INDEX_LEN);
    uint64_t maxSignatures = (uint64_t)1 << height;

    if (currentIndex >= maxSignatures) {
        return 0;
    }

    return maxSignatures - currentIndex;
}

#endif /* HITLS_CRYPTO_LMS */
