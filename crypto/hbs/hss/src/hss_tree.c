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
#ifdef HITLS_CRYPTO_HSS_LMS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "hss_tree.h"
#include "hss_local.h"
#include "lms_internal.h"

#if defined(HITLS_CRYPTO_HSS_SIGN)

/**
 * @ingroup hss_tree
 * @brief Initialize HSS multi-tree context
 */
int32_t HssTreeInitContext(HssMultiTreeCtx *ctx, const HSS_Para *para, uint64_t globalIndex)
{
    ctx->levels = para->levels;
    ctx->globalIndex = globalIndex;
    ctx->para = para;

    /* Calculate tree and leaf indices for each level */
    int32_t ret = HssTreeCalculateIndices(ctx->treeIndices, ctx->leafIndices, globalIndex, para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * @ingroup hss_tree
 * @brief Initialize HSS multi-tree context with seeds
 *
 * Generates all level seeds and initializes tree contexts.
 */
int32_t HssTreeInitContextWithSeeds(HssMultiTreeCtx *ctx, const HSS_Para *para, const uint8_t masterSeed[LMS_SEED_LEN],
    uint64_t globalIndex)
{
    /* Initialize basic context */
    int32_t ret = HssTreeInitContext(ctx, para, globalIndex);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Generate all level seeds using existing HSS functions */
    ret = HssGenerateAllSeeds(ctx->levelI, ctx->levelSeed, masterSeed, ctx->treeIndices, para->levels);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Initialize LMS tree contexts and unified HBS tree contexts for each level */
    for (uint32_t i = 0; i < para->levels; i++) {
        /* LmsTreeCtx: holds LMS-specific fields including cache pointers */
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

/**
 * @ingroup hss_tree
 * @brief Calculate tree and leaf indices from global index
 */
int32_t HssTreeCalculateIndices(uint64_t treeIndices[HSS_LEVELS_ARRAY_SIZE],
    uint32_t leafIndices[HSS_LEVELS_ARRAY_SIZE], uint64_t globalIndex, const HSS_Para *para)
{
    if (para->levels == 0 || para->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }

    /* Decompose global index into per-level indices */
    uint64_t remaining = globalIndex;

    for (int32_t level = para->levels - 1; level >= 0; level--) {
        uint64_t numLeaves = 1ULL << para->levelPara[level].height;
        leafIndices[level] = (uint32_t)(remaining % numLeaves);
        remaining /= numLeaves;
        treeIndices[level] = remaining;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss_tree
 * @brief Generate signed public key (parent signs child)
 *
 * This is a wrapper around the existing HssGenerateSignedPubKey function.
 */
int32_t HssTreeGenerateSignedPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx,
    const HssTreeContext *parent, const HssTreeContext *child, LMS_TreeCache *cache)
{
    return HssGenerateSignedPubKey(output, signCtx, parent, child, cache);
}

static int32_t HssSignIntermediateLayers(uint8_t *signature, uint8_t **sigPtrInOut, const size_t *signatureLen,
    const HssMultiTreeCtx *ctx, uint32_t nspk)
{
    uint8_t *sigPtr = *sigPtrInOut;
    for (uint32_t i = 0; i < nspk; i++) {
        HssTreeContext parent = {ctx->levelI[i], ctx->levelSeed[i], ctx->leafIndices[i]};
        HssTreeContext child = {ctx->levelI[i + 1], ctx->levelSeed[i + 1], 0};
        HssSignContext signCtx = {i, i + 1, ctx->para};
        LMS_TreeCache cache = {ctx->lmsTrees[i].cachedTree, ctx->lmsTrees[i].cachedTreeSize,
                               ctx->lmsTrees[i].treeCacheValid};

        size_t remainingLen = *signatureLen - (size_t)(sigPtr - signature);
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

static int32_t HssSignBottomLayer(uint8_t *signature, uint8_t **sigPtrInOut, const size_t *signatureLen,
    const uint8_t *message, size_t messageLen, const HssMultiTreeCtx *ctx)
{
    uint32_t bottomLevel = ctx->levels - 1;
    uint8_t bottomPrivKey[LMS_PRVKEY_MAX_LEN];

    BSL_Uint64ToByte(ctx->leafIndices[bottomLevel], bottomPrivKey + LMS_PRVKEY_INDEX_OFFSET);
    BSL_Uint32ToByte(ctx->para->lmsType[bottomLevel], bottomPrivKey + LMS_PRVKEY_LMS_TYPE_OFFSET);
    BSL_Uint32ToByte(ctx->para->otsType[bottomLevel], bottomPrivKey + LMS_PRVKEY_OTS_TYPE_OFFSET);
    memcpy(bottomPrivKey + LMS_PRVKEY_I_OFFSET, ctx->levelI[bottomLevel], LMS_I_LEN);
    memcpy(bottomPrivKey + LMS_PRVKEY_SEED_OFFSET, ctx->levelSeed[bottomLevel], LMS_SEED_LEN);

    uint8_t *sigPtr = *sigPtrInOut;
    LMS_InputBuffer msgBuf = {message, messageLen};
    size_t bottomSigLen = *signatureLen - (size_t)(sigPtr - signature);
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

/**
 * @ingroup hss_tree
 * @brief Sign message with HSS multi-tree
 */
int32_t HssTreeSign(uint8_t *signature, size_t *signatureLen, const uint8_t *message, size_t messageLen,
    const HssMultiTreeCtx *ctx)
{
    if (ctx->levels == 0 || ctx->levels > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (*signatureLen < ctx->para->sigLen) {
        *signatureLen = ctx->para->sigLen;
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

#endif /* HITLS_CRYPTO_HSS_SIGN */

#if defined(HITLS_CRYPTO_HSS_VERIFY)

/**
 * @ingroup hss_tree
 * @brief Verify HSS signature
 *
 * Verifies an HSS signature by validating all signed public keys and the bottom-level signature.
 */
int32_t HssTreeVerify(const HSS_Para *para, const uint8_t *publicKey, const uint8_t *message, size_t messageLen,
    const uint8_t *signature, size_t signatureLen)
{
    /* Parse the signature using existing HSS parsing logic */
    HSS_ParsedSig parsed = {0};
    int32_t ret = HssParseSignature(&parsed, para, signature, signatureLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Extract LMS public key from HSS public key (skip levels field) */
    uint32_t topPubKeyLen = para->levelPara[0].pubKeyLen;
    uint8_t currentPubKey[LMS_PUBKEY_MAX_LEN];
    memcpy(currentPubKey, publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET, topPubKeyLen);

    /* Verify each signed public key in the chain */
    for (uint32_t i = 0; i < parsed.nspk; i++) {
        const uint8_t *signedPubKey = parsed.signedPubKeys[i];
        size_t lmsSigLen = parsed.lmsSigLens[i];
        const uint8_t *lmsSig = signedPubKey;
        const uint8_t *childPubKey = signedPubKey + lmsSigLen;

        /* Strictly validate child public key types against the preset configuration */
        uint32_t childLmsType = BSL_ByteToUint32(childPubKey + LMS_PUBKEY_LMS_TYPE_OFFSET);
        uint32_t childOtsType = BSL_ByteToUint32(childPubKey + LMS_PUBKEY_OTS_TYPE_OFFSET);
        if (childLmsType != para->levelPara[i + 1].lmsType || childOtsType != para->levelPara[i + 1].otsType) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
            return CRYPT_HSS_VERIFY_FAIL;
        }

        /* Verify: parent signs child's public key */
        uint32_t childPubKeyLen = para->levelPara[i + 1].pubKeyLen;
        ret = LmsValidateSignature(currentPubKey, childPubKey, childPubKeyLen, lmsSig, lmsSigLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
            return CRYPT_HSS_VERIFY_FAIL;
        }

        /* Move to next level - child becomes the new current public key */
        memcpy(currentPubKey, childPubKey, childPubKeyLen);
    }

    /* Verify the bottom-level signature on the actual message */
    ret = LmsValidateSignature(currentPubKey, message, messageLen, parsed.bottomSig, parsed.bottomSigLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_VERIFY_FAIL);
        return CRYPT_HSS_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_HSS_VERIFY */

#endif /* HITLS_CRYPTO_HSS_LMS */
