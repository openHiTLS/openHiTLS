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
#include "crypt_types.h"
#include "lms_internal.h"

typedef struct {
    const uint8_t *I;
    uint32_t n;
    const LmsFamilyHashFuncs *hashFuncs;
} LmsLeafHashCtx;

typedef struct {
    const uint8_t *I;
    uint32_t r;
    const uint8_t *leftChild;
    const uint8_t *rightChild;
    uint32_t n;
    const LmsFamilyHashFuncs *hashFuncs;
} LmsInternalHashCtx;

typedef struct {
    uint32_t lmsType;
    uint32_t otsType;
    uint32_t h;
    uint32_t n;
    uint32_t height;
    uint32_t q;
    const uint8_t *I;
    const uint8_t *expectedRoot;
    const uint8_t *otsSig;
    const uint8_t *authPath;
} LmsSignatureInfo;

typedef struct {
    uint8_t *currentHash;
    const uint8_t *I;
    uint32_t q;
    const uint8_t *authPath;
    uint32_t height;
    uint32_t n;
    uint32_t numLeaves;
    const LmsFamilyHashFuncs *hashFuncs;
} LmsValidateAuthPathCtx;

static int32_t LmOtsValidateSignature(uint8_t *computedPubKey, const LMS_OtsValidateCtx *ctx,
    const LmsFamilyHashFuncs *hashFuncs, const CRYPT_ConstData *message, const CRYPT_ConstData *signature);

static int32_t LmsComputeLeafHash(uint8_t *leafHash, const LmsLeafHashCtx *ctx, uint32_t r, const uint8_t *otsPubKey)
{
    LmsTreeCtx treeCtx = {.I = ctx->I, .n = ctx->n, .hashFuncs = ctx->hashFuncs};

    int32_t ret = ctx->hashFuncs->leafHash(&treeCtx, r, otsPubKey, leafHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t LmsComputeInternalHash(uint8_t *nodeHash, const LmsInternalHashCtx *ctx)
{
    LmsTreeCtx treeCtx = {.I = ctx->I, .n = ctx->n, .hashFuncs = ctx->hashFuncs};

    int32_t ret = ctx->hashFuncs->nodeHash(&treeCtx, ctx->r, ctx->leftChild, ctx->rightChild, nodeHash);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t LmsValidateParseSignature(const uint8_t *publicKey, const uint8_t *signature, uint32_t signatureLen,
    LmsSignatureInfo *info)
{
    info->lmsType = BSL_ByteToUint32(publicKey + LMS_PUBKEY_LMS_TYPE_OFFSET);
    info->otsType = BSL_ByteToUint32(publicKey + LMS_PUBKEY_OTS_TYPE_OFFSET);
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

    uint32_t otsSigLen = LmOtsGetSigLen(info->otsType);
    if (otsSigLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }
    uint32_t expectedSigLen = LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN + info->height * info->n;

    if (signatureLen != expectedSigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    uint32_t offset = 0;
    info->q = BSL_ByteToUint32(signature + offset);
    offset += LMS_Q_LEN;

    info->otsSig = signature + offset;
    offset += otsSigLen;

    uint32_t sigLmsType = BSL_ByteToUint32(signature + offset);
    offset += LMS_TYPE_LEN;

    if (sigLmsType != info->lmsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }

    info->authPath = signature + offset;
    return CRYPT_SUCCESS;
}

static int32_t LmsValidateAuthPath(const LmsValidateAuthPathCtx *ctx)
{
    uint8_t leftChild[LMS_MAX_HASH];
    uint8_t rightChild[LMS_MAX_HASH];
    uint32_t nodeNum = ctx->numLeaves + ctx->q;
    int32_t ret = CRYPT_SUCCESS;

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
        ret = LmsComputeInternalHash(ctx->currentHash, &hashCtx);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto cleanup;
        }

        nodeNum = parentNode;
    }

cleanup:
    BSL_SAL_CleanseData(leftChild, sizeof(leftChild));
    BSL_SAL_CleanseData(rightChild, sizeof(rightChild));
    return ret;
}

static int32_t LmsVerifyOtsAndComputeLeaf(uint8_t *currentHash, const LmsSignatureInfo *info,
    const LmsFamilyHashFuncs *hashFuncs, const uint8_t *message, uint32_t messageLen)
{
    uint32_t numLeaves = (uint32_t)(1ULL << info->height);
    if (info->q >= numLeaves) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_LEAF_INDEX);
        return CRYPT_LMS_INVALID_LEAF_INDEX;
    }

    uint8_t computedOtsPubKey[LMS_MAX_HASH];
    uint32_t otsSigLen = LmOtsGetSigLen(info->otsType);
    LMS_OtsValidateCtx validateCtx = {info->I, info->q, info->otsType};
    CRYPT_ConstData msgBuf = {message, messageLen};
    CRYPT_ConstData sigBuf = {info->otsSig, otsSigLen};

    int32_t ret = LmOtsValidateSignature(computedOtsPubKey, &validateCtx, hashFuncs, &msgBuf, &sigBuf);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }

    uint32_t nodeNum = numLeaves + info->q;
    LmsLeafHashCtx leafCtx = {info->I, info->n, hashFuncs};
    ret = LmsComputeLeafHash(currentHash, &leafCtx, nodeNum, computedOtsPubKey);
    BSL_SAL_CleanseData(computedOtsPubKey, sizeof(computedOtsPubKey));
    return ret;
}

int32_t LmsValidateSignature(const uint8_t *publicKey, const uint8_t *message, uint32_t messageLen,
    const uint8_t *signature, uint32_t signatureLen)
{
    LmsSignatureInfo info;
    int32_t ret = LmsValidateParseSignature(publicKey, signature, signatureLen, &info);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    const LmsFamilyHashFuncs *hashFuncs = LmsFindHashFuncs(info.lmsType);
    if (hashFuncs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }

    uint8_t currentHash[LMS_MAX_HASH];
    ret = LmsVerifyOtsAndComputeLeaf(currentHash, &info, hashFuncs, message, messageLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(currentHash, sizeof(currentHash));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t numLeaves = (uint32_t)(1ULL << info.height);
    LmsValidateAuthPathCtx ctx = {currentHash, info.I, info.q, info.authPath,
                                  info.height, info.n, numLeaves, hashFuncs};
    ret = LmsValidateAuthPath(&ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(currentHash, sizeof(currentHash));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t diff = 0;
    for (uint32_t i = 0; i < info.n; i++) {
        diff |= currentHash[i] ^ info.expectedRoot[i];
    }

    BSL_SAL_CleanseData(currentHash, sizeof(currentHash));

    if (diff != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_VERIFY_FAIL);
        return CRYPT_LMS_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t LmOtsValidateParams(const uint8_t *signature, uint32_t signatureLen, uint32_t expectedOtsType,
    LmOtsParams *params)
{
    if (signatureLen < LMS_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    uint32_t paramSet = BSL_ByteToUint32(signature);
    if (paramSet != expectedOtsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    int32_t ret = LmOtsLookupParamSet(paramSet, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (signatureLen != LMS_TYPE_LEN + params->n * (params->p + 1)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    return CRYPT_SUCCESS;
}

static int32_t LmOtsValidateChains(uint8_t *chains, const LmsOtsCtx *ctx, const uint8_t *Q, const uint8_t *y)
{
    uint8_t tmp[LMS_MAX_HASH];
    uint32_t maxDigit = (1 << ctx->w) - 1;

    for (uint32_t i = 0; i < ctx->p; i++) {
        memcpy(tmp, y + i * ctx->n, ctx->n);

        uint32_t a = LmOtsCoef(Q, i, ctx->w);
        uint32_t steps = maxDigit - a;
        int32_t ret = LmOtsChain(tmp, a, steps, ctx, i);
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

static int32_t LmOtsValidateSignature(uint8_t *computedPubKey, const LMS_OtsValidateCtx *ctx,
    const LmsFamilyHashFuncs *hashFuncs, const CRYPT_ConstData *message, const CRYPT_ConstData *signature)
{
    LmOtsParams params;
    int32_t ret = LmOtsValidateParams(signature->data, signature->len, ctx->expectedOtsType, &params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    const uint8_t *C = signature->data + LMS_TYPE_LEN;
    const uint8_t *y = C + params.n;

    uint8_t Q[LMS_MAX_HASH + LMS_CHECKSUM_LEN];
    LmsOtsCtx otsCtx = {ctx->I, ctx->q, params.n, params.w, params.p, params.ls, hashFuncs};
    ret = LmOtsComputeQ(Q, &otsCtx, C, message->data, message->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t chainsLen = params.p * params.n;
    uint8_t *chains = BSL_SAL_Malloc(chainsLen);
    if (chains == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmOtsValidateChains(chains, &otsCtx, Q, y);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ClearFree(chains, chainsLen);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = hashFuncs->pkCompress(&otsCtx, chains, computedPubKey);
    BSL_SAL_ClearFree(chains, chainsLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif /* HITLS_CRYPTO_HSS_LMS */
