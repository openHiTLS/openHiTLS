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
#ifdef HITLS_CRYPTO_HSS

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "hss_local.h"
#include "hss_tree.h"

/**
 * @ingroup hss
 * @brief Generate all cryptographic keys for HSS
 * @param rootI      [OUT] Root tree identifier (16 bytes)
 * @param rootSeed   [OUT] Root tree seed (32 bytes)
 * @param rootHash   [OUT] Root tree hash (32 bytes)
 * @param masterSeed [OUT] Master seed (32 bytes)
 * @param levelPara  [IN]  Level 0 LMS parameters
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssGenerateKeys(void *libCtx, uint8_t rootI[LMS_I_LEN], uint8_t rootSeed[LMS_SEED_LEN],
                               uint8_t rootHash[LMS_SHA256_N], uint8_t masterSeed[LMS_SEED_LEN],
                               const LMS_Para *levelPara)
{
    int32_t ret = CRYPT_RandEx(libCtx, masterSeed, LMS_SEED_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_KEYGEN_FAIL);
        return CRYPT_HSS_KEYGEN_FAIL;
    }

    ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = LmsComputeRoot(rootHash, levelPara, rootI, rootSeed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_KEYGEN_FAIL);
        return CRYPT_HSS_KEYGEN_FAIL;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Format HSS public key
 * @param publicKey [OUT] Public key buffer (60 bytes)
 * @param para      [IN]  HSS parameters
 * @param rootI     [IN]  Root tree identifier (16 bytes)
 * @param rootHash  [IN]  Root tree hash (32 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssFormatPublicKey(uint8_t *publicKey, const HSS_Para *para, const uint8_t *rootI,
                                  const uint8_t *rootHash)
{
    LmsPutBigendian(publicKey + HSS_PUBKEY_LEVELS_OFFSET, para->levels, HSS_SIG_NSPK_LEN);
    LmsPutBigendian(publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET, para->lmsType[0], HSS_SIG_NSPK_LEN);
    LmsPutBigendian(publicKey + HSS_PUBKEY_OTS_TYPE_OFFSET, para->otsType[0], HSS_SIG_NSPK_LEN);
    memcpy(publicKey + HSS_PUBKEY_I_OFFSET, rootI, LMS_I_LEN);
    memcpy(publicKey + HSS_PUBKEY_ROOT_OFFSET, rootHash, LMS_SHA256_N);
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Format HSS private key
 * @param privateKey [OUT] Private key buffer (48 bytes)
 * @param para       [IN]  HSS parameters
 * @param masterSeed [IN]  Master seed (32 bytes)
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssFormatPrivateKey(uint8_t *privateKey, const HSS_Para *para, const uint8_t *masterSeed)
{
    LmsPutBigendian(privateKey + HSS_PRVKEY_COUNTER_OFFSET, 0, HSS_PRVKEY_COUNTER_LEN);

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

/* Ensure public and private key buffers are allocated in the HSS context.
 * On any failure, roll back the publicKey we may have just allocated so the
 * ctx never observes a half-initialized state (publicKey set but privateKey
 * NULL, with publicKey still zero-filled because HssFormatPublicKey runs
 * after this helper). Mirrors the cleanup done by CRYPT_LMS_Gen. */
static int32_t HssAllocKeyBuffers(CRYPT_HSS_Ctx *ctx)
{
    bool publicKeyOwnedHere = false;
    if (ctx->publicKey == NULL) {
        ctx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PUBKEY_LEN);
        if (ctx->publicKey == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        publicKeyOwnedHere = true;
    }
    if (ctx->privateKey == NULL) {
        ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);
        if (ctx->privateKey == NULL) {
            if (publicKeyOwnedHere) {
                BSL_SAL_FREE(ctx->publicKey);
                ctx->publicKey = NULL;
            }
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Gen(CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para.pubKeyLen == 0) {
        int32_t ret = HssParaInit(&ctx->para, ctx->para.levels, ctx->para.lmsType, ctx->para.otsType);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    uint8_t masterSeed[LMS_SEED_LEN];
    uint8_t rootI[LMS_I_LEN];
    uint8_t rootSeed[LMS_SEED_LEN];
    uint8_t rootHash[LMS_SHA256_N];

    int32_t ret = HssGenerateKeys(ctx->libCtx, rootI, rootSeed, rootHash, masterSeed, &ctx->para.levelPara[0]);
    if (ret != CRYPT_SUCCESS) {
        goto CLEANUP;
    }

    ret = HssAllocKeyBuffers(ctx);
    if (ret != CRYPT_SUCCESS) {
        goto CLEANUP;
    }

    HssFormatPublicKey(ctx->publicKey, &ctx->para, rootI, rootHash);
    ret = HssFormatPrivateKey(ctx->privateKey, &ctx->para, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        goto CLEANUP;
    }

    ctx->signatureIndex = 0;
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        ctx->treeCacheValid[i] = false;
        ctx->cachedTreeIndex[i] = 0;
    }

CLEANUP:
    /* Cleanse every stack buffer that held key-derivation output, even those
     * that ultimately become public (rootI, rootHash) — matches LmsKeyGen's
     * defensive convention so stale crypto state doesn't linger on the stack
     * for the lifetime of the call frame. */
    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
    BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));
    BSL_SAL_CleanseData(rootI, sizeof(rootI));
    BSL_SAL_CleanseData(rootHash, sizeof(rootHash));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * @ingroup hss
 * @brief Create child tree public key
 * @param childPubKey [OUT] Child public key buffer (56 bytes)
 * @param signCtx     [IN]  Signing context
 * @param child       [IN]  Child tree context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssCreateChildPubKey(uint8_t childPubKey[LMS_PUBKEY_LEN], const HssSignContext *signCtx,
                                    const HssTreeContext *child)
{
    uint8_t childRoot[32];
    int32_t ret = LmsComputeRoot(childRoot, &signCtx->para->levelPara[signCtx->childLevel], child->I, child->seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    LmsPutBigendian(childPubKey + LMS_PUBKEY_LMS_TYPE_OFFSET, signCtx->para->lmsType[signCtx->childLevel],
                    HSS_SIG_NSPK_LEN);
    LmsPutBigendian(childPubKey + LMS_PUBKEY_OTS_TYPE_OFFSET, signCtx->para->otsType[signCtx->childLevel],
                    HSS_SIG_NSPK_LEN);
    memcpy(childPubKey + LMS_PUBKEY_I_OFFSET, child->I, LMS_I_LEN);
    memcpy(childPubKey + LMS_PUBKEY_ROOT_OFFSET, childRoot, LMS_SHA256_N);
    BSL_SAL_CleanseData(childRoot, sizeof(childRoot));
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Sign child public key with parent key
 * @param output       [OUT]    Output signature buffer
 * @param signCtx      [IN]     Signing context
 * @param parent       [IN]     Parent tree context
 * @param childPubKey  [IN]     Child public key (56 bytes)
 * @param cache        [IN/OUT] Tree cache for parent level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssSignChildPubKey(HSS_OutputBuffer *output, const HssSignContext *signCtx, const HssTreeContext *parent,
                                  const uint8_t childPubKey[LMS_PUBKEY_LEN], LMS_TreeCache *cache)
{
    uint8_t parentPrivKey[LMS_PRVKEY_LEN];
    LmsPutBigendian(parentPrivKey + LMS_PRVKEY_INDEX_OFFSET, parent->leafIndex, LMS_PRVKEY_INDEX_LEN);
    LmsPutBigendian(parentPrivKey + LMS_PRVKEY_LMS_TYPE_OFFSET, signCtx->para->lmsType[signCtx->parentLevel],
                    HSS_SIG_NSPK_LEN);
    LmsPutBigendian(parentPrivKey + LMS_PRVKEY_OTS_TYPE_OFFSET, signCtx->para->otsType[signCtx->parentLevel],
                    HSS_SIG_NSPK_LEN);
    memcpy(parentPrivKey + LMS_PRVKEY_I_OFFSET, parent->I, LMS_I_LEN);
    memcpy(parentPrivKey + LMS_PRVKEY_SEED_OFFSET, parent->seed, LMS_SEED_LEN);

    LMS_InputBuffer msgBuf = {childPubKey, LMS_PUBKEY_LEN};
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
    uint8_t childPubKey[LMS_PUBKEY_LEN];
    int32_t ret = HssCreateChildPubKey(childPubKey, signCtx, child);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    size_t parentSigLen = signCtx->para->levelPara[signCtx->parentLevel].sigLen;
    if (*output->len < parentSigLen + LMS_PUBKEY_LEN) {
        BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    /* Write parent signature directly into output buffer (no intermediate allocation) */
    HSS_OutputBuffer sigOutput = {output->data, &parentSigLen};
    ret = HssSignChildPubKey(&sigOutput, signCtx, parent, childPubKey, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Append child public key after the parent signature */
    if (LMS_PUBKEY_LEN > *output->len - parentSigLen) {
        BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }
    memcpy(output->data + parentSigLen, childPubKey, LMS_PUBKEY_LEN);
    *output->len = parentSigLen + LMS_PUBKEY_LEN;
    BSL_SAL_CleanseData(childPubKey, sizeof(childPubKey));
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Message buffer structure
 */
typedef struct {
    const uint8_t *data; /**< Message data */
    uint32_t len; /**< Message length */
} HssMessage;

/**
 * @ingroup hss
 * @brief Generate all level seeds from master seed
 * @param levelI     [OUT] Tree identifiers for each level
 * @param levelSeed  [OUT] Tree seeds for each level
 * @param masterSeed [IN]  Master seed (32 bytes)
 * @param treeIndex  [IN]  Tree indices for each level
 * @param levels     [IN]  Number of levels
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t HssGenerateAllSeeds(uint8_t levelI[HSS_LEVELS_ARRAY_SIZE][LMS_I_LEN],
                            uint8_t levelSeed[HSS_LEVELS_ARRAY_SIZE][LMS_SEED_LEN],
                            const uint8_t masterSeed[LMS_SEED_LEN], const uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE],
                            uint32_t levels)
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

/**
 * @ingroup hss
 * @brief Validate signing preconditions and setup indices
 * @param ctx        [IN]  HSS context
 * @param sigLen     [IN]  Signature buffer length
 * @param counter    [OUT] Current signature counter
 * @param treeIndex  [OUT] Tree indices for each level
 * @param leafIndex  [OUT] Leaf indices for each level
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t HssSignValidateAndSetup(CRYPT_HSS_Ctx *ctx, uint32_t sigLen, uint64_t *counter,
                                       uint64_t treeIndex[HSS_LEVELS_ARRAY_SIZE],
                                       uint32_t leafIndex[HSS_LEVELS_ARRAY_SIZE])
{
    if (ctx->privateKey == NULL || ctx->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    if (sigLen < HssGetSignatureLen(&ctx->para)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    *counter = LmsGetBigendian(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET, HSS_PRVKEY_COUNTER_LEN);
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

    /* Extract master seed from private key */
    uint8_t masterSeed[LMS_SEED_LEN];
    memcpy(masterSeed, ctx->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

    /* Initialize multi-tree context with seeds */
    HssMultiTreeCtx treeCtx;
    ret = HssTree_InitContextWithSeeds(&treeCtx, &ctx->para, masterSeed, counter);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Set up tree caching for each level.  Invalidate a level's cache when its
     * treeIndex has changed — the cached Merkle tree was built with a different
     * (I, seed) pair and reusing it would produce wrong authentication paths. */
    for (uint32_t i = 0; i < ctx->para.levels; i++) {
        if (ctx->cachedTreeIndex[i] != treeCtx.treeIndices[i]) {
            ctx->treeCacheValid[i] = false;
            ctx->cachedTreeIndex[i] = treeCtx.treeIndices[i];
        }
        treeCtx.lmsTrees[i].cachedTree = &ctx->cachedTrees[i];
        treeCtx.lmsTrees[i].cachedTreeSize = &ctx->cachedTreeSizes[i];
        treeCtx.lmsTrees[i].treeCacheValid = &ctx->treeCacheValid[i];
    }

    /* Advance the global counter BEFORE signing.  HssTree_Sign writes
     * intermediate signed-public-key segments into `sig` and may fail partway
     * through (e.g. OOM in the bottom-layer auth-path generation).  If we only
     * incremented the counter on success, a retry would reuse the same
     * (counter -> per-level q) decomposition with the same (I, seed) — that is,
     * the same OTS key — to sign a different message, which destroys the
     * security of the scheme.  Persist the advance first so the index is
     * "consumed" even on partial failure; we trade one wasted leaf for the
     * impossibility of OTS-key reuse. */
    LmsPutBigendian(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET, counter + 1, HSS_PRVKEY_COUNTER_LEN);
    ctx->signatureIndex = counter + 1;

    /* Sign using the tree operations */
    size_t actualSigLen = *sigLen;
    ret = HssTree_Sign(sig, &actualSigLen, msg, msgLen, &treeCtx);

    /* Clean up sensitive data */
    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));
    BSL_SAL_CleanseData(treeCtx.levelSeed, sizeof(treeCtx.levelSeed));

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *sigLen = (uint32_t)actualSigLen;
    return CRYPT_SUCCESS;
}

/**
 * @ingroup hss
 * @brief Parse signed public keys from HSS signature
 * @param parsed    [OUT]    Parsed signature structure
 * @param para      [IN]     HSS parameters
 * @param sigPtr    [IN/OUT] Signature pointer (updated after parsing)
 * @param remaining [IN/OUT] Remaining signature length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
/*
 * Compute the length of an LMS signature by reading OTS and LMS type fields
 * from the raw signature bytes, without relying on pre-populated para->levelPara.
 */
static int32_t HssGetLmsSigLenFromBytes(const uint8_t *sig, size_t remaining, size_t *lmsSigLen)
{
    /* Need q(4) + otsType(4) at minimum */
    if (remaining < LMS_Q_LEN + LMS_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t otsType = (uint32_t)LmsGetBigendian(sig + LMS_Q_LEN, LMS_TYPE_LEN);
    LmOtsParams ots;
    if (LmOtsLookupParamSet(otsType, &ots) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    /* OTS sig: type(4) + C(n) + y[p*n] */
    size_t otsSigLen = LMS_TYPE_LEN + ots.n + (size_t)ots.p * ots.n;

    /* After q + otsSig, need lmsType(4) */
    if (remaining < LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t lmsType = (uint32_t)LmsGetBigendian(sig + LMS_Q_LEN + otsSigLen, LMS_TYPE_LEN);
    uint32_t h, n, height;
    if (LmsLookupParamSet(lmsType, &h, &n, &height) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    /* LMS sig: q(4) + otsSig + lmsType(4) + authPath(height*n) */
    *lmsSigLen = LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN + (size_t)height * n;
    if (*lmsSigLen > remaining) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    return CRYPT_SUCCESS;
}

static int32_t HssParseSignedPubKeys(HSS_ParsedSig *parsed, const HSS_Para *para, const uint8_t **sigPtr,
                                     size_t *remaining)
{
    (void)para; /* para->levelPara no longer needed: lengths parsed from signature bytes */
    for (uint32_t i = 0; i < parsed->nspk; i++) {
        if (i >= HSS_LEVELS_ARRAY_SIZE) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
            return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
        }

        size_t lmsSigLen = 0;
        int32_t ret = HssGetLmsSigLenFromBytes(*sigPtr, *remaining, &lmsSigLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        size_t totalLen = lmsSigLen + LMS_PUBKEY_LEN;
        if (*remaining < totalLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
            return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
        }

        parsed->lmsSigLens[i] = lmsSigLen;
        parsed->signedPubKeys[i] = *sigPtr;
        parsed->signedPubKeyLens[i] = totalLen;

        *sigPtr += totalLen;
        *remaining -= totalLen;
    }
    return CRYPT_SUCCESS;
}

int32_t HssParseSignature(HSS_ParsedSig *parsed, const HSS_Para *para, const uint8_t *signature, size_t signatureLen)
{
    if (signatureLen < HSS_SIG_NSPK_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    const uint8_t *sigPtr = signature;
    size_t remaining = signatureLen;

    parsed->nspk = (uint32_t)LmsGetBigendian(sigPtr, HSS_SIG_NSPK_LEN);
    sigPtr += HSS_SIG_NSPK_LEN;
    remaining -= HSS_SIG_NSPK_LEN;

    if (parsed->nspk != para->levels - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    int32_t ret = HssParseSignedPubKeys(parsed, para, &sigPtr, &remaining);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Derive bottom-level LMS signature length from the remaining bytes */
    size_t bottomSigLen = 0;
    int32_t lenRet = HssGetLmsSigLenFromBytes(sigPtr, remaining, &bottomSigLen);
    if (lenRet != CRYPT_SUCCESS || bottomSigLen != remaining) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_SIGNATURE_PARSE_FAIL);
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }
    parsed->bottomSigLen = bottomSigLen;

    parsed->bottomSig = sigPtr;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_Verify(const CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
                         const uint8_t *sig, uint32_t sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL || ctx->para.levels == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_HSS_NO_KEY);
        return CRYPT_HSS_NO_KEY;
    }

    /* Use the new tree-based verification */
    int32_t ret = HssTree_Verify(&ctx->para, ctx->publicKey, msg, msgLen, sig, sigLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif /* HITLS_CRYPTO_HSS */
