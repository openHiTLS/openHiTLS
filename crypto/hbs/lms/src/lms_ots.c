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
#include "lms_local.h"
#include "lms_common.h"
#include "lms_address.h"

/**
 * @ingroup lms
 * @brief LM-OTS context structure (internal, for backward compatibility)
 *
 * Note: This is kept for internal use. New code should use LmsOtsCtx from lms_common.h
 */
typedef struct {
    const uint8_t *I; /**< Public key identifier (16 bytes) */
    uint32_t q; /**< Leaf index */
    uint32_t n; /**< Hash output length */
    uint32_t w; /**< Winternitz parameter */
    uint32_t p; /**< Number of n-byte string elements */
    uint32_t ls; /**< Checksum left shift */
    const LmsFamilyHashFuncs *hashFuncs; /**< Hash function pointers */
} LmOtsContext;

/**
 * @ingroup lms
 * @brief LM-OTS Chain Function (C function in RFC 8554 Section 4.1)
 *
 * Iteratively applies the hash function to compute a chain segment.
 * This is analogous to XMSS WOTS+ chain function but adapted for LMS parameters.
 *
 * Design Pattern: Follows XMSS XmssWots_Chain pattern for code reusability
 * - XMSS uses chain(x, start, steps) with W=16 (4-bit Winternitz parameter)
 * - LMS uses C(x, start, steps) with W=1/2/4/8 (variable Winternitz parameter)
 * - Both implement the same iterative hash chain concept
 *
 * Reusability: This function eliminates code duplication across:
 * - LmOtsGenerateChains: chains from 0 to (2^w - 1) for public key generation
 * - LmOtsSignChains: chains from 0 to a for signature generation
 * - LmOtsValidateChains: chains from a to (2^w - 1) for signature verification
 *
 * @param buffer [IN/OUT] Input/output buffer (n bytes), modified in place
 * @param start  [IN]     Starting position in chain
 * @param steps  [IN]     Number of steps to iterate
 * @param ctx    [IN]     OTS context containing I, q, n, w, p, ls, and hash functions
 * @param k      [IN]     Chain index
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmOts_Chain(uint8_t *buffer, uint32_t start, uint32_t steps, const LmOtsContext *ctx, uint32_t k)
{
    /* Create a temporary LmsOtsCtx for the hash function */
    LmsOtsCtx otsCtx = {
        .I = ctx->I, .q = ctx->q, .n = ctx->n, .w = ctx->w, .p = ctx->p, .ls = ctx->ls, .hashFuncs = ctx->hashFuncs};

    /* Iterate the hash function 'steps' times starting from 'start' */
    for (uint32_t j = start; j < start + steps; j++) {
        int32_t ret = ctx->hashFuncs->chainHash(&otsCtx, k, j, buffer, buffer);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Extract coefficient from message hash (RFC 8554 Algorithm 2)
 * @param Q [IN] Message hash with checksum
 * @param i [IN] Coefficient index
 * @param w [IN] Winternitz parameter
 * @return Coefficient value (w-bit integer)
 */
uint32_t LmOtsCoef(const uint8_t *Q, uint32_t i, uint32_t w)
{
    uint32_t index = (i * w) / LMS_BITS_PER_BYTE;
    uint32_t digitsPerByte = LMS_BITS_PER_BYTE / w;
    uint32_t shift = w * (~i & (digitsPerByte - 1));
    uint32_t mask = (1 << w) - 1;

    return (Q[index] >> shift) & mask;
}

/**
 * @ingroup lms
 * @brief Compute checksum for OTS signature (RFC 8554 Algorithm 2)
 * @param Q    [IN] Message hash
 * @param qLen [IN] Message hash length
 * @param w    [IN] Winternitz parameter
 * @param ls   [IN] Left shift value
 * @return Checksum value
 */
uint32_t LmOtsComputeChecksum(const uint8_t *Q, uint32_t qLen, uint32_t w, uint32_t ls)
{
    uint32_t sum = 0;
    uint32_t u = LMS_BITS_PER_BYTE * qLen / w;
    uint32_t maxDigit = (1 << w) - 1;

    for (uint32_t i = 0; i < u; i++) {
        sum += maxDigit - LmOtsCoef(Q, i, w);
    }

    return sum << ls;
}

/**
 * @ingroup lms
 * @brief Get OTS public key length
 * @param otsType [IN] OTS type identifier
 * @return Public key length in bytes, 0 on error
 */
size_t LmOtsGetPubKeyLen(uint32_t otsType)
{
    LmOtsParams params;
    if (LmOtsLookupParamSet(otsType, &params) != CRYPT_SUCCESS) {
        return 0;
    }
    return params.n;
}

/**
 * @ingroup lms
 * @brief Get OTS signature length
 * @param otsType [IN] OTS type identifier
 * @return Signature length in bytes, 0 on error
 */
size_t LmOtsGetSigLen(uint32_t otsType)
{
    LmOtsParams params;
    if (LmOtsLookupParamSet(otsType, &params) != CRYPT_SUCCESS) {
        return 0;
    }
    return LMS_TYPE_LEN + params.n + params.p * params.n;
}

/**
 * @ingroup lms
 * @brief Generate all hash chains for OTS public key
 * @param chains [OUT] Output buffer for chain results (p * n bytes)
 * @param ctx    [IN]  OTS context
 * @param seed   [IN]  Seed derivation context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmOtsGenerateChains(uint8_t *chains, const LmOtsContext *ctx, LMS_SeedDerive *seed)
{
    uint8_t tmp[LMS_MAX_HASH];

    LmsSeedDeriveSetJ(seed, LMS_ZERO_INIT_VALUE);

    for (uint32_t i = 0; i < ctx->p; i++) {
        /* On hash failure LmsSeedDerive zeroes `tmp`; ignoring its return would
         * silently chain from a zero secret and produce a broken OTS keypair. */
        int32_t ret = LmsSeedDerive(tmp, seed, (i < ctx->p - 1));
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        /* Chain from 0 to (2^w - 1) to generate public key element */
        uint32_t maxSteps = (1 << ctx->w) - 1;
        ret = LmOts_Chain(tmp, 0, maxSteps, ctx, i);
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
                               uint8_t *publicKey, size_t publicKeyLen)
{
    LmOtsParams params;
    int32_t ret = LmOtsLookupParamSet(otsType, &params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (params.w == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_DIVISION_BY_ZERO);
        return CRYPT_LMS_DIVISION_BY_ZERO;
    }

    /* Validate w is one of the four permitted Winternitz values (RFC 8554 §4.1) */
    if (params.w != 1 && params.w != 2 && params.w != 4 && params.w != 8) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    /* Ensure p is non-zero to prevent division-by-zero in downstream loops */
    if (params.p == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    if (publicKeyLen < params.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    LmOtsContext ctx = {seed->I, seed->q, params.n, params.w, params.p, params.ls, hashFuncs};

    uint8_t *chains = BSL_SAL_Malloc(params.p * params.n);
    if (chains == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmOtsGenerateChains(chains, &ctx, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(chains);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Create LmsOtsCtx for hPblc function */
    LmsOtsCtx otsCtx = {
        .I = ctx.I, .q = ctx.q, .n = ctx.n, .w = ctx.w, .p = ctx.p, .ls = ctx.ls, .hashFuncs = ctx.hashFuncs};

    ret = hashFuncs->pkCompress(&otsCtx, chains, publicKey);
    BSL_SAL_FREE(chains);

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * @ingroup lms
 * @brief Generate randomizer C for OTS signature
 * @param c    [OUT] Randomizer output (n bytes)
 * @param n    [IN]  Randomizer length
 * @param seed [IN]  Seed derivation context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
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

/**
 * @ingroup lms
 * @brief Compute Q = H(I || q || D_MESG || C || message) with checksum
 * @param Q          [OUT] Output Q value (n + 2 bytes)
 * @param ctx        [IN]  OTS context
 * @param C          [IN]  Randomizer (n bytes)
 * @param message    [IN]  Message to hash
 * @param messageLen [IN]  Message length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmOtsComputeQ(uint8_t *Q, const LmOtsContext *ctx, const uint8_t *C, const uint8_t *message,
                             size_t messageLen)
{
    if (messageLen > LMS_MAX_MESSAGE_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    /* Create a temporary tree context for hmsg function */
    LmsTreeCtx treeCtx = {.I = ctx->I, .n = ctx->n, .hashFuncs = ctx->hashFuncs};

    int32_t ret = ctx->hashFuncs->msgHash(&treeCtx, ctx->q, C, message, (uint32_t)messageLen, Q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    LmsPutBigendian(&Q[ctx->n], LmOtsComputeChecksum(Q, ctx->n, ctx->w, ctx->ls), LMS_CHECKSUM_LEN);
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Generate signature chains for OTS signing
 * @param signature [OUT] Output signature buffer
 * @param ctx       [IN]  OTS context
 * @param Q         [IN]  Message hash with checksum
 * @param seed      [IN]  Seed derivation context
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmOtsSignChains(uint8_t *signature, const LmOtsContext *ctx, const uint8_t *Q, LMS_SeedDerive *seed)
{
    uint8_t tmp[LMS_MAX_HASH];

    LmsSeedDeriveSetJ(seed, LMS_ZERO_INIT_VALUE);

    for (uint32_t i = 0; i < ctx->p; i++) {
        /* See LmOtsGenerateChains: ignoring this would chain from a zero
         * secret and emit a forgeable signature element. */
        int32_t ret = LmsSeedDerive(tmp, seed, (i < ctx->p - 1));
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_CleanseData(tmp, sizeof(tmp));
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        /* Chain from 0 to a (where a = coef(Q, i)) */
        uint32_t a = LmOtsCoef(Q, i, ctx->w);
        ret = LmOts_Chain(tmp, 0, a, ctx, i);
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
                  const LMS_InputBuffer *message, LMS_OutputBuffer *signature)
{
    LmOtsParams params;
    int32_t ret = LmOtsLookupParamSet(otsType, &params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (params.w == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_DIVISION_BY_ZERO);
        return CRYPT_LMS_DIVISION_BY_ZERO;
    }

    /* Validate w is one of the four permitted Winternitz values (RFC 8554 §4.1) */
    if (params.w != 1 && params.w != 2 && params.w != 4 && params.w != 8) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    /* Ensure p is non-zero to prevent division-by-zero in downstream loops */
    if (params.p == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    if (signature->len < LMS_TYPE_LEN + params.n + params.p * params.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    LmsPutBigendian(signature->data, otsType, LMS_TYPE_LEN);
    ret = LmOtsGenerateRandomizer(signature->data + LMS_TYPE_LEN, params.n, seed);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t Q[LMS_MAX_HASH + LMS_CHECKSUM_LEN];
    LmOtsContext ctx = {seed->I, seed->q, params.n, params.w, params.p, params.ls, hashFuncs};
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

/**
 * @ingroup lms
 * @brief Validate OTS parameters from signature
 * @param signature       [IN]  Signature buffer
 * @param signatureLen    [IN]  Signature length
 * @param expectedOtsType [IN]  Expected OTS type
 * @param params          [OUT] Parsed OTS parameters
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmOtsValidateParams(const uint8_t *signature, size_t signatureLen, uint32_t expectedOtsType,
                                   LmOtsParams *params)
{
    if (signatureLen < LMS_TYPE_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    uint32_t paramSet = (uint32_t)LmsGetBigendian(signature, LMS_TYPE_LEN);
    if (paramSet != expectedOtsType) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    int32_t ret = LmOtsLookupParamSet(paramSet, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (params->w == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_DIVISION_BY_ZERO);
        return CRYPT_LMS_DIVISION_BY_ZERO;
    }

    if (signatureLen != LMS_TYPE_LEN + params->n * (params->p + 1)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_BUFFER_TOO_SMALL);
        return CRYPT_LMS_BUFFER_TOO_SMALL;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Validate signature chains and compute candidate public key
 * @param finalBuf [OUT] Output buffer for reconstructed public key data
 * @param ctx      [IN]  OTS context
 * @param Q        [IN]  Message hash with checksum
 * @param y        [IN]  Signature y values
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmOtsValidateChains(uint8_t *chains, const LmOtsContext *ctx, const uint8_t *Q, const uint8_t *y)
{
    uint8_t tmp[LMS_MAX_HASH];
    uint32_t maxDigit = (1 << ctx->w) - 1;

    for (uint32_t i = 0; i < ctx->p; i++) {
        memcpy(tmp, y + i * ctx->n, ctx->n);

        /* Chain from a to (2^w - 1) where a = coef(Q, i) */
        uint32_t a = LmOtsCoef(Q, i, ctx->w);
        uint32_t steps = maxDigit - a;
        int32_t ret = LmOts_Chain(tmp, a, steps, ctx, i);
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

int32_t LmOtsValidateSignature(uint8_t *computedPubKey, const LMS_OtsValidateCtx *ctx,
                               const LmsFamilyHashFuncs *hashFuncs, const LMS_InputBuffer *message,
                               const LMS_InputBuffer *signature)
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
    LmOtsContext otsCtx = {ctx->I, ctx->q, params.n, params.w, params.p, params.ls, hashFuncs};
    ret = LmOtsComputeQ(Q, &otsCtx, C, message->data, message->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t *chains = BSL_SAL_Malloc(params.p * params.n);
    if (chains == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmOtsValidateChains(chains, &otsCtx, Q, y);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(chains);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Create LmsOtsCtx for hPblc function */
    LmsOtsCtx otsCtxForHash = {.I = otsCtx.I,
                               .q = otsCtx.q,
                               .n = otsCtx.n,
                               .w = otsCtx.w,
                               .p = otsCtx.p,
                               .ls = otsCtx.ls,
                               .hashFuncs = otsCtx.hashFuncs};

    ret = hashFuncs->pkCompress(&otsCtxForHash, chains, computedPubKey);

    BSL_SAL_CleanseData(Q, sizeof(Q));
    BSL_SAL_FREE(chains);

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif /* HITLS_CRYPTO_LMS */
