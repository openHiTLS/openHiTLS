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
#include "crypt_utils.h"
#include "eal_md_local.h"
#include "crypt_algid.h"
#include "lms_local.h"
#include "lms_hash.h"
#include "lms_common.h"
#include "lms_params.h"

/**
 * @ingroup lms
 * @brief SHA-256 hash function wrapper
 * @param result     [OUT] Hash output (32 bytes)
 * @param message    [IN]  Message to hash
 * @param messageLen [IN]  Message length
 * @return CRYPT_SUCCESS on success, error code on failure
 */
static int32_t LmsHashSha256(uint8_t *result, const void *message, size_t messageLen)
{
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }
    uint32_t outLen = LMS_SHA256_N;
    const CRYPT_ConstData hashData[] = {{message, messageLen}};
    int32_t ret = CRYPT_CalcHash(NULL, hashMethod, hashData, 1, result, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

/* LMS does not use the LmsFamilyHashFuncs.skDerive slot.  Per-leaf OTS private
 * key components are derived through LmsSeedDerive (below), which builds the
 * full RFC 8554 §4 input H(I || q || j || 0xFF || seed) from an explicit
 * LMS_SeedDerive context.  The slot exists only for structural symmetry with
 * the XMSS / SLH-DSA hash-function tables; it is intentionally left NULL in
 * g_lmsHashFuncsSha256.  An earlier placeholder implementation hashed a
 * partially-uninitialized stack buffer (missing the j and seed fields) and
 * has been removed: keeping a broken stub invites silent misuse, whereas a
 * NULL slot fails loudly at the call site if it is ever wired up by mistake.
 */

/**
 * @ingroup lms
 * @brief chainHash - OTS chain iteration function (C function in RFC 8554 Section 4.1)
 * Constructs: H(I || q || k || j || prev)
 * Corresponds to LmsFamilyHashFuncs.chainHash (formerly: f)
 */
static int32_t LmsChainHashSha256(const LmsOtsCtx *ctx, uint32_t k, uint32_t j, const uint8_t *prev, uint8_t *out)
{
    uint8_t iterBuf[LMS_ITER_LEN(LMS_MAX_HASH)];

    memcpy(iterBuf + LMS_ITER_I_OFFSET, ctx->I, LMS_I_LEN);
    LmsPutBigendian(iterBuf + LMS_ITER_Q_OFFSET, ctx->q, LMS_Q_LEN);
    LmsPutBigendian(iterBuf + LMS_ITER_K_OFFSET, k, LMS_K_LEN);
    iterBuf[LMS_ITER_J_OFFSET] = (uint8_t)j;
    memcpy(iterBuf + LMS_ITER_PREV_OFFSET, prev, ctx->n);

    return LmsHashSha256(out, iterBuf, LMS_ITER_LEN(ctx->n));
}

/**
 * @ingroup lms
 * @brief leafHash - Leaf node hash function
 * Constructs: H(I || r || D_LEAF || otsPubKey)
 * Corresponds to LmsFamilyHashFuncs.leafHash (formerly: hLeaf)
 */
static int32_t LmsLeafHashSha256(const LmsTreeCtx *ctx, uint32_t r, const uint8_t *otsPubKey, uint8_t *out)
{
    uint8_t leafBuf[LMS_LEAF_LEN(LMS_MAX_HASH)];

    memcpy(leafBuf + LMS_LEAF_I_OFFSET, ctx->I, LMS_I_LEN);
    LmsPutBigendian(leafBuf + LMS_LEAF_R_OFFSET, r, LMS_R_LEN);
    LmsSetD(leafBuf + LMS_LEAF_D_OFFSET, LMS_D_LEAF);
    memcpy(leafBuf + LMS_LEAF_PK_OFFSET, otsPubKey, ctx->n);

    return LmsHashSha256(out, leafBuf, LMS_LEAF_LEN(ctx->n));
}

/**
 * @ingroup lms
 * @brief nodeHash - Internal node hash function
 * Constructs: H(I || r || D_INTR || left || right)
 * Corresponds to LmsFamilyHashFuncs.nodeHash (formerly: hIntr)
 */
static int32_t LmsNodeHashSha256(const LmsTreeCtx *ctx, uint32_t r, const uint8_t *left, const uint8_t *right,
                                 uint8_t *out)
{
    uint8_t intrBuf[LMS_INTR_LEN(LMS_MAX_HASH)];

    memcpy(intrBuf + LMS_INTR_I_OFFSET, ctx->I, LMS_I_LEN);
    LmsPutBigendian(intrBuf + LMS_INTR_R_OFFSET, r, LMS_R_LEN);
    LmsSetD(intrBuf + LMS_INTR_D_OFFSET, LMS_D_INTR);
    memcpy(intrBuf + LMS_INTR_LEFT_OFFSET, left, ctx->n);
    memcpy(intrBuf + LMS_INTR_RIGHT_OFFSET(ctx->n), right, ctx->n);

    return LmsHashSha256(out, intrBuf, LMS_INTR_LEN(ctx->n));
}

/**
 * @ingroup lms
 * @brief msgHash - Message hash function
 * Constructs: H(I || q || D_MESG || C || message)
 * Corresponds to LmsFamilyHashFuncs.msgHash (formerly: hmsg)
 */
static int32_t LmsMsgHashSha256(const LmsTreeCtx *ctx, uint32_t q, const uint8_t *C, const uint8_t *msg,
                                uint32_t msgLen, uint8_t *out)
{
    uint8_t prefix[LMS_MESG_PREFIX_LEN(LMS_MAX_HASH)];

    memcpy(prefix + LMS_MESG_I_OFFSET, ctx->I, LMS_I_LEN);
    LmsPutBigendian(prefix + LMS_MESG_Q_OFFSET, q, LMS_Q_LEN);
    LmsSetD(prefix + LMS_MESG_D_OFFSET, LMS_D_MESG);
    memcpy(prefix + LMS_MESG_C_OFFSET, C, ctx->n);

    /* Hash prefix || message */
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }

    uint32_t outLen = ctx->n;
    const CRYPT_ConstData hashData[] = {{prefix, LMS_MESG_PREFIX_LEN(ctx->n)}, {msg, msgLen}};
    int32_t ret = CRYPT_CalcHash(NULL, hashMethod, hashData, 2, out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief pkCompress - OTS public key hash function (compress chain ends to public key)
 * Constructs: H(I || q || D_PBLC || chains)
 * Corresponds to LmsFamilyHashFuncs.pkCompress (formerly: hPblc)
 */
static int32_t LmsPkCompressSha256(const LmsOtsCtx *ctx, const uint8_t *chains, uint8_t *out)
{
    uint8_t prefix[LMS_PBLC_PREFIX_LEN];

    memcpy(prefix + LMS_PBLC_I_OFFSET, ctx->I, LMS_I_LEN);
    LmsPutBigendian(prefix + LMS_PBLC_Q_OFFSET, ctx->q, LMS_Q_LEN);
    LmsSetD(prefix + LMS_PBLC_D_OFFSET, LMS_D_PBLC);

    /* Hash prefix || chains */
    const EAL_MdMethod *hashMethod = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    if (hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HASH_FAIL);
        return CRYPT_LMS_HASH_FAIL;
    }

    uint32_t outLen = ctx->n;
    const CRYPT_ConstData hashData[] = {{prefix, LMS_PBLC_PREFIX_LEN}, {chains, ctx->p * ctx->n}};
    int32_t ret = CRYPT_CalcHash(NULL, hashMethod, hashData, 2, out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return CRYPT_LMS_HASH_FAIL;
    }
    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Static hash function table - shared by all LMS algorithms
 */
static const LmsFamilyHashFuncs g_lmsHashFuncsSha256 = {
    .skDerive = NULL, /* unused — see comment above LmsChainHashSha256 */
    .chainHash = LmsChainHashSha256,
    .leafHash = LmsLeafHashSha256,
    .nodeHash = LmsNodeHashSha256,
    .msgHash = LmsMsgHashSha256,
    .pkCompress = LmsPkCompressSha256,
};

int32_t LmsHash(uint8_t *result, const void *message, size_t messageLen)
{
    return LmsHashSha256(result, message, messageLen);
}

/**
 * @ingroup lms
 * @brief Get hash functions for a given algorithm type
 * @param lmsType [IN] LMS algorithm type
 * @return Pointer to hash function table
 */
const LmsFamilyHashFuncs *LmsGetHashFuncs(uint32_t lmsType)
{
    /* Currently all LMS variants use SHA-256 */
    (void)lmsType;
    return &g_lmsHashFuncsSha256;
}

int32_t LmsSetD(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> LMS_BITS_PER_BYTE);
    p[1] = (uint8_t)(value & LMS_BYTE_MASK);
    return CRYPT_SUCCESS;
}

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
    LmsPutBigendian(buffer + LMS_PRG_Q_OFFSET, derive->q, LMS_Q_LEN);
    LmsPutBigendian(buffer + LMS_PRG_J_OFFSET, derive->j, LMS_K_LEN);
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

int32_t LmsLookupParamSet(uint32_t paramSet, uint32_t *h, uint32_t *n, uint32_t *height)
{
    uint32_t vH;
    uint32_t vN;
    uint32_t vHeight;

    switch (paramSet) {
        case LMS_SHA256_M32_H5:
            vH = LMS_HASH_SHA256;
            vN = 32;
            vHeight = 5;
            break;
        case LMS_SHA256_M32_H10:
            vH = LMS_HASH_SHA256;
            vN = 32;
            vHeight = 10;
            break;
        case LMS_SHA256_M32_H15:
            vH = LMS_HASH_SHA256;
            vN = 32;
            vHeight = 15;
            break;
        case LMS_SHA256_M32_H20:
            vH = LMS_HASH_SHA256;
            vN = 32;
            vHeight = 20;
            break;
        case LMS_SHA256_M32_H25:
            vH = LMS_HASH_SHA256;
            vN = 32;
            vHeight = 25;
            break;
        default:
            return CRYPT_LMS_INVALID_PARAM;
    }

    if (h != NULL) {
        *h = vH;
    }
    if (n != NULL) {
        *n = vN;
    }
    if (height != NULL) {
        *height = vHeight;
    }

    return CRYPT_SUCCESS;
}

/**
 * @ingroup lms
 * @brief Lookup LM-OTS parameter set
 * @param paramSet [IN]  OTS parameter set identifier
 * @param params   [OUT] OTS parameters structure
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmOtsLookupParamSet(uint32_t paramSet, LmOtsParams *params)
{
    switch (paramSet) {
        case LMOTS_SHA256_N32_W1:
            params->h = LMS_HASH_SHA256;
            params->n = 32;
            params->w = 1;
            params->p = 265;
            params->ls = 7;
            break;
        case LMOTS_SHA256_N32_W2:
            params->h = LMS_HASH_SHA256;
            params->n = 32;
            params->w = 2;
            params->p = 133;
            params->ls = 6;
            break;
        case LMOTS_SHA256_N32_W4:
            params->h = LMS_HASH_SHA256;
            params->n = 32;
            params->w = 4;
            params->p = 67;
            params->ls = 4;
            break;
        case LMOTS_SHA256_N32_W8:
            params->h = LMS_HASH_SHA256;
            params->n = 32;
            params->w = 8;
            params->p = 34;
            params->ls = 0;
            break;
        default:
            return CRYPT_LMS_INVALID_PARAM;
    }

    return CRYPT_SUCCESS;
}

int32_t LmsParaInit(LMS_Para *para, uint32_t lmsType, uint32_t otsType)
{
    memset(para, 0, sizeof(LMS_Para));

    int32_t ret = LmsLookupParamSet(lmsType, &para->h, &para->n, &para->height);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (para->height < LMS_MIN_HEIGHT || para->height > LMS_MAX_HEIGHT) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_INVALID_PARAM);
        return CRYPT_LMS_INVALID_PARAM;
    }

    LmOtsParams otsParams;
    ret = LmOtsLookupParamSet(otsType, &otsParams);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    para->w = otsParams.w;
    para->p = otsParams.p;
    para->ls = otsParams.ls;

    para->lmsType = lmsType;
    para->otsType = otsType;

    para->pubKeyLen = LMS_PUBKEY_LEN;
    para->prvKeyLen = LMS_PRVKEY_LEN;

    // OTS signature length: 4 + n + p*n
    size_t otsSigLen = 4 + para->n + para->p * para->n;

    // LMS signature length: 4 + otsSigLen + 4 + height*n
    para->sigLen = 4 + otsSigLen + 4 + para->height * para->n;

    // Initialize hash functions
    const LmsFamilyHashFuncs *hashFuncs = LmsGetHashFuncs(lmsType);
    if (hashFuncs == NULL) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    para->hashFuncs = *hashFuncs;

    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_LMS */
