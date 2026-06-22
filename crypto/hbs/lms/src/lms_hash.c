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
    BSL_Uint32ToByte(ctx->q, iterBuf + LMS_ITER_Q_OFFSET);
    BSL_Uint16ToByte((uint16_t)k, iterBuf + LMS_ITER_K_OFFSET);
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
    BSL_Uint32ToByte(r, leafBuf + LMS_LEAF_R_OFFSET);
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
    BSL_Uint32ToByte(r, intrBuf + LMS_INTR_R_OFFSET);
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
    BSL_Uint32ToByte(q, prefix + LMS_MESG_Q_OFFSET);
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
    BSL_Uint32ToByte(ctx->q, prefix + LMS_PBLC_Q_OFFSET);
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

/**
 * @brief Mapping from LMS type code to the corresponding hash function table.
 *
 * The lmsType alone determines which hash algorithm to use
 * (e.g. LMS_SHA256_M32_H5 → SHA-256).  To add a new hash family,
 * implement the six LmsFamilyHashFuncs callbacks, create a new table,
 * and add an entry here.
 */
typedef struct {
    uint32_t lmsType;                /**< LMS parameter set identifier */
    const LmsFamilyHashFuncs *funcs; /**< Function table for this type */
} LmsHashFamilyMapping;

static const LmsHashFamilyMapping g_lmsHashFamilies[] = {
    {LMS_SHA256_M32_H5,  &g_lmsHashFuncsSha256},
    {LMS_SHA256_M32_H10, &g_lmsHashFuncsSha256},
    {LMS_SHA256_M32_H15, &g_lmsHashFuncsSha256},
    {LMS_SHA256_M32_H20, &g_lmsHashFuncsSha256},
    {LMS_SHA256_M32_H25, &g_lmsHashFuncsSha256},
    /* To add a new hash algorithm (e.g. SHA-256/192 or SHAKE256):
     *   {LMS_SHA256_M24_H5,  &g_lmsHashFuncsSha256_192},
     *   {LMS_SHAKE_M32_H5,   &g_lmsHashFuncsShake256},
     *   ...
     */
};

static const LmsFamilyHashFuncs *LmsFindHashFuncs(uint32_t lmsType)
{
    for (size_t i = 0; i < sizeof(g_lmsHashFamilies) / sizeof(g_lmsHashFamilies[0]); i++) {
        if (g_lmsHashFamilies[i].lmsType == lmsType) {
            return g_lmsHashFamilies[i].funcs;
        }
    }
    return NULL;
}

/**
 * @ingroup lms
 * @brief Seed-derivation hash — currently SHA-256.
 *
 * Used by HSS for master-seed → (I, seed) derivation.
 * When a new hash algorithm is added, this function MUST be extended
 * to dispatch on a hash-family parameter so that child-seed derivation
 * uses the same hash as the LMS tree it belongs to.
 */
int32_t LmsHash(uint8_t *result, const void *message, size_t messageLen)
{
    return LmsHashSha256(result, message, messageLen);
}

/**
 * @ingroup lms
 * @brief Get hash functions for a given algorithm type
 * @param lmsType [IN] LMS algorithm type
 * @return Pointer to hash function table, or NULL if unknown
 */
const LmsFamilyHashFuncs *LmsGetHashFuncs(uint32_t lmsType)
{
    return LmsFindHashFuncs(lmsType);
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

/* Lookup tables for LMS / LM-OTS parameter sets.                           */
/* Append a new row when adding a new parameter set (e.g. from RFC 9858).  */

typedef struct {
    uint32_t paramSet;
    uint32_t h;
    uint32_t n;
    uint32_t height;
} LmsParamEntry;

static const LmsParamEntry g_lmsParamTable[] = {
    {LMS_SHA256_M32_H5,  LMS_HASH_SHA256, 32, 5},
    {LMS_SHA256_M32_H10, LMS_HASH_SHA256, 32, 10},
    {LMS_SHA256_M32_H15, LMS_HASH_SHA256, 32, 15},
    {LMS_SHA256_M32_H20, LMS_HASH_SHA256, 32, 20},
    {LMS_SHA256_M32_H25, LMS_HASH_SHA256, 32, 25},
};

int32_t LmsLookupParamSet(uint32_t paramSet, uint32_t *h, uint32_t *n, uint32_t *height)
{
    for (size_t i = 0; i < sizeof(g_lmsParamTable) / sizeof(g_lmsParamTable[0]); i++) {
        if (g_lmsParamTable[i].paramSet == paramSet) {
            if (h != NULL) {
                *h = g_lmsParamTable[i].h;
            }
            if (n != NULL) {
                *n = g_lmsParamTable[i].n;
            }
            if (height != NULL) {
                *height = g_lmsParamTable[i].height;
            }
            return CRYPT_SUCCESS;
        }
    }
    return CRYPT_LMS_INVALID_PARAM;
}

typedef struct {
    uint32_t paramSet;
    uint32_t h;
    uint32_t n;
    uint32_t w;
    uint32_t p;
    uint32_t ls;
} LmOtsParamEntry;

static const LmOtsParamEntry g_lmOtsParamTable[] = {
    {LMOTS_SHA256_N32_W1, LMS_HASH_SHA256, 32, 1, 265, 7},
    {LMOTS_SHA256_N32_W2, LMS_HASH_SHA256, 32, 2, 133, 6},
    {LMOTS_SHA256_N32_W4, LMS_HASH_SHA256, 32, 4, 67,  4},
    {LMOTS_SHA256_N32_W8, LMS_HASH_SHA256, 32, 8, 34,  0},
};

/**
 * @ingroup lms
 * @brief Lookup LM-OTS parameter set
 * @param paramSet [IN]  OTS parameter set identifier
 * @param params   [OUT] OTS parameters structure
 * @return CRYPT_SUCCESS on success, error code on failure
 */
int32_t LmOtsLookupParamSet(uint32_t paramSet, LmOtsParams *params)
{
    for (size_t i = 0; i < sizeof(g_lmOtsParamTable) / sizeof(g_lmOtsParamTable[0]); i++) {
        if (g_lmOtsParamTable[i].paramSet == paramSet) {
            params->h = g_lmOtsParamTable[i].h;
            params->n = g_lmOtsParamTable[i].n;
            params->w = g_lmOtsParamTable[i].w;
            params->p = g_lmOtsParamTable[i].p;
            params->ls = g_lmOtsParamTable[i].ls;
            return CRYPT_SUCCESS;
        }
    }
    return CRYPT_LMS_INVALID_PARAM;
}

int32_t LmsParaInit(LMS_Para *para, uint32_t lmsType, uint32_t otsType)
{
    memset(para, 0, sizeof(LMS_Para));

    int32_t ret = LmsLookupParamSet(lmsType, &para->h, &para->n, &para->height);
    if (ret != CRYPT_SUCCESS) {
        return ret;
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

    /* Public key = type(4) || ots_type(4) || I(16) || root(n)  = 24 + n */
    para->pubKeyLen = 24 + para->n;
    /* Private key = index(8) || lmsType(4) || otsType(4) || I(16) || seed(32) = 32 + 32 */
    para->prvKeyLen = 32 + LMS_SEED_LEN;

    // OTS signature length: 4 + n + p*n
    uint32_t otsSigLen = 4 + para->n + para->p * para->n;

    // LMS signature length: 4 + otsSigLen + 4 + height*n
    para->sigLen = 4 + otsSigLen + 4 + para->height * para->n;

    // Copy hash function table for this algorithm type
    const LmsFamilyHashFuncs *funcs = LmsGetHashFuncs(lmsType);
    if (funcs == NULL) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    para->hashFuncs = *funcs;

    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_LMS */
