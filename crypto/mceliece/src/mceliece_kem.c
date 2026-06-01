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
#ifdef HITLS_CRYPTO_MCELIECE
#include "crypt_mceliece.h"
#include "mceliece_local.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "eal_md_local.h"
#include "bsl_bytes.h"
#include "crypt_utils.h"

// gen e & encode
static int32_t GenVectorE(CRYPT_MCELIECE_Ctx *ctx, uint8_t *c, uint8_t *e)
{
    int32_t ret = FixedWeightVector(ctx, e);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    memset(c, 0, ctx->para->mtBytes);
    ret = EncodeVector(e, &ctx->publicKey->matT, c, ctx->para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

// K = Hash(prefix, e, C)
static int32_t ComputeSessionKeyWithPrefix(uint8_t *sessionKey, uint8_t prefix, const uint8_t *e, const uint8_t *c,
                                           const McelieceParams *params)
{
    size_t inLen = 1 + params->nBytes + params->cipherBytes;
    uint8_t *hashIn = (uint8_t *)BSL_SAL_Malloc(inLen);
    if (hashIn == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    hashIn[0] = prefix;
    memcpy(hashIn + 1, e, params->nBytes);
    memcpy(hashIn + 1 + params->nBytes, c, params->cipherBytes);
    int32_t ret = McElieceShake256(sessionKey, MCELIECE_L_BYTES, hashIn, inLen);
    BSL_SAL_FREE(hashIn);
    return ret;
}

int32_t McElieceShake256(uint8_t *output, const size_t outlen, const uint8_t *input, size_t inLen)
{
    uint32_t len = (uint32_t)outlen;
    return EAL_Md(CRYPT_MD_SHAKE256, NULL, NULL, input, inLen, output, &len, false, false);
}

int32_t McElieceEncapsInternal(CRYPT_MCELIECE_Ctx *ctx, uint8_t *ciphertext, uint8_t *sessionKey, bool isPc)
{
    uint8_t *c0 = ciphertext;
    uint8_t *c1 = ciphertext + ctx->para->cipherBytes - MCELIECE_L_BYTES;

    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(ctx->para->nBytes);
    if (e == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = GenVectorE(ctx, c0, e);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    if (isPc) {
        // PC only: C1 = H(2, e)
        uint8_t hashIn[1 + MCELIECE_L_BYTES];
        hashIn[0] = 2;
        memcpy(hashIn + 1, e, MCELIECE_L_BYTES);
        ret = McElieceShake256(c1, MCELIECE_L_BYTES, hashIn, sizeof(hashIn));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
    }
    uint8_t prefix = 1;
    ret = ComputeSessionKeyWithPrefix(sessionKey, prefix, e, ciphertext, ctx->para);
EXIT:
    BSL_SAL_CleanseData(e, ctx->para->nBytes);
    BSL_SAL_FREE(e);
    return ret;
}

static int32_t BuildVectorAndDecoding(const uint8_t *c0, const CMPrivateKey *sk, const McelieceParams *params,
                                      uint8_t *e, GFElement *decodeSyndrome, GFElement *gfL)
{
    int32_t ret;
    uint8_t *v = BSL_SAL_Calloc(params->nBytes, 1);
    if (v == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (int32_t i = 0; i < params->mt; i++) {
        uint32_t bit = VectorGetBit(c0, i);
        VectorSetBit(v, i, bit);
    }
    GOTO_ERR_IF(SupportFromCbits(gfL, sk->controlbits, params->m, params->n), ret);
    ret = DecodeGoppa(v, &sk->g, gfL, params, e, decodeSyndrome);
ERR:
    BSL_SAL_FREE(v);
    return ret;
}

// Decap algorithm (unified for both pc and non-pc parameter sets)
int32_t McElieceDecapsInternal(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey,
                               const McelieceParams *params, bool isPc)
{
    int32_t ret;
    const uint8_t *c0 = ciphertext;
    const uint8_t *c1 = ciphertext + params->cipherBytes - MCELIECE_L_BYTES;
    // e + decodeSyndrome + veirfySyndrome: params->nBytes || 2 * params->t * sizeof(GFElement) || 2 * params->t * sizeof(GFElement)
    uint32_t memPoolBytes = params->nBytes + 4U * params->t * sizeof(GFElement) + sizeof(GFElement) * params->n;
    uint8_t *memPool = (uint8_t *)BSL_SAL_Calloc(memPoolBytes, 1U);
    if (memPool == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint8_t *e = memPool;
    GFElement *decodeSyndrome = (GFElement *)(memPool + params->nBytes);
    GFElement *verifySyndrome = (GFElement *)(memPool + params->nBytes + 2U * params->t * sizeof(GFElement));
    GFElement *gfL = (GFElement *)(memPool + params->nBytes + 4U * params->t * sizeof(GFElement));
    GOTO_ERR_IF(BuildVectorAndDecoding(c0, sk, params, e, decodeSyndrome, gfL), ret);
    // Recompute syndrome from e
    GOTO_ERR_IF(ComputeSyndrome(e, &sk->g, gfL, params, verifySyndrome), ret);
    // Verify decodeSyndrome == verifySyndrome
    uint32_t mask = ConstTimeMemcmp((uint8_t *)decodeSyndrome, (uint8_t *)verifySyndrome,
        2U * params->t * sizeof(GFElement));
    // Verify error weight == t
    mask &= Uint32ConstTimeEqual(VectorWeight(e, params->nBytes), params->t);
    // b = 1 if errorWeight == t, 0 otherwise
    uint8_t b = (1 & mask) | (0 & (~mask));
    // if errorWeight != t, e[i] = s[i], refernce: https://classic.mceliece.org/mceliece-spec-20221023.pdf, Section 5.6
    for (int32_t i = 0; i < params->nBytes; i++) {
        e[i] = (e[i] & mask) | (sk->s[i] & ~mask);
    }
    if (isPc) {
        // PC only: verify C1
        uint8_t hashIn[1 + MCELIECE_L_BYTES];
        hashIn[0] = 2;
        memcpy(hashIn + 1, e, MCELIECE_L_BYTES);
        uint8_t c1Prime[MCELIECE_L_BYTES];
        GOTO_ERR_IF(McElieceShake256(c1Prime, MCELIECE_L_BYTES, hashIn, sizeof(hashIn)), ret);
        b = Uint8ConstTimeSelect(ConstTimeMemcmp(c1Prime, c1, MCELIECE_L_BYTES), 1 , 0); // If C' != C1, set b <- 0
    }
    ret = ComputeSessionKeyWithPrefix(sessionKey, b, e, ciphertext, params);
ERR:
    BSL_SAL_ClearFree(memPool, memPoolBytes);
    return ret;
}
#endif
