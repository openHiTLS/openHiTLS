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
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
#include "crypt_mceliece.h"
#include "mceliece_local.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "eal_md_local.h"

// gen e & encode
static int32_t GenVectorE(CRYPT_MCELIECE_Ctx *ctx, uint8_t *c, uint8_t *e)
{
    int32_t ret = FixedWeightVector(ctx, e);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memset_s(c, ctx->para->mtBytes, 0, ctx->para->mtBytes);
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
    (void)memcpy_s(hashIn + 1, params->nBytes, e, params->nBytes);
    (void)memcpy_s(hashIn + 1 + params->nBytes, params->cipherBytes, c, params->cipherBytes);
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
        (void)memcpy_s(hashIn + 1, MCELIECE_L_BYTES, e, MCELIECE_L_BYTES);
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
static int32_t BuildVectorAndDecoding(uint8_t *e, const uint8_t *c0, const CMPrivateKey *sk,
                                      const McelieceParams *params)
{
    uint8_t *v = BSL_SAL_Calloc(params->nBytes, 1);
    if (v == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (int32_t i = 0; i < params->mt; i++) {
        uint32_t bit = VectorGetBit(c0, i);
        VectorSetBit(v, i, bit);
    }

    GFElement *gfL = (GFElement *)BSL_SAL_Malloc(sizeof(GFElement) * params->n);
    if (gfL == NULL) {
        BSL_SAL_FREE(v);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    SupportFromCbits(gfL, sk->controlbits, params->m, params->n);

    int32_t decodeSuccess;
    int32_t ret = DecodeGoppa(v, &sk->g, gfL, e, params->nBytes, &decodeSuccess, params);
    BSL_SAL_FREE(gfL);
    BSL_SAL_FREE(v);

    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (decodeSuccess == 0) {
        (void)memcpy_s(e, params->nBytes, sk->s, params->nBytes);
    }
    return CRYPT_SUCCESS;
}

// Decap algorithm (unified for both pc and non-pc parameter sets)
int32_t McElieceDecapsInternal(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey,
                               const McelieceParams *params, bool isPc)
{
    const uint8_t *c0 = ciphertext;
    const uint8_t *c1 = ciphertext + params->cipherBytes - MCELIECE_L_BYTES;

    uint8_t *e = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (e == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BuildVectorAndDecoding(e, c0, sk, params);
    uint8_t b = (ret == CRYPT_SUCCESS) ? 1 : 0; // If e = ⊥, set b <- 0
    if (isPc) {
        // PC only: verify C1
        uint8_t hashIn[1 + MCELIECE_L_BYTES];
        hashIn[0] = 2;
        (void)memcpy_s(hashIn + 1, MCELIECE_L_BYTES, e, MCELIECE_L_BYTES);
        uint8_t c1Prime[MCELIECE_L_BYTES];
        ret = McElieceShake256(c1Prime, MCELIECE_L_BYTES, hashIn, sizeof(hashIn));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        b = memcmp(c1Prime, c1, MCELIECE_L_BYTES) == 0 ? 1 : 0; // If C' != C1, set b <- 0
    }

    ret = ComputeSessionKeyWithPrefix(sessionKey, b, e, ciphertext, params);
EXIT:
    BSL_SAL_CleanseData(e, params->nBytes);
    BSL_SAL_FREE(e);
    return ret;
}
#endif
