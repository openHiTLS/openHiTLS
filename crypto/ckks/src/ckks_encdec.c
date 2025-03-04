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
#ifdef HITLS_CRYPTO_CKKS

#include <math.h>
#include "ckks_local.h"
#include "crypt_ckks.h"
#include "ckks_encdec.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"

double Infinity_Norm(const CKKS_Complex_Array *complex_vec)
{
    size_t n = complex_vec->size;
    double ret = 1.0;
    for (size_t i = 0; i < n; i++) {
        double curr = CKKS_Complex_Cabs(complex_vec->data[i]);
        if (curr > ret) {
            ret = curr;
        }
    }
    return ret;
}

double Default_Err(double magBound, uint32_t degBound)
{
    double scale = DEFAULT_SCALE;
    return scale * sqrt(degBound / 3.0) * magBound;
}

double Default_Scale(double err, int32_t prec)
{
    if (err < 1.0) {
        err = 1.0;
    }
    int exp;
    /* Compute 2^(ceil(log2(err*2^r))) */
    frexp(1 / err, &exp); // 1/err = m * 2^exp
    return ldexp(1.0, prec - exp + 1); // 1.0*2^(prec-exp+1)
}

double Default_Mag(const CKKS_Complex_Array *data)
{
    // if mag is defaulted, set it to 2^(ceil(log2(max(Norm(data),1))))
    double l_norm = Infinity_Norm(data);
    double norm = (l_norm > 1) ? l_norm : 1;
    uint32_t k = 0;
    while ((1u << k) < norm) {
        k++;
    }
    double mag = (double)(1u << k);
    return mag;
}

double RLWE(CRYPT_CKKS_Ctx *ctx, CKKS_DoubleCRT *p0, CKKS_DoubleCRT *p1, CKKS_DoubleCRT *s, BN_Optimizer *opt)
{
    if (ctx == NULL || p0 == NULL || p1 == NULL || s == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t phiM = ctx->para->phiM;
    uint32_t m = ctx->para->m;
    double stdev = ctx->para->stdev;
    uint32_t bits = ctx->para->bits;
    int32_t ret = Randomize_Map(p1->map, ctx->para->moduli, phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    double bound = 0.0;
    ret = Sample_Gaussian_Bound(&bound, p0->poly, stdev);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CKKS_DoubleCRT *tmp = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    ret = CKKS_DoubleCRT_Init(tmp, bits, m, ctx->para->moduli);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CKKS_DoubleCRT_Copy(tmp, p1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CKKS_DoubleCRT_AddSubMul(tmp, tmp, s, ctx->para->moduli, opt, 2); // Multiply
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CKKS_DoubleCRT_AddSubMul(p0, p0, tmp, ctx->para->moduli, opt, 1); // Subtraction
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return bound;
}

int32_t Sample_Small_Poly(CKKS_Poly *poly, double prob)
{
    if (prob < 3.05e-5 || prob > 1) { // prob must be in [2^{-15}, 1]
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret;
    uint32_t bitlen = 16;
    uint32_t high_mask = 1u << (bitlen - 1);
    uint32_t low_mask = high_mask - 1;
    uint32_t polyLen = poly->polyctx->phiM;
    uint32_t threshold = (uint32_t)Coordinate_Wise_Random_Rounding(high_mask * prob);

    for (uint32_t i = 0; i < polyLen; i++) {
        uint32_t u = rand();
        uint32_t uLow = u & low_mask;
        uint32_t uHigh = u & high_mask;
        BN_BigNum *rand_coeff = BN_Create(bitlen);
        BN_BigNum *bn_uhigh = BN_Create(bitlen);
        ret = BN_SetLimb(bn_uhigh, uHigh);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BN_Destroy(rand_coeff);
            BN_Destroy(bn_uhigh);
            return ret;
        }
        if (uLow < threshold) {
            ret = BN_Rshift(rand_coeff, bn_uhigh, bitlen - 2);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                BN_Destroy(rand_coeff);
                BN_Destroy(bn_uhigh);
                return ret;
            }
            ret = BN_SubLimb(rand_coeff, rand_coeff, 1);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                BN_Destroy(rand_coeff);
                BN_Destroy(bn_uhigh);
                return ret;
            }
            ret = BN_Copy(poly->coeffs[i], rand_coeff);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                BN_Destroy(rand_coeff);
                BN_Destroy(bn_uhigh);
                return ret;
            }
            BN_Destroy(rand_coeff);
            BN_Destroy(bn_uhigh);
        } else {
            BN_Zeroize(poly->coeffs[i]);
        }
    }
    ret = CKKS_Poly_Normalized(poly);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t Sample_Small_Bound(double *bound, CKKS_Poly *poly)
{
    uint32_t phiM = poly->polyctx->phiM;
    *bound = sqrt(phiM * log(phiM) / 2.0);

    uint32_t count = 0;
    double val;
    int32_t ret;

    // Assume the polynomial f(x) = sum_{i < k} f_i x^i is chosen, Where each coefficient f_i takes a probability value of 0,
    // with probability prob/2, and -1 with probability prob/2.
    do {
        ret = Sample_Small_Poly(poly, 0.5);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        val = Embedding_Largest_Coeff(poly);
    } while (++count < 1000 && val > *bound);
    if (val > *bound) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_NOISE_OUT_BOUND);
        return CRYPT_CKKS_NOISE_OUT_BOUND;
    }
    return CRYPT_SUCCESS;
}

int32_t Sample_Gaussian_Poly(CKKS_Poly *poly, double stdev, uint32_t phiM)
{
    if (poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t *sampling = (uint32_t *)BSL_SAL_Malloc(phiM * sizeof(uint32_t));
    if (sampling == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    // The Box-Muller method is used to generate Gaussian random numbers
    for (uint32_t i = 0; i < phiM; i += 2) {
        double r1 = (double)(rand() / RAND_MAX);
        double r2 = (double)(rand() / RAND_MAX);
        double theta = 2.0 * PI * r1;
        double rr = sqrt(-2.0 * log(r2));
        if (rr > CKKS_GAUSS_TRUNC) {
            rr = CKKS_GAUSS_TRUNC;
        }
        sampling[i] = (uint32_t)Coordinate_Wise_Random_Rounding(stdev * rr * cos(theta));
        ret = BN_SetLimb(poly->coeffs[i], sampling[i]);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_Free(sampling);
            return ret;
        }
        if (i + 1 < phiM) {
            sampling[i + 1] = (uint32_t)Coordinate_Wise_Random_Rounding(stdev * rr * sin(theta));
            ret = BN_SetLimb(poly->coeffs[i + 1], sampling[i + 1]);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                BSL_SAL_Free(sampling);
                return ret;
            }
        }
    }
    ret = CKKS_Poly_Normalized(poly);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(sampling);
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t Sample_Gaussian_Bound(double *bound, CKKS_Poly *poly, double stdev)
{
    uint32_t phiM = poly->polyctx->phiM;
    *bound = stdev * sqrt(phiM * log(phiM));
    double val;
    uint32_t count = 0;
    int32_t ret;
    do {
        ret = Sample_Gaussian_Poly(poly, stdev, phiM);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        val = Embedding_Largest_Coeff(poly);
    } while (++count < 1000 && val > *bound);
    if (val > *bound) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_NOISE_OUT_BOUND);
        return CRYPT_CKKS_NOISE_OUT_BOUND;
    }
    return ret;
}

int32_t CRYPT_CKKS_PubEnc(const CRYPT_CKKS_Ctx *ctx, const CKKS_Poly *Eptxt, size_t inputLen, uint8_t *out,
                          uint32_t *outLen)
{
    int32_t ret;
    CRYPT_CKKS_PubKey *pubKey = ctx->pubKey;
    if (pubKey == NULL || ctx == NULL || Eptxt == NULL || inputLen == 0 || out == NULL || outLen == NULL ||
        *outLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t bits = ctx->para->bits;
    uint32_t m = ctx->para->m;
    double err = ctx->para->err;
    double stdev = ctx->para->stdev;

    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CKKS_Poly *eptxt_copy = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly));
    CKKS_DoubleCRT *crt_eptxt = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    if (eptxt_copy == NULL || crt_eptxt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CKKS_Poly_Copy(eptxt_copy, Eptxt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_DoubleCRT_Destroy(crt_eptxt);
        CKKS_Poly_Destroy(eptxt_copy);
        return ret;
    }
    ret = CKKS_DoubleCRT_Init(crt_eptxt, bits, m, ctx->para->moduli);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        CKKS_DoubleCRT_Destroy(crt_eptxt);
        CKKS_Poly_Destroy(eptxt_copy);
        return ret;
    }

    CKKS_DoubleCRT *e = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    CKKS_DoubleCRT *r = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    CKKS_DoubleCRT **res = (CKKS_DoubleCRT **)BSL_SAL_Malloc(2 * sizeof(CKKS_DoubleCRT *));
    res[0] = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    res[1] = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    if (e == NULL || r == NULL || res == NULL || res[0] == NULL || res[1] == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        CKKS_DoubleCRT_Destroy(crt_eptxt);
        CKKS_Poly_Destroy(eptxt_copy);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(CKKS_DoubleCRT_Init(e, bits, m, ctx->para->moduli), ret);
    GOTO_ERR_IF(CKKS_DoubleCRT_Init(r, bits, m, ctx->para->moduli), ret);
    GOTO_ERR_IF(CKKS_DoubleCRT_Init(res[0], bits, m, ctx->para->moduli), ret);
    GOTO_ERR_IF(CKKS_DoubleCRT_Init(res[1], bits, m, ctx->para->moduli), ret);

    double r_bound = 0.0;
    double e_bound = 0.0;
    ret = Sample_Small_Bound(&r_bound, r->poly);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    double err_bound = r_bound * pubKey->pubkey_noiseB;

    // ctxt = r*pk + p*(e0,e1) + (ptxt,0), Take e in both loops as e0 and e1, respectively
    for (size_t i = 0; i < 2; i++) {
        if (i == 0) {
            GOTO_ERR_IF(CKKS_DoubleCRT_Copy(res[0], pubKey->b), ret);
        } else {
            GOTO_ERR_IF(CKKS_DoubleCRT_Copy(res[1], pubKey->a), ret);
        }
        GOTO_ERR_IF(CKKS_DoubleCRT_AddSubMul(res[i], res[i], r, ctx->para->moduli, optimizer, 2), ret);
        GOTO_ERR_IF(CKKS_DoubleCRT_AddSubMul(res[i], res[i], e, ctx->para->moduli, optimizer, 0), ret);
        GOTO_ERR_IF(Sample_Gaussian_Bound(&e_bound, e->poly, stdev), ret);
        if (i == 1) {
            e_bound *= pubKey->prvkey_noiseB;
        }
        err_bound += e_bound;
    }

    uint32_t ef = (uint32_t)ceil(ctx->para->noise_bound / err);
    if (ef > 1) {
        GOTO_ERR_IF(CKKS_Poly_Int_Mul(eptxt_copy, eptxt_copy, ef, optimizer), ret);
        ctx->para->ratfactor *= ef;
    } else {
        GOTO_ERR_IF(CKKS_Poly2DoubleCRT(crt_eptxt, eptxt_copy, ctx->para->moduli, optimizer), ret);
        GOTO_ERR_IF(CKKS_DoubleCRT_AddSubMul(res[0], res[0], crt_eptxt, ctx->para->moduli, optimizer, 0), ret);
    }

    ret = CKKS_DoubleCRT_Cipher2Bin(res[0], res[1], out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->para->noise_bound = err_bound + err;

ERR:
    CKKS_DoubleCRT_Destroy(e);
    CKKS_DoubleCRT_Destroy(r);
    BSL_SAL_Free(res);
    CKKS_Poly_Destroy(eptxt_copy);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

int32_t CRYPT_CKKS_PrvDec(const CRYPT_CKKS_Ctx *ctx, CKKS_DoubleCRT **ciphertext, CKKS_Poly *out)
{
    int32_t ret;
    CRYPT_CKKS_PrvKey *prvKey = ctx->prvKey;
    if (prvKey == NULL || ctx == NULL || ciphertext == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    if (optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    CKKS_DoubleCRT *part = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    CKKS_DoubleCRT *plaintext = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    CKKS_DoubleCRT *tmp = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    if (part == NULL || plaintext == NULL || tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BN_OptimizerDestroy(optimizer);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    GOTO_ERR_IF(CKKS_DoubleCRT_Copy(tmp, prvKey->s), ret);
    for (size_t i = 0; i < 2; i++) {
        GOTO_ERR_IF(CKKS_DoubleCRT_Copy(part, ciphertext[i]), ret);
        if (i == 0) {
            GOTO_ERR_IF(CKKS_DoubleCRT_Copy(plaintext, part), ret);
            continue;
        }
        GOTO_ERR_IF(CKKS_DoubleCRT_AddSubMul(tmp, prvKey->s, part, ctx->para->moduli, optimizer, 2), ret);
        GOTO_ERR_IF(CKKS_DoubleCRT_AddSubMul(plaintext, plaintext, tmp, ctx->para->moduli, optimizer, 0), ret);
    }
    GOTO_ERR_IF(CKKS_Poly_Copy(out, plaintext->poly), ret);

ERR:
    CKKS_DoubleCRT_Destroy(part);
    CKKS_DoubleCRT_Destroy(plaintext);
    CKKS_DoubleCRT_Destroy(tmp);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

static int32_t EncryptInputCheck(CRYPT_CKKS_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out,
                                 uint32_t *outLen)
{
    if (ctx == NULL || input == NULL || inputLen == 0 || out == NULL || *outLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_NO_KEY_INFO);
        return CRYPT_CKKS_NO_KEY_INFO;
    }
    uint32_t poly_sz = 2 * ctx->para->phiM * ctx->para->qsz;
    uint32_t map_sz = 2 * ctx->para->phiM * ctx->para->qsz * ctx->para->moduli->modLen;
    uint32_t slot_sz = ctx->para->slots_size;
    uint32_t crt_sz = BN_BITS_TO_BYTES(poly_sz + map_sz) + sizeof(CKKS_Poly);
    if ((*outLen) < crt_sz) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }
    if (inputLen > slot_sz * sizeof(CKKS_Complex)) { // Exceeded the number of valid slots, need to expand m.
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_Encrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *input, uint32_t inputLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = EncryptInputCheck(ctx, input, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CKKS_Complex_Array *input_arr = (CKKS_Complex_Array *)BSL_SAL_Malloc(inputLen);
    ret = CKKS_Bin2ComplexArray(input_arr, input, inputLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ctx->para->mag = Default_Mag(input_arr);
    CKKS_Poly *Eptxt = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly));
    ret = CKKS_Poly_Init(Eptxt, ctx->para->bits, ctx->para->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_CKKS_Encode(ctx, Eptxt, input_arr);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_CKKS_PubEnc(ctx, Eptxt, inputLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

static int32_t DecryptInputCheck(const CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, const uint8_t *out,
                                 const uint32_t *outLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0 || out == NULL || *outLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_NO_KEY_INFO);
        return CRYPT_CKKS_NO_KEY_INFO;
    }

    uint32_t poly_sz = 2 * ctx->para->phiM * ctx->para->qsz;
    uint32_t map_sz = 2 * ctx->para->phiM * ctx->para->qsz * ctx->para->moduli->modLen;
    uint32_t slot_sz = ctx->para->slots_size;
    uint32_t mag_bit = (uint32_t)log2(ctx->para->mag);
    size_t crt_sz = BN_BITS_TO_BYTES(poly_sz + map_sz) + sizeof(CKKS_Poly) + sizeof(CKKS_DoubleCRT);

    if (dataLen < crt_sz) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }
    if ((*outLen) > 2 * slot_sz * BN_BITS_TO_BYTES(mag_bit)) { // Exceeded the number of valid slots, need to expand m.
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_CKKS_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CKKS_CheckCiphertext(CRYPT_CKKS_Ctx *ctx, const CKKS_DoubleCRT *ciphertext0,
                                          const CKKS_DoubleCRT *ciphertext1)
{
    if (!CKKS_PolyCtx_Cmp(ciphertext0->poly->polyctx, ciphertext1->poly->polyctx)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    if (ciphertext0->poly->degree > ctx->para->phiM) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_ERR_CAL_VALUE);
        return CRYPT_CKKS_ERR_CAL_VALUE;
    }
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CKKS_NO_KEY_INFO);
        return CRYPT_CKKS_NO_KEY_INFO;
    }

    int32_t ret = CRYPT_SUCCESS;
    double total_bound = ctx->para->scale * ctx->para->mag + ctx->para->noise_bound;
    uint32_t nbits = ctx->para->bits;
    BN_Optimizer *optimizer = BN_OptimizerCreate();
    BN_BigNum *Q = Get_ModularQ(ctx->para->moduli, ctx->para->bits, optimizer);
    if (Q == NULL || optimizer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BN_BigNum *total_noise_bn = BN_Create(nbits);
    BN_BigNum *bn48 = BN_Create(nbits);
    BN_BigNum *tmp = BN_Create(nbits);
    if (Q == NULL || total_noise_bn == NULL || bn48 == NULL || tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = BN_SetLimb(total_noise_bn, (uint32_t)100 * total_bound);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SetLimb(bn48, 48);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Mul(tmp, Q, bn48, optimizer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (BN_Cmp(total_noise_bn, tmp) == 1) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

EXIT:
    BN_Destroy(Q);
    BN_Destroy(total_noise_bn);
    BN_Destroy(bn48);
    BN_Destroy(tmp);
    BN_OptimizerDestroy(optimizer);
    return ret;
}

int32_t CRYPT_CKKS_Decrypt(CRYPT_CKKS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret = DecryptInputCheck(ctx, data, dataLen, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CKKS_DoubleCRT **crt_Dptxt = (CKKS_DoubleCRT **)BSL_SAL_Malloc(2 * sizeof(CKKS_DoubleCRT *));
    crt_Dptxt[0] = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));
    crt_Dptxt[1] = (CKKS_DoubleCRT *)BSL_SAL_Malloc(sizeof(CKKS_DoubleCRT));

    ret = CKKS_DoubleCRT_Bin2Cipher(data, dataLen, crt_Dptxt[0], crt_Dptxt[1]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Check whether the noise of the ciphertext exceeds 0.48*Q
    ret = CRYPT_CKKS_CheckCiphertext(ctx, crt_Dptxt[0], crt_Dptxt[1]);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CKKS_Poly *ptxt_poly = (CKKS_Poly *)BSL_SAL_Malloc(sizeof(CKKS_Poly));
    ret = CRYPT_CKKS_PrvDec(ctx, crt_Dptxt, ptxt_poly);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    CKKS_Complex_Array *ptxt_complex = (CKKS_Complex_Array *)BSL_SAL_Malloc(sizeof(CKKS_Complex_Array));
    ret = CKKS_Complex_Array_Init(ptxt_complex, ctx->para->phiM);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_CKKS_Decode(ctx, ptxt_poly, ptxt_complex);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CKKS_ComplexArray2Bin(ptxt_complex, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}

static int32_t CRYPT_CKKS_GetLen(const CRYPT_CKKS_Ctx *ctx, GetLenFunc func, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *(int32_t *)val = func(ctx);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CKKS_Ctrl(CRYPT_CKKS_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_CKKS_GetLen(ctx, (GetLenFunc)CRYPT_CKKS_GetBits, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_CKKS_GetLen(ctx, (GetLenFunc)CRYPT_CKKS_GetSecBits, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_CKKS_CTRL_NOT_SUPPORT_ERROR);
            return CRYPT_CKKS_CTRL_NOT_SUPPORT_ERROR;
    }
}

#endif //HITLS_CRYPTO_CKKS