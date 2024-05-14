/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */


/* Some of these codes are adapted from https://ed448goldilocks.sourceforge.net/ by Mike Hamburg */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE448

#include "securec.h"
#include "curve448_local.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"

#define CURVE448_ERROR_INDEX (-2)

// Modulo P = 2^448 - 2^224 - 1
static const Fp16 g_P = {{
    0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff,
    0x0ffffffe, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff
}};

static const Scalar g_ScalarP = {{
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff
}};

static const Scalar g_ScalarR2 = {{
    0x049b9b60, 0xe3539257, 0xc1b195d9, 0x7af32c4b, 0x88ea1859, 0x0d66de23, 0x5ee4d838, 0xae17cf72,
    0xa3c47c44, 0x1a9cc14b, 0xe4d070af, 0x2052bcb7, 0xf823b729, 0x3402a939
}};

static const Scalar g_ScalarMulBaseAdd = {{
    0x4a7bb0cf, 0xc873d6d5, 0x23a70aad, 0xe933d8d7, 0x129c96fd, 0xbb124b65, 0x335dc163, 0x00000008
}};

static const Scalar g_ScalarOne = {{1}};
static const Fp16 g_FpZero = {{0}};
#ifdef HITLS_CRYPTO_ED448
static const Fp16 g_FpOne = {{1}};
#endif

// fast Karatsuba multiplication, (a + bφ) · (c + dφ) =  (ac + bd) + ((a + b)(c + d) − ac)φ
void Curve448FpMul(Fp16 *out, const Fp16 *in1, const Fp16 *in2)
{
    uint64_t num0 = 0; // store (ac + bd)
    uint64_t num1 = 0; // store ((a + b)(c + d) - ac)
    uint64_t tmp;
    uint32_t aPlusB[FP_LIMB_HALF_LEN];
    uint32_t cPlusD[FP_LIMB_HALF_LEN];
    int32_t i, j;

    for (i = 0; i < FP_LIMB_HALF_LEN; i++) {
        aPlusB[i] = in1->data[i] + in1->data[i + FP_LIMB_HALF_LEN];
        cPlusD[i] = in2->data[i] + in2->data[i + FP_LIMB_HALF_LEN];
    }

    for (i = 0; i < FP_LIMB_HALF_LEN; i++) {
        tmp = 0;
        for (j = 0; j <= i; j++) {
            tmp += (uint64_t)in1->data[i - j] * in2->data[j];
            num1 += (uint64_t)aPlusB[i - j] * cPlusD[j];
            num0 += (uint64_t)in1->data[i - j + FP_LIMB_HALF_LEN] * in2->data[j + FP_LIMB_HALF_LEN];
        }

        num0 += tmp;
        num1 -= tmp;
        tmp = 0;

        for (j = i + 1; j < FP_LIMB_HALF_LEN; j++) {
            tmp += (uint64_t)aPlusB[i - j + FP_LIMB_HALF_LEN] * cPlusD[j];
            num1 += (uint64_t)in1->data[i - j + FP_LIMB_LEN] * in2->data[j + FP_LIMB_HALF_LEN];
            num0 -= (uint64_t)in1->data[i - j + FP_LIMB_HALF_LEN] * in2->data[j];
        }
        num0 += tmp;
        num1 += tmp;
        out->data[i] = (uint32_t)num0 & MASK28;
        out->data[i + FP_LIMB_HALF_LEN] = (uint32_t)num1 & MASK28;
        // process carry
        num0 >>= FP_LIMB_BITS;
        num1 >>= FP_LIMB_BITS;
    }
    // process 2 additional carry
    num0 += num1;
    num0 += out->data[FP_LIMB_HALF_LEN];
    num1 += out->data[0];
    out->data[FP_LIMB_HALF_LEN] = (uint32_t)num0 & MASK28;
    out->data[0] = (uint32_t)num1 & MASK28;

    num0 >>= FP_LIMB_BITS;
    num1 >>= FP_LIMB_BITS;
    out->data[FP_LIMB_HALF_LEN + 1] += (uint32_t)num0;
    out->data[1] += (uint32_t)num1;
}

void Curve448FpMulNum(Fp16 *out, const Fp16 *in, uint32_t num)
{
    uint64_t num0 = 0;
    uint64_t num8 = 0;
    int32_t i;

    for (i = 0; i < FP_LIMB_HALF_LEN; i++) {
        num0 += (uint64_t)num * in->data[i];
        num8 += (uint64_t)num * in->data[i + FP_LIMB_HALF_LEN];
        out->data[i] = (uint32_t)num0 & MASK28;
        out->data[i + FP_LIMB_HALF_LEN] = (uint32_t)num8 & MASK28;
        num8 >>= FP_LIMB_BITS;
        num0 >>= FP_LIMB_BITS;
    }

    // process 2 additional carry
    num0 += num8;
    num0 += out->data[FP_LIMB_HALF_LEN];
    out->data[FP_LIMB_HALF_LEN] = (uint32_t)num0 & MASK28;
    num0 >>= FP_LIMB_BITS;
    out->data[FP_LIMB_HALF_LEN + 1] += (uint32_t)num0;

    num8 += out->data[0];
    out->data[0] = (uint32_t)num8 & MASK28;
    num8 >>= FP_LIMB_BITS;
    out->data[1] += (uint32_t)num8;
}

void Curve448FpSqr(Fp16 *out, const Fp16 *in)
{
    Curve448FpMul(out, in, in);
}

void Curve448FpMultiSqr(Fp16 *out, Fp16 *in, int32_t times)
{
    Fp16 tmp;
    int32_t i;
    int32_t timesLocal = times;
    if (timesLocal % 2 == 0) {
        CURVE448_FP_COPY(*out, *in);
    } else {
        Curve448FpSqr(out, in);
        timesLocal -= 1;
    }
    for (i = 0; i < timesLocal; i += 2) {
        Curve448FpSqr(&tmp, out);
        Curve448FpSqr(out, &tmp);
    }
}

void Curve448FpInverse(Fp16 *out, Fp16 *in)
{
    Fp16 t1, l0, l1, l2;

    Curve448FpSqr(&t1, in); // t1 = x^2

    Curve448FpSqr(&l1, &t1); // l1 = x^4
    Curve448FpMul(&l2, &t1, &l1); // l2 = x^6
    Curve448FpSqr(&l1, &l2); // l1 = x^12
    Curve448FpMul(&l2, &t1, &l1); // l2 = x^14 = x^(2^4 - 2^1)
    Curve448FpMultiSqr(&l1, &l2, 3); // l1 = x^112 = x^(2^7 - 2^4), +3

    Curve448FpMul(&l0, &l1, &l2); // l0 = x^(2^7 - 2^1)
    Curve448FpMultiSqr(&l1, &l0, 3); // l1 = x^(2^10 - 2^4), +3
    Curve448FpMul(&l0, &l1, &l2); // l0 = x^(2^10 - 2^1)

    Curve448FpMultiSqr(&l2, &l0, 9); // l2 = x^(2^19 - 2^10), +9
    Curve448FpMul(&l1, &l0, &l2); // l1 = x^(2^19 - 2^1)

    Curve448FpSqr(&l0, &l1); // l0 = x^(2^20 - 2^2)
    Curve448FpMul(&l2, &l0, &t1); // l2 = x^(2^20 - 2^1)

    Curve448FpMultiSqr(&l0, &l2, 18); // l0 = x^(2^38 - 2^19), +18
    Curve448FpMul(&l2, &l1, &l0); // l2 = x^(2^38 - 2^1)

    Curve448FpMultiSqr(&l0, &l2, 37); // l0 = x^(2^75 - 2^38), +37
    Curve448FpMul(&l1, &l2, &l0); // l1 = x^(2^75 - 2^1)

    Curve448FpMultiSqr(&l0, &l1, 37); // l0 = x^(2^112 - 2^38), +37
    Curve448FpMul(&l1, &l2, &l0); // l1 = x^(2^112 - 2^1)

    Curve448FpMultiSqr(&l0, &l1, 111); // l0 = x^(2^223 - 2^112), +111
    Curve448FpMul(&l2, &l1, &l0); // l2 = x^(2^223 - 2^1)

    Curve448FpSqr(&l0, &l2); // l0 = x^(2^224 - 2^2)
    Curve448FpMul(&l1, &t1, &l0); // l1 = x^(2^224 - 2^1)

    Curve448FpMultiSqr(&l0, &l1, 223); // l0 = x^(2^447 - 2^224), +223
    Curve448FpMul(&l1, &l2, &l0); // l1 = x^(2^447 - 2^224 + 2^223 - 2^1) = x^(2^447 - 2^223 - 2^1)

    Curve448FpSqr(&t1, &l1);
    Curve448FpMul(&l0, &t1, in);

    int32_t i;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        out->data[i] = l0.data[i];
    }
}

// out = in / 2
void ScalarDivideBy2(Scalar *out, const Scalar *in)
{
    int64_t carry = 0;
    uint64_t signMask;
    uint32_t addMask = -(in->data[0] & 1); // if lowest bit = 1, add p
    int32_t i;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        carry = (carry + (int64_t)in->data[i]) + (int64_t)(g_ScalarP.data[i] & addMask);
        out->data[i] = (uint32_t)carry;
        signMask = (-((uint64_t)carry >> 63)) & 0xffffffff00000000ULL;
        carry = (int64_t)(((uint64_t)carry >> 32) | signMask);
    }

    for (i = 0; i < SCALAR_LIMB_LEN - 1; i++) {
        out->data[i] = (out->data[i] >> 1) | (out->data[i + 1] << 31);
    }

    out->data[SCALAR_LIMB_LEN - 1] = (out->data[SCALAR_LIMB_LEN - 1] >> 1) | ((uint32_t)carry << 31);
}

// out = sum - sub + ((carry + flag) == -1 ? add : 0)
void ScalarSubAdd(Scalar *out, const uint32_t sum[SCALAR_LIMB_LEN], const Scalar *sub, const Scalar *add, uint32_t flag)
{
    int64_t carry = 0;
    uint64_t signMask;
    uint32_t addMask;
    int32_t i;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        carry = (carry + (int64_t)sum[i]) - (int64_t)sub->data[i];
        out->data[i] = (uint32_t)carry;
        signMask = (-((uint64_t)carry >> 63)) & 0xffffffff00000000ULL;
        carry = (int64_t)(((uint64_t)carry >> 32) | signMask);
    }
    addMask = (uint32_t)carry + flag;
    carry = 0;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        carry = carry + (int64_t)out->data[i] + (int64_t)(add->data[i] & addMask);
        out->data[i] = (uint32_t)carry;
        signMask = (-((uint64_t)carry >> 63)) & 0xffffffff00000000ULL;
        carry = (int64_t)(((uint64_t)carry >> 32) | signMask);
    }
}

#ifdef HITLS_CRYPTO_ED448
// out = -out
void ScalarNeg(Scalar *out)
{
    static const Scalar SCALAR_ZERO = {{0}};
    ScalarSubAdd(out, SCALAR_ZERO.data, out, &g_ScalarP, 0);
}
#endif

void ScalarAdd(Scalar *out, const Scalar *in1, const Scalar *in2)
{
    int64_t carry = 0;
    uint64_t signMask;
    int32_t i;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        carry = (carry + (int64_t)in1->data[i]) + (int64_t)in2->data[i];
        out->data[i] = (uint32_t)carry;
        signMask = (-((uint64_t)carry >> 63)) & 0xffffffff00000000ULL;
        carry = (int64_t)(((uint64_t)carry >> 32) | signMask);
    }

    ScalarSubAdd(out, out->data, &g_ScalarP, &g_ScalarP, (uint32_t)carry);
}

void ScalarMontMul(Scalar *out, const Scalar *in1, const Scalar *in2)
{
    uint32_t accumulate[SCALAR_LIMB_LEN + 1] = {0};
    uint32_t highCarry = 0;

    int32_t i, j;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        uint64_t carry = 0;
        for (j = 0; j < SCALAR_LIMB_LEN; j++) {
            carry += (uint64_t)in1->data[i] * in2->data[j] + accumulate[j];
            accumulate[j] = (uint32_t)carry;
            carry >>= 32; // shift 32
        }
        accumulate[j] = (uint32_t)carry;
        carry = 0;
        uint32_t tmp = accumulate[0] * 0xae918bc5; // montgomery factor

        for (j = 0; j < SCALAR_LIMB_LEN; j++) {
            carry += (uint64_t)tmp * g_ScalarP.data[j] + accumulate[j];
            if (j != 0) {
                accumulate[j - 1] = (uint32_t)(carry);
            }
            carry >>= 32;
        }
        carry += accumulate[j];
        carry += highCarry;
        accumulate[j - 1] = (uint32_t)(carry);
        highCarry = (uint32_t)(carry >> 32);
    }

    // sub add p for reduce
    ScalarSubAdd(out, accumulate, &g_ScalarP, &g_ScalarP, highCarry);
}

void Curve448EncodeFp(const Fp16 *in, uint8_t *out)
{
    int i;
    int j = 0;
    uint32_t tmp;
    // Fp16 has 16 * 28 bits, 28 = 3 * 8 + 4, 56 = 7 * 8, use 8 loops, each process 56 bits
    for (i = 0; i < 8; i++) {
        tmp = in->data[2 * i];
        out[j] = (uint8_t)tmp;
        out[j + 1] = (uint8_t)(tmp >> 8);
        out[j + 2] = (uint8_t)(tmp >> 16);
        out[j + 3] = (uint8_t)(tmp >> 24);

        tmp = in->data[2 * i + 1];
        out[j + 3] |= (uint8_t)((tmp & 0x0f) << 4);
        out[j + 4] = (uint8_t)(tmp >> 4);
        out[j + 5] = (uint8_t)(tmp >> 12);
        out[j + 6] = (uint8_t)(tmp >> 20);
        j += 7;
    }
}

void Curve448DecodeFp(const uint8_t *in, Fp16 *out)
{
    int i;
    int j = 0;
    uint32_t tmp;
    // Fp16 has 16 * 28 bits, 28 = 3 * 8 + 4, 56 = 7 * 8, use 8 loops, each process 56 bits
    for (i = 0; i < 8; i++) {
        tmp = (uint32_t)in[j];
        tmp |= ((uint32_t)in[j + 1]) << 8;
        tmp |= ((uint32_t)in[j + 2]) << 16;
        tmp |= ((uint32_t)(in[j + 3] & 0x0f)) << 24;

        out->data[2 * i] = tmp;

        j += 3;
        tmp = (uint32_t)(in[j] >> 4);
        tmp |= ((uint32_t)in[j + 1]) << 4;
        tmp |= ((uint32_t)in[j + 2]) << 12;
        tmp |= ((uint32_t)in[j + 3]) << 20;

        out->data[2 * i + 1] = tmp;
        j += 4;
    }
}

#ifdef HITLS_CRYPTO_ED448
void ScalarEncode(uint8_t *out, const Scalar *in)
{
    int32_t i;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        PUT_UINT32_LE(in->data[i], out, 4 * i);
    }
}
#endif

// for add and sub, to prevent overflow
void ProcessPartialCarry(Fp16 *in)
{
    uint32_t tmp = in->data[FP_LIMB_LEN - 1] >> FP_LIMB_BITS;
    in->data[8] += tmp;

    int32_t i;
    for (i = FP_LIMB_LEN - 1; i > 0; i--) {
        in->data[i] = (in->data[i] & MASK28) + (in->data[i - 1] >> FP_LIMB_BITS);
    }
    in->data[0] &= MASK28;
    in->data[0] += tmp;
}

// in = in + p * 2, then partial reduce
void ProcessSubCarry(Fp16 *in)
{
    int32_t i;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        in->data[i] += g_P.data[i] * 2;
    }

    ProcessPartialCarry(in);
}

// full reduce to 28 bits
void ProcessFullCarry(Fp16 *in)
{
    int64_t carry = 0;
    uint64_t mask;
    uint64_t signMask;
    ProcessPartialCarry(in);

    int32_t i;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        carry += (int64_t)in->data[i] - (int64_t)g_P.data[i];
        in->data[i] = (uint32_t)((uint64_t)carry & MASK28);
        signMask = (-((uint64_t)carry >> 63)) & 0xfffffff000000000ULL;
        carry = (int64_t)(((uint64_t)carry >> FP_LIMB_BITS) | signMask);
    }

    // carry is 0 or -1 now, mask is 0 or full 1 mask
    mask = (uint64_t)carry;

    uint64_t carry2 = 0;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        carry2 += (uint64_t)in->data[i] + (mask & g_P.data[i]);
        in->data[i] = carry2 & MASK28;
        carry2 >>= FP_LIMB_BITS;
    }
}

void PointNielsToStandard(Curve448Point *out, const PointNiels *in)
{
    CURVE448_FP_ADD(out->y, in->b, in->a);
    CURVE448_FP_SUB(out->x, in->b, in->a);
    Curve448FpMul(&out->t, &out->y, &out->x);
    out->z.data[0] = 1;
    uint32_t i;
    for (i = 1; i < FP_LIMB_LEN; i++) {
        out->z.data[i] = 0;
    }
}

#ifdef HITLS_CRYPTO_ED448
void PointToPNiels(PointPNiels *out, const Curve448Point *in)
{
    CURVE448_FP_SUB(out->a, in->y, in->x);
    CURVE448_FP_ADD(out->b, in->x, in->y);
    Curve448FpMulNum(&out->c, &in->t, 2 * 39082); // edwards d 39081 + 1 = 39082, times 2
    CURVE448_FP_SUB(out->c, g_FpZero, out->c);
    CURVE448_FP_ADD(out->z, in->z, in->z);
}
#endif

void PointAddNiels(Curve448Point *out, const PointNiels *in)
{
    Fp16 a, b, c;
    CURVE448_FP_SUB(b, out->y, out->x);

    Curve448FpMul(&a, &in->a, &b);

    CURVE448_FP_ADD(b, out->y, out->x);
    Curve448FpMul(&out->y, &in->b, &b);
    Curve448FpMul(&out->x, &in->c, &out->t);

    CURVE448_FP_ADD(c, a, out->y);
    CURVE448_FP_SUB(b, out->y, a);
    CURVE448_FP_SUB(out->y, out->z, out->x);
    CURVE448_FP_ADD(a, out->x, out->z);

    Curve448FpMul(&out->z, &a, &out->y);
    Curve448FpMul(&out->x, &out->y, &b);
    Curve448FpMul(&out->y, &a, &c);
    Curve448FpMul(&out->t, &b, &c);
}

#ifdef HITLS_CRYPTO_ED448
void PointSubNiels(Curve448Point *out, const PointNiels *in)
{
    Fp16 a, b, c;
    CURVE448_FP_SUB(b, out->y, out->x);

    Curve448FpMul(&a, &in->b, &b);

    CURVE448_FP_ADD(b, out->y, out->x);
    Curve448FpMul(&out->y, &in->a, &b);
    Curve448FpMul(&out->x, &in->c, &out->t);

    CURVE448_FP_ADD(c, a, out->y);
    CURVE448_FP_SUB(b, out->y, a);
    CURVE448_FP_ADD(out->y, out->z, out->x);
    CURVE448_FP_SUB(a, out->z, out->x);

    Curve448FpMul(&out->z, &a, &out->y);
    Curve448FpMul(&out->x, &out->y, &b);
    Curve448FpMul(&out->y, &a, &c);
    Curve448FpMul(&out->t, &b, &c);
}

void PointPNielsToStandard(Curve448Point *out, const PointPNiels *in)
{
    Fp16 tmp;
    CURVE448_FP_ADD(tmp, in->b, in->a);
    ProcessPartialCarry(&tmp);
    CURVE448_FP_SUB(out->y, in->b, in->a);
    Curve448FpMul(&out->t, &out->y, &tmp);
    Curve448FpMul(&out->x, &in->z, &out->y);
    Curve448FpMul(&out->y, &in->z, &tmp);
    Curve448FpSqr(&out->z, &in->z);
}

// base on "Ed448-Goldilocks, a new elliptic curve"
void PointAddPNiels(Curve448Point *out, const PointPNiels *in)
{
    Fp16 tmp;
    PointNiels n;
    Curve448FpMul(&tmp, &out->z, &in->z);
    CURVE448_FP_COPY(out->z, tmp);
    CURVE448_FP_COPY(n.a, in->a);
    CURVE448_FP_COPY(n.b, in->b);
    CURVE448_FP_COPY(n.c, in->c);
    PointAddNiels(out, &n);
}

int32_t PointEqual(Curve448Point *a, Curve448Point *b)
{
    Fp16 tmp1, tmp2;
    Curve448FpMul(&tmp1, &a->y, &b->x);
    Curve448FpMul(&tmp2, &b->y, &a->x);

    CURVE448_FP_SUB(tmp1, tmp1, tmp2);
    ProcessFullCarry(&tmp1);

    int32_t i;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        if (tmp1.data[i] != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_POINT_NOT_EQUAL);
            return CRYPT_CURVE448_POINT_NOT_EQUAL;
        }
    }
    return CRYPT_SUCCESS;
}
#endif

// decode for len less than or equal to 56
static void ScalarDecodePartial(Scalar *out, const uint8_t *in, uint32_t len)
{
    uint32_t i, j;
    uint32_t k = 0;
    for (i = 0; i < SCALAR_LIMB_LEN; i++) {
        out->data[i] = 0;
        for (j = 0; j < (sizeof(uint32_t)) && k < len; j++, k++) {
            out->data[i] |= ((uint32_t)in[k]) << (8 * j);
        }
    }
}

#ifdef HITLS_CRYPTO_ED448
void ScalarMul(Scalar *out, const Scalar *in1, const Scalar *in2)
{
    ScalarMontMul(out, in1, in2);
    ScalarMontMul(out, out, &g_ScalarR2);
}

void ScalarDecode(Scalar *out, const uint8_t *in, uint32_t len)
{
    Scalar tmp;

    uint32_t index = len - (len % 56); // split to 56 bytes group to prevent overflow
    ScalarDecodePartial(out, &in[index], len - index);

    while (index != 0) {
        index -= 56;
        ScalarDecodePartial(&tmp, &in[index], 56);

        ScalarMontMul(&tmp, &tmp, &g_ScalarOne);
        ScalarAdd(out, out, &tmp);
        ScalarMontMul(out, out, &g_ScalarR2);
    }
    BSL_SAL_CleanseData(&tmp, sizeof(Scalar));
}
#endif

#ifdef HITLS_CRYPTO_X448
// input is always 56 bytes
void ScalarDecodeX448(Scalar *out, const uint8_t *in)
{
    ScalarDecodePartial(out, in, X448_KEY_LEN);
    ScalarMontMul(out, out, &g_ScalarOne);
    ScalarMontMul(out, out, &g_ScalarR2);
}
#endif

uint32_t GetTableIndex(const Scalar *scalar, uint32_t i, uint32_t j)
{
    uint32_t index = 0;
    for (uint32_t k = 0; k < 5; k++) { // table is 5 * 18
        uint32_t bit = i + 18 * (k + j * 5) - 1;
        if (bit < 446) { // 446 is max bits of scalar
            index |= ((scalar->data[bit / 32] >> (bit % 32)) & 1) << k;
        }
    }
    return index;
}

void PointDouble(Curve448Point *out, const Curve448Point *in)
{
    Fp16 a, b, c, d;
    Curve448FpSqr(&c, &in->x);
    Curve448FpSqr(&a, &in->y);
    CURVE448_FP_ADD(d, c, a);
    ProcessPartialCarry(&d);
    CURVE448_FP_ADD(out->t, in->x, in->y);
    ProcessPartialCarry(&out->t);
    Curve448FpSqr(&b, &out->t);

    CURVE448_FP_SUB(b, b, d);
    CURVE448_FP_SUB(out->t, a, c);

    Curve448FpSqr(&out->x, &in->z);
    CURVE448_FP_ADD(out->z, out->x, out->x);
    ProcessPartialCarry(&out->z);
    CURVE448_FP_SUB(a, out->z, out->t);

    Curve448FpMul(&out->x, &a, &b);
    Curve448FpMul(&out->z, &out->t, &a);
    Curve448FpMul(&out->y, &out->t, &d);
    Curve448FpMul(&out->t, &b, &d);
}

#ifdef HITLS_CRYPTO_ED448
// zero is 0, 1, 1, 0
void PointSetZero(Curve448Point *point)
{
    CURVE448_FP_COPY(point->x, g_FpZero);
    CURVE448_FP_COPY(point->y, g_FpOne);
    CURVE448_FP_COPY(point->z, g_FpOne);
    CURVE448_FP_COPY(point->t, g_FpZero);
}

// base on "Ed448-Goldilocks, a new elliptic curve"
void PointSubPNiels(Curve448Point *out, const PointPNiels *in)
{
    Fp16 tmp;
    PointNiels n;
    Curve448FpMul(&tmp, &out->z, &in->z);
    CURVE448_FP_COPY(out->z, tmp);
    CURVE448_FP_COPY(n.a, in->a);
    CURVE448_FP_COPY(n.b, in->b);
    CURVE448_FP_COPY(n.c, in->c);
    PointSubNiels(out, &n);
}

// precompute wnaf table: a = in, compute a, 3a, 5a, 7a ... 15a, 8 elements
void PreComputeTable(PointPNiels out[8], Curve448Point *in)
{
    PointToPNiels(&out[0], in);
    Curve448Point tmp;
    PointPNiels doubleA;

    PointDouble(&tmp, in);
    PointToPNiels(&doubleA, &tmp);

    PointAddPNiels(&tmp, &out[0]); // tmp = 3a
    PointToPNiels(&out[1], &tmp);
    int32_t i;
    for (i = 2; i < 8; i++) { // a to 15a inc 2 = 8 elements
        PointAddPNiels(&tmp, &doubleA);
        PointToPNiels(&out[i], &tmp);
    }
}

uint32_t GetTailZeroBitsNum(uint32_t num)
{
    uint32_t tmp = num;
    uint32_t pos = 0;
    while ((tmp & 1) != 1) {
        tmp >>= 1;
        pos++;
    }
    return pos;
}

void ProcessWnafSlides(WnafSlide *outSlide, uint32_t slideLen, const Scalar *in, uint32_t controlLen)
{
    uint32_t index = slideLen - 1;
    uint32_t mask = controlLen - 1;
    uint32_t i;
    uint32_t pos, num;
    int32_t val;

    outSlide[index].position = -1; // exit
    outSlide[index].val = 0;
    index--;

    uint64_t curScalar = in->data[0] & MASK16;
    // process 16 bits each loop
    for (i = 1; i < 30; i++) { // scalar is 446 bits, 446 / 16 + 1 = 28, process 2 more for carry, total 30
        if (i < 28) { // 446 / 16 + 1 = 28
            if (i % 2 == 0) {
                curScalar += (uint64_t)(in->data[i / 2] << 16);
            } else {
                curScalar += (uint64_t)((in->data[i / 2] >> 16) << 16);
            }
        }

        while ((curScalar & MASK16) != 0) {
            pos = GetTailZeroBitsNum((uint32_t)curScalar);
            num = (uint32_t)(curScalar >> pos); // skipping zeros
            val = (int32_t)(num & mask);
            if ((num & controlLen) != 0) { // minus
                val -= (int32_t)controlLen;
            }
            outSlide[index].position = (int32_t)(pos + 16 * (i - 1));
            outSlide[index].val = val;
            curScalar = (uint64_t)((int64_t)curScalar - (int64_t)val * (int64_t)(1 << pos));
            index--;
        }
        curScalar >>= 16;
    }

    index++;
    for (i = 0; i < slideLen - index; i++) { // shift the array if not filled
        outSlide[i].position = outSlide[i + index].position;
        outSlide[i].val = outSlide[i + index].val;
    }
}

static int32_t ProcessFirstPoint(Curve448Point *out, WnafSlide kSlide, WnafSlide sSlide,
    PointPNiels preComputedA[8], int32_t *kCount, int32_t *sCount) // 3 bits precompute value, 2^3 = 8
{
    int32_t i;
    const PointNiels *element = NULL; // precomputed B
    i = kSlide.position;
    if (i > sSlide.position) {
        PointPNielsToStandard(out, &preComputedA[kSlide.val / 2]); // stores a, 3a, 5a..., div 2 for index
        *kCount = *kCount + 1;
    } else if (i < sSlide.position) {
        i = sSlide.position;
        element = WnafTableLookUp(sSlide.val / 2);
        if (element == NULL) {
            return CURVE448_ERROR_INDEX;
        }
        PointNielsToStandard(out, element);
        *sCount = *sCount + 1;
    } else if (i != 0) {
        element = WnafTableLookUp(sSlide.val / 2);
        if (element == NULL) {
            return CURVE448_ERROR_INDEX;
        }
        PointPNielsToStandard(out, &preComputedA[kSlide.val / 2]); // stores a, 3a, 5a..., div 2 for index
        PointAddNiels(out, element);
        *sCount = *sCount + 1;
        *kCount = *kCount + 1;
    }
    return i;
}

// wnaf table method, base on "New Multibase Non-Adjacent Form Scalar Multiplication
// and its Application to Elliptic Curve Cryptosystems"
// out = k * A + s * B
int32_t Curve448KAMulPlusMulBase(Curve448Point *out, const Scalar *s, const Scalar *k, Curve448Point *a)
{
    WnafSlide kSlide[114]; // 446 bits scalar, 446 / (3 + 1) = 112, plus 2 for carry, 114
    WnafSlide sSlide[77]; // 446 bits scalar, 446 / (5 + 1) = 75, plus 2 for carry, 77

    PointPNiels preComputedA[8]; // 3 bits, 2^3 = 8
    ProcessWnafSlides(kSlide, 114, k, 16); // 114 len, 2^(3+1) = 16
    ProcessWnafSlides(sSlide, 77, s, 64); // 77 len, 2^(5+1) = 64

    int32_t i, kCount, sCount;
    kCount = 0;
    sCount = 0;
    PreComputeTable(preComputedA, a);
    const PointNiels *element = NULL; // precomputed B

    i = ProcessFirstPoint(out, kSlide[0], sSlide[0], preComputedA, &kCount, &sCount);
    if (i == CURVE448_ERROR_INDEX) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_FAIL);
        return CRYPT_CURVE448_FAIL;
    }

    i--;
    for (; i >= 0; i--) {
        PointDouble(out, out);
        if (i == kSlide[kCount].position) {
            if (kSlide[kCount].val > 0) {
                PointAddPNiels(out, &preComputedA[kSlide[kCount].val / 2]);
            } else if (kSlide[kCount].val < 0) {
                PointSubPNiels(out, &preComputedA[(-kSlide[kCount].val) / 2]);
            }
            kCount++;
        }
        if (i != sSlide[sCount].position) {
            continue;
        }

        if (sSlide[sCount].val > 0) {
            element = WnafTableLookUp(sSlide[sCount].val / 2);
            if (element == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_FAIL);
                return CRYPT_CURVE448_FAIL;
            }
            PointAddNiels(out, element);
        } else if (sSlide[sCount].val < 0) {
            element = WnafTableLookUp((-sSlide[sCount].val) / 2);
            if (element == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_FAIL);
                return CRYPT_CURVE448_FAIL;
            }
            PointSubNiels(out, element);
        }
        sCount++;
    }
    return CRYPT_SUCCESS;
}
#endif

void Curve448PrecomputedMulBase(Curve448Point *out, const Scalar *in)
{
    Scalar scalar;
    ScalarAdd(&scalar, in, &g_ScalarMulBaseAdd);
    PointNiels tableElement;
    uint32_t i, j;

    ScalarDivideBy2(&scalar, &scalar);

    for (i = 18; i != 0; i--) { // table has 18 column
        if (i != 18) {
            PointDouble(out, out);
        }
        for (j = 0; j < 5; j++) {
            uint32_t index = GetTableIndex(&scalar, i, j);
            uint32_t invertMask;
            invertMask = (index >> 4) - 1;
            index ^= invertMask;
            index &= 0xf;

            TableLookUp(&tableElement, j, index);

            // niels invert: a = b, b = a, c = -c
            for (uint32_t l = 0; l < FP_LIMB_LEN; l++) {
                uint32_t tmp = (tableElement.a.data[l] ^ tableElement.b.data[l]) & invertMask;
                tableElement.a.data[l] ^= tmp;
                tableElement.b.data[l] ^= tmp;
            }
            Fp16 tmpFp;
            CURVE448_FP_SUB(tmpFp, g_FpZero, tableElement.c);
            for (uint32_t l = 0; l < FP_LIMB_LEN; l++) {
                uint32_t tmp = (tableElement.c.data[l] ^ tmpFp.data[l]) & invertMask;
                tableElement.c.data[l] ^= tmp;
            }
            if (i == 18 && j == 0) { // i = 18, j = 0: first one, convert to point
                PointNielsToStandard(out, &tableElement);
            } else {
                PointAddNiels(out, &tableElement);
            }
        }
    }
    BSL_SAL_CleanseData(&scalar, sizeof(scalar));
}

#ifdef HITLS_CRYPTO_ED448
void Ed448EncodePoint(uint8_t *out, const Curve448Point *in)
{
    Fp16 x, y, z, t, tmp;

    Curve448FpSqr(&x, &in->x);
    Curve448FpSqr(&t, &in->y);
    CURVE448_FP_ADD(tmp, x, t);
    ProcessPartialCarry(&tmp);
    CURVE448_FP_ADD(z, in->y, in->x);
    ProcessPartialCarry(&z);
    Curve448FpSqr(&y, &z);

    CURVE448_FP_SUB(y, y, tmp);
    CURVE448_FP_SUB(z, t, x);

    Curve448FpSqr(&x, &in->z);
    CURVE448_FP_ADD(t, x, x);
    ProcessPartialCarry(&t);
    CURVE448_FP_SUB(t, t, z);
    Curve448FpMul(&x, &t, &y);
    Curve448FpMul(&y, &z, &tmp);
    Curve448FpMul(&z, &tmp, &t);

    Curve448FpInverse(&z, &z);

    Curve448FpMul(&t, &x, &z);
    Curve448FpMul(&x, &y, &z);

    ProcessFullCarry(&x);

    Curve448EncodeFp(&x, out);
    out[ED448_KEY_LEN - 1] = 0;
    out[ED448_KEY_LEN - 1] |= (uint8_t)((t.data[0] & 1) << 7); // shift 7 to highest bit
}

int32_t Curve448FpIsr(Fp16 *out, Fp16 *in)
{
    Fp16 l0, l1, l2;

    Curve448FpSqr(&l1, in); // l1 = x^2
    Curve448FpMul(&l2, in, &l1); // l2 = x^3
    Curve448FpSqr(&l1, &l2); // l1 = x^6
    Curve448FpMul(&l2, in, &l1); // l2 = x^7 = x^(2^3 - 2^0)
    Curve448FpMultiSqr(&l1, &l2, 3); // l1 = x^(2^6 - 2^3), +3

    Curve448FpMul(&l0, &l1, &l2); // l0 = x^(2^6 - 2^0)
    Curve448FpMultiSqr(&l1, &l0, 3); // l1 = x^(2^9 - 2^3), +3
    Curve448FpMul(&l0, &l1, &l2); // l0 = x^(2^9 - 2^0)

    Curve448FpMultiSqr(&l2, &l0, 9); // l2 = x^(2^18 - 2^9), +9
    Curve448FpMul(&l1, &l0, &l2); // l1 = x^(2^18 - 2^0)

    Curve448FpSqr(&l0, &l1); // l0 = x^(2^19 - 2^1)
    Curve448FpMul(&l2, &l0, in); // l2 = x^(2^19 - 2^0)

    Curve448FpMultiSqr(&l0, &l2, 18); // l0 = x^(2^37 - 2^18), +18
    Curve448FpMul(&l2, &l1, &l0); // l2 = x^(2^37 - 2^0)

    Curve448FpMultiSqr(&l0, &l2, 37); // l0 = x^(2^74 - 2^37), +37
    Curve448FpMul(&l1, &l2, &l0); // l1 = x^(2^74 - 2^0)

    Curve448FpMultiSqr(&l0, &l1, 37); // l0 = x^(2^111 - 2^37), +37
    Curve448FpMul(&l1, &l2, &l0); // l1 = x^(2^111 - 2^0)

    Curve448FpMultiSqr(&l0, &l1, 111); // l0 = x^(2^222 - 2^111), +111
    Curve448FpMul(&l2, &l1, &l0); // l2 = x^(2^222 - 2^0)

    Curve448FpSqr(&l0, &l2); // l0 = x^(2^223 - 2^1)
    Curve448FpMul(&l1, in, &l0); // l1 = x^(2^223 - 2^0)

    Curve448FpMultiSqr(&l0, &l1, 223); // l0 = x^(2^446 - 2^223), +223
    Curve448FpMul(&l1, &l2, &l0); // l1 = x^(2^446 - 2^223 + 2^222 - 2^0)
    Curve448FpSqr(&l2, &l1); // l2 = x^(2^447 - 2^223 - 2^1)
    Curve448FpMul(&l0, &l2, in); // l0 = x^(2^447 - 2^223 - 2^0)

    int32_t i;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        out->data[i] = l1.data[i];
    }
    CURVE448_FP_SUB(l0, l0, g_FpOne);
    ProcessFullCarry(&l0);
    for (i = 0; i < FP_LIMB_LEN; i++) {
        if (l0.data[i] != 0) {
            BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_FAIL);
            return CRYPT_CURVE448_FAIL;
        }
    }
    return CRYPT_SUCCESS;
}

bool FpLessThanP(const Fp16 *in)
{
    bool success = false;
    int32_t i;
    for (i = FP_LIMB_LEN - 1; i >= 0; i--) {
        if (g_P.data[i] > in->data[i]) {
            success = true;
            break;
        } else if (g_P.data[i] < in->data[i]) {
            break;
        }
    }
    return success;
}

int32_t ED448DecodePoint(Curve448Point *out, const uint8_t in[ED448_KEY_LEN])
{
    uint8_t localIn[ED448_KEY_LEN];
    (void)memcpy_s(localIn, ED448_KEY_LEN, in, ED448_KEY_LEN);

    uint32_t x0 = localIn[ED448_KEY_LEN - 1] >> 7; // shift 7 to get bit
    localIn[ED448_KEY_LEN - 1] &= 0x7f;
    Curve448DecodeFp(localIn, &out->y);
    if ((localIn[ED448_KEY_LEN - 1] != 0) || (!FpLessThanP(&out->y))) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_FAIL);
        return CRYPT_CURVE448_FAIL;
    }

    Fp16 u, v, a, b, c, d;
    Curve448FpSqr(&out->x, &out->y);
    CURVE448_FP_SUB(u, g_FpOne, out->x);

    Curve448FpMulNum(&v, &out->x, 39081); // edwards d = 39081
    CURVE448_FP_SUB(v, g_FpZero, v);
    CURVE448_FP_SUB(v, g_FpOne, v);

    Curve448FpMul(&out->x, &u, &v);
    if (Curve448FpIsr(&out->t, &out->x) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE448_FAIL);
        return CRYPT_CURVE448_FAIL;
    }

    Curve448FpMul(&out->x, &u, &out->t);
    uint32_t lowBit = out->x.data[0] & 1;

    // x = p - x
    if (lowBit != x0) {
        CURVE448_FP_SUB(out->x, g_FpZero, out->x);
    }
    CURVE448_FP_COPY(out->z, g_FpOne);

    Curve448FpSqr(&c, &out->x);
    Curve448FpSqr(&a, &out->y);
    CURVE448_FP_ADD(d, c, a);
    CURVE448_FP_ADD(out->t, out->y, out->x);
    Curve448FpSqr(&b, &out->t);
    CURVE448_FP_SUB(b, b, d);
    CURVE448_FP_SUB(out->t, a, c);
    Curve448FpSqr(&out->x, &out->z);
    CURVE448_FP_ADD(out->z, out->x, out->x);
    CURVE448_FP_SUB(a, out->z, d);

    Curve448FpMul(&out->x, &a, &b);
    Curve448FpMul(&out->z, &out->t, &a);
    Curve448FpMul(&out->y, &out->t, &d);
    Curve448FpMul(&out->t, &b, &d);
    return CRYPT_SUCCESS;
}
#endif /* HITLS_CRYPTO_ED448 */

#ifdef HITLS_CRYPTO_X448
void X448EncodePoint(uint8_t *out, Curve448Point *in)
{
    Curve448FpInverse(&in->t, &in->x);
    Curve448FpMul(&in->z, &in->t, &in->y);
    Curve448FpSqr(&in->y, &in->z);
    Curve448EncodeFp(&in->y, out);
}

static bool FpEqualZero(Fp16 *in)
{
    CURVE448_FP_SUB(*in, *in, g_FpZero);
    ProcessFullCarry(in);
    uint32_t checkValid = 0;
    uint32_t i;
    for (i = 0; i < FP_LIMB_LEN; i++) {
        checkValid |= in->data[i];
    }
    if (checkValid == 0) {
        return true;
    } else {
        return false;
    }
}

bool CRYPT_X448_ComputeSharedKeyValid(const uint8_t *prvKey, const uint8_t *pubKey, uint8_t *shareKey)
{
    Fp16 x1, x3, t1, t2, tmp;
    uint32_t swap = 0;
    Curve448DecodeFp(pubKey, &x1);
    uint8_t k[X448_KEY_LEN];
    (void)memcpy_s(k, X448_KEY_LEN, prvKey, X448_KEY_LEN);
    k[0] &= 252; // and 252 to clear last 2 bits
    k[X448_KEY_LEN - 1] |= 128; // or 128 to set highest bit
    CURVE448_FP_COPY(x3, x1);
    Fp16 x2 = {{1}};
    Fp16 z2 = {{0}};
    Fp16 z3 = {{1}};

    int32_t t;
    for (t = 447; t >= 0; t--) { // 56 * 8 = 448 bits, 0 - 447
        uint32_t kt = (k[(uint32_t)t >> 3] >> ((uint32_t)t & 7)) & 1; // shift 3 for byte index, and 7 to get low 3 bits
        swap ^= kt;
        CURVE448_FP_CSWAP(swap, x2.data, x3.data);
        CURVE448_FP_CSWAP(swap, z2.data, z3.data);
        swap = kt;

        CURVE448_FP_SUB(t1, x3, z3);
        CURVE448_FP_SUB(t2, x2, z2);
        CURVE448_FP_ADD(x2, x2, z2);
        CURVE448_FP_ADD(z2, x3, z3);

        Curve448FpMul(&z3, &t1, &x2);
        Curve448FpMul(&tmp, &z2, &t2);
        CURVE448_FP_COPY(z2, tmp);
        Curve448FpSqr(&t1, &t2);
        Curve448FpSqr(&t2, &x2);

        CURVE448_FP_ADD(x3, z3, z2);
        CURVE448_FP_SUB(z2, z3, z2);
        Curve448FpMul(&x2, &t2, &t1);
        CURVE448_FP_SUB(t2, t2, t1);
        Curve448FpSqr(&tmp, &z2);
        CURVE448_FP_COPY(z2, tmp);
        Curve448FpMulNum(&z3, &t2, 39082); // edwards d: 39801, z2 *= 39081 + 1 = 39082
        Curve448FpSqr(&tmp, &x3);
        CURVE448_FP_COPY(x3, tmp);
        CURVE448_FP_ADD(t1, t1, z3);
        Curve448FpMul(&z3, &x1, &z2);
        Curve448FpMul(&z2, &t2, &t1);
    }

    CURVE448_FP_CSWAP(swap, x2.data, x3.data);
    CURVE448_FP_CSWAP(swap, z2.data, z3.data);

    Curve448FpInverse(&t1, &z2);
    Curve448FpMul(&t2, &x2, &t1);
    Curve448EncodeFp(&t2, shareKey);

    BSL_SAL_CleanseData(k, sizeof(k));

    return !FpEqualZero(&t2);
}
#endif /* HITLS_CRYPTO_X448 */

#endif /* HITLS_CRYPTO_CURVE448 */
