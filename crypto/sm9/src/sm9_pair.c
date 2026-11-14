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
#ifdef HITLS_CRYPTO_SM9

#include "sm9_local.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include <string.h>

#define SM9_H_BYTE_LEN 40
#define SM9_H_WORD_LEN (SM9_H_BYTE_LEN / 4)

#define SM9_Fp_Assign(result, value)                              \
    do {                                                          \
        if ((result) != (value))                                  \
            memcpy((result), (value), 4 * g_sm9SysPara.wordSize); \
    } while (0)
#define SM9_Fp_SetOne(result) memcpy(result, g_sm9SysPara.qR1, 4 * g_sm9SysPara.wordSize)
#define SM9_Fq_IsZero(value)  SM9_BN_IsZero(value, g_sm9SysPara.wordSize)

#define SM9_Fp_Add(result, left, right) SM9_BN_ModAdd(result, left, right, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize)

#define SM9_Fp_Sub(result, left, right) SM9_BN_ModSub(result, left, right, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize)

#define SM9_Fp_Neg(result, value) \
    SM9_BN_ModSub(result, g_sm9SysPara.ecQ, value, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize)

#define SM9_Fp_LastRes(value) SM9_BN_GetResidue(value, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize)

#define SM9_Fp_Mul(result, left, right) \
    SM9_BN_MontMul(result, left, right, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize)

#define SM9_Fp_Squ(result, value) \
    SM9_BN_MontMul(result, value, value, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize)

#define SM9_Fp_Inv(result, value)                                                                                     \
    do {                                                                                                              \
        SM9_BN_MontMul(result, value, g_sm9SysPara.ecOne, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize); \
        SM9_BN_GetInvMont(result, result, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.qR2,                       \
                          g_sm9SysPara.wordSize);                                                                     \
    } while (0)

#define SM9_Fp_MulRoot(result, value) \
    SM9_BN_MontMul(result, value, g_sm9SysPara.ecRootMont, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize);

static void SM9_BN_Reset(uint32_t *value, int32_t wordSize)
{
    int32_t i;

    for (i = 0; i < wordSize; i++) {
        value[i] = 0;
    }
}

static void SM9_BN_SetInt(uint32_t *value, int32_t word, int32_t wordSize)
{
    int32_t i;

    value[0] = word;
    for (i = 1; i < wordSize; i++) {
        value[i] = 0;
    }
}

static void SM9_BN_Assign(uint32_t *result, const uint32_t *value, int32_t wordSize)
{
    int32_t i;

    if (result == value) {
        return;
    }

    for (i = 0; i < wordSize; i++) {
        result[i] = value[i];
    }
}

int32_t SM9_BN_Compare(const uint32_t *left, const uint32_t *right, int32_t wordSize)
{
    int32_t i;

    for (i = wordSize - 1; i >= 0; i--) {
        if (left[i] > right[i]) {
            return (1);
        }
        if (left[i] < right[i]) {
            return (-1);
        }
    }
    return 0;
}

int32_t SM9_BN_IsZero(uint32_t *value, int32_t wordSize)
{
    int32_t i;

    for (i = 0; i < wordSize; i++) {
        if (value[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int32_t SM9_BN_Equal(const uint32_t *left, const uint32_t *right, int32_t wordSize)
{
    int32_t i;

    for (i = 0; i < wordSize; i++) {
        if (left[i] != right[i]) {
            return 0;
        }
    }
    return 1;
}

static int32_t SM9_BN_GetBitLen(const uint32_t *value, int32_t wordSize)
{
    int32_t i;
    int32_t bitLen;
    uint32_t word = 0;

    for (i = wordSize - 1; i >= 0; i--) {
        if (value[i] != 0) {
            word = value[i];
            break;
        }
    }
    if (i < 0) {
        return 0;
    }

    bitLen = (i << 5) + 1;
    for (i = SM9_BN_WORD_BITS / 2; i > 0; i >>= 1) {
        if ((word >> i) != 0) {
            word >>= i;
            bitLen += i;
        }
    }

    return bitLen;
}

static int32_t SM9_BN_Div2(uint32_t *result, const uint32_t *value, int32_t wordSize)
{
    int32_t i;
    int32_t c = value[0] & SM9_BN_LSB_MASK;
    for (i = 0; i < wordSize - 1; i++) {
        result[i] = (value[i] >> 1) | (value[i + 1] << (SM9_BN_WORD_BITS - 1));
    }
    result[i] = value[i] >> 1;

    return c;
}

static uint32_t SM9_BN_Add(uint32_t *result, const uint32_t *left, const uint32_t *right, int32_t wordSize)
{
    int32_t i;
    uint64_t carry = 0;

    for (i = 0; i < wordSize; i++) {
        carry = (uint64_t)left[i] + (uint64_t)right[i] + carry;
        result[i] = (uint32_t)carry;
        carry = carry >> 32;
    }
    return (uint32_t)carry;
}

static uint32_t SM9_BN_Sub(uint32_t *result, const uint32_t *left, const uint32_t *right, int32_t wordSize)
{
    int32_t i = 0;
    uint64_t borrow = 0;

    for (i = 0; i < wordSize; i++) {
        borrow = (uint64_t)left[i] - (uint64_t)right[i] + borrow;
        result[i] = (uint32_t)borrow;
        borrow = (uint64_t)(((int64_t)borrow) >> 32);
    }
    return (uint32_t)borrow;
}

void SM9_BN_ModAdd(uint32_t *result, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
                   int32_t wordSize)
{
    int32_t i = 256; // Prevent infinite circulation

    if (SM9_BN_Add(result, left, right, wordSize) != 0) {
        while (i-- != 0) {
            if (SM9_BN_Sub(result, result, modulus, wordSize) != 0) {
                break;
            }
        }
    }
}

void SM9_BN_ModSub(uint32_t *result, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
                   int32_t wordSize)
{
    int32_t i = 256; // Prevent infinite circulation

    if (SM9_BN_Sub(result, left, right, wordSize) != 0) {
        while (i-- != 0) {
            if (SM9_BN_Add(result, result, modulus, wordSize) != 0) {
                break;
            }
        }
    }
}

static void SM9_BN_ModNeg(uint32_t *result, const uint32_t *value, const uint32_t *modulus, int32_t wordSize)
{
    int32_t i = 256; // Prevent infinite circulation

    if (SM9_BN_Sub(result, modulus, value, wordSize) != 0) {
        while (i-- != 0) {
            if (SM9_BN_Add(result, result, modulus, wordSize) != 0) {
                break;
            }
        }
    }
}

static void SM9_BN_ModDiv2(uint32_t *result, const uint32_t *value, const uint32_t *modulus, int32_t wordSize)
{
    uint32_t carry;

    if ((value[0] & SM9_BN_LSB_MASK) != 0) {
        carry = SM9_BN_Add(result, value, modulus, wordSize);
        SM9_BN_Div2(result, result, wordSize);
        result[wordSize - 1] |= carry << (SM9_BN_WORD_BITS - 1);
    } else {
        SM9_BN_Div2(result, value, wordSize);
    }
}

static void SM9_BN_ModInv(uint32_t *result, uint32_t *value, uint32_t *modulus, int32_t wordSize)
{
    uint32_t u[SM9_BN_WORDS];
    uint32_t v[SM9_BN_WORDS];
    uint32_t coeffU[SM9_BN_WORDS];
    uint32_t coeffV[SM9_BN_WORDS];

    // Step_1. u=p, v=a, A=1, B=0, C=0, D=1, while( A*p-B*a=u, -C*p+D*a=v )
    SM9_BN_Assign(u, modulus, wordSize);
    SM9_BN_Assign(v, value, wordSize);
    SM9_BN_Reset(coeffU, wordSize);
    SM9_BN_SetInt(coeffV, 1, wordSize);

    // Step_2. While v is nonzero, do
    while (SM9_BN_IsZero(v, wordSize) == 0) {
        // 2.1 If u is even, do { u = u / 2, B = B / 2 mod modulus }
        while ((u[0] & SM9_BN_LSB_MASK) == 0) {
            SM9_BN_Div2(u, u, wordSize);
            SM9_BN_ModDiv2(coeffU, coeffU, modulus, wordSize);
        }
        // 2.2 If v is even, do { v = v / 2, D = D / 2 mod modulus }
        while ((v[0] & SM9_BN_LSB_MASK) == 0) {
            SM9_BN_Div2(v, v, wordSize);
            SM9_BN_ModDiv2(coeffV, coeffV, modulus, wordSize);
        }
        // 2.3 If u > v, do { u = u - v,  B = B + D mod modulus }
        if (SM9_BN_Compare(u, v, wordSize) > 0) {
            SM9_BN_Sub(u, u, v, wordSize);
            SM9_BN_ModAdd(coeffU, coeffU, coeffV, modulus, wordSize);
        }
        // 2.4 If u <= v, do { v = v - u, D = D + B mod modulus }
        else {
            SM9_BN_Sub(v, v, u, wordSize);
            SM9_BN_ModAdd(coeffV, coeffV, coeffU, modulus, wordSize);
        }
    }

    // Step_3. Inverse is -B mod modulus
    SM9_BN_ModNeg(result, coeffU, modulus, wordSize);
}

void SM9_BN_GetInvMont(uint32_t *result, uint32_t *value, uint32_t *modulus, uint32_t montConst, uint32_t *rSquared,
                       int32_t wordSize)
{
    SM9_BN_ModInv(result, value, modulus, wordSize);
    SM9_BN_MontMul(result, result, rSquared, modulus, montConst, wordSize);
}

void SM9_BN_MontMul(uint32_t *result, const uint32_t *left, const uint32_t *right, const uint32_t *modulus,
                    uint32_t montConst, int32_t wordSize)
{
    int32_t i;
    int32_t j;
    uint64_t carry;
    uint32_t reductionFactor;
    uint32_t accumulator[SM9_BN_MAX_WORDS + 2];

    SM9_BN_Reset(accumulator, wordSize + 2);

    for (i = 0; i < wordSize; i++) {
        // accumulator = accumulator + left*right[i]
        carry = 0;
        for (j = 0; j < wordSize; j++) {
            carry = (uint64_t)accumulator[j] + (uint64_t)left[j] * (uint64_t)right[i] + carry;
            accumulator[j] = (uint32_t)carry;
            carry = carry >> 32;
        }
        carry = (uint64_t)accumulator[wordSize] + carry;
        accumulator[wordSize] = (uint32_t)carry;
        accumulator[wordSize + 1] = (uint32_t)(carry >> 32);

        // reductionFactor = accumulator[0] * ((-p)^(-1) mod b) mod b
        carry = (uint64_t)accumulator[0] * (uint64_t)montConst;
        reductionFactor = (uint32_t)carry;

        // accumulator = (accumulator + reductionFactor * p)/b
        carry = (uint64_t)accumulator[0] + (uint64_t)reductionFactor * (uint64_t)modulus[0];
        carry = carry >> 32;
        for (j = 1; j < wordSize; j++) {
            carry = (uint64_t)accumulator[j] + (uint64_t)reductionFactor * (uint64_t)modulus[j] + carry;
            accumulator[j - 1] = (uint32_t)carry;
            carry = carry >> 32;
        }
        carry = (uint64_t)accumulator[wordSize] + carry;
        accumulator[wordSize - 1] = (uint32_t)carry;
        accumulator[wordSize] = accumulator[wordSize + 1] + (uint32_t)(carry >> 32);
    }
    if (accumulator[wordSize] == 0) {
        SM9_BN_Assign(result, accumulator, wordSize);
    } else {
        SM9_BN_Sub(result, accumulator, modulus, wordSize);
    }
}

void SM9_BN_GetResidue(uint32_t *value, const uint32_t *modulus, int32_t wordSize)
{
    if (SM9_BN_Compare(value, modulus, wordSize) >= 0) {
        SM9_BN_Sub(value, value, modulus, wordSize);
    }
}

int32_t SM9_BN_ByteToBN(const uint8_t *input, int32_t byteLen, uint32_t *result, int32_t wordSize)
{
    int32_t wordLen = 0;
    int32_t partialBytes = 0;
    int32_t i = 0;
    int32_t j = 0;

    wordLen = byteLen >> 2;
    partialBytes = byteLen & 0x00000003;

    if (partialBytes != 0) {
        wordLen += 1;
    }

    if (wordLen > wordSize) {
        return 0;
    }

    i = byteLen - 1;
    j = 0;
    while (i >= partialBytes) {
        result[j] = ((uint32_t)input[i]) | ((uint32_t)input[i - 1] << 8) | ((uint32_t)input[i - 2] << 16) |
                    ((uint32_t)input[i - 3] << 24);
        i -= 4;
        j++;
    }

    i = 0;
    while (i < partialBytes) {
        result[j] = (result[j] << 8) | ((uint32_t)input[i]);
        i++;
    }

    return 1;
}

static void SM9_Fp_ReadBytes(uint32_t *dst, const uint8_t *src)
{
    SM9_BN_ByteToBN(src, SM9_BN_BYTES, dst, SM9_BN_WORDS);
    SM9_BN_MontMul(dst, dst, g_sm9SysPara.qR2, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize);
}

static void SM9_Fp2_Assign(SM9_Fp2 *result, SM9_Fp2 *source)
{
    memcpy(result, source, sizeof(SM9_Fp2));
}

static void SM9_Fp2_Add(SM9_Fp2 *result, SM9_Fp2 *left, SM9_Fp2 *right)
{
    SM9_Fp_Add(result->coef0, left->coef0, right->coef0);
    SM9_Fp_Add(result->coef1, left->coef1, right->coef1);
}

static void SM9_Fp2_Sub(SM9_Fp2 *result, SM9_Fp2 *left, SM9_Fp2 *right)
{
    SM9_Fp_Sub(result->coef0, left->coef0, right->coef0);
    SM9_Fp_Sub(result->coef1, left->coef1, right->coef1);
}

static void SM9_Fp2_Neg(SM9_Fp2 *result, SM9_Fp2 *value)
{
    SM9_Fp_Neg(result->coef0, value->coef0);
    SM9_Fp_Neg(result->coef1, value->coef1);
}

static void SM9_Fp2_Mul(SM9_Fp2 *result, SM9_Fp2 *left, SM9_Fp2 *right)
{
    uint32_t tmp0[SM9_BN_WORDS];
    uint32_t tmp1[SM9_BN_WORDS];
    uint32_t tmp2[SM9_BN_WORDS];

    SM9_Fp_Add(tmp0, left->coef0, left->coef1); // T0 = a0 + a1
    SM9_Fp_Add(tmp1, right->coef0, right->coef1); // T1 = b0 + b1
    SM9_Fp_Mul(tmp0, tmp0, tmp1); // T0 = T0 * T1 = (a0+a1)*(b0+b1)
    SM9_Fp_Mul(tmp1, left->coef0, right->coef0); // T1 = a0 * b0
    SM9_Fp_Sub(tmp0, tmp0, tmp1); // T0 = T0 - T1 = (a0+a1)*(b0+b1)-a0*b0
    SM9_Fp_Mul(tmp2, left->coef1, right->coef1); // T2 = a1 * b1
    SM9_Fp_Sub(tmp1, tmp1, tmp2); // T1 = T1 - T2 = a0*b0 - a1*b1
    SM9_Fp_Sub(result->coef0, tmp1, tmp2); // c0 = T1 - T2 = a0*b0 - 2*a1*b1
    SM9_Fp_Sub(result->coef1, tmp0, tmp2); // c1 = T0 - T2 = (a0+a1)*(b0+b1)-a0*b0-a1*b1
}

static void SM9_Fp2_Squ(SM9_Fp2 *result, SM9_Fp2 *value)
{
    uint32_t tmp0[SM9_BN_WORDS];
    uint32_t tmp1[SM9_BN_WORDS];

    SM9_Fp_Sub(tmp0, value->coef0, value->coef1); // v0=a0-a1
    SM9_Fp_Add(tmp1, value->coef0, value->coef1); // v1=a0+a1
    SM9_Fp_Add(tmp1, tmp1, value->coef1); // v1=a0+2*a1
    SM9_Fp_Mul(tmp0, tmp0, tmp1); // v0=v0*v1 = (a0-a1)*(a0+2*a1)
    SM9_Fp_Mul(tmp1, value->coef0, value->coef1); // v1=a0*a1
    SM9_Fp_Sub(result->coef0, tmp0, tmp1); // c0=v0-v1
    SM9_Fp_Add(result->coef1, tmp1, tmp1); // c1=v1+v1
}

static void SM9_Fp2_Inv(SM9_Fp2 *result, SM9_Fp2 *value)
{
    uint32_t tmp0[SM9_BN_WORDS];
    uint32_t tmp1[SM9_BN_WORDS];

    SM9_Fp_Squ(tmp0, value->coef0); // a0 ^ 2
    SM9_Fp_Squ(tmp1, value->coef1); // a1 ^ 2
    SM9_Fp_Add(tmp0, tmp0, tmp1);
    SM9_Fp_Add(tmp0, tmp0, tmp1); // a0 ^ 2 + 2*a1 ^ 2
    SM9_Fp_Inv(tmp0, tmp0); // 1 / (a0 ^ 2 + 2*a1 ^ 2)
    SM9_Fp_Mul(result->coef0, value->coef0, tmp0); // a0 / (a0 ^ 2 + 2*a1 ^ 2)
    SM9_Fp_Neg(tmp1, value->coef1); // -a1
    SM9_Fp_Mul(result->coef1, tmp1, tmp0); // -a1 / (a0 ^ 2 + 2*a1 ^ 2)
}

static void SM9_Fp2_MulCoef0(SM9_Fp2 *result, SM9_Fp2 *value, uint32_t *coefficient)
{
    SM9_Fp_Mul(result->coef0, value->coef0, coefficient);
    SM9_Fp_Mul(result->coef1, value->coef1, coefficient);
}

static void SM9_Fp2_MulVq(SM9_Fp2 *result, SM9_Fp2 *value)
{
    SM9_Fp_Mul(result->coef0, value->coef0, g_sm9SysPara.ecVqMont);
    SM9_Fp_Mul(result->coef1, value->coef1, g_sm9SysPara.ecVqMont);
}

static void SM9_Fp2_MulU(SM9_Fp2 *result, SM9_Fp2 *value)
{
    uint32_t tmp0[SM9_BN_WORDS];

    SM9_Fp_Neg(tmp0, value->coef1);
    SM9_Fp_Assign(result->coef1, value->coef0);
    SM9_Fp_Add(result->coef0, tmp0, tmp0);
}

static void SM9_Fp2_FrobMap(SM9_Fp2 *result, SM9_Fp2 *value)
{
    SM9_Fp_Assign(result->coef0, value->coef0);
    SM9_Fp_Neg(result->coef1, value->coef1);
}

static void SM9_Fp4_Add(SM9_Fp4 *result, SM9_Fp4 *left, SM9_Fp4 *right)
{
    SM9_Fp2_Add(&result->coef0, &left->coef0, &right->coef0);
    SM9_Fp2_Add(&result->coef1, &left->coef1, &right->coef1);
}

static void SM9_Fp4_Sub(SM9_Fp4 *result, SM9_Fp4 *left, SM9_Fp4 *right)
{
    SM9_Fp2_Sub(&result->coef0, &left->coef0, &right->coef0);
    SM9_Fp2_Sub(&result->coef1, &left->coef1, &right->coef1);
}

static void SM9_Fp4_Neg(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2_Neg(&result->coef0, &value->coef0);
    SM9_Fp2_Neg(&result->coef1, &value->coef1);
}

static void SM9_Fp4_Mul(SM9_Fp4 *result, SM9_Fp4 *left, SM9_Fp4 *right)
{
    SM9_Fp2 tmp0;
    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;

    SM9_Fp2_Add(&tmp0, &left->coef0, &left->coef1); // V0 = a0 + a1
    SM9_Fp2_Add(&tmp1, &right->coef0, &right->coef1); // V1 = b0 + b1
    SM9_Fp2_Mul(&tmp0, &tmp0, &tmp1); // V0 = V0 * V1 = (a0+a1)*(b0+b1)
    SM9_Fp2_Mul(&tmp1, &left->coef1, &right->coef1); // V1 = a1 * b1
    SM9_Fp2_Sub(&tmp0, &tmp0, &tmp1); // V0 = V0 - V1 = (a0+a1)*(b0+b1)-a1*b1
    SM9_Fp2_MulU(&tmp1, &tmp1); // V1 = V1 *  u = a1*b1*u
    SM9_Fp2_Mul(&tmp2, &left->coef0, &right->coef0); // V2 = a0 * b0
    SM9_Fp2_Add(&result->coef0, &tmp1, &tmp2); // c0 = V1 + V2 = a0 *b0+a1*b1*u
    SM9_Fp2_Sub(&result->coef1, &tmp0, &tmp2); // c1 = V0 - V2 = v2*v3-v0-v1
}

static void SM9_Fp4_Squ(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2 tmp0;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;

    SM9_Fp2_Sub(&tmp0, &value->coef0, &value->coef1); // tmp0= a0 - a1
    SM9_Fp2_MulU(&tmp3, &value->coef1); // tmp3= u*a1
    SM9_Fp2_Sub(&tmp3, &value->coef0, &tmp3); // tmp3= a0 - u*a1

    SM9_Fp2_Mul(&tmp2, &value->coef0, &value->coef1); // tmp2 = a0 * a1

    SM9_Fp2_Mul(&tmp0, &tmp0, &tmp3); // tmp0=tmp0*tmp3
    SM9_Fp2_Add(&tmp0, &tmp0, &tmp2); // tmp0=tmp0*tmp3+tmp2

    SM9_Fp2_Add(&result->coef1, &tmp2, &tmp2); // c1 = tmp2 + tmp2

    SM9_Fp2_MulU(&result->coef0, &tmp2); // c0 = u*tmp2
    SM9_Fp2_Add(&result->coef0, &result->coef0, &tmp0); // c0 = tmp0 + u*tmp2
}

static void SM9_Fp4_MulCoef0(SM9_Fp4 *result, SM9_Fp4 *value, SM9_Fp2 *coefficient)
{
    SM9_Fp2_Mul(&result->coef0, &value->coef0, coefficient);
    SM9_Fp2_Mul(&result->coef1, &value->coef1, coefficient);
}

static void SM9_Fp4_MulWq(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2_MulCoef0(&result->coef0, &value->coef0, g_sm9SysPara.ecWqMont);
    SM9_Fp2_MulCoef0(&result->coef1, &value->coef1, g_sm9SysPara.ecWqMont);
}

static void SM9_Fp4_MulW2q(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2_MulCoef0(&result->coef0, &value->coef0, g_sm9SysPara.ecW2qMont);
    SM9_Fp2_MulCoef0(&result->coef1, &value->coef1, g_sm9SysPara.ecW2qMont);
}

static void SM9_Fp4_Inv(SM9_Fp4 *result, SM9_Fp4 *value)
{
    // value = a0 + a1 * v, where v ^ 2 = u
    SM9_Fp2 tmp0;
    SM9_Fp2 tmp1;

    SM9_Fp2_Squ(&tmp0, &value->coef0); // a0 ^ 2
    SM9_Fp2_Squ(&tmp1, &value->coef1); // a1 ^ 2
    SM9_Fp2_MulU(&tmp1, &tmp1); // a1^2 * u
    SM9_Fp2_Sub(&tmp0, &tmp0, &tmp1); // a0^2 - a1^2 * u
    SM9_Fp2_Inv(&tmp1, &tmp0); // tmp1=(a0^2 - a1^2 * u) ^ (-1)

    SM9_Fp2_Mul(&result->coef0, &value->coef0, &tmp1); // a0 / (a0^2 - a1^2 * u)
    SM9_Fp2_Neg(&tmp0, &value->coef1); // tmp0=-a1
    SM9_Fp2_Mul(&result->coef1, &tmp0, &tmp1); // -a1 / (a0^2 - a1^2 * u)
}

static void SM9_Fp4_FrobMap(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2_FrobMap(&result->coef0, &value->coef0);
    SM9_Fp2_FrobMap(&result->coef1, &value->coef1);
    SM9_Fp2_MulVq(&result->coef1, &result->coef1);
}

static void SM9_Fp4_MulV(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2 tmpFp2;

    SM9_Fp2_Assign(&tmpFp2, &value->coef0);

    // (a0+a1*v) * v=a0 * v + a1 *v ^2
    // = a1*u+a0 * v
    // tmpFp4.coef0 = a1* u
    SM9_Fp2_MulU(&result->coef0, &value->coef1);

    // tmpFp4.coef1 = a0
    SM9_Fp2_Assign(&result->coef1, &tmpFp2);
}

static void SM9_Fp4_MulCoef1(SM9_Fp4 *result, SM9_Fp4 *value, SM9_Fp2 *coefficient)
{
    SM9_Fp2 tmp0;

    SM9_Fp2_Mul(&tmp0, &value->coef1, coefficient);
    SM9_Fp2_Mul(&result->coef1, &value->coef0, coefficient); // c1 = a0 * b1
    SM9_Fp2_MulU(&result->coef0, &tmp0); // c0 = a1*b1*u
}

static void SM9_Fp4_MulV2(SM9_Fp4 *result, SM9_Fp4 *value)
{
    // (a0+a1*v) * v^2=a0 * v^2 + a1 *v ^ 3
    // = a0*u+a1 * u * v
    // tmpFp4.coef0 = a0* u
    SM9_Fp2_MulU(&result->coef0, &value->coef0);

    // tmpFp4.coef1 = a1* u
    SM9_Fp2_MulU(&result->coef1, &value->coef1);
}

static void SM9_Fp4_GetConj(SM9_Fp4 *result, SM9_Fp4 *value)
{
    SM9_Fp2_Assign(&result->coef0, &value->coef0);
    SM9_Fp2_Neg(&result->coef1, &value->coef1);
}

static void SM9_Fp2_Select(SM9_Fp2 *result, const SM9_Fp2 *left, const SM9_Fp2 *right, uint32_t mask)
{
    for (int32_t i = 0; i < SM9_BN_WORDS; i++) {
        result->coef0[i] = Uint32ConstTimeSelect(mask, left->coef0[i], right->coef0[i]);
        result->coef1[i] = Uint32ConstTimeSelect(mask, left->coef1[i], right->coef1[i]);
    }
}

static void SM9_Fp4_Select(SM9_Fp4 *result, const SM9_Fp4 *left, const SM9_Fp4 *right, uint32_t mask)
{
    SM9_Fp2_Select(&result->coef0, &left->coef0, &right->coef0, mask);
    SM9_Fp2_Select(&result->coef1, &left->coef1, &right->coef1, mask);
}

static void SM9_Fp12_Select(SM9_Fp12 *result, const SM9_Fp12 *left, const SM9_Fp12 *right, uint32_t mask)
{
    SM9_Fp4_Select(&result->coef0, &left->coef0, &right->coef0, mask);
    SM9_Fp4_Select(&result->coef1, &left->coef1, &right->coef1, mask);
    SM9_Fp4_Select(&result->coef2, &left->coef2, &right->coef2, mask);
}

static void SM9_Fp12_Reset(SM9_Fp12 *value)
{
    BSL_SAL_CleanseData(value, sizeof(SM9_Fp12));
}

static void SM9_Fp12_Assign(SM9_Fp12 *result, SM9_Fp12 *source)
{
    memcpy(result, source, sizeof(SM9_Fp12));
}

static void SM9_Fp12_SetOne(SM9_Fp12 *element)
{
    SM9_Fp12_Reset(element);
    SM9_Fp_SetOne(element->coef0.coef0.coef0);
}

void SM9_Fp12_Mul(SM9_Fp12 *result, SM9_Fp12 *left, SM9_Fp12 *right)
{
    SM9_Fp4 tmp0;
    SM9_Fp4 tmp1;
    SM9_Fp4 tmp2;
    SM9_Fp4 tmp3;
    SM9_Fp4 tmp4;
    SM9_Fp4 tmp5;
    SM9_Fp4 tmp6;

    SM9_Fp4_Mul(&tmp0, &left->coef0, &right->coef0); // V0=a0*b0
    SM9_Fp4_Mul(&tmp1, &left->coef1, &right->coef1); // V1=a1*b1
    SM9_Fp4_Mul(&tmp2, &left->coef2, &right->coef2); // V2=a2*b2

    SM9_Fp4_Add(&tmp3, &left->coef1, &left->coef2); // V3= a1 + a2
    SM9_Fp4_Add(&tmp6, &right->coef1, &right->coef2); // V6= b1 + b2
    SM9_Fp4_Mul(&tmp3, &tmp3, &tmp6); // V3=(a1+a2)*(b1+b2)

    SM9_Fp4_Add(&tmp4, &left->coef0, &left->coef1); // tmp4= a0 + a1
    SM9_Fp4_Add(&tmp6, &right->coef0, &right->coef1); // V6= b0 + b1
    SM9_Fp4_Mul(&tmp4, &tmp4, &tmp6); // V4=(a0+a1)*(b0+b1)

    SM9_Fp4_Add(&tmp5, &left->coef0, &left->coef2); // V5= a0 + a2
    SM9_Fp4_Add(&tmp6, &right->coef0, &right->coef2); // V6= b0 + b2
    SM9_Fp4_Mul(&tmp5, &tmp5, &tmp6); // V5=(a0+a2)*(b0+b2)

    SM9_Fp4_Sub(&tmp3, &tmp3, &tmp1); // V3=(a1+a2)*(b1+b2)-V1
    SM9_Fp4_Sub(&tmp3, &tmp3, &tmp2); // V3=(a1+a2)*(b1+b2)-V1-V2
    SM9_Fp4_MulV(&tmp3, &tmp3); // V3=((a1+a2)*(b1+b2)-V1-V2)*v
    SM9_Fp4_Add(&result->coef0, &tmp3, &tmp0); // c0=((a1+a2)*(b1+b2)-V1-V2)*v+V0

    SM9_Fp4_Sub(&tmp4, &tmp4, &tmp0); // V4=(a0+a1)*(b0+b1)-V0
    SM9_Fp4_Sub(&tmp4, &tmp4, &tmp1); // V4=(a0+a1)*(b0+b1)-V0-V1
    SM9_Fp4_MulV(&tmp6, &tmp2); // V6=V2 * v
    SM9_Fp4_Add(&result->coef1, &tmp4, &tmp6); // c1=(a0+a1)*(b0+b1)-V0-V1+V2*v

    SM9_Fp4_Sub(&tmp5, &tmp5, &tmp0); // V5=(a0+a2)*(b0+b2)-V0
    SM9_Fp4_Sub(&tmp5, &tmp5, &tmp2); // V5=(a0+a2)*(b0+b2)-V0-V2
    SM9_Fp4_Add(&result->coef2, &tmp5, &tmp1); // c2=(a0+a2)*(b0+b2)-V0-V2+V1
}

static void SM9_Fp12_Squ(SM9_Fp12 *result, SM9_Fp12 *value)
{
    SM9_Fp4 tmp0;
    SM9_Fp4 tmp1;
    SM9_Fp4 tmp2;
    SM9_Fp4 tmp3;
    SM9_Fp4 tmp4;

    SM9_Fp4_Mul(&tmp0, &value->coef1, &value->coef2);
    SM9_Fp4_Add(&tmp0, &tmp0, &tmp0); // V0 = 2*a1*a2
    SM9_Fp4_Mul(&tmp1, &value->coef0, &value->coef1);
    SM9_Fp4_Add(&tmp1, &tmp1, &tmp1); // V1 = 2*a0*a1
    SM9_Fp4_Add(&tmp2, &value->coef0, &value->coef1);
    SM9_Fp4_Add(&tmp2, &tmp2, &value->coef2);
    SM9_Fp4_Squ(&tmp2, &tmp2); // V2 = (a0+a1+a2) ^ 2
    SM9_Fp4_Squ(&tmp3, &value->coef0); // V3 = a0^2
    SM9_Fp4_Squ(&tmp4, &value->coef2); // V4 = a2^2
    SM9_Fp4_Sub(&tmp2, &tmp2, &tmp1);
    SM9_Fp4_Sub(&tmp2, &tmp2, &tmp0);
    SM9_Fp4_Sub(&tmp2, &tmp2, &tmp3);
    SM9_Fp4_Sub(&result->coef2, &tmp2, &tmp4); // c3 = V2-V1-V0-V3-V4
    SM9_Fp4_MulV(&tmp0, &tmp0);
    SM9_Fp4_Add(&result->coef0, &tmp3, &tmp0); // c0 = V0*u + V3
    SM9_Fp4_MulV(&tmp4, &tmp4);
    SM9_Fp4_Add(&result->coef1, &tmp4, &tmp1); // c1 = V4*u + V1
}

static void SM9_Fp12_Inv(SM9_Fp12 *result, SM9_Fp12 *value)
{
    // (a0*b0 + (a2*b1 + a1*b2) * v) + (a1*b0 + a0*b1 + a2*b2 *v)*w + (a2*b0 + a1*b1 + a0*b2) w ^ 2
    //    Delta = a0 ^ 3 + a1 ^ 3 * v - 3 * a0*a1*a2*v + a2 ^ 3 * v ^ 2
    //    Delta0 = a0 ^ 2 - a1*a2*v
    //    Delta1 = -a0*a1 + a2 ^ 2 * v
    //    Delta2 = a1 ^ 2 - a0*a2
    SM9_Fp4 tmp0;
    SM9_Fp4 tmp1;
    SM9_Fp4 tmp2;
    SM9_Fp4 tmp3;
    SM9_Fp4 tmp4;

    SM9_Fp4_Squ(&tmp0, &value->coef0); // V0=a0^2
    SM9_Fp4_Squ(&tmp1, &value->coef2); // V1=a2^2
    SM9_Fp4_Squ(&tmp2, &value->coef1); // V2=a1^2

    SM9_Fp4_Mul(&tmp3, &tmp0, &value->coef0); // V3=a0^3
    SM9_Fp4_Mul(&tmp4, &tmp2, &value->coef1); // V4=a1^3
    SM9_Fp4_MulV(&tmp4, &tmp4); // V4=a1^3 * v
    SM9_Fp4_Add(&tmp3, &tmp3, &tmp4); // V3=a0^3 + a1^3 * v
    SM9_Fp4_Mul(&tmp4, &tmp1, &value->coef2); // V4=a2^3
    SM9_Fp4_MulV2(&tmp4, &tmp4); // V4=a2^3* v^2
    SM9_Fp4_Add(&tmp3, &tmp3, &tmp4); // V3=a0^3 + a1^3 * v+a2^3*v^2

    SM9_Fp4_Mul(&tmp4, &value->coef0, &value->coef2); // V4=a0*a2
    SM9_Fp4_Sub(&tmp2, &tmp2, &tmp4); // V2=a1^2 - a0*a2

    SM9_Fp4_Mul(&tmp4, &value->coef0, &value->coef1); // V4=a0*a1
    SM9_Fp4_MulV(&tmp1, &tmp1); // V1=a2^2*v
    SM9_Fp4_Sub(&tmp1, &tmp1, &tmp4); // V1=-a0*a1 + a2^2*v

    SM9_Fp4_Mul(&tmp4, &value->coef1, &value->coef2); // V4=a1*a2
    SM9_Fp4_MulV(&tmp4, &tmp4); // V4=a1*a2*v
    SM9_Fp4_Sub(&tmp0, &tmp0, &tmp4); // V0=a0^2 - a1*a2*v

    SM9_Fp4_Mul(&tmp4, &tmp4, &value->coef0); // T3=a0*a1*a2*v
    SM9_Fp4_Sub(&tmp3, &tmp3, &tmp4);
    SM9_Fp4_Sub(&tmp3, &tmp3, &tmp4);
    SM9_Fp4_Sub(&tmp3, &tmp3, &tmp4); // V3=a0^3 + a1^3 * v + a2^3*v^2 - 3*a0*a1*a2*v
    SM9_Fp4_Inv(&tmp3, &tmp3); // V3=(a0^3 + a1^3 * Zeta - 3*a0*a1*a2*Zeta + a2^3*Zeta^2) ^ (-1)
    SM9_Fp4_Mul(&result->coef1, &tmp1, &tmp3); // c1=(-a0*a1 + a2^2*v)/(a0^3 + a1^3 * v - 3*a0*a1*a2*v + a2^3*v^2)
    // c0=(a0^2 - a1*a2*Zeta)/(a0^3 + a1^3 * Zeta - 3*a0*a1*a2*Zeta + a2^3*Zeta^2)
    SM9_Fp4_Mul(&result->coef0, &tmp0, &tmp3);
    // c2=(a1^2 - a0*a2)/(a0^3 + a1^3 * Zeta - 3*a0*a1*a2*Zeta + a2^3*Zeta^2)
    SM9_Fp4_Mul(&result->coef2, &tmp2, &tmp3);
}

static void SM9_Fp12_FrobMap(SM9_Fp12 *result, SM9_Fp12 *value)
{
    // TODO: 加速优化乘法
    SM9_Fp4_FrobMap(&result->coef0, &value->coef0);
    SM9_Fp4_FrobMap(&result->coef1, &value->coef1);
    SM9_Fp4_MulWq(&result->coef1, &result->coef1);
    SM9_Fp4_FrobMap(&result->coef2, &value->coef2);
    SM9_Fp4_MulW2q(&result->coef2, &result->coef2);
}

static void SM9_Fp12_MulForMillerLoop(SM9_Fp12 *result, SM9_Fp12 *left, SM9_Fp12 *right)
{
    SM9_Fp4 tmp0;
    SM9_Fp4 tmp1;
    SM9_Fp4 tmp2;
    SM9_Fp4 tmp3;
    SM9_Fp4 tmp4;
    SM9_Fp4 tmp5;

    SM9_Fp4_Mul(&tmp0, &left->coef0, &right->coef0); // V0 = A0 * B0
    SM9_Fp4_MulCoef1(&tmp1, &left->coef1, &right->coef2.coef0); // V1 = A1 * C0 * v
    SM9_Fp4_Mul(&tmp2, &left->coef1, &right->coef0); // V2 = A1 * B0
    SM9_Fp4_MulCoef1(&tmp3, &left->coef2, &right->coef2.coef0); // V3 = A2 * C0 * v
    SM9_Fp4_Mul(&tmp4, &left->coef2, &right->coef0); // V4 = A2 * B0
    SM9_Fp4_MulCoef0(&tmp5, &left->coef0, &right->coef2.coef0); // V5 = A0 * C0

    SM9_Fp4_Add(&result->coef0, &tmp0, &tmp1); // c0=A0 * B0 + A1 * C0 * v
    SM9_Fp4_Add(&result->coef1, &tmp2, &tmp3); // c1=A1 * B0 + A2 * C0 * v
    SM9_Fp4_Add(&result->coef2, &tmp4, &tmp5); // c2=A1 * B0 + A2 * C0
}

static void SM9_Fp12_MulForFrobMap(SM9_Fp12 *result, SM9_Fp12 *left, SM9_Fp12 *right)
{
    SM9_Fp4 tmp0;
    SM9_Fp4 tmp1;
    SM9_Fp4 tmp2;
    SM9_Fp4 tmp3;
    SM9_Fp4 tmp4;
    SM9_Fp4 tmp5;

    SM9_Fp4_MulCoef1(&tmp0, &left->coef0, &right->coef0.coef1); // V0=A0*b01
    SM9_Fp4_Mul(&tmp1, &left->coef2, &right->coef1); // V1=A2*B1
    SM9_Fp4_MulV(&tmp1, &tmp1); // V1=A2*B1*v
    SM9_Fp4_MulCoef1(&tmp2, &left->coef1, &right->coef0.coef1); // V2=A1*b01
    SM9_Fp4_Mul(&tmp3, &left->coef0, &right->coef1); // V3=A0*B1
    SM9_Fp4_MulCoef1(&tmp4, &left->coef2, &right->coef0.coef1); // V4=A2*b01
    SM9_Fp4_Mul(&tmp5, &left->coef1, &right->coef1); // V5=A1*B1
    SM9_Fp4_Add(&result->coef0, &tmp0, &tmp1); // c0=A0*b01+A2*B1*v
    SM9_Fp4_Add(&result->coef1, &tmp2, &tmp3); // c1=A1*b01+A0*B1
    SM9_Fp4_Add(&result->coef2, &tmp4, &tmp5); // c2=A2*b01+A1*B1
}

static void SM9_Fp12_GetConj(SM9_Fp12 *result, SM9_Fp12 *value)
{
    SM9_Fp4_GetConj(&result->coef0, &value->coef0);
    SM9_Fp4_GetConj(&result->coef1, &value->coef1);
    SM9_Fp4_Neg(&result->coef1, &result->coef1);
    SM9_Fp4_GetConj(&result->coef2, &value->coef2);
}

void SM9_Fp12_Exp(SM9_Fp12 *result, SM9_Fp12 *base, uint32_t *exponent)
{
    int32_t i;
    uint32_t bitMask;
    SM9_Fp12 baseValue;
    SM9_Fp12 squaredValue;
    SM9_Fp12 productValue;

    SM9_Fp12_Assign(&baseValue, base);
    SM9_Fp12_SetOne(result);
    for (i = SM9_BN_BITS - 1; i >= 0; i--) {
        SM9_Fp12_Squ(&squaredValue, result);
        SM9_Fp12_Mul(&productValue, &squaredValue, &baseValue);
        bitMask = 0u - SM9_BN_GET_BIT(exponent, i);
        SM9_Fp12_Select(result, &productValue, &squaredValue, bitMask);
    }
    BSL_SAL_CleanseData(&baseValue, sizeof(baseValue));
    BSL_SAL_CleanseData(&squaredValue, sizeof(squaredValue));
    BSL_SAL_CleanseData(&productValue, sizeof(productValue));
}

static void SM9_EcpJ_Select(SM9_EcpJ *result, const SM9_EcpJ *left, const SM9_EcpJ *right, uint32_t mask)
{
    for (int32_t i = 0; i < SM9_BN_WORDS; i++) {
        result->x[i] = Uint32ConstTimeSelect(mask, left->x[i], right->x[i]);
        result->y[i] = Uint32ConstTimeSelect(mask, left->y[i], right->y[i]);
        result->z[i] = Uint32ConstTimeSelect(mask, left->z[i], right->z[i]);
    }
}

static void SM9_EcpA_SelectNonZero(SM9_EcpA *result, uint32_t mask)
{
    for (int32_t i = 0; i < SM9_BN_WORDS; i++) {
        result->x[i] = Uint32ConstTimeSelect(mask, result->x[i], 0);
        result->y[i] = Uint32ConstTimeSelect(mask, result->y[i], 0);
    }
}

static void SM9_EcpA_Reset(SM9_EcpA *point)
{
    BSL_SAL_CleanseData(point, sizeof(SM9_EcpA));
}

void SM9_EcpA_ToJ(SM9_EcpJ *result, SM9_EcpA *point)
{
    SM9_Fp_Assign(result->x, point->x);
    SM9_Fp_Assign(result->y, point->y);
    SM9_Fp_SetOne(result->z);
}

void SM9_EcpJ_ToA(SM9_EcpA *result, SM9_EcpJ *point)
{
    uint32_t tmp0[SM9_BN_WORDS];
    uint32_t tmp1[SM9_BN_WORDS];

    if (SM9_BN_IsZero(point->z, g_sm9SysPara.wordSize) != 0) {
        SM9_EcpA_Reset(result);
        return;
    }

    SM9_Fp_Inv(tmp0, point->z); // T0 = Z^-1
    SM9_Fp_Squ(tmp1, tmp0); // T1 = Z^-2
    SM9_Fp_Mul(tmp0, tmp1, tmp0); // T0 = Z^-3
    SM9_Fp_Mul(result->x, point->x, tmp1); // X2 = X1 * Z^-3
    SM9_Fp_Mul(result->y, point->y, tmp0); // Y2 = Y1 * Z^-3
}

static void SM9_EcpJ_DoubleJ(SM9_EcpJ *result, SM9_EcpJ *point)
{
    // Cost : 3M+4S+10A (a=0) or 3M+6S+1a+11A (otherwise)    [Change by pengcong 2017-09-27]
    uint32_t tmp1[SM9_BN_WORDS];
    uint32_t tmp2[SM9_BN_WORDS];
    uint32_t tmp3[SM9_BN_WORDS];

    SM9_Fp_Mul(tmp1, point->y, point->y); // T1 = Y1 ^ 2
    SM9_Fp_Add(tmp1, tmp1, tmp1); // T1 = T1 + T1 = 2 * Y1 ^ 2
    SM9_Fp_Mul(tmp2, tmp1, tmp1); // T2 = T1 * T1 = 4 * Y1 ^ 4
    SM9_Fp_Add(tmp2, tmp2, tmp2); // T2 = T2 + T2 = 8 * Y1 ^ 4 = B
    SM9_Fp_Mul(tmp1, tmp1, point->x); // T1 = T1 * X1 = 2 * X1 * Y1 ^ 2
    SM9_Fp_Add(tmp1, tmp1, tmp1); // T1 = T1 + T1 = 4 X1 * Y1 ^ 2 = A
    SM9_Fp_Mul(tmp3, point->x, point->x); // T3 = X1 ^ 2
    SM9_Fp_Add(result->x, tmp3, tmp3); // X3 = T3 + T3 = 2 * X1^2
    SM9_Fp_Add(tmp3, tmp3, result->x); // T3 = T3 + X3 = 3 * X1^2 = C
    SM9_Fp_Mul(result->z, point->y, point->z); // Z3 = Y1 * Z1
    SM9_Fp_Add(result->z, result->z, result->z); // Z3 = Z3 + Z3 = 2 * Y1 * Z1
    SM9_Fp_Mul(result->x, tmp3, tmp3); // X3 = T3 ^ 2 = C ^ 2
    SM9_Fp_Sub(result->x, result->x, tmp1); // X3 = X3 - T1 = C ^ 2 - A
    SM9_Fp_Sub(result->x, result->x, tmp1); // X3 = X3 - T1 = C ^ 2 - 2 * A
    SM9_Fp_Sub(result->y, tmp1, result->x); // Y3 = T1 - X3 = A - X3
    SM9_Fp_Mul(result->y, result->y, tmp3); // Y3 = Y3 * T3 = C * (A - X3)
    SM9_Fp_Sub(result->y, result->y, tmp2); // Y3 = Y3 - T2 = C * (A - X3) - B
}

void SM9_EcpJ_AddA(SM9_EcpJ *result, SM9_EcpJ *projectivePoint, SM9_EcpA *affinePoint)
{
    uint32_t tmp1[SM9_BN_WORDS];
    uint32_t tmp2[SM9_BN_WORDS];
    uint32_t tmp3[SM9_BN_WORDS];

    SM9_Fp_Mul(tmp3, projectivePoint->z, projectivePoint->z); // T3 = Z1^2
    SM9_Fp_Mul(tmp2, tmp3, projectivePoint->z); // T2 = T3 * Z1 = Z1^3
    SM9_Fp_Mul(tmp3, tmp3, affinePoint->x); // T3 = T3 * X2 = X2 * Z1^2 = A
    SM9_Fp_Sub(tmp3, tmp3, projectivePoint->x); // T3 = T3 - X1 = C
    SM9_Fp_Mul(tmp2, tmp2, affinePoint->y); // T2 = Y2 * T2 = Y2 * Z1^3 = B
    SM9_Fp_Sub(tmp2, tmp2, projectivePoint->y); // T2 = T2 - Y1 = B - Y1 = D
    if (SM9_Fq_IsZero(tmp3) != 0 && SM9_Fq_IsZero(tmp2) != 0) {
        SM9_EcpJ_DoubleJ(result, projectivePoint);
        return;
    }
    SM9_Fp_Mul(result->z, projectivePoint->z, tmp3); // Z3 = Z1 * T3 = Z1 * C
    SM9_Fp_Mul(tmp1, tmp3, tmp3); // T1 = T3^2 = C^2
    SM9_Fp_Mul(tmp3, tmp3, tmp1); // T3 = T3 * T1 = C^3
    SM9_Fp_Mul(tmp1, tmp1, projectivePoint->x); // T1 = T1 * X1 = X1 * C^2
    SM9_Fp_Add(result->x, tmp1, tmp1); // X3 = T1 + T1 = 2 * X1 * C^2
    SM9_Fp_Add(result->x, result->x, tmp3); // X3 = X3 + T3 = C^3 + 2*X1 * C^2
    SM9_Fp_Mul(result->y, projectivePoint->y, tmp3); // Y3 = Y1 * T3 = Y1 * C^3
    SM9_Fp_Mul(tmp3, tmp2, tmp2); // T3 = T2^2 = D^2
    SM9_Fp_Sub(result->x, tmp3, result->x); // X3 = T3 - X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
    SM9_Fp_Sub(tmp1, tmp1, result->x); // T1 = T1 - X3 = X1 * C^2 - X3
    SM9_Fp_Mul(tmp1, tmp1, tmp2); // T1 = T1 * T2 = D * (X1 * C ^ 2 - X3)
    SM9_Fp_Sub(result->y, tmp1, result->y); // Y3 = T1 - Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3
}

void SM9_Ecp_KP(SM9_EcpA *result, SM9_EcpA *basePoint, uint32_t *scalar)
{
    int32_t i;
    uint32_t scalarBit;
    uint32_t bitMask;
    uint32_t started = 0;
    SM9_EcpJ accumulator;
    SM9_EcpJ basePointJ;
    SM9_EcpJ doubledPoint;
    SM9_EcpJ addedPoint;
    SM9_EcpJ selectedPoint;

    SM9_EcpA_ToJ(&basePointJ, basePoint);
    SM9_EcpJ_Select(&accumulator, &basePointJ, &basePointJ, 0);
    for (i = SM9_BN_BITS - 1; i >= 0; i--) {
        SM9_EcpJ_DoubleJ(&doubledPoint, &accumulator);
        SM9_EcpJ_AddA(&addedPoint, &doubledPoint, basePoint);
        scalarBit = SM9_BN_GET_BIT(scalar, i);
        bitMask = 0u - scalarBit;
        SM9_EcpJ_Select(&selectedPoint, &addedPoint, &doubledPoint, bitMask);
        SM9_EcpJ_Select(&accumulator, &selectedPoint, &basePointJ, 0u - started);
        started |= scalarBit;
    }
    SM9_EcpJ_ToA(result, &accumulator);
    SM9_EcpA_SelectNonZero(result, 0u - started);
    BSL_SAL_CleanseData(&accumulator, sizeof(accumulator));
    BSL_SAL_CleanseData(&basePointJ, sizeof(basePointJ));
    BSL_SAL_CleanseData(&doubledPoint, sizeof(doubledPoint));
    BSL_SAL_CleanseData(&addedPoint, sizeof(addedPoint));
    BSL_SAL_CleanseData(&selectedPoint, sizeof(selectedPoint));
}

void SM9_FpEcp_KPAddAToA(SM9_EcpA *result, SM9_EcpA *basePoint, uint32_t *scalar, SM9_EcpA *addend, SM9_SysPara *params)
{
    int32_t bitLen = 0;
    int32_t i = 0;
    SM9_EcpJ productPoint;
    (void)params;

    bitLen = SM9_BN_GetBitLen(scalar, g_sm9SysPara.wordSize);
    if (bitLen == 0) {
        SM9_EcpA_Reset(result);
        // return;
    } else {
        SM9_EcpA_ToJ(&productPoint, basePoint);
        for (i = bitLen - 2; i >= 0; i--) {
            SM9_EcpJ_DoubleJ(&productPoint, &productPoint);

            if (SM9_BN_GET_BIT(scalar, i) != 0) {
                SM9_EcpJ_AddA(&productPoint, &productPoint, basePoint);
            }
        }
        // SM9_EcpJ_ToA(result, &productPoint, params);
        // return;
    }
    SM9_EcpJ_AddA(&productPoint, &productPoint, addend);
    SM9_EcpJ_ToA(result, &productPoint);
}

void SM9_EcpA_ReadBytes(SM9_EcpA *dst, const uint8_t *src)
{
    SM9_BN_ByteToBN(src, SM9_BN_BYTES, dst->x, SM9_BN_WORDS);
    SM9_BN_ByteToBN(src + SM9_BN_BYTES, SM9_BN_BYTES, dst->y, SM9_BN_WORDS);
    SM9_BN_MontMul(dst->x, dst->x, g_sm9SysPara.qR2, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize);
    SM9_BN_MontMul(dst->y, dst->y, g_sm9SysPara.qR2, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize);
}

int32_t SM9_EcpA_Check(SM9_EcpA *point)
{
    uint32_t lhs[SM9_BN_WORDS];
    uint32_t rhs[SM9_BN_WORDS];

    SM9_Fp_Squ(lhs, point->y);
    SM9_Fp_LastRes(lhs);

    SM9_Fp_Squ(rhs, point->x);
    SM9_Fp_Mul(rhs, rhs, point->x);
    SM9_Fp_Add(rhs, rhs, g_sm9SysPara.ecFpBMont);
    SM9_Fp_LastRes(rhs);

    if (SM9_BN_Equal(lhs, rhs, g_sm9SysPara.wordSize) != 0) {
        return CRYPT_SUCCESS;
    } else {
        return CRYPT_SM9_ERR_POINT_NOT_ON_CURVE;
    }
}

static int32_t SM9_Fp_CheckFieldElementEncoding(const uint8_t *src)
{
    uint32_t value[SM9_BN_WORDS];

    if (src == NULL) {
        return CRYPT_NULL_INPUT;
    }
    SM9_BN_ByteToBN(src, SM9_BN_BYTES, value, SM9_BN_WORDS);
    int32_t ret = SM9_BN_Compare(value, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize) < 0 ?
        CRYPT_SUCCESS : CRYPT_SM9_ERR_COORDINATE_RANGE;
    BSL_SAL_CleanseData(value, sizeof(value));
    return ret;
}

int32_t SM9_EcpA_ValidateBytes(const uint8_t *src)
{
    SM9_EcpA point;
    int32_t ret = CRYPT_SM9_ERR_COORDINATE_RANGE;

    if (src == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (SM9_Fp_CheckFieldElementEncoding(src) != CRYPT_SUCCESS ||
        SM9_Fp_CheckFieldElementEncoding(src + SM9_BN_BYTES) != CRYPT_SUCCESS) {
        goto EXIT;
    }
    SM9_EcpA_ReadBytes(&point, src);
    ret = SM9_EcpA_Check(&point);

EXIT:
    BSL_SAL_CleanseData(&point, sizeof(point));
    return ret;
}

static void SM9_Ecp2J_Select(SM9_Ecp2J *result, const SM9_Ecp2J *left, const SM9_Ecp2J *right, uint32_t mask)
{
    SM9_Fp2_Select(&result->x, &left->x, &right->x, mask);
    SM9_Fp2_Select(&result->y, &left->y, &right->y, mask);
    SM9_Fp2_Select(&result->z, &left->z, &right->z, mask);
}

static void SM9_Ecp2A_SelectNonZero(SM9_Ecp2A *result, uint32_t mask)
{
    SM9_Fp2 zero = {0};

    SM9_Fp2_Select(&result->x, &result->x, &zero, mask);
    SM9_Fp2_Select(&result->y, &result->y, &zero, mask);
}

void SM9_Ecp2A_ReadBytes(SM9_Ecp2A *dst, const uint8_t *src)
{
    SM9_Fp_ReadBytes(dst->x.coef1, src);
    SM9_Fp_ReadBytes(dst->x.coef0, src + SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->y.coef1, src + 2 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->y.coef0, src + 3 * SM9_BN_BYTES);
}

static void SM9_Ecp2A_Reset(SM9_Ecp2A *point)
{
    BSL_SAL_CleanseData(point, sizeof(SM9_Ecp2A));
}

static void SM9_Fp2_SetOne(SM9_Fp2 *element)
{
    SM9_BN_Assign(element->coef0, g_sm9SysPara.qR1, g_sm9SysPara.wordSize);
    BSL_SAL_CleanseData(element->coef1, 4 * g_sm9SysPara.wordSize);
}

void SM9_Ecp2A_ToJ(SM9_Ecp2J *result, SM9_Ecp2A *point)
{
    SM9_Fp2_Assign(&result->x, &point->x);
    SM9_Fp2_Assign(&result->y, &point->y);
    SM9_Fp2_SetOne(&result->z);
}

static int32_t SM9_Fp2_IsZero(SM9_Fp2 *value)
{
    if (SM9_Fq_IsZero(value->coef0) == 0) {
        return 0;
    }
    if (SM9_Fq_IsZero(value->coef1) == 0) {
        return 0;
    }
    return 1;
}

void SM9_Ecp2J_ToA(SM9_Ecp2A *result, SM9_Ecp2J *point)
{
    SM9_Fp2 tmp0;
    SM9_Fp2 tmp1;

    if (SM9_Fp2_IsZero(&point->z) != 0) {
        SM9_Ecp2A_Reset(result);
        return;
    }

    SM9_Fp2_Inv(&tmp0, &point->z);
    SM9_Fp2_Squ(&tmp1, &tmp0);
    SM9_Fp2_Mul(&tmp0, &tmp0, &tmp1);
    SM9_Fp2_Mul(&result->y, &point->y, &tmp0); // Y1 = Y * Z^-3
    SM9_Fp2_Mul(&result->x, &point->x, &tmp1); // X1 = X * Z ^ -2
}

static void SM9_Ecp2J_DoubleJ(SM9_Ecp2J *result, SM9_Ecp2J *point)
{
    // Cost : 3M+4S+10A (a=0) or 3M+6S+1a+11A (otherwise)    [Change by pengcong 2017-09-27]
    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;

    // A = 4 * X1 * Y1 ^ 2;    B = 8 * Y1 ^ 4;    Cost: 1M+2S+3A
    SM9_Fp2_Squ(&tmp1, &point->y); // T1 = Y1 ^ 2
    SM9_Fp2_Add(&tmp1, &tmp1, &tmp1); // T1 = 2 * Y1 ^ 2
    SM9_Fp2_Squ(&tmp2, &tmp1); // T2 = 4 * Y1 ^ 4
    SM9_Fp2_Add(&tmp2, &tmp2, &tmp2); // T2 = 8 * Y1 ^ 4 = B
    SM9_Fp2_Mul(&tmp1, &tmp1, &point->x); // T1 = 2 * X1 * Y1 ^ 2
    SM9_Fp2_Add(&tmp1, &tmp1, &tmp1); // T1 = 4 X1 * Y1 ^ 2 = A

    // C = 3 * X1 ^ 2 + a * Z1 ^ 4;    Cost: 1S+2A (a = 0)
    SM9_Fp2_Squ(&tmp3, &point->x); // T3 = X1 ^ 2
    SM9_Fp2_Add(&result->x, &tmp3, &tmp3); // X3 = 2 * X1 ^ 2
    SM9_Fp2_Add(&tmp3, &tmp3, &result->x); // T3 = 3 * X1 ^ 2 = C

    // Cost: 2M+1S+5A
    SM9_Fp2_Mul(&result->z, &point->y, &point->z); // Z3 = Y1 * Z1
    SM9_Fp2_Add(&result->z, &result->z, &result->z); // Z3 = 2 * Y1 * Z1
    SM9_Fp2_Squ(&result->x, &tmp3); // X3 = C ^ 2
    SM9_Fp2_Sub(&result->x, &result->x, &tmp1); // X3 = C ^ 2 - A
    SM9_Fp2_Sub(&result->x, &result->x, &tmp1); // X3 = C ^ 2 - 2A
    SM9_Fp2_Sub(&result->y, &tmp1, &result->x); // T1 = A - X3
    SM9_Fp2_Mul(&result->y, &result->y, &tmp3); // T1 = C * (A - X3)
    SM9_Fp2_Sub(&result->y, &result->y, &tmp2); // Y3 = C * (A - X3) - B
}

void SM9_Ecp2J_AddA(SM9_Ecp2J *result, SM9_Ecp2J *projectivePoint, SM9_Ecp2A *affinePoint)
{
    // Cost : 8M+3S+7A
    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;

    SM9_Fp2_Squ(&tmp3, &projectivePoint->z); // T3 = Z1^2
    SM9_Fp2_Mul(&tmp2, &tmp3, &projectivePoint->z); // T2 = Z1^3
    SM9_Fp2_Mul(&tmp3, &tmp3, &affinePoint->x); // T3 = X2 * Z1^2 = A
    SM9_Fp2_Sub(&tmp3, &tmp3, &projectivePoint->x); // T3 = A - X1 = C
    SM9_Fp2_Mul(&tmp2, &tmp2, &affinePoint->y); // T2 = Y2 * Z1 ^ 3 = B
    SM9_Fp2_Sub(&tmp2, &tmp2, &projectivePoint->y); // T2 = B - Y1 = D
    if (SM9_Fp2_IsZero(&tmp3) != 0 && SM9_Fp2_IsZero(&tmp2) != 0) {
        SM9_Ecp2J_DoubleJ(result, projectivePoint);
        return;
    }
    SM9_Fp2_Mul(&result->z, &projectivePoint->z, &tmp3); // Z3 = Z1 * C

    SM9_Fp2_Squ(&tmp1, &tmp3); // T1 = C ^ 2
    SM9_Fp2_Mul(&tmp3, &tmp3, &tmp1); // T3 = C ^ 3
    SM9_Fp2_Mul(&tmp1, &tmp1, &projectivePoint->x); // T1 = X1 * C^2
    SM9_Fp2_Add(&result->x, &tmp1, &tmp1); // X3 = 2 * X1 * C^2
    SM9_Fp2_Add(&result->x, &result->x, &tmp3); // X3 = C ^ 3 + 2 X1 * C^2
    SM9_Fp2_Mul(&result->y, &projectivePoint->y, &tmp3); // Y3 = Y1 * C^3

    SM9_Fp2_Squ(&tmp3, &tmp2); // T3 =  D^2
    SM9_Fp2_Sub(&result->x, &tmp3, &result->x); // X3 = D ^ 2 - ( C ^ 3 + 2 X1 * C^2)
    SM9_Fp2_Sub(&tmp1, &tmp1, &result->x); // T1 = X1 * C ^ 2 - X3
    SM9_Fp2_Mul(&tmp1, &tmp1, &tmp2); // T1 = D * (X1 * C ^ 2 - X3)
    SM9_Fp2_Sub(&result->y, &tmp1, &result->y); // Y3 = D * (X1 * C ^ 2 - X3) - Y1 * C ^ 3
}

void SM9_Ecp2_KP(SM9_Ecp2A *result, SM9_Ecp2A *basePoint, uint32_t *scalar)
{
    int32_t i;
    uint32_t scalarBit;
    uint32_t bitMask;
    uint32_t started = 0;
    SM9_Ecp2J accumulator;
    SM9_Ecp2J basePointJ;
    SM9_Ecp2J doubledPoint;
    SM9_Ecp2J addedPoint;
    SM9_Ecp2J selectedPoint;

    SM9_Ecp2A_ToJ(&basePointJ, basePoint);
    SM9_Ecp2J_Select(&accumulator, &basePointJ, &basePointJ, 0);
    for (i = SM9_BN_BITS - 1; i >= 0; i--) {
        SM9_Ecp2J_DoubleJ(&doubledPoint, &accumulator);
        SM9_Ecp2J_AddA(&addedPoint, &doubledPoint, basePoint);
        scalarBit = SM9_BN_GET_BIT(scalar, i);
        bitMask = 0u - scalarBit;
        SM9_Ecp2J_Select(&selectedPoint, &addedPoint, &doubledPoint, bitMask);
        SM9_Ecp2J_Select(&accumulator, &selectedPoint, &basePointJ, 0u - started);
        started |= scalarBit;
    }
    SM9_Ecp2J_ToA(result, &accumulator);
    SM9_Ecp2A_SelectNonZero(result, 0u - started);
    BSL_SAL_CleanseData(&accumulator, sizeof(accumulator));
    BSL_SAL_CleanseData(&basePointJ, sizeof(basePointJ));
    BSL_SAL_CleanseData(&doubledPoint, sizeof(doubledPoint));
    BSL_SAL_CleanseData(&addedPoint, sizeof(addedPoint));
    BSL_SAL_CleanseData(&selectedPoint, sizeof(selectedPoint));
}

// Check if G2 point is on the curve: y^2 = x^3 + a*x + b (over Fp2)
static int32_t SM9_Ecp2A_Check(SM9_Ecp2A *point)
{
    SM9_Fp2 lhs;
    SM9_Fp2 rhs;
    SM9_Fp2 xCubed;

    // Calculate y^2
    SM9_Fp2_Squ(&lhs, &point->y); // tmp1 = y^2
    // Calculate x^3
    SM9_Fp2_Squ(&xCubed, &point->x); // x3 = x^2
    SM9_Fp2_Mul(&xCubed, &xCubed, &point->x); // x3 = x^3

    // Calculate x^3 + a*x + b
    SM9_Fp2_Mul(&rhs, &point->x, &g_sm9SysPara.ecFp2AMont); // tmp2 = a*x
    SM9_Fp2_Add(&rhs, &xCubed, &rhs); // tmp2 = x^3 + a*x
    SM9_Fp2_Add(&rhs, &rhs, &g_sm9SysPara.ecFp2BMont);

    SM9_Fp_LastRes(lhs.coef0);
    SM9_Fp_LastRes(lhs.coef1);
    SM9_Fp_LastRes(rhs.coef0);
    SM9_Fp_LastRes(rhs.coef1);

    // Check y^2 == x^3 + a*x + b
    if (SM9_BN_Equal(lhs.coef0, rhs.coef0, g_sm9SysPara.wordSize) == 0 ||
        SM9_BN_Equal(lhs.coef1, rhs.coef1, g_sm9SysPara.wordSize) == 0) {
        return CRYPT_SM9_ERR_POINT_NOT_ON_CURVE;
    }
    return CRYPT_SUCCESS;
}

int32_t SM9_Ecp2A_ValidateBytes(const uint8_t *src)
{
    SM9_Ecp2A point;
    SM9_Ecp2A orderMultiple;
    int32_t ret = CRYPT_SM9_ERR_COORDINATE_RANGE;

    if (src == NULL) {
        return CRYPT_NULL_INPUT;
    }
    for (uint32_t i = 0; i < 4; i++) {
        if (SM9_Fp_CheckFieldElementEncoding(src + i * SM9_BN_BYTES) != CRYPT_SUCCESS) {
            goto EXIT;
        }
    }
    SM9_Ecp2A_ReadBytes(&point, src);
    ret = SM9_Ecp2A_Check(&point);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    SM9_Ecp2_KP(&orderMultiple, &point, g_sm9SysPara.ecN);
    ret = CRYPT_SM9_ERR_POINT_NOT_IN_SUBGROUP;
    if (SM9_BN_IsZero(orderMultiple.x.coef0, SM9_BN_WORDS) == 0 ||
        SM9_BN_IsZero(orderMultiple.x.coef1, SM9_BN_WORDS) == 0 ||
        SM9_BN_IsZero(orderMultiple.y.coef0, SM9_BN_WORDS) == 0 ||
        SM9_BN_IsZero(orderMultiple.y.coef1, SM9_BN_WORDS) == 0) {
        goto EXIT;
    }
    ret = CRYPT_SUCCESS;

EXIT:
    BSL_SAL_CleanseData(&point, sizeof(point));
    BSL_SAL_CleanseData(&orderMultiple, sizeof(orderMultiple));
    return ret;
}

static void SM9_Pairing_MulQuaRoot(SM9_Fp2 *result, SM9_Fp2 *value)
{
    uint32_t tmp0[SM9_BN_WORDS];

    SM9_Fp_MulRoot(tmp0, value->coef1); // a1*rootFactor
    SM9_Fp_Add(tmp0, tmp0, tmp0); // 2*a1*rootFactor
    SM9_Fp_MulRoot(result->coef1, value->coef0); // a0*rootFactor
    SM9_Fp_Neg(result->coef0, tmp0); // -2*a1*rootFactor
}

static void SM9_Pairing_MulCubRoot(SM9_Fp2 *result, SM9_Fp2 *value)
{
    uint32_t tmp0[SM9_BN_WORDS];

    SM9_Fp_MulRoot(tmp0, value->coef1); // a1*rootFactor
    SM9_Fp_Add(tmp0, tmp0, tmp0); // 2*a1*rootFactor
    SM9_Fp_MulRoot(result->coef1, value->coef0); // a0*rootFactor
    SM9_Fp_Neg(result->coef0, tmp0); // -2*a1*rootFactor
}

static void SM9_Pairing_MulQuaRootFrobMap(SM9_Fp2 *result, SM9_Fp2 *value)
{
    SM9_Fp2_FrobMap(result, value); // Frob(a0+a1*u)
    SM9_Fp2_MulVq(result, result); // (Frob(a0+a1*u))* (v^q)
}

static void SM9_Fp2_MulWq(SM9_Fp2 *result, SM9_Fp2 *value)
{
    SM9_Fp_Mul(result->coef0, value->coef0, g_sm9SysPara.ecWqMont);
    SM9_Fp_Mul(result->coef1, value->coef1, g_sm9SysPara.ecWqMont);
}

static void SM9_Pairing_MulCubRootFrobMap(SM9_Fp2 *result, SM9_Fp2 *value)
{
    SM9_Fp2_FrobMap(result, value); // Frob(a0+a1*u)
    SM9_Fp2_MulVq(result, result); // (Frob(a0+a1*u))* (v^q)
    SM9_Fp2_MulWq(result, result); // (Frob(a0+a1*u))* (v^q) * (w^q)
}

static void SM9_Pairing_EncDL(SM9_Fp12 *lineValue, SM9_Ecp2J *resultPoint, SM9_Ecp2J *currentPoint, SM9_EcpA *g1Point)
{
    SM9_Ecp2J doubledPoint;

    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;
    SM9_Fp2 tmp4;
    SM9_Fp2 tmp5;
    SM9_Fp2 tmp6;
    SM9_Fp2 tmp7;

    SM9_Fp2_Squ(&tmp1, &currentPoint->x); // T1 = X1 ^ 2 = A
    SM9_Fp2_Add(&tmp2, &tmp1, &tmp1); // T2 = 2 * (X1 ^ 2)
    SM9_Fp2_Add(&tmp1, &tmp1, &tmp2); // T2 = 3 * (X1 ^ 2)
    SM9_Fp2_Mul(&tmp2, &tmp1, &currentPoint->x); // T2 = 3 * (X1 ^ 3) = E
    SM9_Fp2_MulCoef0(&tmp3, &tmp2, g_sm9SysPara.ec4InvMont); // T3 = (3 * (X1 ^ 3)) / 4
    SM9_Fp2_Add(&tmp4, &tmp3, &tmp3); // T4 = (6 * (X1 ^ 3)) / 4 = B0
    SM9_Fp2_Add(&tmp3, &tmp3, &tmp4); // T3 = (9 * (X1 ^ 3)) / 4 = B
    SM9_Fp2_Squ(&tmp5, &currentPoint->y); // T5 = Y1^2 = C
    SM9_Fp2_Add(&tmp6, &tmp5, &tmp5); // T6 = 2*Y1^2 = D;
    SM9_Fp2_Squ(&tmp5, &tmp5); // T5 = C ^ 2 = F
    SM9_Fp2_Squ(&tmp7, &currentPoint->z); // T7 = Z ^ 2 = G

    // Z3 = Y*Z
    SM9_Fp2_Mul(&doubledPoint.z, &currentPoint->y, &currentPoint->z);

    // Y3 = B*(D - B0) - F
    SM9_Fp2_Sub(&tmp4, &tmp6, &tmp4); // T4 = D - B0
    SM9_Fp2_Mul(&tmp4, &tmp4, &tmp3); // T4 = B*(D - B0)
    SM9_Fp2_Sub(&doubledPoint.y, &tmp4, &tmp5); // Y3 = B*(D - B0) - F

    // X3 = X1*(B-D)
    SM9_Fp2_Sub(&tmp4, &tmp3, &tmp6); // T4 = B-D
    SM9_Fp2_Mul(&doubledPoint.x, &tmp4, &currentPoint->x); // X3 = X1*(B-D)

    SM9_Fp2_Mul(&tmp4, &doubledPoint.z, &tmp7); // T4 = Z3 * G
    SM9_Fp2_Add(&tmp4, &tmp4, &tmp4); // T4 = 2 * Z3 * G = H
    SM9_Fp2_Mul(&tmp5, &tmp1, &tmp7); // T5 = A*G
    SM9_Fp2_Neg(&tmp5, &tmp5); // T5 = -A*G

    // l_{2TP}=H * yP * (w ^3) + I * (w ^ 2) + J
    // = (J+H * yP * v) + (I + 0 * v) * w^2, where w^3 = v
    // lineValue = f0  + f1 * w + f2 * w ^ 2, f0, f1, f4 \in F(p^4)
    // f0 = f0_0 + f0_1 * v, f1 = f1_0 + f1_1 * v, f2 = f2_0 + f2_1 * v, f0_0, f0_1 \in F(p^2)
    SM9_Fp12_Reset(lineValue);
    SM9_Fp2_Sub(&lineValue->coef0.coef0, &tmp2, &tmp6); // J = E -D
    SM9_Fp2_MulCoef0(&lineValue->coef0.coef1, &tmp4, g1Point->y); // H * yP
    SM9_Fp2_MulCoef0(&lineValue->coef2.coef0, &tmp5, g1Point->x); // I = - A*G*xP

    *resultPoint = doubledPoint;
}

static void SM9_Pairing_EncAL(SM9_Fp12 *lineValue, SM9_Ecp2J *resultPoint, SM9_Ecp2J *currentPoint, SM9_Ecp2A *addend,
                              SM9_EcpA *g1Point)
{
    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;
    SM9_Fp2 tmp4;

    SM9_Ecp2J sumPoint;

    SM9_Fp2_Squ(&tmp1, &currentPoint->z); // T1 = Z1 ^ 2 = A
    SM9_Fp2_Mul(&tmp2, &tmp1, &currentPoint->z); // T2 = Z1 ^ 3 = B
    SM9_Fp2_Mul(&tmp3, &addend->y, &tmp2); // T3 = Y2 * B
    SM9_Fp2_Sub(&tmp3, &tmp3, &currentPoint->y); // T3 = Y2 * B - Y1 = theta
    SM9_Fp2_Mul(&tmp4, &addend->x, &tmp1); // T4 = X2 * A
    SM9_Fp2_Sub(&tmp4, &tmp4, &currentPoint->x); // T4 = X2 * A - X1 = lambda

    // Z3 = Z * lambda
    SM9_Fp2_Mul(&sumPoint.z, &currentPoint->z, &tmp4); // Z3 = Z * lambda

    SM9_Fp2_Squ(&tmp1, &tmp3); // T1 = theta ^ 2 = C
    SM9_Fp2_Squ(&tmp2, &tmp4); // T2 = lambda ^ 2 = D
    SM9_Fp2_Mul(&tmp4, &tmp2, &tmp4); // T4 = lambda ^ 3 = E
    SM9_Fp2_Sub(&tmp1, &tmp1, &tmp4); // T1 = C - E = F
    SM9_Fp2_Mul(&tmp2, &tmp2, &currentPoint->x); // T2 = X1 * D = G

    // X3 = F - 2 * G
    SM9_Fp2_Sub(&tmp1, &tmp1, &tmp2); // T1 = F - G
    SM9_Fp2_Sub(&sumPoint.x, &tmp1, &tmp2); // X3 = F - 2 * G

    // Y3 = theta * (G-X3) - Y1 * E
    SM9_Fp2_Sub(&tmp2, &tmp2, &sumPoint.x); // T2 = G-X3
    SM9_Fp2_Mul(&tmp2, &tmp2, &tmp3); // T2 = theta * (G-X3)
    SM9_Fp2_Mul(&tmp4, &currentPoint->y, &tmp4); // T4 = Y * E
    SM9_Fp2_Sub(&sumPoint.y, &tmp2, &tmp4); // Y3 = theta * (G-X3) - Y * E

    // M-type twist
    // l_{TQP}= Z3 * yP * w ^ 3 - theta * xp * w ^ 2 + J
    // = Z3 * yP * v - theta * xp * w ^ 2 + J
    // = (J+Z3 * yP * v) + (- theta * xp + 0 * v) * w ^ 2
    // J = theta*X2 - Y2 * Z3
    SM9_Fp12_Reset(lineValue);
    SM9_Fp2_Mul(&tmp1, &tmp3, &addend->x); // T1 = theta*X2
    SM9_Fp2_Mul(&tmp2, &addend->y, &sumPoint.z); // T2 = Y2 * Z3
    SM9_Fp2_Sub(&lineValue->coef0.coef0, &tmp1, &tmp2); // T1 = theta*X2 - Y2 * Z3

    SM9_Fp2_MulCoef0(&lineValue->coef0.coef1, &sumPoint.z, g1Point->y); // Z3 * yP

    SM9_Fp2_MulCoef0(&tmp3, &tmp3, g1Point->x); // theta * xp
    SM9_Fp2_Neg(&lineValue->coef2.coef0, &tmp3); // -theta * xp

    *resultPoint = sumPoint;
}

// addend=(xQ1,yQ1)=((cubic_root*xQ)^q, (quadratic_root*yQ)^q)=((a0+a1*u)*v*w, (b0+b1*u)*v)
// currentPoint=(cubic_root*X, quadratic_root*Y, Z)=((c0+c1*u)*v*w, (d0+d1*u)*v),e0+e1*u)
static void SM9_Pairing_EncALRAteQ1(SM9_Fp12 *lineValue, SM9_Ecp2J *resultPoint, SM9_Ecp2J *currentPoint,
                                    SM9_Ecp2A *addend, SM9_EcpA *g1Point)
{
    SM9_Ecp2J sumPoint;
    SM9_Fp12 lineResult;

    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;
    SM9_Fp2 tmp4;
    SM9_Fp2 tmp5;

    // uint32_t BN_T[SM9_BN_WORDS];

    SM9_Fp2_Squ(&tmp1, &currentPoint->z); // tmp1 = Z ^ 2 = A, Z=e0+e1*u
    SM9_Fp2_Mul(&tmp2, &tmp1, &currentPoint->z); // tmp2 = Z ^ 3 = B

    SM9_Fp2_Mul(&tmp3, &addend->y, &tmp2);
    SM9_Fp2_Sub(&tmp3, &tmp3, &currentPoint->y); // tmp3= Y2 * B - Y1 = theta=(theat0 + theta1*u)*v
    SM9_Fp2_Mul(&tmp4, &addend->x, &tmp1);
    SM9_Fp2_Sub(&tmp4, &tmp4, &currentPoint->x); // tmp4=X2 * A - X1 = lambda =(lambda0 + lambda1*u)*v*w

    // tmp1 = theta ^ 2 = C = ((theat0 + theta1*u)*v)^2
    // = (theat0 + theta1*u)^2 * v^2
    // = (theat0 + theta1*u)^2 * u
    // = c0 + c1*u
    SM9_Fp2_Squ(&tmp1, &tmp3);
    SM9_Fp2_MulU(&tmp1, &tmp1); // (theat0 + theta1*u)^2 * u

    // tmp2 = lambda ^ 2 = D
    // = ((lambda0 + lambda1*u)*v*w)^2
    // = (lambda0 + lambda1*u)^2*v^2*w^2
    // = (lambda0 + lambda1*u)^2*u*w^2
    // = (d0 + d1*u)*w^2
    SM9_Fp2_Squ(&tmp2, &tmp4);
    SM9_Fp2_MulU(&tmp2, &tmp2); // (lambda0 + lambda1*u)^2 * u

    // tmp5 = D*lambda = E
    // = (d0 + d1*u)*w^2 * (lambda0 + lambda1*u)*v*w
    // = (d0 + d1*u)*(lambda0 + lambda1*u)*v*w^3
    // = (d0 + d1*u)*(lambda0 + lambda1*u)*v^2
    // = (d0 + d1*u)*(lambda0 + lambda1*u)*u
    // = e0 + e1*u
    SM9_Fp2_Mul(&tmp5, &tmp2, &tmp4); // (d0 + d1*u)*(lambda0 + lambda1*u)
    SM9_Fp2_MulU(&tmp5, &tmp5); // (d0 + d1*u)*(lambda0 + lambda1*u)*u

    // tmp1 = C - E = F
    // = (c0 + c1*u)-(e0 + e1*u)
    // = f0 + f1*u
    SM9_Fp2_Sub(&tmp1, &tmp1, &tmp5);

    // tmp2 = X * D = G
    // = ((x0 + x1*u)*v*w) * (d0 + d1*u)*w^2
    // = (x0 + x1*u)*(d0 + d1*u)*v*w^3
    // = (x0 + x1*u)*(d0 + d1*u)*v*v
    // = (x0 + x1*u)*(d0 + d1*u)*u
    // = g0+g1*u
    SM9_Fp2_Mul(&tmp2, &tmp2, &currentPoint->x); // (x0 + x1*u)*(d0 + d1*u)
    SM9_Fp2_MulU(&tmp2, &tmp2); // (x0 + x1*u)*(d0 + d1*u)*u

    // X3 = F - 2 * G
    // = (f0 + f1*u)-2*(g0+g1*u)
    // = x30 + x31*u
    SM9_Fp2_Sub(&sumPoint.x, &tmp1, &tmp2);
    SM9_Fp2_Sub(&sumPoint.x, &sumPoint.x, &tmp2);

    // Y3 = theta * (G-X3) - Y * E
    // = ((theat0 + theta1*u)*v) * ((g0+g1*u) - (x30 + x31*u))-((y0 + y1*u)*v)*(e0 + e1*u)
    // = (y30+y31*u)*v
    SM9_Fp2_Sub(&sumPoint.y, &tmp2, &sumPoint.x); // Y3 = G-X3
    SM9_Fp2_Mul(&sumPoint.y, &sumPoint.y, &tmp3); // Y3 = theta * (G-X3)
    SM9_Fp2_Mul(&tmp5, &currentPoint->y, &tmp5); // tmp5 = Y * E
    SM9_Fp2_Sub(&sumPoint.y, &sumPoint.y, &tmp5); // Y3 = theta * (G-X3) - Y * E

    // Z3 = Z * lambda
    // = (z0 + z1*u) * ((lambda0 + lambda1*u)*v*w)
    // = (z0 + z1*u)*(lambda0 + lambda1*u)*v*w
    // = (z30 + z31*u)*v*w
    SM9_Fp2_Mul(&sumPoint.z, &currentPoint->z, &tmp4);

    // M-type twist
    // l_TQ1P := Z3*(yP - Y2) - theta*(xP - X2);

    SM9_Fp12_Reset(&lineResult);

    // Z3*(yP - Y2)
    // = ((z30 + z31*u)*v*w) * ((yP+0*u) - (yq0 + yq1*u)*v)
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*v^2*w
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*u*w
    // = tmp1 * w - tmp2 * v * w
    SM9_Fp2_Mul(&tmp1, &sumPoint.z, &addend->y); // tmp1=(z30 + z31*u) * (yq0 + yq1*u)
    SM9_Fp2_MulU(&tmp1, &tmp1); // tmp1=(z30 + z31*u) * (yq0 + yq1*u)*u
    SM9_Fp2_MulCoef0(&tmp2, &sumPoint.z, g1Point->y); // tmp2=(z30 + z31*u)* (yP+0*u)

    // theta*(xP - X2)
    // = (theat0 + theta1*u)*v * ((xP+0*u) - ((xq0 + xq1*u)*v)*w)
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*v^2*w
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*u*w
    // = tmp4 * v - tmp5 * w
    SM9_Fp2_MulCoef0(&tmp4, &tmp3, g1Point->x); // tmp4=xP * (theat0 + theta1*u)
    SM9_Fp2_Mul(&tmp5, &tmp3, &addend->x); // tmp5=(theat0 + theta1*u)*(xq0 + xq1*u)
    SM9_Fp2_MulU(&tmp5, &tmp5); // tmp5=(theat0 + theta1*u)*(xq0 + xq1*u)*u
    // Z3*(yP - Y2) - theta*(xP - X2)
    // = (tmp1 * w - tmp2 * v * w) - (tmp4 * v - tmp5 * w)
    // = -tmp4 * v + ((tmp1+tmp5)-tmp2*v)* w
    SM9_Fp2_Neg(&lineResult.coef0.coef1, &tmp4);
    SM9_Fp2_Sub(&tmp1, &tmp1, &tmp5);
    SM9_Fp2_Neg(&lineResult.coef1.coef0, &tmp1);
    SM9_Fp2_Assign(&lineResult.coef1.coef1, &tmp2);

    SM9_Fp12_Assign(lineValue, &lineResult);

    *resultPoint = sumPoint;

    // SM9_Fp2_Assign(&resultPoint->x, &sumPoint.x);
    // SM9_Fp2_Assign(&resultPoint->y, &sumPoint.y);
    // SM9_Fp2_Assign(&resultPoint->z, &sumPoint.z);
}

// addend=(xQ1,yQ1)=((cubic_root*xQ)^q2, (quadratic_root*yQ)^q2)=((x0+x1*u)*v*w, (y0+y1*u)*v)
// currentPoint=(x30 + x31*u, (y30+y31*u)*v, (z30 + z31*u)*v*w)
static void SM9_Pairing_EncALRAteQ2(SM9_Fp12 *lineValue, SM9_Ecp2J *currentPoint, SM9_Ecp2A *addend, SM9_EcpA *g1Point)
{
    // SM9_Ecp2J JSum_T;
    SM9_Fp12 lineResult;
    SM9_Fp2 sumZ;

    SM9_Fp2 tmp1;
    SM9_Fp2 tmp2;
    SM9_Fp2 tmp3;
    SM9_Fp2 tmp4;
    SM9_Fp2 tmp5;

    uint32_t tmpScalar[SM9_BN_WORDS];

    int32_t wordSize = 0;

    SM9_BN_Reset(tmpScalar, wordSize);

    // tmp1 = Z ^ 2 = A, Z=(z30 + z31*u)*v*w
    // = ((z30 + z31*u)*v*w)^2
    // = (z30 + z31*u)^2*v^2*w^2
    // = (z30 + z31*u)^2*u*w^2
    // = (a0+a1*u)*w^2
    SM9_Fp2_Squ(&tmp1, &currentPoint->z);
    SM9_Fp2_MulU(&tmp1, &tmp1); // (z30 + z31*u)^2*u

    // tmp2 = Z ^ 3 = B
    // = (a0+a1*u)*w^2 * (z30 + z31*u)*v*w
    // = (a0+a1*u)*(z30 + z31*u)*v*w^3
    // = (a0+a1*u)*(z30 + z31*u)*v*v
    // = (a0+a1*u)*(z30 + z31*u)*u
    // = b0+b1*u
    SM9_Fp2_Mul(&tmp2, &tmp1, &currentPoint->z); // (a0+a1*u)*(z30 + z31*u)
    SM9_Fp2_MulU(&tmp2, &tmp2); // (a0+a1*u)*(z30 + z31*u)*u

    // tmp3= Y2 * B - Y = theta=(theat0 + theta1*u)*v
    // = ((y0+y1*u)*v)*(b0+b1*u)-((y30+y31*u)*v)
    // = (t30+t31*u)*v
    SM9_Fp2_Mul(&tmp3, &addend->y, &tmp2);
    SM9_Fp2_Sub(&tmp3, &tmp3, &currentPoint->y);

    // tmp4=X2 * A - X = lambda =(lambda0 + lambda1*u)
    // = ((x0+x1*u)*v*w)*((a0+a1*u)*w^2)-(x30 + x31*u)
    // = (x0+x1*u)*(a0+a1*u)*v*w^3-(x30 + x31*u)
    // = (x0+x1*u)*(a0+a1*u)*v^2-(x30 + x31*u)
    // = (x0+x1*u)*(a0+a1*u)*u-(x30 + x31*u)
    // = t40+t41*u
    SM9_Fp2_Mul(&tmp4, &addend->x, &tmp1); // (x0+x1*u)*(a0+a1*u)
    SM9_Fp2_MulU(&tmp4, &tmp4); // (x0+x1*u)*(a0+a1*u)*u

    SM9_Fp2_Sub(&tmp4, &tmp4, &currentPoint->x);

    // Z3 = Z * lambda
    // = (z30 + z31*u)*v*w*(lambda0 + lambda1*u)
    // = (z0 + z1*u)*(lambda0 + lambda1*u)*v*w
    // = (z30 + z31*u)*v*w
    SM9_Fp2_Mul(&(sumZ), &currentPoint->z, &tmp4);

    // M-type twist
    // l_TQ1P := Z3*(yP - Y2) - theta*(xP - X2);

    SM9_Fp12_Reset(&lineResult);

    // Z3*(yP - Y2)
    // = ((z30 + z31*u)*v*w) * ((yP+0*u) - (yq0 + yq1*u)*v)
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*v^2*w
    // = (z30 + z31*u)* (yP+0*u) *v*w -  (z30 + z31*u) * (yq0 + yq1*u)*u*w
    // = tmp1 * w - tmp2 * v * w
    SM9_Fp2_Mul(&tmp1, &(sumZ), &addend->y); // tmp1=(z30 + z31*u) * (yq0 + yq1*u)
    SM9_Fp2_MulU(&tmp1, &tmp1); // z30 + z31*u) * (yq0 + yq1*u)*u

    SM9_Fp2_MulCoef0(&tmp2, &(sumZ), g1Point->y); // tmp2=(z30 + z31*u)* (yP+0*u)

    // theta*(xP - X2)
    // = (theat0 + theta1*u)*v * ((xP+0*u) - ((xq0 + xq1*u)*v)*w)
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*v^2*w
    // = xP * (theat0 + theta1*u)*v - (theat0 + theta1*u)*(xq0 + xq1*u)*u*w
    // = tmp4 * v - tmp5 * w
    SM9_Fp2_MulCoef0(&tmp4, &tmp3, g1Point->x); // tmp4=xP * (theat0 + theta1*u)
    SM9_Fp2_Mul(&tmp5, &tmp3, &addend->x); // tmp5=(theat0 + theta1*u)*(xq0 + xq1*u)
    SM9_Fp2_MulU(&tmp5, &tmp5); // tmp5=(theat0 + theta1*u)*(xq0 + xq1*u)*u

    // Z3*(yP - Y2) - theta*(xP - X2)
    // = (tmp1 * w - tmp2 * v * w) - (tmp4 * v - tmp5 * w)
    // = -tmp4 * v + ((tmp1+tmp5)-tmp2*v)* w
    SM9_Fp2_Neg(&lineResult.coef0.coef1, &tmp4);
    SM9_Fp2_Sub(&tmp1, &tmp1, &tmp5);
    SM9_Fp2_Neg(&lineResult.coef1.coef0, &tmp1);
    SM9_Fp2_Assign(&lineResult.coef1.coef1, &tmp2);

    SM9_Fp12_Assign(lineValue, &lineResult);
}

static void SM9_Pairing_MillerRTate(SM9_Fp12 *result, SM9_EcpA *g1Point, SM9_Ecp2A *g2Point, uint32_t *loopScalar)
{
    SM9_Ecp2J currentPoint;
    SM9_Ecp2A transformedPoint;
    SM9_Fp12 lineValue;
    int32_t bitLen;
    int32_t i;

    bitLen = SM9_BN_GetBitLen(loopScalar, g_sm9SysPara.wordSize);
    if (bitLen == 0) {
        SM9_Fp12_Reset(result);
        return;
    }

    SM9_Ecp2A_ToJ(&currentPoint, g2Point);

    // i = bitLen - 2
    SM9_Pairing_EncDL(result, &currentPoint, &currentPoint, g1Point);

    // for (i = bitLen - 2; i >= 0; i--)
    for (i = bitLen - 3; i >= 0; i--) {
        SM9_Fp12_Squ(result, result);
        SM9_Pairing_EncDL(&lineValue, &currentPoint, &currentPoint, g1Point);
        SM9_Fp12_MulForMillerLoop(result, result, &lineValue);
        if (SM9_BN_GET_BIT(loopScalar, i) != 0) {
            SM9_Pairing_EncAL(&lineValue, &currentPoint, &currentPoint, g2Point, g1Point);
            SM9_Fp12_MulForMillerLoop(result, result, &lineValue);
        }
    }

    // X := cubic_root*X;    Y := quadratic_root*Y;
    SM9_Pairing_MulCubRoot(&currentPoint.x, &currentPoint.x);
    SM9_Pairing_MulQuaRoot(&currentPoint.y, &currentPoint.y);

    // xQ := cubic_root*xQ;    yQ := quadratic_root*yQ;
    SM9_Pairing_MulCubRoot(&transformedPoint.x, &g2Point->x);
    SM9_Pairing_MulQuaRoot(&transformedPoint.y, &g2Point->y);

    // xQ1 := xQ^q; xQ = cubic_root*xQ;    yQ1 := yQ^q; yQ = quadratic_root*yQ;
    SM9_Pairing_MulCubRootFrobMap(&transformedPoint.x, &transformedPoint.x);
    SM9_Pairing_MulQuaRootFrobMap(&transformedPoint.y, &transformedPoint.y);
    SM9_Pairing_EncALRAteQ1(&lineValue, &currentPoint, &currentPoint, &transformedPoint, g1Point);
    SM9_Fp12_MulForFrobMap(result, result, &lineValue);

    // X2 := X2^q;    Y2 := -Y2^q;
    SM9_Pairing_MulCubRootFrobMap(&transformedPoint.x, &transformedPoint.x);
    SM9_Pairing_MulQuaRootFrobMap(&transformedPoint.y, &transformedPoint.y);
    SM9_Fp2_Neg(&transformedPoint.y, &transformedPoint.y);
    SM9_Pairing_EncALRAteQ2(&lineValue, &currentPoint, &transformedPoint, g1Point);
    SM9_Fp12_MulForFrobMap(result, result, &lineValue);
}

static void SM9_Pairing_ExpQ6(SM9_Fp12 *result, SM9_Fp12 *value)
{
    SM9_Fp12 tmp1;

    // T1 = Conj(f)
    SM9_Fp12_GetConj(&tmp1, value);
    // Inv = f ^ (-1)
    SM9_Fp12_Inv(result, value);
    // Res_T = Conj(f) / f
    SM9_Fp12_Mul(result, result, &tmp1);
}

static void SM9_Pairing_ExpQ2(SM9_Fp12 *result, SM9_Fp12 *value)
{
    SM9_Fp12 tmp1;

    // T1 = f ^ (p^2)
    SM9_Fp12_FrobMap(&tmp1, value); // T1 = f ^ p
    SM9_Fp12_FrobMap(&tmp1, &tmp1); // T1 = f ^ (p^2)

    // Res_T = f ^ (p^2 + 1)
    SM9_Fp12_Mul(result, &tmp1, value);
}

static void SM9_Pairing_ExpQ4(SM9_Fp12 *result, SM9_Fp12 *value)
{
    SM9_Fp12 y0;
    SM9_Fp12 y1;
    SM9_Fp12 y2;
    SM9_Fp12 y3;
    SM9_Fp12 y4;
    SM9_Fp12 y5;
    SM9_Fp12 y6;

    SM9_Fp12 tmp0;
    SM9_Fp12 tmp1;
    // SM9_Fp12 T2;
    // SM9_Fp12 T3;

    SM9_Fp12_FrobMap(&y0, value); // y0 = f ^ q
    SM9_Fp12_FrobMap(&y2, &y0); // y2 = f ^ (q^2)
    SM9_Fp12_FrobMap(&y3, &y2); // y3 = f ^ (q^3)

    // y0 = (f^q) * f^{q^2} * f^{q^3}
    SM9_Fp12_Mul(&y0, &y0, &y2); // y0 = (f^p) * f^{p^2}
    SM9_Fp12_Mul(&y0, &y0, &y3); // y0 = (f^p) * f^{p^2} * f^{p^3}

    // y1 = 1 / f
    SM9_Fp12_GetConj(&y1, value);

    // y2 = (f^(t^2))^(q^2)
    SM9_Fp12_Exp(&y2, &y2, g_sm9SysPara.ecT); // y2 = (f ^ (q^2))^t
    SM9_Fp12_Exp(&y2, &y2, g_sm9SysPara.ecT); // y2 = (f ^ (q^2))^(t^2)=(f^(t^2))^(q^2)

    // y3 = ((1/f)^t)^q
    SM9_Fp12_Exp(&y4, &y1, g_sm9SysPara.ecT); // tmp1 = (1/f) ^ t
    SM9_Fp12_FrobMap(&y3, &y4); // y3 = ((1/f)^t)^q

    // y5=(1/f)^(t^2)
    SM9_Fp12_Exp(&y5, &y4, g_sm9SysPara.ecT); // T2 = (1/f) ^ (t^2)

    // y4=1/(f^t * (f^(t^2))^q)
    SM9_Fp12_FrobMap(&y6, &y5); // T2=((1/f) ^ (t^2))^q
    SM9_Fp12_Mul(&y4, &y4, &y6); // y4=1/(f^t * (f^(t^2))^q)

    // y6=1/(f^(t^3)*(f^(t^3))^q)
    SM9_Fp12_Exp(&tmp0, &y5, g_sm9SysPara.ecT); // tmp1 = (1/f) ^ (t^3)
    SM9_Fp12_FrobMap(&tmp1, &tmp0); // T2=((1/f) ^ (t^3))^q
    SM9_Fp12_Mul(&y6, &tmp0, &tmp1); // y4=1/(f^t * (f^(t^2))^q)

    SM9_Fp12_Mul(&tmp0, &y6, &y6); // tmp0=y6^2
    SM9_Fp12_Mul(&tmp0, &tmp0, &y4); // tmp0=tmp0*y4 = y4 * y6^2
    SM9_Fp12_Mul(&tmp0, &tmp0, &y5); // tmp0=tmp0*y5 = y4 * y5 *  y6^2
    SM9_Fp12_Mul(&tmp1, &y3, &y5); // tmp1=y3*y5
    SM9_Fp12_Mul(&tmp1, &tmp1, &tmp0); // tmp1=tmp1*tmp0 = y3 * y4 * y5^2 *  y6^2
    SM9_Fp12_Mul(&tmp0, &tmp0, &y2); // tmp0=tmp0*y2 = y2 * y4 * y5 *  y6^2
    SM9_Fp12_Mul(&tmp1, &tmp1, &tmp1); // tmp1=tmp1^2  = y3^2 * y4^2 * y5^4 *  y6^4
    SM9_Fp12_Mul(&tmp1, &tmp1, &tmp0); // tmp1=tmp1*tmp0 = y2 * y3^2 * y4^3 * y5^5 *  y6^6
    SM9_Fp12_Mul(&tmp1, &tmp1, &tmp1); // tmp1=tmp1^2  = y2^2 * y3^4 * y4^6 * y5^10 * y6^12
    SM9_Fp12_Mul(&tmp0, &tmp1, &y1); // tmp0=tmp1*y1 = y1 * y2 * y4 * y5 *  y6^2
    SM9_Fp12_Mul(&tmp1, &tmp1, &y0); // tmp1=tmp1*y0 = y0 * y2^2 * y3^4 * y4^6 * y5^10 * y6^12
    SM9_Fp12_Mul(&tmp0, &tmp0, &tmp0); // tmp0=tmp0^2  = y1^2 * y2^2 * y4^2 * y5^2 *  y6^4
    SM9_Fp12_Mul(result, &tmp0, &tmp1); // tmp0=tmp0*tmp1 = y0 * y1^2 * y2^4 * y3^4 * y4^8 * y5^12 * y6^16
}

static void SM9_Pairing_FinExp(SM9_Fp12 *result, SM9_Fp12 *value)
{
    SM9_Pairing_ExpQ6(result, value);
    SM9_Pairing_ExpQ2(result, result);
    SM9_Pairing_ExpQ4(result, result);
}

void SM9_Pairing_RAte(SM9_Fp12 *result, SM9_EcpA *g1Point, SM9_Ecp2A *g2Point)
{
    SM9_Pairing_MillerRTate(result, g1Point, g2Point, g_sm9SysPara.ec6T2);
    SM9_Pairing_FinExp(result, result);
}

uint32_t SM9_BN_AddInt(uint32_t *result, const uint32_t *value, uint32_t word, int32_t wordSize)
{
    int32_t i = 0;
    uint64_t carry = 0;

    if (word != 0) {
        carry = (uint64_t)value[0] + (uint64_t)word;
        result[0] = (uint32_t)carry;
        carry = carry >> 32;
        for (i = 1; i < wordSize; i++) {
            if (carry == 0) {
                break;
            }
            carry = (uint64_t)value[i] + carry;
            result[i] = (uint32_t)carry;
            carry = carry >> 32;
        }
    }
    if (result != value) {
        for (; i < wordSize; i++) {
            result[i] = value[i];
        }
    }

    return (uint32_t)carry;
}

int32_t SM9_BN_ToByte(uint32_t *value, int32_t wordSize, uint8_t *output, int32_t *byteLen)
{
    int32_t i = 0;
    uint8_t *cursor = NULL;
    uint32_t word = 0;

    cursor = output;
    for (i = wordSize - 1; i >= 0; i--) {
        word = value[i];
        *cursor++ = (uint8_t)((word & 0xFF000000) >> 24);
        *cursor++ = (uint8_t)((word & 0x00FF0000) >> 16);
        *cursor++ = (uint8_t)((word & 0x0000FF00) >> 8);
        *cursor++ = (uint8_t)(word & 0x000000FF);
    }
    if (byteLen != NULL) {
        *byteLen = wordSize << 2;
    }

    return 1;
}

void SM9_Fp_WriteBytes(uint8_t *dst, uint32_t *src)
{
    uint32_t tmp[SM9_BN_WORDS];

    SM9_BN_MontMul(tmp, src, g_sm9SysPara.ecOne, g_sm9SysPara.ecQ, g_sm9SysPara.qMc, g_sm9SysPara.wordSize);
    SM9_BN_GetResidue(tmp, g_sm9SysPara.ecQ, g_sm9SysPara.wordSize);
    SM9_BN_ToByte(tmp, SM9_BN_WORDS, dst, 0);
}

static int32_t SM9_BN_GetWordLen(const uint32_t *value, int32_t wordSize)
{
    int32_t i;

    for (i = wordSize - 1; i >= 0; i--) {
        if (value[i] != 0) {
            return i + 1;
        }
    }
    return 0;
}

static int32_t SM9_BN_ModBasic(uint32_t *remainder, int32_t remainderWords, uint32_t *dividend, int32_t dividendWords,
                               uint32_t *modulus, int32_t modulusWords)
{
    int32_t j = 0;
    uint64_t quotientWord = 0;
    uint64_t carry = 0;
    uint64_t correctionCarry = 0;
    int32_t dividendLen = dividendWords;
    int32_t modulusLen = modulusWords;
    int32_t topIndex = modulusLen - 1;
    uint32_t product[SM9_BN_MAX_WORDS] = {0};
    uint32_t quotient[SM9_BN_MAX_WORDS] = {0};

    for (int32_t i = dividendLen - modulusLen; i >= 0; i--) {
        // quotientWord[i] = (r[i+modulusLen]B+R[i+modulusLen-1])/b[modulusLen-1]
        quotientWord =
            ((((uint64_t)(dividend[i + modulusLen]) << SM9_BN_WORD_BITS) + (uint64_t)dividend[i + modulusLen - 1])) /
            (uint64_t)modulus[topIndex];
        if ((quotientWord & 0xffffffff00000000) != 0) {
            quotient[i] = 0xffffffff;
        } else {
            quotient[i] = (uint32_t)quotientWord;
        }
        carry = 0;
        for (j = 0; j < modulusLen; j++) { // product = quotientWord[i] * modulus
            carry = (uint64_t)quotient[i] * (uint64_t)modulus[j] + carry;
            product[j] = (uint32_t)carry;
            carry >>= SM9_BN_WORD_BITS;
        }
        product[j] = (uint32_t)carry;
        carry = 0;
        for (j = 0; j < modulusLen; j++) { // dividend = dividend - (product << ( 32 * i))
            carry = (uint64_t)dividend[i + j] - (uint64_t)product[j] + carry;
            dividend[i + j] = (uint32_t)carry;
            carry = ((int64_t)carry) >> SM9_BN_WORD_BITS;
        }
        carry = (uint64_t)dividend[i + j] - (uint64_t)product[j] + carry;
        while ((carry & 0x1000000000000000) != 0) { // while r[i+modulusLen] < 0
            correctionCarry = 0;
            for (j = 0; j < modulusLen; j++) { // dividend = dividend + (modulus << ( 32 * i))
                correctionCarry = (uint64_t)dividend[i + j] + (uint64_t)modulus[j] + correctionCarry;
                dividend[i + j] = (uint32_t)correctionCarry;
                correctionCarry = (uint64_t)(correctionCarry >> SM9_BN_WORD_BITS);
            }
            carry = carry + correctionCarry;
            quotient[i] -= 1;
        }
        dividend[i + modulusLen] = (uint32_t)carry;
    }
    int32_t lenRem = SM9_BN_GetWordLen(dividend, modulusWords);
    if (lenRem > remainderWords) {
        return 0;
    }
    SM9_BN_Assign(remainder, dividend, lenRem);
    SM9_BN_Reset(remainder + lenRem, remainderWords - lenRem);
    return 1;
}

static uint32_t SM9_BN_SubInt(uint32_t *result, const uint32_t *value, uint32_t word, int32_t wordSize)
{
    int32_t i = 0;
    uint64_t borrow = 0;

    if (word != 0) {
        borrow = (uint64_t)value[0] - (uint64_t)word + borrow;
        result[0] = (uint32_t)borrow;
        borrow = (uint64_t)(((int64_t)borrow) >> 32);
        for (i = 1; i < wordSize; i++) {
            if (borrow == 0) {
                break;
            }
            borrow = (uint64_t)value[i] + borrow;
            result[i] = (uint32_t)borrow;
            borrow = (uint64_t)(((int64_t)borrow) >> 32);
        }
    }
    if (result != value) {
        for (; i < wordSize; i++) {
            result[i] = value[i];
        }
    }

    return (uint32_t)borrow;
}

int32_t SM9_Hash_H(uint32_t *result, uint8_t tag, const uint8_t *msg, uint32_t msgLen, const uint8_t *suffix,
                   uint32_t suffixLen)
{
    CRYPT_SM3_Ctx ctx;
    uint32_t hashLen = CRYPT_SM3_DIGESTSIZE;
    uint8_t counterBytes[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t hashBytes[2 * SM9_BN_BYTES];
    uint32_t hashWords[SM9_H_WORD_LEN + 1];
    uint32_t orderMinusOne[SM9_BN_WORDS];
    int32_t i;
    int32_t ret;

    for (i = 0; i < 2; i++) {
        GOTO_ERR_IF_EX(CRYPT_SM3_Init(&ctx), ret);
        GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx, &tag, 1), ret);
        GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx, msg, msgLen), ret);
        if (suffix != NULL) {
            GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx, suffix, suffixLen), ret);
        }
        GOTO_ERR_IF_EX(CRYPT_SM3_Update(&ctx, counterBytes, 4), ret);
        GOTO_ERR_IF_EX(CRYPT_SM3_Final(&ctx, hashBytes + i * SM9_BN_BYTES, &hashLen), ret);
        counterBytes[3]++;
    }

    SM9_BN_ByteToBN(hashBytes, SM9_H_BYTE_LEN, hashWords, SM9_H_WORD_LEN);
    hashWords[SM9_H_WORD_LEN] = 0x00000000;

    // h=(hashBytes mod (n-1))+1
    SM9_BN_SubInt(orderMinusOne, g_sm9SysPara.ecN, 1, SM9_BN_WORDS);
    SM9_BN_ModBasic(result, SM9_BN_WORDS, hashWords, SM9_H_WORD_LEN, orderMinusOne, SM9_BN_WORDS);
    SM9_BN_AddInt(result, result, 1, SM9_BN_WORDS);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_CleanseData(&ctx, sizeof(ctx));
    BSL_SAL_CleanseData(hashBytes, sizeof(hashBytes));
    BSL_SAL_CleanseData(hashWords, sizeof(hashWords));
    BSL_SAL_CleanseData(orderMinusOne, sizeof(orderMinusOne));
    return ret;
}

// read fp12 element and convert to MontMode
void SM9_Fp12_ReadBytes(SM9_Fp12 *dst, const uint8_t *src)
{
    SM9_Fp_ReadBytes(dst->coef0.coef0.coef0, src + 11 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef0.coef0.coef1, src + 10 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef0.coef1.coef0, src + 9 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef0.coef1.coef1, src + 8 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef1.coef0.coef0, src + 7 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef1.coef0.coef1, src + 6 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef1.coef1.coef0, src + 5 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef1.coef1.coef1, src + 4 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef2.coef0.coef0, src + 3 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef2.coef0.coef1, src + 2 * SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef2.coef1.coef0, src + SM9_BN_BYTES);
    SM9_Fp_ReadBytes(dst->coef2.coef1.coef1, src);
}

// write fp12 element and convert to NormMode
void SM9_Fp12_WriteBytes(uint8_t *dst, SM9_Fp12 *src)
{
    SM9_Fp_WriteBytes(dst + 11 * SM9_BN_BYTES, src->coef0.coef0.coef0);
    SM9_Fp_WriteBytes(dst + 10 * SM9_BN_BYTES, src->coef0.coef0.coef1);
    SM9_Fp_WriteBytes(dst + 9 * SM9_BN_BYTES, src->coef0.coef1.coef0);
    SM9_Fp_WriteBytes(dst + 8 * SM9_BN_BYTES, src->coef0.coef1.coef1);
    SM9_Fp_WriteBytes(dst + 7 * SM9_BN_BYTES, src->coef1.coef0.coef0);
    SM9_Fp_WriteBytes(dst + 6 * SM9_BN_BYTES, src->coef1.coef0.coef1);
    SM9_Fp_WriteBytes(dst + 5 * SM9_BN_BYTES, src->coef1.coef1.coef0);
    SM9_Fp_WriteBytes(dst + 4 * SM9_BN_BYTES, src->coef1.coef1.coef1);
    SM9_Fp_WriteBytes(dst + 3 * SM9_BN_BYTES, src->coef2.coef0.coef0);
    SM9_Fp_WriteBytes(dst + 2 * SM9_BN_BYTES, src->coef2.coef0.coef1);
    SM9_Fp_WriteBytes(dst + SM9_BN_BYTES, src->coef2.coef1.coef0);
    SM9_Fp_WriteBytes(dst, src->coef2.coef1.coef1);
}

int32_t SM9_Alg_Pair(uint8_t *result, uint8_t *g1Bytes, uint8_t *g2Bytes)
{
    SM9_EcpA g1Point;
    SM9_Ecp2A g2Point;
    SM9_Fp12 pairingValue;

    int32_t ret = SM9_EcpA_ValidateBytes(g1Bytes);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = SM9_Ecp2A_ValidateBytes(g2Bytes);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Read ecpoint P1 and convert to MontMode
    SM9_EcpA_ReadBytes(&g1Point, g1Bytes);
    // Read ecpoint P2 and convert to MontMode
    SM9_Ecp2A_ReadBytes(&g2Point, g2Bytes);
    // Compute pairing
    SM9_Pairing_RAte(&pairingValue, &g1Point, &g2Point);
    // Output to bytes
    SM9_Fp12_WriteBytes(result, &pairingValue);

    return CRYPT_SUCCESS;
}

int32_t SM9_Alg_PairEqual(SM9_EcpA *firstG1, SM9_Ecp2A *firstG2, SM9_EcpA *secondG1, SM9_Ecp2A *secondG2)
{
    SM9_Fp12 pairA;
    SM9_Fp12 pairB;
    uint8_t pairABytes[12 * SM9_BN_BYTES];
    uint8_t pairBBytes[12 * SM9_BN_BYTES];

    SM9_Pairing_RAte(&pairA, firstG1, firstG2);
    SM9_Pairing_RAte(&pairB, secondG1, secondG2);
    SM9_Fp12_WriteBytes(pairABytes, &pairA);
    SM9_Fp12_WriteBytes(pairBBytes, &pairB);
    int32_t ret = ConstTimeMemcmp(pairABytes, pairBBytes, sizeof(pairABytes)) == 0xFFFFFFFFu ?
                      CRYPT_SUCCESS :
                      CRYPT_SM9_PAIRWISE_CHECK_FAIL;

    BSL_SAL_CleanseData(&pairA, sizeof(pairA));
    BSL_SAL_CleanseData(&pairB, sizeof(pairB));
    BSL_SAL_CleanseData(pairABytes, sizeof(pairABytes));
    BSL_SAL_CleanseData(pairBBytes, sizeof(pairBBytes));
    return ret;
}

void SM9_Ecp2A_WriteBytes(uint8_t *dst, SM9_Ecp2A *src)
{
    SM9_Fp_WriteBytes(dst, src->x.coef1);
    SM9_Fp_WriteBytes(dst + SM9_BN_BYTES, src->x.coef0);
    SM9_Fp_WriteBytes(dst + 2 * SM9_BN_BYTES, src->y.coef1);
    SM9_Fp_WriteBytes(dst + 3 * SM9_BN_BYTES, src->y.coef0);
}

void SM9_EcpA_WriteBytes(uint8_t *dst, SM9_EcpA *src)
{
    SM9_Fp_WriteBytes(dst, src->x);
    SM9_Fp_WriteBytes(dst + SM9_BN_BYTES, src->y);
}

#endif // HITLS_CRYPTO_SM9
