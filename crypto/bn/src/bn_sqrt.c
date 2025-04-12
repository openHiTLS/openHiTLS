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
#ifdef HITLS_CRYPTO_ECC

#include <stdint.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bn_optimizer.h"
#include "crypt_bn.h"


static uint32_t GetExp(const BN_BigNum *bn)
{
    uint32_t s = 0;
    while (!BN_GetBit(bn, s)) {
        s++;
    }
    return s;
}

// p does not perform prime number check, but performs parity check.
static int32_t CheckParam(const BN_BigNum *a, const BN_BigNum *p)
{
    if (BN_IsZero(p) || BN_IsOne(p)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_SQRT_PARA);
        return CRYPT_BN_ERR_SQRT_PARA;
    }
    if (!BN_GetBit(p, 0)) { // p must be odd prime
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_SQRT_PARA);
        return CRYPT_BN_ERR_SQRT_PARA;
    }
    if (p->sign || a->sign) { // p、a must be positive
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_SQRT_PARA);
        return CRYPT_BN_ERR_SQRT_PARA;
    }
    if (BN_Cmp(p, a) <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_SQRT_PARA);
        return CRYPT_BN_ERR_SQRT_PARA;
    }
    return CRYPT_SUCCESS;
}

// r = +- a^((p + 1)/4)
static int32_t CalculationRoot(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Mont *mont, BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *temp = OptimizerGetBn(opt, p->size);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF_EX(BN_AddLimb(temp, p, 1), ret);   // p + 1
    GOTO_ERR_IF_EX(BN_Rshift(temp, temp, 2), ret); // (p + 1) / 4 = (p + 1) >> 2
    GOTO_ERR_IF(BN_MontExp(r, a, temp, mont, opt), ret);
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t LegendreFastTempDataCheck(const BN_BigNum *a, const BN_BigNum *pp)
{
    if (a == NULL || pp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t LegendreFast(BN_BigNum *z, const BN_BigNum *p, int32_t *legendre, BN_Optimizer *opt)
{
    int32_t l = 1;
    BN_BigNum *temp = NULL;
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *a = OptimizerGetBn(opt, p->size);      // The variable has been checked for NULL in BN_Copy.
    BN_BigNum *pp = OptimizerGetBn(opt, p->size);
    GOTO_ERR_IF(LegendreFastTempDataCheck(a, pp), ret);
    if (BN_IsOne(z)) {
        *legendre = 1;
        goto ERR;
    }
    if (BN_IsZero(z)) {
        *legendre = 0;
        goto ERR;
    }
    GOTO_ERR_IF_EX(BN_Copy(a, z), ret);
    GOTO_ERR_IF_EX(BN_Copy(pp, p), ret);
    while (true) {
        if (BN_IsZero(a)) {
            *legendre = BN_IsOne(pp) ? l : 0;
            break;
        }
        // Theorem: p is an odd prime number, a and b are numbers that are not divisible by p. (a|p)(b|p) = (ab|p)
        // a = aa * 2^exp
        // (a|pp) = (2|pp)^exp * (aa|pp)
        // If exp is an even number, (a|pp) = (aa|pp)
        uint32_t exp = GetExp(a);
        GOTO_ERR_IF_EX(BN_Rshift(a, a, exp), ret);
        if ((exp & 1) != 0) {
            // pp = +- 1 mod 8, 2 is its quadratic remainder. pp = +-3 mod 8, 2 is its non-quadric remainder.
            if ((pp->data[0] & 1) != 0) {
                // pp->data[0] % 8 = pp->data[0] & 7
                // pp = +- 1 mod 8 = 7 or 1 mod
                l = ((pp->data[0] & 7) == 1 || (pp->data[0] & 7) == 7) ? l : -l;
            } else {
                l = 0;
            }
        }
        // pp->data[0] % 4 = pp->data[0] & 3
        // K(a|pp) = K(pp|a) * (-1)^((a-1)*(pp-1)/4)
        // (a-1)*(pp-1)/4 is an even number only when at least one of A and P mod 4 = 1;
        // if both A and P mod 4 = 3, (a-1)*(pp-1)/4 is an odd number.
        if (((pp->data[0] & 3) == 3) && ((a->data[0] & 3) == 3)) {
            l = -l;
        }
        // K(pp|a) = K(pp%a|a), swap(a,pp)
        GOTO_ERR_IF_EX(BN_Div(NULL, pp, pp, a, opt), ret);
        temp = a;
        a = pp;
        pp = temp;
    }
    ret = CRYPT_SUCCESS;
ERR:
    OptimizerEnd(opt);
    return ret;
}

// Find z so that legendre(z / p) = z^((p-1)/2) mod p != 1
static int32_t GetLegendreZ(BN_BigNum *z, const BN_BigNum *p, BN_Optimizer *opt)
{
    uint32_t maxCnt = 50; // A random number can be generated cyclically for a maximum of 50 times.
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    int32_t legendre;
    BN_BigNum *exp = OptimizerGetBn(opt, p->size); // exp = (p - 1) / 2
    if (exp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF_EX(BN_SubLimb(exp, p, 1), ret);
    GOTO_ERR_IF_EX(BN_Rshift(exp, exp, 1), ret);

    while (maxCnt > 0) {
        GOTO_ERR_IF_EX(BN_RandRangeEx(opt->libCtx, z, p), ret);

        maxCnt--;
        if (BN_IsZero(z)) {
            continue;
        }

        GOTO_ERR_IF_EX(LegendreFast(z, p, &legendre, opt), ret);
        if (legendre == -1) {
            ret = CRYPT_SUCCESS;
            goto ERR;
        }
    }
    ret = CRYPT_BN_ERR_LEGENDE_DATA;
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t SetParaR(BN_BigNum *r, BN_BigNum *q, const BN_BigNum *a, BN_Mont *mont, BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *temp = OptimizerGetBn(opt, q->size);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF_EX(BN_AddLimb(temp, q, 1), ret);            // q + 1
    GOTO_ERR_IF_EX(BN_Rshift(temp, temp, 1), ret);          // (p + 1) / 2
    GOTO_ERR_IF(BN_MontExp(r, a, temp, mont, opt), ret); // r = a^((q+1)/2) mod p
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t TonelliShanksCalculation(BN_BigNum *r, BN_BigNum *c, BN_BigNum *t,
    uint32_t s, const BN_BigNum *p, BN_Optimizer *opt)
{
    uint32_t m = s;
    uint32_t i, j;
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *b = OptimizerGetBn(opt, p->size);
    BN_BigNum *tempT = OptimizerGetBn(opt, p->size);
    if (b == NULL || tempT == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    while (!BN_IsOne(t)) {
        // Find an i (0 < i < s) so that t^(2^i) = 1
        i = 1;
        // repeat modulus square
        GOTO_ERR_IF_EX(BN_ModSqr(tempT, t, p, opt), ret);
        while (!BN_IsOne(tempT)) {
            i++;
            if (i >= m) {
                ret = CRYPT_BN_ERR_NO_SQUARE_ROOT;
                BSL_ERR_PUSH_ERROR(ret);
                goto ERR;
            }
            GOTO_ERR_IF_EX(BN_ModSqr(tempT, tempT, p, opt), ret);
        }

        // b = c^(2^(m-i-1)), if m-i-1 == 0, b = c
        GOTO_ERR_IF_EX(BN_Copy(b, c), ret);
        for (j = m - i - 1; j > 0; j--) {
            GOTO_ERR_IF_EX(BN_ModSqr(b, b, p, opt), ret);
        }
        GOTO_ERR_IF_EX(BN_ModMul(r, r, b, p, opt), ret); // r = r * b
        GOTO_ERR_IF_EX(BN_ModSqr(c, b, p, opt), ret);    // c = b*b
        GOTO_ERR_IF_EX(BN_ModMul(t, t, c, p, opt), ret); // t = t * b * b = t * c
        m = i;
    }
    ret = CRYPT_SUCCESS;
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t SqrtVerify(
    BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Optimizer *opt)
{
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *square = OptimizerGetBn(opt, p->size);
    if (square == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    GOTO_ERR_IF_EX(BN_ModSqr(square, r, p, opt), ret);

    if (BN_Cmp(square, a) != 0) {
        ret = CRYPT_BN_ERR_NO_SQUARE_ROOT;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t BN_ModSqrtTempDataCheck(const BN_BigNum *pSubOne, const BN_BigNum *q,
    const BN_BigNum *z, const BN_BigNum *c, const BN_BigNum *t)
{
    if (pSubOne == NULL || q == NULL || z == NULL || c == NULL || t == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

/* 1. Input parameters a and p. p is an odd prime number, and a is an integer (0 <= a <= p-1)
2. For P-1 processing, let p-1 = q * 2^s
3. If s=1，r = a^((p + 1)/4)
4. Randomly select z (1<= z <= p-1) so that the Legendre symbol of z to p equals -1. (z, p) = 1, (z/p) = a^((p-1)/2)
5. Setting c = z^q, r = a^((q+1)/2), t = a^q, m = s
6. Circulation
    1) If t = 1, return r.
    2) Find an i (0 < i < m) so that t^(2^i) = 1.
    3) b = c^(2^(m-i-1)), r = r * b, t = t*b*b, c = b*b, m = i
7. Verification */
int32_t BN_ModSqrt(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || p == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint32_t s = 0;
    BN_Mont *mont = NULL;
    BN_BigNum *pSubOne = OptimizerGetBn(opt, p->size);
    BN_BigNum *q = OptimizerGetBn(opt, p->size);
    BN_BigNum *z = OptimizerGetBn(opt, p->size);
    BN_BigNum *c = OptimizerGetBn(opt, p->size);
    BN_BigNum *t = OptimizerGetBn(opt, p->size);
    GOTO_ERR_IF(BN_ModSqrtTempDataCheck(pSubOne, q, z, c, t), ret);

    GOTO_ERR_IF_EX(CheckParam(a, p), ret);

    if (BN_IsZero(a) || BN_IsOne(a)) {
        GOTO_ERR_IF_EX(BN_Copy(r, a), ret);
        goto VERIFY;
    }

    mont = BN_MontCreate(p);
    if (mont == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF_EX(BN_SubLimb(pSubOne, p, 1), ret);

    s = GetExp(pSubOne);               // Obtains the power s of factor 2 in p-1.
    GOTO_ERR_IF_EX(BN_Rshift(q, pSubOne, s), ret); // p - 1 = q * 2^s
    if (s == 1) {
        // s==1，r = +- n^((p + 1)/4)
        GOTO_ERR_IF_EX(CalculationRoot(r, a, p, mont, opt), ret);
        goto VERIFY;
    }
    // Randomly select z(1<= z <= p-1), so that the Legendre symbol of z to p equals -1. (z, p) = 1, (z/p) = a^((p-1)/2)
    GOTO_ERR_IF(GetLegendreZ(z, p, opt), ret);

    GOTO_ERR_IF(BN_MontExp(c, z, q, mont, opt), ret); // c = z^q mod p
    GOTO_ERR_IF(BN_MontExp(t, a, q, mont, opt), ret); // t = a^q mod p
    GOTO_ERR_IF_EX(SetParaR(r, q, a, mont, opt), ret);   // r = a^((q+1)/2) mod p

    // Circulation
    // 1) If t = 1, return r.
    // 2) Find an i (0 < i < m) so that t^(2^i) = 1
    // 3) b = c^(2^(m-i-1)), r = r * b, t = t*b*b, c = b*b, m = i
    GOTO_ERR_IF_EX(TonelliShanksCalculation(r, c, t, s, p, opt), ret);

VERIFY:
    GOTO_ERR_IF_EX(SqrtVerify(r, a, p, opt), ret);

ERR:
    OptimizerEnd(opt);
    BN_MontDestroy(mont);
    return ret;
}
#endif /* HITLS_CRYPTO_ECC */
