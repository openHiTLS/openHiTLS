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
#ifdef HITLS_CRYPTO_BN

#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "bn_optimizer.h"


/* Euclidean algorithm */
static int32_t BnGcdDiv(BN_BigNum *r, BN_BigNum *max, BN_BigNum *min, BN_Optimizer *opt)
{
    int32_t ret = CRYPT_SUCCESS;
    BN_BigNum *tmp = NULL;
    BN_BigNum *big = max;
    BN_BigNum *small = min;
    do {
        ret = BN_Div(NULL, big, big, small, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_IsOne(big)) {
            return BN_Copy(r, big);
        }
        if (BN_IsZero(big)) {
            return BN_Copy(r, small);
        }
        /* ensure that big > small in the next calculation of remainder */
        tmp = big;
        big = small;
        small = tmp;
    } while (true);
    return CRYPT_SUCCESS;
}

int32_t BnGcdCheckInput(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, const BN_Optimizer *opt)
{
    bool invalidInput = (a == NULL || b == NULL || r == NULL || opt == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    /* The GCD may be the minimum value between a and b. Ensure the r space before calculation. */
    uint32_t needSize = (a->size < b->size) ? a->size : b->size;
    int32_t ret = BnExtend(r, needSize);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // a and b cannot be 0
    if (BN_IsZero(a) || BN_IsZero(b)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_GCD_NO_ZERO);
        return CRYPT_BN_ERR_GCD_NO_ZERO;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Gcd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt)
{
    int32_t ret = BnGcdCheckInput(r, a, b, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = BinCmp(a->data, a->size, b->data, b->size);
    if (ret == 0) { // For example, a == b is the greatest common divisor of itself
        ret = BN_Copy(r, a);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        r->sign = false; // the greatest common divisor is a positive integer
        return CRYPT_SUCCESS;
    }
    const BN_BigNum *bigNum = (ret > 0) ? a : b;
    const BN_BigNum *smallNum = (ret > 0) ? b : a;
    ret = OptimizerStart(opt); // use the optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* Apply for temporary space of BN objects a and b. */
    BN_BigNum *max = OptimizerGetBn(opt, bigNum->size);
    BN_BigNum *min = OptimizerGetBn(opt, smallNum->size);
    if (max == NULL || min == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    ret = BN_Copy(max, bigNum);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Copy(min, smallNum);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // obtain the GCD, ensure that input parameter max > min
    ret = BnGcdDiv(r, max, min, opt);
    if (ret == CRYPT_SUCCESS) {
        r->sign = false; // The GCD is a positive integer
    }
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

static int32_t InverseReady(BN_BigNum *a, BN_BigNum *b, const BN_BigNum *x, const BN_BigNum *m, BN_Optimizer *opt)
{
    int32_t ret = BN_Copy(a, m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    a->sign = false;
    ret = BN_Mod(b, x, m, opt); // b must be a positive number and do not need to convert symbols.
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (BN_IsZero(b)) { // does not satisfy x and m interprime, so it cannot obtain the inverse module.
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    return CRYPT_SUCCESS;
}

static int32_t InverseCore(BN_BigNum *r, BN_BigNum *x, BN_BigNum *y, uint32_t mSize, BN_Optimizer *opt)
{
    BN_BigNum *a = x;
    BN_BigNum *b = y;
    BN_BigNum *c = OptimizerGetBn(opt, mSize); // One more bit is reserved for addition and subtraction.
    BN_BigNum *d = OptimizerGetBn(opt, mSize);
    BN_BigNum *e = OptimizerGetBn(opt, mSize * 2); // multiplication of c requires 2x space
    BN_BigNum *t = OptimizerGetBn(opt, mSize);
    if (c == NULL || d == NULL || e == NULL || t == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    (void)BN_SetBit(d, 0); // can ignore the return value
    do {
        int32_t ret = BN_Div(t, a, a, b, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_IsZero(a)) {
            if (BN_IsOne(b)) { // b is 1
                return BN_SetLimb(r, 1); // obtains the inverse modulus value 1
            }
            break;  // Failed to obtain the inverse modulus value.
        }
        t->sign = !t->sign;
        ret = BN_Mul(e, t, d, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ret = BN_Add(c, c, e);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_IsOne(a)) {
            return BN_Copy(r, c); // Obtain the module inverse.
        }
        // Switch a b
        BN_BigNum *tmp = a;
        a = b;
        b = tmp;
        // Switch c d
        tmp = c;
        c = d;
        d = tmp;
    } while (true);
    BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
    return CRYPT_BN_ERR_NO_INVERSE;
}

int32_t InverseInputCheck(BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *m, const BN_Optimizer *opt)
{
    bool invalidInput = (r == NULL || x == NULL || m == NULL || opt == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    /* cannot be 0 */
    if (BN_IsZero(x) || BN_IsZero(m)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    return BnExtend(r, m->size);
}

int32_t BN_ModInv(BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *m, BN_Optimizer *opt)
{
    int32_t ret = InverseInputCheck(r, x, m, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = OptimizerStart(opt); // use the optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *a = OptimizerGetBn(opt, m->size);
    BN_BigNum *b = OptimizerGetBn(opt, m->size);
    BN_BigNum *t = OptimizerGetBn(opt, m->size);
    bool invalidInput = (a == NULL || b == NULL || t == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto ERR;
    }
    /* Take positive numbers a and b first. */
    ret = InverseReady(a, b, x, m, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    /* Extended Euclidean algorithm */
    ret = InverseCore(t, a, b, m->size, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Prevent the negative number.
    ret = BN_Mod(r, t, m, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
ERR:
    OptimizerEnd(opt); // Release occupation from the optimizer.
    return ret;
}

#if defined(HITLS_CRYPTO_PAILLIER) || defined(HITLS_CRYPTO_RSA_CHECK)

int32_t BN_Lcm(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BN_BigNum *gcd = BN_Create(BN_Bits(r));
    if (gcd == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Gcd(gcd, a, b, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BN_Destroy(gcd);
        return ret;
    }
    if (BN_IsOne(gcd) == false) {
        ret = BN_Div(r, NULL, a, gcd, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BN_Destroy(gcd);
            return ret;
        }
        BN_Destroy(gcd);
        return BN_Mul(r, r, b, opt);
    }
    BN_Destroy(gcd); // a and b are coprime.
    return BN_Mul(r, a, b, opt);
}
#endif

#endif /* HITLS_CRYPTO_BN */
