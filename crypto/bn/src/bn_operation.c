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

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bn_basic.h"
#include "bn_bincal.h"
#include "bn_ucal.h"
#include "bn_optimizer.h"

#define SMALL_CONQUER_SIZE 8

int32_t BN_Cmp(const BN_BigNum *a, const BN_BigNum *b)
{
    if (a == NULL || b == NULL) {
        if (a != NULL) {
            return -1;
        }
        if (b != NULL) {
            return 1;
        }
        return 0;
    }
    if (a->sign != b->sign) {
        return a->sign == false ? 1 : -1;
    }
    if (a->sign == true) {
        return BinCmp(b->data, b->size, a->data, a->size);
    }
    return BinCmp(a->data, a->size, b->data, b->size);
}

int32_t BN_Add(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b)
{
    if (r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (a->sign == b->sign) {
        r->sign = a->sign;
        return UAdd(r, a, b);
    }
    // compare absolute value
    int32_t res = BinCmp(a->data, a->size, b->data, b->size);
    if (res > 0) {
        r->sign = a->sign;
        return USub(r, a, b);
    } else if (res < 0) {
        r->sign = b->sign;
        return USub(r, b, a);
    }
    return BN_Zeroize(r);
}

int32_t BN_AddLimb(BN_BigNum *r, const BN_BigNum *a, BN_UINT w)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->size == 0) {
        return BN_SetLimb(r, w);
    }
    int32_t ret;
    if (a->sign == false) { // a is positive
        ret = BnExtend(r, a->size + 1);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        BN_UINT carry = BinInc(r->data, a->data, a->size, w);
        if (carry != 0) {
            uint32_t size = a->size;
            r->size = size + 1;
            r->data[size] = carry;
        } else {
            r->size = a->size;
        }
        r->sign = false;
        return CRYPT_SUCCESS;
    }
    ret = BnExtend(r, a->size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (a->size == 1) {
        if (a->data[0] > w) {
            r->sign = true;
            r->data[0] = a->data[0] - w;
            r->size = 1;
        } else if (a->data[0] == w) {
            r->sign = false;
            r->data[0] = 0;
            r->size = 0;
        } else {
            r->sign = false;
            r->data[0] = w - a->data[0];
            r->size = 1;
        }
        return CRYPT_SUCCESS;
    }
    r->sign = true;
    UDec(r, a, w);
    return CRYPT_SUCCESS;
}

int32_t BN_Sub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b)
{
    if (r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->sign != b->sign) {
        r->sign = a->sign;
        return UAdd(r, a, b);
    }
    // compare absolute value
    int32_t res = BinCmp(a->data, a->size, b->data, b->size);
    if (res == 0) {
        return BN_Zeroize(r);
    } else if (res > 0) {
        r->sign = a->sign;
        return USub(r, a, b);
    }
    r->sign = !b->sign;
    return USub(r, b, a);
}

int32_t BN_SubLimb(BN_BigNum *r, const BN_BigNum *a, BN_UINT w)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    if (a->size == 0) {
        if (BN_SetLimb(r, w) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        r->sign = (w == 0) ? false : true;
        return CRYPT_SUCCESS;
    }
    if (a->sign == true) {
        ret = BnExtend(r, a->size + 1);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        BN_UINT carry = BinInc(r->data, a->data, a->size, w);
        if (carry != 0) {
            uint32_t size = a->size;
            r->data[size] = carry;
            r->size = size + 1;
        } else {
            r->size = a->size;
        }
        r->sign = true;
        return CRYPT_SUCCESS;
    }
    ret = BnExtend(r, a->size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (a->size == 1) {
        if (a->data[0] >= w) {
            r->data[0] = a->data[0] - w;
            r->size = BinFixSize(r->data, 1);
        } else {
            r->sign = true;
            r->data[0] = w - a->data[0];
            r->size = 1;
        }
        return CRYPT_SUCCESS;
    }
    r->sign = false;
    UDec(r, a, w);
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_BN_COMBA
static int32_t BnMulConquer(BN_BigNum *t, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt)
{
    if (a->size <= SMALL_CONQUER_SIZE && a->size % 2 == 0) { // 2 is to check if a->size is even
        MulConquer(t->data, a->data, b->data, a->size, NULL, false);
    } else {
        BN_BigNum *tmpBn = OptimizerGetBn(opt, SpaceSize(a->size));
        if (tmpBn == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            return CRYPT_BN_OPTIMIZER_GET_FAIL;
        }
        MulConquer(t->data, a->data, b->data, a->size, tmpBn->data, false);
    }
    t->size = a->size + b->size;
    return CRYPT_SUCCESS;
}
#endif

int32_t BN_Mul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (a->size == 0 || b->size == 0) {
        return BN_Zeroize(r);
    }
    uint32_t size = a->size + b->size;
    int32_t ret = BnExtend(r, size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *t = NULL;
    if (r == a || r == b) {
        t = OptimizerGetBn(opt, r->room); // apply for a BN object
        if (t == NULL) {
            OptimizerEnd(opt); // release occupation from the optimizer
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            return CRYPT_BN_OPTIMIZER_GET_FAIL;
        }
    } else {
        t = r;
    }

    t->sign = a->sign != b->sign;
#ifdef HITLS_CRYPTO_BN_COMBA
    if (a->size == b->size) {
        ret = BnMulConquer(t, a, b, opt);
        if (ret != CRYPT_SUCCESS) {
            OptimizerEnd(opt);
            return ret;
        }
    } else {
#endif
        t->size = BinMul(t->data, t->room, a->data, a->size, b->data, b->size);
#ifdef HITLS_CRYPTO_BN_COMBA
    }
#endif

    if (r != t) {
        ret = BN_Copy(r, t);
        if (ret != CRYPT_SUCCESS) {
            OptimizerEnd(opt); // release occupation from the optimizer
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    r->size = BinFixSize(r->data, size);
    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

int32_t BN_MulLimb(BN_BigNum *r, const BN_BigNum *a, const BN_UINT w)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (BN_Bits(a) == 0 || w == 0) {
        return BN_Zeroize(r);
    }

    int32_t ret = BnExtend(r, a->size + 1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_UINT carry = 0;
    uint32_t loc;
    for (loc = 0; loc < a->size; loc++) {
        BN_UINT rh;
        BN_UINT rl;
        MUL_AB(rh, rl, a->data[loc], w);
        ADD_AB(carry, r->data[loc], rl, carry);
        carry += rh;
    }
    if (carry != 0) {
        r->data[loc++] = carry; // Input parameter checking ensures that no out-of-bounds
    }
    r->sign = a->sign;
    r->size = loc;
    return CRYPT_SUCCESS;
}

int32_t BN_Sqr(BN_BigNum *r, const BN_BigNum *a, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->size == 0) {
        return BN_Zeroize(r);
    }
    int32_t ret = BnExtend(r, a->size * 2); // The maximum bit required for mul is 2x that of a.
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

#ifdef HITLS_CRYPTO_BN_COMBA
    if (a->size <= SMALL_CONQUER_SIZE && a->size % 2 == 0) { // 2 is to check if a->size is even.
        SqrConquer(r->data, a->data, a->size, NULL, false);
    } else {
        BN_BigNum *tmpBn = OptimizerGetBn(opt, SpaceSize(a->size));
        if (tmpBn == NULL) {
            OptimizerEnd(opt);
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            return CRYPT_BN_OPTIMIZER_GET_FAIL;
        }
        SqrConquer(r->data, a->data, a->size, tmpBn->data, false);
    }
#else
    BinSqr(r->data, a->size << 1, a->data, a->size);
#endif

    r->size = BinFixSize(r->data, a->size * 2); // The r->data size is a->size * 2.
    r->sign = false; // The square must be positive.
    OptimizerEnd(opt);
    return CRYPT_SUCCESS;
}

int32_t DivInputCheck(const BN_BigNum *q, const BN_BigNum *r, const BN_BigNum *x,
    const BN_BigNum *y, const BN_Optimizer *opt)
{
    if (x == NULL || y == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (q == r) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    // The divisor cannot be 0.
    if (y->size == 0) {
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    return CRYPT_SUCCESS;
}

// If x <= y, perform special processing.
int32_t DivSimple(BN_BigNum *q, BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *y, int32_t flag)
{
    int32_t ret;
    if (flag < 0) {
        if (r != NULL) {
            ret = BN_Copy(r, x);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
        if (q != NULL) {
            return BN_Zeroize(q);
        }
    } else {
        if (q != NULL) {
            bool sign = (x->sign != y->sign);
            ret = BN_SetLimb(q, 1);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            q->sign = sign;
        }
        if (r != NULL) {
            return BN_Zeroize(r);
        }
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Div(BN_BigNum *q, BN_BigNum *r, const BN_BigNum *x, const BN_BigNum *y, BN_Optimizer *opt)
{
    int32_t ret = DivInputCheck(q, r, x, y, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = BinCmp(x->data, x->size, y->data, y->size);
    if (ret <= 0) { // simple processing when dividend <= divisor
        return DivSimple(q, r, x, y, ret);
    }

    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* Apply for temporary space for the q and r of the BN. */
    BN_BigNum *qTmp = OptimizerGetBn(opt, x->size + 2);  // BinDiv:x->room >= xSize + 2
    BN_BigNum *rTmp = OptimizerGetBn(opt, x->size + 2);  // BinDiv:x->room >= xSize + 2
    BN_BigNum *yTmp = OptimizerGetBn(opt, y->size);
    if (qTmp == NULL || rTmp == NULL || yTmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto err;
    }

    (void)memcpy_s(yTmp->data, y->size * sizeof(BN_UINT), y->data, y->size * sizeof(BN_UINT));
    (void)memcpy_s(rTmp->data, x->size * sizeof(BN_UINT), x->data, x->size * sizeof(BN_UINT));
    rTmp->sign = x->sign;

    rTmp->size = BinDiv(qTmp->data, &(qTmp->size), rTmp->data, x->size, yTmp->data, y->size);
    if (q != NULL) {
        ret = BnExtend(q, qTmp->size);
        if (ret != CRYPT_SUCCESS) {
            goto err;
        }
        q->sign = (x->sign != y->sign);
        (void)memcpy_s(q->data, qTmp->size * sizeof(BN_UINT), qTmp->data, qTmp->size * sizeof(BN_UINT));
        q->size = qTmp->size;
    }
    if (r != NULL) {
        ret = BnExtend(r, rTmp->size);
        if (ret != CRYPT_SUCCESS) {
            goto err;
        }
        r->sign = (rTmp->size == 0) ? false : rTmp->sign; // The symbol can only be positive when the value is 0.
        (void)memcpy_s(r->data, rTmp->size * sizeof(BN_UINT), rTmp->data, rTmp->size * sizeof(BN_UINT));
        r->size = rTmp->size;
    }
err:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t DivLimbInputCheck(const BN_BigNum *q, const BN_UINT *r, const BN_BigNum *x, const BN_UINT y)
{
    if (x == NULL || (q == NULL && r == NULL)) { // q and r cannot be NULL at the same time
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (y == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    return CRYPT_SUCCESS;
}

int32_t BN_DivLimb(BN_BigNum *q, BN_UINT *r, const BN_BigNum *x, const BN_UINT y)
{
    int32_t ret = DivLimbInputCheck(q, r, x, y);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Apply for a copy of object x.
    BN_BigNum *xTmp = BN_Dup(x);
    if (xTmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BN_UINT rem = 0;
    BN_UINT yTmp = y;
    uint32_t shifts;
    if (x->size == 0) {
        goto end;
    }

    shifts = GetZeroBitsUint(yTmp);
    if (shifts != 0) {
        yTmp <<= shifts; // Ensure that the most significant bit of the divisor is 1.
        ret = BN_Lshift(xTmp, xTmp, shifts);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BN_Destroy(xTmp);
            return ret;
        }
    }

    for (int32_t i = (int32_t)(xTmp->size - 1); i >= 0; i--) {
        BN_UINT quo;
        DIV_ND(quo, rem, rem, xTmp->data[i], yTmp);
        xTmp->data[i] = quo;
    }

    xTmp->size = BinFixSize(xTmp->data, xTmp->size);
    if (xTmp->size == 0) {
        xTmp->sign = 0;
    }
    rem >>= shifts;

end:
    if (q != NULL) {
        ret = BN_Copy(q, xTmp);
        if (ret != CRYPT_SUCCESS) {
            BN_Destroy(xTmp);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (r != NULL) {
        *r = rem;
    }
    BN_Destroy(xTmp);
    return ret;
}

int32_t BN_Mod(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *m, BN_Optimizer *opt)
{
    // check input parameters
    if (r == NULL || a == NULL || m == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (m->size == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    int32_t ret = BnExtend(r, m->size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = OptimizerStart(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_BigNum *t = OptimizerGetBn(opt, m->size);
    if (t == NULL) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    ret = BN_Div(NULL, t, a, m, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        OptimizerEnd(opt);
        return ret;
    }
    // t is a positive number
    if (t->sign == false) {
        ret = BN_Copy(r, t);
        OptimizerEnd(opt);
        return ret;
    }
    // When t is a negative number, the modulo operation result must be positive.
    if (m->sign == true) { // m is a negative number
        ret = BN_Sub(r, t, m);
    } else { // m is a positive number
        ret = BN_Add(r, t, m);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    OptimizerEnd(opt);
    return ret;
}

int32_t BN_ModLimb(BN_UINT *r, const BN_BigNum *a, const BN_UINT m)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (m == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }

    if (a->size == 0) {
        *r = 0;
        return CRYPT_SUCCESS;
    }
    int32_t ret = BN_DivLimb(NULL, r, a, m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (a->sign) {
        *r = m - *r;
    }
    return ret;
}

// Check the input parameters of basic operations such as modulo addition, subtraction, and multiplication.
int32_t ModBaseInputCheck(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, const BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BnExtend(r, mod->size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    // mod cannot be 0
    if (BN_IsZero(mod)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }

    return CRYPT_SUCCESS;
}

int32_t BN_ModSub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, const BN_BigNum *mod, BN_Optimizer *opt)
{
    int32_t ret = ModBaseInputCheck(r, a, b, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    /* Difference: Apply for the temporary space of the BN object. */
    uint32_t subTmpSize = (a->size > b ->size) ? a->size : b->size;
    BN_BigNum *t = OptimizerGetBn(opt, subTmpSize);
    if (t == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Sub(t, a, b), ret);
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t BN_ModAdd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, const BN_BigNum *mod, BN_Optimizer *opt)
{
    int32_t ret = ModBaseInputCheck(r, a, b, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    /* Difference: Apply for the temporary space of the BN object. */
    uint32_t addTmpSize = (a->size > b ->size) ? a->size : b->size;
    BN_BigNum *t = OptimizerGetBn(opt, addTmpSize);
    if (t == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Add(t, a, b), ret);
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t BN_ModMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, const BN_BigNum *mod, BN_Optimizer *opt)
{
    int32_t ret = ModBaseInputCheck(r, a, b, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    /* Apply for the temporary space of the BN object. */
    BN_BigNum *t = OptimizerGetBn(opt, a->size + b->size + 1);
    if (t == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Mul(t, a, b, opt), ret);
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t BN_ModSqr(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *mod, BN_Optimizer *opt)
{
    bool invalidInput = (r == NULL || a == NULL || mod == NULL || opt == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // mod cannot be 0
    if (BN_IsZero(mod)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }

    int32_t ret = BnExtend(r, mod->size);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    /* Apply for the temporary space of the BN object. */
    BN_BigNum *t = OptimizerGetBn(opt, (a->size << 1) + 1);
    if (t == NULL) {
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_Sqr(t, a, opt), ret);
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t ModExpInputCheck(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e,
    const BN_BigNum *m, const BN_Optimizer *opt)
{
    bool invalidInput = (r == NULL || a == NULL || e == NULL || m == NULL || opt == NULL);
    if (invalidInput) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // mod cannot be 0
    if (BN_IsZero(m)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    // the power cannot be negative
    if (e->sign == true) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_EXP_NO_NEGATIVE);
        return CRYPT_BN_ERR_EXP_NO_NEGATIVE;
    }
    return BnExtend(r, m->size);
}

int32_t ModExpCore(BN_BigNum *x, BN_BigNum *y, const BN_BigNum *e, const BN_BigNum *m, BN_Optimizer *opt)
{
    int32_t ret;
    if (BN_GetBit(e, 0) == 1) {
        (void)BN_Copy(x, y); // ignores the returned value, we can ensure that no error occurs when applying memory
    } else { // set the value to 1
        (void)BN_SetLimb(x, 1); // ignores the returned value, we can ensure that no error occurs when applying memory
    }

    uint32_t bits = BN_Bits(e);
    for (uint32_t i = 1; i < bits; i++) {
        ret = BN_ModSqr(y, y, m, opt); // y is a temporary variable, which is multiplied by x
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        if (BN_GetBit(e, i) == 1) {
            ret = BN_ModMul(x, x, y, m, opt); // x^1101  = x^1 * x^100 * x^1000
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t SwitchMont(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, const BN_BigNum *m, BN_Optimizer *opt)
{
    BN_Mont *mont = BN_MontCreate(m);
    if (mont == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = BN_MontExp(r, a, e, mont, opt);
    BN_MontDestroy(mont);
    return ret;
}

int32_t BN_ModExp(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e, const BN_BigNum *m, BN_Optimizer *opt)
{
    int32_t ret = ModExpInputCheck(r, a, e, m, opt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // When m = 1 or -1
    if (m->size == 1 && m->data[0] == 1) {
        return BN_Zeroize(r);
    }
    if (BN_IsOdd(m) && !BN_IsNegative(m)) {
        return SwitchMont(r, a, e, m, opt);
    }

    ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Apply for the temporary space of the BN object. */
    BN_BigNum *x = OptimizerGetBn(opt, m->size);
    BN_BigNum *y = OptimizerGetBn(opt, m->size);
    if (x == NULL || y == NULL) {
        OptimizerEnd(opt); // release occupation from the optimizer
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    // step 1: Obtain the modulus once, and then determine the power and remainder.
    ret = BN_Mod(y, a, m, opt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // step2: check the power. Any number to the power of 0 is 1. (0 to the power of 0 to the power of 0)
    if (BN_IsZero(e) || BN_IsOne(y)) {
        OptimizerEnd(opt);
        return BN_SetLimb(r, 1);
    }
    // step3: The remainder is 0 and the result must be 0.
    if (BN_IsZero(y)) {
        OptimizerEnd(opt); // release occupation from the optimizer
        return BN_Zeroize(r);
    }
    /* Power factorization: e binary x^1101  = x^1 * x^100 * x^1000
                            e Decimal x^13    = x^1 * x^4 * x^8  */
    ret = ModExpCore(x, y, e, m, opt);
    if (ret != CRYPT_SUCCESS) {
        OptimizerEnd(opt);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Copy(r, x);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    OptimizerEnd(opt); // release occupation from the optimizer

    return ret;
}

int32_t BN_Rshift(BN_BigNum *r, const BN_BigNum *a, uint32_t n)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_Bits(a) <= n) {
        return BN_Zeroize(r);
    }
    int32_t ret = BnExtend(r, BITS_TO_BN_UNIT(BN_Bits(a) - n));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    r->sign = a->sign;
    uint32_t size = BinRshift(r->data, a->data, a->size, n);
    if (size < r->size) {
        if (memset_s(r->data + size, (r->room - size) * sizeof(BN_UINT), 0,
            (r->size - size) * sizeof(BN_UINT)) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
    }
    r->size = size;
    return CRYPT_SUCCESS;
}

int32_t BN_Lshift(BN_BigNum *r, const BN_BigNum *a, uint32_t n)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t incUnit = n % BN_UINT_BITS == 0 ? (n / BN_UINT_BITS) : ((n / BN_UINT_BITS) + 1);
    int32_t ret = BnExtend(r, a->size + incUnit);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (a->size != 0) {
        r->size = BinLshift(r->data, a->data, a->size, n);
    } else {
        (void)BN_Zeroize(r);
    }
    r->sign = a->sign;
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_ECC
// '~mask' is the mask of a and 'mask' is the mask of b.
int32_t BN_CopyWithMask(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    BN_UINT mask)
{
    if (r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((a->room != r->room) || (b->room != r->room)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_MASKCOPY_LEN);
        return CRYPT_BN_ERR_MASKCOPY_LEN;
    }
    BN_UINT rmask = ~mask;
    uint32_t len = r->room;
    BN_UINT *dst = r->data;
    BN_UINT *srcA = a->data;
    BN_UINT *srcB = b->data;
    for (uint32_t i = 0; i < len; i++) {
        dst[i] = (srcA[i] & rmask) ^ (srcB[i] & mask);
    }
    r->sign = (mask != 0) ? (a->sign) : (b->sign);
    r->size = (a->size & (uint32_t)rmask) ^ (b->size & (uint32_t)mask);
    return CRYPT_SUCCESS;
}
#endif

#if defined(HITLS_CRYPTO_ECC) && defined(HITLS_CRYPTO_CURVE_MONT)
/* Invoked by the ECC module and the sign can be ignored.
 * if mask = BN_MASK, a, b --> b, a
 * if mask = 0, a, b --> a, b
 */
int32_t BN_SwapWithMask(BN_BigNum *a, BN_BigNum *b, BN_UINT mask)
{
    if (a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (a->room != b->room) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_SWAP_LEN);
        return CRYPT_BN_ERR_SWAP_LEN;
    }
    BN_UINT rmask = ~mask;
    BN_UINT *srcA = a->data;
    BN_UINT *srcB = b->data;
    BN_UINT tmp1;
    BN_UINT tmp2;
    uint32_t tmp3;
    uint32_t tmp4;
    for (uint32_t i = 0; i < a->room; i++) {
        tmp1 = srcA[i];
        tmp2 = srcB[i];
        srcA[i] = (tmp1 & rmask) | (tmp2 & mask);
        srcB[i] = (tmp2 & rmask) | (tmp1 & mask);
    }
    tmp3 = a->size;
    tmp4 = b->size;
    a->size = (tmp3 & (uint32_t)rmask) | (tmp4 & (uint32_t)mask);
    b->size = (tmp4 & (uint32_t)rmask) | (tmp3 & (uint32_t)mask);
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_ECC and HITLS_CRYPTO_CURVE_MONT

#endif /* HITLS_CRYPTO_BN */
