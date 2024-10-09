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
    if (BN_ISNEG(a->flag ^ b->flag)) {
        return BN_ISNEG(a->flag) ? -1 : 1;
    }
    if (BN_ISNEG(a->flag)) {
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
    // Ensure that r is sufficient to carry the sum.
    uint32_t aBits = BN_Bits(a);
    uint32_t bBits = BN_Bits(b);
    uint32_t maxbits = (aBits >= bBits) ? aBits : bBits;
    uint32_t tmpFlag = 0;
    if (!BN_ISNEG(a->flag ^ b->flag)) {
        maxbits += 1;
    }
    if (BnExtend(r, BITS_TO_BN_UNIT(maxbits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (!BN_ISNEG(a->flag ^ b->flag)) {
        tmpFlag = BN_GETNEG(a->flag);
        UAdd(r, a, b);
        goto END;
    }
    // compare absolute value
    int32_t res = BinCmp(a->data, a->size, b->data, b->size);
    if (res > 0) {
        tmpFlag = BN_GETNEG(a->flag);
        USub(r, a, b);
        goto END;
    } else if (res < 0) {
        tmpFlag = BN_GETNEG(b->flag);
        USub(r, b, a);
        goto END;
    } else {
        return BN_Zeroize(r);
    }
END:
    BN_CLRNEG(r->flag);
    r->flag |= tmpFlag;
    return CRYPT_SUCCESS;
}

int32_t BN_AddLimb(BN_BigNum *r, const BN_BigNum *a, BN_UINT w)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a)) {
        return BN_SetLimb(r, w);
    }
    uint32_t needBits = BN_Bits(a);
    // process where the size of a is equal to 1 and the actual value of a is less than w
    if (a->size == 1 && a->data[0] < w) {
        needBits = BN_UINT_BITS - GetZeroBitsUint(w);
    }
    if (!BN_ISNEG(a->flag)) {
        needBits += 1;
    }
    if (BnExtend(r, BITS_TO_BN_UNIT(needBits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (!BN_ISNEG(a->flag)) { // a is positive
        BN_CLRNEG(r->flag);
        UInc(r, a, w);
        return CRYPT_SUCCESS;
    }

    if (a->size == 1) {
        if (a->data[0] > w) {
            BN_SETNEG(r->flag);
            r->data[0] = a->data[0] - w;
            r->size = 1;
        } else if (a->data[0] == w) {
            BN_CLRNEG(r->flag);
            r->data[0] = 0;
            r->size = 0;
        } else {
            BN_CLRNEG(r->flag);
            r->data[0] = w - a->data[0];
            r->size = 1;
        }
        return CRYPT_SUCCESS;
    }
    BN_SETNEG(r->flag);
    UDec(r, a, w);
    return CRYPT_SUCCESS;
}

int32_t BN_Sub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b)
{
    if (r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // Ensure that r is sufficient to carry the maximum value of the subtraction between num with different sign bits.
    uint32_t aBits = BN_Bits(a);
    uint32_t bBits = BN_Bits(b);
    uint32_t maxbits = (aBits >= bBits) ? aBits : bBits;
    uint32_t tmpFlag = 0;
    if (BN_ISNEG(a->flag ^ b->flag)) {
        maxbits += 1;
    }
    if (BnExtend(r, BITS_TO_BN_UNIT(maxbits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (BN_ISNEG(a->flag ^ b->flag)) {
        tmpFlag = BN_GETNEG(a->flag);
        BN_CLRNEG(r->flag);
        r->flag |= tmpFlag;
        UAdd(r, a, b);
        return CRYPT_SUCCESS;
    }
    // compare absolute value
    int32_t res = BinCmp(a->data, a->size, b->data, b->size);
    if (res == 0) {
        return BN_Zeroize(r);
    } else if (res > 0) {
        tmpFlag = BN_GETNEG(a->flag);
        BN_CLRNEG(r->flag);
        r->flag |= tmpFlag;
        USub(r, a, b);
        return CRYPT_SUCCESS;
    }
    tmpFlag = BN_GETNEG(b->flag) ^ CRYPT_BN_FLAG_ISNEGTIVE;
    BN_CLRNEG(r->flag);
    r->flag |= tmpFlag;
    USub(r, b, a);
    return CRYPT_SUCCESS;
}

int32_t BN_SubLimb(BN_BigNum *r, const BN_BigNum *a, BN_UINT w)
{
    if (r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a)) {
        if (BN_SetLimb(r, w) != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        if (w == 0) {
            BN_CLRNEG(r->flag);
        } else {
            BN_SETNEG(r->flag);
        }
        return CRYPT_SUCCESS;
    }
    uint32_t needBits = BN_Bits(a);
    // process where the size of a is less than or equal to 1 and the actual value of a is less than w
    if (a->size == 1 && a->data[0] < w) {
        needBits = BN_UINT_BITS - GetZeroBitsUint(w);
    }
    if (BN_ISNEG(a->flag)) {
        needBits += 1;
    }
    if (BnExtend(r, BITS_TO_BN_UNIT(needBits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (BN_ISNEG(a->flag)) {
        BN_SETNEG(r->flag);
        UInc(r, a, w);
        return CRYPT_SUCCESS;
    }
    if (a->size == 1) {
        if (a->data[0] >= w) {
            r->data[0] = a->data[0] - w;
            r->size = BinFixSize(r->data, 1);
        } else {
            BN_SETNEG(r->flag);
            r->data[0] = w - a->data[0];
            r->size = 1;
        }
        return CRYPT_SUCCESS;
    }
    BN_CLRNEG(r->flag);
    UDec(r, a, w);
    return CRYPT_SUCCESS;
}

int32_t BN_Mul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (BN_Bits(a) == 0 || BN_Bits(b) == 0) {
        return BN_Zeroize(r);
    }
    uint32_t bits = BN_Bits(a) + BN_Bits(b);
    if (BnExtend(r, BITS_TO_BN_UNIT(bits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BN_BigNum *t = NULL;
    if (r == a || r == b) {
        int32_t ret = OptimizerStart(opt); // using the Optimizer
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        t = OptimizerGetBn(opt, r->room); // apply for a BN object
        if (t == NULL) {
            OptimizerEnd(opt); // release occupation from the optimizer
            BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
            return CRYPT_BN_OPTIMIZER_GET_FAIL;
        }
    } else {
        t = r;
    }
    if (BN_ISNEG(a->flag ^ b->flag)) {
        BN_SETNEG(t->flag);
    } else {
        BN_CLRNEG(t->flag);
    }
    t->size = BinMul(t->data, t->room, a->data, a->size, b->data, b->size);
    if (r != t) {
        int32_t ret = BN_Copy(r, t);
        if (ret != CRYPT_SUCCESS) {
            OptimizerEnd(opt); // release occupation from the optimizer
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        OptimizerEnd(opt); // release occupation from the optimizer
    }
    return CRYPT_SUCCESS;
}

int32_t BN_Sqr(BN_BigNum *r, const BN_BigNum *a, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t bits = BN_Bits(a) * 2; // The maximum bit required for mul is 2x that of a.
    if (BnExtend(r, BITS_TO_BN_UNIT(bits)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if (a->size == 0) {
        BN_Zeroize(r);
        return CRYPT_SUCCESS;
    }
    int32_t ret = OptimizerStart(opt); // using the Optimizer
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // Apply for a temporary BN object. The size is 1 + twice the size of a.
    BN_BigNum *t = OptimizerGetBn(opt, (a->size * 2) + 1);
    if (t == NULL) {
        OptimizerEnd(opt); // release occupation from the optimizer
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        return CRYPT_BN_OPTIMIZER_GET_FAIL;
    }
    t->size = BinSqr(t->data, t->room, a->data, a->size);
    (void)BN_Copy(r, t); // The preceding verification has been performed. The return value can be ignored.
    OptimizerEnd(opt); // release occupation from the optimizer
    BN_CLRNEG(r->flag); // The square must be positive.
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
    if (BN_Bits(y) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    return CRYPT_SUCCESS;
}

// If x <= y, perform special processing.
int32_t DivSimple(BN_BigNum *q, BN_BigNum *r, const BN_BigNum *x,
    const BN_BigNum *y, int32_t flag)
{
    int32_t ret = CRYPT_SUCCESS;
    if (flag < 0) {
        if (r != NULL) {
            ret = BN_Copy(r, x);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
        }
        if (q != NULL) {
            ret = BN_Zeroize(q);
        }
    } else {
        if (q != NULL) {
            uint32_t tmpFlag = BN_GETNEG(x->flag ^ y->flag);
            ret = BN_SetLimb(q, 1);
            if (ret != 0) {
                return ret;
            }
            BN_CLRNEG(q->flag);
            q->flag |= tmpFlag;
        }
        if (r != NULL) {
            ret = BN_Zeroize(r);
        }
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t BN_Div(BN_BigNum *q, BN_BigNum *r, const BN_BigNum *x,
    const BN_BigNum *y, BN_Optimizer *opt)
{
    int32_t ret = DivInputCheck(q, r, x, y, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
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
    BN_BigNum *qTmp =
        OptimizerGetBn(opt, x->size + 2);  // BinDiv:x->room >= xSize + 2
    BN_BigNum *rTmp =
        OptimizerGetBn(opt, x->size + 2);  // BinDiv:x->room >= xSize + 2
    if (qTmp == NULL || rTmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_OPTIMIZER_GET_FAIL);
        ret = CRYPT_BN_OPTIMIZER_GET_FAIL;
        goto ERR;
    }

    ret = BN_Copy(rTmp, x);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    qTmp->size = qTmp->room;
    rTmp->size = BinDiv(qTmp->data, &(qTmp->size), rTmp->data, rTmp->size, y->data, y->size);
    if (rTmp->size == 0) {
        BN_CLRNEG(rTmp->flag);
    }
    if (qTmp->size != 0 && BN_ISNEG(x->flag ^ y->flag)) {
        BN_SETNEG(qTmp->flag);
    }

    if (q != NULL) {
        ret = BN_Copy(q, qTmp);
        if (ret != CRYPT_SUCCESS) {
            goto ERR;
        }
    }
    if (r != NULL) {
        ret = BN_Copy(r, rTmp);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
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
    if (BnExtend(r, m->size) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = OptimizerStart(opt);
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
    if (!BN_ISNEG(t->flag)) {
        ret = BN_Copy(r, t);
        OptimizerEnd(opt);
        return ret;
    }
    // When t is a negative number, the modulo operation result must be positive.
    if (BN_ISNEG(m->flag)) { // m is a negative number
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

// Check the input parameters of basic operations such as modulo addition, subtraction, and multiplication.
int32_t ModBaseInputCheck(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, const BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || b == NULL || mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BnExtend(r, mod->size) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // mod cannot be 0
    if (BN_IsZero(mod)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }

    return CRYPT_SUCCESS;
}

int32_t BN_ModSub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, BN_Optimizer *opt)
{
    int32_t ret;
    ret = ModBaseInputCheck(r, a, b, mod, opt);
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
    ret = BN_Sub(t, a, b);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t BN_ModAdd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, BN_Optimizer *opt)
{
    int32_t ret;
    ret = ModBaseInputCheck(r, a, b, mod, opt);
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
    ret = BN_Add(t, a, b);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t BN_ModMul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b,
    const BN_BigNum *mod, BN_Optimizer *opt)
{
    int32_t ret;

    ret = ModBaseInputCheck(r, a, b, mod, opt);
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
    ret = BN_Mul(t, a, b, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Mod(r, t, mod, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    OptimizerEnd(opt); // release occupation from the optimizer
    return ret;
}

int32_t BN_ModSqr(
    BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *mod, BN_Optimizer *opt)
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

    if (BnExtend(r, mod->size) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = OptimizerStart(opt); // using the Optimizer
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
    ret = BN_Sqr(t, a, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
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
    if (BN_ISNEG(e->flag)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_EXP_NO_NEGATIVE);
        return CRYPT_BN_ERR_EXP_NO_NEGATIVE;
    }
    if (BnExtend(r, m->size) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

int32_t ModExpCore(BN_BigNum *x, BN_BigNum *y, const BN_BigNum *e,
    const BN_BigNum *m, BN_Optimizer *opt)
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

static int32_t SwitchMont(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e,
    const BN_BigNum *m, BN_Optimizer *opt)
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

int32_t BN_ModExp(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *e,
    const BN_BigNum *m, BN_Optimizer *opt)
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
    if (BnExtend(r, BITS_TO_BN_UNIT(BN_Bits(a) - n)) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint32_t tmpFlag = BN_GETNEG(a->flag);
    uint32_t size = BinRshift(r->data, a->data, a->size, n);
    if (size < r->size) {
        if (memset_s(r->data + size, (r->room - size) * sizeof(BN_UINT), 0,
            (r->size - size) * sizeof(BN_UINT)) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
    }
    BN_CLRNEG(r->flag);
    r->flag |= tmpFlag;
    r->size = size;
    return CRYPT_SUCCESS;
}

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
    uint32_t tmpFlag = (mask != 0) ? (a->flag) : (b->flag);
    for (uint32_t i = 0; i < len; i++) {
        dst[i] = (srcA[i] & rmask) ^ (srcB[i] & mask);
    }
    BN_CLRNEG(r->flag);
    r->flag |= BN_GETNEG(tmpFlag);
    r->size = (a->size & (uint32_t)rmask) ^ (b->size & (uint32_t)mask);
    return CRYPT_SUCCESS;
}
#endif /* HITLS_CRYPTO_BN */
