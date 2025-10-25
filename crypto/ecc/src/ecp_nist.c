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

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "ecc_local.h"

#if defined(HITLS_CRYPTO_CURVE_NISTP224) || defined(HITLS_CRYPTO_CURVE_NISTP256) || \
    defined(HITLS_CRYPTO_CURVE_NISTP384) || defined(HITLS_CRYPTO_CURVE_NISTP521) || defined(HITLS_CRYPTO_CURVE_SM2)

static int32_t CreatTmpBn(BN_BigNum **t1, BN_BigNum **t2, BN_BigNum **t3, BN_BigNum **t4, uint32_t bits)
{
    *t1 = BN_Create(bits);
    *t2 = BN_Create(bits);
    *t3 = BN_Create(bits);
    *t4 = BN_Create(bits);
    if (*t1 == NULL || *t2 == NULL || *t3 == NULL || *t4 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static void DestroyTmpBn(BN_BigNum *t1, BN_BigNum *t2, BN_BigNum *t3, BN_BigNum *t4)
{
    BN_Destroy(t1);
    BN_Destroy(t2);
    BN_Destroy(t3);
    BN_Destroy(t4);
}

// Jacobian coordinate double the point
int32_t ECP_NistPointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    uint32_t bits = BN_Bits(para->p);

    BN_Optimizer *opt = BN_OptimizerCreate();
    BN_BigNum *t1 = BN_Create(bits);
    BN_BigNum *t2 = BN_Create(bits);
    BN_BigNum *t3 = BN_Create(bits);
    BN_BigNum *halfP = ECP_HalfPGet(para->p);
    if (t1 == NULL || t2 == NULL || t3 == NULL || halfP == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &a->z, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(t2, &a->x, t1, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t1, &a->x, t1, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, t1, para->p, opt), ret);

    GOTO_ERR_IF(BN_ModAddQuick(t3, t2, t2, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t2, t3, t2, para->p, opt), ret); // t2 = 3*t2
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &a->y, &a->y, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->y, &a->z, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->y, &r->y, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, &r->y, &a->x, para->p, opt), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->y, &r->y, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, halfP, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t1, t3, t3, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, opt), ret);

    GOTO_ERR_IF(BN_ModSubQuick(t1, t3, &r->x, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t2, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t1, &r->y, para->p, opt), ret);
ERR:
    BN_Destroy(t1);
    BN_Destroy(t2);
    BN_Destroy(t3);
    BN_Destroy(halfP);
    BN_OptimizerDestroy(opt);
    return ret;
}

// Jacobian coordinate multi-double the point: r = (2^m) * pt
int32_t ECP_NistPointMultDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t tm = m;
    int32_t ret;
    uint32_t bits = BN_Bits(para->p);
    BN_BigNum *ta = NULL, *tb = NULL, *tc = NULL, *tw = NULL;
    BN_BigNum *halfP = ECP_HalfPGet(para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    GOTO_ERR_IF_EX(CreatTmpBn(&ta, &tb, &tc, &tw, bits), ret);
    if (halfP == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF(BN_Copy(&r->x, &a->x), ret);
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &a->y, &a->y, para->p, opt), ret);
    GOTO_ERR_IF(BN_Copy(&r->z, &a->z), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(tw, &a->z, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(tw, tw, para->p, opt), ret);

    while (tm > 0) {
        // 3.1
        // ta = 3*(x^2 - tw)
        GOTO_ERR_IF(para->method->bnModNistEccSqr(ta, &r->x, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(tc, ta, tw, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(ta, tc, tc, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(ta, ta, tc, para->p, opt), ret);
        // tb = x*(y^2)
        GOTO_ERR_IF(para->method->bnModNistEccSqr(tc, &r->y, para->p, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccMul(tb, tc, &r->x, para->p, opt), ret);

        // 3.2
        // x = ta^2 - 2*tb
        GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, ta, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, tb, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, tb, para->p, opt), ret);
        // z = zy
        GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->z, &r->y, para->p, opt), ret);

        // 3.3
        // tc = y^4
        GOTO_ERR_IF(para->method->bnModNistEccSqr(tc, &r->y, para->p, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccSqr(tc, tc, para->p, opt), ret);
        // m = m - 1, if bit > 0, tw = tw * (y^4)
        tm--;
        if (tm > 0) {
            GOTO_ERR_IF(para->method->bnModNistEccMul(tw, tw, tc, para->p, opt), ret);
        }
        // 3.4
        // y = 2*ta*(tb - x) - (y^4)
        GOTO_ERR_IF(BN_ModSubQuick(&r->y, tb, &r->x, para->p, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, ta, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(&r->y, &r->y, &r->y, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->y, &r->y, tc, para->p, opt), ret);
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, halfP, para->p, opt), ret);
ERR:
    DestroyTmpBn(ta, tb, tc, tw);
    BN_Destroy(halfP);
    BN_OptimizerDestroy(opt);
    return ret;
}

// Point addition calculation (Jacobian point a plus affine point b)
// Algorithm Reference ECP_NistPointAddAffineMont.
int32_t ECP_NistPointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a,
    const ECC_Point *b)
{
    if (para == NULL || r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(&a->z)) {
        // If point a is an infinity point, r = b
        return ECC_CopyPoint(r, b);
    }
    int32_t ret;
    uint32_t bits = BN_Bits(para->p);

    BN_Optimizer *op = BN_OptimizerCreate();
    BN_BigNum *t1 = NULL, *t2 = NULL, *t3 = NULL, *t4 = NULL;
    GOTO_ERR_IF_EX(CreatTmpBn(&t1, &t2, &t3, &t4, bits), ret);
    if (op == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &a->z, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t1, &a->z, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, &b->x, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, &b->y, para->p, op), ret);
    GOTO_ERR_IF(BN_ModSubQuick(t1, t1, &a->x, para->p, op), ret);
    GOTO_ERR_IF(BN_ModSubQuick(t2, t2, &a->y, para->p, op), ret);

    if (BN_IsZero(t1)) {
        if (BN_IsZero(t2)) {
            // If two points are equal, use double the point for calculation.
            GOTO_ERR_IF(ECP_NistPointDouble(para, r, b), ret);
            goto ERR;
        } else {
            // Obtain the infinity point.
            GOTO_ERR_IF(BN_SetLimb(&r->z, 0), ret);
            goto ERR;
        }
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &a->z, t1, para->p, op), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, t1, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t1, t3, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, &a->x, para->p, op), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t1, t3, t3, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->p, op), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, op), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t4, para->p, op), ret);
    GOTO_ERR_IF(BN_ModSubQuick(t3, t3, &r->x, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, t2, para->p, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t4, &a->y, para->p, op), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t3, t4, para->p, op), ret);
ERR:
    DestroyTmpBn(t1, t2, t3, t4);
    BN_OptimizerDestroy(op);
    return ret;
}

// Point addition calculation (Jacobian point a plus Jacobian point b)
// Algorithm Reference ECP_NistPointAddMont.
int32_t ECP_NistPointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a,
    const ECC_Point *b)
{
    if (para == NULL || r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(&a->z)) {
        // If point a is an infinity point, r = b
        return ECC_CopyPoint(r, b);
    }
    if (BN_IsZero(&b->z)) {
        // If point b is an infinity point, r = a
        return ECC_CopyPoint(r, a);
    }
    int32_t ret;
    BN_Optimizer *op = BN_OptimizerCreate();
    if (op == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(op);
    BN_BigNum *t1 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t3 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t4 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t5 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t6 = OptimizerGetBn(op, a->x.room);
    if (t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL || t5 == NULL || t6 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &b->z, para->p, op), ret); // Z2^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t1, &b->z, para->p, op), ret); // Z2^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t5, t1, &a->x, para->p, op), ret); // U1 = X1*Z2^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t6, t2, &a->y, para->p, op), ret); // S1 = Y1*Z2^3
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, &a->z, para->p, op), ret); // T3 = Z1^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &a->z, &b->y, para->p, op), ret); // r->y = Y2*Z1
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &a->z, &b->z, para->p, op), ret); // r->z = Z2*Z1
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, t3, &r->y, para->p, op), ret); // S2 = Y2 * Z1^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->x, t3, &b->x, para->p, op), ret); // U2 = Z1^2 * X2

    GOTO_ERR_IF(BN_ModSubQuick(t1, &r->x, t5, para->p, op), ret); // H = U2 - U1
    GOTO_ERR_IF(BN_ModSubQuick(t2, &r->y, t6, para->p, op), ret); // r = S2 - S1
    if (BN_IsZero(t1) && BN_IsZero(t2)) {
        GOTO_ERR_IF(para->method->pointDouble(para, r, b), ret);
        goto ERR;
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, t1, &r->z, para->p, op), ret); // r->z = H * Z2*Z1
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, t1, para->p, op), ret); // t3 = H^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t3, para->p, op), ret); // t1 = H^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, t5, para->p, op), ret); // t3 = H^2 * U1
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->p, op), ret); // r->x = r ^ 2

    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t3, para->p, op), ret); // r ^ 2 - H^2*U1
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t3, para->p, op), ret); // r ^ 2 - 2*H^2 * U1
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, op), ret); // r ^ 2 - 2*H^2*U1 - H^3
    GOTO_ERR_IF(BN_ModSubQuick(t3, t3, &r->x, para->p, op), ret); // H^2 * U1 - X3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t2, t3, para->p, op), ret); // r * (H^2 * U1 - X3)
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t6, para->p, op), ret); // t1 = H^3 * S1
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t3, t1, para->p, op), ret); // r * (H^2 * U1 - X3) - H^3 * S1
ERR:
    BN_OptimizerDestroy(op);
    return ret;
}

#endif

int32_t ECP_ModOrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    int32_t ret;
    BN_Optimizer *opt = NULL;
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = BN_ModInv(r, a, para->n, opt);
    BN_OptimizerDestroy(opt);
    return ret;
}
#endif /* HITLS_CRYPTO_ECC */
