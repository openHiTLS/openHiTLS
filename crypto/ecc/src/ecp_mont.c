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

#if defined(HITLS_CRYPTO_ECC) && defined(HITLS_CRYPTO_CURVE_MONT)

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "ecc_local.h"

#ifdef HITLS_CRYPTO_CURVE_MONT_NIST

// Jacobian coordinate double the point
int32_t ECP_NistPointDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (a == NULL || r == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(opt);
    int32_t ret;
    BN_BigNum *halfP = ECP_HalfPGet(para->p);
    BN_BigNum *t1 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t3 = OptimizerGetBn(opt, a->x.room);
    if (t1 == NULL || t2 == NULL || t3 == NULL || halfP == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF(para->method->bnMontEnc(halfP, para->montP, opt, false), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &a->z, para->montP, opt), ret);

    GOTO_ERR_IF(BN_ModSubQuick(t2, &a->x, t1, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t1, &a->x, t1, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, t1, para->montP, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t3, t2, t2, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t2, t3, t2, para->p, opt), ret); // t2 = 3*t2
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &a->y, &a->y, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->y, &a->z, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->y, &r->y, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, &r->y, &a->x, para->montP, opt), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->y, &r->y, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, halfP, para->montP, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t1, t3, t3, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, opt), ret);

    GOTO_ERR_IF(BN_ModSubQuick(t1, t3, &r->x, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t2, para->montP, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t1, &r->y, para->p, opt), ret);
ERR:
    BN_OptimizerDestroy(opt);
    BN_Destroy(halfP);
    return ret;
}

// Jacobian coordinate multi-double the point: r = (2^m) * pt
int32_t ECP_NistPointMultDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m)
{
    if (a == NULL || r == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t tm = m;
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    (void)OptimizerStart(opt);
    BN_BigNum *ta = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *tb = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *tc = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *tw = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *halfP = ECP_HalfPGet(para->p);
    if (ta == NULL || tb == NULL || tc == NULL || tw == NULL || halfP == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF(BN_Copy(&r->x, &a->x), ret);
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &a->y, &a->y, para->p, opt), ret);
    GOTO_ERR_IF(BN_Copy(&r->z, &a->z), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(tw, &a->z, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(tw, tw, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnMontEnc(halfP, para->montP, opt, false), ret);

    while (tm > 0) {
        // 3.1
        // ta = 3*(x^2 - tw)
        GOTO_ERR_IF(para->method->bnModNistEccSqr(ta, &r->x, para->montP, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(tc, ta, tw, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(ta, tc, tc, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(ta, ta, tc, para->p, opt), ret);
        // tb = x*(y^2)
        GOTO_ERR_IF(para->method->bnModNistEccSqr(tc, &r->y, para->montP, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccMul(tb, tc, &r->x, para->montP, opt), ret);

        // 3.2
        // x = ta^2 - 2*tb
        GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, ta, para->montP, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, tb, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, tb, para->p, opt), ret);
        // z = zy
        GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->z, &r->y, para->montP, opt), ret);

        // 3.3
        // tc = y^4
        GOTO_ERR_IF(para->method->bnModNistEccSqr(tc, &r->y, para->montP, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccSqr(tc, tc, para->montP, opt), ret);
        // m = m - 1, if bit > 0, tw = tw * (y^4)
        tm--;
        if (tm > 0) {
            GOTO_ERR_IF(para->method->bnModNistEccMul(tw, tw, tc, para->montP, opt), ret);
        }
        // 3.4
        // y = 2*ta*(tb - x) - (y^4)
        GOTO_ERR_IF(BN_ModSubQuick(&r->y, tb, &r->x, para->p, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, ta, para->montP, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(&r->y, &r->y, &r->y, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->y, &r->y, tc, para->p, opt), ret);
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, halfP, para->montP, opt), ret);
ERR:
    BN_Destroy(halfP);
    BN_OptimizerDestroy(opt); // no need to end opt.
    return ret;
}

// Point addition calculation (Jacobian point a plus Jacobian point b)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo
int32_t ECP_NistPointAddMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    if (para == NULL || r == NULL || a == NULL || b == NULL) {
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
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(opt);
    BN_BigNum *t1 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t3 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t4 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t5 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t6 = OptimizerGetBn(opt, a->x.room);
    if (t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL || t5 == NULL || t6 == NULL) {
        BN_OptimizerDestroy(opt); // no need to end opt.
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret;
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &b->z, para->montP, opt), ret); // Z2^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t1, &b->z, para->montP, opt), ret); // Z2^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t5, t1, &a->x, para->montP, opt), ret); // U1 = X1*Z2^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t6, t2, &a->y, para->montP, opt), ret); // S1 = Y1*Z2^3
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, &a->z, para->montP, opt), ret); // T3 = Z1^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &a->z, &b->y, para->montP, opt), ret); // r->y = Y2*Z1
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &a->z, &b->z, para->montP, opt), ret); // r->z = Z2*Z1
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, t3, &r->y, para->montP, opt), ret); // S2 = Y2 * Z1^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->x, t3, &b->x, para->montP, opt), ret); // U2 = Z1^2 * X2

    GOTO_ERR_IF(BN_ModSubQuick(t1, &r->x, t5, para->p, opt), ret); // H = U2 - U1
    GOTO_ERR_IF(BN_ModSubQuick(t2, &r->y, t6, para->p, opt), ret); // r = S2 - S1
    if (BN_IsZero(t1) && BN_IsZero(t2)) {
        GOTO_ERR_IF(para->method->pointDouble(para, r, b), ret);
        goto ERR;
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, t1, &r->z, para->montP, opt), ret); // r->z = H * Z2*Z1
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, t1, para->montP, opt), ret); // t3 = H^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t3, para->montP, opt), ret); // t1 = H^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, t5, para->montP, opt), ret); // t3 = H^2 * U1
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->montP, opt), ret); // r->x = r ^ 2

    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t3, para->p, opt), ret); // r ^ 2 - H^2*U1
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t3, para->p, opt), ret); // r ^ 2 - 2*H^2 * U1
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, opt), ret); // r ^ 2 - 2*H^2*U1 - H^3
    GOTO_ERR_IF(BN_ModSubQuick(t3, t3, &r->x, para->p, opt), ret); // H^2 * U1 - X3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t2, t3, para->montP, opt), ret); // r * (H^2 * U1 - X3)
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t6, para->montP, opt), ret); // t1 = H^3 * S1
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t3, t1, para->p, opt), ret); // r * (H^2 * U1 - X3) - H^3 * S1
ERR:
    BN_OptimizerDestroy(opt); // no need to end opt.
    return ret;
}

// cal r = a + b (b->z = 1)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2004-hmv
int32_t ECP_NistPointAddAffineMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    int32_t ret;
    if (a == NULL || b == NULL || r == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(&a->z)) { // if point a is an infinity point, r = b,
        return ECC_CopyPoint(r, b);
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(opt);
    BN_BigNum *t1 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t3 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t4 = OptimizerGetBn(opt, a->x.room);
    if (t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &a->z, para->montP, opt), ret); // T1 = Z1^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t1, &a->z, para->montP, opt), ret); // T2 = Z1^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, &b->x, para->montP, opt), ret); // T1 = X2*T1
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, &b->y, para->montP, opt), ret); // T2 = Y2*T2
    GOTO_ERR_IF(BN_ModSubQuick(t1, t1, &a->x, para->p, opt), ret); // T1 = T1-X1
    GOTO_ERR_IF(BN_ModSubQuick(t2, t2, &a->y, para->p, opt), ret); // T2 = T2-Y1

    if (BN_IsZero(t1)) {
        if (BN_IsZero(t2)) {
            // If two points are equal, use double for calculation.
            GOTO_ERR_IF(para->method->pointDouble(para, r, b), ret);
        } else {
            // Obtain the infinite point.
            GOTO_ERR_IF(BN_SetLimb(&r->z, 0), ret);
        }
        goto ERR;
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &a->z, t1, para->montP, opt), ret); // Z3 = Z1 * T1

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, t1, para->montP, opt), ret); // T3 = T1 ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t1, t3, para->montP, opt), ret); // T4 = T3 * T1
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, &a->x, para->montP, opt), ret); // T3 = T3 * X1
    GOTO_ERR_IF(BN_ModAddQuick(t1, t3, t3, para->p, opt), ret); // T1 = 2 * T3
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->montP, opt), ret); // X3 = T2 ^ 2
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, opt), ret); // X3 = X3 - T1
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t4, para->p, opt), ret); // X3 = X3 - T4
    GOTO_ERR_IF(BN_ModSubQuick(t3, t3, &r->x, para->p, opt), ret); // T3 = T3 - X3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, t2, para->montP, opt), ret); // T3 = T3 * T2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t4, &a->y, para->montP, opt), ret); // T4 = T4 * Y1
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t3, t4, para->p, opt), ret); // Y3 = T3 - T4
ERR:
    BN_OptimizerDestroy(opt); // no need to end opt.
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_CURVE_MONT_PRIME
/*
 prime curves point multi-double r = (2^m)*a
 Calculation procedure:
    1. If the point is an infinity point, return the infinity point.
    2. Y = 2*Y, W = Z^4
    3. If m > 0, repeat the following steps:
            A = 3*X^2 + a*W
            B = X*Y^2
            X = A^2 - 2*B
            Z = Z*Y
            m = m - 1
            if m > 0 then W = W*Y^4
            Y = 2*A*(B-X)-Y^4
    4. Return (X, Y/2, Z)
*/
int32_t ECP_PrimePointDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        return CRYPT_NULL_INPUT;
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    (void)OptimizerStart(opt);
    BN_BigNum *t1 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t3 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *halfP = ECP_HalfPGet(para->p);
    if (t1 == NULL || t2 == NULL || t3 == NULL || halfP == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    GOTO_ERR_IF(para->method->bnMontEnc(halfP, para->montP, opt, false), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &a->z, para->montP, opt), ret); // Z1^2
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t2, t1, para->montP, opt), ret); // Z1^4
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t2, para->a, para->montP, opt), ret); // a*Z1^4
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t2, &a->x, para->montP, opt), ret); // X1^2
    GOTO_ERR_IF(BN_ModAddQuick(t3, t2, t2, para->p, opt), ret); // 2*X1^2
    GOTO_ERR_IF(BN_ModAddQuick(t2, t3, t2, para->p, opt), ret); // 3*X1^2
    GOTO_ERR_IF(BN_ModAddQuick(t2, t1, t2, para->p, opt), ret); // t2 = 3*X1^2 + a*Z1^4
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &a->y, &a->y, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->y, &a->z, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->y, &r->y, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, &r->y, &a->x, para->montP, opt), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->y, &r->y, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, halfP, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->montP, opt), ret);
    GOTO_ERR_IF(BN_ModAddQuick(t1, t3, t3, para->p, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, opt), ret);

    GOTO_ERR_IF(BN_ModSubQuick(t1, t3, &r->x, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, t2, para->montP, opt), ret);
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t1, &r->y, para->p, opt), ret);
ERR:
    BN_Destroy(halfP);
    BN_OptimizerDestroy(opt); // no need to end opt.
    return ret;
}

// Point addition calculation (Jacobian point a plus Jacobian point b)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
int32_t ECP_PrimePointAddMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a,
    const ECC_Point *b)
{
    bool flag = (para == NULL) || (r == NULL) || (a == NULL) || (b == NULL);
    if (flag) {
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(&a->z)) {
        return ECC_CopyPoint(r, b);
    }
    if (BN_IsZero(&b->z)) {
        return ECC_CopyPoint(r, a);
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(opt);
    BN_BigNum *t0 = OptimizerGetBn(opt, para->p->size);
    BN_BigNum *t1 = OptimizerGetBn(opt, para->p->size);
    BN_BigNum *t2 = OptimizerGetBn(opt, para->p->size);
    BN_BigNum *t3 = OptimizerGetBn(opt, para->p->size);
    BN_BigNum *t4 = OptimizerGetBn(opt, para->p->size);
    BN_BigNum *t5 = OptimizerGetBn(opt, para->p->size);
    flag = (t0 == NULL) || (t1 == NULL) || (t2 == NULL) || (t3 == NULL) || (t4 == NULL) || (t5 == NULL);
    if (flag) {
        BN_OptimizerDestroy(opt); // no need to end opt.
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret;
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t0, &a->z, para->montP, opt), ret); // z1z1 = z1^2
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t5, &b->z, para->montP, opt), ret); // z2z2 = z2^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, &a->x, t5, para->montP, opt), ret); // u1 = x1*z2z2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, &b->x, t0, para->montP, opt), ret); // u2 = x2*z1z1

    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, &b->z, t5, para->montP, opt), ret); // z2 * z2z2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, &a->y, t2, para->montP, opt), ret); // s1 = y1 * z2 * z2z2

    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, &a->z, t0, para->montP, opt), ret); // z1 * z1z1
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, &b->y, t4, para->montP, opt), ret); // s2 = y2 * z1 * z1z1

    GOTO_ERR_IF(BN_ModAddQuick(t0, t0, t5, para->p, opt), ret); // z1z1 + z2z2
    GOTO_ERR_IF(BN_ModSubQuick(t3, t3, t1, para->p, opt), ret); // h = u2 - u1
    GOTO_ERR_IF(BN_ModSubQuick(t4, t4, t2, para->p, opt), ret); // s2 - s1
    if (BN_IsZero(t3) && BN_IsZero(t4)) {
        GOTO_ERR_IF(para->method->pointDouble(para, r, b), ret);
        goto ERR;
    }
    GOTO_ERR_IF(BN_ModAddQuick(t5, t3, t3, para->p, opt), ret); // 2h
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, t4, t4, para->p, opt), ret); // r = 2(s2 - s1)
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t5, t5, para->montP, opt), ret); // i = (2h)^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t3, t5, para->montP, opt), ret); // j = h*i

    GOTO_ERR_IF(para->method->bnModNistEccMul(t5, t1, t5, para->montP, opt), ret); // v = u1 * i
    GOTO_ERR_IF(BN_ModAddQuick(t1, t5, t5, para->p, opt), ret); // 2 * v
    GOTO_ERR_IF(BN_ModAddQuick(t1, t1, t4, para->p, opt), ret); // 2 * v + j
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, &r->y, para->montP, opt), ret); // rr ^ 2
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, opt), ret); // r->x = rr ^ 2 - j - z * v

    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, t4, para->montP, opt), ret); // s1 * j
    GOTO_ERR_IF(BN_ModAddQuick(t2, t2, t2, para->p, opt), ret); // 2 * s1 * j
    GOTO_ERR_IF(BN_ModSubQuick(t5, t5, &r->x, para->p, opt), ret); // v = v - x3
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, t5, para->montP, opt), ret); // r * (v - x3)
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, &r->y, t2, para->p, opt), ret); // r * (v - x3) - 2 * s1 * j

    GOTO_ERR_IF(BN_ModAddQuick(&r->z, &a->z, &b->z, para->p, opt), ret); // z1 + z2
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->z, &r->z, para->montP, opt), ret); // (z1 + z2) ^ 2
    GOTO_ERR_IF(BN_ModSubQuick(&r->z, &r->z, t0, para->p, opt), ret); // (z1 + z2) ^ 2 - z1z1 - z2z2
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->z, t3, para->montP, opt), ret); // r->z * h

ERR:
    BN_OptimizerDestroy(opt); // no need to end opt.
    return ret;
}

// Jacobian coordinate multi-double the point: r = (2^m) * pt
int32_t ECP_PrimePointMultDoubleMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m)
{
    if (para == NULL || r == NULL || a == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t tm = m;
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(opt);
    BN_BigNum *t1 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *ta = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *tb = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *tw = OptimizerGetBn(opt, a->x.room);
    BN_BigNum *halfP = ECP_HalfPGet(para->p);
    if (t1 == NULL || t2 == NULL || ta == NULL || tb == NULL || tw == NULL || halfP == NULL) {
        goto ERR;
    }

    GOTO_ERR_IF(BN_Copy(&r->x, &a->x), ret);
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &a->y, &a->y, para->p, opt), ret);
    GOTO_ERR_IF(BN_Copy(&r->z, &a->z), ret);
    GOTO_ERR_IF(para->method->bnMontEnc(halfP, para->montP, opt, false), ret);

    GOTO_ERR_IF(para->method->bnModNistEccSqr(tw, &a->z, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(tw, tw, para->montP, opt), ret); // Z^4

    while (tm > 0) {
        // A = 3*X^2 + a*W
        GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &r->x, para->montP, opt), ret); // X^2
        GOTO_ERR_IF(BN_ModAddQuick(ta, t1, t1, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(ta, ta, t1, para->p, opt), ret); // 3*X^2
        GOTO_ERR_IF(para->method->bnModNistEccMul(t2, para->a, tw, para->montP, opt), ret); // a*W
        GOTO_ERR_IF(BN_ModAddQuick(ta, ta, t2, para->p, opt), ret); // A = 3*X^2 + a*W

        GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &r->y, para->montP, opt), ret); // t1 = Y^2
        GOTO_ERR_IF(para->method->bnModNistEccMul(tb, t1, &r->x, para->montP, opt), ret); // B = X*Y^2

        GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, t1, para->montP, opt), ret); // t1 = Y^4

        GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, ta, para->montP, opt), ret); // A^2
        GOTO_ERR_IF(BN_ModAddQuick(t2, tb, tb, para->p, opt), ret); // 2*B
        GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t2, para->p, opt), ret); // X = A^2 - 2*B

        GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->z, &r->y, para->montP, opt), ret);

        // m = m - 1
        tm--;
        if (tm > 0) {
            GOTO_ERR_IF(para->method->bnModNistEccMul(tw, tw, t1, para->montP, opt), ret);
        }
        GOTO_ERR_IF(BN_ModSubQuick(&r->y, tb, &r->x, para->p, opt), ret);
        GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, ta, para->montP, opt), ret);
        GOTO_ERR_IF(BN_ModAddQuick(&r->y, &r->y, &r->y, para->p, opt), ret);
        GOTO_ERR_IF(BN_ModSubQuick(&r->y, &r->y, t1, para->p, opt), ret);
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &r->y, halfP, para->montP, opt), ret);
ERR:
    BN_Destroy(halfP);
    BN_OptimizerDestroy(opt);
    return ret;
}

/*
 prime curve point addition r = a + b, , depending on the method->pointDouble point operation.
 Calculation formula:
    X3 = (Y2*Z1^3-Y1)^2 - (X2*Z1^2-X1)^2 * (X1+X2*Z1^2)
    Y3 = (Y2*Z1^3-Y1) * (X1*(X2*Z1^2-X1)^2-X3) - Y1 * (X2*Z1^2-X1)^3
    Z3 = (X2*Z1^2-X1) * Z1
*/
int32_t ECP_PrimePointAddAffineMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    if (para == NULL || r == NULL || a == NULL || b == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(&a->z)) { // if point a is an infinity point, r = b,
        return ECC_CopyPoint(r, b);
    }
    BN_Optimizer *op = BN_OptimizerCreate();
    if (op == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)OptimizerStart(op);
    BN_BigNum *t1 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t2 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t3 = OptimizerGetBn(op, a->x.room);
    BN_BigNum *t4 = OptimizerGetBn(op, a->x.room);
    if (t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL) {
        BN_OptimizerDestroy(op);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t1, &a->z, para->montP, op), ret); // Z1^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t1, &a->z, para->montP, op), ret); // Z1^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, &b->x, para->montP, op), ret); // X2*Z1^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, &b->y, para->montP, op), ret); // Y2*Z1^3
    GOTO_ERR_IF(BN_ModSubQuick(t1, t1, &a->x, para->p, op), ret); // X2*Z1^2 - X1
    GOTO_ERR_IF(BN_ModSubQuick(t2, t2, &a->y, para->p, op), ret); // Y2*Z1^3 - Y1

    if (BN_IsZero(t1)) {
        if (BN_IsZero(t2)) {
            // If two points are equal, use double for calculation.
            GOTO_ERR_IF(para->method->pointDouble(para, r, b), ret);
        } else {
            // Obtain the infinite point.
            GOTO_ERR_IF(BN_SetLimb(&r->z, 0), ret);
        }
        goto ERR;
    }
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &a->z, t1, para->montP, op), ret); // Z3 = (X2*Z1^2 - X1)*Z1

    GOTO_ERR_IF(para->method->bnModNistEccSqr(t3, t1, para->montP, op), ret); // (X2*Z1^2 - X1)^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t1, t3, para->montP, op), ret); // (X2*Z1^2 - X1)^3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, &a->x, para->montP, op), ret); // X1*(X2*Z1^2 - X1)^2
    GOTO_ERR_IF(BN_ModAddQuick(t1, t3, t3, para->p, op), ret); // 2*X1*(X2*Z1^2 - X1)^2
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, t2, para->montP, op), ret); // (Y2*Z1^3 - Y1)^2
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t1, para->p, op), ret); // (Y2*Z1^3-Y1)^2 - 2*X1*(X2*Z1^2-X1)^2
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t4, para->p, op), ret); // X3
    GOTO_ERR_IF(BN_ModSubQuick(t3, t3, &r->x, para->p, op), ret); // X1*(X2*Z1^2-X1)^2 - X3
    // (Y2*Z1^3-Y1)*(X1*(X2*Z1^2-X1)^2-X3)
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, t3, t2, para->montP, op), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, t4, &a->y, para->montP, op), ret); // Y1*(X2*Z1^2 - X1)^3
    GOTO_ERR_IF(BN_ModSubQuick(&r->y, t3, t4, para->p, op), ret); // Y3
ERR:
    BN_OptimizerDestroy(op);
    return ret;
}
#endif

int32_t ECP_Point2AffineMont(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    if (pt == NULL || r == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != r->id || para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (BN_IsOne(&pt->z)) {
        return ECC_CopyPoint(r, pt);
    }
    uint32_t bits = BN_Bits(para->p);
    BN_BigNum *inv = BN_Create(bits);
    BN_BigNum *zz = BN_Create(bits);
    BN_Optimizer *opt = BN_OptimizerCreate();
    ECC_Point *base = ECC_DupPoint(pt);
    int32_t ret;
    if (inv == NULL || zz == NULL || opt == NULL || base == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    GOTO_ERR_IF(para->method->modInv(inv, &base->z, para->p, opt), ret);
    GOTO_ERR_IF(para->method->bnMontEnc(&base->x, para->montP, opt, false), ret);
    GOTO_ERR_IF(para->method->bnMontEnc(&base->y, para->montP, opt, false), ret);
    GOTO_ERR_IF(para->method->bnMontEnc(inv, para->montP, opt, false), ret);
    GOTO_ERR_IF(para->method->bnModNistEccSqr(zz, inv, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->x, &base->x, zz, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(zz, zz, inv, para->montP, opt), ret);
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->y, &base->y, zz, para->montP, opt), ret);
    GOTO_ERR_IF(BN_SetLimb(&r->z, 1), ret);
    para->method->bnMontDec(&r->x, para->montP);
    para->method->bnMontDec(&r->y, para->montP);
ERR:
    BN_Destroy(zz);
    BN_Destroy(inv);
    ECC_FreePoint(base);
    BN_OptimizerDestroy(opt);
    return ret;
}

/*
 * XZ coordinates for short Weierstrass curves
 * https://hyperelliptic.org/EFD/g1p/auto-shortw-xz.html#ladder-mladd-2002-bj-3
 * MontLadderDoubleAndAdd return:
 *    r2 = 2 * r2
 *    r3 = r2 + r3
*/
static int32_t MontLadderDoubleAndAdd(ECC_Para *para, ECC_Point *r2, ECC_Point *r3, ECC_Point *p, BN_Optimizer *opt)
{
    int32_t ret;
    (void)OptimizerStart(opt);
    BN_BigNum *t0 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t1 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t3 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t4 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t5 = OptimizerGetBn(opt, p->x.room);
    if (t0 == NULL || t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL || t5 == NULL) {
        OptimizerEnd(opt);
        return CRYPT_MEM_ALLOC_FAIL; // 不需要释放其他大数，统一交给大数优化器管理
    }
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r2->y, &r2->x, para->montP, opt), ret); // x2 ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r3->y, &r2->z, para->montP, opt), ret); // z2 ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t0, &r2->x, &r2->z, para->montP, opt), ret); // X2 * Z2
    GOTO_ERR_IF(BN_ModAddQuick(t0, t0, t0, para->p, opt), ret); // 2 * X2 * Z2
    GOTO_ERR_IF(BN_ModAddQuick(t0, t0, t0, para->p, opt), ret); // 4 * X2 * Z2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, para->a, &r3->y, para->montP, opt), ret); // aZZ = a * ZZ

    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, &r2->x, &r3->x, para->montP, opt), ret); // X2 * X3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t3, &r2->z, &r3->z, para->montP, opt), ret); // Z2 * Z3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t4, &r2->x, &r3->z, para->montP, opt), ret); // X2 * Z3
    GOTO_ERR_IF(para->method->bnModNistEccMul(t5, &r2->z, &r3->x, para->montP, opt), ret); // Z2 * X3

    GOTO_ERR_IF(BN_ModSubQuick(&r2->x, &r2->y, t1, para->p, opt), ret); // XX - aZZ
    GOTO_ERR_IF(BN_ModAddQuick(&r2->z, &r2->y, t1, para->p, opt), ret); // XX + aZZ
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r2->z, t0, &r2->z, para->montP, opt), ret); // E * (XX + aZZ)

    GOTO_ERR_IF(para->method->bnModNistEccMul(t0, t0, &r3->y, para->montP, opt), ret); // E * ZZ
    GOTO_ERR_IF(para->method->bnModNistEccMul(t0, t0, para->b, para->montP, opt), ret); // b *  E * ZZ
    GOTO_ERR_IF(BN_ModAddQuick(t0, t0, t0, para->p, opt), ret); // 2b *  E * ZZ

    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r2->x, &r2->x, para->montP, opt), ret); // (XX - aZZ) ^ 2
    GOTO_ERR_IF(BN_ModSubQuick(&r2->x, &r2->x, t0, para->p, opt), ret); // (XX - aZZ) ^ 2 - 2b *  E * ZZ

    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r3->y, &r3->y, para->montP, opt), ret); // ZZ ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r3->y, &r3->y, para->b, para->montP, opt), ret); // b * ZZ^2
    GOTO_ERR_IF(BN_ModAddQuick(&r3->y, &r3->y, &r3->y, para->p, opt), ret); // 2 * b * ZZ^2
    GOTO_ERR_IF(BN_ModAddQuick(&r3->y, &r3->y, &r3->y, para->p, opt), ret); // 4 * b * ZZ^2
    GOTO_ERR_IF(BN_ModAddQuick(&r2->z, &r2->z, &r3->y, para->p, opt), ret); // E * (XX + aZZ) + 4 * b * ZZ^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(&r3->x, para->a, t3, para->montP, opt), ret); // a * B
    GOTO_ERR_IF(BN_ModSubQuick(&r3->x, t2, &r3->x, para->p, opt), ret); // A - a * B
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r3->x, &r3->x, para->montP, opt), ret); // (A - a * B) ^ 2
    GOTO_ERR_IF(BN_ModAddQuick(t2, t4, t5, para->p, opt), ret); // C + D
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, t3, para->montP, opt), ret); // B * (C + D)
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, para->b, para->montP, opt), ret); // b * B * (C + D)
    GOTO_ERR_IF(BN_ModAddQuick(t2, t2, t2, para->p, opt), ret); // 2 * b * B * (C + D)
    GOTO_ERR_IF(BN_ModAddQuick(t2, t2, t2, para->p, opt), ret); // 4 * b * B * (C + D)
    GOTO_ERR_IF(BN_ModSubQuick(&r3->x, &r3->x, t2, para->p, opt), ret); // (A - a * B) ^ 2 - 4 * b * B * (C + D)

    GOTO_ERR_IF(BN_ModSubQuick(t4, t4, t5, para->p, opt), ret); // C - D
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t4, t4, para->montP, opt), ret); // (C - D) ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r3->z, &p->x, t4, para->montP, opt), ret); // px * (C + D) ^ 2

 ERR:
    OptimizerEnd(opt);
    return ret;
}

/*
 * ref <Weierstraß Elliptic Curves and side-Channel Attacks> formula 8.
 * XZ coordinates [database entry] represent x y as X Z satisfying the following equations:
 * x = X / Z
 * MontLadderRecoverYAndToMont return:
 *    r1->x = r1->x / r1->z
 *    r1->y = (2b + (a + x*x1)*(x + x1) - x2(x - x1)^2) / (2*y)
 *          = (2b*z2*(z1^2) + z2(a*z1 + x*x1)(x*z1 + x1) - x2(x*z1 - x1) ^ 2) / (2y*z2*(z1^2))
 */
static int32_t MontLadderRecoverYAndToMont(ECC_Para *para, ECC_Point *r1, ECC_Point *r2, ECC_Point *p,
    BN_Optimizer *opt)
{
    int32_t ret;
    if (BN_IsZero(&r1->z)) {
        para->method->bnMontDec(&r1->x, para->montP);
        para->method->bnMontDec(&r1->y, para->montP);
        return CRYPT_SUCCESS;
    }
    if (BN_IsZero(&r2->z)) {
        GOTO_ERR_IF(ECC_CopyPoint(r1, p), ret); // r2 = r1 + p = 0 -> r1 = -p
        GOTO_ERR_IF(BN_Sub(&r1->y, para->p, &r1->y), ret);
        para->method->bnMontDec(&r1->x, para->montP);
        para->method->bnMontDec(&r1->y, para->montP);
        GOTO_ERR_IF(BN_SetLimb(&r1->z, 1), ret);
        return CRYPT_SUCCESS;
    }
    (void)OptimizerStart(opt);
    BN_BigNum *t0 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t1 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t2 = OptimizerGetBn(opt, p->x.room);
    BN_BigNum *t3 = OptimizerGetBn(opt, p->x.room);
    if (t0 == NULL || t1 == NULL || t2 == NULL || t3 == NULL) {
        OptimizerEnd(opt);
        return CRYPT_MEM_ALLOC_FAIL;  // Other bn do not need to be released. They are managed by the opt.
    }
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t0, &r1->z, para->montP, opt), ret); // t0 = z1 ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t0, t0, &r2->z, para->montP, opt), ret); // t0 = z2 * z1^2

    GOTO_ERR_IF(BN_ModAddQuick(t1, para->b, para->b, para->p, opt), ret); // 2b
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t0, t1, para->montP, opt), ret); // t1 = 2b*z2*z1^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, para->a, &r1->z, para->montP, opt), ret); // t2 = a*z1
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r2->y, &p->x, &r1->x, para->montP, opt), ret); // r2->y = x*x1
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r1->y, &p->x, &r1->z, para->montP, opt), ret); // t4 = x*z1
    GOTO_ERR_IF(BN_ModAddQuick(t2, t2, &r2->y, para->p, opt), ret); // a*z1 + x*x1
    GOTO_ERR_IF(BN_ModAddQuick(&r1->y, &r1->y, &r1->x, para->p, opt), ret); // x*z1 + x1
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, &r2->z, para->montP, opt), ret); // (a*z1 + x*x1) * z2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, &r1->y, para->montP, opt), ret); // t2=(a*z1+x*x1)*z2*(x*z1+x1)

    GOTO_ERR_IF(para->method->bnModNistEccMul(&r2->y, &p->x, &r1->z, para->montP, opt), ret); // x * z1
    GOTO_ERR_IF(BN_ModSubQuick(&r2->y, &r2->y, &r1->x, para->p, opt), ret); // x * z1 - x1
    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r2->y, &r2->y, para->montP, opt), ret); // (x * z1 - x1) ^ 2
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r2->y, &r2->y, &r2->x, para->montP, opt), ret); // x2 * (x * z1 - x1) ^ 2
    GOTO_ERR_IF(BN_ModAddQuick(t1, t1, t2, para->p, opt), ret); // 2b*z2*z1^2 + t2
    GOTO_ERR_IF(BN_ModSubQuick(t1, t1, &r2->y, para->p, opt), ret); // 2b*z2*z1^2 + t2 - r2->y
    GOTO_ERR_IF(para->method->bnModNistEccMul(t1, t1, &r1->z, para->montP, opt), ret); // (2b*z2*z1^2 - t2 - r2->y) * z1

    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t0, &p->y, para->montP, opt), ret); // t2 = z2 * z1^2 * y
    GOTO_ERR_IF(BN_ModAddQuick(t2, t2, t2, para->p, opt), ret); // 2 * y * z2 * z1^2

    GOTO_ERR_IF(para->method->bnModNistEccMul(t0, &r1->x, t2, para->montP, opt), ret); // x * (2 * y * z2 * z1^2)
    GOTO_ERR_IF(para->method->bnModNistEccMul(t2, t2, &r1->z, para->montP, opt), ret); // (2 * y * z2 * z1^2) * z1

    para->method->bnMontDec(t2, para->montP);
    GOTO_ERR_IF(para->method->modInv(t2, t2, para->p, opt), ret); // (2 * y * z2 * z1^2) * -1
    GOTO_ERR_IF(para->method->bnMontEnc(t2, para->montP, opt, false), ret);

    GOTO_ERR_IF(para->method->bnModNistEccMul(&r1->x, t0, t2, para->montP, opt), ret); // x1 / z1
    // (2b*z2*z1^2 - t2 - t3) * ((2 * y * z2 * z1^2)
    GOTO_ERR_IF(para->method->bnModNistEccMul(&r1->y, t1, t2, para->montP, opt), ret);
    para->method->bnMontDec(&r1->x, para->montP);
    para->method->bnMontDec(&r1->y, para->montP);
    GOTO_ERR_IF(BN_SetLimb(&r1->z, 1), ret); // x * (2 * y * z2 * z1^2)
ERR:
    OptimizerEnd(opt);
    return ret;
}

/*
 * XZ coordinates for short Weierstrass curves
 * 2M + 5S + 1*b2 + 1*a + 1*b4
 * https://hyperelliptic.org/EFD/g1p/auto-shortw-xz.html#doubling-dbl-2002-bj-3
 * p->z = 1, the above formula can reduce the calculation amount.
 * MontLadderDouble return:
 *    r = 2 * p
*/
static int32_t MontLadderDouble(const ECC_Para *para, ECC_Point *r, ECC_Point *p, BN_Optimizer *opt)
{
    int32_t ret;
    (void)OptimizerStart(opt);
    BN_BigNum *t0 = OptimizerGetBn(opt, p->x.room);
    if (t0 == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF(para->method->bnModNistEccSqr(t0, &p->x, para->montP, opt), ret); // x^2
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &p->x, &p->x, para->p, opt), ret); // 2 * x
    GOTO_ERR_IF(BN_ModAddQuick(&r->y, &r->y, &r->y, para->p, opt), ret); // ry = 4 * x * z = 4 * x (z = 1)

    GOTO_ERR_IF(BN_ModSubQuick(&r->x, t0, para->a, para->p, opt), ret); // t0 - a
    GOTO_ERR_IF(BN_ModAddQuick(&r->z, t0, para->a, para->p, opt), ret); // t0 + a

    GOTO_ERR_IF(para->method->bnModNistEccSqr(&r->x, &r->x, para->montP, opt), ret); // (t0 - a)^2
    GOTO_ERR_IF(para->method->bnModNistEccMul(t0, para->b, &r->y, para->montP, opt), ret); // b * ry
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t0, para->p, opt), ret); // (t0 - a)^2 - b * ry
    GOTO_ERR_IF(BN_ModSubQuick(&r->x, &r->x, t0, para->p, opt), ret); // (t0 - a)^2 - 2 * b * ry

    GOTO_ERR_IF(para->method->bnModNistEccMul(&r->z, &r->y, &r->z, para->montP, opt), ret); // ry * (t0 + a)
    GOTO_ERR_IF(BN_ModAddQuick(t0, para->b, para->b, para->p, opt), ret); // 2 * b
    GOTO_ERR_IF(BN_ModAddQuick(t0, t0, t0, para->p, opt), ret); // 4 * b
    GOTO_ERR_IF(BN_ModAddQuick(&r->z, &r->z, t0, para->p, opt), ret); // ry * (t0 + a) + 4 * b

ERR:
    OptimizerEnd(opt);
    return ret;
}

static int32_t ECP_PointSwapWithMask(ECC_Point *a, ECC_Point *b, BN_UINT mask)
{
    int32_t ret;
    GOTO_ERR_IF(BN_SwapWithMask(&a->x, &b->x, mask), ret);
    GOTO_ERR_IF(BN_SwapWithMask(&a->y, &b->y, mask), ret);
    GOTO_ERR_IF(BN_SwapWithMask(&a->z, &b->z, mask), ret);
ERR:
    return ret;
}

/*
 * ref <Weierstraß Elliptic Curves and side-Channel Attacks>
 * Montgomery ladder to achieve k * Pt
 */
int32_t ECP_PointMulMont(ECC_Para *para,  ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (((pt != NULL) && (para->id != pt->id)) || (para->id != r->id)) {
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (pt != NULL && BN_IsZero(&pt->z)) {
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (BN_IsZero(k)) {
        BN_Zeroize(&r->z);
        return CRYPT_SUCCESS;
    }
    if (BN_Cmp(k, para->n) == 0 && pt != NULL) {
        return ECP_PointMulFast(para, r, para->n, pt);
    }
    int32_t ret;
    BN_UINT mask1 = 0;
    BN_UINT mask2 = 0;
    BN_UINT tmp;
    uint32_t bits;
    ECC_Point *base = (pt != NULL) ? ECC_DupPoint(pt) : ECC_GetGFromPara(para);
    ECC_Point *r1 = ECC_NewPoint(para);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (base == NULL || r1 == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Convert base to affine.
    GOTO_ERR_IF(ECP_Point2Affine(para, base, base), ret);
    GOTO_ERR_IF(ECC_PointToMont(para, base, opt), ret);
    GOTO_ERR_IF(ECC_CopyPoint(r, base), ret); // r = base
    GOTO_ERR_IF(MontLadderDouble(para, r1, r, opt), ret);
    bits = BN_Bits(k);
    for (uint32_t i = bits - 1; i > 0; i--) {
        tmp = BN_GetBit(k, i - 1);
        mask2 = (-tmp) & BN_MASK;
        GOTO_ERR_IF(ECP_PointSwapWithMask(r, r1, mask2 ^ mask1), ret);
        GOTO_ERR_IF(MontLadderDoubleAndAdd(para, r, r1, base, opt), ret);
        mask1 ^= (mask2 ^ mask1);
    }
    GOTO_ERR_IF(ECP_PointSwapWithMask(r, r1, mask1), ret);
    GOTO_ERR_IF(MontLadderRecoverYAndToMont(para, r, r1, base, opt), ret);
ERR:
    BN_OptimizerDestroy(opt);
    ECC_FreePoint(r1);
    ECC_FreePoint(base);
    return ret;
}

#endif /* HITLS_CRYPTO_ECC */
