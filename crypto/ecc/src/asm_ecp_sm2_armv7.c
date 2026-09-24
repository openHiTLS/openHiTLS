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
#if defined(HITLS_CRYPTO_CURVE_SM2_ARMV7) && defined(HITLS_THIRTY_TWO_BITS)
#include <stdint.h>
#include <string.h>
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "asm_ecp_sm2_armv7.h"

static const Sm2Fp g_Sm2Zero = {0};

static const Sm2Fp g_Sm2One = {1};

static const Sm2Fp g_Sm2Gx = {0x334c74c7U, 0x715a4589U, 0xf2660be1U, 0x8fe30bbfU,
                              0x6a39c994U, 0x5f990446U, 0x1f198119U, 0x32c4ae2cU};
static const Sm2Fp g_Sm2Gy = {0x2139f0a0U, 0x02df32e5U, 0xc62a4740U, 0xd0a9877cU,
                              0x6b692153U, 0x59bdcee3U, 0xf4f6779cU, 0xbc3736a2U};

static void ECP_Sm2FpSet(Sm2Fp r, const Sm2Fp a)
{
    memcpy(r, a, sizeof(Sm2Fp));
}

static int ECP_Sm2FpIsEven(const Sm2Fp a)
{
    return (int)(a[0] & 1) ^ 1;
}

static int ECP_Sm2FpIsZero(const Sm2Fp a)
{
    uint32_t r = 0;
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        r |= a[i];
    }
    return r == 0;
}

static int ECP_Sm2FpIsOne(const Sm2Fp a)
{
    uint32_t r = a[0] ^ 1;
    for (uint32_t i = 1; i < SM2_LIMBS; i++) {
        r |= a[i];
    }
    return r == 0;
}

static int ECP_Sm2FpEqu(const Sm2Fp a, const Sm2Fp b)
{
    uint32_t r = 0;
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        r |= a[i] ^ b[i];
    }
    return r == 0;
}

static uint32_t ECP_Sm2FpIsZeroMask(const Sm2Fp a)
{
    uint32_t r = 0;
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        r |= a[i];
    }
    return Uint32ConstTimeIsZero(r);
}

static uint32_t ECP_Sm2FpEqualMask(const Sm2Fp a, const Sm2Fp b)
{
    uint32_t r = 0;
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        r |= a[i] ^ b[i];
    }
    return Uint32ConstTimeIsZero(r);
}

/**
 * @brief Computes multiplicative inverse modulo sm2_p, i.e., r ≡ a^-1 mod sm2_p.
 * @param [out] r The result number.
 * @param [in] q The number to invert.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 2.22
 */
static void ECP_Sm2FpInv(Sm2Fp r, const Sm2Fp q)
{
    Sm2Fp v = {0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU};
    if (ECP_Sm2FpIsZero(q) || ECP_Sm2FpEqu(q, v)) {
        ECP_Sm2FpSet(r, g_Sm2Zero);
        return;
    }
    Sm2Fp u, a = {1}, c = {0};
    ECP_Sm2FpSet(u, q);
    while (ECP_Sm2FpIsOne(u) == 0 && ECP_Sm2FpIsOne(v) == 0) {
        while (ECP_Sm2FpIsEven(u)) {
            ECP_Sm2FpHaf(u, u);
            ECP_Sm2FpHaf(a, a);
        }
        while (ECP_Sm2FpIsEven(v)) {
            ECP_Sm2FpHaf(v, v);
            ECP_Sm2FpHaf(c, c);
        }
        if (ECP_Sm2FpCmp(u, v)) {
            ECP_Sm2FpSub(u, u, v);
            ECP_Sm2FpSub(a, a, c);
        } else {
            ECP_Sm2FpSub(v, v, u);
            ECP_Sm2FpSub(c, c, a);
        }
    }
    if (ECP_Sm2FpIsOne(u)) {
        ECP_Sm2FpSet(r, a);
    } else {
        ECP_Sm2FpSet(r, c);
    }
}

/**
 * @brief Computes multiplicative inverse modulo sm2_n, i.e., r ≡ a^-1 mod sm2_n.
 * @param [out] r The result number.
 * @param [in] q The number to invert.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 2.22
 */
static void ECP_Sm2FnInv(Sm2Fp r, const Sm2Fp q)
{
    Sm2Fp v = {0x39D54123U, 0x53BBF409U, 0x21C6052BU, 0x7203DF6BU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU};
    if (ECP_Sm2FpIsZero(q) || ECP_Sm2FpEqu(q, v)) {
        ECP_Sm2FpSet(r, g_Sm2Zero);
        return;
    }
    Sm2Fp u, a = {1}, c = {0};
    ECP_Sm2FpSet(u, q);
    while (ECP_Sm2FpIsOne(u) == 0 && ECP_Sm2FpIsOne(v) == 0) {
        while (ECP_Sm2FpIsEven(u)) {
            ECP_Sm2FnHaf(u, u);
            ECP_Sm2FnHaf(a, a);
        }
        while (ECP_Sm2FpIsEven(v)) {
            ECP_Sm2FnHaf(v, v);
            ECP_Sm2FnHaf(c, c);
        }
        if (ECP_Sm2FpCmp(u, v)) {
            ECP_Sm2FnSub(u, u, v);
            ECP_Sm2FnSub(a, a, c);
        } else {
            ECP_Sm2FnSub(v, v, u);
            ECP_Sm2FnSub(c, c, a);
        }
    }
    if (ECP_Sm2FpIsOne(u)) {
        ECP_Sm2FpSet(r, a);
    } else {
        ECP_Sm2FpSet(r, c);
    }
}

//**********************************************************************************************************************

static void ECP_Sm2PointSet(Sm2Point *p, const Sm2Fp x, const Sm2Fp y, const Sm2Fp z)
{
    ECP_Sm2FpSet(p->x, x);
    ECP_Sm2FpSet(p->y, y);
    ECP_Sm2FpSet(p->z, z);
}

static void ECP_Sm2PointSetInfinity(Sm2Point *r)
{
    ECP_Sm2PointSet(r, g_Sm2One, g_Sm2One, g_Sm2Zero);
}

static int ECP_Sm2PointAtInfinity(const Sm2Point *r)
{
    return ECP_Sm2FpIsZero(r->z);
}

static uint32_t ECP_Sm2PointAtInfinityMask(const Sm2Point *r)
{
    return ECP_Sm2FpIsZeroMask(r->z);
}

static void ECP_Sm2PointSelect(Sm2Point *r, const Sm2Point *a, const Sm2Point *b, uint32_t mask)
{
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        r->x[i] = Uint32ConstTimeSelect(mask, a->x[i], b->x[i]);
        r->y[i] = Uint32ConstTimeSelect(mask, a->y[i], b->y[i]);
        r->z[i] = Uint32ConstTimeSelect(mask, a->z[i], b->z[i]);
    }
}

/**
 * @brief Converts a jacobian point to affine coordinates.
 * @param [in] a Pointer to the jacobian point to convert.
 * @param [out] r Pointer to the resulting affine point.
 */
void ECP_Sm2PointToAffineCore(const Sm2Point *a, Sm2Point *r)
{
    if (ECP_Sm2PointAtInfinity(a)) {
        ECP_Sm2PointSetInfinity(r);
        return;
    }
    Sm2Fp t1, t2;
    ECP_Sm2FpInv(t1, a->z);
    ECP_Sm2FpSqr(t2, t1);
    ECP_Sm2FpMul(r->x, t2, a->x);
    ECP_Sm2FpMul(t2, t2, t1);
    ECP_Sm2FpMul(r->y, t2, a->y);
    ECP_Sm2FpSet(r->z, g_Sm2One);
}

/**
 * @brief Doubles a jacobian point.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] a Pointer to the SM2jacobianPoint to be doubled.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2004-hmv
 */
static void ECP_Sm2PointDouFormula(Sm2Point *r, const Sm2Point *a)
{
    // A = 3(x1 - z1^2) * (x1 + z1^2)
    // B = 2Y1, z3 = B * z1, C = B^2
    // D = C * x1, x3 = A^2 - 2D, (D - x3) * A - C^2/2
    const uint32_t *x1 = a->x, *y1 = a->y, *z1 = a->z;
    Sm2Fp t1, t2, t3, x3, y3, z3;
    ECP_Sm2FpSqr(t1, z1); // t1 = z1^2
    ECP_Sm2FpSub(t2, x1, t1); // t2 = x1 - z1^2
    ECP_Sm2FpAdd(t1, x1, t1); // t1 = x1 + z1^2
    ECP_Sm2FpMul(t2, t2, t1); // t2 = x1^2 - z1^4
    ECP_Sm2FpDou(t3, t2); // t3 = 2(x1^2 - z1^4)
    ECP_Sm2FpAdd(t2, t2, t3); // t2 = A = 3t2 = 3(x1^2 - z1^4)
    ECP_Sm2FpDou(y3, y1); // y3 = B = 2y1
    ECP_Sm2FpMul(z3, y3, z1); // z3 = B * z1
    ECP_Sm2FpSqr(y3, y3); // y3 = C = B^2
    ECP_Sm2FpMul(t3, y3, x1); // t3 = D = C * x1
    ECP_Sm2FpSqr(y3, y3); // y3 = C^2
    ECP_Sm2FpHaf(y3, y3); // y3 = C^2/2
    ECP_Sm2FpSqr(x3, t2); // x3 = A^2
    ECP_Sm2FpDou(t1, t3); // t1 = 2D
    ECP_Sm2FpSub(x3, x3, t1); // x3 = A^2 - 2D
    ECP_Sm2FpSub(t1, t3, x3); // t1 = D - x3
    ECP_Sm2FpMul(t1, t1, t2); // t1 = (D - x3) * A
    ECP_Sm2FpSub(y3, t1, y3); // y3 = (D - x3) * A - C^2/2
    ECP_Sm2PointSet(r, x3, y3, z3);
}

static void ECP_Sm2PointDouCore(Sm2Point *r, const Sm2Point *a)
{
    if (ECP_Sm2PointAtInfinity(a)) {
        *r = *a;
        return;
    }
    ECP_Sm2PointDouFormula(r, a);
}

static void ECP_Sm2PointDouConsttime(Sm2Point *r, const Sm2Point *a)
{
    Sm2Point doubled;
    uint32_t infMask = ECP_Sm2PointAtInfinityMask(a);
    ECP_Sm2PointDouFormula(&doubled, a);
    ECP_Sm2PointSelect(r, a, &doubled, infMask);
}

/**
 * @brief Adds two jacobian points.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] p Pointer to the first SM2jacobianPoint.
 * @param [in] q Pointer to the second SM2jacobianPoint.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
 */
static void ECP_Sm2PointAddCore(Sm2Point *r, const Sm2Point *p, const Sm2Point *q)
{
    // Check if one of the points is the point at infinity
    if (ECP_Sm2PointAtInfinity(p)) {
        *r = *q;
        return;
    }
    if (ECP_Sm2PointAtInfinity(q)) {
        *r = *p;
        return;
    }

    const uint32_t *x1 = p->x, *y1 = p->y, *z1 = p->z;
    const uint32_t *x2 = q->x, *y2 = q->y, *z2 = q->z;
    Sm2Fp x3, y3, z3, u1, u2, s1, s2, h, n, h2, h3, u1h2, t1, t2;

    ECP_Sm2FpSqr(t1, z1); // t1 = z1^2
    ECP_Sm2FpSqr(t2, z2); // t2 = z2^2
    ECP_Sm2FpMul(u1, x1, t2); // u1 = x1 * z2^2
    ECP_Sm2FpMul(u2, x2, t1); // u2 = x2 * z1^2
    ECP_Sm2FpMul(t1, t1, z1); // t1 = z1^3
    ECP_Sm2FpMul(t2, t2, z2); // t2 = z2^3
    ECP_Sm2FpMul(s1, y1, t2); // s1 = y1 * z2^3
    ECP_Sm2FpMul(s2, y2, t1); // s2 = y2 * z1^3
    if (ECP_Sm2FpEqu(u1, u2)) {
        if (ECP_Sm2FpEqu(s1, s2)) {
            ECP_Sm2PointDouCore(r, p);
        } else {
            ECP_Sm2PointSetInfinity(r);
        }
        return;
    }
    ECP_Sm2FpSub(h, u2, u1); // h = u2 - u1
    ECP_Sm2FpSub(n, s2, s1); // n = s2 - s1
    ECP_Sm2FpSqr(h2, h); // h2 = h^2
    ECP_Sm2FpMul(h3, h2, h); // h3 = h^3
    ECP_Sm2FpMul(u1h2, u1, h2); // u1h2 = u1 * h^2
    ECP_Sm2FpDou(t1, u1h2); // t1 = 2u1h2
    ECP_Sm2FpSqr(x3, n); // x3 = n^2
    ECP_Sm2FpSub(x3, x3, h3); // x3 = n^2 - h3
    ECP_Sm2FpSub(x3, x3, t1); // x3 = n^2 - h3 - 2u1h2
    ECP_Sm2FpMul(t1, s1, h3); // t1 = s1 * h3
    ECP_Sm2FpSub(y3, u1h2, x3); // y3 = u1h2 - x3
    ECP_Sm2FpMul(y3, y3, n); // y3 = n * (u1h2 - x3)
    ECP_Sm2FpSub(y3, y3, t1); // y3 = n * (u1h2 - x3) - s1 * h3
    ECP_Sm2FpMul(z3, z1, z2); // z3 = z1 * z2
    ECP_Sm2FpMul(z3, z3, h); // z3 = h * z1 * z2
    ECP_Sm2PointSet(r, x3, y3, z3);
}

static void ECP_Sm2PointAddConsttime(Sm2Point *r, const Sm2Point *p, const Sm2Point *q)
{
    const uint32_t *x1 = p->x, *y1 = p->y, *z1 = p->z;
    const uint32_t *x2 = q->x, *y2 = q->y, *z2 = q->z;
    Sm2Fp x3, y3, z3, u1, u2, s1, s2, h, n, h2, h3, u1h2, t1, t2;
    Sm2Point add, doubled, inf, tmp;

    ECP_Sm2FpSqr(t1, z1);
    ECP_Sm2FpSqr(t2, z2);
    ECP_Sm2FpMul(u1, x1, t2);
    ECP_Sm2FpMul(u2, x2, t1);
    ECP_Sm2FpMul(t1, t1, z1);
    ECP_Sm2FpMul(t2, t2, z2);
    ECP_Sm2FpMul(s1, y1, t2);
    ECP_Sm2FpMul(s2, y2, t1);

    ECP_Sm2FpSub(h, u2, u1);
    ECP_Sm2FpSub(n, s2, s1);
    ECP_Sm2FpSqr(h2, h);
    ECP_Sm2FpMul(h3, h2, h);
    ECP_Sm2FpMul(u1h2, u1, h2);
    ECP_Sm2FpDou(t1, u1h2);
    ECP_Sm2FpSqr(x3, n);
    ECP_Sm2FpSub(x3, x3, h3);
    ECP_Sm2FpSub(x3, x3, t1);
    ECP_Sm2FpMul(t1, s1, h3);
    ECP_Sm2FpSub(y3, u1h2, x3);
    ECP_Sm2FpMul(y3, y3, n);
    ECP_Sm2FpSub(y3, y3, t1);
    ECP_Sm2FpMul(z3, z1, z2);
    ECP_Sm2FpMul(z3, z3, h);
    ECP_Sm2PointSet(&add, x3, y3, z3);

    ECP_Sm2PointDouFormula(&doubled, p);
    ECP_Sm2PointSetInfinity(&inf);

    uint32_t pInf = ECP_Sm2PointAtInfinityMask(p);
    uint32_t qInf = ECP_Sm2PointAtInfinityMask(q);
    uint32_t uEq = ECP_Sm2FpEqualMask(u1, u2);
    uint32_t sEq = ECP_Sm2FpEqualMask(s1, s2);
    uint32_t samePoint = uEq & sEq;
    uint32_t inversePoint = uEq & ~sEq;

    ECP_Sm2PointSelect(&tmp, &inf, &add, inversePoint);
    ECP_Sm2PointSelect(&tmp, &doubled, &tmp, samePoint);
    ECP_Sm2PointSelect(&tmp, p, &tmp, qInf);
    ECP_Sm2PointSelect(r, q, &tmp, pInf);
}

/**
 * @brief Point addition, affine-jacobian coordinates
 * @param [out] r The result of the addition.
 * @param [in] p The jacobian point.
 * @param [in] q The affine point.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2004-hmv
 */
static void ECP_Sm2PointAddWithAffineCore(Sm2Point *r, const Sm2Point *p, const Sm2Point *q)
{
    if (ECP_Sm2PointAtInfinity(p)) {
        *r = *q;
        return;
    }
    if (ECP_Sm2FpIsZero(q->x) && ECP_Sm2FpIsZero(q->y)) {
        *r = *p;
        return;
    }

    const uint32_t *x1 = p->x, *y1 = p->y, *z1 = p->z, *x2 = q->x, *y2 = q->y;
    Sm2Fp x3, y3, z3, t1, t2, t3, t4;

    ECP_Sm2FpSqr(t1, z1); // t1 = A = z1^2
    ECP_Sm2FpMul(t2, t1, z1); // t2 = B = z1 * A
    ECP_Sm2FpMul(t1, t1, x2); // t1 = C = x2 * A
    ECP_Sm2FpMul(t2, t2, y2); // t2 = D = y2 * B
    ECP_Sm2FpSub(t1, t1, x1); // t1 = E = C - x1
    ECP_Sm2FpSub(t2, t2, y1); // t2 = F = D - y1
    if (ECP_Sm2FpEqu(t1, g_Sm2Zero)) {
        if (ECP_Sm2FpEqu(t2, g_Sm2Zero)) {
            Sm2Point t;
            ECP_Sm2PointSet(&t, x2, y2, g_Sm2One);
            ECP_Sm2PointDouCore(r, &t);
        } else {
            ECP_Sm2PointSetInfinity(r);
        }
        return;
    }
    ECP_Sm2FpMul(z3, z1, t1); // z3 = z1 * E
    ECP_Sm2FpSqr(t3, t1); // t3 = G = E^2
    ECP_Sm2FpMul(t4, t3, t1); // t4 = H = E^3
    ECP_Sm2FpMul(t3, t3, x1); // t3 = I = x1 * G
    ECP_Sm2FpDou(t1, t3); // t1 = 2I
    ECP_Sm2FpSqr(x3, t2); // x3 = F^2
    ECP_Sm2FpSub(x3, x3, t1); // x3 = F^2 - 2I
    ECP_Sm2FpSub(x3, x3, t4); // x3 = F^2 - 2I - H
    ECP_Sm2FpSub(t3, t3, x3); // t3 = I - x3
    ECP_Sm2FpMul(t3, t3, t2); // t3 = (I - x3) * F
    ECP_Sm2FpMul(t4, t4, y1); // t4 = y1 * H
    ECP_Sm2FpSub(y3, t3, t4); // y3 = (I - x3) * F - y1 * H
    ECP_Sm2PointSet(r, x3, y3, z3);
}

/**
 * @brief Performs scalar multiplication on a jacobian point.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] m Scalar for multiplication.
 * @param [in] p Pointer to the SM2jacobianPoint to be multiplied.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 3.23
 */
static void ECP_Sm2PointMultDoubleCore(Sm2Point *r, uint32_t m, const Sm2Point *p)
{
    if (ECP_Sm2PointAtInfinity(p)) {
        ECP_Sm2PointSet(r, p->x, p->y, p->z);
        return;
    }

    Sm2Fp x, y, z, w, a, b, t;
    ECP_Sm2FpSet(x, p->x);
    ECP_Sm2FpSet(y, p->y);
    ECP_Sm2FpSet(z, p->z);
    ECP_Sm2FpDou(y, y); // y = 2y
    ECP_Sm2FpSqr(w, z);
    ECP_Sm2FpSqr(w, w); // w = z^4
    while (m--) {
        ECP_Sm2FpSqr(a, x);
        ECP_Sm2FpSub(a, a, w);
        ECP_Sm2FpDou(t, a);
        ECP_Sm2FpAdd(a, a, t); // a = 3(x^2 - w)
        ECP_Sm2FpSqr(b, y);
        ECP_Sm2FpMul(b, x, b); // b = x * y^2
        ECP_Sm2FpSqr(x, a);
        ECP_Sm2FpSub(x, x, b);
        ECP_Sm2FpSub(x, x, b); // x = a^2 - 2b
        ECP_Sm2FpMul(z, z, y); // z = z * y
        ECP_Sm2FpSqr(t, y);
        ECP_Sm2FpSqr(t, t); // t = y^4
        if (m) {
            ECP_Sm2FpMul(w, w, t); // w = w * y^4
        }
        ECP_Sm2FpSub(y, b, x);
        ECP_Sm2FpMul(y, y, a);
        ECP_Sm2FpDou(y, y);
        ECP_Sm2FpSub(y, y, t); // y = 2(b-x) - y^4
    }
    ECP_Sm2FpHaf(y, y);
    ECP_Sm2PointSet(r, x, y, z);
}

static uint32_t ECP_Sm2FpGetBits(const Sm2Fp a, uint32_t pos, uint32_t n)
{
    uint32_t word = pos >> 5;
    uint32_t offset = pos & 31;
    uint32_t val = a[word] >> offset;
    if (offset + n > 32 && word + 1 < SM2_LIMBS) {
        val |= a[word + 1] << (32 - offset);
    }
    return val & ((1u << n) - 1u);
}

static void ECP_Sm2PointSelectWindow(Sm2Point *r, const Sm2Point table[16], uint32_t window)
{
    ECP_Sm2PointSetInfinity(r);
    for (int j = 0; j < 16; j++) {
        uint32_t mask = Uint32ConstTimeEqual(window, (uint32_t)j);
        ECP_Sm2PointSelect(r, &table[j], r, mask);
    }
}

static void ECP_Sm2FpFixedWindowTable(Sm2Point table[16], const Sm2Point *g)
{
    ECP_Sm2PointSetInfinity(&table[0]);
    table[1] = *g;
    ECP_Sm2PointDouCore(&table[2], g);
    for (int i = 3; i < 16; i++) {
        ECP_Sm2PointAddCore(&table[i], &table[i - 1], &table[1]);
    }
}

/**
 * @brief Multiplies a scalar with a given jacobian point using fixed-window (w=4) method.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] k Scalar for multiplication.
 * @param [in] g Pointer to the SM2jacobianPoint to be multiplied.
 */
static void ECP_Sm2PointMulCore(Sm2Point *r, const Sm2Fp k, const Sm2Point *g)
{
    Sm2Point table[16];
    ECP_Sm2FpFixedWindowTable(table, g);

    uint32_t numWindows = SM2_BITS / 4;
    uint32_t Ki = ECP_Sm2FpGetBits(k, (numWindows - 1) * 4, 4);

    ECP_Sm2PointSelectWindow(r, table, Ki);
    Sm2Point sel;
    for (int i = (int)numWindows - 2; i >= 0; i--) {
        ECP_Sm2PointDouConsttime(r, r);
        ECP_Sm2PointDouConsttime(r, r);
        ECP_Sm2PointDouConsttime(r, r);
        ECP_Sm2PointDouConsttime(r, r);
        Ki = ECP_Sm2FpGetBits(k, (uint32_t)i * 4, 4);
        ECP_Sm2PointSelectWindow(&sel, table, Ki);
        ECP_Sm2PointAddConsttime(r, r, &sel);
    }
}

/**
 * @brief Multiplies a scalar with the base generator point using fixed-window (w=4) method.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] k Scalar used for the generation.
 */
static void ECP_Sm2PointGenCore(Sm2Point *r, const Sm2Fp k)
{
    Sm2Point G;
    ECP_Sm2PointSet(&G, g_Sm2Gx, g_Sm2Gy, g_Sm2One);

    Sm2Point table[16];
    ECP_Sm2FpFixedWindowTable(table, &G);

    uint32_t numWindows = SM2_BITS / 4;
    uint32_t Ki = ECP_Sm2FpGetBits(k, (numWindows - 1) * 4, 4);

    ECP_Sm2PointSelectWindow(r, table, Ki);
    Sm2Point sel;
    for (int i = (int)numWindows - 2; i >= 0; i--) {
        ECP_Sm2PointDouConsttime(r, r);
        ECP_Sm2PointDouConsttime(r, r);
        ECP_Sm2PointDouConsttime(r, r);
        ECP_Sm2PointDouConsttime(r, r);
        Ki = ECP_Sm2FpGetBits(k, (uint32_t)i * 4, 4);
        ECP_Sm2PointSelectWindow(&sel, table, Ki);
        ECP_Sm2PointAddConsttime(r, r, &sel);
    }
}

static int32_t ECP_SM2FpGet(Sm2Fp dst, const BN_BigNum *src)
{
    if (src->size > SM2_LIMBS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    ECP_Sm2FpSet(dst, g_Sm2Zero);
    if (BN_IsZero(src)) {
        return CRYPT_SUCCESS;
    }
    for (uint32_t i = 0; i < src->size; i++) {
        dst[i] = src->data[i];
    }
    return CRYPT_SUCCESS;
}

static int32_t ECP_SM2FpPut(const Sm2Fp src, BN_BigNum *dst)
{
    int32_t ret = BN_Extend(dst, SM2_LIMBS);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_Zeroize(dst);
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        dst->data[i] = src[i];
        if (dst->data[i] != 0) {
            dst->size = i + 1;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t ECP_SM2PointGet(Sm2Point *dst, const ECC_Point *src)
{
    int32_t ret;
    GOTO_ERR_IF_EX(ECP_SM2FpGet(dst->x, &src->x), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpGet(dst->y, &src->y), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpGet(dst->z, &src->z), ret);
ERR:
    return ret;
}

static int32_t ECP_SM2PointPut(const Sm2Point *src, ECC_Point *dst)
{
    int32_t ret;
    GOTO_ERR_IF_EX(ECP_SM2FpPut(src->x, &dst->x), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpPut(src->y, &dst->y), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpPut(src->z, &dst->z), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2Mul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = data;
    if (r == NULL || a == NULL || b == NULL || mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // Ensure that no out-of-bounds access occurs.
    if ((mod->size > b->room) || (mod->size > a->room)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    if (a->size == 0 || b->size == 0) {
        return BN_Zeroize(r);
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp u, v;
    GOTO_ERR_IF(ECP_SM2FpGet(u, a), ret);
    GOTO_ERR_IF(ECP_SM2FpGet(v, b), ret);
    ECP_Sm2FpMul(u, u, v);
    GOTO_ERR_IF(ECP_SM2FpPut(u, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2Sqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = (BN_BigNum *)data;
    if (r == NULL || a == NULL || mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // Ensure that no out-of-bounds access occurs.
    if (mod->size > a->room) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    if (a->size == 0) {
        return BN_Zeroize(r);
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    GOTO_ERR_IF(ECP_SM2FpGet(n, a), ret);
    ECP_Sm2FpSqr(n, n);
    GOTO_ERR_IF(ECP_SM2FpPut(n, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2Inv(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || p == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a) || BN_IsZero(p)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    GOTO_ERR_IF(ECP_SM2FpGet(n, a), ret);
    ECP_Sm2FpInv(n, n);
    GOTO_ERR_IF(ECP_SM2FpPut(n, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2OrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    (void)para;
    if (BN_IsZero(a)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    if (BN_Cmp(para->n, a) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    GOTO_ERR_IF(ECP_SM2FpGet(n, a), ret);
    ECP_Sm2FnInv(n, n);
    GOTO_ERR_IF(ECP_SM2FpPut(n, r), ret);
    if (BN_IsZero(r)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    return CRYPT_SUCCESS;
ERR:
    return ret;
}

int32_t ECP_Sm2Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    (void)para;
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p;
    Sm2Fp t1, t2;
    GOTO_ERR_IF_EX(ECP_SM2PointGet(&p, a), ret);
    ECP_Sm2FpInv(t1, p.z);
    ECP_Sm2FpSqr(t2, t1);
    ECP_Sm2FpMul(p.x, t2, p.x);
    ECP_Sm2FpMul(t2, t2, t1);
    ECP_Sm2FpMul(p.y, t2, p.y);
    GOTO_ERR_IF_EX(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2Point2AffineWithInv(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const BN_BigNum *inv)
{
    if (para == NULL || r == NULL || a == NULL || inv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != a->id || para->id != r->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(&a->z)) {
        // Infinite point multiplied by z is meaningless.
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2FpGet(n, inv), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, a), ret);
    ECP_Sm2FpSqr(p.z, n);
    ECP_Sm2FnMul(p.x, p.z, q.x);
    ECP_Sm2FnMul(p.y, p.z, q.y);
    ECP_Sm2FnMul(p.y, p.y, n);
    ECP_Sm2FpSet(p.z, g_Sm2One);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
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
    if (BN_Cmp(&a->x, &b->x) == 0 && BN_Cmp(&a->y, &b->y) == 0 && BN_Cmp(&a->z, &b->z) == 0) {
        return para->method->pointDouble(para, r, a);
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, b), ret);
    ECP_Sm2PointAddCore(&p, &p, &q);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2PointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    (void)para;
    if (BN_IsZero(&a->z)) { // If point a is an infinity point, r = b
        return ECC_CopyPoint(r, b);
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, b), ret);
    ECP_Sm2PointAddWithAffineCore(&p, &p, &q);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    (void)para;
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    ECP_Sm2PointDouCore(&p, &p);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointMultDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    ECP_Sm2PointMultDoubleCore(&p, m, &p);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *scalar, const ECC_Point *pt)
{
    (void)para;
    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp k;
    Sm2Point p;
    GOTO_ERR_IF(ECP_SM2FpGet(k, scalar), ret);
    if (pt == NULL) {
        ECP_Sm2PointGenCore(&p, k);
    } else {
        GOTO_ERR_IF_EX(ECP_SM2PointGet(&p, pt), ret);
        ECP_Sm2PointMulCore(&p, k, &p);
    }
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF_EX(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2PointMulFast(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    return ECP_Sm2PointMul(para, r, k, pt);
}

int32_t ECP_Sm2PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    (void)para;
    if (BN_Bits(k1) > SM2_BITS || BN_Bits(k2) > SM2_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp s, t;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2FpGet(s, k1), ret);
    GOTO_ERR_IF(ECP_SM2FpGet(t, k2), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, pt), ret);
    ECP_Sm2PointGenCore(&p, s);
    ECP_Sm2PointMulCore(&q, t, &q);
    ECP_Sm2PointAddConsttime(&p, &p, &q);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}
#endif
