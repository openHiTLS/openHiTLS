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
#if defined(HITLS_CRYPTO_CURVE_SM2) && defined(HITLS_SIXTY_FOUR_BITS)

#include <stdint.h>
#include "securec.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "asm_ecp_sm2.h"

#define SM2_MASK2 0xff
#define WINDOW_SIZE 4
#define PRECOMPUTED_TABLE_SIZE (1 << WINDOW_SIZE)
#define WINDOW_HALF_TABLE_SIZE 8
#define SM2_NUMTOOFFSET(num) (((num) < 0) ? (WINDOW_HALF_TABLE_SIZE - 1 - (((num) - 1) >> 1)) : (((num) - 1) >> 1))

static const BN_UINT g_sm2p[SM2_LIMBS] = {
    0xffffffffffffffff, 0xffffffff00000000,
    0xffffffffffffffff, 0xfffffffeffffffff
};

static const BN_UINT g_sm2ord[SM2_LIMBS] = {
    0x53bbf40939d54123, 0x7203df6b21c6052b,
    0xffffffffffffffff, 0xfffffffeffffffff
};

static const BN_UINT g_one[SM2_LIMBS] = {1, 0, 0, 0};

#define FDIV(uout, uin, xout, xin, div, mod)         \
    do {                                             \
        ECP_Sm2Div##div(uout, uin);                      \
        ECP_Sm2Div##div##Mod##mod(xout, xin); \
    } while (0)

#define FSUB(uout, uin, xout, xin, mod)             \
    do {                                            \
        ECP_Sm2BnSub(uout, uout, uin);                    \
        ECP_Sm2SubMod##mod(xout, xout, xin); \
    } while (0)

#define FSUB_DIV(u, v, x1, x2, div, mod)  \
    do {                                  \
        if (IsGreater(u, v) == 1) {      \
            FSUB(u, v, x1, x2, mod);      \
            FDIV(u, u, x1, x1, div, mod); \
        } else {                          \
            FSUB(v, u, x2, x1, mod);      \
            FDIV(v, v, x2, x2, div, mod); \
        }                                 \
    } while (0)

static uint32_t IsZero(BN_UINT a)
{
    BN_UINT t = a;
    t |= (0 - t);
    t = ~t;
    t >>= (BN_UNIT_BITS - 1);
    return (uint32_t)t;
}

static uint32_t IsZeros(const BN_UINT *a)
{
    BN_UINT res = a[0] ^ 0;
    for (uint32_t i = 1; i < SM2_LIMBS; i++) {
        res |= a[i] ^ 0;
    }
    return IsZero(res);
}

static uint32_t IsEqual(const BN_UINT *a, const BN_UINT *b)
{
    BN_UINT res = a[0] ^ b[0];
    for (uint32_t i = 1; i < SM2_LIMBS; i++) {
        res |= a[i] ^ b[i];
    }
    return IsZero(res);
}

#define IS_ONE(a) IsEqual(a, g_one)

static int32_t IsGreater(const BN_UINT *a, const BN_UINT *b)
{
    for (int32_t i = (int32_t)(SM2_LIMBS - 1); i >= 0; --i) {
        if (a[i] > b[i]) {
            return 1;
        }
        if (a[i] < b[i]) {
            return -1;
        }
    }

    return 0;
}

/*
 * Radix-4 Binary algorithm for modular inversion in Fp
 * ref. <Ultra High-Speed SM2 ASIC Implementation>
*/

/* Modular inv: out = in^(-1) mod p */
static void ECP_Sm2ModInverse(BN_UINT *out, const BN_UINT *in)
{
    BN_UINT u[SM2_LIMBS] ALIGN32;
    BN_UINT v[SM2_LIMBS] ALIGN32;
    BN_UINT x1[SM2_LIMBS] ALIGN32 = {1, 0, 0, 0};
    BN_UINT x2[SM2_LIMBS] ALIGN32 = {0};
    BN_UINT c;
    BN_UINT d;
    if (IsZeros(in) != 0) {
        return;
    }
    (void)memcpy_s(u, SM2_BYTES_NUM, in, SM2_BYTES_NUM);
    (void)memcpy_s(v, SM2_BYTES_NUM, g_sm2p, SM2_BYTES_NUM);
    while (((!IS_ONE(u)) != 0) && ((!IS_ONE(v)) != 0)) {
        c = u[0] & 0x3; // Use 0x03 to obtain the last two bits.
        d = v[0] & 0x3;
        if (c == 0) {
            FDIV(u, u, x1, x1, 4, P);
        } else if (d == 0) {
            FDIV(v, v, x2, x2, 4, P);
        } else if (c == d) {
            FSUB_DIV(u, v, x1, x2, 4, P);
        } else if (c == 2) { // if c == 2
            FDIV(u, u, x1, x1, 2, P);
            FSUB_DIV(u, v, x1, x2, 2, P);
        } else if (d == 2) { // if d == 2
            FDIV(v, v, x2, x2, 2, P);
            FSUB_DIV(u, v, x1, x2, 2, P);
        } else {
            FSUB_DIV(u, v, x1, x2, 2, P);
        }
    }
    if (IS_ONE(u) != 0) {
        (void)memcpy_s(out, SM2_BYTES_NUM, x1, SM2_BYTES_NUM);
    } else {
        (void)memcpy_s(out, SM2_BYTES_NUM, x2, SM2_BYTES_NUM);
    }
}

/* Modular inv: out = in^(-1) mod n, where n = ord(p) */
static void ECP_Sm2InvModOrd(BN_UINT *out, const BN_UINT *in)
{
    BN_UINT u[SM2_LIMBS] ALIGN32;
    BN_UINT v[SM2_LIMBS] ALIGN32;
    BN_UINT x1[SM2_LIMBS] ALIGN32 = {1, 0, 0, 0};
    BN_UINT x2[SM2_LIMBS] ALIGN32 = {0};
    BN_UINT c;
    BN_UINT d;
    if (IsZeros(in) != 0) {
        return;
    }
    (void)memcpy_s(u, SM2_BYTES_NUM, in, SM2_BYTES_NUM);
    (void)memcpy_s(v, SM2_BYTES_NUM, g_sm2ord, SM2_BYTES_NUM);
    while (((!IS_ONE(u)) != 0) && ((!IS_ONE(v)) != 0)) {
        c = u[0] & 0x3; // Use 0x03 to obtain the last two bits.
        d = v[0] & 0x3;
        if (c == 0) {
            FDIV(u, u, x1, x1, 4, Ord);
        } else if (d == 0) {
            FDIV(v, v, x2, x2, 4, Ord);
        } else if (c == d) {
            FSUB_DIV(u, v, x1, x2, 4, Ord);
        } else if (c == 2) { // if c == 2
            FDIV(u, u, x1, x1, 2, Ord);
            FSUB_DIV(u, v, x1, x2, 2, Ord);
        } else if (d == 2) { // if d == 2
            FDIV(v, v, x2, x2, 2, Ord);
            FSUB_DIV(u, v, x1, x2, 2, Ord);
        } else {
            FSUB_DIV(u, v, x1, x2, 2, Ord);
        }
    }
    if (IS_ONE(u) != 0) {
        (void)memcpy_s(out, SM2_BYTES_NUM, x1, SM2_BYTES_NUM);
    } else {
        (void)memcpy_s(out, SM2_BYTES_NUM, x2, SM2_BYTES_NUM);
    }
}

static int32_t ECP_Sm2Point2Array(SM2_point *r, const ECC_Point *p)
{
    int32_t ret;
    uint32_t len = SM2_LIMBS;
    GOTO_ERR_IF_EX(BN_Bn2U64Array(&p->x, (BN_UINT *)&r->x, &len), ret);
    GOTO_ERR_IF_EX(BN_Bn2U64Array(&p->y, (BN_UINT *)&r->y, &len), ret);
    GOTO_ERR_IF_EX(BN_Bn2U64Array(&p->z, (BN_UINT *)&r->z, &len), ret);
ERR:
    return ret;
}

static int32_t ECP_Sm2Array2Point(ECC_Point *r, const SM2_point *a)
{
    int32_t ret;
    GOTO_ERR_IF_EX(BN_U64Array2Bn(&r->x, (const BN_UINT *)a->x, SM2_LIMBS), ret);
    GOTO_ERR_IF_EX(BN_U64Array2Bn(&r->y, (const BN_UINT *)a->y, SM2_LIMBS), ret);
    GOTO_ERR_IF_EX(BN_U64Array2Bn(&r->z, (const BN_UINT *)a->z, SM2_LIMBS), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2GetAffine(SM2_AffinePoint *r, const SM2_point *a)
{
    BN_UINT zInv3[SM2_LIMBS] ALIGN32 = {0};
    BN_UINT zInv2[SM2_LIMBS] ALIGN32 = {0};
    if (IsZeros(a->z) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (IsEqual(a->z, g_one) != 0) {
        (void)memcpy_s(r->x, sizeof(r->x), a->x, sizeof(r->x));
        (void)memcpy_s(r->y, sizeof(r->y), a->y, sizeof(r->x));
        return CRYPT_SUCCESS;
    }

    ECP_Sm2ModInverse(zInv3, a->z);
    ECP_Sm2Sqr(zInv2, zInv3);
    ECP_Sm2Mul(r->x, a->x, zInv2);
    ECP_Sm2Mul(zInv3, zInv3, zInv2);
    ECP_Sm2Mul(r->y, a->y, zInv3);

    return CRYPT_SUCCESS;
}

int32_t ECP_Sm2Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (r == NULL || a == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || a->id != CRYPT_ECC_SM2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }

    SM2_point temp = {0};
    SM2_AffinePoint rTemp = {0};
    int32_t ret;
    GOTO_ERR_IF_EX(ECP_Sm2Point2Array(&temp, a), ret);
    GOTO_ERR_IF_EX(ECP_Sm2GetAffine(&rTemp, &temp), ret);
    GOTO_ERR_IF_EX(BN_Array2BN(&r->x, rTemp.x, SM2_LIMBS), ret);
    GOTO_ERR_IF_EX(BN_Array2BN(&r->y, rTemp.y, SM2_LIMBS), ret);
    GOTO_ERR_IF_EX(BN_SetLimb(&r->z, 1), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2PointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    return ECP_NistPointDouble(para, r, a);
}

int32_t ECP_Sm2PointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    return ECP_NistPointAddAffine(para, r, a, b);
}

static void ECP_Sm2ScalarMulG(SM2_point *r, const BN_UINT *k)
{
    const BN_UINT *precomputed = ECP_Sm2Precomputed();
    uint32_t index;
    for (int32_t i = SM2_BYTES_NUM - 1; i >= 0; --i) {
        index = (k[i / sizeof(BN_UINT)] >> (SM2_BITSOFBYTES * (i % sizeof(BN_UINT)))) & SM2_MASK2;
#ifndef HITLS_SM2_PRECOMPUTE_512K_TBL
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
        ECP_Sm2PointDoubleMont(r, r);
#endif
        if (index != 0) {
#ifdef HITLS_SM2_PRECOMPUTE_512K_TBL
            index = index + i * SM2_BITS;
#endif
            index = index * SM2_BITSOFBYTES;
            ECP_Sm2PointAddAffineMont(r, r, (const SM2_AffinePoint *)&precomputed[index]);
        }
    }
}

static int32_t ECP_Sm2WnafMul(SM2_point *r, const BN_BigNum *k, SM2_point p)
{
    ReCodeData *recodeK = ECC_ReCodeK(k, WINDOW_SIZE);
    if (recodeK == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    SM2_point doublePoint;
    SM2_point precomputed[PRECOMPUTED_TABLE_SIZE] ALIGN64;
    ECP_Sm2ToMont(precomputed[0].x, p.x);
    ECP_Sm2ToMont(precomputed[0].y, p.y);
    ECP_Sm2ToMont(precomputed[0].z, p.z);
    ECP_Sm2PointDoubleMont(&doublePoint, &precomputed[0]);

    (void)memcpy_s(precomputed[WINDOW_HALF_TABLE_SIZE].x, SM2_BYTES_NUM, precomputed[0].x, SM2_BYTES_NUM);
    ECP_Sm2Neg(precomputed[WINDOW_HALF_TABLE_SIZE].y, precomputed[0].y);
    (void)memcpy_s(precomputed[WINDOW_HALF_TABLE_SIZE].z, SM2_BYTES_NUM, precomputed[0].z, SM2_BYTES_NUM);

    for (uint32_t i = 1; i < WINDOW_HALF_TABLE_SIZE; i++) {
        ECP_Sm2PointAddMont(&precomputed[i], &precomputed[i - 1], &doublePoint); // 1, 3, 5, 7, 9, 11, 13, 15
        (void)memcpy_s(precomputed[i + WINDOW_HALF_TABLE_SIZE].x, SM2_BYTES_NUM, precomputed[i].x, SM2_BYTES_NUM);
        ECP_Sm2Neg(precomputed[i + WINDOW_HALF_TABLE_SIZE].y, precomputed[i].y);
        (void)memcpy_s(precomputed[i + WINDOW_HALF_TABLE_SIZE].z, SM2_BYTES_NUM, precomputed[i].z, SM2_BYTES_NUM);
    }
    int8_t index = SM2_NUMTOOFFSET(recodeK->num[0]);
    (void)memcpy_s(r, sizeof(SM2_point), &precomputed[index], sizeof(SM2_point));
    uint32_t w = recodeK->wide[0];
    while (w != 0) {
        ECP_Sm2PointDoubleMont(r, r);
        w--;
    }
    for (uint32_t i = 1; i < recodeK->size; i++) {
        index = SM2_NUMTOOFFSET(recodeK->num[i]);
        ECP_Sm2PointAddMont(r, r, &precomputed[index]);
        w = recodeK->wide[i];
        while (w != 0) {
            ECP_Sm2PointDoubleMont(r, r);
            w--;
        }
    }
    ECC_ReCodeFree(recodeK);
    return CRYPT_SUCCESS;
}

int32_t ECP_Sm2PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *scalar, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || scalar == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || (pt != NULL && (pt->id != CRYPT_ECC_SM2))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (pt != NULL && BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (BN_IsZero(scalar)) {
        return BN_Zeroize(&r->z);
    }
    int32_t ret;
    BN_UINT k[SM2_LIMBS] = {0};
    uint32_t klen = SM2_LIMBS;
    SM2_point re = {0};
    SM2_point sm2Pt = {0};
    GOTO_ERR_IF_EX(BN_Bn2U64Array(scalar, k, &klen), ret);
    if (pt == NULL) {
        // calculate k*G
        ECP_Sm2ScalarMulG(&re, k);
    } else {
        // point 2 affine
        GOTO_ERR_IF_EX(ECP_Sm2Point2Array(&sm2Pt, pt), ret);
        GOTO_ERR_IF_EX(ECP_Sm2WnafMul(&re, scalar, sm2Pt), ret);
    }
    ECP_Sm2FromMont(re.x, re.x);
    ECP_Sm2FromMont(re.y, re.y);
    ECP_Sm2FromMont(re.z, re.z);
    // SM2_point 2 ECC_Point
    GOTO_ERR_IF_EX(ECP_Sm2Array2Point(r, &re), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointMulFast(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    return ECP_Sm2PointMul(para, r, k, pt);
}

int32_t ECP_Sm2OrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    int32_t ret = BN_Extend(r, SM2_LIMBS);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ECP_Sm2InvModOrd(r->data, a->data);
    r->size = SM2_LIMBS;
    BN_FixSize(r);
    if (BN_IsZero(r)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    return CRYPT_SUCCESS;
}

static int32_t ECP_Sm2PointMulAddCheck(
    ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    bool flag = (para == NULL || r == NULL || k1 == NULL || k2 == NULL || pt == NULL);
    uint32_t bits1;
    uint32_t bits2;
    if (flag) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || pt->id != CRYPT_ECC_SM2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    // Special processing of the infinite point.
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    bits1 = BN_Bits(k1);
    bits2 = BN_Bits(k2);
    if (bits1 > SM2_BITS || bits2 > SM2_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }

    return CRYPT_SUCCESS;
}

// r = k1 * G + k2 * pt
int32_t ECP_Sm2PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    int32_t ret = ECP_Sm2PointMulAddCheck(para, r, k1, k2, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_UINT k1Uint[SM2_LIMBS] = {0};
    uint32_t k1Len = SM2_LIMBS;
    SM2_point k1G = {0};
    SM2_point k2Pt = {0};
    SM2_point sm2Pt = {0};
    GOTO_ERR_IF_EX(BN_Bn2U64Array(k1, k1Uint, &k1Len), ret);
    GOTO_ERR_IF_EX(ECP_Sm2Point2Array(&sm2Pt, pt), ret);

    // k1 * G
    ECP_Sm2ScalarMulG(&k1G, k1Uint);
    // k2 * pt
    GOTO_ERR_IF_EX(ECP_Sm2WnafMul(&k2Pt, k2, sm2Pt), ret);
    ECP_Sm2PointAddMont(&k2Pt, &k1G, &k2Pt);

    ECP_Sm2FromMont(k2Pt.x, k2Pt.x);
    ECP_Sm2FromMont(k2Pt.y, k2Pt.y);
    ECP_Sm2FromMont(k2Pt.z, k2Pt.z);
    GOTO_ERR_IF_EX(ECP_Sm2Array2Point(r, &k2Pt), ret);
ERR:
    return ret;
}

#endif
