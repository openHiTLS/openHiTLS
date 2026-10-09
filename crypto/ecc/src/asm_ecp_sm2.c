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
#include "bsl_util_internal.h"
#include "asm_ecp_sm2.h"

#define SM2_MASK2 0xff
#define WINDOW_SIZE 4
#define PRECOMPUTED_TABLE_SIZE (1 << WINDOW_SIZE)
#define WINDOW_HALF_TABLE_SIZE 8
#define SM2_NUMTOOFFSET(num) (((num) < 0) ? (WINDOW_HALF_TABLE_SIZE - 1 - (((num) - 1) >> 1)) : (((num) - 1) >> 1))

static const BN_UINT g_one[SM2_LIMBS] = {1, 0, 0, 0};

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

#ifdef HITLS_INT128
typedef int128_t Sm2SgWide;
typedef uint128_t Sm2SgUWide;
#define SM2_SG_BITS   60
#define SM2_SG_LIMBS  5
#define SM2_SG_ROUNDS 13
#else
typedef int64_t Sm2SgWide;
typedef uint64_t Sm2SgUWide;
#define SM2_SG_BITS   30
#define SM2_SG_LIMBS  9
#define SM2_SG_ROUNDS 25
#endif

#define SM2_SG_MASK ((((uint64_t)1) << SM2_SG_BITS) - 1)

typedef struct {
    int64_t value[SM2_SG_LIMBS];
    uint64_t inverse;
} Sm2SgModulus;

/* Radix-2^SM2_SG_BITS modulus and its inverse modulo 2^64. */
static const Sm2SgModulus g_sm2p = {
#ifdef HITLS_INT128
    {0xfffffffffffffff, 0xffffff00000000f, 0xfffffffffffffff, 0xfffefffffffffff, 0xffff},
#else
    {0x3fffffff, 0x3fffffff, 0xf, 0x3fffffc0, 0x3fffffff, 0x3fffffff, 0x3fffffff, 0x3fffbfff, 0xffff},
#endif
    0xffffffffffffffff
};

static const Sm2SgModulus g_sm2ord = {
#ifdef HITLS_INT128
    {0x3bbf40939d54123, 0x3df6b21c6052b5, 0xfffffffffffff72, 0xfffefffffffffff, 0xffff},
#else
    {0x39d54123, 0xeefd024, 0x1c6052b5, 0xf7dac8, 0x3fffff72, 0x3fffffff, 0x3fffffff, 0x3fffbfff, 0xffff},
#endif
    0xcd8061778dcaf68b
};

static int64_t Sm2Divsteps(int64_t eta, uint64_t f, uint64_t g, int64_t *outU, int64_t *outV, int64_t *outS,
                           int64_t *outT)
{
    uint64_t u = 1;
    uint64_t v = 0;
    uint64_t s = 0;
    uint64_t t = 1;
    for (uint32_t i = 0; i < SM2_SG_BITS; i++) {
        uint64_t neg = (uint64_t)(eta >> 63); /* Mask: eta < 0 ? 0xff..fff : 0. */
        uint64_t odd = (uint64_t)0 - (g & 1);
        g += (((f ^ neg) - neg) & odd); /* g += q*(eta < 0 ? -f : f). */
        s += (((u ^ neg) - neg) & odd); /* s += q*(eta < 0 ? -u : u). */
        t += (((v ^ neg) - neg) & odd); /* t += q*(eta < 0 ? -v : v). */
        neg &= odd; /* Swap mask: eta_old < 0 and q = 1. */
        eta = (int64_t)((uint64_t)eta ^ (uint64_t)neg) - 1; /* eta' = swap ? -eta_old-2 : eta_old-1. */
        f += g & neg; /* If swapping: f_old + (g_old - f_old) = g_old. */
        u += s & neg; /* If swapping: u_old + (s_old - u_old) = s_old. */
        v += t & neg; /* If swapping: v_old + (t_old - v_old) = t_old. */
        g >>= 1; /* g' = (g_old + q*(eta_old < 0 ? -f_old : f_old))/2, retaining low bits. */
        u <<= 1; /* Scale u by 2 to share the new denominator 2^(i+1). */
        v <<= 1; /* Scale v by 2 to share the new denominator 2^(i+1). */
    }
    *outU = (int64_t)u;
    *outV = (int64_t)v;
    *outS = (int64_t)s;
    *outT = (int64_t)t;
    return eta;
}

static void Sm2UpdateFg(int64_t *f, int64_t *g, int64_t u, int64_t v, int64_t s, int64_t t)
{
    Sm2SgWide cf = ((Sm2SgWide)u * f[0] + (Sm2SgWide)v * g[0]) >> SM2_SG_BITS;
    Sm2SgWide cg = ((Sm2SgWide)s * f[0] + (Sm2SgWide)t * g[0]) >> SM2_SG_BITS;
    for (uint32_t i = 1; i < SM2_SG_LIMBS; i++) {
        cf += (Sm2SgWide)u * f[i] + (Sm2SgWide)v * g[i]; /* Add limb i products to the signed carry. */
        cg += (Sm2SgWide)s * f[i] + (Sm2SgWide)t * g[i]; /* Add limb i products to the signed carry. */
        f[i - 1] = (int64_t)((Sm2SgUWide)cf & SM2_SG_MASK); /* Division by 2^k moves limb i to i-1. */
        g[i - 1] = (int64_t)((Sm2SgUWide)cg & SM2_SG_MASK); /* Store the quotient limb's low k bits. */
        cf >>= SM2_SG_BITS; /* Propagate the signed carry to the next limb. */
        cg >>= SM2_SG_BITS; /* Propagate the signed carry to the next limb. */
    }
    f[SM2_SG_LIMBS - 1] = (int64_t)cf; /* Keep the signed top limb of (u*f_old+v*g_old)/2^k. */
    g[SM2_SG_LIMBS - 1] = (int64_t)cg; /* Keep the signed top limb of (s*f_old+t*g_old)/2^k. */
}

/* B = 2^SM2_SG_BITS, N = sum(modulus[i]*B^i), inverse*N = 1 (mod B).
 * Preserve f = d*a (mod N), g = e*a (mod N) for the original input a:
 * d_new = (u*d_old + v*e_old + md*N)/B; e_new = (s*d_old + t*e_old + me*N)/B.
 */
static void Sm2UpdateDe(int64_t *d, int64_t *e, int64_t u, int64_t v, int64_t s, int64_t t,
                        const int64_t *modulus, uint64_t inverse)
{
    int64_t sd = d[SM2_SG_LIMBS - 1] >> 63; /* sd = d < 0 ? -1 : 0. */
    int64_t se = e[SM2_SG_LIMBS - 1] >> 63; /* se = e < 0 ? -1 : 0. */
    int64_t md = (u & sd) + (v & se); /* md = (d < 0 ? u : 0) + (e < 0 ? v : 0). */
    int64_t me = (s & sd) + (t & se); /* me = (d < 0 ? s : 0) + (e < 0 ? t : 0). */
    Sm2SgWide cd = (Sm2SgWide)u * d[0] + (Sm2SgWide)v * e[0];
    Sm2SgWide ce = (Sm2SgWide)s * d[0] + (Sm2SgWide)t * e[0];
    md -= (int64_t)((inverse * (uint64_t)cd + (uint64_t)md) & SM2_SG_MASK);
    me -= (int64_t)((inverse * (uint64_t)ce + (uint64_t)me) & SM2_SG_MASK);
    cd = (cd + (Sm2SgWide)modulus[0] * md) >> SM2_SG_BITS;
    ce = (ce + (Sm2SgWide)modulus[0] * me) >> SM2_SG_BITS;
    for (uint32_t i = 1; i < SM2_SG_LIMBS; i++) {
        cd += (Sm2SgWide)u * d[i] + (Sm2SgWide)v * e[i] + (Sm2SgWide)modulus[i] * md;
        ce += (Sm2SgWide)s * d[i] + (Sm2SgWide)t * e[i] + (Sm2SgWide)modulus[i] * me;
        d[i - 1] = (int64_t)((Sm2SgUWide)cd & SM2_SG_MASK);
        e[i - 1] = (int64_t)((Sm2SgUWide)ce & SM2_SG_MASK);
        cd >>= SM2_SG_BITS;
        ce >>= SM2_SG_BITS;
    }
    d[SM2_SG_LIMBS - 1] = (int64_t)cd;
    e[SM2_SG_LIMBS - 1] = (int64_t)ce;
}

static void Sm2Normalize(int64_t *r, int64_t sign, const int64_t *modulus)
{
    int64_t addMask = r[SM2_SG_LIMBS - 1] >> 63; /* addMask = r < 0 ? -1 : 0; initially -2N < r < N. */
    for (uint32_t i = 0; i < SM2_SG_LIMBS; i++) {
        r[i] += modulus[i] & addMask; /* r += (r_old < 0 ? N : 0), giving -N < r < N. */
    }
    int64_t negMask = sign >> 63; /* negMask = sign < 0 ? -1 : 0. */
    for (uint32_t i = 0; i < SM2_SG_LIMBS; i++) {
        r[i] = (r[i] ^ negMask) - negMask; /* r[i] = sign < 0 ? -r[i] : r[i]; still -N < r < N. */
    }
    for (uint32_t i = 0; i < SM2_SG_LIMBS - 1; i++) {
        r[i + 1] += r[i] >> SM2_SG_BITS; /* r[i+1] += floor(r[i]/2^k), k = SM2_SG_BITS. */
        r[i] = (int64_t)((uint64_t)r[i] & SM2_SG_MASK); /* r[i] = r[i] mod 2^k, in [0, 2^k). */
    }
    addMask = r[SM2_SG_LIMBS - 1] >> 63; /* addMask = r < 0 ? -1 : 0 after carry propagation. */
    for (uint32_t i = 0; i < SM2_SG_LIMBS; i++) {
        r[i] += modulus[i] & addMask; /* r += (r_old < 0 ? N : 0), giving 0 <= r < N. */
    }
    for (uint32_t i = 0; i < SM2_SG_LIMBS - 1; i++) {
        r[i + 1] += r[i] >> SM2_SG_BITS; /* r[i+1] += floor(r[i]/2^k). */
        r[i] = (int64_t)((uint64_t)r[i] & SM2_SG_MASK); /* r[i] = r[i] mod 2^k, preserving the full value. */
    }
}

static void Sm2ToRadix(int64_t *r, const BN_UINT *a)
{
    for (uint32_t i = 0; i < SM2_SG_LIMBS; i++) {
        uint32_t bit = i * SM2_SG_BITS;
        uint32_t word = bit / 64;
        uint32_t shift = bit % 64;
        BN_UINT value = a[word] >> shift;
        if (shift != 0 && word + 1 < SM2_LIMBS) {
            value |= a[word + 1] << (64 - shift);
        }
        r[i] = (int64_t)((uint64_t)value & SM2_SG_MASK);
    }
}

static void Sm2FromRadix(BN_UINT *a, const int64_t *r)
{
    memset(a, 0, SM2_BYTES_NUM);
    for (uint32_t i = 0; i < SM2_SG_LIMBS; i++) {
        uint32_t bit = i * SM2_SG_BITS;
        uint32_t word = bit / 64;
        uint32_t shift = bit % 64;
        BN_UINT value = (BN_UINT)((uint64_t)r[i] & SM2_SG_MASK);
        a[word] |= value << shift;
        if (shift != 0 && word + 1 < SM2_LIMBS) {
            a[word + 1] |= value >> (64 - shift);
        }
    }
}

/*
 * Bernstein and Yang, "Fast constant-time gcd computation and modular inversion",
 * 2019-04-13, Theorem 11.2, p. 27: for 256-bit inputs with odd modulus,
 * floor((49*256 + 57)/17) = 741 divsteps suffice for g = 0.
 * Both fixed schedules exceed this bound: 13x60 or 25x30 divsteps.
 * https://gcd.cr.yp.to/safegcd-20190413.pdf#page=27
 */
static void ECP_Sm2SafegcdInv(BN_UINT *out, const BN_UINT *in, const Sm2SgModulus *modulus)
{
    int64_t d[SM2_SG_LIMBS] = {0};
    int64_t e[SM2_SG_LIMBS] = {1};
    int64_t f[SM2_SG_LIMBS];
    int64_t g[SM2_SG_LIMBS];
    const int64_t *mod = modulus->value;
    int64_t u;
    int64_t v;
    int64_t s;
    int64_t t;
    int64_t eta = -1;
    memcpy(f, mod, sizeof(f));
    Sm2ToRadix(g, in);

    for (uint32_t i = 0; i < SM2_SG_ROUNDS; i++) {
        eta = Sm2Divsteps(eta, (uint64_t)f[0], (uint64_t)g[0], &u, &v, &s, &t);
        Sm2UpdateFg(f, g, u, v, s, t);
        Sm2UpdateDe(d, e, u, v, s, t, mod, modulus->inverse);
    }
    Sm2Normalize(d, f[SM2_SG_LIMBS - 1], mod);
    Sm2FromRadix(out, d);
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

    ECP_Sm2SafegcdInv(zInv3, a->z, &g_sm2p);
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
    if (recodeK->size == 0) {
        ECC_ReCodeFree(recodeK);
        return CRYPT_SUCCESS;
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
    BSL_SAL_CleanseData(k, sizeof(k));
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
    if (BN_Cmp(para->n, a) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    BN_UINT input[SM2_LIMBS] = {0};
    uint32_t len = SM2_LIMBS;
    int32_t ret = BN_Bn2U64Array(a, input, &len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = BN_Extend(r, SM2_LIMBS);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(input, sizeof(input));
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ECP_Sm2SafegcdInv(r->data, input, &g_sm2ord);
    BSL_SAL_CleanseData(input, sizeof(input));
    r->size = SM2_LIMBS;
    r->sign = false;
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
    BSL_SAL_CleanseData(k1Uint, SM2_LIMBS * sizeof(BN_UINT));
    return ret;
}

#endif
