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
#ifdef HITLS_CRYPTO_ECC_LITE

#include <string.h>
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "bn_bincal.h"
#include "crypt_utils.h"
#include "ecc_local.h"
#include "crypt_ecc_pkey.h"

static BN_UINT liteBinAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    BN_UINT carry = 0;
    for (uint32_t i = 0; i < n; i++) {
        BN_UINT sum = a[i] + b[i];
        BN_UINT value = sum + carry;
        carry = (sum < a[i]) | (value < sum);
        r[i] = value;
    }
    return carry;
}

static BN_UINT liteBinSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    BN_UINT borrow = 0;
    for (uint32_t i = 0; i < n; i++) {
        BN_UINT difference = a[i] - b[i];
        BN_UINT value = difference - borrow;
        borrow = (a[i] < b[i]) | (difference < borrow);
        r[i] = value;
    }
    return borrow;
}

void EccLiteBnFree(ECC_LiteBn *a)
{
    BSL_SAL_ClearFree(a, sizeof(ECC_LiteBn));
}

void EccLiteBnZero(ECC_LiteBn *a)
{
    (void)memset(a->data, 0, sizeof(a->data));
}

void EccLiteBnSetLimb(ECC_LiteBn *r, BN_UINT w)
{
    EccLiteBnZero(r);
    r->data[0] = w;
}

static bool EccLiteWordsIsZero(const BN_UINT *a, uint32_t n)
{
    BN_UINT acc = 0;
    for (uint32_t i = 0; i < n; i++) {
        acc |= a[i];
    }
    return acc == 0;
}

bool EccLiteBnIsZero(const ECC_LiteBn *a)
{
    return EccLiteWordsIsZero(a->data, ECC_LITE_MAX_WORDS);
}

bool EccLiteBnIsOne(const ECC_LiteBn *a)
{
    BN_UINT acc = a->data[0] ^ 1u;
    for (uint32_t i = 1; i < ECC_LITE_MAX_WORDS; i++) {
        acc |= a->data[i];
    }
    return acc == 0;
}

bool EccLiteBnLessThan(const ECC_LiteBn *a, const BN_UINT *b, uint32_t words)
{
    bool less = false;
    for (uint32_t i = 0; i < words; i++) {
        less = (a->data[i] < b[i]) | ((a->data[i] == b[i]) & less);
    }
    return less & EccLiteWordsIsZero(a->data + words, ECC_LITE_MAX_WORDS - words);
}

void EccLiteBnCopy(ECC_LiteBn *r, const ECC_LiteBn *a)
{
    (void)memcpy(r->data, a->data, sizeof(r->data));
}

int32_t EccLiteBnBin2Bn(ECC_LiteBn *r, const uint8_t *bin, uint32_t binLen, uint32_t maxBytes)
{
    if (binLen > maxBytes || binLen > ECC_LITE_MAX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_BITS_TOO_MAX);
        return CRYPT_BN_BITS_TOO_MAX;
    }

    EccLiteBnZero(r);
    for (uint32_t i = 0; i < binLen; i++) {
        uint32_t src = binLen - 1u - i;
        uint32_t word = i / sizeof(BN_UINT);
        uint32_t shift = (i % sizeof(BN_UINT)) * 8u;
        r->data[word] |= ((BN_UINT)bin[src]) << shift;
    }
    return CRYPT_SUCCESS;
}

void EccLiteBnSetWords(ECC_LiteBn *r, const BN_UINT *data, uint32_t size)
{
    EccLiteBnZero(r);
    if (size != 0) {
        (void)memcpy(r->data, data, size * sizeof(BN_UINT));
    }
}

/*
 * Montgomery-domain fixed-limb field arithmetic for NIST P-192/P-256, operating
 * on raw BN_UINT[n] limb arrays (n = 3 for P-192, 4 for P-256).
 *
 * For both primes the low 64-bit limb of p is 2^64 - 1, so p == -1 (mod 2^64)
 * and the Montgomery constant n0' == -p^-1 == 1 (mod 2^64); the reduction below
 * exploits n0' == 1 (the per-limb multiplier is simply the running low limb).
 * Field elements are kept in Montgomery form (a*R mod p, R = 2^(64*n)) in the
 * range [0, p), so a single Montgomery multiply implements one modular multiply.
 */
/* Add mod back when subtraction borrowed; borrow is 0 or 1. */
static void LiteFReduce(BN_UINT *r, const BN_UINT *mod, uint32_t n, BN_UINT borrow)
{
    BN_UINT mask = (BN_UINT)0 - (borrow & 1u);
    BN_UINT carry = 0;
    for (uint32_t i = 0; i < n; i++) {
        ADD_ABC(carry, r[i], r[i], mod[i] & mask, carry);
    }
}

/* r = a * b * R^-1 mod p, with a, b, r < p in Montgomery form. n0' == 1. */
static void LiteFMul(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, const BN_UINT *mod, uint32_t n)
{
    ALIGN32 BN_UINT t[(ECC_LITE_MAX_WORDS * 2u) + 2u] = {0};
    // Form the full product before Montgomery reduction.
    for (uint32_t i = 0; i < n; i++) {
        BN_UINT carry = 0;
        for (uint32_t j = 0; j < n; j++) {
            MULADC_AB(t[i + j], a[i], b[j], carry);
        }
        t[i + n] = carry;
    }
    for (uint32_t i = 0; i < n; i++) {
        BN_UINT m = t[i]; // m = t[i] * n0', n0' == 1.
        BN_UINT carry = 0;
        // Add m * mod * 2^(64*i); mod[0] == -1 makes limb i zero.
        for (uint32_t j = 0; j < n; j++) {
            MULADC_AB(t[i + j], m, mod[j], carry);
        }
        // Propagate carry through t[2n] now; always visit every remaining limb.
        for (uint32_t k = i + n; k <= (n << 1); k++) {
            BN_UINT addCarry = 0;
            ADD_AB(addCarry, t[k], t[k], carry);
            carry = addCarry;
        }
    }
    // The low n limbs are zero; t + n represents division by R.
    // The result is < 2p; t[2n] cancels the low-limb borrow.
    BN_UINT borrow = liteBinSub(r, t + n, mod, n);
    LiteFReduce(r, mod, n, borrow ^ t[n << 1]);
    BSL_SAL_CleanseData(t, sizeof(t));
}

/* r = a + b mod p (constant-time), a, b, r < p. */
static void LiteFAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, const BN_UINT *mod, uint32_t n)
{
    BN_UINT carry = liteBinAdd(r, a, b, n);
    BN_UINT borrow = liteBinSub(r, r, mod, n);
    LiteFReduce(r, mod, n, borrow ^ carry);
}

/* r = a - b mod p (constant-time), a, b, r < p. */
static void LiteFSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, const BN_UINT *mod, uint32_t n)
{
    BN_UINT borrow = liteBinSub(r, a, b, n);
    LiteFReduce(r, mod, n, borrow);
}

static void LiteFToMont(BN_UINT *r, const BN_UINT *a, const ECC_Para *para)
{
    LiteFMul(r, a, EccLiteParaData(para, ECC_LITE_RR), EccLiteParaData(para, ECC_LITE_P), para->words);
}

static void LiteFFromMont(BN_UINT *r, const BN_UINT *a, const BN_UINT *mod, uint32_t n)
{
    ALIGN32 BN_UINT one[ECC_LITE_MAX_WORDS] = {1u};
    LiteFMul(r, a, one, mod, n);
}

/*
 * Modular inverse via Fermat's little theorem: r = a^(p-2) mod p, computed with
 * Montgomery squarings/multiplications so the result stays in Montgomery form.
 * The exponent (p-2) is public, so the square-and-multiply schedule is
 * independent of the secret operand (constant time w.r.t. a).
 */
static void LiteFInv(BN_UINT *r, const BN_UINT *a, const ECC_Para *para)
{
    const BN_UINT *mod = EccLiteParaData(para, ECC_LITE_P);
    uint32_t n = para->words;
    ALIGN32 BN_UINT base[ECC_LITE_MAX_WORDS];
    (void)memcpy(base, a, para->bytes);
    (void)memcpy(r, EccLiteParaData(para, ECC_LITE_ONE), para->bytes);
    for (uint32_t i = n; i > 0u; i--) {
        // Both primes end in UINT64_MAX, so p - 2 changes only the low limb.
        BN_UINT exp = mod[i - 1u] - (i == 1u ? 2u : 0u);
        for (uint32_t bit = BN_UINT_BITS; bit > 0u; bit--) {
            LiteFMul(r, r, r, mod, n);
            if (((exp >> (bit - 1u)) & 1u) != 0) {
                LiteFMul(r, r, base, mod, n);
            }
        }
    }
    BSL_SAL_CleanseData(base, sizeof(base));
}

/*
 * Scalar multiplication for NIST P-192/P-256 (a = -3).
 *
 * The kernel is a differential (x-only) Montgomery ladder in projective (X:Z)
 * coordinates, using Izu-Takagi addition and Brier-Joye y-recovery.
 * Field elements are raw limb arrays kept in
 * Montgomery form, so each modular multiply is a single Montgomery
 * multiplication. The straight-line point formulas (double-base, combined
 * double-and-add, and the co-Z y-recovery) are encoded as compact bytecode
 * tables executed by a tiny interpreter (LiteRunProg); this keeps the field
 * schedule in read-only data instead of unrolled call sequences, which is far
 * smaller than inlining every operation.
 *
 * Side-channel hardening:
 *   - the scalar is regularized to a fixed bit length (k + n or k + 2n) so the
 *     loop always runs the same number of iterations regardless of the key;
 *   - ladder registers are exchanged with a constant-time conditional swap;
 *   - the field schedule is a fixed program, independent of the operands;
 *   - the final inversion uses Fermat's little theorem (LiteFInv).
 */
typedef BN_UINT Fe[ECC_LITE_MAX_WORDS];

/* Bytecode: each instruction is {op, dst, src1, src2}; OP_END terminates. */
#define OP_END 0
#define OP_MUL 1
#define OP_ADD 2
#define OP_SUB 3
#define OP_INV 4

/* Register file layout shared by all programs. */
#define RG_R0X 0
#define RG_R0Z 1
#define RG_R1X 2
#define RG_R1Z 3
#define RG_A   4
#define RG_B   5
#define RG_XP  6
#define RG_YP  7
#define RG_ONE 8
#define RG_T0  9
#define RG_T1  10
#define RG_T2  11
#define RG_T3  12
#define RG_T4  13
#define RG_T5  14
#define NREG   15

/* Formulas use x = X/Z and curve coefficients a, b; all field values are Montgomery encoded. */
/* MontLadderDouble: R1 = 2P, with affine P = (x, y). */
static const uint8_t LITE_DBL_BASE[] = {
    OP_MUL, RG_T0,  RG_XP,  RG_XP,  // x^2
    OP_ADD, RG_T1,  RG_XP,  RG_XP,  // 2*x
    OP_ADD, RG_T1,  RG_T1,  RG_T1,  // E = 4*x
    OP_SUB, RG_T2,  RG_T0,  RG_A,   // x^2 - a
    OP_ADD, RG_T3,  RG_T0,  RG_A,   // x^2 + a
    OP_MUL, RG_R1X, RG_T2,  RG_T2,  // (x^2 - a)^2
    OP_MUL, RG_T4,  RG_B,   RG_T1,  // b*E
    OP_SUB, RG_R1X, RG_R1X, RG_T4,  // (x^2 - a)^2 - b*E
    OP_SUB, RG_R1X, RG_R1X, RG_T4,  // X1 = (x^2 - a)^2 - 2*b*E
    OP_MUL, RG_R1Z, RG_T1,  RG_T3,  // E*(x^2 + a)
    OP_ADD, RG_T4,  RG_B,   RG_B,   // 2*b
    OP_ADD, RG_T4,  RG_T4,  RG_T4,  // 4*b
    OP_ADD, RG_R1Z, RG_R1Z, RG_T4,  // Z1 = E*(x^2 + a) + 4*b
    OP_END, 0,      0,      0,
};

/*
 * Izu-Takagi: (R0, R1) <- (2*R0, R0 + R1), with x(R1 - R0) = x.
 * https://hyperelliptic.org/EFD/g1p/auto-shortw-xz.html#diffadd-mdadd-2002-it-4
 * https://hyperelliptic.org/EFD/g1p/auto-shortw-xz.html#doubling-dbl-2002-bj-3
 */
static const uint8_t LITE_DBL_ADD[] = {
    OP_MUL, RG_T0,  RG_R0X, RG_R1X, // T1 = X0*X1
    OP_MUL, RG_T1,  RG_R0Z, RG_R1Z, // T2 = Z0*Z1
    OP_MUL, RG_T2,  RG_R0X, RG_R1Z, // T3 = X0*Z1
    OP_MUL, RG_T3,  RG_R0Z, RG_R1X, // T4 = Z0*X1
    OP_MUL, RG_R1X, RG_A,   RG_T1,  // X1 = a*T2
    OP_ADD, RG_R1X, RG_T0,  RG_R1X, // X1 = T1 + X1
    OP_ADD, RG_T0,  RG_T2,  RG_T3,  // T1 = T3 + T4
    OP_MUL, RG_R1X, RG_R1X, RG_T0,  // X1 = X1*T1
    OP_ADD, RG_R1X, RG_R1X, RG_R1X, // X1 = X1 + X1
    OP_MUL, RG_T0,  RG_T1,  RG_T1,  // T1 = T2^2
    OP_MUL, RG_T0,  RG_T0,  RG_B,   // T1 = b*T1
    OP_ADD, RG_T0,  RG_T0,  RG_T0,  // T1 = T1 + T1
    OP_ADD, RG_T0,  RG_T0,  RG_T0,  // T1 = T1 + T1
    OP_ADD, RG_R1X, RG_R1X, RG_T0,  // X1 = X1 + T1
    OP_SUB, RG_T2,  RG_T2,  RG_T3,  // T3 = T3 - T4
    OP_MUL, RG_R1Z, RG_T2,  RG_T2,  // Z1' = T3^2
    OP_MUL, RG_T2,  RG_XP,  RG_R1Z, // T3 = x*Z1'
    OP_SUB, RG_R1X, RG_R1X, RG_T2,  // X1' = X1 - T3
    OP_MUL, RG_T0,  RG_R0X, RG_R0X, // T1 = X0^2
    OP_MUL, RG_T1,  RG_R0Z, RG_R0Z, // T2 = Z0^2
    OP_MUL, RG_T2,  RG_R0X, RG_R0Z, // T3 = X0*Z0
    OP_ADD, RG_T2,  RG_T2,  RG_T2,  // T3 = T3 + T3
    OP_ADD, RG_T2,  RG_T2,  RG_T2,  // T3 = T3 + T3
    OP_MUL, RG_T3,  RG_A,   RG_T1,  // T4 = a*T2
    OP_SUB, RG_R0X, RG_T0,  RG_T3,  // X0 = T1 - T4
    OP_ADD, RG_R0Z, RG_T0,  RG_T3,  // Z0 = T1 + T4
    OP_MUL, RG_R0Z, RG_T2,  RG_R0Z, // Z0 = T3*Z0
    OP_MUL, RG_T3,  RG_T2,  RG_T1,  // T4 = T3*T2
    OP_MUL, RG_T3,  RG_T3,  RG_B,   // T4 = b*T4
    OP_ADD, RG_T3,  RG_T3,  RG_T3,  // T4 = T4 + T4
    OP_MUL, RG_R0X, RG_R0X, RG_R0X, // X0 = X0^2
    OP_SUB, RG_R0X, RG_R0X, RG_T3,  // X0' = X0 - T4
    OP_MUL, RG_T3,  RG_T1,  RG_T1,  // T4 = T2^2
    OP_MUL, RG_T3,  RG_T3,  RG_B,   // T4 = b*T4
    OP_ADD, RG_T3,  RG_T3,  RG_T3,  // T4 = T4 + T4
    OP_ADD, RG_T3,  RG_T3,  RG_T3,  // T4 = T4 + T4
    OP_ADD, RG_R0Z, RG_R0Z, RG_T3,  // Z0' = Z0 + T4
    OP_END, 0,      0,      0,
};

/*
 * MontLadderRecoverYAndToMont formulas, with R1 = R0 + P and Q = Z1*Z0^2:
 * N = 2*b*Q + Z1*(a*Z0 + x*X0)*(x*Z0 + X0) - X1*(x*Z0 - X0)^2; D = 2*y*Q.
 * RG_T4 = X0/Z0 and RG_T5 = N/D share one inversion; outputs stay Montgomery encoded.
 */
static const uint8_t LITE_RECOVER[] = {
    OP_MUL, RG_T0,  RG_R0Z, RG_R0Z, // Z0^2
    OP_MUL, RG_T0,  RG_T0,  RG_R1Z, // Q = Z1*Z0^2
    OP_ADD, RG_T1,  RG_B,   RG_B,   // 2*b
    OP_MUL, RG_T1,  RG_T0,  RG_T1,  // 2*b*Q
    OP_MUL, RG_T2,  RG_A,   RG_R0Z, // a*Z0
    OP_MUL, RG_T3,  RG_XP,  RG_R0X, // x*X0
    OP_ADD, RG_T2,  RG_T2,  RG_T3,  // a*Z0 + x*X0
    OP_MUL, RG_T3,  RG_XP,  RG_R0Z, // x*Z0
    OP_ADD, RG_T3,  RG_T3,  RG_R0X, // x*Z0 + X0
    OP_MUL, RG_T2,  RG_T2,  RG_R1Z, // Z1*(a*Z0 + x*X0)
    OP_MUL, RG_T2,  RG_T2,  RG_T3,  // Z1*(a*Z0 + x*X0)*(x*Z0 + X0)
    OP_MUL, RG_T3,  RG_XP,  RG_R0Z, // x*Z0
    OP_SUB, RG_T3,  RG_T3,  RG_R0X, // x*Z0 - X0
    OP_MUL, RG_T3,  RG_T3,  RG_T3,  // (x*Z0 - X0)^2
    OP_MUL, RG_T3,  RG_T3,  RG_R1X, // X1*(x*Z0 - X0)^2
    OP_ADD, RG_T1,  RG_T1,  RG_T2,  // 2*b*Q + Z1*(a*Z0 + x*X0)*(x*Z0 + X0)
    OP_SUB, RG_T1,  RG_T1,  RG_T3,  // N: subtract X1*(x*Z0 - X0)^2
    OP_MUL, RG_T1,  RG_T1,  RG_R0Z, // N*Z0
    OP_MUL, RG_T2,  RG_T0,  RG_YP,  // y*Q
    OP_ADD, RG_T2,  RG_T2,  RG_T2,  // D = 2*y*Q
    OP_MUL, RG_T4,  RG_R0X, RG_T2,  // X0*D
    OP_MUL, RG_T2,  RG_T2,  RG_R0Z, // D*Z0
    OP_INV, RG_T2,  RG_T2,  0,      // (D*Z0)^-1
    OP_MUL, RG_T4,  RG_T4,  RG_T2,  // Affine x = X0/Z0
    OP_MUL, RG_T5,  RG_T1,  RG_T2,  // Affine y = N/D
    OP_END, 0,      0,      0,
};

/*
 * Affine y^2 = x^3 - 3*x + b: RG_R0X = x, RG_R0Z = y, RG_R1X = b.
 * The caller compares RG_T0 (right side) with RG_T1 (left side).
 */
static const uint8_t LITE_ON_CURVE[] = {
    OP_MUL, RG_T0,  RG_R0X, RG_R0X, // x^2
    OP_MUL, RG_T0,  RG_T0,  RG_R0X, // x^3
    OP_ADD, RG_T1,  RG_R0X, RG_R0X, // 2*x
    OP_ADD, RG_T1,  RG_T1,  RG_R0X, // 3*x
    OP_SUB, RG_T0,  RG_T0,  RG_T1,  // x^3 - 3*x
    OP_ADD, RG_T0,  RG_T0,  RG_R1X, // x^3 - 3*x + b
    OP_MUL, RG_T1,  RG_R0Z, RG_R0Z, // y^2
    OP_END, 0,      0,      0,
};

static void LiteRunProg(const uint8_t *prog, Fe *reg, const ECC_Para *para)
{
    const BN_UINT *p = EccLiteParaData(para, ECC_LITE_P);
    uint32_t n = para->words;
    for (; prog[0] != OP_END; prog += 4) {
        BN_UINT *d = reg[prog[1]];
        const BN_UINT *s1 = reg[prog[2]];
        const BN_UINT *s2 = reg[prog[3]];
        switch (prog[0]) {
            case OP_MUL:
                LiteFMul(d, s1, s2, p, n);
                break;
            case OP_ADD:
                LiteFAdd(d, s1, s2, p, n);
                break;
            case OP_SUB:
                LiteFSub(d, s1, s2, p, n);
                break;
            default:
                LiteFInv(d, s1, para);
                break;
        }
    }
}

static int32_t ECP_PointAtInfinity(const ECC_Para *para, const ECC_Point *pt)
{
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (EccLiteBnIsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    return CRYPT_SUCCESS;
}

static int32_t ECP_PointOnCurve(const ECC_Para *para, const ECC_Point *pt)
{
    int32_t ret = ECP_PointAtInfinity(para, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (!EccLiteBnIsOne(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_NOT_AFFINE);
        return CRYPT_ECC_POINT_NOT_AFFINE;
    }

    uint32_t n = para->words;
    ALIGN32 Fe reg[NREG] = {0};
    (void)memcpy(reg[RG_R0X], pt->x.data, sizeof(Fe));
    (void)memcpy(reg[RG_R0Z], pt->y.data, sizeof(Fe));
    (void)memcpy(reg[RG_R1X], EccLiteParaData(para, ECC_LITE_BM), para->bytes);
    LiteRunProg(LITE_ON_CURVE, reg, para);
    if (ConstTimeMemcmp((const uint8_t *)reg[RG_T0], (const uint8_t *)reg[RG_T1], n * sizeof(BN_UINT)) != 0xffffffffu) {
        ret = CRYPT_ECC_POINT_NOT_ON_CURVE;
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void LitePointSwap(Fe *reg, BN_UINT mask)
{
    BinSwapMaskedConsttime(reg[RG_R0X], reg[RG_R1X], ECC_LITE_MAX_WORDS, mask);
    BinSwapMaskedConsttime(reg[RG_R0Z], reg[RG_R1Z], ECC_LITE_MAX_WORDS, mask);
}

int32_t ECP_LitePointMul(ECC_Para *para, ECC_Point *r, const ECC_LiteBn *k, const ECC_Point *pt)
{
    if (pt != NULL && !EccLiteBnIsOne(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }

    const BN_UINT *p = EccLiteParaData(para, ECC_LITE_P);
    uint32_t n = para->words;
    ALIGN32 Fe reg[NREG] = {0};
    for (uint32_t i = 0; i <= RG_ONE - RG_A; i++) {
        (void)memcpy(reg[RG_A + i], EccLiteParaData(para, ECC_LITE_AM + i), para->bytes);
    }
    if (pt != NULL) {
        (void)memcpy(reg[RG_XP], pt->x.data, sizeof(Fe));
        (void)memcpy(reg[RG_YP], pt->y.data, sizeof(Fe));
    }
    (void)memcpy(reg[RG_R0X], reg[RG_XP], sizeof(Fe));
    (void)memcpy(reg[RG_R0Z], reg[RG_ONE], sizeof(Fe));
    LiteRunProg(LITE_DBL_BASE, reg, para); // R1 = 2 * base

    // dblAdd leaves T4/T5 unused. Select k+n or k+2n with an implicit high 1 bit.
    uint32_t numBits = para->bytes * 8u;
    BN_UINT *kk = reg[RG_T4];
    BN_UINT *k1 = reg[RG_T5];
    const BN_UINT *order = EccLiteParaData(para, ECC_LITE_N);
    BN_UINT carry = liteBinAdd(kk, k->data, order, n);
    (void)liteBinAdd(k1, kk, order, n);
    BinSelectByMaskConsttime(kk, kk, k1, n, (BN_UINT)0 - carry);

    BN_UINT prev = 0;
    for (uint32_t i = numBits; i > 0u; i--) {
        BN_UINT bit = (kk[(i - 1u) / BN_UINT_BITS] >> ((i - 1u) % BN_UINT_BITS)) & 1u;
        BN_UINT mask = (BN_UINT)0 - (bit ^ prev);
        LitePointSwap(reg, mask);
        LiteRunProg(LITE_DBL_ADD, reg, para);
        prev = bit;
    }
    LitePointSwap(reg, (BN_UINT)0 - prev);

    BN_UINT infinity = (BN_UINT)EccLiteWordsIsZero(reg[RG_R0Z], n);
    BN_UINT negative = (BN_UINT)0 - (BN_UINT)EccLiteWordsIsZero(reg[RG_R1Z], n);
    LiteRunProg(LITE_RECOVER, reg, para);
    (void)memset(reg[RG_T0], 0, sizeof(Fe));
    LiteFSub(reg[RG_T0], reg[RG_T0], reg[RG_YP], p, n);
    BinSelectByMaskConsttime(reg[RG_T4], reg[RG_XP], reg[RG_T4], n, negative);
    BinSelectByMaskConsttime(reg[RG_T5], reg[RG_T0], reg[RG_T5], n, negative);
    r->id = para->id;
    EccLiteBnSetWords(&r->x, reg[RG_T4], n);
    EccLiteBnSetWords(&r->y, reg[RG_T5], n);
    EccLiteBnSetLimb(&r->z, 1u ^ infinity);
    BSL_SAL_CleanseData(reg, sizeof(reg));
    return CRYPT_SUCCESS;
}

static int32_t LiteDecodePointCheck(const ECC_Para *para, const ECC_Point *pt, const uint8_t *data, uint32_t dataLen)
{
    if (para == NULL || pt == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (dataLen != ((para->bytes << 1) + 1u) || data[0] != 0x04u) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_ERR_POINT_CODE);
        return CRYPT_ECC_ERR_POINT_CODE;
    }
    return CRYPT_SUCCESS;
}

int32_t ECC_DecodePoint(const ECC_Para *para, ECC_Point *pt, const uint8_t *data, uint32_t dataLen)
{
    int32_t ret = LiteDecodePointCheck(para, pt, data, dataLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    EccLiteBnSetLimb(&pt->z, 1u);
    GOTO_ERR_IF_EX(EccLiteBnBin2Bn(&pt->x, data + 1, para->bytes, para->bytes), ret);
    GOTO_ERR_IF_EX(EccLiteBnBin2Bn(&pt->y, data + 1 + para->bytes, para->bytes, para->bytes), ret);
    if (!EccLiteBnLessThan(&pt->x, EccLiteParaData(para, ECC_LITE_P), para->words) ||
        !EccLiteBnLessThan(&pt->y, EccLiteParaData(para, ECC_LITE_P), para->words)) {
        ret = CRYPT_ECC_POINT_NOT_ON_CURVE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    LiteFToMont(pt->x.data, pt->x.data, para);
    LiteFToMont(pt->y.data, pt->y.data, para);
    GOTO_ERR_IF_EX(ECP_PointOnCurve(para, pt), ret);
    return CRYPT_SUCCESS;
ERR:
    EccLiteBnZero(&pt->z);
    return ret;
}

ECC_Point *ECC_NewPoint(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    ECC_Point *pt = BSL_SAL_Calloc(sizeof(ECC_Point), 1u);
    if (pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    pt->id = para->id;
    return pt;
}

void ECC_FreePoint(ECC_Point *pt)
{
    BSL_SAL_ClearFree(pt, sizeof(ECC_Point));
}

static void LiteGetCoordinate(const ECC_Para *para, const ECC_LiteBn *a, CRYPT_Data *out)
{
    ALIGN32 ECC_LiteBn value = {0};
    LiteFFromMont(value.data, a->data, EccLiteParaData(para, ECC_LITE_P), para->words);
    for (uint32_t i = 0; i < para->bytes; i++) {
        out->data[para->bytes - 1u - i] = (uint8_t)(value.data[i / sizeof(BN_UINT)] >> ((i % sizeof(BN_UINT)) * 8u));
    }
    out->len = para->bytes;
    BSL_SAL_CleanseData(&value, sizeof(value));
}

int32_t ECC_GetPoint(const ECC_Para *para, ECC_Point *pt, CRYPT_Data *x, CRYPT_Data *y)
{
    if (para == NULL || pt == NULL || x == NULL || x->data == NULL || (y != NULL && y->data == NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != pt->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if ((x->len < para->bytes) || ((y != NULL) && (y->len < para->bytes))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_ECC_BUFF_LEN_NOT_ENOUGH;
    }
    if (EccLiteBnIsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (!EccLiteBnIsOne(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
        return CRYPT_ECC_NOT_SUPPORT;
    }
    LiteGetCoordinate(para, &pt->x, x);
    if (y != NULL) {
        LiteGetCoordinate(para, &pt->y, y);
    }
    return CRYPT_SUCCESS;
}

int32_t ECC_PointMul(ECC_Para *para, ECC_Point *r, const ECC_LiteBn *k, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != r->id || (pt != NULL && para->id != pt->id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (!EccLiteBnLessThan(k, EccLiteParaData(para, ECC_LITE_N), para->words)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }
    return ECP_LitePointMul(para, r, k, pt);
}

int32_t ECC_GetSecBits(const ECC_Para *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (para->bytes >= 32u) {
        return 128;
    }
    return 80;
}

#ifdef HITLS_CRYPTO_CURVE_NISTP192
static const BN_UINT NIST_P192_DATA[] = {
    [ECC_LITE_P * 3] = 0xffffffffffffffffULL,   0xfffffffffffffffeULL, 0xffffffffffffffffULL,
    [ECC_LITE_N * 3] = 0x146bc9b1b4d22831ULL,   0xffffffff99def836ULL, 0xffffffffffffffffULL,
    [ECC_LITE_AM * 3] = 0xfffffffffffffffcULL,  0xfffffffffffffffbULL, 0xffffffffffffffffULL,
    [ECC_LITE_BM * 3] = 0x62d9e406a6e33a98ULL,  0x7281cdb219076ae2ULL, 0x73c8eec557c0b131ULL,
    [ECC_LITE_XM * 3] = 0x0d8cb30c332fa108ULL,  0x8a4bd3f776d12909ULL, 0x954cc8f9f3d218f7ULL,
    [ECC_LITE_YM * 3] = 0x7b12a3371e422289ULL,  0xde22b5248966f05eULL, 0x6a293d836aeda84dULL,
    [ECC_LITE_ONE * 3] = 0x0000000000000001ULL, 0x0000000000000001ULL, 0x0000000000000000ULL,
    [ECC_LITE_RR * 3] = 0x0000000000000001ULL,  0x0000000000000002ULL, 0x0000000000000001ULL,
};
#endif

#ifdef HITLS_CRYPTO_CURVE_NISTP256
static const BN_UINT NIST_P256_DATA[] = {
    [ECC_LITE_P * 4] = 0xffffffffffffffffULL,   0x00000000ffffffffULL, 0x0000000000000000ULL, 0xffffffff00000001ULL,
    [ECC_LITE_N * 4] = 0xf3b9cac2fc632551ULL,   0xbce6faada7179e84ULL, 0xffffffffffffffffULL, 0xffffffff00000000ULL,
    [ECC_LITE_AM * 4] = 0xfffffffffffffffcULL,  0x00000003ffffffffULL, 0x0000000000000000ULL, 0xfffffffc00000004ULL,
    [ECC_LITE_BM * 4] = 0xd89cdf6229c4bddfULL,  0xacf005cd78843090ULL, 0xe5a220abf7212ed6ULL, 0xdc30061d04874834ULL,
    [ECC_LITE_XM * 4] = 0x79e730d418a9143cULL,  0x75ba95fc5fedb601ULL, 0x79fb732b77622510ULL, 0x18905f76a53755c6ULL,
    [ECC_LITE_YM * 4] = 0xddf25357ce95560aULL,  0x8b4ab8e4ba19e45cULL, 0xd2e88688dd21f325ULL, 0x8571ff1825885d85ULL,
    [ECC_LITE_ONE * 4] = 0x0000000000000001ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL, 0x00000000fffffffeULL,
    [ECC_LITE_RR * 4] = 0x0000000000000003ULL,  0xfffffffbffffffffULL, 0xfffffffffffffffeULL, 0x00000004fffffffdULL,
};
#endif

ECC_Para *ECC_NewPara(CRYPT_PKEY_ParaId id)
{
    const BN_UINT *data;
    uint32_t words;
    switch (id) {
#ifdef HITLS_CRYPTO_CURVE_NISTP192
        case CRYPT_ECC_NISTP192:
            data = NIST_P192_DATA;
            words = 3;
            break;
#endif
#ifdef HITLS_CRYPTO_CURVE_NISTP256
        case CRYPT_ECC_NISTP256:
            data = NIST_P256_DATA;
            words = 4;
            break;
#endif
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ECDH_ERR_UNSUPPORT_CURVE_TYPE);
            return NULL;
    }
    ECC_Para *para = BSL_SAL_Calloc(1, sizeof(ECC_Para));
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    para->data = data;
    para->words = words;
    para->bytes = words * sizeof(BN_UINT);
    para->id = id;
    return para;
}

CRYPT_PKEY_ParaId GetCurveId(const CRYPT_EccPara *eccPara)
{
    (void)eccPara;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_PKEY_PARAID_MAX;
}

int32_t ECC_GetPara(const ECC_Pkey *pkey, CRYPT_EccPara *eccPara)
{
    (void)pkey;
    (void)eccPara;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}

#ifdef HITLS_BSL_PARAMS
int32_t ECC_GetParaEx(const ECC_Pkey *ctx, BSL_Param *para)
{
    (void)ctx;
    (void)para;
    BSL_ERR_PUSH_ERROR(CRYPT_ECC_NOT_SUPPORT);
    return CRYPT_ECC_NOT_SUPPORT;
}
#endif

void ECC_FreePara(ECC_Para *para)
{
    if (para == NULL) {
        return;
    }
    BSL_SAL_Free(para);
}

int32_t ECC_CofactorIsOne(const ECC_Para *para)
{
    return para != NULL;
}

CRYPT_PKEY_ParaId ECC_GetParaId(const ECC_Para *para)
{
    if (para == NULL) {
        return CRYPT_PKEY_PARAID_MAX;
    }
    return para->id;
}

int32_t ECC_SetPara(ECC_Pkey *ctx, ECC_Para *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    EccLiteBnFree(ctx->prvkey);
    ctx->prvkey = NULL;
    ECC_FreePoint(ctx->pubkey);
    ctx->pubkey = NULL;

    ECC_FreePara(ctx->para);
    ctx->para = para;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_ECC_LITE */
