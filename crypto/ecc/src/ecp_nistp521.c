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
#if defined(HITLS_CRYPTO_CURVE_NISTP521) && defined(HITLS_CRYPTO_NIST_USE_ACCEL)

#include <stdint.h>
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_util_internal.h"
#include "crypt_bn.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "ecc_utils.h"

#ifndef HITLS_INT128
#error "This nistp521 implementation require the compiler support 128-bits integer."
#endif

#define FELEM_BITS          521
/* Each element of a BigNum array is carried by 2 ^ 58 */
#define BASE_BITS           58
/* The length of a BigNum array is 9: 58 * 9 = 522 > 521 */
#define NUM_LIMBS           9
/* Mask with 58 bits */
#define MASK_58BITS         ((uint64_t)0x3FFFFFFFFFFFFFF)
/* Mask with 57 bits */
#define MASK_57BITS         ((uint64_t)0x1FFFFFFFFFFFFFF)
/* The pre-calculation table of the G table has 16 points. */
#define TABLE_G_SIZE        16
/* The pre-calculation table of the P table has 17 points. */
#define TABLE_P_SIZE        17
/* Forcibly convert to uint128_t */
#define U128(x)  ((uint128_t)(x))

/* Obtain the nth bit of a BigNum. The BigNum is stored in the uint64_t array in little-endian order. */
#define GET_ARRAY64_BIT(k, n) ((((k)->data)[(n) / 64] >> ((n) & 63)) & 1)

typedef struct {
    uint64_t data[NUM_LIMBS];
} Array64;

typedef struct {
    uint64_t data[NUM_LIMBS];
} Felem;

typedef struct {
    uint128_t data[NUM_LIMBS];
} LongFelem;

typedef struct {
    Felem x, y, z; /* Each point contains three coordinates x, y, and z. */
} Point;

/*
 *  The point type (Point) contains three field elements (Felem) (x, y, and z).
 *  Each field element consists of nine 64-bit data blocks (uint64_t).
 *  Point :pt
 *      Felem :x
 *          uint64_t :x[9]
 *      Felem :y
 *          uint64_t :y[9]
 *      Felem :z
 *          uint64_t :z[9]
 */

static inline void FelemToArray64(Array64 *array, const Felem *felem)
{
    uint32_t shift = 0;
    for (int32_t i = 0; i + 1 < NUM_LIMBS; i++) {
        array->data[i] = (felem->data[i] >> shift) | (felem->data[i + 1] << (BASE_BITS - shift));   // i < 8, shift < 48
        /* Felem is carried 1 every 58 bits, and array is carried 1 every 64 bits. The difference is 6 bits. */
        shift += 6;
    }
    array->data[8] = felem->data[8] >> shift; /* felem->data[8] is the last data block. */
}

static inline void Array64ToFelem(Felem *felem, const Array64 *array)
{
    uint32_t shift = 0;
    felem->data[0] = array->data[0] & MASK_58BITS;
    for (int32_t i = 1; i < NUM_LIMBS; i++) {
        /* Felem is carried 1 every 58 bits, and array is carried 1 every 64 bits. The difference is 6 bits. */
        shift += 6;
        felem->data[i] = ((array->data[i - 1] >> (64 - shift)) | (array->data[i] << shift)) & MASK_58BITS;
    }
}

static inline void FelemAssign(Felem *r, const Felem *a)
{
    r->data[0] = a->data[0]; // r->data[0] take the value
    r->data[1] = a->data[1]; // r->data[1] take the value
    r->data[2] = a->data[2]; // r->data[2] take the value
    r->data[3] = a->data[3]; // r->data[3] take the value
    r->data[4] = a->data[4]; // r->data[4] take the value
    r->data[5] = a->data[5]; // r->data[5] take the value
    r->data[6] = a->data[6]; // r->data[6] take the value
    r->data[7] = a->data[7]; // r->data[7] take the value
    r->data[8] = a->data[8]; // r->data[8] take the value
}

static inline void FelemPointAssign(Point *ptR, const Point *ptIn)
{
    FelemAssign(&ptR->x, &ptIn->x);
    FelemAssign(&ptR->y, &ptIn->y);
    FelemAssign(&ptR->z, &ptIn->z);
}

static inline void FelemAssignWithMask(Felem *r, const Felem *a, uint64_t mask)
{
    uint64_t rmask = ~mask;
    r->data[0] = (a->data[0] & mask) | (r->data[0] & rmask); // r->data[0] Obtain a new value or remain unchanged.
    r->data[1] = (a->data[1] & mask) | (r->data[1] & rmask); // r->data[1] Obtain a new value or remain unchanged.
    r->data[2] = (a->data[2] & mask) | (r->data[2] & rmask); // r->data[2] Obtain a new value or remain unchanged.
    r->data[3] = (a->data[3] & mask) | (r->data[3] & rmask); // r->data[3] Obtain a new value or remain unchanged.
    r->data[4] = (a->data[4] & mask) | (r->data[4] & rmask); // r->data[4] Obtain a new value or remain unchanged.
    r->data[5] = (a->data[5] & mask) | (r->data[5] & rmask); // r->data[5] Obtain a new value or remain unchanged.
    r->data[6] = (a->data[6] & mask) | (r->data[6] & rmask); // r->data[6] Obtain a new value or remain unchanged.
    r->data[7] = (a->data[7] & mask) | (r->data[7] & rmask); // r->data[7] Obtain a new value or remain unchanged.
    r->data[8] = (a->data[8] & mask) | (r->data[8] & rmask); // r->data[8] Obtain a new value or remain unchanged.
}

static inline void FelemPointAssignWithMask(Point *ptR, const Point *ptIn, uint64_t mask)
{
    FelemAssignWithMask(&ptR->x, &ptIn->x, mask);
    FelemAssignWithMask(&ptR->y, &ptIn->y, mask);
    FelemAssignWithMask(&ptR->z, &ptIn->z, mask);
}

static inline void FelemSetLimb(Felem *felem, const uint64_t a)
{
    felem->data[0] = a; // r->data[0] take the value of a
    felem->data[1] = 0; // r->data[1] clear to 0
    felem->data[2] = 0; // r->data[2] clear to 0
    felem->data[3] = 0; // r->data[3] clear to 0
    felem->data[4] = 0; // r->data[4] clear to 0
    felem->data[5] = 0; // r->data[5] clear to 0
    felem->data[6] = 0; // r->data[6] clear to 0
    felem->data[7] = 0; // r->data[7] clear to 0
    felem->data[8] = 0; // r->data[8] clear to 0
}

static inline void LongFelemMulLimb(LongFelem *r, const LongFelem *a, uint64_t limb)
{
    r->data[0] = a->data[0] * limb; // r->data[0] take the value
    r->data[1] = a->data[1] * limb; // r->data[1] take the value
    r->data[2] = a->data[2] * limb; // r->data[2] take the value
    r->data[3] = a->data[3] * limb; // r->data[3] take the value
    r->data[4] = a->data[4] * limb; // r->data[4] take the value
    r->data[5] = a->data[5] * limb; // r->data[5] take the value
    r->data[6] = a->data[6] * limb; // r->data[6] take the value
    r->data[7] = a->data[7] * limb; // r->data[7] take the value
    r->data[8] = a->data[8] * limb; // r->data[8] take the value
}

static inline void FelemMulLimb(Felem *r, const Felem *a, uint64_t b)
{
    r->data[0] = a->data[0] * b; // r->data[0] take the value
    r->data[1] = a->data[1] * b; // r->data[1] take the value
    r->data[2] = a->data[2] * b; // r->data[2] take the value
    r->data[3] = a->data[3] * b; // r->data[3] take the value
    r->data[4] = a->data[4] * b; // r->data[4] take the value
    r->data[5] = a->data[5] * b; // r->data[5] take the value
    r->data[6] = a->data[6] * b; // r->data[6] take the value
    r->data[7] = a->data[7] * b; // r->data[7] take the value
    r->data[8] = a->data[8] * b; // r->data[8] take the value
}

static inline void FelemAdd(Felem *r, const Felem *a, const Felem *b)
{
    r->data[0] = a->data[0] + b->data[0]; // r->data[0] take the value
    r->data[1] = a->data[1] + b->data[1]; // r->data[1] take the value
    r->data[2] = a->data[2] + b->data[2]; // r->data[2] take the value
    r->data[3] = a->data[3] + b->data[3]; // r->data[3] take the value
    r->data[4] = a->data[4] + b->data[4]; // r->data[4] take the value
    r->data[5] = a->data[5] + b->data[5]; // r->data[5] take the value
    r->data[6] = a->data[6] + b->data[6]; // r->data[6] take the value
    r->data[7] = a->data[7] + b->data[7]; // r->data[7] take the value
    r->data[8] = a->data[8] + b->data[8]; // r->data[8] take the value
}

/*
 * input:
 *   a->data[i] < 7*2^61
 *   b->data[i] < 2^60 - 2^3
 * output:
 *   r->data[i] <= max(a->data[i]) + 2^61 - 2^3
 */
static inline void FelemSub(Felem *r, const Felem *a, const Felem *b)
{
    r->data[0] = a->data[0] + (MASK_58BITS << 3) - b->data[0]; // b->data[0] < 2^61 - 2^3
    r->data[1] = a->data[1] + (MASK_58BITS << 3) - b->data[1]; // b->data[1] < 2^61 - 2^3
    r->data[2] = a->data[2] + (MASK_58BITS << 3) - b->data[2]; // b->data[2] < 2^61 - 2^3
    r->data[3] = a->data[3] + (MASK_58BITS << 3) - b->data[3]; // b->data[3] < 2^61 - 2^3
    r->data[4] = a->data[4] + (MASK_58BITS << 3) - b->data[4]; // b->data[4] < 2^61 - 2^3
    r->data[5] = a->data[5] + (MASK_58BITS << 3) - b->data[5]; // b->data[5] < 2^61 - 2^3
    r->data[6] = a->data[6] + (MASK_58BITS << 3) - b->data[6]; // b->data[6] < 2^61 - 2^3
    r->data[7] = a->data[7] + (MASK_58BITS << 3) - b->data[7]; // b->data[7] < 2^61 - 2^3
    r->data[8] = a->data[8] + (MASK_57BITS << 3) - b->data[8]; // b->data[8] < 2^60 - 2^3
}
/*
 * input:
 *   r->data[i] < 2^127
 *   a->data[i] < 2^64 - 2^6
 * output:
 *   r->data[i] <= r->data[i] + 2^64 - 2^6
 */
static inline void LongFelemDiff(LongFelem *r, const Felem *a)
{
    r->data[0] += (MASK_58BITS << 6) - a->data[0]; // a->data[0] < 2^64 - 2^6
    r->data[1] += (MASK_58BITS << 6) - a->data[1]; // a->data[1] < 2^64 - 2^6
    r->data[2] += (MASK_58BITS << 6) - a->data[2]; // a->data[2] < 2^64 - 2^6
    r->data[3] += (MASK_58BITS << 6) - a->data[3]; // a->data[3] < 2^64 - 2^6
    r->data[4] += (MASK_58BITS << 6) - a->data[4]; // a->data[4] < 2^64 - 2^6
    r->data[5] += (MASK_58BITS << 6) - a->data[5]; // a->data[5] < 2^64 - 2^6
    r->data[6] += (MASK_58BITS << 6) - a->data[6]; // a->data[6] < 2^64 - 2^6
    r->data[7] += (MASK_58BITS << 6) - a->data[7]; // a->data[7] < 2^64 - 2^6
    r->data[8] += (MASK_57BITS << 6) - a->data[8]; // a->data[8] < 2^63 - 2^6
}

static inline void FelemNeg(Felem *r, const Felem *a)
{
    r->data[0] = (MASK_58BITS << 3) - a->data[0]; // a->data[0], r->data[0] < 2^61 - 2^3
    r->data[1] = (MASK_58BITS << 3) - a->data[1]; // a->data[1], r->data[1] < 2^61 - 2^3
    r->data[2] = (MASK_58BITS << 3) - a->data[2]; // a->data[2], r->data[2] < 2^61 - 2^3
    r->data[3] = (MASK_58BITS << 3) - a->data[3]; // a->data[3], r->data[3] < 2^61 - 2^3
    r->data[4] = (MASK_58BITS << 3) - a->data[4]; // a->data[4], r->data[4] < 2^61 - 2^3
    r->data[5] = (MASK_58BITS << 3) - a->data[5]; // a->data[5], r->data[5] < 2^61 - 2^3
    r->data[6] = (MASK_58BITS << 3) - a->data[6]; // a->data[6], r->data[6] < 2^61 - 2^3
    r->data[7] = (MASK_58BITS << 3) - a->data[7]; // a->data[7], r->data[7] < 2^61 - 2^3
    r->data[8] = (MASK_57BITS << 3) - a->data[8]; // a->data[8], r->data[8] < 2^60 - 2^3
}

/* Calculate r = a / 2, which can be regarded as a cyclic right shift by one bit in the modulo P(2^521-1) field. */
static inline void FelemDivTwo(Felem *r, const Felem *a)
{
    const uint64_t *pa = a->data;
    r->data[0] = (pa[0] >> 1) + ((pa[1] & 1) << 57); // The 57th bit plus the LSB of pa[1]
    r->data[1] = (pa[1] >> 1) + ((pa[2] & 1) << 57); // The 57th bit plus the LSB of pa[2]
    r->data[2] = (pa[2] >> 1) + ((pa[3] & 1) << 57); // The 57th bit plus the LSB of pa[3]
    r->data[3] = (pa[3] >> 1) + ((pa[4] & 1) << 57); // The 57th bit plus the LSB of pa[4]
    r->data[4] = (pa[4] >> 1) + ((pa[5] & 1) << 57); // The 57th bit plus the LSB of pa[5]
    r->data[5] = (pa[5] >> 1) + ((pa[6] & 1) << 57); // The 57th bit plus the LSB of pa[6]
    r->data[6] = (pa[6] >> 1) + ((pa[7] & 1) << 57); // The 57th bit plus the LSB of pa[7]
    r->data[7] = (pa[7] >> 1) + ((pa[8] & 1) << 57); // The 57th bit plus the LSB of pa[8]
    r->data[8] = (pa[8] >> 1) + ((pa[0] & 1) << 56); // The 56th bit plus the LSB of pa[0]
}

/*
 * reduce to prevent subsequent calculation overflow.
 * input:
 *   in[i] < 2^128
 * output:
 *   out[i] < 2^59 + 2^14
 */
static void FelemReduce(Felem *r, const LongFelem *a)
{
    uint64_t tmp;
    const uint32_t shift2 = BASE_BITS * 2; // 116 = 58 * 2
    r->data[0] = (uint64_t)(a->data[0] & MASK_58BITS); // r->data[0] < 2^58
    r->data[1] = (uint64_t)(a->data[1] & MASK_58BITS); // r->data[1] < 2^58
    r->data[2] = (uint64_t)(a->data[2] & MASK_58BITS); // r->data[2] < 2^58
    r->data[3] = (uint64_t)(a->data[3] & MASK_58BITS); // r->data[3] < 2^58
    r->data[4] = (uint64_t)(a->data[4] & MASK_58BITS); // r->data[4] < 2^58
    r->data[5] = (uint64_t)(a->data[5] & MASK_58BITS); // r->data[5] < 2^58
    r->data[6] = (uint64_t)(a->data[6] & MASK_58BITS); // r->data[6] < 2^58
    r->data[7] = (uint64_t)(a->data[7] & MASK_58BITS); // r->data[7] < 2^58
    r->data[8] = (uint64_t)(a->data[8] & MASK_58BITS); // r->data[8] < 2^58

    r->data[1] += (uint64_t)(a->data[0] >> BASE_BITS) & MASK_58BITS; // r->data[1] < 2^59
    r->data[2] += (uint64_t)(a->data[1] >> BASE_BITS) & MASK_58BITS; // r->data[2] < 2^59
    r->data[3] += (uint64_t)(a->data[2] >> BASE_BITS) & MASK_58BITS; // r->data[3] < 2^59
    r->data[4] += (uint64_t)(a->data[3] >> BASE_BITS) & MASK_58BITS; // r->data[4] < 2^59
    r->data[5] += (uint64_t)(a->data[4] >> BASE_BITS) & MASK_58BITS; // r->data[5] < 2^59
    r->data[6] += (uint64_t)(a->data[5] >> BASE_BITS) & MASK_58BITS; // r->data[6] < 2^59
    r->data[7] += (uint64_t)(a->data[6] >> BASE_BITS) & MASK_58BITS; // r->data[7] < 2^59
    r->data[8] += (uint64_t)(a->data[7] >> BASE_BITS) & MASK_58BITS; // r->data[8] < 2^59
    // a->data[8] The most significant bits above 58bits correspond to the most significant bits above 522 bits.
    tmp = (uint64_t)(a->data[8] >> BASE_BITS) & MASK_58BITS;
    r->data[0] += tmp << 1; // r->data[0] < 3*2^58

    r->data[2] += (uint64_t)(a->data[0] >> shift2); // r->data[2] < 2^59 + 2^6
    r->data[3] += (uint64_t)(a->data[1] >> shift2); // r->data[3] < 2^59 + 2^6
    r->data[4] += (uint64_t)(a->data[2] >> shift2); // r->data[4] < 2^59 + 2^6, add the upper bits of a[2]116 bits.
    r->data[5] += (uint64_t)(a->data[3] >> shift2); // r->data[5] < 2^59 + 2^6, add the upper bits of a[3]116 bits.
    r->data[6] += (uint64_t)(a->data[4] >> shift2); // r->data[6] < 2^59 + 2^6, add the upper bits of a[4]116 bits.
    r->data[7] += (uint64_t)(a->data[5] >> shift2); // r->data[7] < 2^59 + 2^6, add the upper bits of a[5]116 bits.
    r->data[8] += (uint64_t)(a->data[6] >> shift2); // r->data[8] < 2^59 + 2^6, add the upper bits of a[6]116 bits.
    // a->data[7] The most significant bits above 116bits correspond to the most significant bits above 522 bits.
    tmp = (uint64_t)(a->data[7] >> shift2);
    r->data[0] += tmp << 1; // r->data[0] < 3*2^58 + 2^13
    // a->data[8] The most significant bits above 116bits correspond to the most significant bits above 580 bits.
    tmp = (uint64_t)(a->data[8] >> shift2);
    r->data[1] += tmp << 1; // r->data[1] < 2^59 + 2^13

    /* Considering that out[0] may be too large, carry needs to be continued. */
    r->data[1] += r->data[0] >> BASE_BITS; // r->data[1] < 2^59 + 2^14
    r->data[0] &= MASK_58BITS; // r->data[0] < 2^58
}
/*
 * Reduce the number of bits to less than 58 to prevent subsequent operation overflow.
 * input:
 *   felem->data[i] < 2^64 - 2^6
 * output:
 *   felem->data[i] < 2^58
 */
static void FelemShrink(Felem *felem)
{
    uint64_t carry = 0; /* Carry value between Limb */

    /* Reduce each limb to less than 58 bits */
    for (int32_t i = 0; i < NUM_LIMBS - 1; i++) {
        felem->data[i] += carry;                         /* plus the carry of the previous block */
        carry = (uint64_t)(felem->data[i] >> BASE_BITS); /* Take the carry of this block. */
        felem->data[i] &= MASK_58BITS;                   /* 58 bits reserved */
    }
    felem->data[NUM_LIMBS - 1] += carry;
    carry = felem->data[NUM_LIMBS - 1] >> 57; /* 521 = 58 * 8 + 57, carry the upper bits to the lower bits */
    felem->data[NUM_LIMBS - 1] &= MASK_57BITS; /* The upper bits are discarded, only the lower 521 bits are retained */

    /* Add the bits above 521 to the lower bits. */
    for (int32_t i = 0; i < NUM_LIMBS; i++) {
        felem->data[i] += carry;                         /* plus the carry of the previous block */
        carry = (uint64_t)(felem->data[i] >> BASE_BITS); /* Take the carry of this block. */
        felem->data[i] &= MASK_58BITS;                   /* 58 bits reserved */
    }
}

/*
 * Reduce felem to a unique value less than P.
 * input:
 *   felem->data[i] < 2^64 - 2^6
 * output:
 *   felem->data[i] < 2^58
 * Return value:
 *  If felem is 0, the mask is all 1s. Otherwise, the mask is 0.
 */
static uint64_t FelemContract(Felem *felem)
{
    uint64_t notP = 0;
    uint64_t notZero = 0;
    uint64_t mask;
    uint64_t carry;
    FelemShrink(felem);

    /* After the shrink command is executed, felem->data[i] < 2^58, but it may still be greater than 521 bits. */
    carry = felem->data[NUM_LIMBS - 1] >> 57;            /* 521 = 58 * 8 + 57, carry the upper bits to the lower bits */
    felem->data[NUM_LIMBS - 1] &= MASK_57BITS;
    /* Add the bits above 521 to the lower bits. */
    for (int32_t i = 0; i < NUM_LIMBS; i++) {
        felem->data[i] += carry;                            /* plus the carry of the previous block */
        carry = (uint64_t)(felem->data[i] >> BASE_BITS);    /* Take the carry of this block. */
        felem->data[i] &= MASK_58BITS;                      /* 58 bits reserved */
    }

    /* Check whether the value is P. */
    for (int32_t i = 0; i < NUM_LIMBS - 1; i++) {
        notP |= felem->data[i] ^ MASK_58BITS; /* If the value of felem is P, the value remains 0. */
    }
    notP |= felem->data[NUM_LIMBS - 1] ^ MASK_57BITS;
    /* The most significant bit is 1 only when notP = 0. In this case, the mask is 0. */
    mask = 0 - ((0 - notP) >> 63);      /* Shift rightwards by 63 bits and get the most significant bit. */

    for (int32_t i = 0; i < NUM_LIMBS; i++) {
        felem->data[i] &= mask;         /* If the value is P, clear all the bits to 0 */
        notZero |= felem->data[i];      /* an determine whether the value is zero. */
    }
    /* only when notZero == 0, the most significant bit is 1. In this case, each bit of the mask is all 1s. */
    mask = ((0 - notZero) >> 63) - 1;   /* Shift rightwards by 63 bits and get the most significant bit. */
    return mask;
}

/* Convert a BigNum to the Felem *. Note that the value cannot be a negative number and cannot be greater than P. */
static int32_t BN2Felem(Felem *r, const BN_BigNum *a)
{
    int32_t ret;
    Array64 array = {0};
    uint32_t len = NUM_LIMBS;
    ret = BN_Bn2U64Array(a, array.data, &len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    Array64ToFelem(r, &array);
    return CRYPT_SUCCESS;
}

/* Felem * Convert to BigNum */
static int32_t Felem2BN(BN_BigNum *r, const Felem *a)
{
    Array64 array = {0};
    uint32_t len = NUM_LIMBS;
    Felem felem;
    FelemAssign(&felem, a);
    FelemContract(&felem);
    FelemToArray64(&array, &felem);
    return BN_U64Array2Bn(r, array.data, len);
}

/*
 * Calculate r = a * b
 * input:
 *   a->data[i] < 2^63
 *   b->data[i] < 2^128 / (17*a[i])
 * output:
 *   r->data[i] < 17(max(a[i]*b[i]))
 */
static void FelemMul(LongFelem *r, const Felem *a, const Felem *b)
{
    Felem ax2;
    const uint64_t *pa = a->data;
    const uint64_t *pb = b->data;
    const uint64_t *p2 = ax2.data;
    /* Because the modulo P is 2^521 - 1, the higher bits above the 521 bits
       can be truncated and then added to the lower bits. */
    FelemMulLimb(&ax2, a, 2);

    r->data[0] = U128(pa[0]) * pb[0] + U128(p2[1]) * pb[8] + U128(p2[2]) * pb[7] + // 0 = 0+0, 1+8, 2+7 (mod 9)
                 U128(p2[3]) * pb[6] + U128(p2[4]) * pb[5] + U128(p2[5]) * pb[4] + // 0 = 3+6, 4+5, 5+4 (mod 9)
                 U128(p2[6]) * pb[3] + U128(p2[7]) * pb[2] + U128(p2[8]) * pb[1];  // 0 = 6+3, 7+2, 8+1 (mod 9)

    r->data[1] = U128(pa[0]) * pb[1] + U128(pa[1]) * pb[0] + U128(p2[2]) * pb[8] + // 1 = 0+1, 1+0, 2+8 (mod 9)
                 U128(p2[3]) * pb[7] + U128(p2[4]) * pb[6] + U128(p2[5]) * pb[5] + // 1 = 3+7, 4+6, 5+5 (mod 9)
                 U128(p2[6]) * pb[4] + U128(p2[7]) * pb[3] + U128(p2[8]) * pb[2];  // 1 = 6+4, 7+3, 8+2 (mod 9)

    r->data[2] = U128(pa[0]) * pb[2] + U128(pa[1]) * pb[1] + U128(pa[2]) * pb[0] + // 2 = 0+2, 1+1, 2+0 (mod 9)
                 U128(p2[3]) * pb[8] + U128(p2[4]) * pb[7] + U128(p2[5]) * pb[6] + // 2 = 3+8, 4+7, 5+6 (mod 9)
                 U128(p2[6]) * pb[5] + U128(p2[7]) * pb[4] + U128(p2[8]) * pb[3];  // 2 = 6+5, 7+4, 8+3 (mod 9)

    r->data[3] = U128(pa[0]) * pb[3] + U128(pa[1]) * pb[2] + U128(pa[2]) * pb[1] + // 3 = 0+3, 1+2, 2+1 (mod 9)
                 U128(pa[3]) * pb[0] + U128(p2[4]) * pb[8] + U128(p2[5]) * pb[7] + // 3 = 3+0, 4+8, 5+7 (mod 9)
                 U128(p2[6]) * pb[6] + U128(p2[7]) * pb[5] + U128(p2[8]) * pb[4];  // 3 = 6+6, 7+5, 8+4 (mod 9)

    r->data[4] = U128(pa[0]) * pb[4] + U128(pa[1]) * pb[3] + U128(pa[2]) * pb[2] + // 4 = 0+4, 1+3, 2+2 (mod 9)
                 U128(pa[3]) * pb[1] + U128(pa[4]) * pb[0] + U128(p2[5]) * pb[8] + // 4 = 3+1, 4+0, 5+8 (mod 9)
                 U128(p2[6]) * pb[7] + U128(p2[7]) * pb[6] + U128(p2[8]) * pb[5];  // 4 = 6+7, 7+6, 8+5 (mod 9)

    r->data[5] = U128(pa[0]) * pb[5] + U128(pa[1]) * pb[4] + U128(pa[2]) * pb[3] + // 5 = 0+5, 1+4, 2+3 (mod 9)
                 U128(pa[3]) * pb[2] + U128(pa[4]) * pb[1] + U128(pa[5]) * pb[0] + // 5 = 3+2, 4+1, 5+0 (mod 9)
                 U128(p2[6]) * pb[8] + U128(p2[7]) * pb[7] + U128(p2[8]) * pb[6];  // 5 = 6+8, 7+7, 8+6 (mod 9)

    r->data[6] = U128(pa[0]) * pb[6] + U128(pa[1]) * pb[5] + U128(pa[2]) * pb[4] + // 6 = 0+6, 1+5, 2+4 (mod 9)
                 U128(pa[3]) * pb[3] + U128(pa[4]) * pb[2] + U128(pa[5]) * pb[1] + // 6 = 3+3, 4+2, 5+1 (mod 9)
                 U128(pa[6]) * pb[0] + U128(p2[7]) * pb[8] + U128(p2[8]) * pb[7];  // 6 = 6+0, 7+8, 8+7 (mod 9)

    r->data[7] = U128(pa[0]) * pb[7] + U128(pa[1]) * pb[6] + U128(pa[2]) * pb[5] + // 7 = 0+7, 1+6, 2+5 (mod 9)
                 U128(pa[3]) * pb[4] + U128(pa[4]) * pb[3] + U128(pa[5]) * pb[2] + // 7 = 3+4, 4+3, 5+2 (mod 9)
                 U128(pa[6]) * pb[1] + U128(pa[7]) * pb[0] + U128(p2[8]) * pb[8];  // 7 = 6+1, 7+0, 8+8 (mod 9)

    r->data[8] = U128(pa[0]) * pb[8] + U128(pa[1]) * pb[7] + U128(pa[2]) * pb[6] + // 8 = 0+8, 1+7, 2+6 (mod 9)
                 U128(pa[3]) * pb[5] + U128(pa[4]) * pb[4] + U128(pa[5]) * pb[3] + // 8 = 3+5, 4+4, 5+3 (mod 9)
                 U128(pa[6]) * pb[2] + U128(pa[7]) * pb[1] + U128(pa[8]) * pb[0];  // 8 = 6+2, 7+1, 8+0 (mod 9)
}

/*
 * Calculate r = a^2
 * input:
 *   a->data[i] < 2^62 - 2^57
 * output:
 *   r->data[i] < 17*max(a[i]*a[i])
 */
static void FelemSqr(LongFelem *r, const Felem *a)
{
    Felem ax2;
    Felem ax4;
    const uint64_t *pa = a->data;
    const uint64_t *p2 = ax2.data;
    const uint64_t *p4 = ax4.data;
    /* Because the modulo P is 2^521 - 1, the higher bits above the 521 bits
       can be truncated and then added to the lower bits. */
    FelemMulLimb(&ax2, a, 2); /* ax2 is twice the value of a */
    FelemMulLimb(&ax4, a, 4); /* ax4 is 4 times the value of a */

    r->data[0] = U128(pa[0]) * pa[0]; // 0 = 0+0 (mod 9)
    r->data[1] = U128(p2[5]) * pa[5]; // 1 = 5+5 (mod 9)
    r->data[2] = U128(pa[1]) * pa[1]; // 2 = 1+1 (mod 9)
    r->data[3] = U128(p2[6]) * pa[6]; // 3 = 6+6 (mod 9)
    r->data[4] = U128(pa[2]) * pa[2]; // 4 = 2+2 (mod 9)
    r->data[5] = U128(p2[7]) * pa[7]; // 5 = 7+7 (mod 9)
    r->data[6] = U128(pa[3]) * pa[3]; // 6 = 3+3 (mod 9)
    r->data[7] = U128(p2[8]) * pa[8]; // 7 = 8+8 (mod 9)
    r->data[8] = U128(pa[4]) * pa[4]; // 8 = 4+4 (mod 9)

    // r->data[0] < 17*49*2^114 < 2^124
    // 0 = 1+8, 2+7, 3+6, 4+5 (mod 9)
    r->data[0] += U128(p4[1]) * pa[8] + U128(p4[2]) * pa[7] + U128(p4[3]) * pa[6] + U128(p4[4]) * pa[5];
    // 1 = 0+1, 2+8, 3+7, 4+6 (mod 9)
    r->data[1] += U128(p2[0]) * pa[1] + U128(p4[2]) * pa[8] + U128(p4[3]) * pa[7] + U128(p4[4]) * pa[6];
    // 2 = 0+2, 3+8, 4+7, 5+6 (mod 9)
    r->data[2] += U128(p2[0]) * pa[2] + U128(p4[3]) * pa[8] + U128(p4[4]) * pa[7] + U128(p4[5]) * pa[6];
    // 3 = 0+3, 1+2, 4+8, 5+7 (mod 9)
    r->data[3] += U128(p2[0]) * pa[3] + U128(p2[1]) * pa[2] + U128(p4[4]) * pa[8] + U128(p4[5]) * pa[7];
    // 4 = 0+4, 1+3, 5+8, 6+7 (mod 9)
    r->data[4] += U128(p2[0]) * pa[4] + U128(p2[1]) * pa[3] + U128(p4[5]) * pa[8] + U128(p4[6]) * pa[7];
    // 5 = 0+5, 1+4, 2+3, 6+8 (mod 9)
    r->data[5] += U128(p2[0]) * pa[5] + U128(p2[1]) * pa[4] + U128(p2[2]) * pa[3] + U128(p4[6]) * pa[8];
    // 6 = 0+6, 1+5, 2+4, 7+8 (mod 9)
    r->data[6] += U128(p2[0]) * pa[6] + U128(p2[1]) * pa[5] + U128(p2[2]) * pa[4] + U128(p4[7]) * pa[8];
    // 7 = 0+7, 1+6, 2+5, 3+4 (mod 9)
    r->data[7] += U128(p2[0]) * pa[7] + U128(p2[1]) * pa[6] + U128(p2[2]) * pa[5] + U128(p2[3]) * pa[4];
    // 8 = 0+8, 1+7, 2+6, 3+5 (mod 9)
    r->data[8] += U128(p2[0]) * pa[8] + U128(p2[1]) * pa[7] + U128(p2[2]) * pa[6] + U128(p2[3]) * pa[5];
}

// Multiply and reduce
static inline void FelemMulReduce(Felem *r, const Felem *a, const Felem *b)
{
    LongFelem tmp;
    FelemMul(&tmp, a, b);
    FelemReduce(r, &tmp);
}

// Square and reduce
static inline void FelemSqrReduce(Felem *r, const Felem *in)
{
    LongFelem tmp;
    FelemSqr(&tmp, in);
    FelemReduce(r, &tmp);
}

/*
 * Calculate r = 1/a (mod P)
 *  Fermat's Little Theorem:
 *  a^p = a mod p
 *  a^(p-1) = 1 mod p
 *  a^(p-2) = a^(-1) mod p
 *  Calculate the inverse modulus value according to this formula and:
 *  p = 2^521 - 1
 *  p - 2 = 2^521 - 3 = (2^519 - 1) << 2 + 1
*/
static void FelemInv(Felem *r, const Felem *a)
{
    Felem tmp1, tmp2, tmp3;
    int32_t bits;
    /* Calculate a^e and update the e value until e = p - 2 */
    FelemSqrReduce(&tmp1, a);             /* (10) */
    FelemMulReduce(&tmp1, &tmp1, a);      /* (11) */

    FelemSqrReduce(&tmp2, &tmp1);         /* (110) */
    FelemMulReduce(&tmp3, &tmp2, a);      /* (111) is stored in tmp3 */
    FelemSqrReduce(&tmp2, &tmp2);         /* (1100) */
    FelemMulReduce(&tmp1, &tmp2, &tmp1);  /* (1111) */

    FelemSqrReduce(&tmp2, &tmp1);         /* (0001 1110) */
    FelemSqrReduce(&tmp2, &tmp2);         /* (0011 1100) */
    FelemSqrReduce(&tmp2, &tmp2);         /* (0111 1000) */
    FelemMulReduce(&tmp3, &tmp2, &tmp3);  /* (0111 1111) is stored in tmp3 */
    FelemSqrReduce(&tmp2, &tmp2);         /* (1111 0000) */
    FelemMulReduce(&tmp1, &tmp2, &tmp1);  /* 2^8 - 1 */

    /* The current value of e is (11111111) The value consists of 8 bits */
    bits = 8;

    /* Perform the square & multiplication until the value of e becomes 2 ^ 512 - 1, that is, 512 bits */
    while (bits < 512) {
        FelemAssign(&tmp2, &tmp1);
        for (int32_t i = 0; i < bits; i++) {   /* e value shifts to the left */
            FelemSqrReduce(&tmp2, &tmp2);
        }
        FelemMulReduce(&tmp1, &tmp2, &tmp1);   /* e Change the lower bits 0 to 1, e = 2^bits - 1 */
        /* In this case, the bit length of the e value becomes twice (* 2). */
        bits *= 2;
    }
    /* In this case, the value of e is 2^512-1 */
    for (int32_t i = 0; i < 7; i++) {     /* e value shifts to the left by 7 bits */
        FelemSqrReduce(&tmp1, &tmp1);
    }
    FelemMulReduce(&tmp1, &tmp1, &tmp3);  /* 2^519 - 1, plus the previous &tmp3 */

    FelemSqrReduce(&tmp1, &tmp1);
    FelemSqrReduce(&tmp1, &tmp1);         /* (2^519 - 1) << 2 */
    FelemMulReduce(r, &tmp1, a);          /* p - 2 */
}

/*
 *  "dbl-2001-b"
 *    delta = Z1^2
 *    gamma = Y1^2
 *    beta = X1*gamma
 *    alpha = 3*(X1-delta)*(X1+delta)
 *    X3 = alpha^2-8*beta
 *    Z3 = (Y1+Z1)^2-gamma-delta
 *    Y3 = alpha*(4*beta-X3)-8*gamma^2
*/
/* Calculate the double point coordinates. */
static void FelemPointDouble(Point *pointOut, const Point *pointIn)
{
    Felem delta, gamma, beta, alpha;
    Felem tmp1, tmp2;
    LongFelem ltmp1;

    /* delta = Z1^2 */
    FelemSqrReduce(&delta, &pointIn->z);        // delta[i] < 2^59 + 2^14
    /* gamma = Y1^2 */
    FelemSqrReduce(&gamma, &pointIn->y);        // gamma[i] < 2^59 + 2^14
    /* beta = X1*gamma */
    FelemMulReduce(&beta, &pointIn->x, &gamma); // beta[i] < 2^59 + 2^14

    /* X1 - delta */
    FelemSub(&tmp1, &pointIn->x, &delta);       // tmp1[i] < 9*2^59 + 2^14
    /* X1 + delta */
    FelemAdd(&tmp2, &pointIn->x, &delta);       // tmp2[i] < 2^60 + 2^15
    /* 3*(X1 + delta) */
    FelemMulLimb(&tmp2, &tmp2, 3);              // tmp2[i] < 6*(2^59 + 2^14)
    /* alpha = 3*(X1-delta)*(X1+delta) */
    FelemMulReduce(&alpha, &tmp1, &tmp2);       // alpha[i] < 2^59 + 2^14

    /* alpha^2 */
    FelemSqr(&ltmp1, &alpha);                   // ltmp1[i] < 2^125
    /* 8*beta */
    FelemMulLimb(&tmp2, &beta, 8);              // tmp2[i] < 2^62 + 2^17
    /* alpha^2-8*beta */
    LongFelemDiff(&ltmp1, &tmp2);               // ltmp1[i] < 2^126
    /* X3 = alpha^2-8*beta */
    FelemReduce(&pointOut->x, &ltmp1);

    /* Y1+Z1 */
    FelemAdd(&tmp1, &pointIn->y, &pointIn->z);  // tmp1[i] < 2^60 + 2^15
    /* (Y1+Z1)^2 */
    FelemSqr(&ltmp1, &tmp1);                    // ltmp1[i] < 17*(2^60 + 2^15)
    /* gamma+delta */
    FelemAdd(&tmp2, &gamma, &delta);            // tmp2[i] < 2^60 + 2^15
    /* (Y1+Z1)^2 - gamma - delta */
    LongFelemDiff(&ltmp1, &tmp2);
    /* Z3 = (Y1+Z1)^2-gamma-delta */
    FelemReduce(&pointOut->z, &ltmp1);

    /* 4*beta */
    FelemMulLimb(&tmp2, &beta, 4);              // tmp2[i] < 2^61 + 2^16
    /* 4*beta-X3 */
    FelemSub(&tmp1, &tmp2, &pointOut->x);       // tmp1[i] < 2^62 + 2^16
    FelemShrink(&tmp1); // Subtraction and reduction process can be optimized
    /* alpha*(4*beta-X3) */
    FelemMul(&ltmp1, &alpha, &tmp1);            // ltmp1[i] < 2^128
    /* gamma^2 */
    FelemSqrReduce(&tmp2, &gamma);              // tmp2[i] < 2^59 + 2^14
    /* 8*gamma^2 */
    FelemMulLimb(&tmp1, &tmp2, 8);              // tmp1[i] < 2^62 + 2^17
    /* alpha*(4*beta-X3)-8*gamma^2 */
    LongFelemDiff(&ltmp1, &tmp1);
    /* Y3 = alpha*(4*beta-X3)-8*gamma^2 */
    FelemReduce(&pointOut->y, &ltmp1);
}

/*
 *  "add-2007-bl"
 *    Z1Z1 = Z1^2
 *    Z2Z2 = Z2^2
 *    U1 = X1*Z2Z2
 *    S1 = Y1*Z2*Z2Z2
 *    U2 = X2*Z1Z1
 *    S2 = Y2*Z1*Z1Z1
 *    H = U2-U1
 *    r = 2*(S2-S1)
 *    I = (2*H)^2
 *    J = H*I
 *    V = U1*I
 *    X3 = r^2-J-2*V
 *    Y3 = r*(V-X3)-2*S1*J
 *    Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
*/
/* Calculate the point addition coordinates, pt3 = pt1 + pt2 */
static void FelemPointAdd(Point *pt3, const Point *pt1, const Point *pt2)
{
    uint64_t pointEqual, xEqual, yEqual, z1Zero, z2Zero;
    Felem z1z1, z2z2, u1, u2, s1, s2, h, r, i, j, v, tmp1;
    Point res;
    LongFelem ltmp1;

    /* Z1Z1 = Z1^2 */
    FelemSqrReduce(&z1z1, &pt1->z);
    z1Zero = FelemContract(&z1z1);              // z1z1[i] < 2^58

    /* Z2Z2 = Z2^2 */
    FelemSqrReduce(&z2z2, &pt2->z);
    z2Zero = FelemContract(&z2z2);              // z2z2[i] < 2^58

    /* U1 = X1*Z2Z2 */
    FelemMulReduce(&u1, &pt1->x, &z2z2);        // u1[i] < 2^59 + 2^14

    /* S1 = Y1*Z2*Z2Z2 */
    FelemMulReduce(&tmp1, &pt1->y, &pt2->z);
    FelemMulReduce(&s1, &tmp1, &z2z2);          // s1[i] < 2^59 + 2^14

    /* U2 = X2*Z1Z1 */
    FelemMulReduce(&u2, &pt2->x, &z1z1);        // u2[i] < 2^59 + 2^14

    /* S2 = Y2*Z1*Z1Z1 */
    FelemMulReduce(&tmp1, &pt2->y, &pt1->z);
    FelemMulReduce(&s2, &tmp1, &z1z1);          // s2[i] < 2^59 + 2^14

    /* H = U2-U1 */
    FelemSub(&h, &u2, &u1);
    xEqual = FelemContract(&h);                 // h[i] < 2^58

    /* r = 2*(S2-S1) */
    FelemSub(&tmp1, &s2, &s1);
    yEqual = FelemContract(&tmp1);
    /* If the coordinates are equal, use the double point formula. */
    pointEqual = (xEqual & yEqual & (~z1Zero) & (~z2Zero));
    if (pointEqual != 0) {
        FelemPointDouble(pt3, pt1);
        return;
    }
    FelemMulLimb(&r, &tmp1, 2);                 // r[i] < 2^59

    /* I = (2*h)^2 */
    FelemMulLimb(&tmp1, &h, 2);                 // tmp1[i] < 2^59
    FelemSqrReduce(&i, &tmp1);

    /* J = H*I */
    FelemMulReduce(&j, &h, &i);                 // j[i] < 2^59 + 2^14

    /* v = U1*I */
    FelemMulReduce(&v, &u1, &i);                // v[i] < 2^59 + 2^14

    /* X3 = r^2-j-2*v */
    FelemSqr(&ltmp1, &r);                       // ltmp1[i] < 17*2^118
    FelemMulLimb(&tmp1, &v, 2);                 // tmp1[i] < 2^60 + 2^15
    FelemAdd(&tmp1, &tmp1, &j);                 // tmp1[i] < 3*(2^59 + 2^14)
    LongFelemDiff(&ltmp1, &tmp1);               // ltmp1 < 2^123
    FelemReduce(&res.x, &ltmp1);                // x[i] < 2^59 + 2^14

    /* Y3 = r*(v-X3)-2*S1*j */
    FelemSub(&tmp1, &v, &res.x);                // tmp1[i] < 5*2^59 + 2^14
    FelemMul(&ltmp1, &r, &tmp1);                // ltmp1[i] < 17*(5*2^59 + 2^14)*(2^59) < 2^125
    FelemMulReduce(&tmp1, &s1, &j);             // tmp1[i] < 2^59 + 2^14
    FelemMulLimb(&tmp1, &tmp1, 2);              // tmp1[i] < 2^60 + 2^15
    LongFelemDiff(&ltmp1, &tmp1);               // ltmp1[i] < 2^125 + 2^64 - 2^6
    FelemReduce(&res.y, &ltmp1);                // y3[i] < 2^59 + 2^14

    /* Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H */
    FelemAdd(&tmp1, &pt1->z, &pt2->z);          // tmp1[i] < 2^60 + 2^15
    FelemSqr(&ltmp1, &tmp1);                    // ltmp1[i] < 17*(2^120 + 2^76 + 2^30)
    FelemAdd(&tmp1, &z1z1, &z2z2);              // tmp1[i] < 2^59
    LongFelemDiff(&ltmp1, &tmp1);               // ltmp1[i] < 2^125
    FelemReduce(&tmp1, &ltmp1);                 // tmp1[i] < 2^59 + 2^14
    FelemMulReduce(&res.z, &tmp1, &h);          // z3[i] < 2^59 + 2^14

    FelemPointAssignWithMask(&res, pt2, z1Zero);
    FelemPointAssignWithMask(&res, pt1, z2Zero);
    FelemPointAssign(pt3, &res);
}

/*
 * "madd-2007-bl"
 *    Z1Z1 = Z1^2
 *    U2 = X2*Z1Z1
 *    S2 = Y2*Z1*Z1Z1
 *    H = U2-X1
 *    r = 2*(S2-Y1)
 *    HH = H^2
 *    I = 4*HH
 *    J = H*I
 *    V = X1*I
 *    X3 = r^2-J-2*V
 *    Y3 = r*(V-X3)-2*Y1*J
 *    Z3 = (Z1+H)^2-Z1Z1-HH
*/
/* Calculate the points coordinates addition in the mixed coordinate system, pt3 = pt1 + pt2, z2 == 1 */
static void FelemPointMixAdd(Point *pt3, const Point *pt1, const Point *pt2)
{
    uint64_t pointEqual, xEqual, yEqual, z1Zero, z2Zero;
    Felem z1z1, h, hh, r, i, j, v, tmp1, tmp2;
    Point res;
    LongFelem ltmp1;

    /* Z1Z1 = Z1^2 */
    FelemSqrReduce(&z1z1, &pt1->z);
    z1Zero = FelemContract(&z1z1);              // z1z1[i] < 2^58

    FelemAssign(&tmp1, &pt2->z);
    z2Zero = FelemContract(&tmp1);

    /* U2 = X2*Z1Z1 */
    FelemMulReduce(&tmp2, &pt2->x, &z1z1);      // tmp2[i] < 2^59 + 2^14

    /* S2 = Y2*Z1*Z1Z1 */
    FelemMulReduce(&tmp1, &pt2->y, &pt1->z);
    FelemMulReduce(&tmp1, &tmp1, &z1z1);        // tmp1[i] < 2^59 + 2^14

    /* H = U2-X1 */
    FelemSub(&h, &tmp2, &pt1->x);
    xEqual = FelemContract(&h);                 // h[i] < 2^58

    /* r = 2*(S2-Y1) */
    FelemSub(&tmp1, &tmp1, &pt1->y);
    yEqual = FelemContract(&tmp1);
    /* If the coordinates are equal, use the double point formula. */
    pointEqual = (xEqual & yEqual & (~z1Zero) & (~z2Zero));
    if (pointEqual != 0) {
        FelemPointDouble(pt3, pt1);
        return;
    }
    FelemMulLimb(&r, &tmp1, 2);                 // r[i] < 2^59

    /* HH = H^2 */
    FelemSqrReduce(&hh, &h);                    // hh[i] < 2^59 + 2^14

    /* I = 4*HH */
    FelemMulLimb(&i, &hh, 4);                   // i[i] < 2^61 + 2^16

    /* J = H*I */
    FelemMulReduce(&j, &h, &i);                 // j[i] < 2^59 + 2^14

    /* V = X1*I */
    FelemMulReduce(&v, &pt1->x, &i);            // v[i] < 2^59 + 2^14

    /* X3 = r^2-J-2*V */
    FelemMulLimb(&tmp1, &v, 2);                 // tmp1[i] < 2^60 + 2^15
    FelemAdd(&tmp2, &j, &tmp1);                 // tmp2[i] < 3*2^59 + 3*2^14
    FelemSqr(&ltmp1, &r);                       // ltmp1[i] < 17*2^118
    LongFelemDiff(&ltmp1, &tmp2);               // ltmp1[i] < 2^123
    FelemReduce(&res.x, &ltmp1);                // x3[i] < 2^59 + 2^14

    /* Y3 = r*(V-X3)-2*Y1*J */
    FelemSub(&tmp1, &v, &res.x);                // tmp1[i] < 5*2^59 + 2^14
    FelemMul(&ltmp1, &r, &tmp1);                // ltmp1[i] < 17*(5*2^59 + 2^14)*(2^59) < 2^125
    FelemMulReduce(&tmp2, &pt1->y, &j);         // tmp2[i] < 2^59 + 2^14
    FelemMulLimb(&tmp1, &tmp2, 2);              // tmp1[i] < 2^60 + 2^15
    LongFelemDiff(&ltmp1, &tmp1);               // ltmp1[i] < 2^125 + 2^64 - 2^6
    FelemReduce(&res.y, &ltmp1);                // y3[i] < 2^59 + 2^14

    /* Z3 = (Z1+H)^2-Z1Z1-HH */
    FelemAdd(&tmp1, &pt1->z, &h);               // tmp1[i] < 3*2^59 + 2^14
    FelemSqr(&ltmp1, &tmp1);                    // ltmp1[i] < 17*(9*2^118 + 3*2^74 + 2^28)
    FelemAdd(&tmp2, &z1z1, &hh);                // tmp2[i] < 3*2^59 + 2^14
    LongFelemDiff(&ltmp1, &tmp2);               // ltmp1[i] < 2^126
    FelemReduce(&res.z, &ltmp1);                // z3[i] < 2^59 + 2^14

    FelemPointAssignWithMask(&res, pt2, z1Zero);
    FelemPointAssignWithMask(&res, pt1, z2Zero);
    FelemPointAssign(pt3, &res);
}

/*
 *  Y = 2*Y
 *  W = Z^4
 *  while (m > 0) {
 *      A = 3*(X^2-W)
 *      B = X*Y^2
 *      X = A^2-2*B
 *      Z = Z*Y
 *      m = m-1
 *      if (m > 0) {
 *          W = W*Y^4
 *      }
 *      Y = 2*A*(B-X)-Y^4
 *  }
 *  Y = Y/2
*/
static void FelemPointMultDouble(Point *pointOut, const Point *pointIn, int32_t m)
{
    Felem x, y, z;
    Felem w, a, b;
    Felem tmp1, tmp2, tmp3;
    LongFelem ltmp1;
    int32_t left = m;
    if (left == 1) {
        FelemPointDouble(pointOut, pointIn);
        return;
    }

    FelemAssign(&x, &pointIn->x);
    FelemAssign(&z, &pointIn->z);
    /* Y = 2*Y */
    FelemMulLimb(&y, &pointIn->y, 2);           // y[i] < 2^60 + 2^15
    /* W = Z^4 */
    FelemSqrReduce(&tmp1, &pointIn->z);
    FelemSqrReduce(&w, &tmp1);                  // w[i] < 2^59 + 2^14
    while (left > 0) {
        /* A = 3*(X^2-W) */
        FelemSqr(&ltmp1, &x);                   // ltmp1[i] < 17*(2^118 + 2^74 + 2^28) < 17*(2^118 + 2^75)
        LongFelemDiff(&ltmp1, &w);              // ltmp1[i] < 18*2^118
        LongFelemMulLimb(&ltmp1, &ltmp1, 3);    // ltmp1[i] < 3*18*2^118 < 2^124
        FelemReduce(&a, &ltmp1);                // a[i] < 2^59 + 2^14

        /* B = X*Y^2 */
        FelemSqrReduce(&tmp3, &y);              // tmp3[i] < 2^59 + 2^14, tmp3 = Y^2
        FelemMulReduce(&b, &x, &tmp3);          // b[i] < 2^59 + 2^14

        /* X = A^2-2*B */
        FelemSqr(&ltmp1, &a);                   // ltmp1[i] < 17*(2^118 + 2^74 + 2^28) < 17*(2^118 + 2^75)
        FelemMulLimb(&tmp1, &b, 2);             // tmp1[i] < 2^60 + 2^15
        LongFelemDiff(&ltmp1, &tmp1);           // ltmp1[i] < 18*2^118
        FelemReduce(&x, &ltmp1);                // x[i] < 2^59 + 2^14

        /* Z = Z*Y */
        FelemMulReduce(&z, &z, &y);             // z[i] < 2^59 + 2^14
        FelemSqrReduce(&tmp3, &tmp3);           // tmp3[i] < 2^59 + 2^14, tmp3 = Y^4
        left--;
        if (left > 0) {
            /* W = W*Y^4 */
            FelemMulReduce(&w, &tmp3, &w);      // w[i] < 2^59 + 2^14
        }

        /* Y = 2*A*(B-X)-Y^4 */
        FelemMulLimb(&tmp1, &a, 2);             // tmp1[i] < 2^60 + 2^15
        FelemSub(&tmp2, &b, &x);                // b[i] < 5*2^59 + 2^14
        FelemMul(&ltmp1, &tmp1, &tmp2);         // ltmp1[i] < 17*(5*2^119 + 6*2^74 + 2^29) < 2^126
        LongFelemDiff(&ltmp1, &tmp3);           // ltmp1[i] < 2^126 + 2^64
        FelemReduce(&y, &ltmp1);
    }

    /* Y = Y/2 */
    FelemDivTwo(&pointOut->y, &y);
    FelemAssign(&pointOut->x, &x);
    FelemAssign(&pointOut->z, &z);
}

/*
 * Pre-computation table of base point G, which contains the X, Y, Z coordinates of n*G.
 *
 * index      corresponding bit                       Value of n
 *   0              0 0 0 0                    0     + 0     + 0     + 0
 *   1              0 0 0 1                    0     + 0     + 0     + 1
 *   2              0 0 1 0                    0     + 0     + 2^130 + 0
 *   3              0 0 1 1                    0     + 0     + 2^130 + 1
 *   4              0 1 0 0                    0     + 2^260 + 0     + 0
 *   5              0 1 0 1                    0     + 2^260 + 0     + 1
 *   6              0 1 1 0                    0     + 2^260 + 2^130 + 0
 *   7              0 1 1 1                    0     + 2^260 + 2^130 + 1
 *   8              1 0 0 0                    2^390 + 0     + 0     + 0
 *   9              1 0 0 1                    2^390 + 0     + 0     + 1
 *  10              1 0 1 0                    2^390 + 0     + 2^130 + 0
 *  11              1 0 1 1                    2^390 + 0     + 2^130 + 1
 *  12              1 1 0 0                    2^390 + 2^260 + 0     + 0
 *  13              1 1 0 1                    2^390 + 2^260 + 0     + 1
 *  14              1 1 1 0                    2^390 + 2^260 + 2^130 + 0
 *  15              1 1 1 1                    2^390 + 2^260 + 2^130 + 1
 */
static const Point PRE_COMPUTE_G[TABLE_G_SIZE] = {
    {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {{0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {{0, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x017e7e31c2e5bd66, 0x022cf0615a90a6fe, 0x00127a2ffa8de334,
          0x01dfbf9d64a3f877, 0x006b4d3dbaa14b5e, 0x014fed487e0a2bd8,
          0x015b4429c6481390, 0x03a73678fb2d988e, 0x00c6858e06b70404}},
        {{0x00be94769fd16650, 0x031c21a89cb09022, 0x039013fad0761353,
          0x02657bd099031542, 0x03273e662c97ee72, 0x01e6d11a05ebef45,
          0x03d1bd998f544495, 0x03001172297ed0b1, 0x011839296a789a3b}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x0373faacbc875bae, 0x00f325023721c671, 0x00f666fd3dbde5ad,
          0x01a6932363f88ea7, 0x01fc6d9e13f9c47b, 0x03bcbffc2bbf734e,
          0x013ee3c3647f3a92, 0x029409fefe75d07d, 0x00ef9199963d85e5}},
        {{0x011173743ad5b178, 0x02499c7c21bf7d46, 0x035beaeabb8b1a58,
          0x00f989c4752ea0a3, 0x0101e1de48a9c1a3, 0x01a20076be28ba6c,
          0x02f8052e5eb2de95, 0x01bfe8f82dea117c, 0x0160074d3c36ddb7}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x012f3fc373393b3b, 0x03d3d6172f1419fa, 0x02adc943c0b86873,
          0x00d475584177952b, 0x012a4d1673750ee2, 0x00512517a0f13b0c,
          0x02b184671a7b1734, 0x0315b84236f1a50a, 0x00a4afc472edbdb9}},
        {{0x00152a7077f385c4, 0x03044007d8d1c2ee, 0x0065829d61d52b52,
          0x00494ff6b6631d0d, 0x00a11d94d5f06bcf, 0x02d2f89474d9282e,
          0x0241c5727c06eeb9, 0x0386928710fbdb9d, 0x01f883f727b0dfbe}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x019b0c3c9185544d, 0x006243a37c9d97db, 0x02ee3cbe030a2ad2,
          0x00cfdd946bb51e0d, 0x0271c00932606b91, 0x03f817d1ec68c561,
          0x03f37009806a369c, 0x03c1f30baf184fd5, 0x01091022d6d2f065}},
        {{0x0292c583514c45ed, 0x0316fca51f9a286c, 0x00300af507c1489a,
          0x0295f69008298cf1, 0x02c0ed8274943d7b, 0x016509b9b47a431e,
          0x02bc9de9634868ce, 0x005b34929bffcb09, 0x000c1a0121681524}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x0286abc0292fb9f2, 0x02665eee9805b3f7, 0x01ed7455f17f26d6,
          0x0346355b83175d13, 0x006284944cd0a097, 0x0191895bcdec5e51,
          0x02e288370afda7d9, 0x03b22312bfefa67a, 0x01d104d3fc0613fe}},
        {{0x0092421a12f7e47f, 0x0077a83fa373c501, 0x03bd25c5f696bd0d,
          0x035c41e4d5459761, 0x01ca0d1742b24f53, 0x00aaab27863a509c,
          0x018b6de47df73917, 0x025c0b771705cd01, 0x01fd51d566d760a7}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x01dd92ff6b0d1dbd, 0x039c5e2e8f8afa69, 0x0261ed13242c3b27,
          0x0382c6e67026e6a0, 0x01d60b10be2089f9, 0x03c15f3dce86723f,
          0x03c764a32d2a062d, 0x017307eac0fad056, 0x018207c0b96c5256}},
        {{0x0196a16d60e13154, 0x03e6ce74c0267030, 0x00ddbf2b4e52a5aa,
          0x012738241bbf31c8, 0x00ebe8dc04685a28, 0x024c2ad6d380d4a2,
          0x035ee062a6e62d0e, 0x0029ed74af7d3a0f, 0x00eef32aec142ebd}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x00c31ec398993b39, 0x03a9f45bcda68253, 0x00ac733c24c70890,
          0x00872b111401ff01, 0x01d178c23195eafb, 0x03bca2c816b87f74,
          0x0261a9af46fbad7a, 0x0324b2a8dd3d28f9, 0x00918121d8f24e23}},
        {{0x032bc8c1ca983cd7, 0x00d869dfb08fc8c6, 0x01693cb61fce1516,
          0x012a5ea68f4e88a8, 0x010869cab88d7ae3, 0x009081ad277ceee1,
          0x033a77166d064cdc, 0x03955235a1fb3a95, 0x01251a4a9b25b65e}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x00148a3a1b27f40b, 0x0123186df1b31fdc, 0x00026e7beaad34ce,
          0x01db446ac1d3dbba, 0x0299c1a33437eaec, 0x024540610183cbb7,
          0x0173bb0e9ce92e46, 0x02b937e43921214b, 0x01ab0436a9bf01b5}},
        {{0x0383381640d46948, 0x008dacbf0e7f330f, 0x03602122bcc3f318,
          0x01ee596b200620d6, 0x03bd0585fda430b3, 0x014aed77fd123a83,
          0x005ace749e52f742, 0x0390fe041da2b842, 0x0189a8ceb3299242}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x012a19d6b3282473, 0x00c0915918b423ce, 0x023a954eb94405ae,
          0x00529f692be26158, 0x0289fa1b6fa4b2aa, 0x0198ae4ceea346ef,
          0x0047d8cdfbdedd49, 0x00cc8c8953f0f6b8, 0x001424abbff49203}},
        {{0x0256732a1115a03a, 0x0351bc38665c6733, 0x03f7b950fb4a6447,
          0x000afffa94c22155, 0x025763d0a4dab540, 0x000511e92d4fc283,
          0x030a7e9eda0ee96c, 0x004c3cd93a28bf0a, 0x017edb3a8719217f}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x011de5675a88e673, 0x031d7d0f5e567fbe, 0x0016b2062c970ae5,
          0x03f4a2be49d90aa7, 0x03cef0bd13822866, 0x03f0923dcf774a6c,
          0x0284bebc4f322f72, 0x016ab2645302bb2c, 0x01793f95dace0e2a}},
        {{0x010646e13527a28f, 0x01ca1babd59dc5e7, 0x01afedfd9a5595df,
          0x01f15785212ea6b1, 0x0324e5d64f6ae3f4, 0x02d680f526d00645,
          0x0127920fadf627a7, 0x03b383f75df4f684, 0x0089e0057e783b0a}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x00f334b9eb3c26c6, 0x0298fdaa98568dce, 0x01c2d24843a82292,
          0x020bcb24fa1b0711, 0x02cbdb3d2b1875e6, 0x0014907598f89422,
          0x03abe3aa43b26664, 0x02cbf47f720bc168, 0x0133b5e73014b79b}},
        {{0x034aab5dab05779d, 0x00cdc5d71fee9abb, 0x0399f16bd4bd9d30,
          0x03582fa592d82647, 0x02be1cdfb775b0e9, 0x0034f7cea32e94cb,
          0x0335a7f08f56f286, 0x03b707e9565d1c8b, 0x0015c946ea5b614f}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x024676f6cff72255, 0x00d14625cac96378, 0x00532b6008bc3767,
          0x01fc16721b985322, 0x023355ea1b091668, 0x029de7afdc0317c3,
          0x02fc8a7ca2da037c, 0x02de1217d74a6f30, 0x013f7173175b73bf}},
        {{0x0344913f441490b5, 0x0200f9e272b61eca, 0x0258a246b1dd55d2,
          0x03753db9ea496f36, 0x025e02937a09c5ef, 0x030cbd3d14012692,
          0x01793a67e70dc72a, 0x03ec1d37048a662e, 0x006550f700c32a8d}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x00d3f48a347eba27, 0x008e636649b61bd8, 0x00d3b93716778fb3,
          0x004d1915757bd209, 0x019d5311a3da44e0, 0x016d1afcbbe6aade,
          0x0241bf5f73265616, 0x0384672e5d50d39b, 0x005009fee522b684}},
        {{0x029b4fab064435fe, 0x018868ee095bbb07, 0x01ea3d6936cc92b8,
          0x000608b00f78a2f3, 0x02db911073d1c20f, 0x018205938470100a,
          0x01f1e4964cbe6ff2, 0x021a19a29eed4663, 0x01414485f42afa81}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x01612b3a17f63e34, 0x03813992885428e6, 0x022b3c215b5a9608,
          0x029b4057e19f2fcb, 0x0384059a587af7e6, 0x02d6400ace6fe610,
          0x029354d896e8e331, 0x00c047ee6dfba65e, 0x0037720542e9d49d}},
        {{0x02ce9eed7c5e9278, 0x0374ed703e79643b, 0x01316c54c4072006,
          0x005aaa09054b2ee8, 0x002824000c840d57, 0x03d4eba24771ed86,
          0x0189c50aabc3bdae, 0x0338c01541e15510, 0x00466d56e38eed42}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x007efd8330ad8bd6, 0x02465ed48047710b, 0x0034c6606b215e0c,
          0x016ae30c53cbf839, 0x01fa17bd37161216, 0x018ead4e61ce8ab9,
          0x005482ed5f5dee46, 0x037543755bba1d7f, 0x005e5ac7e70a9d0f}},
        {{0x0117e1bb2fdcb2a2, 0x03deea36249f40c4, 0x028d09b4a6246cb7,
          0x03524b8855bcf756, 0x023d7d109d5ceb58, 0x0178e43e3223ef9c,
          0x0154536a0c6e966a, 0x037964d1286ee9fe, 0x0199bcd90e125055}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }
};

/*
 * Pre-computation table of base point G, which contains the X, Y, Z coordinates of n*G.
 *
 * index       corresponding bit                      value of n
 *   0              0 0 0 0                   0     + 0     + 0     + 0
 *   1              0 0 0 1                   0     + 0     + 0     + 2^65
 *   2              0 0 1 0                   0     + 0     + 2^195 + 0
 *   3              0 0 1 1                   0     + 0     + 2^195 + 2^65
 *   4              0 1 0 0                   0     + 2^325 + 0     + 0
 *   5              0 1 0 1                   0     + 2^325 + 0     + 2^65
 *   6              0 1 1 0                   0     + 2^325 + 2^195 + 0
 *   7              0 1 1 1                   0     + 2^325 + 2^195 + 2^65
 *   8              1 0 0 0                   2^455 + 0     + 0     + 0
 *   9              1 0 0 1                   2^455 + 0     + 0     + 2^65
 *  10              1 0 1 0                   2^455 + 0     + 2^195 + 0
 *  11              1 0 1 1                   2^455 + 0     + 2^195 + 2^65
 *  12              1 1 0 0                   2^455 + 2^325 + 0     + 0
 *  13              1 1 0 1                   2^455 + 2^325 + 0     + 2^65
 *  14              1 1 1 0                   2^455 + 2^325 + 2^195 + 0
 *  15              1 1 1 1                   2^455 + 2^325 + 2^195 + 2^65
 */
static const Point PRE_COMPUTE_G2[TABLE_G_SIZE] = {
    {
        {{0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {{0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {{0, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x0192b0164b374ff4, 0x037b520497f54a7c, 0x00ac45dfa717d3aa,
          0x012692d390795d21, 0x013153d4af815b65, 0x01dda688f88c3a92,
          0x0205e32bd883b127, 0x025156b962597ab5, 0x00a54cc9cfcf7717}},
        {{0x00fe2ea43f30741f, 0x0144a9495978f5d7, 0x035adaea005bd79c,
          0x009dff281db66901, 0x00166a36786b2593, 0x01d7f68c07aa0052,
          0x013e05225075d36d, 0x03181b67caeea6b5, 0x009004fc6adc182a}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x0287bbca1236bec1, 0x03aaf618239ad718, 0x013ef15fcd3c6c16,
          0x031f697f988c94c6, 0x01ac806cb8d4ee71, 0x0035f8035894c512,
          0x00a16689152cf169, 0x02236a87815c0f48, 0x014f6480d486bbf5}},
        {{0x03f70ab3fe2753e3, 0x03d291808faf7e0d, 0x00d7d89caf63a562,
          0x029ead2c77ee5cd6, 0x022c8c3421387422, 0x02e384f360359525,
          0x01901927d338b4bd, 0x0010c294d54a76b1, 0x00c739a28761a676}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x0321984bf604e26a, 0x00a0a4346e1beaa6, 0x03959055560b38f4,
          0x001c383384c9b58c, 0x013212bf16c0badc, 0x00fc4f13c1530004,
          0x0297632bcdf70503, 0x0306dbd604f5574d, 0x016c53a4d13a129b}},
        {{0x03534a0ccd1d6c44, 0x02279af4660bfa03, 0x030eb700f21771d7,
          0x01134017e2c6529e, 0x0237abadf41d7409, 0x03547fae79ff1ce6,
          0x027b74026ac60650, 0x038912af6d6a8213, 0x00c3257758f97db5}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x037d9850fb6f765b, 0x01b6f2b4333f3817, 0x025e9d97d6f42afe,
          0x00a0ddfdfa42799a, 0x02bfc71aab1b4029, 0x0378d9bd912c361e,
          0x012c4f53cffd5151, 0x03a0621175f5d2ca, 0x0017e0822ef93f88}},
        {{0x03f7c1d7104d2069, 0x03848b7b03f6c63f, 0x003395646b614e53,
          0x0342d1dd97dbc1e9, 0x022cb3def43f2341, 0x02a5f4833f79b757,
          0x037b25687d324787, 0x031f409c8d51daf2, 0x010bb03f98dc9303}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x03efcaf76c0f7bd7, 0x015b1ffdf6ccf484, 0x0263903e662a439d,
          0x036dfdd7c185fe97, 0x015b51f55e640b08, 0x01b1764270cbce73,
          0x01e346d1bb5c8f2a, 0x03199be2199e0b68, 0x004adb8d3d68e650}},
        {{0x019bce039c0da6bf, 0x0280560629ade3b2, 0x01418eb6001c82e3,
          0x01e464b38910b655, 0x02b21034d1a402e4, 0x028c2df0b056c5fa,
          0x032be9714380fe04, 0x01f9ecd5a9a2fcca, 0x015aa21ec32e0387}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x036ad61ba5561dd5, 0x02dab309a8810a66, 0x037393ceee004b75,
          0x001e6bf8a4921c61, 0x0316b2aa5307a051, 0x0014c93b7032e644,
          0x03f6b33b796d11e2, 0x023d7387badaa578, 0x003387854547b6ca}},
        {{0x002d4c5b57434eda, 0x01d6e1888a73d938, 0x0018f0f64605d2fa,
          0x028a20eeb35b0cc6, 0x03b68c858d509955, 0x01141d740c8bd567,
          0x010750725080144c, 0x023d6ac06393f441, 0x0042923f464fb5d1}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x037549a3c618e088, 0x008b414778fa66e4, 0x00723b6b05db1367,
          0x013e930419c79520, 0x0191ed1c4447ff41, 0x00bee132be6a81cb,
          0x02fa7516973beafc, 0x02e25b501cead6d6, 0x01fdb7d1dc08792c}},
        {{0x039cb1f8f679b9d1, 0x0083db2827d85eaf, 0x03b023aa80726182,
          0x022a7457eb1c3efa, 0x03caef438de54158, 0x033997a18583466f,
          0x02d7bffa14e33c59, 0x001b92a9cd69ce59, 0x0113258b03a75ad8}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x0324c5b4c56caae5, 0x0151cedc6869fdbe, 0x039370cf6ff1d385,
          0x00d2d6b3a7948969, 0x0126b6384f3cdb06, 0x02f045c111b79e63,
          0x00519f9f1ede134e, 0x03baffa03938dd55, 0x0179812e76db6349}},
        {{0x00b69f323b354956, 0x01e0bb3f034a976c, 0x02befa0dff80f27c,
          0x0098b221eb08aecb, 0x030ca3bf38ae8e58, 0x01327945cb922185,
          0x0308de377b1b7b43, 0x03ab15750b28636d, 0x0091c1b0482a4305}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x02c1b0be6b746613, 0x00478b27bfbe1387, 0x03ac86e5d9c6a2d3,
          0x034f25d578d34127, 0x014e05b75ec6fecc, 0x01f44f38b4e2189f,
          0x00660fddda38b664, 0x03d587c9195d6412, 0x00e9dcec7d477b78}},
        {{0x03321366097b5fe6, 0x011364f5be162f87, 0x03d074359e750aaa,
          0x01d55171921585a2, 0x022527bb5c6eb7c7, 0x01428f6af0426fe3,
          0x0036bb94e1d4d74e, 0x03c7c757a44dbe6a, 0x0088a86c9ed6cbef}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x02bff33e6cbff097, 0x019cccbe703a64a6, 0x01e7d4c24e09e350,
          0x021908a33eaf46a0, 0x01a07762f8cc7516, 0x01e12df29d8644c9,
          0x0098c656997c8284, 0x0373d9622e713265, 0x01ff6b101932f0be}},
        {{0x0048f9e92e2c1256, 0x033fae66bf45eb34, 0x0341ddb09e352f2b,
          0x0019a6a6560f97fe, 0x02cda473f1bd03ab, 0x013c344018f55636,
          0x00329598b2276e7e, 0x0388a96e2249b63f, 0x00b6d123f38483d2}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x02a97232bae87062, 0x0069587df4826cd5, 0x021402a5fdf14035,
          0x026f406d0b49dc31, 0x01efc862b95739c4, 0x00a6e35dc23a4083,
          0x0385b4e2faa85fd8, 0x01deae552ff5231e, 0x019e03275123852a}},
        {{0x0120d17ebd7a996d, 0x00a56e635a2ab069, 0x03a2d775353348fe,
          0x02c60edc1e521033, 0x01078fbf7ab9fefc, 0x0375262d1601e76e,
          0x00d963629d272a65, 0x027c82575888f1bb, 0x013629c8c2a9841f}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x02634027d95abe73, 0x01c2e2ef1799e9c6, 0x02eedf3cf13b5ffc,
          0x0060e6a5de211043, 0x01a7806f233bb516, 0x0355633a88a8638c,
          0x01dcbcc58d7d5dcc, 0x02071903acda896f, 0x01dce602b80ca444}},
        {{0x013c47920922ddb6, 0x013f221e68d728d8, 0x0128ca5192ab3cb8,
          0x002a19a405f6d544, 0x0074330020d40403, 0x0085611df0ce1a97,
          0x028fda4edff5fc93, 0x0303b834136862a5, 0x00f443f3b7cd86cf}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x00f5614d1673ed2e, 0x03e442a78b43dbb3, 0x02408ebf00c8324c,
          0x0043b6f94f69ea8b, 0x02a32bb5a7c8f6ac, 0x02b7758b243883fa,
          0x00f4bd68881089bf, 0x03f61eb91693a587, 0x001d298cf9f11b0b}},
        {{0x00ee97751d8d6f36, 0x0318dcb929941397, 0x022cf9840311e590,
          0x02fc6b1da06aae09, 0x0134298323032dcf, 0x00d7b9072d9bb059,
          0x01a099906260485b, 0x037d9ca3796ce405, 0x0147a49ba1ca4467}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x030993f7ba6f7b2c, 0x019720e705ec5bc1, 0x001c9ee10167839e,
          0x0378869753d92351, 0x02bb1ace9f456b2e, 0x0336d504d809599d,
          0x02d549f9910bffd0, 0x019c6284b1ec6150, 0x00c67a7fcc4ffb2c}},
        {{0x022fe778c100a1dc, 0x01d14e5e8e693cb1, 0x03c139f63d3a44d9,
          0x01d0b45344a8a5c9, 0x0253f5e630be559d, 0x01eaad81980912b1,
          0x003febb5458d1ece, 0x01c6d59feaae8cfd, 0x01c3558976ca7dd7}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }, {
        {{0x01ec0d67348526ae, 0x0334bb61a85f8ed5, 0x0286ba7fecf2d764,
          0x01600344518c0c0c, 0x034e83852188ae46, 0x023d71754d3c015c,
          0x010eeccfb5a5a825, 0x004247e9a02cded9, 0x0187b9aa607ca24c}},
        {{0x00e77b967bc701ac, 0x022a2a00ef91bdc3, 0x01fa7bfaf46148d2,
          0x003feb6276929d54, 0x028ad7f3a3f075ca, 0x035f6ba48b87bd53,
          0x03fd400e74a80040, 0x0150a714837d88b5, 0x003969fa95c4e093}},
        {{1, 0, 0, 0, 0, 0, 0, 0, 0}}
    }
};

/* Select the point with subscript index in the table and place it in the point.
   The anti-side channel processing exists. */
static void GetPointFromTable(Point *point, const Point table[],
                              uint32_t pointNum, const uint64_t index)
{
    uint64_t mask, i;
    for (i = 0; i < pointNum; i++) {
        /* If i is equal to index, the last mask is all Fs. Otherwise, the last mask is all 0s. */
        /* Shift rightwards by 63 bits and get the most significant bit. */
        mask = (0 - (i ^ index)) >> 63;
        mask--;
        /* Conditionally assign a value, which takes effect only when i = index. */
        FelemPointAssignWithMask(point, &table[i], mask);
    }
}

/*
 * Four bits at a fixed interval are intercepted from the scalar k1,
   and then decoded to obtain the index of the precomputation table G
 * input:
 *      k1  indicates a array of scalars, consisting of nine 64-bit data in little-endian order.
 *      i   Corresponding bit. The value is an integer ranging [0, 65]
 * output:
 *      Value range: 0–15, indicating the index of the pre-computation table.
 */
static void GetIndexOfTableG(uint64_t *value1, uint64_t *value2, const Array64 *k1, uint32_t i)
{
    // The scalar k1 contains a maximum of 521 bits. 521 = 65 * 4 * 2 + 1. Therefore, one bit needs special processing.
    if (i == 0) {
        *value1 = k1->data[0] & 1; // get the least significant bit of the scalar
        *value2 = 0;
    } else {
        uint64_t bits1, bits2;
        bits1 = GET_ARRAY64_BIT(k1, i + 390) << 3;   // 3rd corresponds to the scalar k1 bit: [391, 455]
        bits1 |= GET_ARRAY64_BIT(k1, i + 260) << 2;  // 2nd corresponds to the scalar k1 bit: [261, 325]
        bits1 |= GET_ARRAY64_BIT(k1, i + 130) << 1;  // 1st corresponds to the scalar k1 bit: [131, 195]
        bits1 |= GET_ARRAY64_BIT(k1, i);             // 0th corresponds to the scalar k1 bit: [1  , 65]
        *value1 = bits1;
        bits2 = GET_ARRAY64_BIT(k1, i + 455) << 3;   // 3rd corresponds to the scalar k1 bit: [456, 520]
        bits2 |= GET_ARRAY64_BIT(k1, i + 325) << 2;  // 2nd corresponds to the scalar k1 bit: [326, 390]
        bits2 |= GET_ARRAY64_BIT(k1, i + 195) << 1;  // 1st corresponds to the scalar k1 bit: [196, 260]
        bits2 |= GET_ARRAY64_BIT(k1, i + 65);        // 0th corresponds to the scalar k1 bit: [66 , 130]
        *value2 = bits2;
    }
}

/*
 * Six consecutive bits (i-1 to i+4) are intercepted from the scalar k2,
   and then decoded to obtain an index of the precomputation table P and a sign of a point
 * input:
 *      k2  indicates a array of scalars, consisting of nine 64-bit data in little-endian order.
 *      i   Corresponding bit. The value range is [0, 520], which can be exactly divisible by 5.
 * output:
 *      sign    0 or 1: indicates whether the corresponding point needs negation.
 *      value   0-16: indicates the index of the pre-computation table.
 */
static void GetIndexOfTableP(uint64_t *sign, uint64_t *value, const Array64 *k2, uint32_t i)
{
    uint32_t s, v;
    uint64_t bits;
    if (i == 0) {
        // When i is the least significant bit, only the four least significant bits of k2 are truncated.
        bits = k2->data[0] << 1;
    } else {
        uint32_t num = (i - 1) / 64;    // Each uint64_t contains 64 bits.
        uint32_t shift = (i - 1) % 64;  // Each uint64_t contains 64 bits.
        bits = (k2->data[num] >> shift);
        if (shift + 6 > 64) { // (64 - shift) bits have been truncated. If it is less than 6 bits, continue truncating.
            bits |= k2->data[num + 1] << (64 - shift);
        }
    }
    // truncates six bits. (5-bit signed number complement + 1-bit low-order carry flag)
    bits &= (1 << (WINDOW_SIZE + 1)) - 1;

    DecodeScalarCode(&s, &v, (uint32_t)bits);
    *sign = s;
    *value = v;
}

/*
 * Calculation point coordinate r = k1 * G + k2 * P
 * input:
 *      k1 a scalar multiplied by point G. If k1 is null, it will be not calculated.
 *      k2 a scalar multiplied by point P. If k1 is null, it will be not calculated.
 *      preCompute  P-point precalculation table (0P, 1P, ... 16P) 17 points in total.
 * output:
 *      r   Point of the calculation result
 */
static void FelemPointMul(Point *r, const Array64 *k1, const Array64 *k2,
                          const Point preCompute[TABLE_P_SIZE])
{
    Point res = {0}; // res is initialized to 0.
    Point tmp = {0};
    Felem negY;
    uint64_t mask, sign, index, index2;
    bool computeG = k1 != NULL;
    bool computeP = k2 != NULL;
    bool isZero = true; // Whether the res point is zero.
    int32_t step = computeP ? 5 : 1; // Times of one cycle multiple the point
    /* P point multiplication requires 520 times, and G point multiplication requires 65 times. */
    for (int32_t i = computeP ? 520 : 65; i >= 0; i -= step) {
        /* If the point out remains zero, the double point operation has no effect, skipping */
        if (!isZero) {
            FelemPointMultDouble(&res, &res, step);
        }
        // Calculate the multiplication of point G. i starts calculation in the range [0, 65].
        if (computeG && (i <= 65)) {
            /* If the G-point multiplication starts, the step of the multiple point needs to be changed to 1. */
            step = 1;
            /* Obtain the corresponding bits. */
            GetIndexOfTableG(&index, &index2, k1, (uint32_t)i);
            /* Add the points in Table 1 */
            if (isZero) {
                /* If the point out is zero, the point addition operation is equivalent to direct assignment. */
                GetPointFromTable(&res, PRE_COMPUTE_G, TABLE_G_SIZE, index);
                isZero = false;
            } else {
                GetPointFromTable(&tmp, PRE_COMPUTE_G, TABLE_G_SIZE, index);
                // precomputation table G is all affine coordinates, use the hybrid coordinates for acceleration.
                FelemPointMixAdd(&res, &res, &tmp);
            }
            /* Add the points in Table 2 */
            if (i != 0) {
                GetPointFromTable(&tmp, PRE_COMPUTE_G2, TABLE_G_SIZE, index2);
                // precomputation table G2 is all affine coordinates, use the hybrid coordinates for acceleration.
                FelemPointMixAdd(&res, &res, &tmp);
            }
        }
        // Calculate the multiplication of point P. The calculation is performed every 5 bits.
        if (computeP && (i % 5 == 0)) {
            /* Obtain the corresponding bits. */
            GetIndexOfTableP(&sign, &index, k2, (uint32_t)i);
            GetPointFromTable(&tmp, preCompute, TABLE_P_SIZE, index);
            /* If the value is a negative number, the point is also negative. */
            FelemNeg(&negY, &tmp.y);
            mask = 0 - sign;
            FelemAssignWithMask(&tmp.y, &negY, mask);
            /* execute point addition */
            if (isZero) {
                /* If the point out is zero, the point addition operation is equivalent to direct assignment. */
                FelemPointAssign(&res, &tmp);
                isZero = false;
            } else {
                // precomputation table P is not necessarily affine coordinates, using Jacobian coordinates addition.
                FelemPointAdd(&res, &res, &tmp);
            }
        }
    }
    FelemPointAssign(r, &res);
}

/*
 * calculate pre-calculation table for the P point
 * input:
 *      pt  P point
 * output:
 *      preCompute  precalculation table of P point, (0P, 1P, ... 16P) 17 points in total
 */
static int32_t InitPreComputeTable(Point preCompute[TABLE_P_SIZE], const ECC_Point *pt)
{
    int32_t ret;
    /* zero point */
    FelemSetLimb(&preCompute[0].x, 0);
    FelemSetLimb(&preCompute[0].y, 0);
    FelemSetLimb(&preCompute[0].z, 0);
    /* 1x point */
    GOTO_ERR_IF_EX(BN2Felem(&preCompute[1].x, &pt->x), ret);
    GOTO_ERR_IF_EX(BN2Felem(&preCompute[1].y, &pt->y), ret);
    GOTO_ERR_IF_EX(BN2Felem(&preCompute[1].z, &pt->z), ret);
    /* 2 to 16x points */
    for (uint32_t i = 2; i < TABLE_P_SIZE; i++) {
        if ((i & 1) == 0) {
            /* If multiple for even times, use the multiple point formula (2n)*P = 2*(n*P), where i == 2n */
            FelemPointDouble(&preCompute[i], &preCompute[i / 2]);
        } else {
            /* If multiple for odd times, use the point addition formula n*P = P + (n-1)*P, where i == n */
            FelemPointAdd(&preCompute[i], &preCompute[1], &preCompute[i - 1]);
        }
    }
ERR:
    return ret;
}

static int32_t ComputePointMulAdd(Point *out, const Array64 *binG, const Array64 *binP, const ECC_Point *pt)
{
    // The stack space of a function cannot exceed 4096 bytes.
    // Therefore, the precomputation table is allocated by the function.
    Point preCompute[TABLE_P_SIZE]; /* Pre-calculation table of point pt */
    int32_t ret = InitPreComputeTable(preCompute, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    FelemPointMul(out, binG, binP, preCompute);
    return CRYPT_SUCCESS;
}

/* Calculate r = k1 * G + k2 * pt */
int32_t ECP521_PointMulAdd(ECC_Para *para, ECC_Point *r,
                           const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    int32_t ret;
    Array64 binG = {0};
    Array64 binP = {0};
    Point *out = NULL;
    uint32_t len;
    /* Input parameter check */
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP521), ret);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP521), ret);
    GOTO_ERR_IF(CheckBnValid(k1, FELEM_BITS), ret);
    GOTO_ERR_IF(CheckBnValid(k2, FELEM_BITS), ret);
    GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP521), ret);
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    /* Convert the input BigNum */
    len = NUM_LIMBS;
    GOTO_ERR_IF(BN_Bn2U64Array(k1, binG.data, &len), ret);
    len = NUM_LIMBS;
    GOTO_ERR_IF(BN_Bn2U64Array(k2, binP.data, &len), ret);
    /* Calculate */

    out = BSL_SAL_Malloc(sizeof(Point));
    if (out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GOTO_ERR_IF_EX(ComputePointMulAdd(out, &binG, &binP, pt), ret);
    /* Output result */
    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out->x), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out->y), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out->z), ret);
ERR:
    BSL_SAL_Free(out);
    return ret;
}

/* Calculate r = k * pt; If pt is NULL, calculate r = k * G. This is the ConstTime processing function. */
int32_t ECP521_PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    int32_t ret;
    Array64 bin = {0};
    uint32_t len = NUM_LIMBS;
    Point preCompute[TABLE_P_SIZE]; /* Pre-calculation table of Point pt */
    Point out;
    /* Input parameter check */
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP521), ret);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP521), ret);
    GOTO_ERR_IF(CheckBnValid(k, FELEM_BITS), ret);
    if (pt != NULL) {
        if (pt->id != CRYPT_ECC_NISTP521) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
            return CRYPT_ECC_POINT_ERR_CURVE_ID;
        }
        if (BN_IsZero(&pt->z)) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
            return CRYPT_ECC_POINT_AT_INFINITY;
        }
    }
    /* Convert the input BigNum */
    GOTO_ERR_IF(BN_Bn2U64Array(k, bin.data, &len), ret);
    /* Calculate */
    if (pt != NULL) {
        GOTO_ERR_IF_EX(InitPreComputeTable(preCompute, pt), ret);
        FelemPointMul(&out, NULL, &bin, preCompute);
    } else {
        FelemPointMul(&out, &bin, NULL, NULL);
    }
    /* Output result */
    GOTO_ERR_IF_EX(Felem2BN(&r->x, &out.x), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &out.y), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->z, &out.z), ret);
ERR:
    return ret;
}

static int32_t MakeAffineWithInv(ECC_Point *r, const ECC_Point *a, const Felem *zInv)
{
    int32_t ret;
    Felem x, y, tmp;
    GOTO_ERR_IF_EX(BN2Felem(&x, &a->x), ret);
    GOTO_ERR_IF_EX(BN2Felem(&y, &a->y), ret);
    FelemMulReduce(&y, &y, zInv);  // y/z
    FelemSqrReduce(&tmp, zInv);    // 1/(z^2)
    FelemMulReduce(&x, &x, &tmp);  // x/(z^2)
    FelemMulReduce(&y, &y, &tmp);  // y/(z^3)
    GOTO_ERR_IF_EX(Felem2BN(&r->x, &x), ret);
    GOTO_ERR_IF_EX(Felem2BN(&r->y, &y), ret);
    GOTO_ERR_IF_EX(BN_SetLimb(&r->z, 1), ret);
ERR:
    return ret;
}

/* Convert a point to affine coordinates. */
int32_t ECP521_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    int32_t ret;
    Felem z, zInv;
    /* Input parameter check */
    GOTO_ERR_IF(CheckParaValid(para, CRYPT_ECC_NISTP521), ret);
    GOTO_ERR_IF(CheckPointValid(r, CRYPT_ECC_NISTP521), ret);
    GOTO_ERR_IF(CheckPointValid(pt, CRYPT_ECC_NISTP521), ret);
    /* Special data processing */
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    /* Convert the input data. */
    GOTO_ERR_IF_EX(BN2Felem(&z, &pt->z), ret);
    /* Calculate and output result */
    FelemInv(&zInv, &z);
    GOTO_ERR_IF_EX(MakeAffineWithInv(r, pt, &zInv), ret);
ERR:
    return ret;
}

#endif /* defined(HITLS_CRYPTO_CURVE_NISTP521) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */
