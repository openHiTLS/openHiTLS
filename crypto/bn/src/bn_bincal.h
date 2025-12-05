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

#ifndef BN_BINCAL_H
#define BN_BINCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "bn_basic.h"

#if defined(HITLS_CRYPTO_BN_X8664)
    #include "bn_bincal_x8664.h"
#elif defined(HITLS_CRYPTO_BN_ARMV8)
    #include "bn_bincal_armv8.h"
#else
    #include "bn_bincal_noasm.h"
#endif

#ifdef __cplusplus
extern "c" {
#endif

/* r = a + b, input 'carry' means carry */
#define ADD_AB(carry, r, a, b)       \
    do {                             \
        BN_UINT macroTmpT = (a) + (b);     \
        (carry) = macroTmpT < (a) ? 1 : 0; \
        (r) = macroTmpT;                   \
    } while (0)

/* r = a - b, input 'borrow' means borrow digit */
#define SUB_AB(borrow, r, a, b)         \
    do {                                \
        BN_UINT macroTmpT = (a) - (b);        \
        (borrow) = ((a) < (b)) ? 1 : 0; \
        (r) = macroTmpT;                      \
    } while (0)

/* r = a - b - c, input 'borrow' means borrow digit */
#define SUB_ABC(borrow, r, a, b, c)         \
    do {                                    \
        BN_UINT macroTmpS = (a) - (b);            \
        BN_UINT macroTmpB = ((a) < (b)) ? 1 : 0;  \
        macroTmpB += (macroTmpS < (c)) ? 1 : 0;         \
        (r) = macroTmpS - (c);                    \
        borrow = macroTmpB;                       \
    } while (0)

#define BN_UINT_HALF_BITS (BN_UINT_BITS >> 1)

/* carry value of the upper part */
#define BN_UINT_HC ((BN_UINT)1 << BN_UINT_HALF_BITS)

/* Takes the low bit and assigns it to the high bit. */
#define BN_UINT_LO_TO_HI(t) ((t) << BN_UINT_HALF_BITS)

/* Takes the high bit and assigns it to the high bit. */
#define BN_UINT_HI_TO_HI(t) ((t) & ((BN_UINT)0 - BN_UINT_HC))

/* Takes the low bit and assigns it to the low bit. */
#define BN_UINT_LO(t) ((t) & (BN_UINT_HC - 1))

/* Takes the high bit and assigns it to the low bit. */
#define BN_UINT_HI(t) ((t) >> BN_UINT_HALF_BITS)

/* copy bytes, ensure that dstLen >= srcLen */
#define BN_COPY_BYTES(dst, dstlen, src, srclen)                             \
    do {                                                                    \
        uint32_t macroTmpI;                                                       \
        for (macroTmpI = 0; macroTmpI < (srclen); macroTmpI++) { (dst)[macroTmpI] = (src)[macroTmpI]; }   \
        for (; macroTmpI < (dstlen); macroTmpI++) { (dst)[macroTmpI] = 0; }                   \
    } while (0)

/* r = a * b + r + c, where c is refreshed as the new carry value */
#define MULADD_ABC(c, r, a, b)                  \
do {                                            \
    BN_UINT macroTmpAl = BN_UINT_LO(a);               \
    BN_UINT macroTmpAh = BN_UINT_HI(a);               \
    BN_UINT macroTmpBl = BN_UINT_LO(b);               \
    BN_UINT macroTmpBh = BN_UINT_HI(b);               \
    BN_UINT macroTmpX3 = macroTmpAh * macroTmpBh;                 \
    BN_UINT macroTmpX2 = macroTmpAh * macroTmpBl;                 \
    BN_UINT macroTmpX1 = macroTmpAl * macroTmpBh;                 \
    BN_UINT macroTmpX0 = macroTmpAl * macroTmpBl;                 \
    (r) += (c);                                 \
    (c) = ((r) < (c)) ? 1 : 0;                  \
    macroTmpX1 += macroTmpX2;                               \
    (c) += (macroTmpX1 < macroTmpX2) ? BN_UINT_HC : 0;      \
    macroTmpX2 = macroTmpX0;                                \
    macroTmpX0 += macroTmpX1 << BN_UINT_HALF_BITS;        \
    (c) += (macroTmpX0 < macroTmpX2) ? 1 : 0;               \
    (c) += BN_UINT_HI(macroTmpX1);                    \
    (c) += macroTmpX3;                                \
    (r) += macroTmpX0;                                \
    (c) += ((r) < macroTmpX0) ? 1 : 0;                \
} while (0)

/* r = a + b + c, input 'carry' means carry. Note that a and carry cannot be the same variable. */
#define ADD_ABC(carry, r, a, b, c)      \
    do {                                \
        BN_UINT macroTmpS = (b) + (c);        \
        carry = (macroTmpS < (c)) ? 1 : 0;    \
        (r) = macroTmpS + (a);                \
        carry += ((r) < macroTmpS) ? 1 : 0;   \
    } while (0)

BN_UINT BinAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n);

BN_UINT BinSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n);

BN_UINT BinInc(BN_UINT *r, const BN_UINT *a, uint32_t size, BN_UINT w);

BN_UINT BinDec(BN_UINT *r, const BN_UINT *a, uint32_t n, BN_UINT w);

uint32_t BinRshift(BN_UINT *r, const BN_UINT *a, uint32_t n, uint32_t bits);

BN_UINT BinSubMul(BN_UINT *r, const BN_UINT *a, BN_UINT aSize, BN_UINT m);

uint32_t BinLshift(BN_UINT *r, const BN_UINT *a, uint32_t n, uint32_t bits);

BN_UINT BinMulAcc(BN_UINT *r, const BN_UINT *a, uint32_t aSize, BN_UINT b);

uint32_t BinMul(BN_UINT *r, uint32_t rRoom, const BN_UINT *a, uint32_t aSize, const BN_UINT *b, uint32_t bSize);

uint32_t BinSqr(BN_UINT *r, uint32_t rRoom, const BN_UINT *a, uint32_t aSize);

uint32_t GetZeroBitsUint(BN_UINT x);

uint32_t BinFixSize(const BN_UINT *data, uint32_t size);

int32_t BinCmp(const BN_UINT *a, uint32_t aSize, const BN_UINT *b, uint32_t bSize);

uint32_t BinBits(const BN_UINT *data, uint32_t size);

uint32_t BinDiv(BN_UINT *q, uint32_t *qSize, BN_UINT *x, uint32_t xSize, BN_UINT *y, uint32_t ySize);

#ifdef HITLS_CRYPTO_BN_COMBA
uint32_t SpaceSize(uint32_t size);

// Perform a multiplication calculation of 4 blocks of data, r = a^2,
// where the length of r is 8, and the length of a is 4.
void MulComba4(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);

// Calculate the square of 4 blocks of data, r = a^2, where the length of r is 8, and the length of a is 4.
void SqrComba4(BN_UINT *r, const BN_UINT *a);

// Perform a multiplication calculation of 6 blocks of data, r = a*b,
// where the length of r is 12, the length of a and b is 6.
void MulComba6(BN_UINT *r, const BN_UINT *a, const BN_UINT *b);

// Calculate the square of 6 blocks of data, r = a^2, where the length of r is 12, and the length of a is 6.
void SqrComba6(BN_UINT *r, const BN_UINT *a);

void MulConquer(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t size, BN_UINT *space, bool consttime);

void SqrConquer(BN_UINT *r, const BN_UINT *a, uint32_t size, BN_UINT *space, bool consttime);
#endif

int32_t MontSqrBinCore(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime);

int32_t MontMulBinCore(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, BN_Mont *mont,
    BN_Optimizer *opt, bool consttime);

int32_t MontEncBinCore(BN_UINT *r, BN_Mont *mont, BN_Optimizer *opt, bool consttime);

void ReduceCore(BN_UINT *r, BN_UINT *x, const BN_UINT *m, uint32_t mSize, BN_UINT m0);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif