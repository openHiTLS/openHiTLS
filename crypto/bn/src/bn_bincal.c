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

#include <stdint.h>
#include "securec.h"
#include "bn_bincal.h"

/* r = a + w, the length of r and a array is 'size'. The return value is the carry. */
BN_UINT BinInc(BN_UINT *r, const BN_UINT *a, uint32_t size, BN_UINT w)
{
    uint32_t i;
    BN_UINT carry = w;
    for (i = 0; i < size && carry != 0; i++) {
        ADD_AB(carry, r[i], a[i], carry);
    }
    if (r != a) {
        for (; i < size; i++) {
            r[i] = a[i];
        }
    }

    return carry;
}
/* r = a - w, the length of r and a array is 'size'. The return value is the borrow-digit. */
BN_UINT BinDec(BN_UINT *r, const BN_UINT *a, uint32_t n, BN_UINT w)
{
    uint32_t i;
    BN_UINT borrow = w;
    for (i = 0; (i < n) && (borrow > 0); i++) {
        SUB_AB(borrow, r[i], a[i], borrow);
    }
    if (r != a) {
        for (; i < n; i++) {
            r[i] = a[i];
        }
    }
    return borrow;
}
/* r = a >> bits, the return value is the valid length of r after the shift.
 * The array length of a is n. The length of the r array must meet the requirements of the accepted calculation result,
 * which is guaranteed by the input parameter.
 */
uint32_t BinRshift(BN_UINT *r, const BN_UINT *a, uint32_t n, uint32_t bits)
{
    uint32_t nw = bits / BN_UINT_BITS; /* shift words */
    uint32_t nb = bits % BN_UINT_BITS; /* shift bits */
    /**
     * unsigned shift operand cannot be greater than or equal to the data bit width
     * Otherwise, undefined behavior is triggered.
     */
    uint32_t na = (BN_UINT_BITS - nb) % BN_UINT_BITS;
    uint32_t rsize = n - nw;
    uint32_t i;
    BN_UINT hi;
    BN_UINT lo = a[nw];
    /* When nb == 0, discard the value of (hi << na) with the all-zero mask. */
    BN_UINT mask = ~BN_IsZeroUintConsttime(nb);
    /* Assigns values from the lower bits. */
    for (i = nw; i < n - 1; i++) {
        hi = a[i + 1];
        r[i - nw] = (lo >> nb) | ((hi << na) & mask);
        lo = hi;
    }
    lo >>= nb;
    if (lo != 0) {
        r[rsize - 1] = lo;
    } else {
        rsize--;
    }
    return rsize;
}
/* r = a << bits. The return value is the valid length of r after the shift.
 * The array length of a is n. The length of the r array must meet the requirements of the accepted calculation result,
 * which is guaranteed by the input parameter.
 */
uint32_t BinLshift(BN_UINT *r, const BN_UINT *a, uint32_t n, uint32_t bits)
{
    uint32_t nw = bits / BN_UINT_BITS; /* shift words */
    uint32_t nb = bits % BN_UINT_BITS; /* shift bits */
    /**
     * unsigned shift operand cannot be greater than or equal to the data bit width
     * Otherwise, undefined behavior is triggered.
     */
    uint32_t na = (BN_UINT_BITS - nb) % BN_UINT_BITS;
    uint32_t rsize = n + nw;
    uint32_t i;
    BN_UINT hi = a[n - 1];
    BN_UINT lo;
    /* When nb == 0, discard the value of (hi << na) with the all-zero mask. */
    BN_UINT mask = ~BN_IsZeroUintConsttime(nb);
    lo = (hi >> na) & mask;
    /* Assign a value to the most significant bit. */
    if (lo != 0) {
        r[rsize++] = lo;
    }
    /* Assign a value from the most significant bits. */
    for (i = n - 1; i > 0; i--) {
        lo = a[i - 1];
        r[i + nw] = (hi << nb) | ((lo >> na) & mask);
        hi = lo;
    }
    r[nw] = a[0] << nb;
    /* Clear the lower bits to 0. */
    if (nw != 0) {
        (void)memset_s(r, nw * sizeof(BN_UINT), 0, nw * sizeof(BN_UINT));
    }

    return rsize;
}
/* r = a * b + r. The return value is a carry. */
BN_UINT BinMulAcc(BN_UINT *r, const BN_UINT *a, uint32_t aSize, BN_UINT b)
{
    BN_UINT c = 0;
    BN_UINT *rr = r;
    const BN_UINT *aa = a;
    uint32_t size = aSize;
#ifndef HITLS_CRYPTO_BN_SMALL_MEM
    while (size >= 4) { /* a group of 4 */
        MULADD_ABC(c, rr[0], aa[0], b);  /* offset 0 */
        MULADD_ABC(c, rr[1], aa[1], b);  /* offset 1 */
        MULADD_ABC(c, rr[2], aa[2], b);  /* offset 2 */
        MULADD_ABC(c, rr[3], aa[3], b);  /* offset 3 */
        aa += 4;        /* a group of 4 */
        rr += 4;        /* a group of 4 */
        size -= 4;      /* a group of 4 */
    }
#endif
    while (size > 0) {
        MULADD_ABC(c, rr[0], aa[0], b);
        aa++;
        rr++;
        size--;
    }
    return c;
}
/* r = a * b rRoom >= aSize + bSize. The length is guaranteed by the input parameter. r != a, r != b.
 * The return value is the valid length of the result. */
uint32_t BinMul(BN_UINT *r, uint32_t rRoom, const BN_UINT *a, uint32_t aSize, const BN_UINT *b, uint32_t bSize)
{
    BN_UINT carry = 0;
    (void)memset_s(r, rRoom * sizeof(BN_UINT), 0, rRoom * sizeof(BN_UINT));
    /* Result combination of cyclic calculation data units. */
    for (uint32_t i = 0; i < bSize; i++) {
        carry = 0;
        uint32_t j = 0;
        BN_UINT t = b[i];
        for (; j < aSize; j++) {
            MULADC_AB(r[i + j], a[j], t, carry);
        }
        if (carry != 0) {
            r[i + j] = carry;
        }
    }
    return aSize + bSize - (carry == 0);
}

/* r = a * a rRoom >= aSize * 2. The length is guaranteed by the input parameter. r != a.
 * The return value is the valid length of the result. */
uint32_t BinSqr(BN_UINT *r, uint32_t rRoom, const BN_UINT *a, uint32_t aSize)
{
    uint32_t i;
    BN_UINT carry;

    (void)memset_s(r, rRoom * sizeof(BN_UINT), 0, rRoom * sizeof(BN_UINT));
    /* Calculate unequal data units, similar to trapezoid. */
    for (i = 0; i < aSize - 1; i++) {
        BN_UINT t = a[i];
        uint32_t j;
        for (j = i + 1, carry = 0; j < aSize; j++) {
            MULADC_AB(r[i + j], a[j], t, carry);
        }
        r[i + j] = carry;
    }
    /* In the square, the multiplier unit is symmetrical. r = r * 2 */
    BinLshift(r, r, 2 * aSize - 1, 1);
    /* Calculate the direct squared data unit and add it to the result. */
    for (i = 0, carry = 0; i < aSize; i++) {
        BN_UINT rh, rl;
        SQR_A(rh, rl, a[i]);
        ADD_ABC(carry, r[i << 1], r[i << 1], rl, carry);
        ADD_ABC(carry, r[(i << 1) + 1], r[(i << 1) + 1], rh, carry);
    }
    return aSize + aSize - (r[(aSize << 1) - 1] == 0);
}

/* refresh the size */
uint32_t BinFixSize(const BN_UINT *data, uint32_t size)
{
    uint32_t fix = size;
    uint32_t i = size;
    for (; i > 0; i--) {
        if (data[i - 1] != 0) {
            return fix;
        };
        fix--;
    }
    return fix;
}

/* compare BN array. Maybe aSize != bSize;
 * return 0, if a == b
 * return 1, if a > b
 * return -1, if a < b
 */
int32_t BinCmp(const BN_UINT *a, uint32_t aSize, const BN_UINT *b, uint32_t bSize)
{
    if (aSize == bSize) {
        uint32_t len = aSize;

        while (len > 0) {
            len--;
            if (a[len] != b[len]) {
                return a[len] > b[len] ? 1 : -1;
            }
        }
        return 0;
    }
    return aSize > bSize ? 1 : -1;
}

/* obtain bits */
uint32_t BinBits(const BN_UINT *data, uint32_t size)
{
    if (size == 0) {
        return 0;
    }
    return (size * BN_UINT_BITS - GetZeroBitsUint(data[size - 1]));
}

/**
 * Try to reduce the borrowing cost, guarantee h|l >= q * yl. If q is too large, reduce q.
 * Each time q decreases by 1, h increases by yh. y was previously offset, and the most significant bit of yh is 1.
 * Therefore (q * yl << BN_UINT_BITS) < (yh * 2), number of borrowing times ≤ 2.
 */
static BN_UINT TryDiv(BN_UINT q, BN_UINT h, BN_UINT l, BN_UINT yh, BN_UINT yl)
{
    BN_UINT rh, rl;
    MUL_AB(rh, rl, q, yl);
    /* Compare h|l >= rh|rl. Otherwise, reduce q. */
    if (rh < h || (rh == h && rl <= l)) {
        return q;
    }
    BN_UINT nq = q - 1;
    BN_UINT nh = h + yh;
    /* If carry occurs, no judgment is required. */
    if (nh < yh) {
        return nq;
    }
    /* rh|rl - yl */
    if (rl < yl) {
        rh--;
    }
    rl -= yl;

    /* Compare r|l >= rh|rl. Otherwise, reduce q. */
    if (rh < nh || (rh == nh && rl <= l)) {
        return nq;
    }
    nq--;
    return nq;
}
/* Divide core operation */
static void BinDivCore(BN_UINT *q, uint32_t *qSize, BN_UINT *x, uint32_t xSize, const BN_UINT *y, uint32_t ySize)
{
    BN_UINT yy = y[ySize - 1];  /* Obtain the most significant bit of the data. */
    uint32_t i;
    for (i = xSize; i >= ySize; i--) {
        BN_UINT qq;
        if (x[i] == yy) {
            qq = (BN_UINT)-1;
        } else {
            BN_UINT rr;
            DIV_ND(qq, rr, x[i], x[i - 1], yy);
            if (ySize > 1) { /* If ySize is 1, do not need to try divide. */
            /* Obtain the least significant bit data, that is, make subscript - 2. */
                qq = TryDiv(qq, rr, x[i - 2], yy, y[ySize - 2]);
            }
        }
        if (qq > 0) {
            /* After the TryDiv is complete, perform the double subtraction. */
            BN_UINT extend = BinSubMul(&x[i - ySize], y, ySize, qq);
            extend = (x[i] -= extend);
            if (extend > 0) {
                /* reverse, borrowing required */
                extend = BinAdd(&x[i - ySize], &x[i - ySize], y, ySize);
                x[i] += extend;
                qq--;
            }
            if (q != NULL && qq != 0) {
                /* update quotient */
                q[i - ySize] = qq;
                *qSize = (*qSize) > (i - ySize + 1) ? (*qSize) : (i - ySize + 1);
            }
        }
    }
}

// The L-shift of the divisor does not exceed the highest BN_UINT.
static void BnLshiftSimple(BN_UINT *a, uint32_t aSize, uint32_t bits)
{
    uint32_t rem = BN_UNIT_BITS - bits;
    BN_UINT nextBits = 0;
    for (uint32_t i = 0; i < aSize; i++) {
        BN_UINT n = a[i];
        a[i] = (n << bits) | nextBits;
        nextBits = (n >> rem);
    }
    return;
}

/**
 * x / y = q...x, the return value is the updated xSize.
 * q and asize are both NULL or not NULL. Other input parameters must be valid.
 * q, x and y cannot be the same pointer, the data in q must be 0.
 * Ensure that x->room >= xSize + 2, and the extra two spaces need to be cleared. Extra space is used during try divide.
 * this interface does not ensure that the y is consistent after running.
 */
uint32_t BinDiv(BN_UINT *q, uint32_t *qSize, BN_UINT *x, uint32_t xSize, BN_UINT *y, uint32_t ySize)
{
    uint32_t shifts = GetZeroBitsUint(y[ySize - 1]);
    uint32_t xNewSize = xSize;
    /* Left shift until the maximum displacement of the divisor is full. */
    if (shifts != 0) {
        BnLshiftSimple(y, ySize, shifts);
        xNewSize = BinLshift(x, x, xSize, shifts);
    }
    BinDivCore(q, qSize, x, xSize, y, ySize);
    /* shift compensation */
    if (shifts != 0) {
        xNewSize = BinRshift(x, x, xNewSize, shifts);
    }
    return BinFixSize(x, xNewSize);
}
#endif /* HITLS_CRYPTO_BN */
