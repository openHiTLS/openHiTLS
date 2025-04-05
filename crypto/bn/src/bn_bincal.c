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

/* r = a + b, the length of r, a and b array is n. The return value is the carry. */
BN_UINT BinAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    BN_UINT carry = 0;
    uint32_t nn = n;
    const BN_UINT *aa = a;
    const BN_UINT *bb = b;
    BN_UINT *rr = r;
    while (nn >= 4) {
        ADD_ABC(carry, rr[0], aa[0], bb[0], carry);
        ADD_ABC(carry, rr[1], aa[1], bb[1], carry);
        ADD_ABC(carry, rr[2], aa[2], bb[2], carry);
        ADD_ABC(carry, rr[3], aa[3], bb[3], carry);
        rr += 4;
        aa += 4;
        bb += 4;
        nn -= 4;
    }
    uint32_t i = 0;
    for (; i < nn; i++) {
        ADD_ABC(carry, rr[i], aa[i], bb[i], carry);
    }
    return carry;
}

/* r = a - b, the length of r, a and b array is n. The return value is the borrow-digit. */
BN_UINT BinSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    BN_UINT borrow = 0;
    uint32_t nn = n;
    const BN_UINT *aa = a;
    const BN_UINT *bb = b;
    BN_UINT *rr = r;
    while (nn >= 4) {
        SUB_ABC(borrow, rr[0], aa[0], bb[0], borrow);
        SUB_ABC(borrow, rr[1], aa[1], bb[1], borrow);
        SUB_ABC(borrow, rr[2], aa[2], bb[2], borrow);
        SUB_ABC(borrow, rr[3], aa[3], bb[3], borrow);
        rr += 4;
        aa += 4;
        bb += 4;
        nn -= 4;
    }
    uint32_t i = 0;
    for (; i < nn; i++) {
        SUB_ABC(borrow, rr[i], aa[i], bb[i], borrow);
    }
    return borrow;
}

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
    while (size >= 4) {
        MULADD_ABC(c, rr[0], aa[0], b);
        MULADD_ABC(c, rr[1], aa[1], b);
        MULADD_ABC(c, rr[2], aa[2], b);
        MULADD_ABC(c, rr[3], aa[3], b);
        aa += 4;
        rr += 4;
        size -= 4;
    }
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
    uint32_t i, j;
    (void)memset_s(r, rRoom * sizeof(BN_UINT), 0, rRoom * sizeof(BN_UINT));
    /* Result combination of cyclic calculation data units. */
    for (i = 0; i < bSize; i++) {
        BN_UINT t = b[i];
        for (j = 0, carry = 0; j < aSize; j++) {
            BN_UINT rh, rl;
            MUL_AB(rh, rl, a[j], t);
            ADD_ABC(carry, r[i + j], r[i + j], rl, carry);
            carry += rh;
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
    BN_UINT rh, rl;

    (void)memset_s(r, rRoom * sizeof(BN_UINT), 0, rRoom * sizeof(BN_UINT));
    if (aSize < 1) {
        return 0;
    }

    /* Calculate unequal data units, similar to trapezoid. */
    for (i = 0; i < aSize - 1; i++) {
        BN_UINT t = a[i];
        uint32_t j;
        for (j = i + 1, carry = 0; j < aSize; j++) {
            MUL_AB(rh, rl, a[j], t);
            ADD_ABC(carry, r[i + j], rl, r[i + j], carry);
            carry += rh;
        }
        r[i + j] = carry;
    }
    /* In the square, the multiplier unit is symmetrical. r = r * 2 */
    BinLshift(r, r, 2 * aSize - 1, 1);
    /* Calculate the direct squared data unit and add it to the result. */
    for (i = 0, carry = 0; i < aSize; i++) {
        SQR_A(rh, rl, a[i]);
        ADD_ABC(carry, r[i << 1], r[i << 1], rl, carry);
        ADD_ABC(carry, r[(i << 1) + 1], r[(i << 1) + 1], rh, carry);
    }
    return aSize + aSize - (r[(aSize << 1) - 1] == 0);
}

/* Obtains the number of 0s in the first x most significant bits of data. */
uint32_t GetZeroBitsUint(BN_UINT x)
{
    BN_UINT t = x;
    BN_UINT mask;
    uint32_t bits = 0;
    uint32_t base = BN_UINT_BITS >> 1;
    BN_UINT m = (BN_UINT)(-1);
    uint32_t shift = BN_UINT_BITS >> 1;
    /* dichotomy */
    do {
        m <<= shift;
        mask = BN_IsZeroUintConsttime(t & m);   /* Check whether the upper half part is valid. */
        bits += base & (uint32_t)mask;
        t = ((t << shift) & mask) | (t & ~mask); /* Select the all upper or lower part of t based on the mask value. */
        shift >>= 1;
        base >>= 1; /* dichotomy, reduce the scope to 1/2 of each inspection */
    } while (shift > 0);

    mask = BN_IsZeroUintConsttime(t & m);
    bits += 1 & mask;
    return bits;
}

/* refresh the size */
uint32_t BinFixSize(const BN_UINT *data, uint32_t size)
{
    uint32_t fix = size;
    uint32_t i = size;
    BN_UINT m = (BN_UINT)(-1);
    for (; i > 0; i--) {
        m &= BN_IsZeroUintConsttime(data[i - 1]);
        fix -= 1 & m;
    }
    return fix;
}

/* compare */
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

/* Multiply and then subtract. The return value is borrow digit. */
static BN_UINT BinSubMul(BN_UINT *r, const BN_UINT *a, uint32_t aSize, BN_UINT m)
{
    BN_UINT borrow = 0;
    uint32_t i;
    for (i = 0; i < aSize; i++) {
        BN_UINT ah, al;
        MUL_AB(ah, al, a[i], m);
        SUB_ABC(borrow, r[i], r[i], al, borrow);
        borrow += ah;
    }

    return borrow;
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

/**
 * x / y = q...x, the return value is the updated xSize.
 * q and asize are both NULL or not NULL. Other input parameters must be valid.
 * q, x and y cannot be the same pointer.
 * Ensure that x->room >= xSize + 2, and the extra two spaces need to be cleared. Extra space is used during try divide.
 */
uint32_t BinDiv(BN_UINT *q, uint32_t *qSize, BN_UINT *x, uint32_t xSize, BN_UINT *y, uint32_t ySize)
{
    if (q != NULL) {
        (void)memset_s(q, *qSize * sizeof(BN_UINT), 0, *qSize * sizeof(BN_UINT));
        *qSize = 0;
    }
    if (xSize < ySize) {
        return xSize;
    }
    uint32_t shifts = GetZeroBitsUint(y[ySize - 1]);
    BN_UINT xNewSize = xSize;
    BN_UINT yNewSize = ySize;
    /* Left shift until the maximum displacement of the divisor is full. */
    if (shifts != 0) {
        xNewSize = BinLshift(x, x, xSize, shifts);
        yNewSize = BinLshift(y, y, ySize, shifts);
    }
    BinDivCore(q, qSize, x, xSize, y, ySize);
    /* shift compensation */
    if (shifts != 0) {
        xNewSize = (BN_UINT)BinRshift(x, x, (uint32_t)xNewSize, shifts);
        yNewSize = (BN_UINT)BinRshift(y, y, (uint32_t)yNewSize, shifts);
        (void)yNewSize;
    }
    return BinFixSize(x, (uint32_t)xNewSize);
}
#endif /* HITLS_CRYPTO_BN */
