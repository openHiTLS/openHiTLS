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
#include "bn_bincal.h"

/* r = a + b, the length of r, a and b array is n. The return value is the carry. */
BN_UINT BinAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    BN_UINT carry = 0;
    uint32_t nn = n;
    const BN_UINT *aa = a;
    const BN_UINT *bb = b;
    BN_UINT *rr = r;
#ifndef HITLS_CRYPTO_BN_SMALL_MEM
    while (nn >= 4) { /* Process 4 groups in batches. */
        ADD_ABC(carry, rr[0], aa[0], bb[0], carry); /* offset 0 */
        ADD_ABC(carry, rr[1], aa[1], bb[1], carry); /* offset 1 */
        ADD_ABC(carry, rr[2], aa[2], bb[2], carry); /* offset 2 */
        ADD_ABC(carry, rr[3], aa[3], bb[3], carry); /* offset 3 */
        rr += 4; /* a group of 4 */
        aa += 4; /* a group of 4 */
        bb += 4; /* a group of 4 */
        nn -= 4; /* a group of 4 */
    }
#endif
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
#ifndef HITLS_CRYPTO_BN_SMALL_MEM
    while (nn >= 4) { /* Process 4 groups in batches. */
        SUB_ABC(borrow, rr[0], aa[0], bb[0], borrow); /* offset 0 */
        SUB_ABC(borrow, rr[1], aa[1], bb[1], borrow); /* offset 1 */
        SUB_ABC(borrow, rr[2], aa[2], bb[2], borrow); /* offset 2 */
        SUB_ABC(borrow, rr[3], aa[3], bb[3], borrow); /* offset 3 */
        rr += 4; /* a group of 4 */
        aa += 4; /* a group of 4 */
        bb += 4; /* a group of 4 */
        nn -= 4; /* a group of 4 */
    }
#endif
    uint32_t i = 0;
    for (; i < nn; i++) {
        SUB_ABC(borrow, rr[i], aa[i], bb[i], borrow);
    }
    return borrow;
}

/* Obtains the number of 0s in the first x most significant bits of data. */
uint32_t GetZeroBitsUint(BN_UINT x)
{
    BN_UINT iter;
    BN_UINT tmp = x;
    uint32_t bits = BN_UNIT_BITS;
    uint32_t base = BN_UNIT_BITS >> 1;
    do {
        iter = tmp >> base;
        if (iter != 0) {
            tmp = iter;
            bits -= base;
        }
        base = base >> 1;
    } while (base != 0);

    return (uint32_t)(bits - tmp);
}

/* Multiply and then subtract. The return value is borrow digit. */
BN_UINT BinSubMul(BN_UINT *r, const BN_UINT *a, BN_UINT aSize, BN_UINT m)
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

#endif /* HITLS_CRYPTO_BN */
