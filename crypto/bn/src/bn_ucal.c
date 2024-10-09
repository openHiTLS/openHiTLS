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

#include "securec.h"
#include "bn_bincal.h"

/* the user should guaranteed a.size >= b.size */
void USub(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b)
{
    uint32_t maxSize = a->size;
    uint32_t minSize = b->size;

    BN_UINT *rr = r->data;
    const BN_UINT *aa = a->data;
    const BN_UINT *bb = b->data;

    BN_UINT borrow = BinSub(rr, aa, bb, minSize);
    rr += minSize;
    aa += minSize;

    uint32_t diff = maxSize - minSize;
    while (diff > 0) {
        BN_UINT t = *aa;
        aa++;
        *rr = t - borrow;
        rr++;
        borrow = t < borrow;
        diff--;
    }
    while (maxSize != 0) {
        rr--;
        if (*rr != 0) {
            break;
        }
        maxSize--;
    }
    r->size = maxSize;
}

void UInc(BN_BigNum *r, const BN_BigNum *a, BN_UINT w)
{
    uint32_t size = a->size;

    BN_UINT carry = BinInc(r->data, a->data, size, w);
    if (carry != 0) {
        r->data[size++] = carry;
    }
    r->size = size;
}

void UDec(BN_BigNum *r, const BN_BigNum *a, BN_UINT w)
{
    uint32_t size = a->size;

    // the user should guaranteed size > 1, the return value must be 0 thus the return value is ignored
    (void)BinDec(r->data, a->data, size, w);
    r->size = BinFixSize(r->data, size);
}

void UAdd(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b)
{
    const BN_BigNum *max = (a->size < b->size) ? b : a;
    const BN_BigNum *min = (a->size < b->size) ? a : b;
    uint32_t maxSize = max->size;
    uint32_t minSize = min->size;

    r->size = maxSize;
    BN_UINT *rr = r->data;
    const BN_UINT *aa = max->data;
    const BN_UINT *bb = min->data;

    BN_UINT carry = BinAdd(rr, aa, bb, minSize);
    rr += minSize;
    aa += minSize;

    uint32_t diff = maxSize - minSize;
    while (diff > 0) {
        ADD_AB(carry, *rr, *aa, carry);
        aa++, rr++, diff--;
    }
    if (carry != 0) {
        *rr = carry;
        r->size += 1;
    }
    (void)memset_s(r->data + r->size, (r->room - r->size) *  sizeof(BN_UINT), 0,
        (r->room - r->size) *  sizeof(BN_UINT));
}
#endif /* HITLS_CRYPTO_BN */
