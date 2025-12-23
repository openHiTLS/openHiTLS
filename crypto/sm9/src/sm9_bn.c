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
#ifdef HITLS_CRYPTO_SM9

#include "sm9_bn.h"
#include <stdio.h>
#include <stdlib.h>

void bn_reset(uint32_t *x, int32_t wsize)
{
    int32_t i;

    for (i = 0; i < wsize; i++)
        x[i] = 0;
}

void bn_set_int(uint32_t *x, int32_t n, int32_t wsize)
{
    int32_t i;

    x[0] = n;
    for (i = 1; i < wsize; i++)
        x[i] = 0;
}

void bn_assign(uint32_t *y, const uint32_t *x, int32_t wsize)
{
    int32_t i;

    if (y == x)
        return;

    for (i = 0; i < wsize; i++)
        y[i] = x[i];
}

int32_t bn_cmp(const uint32_t *x, const uint32_t *y, int32_t wsize)
{
    int32_t i;

    for (i = wsize - 1; i >= 0; i--) {
        if (x[i] > y[i])    return (1);
        if (x[i] < y[i])    return (-1);
    }
    return 0;
}

int32_t bn_is_zero(uint32_t *x, int32_t wsize)
{
    int32_t i;

    for (i = 0; i < wsize; i++) {
        if (x[i])
            return 0;
    }
    return 1;
}

int32_t bn_is_nonzero(uint32_t *x, int32_t wsize)
{
    int32_t i;

    for (i = 0; i < wsize; i++) {
        if (x[i])
            return 1;
    }
    return 0;
}

int32_t bn_equal(const uint32_t *x, const uint32_t *y, int32_t wsize)
{
    int32_t i;

    for (i = 0; i < wsize; i++) {
        if (x[i] != y[i])
            return 0;
    }
    return 1;
}

int32_t bn_get_bitlen(const uint32_t *x, int32_t wsize)
{
    /***********************/
    int32_t i;
    int32_t bits;
    uint32_t t;
    /***********************/

    for (i = wsize - 1; i >= 0; i--) {
        if (x[i]) {
            t = x[i];
            break;
        }
    }
    if (i < 0)
        return 0;

    bits = (i << 5) + 1;
    for (i = WORDBITS / 2; i > 0; i >>= 1) {
        if (t >> i) {
            t >>= i;
            bits += i;
        }
    }

    return bits;
}

int32_t bn_get_wordlen(const uint32_t *x, int32_t wsize)
{
    int32_t i;

    for (i = wsize - 1; i >= 0; i--) {
        if (x[i] != 0)
            return i + 1;
    }
    return 0;
}

int32_t bn_div_2(uint32_t *y, const uint32_t *x, int32_t wsize)
{
    int32_t i;
    int32_t c = x[0] & LSBOfWord;
    for (i = 0; i < wsize - 1; i++) {
        y[i] = (x[i] >> 1) | (x[i + 1] << (WORDBITS - 1));
    }
    y[i] = x[i] >> 1;

    return c;
}

uint32_t bn_add(uint32_t *r, const uint32_t *x, const uint32_t *y, int32_t wsize)
{
    /*********************/
    int32_t i;
    uint64_t carry = 0;
    /*********************/

    for (i = 0; i < wsize; i++) {
        carry = (uint64_t)x[i] + (uint64_t)y[i] + carry;
        r[i] = (uint32_t)carry;
        carry = carry >> 32;
    }
    return (uint32_t)carry;
}

uint32_t bn_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, int32_t wsize)
{
    /**********************/
    int32_t i = 0;
    uint64_t borrow = 0;
    /**********************/

    for (i = 0; i < wsize; i++) {
        borrow = (uint64_t)x[i] - (uint64_t)y[i] + borrow;
        r[i] = (uint32_t)borrow;
        borrow = (uint64_t)(((int64_t)borrow) >> 32);
    }
    return (uint32_t)borrow;
}

void bn_mod_add(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int32_t wsize)
{
    int32_t i = 256; // Prevent infinite circulation

    if (bn_add(r, x, y, wsize)) {
        while (i--)    { if (bn_sub(r, r, m, wsize))    break; }
    }
}

void bn_mod_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int32_t wsize)
{
    int32_t i = 256; // Prevent infinite circulation

    if (bn_sub(r, x, y, wsize)) {
        while (i--)    { if (bn_add(r, r, m, wsize))    break; }
    }
}

void bn_mod_inv(uint32_t *r, uint32_t *x, uint32_t *m, int32_t wsize)
{
    uint32_t bn_u[BNWordLen];
    uint32_t bn_v[BNWordLen];
    uint32_t bn_B[BNWordLen];
    uint32_t bn_D[BNWordLen];

    // Step_1. u=p, v=a, A=1, B=0, C=0, D=1, while( A*p-B*a=u, -C*p+D*a=v )
    bn_assign(bn_u, m, wsize);
    bn_assign(bn_v, x, wsize);
    bn_reset(bn_B, wsize);
    bn_set_int(bn_D, 1, wsize);

    // Step_2. While v is nonzero, do
    while (bn_is_nonzero(bn_v, wsize)) {
        // 2.1 If u is even, do { u = u / 2, B = B / 2 mod m }
        while ((bn_u[0] & LSBOfWord) == 0) {
            bn_div_2(bn_u, bn_u, wsize);
            bn_mod_div_2(bn_B, bn_B, m, wsize);
        }
        // 2.2 If v is even, do { v = v / 2, D = D / 2 mod m }
        while ((bn_v[0] & LSBOfWord) == 0) {
            bn_div_2(bn_v, bn_v, wsize);
            bn_mod_div_2(bn_D, bn_D, m, wsize);
        }
        // 2.3 If u > v, do { u = u - v,  B = B + D mod m }
        if (bn_cmp(bn_u, bn_v, wsize) > 0) {
            bn_sub(bn_u, bn_u, bn_v, wsize);
            bn_mod_add(bn_B, bn_B, bn_D, m, wsize);
        }
        // 2.4 If u <= v, do { v = v - u, D = D + B mod m }
        else {
            bn_sub(bn_v, bn_v, bn_u, wsize);
            bn_mod_add(bn_D, bn_D, bn_B, m, wsize);
        }
    }

    // Step_3. Inverse is -B mod m
    bn_mod_neg(r, bn_B, m, wsize);
}

void BN_GetInv_Mont(uint32_t *r, uint32_t *x, uint32_t *m, uint32_t mc, uint32_t *pwRRModule, int32_t wsize)
{
    bn_mod_inv(r, x, m, wsize);
    bn_mont_mul(r, r, pwRRModule, m, mc, wsize);
}

void bn_mod_neg(uint32_t *r, const uint32_t *x, const uint32_t *m, int32_t wsize)
{
    int32_t i = 256; // Prevent infinite circulation

    if (bn_sub(r, m, x, wsize)) {
        while (i--)    { if (bn_add(r, r, m, wsize))    break; }
    }
}

void bn_mod_div_2(uint32_t *r, const uint32_t *x, const uint32_t *m, int32_t wsize)
{
    uint32_t carry;

    if ((x[0] & LSBOfWord)) {
        carry = bn_add(r, x, m, wsize);
        bn_div_2(r, r, wsize);
        r[wsize - 1] |= carry << (WORDBITS - 1);
    } else
        bn_div_2(r, x, wsize);
}

void bn_mont_mul(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, uint32_t mc, int32_t wsize)
{
    int32_t i;
    int32_t j;
    uint64_t carry;
    uint32_t U;
    uint32_t D[BN_MAX_WORDSIZE + 2];

    bn_reset(D, wsize + 2);

    for (i = 0; i < wsize; i++) {
        // D = D + x*y[i]
        carry = 0;
        for (j = 0; j < wsize; j++) {
            carry = (uint64_t)D[j] + (uint64_t)x[j] * (uint64_t)y[i] + carry;
            D[j] = (uint32_t)carry;
            carry = carry >> 32;
        }
        carry = (uint64_t)D[wsize] + carry;
        D[wsize] = (uint32_t)carry;
        D[wsize + 1] = (uint32_t)(carry >> 32);

        // U = D[0] * ((-p)^(-1) mod b) mod b
        carry = (uint64_t)D[0] * (uint64_t)mc;
        U = (uint32_t)carry;

        // D = (D + U * p)/b
        carry = (uint64_t)D[0] + (uint64_t)U * (uint64_t)m[0];
        carry = carry >> 32;
        for (j = 1; j < wsize; j++) {
            carry = (uint64_t)D[j] + (uint64_t)U * (uint64_t)m[j] + carry;
            D[j - 1] = (uint32_t)carry;
            carry = carry >> 32;
        }
        carry = (uint64_t)D[wsize] + carry;
        D[wsize - 1] = (uint32_t)carry;
        D[wsize] = D[wsize + 1] + (uint32_t)(carry >> 32);
    }
    if (D[wsize] == 0)
        bn_assign(r, D, wsize);
    else
        bn_sub(r, D, m, wsize);
}

void bn_mont_redc(uint32_t *r, const uint32_t *x, const uint32_t *m, uint32_t mc, int32_t wsize)
{
    int32_t i;
    int32_t j;
    uint64_t carry;
    uint32_t U;
    uint32_t D[BN_MAX_WORDSIZE];

    // D = x
    bn_assign(D, x, wsize);
    for (i = 0; i < wsize; i++) {
        // U = D[0] * ((-p)^(-1) mod b) mod b
        U = (uint32_t)((uint64_t)D[0] * (uint64_t)mc);

        // D = (D + U * p)/b
        carry = ((uint64_t)D[0] + (uint64_t)U * (uint64_t)m[0]) >> 32;
        for (j = 1; j < wsize; j++) {
            carry = (uint64_t)D[j] + (uint64_t)U * (uint64_t)m[j] + carry;
            D[j - 1] = (uint32_t)carry;
            carry = carry >> 32;
        }
        D[wsize - 1] = (uint32_t)carry;
    }
    if (bn_cmp(D, m, wsize) > 0)
        bn_sub(r, D, m, wsize);
    else
        bn_assign(r, D, wsize);
}

void bn_get_res(uint32_t *x, const uint32_t *m, int32_t wsize)
{
    if (bn_cmp(x, m, wsize) > 0)
        bn_sub(x, x, m, wsize);
}

int32_t BN_Mod_Basic(uint32_t *rem, int32_t iBNWordLen_r, uint32_t *pwBNX,
                     int32_t iBNWordLen_X, uint32_t *pwBNM, int32_t iBNWordLen_M)
{
    int32_t j = 0;
    uint64_t q = 0;
    uint64_t carry = 0;
    uint64_t tmp = 0;
    int32_t k = iBNWordLen_X;
    int32_t l = iBNWordLen_M;
    int32_t ll = l - 1;
    uint32_t temp[BN_MAX_WORDSIZE] = {0};
    uint32_t quo_tmp[BN_MAX_WORDSIZE] = {0};

    for (int32_t i = k - l; i >= 0; i--) {
        // q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
        q = ((((uint64_t)(pwBNX[i + l]) << WordLen) + (uint64_t)pwBNX[i + l - 1])) / (uint64_t)pwBNM[ll];
        if (q & 0xffffffff00000000)
            quo_tmp[i] = 0xffffffff;
        else
            quo_tmp[i] = (uint32_t)q;
        carry = 0;
        for (j = 0; j < l; j++) { // temp = q[i] * pwBNM
            carry = (uint64_t)quo_tmp[i] * (uint64_t)pwBNM[j] + carry;
            temp[j] = (uint32_t)carry;
            carry >>= WordLen;
        }
        temp[j] = (uint32_t)carry;
        carry = 0;
        for (j = 0; j < l; j++) { // pwBNX = pwBNX - (temp << ( 32 * i))
            carry = (uint64_t)pwBNX[i + j] - (uint64_t)temp[j] + carry;
            pwBNX[i + j] = (uint32_t) carry;
            carry = ((int64_t)carry) >> WordLen;
        }
        carry = (uint64_t)pwBNX[i + j] - (uint64_t)temp[j] + carry;
        while (carry & 0x1000000000000000) { // while r[i+l] < 0
            tmp = 0;
            for (j = 0; j < l; j++) { // pwBNX = pwBNX + (pwBNM << ( 32 * i))
                tmp = (uint64_t)pwBNX[i + j] + (uint64_t)pwBNM[j] + tmp;
                pwBNX[i + j] = (uint32_t)tmp;
                tmp = (uint64_t)(tmp >> WordLen);
            }
            carry = carry + tmp;
            quo_tmp[i] -= 1;
        }
        pwBNX[i + l] = (uint32_t)carry;
    }
    int32_t lenRem = bn_get_wordlen(pwBNX, iBNWordLen_M);
    if (lenRem > iBNWordLen_r)
        return 0;
    bn_assign(rem, pwBNX, lenRem);
    return 1;
}

int32_t ByteToBN(const uint8_t *pByteBuf, int32_t bytelen, uint32_t *pwBN, int32_t wsize)
{
    /*******************/
    int32_t ExpLen = 0;
    int32_t Rem = 0;
    int32_t i = 0;
    int32_t j = 0;
    /*******************/

    ExpLen = bytelen >> 2;
    Rem = bytelen & 0x00000003;

    if (Rem != 0) {
        ExpLen += 1;
    }

    if (ExpLen > wsize) {
        return 0;
    }

    i = bytelen - 1;
    j = 0;
    while (i >= Rem) {
        pwBN[j] = ((uint32_t)pByteBuf[i]) | ((uint32_t)pByteBuf[i - 1] << 8) |
                  ((uint32_t)pByteBuf[i - 2] << 16) | ((uint32_t)pByteBuf[i - 3] << 24);
        i -= 4;
        j++;
    }

    i = 0;
    while (i < Rem) {
        pwBN[j] = (pwBN[j] << 8) | ((uint32_t)pByteBuf[i]);
        i++;
    }

    return 1;
}

int32_t BNToByte(uint32_t *pwBN, int32_t wsize, uint8_t *pByteBuf, int32_t *bytelen)
{
    /*******************/
    int32_t i = 0;
    uint8_t *P = NULL;
    uint32_t W = 0;
    /*******************/

    P = pByteBuf;
    for (i = wsize - 1; i >= 0; i--) {
        W = pwBN[i];
        *P++=(uint8_t) ((W & 0xFF000000) >> 24);
        *P++=(uint8_t) ((W & 0x00FF0000) >> 16);
        *P++=(uint8_t) ((W & 0x0000FF00) >> 8);
        *P++=(uint8_t) (W &  0x000000FF) ;
    }
    if (bytelen)
        *bytelen = wsize << 2;

    return 1;
}

uint32_t bn_add_int(uint32_t *r, const uint32_t *x, uint32_t n, int32_t wsize)
{
    /*********************/
    int32_t i = 0;
    uint64_t carry = 0;
    /*********************/

    if (n) {
        carry = (uint64_t)x[0] + (uint64_t)n;
        r[0] = (uint32_t)carry;
        carry = carry >> 32;
        for (i = 1; i < wsize; i++) {
            if (carry == 0)
                break;
            carry = (uint64_t)x[i] + carry;
            r[i] = (uint32_t)carry;
            carry = carry >> 32;
        }
    }
    if (r != x) {
        for (; i < wsize; i++)
            r[i] = x[i];
    }

    return (uint32_t)carry;
}

uint32_t bn_sub_int(uint32_t *r, const uint32_t *x, uint32_t n, int32_t wsize)
{
    /**********************/
    int32_t i = 0;
    uint64_t borrow = 0;
    /**********************/

    if (n) {
        borrow = (uint64_t)x[0] - (uint64_t)n + borrow;
        r[0] = (uint32_t)borrow;
        borrow = (uint64_t)(((int64_t)borrow) >> 32);
        for (i = 1; i < wsize; i++) {
            if (borrow == 0)    break;
            borrow = (uint64_t)x[i] + borrow;
            r[i] = (uint32_t)borrow;
            borrow = (uint64_t)(((int64_t)borrow) >> 32);
        }
    }
    if (r != x) {
        for (; i < wsize; i++)
            r[i] = x[i];
    }

    return (uint32_t)borrow;
}

#endif // HITLS_CRYPTO_SM9
