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

#include "bn.h"
#include <stdio.h>
#include <stdlib.h>

void bn_reset(uint32_t *x, int wsize)
{
    int i;

    for (i = 0; i < wsize; i++)
        x[i] = 0;
}

void bn_set_int(uint32_t *x, int n, int wsize)
{
    int i;

    x[0] = n;
    for (i = 1; i < wsize; i++)
        x[i] = 0;
}

void bn_assign(uint32_t *y, const uint32_t *x, int wsize)
{
    int i;

    if (y == x)
        return;

    for (i = 0; i < wsize; i++)
        y[i] = x[i];
}

int bn_cmp(const uint32_t *x, const uint32_t *y, int wsize)
{
    int i;

    for (i = wsize - 1; i >= 0; i--)
    {
        if (x[i] > y[i])    return (1);
        if (x[i] < y[i])    return (-1);
    }
    return 0;
}

int bn_cmp_int(const uint32_t *x, unsigned int n, int wsize)
{
    int i;

    for (i = 1; i < wsize; i++)
    {
        if (x[i])    return (1);
    }
    if (x[0] > n)    return (1);
    if (x[0] < n)    return (-1);

    return 0;
}

void BN_Print(uint32_t *pwBN, int32_t wsize)
{
    /*****************/
    int32_t i = 0;
    /*****************/

    for (i = wsize - 1; i >= 0; i--)
    {
        printf("%08X", pwBN[i]);
    }

    printf("\n");
}

int bn_is_zero(uint32_t *x, int wsize)
{
    int i;

    for (i = 0; i < wsize; i++)
    {
        if (x[i])
            return 0;
    }
    return 1;
}

int bn_is_nonzero(uint32_t *x, int wsize)
{
    int i;

    for (i = 0; i < wsize; i++)
    {
        if (x[i])
            return 1;
    }
    return 0;
}

int bn_is_one(uint32_t *x, int wsize)
{
    /********/
    int i;
    /********/

    if (x[0] != 1)
    {
        return 0;
    }
    for (i = 1; i < wsize; i++)
    {
        if (x[i])
            return 0;
    }
    return 1;
}

int bn_is_even(uint32_t *x)
{
    return (BN_LSB(x, BN_MAX_WORDSIZE) == 0);
}

int bn_is_odd(uint32_t *x)
{
    return (BN_LSB(x, BN_MAX_WORDSIZE) == 1);
}

int bn_equal(const uint32_t *x, const uint32_t *y, int wsize)
{
    int i;

    for (i = 0; i < wsize; i++)
    {
        if (x[i] != y[i])
            return 0;
    }
    return 1;
}

int bn_get_bitlen(const uint32_t *x, int wsize)
{
    /***********************/
    int i, bits;
    uint32_t t;
    /***********************/

    for (i = wsize - 1; i >= 0; i--)
    {
        if (x[i])
        {
            t = x[i];
            break;
        }
    }
    if (i < 0)
        return 0;

    bits = (i << 5) + 1;
    for (i = WORDBITS / 2; i > 0; i >>= 1)
    {
        if (t >> i)
        {
            t >>= i;
            bits += i;
        }
    }

    return bits;
}

int bn_get_wordlen(const uint32_t *x, int wsize)
{
    int i;

    for (i = wsize - 1; i >= 0; i--)
    {
        if (x[i] != 0)
            return i + 1;
    }
    return 0;
}

void BN_GetLen(int32_t *pBitLen, int32_t *pU32Len, uint32_t *pwBN, int32_t wsize)
{
    /***********************/
    int32_t i = 0;
    int32_t j = 0;
    uint32_t tmp = 0;
    /***********************/

    *pU32Len = 0;
    for (i = wsize - 1; i >= 0; i--)
    {
        if (pwBN[i] != 0)
        {
            break;
        }
    }
    if (i == -1)
    {
        *pBitLen = 0;
        *pU32Len = 0;
    }
    else
    {
        j = 0;
        tmp = pwBN[i];
        while ((tmp & MSBOfWord) == 0)
        {
            tmp = tmp << 1;
            j++;
        }
        *pU32Len = i + 1;
        *pBitLen = (i << 5) + (WordLen - j);
    }
}

int bn_div_2(uint32_t *y, const uint32_t *x, int wsize)
{
    int i, c;

    c = x[0] & LSBOfWord;
    for(i = 0; i < wsize - 1; i++)
    {
        y[i] = (x[i] >> 1) | (x[i + 1] << (WORDBITS - 1));
    }
    y[i] = x[i] >> 1;

    return c;
}

int bn_mul_2(uint32_t *y, const uint32_t *x, int wsize)
{
    int i, c;

    c = x[wsize - 1] & MSBOfWord;
    for (i = wsize - 1; i > 0; i--)
    {
        y[i] = (x[i] << 1) | (x[i - 1] >> (WORDBITS - 1));
    }
    y[0] = x[0] << 1;

    return c;
}

uint32_t bn_add(uint32_t *r, const uint32_t *x, const uint32_t *y, int wsize)
{
    /*********************/
    int i;
    uint64_t carry = 0;
    /*********************/

    for (i = 0; i < wsize; i++)
    {
        carry = (uint64_t)x[i] + (uint64_t)y[i] + carry;
        r[i] = (uint32_t)carry;
        carry = carry >> 32;
    }
    return (uint32_t)carry;
}

uint32_t bn_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, int wsize)
{
    /**********************/
    int i = 0;
    uint64_t borrow = 0;
    /**********************/

    for (i = 0; i < wsize; i++)
    {
        borrow = (uint64_t)x[i] - (uint64_t)y[i] + borrow;
        r[i] = (uint32_t)borrow;
        borrow = (uint64_t)(((int64_t)borrow) >> 32);
    }
    return (uint32_t)borrow;
}

void bn_mod_add(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int wsize)
{
    int i = 256;//Prevent infinite circulation

    if (bn_add(r, x, y, wsize))
    {
        while (i--)    { if (bn_sub(r, r, m, wsize))    break; }
    }
}

void bn_mod_sub(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, int wsize)
{
    int i = 256;//Prevent infinite circulation

    if (bn_sub(r, x, y, wsize))
    {
        while (i--)    { if (bn_add(r, r, m, wsize))    break; }
    }
}

void bn_mod_inv(uint32_t *r, uint32_t *x, uint32_t *m, int wsize)
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
    while (bn_is_nonzero(bn_v, wsize))
    {
        // 2.1 If u is even, do { u = u / 2, B = B / 2 mod m }
        while ((bn_u[0] & LSBOfWord) == 0)
        {
            bn_div_2(bn_u, bn_u, wsize);
            bn_mod_div_2(bn_B, bn_B, m, wsize);
        }
        // 2.2 If v is even, do { v = v / 2, D = D / 2 mod m }
        while ((bn_v[0] & LSBOfWord) == 0)
        {
            bn_div_2(bn_v, bn_v, wsize);
            bn_mod_div_2(bn_D, bn_D, m, wsize);
        }
        // 2.3 If u > v, do { u = u - v,  B = B + D mod m }
        if (bn_cmp(bn_u, bn_v, wsize) > 0)
        {
            bn_sub(bn_u, bn_u, bn_v, wsize);
            bn_mod_add(bn_B, bn_B, bn_D, m, wsize);
        }
        // 2.4 If u <= v, do { v = v - u, D = D + B mod m }
        else
        {
            bn_sub(bn_v, bn_v, bn_u, wsize);
            bn_mod_add(bn_D, bn_D, bn_B, m, wsize);
        }
    }

    // Step_3. Inverse is -B mod m
    bn_mod_neg(r, bn_B, m, wsize);
}

void BN_GetInv_Mont(uint32_t *r, uint32_t *x, uint32_t *m, uint32_t mc, uint32_t *pwRRModule, int wsize)
{
    bn_mod_inv(r, x, m, wsize);
    bn_mont_mul(r, r, pwRRModule, m, mc, wsize);
}

void bn_mod_neg(uint32_t *r, const uint32_t *x, const uint32_t *m, int wsize)
{
    int i = 256;//Prevent infinite circulation

    if (bn_sub(r, m, x, wsize))
    {
        while (i--)    { if (bn_add(r, r, m, wsize))    break; }
    }
}

void bn_mod_div_2(uint32_t *r, const uint32_t *x, const uint32_t *m, int wsize)
{
    uint32_t carry;

    if ((x[0] & LSBOfWord))
    {
        carry = bn_add(r, x, m, wsize);
        bn_div_2(r, r, wsize);
        r[wsize - 1] |= carry << (WORDBITS - 1);
    }
    else
        bn_div_2(r, x, wsize);
}

int bn_mont_init(uint32_t *mc, const uint32_t *m)
{
    uint32_t x, a;

    /* fast inversion mod 2^k */
    a = m[0];

    if ((a & 1) == 0)
        return -1;

    x = (((a + 2) & 4) << 1) + a;    /* here x*a==1 mod 2^4 */
    x *= 2 - (a * x);                /* here x*a==1 mod 2^8 */
    x *= 2 - (a * x);                /* here x*a==1 mod 2^16 */
    x *= 2 - (a * x);                /* here x*a==1 mod 2^32 */

    /* mc = -1/m mod b */
    *mc = (~x + 1) & 0xFFFFFFFF;

    return 0;
}

void bn_mont_mul(uint32_t *r, const uint32_t *x, const uint32_t *y, const uint32_t *m, uint32_t mc, int wsize)
{
    int i, j;
    uint64_t carry;
    uint32_t U;
    uint32_t D[BN_MAX_WORDSIZE + 2];

    bn_reset(D, wsize + 2);

    for (i = 0; i < wsize; i++)
    {
        // D = D + x*y[i]
        carry = 0;
        for (j = 0; j < wsize; j++)
        {
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
        for (j = 1; j < wsize; j++)
        {
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

void bn_mont_redc(uint32_t *r, const uint32_t *x, const uint32_t *m, uint32_t mc, int wsize)
{
    int i, j;
    uint64_t carry;
    uint32_t U;
    uint32_t D[BN_MAX_WORDSIZE];

    // D = x
    bn_assign(D, x, wsize);
    for (i = 0; i < wsize; i++)
    {
        // U = D[0] * ((-p)^(-1) mod b) mod b
        U = (uint32_t)((uint64_t)D[0] * (uint64_t)mc);

        // D = (D + U * p)/b
        carry = ((uint64_t)D[0] + (uint64_t)U * (uint64_t)m[0]) >> 32;
        for (j = 1; j < wsize; j++)
        {
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

void bn_mont_squ(uint32_t *r, const uint32_t *x, const uint32_t *m, uint32_t mc, int wsize)
{
    bn_mont_mul(r, x, x, m, mc, wsize);
}

int bn_mont_parity(uint32_t *x, const uint32_t *m, uint32_t mc, int wsize)
{
    uint32_t t[BN_MAX_WORDSIZE];

    bn_mont_redc(t, x, m, mc, wsize);
    bn_get_res(t, m, wsize);

    return BN_LSB(t, wsize);
}

void bn_mont_exp(uint32_t *r, const uint32_t *x, const uint32_t *e, const uint32_t *m, uint32_t mc, int wsize)
{
    int i, bitlen;
    uint32_t t[BN_MAX_WORDSIZE];

    bitlen = bn_get_bitlen(e, wsize);
    if (bitlen == 0)
    {
        bn_set_int(r, 1, wsize);
        return;
    }
    if (bitlen == 1)
    {
        bn_assign(r, x, wsize);
        return;
    }

    bn_assign(t, x, wsize);
    for (i = bitlen - 2; i >= 0; i--)
    {
        bn_mont_squ(t, t, m, mc, wsize);
        if (BN_BIT(e, i))
            bn_mont_mul(t, t, x, m, mc, wsize);
    }
    bn_assign(r, t, wsize);
}

void BN_Random(uint32_t *pwBN, int32_t wsize)
{
    /*******************/
    int32_t i = 0;
    uint8_t B0 = 0;
    uint8_t B1 = 0;
    uint8_t B2 = 0;
    uint8_t B3 = 0;
    /*******************/

    for (i = 0; i < wsize; i++)
    {
        B0 = (uint8_t)rand();
        B1 = (uint8_t)rand();
        B2 = (uint8_t)rand();
        B3 = (uint8_t)rand();
        pwBN[i] = ((uint32_t)B3 << 24) | ((uint32_t)B2 << 16) | ((uint32_t)B1 << 8) | ((uint32_t)B0);
    }
}

void bn_get_res(uint32_t *x, const uint32_t *m, int wsize)
{
    if (bn_cmp(x, m, wsize) > 0)
        bn_sub(x, x, m, wsize);
}

int32_t BN_Mod_Basic(uint32_t *rem, int32_t iBNWordLen_r, uint32_t *pwBNX, int32_t iBNWordLen_X, uint32_t *pwBNM, int32_t iBNWordLen_M)
{
    /******************************/
    int32_t i = 0;
    int32_t j = 0;
    uint64_t q = 0;
    uint64_t carry = 0;
    uint64_t tmp = 0;
    int32_t k = 0;
    int32_t l = 0;
    int32_t ll = 0;
    int32_t len_rem = 0;
    uint32_t temp[BN_MAX_WORDSIZE];
    uint32_t quo_tmp[BN_MAX_WORDSIZE];
    /******************************/

    bn_reset(temp, BN_MAX_WORDSIZE);
    bn_reset(quo_tmp, BN_MAX_WORDSIZE);
    k = iBNWordLen_X;
    l = iBNWordLen_M;
    ll = l - 1;
    for (i = k - l; i >= 0; i--)
    {
        q = ((((uint64_t)(pwBNX[i + l]) << WordLen) + (uint64_t)pwBNX[i + l - 1]))/(uint64_t)pwBNM[ll];//q[i] = (r[i+l]B+R[i+l-1])/b[l-1]
        if(q & 0xffffffff00000000)
            quo_tmp[i] = 0xffffffff;
        else
            quo_tmp[i] = (uint32_t)q;
        carry = 0;
        for(j = 0; j < l; j++)//temp = q[i] * pwBNM
        {
            carry = (uint64_t)quo_tmp[i] * ( uint64_t)pwBNM[j] + carry;
            temp[j] = (uint32_t)carry;
            carry >>= WordLen;
        }
        temp[j] = (uint32_t)carry;
        carry = 0;
        for(j = 0; j < l; j++)//pwBNX = pwBNX - (temp << ( 32 * i))
        {
            carry = (uint64_t)pwBNX[i+j] - (uint64_t)temp[j] + carry;
            pwBNX[i+j] = (uint32_t) carry;
            carry = ((int64_t)carry) >> WordLen;
        }
        carry = (uint64_t)pwBNX[i+j] - (uint64_t)temp[j] + carry;
        while(carry & 0x1000000000000000)//while r[i+l] < 0
        {
            tmp = 0;
            for(j = 0; j < l; j++)//pwBNX = pwBNX + (pwBNM << ( 32 * i))
            {
                tmp = (uint64_t)pwBNX[i+j] + (uint64_t)pwBNM[j]+tmp;
                pwBNX[i + j] = (uint32_t)tmp;
                tmp = (uint64_t)(tmp >> WordLen);
            }
            carry = carry + tmp;
            quo_tmp[i] -= 1;
        }
        pwBNX[i + l] = (uint32_t)carry;
    }
    len_rem = bn_get_wordlen(pwBNX, iBNWordLen_M);
    if (len_rem > iBNWordLen_r)
        return 0;
    bn_assign(rem, pwBNX, len_rem);
    return 1;
}

int bn_get_bytes(uint32_t *pWord, int wordlen, unsigned char *pByte, int bytelen)
{
    int b, j, w;

    if (wordlen)
    {
        if (bytelen > wordlen *WORDBYTES)
            return -1;
    }

    for (b = bytelen, w = 0; b >= WORDBYTES; b -= WORDBYTES)
    {
        pWord[w++] = ((uint32_t)pByte[b - 4] << 24) |
            ((uint32_t)pByte[b - 3] << 16) |
            ((uint32_t)pByte[b - 2] << 8) |
            ((uint32_t)pByte[b - 1]);
    }
    if (b > 0)
    {
        pWord[w] = 0;
        while (b--)
        {
            pWord[w] = (pWord[w] << 8) | pByte[b];
        }
        w++;
    }

    // reset other unused word
    for (j = w; j < wordlen; j++)
    {
        pWord[j++] = 0;
    }

    return w;
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

    if (Rem != 0)
    {
        ExpLen += 1;
    }

    if (ExpLen > wsize)
    {
        return 0;
    }

    i = bytelen - 1;
    j = 0;
    while (i >= Rem)
    {
        pwBN[j] = ((uint32_t)pByteBuf[i]) | ((uint32_t)pByteBuf[i - 1] << 8) | ((uint32_t)pByteBuf[i - 2] << 16) | ((uint32_t)pByteBuf[i - 3] << 24);
        i -= 4;
        j++;
    }

    i = 0;
    while (i < Rem)
    {
        pwBN[j] = (pwBN[j] << 8) | ((uint32_t)pByteBuf[i]);
        i++;
    }

    return 1;
}

int BN_WriteBytes(unsigned char *pbDst, int iWords, uint32_t *pwSrc)
{
    /*******************/
    int i, j;
    unsigned char *s, *e;
    uint32_t TE, TS;
    /*******************/

    s = pbDst;
    e = pbDst + iWords * WordByteLen - 1;
    i = 0;
    j = iWords - 1;
    while (i < j)
    {
        TE = pwSrc[i++];
        TS = pwSrc[j--];

        *s++ = (unsigned char)((TS & 0xFF000000) >> 24);
        *s++ = (unsigned char)((TS & 0x00FF0000) >> 16);
        *s++ = (unsigned char)((TS & 0x0000FF00) >>  8);
        *s++ = (unsigned char)((TS & 0x000000FF)      );

        *e-- = (unsigned char)((TE & 0x000000FF));
        *e-- = (unsigned char)((TE & 0x0000FF00) >> 8);
        *e-- = (unsigned char)((TE & 0x00FF0000) >> 16);
        *e-- = (unsigned char)((TE & 0xFF000000) >> 24);
    }
    if (i == j)
    {
        TS = pwSrc[i];
        *s++ = (unsigned char)((TS & 0xFF000000) >> 24);
        *s++ = (unsigned char)((TS & 0x00FF0000) >> 16);
        *s++ = (unsigned char)((TS & 0x0000FF00) >> 8);
        *s++ = (unsigned char)((TS & 0x000000FF));
    }

    return iWords * BNWordLen;
}

int bn_put_bytes(unsigned char *pByte, int bytelen, uint32_t *pWord, int wordlen)
{
    int w, b;

    if (bytelen)
    {
        if (wordlen > bytelen / WORDBYTES)
            return -1;
    }

    for (w = wordlen - 1, b = 0; w >= 0; w--)
    {
        pByte[b++] = (unsigned char)(pWord[w] >> 24) & 0xFF;
        pByte[b++] = (unsigned char)(pWord[w] >> 16) & 0xFF;
        pByte[b++] = (unsigned char)(pWord[w] >>  8) & 0xFF;
        pByte[b++] = (unsigned char)(pWord[w]      ) & 0xFF;
    }

    return b;
}

int32_t BNToByte(uint32_t *pwBN,int32_t wsize,uint8_t *pByteBuf,int32_t *bytelen)
{
    /*******************/
    int32_t i = 0;
    uint8_t *P = NULL;
    uint32_t W = 0;
    /*******************/

    P = pByteBuf;
    for(i = wsize - 1; i >= 0; i--)
    {
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

void bn_lsr(uint32_t* r, const uint32_t* x, int n, int wsize)
{
    int i;

    n = n & (WORDBITS - 1);
    for (i = 0; i < wsize - 1; i++)
    {
        r[i] = (x[i] >> n) | (x[i + 1] << (WORDBITS - n));
    }
    r[i] = x[i] >> n;
}

uint32_t bn_add_int(uint32_t *r, const uint32_t *x, unsigned int n, int wsize)
{
    /*********************/
    int i = 0;
    uint64_t carry = 0;
    /*********************/

    if (n)
    {
        carry = (uint64_t)x[0] + (uint64_t)n;
        r[0] = (uint32_t)carry;
        carry = carry >> 32;
        for (i = 1; i < wsize; i++)
        {
            if (carry == 0)
                break;
            carry = (uint64_t)x[i] + carry;
            r[i] = (uint32_t)carry;
            carry = carry >> 32;
        }
    }
    if (r != x)
    {
        for (; i < wsize; i++)
            r[i] = x[i];
    }

    return (uint32_t)carry;
}

uint32_t bn_sub_int(uint32_t *r, const uint32_t *x, unsigned int n, int wsize)
{
    /**********************/
    int i = 0;
    uint64_t borrow = 0;
    /**********************/

    if (n)
    {
        borrow = (uint64_t)x[0] - (uint64_t)n + borrow;
        r[0] = (uint32_t)borrow;
        borrow = (uint64_t)(((int64_t)borrow) >> 32);
        for (i = 1; i < wsize; i++)
        {
            if (borrow == 0)    break;
            borrow = (uint64_t)x[i] + borrow;
            r[i] = (uint32_t)borrow;
            borrow = (uint64_t)(((int64_t)borrow) >> 32);
        }
    }
    if (r != x)
    {
        for (; i < wsize; i++)
            r[i] = x[i];
    }

    return (uint32_t)borrow;
}

int bn_mont_sqrt(uint32_t* r, const uint32_t *x, const uint32_t *m, uint32_t mc, int wsize)
{
    uint32_t t[BN_MAX_WORDSIZE];
    uint32_t y[BN_MAX_WORDSIZE];
    uint32_t z[BN_MAX_WORDSIZE];

    /* SPECIAL CASE: if prime mod 4 == 3
     * compute directly: res = n^(prime+1)/4 mod prime
     * Handbook of Applied Cryptography algorithm 3.36
     */
    if ((m[0] & 3) == 3)    //If p mod 4 == 3
    {
        bn_lsr(t, m, 2, wsize);//t = u = p >> 2
        bn_add_int(t, t, 1, wsize);//t = u + 1
        bn_mont_exp(y, x, t, m, mc, wsize);//y = x ^ (u+1)

        bn_mont_squ(z, y, m, mc, wsize);//z = y ^ 2
        if (bn_equal(z, x, wsize) == 1) //if z = x, exist square root
        {
            bn_assign(r, y, wsize);
            return 0;
        }
        else
            return -1;
    }
    if ((m[0] & 7) == 5)    //If p mod 8 == 5
    {
        bn_lsr(t, m, 3, wsize);//t = u = p >> 3
        bn_mont_exp(y, x, t, m, mc, wsize);//y = x ^ u
        bn_mont_squ(z, y, m, mc, wsize);//z = x ^ 2u
        bn_mont_mul(z, z, x, m, mc, wsize);//z = x ^ (2u+1)
        bn_mont_redc(z, z, m, mc, wsize);
        if (bn_is_one(z, wsize))    //If z == 1
        {
            bn_mont_mul(r, y, x, m, mc, wsize);//y = x ^ (u+1)
            return 0;
        }
        else
        {
            bn_sub(z, m, z, wsize);
            if (bn_is_one(z, wsize)) //If z == -1
            {
                bn_mod_add(y, x, x, m, wsize);
                bn_mod_add(y, y, y, m, wsize);//y = 4x
                bn_mont_exp(y, y, t, m, mc, wsize);//y = (4x) ^ u
                bn_mont_mul(y, y, x, m, mc, wsize);//y = x * (4x)^u
                bn_mod_add(r, y, y, m, wsize);//y = 2x * (4x)^u
                return 0;
            }
            else
                return -1;
        }
    }
    if ((m[0] & 7) == 1)
    {
        return -1;
    }

    return -1;
}

#endif // HITLS_CRYPTO_SM9
