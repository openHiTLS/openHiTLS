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

#ifndef HITLS_SIXTY_FOUR_BITS
#error Bn binical x8664 optimizer must open BN-64.
#endif

// r = a + b, len = n, return carry
BN_UINT BinAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    if (n == 0) {
        return 0;
    }

    BN_UINT ret = n;
    asm volatile (
                  ".p2align 4                          \n"
                  "       mov     %0, %%rcx            \n"
                  "       and     $3, %%rcx            \n" // will clear CF
                  "       shr     $2, %0               \n"
                  "       clc                          \n"
                  "       jz      aone                 \n" // n / 4 > = 0 , goto step 4
                  "4:     movq    0(%2), %%r8          \n"
                  "       movq    8(%2), %%r9          \n"
                  "       movq    16(%2), %%r10        \n"
                  "       movq    24(%2), %%r11        \n"
                  "       adcq    0(%3), %%r8          \n"
                  "       adcq    8(%3), %%r9          \n"
                  "       adcq    16(%3), %%r10        \n"
                  "       adcq    24(%3), %%r11        \n"
                  "       movq    %%r8, 0(%1)          \n"
                  "       movq    %%r9, 8(%1)          \n"
                  "       movq    %%r10, 16(%1)        \n"
                  "       movq    %%r11, 24(%1)        \n"
                  "       lea     32(%1), %1           \n"
                  "       lea     32(%2), %2           \n"
                  "       lea     32(%3), %3           \n"
                  "       dec     %0                   \n"
                  "       jnz     4b                   \n"
                  "aone:  jrcxz   eadd                 \n" // n % 4 == 0, goto end
                  "1:     movq    (%2,%0,8),  %%r8     \n"
                  "       adcq    (%3,%0,8),  %%r8     \n"
                  "       movq    %%r8, (%1,%0,8)      \n"
                  "       inc     %0                   \n"
                  "       dec     %%rcx                \n"
                  "       jnz     1b                   \n"
                  "eadd:  sbbq    %0, %0               \n"
                  :"+&r" (ret)
                  :"r"(r), "r"(a), "r"(b)
                  :"r8", "r9", "r10", "r11", "rcx", "cc", "memory");

    return ret & 1;
}

// r = a - b, len = n, return carry
BN_UINT BinSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    if (n == 0) {
        return 0;
    }

    BN_UINT res = n;
    asm volatile (
                  ".p2align 4                          \n"
                  "       mov     %0, %%rcx            \n"
                  "       and     $3, %%rcx            \n"
                  "       shr     $2, %0               \n"
                  "       clc                          \n"
                  "       jz      sone                 \n" // n / 4 > = 0 , goto step 4
                  "4:     movq    0(%2), %%r8          \n"
                  "       movq    8(%2), %%r9          \n"
                  "       movq    16(%2), %%r10        \n"
                  "       movq    24(%2), %%r11        \n"
                  "       sbbq    0(%3), %%r8          \n"
                  "       sbbq    8(%3), %%r9          \n"
                  "       sbbq    16(%3), %%r10        \n"
                  "       sbbq    24(%3), %%r11        \n"
                  "       movq    %%r8, 0(%1)          \n"
                  "       movq    %%r9, 8(%1)          \n"
                  "       movq    %%r10, 16(%1)        \n"
                  "       movq    %%r11, 24(%1)        \n"
                  "       lea     32(%1), %1           \n"
                  "       lea     32(%2), %2           \n"
                  "       lea     32(%3), %3           \n"
                  "       dec     %0                   \n"
                  "       jnz     4b                   \n"
                  "sone:  jrcxz   esub                 \n" // n % 4 == 0, goto end
                  "1:     movq    (%2,%0,8),  %%r8     \n"
                  "       sbbq    (%3,%0,8),  %%r8     \n"
                  "       movq    %%r8, (%1,%0,8)      \n"
                  "       inc     %0                   \n"
                  "       dec     %%rcx                \n"
                  "       jnz     1b                   \n"
                  "esub:  sbbq    %0, %0               \n"
                  :"+&r" (res)
                  :"r"(r), "r"(a), "r"(b)
                  :"r8", "r9", "r10", "r11", "rcx", "cc", "memory");

    return res & 1;
}

// r = r - a * m, return the carry;
BN_UINT BinSubMul(BN_UINT *r, const BN_UINT *a, BN_UINT aSize, BN_UINT m)
{
    BN_UINT borrow = 0;
    BN_UINT i = 0;
    asm volatile (
                  ".p2align 4                          \n"
                  "endy:  movq    %5, %%rax            \n" // rax = m
                  "       mulq    (%4,%1,8)            \n" // rax -> al, rdx -> ah
                  "       addq    %0,  %%rax           \n" // rax = al + borrow
                  "       adcq    $0,  %%rdx           \n" // if has carry, rdx++
                  "       subq    %%rax,  (%3,%1,8)    \n" // r[i] = r[i] - (al + borrow)
                  "       adcq    $0,  %%rdx           \n" // if has carry, borrow++
                  "       movq    %%rdx,  %0           \n"
                  "       inc     %1                   \n"
                  "       dec     %2                   \n"
                  "       jnz     endy                 \n"
                :"+&r" (borrow), "+r"(i), "+r"(aSize)
                :"r"(r), "r"(a), "r"(m)
                :"rax", "rdx", "cc", "memory");
    return borrow;
}

/* Obtains the number of 0s in the first x most significant bits of data. */
uint32_t GetZeroBitsUint(BN_UINT x)
{
    BN_UINT count;
    asm ("lzcnt %1, %0" : "=r" (count) : "r" (x));
    return count;
}

#endif /* HITLS_CRYPTO_BN */
