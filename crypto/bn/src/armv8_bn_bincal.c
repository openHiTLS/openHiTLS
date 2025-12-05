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

#ifndef HITLS_SIXTY_FOUR_BITS
#error Bn binical armv8 optimizer must opens BN-64.
#endif

#include <stdint.h>
#include "bn_bincal.h"

// r = a + b, len = n, return carry
BN_UINT BinAdd(BN_UINT *r, const BN_UINT *a, const BN_UINT *b,  uint32_t n)
{
    if (n == 0) {
        return 0;
    }

    BN_UINT ret = 0;
    BN_UINT times = n >> 2;
    BN_UINT rem = n & 3;
    asm volatile(
                ".align 3                              \n"
                "       mov   %0, #1                   \n"
                "       adcs  %0, xzr, %0              \n" // clear C flags
                "       mov   %0, #0                   \n"
                "       cbz   %1, 3f                 \n"
                "4:     add   x4, %3, %0               \n"
                "       add   x5, %4, %0               \n"
                "       add   x6, %5, %0               \n"
                "       ldp   x7, x8, [x5]             \n"
                "       ldp   x9, x10, [x5,#16]        \n"
                "       ldp   x11, x12, [x6]           \n"
                "       ldp   x13, x14, [x6,#16]       \n"
                "       adcs   x7, x7, x11             \n"
                "       adcs   x8, x8, x12             \n"
                "       adcs   x9, x9, x13             \n"
                "       adcs   x10, x10, x14           \n"
                "       stp    x7, x8, [x4]            \n"
                "       stp    x9, x10, [x4, #16]      \n"
                "       sub    %1, %1, #0x1            \n"
                "       add    %0, %0, #0x20           \n"
                "       cbnz   %1, 4b                  \n"
                "3:  cbz    %2, 2f                \n" // times <= 0, jump to single cycle
                "1:     ldr    x7, [%4, %0]            \n"
                "       ldr    x8, [%5, %0]            \n"
                "       adcs   x7, x7, x8              \n"
                "       str    x7, [%3, %0]            \n"
                "       sub    %2, %2, #0x1            \n"
                "       add    %0, %0, #0x8            \n"
                "       cbnz   %2, 1b                  \n"
                "2:  mov    %0, #0                  \n"
                "       adcs   %0, xzr, %0             \n"
                  :"+&r" (ret), "+r"(times), "+r"(rem)
                  :"r"(r), "r"(a), "r"(b)
                  :"x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "cc", "memory");

    return ret & 1;
}

// r = a - b, len = n, return carry
BN_UINT BinSub(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t n)
{
    if (n == 0) {
        return 0;
    }

    BN_UINT ret = 0;
    BN_UINT rem = n & 3;
    BN_UINT times = n >> 2;
    asm volatile(
                ".align 3                              \n"
                "       mov   %0, #1                   \n"
                "       sbcs  %0, %0, xzr              \n" // clear C flags
                "       mov   %0, #0                   \n"
                "       cbz	  %1, 2f                 \n"
                "4:     add   x4, %3, %0               \n"
                "       add	  x5, %4, %0               \n"
                "       add	  x6, %5, %0               \n"
                "       ldp   x7, x8, [x5]             \n"
                "       ldp   x9, x10, [x5,#16]        \n"
                "       ldp   x11, x12, [x6]           \n"
                "       ldp   x13, x14, [x6,#16]       \n"
                "       sbcs   x7, x7, x11             \n"
                "       sbcs   x8, x8, x12             \n"
                "       sbcs   x9, x9, x13             \n"
                "       sbcs   x10, x10, x14           \n"
                "       stp    x7, x8, [x4]            \n"
                "       stp    x9, x10, [x4, #16]      \n"
                "       sub    %1, %1, #0x1            \n"
                "       add    %0, %0, #0x20           \n"
                "       cbnz   %1, 4b                  \n"
                "2:  cbz    %2, 3f                \n" // times <= 0, jump to single cycle
                "1:     ldr    x7, [%4, %0]            \n"
                "       ldr    x8, [%5, %0]            \n"
                "       sbcs   x7, x7, x8              \n"
                "       str    x7, [%3, %0]            \n"
                "       sub    %2, %2, #0x1            \n"
                "       add    %0, %0, #0x8            \n"
                "       cbnz   %2, 1b                  \n"
                "3:  mov   %0,#0                    \n"
                "       sbcs  %0,xzr,%0                \n"
                  :"+&r" (ret), "+r"(times), "+r"(rem)
                  :"r"(r), "r"(a), "r"(b)
                  :"x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "cc", "memory");

    return ret & 1;
}

// r = r - a * m, return the carry;
BN_UINT BinSubMul(BN_UINT *r, const BN_UINT *a, BN_UINT aSize, BN_UINT m)
{
    BN_UINT borrow = 0;
    BN_UINT i = 0;
    asm volatile(
                ".align 3                               \n"
                "2:  ldr   x4, [%3, %1]              \n" // x4 = r[i]
                "       ldr   x5, [%4, %1]              \n" // x5 = r[i]
                "	    mul   x7, x5, %5                \n" // x7 = al
                "       umulh x6, x5, %5                \n" // x6 = ah
                "       adds  x7, %0, x7                \n" // x7 = borrow + al
                "       adcs  %0, x6, xzr               \n" // borrow = ah + H(borrow + al)
                "       cmp   x7, x4                    \n" // if r[i] > borrow + al, dont needs carry
                "       beq   1f                        \n"
                "       adc   %0, %0, xzr               \n"
                "1:     sub   x4, x4, x7                \n"
                "       str   x4, [%3, %1]              \n"
                "       sub   %2, %2, #0x1              \n"
                "       add   %1, %1, #0x8              \n"
                "       cbnz  %2, 2b                  \n"
                :"+&r" (borrow), "+r"(i), "+r"(aSize)
                :"r"(r), "r"(a), "r"(m)
                :"x4", "x5", "x6", "x7", "cc", "memory");

    return borrow;
}

/* Obtains the number of 0s in the first x most significant bits of data. */
uint32_t GetZeroBitsUint(BN_UINT x)
{
    BN_UINT count;
    asm ("clz %0, %1" : "=r" (count) : "r" (x));
    return (uint32_t)count;
}

#endif /* HITLS_CRYPTO_BN */
