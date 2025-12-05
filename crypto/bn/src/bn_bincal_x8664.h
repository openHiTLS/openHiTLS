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
#ifndef BN_BINCAL_X8664_H
#define BN_BINCAL_X8664_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "bn_basic.h"

#ifdef __cplusplus
extern "c" {
#endif

// wh | wl = u * v
#define MUL_AB(wh, wl, u, v)                                           \
    {                                                                  \
        __asm("mulq %3" : "=d"(wh), "=a"(wl) : "a"(u), "r"(v) : "cc"); \
    }
// wh | wl = u ^ 2
#define SQR_A(wh, wl, u)                                               \
    {                                                                  \
        __asm("mulq %2 " : "=d"(wh), "=a"(wl) : "a"(u) : "cc"); \
    }

// nh | nl / d = q...r
#define DIV_ND(q, r, nh, nl, d)                                                  \
    {                                                                            \
        __asm("divq   %4" : "=a"(q), "=d"(r) : "d"(nh), "a"(nl), "r"(d) : "cc"); \
    }

/* r += c
 * c = carry
 */
#define ADD_CARRY(carry, r)          \
    do {                             \
        __asm("addq %1, %0 \n\t "    \
              "adcq %4, %1 \n\t "    \
              "adcq $0, %2 \n\t "    \
              : "+m"(l), "+r"(carry) \
              :                      \
              : "cc");               \
    } while (0)

/* h|m|l = h|m|l + u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULXADD_AB(h, m, l, u, v)                                     \
    do {                                                             \
        BN_UINT hi, lo;                                              \
        __asm("mulq %0, %1, %2" : "=a"(lo), "=d"(hi) : "a"(u), "m"(v) : "cc"); \
        __asm("addq %3, %0 \n\t "                                    \
              "adcq %4, %1 \n\t "                                    \
              "adcq $0, %2 \n\t "                                    \
              : "+r"(l), "+r"(m), "+r"(h)                            \
              : "r"(lo), "r"(hi)                                     \
              : "cc");                                               \
    } while (0)

// (hi, lo) = a * b
// r += lo + carry
// carry = hi + c
#define MULADC_AB(r, a, b, carry)                                      \
    do {                                                               \
        BN_UINT hi, lo;                                                \
        __asm("mulq %3" : "=a"(lo), "=d"(hi) : "a"(a), "g"(b) : "cc"); \
        __asm("addq %3, %1 \n\t"                                       \
              "adcq $0, %2 \n\t"                                       \
              "addq %1, %0 \n\t"                                       \
              "adcq $0, %2 \n\t"                                       \
              "movq %2, %1 \n\t"                                       \
              : "+r"(r), "+r"(carry), "+r"(hi)                         \
              : "r"(lo)                                                \
              : "cc");                                                 \
    } while (0)

/* h|m|l = h|m|l + u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULADD_AB(h, m, l, u, v)                                       \
    do {                                                               \
        BN_UINT hi, lo;                                                \
        __asm("mulq %3" : "=a"(lo), "=d"(hi) : "a"(u), "m"(v) : "cc"); \
        __asm("addq %3, %0 \n\t "                                      \
              "adcq %4, %1 \n\t "                                      \
              "adcq $0, %2 \n\t "                                      \
              : "+r"(l), "+r"(m), "+r"(h)                              \
              : "r"(lo), "r"(hi)                                       \
              : "cc");                                                 \
    } while (0)

/* h|m|l = h|m|l + 2 * u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULADD_AB2(h, m, l, u, v)                                     \
    do {                                                             \
        BN_UINT hi, lo;                                              \
        __asm("mulq %3" : "=a"(lo), "=d"(hi) : "a"(u), "m"(v) : "cc"); \
        __asm("addq %3, %0 \n\t "                                    \
              "adcq %4, %1 \n\t "                                    \
              "adcq $0, %2 \n\t "                                    \
              "addq %3, %0 \n\t "                                    \
              "adcq %4, %1 \n\t "                                    \
              "adcq $0, %2 \n\t "                                    \
              : "+r"(l), "+r"(m), "+r"(h)                            \
              : "r"(lo), "r"(hi)                                     \
              : "cc");                                               \
    } while (0)

/* h|m|l = h|m|l + u * u. Ensure that the value of h is not too large to avoid carry. */
#define SQRADD_A(h, m, l, u)   MULADD_AB(h, m, l, u, u)

// Modular operation, satisfy d < (1 << BN_UINT_HALF_BITS) r = nh | nl % d
#define MOD_HALF(r, nh, nl, d)                                  \
    do {                                                        \
        BN_UINT tmp = 0;                                      \
        __asm("divq   %4" : "=a"(tmp), "=d"(r) : "d"(nh), "a"(nl), "r"(d) : "cc"); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif