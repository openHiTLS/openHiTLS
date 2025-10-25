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
#ifndef BN_BINCAL_ARMV8_H
#define BN_BINCAL_ARMV8_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include "bn_basic.h"

#ifdef __cplusplus
extern "c" {
#endif

// wh | wl = u * v
#define MUL_AB(wh, wl, u, v)                         \
    {                                                \
        __asm("mul   %1, %2, %3                \n\t" \
              "umulh %0, %2, %3                \n\t" \
              : "=&r"(wh), "=&r"(wl)                 \
              : "r"(u), "r"(v)                       \
              : "cc");                               \
    }
// wh | wl = u ^ 2
#define SQR_A(wh, wl, u)                             \
    {                                                \
        __asm("mul   %1, %2, %2                \n\t" \
              "umulh %0, %2, %2                \n\t" \
              : "=&r"(wh), "=&r"(wl)                 \
              : "r"(u)                               \
              : "cc");                               \
    }

/* nh|nl / d = q...r */
#define DIV_ND(q, r, nh, nl, d)                                 \
    do {                                                        \
        BN_UINT macroTmpD1, macroTmpD0, macroTmpQ1, macroTmpQ0, macroTmpR1, macroTmpR0, macroTmpM;        \
                                                                \
        macroTmpD1 = BN_UINT_HI(d);                                   \
        macroTmpD0 = BN_UINT_LO(d);                                   \
                                                                \
        macroTmpQ1 = (nh) / macroTmpD1;                                     \
        macroTmpR1 = (nh) - macroTmpQ1 * macroTmpD1;                              \
        macroTmpM = macroTmpQ1 * macroTmpD0;                                      \
        macroTmpR1 = (macroTmpR1 << (BN_UINT_BITS >> 1)) | BN_UINT_HI(nl);  \
        if (macroTmpR1 < macroTmpM) {                                       \
            macroTmpQ1--, macroTmpR1 += (d);                                \
            if (macroTmpR1 >= (d)) {                                  \
                if (macroTmpR1 < macroTmpM) {                               \
                    macroTmpQ1--;                                     \
                    macroTmpR1 += (d);                                \
                }                                               \
            }                                                   \
        }                                                       \
        macroTmpR1 -= macroTmpM;                                            \
                                                                \
        macroTmpQ0 = macroTmpR1 / macroTmpD1;                                     \
        macroTmpR0 = macroTmpR1 - macroTmpQ0 * macroTmpD1;                              \
        macroTmpM = macroTmpQ0 * macroTmpD0;                                      \
        macroTmpR0 = (macroTmpR0 << (BN_UINT_BITS >> 1)) | BN_UINT_LO(nl);  \
        if (macroTmpR0 < macroTmpM) {                                       \
            macroTmpQ0--, macroTmpR0 += (d);                                \
            if (macroTmpR0 >= (d)) {                                  \
                if (macroTmpR0 < macroTmpM) {                               \
                    macroTmpQ0--;                                     \
                    macroTmpR0 += (d);                                \
                }                                               \
            }                                                   \
        }                                                       \
        macroTmpR0 -= macroTmpM;                                            \
                                                                \
        (q) = (macroTmpQ1 << (BN_UINT_BITS >> 1)) | macroTmpQ0;             \
        (r) = macroTmpR0;                                             \
    } while (0)

// (hi, lo) = a * b
// r += lo + carry
// carry = hi + c
#define MULADC_AB(r, a, b, carry)              \
    do {                                       \
        BN_UINT hi, lo;                        \
        __asm("mul %0, %2, %3 \n\t"            \
              "umulh %1, %2, %3 \n\t"          \
              : "=&r"(lo), "=&r"(hi)             \
              : "r"(a), "r"(b)                 \
              : "cc");                         \
        __asm("adds %1, %1, %3 \n\t"           \
              "adc %2, %2, xzr \n\t "          \
              "adds %0, %0, %1 \n\t"           \
              "adc %2, %2, xzr \n\t "          \
              "mov %1, %2 \n\t"                \
              : "+&r"(r), "+&r"(carry), "+&r"(hi) \
              : "r"(lo)                        \
              : "cc");                         \
    } while (0)

/* h|m|l = h|m|l + u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULADD_AB(h, m, l, u, v)          \
    do {                                  \
        BN_UINT hi, lo;                   \
        __asm("mul %0, %2, %3 \n\t"       \
              "umulh %1, %2, %3 \n\t"     \
              : "=&r"(lo), "=&r"(hi)        \
              : "r"(u), "r"(v)            \
              : "cc");                    \
        __asm("adds %0, %0, %3 \n\t "     \
              "adcs %1, %1, %4 \n\t "     \
              "adc %2, %2, xzr \n\t "     \
              : "+&r"(l), "+&r"(m), "+&r"(h) \
              : "r"(lo), "r"(hi)          \
              : "cc");                    \
    } while (0)

/* h|m|l = h|m|l + 2 * u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULADD_AB2(h, m, l, u, v)         \
    do {                                  \
        BN_UINT hi, lo;                   \
        __asm("mul %0, %2, %3 \n\t"       \
              "umulh %1, %2, %3 \n\t"     \
              : "=&r"(lo), "=&r"(hi)        \
              : "r"(u), "r"(v)            \
              : "cc");                    \
        __asm("adds %0, %0, %3 \n\t "     \
              "adcs %1, %1, %4 \n\t "     \
              "adc %2, %2, xzr \n\t "     \
              "adds %0, %0, %3 \n\t "     \
              "adcs %1, %1, %4 \n\t "     \
              "adc %2, %2, xzr \n\t "     \
              : "+&r"(l), "+&r"(m), "+&r"(h) \
              : "r"(lo), "r"(hi)          \
              : "cc");                    \
    } while (0)

/* h|m|l = h|m|l + u * u. Ensure that the value of h is not too large to avoid carry. */
#define SQRADD_A(h, m, l, u)   MULADD_AB(h, m, l, u, u)

// Modular operation, satisfy d < (1 << BN_UINT_HALF_BITS) r = nh | nl % d
#define MOD_HALF(r, nh, nl, d)                                  \
    do {                                                        \
        BN_UINT macroTmpD = (d);                                      \
        (r) = (nh) % macroTmpD;                                       \
        (r) = ((r) << BN_UINT_HALF_BITS) | BN_UINT_HI((nl));  \
        (r) = (r) % macroTmpD;                                        \
        (r) = ((r) << BN_UINT_HALF_BITS) | BN_UINT_LO((nl));  \
        (r) = (r) % macroTmpD;                                        \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_BN */

#endif