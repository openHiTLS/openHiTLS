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
#ifndef BN_BINCAL_NOASM_H
#define BN_BINCAL_NOASM_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_BN

#include <stdint.h>
#include "bn_basic.h"

#ifdef __cplusplus
extern "c" {
#endif

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

#define MUL_AB(wh, wl, u, v)                                \
    do {                                                    \
        BN_UINT macroTmpUl = BN_UINT_LO(u);                       \
        BN_UINT macroTmpUh = BN_UINT_HI(u);                       \
        BN_UINT macroTmpVl = BN_UINT_LO(v);                       \
        BN_UINT macroTmpVh = BN_UINT_HI(v);                       \
                                                            \
        BN_UINT macroTmpX0 = macroTmpUl * macroTmpVl;            \
        BN_UINT macroTmpX1 = macroTmpUl * macroTmpVh;            \
        BN_UINT macroTmpX2 = macroTmpUh * macroTmpVl;            \
        BN_UINT macroTmpX3 = macroTmpUh * macroTmpVh;            \
                                                              \
        macroTmpX1 += BN_UINT_HI(macroTmpX0);                             \
        macroTmpX1 += macroTmpX2;                                         \
        if (macroTmpX1 < macroTmpX2) { macroTmpX3 += BN_UINT_HC; }              \
                                                              \
        (wh) = macroTmpX3 + BN_UINT_HI(macroTmpX1);                       \
        (wl) = (macroTmpX1 << (BN_UINT_BITS >> 1)) | BN_UINT_LO(macroTmpX0); \
    } while (0)

#define SQR_A(wh, wl, u)                       \
    do {                                       \
        BN_UINT macroTmpUl = BN_UINT_LO(u);          \
        BN_UINT macroTmpUh = BN_UINT_HI(u);          \
                                               \
        BN_UINT macroTmpX0 = macroTmpUl * macroTmpUl;            \
        BN_UINT macroTmpX1 = macroTmpUl * macroTmpUh;            \
        BN_UINT macroTmpX2 = macroTmpUh * macroTmpUh;            \
                                               \
        BN_UINT macroTmpT = macroTmpX1 << 1;               \
        macroTmpT += BN_UINT_HI(macroTmpX0);                                \
        if (macroTmpT < macroTmpX1) { macroTmpX2 += BN_UINT_HC; }                 \
                                                                \
        (wh) = macroTmpX2 + BN_UINT_HI(macroTmpT);                          \
        (wl) = (macroTmpT << (BN_UINT_BITS >> 1)) | BN_UINT_LO(macroTmpX0); \
    } while (0)

/* r = a + b + c, input 'carry' means carry. Note that a and carry cannot be the same variable. */
#define ADD_ABC(carry, r, a, b, c)      \
    do {                                \
        BN_UINT macroTmpS = (b) + (c);        \
        carry = (macroTmpS < (c)) ? 1 : 0;    \
        (r) = macroTmpS + (a);                \
        carry += ((r) < macroTmpS) ? 1 : 0;   \
    } while (0)

// (hi, lo) = a * b
// r += lo + carry
// carry = hi + c
#define MULADC_AB(r, a, b, carry)              \
    do {                                       \
        BN_UINT hi, lo;                        \
        MUL_AB(hi, lo, a, b);                  \
        ADD_ABC(carry, r, r, lo, carry);       \
        carry += hi;                           \
    } while (0)

/* h|m|l = h|m|l + u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULADD_AB(h, m, l, u, v)                            \
    do {                                                    \
        BN_UINT macroTmpUl = BN_UINT_LO(u);                       \
        BN_UINT macroTmpUh = BN_UINT_HI(u);                       \
        BN_UINT macroTmpVl = BN_UINT_LO(v);                       \
        BN_UINT macroTmpVh = BN_UINT_HI(v);                       \
                                                            \
        BN_UINT macroTmpX3 = macroTmpUh * macroTmpVh;            \
        BN_UINT macroTmpX2 = macroTmpUh * macroTmpVl;            \
        BN_UINT macroTmpX1 = macroTmpUl * macroTmpVh;            \
        BN_UINT macroTmpX0 = macroTmpUl * macroTmpVl;            \
        macroTmpX1 += BN_UINT_HI(macroTmpX0);              \
        macroTmpX0 = (u) * (v); \
        macroTmpX1 += macroTmpX2;                          \
        macroTmpX3 = macroTmpX3 + BN_UINT_HI(macroTmpX1); \
            \
        (l) += macroTmpX0; \
        \
        if (macroTmpX1 < macroTmpX2) { macroTmpX3 += BN_UINT_HC; }    \
        macroTmpX3 += ((l) < macroTmpX0); \
        (m) += macroTmpX3; \
        (h) += ((m) < macroTmpX3);  \
    } while (0)

/* h|m|l = h|m|l + 2 * u * v. Ensure that the value of h is not too large to avoid carry. */
#define MULADD_AB2(h, m, l, u, v)                            \
    do {                                     \
        MULADD_AB((h), (m), (l), (u), (v));   \
        MULADD_AB((h), (m), (l), (u), (v));   \
    } while (0)

/* h|m|l = h|m|l + v * v. Ensure that the value of h is not too large to avoid carry. */
#define SQRADD_A(h, m, l, v)  \
do { \
    BN_UINT macroTmpVl = BN_UINT_LO(v);                       \
    BN_UINT macroTmpVh = BN_UINT_HI(v);                       \
                                                        \
    BN_UINT macroTmpX3 = macroTmpVh * macroTmpVh;            \
    BN_UINT macroTmpX2 = macroTmpVh * macroTmpVl;            \
    BN_UINT macroTmpX1 = macroTmpX2;            \
    BN_UINT macroTmpX0 = macroTmpVl * macroTmpVl;            \
    macroTmpX1 += BN_UINT_HI(macroTmpX0);              \
    macroTmpX0 = (v) * (v); \
    macroTmpX1 += macroTmpX2;                          \
    macroTmpX3 = macroTmpX3 + BN_UINT_HI(macroTmpX1); \
        \
    (l) += macroTmpX0; \
    \
    if (macroTmpX1 < macroTmpX2) { macroTmpX3 += BN_UINT_HC; }              \
    if ((l) < macroTmpX0) { macroTmpX3 += 1; } \
    (m) += macroTmpX3; \
    if ((m) < macroTmpX3) { (h)++; } \
} while (0)

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