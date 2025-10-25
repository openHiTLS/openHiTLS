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

// Fast GF(2^13) with log/antilog tables (correct, table-based)
#include <assert.h>
#include "mceliece_gf.h"
#include "securec.h"

static GFElement gfLog[MCELIECE_Q];
static GFElement gfAntilog[MCELIECE_Q];

static inline int WrapExp(int e)
{
    int m = (int)MCELIECE_Q - 1;
    e %= m;
    return (e < 0) ? (e + m) : e;
}

// Bitwise multiply (for table initialization only)
static GFElement GFMulForInit(GFElement a, GFElement b, int m)
{
    unsigned int aq = a & MCELIECE_Q_1;
    unsigned int bq = b & MCELIECE_Q_1;
    unsigned int acc = 0;
    while (bq) {
        if (bq & 1u) {
            acc ^= aq;
        }
        bq >>= 1;
        aq <<= 1;
        if (aq & (1u << m)) {
            aq ^= MCELIECE_GF_POLY;
        }
    }
    return (GFElement)(acc & MCELIECE_Q_1);
}

void GFInitial(const int m)
{
    memset_s(gfLog, (size_t)MCELIECE_Q * sizeof(GFElement), 0, (size_t)MCELIECE_Q * sizeof(GFElement));
    memset_s(gfAntilog, (size_t)MCELIECE_Q * sizeof(GFElement), 0, (size_t)MCELIECE_Q * sizeof(GFElement));

    assert(m == 13 && MCELIECE_Q == 8192);
    const GFElement generator = 3;  // primitive element used to generate the field
    GFElement p = 1;

    for (int i = 0; i < (int)MCELIECE_Q - 1; i++) {
        gfAntilog[i] = p;
        gfLog[p] = (GFElement)i;
        p = GFMulForInit(p, generator, m);
        if (i > 0 && p == 1) {
            break;  // completed cycle
        }
    }
    // Optional mirror so index (Q-1) maps cleanly to 1; indices are wrapped anyway
    gfAntilog[MCELIECE_Q - 1] = 1;
    gfLog[0] = 0;  // never used; keep defined
}

GFElement GFAddtion(GFElement a, GFElement b)
{
    return (GFElement)(a ^ b);
}

GFElement GFMultiplication(GFElement a, GFElement b)
{
    if ((a & MCELIECE_Q_1) == 0 || (b & MCELIECE_Q_1) == 0) {
        return 0;
    }
    int la = gfLog[a & MCELIECE_Q_1];
    int lb = gfLog[b & MCELIECE_Q_1];
    int idx = WrapExp(la + lb);
    return gfAntilog[idx];
}

GFElement GFInverse(GFElement a)
{
    a &= MCELIECE_Q_1;
    if (a == 0) {
        return 0;
    }
    if (a == 1) {
        return 1;
    }
    int la = gfLog[a];
    int idx = WrapExp(((int)MCELIECE_Q - 1) - la);
    return gfAntilog[idx];
}

GFElement GFDivision(GFElement a, GFElement b)
{
    a &= MCELIECE_Q_1;
    b &= MCELIECE_Q_1;
    if (b == 0) {
        return 0;
    }
    if (a == 0) {
        return 0;
    }
    int la = gfLog[a];
    int lb = gfLog[b];
    int idx = WrapExp(la - lb);
    return gfAntilog[idx];
}

GFElement GFPower(GFElement base, int exp)
{
    if (exp == 0) {
        return 1;
    }
    if ((base & MCELIECE_Q_1) == 0) {
        return 0;
    }
    GFElement result = 1;
    base &= MCELIECE_Q_1;
    while (exp > 0) {
        if (exp & 1) {
            result = GFMultiplication(result, base);
        }
        base = GFMultiplication(base, base);
        exp >>= 1;
    }
    return result;
}
