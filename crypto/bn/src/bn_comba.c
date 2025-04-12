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
#if defined(HITLS_CRYPTO_BN) && defined(HITLS_CRYPTO_BN_COMBA)

#include <stdint.h>
#include "bn_bincal.h"

#define SQR_COMBA_BEGIN_1(r, a, h, m, l) do {                   \
    SQRADD_A((h), (m), (l), (a)[0]);                            \
    (r)[0] = (l);                                               \
    (l) = 0;                                                    \
    MULADD_AB2((l), (h), (m), (a)[0], (a)[1]);                  \
    (r)[1] = (m);                                               \
    (m) = 0;                                                    \
    MULADD_AB2((m), (l), (h), (a)[0], (a)[2]);  /* 0 + 2 = 2 */ \
    SQRADD_A((m), (l), (h), (a)[1]);            /* 1 + 1 = 2 */ \
    (r)[2] = (h);                               /* 2 */         \
    (h) = 0;                                                    \
    MULADD_AB2((h), (m), (l), (a)[1], (a)[2]);  /* 1 + 2 = 3 */ \
    MULADD_AB2((h), (m), (l), (a)[0], (a)[3]);  /* 0 + 3 = 3 */ \
    (r)[3] = (l);                               /* 3 */         \
    (l) = 0;                                                    \
} while (0)

#define SQR_COMBA_BEGIN_2(r, a, h, m, l) do {                   \
    MULADD_AB2((l), (h), (m), (a)[0], (a)[4]);  /* 0 + 4 = 4 */ \
    MULADD_AB2((l), (h), (m), (a)[1], (a)[3]);  /* 1 + 3 = 4 */ \
    SQRADD_A((l), (h), (m), (a)[2]);            /* 2 + 2 = 4 */ \
    (r)[4] = (m);                               /* 4 */         \
    (m) = 0;                                                    \
    MULADD_AB2((m), (l), (h), (a)[2], (a)[3]);  /* 2 + 3 = 5 */ \
    MULADD_AB2((m), (l), (h), (a)[1], (a)[4]);  /* 1 + 4 = 5 */ \
    MULADD_AB2((m), (l), (h), (a)[0], (a)[5]);  /* 0 + 5 = 5 */ \
    (r)[5] = (h);                               /* 5 */         \
    (h) = 0;                                                    \
} while (0)

#define MUL_COMBA_BEGIN_1(r, a, b, h, m, l) do {                \
    MULADD_AB((h), (m), (l), (a)[0], (b)[0]);                   \
    (r)[0] = (l);                                               \
    (l) = 0;                                                    \
    MULADD_AB((l), (h), (m), (a)[0], (b)[1]);                   \
    MULADD_AB((l), (h), (m), (a)[1], (b)[0]);                   \
    (r)[1] = (m);                                               \
    (m) = 0;                                                    \
    MULADD_AB((m), (l), (h), (a)[2], (b)[0]);   /* 2 + 0 = 2 */ \
    MULADD_AB((m), (l), (h), (a)[1], (b)[1]);   /* 1 + 1 = 2 */ \
    MULADD_AB((m), (l), (h), (a)[0], (b)[2]);   /* 0 + 2 = 2 */ \
    (r)[2] = (h);                                               \
    (h) = 0;                                                    \
    MULADD_AB((h), (m), (l), (a)[0], (b)[3]);   /* 0 + 3 = 3 */ \
    MULADD_AB((h), (m), (l), (a)[1], (b)[2]);   /* 1 + 2 = 3 */ \
    MULADD_AB((h), (m), (l), (a)[2], (b)[1]);   /* 2 + 1 = 3 */ \
    MULADD_AB((h), (m), (l), (a)[3], (b)[0]);   /* 3 + 9 = 3 */ \
    (r)[3] = (l);                               /* 3 */         \
    (l) = 0;                                                    \
} while (0)

#define MUL_COMBA_BEGIN_2(r, a, b, h, m, l) do {                \
    MULADD_AB((l), (h), (m), (a)[4], (b)[0]);   /* 4 + 0 = 4 */ \
    MULADD_AB((l), (h), (m), (a)[3], (b)[1]);   /* 3 + 1 = 4 */ \
    MULADD_AB((l), (h), (m), (a)[2], (b)[2]);   /* 2 + 2 = 4 */ \
    MULADD_AB((l), (h), (m), (a)[1], (b)[3]);   /* 1 + 3 = 4 */ \
    MULADD_AB((l), (h), (m), (a)[0], (b)[4]);   /* 0 + 4 = 4 */ \
    (r)[4] = (m);                               /* 4 */         \
    (m) = 0;                                                    \
    MULADD_AB((m), (l), (h), (a)[0], (b)[5]);   /* 0 + 5 = 5 */ \
    MULADD_AB((m), (l), (h), (a)[1], (b)[4]);   /* 1 + 4 = 5 */ \
    MULADD_AB((m), (l), (h), (a)[2], (b)[3]);   /* 2 + 3 = 5 */ \
    MULADD_AB((m), (l), (h), (a)[3], (b)[2]);   /* 3 + 2 = 5 */ \
    MULADD_AB((m), (l), (h), (a)[4], (b)[1]);   /* 4 + 1 = 5 */ \
    MULADD_AB((m), (l), (h), (a)[5], (b)[0]);   /* 5 + 0 = 5 */ \
    (r)[5] = (h);                               /* 5 */         \
    (h) = 0;                                                    \
} while (0)

#define MUL_COMBA_BEGIN_3(r, a, b, h, m, l) do {                \
    MULADD_AB((h), (m), (l), (a)[6], (b)[0]);   /* 6 + 0 = 6 */ \
    MULADD_AB((h), (m), (l), (a)[5], (b)[1]);   /* 5 + 1 = 6 */ \
    MULADD_AB((h), (m), (l), (a)[4], (b)[2]);   /* 4 + 2 = 6 */ \
    MULADD_AB((h), (m), (l), (a)[3], (b)[3]);   /* 3 + 3 = 6 */ \
    MULADD_AB((h), (m), (l), (a)[2], (b)[4]);   /* 2 + 4 = 6 */ \
    MULADD_AB((h), (m), (l), (a)[1], (b)[5]);   /* 1 + 5 = 6 */ \
    MULADD_AB((h), (m), (l), (a)[0], (b)[6]);   /* 0 + 6 = 6 */ \
    (r)[6] = (l);                               /* 6 */         \
    (l) = 0;                                                    \
    MULADD_AB((l), (h), (m), (a)[0], (b)[7]);   /* 0 + 7 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[1], (b)[6]);   /* 1 + 6 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[2], (b)[5]);   /* 2 + 5 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[3], (b)[4]);   /* 3 + 4 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[4], (b)[3]);   /* 4 + 3 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[5], (b)[2]);   /* 5 + 2 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[6], (b)[1]);   /* 6 + 1 = 7 */ \
    MULADD_AB((l), (h), (m), (a)[7], (b)[0]);   /* 7 + 0 = 7 */ \
    (r)[7] = (m);                               /* 7 */         \
    (m) = 0;                                                    \
    MULADD_AB((m), (l), (h), (a)[7], (b)[1]);   /* 7 + 1 = 8 */ \
    MULADD_AB((m), (l), (h), (a)[6], (b)[2]);   /* 6 + 2 = 8 */ \
    MULADD_AB((m), (l), (h), (a)[5], (b)[3]);   /* 5 + 3 = 8 */ \
    MULADD_AB((m), (l), (h), (a)[4], (b)[4]);   /* 4 + 4 = 8 */ \
    MULADD_AB((m), (l), (h), (a)[3], (b)[5]);   /* 3 + 5 = 8 */ \
    MULADD_AB((m), (l), (h), (a)[2], (b)[6]);   /* 2 + 6 = 8 */ \
    MULADD_AB((m), (l), (h), (a)[1], (b)[7]);   /* 1 + 7 = 8 */ \
    (r)[8] = (h);                               /* 8 */         \
    (h) = 0;                                                    \
} while (0)

static void SqrComba8(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;

    SQR_COMBA_BEGIN_1(r, a, h, m, l);
    SQR_COMBA_BEGIN_2(r, a, h, m, l);

    MULADD_AB2(h, m, l, a[0], a[6]);    /* 0 + 6 = 6 */
    MULADD_AB2(h, m, l, a[1], a[5]);    /* 1 + 5 = 6 */
    MULADD_AB2(h, m, l, a[2], a[4]);    /* 2 + 4 = 6 */
    SQRADD_A(h, m, l, a[3]);            /* 3 + 3 = 6 */
    r[6] = l;                           /* 6 */
    l = 0;

    MULADD_AB2(l, h, m, a[3], a[4]);    /* 3 + 4 = 7 */
    MULADD_AB2(l, h, m, a[2], a[5]);    /* 2 + 5 = 7 */
    MULADD_AB2(l, h, m, a[1], a[6]);    /* 1 + 6 = 7 */
    MULADD_AB2(l, h, m, a[0], a[7]);    /* 0 + 7 = 7 */
    r[7] = m;                           /* 7 */
    m = 0;

    MULADD_AB2(m, l, h, a[1], a[7]);    /* 1 + 7 = 8 */
    MULADD_AB2(m, l, h, a[2], a[6]);    /* 2 + 6 = 8 */
    MULADD_AB2(m, l, h, a[3], a[5]);    /* 3 + 5 = 8 */
    SQRADD_A(m, l, h, a[4]);            /* 4 + 4 = 8 */
    r[8] = h;                           /* 8 */
    h = 0;

    MULADD_AB2(h, m, l, a[4], a[5]);    /* 4 + 5 = 9 */
    MULADD_AB2(h, m, l, a[3], a[6]);    /* 3 + 6 = 9 */
    MULADD_AB2(h, m, l, a[2], a[7]);    /* 2 + 7 = 9 */
    r[9] = l;                           /* 9 */
    l = 0;

    MULADD_AB2(l, h, m, a[3], a[7]);    /* 3 + 7 = 10 */
    MULADD_AB2(l, h, m, a[4], a[6]);    /* 4 + 6 = 10 */
    SQRADD_A(l, h, m, a[5]);            /* 5 + 5 = 10 */
    r[10] = m;                          /* 10 */
    m = 0;

    MULADD_AB2(m, l, h, a[5], a[6]);    /* 5 + 6 = 11 */
    MULADD_AB2(m, l, h, a[4], a[7]);    /* 4 + 7 = 11 */
    r[11] = h;                          /* 11 */
    h = 0;

    MULADD_AB2(h, m, l, a[5], a[7]);    /* 5 + 7 = 12 */
    SQRADD_A(h, m, l, a[6]);            /* 6 + 6 = 12 */
    r[12] = l;                          /* 12 */
    l = 0;

    MULADD_AB2(l, h, m, a[6], a[7]);    /* 6 + 7 = 13 */
    r[13] = m;                          /* 13 */
    m = 0;

    SQRADD_A(m, l, h, a[7]);            /* 7 + 7 = 14 */
    r[14] = h;                          /* 14 */
    r[15] = l;                          /* 15 */
}

void SqrComba6(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;

    SQR_COMBA_BEGIN_1(r, a, h, m, l);
    SQR_COMBA_BEGIN_2(r, a, h, m, l);

    MULADD_AB2(h, m, l, a[1], a[5]);    /* 1 + 5 = 6 */
    MULADD_AB2(h, m, l, a[2], a[4]);    /* 2 + 4 = 6 */
    SQRADD_A(h, m, l, a[3]);            /* 3 + 3 = 6 */
    r[6] = l;                           /* 6 */
    l = 0;

    MULADD_AB2(l, h, m, a[3], a[4]);    /* 3 + 4 = 7 */
    MULADD_AB2(l, h, m, a[2], a[5]);    /* 2 + 5 = 7 */
    r[7] = m;                           /* 7 */
    m = 0;

    MULADD_AB2(m, l, h, a[3], a[5]);    /* 3 + 5 = 8 */
    SQRADD_A(m, l, h, a[4]);            /* 4 + 4 = 8 */
    r[8] = h;                           /* 8 */
    h = 0;

    MULADD_AB2(h, m, l, a[4], a[5]);    /* 4 + 5 = 9 */
    r[9] = l;                           /* 9 */
    l = 0;

    SQRADD_A(l, h, m, a[5]);            /* 5 + 5 = 10 */
    r[10] = m;                          /* 10 */
    r[11] = h;                          /* 11 */
}

void SqrComba4(BN_UINT *r, const BN_UINT *a)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;

    SQR_COMBA_BEGIN_1(r, a, h, m, l);

    MULADD_AB2(l, h, m, a[1], a[3]);    /* 1 + 3 = 4 */
    SQRADD_A(l, h, m, a[2]);            /* 2 + 2 = 4 */
    r[4] = m;                           /* 4 */
    m = 0;

    MULADD_AB2(m, l, h, a[2], a[3]);    /* 2 + 3 = 5 */
    r[5] = h;                           /* 5 */
    h = 0;

    SQRADD_A(h, m, l, a[3]);            /* 3 + 3 = 6 */
    r[6] = l;                           /* 6 */
    r[7] = m;                           /* 7 */
}

static void SqrComba(BN_UINT *r, const BN_UINT *a, uint32_t size)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;
    if (size == 3) {                        /* 3 */
        SQRADD_A(h, m, l, a[0]);
        r[0] = l;
        l = 0;

        MULADD_AB2(l, h, m, a[0], a[1]);
        r[1] = m;
        m = 0;

        MULADD_AB2(m, l, h, a[0], a[2]);    /* 0 + 2 = 2 */
        SQRADD_A(m, l, h, a[1]);            /* 1 + 1 = 2 */
        r[2] = h;                           /* 2 */
        h = 0;

        MULADD_AB2(h, m, l, a[1], a[2]);    /* 1 + 2 = 3 */
        r[3] = l;                           /* 3 */
        l = 0;

        SQRADD_A(l, h, m, a[2]);            /* 2 + 2 = 4 */
        r[4] = m;                           /* 4 */
        r[5] = h;                           /* 5 */
        return;
    }
    if (size == 2) {                        /* 2 */
        SQRADD_A(h, m, l, a[0]);
        r[0] = l;
        l = 0;

        MULADD_AB2(l, h, m, a[0], a[1]);
        r[1] = m;
        m = 0;
    
        SQRADD_A(m, l, h, a[1]);            /* 1 + 1 = 2 */
        r[2] = h;                           /* 2 */
        r[3] = l;                           /* 3 */
        return;
    }
    SQR_A(r[1], r[0], a[0]);                /* size == 1 */
}

void MulComba8(BN_UINT *r, const BN_UINT *a, const BN_UINT *b)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;

    MUL_COMBA_BEGIN_1(r, a, b, h, m, l);
    MUL_COMBA_BEGIN_2(r, a, b, h, m, l);
    MUL_COMBA_BEGIN_3(r, a, b, h, m, l);

    MULADD_AB(h, m, l, a[2], b[7]);     /* 2 + 7 = 9 */
    MULADD_AB(h, m, l, a[3], b[6]);     /* 3 + 6 = 9 */
    MULADD_AB(h, m, l, a[4], b[5]);     /* 4 + 5 = 9 */
    MULADD_AB(h, m, l, a[5], b[4]);     /* 5 + 4 = 9 */
    MULADD_AB(h, m, l, a[6], b[3]);     /* 6 + 3 = 9 */
    MULADD_AB(h, m, l, a[7], b[2]);     /* 7 + 2 = 9 */
    r[9] = l;                           /* 9 */
    l = 0;

    MULADD_AB(l, h, m, a[7], b[3]);     /* 7 + 3 = 10 */
    MULADD_AB(l, h, m, a[6], b[4]);     /* 6 + 4 = 10 */
    MULADD_AB(l, h, m, a[5], b[5]);     /* 5 + 5 = 10 */
    MULADD_AB(l, h, m, a[4], b[6]);     /* 4 + 6 = 10 */
    MULADD_AB(l, h, m, a[3], b[7]);     /* 3 + 7 = 10 */
    r[10] = m;                          /* 10 */
    m = 0;

    MULADD_AB(m, l, h, a[4], b[7]);     /* 4 + 7 = 11 */
    MULADD_AB(m, l, h, a[5], b[6]);     /* 5 + 6 = 11 */
    MULADD_AB(m, l, h, a[6], b[5]);     /* 6 + 5 = 11 */
    MULADD_AB(m, l, h, a[7], b[4]);     /* 7 + 4 = 11 */
    r[11] = h;                          /* 11 */
    h = 0;

    MULADD_AB(h, m, l, a[7], b[5]);     /* 7 + 5 = 12 */
    MULADD_AB(h, m, l, a[6], b[6]);     /* 6 + 6 = 12 */
    MULADD_AB(h, m, l, a[5], b[7]);     /* 5 + 7 = 12 */
    r[12] = l;                          /* 12 */
    l = 0;

    MULADD_AB(l, h, m, a[6], b[7]);     /* 6 + 7 = 13 */
    MULADD_AB(l, h, m, a[7], b[6]);     /* 7 + 6 = 13 */
    r[13] = m;                          /* 13 */
    m = 0;

    MULADD_AB(m, l, h, a[7], b[7]);     /* 7 + 7 = 14 */
    r[14] = h;                          /* 14 */
    r[15] = l;                          /* 15 */
}

void MulComba6(BN_UINT *r, const BN_UINT *a, const BN_UINT *b)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;

    MUL_COMBA_BEGIN_1(r, a, b, h, m, l);
    MUL_COMBA_BEGIN_2(r, a, b, h, m, l);

    MULADD_AB(h, m, l, a[5], b[1]);     /* 5 + 1 = 6 */
    MULADD_AB(h, m, l, a[4], b[2]);     /* 4 + 2 = 6 */
    MULADD_AB(h, m, l, a[3], b[3]);     /* 3 + 3 = 6 */
    MULADD_AB(h, m, l, a[2], b[4]);     /* 2 + 4 = 6 */
    MULADD_AB(h, m, l, a[1], b[5]);     /* 1 + 5 = 6 */
    r[6] = l;                           /* 6 */
    l = 0;

    MULADD_AB(l, h, m, a[2], b[5]);     /* 2 + 5 = 7 */
    MULADD_AB(l, h, m, a[3], b[4]);     /* 3 + 4 = 7 */
    MULADD_AB(l, h, m, a[4], b[3]);     /* 4 + 3 = 7 */
    MULADD_AB(l, h, m, a[5], b[2]);     /* 5 + 2 = 7 */
    r[7] = m;                           /* 7 */
    m = 0;

    MULADD_AB(m, l, h, a[5], b[3]);     /* 5 + 3 = 8 */
    MULADD_AB(m, l, h, a[4], b[4]);     /* 4 + 4 = 8 */
    MULADD_AB(m, l, h, a[3], b[5]);     /* 3 + 5 = 8 */
    r[8] = h;                           /* 8 */
    h = 0;

    MULADD_AB(h, m, l, a[4], b[5]);     /* 4 + 5 = 9 */
    MULADD_AB(h, m, l, a[5], b[4]);     /* 5 + 4 = 9 */
    r[9] = l;                           /* 9 */
    l = 0;

    MULADD_AB(l, h, m, a[5], b[5]);     /* 5 + 5 = 10 */
    r[10] = m;                          /* 10 */
    r[11] = h;                          /* 11 */
}

void MulComba4(BN_UINT *r, const BN_UINT *a, const BN_UINT *b)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;

    MUL_COMBA_BEGIN_1(r, a, b, h, m, l);

    MULADD_AB(l, h, m, a[3], b[1]);    /* 3 + 1 = 4 */
    MULADD_AB(l, h, m, a[2], b[2]);    /* 2 + 2 = 4 */
    MULADD_AB(l, h, m, a[1], b[3]);    /* 1 + 3 = 4 */
    r[4] = m;                          /* 4 */
    m = 0;

    MULADD_AB(m, l, h, a[2], b[3]);    /* 2 + 3 = 5 */
    MULADD_AB(m, l, h, a[3], b[2]);    /* 3 + 2 = 5 */
    r[5] = h;                          /* 5 */
    h = 0;

    MULADD_AB(h, m, l, a[3], b[3]);    /* 3 + 3 = 6 */
    r[6] = l;                          /* 6 */
    r[7] = m;                          /* 7 */
}

static void MulComba(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t size)
{
    BN_UINT h = 0;
    BN_UINT m = 0;
    BN_UINT l = 0;
    if (size == 3) {                        /* 3 */
        MULADD_AB(h, m, l, a[0], b[0]);
        r[0] = l;
        l = 0;

        MULADD_AB(l, h, m, a[0], b[1]);
        MULADD_AB(l, h, m, a[1], b[0]);
        r[1] = m;
        m = 0;

        MULADD_AB(m, l, h, a[2], b[0]);     /* 2 + 0 = 2 */
        MULADD_AB(m, l, h, a[1], b[1]);     /* 1 + 1 = 2 */
        MULADD_AB(m, l, h, a[0], b[2]);     /* 0 + 2 = 2 */
        r[2] = h;
        h = 0;

        MULADD_AB(h, m, l, a[1], b[2]);     /* 1 + 2 = 3 */
        MULADD_AB(h, m, l, a[2], b[1]);     /* 2 + 1 = 3 */
        r[3] = l;                           /* 3 */
        l = 0;

        MULADD_AB(l, h, m, a[2], b[2]);     /* 2 + 2 = 4 */
        r[4] = m;                           /* 4 */
        r[5] = h;                           /* 5 */
        return;
    }
    if (size == 2) {                        /* 2 */
        MULADD_AB(h, m, l, a[0], b[0]);
        r[0] = l;
        l = 0;

        MULADD_AB(l, h, m, a[0], b[1]);
        MULADD_AB(l, h, m, a[1], b[0]);
        r[1] = m;
        m = 0;

        MULADD_AB(m, l, h, a[1], b[1]);
        r[2] = h;                           /* 2 */
        r[3] = l;                           /* 3 */
        return;
    }
    MUL_AB(r[1], r[0], a[0], b[0]);         /* size == 1 */
}

uint32_t SpaceSize(uint32_t size)
{
    uint32_t base = 8; /* Perform 8x batch processing */
    while (size > base) {
        base <<= 1;
    }
    return base * 4; /* 2x expansion. Each layer requires 2 * size temporary space, 2 * 2 = 4 */
}

/* compare BN array.
 * return 0, if a == b
 * return 1, if a > b
 * return -1, if a < b
 */
static int32_t BinCmpSame(const BN_UINT *a, const BN_UINT *b, uint32_t size)
{
    int64_t idx = (int64_t)size;
    while (--idx >= 0) {
        if (a[idx] != b[idx]) {
            return a[idx] > b[idx] ? 1 : -1;
        }
    }
    return 0;
}

/* The caller promised that aSize >= bSize.
 * r = ABS(a - b). Need to ensure that aSize == bSize + (0 || 1).
 * return 0 if a > b
 * return 1 if a <= b
 */
static uint32_t ABS_Sub(BN_UINT *t, const BN_UINT *a, uint32_t aSize, const BN_UINT *b, uint32_t bSize)
{
    int32_t ret;
    do {
        if (aSize > bSize) {
            t[bSize] = a[bSize]; /* bSize = aSize - 1 */
            if (a[bSize] > 0) {
                ret = 1;
                break;
            }
        }
        ret = BinCmpSame(a, b, bSize);
    } while (0);
    if (ret > 0) {
        BN_UINT borrow = BinSub(t, a, b, bSize);
        if (aSize > bSize) { /* When the length difference exists and a > b exists, the borrowing is processed. */
            t[bSize] -= borrow;
        }
        return 0;
    } else {
        BinSub(t, b, a, bSize);
        return 1;
    }
    return 0;
}

/** Only aSize == bSize is supported. This interface will recurse. The recursion depth is O(deep) = log2(size)
 *  Ensure that space >= SpaceSize(size)
 *  (ah|al * bh|bl) = (((ah*bh) << 2) + (((ah*bh) + (al*bl) - (ah - al)(bh - bl)) << 1) + (al*bl))
 */
void MulConquer(BN_UINT *r, const BN_UINT *a, const BN_UINT *b, uint32_t size, BN_UINT *space, bool consttime)
{
    if (!consttime) {
        if (size == 8) { /* Perform 8x batch processing */
            MulComba8(r, a, b);
            return;
        }
        if (size == 6) { /* Perform 6x batch processing */
            MulComba6(r, a, b);
            return;
        }
        if (size == 4) { /* Perform 4x batch processing */
            MulComba4(r, a, b);
            return;
        }
        if (size < 4) { /* Less than 4, simple processing */
            MulComba(r, a, b, size);
            return;
        }
    } else if (size <= 8) { /* Calculate if the block size is smaller than 8. */
        BinMul(r, size << 1, a, size, b, size);
        return;
    }

    /* truncates the length of the low bits of the BigNum, that is the length of al bl. */
    const uint32_t sizeLo = size >> 1;
    const uint32_t sizeLo2 = sizeLo << 1;
    const uint32_t shift1 = sizeLo;          /* (((ah*bh) + (al*bl) - (ah - al)(bh - bl)) << 1) location */
    const uint32_t shift2 = shift1 << 1;     /* ((ah*bh) << 2) location */
    /* truncates the length of the high bits of the BigNum, that is the length of ah bh. */
    const uint32_t sizeHi = size - sizeLo;
    const uint32_t sizeHi2 = sizeHi << 1;

    /* Split the input 'space'. The current function uses tmp1 and tmp2,
     * and the remaining newspace is used by the lower layer.
     * space = tmp1_lo..tmp1_hi | tmp2_lo..tmp2_hi | newSpace, sizeof(tmp1_lo) == sizeHi.
     */
    BN_UINT *tmp1 = space;
    BN_UINT *tmp2 = tmp1 + sizeHi2;
    BN_UINT *newSpace = tmp2 + sizeHi2;

    /* tmp2_lo = (ah-al) */
    uint32_t sign = ABS_Sub(tmp2, a + shift1, sizeHi, a, sizeLo);
    /* tmp2_hi = (bh-bl) */
    sign ^= ABS_Sub(tmp2 + sizeHi, b + shift1, sizeHi, b, sizeLo);

    MulConquer(r,          a,          b,             sizeLo, newSpace, consttime); /* calculate (al*bl) */
    MulConquer(r + shift2, a + shift1, b + shift1,    sizeHi, newSpace, consttime); /* calculate (ah*bh) */
    MulConquer(tmp1,       tmp2,       tmp2 + sizeHi, sizeHi, newSpace, consttime); /* calculate (ah-al)(bh-bl) */
    /* At this time r has stored ((ah*bh) << 2) and (al*bl) */
    /* carry should be added in (r + shift1)[sizeHi * 2] */
    /* tmp2 is (ah*bh) + (al*bl), but the processing length here is sizeLo * 2 */
    BN_UINT carry = BinAdd(tmp2, r, r + shift2, sizeLo2);
    if (sizeHi > sizeLo) {
        /* If there is a length difference, the length of (ah*bh) is sizeLo * 2 + 2,
           and the tail of (ah*bh) needs to be processed. */
        /* point to (r + shift2)[sizeLo * 2], the unprocessed tail of (ah*bh) */
        const uint32_t position = shift2 + (sizeLo2);
        tmp2[sizeLo2] = r[position] + carry;
        carry = (tmp2[sizeLo2] < carry) ? 1 : 0;
        /* continue the processing */
        tmp2[(sizeLo2) + 1] = r[position + 1] + carry;
        carry = (tmp2[sizeLo2 + 1] < carry) ? 1 : 0;
    }
    /* tmp1 = (ah*bh) + (al*bl) - (ah-al)(bh-bl), tmp2 is (ah*bh) + (al*bl) */
    if (sign == 1) {
        carry += BinAdd(tmp1, tmp2, tmp1, sizeHi2);
    } else {
        carry -= BinSub(tmp1, tmp2, tmp1, sizeHi2);
    }
    /* finally r adds tmp1, that is (ah*bh) + (al*bl) - (ah - al)(bh - bl) */
    carry += BinAdd(r + shift1, r + shift1, tmp1, sizeHi2);
    for (uint32_t i = shift1 + sizeHi2; carry > 0 && i < (size << 1); i++) {
        ADD_AB(carry, r[i], r[i], carry);
    }
}

/** This interface will recurse. The recursion depth is O(deep) = log2(size)
 *  Ensure that space >= SpaceSize(size)
 *  (x|y)^2 = ((x^2 << 2) + ((x^2 + y^2 - (x - y)^2)) << 1) + y^2)
 */
void SqrConquer(BN_UINT *r, const BN_UINT *a, uint32_t size, BN_UINT *space, bool consttime)
{
    if (!consttime) {
        if (size == 8) { /* Perform 8x batch processing */
            SqrComba8(r, a);
            return;
        }
        if (size == 6) { /* Perform 6x batch processing */
            SqrComba6(r, a);
            return;
        }
        if (size == 4) { /* Perform 4x batch processing */
            SqrComba4(r, a);
            return;
        }
        if (size < 4) { /* Less than 4, simple processing */
            SqrComba(r, a, size);
            return;
        }
    } else if (size <= 8) { /* Calculate if the block size is smaller than 8. */
        BinSqr(r, size << 1, a, size);
        return;
    }

    /* truncates the length of the high bits of the BigNum, that is the length of x. */
    const uint32_t sizeHi = (size + 1) >> 1;
    /* truncates the length of the low bits of the BigNum, that is the length of y. */
    const uint32_t sizeLo = size >> 1;
    const uint32_t shift1 = sizeLo;          /* ((x^2 + y^2 - (x - y)^2)) << 1) location */
    const uint32_t shift2 = shift1 << 1;     /* ((x^2 << 2) location */

    /* Split the input 'space'. The current function uses tmp1 and tmp2,
       and the remaining newspace is used by the lower layer. */
    BN_UINT *tmp1 = space;
    BN_UINT *tmp2 = tmp1 + (sizeHi << 1);
    BN_UINT *newSpace = tmp2 + (sizeHi << 1);

    /* tmp2 is the upper bits of num minus the lower bits of num, (x-y) */
    (void)ABS_Sub(tmp2, a + shift1, sizeHi, a, sizeLo);

    SqrConquer(r,          a,          sizeLo, newSpace, consttime); /* calculate y^2 */
    SqrConquer(r + shift2, a + shift1, sizeHi, newSpace, consttime); /* calculate x^2 */
    SqrConquer(tmp1,       tmp2,       sizeHi, newSpace, consttime); /* calculate (x-y)^2 */

    /* At this time r has stored (x^2 << 2) and y^2 */
    /* carry should be added in (r + shift1)[sizeHi * 2] */
    /* tmp2 = x^2 + y^2, but the processing length here is sizeLo * 2 */
    BN_UINT carry = BinAdd(tmp2, r, r + shift2, sizeLo << 1);
    if (sizeHi > sizeLo) {
        /* If there is a length difference, the length of x^2 is sizeLo * 2 + 2,
           and the tail of x^2 needs to be processed. */
        /* point to (r + shift2)[sizeLo * 2], the unprocessed tail of x^2 */
        const uint32_t position = shift2 + (sizeLo << 1);
        tmp2[sizeLo << 1] = r[position] + carry;
        carry = (tmp2[sizeLo << 1] < carry) ? 1 : 0;
        /* continue the processing */
        tmp2[(sizeLo << 1) + 1] = r[position + 1] + carry;
        carry = (tmp2[(sizeLo << 1) + 1] < carry) ? 1 : 0;
    }
    /* tmp1 = x^2 + y^2 - (x-y)^2, tmp2 is x^2 + y^2 */
    carry -= BinSub(tmp1, tmp2, tmp1, sizeHi << 1);
    /* finally r adds x^2 + y^2 - (x-y)^2 */
    carry += BinAdd(r + shift1, r + shift1, tmp1, sizeHi << 1);

    uint32_t i;
    for (i = shift1 + (sizeHi << 1); carry > 0 && i < (size << 1); i++) {
        ADD_AB(carry, r[i], r[i], carry);
    }
}
#endif /* HITLS_CRYPTO_BN_COMBA */
