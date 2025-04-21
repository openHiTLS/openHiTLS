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
/* Some of these codes are adapted from https://ed25519.cr.yp.to/software.html */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CURVE25519

#include <stdbool.h>
#include "securec.h"
#include "curve25519_local.h"
#include "bsl_sal.h"
#ifdef HITLS_CRYPTO_ED25519
#define CRYPT_CURVE25519_OPTLEN 32
#endif
#define CONDITION_COPY(dst, src, indicate)     \
    (int32_t)((uint32_t)(dst) ^ (((uint32_t)(dst) ^ (uint32_t)(src)) & (indicate)))

// process Fp multiplication carry
#define FP_PROCESS_CARRY(h)                           \
do {                                                  \
    int64_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;            \
    carry0 = h##0 + (1 << 25); h##1 += carry0 >> 26; h##0 -= carry0 & CURVE25519_MASK_HIGH_38;         \
    carry4 = h##4 + (1 << 25); h##5 += carry4 >> 26; h##4 -= carry4 & CURVE25519_MASK_HIGH_38;         \
    carry1 = h##1 + (1 << 24); h##2 += carry1 >> 25; h##1 -= carry1 & CURVE25519_MASK_HIGH_39;         \
    carry5 = h##5 + (1 << 24); h##6 += carry5 >> 25; h##5 -= carry5 & CURVE25519_MASK_HIGH_39;         \
    carry2 = h##2 + (1 << 25); h##3 += carry2 >> 26; h##2 -= carry2 & CURVE25519_MASK_HIGH_38;         \
    carry6 = h##6 + (1 << 25); h##7 += carry6 >> 26; h##6 -= carry6 & CURVE25519_MASK_HIGH_38;         \
    carry3 = h##3 + (1 << 24); h##4 += carry3 >> 25; h##3 -= carry3 & CURVE25519_MASK_HIGH_39;         \
    carry7 = h##7 + (1 << 24); h##8 += carry7 >> 25; h##7 -= carry7 & CURVE25519_MASK_HIGH_39;         \
    carry4 = h##4 + (1 << 25); h##5 += carry4 >> 26; h##4 -= carry4 & CURVE25519_MASK_HIGH_38;         \
    carry8 = h##8 + (1 << 25); h##9 += carry8 >> 26; h##8 -= carry8 & CURVE25519_MASK_HIGH_38;         \
    carry9 = h##9 + (1 << 24); h##0 += (carry9 >> 25) * 19; h##9 -= carry9 & CURVE25519_MASK_HIGH_39;  \
    carry0 = h##0 + (1 << 25); h##1 += carry0 >> 26; h##0 -= carry0 & CURVE25519_MASK_HIGH_38;         \
} while (0)

// h0...h9 to Fp25
#define INT64_2_FP25(h, out)                  \
do {                                    \
    (out)[0] = (int32_t)h##0;     \
    (out)[1] = (int32_t)h##1;     \
    (out)[2] = (int32_t)h##2;     \
    (out)[3] = (int32_t)h##3;     \
    (out)[4] = (int32_t)h##4;     \
    (out)[5] = (int32_t)h##5;     \
    (out)[6] = (int32_t)h##6;     \
    (out)[7] = (int32_t)h##7;     \
    (out)[8] = (int32_t)h##8;     \
    (out)[9] = (int32_t)h##9;     \
} while (0)

#define FP25_2_INT32(in, out)    \
do {                        \
    out##0 = (in)[0];  \
    out##1 = (in)[1];  \
    out##2 = (in)[2];  \
    out##3 = (in)[3];  \
    out##4 = (in)[4];  \
    out##5 = (in)[5];  \
    out##6 = (in)[6];  \
    out##7 = (in)[7];  \
    out##8 = (in)[8];  \
    out##9 = (in)[9];  \
} while (0)

/* out = f * g */
void FpMul(Fp25 out, const Fp25 f, const Fp25 g)
{
    int32_t f0, f1, f2, f3, f4, f5, f6, f7, f8, f9;
    int32_t g0, g1, g2, g3, g4, g5, g6, g7, g8, g9;
    int64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;

    FP25_2_INT32(f, f);
    FP25_2_INT32(g, g);

    int32_t f1_2 = f1 * 2;
    int32_t f3_2 = f3 * 2;
    int32_t f5_2 = f5 * 2;
    int32_t f7_2 = f7 * 2;
    int32_t f9_2 = f9 * 2;

    int32_t g1_19 = g1 * 19;
    int32_t g2_19 = g2 * 19;
    int32_t g3_19 = g3 * 19;
    int32_t g4_19 = g4 * 19;
    int32_t g5_19 = g5 * 19;
    int32_t g6_19 = g6 * 19;
    int32_t g7_19 = g7 * 19;
    int32_t g8_19 = g8 * 19;
    int32_t g9_19 = g9 * 19;

    /*  h0  =  f0g0 + 38f1g9 + 19f2g8 + 38f3g7 + 19f4g6 + 38f5g5 + 19f6g4 + 38f7g3 + 19f8g2 + 38f9g1
        h1  =  f0g1 + f1g0   + 19f2g9 + 19f3g8 + 19f4g7 + 19f5g6 + 19f6g5 + 19f7g4 + 19f8g3 + 19f9g2
        h2  =  f0g2 + 2f1g1  + f2g0   + 38f3g9 + 19f4g8 + 38f5g7 + 19f6g6 + 38f7g5 + 19f8g4 + 38f9g2
        h3  =  f0g3 + f1g2   + f2g1   + f3g0   + 19f4g9 + 19f5g8 + 19f6g7 + 19f7g6 + 19f8g5 + 19f9g4
        h4  =  f0g4 + 2f1g3  + f2g2   + 2f3g1  + f4g0   + 38f5g9 + 19f6g8 + 38f7g7 + 19f8g6 + 38f9g5
        h5  =  f0g5 + f1g4   + f2g3   + f3g2   + f4g1   + f5g0   + 19f6g9 + 19f7g8 + 19f8g7 + 19f9g6
        h6  =  f0g6 + 2f1g5  + f2g4   + 2f3g3  + f4g2   + 2f5g1  + f6g0   + 38f7g9 + 19f8g8 + 38f9g7
        h7  =  f0g7 + f1g6   + f2g5   + f3g4   + f4g3   + f5g2   + f6g1   + f7g0   + 19f8g9 + 19f9g8
        h8  =  f0g8 + 2f1g7  + f2g6   + 2f3g5  + f4g4   + 2f5g3  + f6g2   + 2f7g1  + f8g0   + 38f9g9
        h9  =  f0g9 + f1g8   + f2g7   + f3g6   + f4g5   + f5g4   + f6g3   + f7g2   + f8g1   + f9g0
        The calculation is performed by column. */

    h0 = (int64_t)f0 * g0;
    h1 = (int64_t)f0 * g1;
    h2 = (int64_t)f0 * g2;
    h3 = (int64_t)f0 * g3;
    h4 = (int64_t)f0 * g4;
    h5 = (int64_t)f0 * g5;
    h6 = (int64_t)f0 * g6;
    h7 = (int64_t)f0 * g7;
    h8 = (int64_t)f0 * g8;
    h9 = (int64_t)f0 * g9;

    h0 += (int64_t)f1_2 * g9_19;
    h1 += (int64_t)f1 * g0;
    h2 += (int64_t)f1_2 * g1;
    h3 += (int64_t)f1 * g2;
    h4 += (int64_t)f1_2 * g3;
    h5 += (int64_t)f1 * g4;
    h6 += (int64_t)f1_2 * g5;
    h7 += (int64_t)f1 * g6;
    h8 += (int64_t)f1_2 * g7;
    h9 += (int64_t)f1 * g8;

    h0 += (int64_t)f2 * g8_19;
    h1 += (int64_t)f2 * g9_19;
    h2 += (int64_t)f2 * g0;
    h3 += (int64_t)f2 * g1;
    h4 += (int64_t)f2 * g2;
    h5 += (int64_t)f2 * g3;
    h6 += (int64_t)f2 * g4;
    h7 += (int64_t)f2 * g5;
    h8 += (int64_t)f2 * g6;
    h9 += (int64_t)f2 * g7;

    h0 += (int64_t)f3_2 * g7_19;
    h1 += (int64_t)f3 * g8_19;
    h2 += (int64_t)f3_2 * g9_19;
    h3 += (int64_t)f3 * g0;
    h4 += (int64_t)f3_2 * g1;
    h5 += (int64_t)f3 * g2;
    h6 += (int64_t)f3_2 * g3;
    h7 += (int64_t)f3 * g4;
    h8 += (int64_t)f3_2 * g5;
    h9 += (int64_t)f3 * g6;

    h0 += (int64_t)f4 * g6_19;
    h1 += (int64_t)f4 * g7_19;
    h2 += (int64_t)f4 * g8_19;
    h3 += (int64_t)f4 * g9_19;
    h4 += (int64_t)f4 * g0;
    h5 += (int64_t)f4 * g1;
    h6 += (int64_t)f4 * g2;
    h7 += (int64_t)f4 * g3;
    h8 += (int64_t)f4 * g4;
    h9 += (int64_t)f4 * g5;

    h0 += (int64_t)f5_2 * g5_19;
    h1 += (int64_t)f5 * g6_19;
    h2 += (int64_t)f5_2 * g7_19;
    h3 += (int64_t)f5 * g8_19;
    h4 += (int64_t)f5_2 * g9_19;
    h5 += (int64_t)f5 * g0;
    h6 += (int64_t)f5_2 * g1;
    h7 += (int64_t)f5 * g2;
    h8 += (int64_t)f5_2 * g3;
    h9 += (int64_t)f5 * g4;

    h0 += (int64_t)f6 * g4_19;
    h1 += (int64_t)f6 * g5_19;
    h2 += (int64_t)f6 * g6_19;
    h3 += (int64_t)f6 * g7_19;
    h4 += (int64_t)f6 * g8_19;
    h5 += (int64_t)f6 * g9_19;
    h6 += (int64_t)f6 * g0;
    h7 += (int64_t)f6 * g1;
    h8 += (int64_t)f6 * g2;
    h9 += (int64_t)f6 * g3;

    h0 += (int64_t)f7_2 * g3_19;
    h1 += (int64_t)f7 * g4_19;
    h2 += (int64_t)f7_2 * g5_19;
    h3 += (int64_t)f7 * g6_19;
    h4 += (int64_t)f7_2 * g7_19;
    h5 += (int64_t)f7 * g8_19;
    h6 += (int64_t)f7_2 * g9_19;
    h7 += (int64_t)f7 * g0;
    h8 += (int64_t)f7_2 * g1;
    h9 += (int64_t)f7 * g2;

    h0 += (int64_t)f8 * g2_19;
    h1 += (int64_t)f8 * g3_19;
    h2 += (int64_t)f8 * g4_19;
    h3 += (int64_t)f8 * g5_19;
    h4 += (int64_t)f8 * g6_19;
    h5 += (int64_t)f8 * g7_19;
    h6 += (int64_t)f8 * g8_19;
    h7 += (int64_t)f8 * g9_19;
    h8 += (int64_t)f8 * g0;
    h9 += (int64_t)f8 * g1;

    h0 += (int64_t)f9_2 * g1_19;
    h1 += (int64_t)f9 * g2_19;
    h2 += (int64_t)f9_2 * g3_19;
    h3 += (int64_t)f9 * g4_19;
    h4 += (int64_t)f9_2 * g5_19;
    h5 += (int64_t)f9 * g6_19;
    h6 += (int64_t)f9_2 * g7_19;
    h7 += (int64_t)f9 * g8_19;
    h8 += (int64_t)f9_2 * g9_19;
    h9 += (int64_t)f9 * g0;

    FP_PROCESS_CARRY(h);

    INT64_2_FP25(h, out);
}

void FpSquareDoubleCore(Fp25 out, const Fp25 in, bool doDouble)
{
    int64_t h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;
    int32_t f0, f1, f2, f3, f4, f5, f6, f7, f8, f9;

    FP25_2_INT32(in, f);

    int32_t f0_2 = f0 * 2;
    int32_t f1_2 = f1 * 2;
    int32_t f2_2 = f2 * 2;
    int32_t f3_2 = f3 * 2;
    int32_t f4_2 = f4 * 2;
    int32_t f5_2 = f5 * 2;
    int32_t f6_2 = f6 * 2;
    int32_t f7_2 = f7 * 2;

    int32_t f9_38 = f9 * 38;
    int32_t f8_19 = f8 * 19;
    int32_t f7_38 = f7 * 38;
    int32_t f6_19 = f6 * 19;
    int32_t f5_19 = f5 * 19;

    h0 = (int64_t)f0 * f0;
    h1 = (int64_t)f0_2 * f1;
    h2 = (int64_t)f0_2 * f2;
    h3 = (int64_t)f0_2 * f3;
    h4 = (int64_t)f0_2 * f4;
    h5 = (int64_t)f0_2 * f5;
    h6 = (int64_t)f0_2 * f6;
    h7 = (int64_t)f0_2 * f7;
    h8 = (int64_t)f0_2 * f8;
    h9 = (int64_t)f0_2 * f9;

    h0 += (int64_t)f1_2 * f9_38;
    h1 += (int64_t)f2 * f9_38;
    h2 += (int64_t)f1_2 * f1;
    h3 += (int64_t)f1_2 * f2;
    h4 += (int64_t)f1_2 * f3_2;
    h5 += (int64_t)f1_2 * f4;
    h6 += (int64_t)f1_2 * f5_2;
    h7 += (int64_t)f1_2 * f6;
    h8 += (int64_t)f1_2 * f7_2;
    h9 += (int64_t)f1_2 * f8;

    h0 += (int64_t)f2_2 * f8_19;
    h1 += (int64_t)f3_2 * f8_19;
    h2 += (int64_t)f3_2 * f9_38;
    h3 += (int64_t)f4 * f9_38;
    h4 += (int64_t)f2 * f2;
    h5 += (int64_t)f2_2 * f3;
    h6 += (int64_t)f2_2 * f4;
    h7 += (int64_t)f2_2 * f5;
    h8 += (int64_t)f2_2 * f6;
    h9 += (int64_t)f2_2 * f7;

    h0 += (int64_t)f3_2 * f7_38;
    h1 += (int64_t)f4 * f7_38;
    h2 += (int64_t)f4_2 * f8_19;
    h3 += (int64_t)f5_2 * f8_19;
    h4 += (int64_t)f5_2 * f9_38;
    h5 += (int64_t)f6 * f9_38;
    h6 += (int64_t)f3_2 * f3;
    h7 += (int64_t)f3_2 * f4;
    h8 += (int64_t)f3_2 * f5_2;
    h9 += (int64_t)f3_2 * f6;

    h0 += (int64_t)f4_2 * f6_19;
    h1 += (int64_t)f5_2 * f6_19;
    h2 += (int64_t)f5_2 * f7_38;
    h3 += (int64_t)f6 * f7_38;
    h4 += (int64_t)f6_2 * f8_19;
    h5 += (int64_t)f7_2 * f8_19;
    h6 += (int64_t)f7_2 * f9_38;
    h7 += (int64_t)f8 * f9_38;
    h8 += (int64_t)f4 * f4;
    h9 += (int64_t)f4_2 * f5;

    h0 += (int64_t)f5_2 * f5_19;
    h2 += (int64_t)f6 * f6_19;
    h4 += (int64_t)f7 * f7_38;
    h6 += (int64_t)f8 * f8_19;
    h8 += (int64_t)f9 * f9_38;

    if (doDouble) {
        h0 *= 2;
        h1 *= 2;
        h2 *= 2;
        h3 *= 2;
        h4 *= 2;
        h5 *= 2;
        h6 *= 2;
        h7 *= 2;
        h8 *= 2;
        h9 *= 2;
    }

    FP_PROCESS_CARRY(h);

    INT64_2_FP25(h, out);
}

/* out = in1 ^ (4 * 2 ^ (2 * times)) * in2 */
static void FpMultiSquare(Fp25 in1, Fp25 in2, Fp25 out, int32_t times)
{
    int32_t i;
    Fp25 temp1, temp2;
    FpSquareDoubleCore(temp1, in1, false);
    FpSquareDoubleCore(temp2, temp1, false);
    for (i = 0; i < times; i++) {
        FpSquareDoubleCore(temp1, temp2, false);
        FpSquareDoubleCore(temp2, temp1, false);
    }
    FpMul(out, in2, temp2);
}

/* out = a ^ -1 */
void FpInvert(Fp25 out, const Fp25 a)
{
    int32_t i;
    Fp25 a0;    /* save a^1         */
    Fp25 a1;    /* save a^2         */
    Fp25 a2;    /* save a^11        */
    Fp25 a3;    /* save a^(2^5-1)   */
    Fp25 a4;    /* save a^(2^10-1)  */
    Fp25 a5;    /* save a^(2^20-1)  */
    Fp25 a6;    /* save a^(2^40-1)  */
    Fp25 a7;    /* save a^(2^50-1)  */
    Fp25 a8;    /* save a^(2^100-1) */
    Fp25 a9;    /* save a^(2^200-1) */
    Fp25 a10;   /* save a^(2^250-1) */
    Fp25 temp1, temp2;

    /* We know a×b=1(mod p), then a and b are inverses of mod p, i.e. a=b^(-1), b=a^(-1);
     * According to Fermat's little theorem a^(p-1)=1(mod p), so a*a^(p-2)=1(mod p);
     * So the inverse element of a is a^(-1) = a^(p-2)(mod p)
     * Here it is, p=2^255-19, thus we need to compute a^(2^255-21)(mod(2^255-19))
     */

    /* a^1 */
    CURVE25519_FP_COPY(a0, a);

    /* a^2 */
    FpSquareDoubleCore(a1, a0, false);

    /* a^4 */
    FpSquareDoubleCore(temp1, a1, false);

    /* a^8 */
    FpSquareDoubleCore(temp2, temp1, false);

    /* a^9 */
    FpMul(temp1, a0, temp2);

    /* a^11 */
    FpMul(a2, a1, temp1);

    /* a^22 */
    FpSquareDoubleCore(temp2, a2, false);

    /* a^(2^5-1) = a^(9+22) */
    FpMul(a3, temp1, temp2);

    /* a^(2^10-1) = a^(2^10-2^5) * a^(2^5-1) */
    FpSquareDoubleCore(temp1, a3, false);
    for (i = 0; i < 2; i++) { // (2 * 2)^2
        FpSquareDoubleCore(temp2, temp1, false);
        FpSquareDoubleCore(temp1, temp2, false);
    }
    FpMul(a4, a3, temp1);

    /* a^(2^20-1) = a^(2^20-2^10) * a^(2^10-1) */
    FpMultiSquare(a4, a4, a5, 4); // (2 * 2) ^ 4

    /* a^(2^40-1) = a^(2^40-2^20) * a^(2^20-1) */
    FpMultiSquare(a5, a5, a6, 9); // (2 * 2) ^ 9

    /* a^(2^50-1) = a^(2^50-2^10) * a^(2^10-1) */
    FpMultiSquare(a6, a4, a7, 4); // (2 * 2) ^ 4

    /* a^(2^100-1) = a^(2^100-2^50) * a^(2^50-1) */
    FpMultiSquare(a7, a7, a8, 24); // (2 * 2) ^ 24

    /* a^(2^200-1) = a^(2^200-2^100) * a^(2^100-1) */
    FpMultiSquare(a8, a8, a9, 49); // (2 * 2) ^ 49

    /* a^(2^250-1) = a^(2^250-2^50) * a^(2^50-1) */
    FpMultiSquare(a9, a7, a10, 24); // (2 * 2) ^ 24

    /* a^(2^5*(2^250-1)) = (a^(2^250-1))^5 */
    FpSquareDoubleCore(temp1, a10, false);
    FpSquareDoubleCore(temp2, temp1, false);
    FpSquareDoubleCore(temp1, temp2, false);
    FpSquareDoubleCore(temp2, temp1, false);
    FpSquareDoubleCore(temp1, temp2, false);

    /* The output：a^(2^255-21) = a(2^5*(2^250-1)+11) = a^(2^5*(2^250-1)) * a^11 */
    FpMul(out, a2, temp1);
}

#ifdef HITLS_CRYPTO_ED25519
/* out = in ^ ((q - 5) / 8) */
static void FpPowq58(Fp25 out, Fp25 in)
{
    Fp25 a, b, c;
    int32_t i;
    FpSquareDoubleCore(a, in, false);
    FpSquareDoubleCore(b, a, false);
    FpSquareDoubleCore(b, b, false);
    FpMul(b, in, b);
    FpMul(a, a, b);
    FpSquareDoubleCore(a, a, false);
    FpMul(a, b, a);
    FpSquareDoubleCore(b, a, false);
    // b = a ^ (2^5)
    for (i = 1; i < 5; i++) {
        FpSquareDoubleCore(b, b, false);
    }
    FpMul(a, b, a);
    FpSquareDoubleCore(b, a, false);
    // b = a ^ (2^10)
    for (i = 1; i < 10; i++) {
        FpSquareDoubleCore(b, b, false);
    }
    FpMul(b, b, a);
    FpSquareDoubleCore(c, b, false);

    // c = b ^ (2^20)
    for (i = 1; i < 20; i++) {
        FpSquareDoubleCore(c, c, false);
    }
    FpMul(b, c, b);

    // b = b ^ (2^10)
    for (i = 0; i < 10; i++) {
        FpSquareDoubleCore(b, b, false);
    }

    FpMul(a, b, a);
    FpSquareDoubleCore(b, a, false);

    // b = a ^ (2^50)
    for (i = 1; i < 50; i++) {
        FpSquareDoubleCore(b, b, false);
    }
    FpMul(b, b, a);
    FpSquareDoubleCore(c, b, false);

    // c = b ^ (2 ^ 100)
    for (i = 1; i < 100; i++) {
        FpSquareDoubleCore(c, c, false);
    }
    FpMul(b, c, b);

    // b = b ^ (2^50)
    for (i = 0; i < 50; i++) {
        FpSquareDoubleCore(b, b, false);
    }
    FpMul(a, b, a);
    FpSquareDoubleCore(a, a, false);
    FpSquareDoubleCore(a, a, false);
    FpMul(out, a, in);
}
#endif

static void PaddingUnload(uint8_t out[32], Fp25 pFp25)
{
    int32_t *p = (int32_t *)pFp25;

    /* Take a polynomial form number into a 32-byte array */
    CURVE25519_BYTES4_PADDING_UNLOAD(out, 2, p);                /* p0 unload 4 bytes on out[0] expand 2 */
    CURVE25519_BYTES3_PADDING_UNLOAD(out + 4, 2, 3, p + 1);     /* p1 unload 3 bytes on out[4] shift 2 expand 3 */
    CURVE25519_BYTES3_PADDING_UNLOAD(out + 7, 3, 5, p + 2);     /* p2 unload 3 bytes on out[7] shift 3 expand 5 */
    CURVE25519_BYTES3_PADDING_UNLOAD(out + 10, 5, 6, p + 3);    /* p3 unload 3 bytes on out[10] shift 5 expand 6 */
    CURVE25519_BYTES3_UNLOAD(out + 13, 6, p + 4);               /* p4 unload 3 bytes on out[13] shift 6 */

    CURVE25519_BYTES4_PADDING_UNLOAD(out + 16, 1, p + 5);       /* p5 unload 4 bytes on out[16] expand 1 */
    CURVE25519_BYTES3_PADDING_UNLOAD(out + 20, 1, 3, p + 6);    /* p6 unload 3 bytes on out[20] shift 1 expand 3 */
    CURVE25519_BYTES3_PADDING_UNLOAD(out + 23, 3, 4, p + 7);    /* p7 unload 3 bytes on out[23] shift 3 expand 4 */
    CURVE25519_BYTES3_PADDING_UNLOAD(out + 26, 4, 6, p + 8);    /* p8 unload 3 bytes on out[26] shift 4 expand 6 */
    CURVE25519_BYTES3_UNLOAD(out + 29, 6, p + 9);               /* p9 unload 3 bytes on out[29] shift 6 */
}

void PolynomialToData(uint8_t out[32], const Fp25 polynomial)
{
    Fp25 pFp25;
    uint32_t pos;
    uint32_t over;
    uint32_t mul19;
    uint32_t signMask;

    CURVE25519_FP_COPY(pFp25, polynomial);

    /* First process, all the carry transport to pFp25[0] */
    mul19 = (uint32_t)pFp25[9] * 19; // mul 19 for mod
    over = mul19 + (1 << 24); // plus 1 << 24 for carry
    // restricted to 25 bits, shift 31 for sign
    signMask = (-(over >> 31)) & MASK_HIGH32(25);
    over = (over >> 25) | signMask; // 25 bits
    pos = 0;
    do {
        over = (uint32_t)pFp25[pos] + over;
        // first carry is restricted to 25 bits, shift 31 for sign
        signMask = (-(over >> 31)) & MASK_HIGH32(25);
        over = (over >> 25) | signMask; // 25 bits
        pos++;

        over = (uint32_t)pFp25[pos] + over;
        // second carry is restricted to 26 bits, shift 31 for sign
        signMask = (-(over >> 31)) & MASK_HIGH32(26);
        over = (over >> 26) | signMask; // 26 bits
        pos++;
    } while (pos < 10); // process from 0 to 9, pos < 10
    mul19 = over * 19; // mul 19 for mod
    pFp25[0] += (int32_t)mul19;

    /* We subtracted 2^255-19 and get the result
     * all polynomial[i] is restricted to 25 bits or 26 bits
     */
    pos = 0;
    do {
        // first polynomial is restricted to 26 bits, shift 31 for sign
        signMask = (-((uint32_t)pFp25[pos] >> 31)) & MASK_HIGH32(26);
        over = ((uint32_t)pFp25[pos] >> 26) | signMask; // 26 bits
        pFp25[pos] = (int32_t)((uint32_t)pFp25[pos] & MASK_LOW32(26)); // 26 bits
        pos++;
        pFp25[pos] += (int32_t)over;

        // second polynomial is restricted to 25 bits, shift 31 for sign
        signMask = (-((uint32_t)pFp25[pos] >> 31)) & MASK_HIGH32(25);
        over = ((uint32_t)pFp25[pos] >> 25) | signMask; // 25 bits
        pFp25[pos] = (int32_t)((uint32_t)pFp25[pos] & MASK_LOW32(25));
        pos++;
        pFp25[pos] += (int32_t)over;
    } while (pos < 8); // process form 0 to 7, pos < 8

    // process pFp25[8], restricted to 26 bits, shift 31 for sign
    signMask = (-((uint32_t)pFp25[pos] >> 31)) & MASK_HIGH32(26);
    over = ((uint32_t)pFp25[pos] >> 26) | signMask; // 26 bits
    pFp25[pos] = (int32_t)((uint32_t)pFp25[pos] & MASK_LOW32(26)); // 26 bits
    pos++;
    // process pFp25[9]
    pFp25[pos] += (int32_t)over;
    pFp25[pos] = (int32_t)((uint32_t)pFp25[pos] & MASK_LOW32(25)); // pFp25[9] is restricted to 25 bits

    PaddingUnload(out, pFp25);
}

/* unified addition in Extended twist Edwards Coordinate */
/* out = out + tableElement */
static void GeAdd(GeE *out, const GePre *tableElement)
{
    Fp25 a;
    Fp25 b;
    Fp25 c;
    Fp25 d;
    Fp25 e;
    Fp25 f;
    Fp25 g;
    Fp25 h;
    /* a = (Y1 − X1) * (Y2 − X2), b = (Y1 + X1) * (Y2 + X2)
     * c = 2 * d * T1 * X2 * Y2, d = 2 * Z1
     * e = b − a, f = d − c, g = d + c, h = b + a
     * X3 = e * f, Y3 = g * h, T3 = e * h, Z3 = f * g
     */
    CURVE25519_FP_ADD(e, out->y, out->x);
    CURVE25519_FP_SUB(f, out->y, out->x);
    FpMul(b, e, tableElement->yplusx);
    FpMul(a, f, tableElement->yminusx);
    FpMul(c, out->t, tableElement->xy2d);
    CURVE25519_FP_ADD(d, out->z, out->z);
    CURVE25519_FP_SUB(e, b, a);
    CURVE25519_FP_SUB(f, d, c);
    CURVE25519_FP_ADD(g, d, c);
    CURVE25519_FP_ADD(h, b, a);
    FpMul(out->x, e, f);
    FpMul(out->y, h, g);
    FpMul(out->z, g, f);
    FpMul(out->t, e, h);
}

#ifdef HITLS_CRYPTO_ED25519
/* out = out - tableElement */
static void GeSub(GeE *out, const GePre *tableElement)
{
    Fp25 a;
    Fp25 b;
    Fp25 c;
    Fp25 d;
    Fp25 e;
    Fp25 f;
    Fp25 g;
    Fp25 h;

    CURVE25519_FP_ADD(e, out->y, out->x);
    CURVE25519_FP_SUB(f, out->y, out->x);
    FpMul(b, e, tableElement->yminusx);
    FpMul(a, f, tableElement->yplusx);
    FpMul(c, out->t, tableElement->xy2d);
    CURVE25519_FP_ADD(d, out->z, out->z);
    CURVE25519_FP_SUB(e, b, a);
    CURVE25519_FP_ADD(f, d, c);
    CURVE25519_FP_SUB(g, d, c);
    CURVE25519_FP_ADD(h, b, a);
    FpMul(out->x, e, f);
    FpMul(out->y, h, g);
    FpMul(out->z, g, f);
    FpMul(out->t, e, h);
}
#endif

/* double in Projective twist Edwards Coordinate */
static void ProjectiveDouble(GeC *complete, const GeP *projective)
{
    Fp25 tmp;
    FpSquareDoubleCore((complete->x), (projective->x), false);
    FpSquareDoubleCore((complete->z), (projective->y), false);
    // T = 2 * Z^2
    FpSquareDoubleCore(complete->t, projective->z, true);
    CURVE25519_FP_ADD(complete->y, projective->x, projective->y);
    FpSquareDoubleCore(tmp, complete->y, false);
    // tmp = (X1 + Y1) ^ 2, T = 2 * Z^2, X = X1 ^ 2, Y = Z1 ^ 2, Z = Y1 ^ 2
    CURVE25519_FP_ADD(complete->y, complete->z, complete->x);
    CURVE25519_FP_SUB(complete->z, complete->z, complete->x);
    CURVE25519_FP_SUB(complete->x, tmp, complete->y);
    CURVE25519_FP_SUB(complete->t, complete->t, complete->z);
}

/* Convert complete coordinate to projective coordinate */
static void GeCompleteToProjective(GeP *out, const GeC *complete)
{
    FpMul(out->x, complete->t, complete->x);
    FpMul(out->y, complete->z, complete->y);
    FpMul(out->z, complete->t, complete->z);
}

/* p1 = 16 * p1 */
static void P1DoubleFourTimes(GeE *p1)
{
    GeP p;
    GeC c;
    // From extended coordinate to projective coordinate, just ignore T
    CURVE25519_FP_COPY(p.x, p1->x);
    CURVE25519_FP_COPY(p.y, p1->y);
    CURVE25519_FP_COPY(p.z, p1->z);
    // double 4 times to get 16p1
    ProjectiveDouble(&c, &p);
    GeCompleteToProjective(&p, &c);
    ProjectiveDouble(&c, &p);
    GeCompleteToProjective(&p, &c);
    ProjectiveDouble(&c, &p);
    GeCompleteToProjective(&p, &c);
    ProjectiveDouble(&c, &p);
    FpMul(p1->x, c.x, c.t);
    FpMul(p1->y, c.y, c.z);
    FpMul(p1->z, c.z, c.t);
    FpMul(p1->t, c.x, c.y);
}

static void SetExtendedBasePoint(GeE *out)
{
    CURVE25519_FP_SET(out->x, 0);
    CURVE25519_FP_SET(out->y, 1);
    CURVE25519_FP_SET(out->t, 0);
    CURVE25519_FP_SET(out->z, 1);
}

/* Multiple with Base point, see paper: High-speed high-security signatures */
void ScalarMultiBase(GeE *out, const uint8_t in[CRYPT_CURVE25519_KEYLEN])
{
    uint8_t carry;
    // inLen is always 32, buffer needs 32 * 2 = 64
    uint8_t privateKey[64];
    int32_t i;
    GePre preCompute;

    // split 32 8bits input into 64 4bits-based number
    for (i = 0; i < 32; i++) {
        privateKey[i * 2] = in[i] & 15;            // and 15 to get low 4 bits, stored in 2i
        privateKey[i * 2 + 1] = (in[i] >> 4) & 15; // shift 4 then and 15 to get upper 4 bits, stored in 2i+1
    }
    carry = 0;
    /**
     * change from 0 - 15 to -8 - 7, if privateKey[i] >= 8, carry = 1, privateKey[i] -= 16
     * if privateKey[i] < 8, privateKey[i] = privateKey[i]
     */
    for (i = 0; i < 63; i++) { // 0 to 63
        privateKey[i] += carry;
        carry = (privateKey[i] + 8) >> 4; // plus 8 then shit 4 to get carry
        privateKey[i] -= carry << 4;      // left shift 4
    }
    // never overflow since we set first bit to 0 of private key
    privateKey[63] += carry; // last one is 63
    // set base point X:Y:T:Z -> 0:1:0:1
    SetExtendedBasePoint(out);
    for (i = 1; i < 64; i += 2) { // form 1 to 63, process all odd element, increment by 2, i < 64
        TableLookup(&preCompute, i / 2, (int8_t)privateKey[i]); // position goes from 0 to 31, i / 2 = pos
        // Fit with paper: Twisted Edwards Curves Revisited
        GeAdd(out, &preCompute);
    }
    // now we have P1, double it four times we have 16P1, P1 is in Extended now, we do double in projective coordinate
    P1DoubleFourTimes(out);
    // Add P0 with precomute
    for (i = 0; i < 64; i += 2) { // form 0 to 62, process all even element, increment by 2, i < 64
        TableLookup(&preCompute, i / 2, (int8_t)privateKey[i]); // position goes from 0 to 31, i / 2 = pos
        GeAdd(out, &preCompute);
    }
    // clean up private key information
    BSL_SAL_CleanseData(privateKey, sizeof(privateKey));
}

#ifdef HITLS_CRYPTO_ED25519
void PointEncoding(const GeE *point, uint8_t *output, uint32_t outputLen)
{
    Fp25 zInvert;
    Fp25 x;
    Fp25 y;
    uint8_t xData[CRYPT_CURVE25519_KEYLEN];
    /* x = X / Z, y = Y / Z */
    (void)outputLen;
    FpInvert(zInvert, point->z);
    FpMul(x, point->x, zInvert);
    FpMul(y, point->y, zInvert);
    PolynomialToData(output, y);
    PolynomialToData(xData, x);
    // PointEcoding writes only 32 bytes data, therefore output[31] is the last one
    output[31] ^= (xData[0] & 0x1) << 7; // last one is output[31], get only last bit then shift 7
}
#endif

static void FeCmove(Fp25 dst, const Fp25 src, const uint32_t indicator)
{
    // if indicator = 1, now it will be 111111111111b....
    const uint32_t indicate = 0 - indicator;
    /* des become source if dst->data[i] ^ src->data[i] is in 1111....b, or it does not change if
    (dst->data[i] ^ src->data[i]) & indicate is all 0 */
    dst[0] = CONDITION_COPY(dst[0], src[0], indicate); // 0
    dst[1] = CONDITION_COPY(dst[1], src[1], indicate); // 1
    dst[2] = CONDITION_COPY(dst[2], src[2], indicate); // 2
    dst[3] = CONDITION_COPY(dst[3], src[3], indicate); // 3
    dst[4] = CONDITION_COPY(dst[4], src[4], indicate); // 4
    dst[5] = CONDITION_COPY(dst[5], src[5], indicate); // 5
    dst[6] = CONDITION_COPY(dst[6], src[6], indicate); // 6
    dst[7] = CONDITION_COPY(dst[7], src[7], indicate); // 7
    dst[8] = CONDITION_COPY(dst[8], src[8], indicate); // 8
    dst[9] = CONDITION_COPY(dst[9], src[9], indicate); // 9
}

void ConditionalMove(GePre *preCompute, const GePre *tableElement, uint32_t indicator)
{
    FeCmove(preCompute->yplusx, tableElement->yplusx, indicator);
    FeCmove(preCompute->yminusx, tableElement->yminusx, indicator);
    FeCmove(preCompute->xy2d, tableElement->xy2d, indicator);
}

void DataToPolynomial(Fp25 out, const uint8_t data[32])
{
    const uint8_t *t = data;
    uint64_t p[10];
    uint64_t over;
    int32_t i;
    uint64_t signMask;

    /* f0, load 32 bits */
    CURVE25519_BYTES4_LOAD(p, t);
    /* f1, load 24 bits from t4, shift bits: 26 - 24 - (8 - x) = 0 -> x = 6 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 1, 6, t + 4);
    /* f2, load 24 bits from t7, shift bits: 51 - 48 - (8 - x) = 0 -> x = 5 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 2, 5, t + 7);
    /* f3, load 24 bits from t10, shift bits: 77 - 72 - (8 - x) = 0 -> x = 3 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 3, 3, t + 10);
    /* f4, load 24 bits from t13, shift bits: 102 - 96 - (8 - x) = 0 -> x = 2 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 4, 2, t + 13);
    /* f5, load 32 bits from t16 */
    CURVE25519_BYTES4_LOAD(p + 5, t + 16);
    /* f6, load 24 bits from t20, shift bits: 153 - 152 - (8 - x) = 0 -> x = 7 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 6, 7, t + 20);
    /* f7, load 24 bits from t23, shift bits: 179 - 176 - (8 - x) = 0 -> x = 5 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 7, 5, t + 23);
    /* f8, load 24 bits from t26, shift bits: 204 - 200 - (8 - x) = 0 -> x = 4 */
    CURVE25519_BYTES3_LOAD_PADDING(p + 8, 4, t + 26);
    /* f9, load 24 bits from t29, shift bits: 230 - 224 - (8 - x) = 0 -> x = 2 */
    CURVE25519_BYTES3_LOAD(p + 9, t + 29);
    p[9] = (p[9] & 0x7fffff) << 2; /* p9 is 25 bits, left shift 2 */

    /* Limiting the number of bits, exchange 2^1 to 2^25.5, turn into polynomial representation */
    /* f9->f0, shift 24 for carry */
    over = p[9] + (1 << 24);
    signMask = MASK_HIGH64(25) & (-((over) >> 63)); // shift 63 bits for sign, mask 25 bits
    p[0] += ((over >> 25) | signMask) * 19; // 24 bits plus sign is 25, mul 19 for mod
    p[9] -= MASK_HIGH64(39) & over; // 64 - 25 = 39 bits mask

    /* f1->f2, restricted to 24 bits */
    PROCESS_CARRY(p[1], p[2], signMask, over, 24);
    /* f3->f4, restricted to 24 bits */
    PROCESS_CARRY(p[3], p[4], signMask, over, 24);
    /* f5->f6, restricted to 24 bits */
    PROCESS_CARRY(p[5], p[6], signMask, over, 24);
    /* f7->f8, restricted to 24 bits */
    PROCESS_CARRY(p[7], p[8], signMask, over, 24);

    /* f0->f1, restricted to 25 bits */
    PROCESS_CARRY(p[0], p[1], signMask, over, 25);
    /* f2->f3, restricted to 25 bits */
    PROCESS_CARRY(p[2], p[3], signMask, over, 25);
    /* f4->f5, restricted to 25 bits */
    PROCESS_CARRY(p[4], p[5], signMask, over, 25);
    /* f6->f7, restricted to 25 bits */
    PROCESS_CARRY(p[6], p[7], signMask, over, 25);
    /* f8->f9, restricted to 25 bits */
    PROCESS_CARRY(p[8], p[9], signMask, over, 25);

    /* After process carry, polynomial every term would not exceed 32 bits, convert form 0 to 9, i < 10 */
    for (i = 0; i < 10; i++) {
        out[i] = (int32_t)p[i];
    }
}

#ifdef HITLS_CRYPTO_ED25519
static bool CheckZero(Fp25 x)
{
    uint8_t tmp[32];
    const uint8_t zero[32] = {0};
    PolynomialToData(tmp, x);
    if (memcmp(tmp, zero, sizeof(zero)) == 0) {
        return true;
    } else {
        return false;
    }
}

static uint8_t GetXBit(Fp25 in)
{
    uint8_t tmp[32];
    PolynomialToData(tmp, in);

    return tmp[0] & 0x1;
}

static const Fp25 SQRTM1 = {-32595792, -7943725, 9377950, 3500415, 12389472, -272473,
    -25146209, -2005654, 326686, 11406482};
static const Fp25 D = {-10913610, 13857413, -15372611, 6949391, 114729, -8787816,
    -6275908, -3247719, -18696448, -12055116};

int32_t PointDecoding(GeE *point, const uint8_t in[CRYPT_CURVE25519_KEYLEN])
{
    Fp25 u, v, v3, x2, result;
    // get the last block (31), shift 7 for first bit
    uint8_t x0 = in[31] >> 7;
    DataToPolynomial(point->y, in);
    
    CURVE25519_FP_SET(point->z, 1);
    FpSquareDoubleCore(u, point->y, false);
    FpMul(v, u, D);
    CURVE25519_FP_SUB(u, u, point->z);
    CURVE25519_FP_ADD(v, v, point->z);

    FpSquareDoubleCore(v3, v, false);
    FpMul(v3, v3, v);
    FpSquareDoubleCore(point->x, v3, false);
    FpMul(point->x, point->x, v);
    FpMul(point->x, point->x, u);

    /* x = x ^ ((q - 5) / 8) */
    FpPowq58(point->x, point->x);

    FpMul(point->x, point->x, v3);
    FpMul(point->x, point->x, u);
    FpSquareDoubleCore(x2, point->x, false);
    FpMul(x2, x2, v);
    CURVE25519_FP_SUB(result, x2, u);
    
    if (CheckZero(result) == false) {
        CURVE25519_FP_ADD(result, x2, u);
        if (CheckZero(result) == false) {
            return 1;
        }
        FpMul(point->x, point->x, SQRTM1);
    }
    uint8_t bit = GetXBit(point->x);
    if (bit != x0) {
        CURVE25519_FP_NEGATE(point->x, point->x);
    }
    FpMul(point->t, point->x, point->y);

    return 0;
}

static void ScalarMulAddPreLoad(const uint8_t in[CRYPT_CURVE25519_KEYLEN],
    uint64_t out[UINT8_32_21BITS_BLOCKNUM])
{
    CURVE25519_BYTES3_LOAD(&out[0], in);
    out[0] = out[0] & MASK_64_LOW21;

    CURVE25519_BYTES4_LOAD(&out[1], in + 2); // 1: load 4 bytes form position 2
    out[1]  = MASK_64_LOW21 & (out[1] >> 5); // 1: 8 - ((3 * 8) mod 21) mod 8 = 5

    CURVE25519_BYTES3_LOAD(&out[2], in + 5); // 2: load 3 bytes form position 5
    out[2]  = MASK_64_LOW21 & (out[2] >> 2); // 2: 8 - ((6 * 8) mod 21) mod 8 = 2

    CURVE25519_BYTES4_LOAD(&out[3], in + 7); // 3: load 4 bytes form position 7
    out[3]  = MASK_64_LOW21 & (out[3] >> 7); // 3: 8 - ((8 * 8) mod 21) mod 8 = 7

    CURVE25519_BYTES4_LOAD(&out[4], in + 10); // 4: load 4 bytes form position 10
    out[4]  = MASK_64_LOW21 & (out[4] >> 4); // 4: 8 - ((11 * 8) mod 21) mod 8 = 4

    CURVE25519_BYTES3_LOAD(&out[5], in + 13); // 5: load 3 bytes form position 13
    out[5]  = MASK_64_LOW21 & (out[5] >> 1); // 5: 8 - ((14 * 8) mod 21) mod 8 = 1

    CURVE25519_BYTES4_LOAD(&out[6], in + 15); // 6: load 4 bytes form position 15
    out[6]  = MASK_64_LOW21 & (out[6] >> 6); // 6: 8 - ((16 * 8) mod 21) mod 8 = 6

    CURVE25519_BYTES3_LOAD(&out[7], in + 18); // 7: load 3 bytes form position 18
    out[7]  = MASK_64_LOW21 & (out[7] >> 3); // 7: 8 - ((19 * 8) mod 21) mod 8 = 3

    CURVE25519_BYTES3_LOAD(&out[8], in + 21); // 8: load 3 bytes form position 21
    out[8]  = MASK_64_LOW21 & out[8]; // 8: ((22 * 8) mod 21) mod 8 = 0

    CURVE25519_BYTES4_LOAD(&out[9], in + 23); // 9: load 4 bytes form position 23
    out[9]  = MASK_64_LOW21 & (out[9] >> 5); // 9: 8 - ((24 * 8) mod 21) mod 8 = 5

    CURVE25519_BYTES3_LOAD(&out[10], in + 26); // 10: load 3 bytes form position 26
    out[10] = MASK_64_LOW21 & (out[10] >> 2); // 10: 8 - ((27 * 8) mod 21) mod 8 = 2

    CURVE25519_BYTES4_LOAD(&out[11], in + 28); // 11: load 4 bytes form position 28
    out[11] = (out[11] >> 7); // 11: 8 - ((29 * 8) mod 21) mod 8 = 7
}

static void ModuloLPreLoad(const uint8_t s[CRYPT_CURVE25519_SIGNLEN], uint64_t s21Bits[UINT8_64_21BITS_BLOCKNUM])
{
    CURVE25519_BYTES3_LOAD(&s21Bits[0], s);
    s21Bits[0] = s21Bits[0] & MASK_64_LOW21;

    CURVE25519_BYTES4_LOAD(&s21Bits[1], s + 2); // 1: load 4 bytes form position 2
    s21Bits[1]  = MASK_64_LOW21 & (s21Bits[1] >> 5); // 1: 8 - ((3 * 8) mod 21) mod 8 = 5

    CURVE25519_BYTES3_LOAD(&s21Bits[2], s + 5); // 2: load 3 bytes form position 5
    s21Bits[2]  = MASK_64_LOW21 & (s21Bits[2] >> 2); // 2: 8 - ((6 * 8) mod 21) mod 8 = 2

    CURVE25519_BYTES4_LOAD(&s21Bits[3], s + 7); // 3: load 4 bytes form position 7
    s21Bits[3]  = MASK_64_LOW21 & (s21Bits[3] >> 7); // 3: 8 - ((8 * 8) mod 21) mod 8 = 7

    CURVE25519_BYTES4_LOAD(&s21Bits[4], s + 10); // 4: load 4 bytes form position 10
    s21Bits[4]  = MASK_64_LOW21 & (s21Bits[4] >> 4); // 4: 8 - ((11 * 8) mod 21) mod 8 = 4

    CURVE25519_BYTES3_LOAD(&s21Bits[5], s + 13); // 5: load 3 bytes form position 13
    s21Bits[5]  = MASK_64_LOW21 & (s21Bits[5] >> 1); // 5: 8 - ((14 * 8) mod 21) mod 8 = 1

    CURVE25519_BYTES4_LOAD(&s21Bits[6], s + 15); // 6: load 4 bytes form position 15
    s21Bits[6]  = MASK_64_LOW21 & (s21Bits[6] >> 6); // 6: 8 - ((16 * 8) mod 21) mod 8 = 6

    CURVE25519_BYTES3_LOAD(&s21Bits[7], s + 18); // 7: load 3 bytes form position 18
    s21Bits[7]  = MASK_64_LOW21 & (s21Bits[7] >> 3); // 7: 8 - ((19 * 8) mod 21) mod 8 = 3

    CURVE25519_BYTES3_LOAD(&s21Bits[8], s + 21); // 8: load 3 bytes form position 21
    s21Bits[8]  = MASK_64_LOW21 & s21Bits[8]; // 8: ((22 * 8) mod 21) mod 8 = 0

    CURVE25519_BYTES4_LOAD(&s21Bits[9], s + 23); // 9: load 4 bytes form position 23
    s21Bits[9]  = MASK_64_LOW21 & (s21Bits[9] >> 5); // 9: 8 - ((24 * 8) mod 21) mod 8 = 5

    CURVE25519_BYTES3_LOAD(&s21Bits[10], s + 26); // 10: load 3 bytes form position 26
    s21Bits[10] = MASK_64_LOW21 & (s21Bits[10] >> 2); // 10: 8 - ((27 * 8) mod 21) mod 8 = 2

    CURVE25519_BYTES4_LOAD(&s21Bits[11], s + 28); // 11: load 4 bytes form position 28
    s21Bits[11] = MASK_64_LOW21 & (s21Bits[11] >> 7); // 11: 8 - ((29 * 8) mod 21) mod 8 = 7

    CURVE25519_BYTES4_LOAD(&s21Bits[12], s + 31); // 12: load 4 bytes form position 31
    s21Bits[12] = MASK_64_LOW21 & (s21Bits[12] >> 4); // 12: 8 - ((32 * 8) mod 21) mod 8 = 4

    CURVE25519_BYTES3_LOAD(&s21Bits[13], s + 34); // 13: load 3 bytes form position 34
    s21Bits[13] = MASK_64_LOW21 & (s21Bits[13] >> 1); // 13: 8 - ((35 * 8) mod 21) mod 8 = 1

    CURVE25519_BYTES4_LOAD(&s21Bits[14], s + 36); // 14: load 4 bytes form position 36
    s21Bits[14] = MASK_64_LOW21 & (s21Bits[14] >> 6); // 14: 8 - ((37 * 8) mod 21) mod 8 = 6

    CURVE25519_BYTES3_LOAD(&s21Bits[15], s + 39); // 15: load 3 bytes form position 39
    s21Bits[15] = MASK_64_LOW21 & (s21Bits[15] >> 3); // 15: 8 - ((40 * 8) mod 21) mod 8 = 3

    CURVE25519_BYTES3_LOAD(&s21Bits[16], s + 42); // 16: load 3 bytes form position 42
    s21Bits[16] = MASK_64_LOW21 & s21Bits[16]; // 16: ((43 * 8) mod 21) mod 8 = 0

    CURVE25519_BYTES4_LOAD(&s21Bits[17], s + 44); // 17: load 4 bytes form position 44
    s21Bits[17] = MASK_64_LOW21 & (s21Bits[17] >> 5); // 17: 8 - ((45 * 8) mod 21) mod 8 = 5

    CURVE25519_BYTES3_LOAD(&s21Bits[18], s + 47); // 18: load 3 bytes form position 47
    s21Bits[18] = MASK_64_LOW21 & (s21Bits[18] >> 2); // 18: 8 - ((48 * 8) mod 21) mod 8 = 2

    CURVE25519_BYTES4_LOAD(&s21Bits[19], s + 49); // 19: load 4 bytes form position 49
    s21Bits[19] = MASK_64_LOW21 & (s21Bits[19] >> 7); // 19: 8 - ((50 * 8) mod 21) mod 8 = 7

    CURVE25519_BYTES4_LOAD(&s21Bits[20], s + 52); // 20: load 4 bytes form position 52
    s21Bits[20] = MASK_64_LOW21 & (s21Bits[20] >> 4); // 20: 8 - ((53 * 8) mod 21) mod 8 = 4

    CURVE25519_BYTES3_LOAD(&s21Bits[21], s + 55); // 21: load 3 bytes form position 55
    s21Bits[21] = MASK_64_LOW21 & (s21Bits[21] >> 1); // 21: 8 - ((56 * 8) mod 21) mod 8 = 1

    CURVE25519_BYTES4_LOAD(&s21Bits[22], s + 57); // 22: load 4 bytes form position 57
    s21Bits[22] = MASK_64_LOW21 & (s21Bits[22] >> 6); // 22: 8 - ((58 * 8) mod 21) mod 8 = 6

    CURVE25519_BYTES4_LOAD(&s21Bits[23], s + 60); // 23: load 4 bytes form position 60
    s21Bits[23] = s21Bits[23] >> 3;  // 23: 8 - ((61 * 8) mod 21) mod 8 = 3
}

static void UnloadTo8Bits(uint8_t s8Bits[CRYPT_CURVE25519_OPTLEN], uint64_t s21Bits[UINT8_64_21BITS_BLOCKNUM])
{
    s8Bits[0] = (uint8_t)s21Bits[0];

    // 1: load from 8 on block 0
    s8Bits[1] = (uint8_t)(s21Bits[0] >> 8);

    // 2: load from (16 + 1) to 21 on block 0 and 1 to 3 on block 1, 8 - 3 = 5
    s8Bits[2] = (uint8_t)((s21Bits[0] >> 16) | (s21Bits[1] << 5));

    // 3: load from (3 + 1) on block 1
    s8Bits[3] = (uint8_t)(s21Bits[1] >> 3);

    // 4: load from (11 + 1) on block 1
    s8Bits[4] = (uint8_t)(s21Bits[1] >> 11);

    // 5: load from (19 + 1) to 21 on block 1 and 1 to 6 on block 2, 8 - 6 = 2
    s8Bits[5] = (uint8_t)((s21Bits[1] >> 19) | (s21Bits[2] << 2));

    // 6: load from (6 + 1) on block 2
    s8Bits[6] = (uint8_t)(s21Bits[2] >> 6);

    // 7: load from (14 + 1) to 21 on block 2 and 1 on block 3, 8 - 7 = 1
    s8Bits[7] = (uint8_t)((s21Bits[2] >> 14) | (s21Bits[3] << 7));

    // 8: load from (1 + 1) on block 3
    s8Bits[8] = (uint8_t)(s21Bits[3] >> 1);

    // 9: load from (9 + 1) on block 3
    s8Bits[9] = (uint8_t)(s21Bits[3] >> 9);

    // 10: load from (17 + 1) to 21 on block 3 and 1 to 4 on block 4, 8 - 4 = 4
    s8Bits[10] = (uint8_t)((s21Bits[3] >> 17) | (s21Bits[4] << 4));

    // 11: load from (4 + 1) on block 4
    s8Bits[11] = (uint8_t)(s21Bits[4] >> 4);

    // 12: load from (12 + 1) on block 4
    s8Bits[12] = (uint8_t)(s21Bits[4] >> 12);

    // 13: load from (20 + 1) on block 4 and 1 to 7 on block 5, 8 - 7 = 1
    s8Bits[13] = (uint8_t)((s21Bits[4] >> 20) | (s21Bits[5] << 1));

    // 14: load from (7 + 1) on block 5
    s8Bits[14] = (uint8_t)(s21Bits[5] >> 7);

    // 15: load from (15 + 1) to 21 on block 5 and 1 to 2 on block 6, 8 - 2 = 6
    s8Bits[15] = (uint8_t)((s21Bits[5] >> 15) | (s21Bits[6] << 6));

    // 16: load from (2 + 1) on block 6
    s8Bits[16] = (uint8_t)(s21Bits[6] >> 2);

    // 17: load from (10 + 1) on block 6
    s8Bits[17] = (uint8_t)(s21Bits[6] >> 10);

    // 18: load from (18 + 1) to 21 on block 6 and 1 to 5 on block 7, 8 - 5 = 3
    s8Bits[18] = (uint8_t)((s21Bits[6] >> 18) | (s21Bits[7] << 3));

    // 19: load from (5 + 1) on block 7
    s8Bits[19] = (uint8_t)(s21Bits[7] >> 5);

    // 20: load from (13 + 1) on block 7
    s8Bits[20] = (uint8_t)(s21Bits[7] >> 13);

    // 21: load 8bits on block 8
    s8Bits[21] = (uint8_t)s21Bits[8];

    // 22: load from (8 + 1) on block 8
    s8Bits[22] = (uint8_t)(s21Bits[8] >> 8);

    // 23: load from (16 + 1) to 21 on block 8 and 1 to 3 on block 9, 8 - 3 = 5
    s8Bits[23] = (uint8_t)((s21Bits[8] >> 16) | (s21Bits[9] << 5));

    // 24: load from (3 + 1) on block 9
    s8Bits[24] = (uint8_t)(s21Bits[9] >> 3);

    // 25: load from (11 + 1) on block 9
    s8Bits[25] = (uint8_t)(s21Bits[9] >> 11);

    // 26: load from (19 + 1) to 21 on block 9 and 1 to 6 on block 10, 8 - 6 = 2
    s8Bits[26] = (uint8_t)((s21Bits[9] >> 19) | (s21Bits[10] <<  2));

    // 27: load from (6 + 1) on block 10
    s8Bits[27] = (uint8_t)(s21Bits[10] >> 6);

    // 28: load from (14 + 1) to 21 on block 10 and 1 on block 11, 8 - 7 = 1
    s8Bits[28] = (uint8_t)((s21Bits[10] >> 14) | (s21Bits[11] << 7));

    // 29: load from (1 + 1) on block 11
    s8Bits[29] = (uint8_t)(s21Bits[11] >> 1);

    // 30: load from (9 + 1) on block 11
    s8Bits[30] = (uint8_t)(s21Bits[11] >> 9);

    // 31: load from (17 + 1) on block 11
    s8Bits[31] = (uint8_t)(s21Bits[11] >> 17);
}

static void ModuloLCore(uint64_t s21Bits[UINT8_64_21BITS_BLOCKNUM])
{
    int32_t i;
    uint64_t signMask1, signMask2;
    uint64_t carry1, carry2;

    // multiply by l0, start with {11, 12, 13, 14, 15, 16} to {6, 7, 8, 9, 10, 11, 12}
    CURVE25519_MULTI_BY_L0(s21Bits, 11);
    CURVE25519_MULTI_BY_L0(s21Bits, 10);
    CURVE25519_MULTI_BY_L0(s21Bits, 9);
    CURVE25519_MULTI_BY_L0(s21Bits, 8);
    CURVE25519_MULTI_BY_L0(s21Bits, 7);
    CURVE25519_MULTI_BY_L0(s21Bits, 6);

    // need to process carry to prevent overflow, process carry from 6->7, 8->9 ... 16->17, increment by 2
    for (i = 6; i <= 16; i += 2) {
        // 21 bits minus sign is 20 bits
        PROCESS_CARRY(s21Bits[i], s21Bits[i + 1], signMask1, carry1, 20);
    }

    // process carry from 7->8, 9->10 ... 15->16, increment by 2
    for (i = 7; i <= 15; i += 2) {
        // 21 bits minus sign bit is 20 bits
        PROCESS_CARRY(s21Bits[i], s21Bits[i + 1], signMask2, carry2, 20);
    }

    // {5, 6, 7, 8, 9, 10} to {0, 1, 2, 3, 4, 5, 6}
    CURVE25519_MULTI_BY_L0(s21Bits, 5);
    CURVE25519_MULTI_BY_L0(s21Bits, 4);
    CURVE25519_MULTI_BY_L0(s21Bits, 3);
    CURVE25519_MULTI_BY_L0(s21Bits, 2);
    CURVE25519_MULTI_BY_L0(s21Bits, 1);
    CURVE25519_MULTI_BY_L0(s21Bits, 0);

    // process carry again, from 0->1, 2->3 ... 10->11, increment by 2
    for (i = 0; i <= 10; i += 2) {
        // 21 bits minus sign bit is 20 bits
        PROCESS_CARRY(s21Bits[i], s21Bits[i + 1], signMask1, carry1, 20);
    }

    // from 1->2, 3->4 ... 11->12, increment by 2
    for (i = 1; i <= 11; i += 2) {
        // 21 bits minus sign is 20 bits
        PROCESS_CARRY(s21Bits[i], s21Bits[i + 1], signMask2, carry2, 20);
    }

    CURVE25519_MULTI_BY_L0(s21Bits, 0);

    // process carry from 0 to 11
    for (i = 0; i <= 11; i++) {
        PROCESS_CARRY_UNSIGN(s21Bits[i], s21Bits[i + 1], signMask1, carry1, 21); // s21Bits is 21 bits
    }

    CURVE25519_MULTI_BY_L0(s21Bits, 0);

    // from 0 to 10
    for (i = 0; i <= 10; i++) {
        PROCESS_CARRY_UNSIGN(s21Bits[i], s21Bits[i + 1], signMask1, carry1, 21); // s21Bits is 21 bits
    }
}

void ModuloL(uint8_t s[CRYPT_CURVE25519_SIGNLEN])
{
    // 24 of 21 bits block
    uint64_t s21Bits[UINT8_64_21BITS_BLOCKNUM] = {0};

    ModuloLPreLoad(s, s21Bits);

    ModuloLCore(s21Bits);

    UnloadTo8Bits(s, s21Bits);
}

static void MulAdd(uint64_t s21Bits[UINT8_64_21BITS_BLOCKNUM], const uint64_t a21Bits[UINT8_32_21BITS_BLOCKNUM],
    const uint64_t b21Bits[UINT8_32_21BITS_BLOCKNUM], const uint64_t c21Bits[UINT8_32_21BITS_BLOCKNUM])
{
    // s0 = c0 + a0b0
    s21Bits[0] = c21Bits[0] + a21Bits[0] * b21Bits[0];

    // s1 = c1 + a0b1 + a1b0
    s21Bits[1] = c21Bits[1] + a21Bits[0] * b21Bits[1] + a21Bits[1] * b21Bits[0];

    // s2 = c2 + a0b2 + b1a1 + a2b0
    s21Bits[2] = c21Bits[2] + a21Bits[0] * b21Bits[2] + a21Bits[1] * b21Bits[1] + a21Bits[2] * b21Bits[0];

    // s3 = c3 + a0b3 + a1b2 + a2b1 + a3b0
    s21Bits[3] = c21Bits[3] + a21Bits[0] * b21Bits[3] + a21Bits[1] * b21Bits[2] +
                 a21Bits[2] * b21Bits[1] + a21Bits[3] * b21Bits[0]; // a2b1 + a3b0

    // s4 = c4 + a0b4 +a1b3 + a2b2 + a3b1 + a4b0
    s21Bits[4] = c21Bits[4] + a21Bits[0] * b21Bits[4] + a21Bits[1] * b21Bits[3] +
                 a21Bits[2] * b21Bits[2] + a21Bits[3] * b21Bits[1] + a21Bits[4] * b21Bits[0]; // a2b2 + a3b1 + a4b0

    // s5 = c5 + a0b5 + a1b4 + a2b3 + a3b2 + a4b1 + a5b0
    s21Bits[5] = c21Bits[5] + a21Bits[0] * b21Bits[5] + a21Bits[1] * b21Bits[4] + a21Bits[2] * b21Bits[3] +
                 a21Bits[3] * b21Bits[2] + a21Bits[4] * b21Bits[1] + a21Bits[5] * b21Bits[0]; // a3b2 + a4b1 + a5b0

    // s6 = c6 + a0b6 + a1b5 + a2b4 + a3b3 + a2b4 + a5b1 + a6b0
    s21Bits[6] = c21Bits[6] + a21Bits[0] * b21Bits[6] + a21Bits[1] * b21Bits[5] + a21Bits[2] * b21Bits[4] +
                 a21Bits[3] * b21Bits[3] + a21Bits[4] * b21Bits[2] + a21Bits[5] * b21Bits[1] + // a3b3 + a2b4 + a5b1
                 a21Bits[6] * b21Bits[0]; // a6b0

    // s7 = c7 + a0b7 + a1b6 + a2b5 + a3b4 + a4b3 + a5b2 + a6b1 + a7b0
    s21Bits[7] = c21Bits[7] + a21Bits[0] * b21Bits[7] + a21Bits[1] * b21Bits[6] + a21Bits[2] * b21Bits[5] +
                 a21Bits[3] * b21Bits[4] + a21Bits[4] * b21Bits[3] + a21Bits[5] * b21Bits[2] + // a3b4 + a4b3 + a5b2
                 a21Bits[6] * b21Bits[1] + a21Bits[7] * b21Bits[0]; // a6b1 + a7b0

    // s8 = c8 + a0b8 + a1b7 + a2b6 + a3b5 + a4b4 + a5b3 + a6b2 + a7b1 + a8b0
    s21Bits[8] = c21Bits[8] + a21Bits[0] * b21Bits[8] + a21Bits[1] * b21Bits[7] + a21Bits[2] * b21Bits[6] +
                 a21Bits[3] * b21Bits[5] + a21Bits[4] * b21Bits[4] + a21Bits[5] * b21Bits[3] + // a3b5 + a4b4 + a5b3
                 a21Bits[6] * b21Bits[2] + a21Bits[7] * b21Bits[1] + a21Bits[8] * b21Bits[0]; // a6b2 + a7b1 + a8b0

    // s9 = c9 + a0b9 + a1b8 + a2b7 + a3b6 + a4b5 + a5b4 + a6b3 + a7b2 + a8b1 + a9b0
    s21Bits[9] = c21Bits[9] + a21Bits[0] * b21Bits[9] + a21Bits[1] * b21Bits[8] + a21Bits[2] * b21Bits[7] +
                 a21Bits[3] * b21Bits[6] + a21Bits[4] * b21Bits[5] + a21Bits[5] * b21Bits[4] + // a3b6 + a4b5 + a5b4
                 a21Bits[6] * b21Bits[3] + a21Bits[7] * b21Bits[2] + a21Bits[8] * b21Bits[1] + // a6b3 + a7b2 + a8b1
                 a21Bits[9] * b21Bits[0]; // a9b0

    // s10 = c10 + a0b10 + a1b9 + a2b8 + a3b7 + a4b6 + a5b5 + a6b4 + a7b3 + a8b2 + a9b1 + a10b0
    s21Bits[10] = c21Bits[10] + a21Bits[0] * b21Bits[10] + a21Bits[1] * b21Bits[9] + a21Bits[2] * b21Bits[8] +
                  a21Bits[3] * b21Bits[7] + a21Bits[4] * b21Bits[6] + a21Bits[5] * b21Bits[5] + // a3b7 + a4b6 + a5b5
                  a21Bits[6] * b21Bits[4] + a21Bits[7] * b21Bits[3] + a21Bits[8] * b21Bits[2] + // a6b4 + a7b3 + a8b2
                  a21Bits[9] * b21Bits[1] + a21Bits[10] * b21Bits[0]; // a9b1 + a10b0

    // s11 = c11 + a0b11 + a1b10 + a2b9 + a3b8 + a4b7 + a5b6 + a6b5 + a7b4 + a8b3 + a9b2 + a10b1 + a11b0
    s21Bits[11] = c21Bits[11] + a21Bits[0] * b21Bits[11] + a21Bits[1] * b21Bits[10] + a21Bits[2] * b21Bits[9] +
                  a21Bits[3] * b21Bits[8] + a21Bits[4] * b21Bits[7] + a21Bits[5] * b21Bits[6] + // a3b8 + a4b7 + a5b6
                  a21Bits[6] * b21Bits[5] + a21Bits[7] * b21Bits[4] + a21Bits[8] * b21Bits[3] + // a6b5 + a7b4 + a8b3
                  a21Bits[9] * b21Bits[2] + a21Bits[10] * b21Bits[1] + a21Bits[11] * b21Bits[0]; // a9b2 + a10b1 + a11b0

    // s12 = a1b11 + a2b10 + a3b9 + a4b8 + a5b7 + a6b6 + a7b5 + a8b4 + a9b3 + a10b2 + a11b1
    s21Bits[12] = a21Bits[1] * b21Bits[11] + a21Bits[2] * b21Bits[10] + a21Bits[3] * b21Bits[9] +
                  a21Bits[4] * b21Bits[8] + a21Bits[5] * b21Bits[7] + a21Bits[6] * b21Bits[6] + // a4b8 + a5b7 + a6b6
                  a21Bits[7] * b21Bits[5] + a21Bits[8] * b21Bits[4] + a21Bits[9] * b21Bits[3] + // a7b5 + a8b4 + a9b3
                  a21Bits[10] * b21Bits[2] + a21Bits[11] * b21Bits[1]; // a10b2 + a11b1

    // s13 = a2b11 + a3b10 + a4b9 + a5b8 + a6b7 + a7b6 + a8b5 + a9b4 + a10b3 + a11b2
    s21Bits[13] = a21Bits[2] * b21Bits[11] + a21Bits[3] * b21Bits[10] + a21Bits[4] * b21Bits[9] +
                  a21Bits[5] * b21Bits[8] + a21Bits[6] * b21Bits[7] + a21Bits[7] * b21Bits[6] + // a5b8 + a6b7 + a7b6
                  a21Bits[8] * b21Bits[5] + a21Bits[9] * b21Bits[4] + a21Bits[10] * b21Bits[3] + // a8b5 + a9b4 + a10b3
                  a21Bits[11] * b21Bits[2]; // a11b2

    // s14 = a3b11 + a4b10 + a5b9 + a6b8 + a7b7 + a8b6 + a9b5 + a10b4 + a11b3
    s21Bits[14] = a21Bits[3] * b21Bits[11] + a21Bits[4] * b21Bits[10] + a21Bits[5] * b21Bits[9] +
                  a21Bits[6] * b21Bits[8] + a21Bits[7] * b21Bits[7] + a21Bits[8] * b21Bits[6] + // a6b8 + a7b7 + a8b6
                  a21Bits[9] * b21Bits[5] + a21Bits[10] * b21Bits[4] + a21Bits[11] * b21Bits[3]; // a9b5 + a10b4 + a11b3

    // s15 = a4b11 + a5b10 + a6b9 + a7b8 + a8b7 + a9b6 + a10b5 + a11b4
    s21Bits[15] = a21Bits[4] * b21Bits[11] + a21Bits[5] * b21Bits[10] + a21Bits[6] * b21Bits[9] +
                  a21Bits[7] * b21Bits[8] + a21Bits[8] * b21Bits[7] + a21Bits[9] * b21Bits[6] + // a7b8 + a8b7 + a9b6
                  a21Bits[10] * b21Bits[5] + a21Bits[11] * b21Bits[4]; // a10b5 + a11b4

    // s16 = a5b11 + a6b10 + a7b9 + a8b8 + a9b7 + a10b6 + a11b5
    s21Bits[16] = a21Bits[5] * b21Bits[11] + a21Bits[6] * b21Bits[10] + a21Bits[7] * b21Bits[9] +
                  a21Bits[8] * b21Bits[8] + a21Bits[9] * b21Bits[7] + a21Bits[10] * b21Bits[6] + // a8b8 + a9b7 + a10b6
                  a21Bits[11] * b21Bits[5]; // a11b5

    // s17 = a6b11 + a7b10 + a8b9 + a9b8 + a10b7 + a11b6
    s21Bits[17] = a21Bits[6] * b21Bits[11] + a21Bits[7] * b21Bits[10] + a21Bits[8] * b21Bits[9] +
                  a21Bits[9] * b21Bits[8] + a21Bits[10] * b21Bits[7] + a21Bits[11] * b21Bits[6]; // a9b8 + a10b7 + a11b6

    // s18 = a7b11 + a8b10 + a9b9 + a10b8 + a11b7
    s21Bits[18] = a21Bits[7] * b21Bits[11] + a21Bits[8] * b21Bits[10] + a21Bits[9] * b21Bits[9] +
                  a21Bits[10] * b21Bits[8] + a21Bits[11] * b21Bits[7]; // a10b8 + a11b7

    // s19 = a8b11 + a9b10 + a10b9 + a11b8
    s21Bits[19] = a21Bits[8] * b21Bits[11] + a21Bits[9] * b21Bits[10] + a21Bits[10] * b21Bits[9] +
                  a21Bits[11] * b21Bits[8]; // a11b8

    // s20 = a9b11 + a10b10 + a11b9
    s21Bits[20] = a21Bits[9] * b21Bits[11] + a21Bits[10] * b21Bits[10] + a21Bits[11] * b21Bits[9];

    // s21 = a10b11 + a11b10
    s21Bits[21] = a21Bits[10] * b21Bits[11] + a21Bits[11] * b21Bits[10];

    // s22 = a11b11
    s21Bits[22] = a21Bits[11] * b21Bits[11];

    // s23 = 0
    s21Bits[23] = 0;
}

void ScalarMulAdd(uint8_t s[CRYPT_CURVE25519_KEYLEN], const uint8_t a[CRYPT_CURVE25519_KEYLEN],
    const uint8_t b[CRYPT_CURVE25519_KEYLEN], const uint8_t c[CRYPT_CURVE25519_KEYLEN])
{
    uint64_t a21Bits[UINT8_32_21BITS_BLOCKNUM];
    uint64_t b21Bits[UINT8_32_21BITS_BLOCKNUM];
    uint64_t c21Bits[UINT8_32_21BITS_BLOCKNUM];

    ScalarMulAddPreLoad(a, a21Bits);
    ScalarMulAddPreLoad(b, b21Bits);
    ScalarMulAddPreLoad(c, c21Bits);

    uint64_t s21Bits[UINT8_64_21BITS_BLOCKNUM];

    MulAdd(s21Bits, a21Bits, b21Bits, c21Bits);

    int32_t i;
    uint64_t signMask1, signMask2;
    uint64_t carryA, carryB;

    // process carry 0->1, 2->3 ... 22->23
    for (i = 0; i <= 22; i += 2) {
        // 21 bits minus sign bit is 20 bits
        PROCESS_CARRY(s21Bits[i], s21Bits[i + 1], signMask1, carryA, 20);
    }

    // process carry 1->2, 3->4 ... 21->22
    for (i = 1; i <= 21; i += 2) {
        // 21 bits minus sign bit is 20 bits
        PROCESS_CARRY(s21Bits[i], s21Bits[i + 1], signMask2, carryB, 20);
    }

    ModuloLCore(s21Bits);

    UnloadTo8Bits(s, s21Bits);
}

/* RFC8032, out = a + b */
static void PointAdd(GeE *out, GeE *greA, GeE *greB)
{
    const Fp25 d2 = {-21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199};
    Fp25 a, b, c, d, e, f, g, h;
    CURVE25519_FP_SUB(e, greA->y, greA->x);
    CURVE25519_FP_SUB(f, greB->y, greB->x);
    CURVE25519_FP_ADD(g, greA->y, greA->x);
    CURVE25519_FP_ADD(h, greB->y, greB->x);
    FpMul(a, e, f);
    FpMul(b, g, h);
    FpMul(c, greA->t, greB->t);
    FpMul(c, c, d2);
    FpMul(d, greA->z, greB->z);
    CURVE25519_FP_ADD(d, d, d);
    CURVE25519_FP_SUB(e, b, a);
    CURVE25519_FP_SUB(f, d, c);
    CURVE25519_FP_ADD(g, d, c);
    CURVE25519_FP_ADD(h, b, a);
    FpMul(out->x, e, f);
    FpMul(out->y, g, h);
    FpMul(out->z, f, g);
    FpMul(out->t, e, h);
}

static void PointAddPrecompute(GeE *out, GeE *greA, GeEPre *greB)
{
    Fp25 a, b, c, d, e, f, g, h;
    CURVE25519_FP_SUB(e, greA->y, greA->x);
    CURVE25519_FP_ADD(g, greA->y, greA->x);
    FpMul(a, e, greB->yminusx);
    FpMul(b, g, greB->yplusx);
    FpMul(c, greA->t, greB->t2z);
    FpMul(d, greA->z, greB->z);
    CURVE25519_FP_ADD(d, d, d);
    CURVE25519_FP_SUB(e, b, a);
    CURVE25519_FP_SUB(f, d, c);
    CURVE25519_FP_ADD(g, d, c);
    CURVE25519_FP_ADD(h, b, a);
    FpMul(out->x, e, f);
    FpMul(out->y, g, h);
    FpMul(out->z, f, g);
    FpMul(out->t, e, h);
}

static void PointSubPrecompute(GeE *out, GeE *greA, GeEPre *greB)
{
    Fp25 a, b, c, d, e, f, g, h;
    CURVE25519_FP_SUB(e, greA->y, greA->x);
    CURVE25519_FP_ADD(g, greA->y, greA->x);
    FpMul(a, e, greB->yplusx);
    FpMul(b, g, greB->yminusx);
    FpMul(c, greA->t, greB->t2z);
    FpMul(d, greA->z, greB->z);
    CURVE25519_FP_ADD(d, d, d);
    CURVE25519_FP_SUB(e, b, a);
    CURVE25519_FP_ADD(f, d, c);
    CURVE25519_FP_SUB(g, d, c);
    CURVE25519_FP_ADD(h, b, a);
    FpMul(out->x, e, f);
    FpMul(out->y, g, h);
    FpMul(out->z, f, g);
    FpMul(out->t, e, h);
}

static void P1DoubleN(GeE *p1, int32_t n)
{
    GeP p;
    GeC c;
    int32_t i;
    // From extended coordinate to projective coordinate, just ignore T
    CURVE25519_FP_COPY(p.x, p1->x);
    CURVE25519_FP_COPY(p.y, p1->y);
    CURVE25519_FP_COPY(p.z, p1->z);

    ProjectiveDouble(&c, &p);
    for (i = 1; i < n; i++) {
        GeCompleteToProjective(&p, &c);
        ProjectiveDouble(&c, &p);
    }

    FpMul(p1->x, c.t, c.x);
    FpMul(p1->y, c.z, c.y);
    FpMul(p1->z, c.t, c.z);
    FpMul(p1->t, c.y, c.x);
}

static void PointToPrecompute(GeEPre *out, GeE *in)
{
    const Fp25 d2 = {-21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199};

    CURVE25519_FP_ADD(out->yplusx, in->y, in->x);
    CURVE25519_FP_SUB(out->yminusx, in->y, in->x);
    CURVE25519_FP_COPY(out->z, in->z);
    FpMul(out->t2z, in->t, d2);
}

static void FlipK(int8_t slide[256], uint32_t start)
{
    uint32_t k;
    for (k = start; k < 256; k++) {
        if (slide[k] == 0) {
            slide[k] = 1;
            break;
        } else {
            slide[k] = 0;
        }
    }
}

static void SlideReduce(int8_t *out, uint32_t outLen, const uint8_t *in, uint32_t inLen)
{
    uint32_t i, j;
    int8_t tmp;
    (void)outLen;
    (void)inLen;
    // 32 * 8 = 256
    for (i = 0; i < 256; i++) {
        // turn 32 8bits to 256 1bit, block: in[i >> 3], bit: (i & 7)
        out[i] = (int8_t)((in[i >> 3] >> (i & 7)) & 1);
    }
    // 32 * 8 = 256
    for (i = 0; i < 256; i++) {
        if (out[i] == 0) {
            continue;
        }
        for (j = 1; j <= 6 && (i + j) < 256; j++) { // check next 6 since 2^6 - 2^5 = 16 > 15, 256 is array length
            if (out[i + j] == 0) {
                continue;
            }
            // range 15 to -15
            tmp = (int8_t)((uint8_t)(out[i + j]) << j);
            if (out[i] + tmp <= 15) { // max 15,  0x1, 0x1, 0x1, 0x1 , 0 -> 0x1111, 0, 0, 0, 0
                out[i] += tmp;
                out[i + j] = 0;
            } else if (out[i] - tmp >= -15) { // min -15, 0x1111, 0, 0, 0, 1, 1 -> -1, 0, 0, 0, 0, 1
                out[i] -= tmp;
                FlipK(out, i + j);
            } else {
                break;
            }
        }
    }
}

// Base on article "High-speed high-security signatures"
// stores B, 3B, 5B, 7B, 9B, 11B, 13B, 15B, with B as ed25519 base point
static const GePre g_precomputedB[8] = {
    {
        {25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626,
            -11754271, -6079156, 2047605},
        {-12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692,
            5043384, 19500929, -15469378},
        {-8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919,
            11864899, -24514362, -4438546},
    },
    {
        {15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600,
            -14772189, 28944400, -1550024},
        {16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577,
            -11775962, 7689662, 11199574},
        {30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774,
            10017326, -17749093, -9920357},
    },
    {
        {10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885,
            14515107, -15438304, 10819380},
        {4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668,
            12483688, -12668491, 5581306},
        {19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350,
            13850243, -23678021, -15815942},
    },
    {
        {5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852,
            5230134, -23952439, -15175766},
        {-30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025,
            16520125, 30598449, 7715701},
        {28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660,
            1370708, 29794553, -1409300},
    },
    {
        {-22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211,
            -1361450, -13062696, 13821877},
        {-6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028,
            -7212327, 18853322, -14220951},
        {4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358,
            -10431137, 2207753, -3209784},
    },
    {
        {-25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364,
            -663000, -31111463, -16132436},
        {25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789,
            15725684, 171356, 6466918},
        {23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339,
            -14088058, -30714912, 16193877},
    },
    {
        {-33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398,
            4729455, -18074513, 9256800},
        {-25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405,
            9761698, -19827198, 630305},
        {-13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551,
            -15960994, -2449256, -14291300},
    },
    {
        {-3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575,
            15033784, 25105118, -7894876},
        {-24326370, 15950226, -31801215, -14592823, -11662737, -5090925,
            1573892, -2625887, 2198790, -15804619},
        {-3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022,
            -16236442, -32461234, -12290683},
    },
};

/* out = hash * p + s * B */
void KAMulPlusMulBase(GeE *out, const uint8_t hash[CRYPT_CURVE25519_KEYLEN],
    const GeE *p, const uint8_t s[CRYPT_CURVE25519_KEYLEN])
{
    SetExtendedBasePoint(out);
    GeE tmpP[8]; // stores p, 3p, 5p, 7p, 9p, 11p, 13p, 15p
    GeE doubleP;
    GeEPre preComputedP[8]; // stores p, 3p, 5p, 7p, 9p, 11p, 13p, 15p
    int8_t slideP[256];
    int8_t slideS[256];
    int32_t i;

    SlideReduce(slideP, 256, hash, CRYPT_CURVE25519_KEYLEN);
    SlideReduce(slideS, 256, s, CRYPT_CURVE25519_KEYLEN);

    CURVE25519_GE_COPY(tmpP[0], *p);
    CURVE25519_GE_COPY(doubleP, *p);

    PointToPrecompute(&preComputedP[0], &tmpP[0]);
    P1DoubleN(&doubleP, 1);

    for (i = 1; i < 8; i += 1) { // p, 3p, ....., 13p, 15p, total 8
        PointAdd(&tmpP[i], &tmpP[i - 1], &doubleP);
        PointToPrecompute(&preComputedP[i], &tmpP[i]);
    }

    int32_t zeroCount = 0;
    i = 255; // 255 to 0
    while (i >= 0 && slideP[i] == 0 && slideS[i] == 0) {
        i--;
    }
    for (; i >= 0; i--) {
        while (i >= 0 && slideP[i] == 0 && slideS[i] == 0) {
            zeroCount++;
            i--;
        }
        if (i < 0) {
            P1DoubleN(out, zeroCount);
            break;
        } else {
            P1DoubleN(out, zeroCount + 1);
        }
        zeroCount = 0;
        if (slideP[i] > 0) {
            PointAddPrecompute(out, out, &preComputedP[slideP[i] / 2]); // preComputedP[i] = (i * 2 + 1)P
        } else if (slideP[i] < 0) {
            PointSubPrecompute(out, out, &preComputedP[(-slideP[i]) / 2]); // preComputedP[i] = (i * 2 + 1)P
        }
        if (slideS[i] > 0) {
            GeAdd(out, &g_precomputedB[slideS[i] / 2]); // g_precomputedB[i] = (i * 2 + 1)P
        } else if (slideS[i] < 0) {
            GeSub(out, &g_precomputedB[(-slideS[i]) / 2]); // g_precomputedB[i] = (i * 2 + 1)P
        }
    }
}
#endif /* HITLS_CRYPTO_ED25519 */

#endif /* HITLS_CRYPTO_CURVE25519 */
