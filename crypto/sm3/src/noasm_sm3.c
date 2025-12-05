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
#ifdef HITLS_CRYPTO_SM3

#include <stdint.h>
#include "crypt_utils.h"
#include "bsl_sal.h"
#include "crypt_sm3.h"

#define K0   0x79cc4519U
#define K1   0xf3988a32U
#define K2   0xe7311465U
#define K3   0xce6228cbU
#define K4   0x9cc45197U
#define K5   0x3988a32fU
#define K6   0x7311465eU
#define K7   0xe6228cbcU
#define K8   0xcc451979U
#define K9   0x988a32f3U
#define K10  0x311465e7U
#define K11  0x6228cbceU
#define K12  0xc451979cU
#define K13  0x88a32f39U
#define K14  0x11465e73U
#define K15  0x228cbce6U
#define K16  0x9d8a7a87U
#define K17  0x3b14f50fU
#define K18  0x7629ea1eU
#define K19  0xec53d43cU
#define K20  0xd8a7a879U
#define K21  0xb14f50f3U
#define K22  0x629ea1e7U
#define K23  0xc53d43ceU
#define K24  0x8a7a879dU
#define K25  0x14f50f3bU
#define K26  0x29ea1e76U
#define K27  0x53d43cecU
#define K28  0xa7a879d8U
#define K29  0x4f50f3b1U
#define K30  0x9ea1e762U
#define K31  0x3d43cec5U
#define K32  0x7a879d8aU
#define K33  0xf50f3b14U
#define K34  0xea1e7629U
#define K35  0xd43cec53U
#define K36  0xa879d8a7U
#define K37  0x50f3b14fU
#define K38  0xa1e7629eU
#define K39  0x43cec53dU
#define K40  0x879d8a7aU
#define K41  0x0f3b14f5U
#define K42  0x1e7629eaU
#define K43  0x3cec53d4U
#define K44  0x79d8a7a8U
#define K45  0xf3b14f50U
#define K46  0xe7629ea1U
#define K47  0xcec53d43U
#define K48  0x9d8a7a87U
#define K49  0x3b14f50fU
#define K50  0x7629ea1eU
#define K51  0xec53d43cU
#define K52  0xd8a7a879U
#define K53  0xb14f50f3U
#define K54  0x629ea1e7U
#define K55  0xc53d43ceU
#define K56  0x8a7a879dU
#define K57  0x14f50f3bU
#define K58  0x29ea1e76U
#define K59  0x53d43cecU
#define K60  0xa7a879d8U
#define K61  0x4f50f3b1U
#define K62  0x9ea1e762U
#define K63  0x3d43cec5U

#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

#define CRYPT_SM3_ROUND(A, B, C, D, E, F, G, H, K, FF, GG, Wj, Wi) do {   \
    uint32_t a12 = ROTL32((A), 12);                            \
    uint32_t ss1 = ROTL32(a12 + (E) + (K), 7);                 \
    uint32_t ss2 = ss1 ^ a12;                                  \
    uint32_t tt1 = FF((A), (B), (C)) + (D) + ss2 + (Wi);       \
    uint32_t tt2 = GG((E), (F), (G)) + (H) + ss1 + (Wj);       \
    (H) = tt1;    (D) = P0(tt2);                                \
    (B) = ROTL32((B), 9);   (F) = ROTL32((F), 19);              \
} while (0)

#define ROUND00_15(A, B, C, D, E, F, G, H, K, Wj, Wi)  \
    CRYPT_SM3_ROUND(A, B, C, D, E, F, G, H, K, FF0, GG0, Wj, Wi)

#define ROUND16_63(A, B, C, D, E, F, G, H, K, Wj, Wi)  \
    CRYPT_SM3_ROUND(A, B, C, D, E, F, G, H, K, FF1, GG1, Wj, Wi)

#define EXPAND(W1, W2, W3, W4, W5)     \
    (P1((W1) ^ (W2) ^ ROTL32((W3), 15)) ^ ROTL32((W4), 7) ^ (W5))

/* see the GM standard document GM/T 0004-2012 chapter 5.3.3 */
void SM3_Compress(uint32_t state[8], const uint8_t *data, uint32_t blockCnt)
{
    uint32_t w[16] = {0};
    const uint8_t *input = data;
    uint32_t count = blockCnt;

    while (count > 0) {
        /* converts data to 32 bits for calculation */
        w[0] = GET_UINT32_BE(input, 0);
        w[1] = GET_UINT32_BE(input, 4);
        w[2] = GET_UINT32_BE(input, 8);
        w[3] = GET_UINT32_BE(input, 12);
        w[4] = GET_UINT32_BE(input, 16);
        w[5] = GET_UINT32_BE(input, 20);
        w[6] = GET_UINT32_BE(input, 24);
        w[7] = GET_UINT32_BE(input, 28);
        w[8] = GET_UINT32_BE(input, 32);
        w[9] = GET_UINT32_BE(input, 36);
        w[10] = GET_UINT32_BE(input, 40);
        w[11] = GET_UINT32_BE(input, 44);
        w[12] = GET_UINT32_BE(input, 48);
        w[13] = GET_UINT32_BE(input, 52);
        w[14] = GET_UINT32_BE(input, 56);
        w[15] = GET_UINT32_BE(input, 60);

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        // 0 ~ 15 round
        ROUND00_15(a, b, c, d, e, f, g, h, K0, w[0], w[0] ^ w[4]);
        ROUND00_15(h, a, b, c, d, e, f, g, K1, w[1], w[1] ^ w[5]);
        ROUND00_15(g, h, a, b, c, d, e, f, K2, w[2], w[2] ^ w[6]);
        ROUND00_15(f, g, h, a, b, c, d, e, K3, w[3], w[3] ^ w[7]);
        ROUND00_15(e, f, g, h, a, b, c, d, K4, w[4], w[4] ^ w[8]);
        ROUND00_15(d, e, f, g, h, a, b, c, K5, w[5], w[5] ^ w[9]);
        ROUND00_15(c, d, e, f, g, h, a, b, K6, w[6], w[6] ^ w[10]);
        ROUND00_15(b, c, d, e, f, g, h, a, K7, w[7], w[7] ^ w[11]);
        ROUND00_15(a, b, c, d, e, f, g, h, K8, w[8], w[8] ^ w[12]);
        ROUND00_15(h, a, b, c, d, e, f, g, K9, w[9], w[9] ^ w[13]);
        ROUND00_15(g, h, a, b, c, d, e, f, K10, w[10], w[10] ^ w[14]);
        ROUND00_15(f, g, h, a, b, c, d, e, K11, w[11], w[11] ^ w[15]);
        w[0] = EXPAND(w[0], w[7], w[13], w[3], w[10]);
        ROUND00_15(e, f, g, h, a, b, c, d, K12, w[12], w[12] ^ w[0]);
        w[1] = EXPAND(w[1], w[8], w[14], w[4], w[11]);
        ROUND00_15(d, e, f, g, h, a, b, c, K13, w[13], w[13] ^ w[1]);
        w[2] = EXPAND(w[2], w[9], w[15], w[5], w[12]);
        ROUND00_15(c, d, e, f, g, h, a, b, K14, w[14], w[14] ^ w[2]);
        w[3] = EXPAND(w[3], w[10], w[0], w[6], w[13]);
        ROUND00_15(b, c, d, e, f, g, h, a, K15, w[15], w[15] ^ w[3]);

        // 16 ~ 63 round
        w[4]  = EXPAND(w[4],  w[11], w[1], w[7],  w[14]);
        ROUND16_63(a, b, c, d, e, f, g, h, K16, w[0], w[0] ^ w[4]);
        w[5]  = EXPAND(w[5],  w[12], w[2], w[8],  w[15]);
        ROUND16_63(h, a, b, c, d, e, f, g, K17, w[1], w[1] ^ w[5]);
        w[6]  = EXPAND(w[6],  w[13], w[3], w[9],  w[0]);
        ROUND16_63(g, h, a, b, c, d, e, f, K18, w[2], w[2] ^ w[6]);
        w[7]  = EXPAND(w[7],  w[14], w[4], w[10], w[1]);
        ROUND16_63(f, g, h, a, b, c, d, e, K19, w[3], w[3] ^ w[7]);
        w[8]  = EXPAND(w[8],  w[15], w[5], w[11], w[2]);
        ROUND16_63(e, f, g, h, a, b, c, d, K20, w[4], w[4] ^ w[8]);
        w[9]  = EXPAND(w[9],  w[0], w[6], w[12], w[3]);
        ROUND16_63(d, e, f, g, h, a, b, c, K21, w[5], w[5] ^ w[9]);
        w[10] = EXPAND(w[10], w[1], w[7], w[13], w[4]);
        ROUND16_63(c, d, e, f, g, h, a, b, K22, w[6], w[6] ^ w[10]);
        w[11] = EXPAND(w[11], w[2], w[8], w[14], w[5]);
        ROUND16_63(b, c, d, e, f, g, h, a, K23, w[7], w[7] ^ w[11]);
        w[12] = EXPAND(w[12], w[3], w[9], w[15], w[6]);
        ROUND16_63(a, b, c, d, e, f, g, h, K24, w[8], w[8] ^ w[12]);
        w[13] = EXPAND(w[13], w[4], w[10], w[0], w[7]);
        ROUND16_63(h, a, b, c, d, e, f, g, K25, w[9], w[9] ^ w[13]);
        w[14] = EXPAND(w[14], w[5], w[11], w[1], w[8]);
        ROUND16_63(g, h, a, b, c, d, e, f, K26, w[10], w[10] ^ w[14]);
        w[15] = EXPAND(w[15], w[6], w[12], w[2], w[9]);
        ROUND16_63(f, g, h, a, b, c, d, e, K27, w[11], w[11] ^ w[15]);
        w[0] = EXPAND(w[0], w[7], w[13], w[3], w[10]);
        ROUND16_63(e, f, g, h, a, b, c, d, K28, w[12], w[12] ^ w[0]);
        w[1] = EXPAND(w[1], w[8], w[14], w[4], w[11]);
        ROUND16_63(d, e, f, g, h, a, b, c, K29, w[13], w[13] ^ w[1]);
        w[2] = EXPAND(w[2], w[9], w[15], w[5], w[12]);
        ROUND16_63(c, d, e, f, g, h, a, b, K30, w[14], w[14] ^ w[2]);
        w[3] = EXPAND(w[3], w[10], w[0], w[6], w[13]);
        ROUND16_63(b, c, d, e, f, g, h, a, K31, w[15], w[15] ^ w[3]);

        w[4]  = EXPAND(w[4],  w[11], w[1], w[7],  w[14]);
        ROUND16_63(a, b, c, d, e, f, g, h, K32, w[0], w[0] ^ w[4]);
        w[5]  = EXPAND(w[5],  w[12], w[2], w[8],  w[15]);
        ROUND16_63(h, a, b, c, d, e, f, g, K33, w[1], w[1] ^ w[5]);
        w[6]  = EXPAND(w[6],  w[13], w[3], w[9],  w[0]);
        ROUND16_63(g, h, a, b, c, d, e, f, K34, w[2], w[2] ^ w[6]);
        w[7]  = EXPAND(w[7],  w[14], w[4], w[10], w[1]);
        ROUND16_63(f, g, h, a, b, c, d, e, K35, w[3], w[3] ^ w[7]);
        w[8]  = EXPAND(w[8],  w[15], w[5], w[11], w[2]);
        ROUND16_63(e, f, g, h, a, b, c, d, K36, w[4], w[4] ^ w[8]);
        w[9]  = EXPAND(w[9],  w[0], w[6], w[12], w[3]);
        ROUND16_63(d, e, f, g, h, a, b, c, K37, w[5], w[5] ^ w[9]);
        w[10] = EXPAND(w[10], w[1], w[7], w[13], w[4]);
        ROUND16_63(c, d, e, f, g, h, a, b, K38, w[6], w[6] ^ w[10]);
        w[11] = EXPAND(w[11], w[2], w[8], w[14], w[5]);
        ROUND16_63(b, c, d, e, f, g, h, a, K39, w[7], w[7] ^ w[11]);
        w[12] = EXPAND(w[12], w[3], w[9], w[15], w[6]);
        ROUND16_63(a, b, c, d, e, f, g, h, K40, w[8], w[8] ^ w[12]);
        w[13] = EXPAND(w[13], w[4], w[10], w[0], w[7]);
        ROUND16_63(h, a, b, c, d, e, f, g, K41, w[9], w[9] ^ w[13]);
        w[14] = EXPAND(w[14], w[5], w[11], w[1], w[8]);
        ROUND16_63(g, h, a, b, c, d, e, f, K42, w[10], w[10] ^ w[14]);
        w[15] = EXPAND(w[15], w[6], w[12], w[2], w[9]);
        ROUND16_63(f, g, h, a, b, c, d, e, K43, w[11], w[11] ^ w[15]);
        w[0] = EXPAND(w[0], w[7], w[13], w[3], w[10]);
        ROUND16_63(e, f, g, h, a, b, c, d, K44, w[12], w[12] ^ w[0]);
        w[1] = EXPAND(w[1], w[8], w[14], w[4], w[11]);
        ROUND16_63(d, e, f, g, h, a, b, c, K45, w[13], w[13] ^ w[1]);
        w[2] = EXPAND(w[2], w[9], w[15], w[5], w[12]);
        ROUND16_63(c, d, e, f, g, h, a, b, K46, w[14], w[14] ^ w[2]);
        w[3] = EXPAND(w[3], w[10], w[0], w[6], w[13]);
        ROUND16_63(b, c, d, e, f, g, h, a, K47, w[15], w[15] ^ w[3]);

        w[4]  = EXPAND(w[4],  w[11], w[1], w[7],  w[14]);
        ROUND16_63(a, b, c, d, e, f, g, h, K48, w[0], w[0] ^ w[4]);
        w[5]  = EXPAND(w[5],  w[12], w[2], w[8],  w[15]);
        ROUND16_63(h, a, b, c, d, e, f, g, K49, w[1], w[1] ^ w[5]);
        w[6]  = EXPAND(w[6],  w[13], w[3], w[9],  w[0]);
        ROUND16_63(g, h, a, b, c, d, e, f, K50, w[2], w[2] ^ w[6]);
        w[7]  = EXPAND(w[7],  w[14], w[4], w[10], w[1]);
        ROUND16_63(f, g, h, a, b, c, d, e, K51, w[3], w[3] ^ w[7]);
        w[8]  = EXPAND(w[8],  w[15], w[5], w[11], w[2]);
        ROUND16_63(e, f, g, h, a, b, c, d, K52, w[4], w[4] ^ w[8]);
        w[9]  = EXPAND(w[9],  w[0], w[6], w[12], w[3]);
        ROUND16_63(d, e, f, g, h, a, b, c, K53, w[5], w[5] ^ w[9]);
        w[10] = EXPAND(w[10], w[1], w[7], w[13], w[4]);
        ROUND16_63(c, d, e, f, g, h, a, b, K54, w[6], w[6] ^ w[10]);
        w[11] = EXPAND(w[11], w[2], w[8], w[14], w[5]);
        ROUND16_63(b, c, d, e, f, g, h, a, K55, w[7], w[7] ^ w[11]);
        w[12] = EXPAND(w[12], w[3], w[9], w[15], w[6]);
        ROUND16_63(a, b, c, d, e, f, g, h, K56, w[8], w[8] ^ w[12]);
        w[13] = EXPAND(w[13], w[4], w[10], w[0], w[7]);
        ROUND16_63(h, a, b, c, d, e, f, g, K57, w[9], w[9] ^ w[13]);
        w[14] = EXPAND(w[14], w[5], w[11], w[1], w[8]);
        ROUND16_63(g, h, a, b, c, d, e, f, K58, w[10], w[10] ^ w[14]);
        w[15] = EXPAND(w[15], w[6], w[12], w[2], w[9]);
        ROUND16_63(f, g, h, a, b, c, d, e, K59, w[11], w[11] ^ w[15]);
        w[0] = EXPAND(w[0], w[7], w[13], w[3], w[10]);
        ROUND16_63(e, f, g, h, a, b, c, d, K60, w[12], w[12] ^ w[0]);
        w[1] = EXPAND(w[1], w[8], w[14], w[4], w[11]);
        ROUND16_63(d, e, f, g, h, a, b, c, K61, w[13], w[13] ^ w[1]);
        w[2] = EXPAND(w[2], w[9], w[15], w[5], w[12]);
        ROUND16_63(c, d, e, f, g, h, a, b, K62, w[14], w[14] ^ w[2]);
        w[3] = EXPAND(w[3], w[10], w[0], w[6], w[13]);
        ROUND16_63(b, c, d, e, f, g, h, a, K63, w[15], w[15] ^ w[3]);

        state[0] ^= a;
        state[1] ^= b;
        state[2] ^= c;
        state[3] ^= d;
        state[4] ^= e;
        state[5] ^= f;
        state[6] ^= g;
        state[7] ^= h;

        input += CRYPT_SM3_BLOCKSIZE;
        count--;
    }
}
#endif // HITLS_CRYPTO_SM3
