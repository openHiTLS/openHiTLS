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
#if defined(HITLS_CRYPTO_SHA512) && !defined(HITLS_CRYPTO_SHA512_SMALL_MEM)

#include "crypt_sha2.h"
#include "crypt_utils.h"
#include "sha2_core.h"

#ifndef U64
#define U64(v) (uint64_t)(v)
#endif

// define in rfc 4634
static const uint64_t K512[80] = {
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd), U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019), U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe), U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1), U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3), U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483), U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210), U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725), U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926), U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8), U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001), U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910), U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53), U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb), U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60), U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9), U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207), U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6), U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493), U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a), U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817),
};

#undef ROUND00_15
#undef ROUND16_79

#define SHA512_CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_BSIG0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SHA512_BSIG1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SHA512_SSIG0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SHA512_SSIG1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

#define SHA512_ROUND(a, b, c, d, e, f, g, h, t, s, w) \
do { \
    (h) += SHA512_BSIG1(e) + SHA512_CH(e, f, g) + K512[t] + (w)[s]; \
    (d) += (h); \
    (h) += SHA512_BSIG0(a) + SHA512_MAJ(a, b, c); \
} while (0)

#define ROUND00_15(w, a, b, c, d, e, f, g, h, t, M) \
do { \
    (w)[t] = Uint64FromBeBytes((M) + (t) * 8); \
    SHA512_ROUND(a, b, c, d, e, f, g, h, t, t, w); \
} while (0)

#define ROUND16_79(w, a, b, c, d, e, f, g, h, t, s) \
do { \
    (w)[s] += SHA512_SSIG1((w)[((s) + 14) & 0xF]) + (w)[((s) + 9) & 0xF] + SHA512_SSIG0((w)[((s) + 1) & 0xF]); \
    SHA512_ROUND(a, b, c, d, e, f, g, h, (t) + (s), s, w); \
} while (0)

void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *bl, uint32_t bcnt)
{
    uint32_t t;
    uint64_t w[16];
    const uint8_t *block = bl;
    uint32_t blockn = bcnt;

    while (blockn > 0) {
        uint64_t a = hash[0];
        uint64_t b = hash[1];
        uint64_t c = hash[2];
        uint64_t d = hash[3];
        uint64_t e = hash[4];
        uint64_t f = hash[5];
        uint64_t g = hash[6];
        uint64_t h = hash[7];

        ROUND00_15(w, a, b, c, d, e, f, g, h, 0, block);
        ROUND00_15(w, h, a, b, c, d, e, f, g, 1, block);
        ROUND00_15(w, g, h, a, b, c, d, e, f, 2, block);
        ROUND00_15(w, f, g, h, a, b, c, d, e, 3, block);
        ROUND00_15(w, e, f, g, h, a, b, c, d, 4, block);
        ROUND00_15(w, d, e, f, g, h, a, b, c, 5, block);
        ROUND00_15(w, c, d, e, f, g, h, a, b, 6, block);
        ROUND00_15(w, b, c, d, e, f, g, h, a, 7, block);
        ROUND00_15(w, a, b, c, d, e, f, g, h, 8, block);
        ROUND00_15(w, h, a, b, c, d, e, f, g, 9, block);
        ROUND00_15(w, g, h, a, b, c, d, e, f, 10, block);
        ROUND00_15(w, f, g, h, a, b, c, d, e, 11, block);
        ROUND00_15(w, e, f, g, h, a, b, c, d, 12, block);
        ROUND00_15(w, d, e, f, g, h, a, b, c, 13, block);
        ROUND00_15(w, c, d, e, f, g, h, a, b, 14, block);
        ROUND00_15(w, b, c, d, e, f, g, h, a, 15, block);

        // 16th - 79th round of operation, corresponding to steps 1 and 3 in rfc6234 6.4
        for (t = 16; t < 80; t += 16) {
            ROUND16_79(w, a, b, c, d, e, f, g, h, t, 0);
            ROUND16_79(w, h, a, b, c, d, e, f, g, t, 1);
            ROUND16_79(w, g, h, a, b, c, d, e, f, t, 2);
            ROUND16_79(w, f, g, h, a, b, c, d, e, t, 3);
            ROUND16_79(w, e, f, g, h, a, b, c, d, t, 4);
            ROUND16_79(w, d, e, f, g, h, a, b, c, t, 5);
            ROUND16_79(w, c, d, e, f, g, h, a, b, t, 6);
            ROUND16_79(w, b, c, d, e, f, g, h, a, t, 7);
            ROUND16_79(w, a, b, c, d, e, f, g, h, t, 8);
            ROUND16_79(w, h, a, b, c, d, e, f, g, t, 9);
            ROUND16_79(w, g, h, a, b, c, d, e, f, t, 10);
            ROUND16_79(w, f, g, h, a, b, c, d, e, t, 11);
            ROUND16_79(w, e, f, g, h, a, b, c, d, t, 12);
            ROUND16_79(w, d, e, f, g, h, a, b, c, t, 13);
            ROUND16_79(w, c, d, e, f, g, h, a, b, t, 14);
            ROUND16_79(w, b, c, d, e, f, g, h, a, t, 15);
        }

        // RFC6234 STEP 4: Compute the intermediate hash value H(i)
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;

        block += CRYPT_SHA2_512_BLOCKSIZE;
        blockn--;
    }
}
#endif
