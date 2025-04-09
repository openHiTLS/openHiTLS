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

/**
 * An implementation of sha1 that has 70% less in rom but lower performance.
 */
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SHA512) && defined(HITLS_CRYPTO_SHA512_SMALL_MEM)

#include "crypt_sha2.h"
#include "crypt_utils.h"
#include "sha2_core.h"

#ifndef U64
#define U64(v) (uint64_t)(v)
#endif

// define in rfc 4634
static const uint64_t K512[80] = {
    // Round 0-15
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd), U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019), U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe), U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1), U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    // Round 16-31
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3), U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483), U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210), U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725), U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    // Round 32-47
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926), U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8), U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001), U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910), U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    // Round 48-63
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53), U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb), U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60), U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9), U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    // Round 64-79
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207), U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6), U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493), U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a), U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

#undef ROUND00_15
#undef ROUND16_79

#define SHA512_CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_BSIG0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SHA512_BSIG1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SHA512_SSIG0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SHA512_SSIG1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

// Prepare the message schedule W
static inline void Sha512ExtendMessage(uint64_t *w, uint32_t t)
{
    w[t & 0xF] += SHA512_SSIG1(w[(t - 2) & 0xF]) + w[(t - 7) & 0xF] + SHA512_SSIG0(w[(t - 15) & 0xF]);
}

// Perform the main hash computation
static inline void Sha512Compress(uint64_t *state, uint64_t w, uint64_t k)
{
    uint64_t t1 = state[7] + SHA512_BSIG1(state[4]) + SHA512_CH(state[4], state[5], state[6]) + k + w;
    uint64_t t2 = SHA512_BSIG0(state[0]) + SHA512_MAJ(state[0], state[1], state[2]);

    state[7] = state[6];       // h = g
    state[6] = state[5];       // g = f
    state[5] = state[4];       // f = e
    state[4] = state[3] + t1;  // e = d + T1
    state[3] = state[2];       // d = c
    state[2] = state[1];       // c = b
    state[1] = state[0];       // b = a
    state[0] = t1 + t2;        // a = T1 + T2
}

void SHA512CompressMultiBlocks(uint64_t hash[8], const uint8_t *bl, uint32_t bcnt)
{
    uint32_t t;
    uint64_t state[8];
    uint64_t w[16];
    const uint8_t *block = bl;
    uint32_t blockn = bcnt;

    while (blockn > 0) {
        // Initialize the working variables
        for (t = 0; t < 8; t++) {
            state[t] = hash[t];
        }

        // Handle the first 16 rounds
        for (t = 0; t < 16; t++) {
            w[t] = Uint64FromBeBytes(block + t * 8);
            Sha512Compress(state, w[t], K512[t]);
        }

        // 16th - 79th round of operation, corresponding to steps 1 and 3 in rfc6234 6.4
        for (t = 16; t < 80; t++) {
            Sha512ExtendMessage(w, t);
            Sha512Compress(state, w[t & 0xF], K512[t]);
        }

        // RFC6234 STEP 4: Compute the intermediate hash value H(i)
        for (t = 0; t < 8; t++) {
            hash[t] += state[t];
        }

        block += CRYPT_SHA2_512_BLOCKSIZE;
        blockn--;
    }
}
#endif // HITLS_CRYPTO_SHA512 && HITLS_CRYPTO_SHA512_SMALL_MEM
