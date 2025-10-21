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
 * An implementation of sha1 that has 65% less in rom but lower performance.
 */
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_SHA256) && defined(HITLS_CRYPTO_SHA256_SMALL_MEM)

#include "crypt_sha2.h"
#include "crypt_utils.h"
#include "sha2_core.h"

// Move constants to .rodata section
static const uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

#define ROTR32(x, n) (((x) << (32 - (n))) | ((x) >> (n)))

#define S0(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ ((x) >> 3))
#define S1(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10))

#define R(w, t) (S1((w)[(t) - 2]) + (w)[(t) - 7] + S0((w)[(t) - 15]) + (w)[(t)-16])

#define CRYPT_SHA256_ROUND(a, b, c, d, e, f, g, h, i, k) \
    do { \
        uint32_t t1 = (h) + (ROTR32((e), 6) ^ ROTR32((e), 11) ^ ROTR32((e), 25)) + \
            ((g) ^ ((e) & ((f) ^ (g)))) + (k) + (i); \
        uint32_t t2 = (ROTR32((a), 2) ^ ROTR32((a), 13) ^ ROTR32((a), 22)) + (((a) & ((b) | (c))) | ((b) & (c))); \
        (h) = (g); \
        (g) = (f); \
        (f) = (e); \
        (e) = (d) + t1; \
        (d) = (c); \
        (c) = (b); \
        (b) = (a); \
        (a) = t1 + t2; \
    } while (0)

static void CompressBlock(uint32_t state[8], const uint8_t block[CRYPT_SHA2_256_BLOCKSIZE])
{
    uint32_t w[64];

    // RFC 6234 6.2.2 Initialize the working variables
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    // RFC 6234 6.2.1. Prepare the message schedule w:
    for (unsigned i = 0; i < 16; i++) {
        w[i] = GET_UINT32_BE(block, 4 * i);
    }

    // Expand message schedule
    for (unsigned i = 16; i < 64; i++) {
        w[i] = R(w, i);
    }

    // RFC 6234 6.2.3 Perform the main hash computation
    for (unsigned i = 0; i < 64; i++) {
        CRYPT_SHA256_ROUND(a, b, c, d, e, f, g, h, w[i], K256[i]);
    }

    // RFC 6234 6.2.4. Compute the intermediate hash value H(i):
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}
#undef ROTR32
#undef CRYPT_SHA256_ROUND

void SHA256CompressMultiBlocks(uint32_t hash[8], const uint8_t *in, uint32_t num)
{
    uint32_t n = num;
    const uint8_t *p = in;
    while (n--) {
        CompressBlock(hash, p);
        p += CRYPT_SHA2_256_BLOCKSIZE;
    }
}
#endif // HITLS_CRYPTO_SHA256 && HITLS_CRYPTO_SHA256_SMALL_MEM
