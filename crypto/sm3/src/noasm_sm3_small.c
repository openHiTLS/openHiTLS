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
#if defined(HITLS_CRYPTO_SM3) && defined(HITLS_CRYPTO_SM3_SMALL_MEM)

#include <stdint.h>
#include "crypt_utils.h"
#include "crypt_sm3.h"
#include "sm3_local.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static uint32_t Sm3P0(uint32_t x)
{
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

static uint32_t Sm3P1(uint32_t x)
{
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

static uint32_t Sm3FF0(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static uint32_t Sm3FF1(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (x & z) | (y & z);
}

static uint32_t Sm3GG0(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static uint32_t Sm3GG1(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (~x & z);
}

static uint32_t Sm3Expand(uint32_t w1, uint32_t w2, uint32_t w3, uint32_t w4, uint32_t w5)
{
    return Sm3P1(w1 ^ w2 ^ ROTL32(w3, 15)) ^ ROTL32(w4, 7) ^ w5;
}

/* GM/T 0004-2012 round constants computed on the fly:
 * Tj = 0x79CC4519,  j = 0..15
 * Tj = 0x7A879D8A,  j = 16..63
 * Kj = ROTL32(Tj, j)
 */
static uint32_t Sm3K(uint32_t j)
{
    uint32_t t = (j < 16U) ? 0x79CC4519U : 0x7A879D8AU;
    int32_t n = j & 0x1FU;

    return (n == 0U) ? t : ROTL32(t, n);
}

/* see the GM standard document GM/T 0004-2012 chapter 5.3.3 */
void SM3_Compress(uint32_t state[8], const uint8_t *data, uint32_t blockCnt)
{
    uint32_t w[16];
    const uint8_t *input = data;
    uint32_t count = blockCnt;

    while (count > 0) {
        uint32_t i;
        for (i = 0; i < 16; i++) {
            w[i] = GET_UINT32_BE(input, i * 4);
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        /* Rounds 0..15: for j>=12 pre-compute W_{j+4} into w[(j+4)%16] before the round. */
        for (i = 0; i < 16; i++) {
            if (i >= 12U) {
                w[(i - 12U) & 0xFU] = Sm3Expand(w[(i - 12U) & 0xFU], w[(i - 5U) & 0xFU],
                    w[(i + 1U) & 0xFU], w[(i - 9U) & 0xFU], w[(i - 2U) & 0xFU]);
            }
            uint32_t Kj = Sm3K(i);
            uint32_t wj = w[i & 0xFU];
            uint32_t wi = wj ^ w[(i + 4U) & 0xFU];
            uint32_t a12 = ROTL32(a, 12);
            uint32_t ss1 = ROTL32(a12 + e + Kj, 7);
            uint32_t ss2 = ss1 ^ a12;
            uint32_t tt1 = Sm3FF0(a, b, c) + d + ss2 + wi;
            uint32_t tt2 = Sm3GG0(e, f, g) + h + ss1 + wj;
            h = g;
            g = ROTL32(f, 19);
            f = e;
            e = Sm3P0(tt2);
            d = c;
            c = ROTL32(b, 9);
            b = a;
            a = tt1;
        }

        /* Rounds 16..63: pre-compute W_{j+4} into w[(j+4)%16] before the round. */
        for (i = 16; i < 64; i++) {
            w[(i - 12U) & 0xFU] = Sm3Expand(w[(i - 12U) & 0xFU], w[(i - 5U) & 0xFU],
                w[(i + 1U) & 0xFU], w[(i - 9U) & 0xFU], w[(i - 2U) & 0xFU]);
            uint32_t Kj = Sm3K(i);
            uint32_t wj = w[i & 0xFU];
            uint32_t wi = wj ^ w[(i + 4U) & 0xFU];
            uint32_t a12 = ROTL32(a, 12);
            uint32_t ss1 = ROTL32(a12 + e + Kj, 7);
            uint32_t ss2 = ss1 ^ a12;
            uint32_t tt1 = Sm3FF1(a, b, c) + d + ss2 + wi;
            uint32_t tt2 = Sm3GG1(e, f, g) + h + ss1 + wj;
            h = g;
            g = ROTL32(f, 19);
            f = e;
            e = Sm3P0(tt2);
            d = c;
            c = ROTL32(b, 9);
            b = a;
            a = tt1;
        }

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_SM3 && HITLS_CRYPTO_SM3_SMALL_MEM */
