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
#ifdef HITLS_CRYPTO_BLAKE2S256

#include "blake2s_core.h"
#include "crypt_blake2.h"
#include "crypt_utils.h"

#define BLAKE2S_ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define BLAKE2S_G(v, a, b, c, d, x, y) \
    do { \
        (v)[a] = (v)[a] + (v)[b] + (x); \
        (v)[d] = BLAKE2S_ROR32((v)[d] ^ (v)[a], 16); \
        (v)[c] = (v)[c] + (v)[d]; \
        (v)[b] = BLAKE2S_ROR32((v)[b] ^ (v)[c], 12); \
        (v)[a] = (v)[a] + (v)[b] + (y); \
        (v)[d] = BLAKE2S_ROR32((v)[d] ^ (v)[a], 8); \
        (v)[c] = (v)[c] + (v)[d]; \
        (v)[b] = BLAKE2S_ROR32((v)[b] ^ (v)[c], 7); \
    } while (0)

#define BLAKE2S_ROUND(r, v, m) \
    do { \
        BLAKE2S_G((v), 0, 4, 8, 12, (m)[g_blake2sSigma[(r)][0]], (m)[g_blake2sSigma[(r)][1]]); \
        BLAKE2S_G((v), 1, 5, 9, 13, (m)[g_blake2sSigma[(r)][2]], (m)[g_blake2sSigma[(r)][3]]); \
        BLAKE2S_G((v), 2, 6, 10, 14, (m)[g_blake2sSigma[(r)][4]], (m)[g_blake2sSigma[(r)][5]]); \
        BLAKE2S_G((v), 3, 7, 11, 15, (m)[g_blake2sSigma[(r)][6]], (m)[g_blake2sSigma[(r)][7]]); \
        BLAKE2S_G((v), 0, 5, 10, 15, (m)[g_blake2sSigma[(r)][8]], (m)[g_blake2sSigma[(r)][9]]); \
        BLAKE2S_G((v), 1, 6, 11, 12, (m)[g_blake2sSigma[(r)][10]], (m)[g_blake2sSigma[(r)][11]]); \
        BLAKE2S_G((v), 2, 7, 8, 13, (m)[g_blake2sSigma[(r)][12]], (m)[g_blake2sSigma[(r)][13]]); \
        BLAKE2S_G((v), 3, 4, 9, 14, (m)[g_blake2sSigma[(r)][14]], (m)[g_blake2sSigma[(r)][15]]); \
    } while (0)

static const uint8_t g_blake2sSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static const uint32_t g_blake2sIv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

void BLAKE2S_Compress(uint32_t h[CRYPT_BLAKE2S_STATE_SIZE], const uint8_t block[CRYPT_BLAKE2S_BLOCKSIZE],
                      uint64_t counter, uint32_t flag)
{
    uint32_t m[CRYPT_BLAKE2s_COMPRESS_STATE_SIZE];
    uint32_t v[CRYPT_BLAKE2s_COMPRESS_STATE_SIZE];

    for (uint32_t i = 0; i < CRYPT_BLAKE2s_COMPRESS_STATE_SIZE; i++) {
        m[i] = GET_UINT32_LE(block, i * sizeof(uint32_t));
    }

    for (uint32_t i = 0; i < CRYPT_BLAKE2S_STATE_SIZE; i++) {
        v[i] = h[i];
        v[i + 8] = g_blake2sIv[i];
    }

    v[12] ^= (uint32_t)counter;
    v[13] ^= (uint32_t)(counter >> 32);
    v[14] ^= flag;
    BLAKE2S_ROUND(0, v, m);
    BLAKE2S_ROUND(1, v, m);
    BLAKE2S_ROUND(2, v, m);
    BLAKE2S_ROUND(3, v, m);
    BLAKE2S_ROUND(4, v, m);
    BLAKE2S_ROUND(5, v, m);
    BLAKE2S_ROUND(6, v, m);
    BLAKE2S_ROUND(7, v, m);
    BLAKE2S_ROUND(8, v, m);
    BLAKE2S_ROUND(9, v, m);

    h[0] ^= v[0] ^ v[0 + 8];
    h[1] ^= v[1] ^ v[1 + 8];
    h[2] ^= v[2] ^ v[2 + 8];
    h[3] ^= v[3] ^ v[3 + 8];
    h[4] ^= v[4] ^ v[4 + 8];
    h[5] ^= v[5] ^ v[5 + 8];
    h[6] ^= v[6] ^ v[6 + 8];
    h[7] ^= v[7] ^ v[7 + 8];
}

#endif // HITLS_CRYPTO_BLAKE2S256
