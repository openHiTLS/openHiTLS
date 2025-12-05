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
#ifdef HITLS_CRYPTO_SHA3

#include <stdlib.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "crypt_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

static void SHA3_Keccak(uint8_t *state);
static void Round(const uint64_t *a, uint64_t *e, uint32_t i);

#define ROL64(a, offset) ((((uint64_t)(a)) << (offset)) ^ (((uint64_t)(a)) >> (64 - (offset))))

// the rotation offsets, see https://keccak.team/keccak_specs_summary.html
static const uint8_t g_rotationOffset[5][5] = {
    {  0,  1, 62, 28, 27 },
    { 36, 44,  6, 55, 20 },
    {  3, 10, 43, 25, 39 },
    { 41, 45, 15, 21,  8 },
    { 18,  2, 61, 56, 14 }
};

// the round constants, see https://keccak.team/keccak_specs_summary.html
static const uint64_t g_roundConstant[24] = {
    (uint64_t)0x0000000000000001, (uint64_t)0x0000000000008082,
    (uint64_t)0x800000000000808a, (uint64_t)0x8000000080008000,
    (uint64_t)0x000000000000808b, (uint64_t)0x0000000080000001,
    (uint64_t)0x8000000080008081, (uint64_t)0x8000000000008009,
    (uint64_t)0x000000000000008a, (uint64_t)0x0000000000000088,
    (uint64_t)0x0000000080008009, (uint64_t)0x000000008000000a,
    (uint64_t)0x000000008000808b, (uint64_t)0x800000000000008b,
    (uint64_t)0x8000000000008089, (uint64_t)0x8000000000008003,
    (uint64_t)0x8000000000008002, (uint64_t)0x8000000000000080,
    (uint64_t)0x000000000000800a, (uint64_t)0x800000008000000a,
    (uint64_t)0x8000000080008081, (uint64_t)0x8000000000008080,
    (uint64_t)0x0000000080000001, (uint64_t)0x8000000080008008
};

// Absorbing function of the sponge structure
const uint8_t *SHA3_Absorb(uint8_t *state, const uint8_t *in, uint32_t inLen, uint32_t r)
{
    const uint8_t *data = (const uint8_t *)in;
    uint64_t *pSt = (uint64_t *)(uintptr_t)state;
    uint32_t dataLen = inLen;
    // Divide one block data into some uint64_t data (8 bytes) and perform XOR with the status variable.
    uint32_t blockInWord = r / 8;

    while (dataLen >= r) {
        for (uint32_t i = 0; i < blockInWord; i++) {
            uint64_t oneLane = GET_UINT64_LE(data, i << 3);
            pSt[i] ^= oneLane;
        }

        // Process one block data.
        SHA3_Keccak(state);
        dataLen -= r;
        data += r;
    }

    return (const uint8_t *)data;
}

// Squeezing function of the sponge structure
void SHA3_Squeeze(uint8_t *state, uint8_t *out, uint32_t outLen, uint32_t r, bool isNeedKeccak)
{
    uint32_t dataLen = outLen;
    uint32_t copyLen;
    // Divide one block data into some uint64_t data (8 bytes) and perform XOR with the status variable.
    uint32_t blockInWord = r / 8;
    uint64_t *oneLane = (uint64_t *)(uintptr_t)state;
    uint8_t outTmp[168];  // 168 = (1600 - 128 * 2) / 8, blockSize of the shake128 algorithm is the maximum.

    while (dataLen > 0) {
        copyLen = (dataLen > r) ? r : dataLen;

        for (uint32_t i = 0; i < blockInWord; i++) {
            PUT_UINT64_LE(oneLane[i], outTmp, i << 3); // left shift by 3 bits equals i * 8.
        }
        (void)memcpy_s(out + outLen - dataLen, dataLen, outTmp, copyLen);
        dataLen -= copyLen;
        if (dataLen > 0 || isNeedKeccak) {
            SHA3_Keccak(state);
        }
    }
}

static void SHA3_Keccak(uint8_t *state)
{
    uint8_t stTmp[200] = {0};

    // See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    // SHA3 depends on keccak-p[1600,24] for 24 rounds of cyclic calculation.
    for (uint32_t i = 0; i < 24; i += 2) {
        Round((uint64_t *)(uintptr_t)state, (uint64_t *)(uintptr_t)stTmp, i);
        Round((uint64_t *)(uintptr_t)stTmp, (uint64_t *)(uintptr_t)state, i + 1);
    }
}

// see section 2.4 Algorithm 1 in https://keccak.team/files/Keccak-implementation-3.2.pdf
static void Round(const uint64_t *a, uint64_t *e, uint32_t i)
{
    uint64_t c[5], d[5];

    // The corresponding formula for calculating the indexes of array A and array E is (5 * x) + y,
    // the value of x is in [0, 4] and the value of y is [0, 4].
    // The row coordinates of the array index correspond to y in the algorithm principle,
    // and the column coordinates correspond to x in the algorithm principle, for example, A[1, 1] = A[5 * 1 + 1] = A[6]
    // THETA operation
    c[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    c[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    c[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    c[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    c[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

    d[0] = ROL64(c[1], 1) ^ c[4];
    d[1] = ROL64(c[2], 1) ^ c[0];
    d[2] = ROL64(c[3], 1) ^ c[1];
    d[3] = ROL64(c[4], 1) ^ c[2];
    d[4] = ROL64(c[0], 1) ^ c[3];

    // THETA RHP Pi operation
    c[0] =       a[0]  ^ d[0];
    c[1] = ROL64(a[6]  ^ d[1], g_rotationOffset[1][1]);
    c[2] = ROL64(a[12] ^ d[2], g_rotationOffset[2][2]);
    c[3] = ROL64(a[18] ^ d[3], g_rotationOffset[3][3]);
    c[4] = ROL64(a[24] ^ d[4], g_rotationOffset[4][4]);

    // CHI IOTA operation,
    e[0] = c[0] ^ (~c[1] & c[2]) ^ g_roundConstant[i];
    // CHI operation
    e[1] = c[1] ^ (~c[2] & c[3]);
    e[2] = c[2] ^ (~c[3] & c[4]);
    e[3] = c[3] ^ (~c[4] & c[0]);
    e[4] = c[4] ^ (~c[0] & c[1]);

    // THETA RHP Pi operation
    c[0] = ROL64(a[3] ^ d[3], g_rotationOffset[0][3]);
    c[1] = ROL64(a[9] ^ d[4], g_rotationOffset[1][4]);
    c[2] = ROL64(a[10] ^ d[0], g_rotationOffset[2][0]);
    c[3] = ROL64(a[16] ^ d[1], g_rotationOffset[3][1]);
    c[4] = ROL64(a[22] ^ d[2], g_rotationOffset[4][2]);

    // CHI operation
    e[5] = c[0] ^ (~c[1] & c[2]);
    e[6] = c[1] ^ (~c[2] & c[3]);
    e[7] = c[2] ^ (~c[3] & c[4]);
    e[8] = c[3] ^ (~c[4] & c[0]);
    e[9] = c[4] ^ (~c[0] & c[1]);

    // THETA RHP Pi operation
    c[0] = ROL64(a[1] ^ d[1], g_rotationOffset[0][1]);
    c[1] = ROL64(a[7] ^ d[2], g_rotationOffset[1][2]);
    c[2] = ROL64(a[13] ^ d[3], g_rotationOffset[2][3]);
    c[3] = ROL64(a[19] ^ d[4], g_rotationOffset[3][4]);
    c[4] = ROL64(a[20] ^ d[0], g_rotationOffset[4][0]);

    // CHI operation
    e[10] = c[0] ^ (~c[1] & c[2]);
    e[11] = c[1] ^ (~c[2] & c[3]);
    e[12] = c[2] ^ (~c[3] & c[4]);
    e[13] = c[3] ^ (~c[4] & c[0]);
    e[14] = c[4] ^ (~c[0] & c[1]);

    // THETA RHP Pi operation
    c[0] = ROL64(a[4] ^ d[4], g_rotationOffset[0][4]);
    c[1] = ROL64(a[5] ^ d[0], g_rotationOffset[1][0]);
    c[2] = ROL64(a[11] ^ d[1], g_rotationOffset[2][1]);
    c[3] = ROL64(a[17] ^ d[2], g_rotationOffset[3][2]);
    c[4] = ROL64(a[23] ^ d[3], g_rotationOffset[4][3]);

    // CHI operation
    e[15] = c[0] ^ (~c[1] & c[2]);
    e[16] = c[1] ^ (~c[2] & c[3]);
    e[17] = c[2] ^ (~c[3] & c[4]);
    e[18] = c[3] ^ (~c[4] & c[0]);
    e[19] = c[4] ^ (~c[0] & c[1]);

    // THETA RHP Pi operation
    c[0] = ROL64(a[2] ^ d[2], g_rotationOffset[0][2]);
    c[1] = ROL64(a[8] ^ d[3], g_rotationOffset[1][3]);
    c[2] = ROL64(a[14] ^ d[4], g_rotationOffset[2][4]);
    c[3] = ROL64(a[15] ^ d[0], g_rotationOffset[3][0]);
    c[4] = ROL64(a[21] ^ d[1], g_rotationOffset[4][1]);

    // CHI operation
    e[20] = c[0] ^ (~c[1] & c[2]);
    e[21] = c[1] ^ (~c[2] & c[3]);
    e[22] = c[2] ^ (~c[3] & c[4]);
    e[23] = c[3] ^ (~c[4] & c[0]);
    e[24] = c[4] ^ (~c[0] & c[1]);
}

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SHA3
