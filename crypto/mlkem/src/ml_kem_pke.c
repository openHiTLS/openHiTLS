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
#ifdef HITLS_CRYPTO_MLKEM
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_sha3.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "eal_md_local.h"
#include "ml_kem_local.h"

#define BITS_OF_BYTE 8
#define MLKEM_K_MAX    4
#define MLKEM_ETA1_MAX    3
#define MLKEM_ETA2_MAX    2

// A LUT of the primitive n-th roots of unity (psi) in bit-reversed order.
static const int16_t PRE_COMPUT_TABLE_NTT[MLKEM_N_HALF] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476,
    3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
    2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220,
    375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
};

// A LUT of all powers of psi^{-1} in bit-reversed order.
static const int16_t PRE_COMPUT_TABLE_INTT[MLKEM_N_HALF] = {
    1, 1600, 40, 749, 2481, 1432, 2699, 687, 1583, 2760, 69, 543, 2532, 3136, 1410, 2267, 2508, 1355, 450, 936, 447,
    2794, 1235, 1903, 1996, 1089, 3273, 283, 1853, 1990, 882, 3033, 2419, 2102, 219, 855, 2681, 1848, 712, 682, 927,
    1795, 461, 1891, 2877, 2522, 1894, 1010, 1414, 2009, 3296, 464, 2697, 816, 1352, 2679, 1274, 1052, 1025, 2132,
    1573, 76, 2998, 3040, 1175, 2444, 394, 1219, 2300, 1455, 2117, 1607, 2443, 554, 1179, 2186, 2303, 2926, 2237,
    525, 735, 863, 2768, 1230, 2572, 556, 3010, 2266, 1684, 1239, 780, 2954, 109, 1292, 1031, 1745, 2688, 3061,
    992, 2596, 941, 892, 1021, 2390, 642, 1868, 2377, 1482, 1540, 540, 1678, 1626, 279, 314, 1173, 2573, 3096,
    48, 667, 1920, 2229, 1041, 2606, 1692, 680, 2746, 568, 3312
};

typedef struct {
    int16_t *bufAddr;
    int16_t *matrix[MLKEM_K_MAX][MLKEM_K_MAX];
    int16_t *vectorS[MLKEM_K_MAX];
    int16_t *vectorE[MLKEM_K_MAX];
    int16_t *vectorT[MLKEM_K_MAX];
} MLKEM_MatrixSt;  // Intermediate data of the key generation and encryption.

typedef struct {
    int16_t *bufAddr;
    int16_t *vectorS[MLKEM_K_MAX];
    int16_t *vectorC1[MLKEM_K_MAX];
    int16_t *vectorC2;
    int16_t *polyM;
} MLKEM_DecVectorSt;  // Intermediate data of the decryption.

static int32_t CreateMatrixBuf(uint8_t k, MLKEM_MatrixSt *st)
{
    // A total of (k * k + 3 * k) data blocks are required. Each block has 512 bytes.
    int16_t *buf = BSL_SAL_Malloc((k * k + 3 * k) * MLKEM_N * sizeof(int16_t));
    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    st->bufAddr = buf;  // Used to release memory.
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            st->matrix[i][j] = buf + (i * k + j) * MLKEM_N;
        }
        // vectorS,vectorE,vectorT use 3 * k data blocks.
        st->vectorS[i] = buf + (k * k + i * 3) * MLKEM_N;
        st->vectorE[i] = buf + (k * k + i * 3 + 1) * MLKEM_N;
        st->vectorT[i] = buf + (k * k + i * 3 + 2) * MLKEM_N;
    }
    return CRYPT_SUCCESS;
}

static void MatrixBufFree(uint8_t k, MLKEM_MatrixSt *st)
{
    // A total of (k * k + 3 * k) data blocks, each block has 512 bytes.
    BSL_SAL_ClearFree(st->bufAddr, (k * k + 3 * k) * MLKEM_N * sizeof(int16_t));
}

static int32_t CreateDecVectorBuf(uint8_t k, MLKEM_DecVectorSt *st)
{
    // A total of (k * 2 + 2) data blocks are required. Each block has 512 bytes.
    int16_t *buf = BSL_SAL_Malloc((k * 2 + 2) * MLKEM_N * sizeof(int16_t));
    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    st->bufAddr = buf;  // Used to release memory.
    for (uint8_t i = 0; i < k; i++) {
        st->vectorS[i] = buf + (i) * MLKEM_N;
        st->vectorC1[i] = buf + (k + i) * MLKEM_N;
    }
    // vectorC2 and polyM use 2 * k data blocks.
    st->vectorC2 = buf + (k * 2) * MLKEM_N;
    st->polyM = buf + (k * 2 + 1) * MLKEM_N;
    return CRYPT_SUCCESS;
}

static void DecVectorBufFree(uint8_t k, MLKEM_DecVectorSt *st)
{
    // A total of (k * 2 + 2) data blocks, each block has 512 bytes.
    BSL_SAL_ClearFree(st->bufAddr, (k * 2 + 2) * MLKEM_N * sizeof(int16_t));
}

// Compress
typedef struct {
    uint64_t barrettMultiplier;  /* round(2 ^ barrettShift / MLKEM_Q) */
    uint16_t barrettShift;
    uint16_t halfQ;              /* rounded (MLKEM_Q / 2) down or up */
    uint8_t  bits;
} MLKEM_BARRET_REDUCE;

// The values of du and dv are from NIST.FIPS.203 Table 2.
static const MLKEM_BARRET_REDUCE MLKEM_BARRETT_TABLE[] = {
    {80635   /* round(2^28/MLKEM_Q) */, 28, 1665 /* Ceil(MLKEM_Q/2)  */, 1},
    {1290167 /* round(2^32/MLKEM_Q) */, 32, 1665 /* Ceil(MLKEM_Q/2)  */, 10},  // 10 is mlkem768 du
    {80635   /* round(2^28/MLKEM_Q) */, 28, 1665 /* Ceil(MLKEM_Q/2)  */, 4},   // 4 is mlkem768 dv
    {40318   /* round(2^27/MLKEM_Q) */, 27, 1664 /* Floor(MLKEM_Q/2) */, 5},   // 5 is mlkem1024 dv
    {645084  /* round(2^31/MLKEM_Q) */, 31, 1664 /* Floor(MLKEM_Q/2) */, 11}   // 11 is mlkem1024 du
};

static int16_t DivMlKemQ(uint16_t x, uint8_t bits, uint16_t halfQ, uint16_t barrettShift, uint64_t barrettMultiplier)
{
    uint64_t round = ((uint64_t)x << bits) + halfQ;
    round *= barrettMultiplier;
    round >>= barrettShift;
    return (int16_t)(round & ((1 << bits) - 1));
}

static int16_t Compress(int16_t x, uint8_t d)
{
    int16_t value = 0;
    uint16_t t = (uint16_t)(x + MLKEM_Q) % MLKEM_Q;
    /* Computing (x << d) / MLKEM_Q by Barret Reduce */
    for (uint32_t i = 0; i < sizeof(MLKEM_BARRETT_TABLE) / sizeof(MLKEM_BARRET_REDUCE); i++) {
        if (d == MLKEM_BARRETT_TABLE[i].bits) {
            value = DivMlKemQ(t,
                MLKEM_BARRETT_TABLE[i].bits,
                MLKEM_BARRETT_TABLE[i].halfQ,
                MLKEM_BARRETT_TABLE[i].barrettShift,
                MLKEM_BARRETT_TABLE[i].barrettMultiplier);
            break;
        }
    }
    return value;
}

// DeCompress
static int16_t DeCompress(int16_t x, uint8_t bits)
{
    uint32_t product = (uint32_t)x * MLKEM_Q;
    uint32_t power = 1 << bits;
    return (int16_t)((product >> bits) + ((product & (power - 1)) >> (bits - 1)));
}

// hash functions
static int32_t HashFuncH(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHA3_256, libCtx, NULL, in, inLen, out, &len, libCtx != NULL);
}

static int32_t HashFuncG(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHA3_512, libCtx, NULL, in, inLen, out, &len, libCtx != NULL);
}

static int32_t HashFuncXOF(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHAKE128, libCtx, NULL, in, inLen, out, &len, libCtx != NULL);
}

static int32_t HashFuncJ(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHAKE256, libCtx, NULL, in, inLen, out, &len, libCtx != NULL);
}

static int32_t PRF(void *libCtx, uint8_t *extSeed, uint32_t extSeedLen, uint8_t *outBuf, uint32_t bufLen)
{
    uint32_t len = bufLen;
    return EAL_Md(CRYPT_MD_SHAKE256, libCtx, NULL, extSeed, extSeedLen, outBuf, &len, libCtx != NULL);
}

static int32_t Parse(uint16_t *polyNtt, uint8_t *arrayB, uint32_t arrayLen, uint32_t n)
{
    uint32_t i = 0;
    uint32_t j = 0;
    while (j < n) {
        if (i + 3 > arrayLen) {  // 3 bytes of arrayB are read in each round.
            BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_KEYLEN_ERROR);
            return CRYPT_MLKEM_KEYLEN_ERROR;
        }
        // The 4 bits of each byte are combined with the 8 bits of another byte into 12 bits.
        uint16_t d1 = ((uint16_t)arrayB[i]) + (((uint16_t)arrayB[i + 1] & 0x0f) << 8);  // 4 bits.
        uint16_t d2 = (((uint16_t)arrayB[i + 1]) >> 4) + (((uint16_t)arrayB[i + 2]) << 4);
        if (d1 < MLKEM_Q) {
            polyNtt[j] = d1;
            j++;
        }
        if (d2 < MLKEM_Q && j < n) {
            polyNtt[j] = d2;
            j++;
        }
        i += 3;  // 3 bytes are processed in each round.
    }
    return CRYPT_SUCCESS;
}

static void EncodeBits1(uint8_t *r, uint16_t *polyF)
{
    for (uint32_t i = 0; i < MLKEM_N / BITS_OF_BYTE; i++) {
        r[i] = (uint8_t)polyF[BITS_OF_BYTE * i];
        for (uint32_t j = 1; j < BITS_OF_BYTE; j++) {
            r[i] = (uint8_t)(polyF[BITS_OF_BYTE * i + j] << j) | r[i];
        }
    }
}

static void EncodeBits4(uint8_t *r, uint16_t *polyF)
{
    for (uint32_t i = 0; i < MLKEM_N / 2; i++) { // Two 4 bits are combined into 1 byte.
        r[i] = ((uint8_t)polyF[2 * i] | ((uint8_t)polyF[2 * i + 1] << 4));
    }
}

static void EncodeBits5(uint8_t *r, uint16_t *polyF)
{
    uint32_t indexR;
    uint32_t indexF;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++) {
        indexR = 5 * i;  // Each element in polyF has 5 bits.
        indexF = 8 * i;  // Each element in r has 8 bits.
        // 8 polyF elements are padded to 5 bytes.
        r[indexR + 0] = (uint8_t)(polyF[indexF] | (polyF[indexF + 1] << 5));
        r[indexR + 1] =
            (uint8_t)((polyF[indexF + 1] >> 3) | (polyF[indexF + 2] << 2) | (polyF[indexF + 3] << 7));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 3] >> 1) | (polyF[indexF + 4] << 4));
        r[indexR + 3] =
            (uint8_t)((polyF[indexF + 4] >> 4) | (polyF[indexF + 5] << 1) | (polyF[indexF + 6] << 6));
        r[indexR + 4] = (uint8_t)((polyF[indexF + 6] >> 2) | (polyF[indexF + 7] << 3));
    }
}

static void EncodeBits10(uint8_t *r, uint16_t *polyF)
{
    uint32_t indexR;
    uint32_t indexF;
    for (uint32_t i = 0; i < MLKEM_N / 4; i++) {
        // 4 polyF elements are padded to 5 bytes.
        indexR = 5 * i;
        indexF = 4 * i;
        r[indexR + 0] = (uint8_t)polyF[indexF];
        r[indexR + 1] = (uint8_t)((polyF[indexF] >> 8) | (polyF[indexF + 1] << 2));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 1] >> 6) | (polyF[indexF + 2] << 4));
        r[indexR + 3] = (uint8_t)((polyF[indexF + 2] >> 4) | (polyF[indexF + 3] << 6));
        r[indexR + 4] = (uint8_t)(polyF[indexF + 3] >> 2);
    }
}

static void EncodeBits11(uint8_t *r, uint16_t *polyF)
{
    uint32_t indexR;
    uint32_t indexF;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++) {
        // 8 polyF elements are padded to 11 bytes.
        indexR = 11 * i;
        indexF = 8 * i;
        r[indexR + 0] = (uint8_t)polyF[indexF];
        r[indexR + 1] = (uint8_t)((polyF[indexF] >> 8) | (polyF[indexF + 1] << 3));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 1] >> 5) | (polyF[indexF + 2] << 6));
        r[indexR + 3] = (uint8_t)((polyF[indexF + 2] >> 2));
        r[indexR + 4] = (uint8_t)((polyF[indexF + 2] >> 10) | (polyF[indexF + 3] << 1));
        r[indexR + 5] = (uint8_t)((polyF[indexF + 3] >> 7) | (polyF[indexF + 4] << 4));
        r[indexR + 6] = (uint8_t)((polyF[indexF + 4] >> 4) | (polyF[indexF + 5] << 7));
        r[indexR + 7] = (uint8_t)((polyF[indexF + 5] >> 1));
        r[indexR + 8] = (uint8_t)((polyF[indexF + 5] >> 9) | (polyF[indexF + 6] << 2));
        r[indexR + 9] = (uint8_t)((polyF[indexF + 6] >> 6) | (polyF[indexF + 7] << 5));
        r[indexR + 10] = (uint8_t)(polyF[indexF + 7] >> 3);
    }
}

static void EncodeBits12(uint8_t *r, uint16_t *polyF)
{
    uint32_t i;
    uint16_t t0;
    uint16_t t1;
    for (i = 0; i < MLKEM_N / 2; i++) {
        // 2 polyF elements are padded to 3 bytes.
        t0 = polyF[2 * i];
        t1 = polyF[2 * i + 1];
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

// Encodes an array of d-bit integers into a byte array for 1 ≤ d ≤ 12.
static void ByteEncode(uint8_t *r, int16_t *polyF, uint8_t bit)
{
    switch (bit) {  // Valid bits of each element in polyF.
        case 1:    // 1 Used for K-PKE.Decrypt Step 7.
            EncodeBits1(r, (uint16_t *)polyF);
            break;
        case 4:    // From FIPS 203 Table 2, dv = 4
            EncodeBits4(r, (uint16_t *)polyF);
            break;
        case 5:    // dv = 5
            EncodeBits5(r, (uint16_t *)polyF);
            break;
        case 10:   // du = 10
            EncodeBits10(r, (uint16_t *)polyF);
            break;
        case 11:    // du = 11
            EncodeBits11(r, (uint16_t *)polyF);
            break;
        case 12:    // 12 Used for K-PKE.KeyGen Step 19.
            EncodeBits12(r, (uint16_t *)polyF);
            break;
        default:
            break;
    }
}

static void DecodeBits1(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    uint32_t j;
    for (i = 0; i < MLKEM_N / BITS_OF_BYTE; i++) {
        // 1 byte data is decoded into 8 polyF elements.
        for (j = 0; j < BITS_OF_BYTE; j++) {
            polyF[BITS_OF_BYTE * i + j] = (a[i] >> j) & 0x01;
        }
    }
}

static void DecodeBits4(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    for (i = 0; i < MLKEM_N / 2; i++) {
        // 1 byte data is decoded into 2 polyF elements.
        polyF[2 * i] = a[i] & 0xF;
        polyF[2 * i + 1] = (a[i] >> 4) & 0xF;
    }
}

static void DecodeBits5(int16_t *polyF, const uint8_t *a)
{
    uint32_t indexF;
    uint32_t indexA;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++) {
        // 8 byte data is decoded into 5 polyF elements.
        indexF = 8 * i;
        indexA = 5 * i;
        // value & 0x1F is used to obtain 5 bits.
        polyF[indexF + 0] = ((a[indexA + 0] >> 0)) & 0x1F;
        polyF[indexF + 1] = ((a[indexA + 0] >> 5) | (a[indexA + 1] << 3)) & 0x1F;
        polyF[indexF + 2] = ((a[indexA + 1] >> 2)) & 0x1F;
        polyF[indexF + 3] = ((a[indexA + 1] >> 7) | (a[indexA + 2] << 1)) & 0x1F;
        polyF[indexF + 4] = ((a[indexA + 2] >> 4) | (a[indexA + 3] << 4)) & 0x1F;
        polyF[indexF + 5] = ((a[indexA + 3] >> 1)) & 0x1F;
        polyF[indexF + 6] = ((a[indexA + 3] >> 6) | (a[indexA + 4] << 2)) & 0x1F;
        polyF[indexF + 7] = ((a[indexA + 4] >> 3)) & 0x1F;
    }
}

static void DecodeBits10(int16_t *polyF, const uint8_t *a)
{
    uint32_t indexF;
    uint32_t indexA;
    for (uint32_t i = 0; i < MLKEM_N / 4; i++) {
        // 5 byte data is decoded into 4 polyF elements.
        indexF = 4 * i;
        indexA = 5 * i;
        // value & 0x3FF is used to obtain 10 bits.
        polyF[indexF + 0] = ((a[indexA + 0] >> 0) | ((uint16_t)a[indexA + 1] << 8)) & 0x3FF;
        polyF[indexF + 1] = ((a[indexA + 1] >> 2) | ((uint16_t)a[indexA + 2] << 6)) & 0x3FF;
        polyF[indexF + 2] = ((a[indexA + 2] >> 4) | ((uint16_t)a[indexA + 3] << 4)) & 0x3FF;
        polyF[indexF + 3] = ((a[indexA + 3] >> 6) | ((uint16_t)a[indexA + 4] << 2)) & 0x3FF;
    }
}

static void DecodeBits11(int16_t *polyF, const uint8_t *a)
{
    uint32_t indexF;
    uint32_t indexA;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++) {
        // use type conversion because 11 > 8
        indexF = 8 * i;
        indexA = 11 * i;
        // value & 0x7FF is used to obtain 11 bits.
        polyF[indexF + 0] = ((a[indexA + 0] >> 0) | ((uint16_t)a[indexA + 1] << 8)) & 0x7FF;
        polyF[indexF + 1] = ((a[indexA + 1] >> 3) | ((uint16_t)a[indexA + 2] << 5)) & 0x7FF;
        polyF[indexF + 2] = ((a[indexA + 2] >> 6) | ((uint16_t)a[indexA + 3] << 2) |
            ((uint16_t)a[indexA + 4] << 10)) & 0x7FF;
        polyF[indexF + 3] = ((a[indexA + 4] >> 1) | ((uint16_t)a[indexA + 5] << 7)) & 0x7FF;
        polyF[indexF + 4] = ((a[indexA + 5] >> 4) | ((uint16_t)a[indexA + 6] << 4)) & 0x7FF;
        polyF[indexF + 5] = ((a[indexA + 6] >> 7) | ((uint16_t)a[indexA + 7] << 1) |
            ((uint16_t)a[indexA + 8] << 9)) & 0x7FF;
        polyF[indexF + 6] = ((a[indexA + 8] >> 2) | ((uint16_t)a[indexA + 9] << 6)) & 0x7FF;
        polyF[indexF + 7] = ((a[indexA + 9] >> 5) | ((uint16_t)a[indexA + 10] << 3)) & 0x7FF;
    }
}

static int32_t DecodeBits12(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    for (i = 0; i < MLKEM_N / 2; i++) {
        // 3 byte data is decoded into 2 polyF elements, value & 0xFFF is used to obtain 12 bits.
        polyF[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        polyF[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
        /* According to Section 7.2 of NIST.FIPS.203, when decapsulating, use ByteDecode and ByteEncode
         * to check that the data does not change after decoding and re-encoding. This is equivalent to
         * checking that there is no data that exceeds the modulus q after decoding.
         */
        if (polyF[2 * i] >= MLKEM_Q || polyF[2 * i + 1] >= MLKEM_Q) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
    }
    return CRYPT_SUCCESS;
}

// Decodes a byte array into an array of d-bit integers for 1 ≤ d ≤ 12.
static void ByteDecode(int16_t *polyF, const uint8_t *a, uint8_t bit)
{
    switch (bit) {
        case 1:
            DecodeBits1(polyF, a);
            break;
        case 4:
            DecodeBits4(polyF, a);
            break;
        case 5:
            DecodeBits5(polyF, a);
            break;
        case 10:
            DecodeBits10(polyF, a);
            break;
        case 11:
            DecodeBits11(polyF, a);
            break;
        case 12:
            (void)DecodeBits12(polyF, a);
            break;
        default:
            break;
    }
}

static int32_t GenMatrix(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *digest,
    int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX], bool isEnc)
{
    uint8_t k = ctx->info->k;
    uint8_t p[MLKEM_SEED_LEN + 2];  // Reserved lengths of i and j is 2 byte.
    uint8_t xofOut[MLKEM_XOF_OUTPUT_LENGTH];

    (void)memcpy_s(p, MLKEM_SEED_LEN, digest, MLKEM_SEED_LEN);
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            if (isEnc) {
                p[MLKEM_SEED_LEN] = i;
                p[MLKEM_SEED_LEN + 1] = j;
            } else {
                p[MLKEM_SEED_LEN] = j;
                p[MLKEM_SEED_LEN + 1] = i;
            }
            int32_t ret = HashFuncXOF(ctx->libCtx, p, MLKEM_SEED_LEN + 2, xofOut, MLKEM_XOF_OUTPUT_LENGTH);
            RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
            ret = Parse((uint16_t *)polyMatrix[i][j], xofOut, MLKEM_XOF_OUTPUT_LENGTH, MLKEM_N);
            RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, int16_t *polyS[], uint8_t *nonce)
{
    uint8_t q[MLKEM_SEED_LEN + 1] = { 0 };  // Reserved lengths of nonce is 1 byte.
    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX] = { 0 };
    (void)memcpy_s(q, MLKEM_SEED_LEN, digest, MLKEM_SEED_LEN);

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = *nonce;
        int32_t ret = PRF(ctx->libCtx, q, MLKEM_SEED_LEN + 1, prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX);
        RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
        MLKEM_SamplePolyCBD(polyS[i], prfOut, ctx->info->eta1);
        *nonce = *nonce + 1;
        MLKEM_ComputNTT(polyS[i], PRE_COMPUT_TABLE_NTT, MLKEM_N_HALF);
    }
    return CRYPT_SUCCESS;
}

static int32_t SampleEta2(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, int16_t *polyS[], uint8_t *nonce)
{
    uint8_t q[MLKEM_SEED_LEN + 1] = { 0 };  // Reserved lengths of nonce is 1 byte.
    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX] = { 0 };
    (void)memcpy_s(q, MLKEM_SEED_LEN, digest, MLKEM_SEED_LEN);

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = *nonce;
        int32_t ret = PRF(ctx->libCtx, q, MLKEM_SEED_LEN + 1, prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX);
        RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
        MLKEM_SamplePolyCBD(polyS[i], prfOut, ctx->info->eta2);
        *nonce = *nonce + 1;
    }
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 13 K-PKE.KeyGen(𝑑)
static int32_t PkeKeyGen(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *pk, uint8_t *dk, uint8_t *d)
{
    uint8_t k = ctx->info->k;
    uint8_t nonce = 0;
    uint8_t seed[MLKEM_SEED_LEN + 1] = { 0 };  // Reserved lengths of k is 1 byte.
    uint8_t digest[CRYPT_SHA3_512_DIGESTSIZE] = { 0 };

    // (p,q) = G(d || k)
    (void)memcpy_s(seed, MLKEM_SEED_LEN + 1, d, MLKEM_SEED_LEN);
    seed[MLKEM_SEED_LEN] = k;
    int32_t ret = HashFuncG(ctx->libCtx, seed, MLKEM_SEED_LEN + 1, digest, CRYPT_SHA3_512_DIGESTSIZE);  // Step 1
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // expand 32+1 bytes to two pseudorandom 32-byte seeds
    uint8_t *p = digest;
    uint8_t *q = digest + CRYPT_SHA3_512_DIGESTSIZE / 2;

    MLKEM_MatrixSt st = { 0 };
    ret = CreateMatrixBuf(k, &st);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    GOTO_ERR_IF(GenMatrix(ctx, p, st.matrix, false), ret);  // Step 3 - 7
    GOTO_ERR_IF(SampleEta1(ctx, q, st.vectorS, &nonce), ret);  // Step 8 - 11
    GOTO_ERR_IF(SampleEta1(ctx, q, st.vectorE, &nonce), ret);  // Step 12 - 15
    for (uint8_t i = 0; i < k; i++) {  // Step 18
        MLKEM_MatrixMulAdd(k, st.matrix[i], st.vectorS, st.vectorE[i], st.vectorT[i], PRE_COMPUT_TABLE_NTT);
    }
    // output: pk, dk,  ekPKE ← ByteEncode12(𝐭)‖p.
    for (uint8_t i = 0; i < k; i++) {
        // Step 19
        ByteEncode(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, st.vectorT[i], MLKEM_BITS_OF_Q);
        // Step 20
        ByteEncode(dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, st.vectorS[i], MLKEM_BITS_OF_Q);
    }
    // The buffer of pk is sufficient, check it before calling this function.
    (void)memcpy_s(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * k, MLKEM_SEED_LEN, p, MLKEM_SEED_LEN);

ERR:
    MatrixBufFree(k, &st);
    return ret;
}

// NIST.FIPS.203 Algorithm 14 K-PKE.Encrypt(ekPKE,𝑚,𝑟)
static int32_t PkeEncrypt(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, const uint8_t *ek, uint8_t *m, uint8_t *r)
{
    uint8_t i;
    uint32_t n;
    uint8_t k = ctx->info->k;
    uint8_t nonce = 0; // Step 1
    uint8_t seedE[MLKEM_SEED_LEN + 1];
    uint8_t bufEncE[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX];
    int16_t polyVectorE2[MLKEM_N] = { 0 };
    int16_t polyVectorC2[MLKEM_N] = { 0 };
    int16_t polyVectorM[MLKEM_N] = { 0 };

    MLKEM_MatrixSt st = { 0 };
    int32_t ret = CreateMatrixBuf(k, &st);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    GOTO_ERR_IF(GenMatrix(ctx, ek + MLKEM_CIPHER_LEN * k, st.matrix, true), ret);  // Step 3 - 8
    GOTO_ERR_IF(SampleEta1(ctx, r, st.vectorS, &nonce), ret);  // Step 9 - 12
    GOTO_ERR_IF(SampleEta2(ctx, r, st.vectorE, &nonce), ret);  // Step 13 - 16

    // Step 17
    (void)memcpy_s(seedE, MLKEM_SEED_LEN, r, MLKEM_SEED_LEN);
    seedE[MLKEM_SEED_LEN] = nonce;
    GOTO_ERR_IF(PRF(ctx->libCtx, seedE, MLKEM_SEED_LEN + 1, bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2), ret);
    MLKEM_SamplePolyCBD(polyVectorE2, bufEncE, ctx->info->eta2);

    // Step 18
    for (i = 0; i < k; i++) {
        MLKEM_MatrixMulAdd(k, st.matrix[i], st.vectorS, NULL, st.vectorT[i], PRE_COMPUT_TABLE_NTT);
    }

    // Step 19
    for (i = 0; i < k; i++) {
        MLKEM_ComputINTT(st.vectorT[i], PRE_COMPUT_TABLE_INTT, MLKEM_N_HALF);
        for (n = 0; n < MLKEM_N; n++) {
            st.vectorT[i][n] = Compress(st.vectorT[i][n] + st.vectorE[i][n], ctx->info->du);
        }
    }

    // Step 21
    for (i = 0; i < k; i++) {
        GOTO_ERR_IF(DecodeBits12(st.vectorE[i], ek + MLKEM_CIPHER_LEN * i), ret);
    }
    MLKEM_MatrixMulAdd(k, st.vectorE, st.vectorS, NULL, polyVectorC2, PRE_COMPUT_TABLE_NTT);

    ByteDecode(polyVectorM, m, 1);
    MLKEM_ComputINTT(polyVectorC2, PRE_COMPUT_TABLE_INTT, MLKEM_N_HALF);

    for (n = 0; n < MLKEM_N; n++) {
        polyVectorM[n] = DeCompress(polyVectorM[n], 1); // Step 20
        // Step 22
        polyVectorC2[n] = Compress(polyVectorC2[n] + polyVectorE2[n] + polyVectorM[n], ctx->info->dv);
    }

    // Step 22
    for (i = 0; i < k; i++) {
        ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * i, st.vectorT[i], ctx->info->du);
    }
    // Step 23
    ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * k, polyVectorC2, ctx->info->dv);
ERR:
    MatrixBufFree(k, &st);
    return ret;
}

// NIST.FIPS.203 Algorithm 15 K-PKE.Decrypt(dkPKE, 𝑐)
static int32_t PkeDecrypt(const CRYPT_MlKemInfo *algInfo, uint8_t *result, const uint8_t *dk,
    const uint8_t *ciphertext)
{
    uint8_t i;
    uint8_t k = algInfo->k;
    uint32_t n;

    MLKEM_DecVectorSt st = { 0 };
    int32_t ret = CreateDecVectorBuf(k, &st);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    for (i = 0; i < k; i++) {
        ByteDecode(st.vectorC1[i], ciphertext + MLKEM_ENCODE_BLOCKSIZE * algInfo->du * i, algInfo->du);  // Step 3
        ByteDecode(st.vectorS[i], dk + MLKEM_ENCODE_BLOCKSIZE * MLKEM_BITS_OF_Q * i, MLKEM_BITS_OF_Q);   // Step 5
    }
    ByteDecode(st.vectorC2, ciphertext + MLKEM_ENCODE_BLOCKSIZE * algInfo->du * k, algInfo->dv);   // Step 4

    for (i = 0; i < k; i++) {
        for (n = 0; n < MLKEM_N; n++) {
            st.vectorC1[i][n] = DeCompress(st.vectorC1[i][n], algInfo->du);  // Step 3
            if (i == 0) {
                st.vectorC2[n] = DeCompress(st.vectorC2[n], algInfo->dv);  // Step 4
            }
        }
        MLKEM_ComputNTT(st.vectorC1[i], PRE_COMPUT_TABLE_NTT, MLKEM_N_HALF);
    }

    MLKEM_MatrixMulAdd(k, st.vectorS, st.vectorC1, NULL, st.polyM, PRE_COMPUT_TABLE_NTT);      // Step 6

    // polyM = intt(polyM)
    MLKEM_ComputINTT(st.polyM, PRE_COMPUT_TABLE_INTT, MLKEM_N_HALF);

    // c2 - polyM
    for (n = 0; n < MLKEM_N; n++) {
        st.polyM[n] = Compress(st.vectorC2[n] - st.polyM[n], 1);
    }

    ByteEncode(result, st.polyM, 1);  // Step 7
    DecVectorBufFree(k, &st);
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 16 ML-KEM.KeyGen_internal(𝑑,𝑧)
int32_t MLKEM_KeyGenInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *d, uint8_t *z)
{
    const CRYPT_MlKemInfo *algInfo = ctx->info;
    uint32_t dkPkeLen = MLKEM_CIPHER_LEN * algInfo->k;

    // (ekPKE,dkPKE) ← K-PKE.KeyGen(𝑑)
    int32_t ret = PkeKeyGen(ctx, ctx->ek, ctx->dk, d);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // dk ← (dkPKE‖ek‖H(ek)‖𝑧)
    if (memcpy_s(ctx->dk + dkPkeLen, ctx->dkLen - dkPkeLen, ctx->ek, ctx->ekLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }

    ret = HashFuncH(ctx->libCtx, ctx->ek, ctx->ekLen, ctx->dk + dkPkeLen + ctx->ekLen, CRYPT_SHA3_256_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    if (memcpy_s(ctx->dk + dkPkeLen + ctx->ekLen + CRYPT_SHA3_256_DIGESTSIZE,
        ctx->dkLen - (dkPkeLen + ctx->ekLen + CRYPT_SHA3_256_DIGESTSIZE), z, MLKEM_SEED_LEN) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 17 ML-KEM.Encaps_internal(ek,𝑚)
int32_t MLKEM_EncapsInternal(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *sk, uint32_t *skLen,
    uint8_t *m)
{
    uint8_t mhek[MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE];  // m and H(ek)
    uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE];    // K and r

    //  (K,r) = G(m || H(ek))
    (void)memcpy_s(mhek, MLKEM_SEED_LEN, m, MLKEM_SEED_LEN);
    int32_t ret = HashFuncH(ctx->libCtx, ctx->ek, ctx->ekLen, mhek + MLKEM_SEED_LEN, CRYPT_SHA3_256_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    ret = HashFuncG(ctx->libCtx, mhek, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE, kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    (void)memcpy_s(sk, *skLen, kr, MLKEM_SHARED_KEY_LEN);

    // 𝑐 ← K-PKE.Encrypt(ek,𝑚,𝑟)
    ret = PkeEncrypt(ctx, ct, ctx->ek, m, kr + MLKEM_SHARED_KEY_LEN);
    BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    *ctLen = ctx->info->cipherLen;
    *skLen = ctx->info->sharedLen;
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 18 ML-KEM.Decaps_internal(dk, 𝑐)
int32_t MLKEM_DecapsInternal(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t ctLen, uint8_t *sk, uint32_t *skLen)
{
    const CRYPT_MlKemInfo *algInfo = ctx->info;
    const uint8_t *dk = ctx->dk;                            // Step 1  dkPKE ← dk[0 : 384k]
    const uint8_t *ek = dk + MLKEM_CIPHER_LEN * algInfo->k; // Step 2  ekPKE ← dk[384k : 768k +32]
    const uint8_t *h = ek + algInfo->encapsKeyLen;          // Step 3  h ← dk[768k +32 : 768k +64]
    const uint8_t *z = h + MLKEM_SEED_LEN;                  // Step 4  z ← dk[768k +64 : 768k +96]

    uint8_t mh[MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE];    // m′ and h
    uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE];    // K' and r'

    // NIST.FIPS.203: test = H(dk[384k : 768k + 32]) and check test == h
    int32_t ret = HashFuncH(ctx->libCtx, ek, 384 * ctx->info->k + 32, mh, CRYPT_SHA3_256_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    if (memcmp(h, mh, CRYPT_SHA3_256_DIGESTSIZE) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_INVALID_PRVKEY);
        return CRYPT_MLKEM_INVALID_PRVKEY;
    }

    ret = PkeDecrypt(algInfo, mh, dk, ct);  // Step 5: 𝑚′ ← K-PKE.Decrypt(dkPKE, 𝑐)
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    // Step 6: (K′,r′) ← G(m′ || h)
    (void)memcpy_s(mh + MLKEM_SEED_LEN, CRYPT_SHA3_256_DIGESTSIZE, h, CRYPT_SHA3_256_DIGESTSIZE);
    ret = HashFuncG(ctx->libCtx, mh, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE, kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    // Step 8: 𝑐′ ← K-PKE.Encrypt(ekPKE,𝑚′,𝑟′)
    uint8_t *r = kr + MLKEM_SHARED_KEY_LEN;
    uint8_t *newCt = BSL_SAL_Malloc(ctLen + MLKEM_SEED_LEN);
    RETURN_RET_IF(newCt == NULL, BSL_MALLOC_FAIL);
    GOTO_ERR_IF(PkeEncrypt(ctx, newCt, ek, mh, r), ret);

    // Step 9: if c != c′
    if (memcmp(ct, newCt, ctLen) == 0) {
        (void)memcpy_s(sk, *skLen, kr, MLKEM_SHARED_KEY_LEN);
    } else {
        // Step 7: K = J(z || c)
        (void)memcpy_s(newCt, ctLen + MLKEM_SEED_LEN, z, MLKEM_SEED_LEN);
        (void)memcpy_s(newCt + MLKEM_SEED_LEN, ctLen, ct, ctLen);
        GOTO_ERR_IF(HashFuncJ(ctx->libCtx, newCt, ctLen + MLKEM_SEED_LEN, sk, MLKEM_SHARED_KEY_LEN), ret);
    }
    *skLen = MLKEM_SHARED_KEY_LEN;
ERR:
    BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
    BSL_SAL_Free(newCt);
    return ret;
}

#endif