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
#define MLKEM_ETA1_MAX    3
#define MLKEM_ETA2_MAX    2

typedef void (*CompressFunc)(int16_t *x);

/*
 * zeta converted to Plantard domin
 * x = (zeta * (-2^(2l)) mod q) * (q^-1 mod 2^(2l))
 * quotient = round(x / 2^(2l))
 * x -= quotient * 2^(2l)
 */
static const int32_t CONST_ZETA_POWER_1[MLKEM_N_HALF] = {
    1290168, -2064267850, -966335387, -51606696, -886345008, 812805467, -1847519726, 1094061961,
    1370157786, -1819136043, 249002310, 1028263423, -700560901, -89021551, 734105255, -2042335004,
    381889553, -1137927652, 1727534158, 1904287092, -365117376, 72249375, -1404992305, 1719793153,
    1839778722, -1593356746, 690239563, -576704830, -1207596692, -580575332, -1748176835, 1059227441,
    372858381, 427045412, -98052722, -2029433330, 1544330386, -1322421591, -1357256111, -1643673275,
    838608815, -1744306333, -1052776603, 815385801, -598637676, 42575525, 1703020977, -1824296712,
    -1303069080, 1851390229, 1041165097, 583155668, 1855260731, -594767174, 1979116802, -1195985185,
    -879894171, -918599193, 1910737929, 836028480, -1103093132, -282546662, 1583035408, 1174052340,
    21932846, -732815086, 752167598, -877313836, 2112004045, 932791035, -1343064270, 1419184148,
    1817845876, -860541660, -61928035, 300609006, 975366560, -1513366367, -405112565, -359956706,
    -2097812202, 2130066389, -696690399, -1986857805, -1912028096, 1228239371, 1884934581, -828287474,
    1211467195, -1317260921, -1150829326, -1214047529, 945692709, -1279846067, 345764865, 826997308,
    2043625172, -1330162596, -1666896289, -140628247, 483812778, -1006330577, -1598517416, 2122325384,
    1371447954, 411563403, -717333077, 976656727, -1586905909, 723783916, -1113414471, -948273043,
    -677337888, 1408862808, 519937465, 1323711759, 1474661346, -1521107372, -714752743, 1143088323,
    -2073299022, 1563682897, -1877193576, 1327582262, -1572714068, -508325958, 1141798155, -1515946702,
};

static const int32_t CONST_ZETA_POWER_2[MLKEM_N_HALF] = {
    21932846, -21932845, -732815086, 732815087, 752167598, -752167597, -877313836, 877313837,
    2112004045, -2112004044, 932791035, -932791034, -1343064270, 1343064271, 1419184148, -1419184147,
    1817845876, -1817845875, -860541660, 860541661, -61928035, 61928036, 300609006, -300609005,
    975366560, -975366559, -1513366367, 1513366368, -405112565, 405112566, -359956706, 359956707,
    -2097812202, 2097812203, 2130066389, -2130066388, -696690399, 696690400, -1986857805, 1986857806,
    -1912028096, 1912028097, 1228239371, -1228239370, 1884934581, -1884934580, -828287474, 828287475,
    1211467195, -1211467194, -1317260921, 1317260922, -1150829326, 1150829327, -1214047529, 1214047530,
    945692709, -945692708, -1279846067, 1279846068, 345764865, -345764864, 826997308, -826997307,
    2043625172, -2043625171, -1330162596, 1330162597, -1666896289, 1666896290, -140628247, 140628248,
    483812778, -483812777, -1006330577, 1006330578, -1598517416, 1598517417, 2122325384, -2122325383,
    1371447954, -1371447953, 411563403, -411563402, -717333077, 717333078, 976656727, -976656726,
    -1586905909, 1586905910, 723783916, -723783915, -1113414471, 1113414472, -948273043, 948273044,
    -677337888, 677337889, 1408862808, -1408862807, 519937465, -519937464, 1323711759, -1323711758,
    1474661346, -1474661345, -1521107372, 1521107373, -714752743, 714752744, 1143088323, -1143088322,
    -2073299022, 2073299023, 1563682897, -1563682896, -1877193576, 1877193577, 1327582262, -1327582261,
    -1572714068, 1572714069, -508325958, 508325959, 1141798155, -1141798154, -1515946702, 1515946703,
};

int32_t MLKEM_CreateMatrixBuf(uint8_t k, MLKEM_MatrixSt *st)
{
    // A total of (k * k + 3 * k) data blocks are required. Each block has 512 bytes.
    if (st->bufAddr != NULL) {
        return CRYPT_SUCCESS;
    }
    int16_t *buf = BSL_SAL_Calloc((k * k + 3 * k) * MLKEM_N, sizeof(int16_t));

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

// Compress
// The values of du and dv are from NIST.FIPS.203 Table 2.
static void DivMlKemQBit4(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 41285360; // 2^4 * round(2^33 / q) = 41285360
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0xF);
    }
}

static void DivMlKemQBit5(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 82570720; // 2^5 * round(2^33 / q) = 82570720
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0x1F);
    }
}

static void DivMlKemQBit10(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 2642263040; // 2^10 * round(2^33 / q) = 2642263040
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0x3FF);
    }
}

static void DivMlKemQBit11(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint64_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 5284526080; // 2^11 * round(2^33 / q) = 5284526080
        x[i] = (int16_t)(((tmp + (1ULL << 32)) >> 33) & 0x7FF);
    }
}

static void DivMlKemQBit1(int16_t *x)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint32_t tmp = x[i] + ((x[i] >> 15) & MLKEM_Q);
        tmp = tmp * 1290168; // 2^1 * round(2^31 / q) = 1290168
        x[i] = (int16_t)(((tmp + (1U << 30)) >> 31) & 0x1);
    }
}

static CompressFunc g_compressFuncsTable[] = {
    NULL, DivMlKemQBit1, NULL, NULL, DivMlKemQBit4, DivMlKemQBit5, NULL,
    NULL, NULL, NULL, DivMlKemQBit10, DivMlKemQBit11
};

static void PolyCompress(int16_t *x, uint8_t d)
{
    g_compressFuncsTable[d](x);
}

static void MlkemAddPoly(const int16_t *a, int16_t *b)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        b[i] += a[i];
    }
}

static void MlkemSubPoly(const int16_t *a, int16_t *b)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        b[i] = a[i] - b[i];
    }
}

// DeCompress
static void PolyDeCompress(int16_t *x, uint8_t bits)
{
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        uint32_t product = (uint32_t)x[i] * MLKEM_Q;
        uint32_t power = 1 << bits;
        x[i] = (int16_t)((product >> bits) + ((product & (power - 1)) >> (bits - 1)));
    }
}

// hash functions
static int32_t HashFuncH(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHA3_256, libCtx, NULL, in, inLen, out, &len, false, libCtx != NULL);
}

static int32_t HashFuncG(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHA3_512, libCtx, NULL, in, inLen, out, &len, false, libCtx != NULL);
}

static int32_t HashFuncJ(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    uint32_t len = outLen;
    return EAL_Md(CRYPT_MD_SHAKE256, libCtx, NULL, in, inLen, out, &len, false, libCtx != NULL);
}

static int32_t PRF(void *libCtx, uint8_t *extSeed, uint32_t extSeedLen, uint8_t *outBuf, uint32_t bufLen)
{
    uint32_t len = bufLen;
    return EAL_Md(CRYPT_MD_SHAKE256, libCtx, NULL, extSeed, extSeedLen, outBuf, &len, false, libCtx != NULL);
}

static int32_t Parse(uint16_t *polyNtt, uint8_t *arrayB, uint32_t *curLen)
{
    uint32_t i = 0;
    while (*curLen < MLKEM_N && i < CRYPT_SHAKE128_BLOCKSIZE) {
        // The 4 bits of each byte are combined with the 8 bits of another byte into 12 bits.
        uint16_t d1 = ((uint16_t)arrayB[i]) + (((uint16_t)arrayB[i + 1] & 0x0f) << 8);  // 4 bits.
        uint16_t d2 = (((uint16_t)arrayB[i + 1]) >> 4) + (((uint16_t)arrayB[i + 2]) << 4);

        int32_t mask = (MLKEM_Q - 1 - d1) >> 31;
        polyNtt[*curLen] = (int16_t)(d1 & ~mask);
        *curLen += 1 + mask;

        if (*curLen < MLKEM_N) {
            mask = (MLKEM_Q - 1 - d2) >> 31;
            polyNtt[*curLen] = (int16_t)(d2 & ~mask);
            *curLen += 1 + mask;
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
            for (int32_t i = 0; i < MLKEM_N; ++i) {
                polyF[i] += (polyF[i] >> 15) & MLKEM_Q;
            }
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
         * check that there is no data that exceeds the modulus q after decoding.
         */
        if (polyF[2 * i] >= MLKEM_Q || polyF[2 * i + 1] >= MLKEM_Q) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_DECODE_KEY_OVERFLOW);
            return CRYPT_MLKEM_DECODE_KEY_OVERFLOW;
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
    uint8_t xofOut[CRYPT_SHAKE128_BLOCKSIZE];

    EAL_MdMethod method = {0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    void *provCtx = NULL;
    if (EAL_MdFindMethodEx(CRYPT_MD_SHAKE128, ctx->libCtx, NULL, &method, &provCtx, ctx->libCtx != NULL) == NULL) {
        return CRYPT_EAL_ERR_ALGID;
    }

    void *hashCtx = method.newCtx(provCtx, CRYPT_MD_SHAKE128);
    if (hashCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy_s(p, MLKEM_SEED_LEN, digest, MLKEM_SEED_LEN);
    int32_t ret = CRYPT_SUCCESS;
    uint32_t curLen;
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            if (isEnc) {
                p[MLKEM_SEED_LEN] = i;
                p[MLKEM_SEED_LEN + 1] = j;
            } else {
                p[MLKEM_SEED_LEN] = j;
                p[MLKEM_SEED_LEN + 1] = i;
            }
            curLen = 0;
            GOTO_ERR_IF(method.init(hashCtx, NULL), ret);
            GOTO_ERR_IF(method.update(hashCtx, p, MLKEM_SEED_LEN + 2), ret);
            while (curLen < MLKEM_N) {
                GOTO_ERR_IF(method.squeeze(hashCtx, xofOut, CRYPT_SHAKE128_BLOCKSIZE), ret);
                GOTO_ERR_IF(Parse((uint16_t *)polyMatrix[i][j], xofOut, &curLen), ret);
            }
        }
    }
ERR:
    method.freeCtx(hashCtx);
    return ret;
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
        MLKEM_ComputNTT(polyS[i], CONST_ZETA_POWER_1);
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
static int32_t PkeKeyGen(CRYPT_ML_KEM_Ctx *ctx, uint8_t *pk, uint8_t *dk, uint8_t *d)
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
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    GOTO_ERR_IF(GenMatrix(ctx, p, ctx->keyData.matrix, false), ret);  // Step 3 - 7
    GOTO_ERR_IF(SampleEta1(ctx, q, ctx->keyData.vectorS, &nonce), ret);  // Step 8 - 11
    for (int32_t i = 0; i < k; ++i) {
        for (int32_t j = 0; j < MLKEM_N; ++j) {
            ctx->keyData.vectorS[i][j] = BarrettReduction(ctx->keyData.vectorS[i][j]);
        }
    }
    GOTO_ERR_IF(SampleEta1(ctx, q, ctx->keyData.vectorT, &nonce), ret);  // Step 12 - 15

    int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF];
    MLKEM_ComputeMulCache(k, ctx->keyData.vectorS, mulCache, CONST_ZETA_POWER_2);
    MLKEM_MatrixMulAdd(k, (int16_t **)ctx->keyData.matrix, ctx->keyData.vectorS, ctx->keyData.vectorT,
                       mulCache);
    // output: pk, dk,  ekPKE ← ByteEncode12(𝐭)‖p.
    for (uint8_t i = 0; i < k; i++) {
        // Step 19
        ByteEncode(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, ctx->keyData.vectorT[i], MLKEM_BITS_OF_Q);
        // Step 20
        ByteEncode(dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, ctx->keyData.vectorS[i], MLKEM_BITS_OF_Q);
    }
    // The buffer of pk is sufficient, check it before calling this function.
    (void)memcpy_s(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * k, MLKEM_SEED_LEN, p, MLKEM_SEED_LEN);

ERR:
    return ret;
}

int32_t MLKEM_DecodeDk(CRYPT_ML_KEM_Ctx *ctx, const uint8_t *dk, uint32_t dkLen)
{
    if (ctx == NULL || dk == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return CRYPT_MLKEM_KEYINFO_NOT_SET;
    }
    if (ctx->info->decapsKeyLen != dkLen) {
        return CRYPT_MLKEM_KEYLEN_ERROR;
    }
    uint8_t k = ctx->info->k;
    if (MLKEM_CreateMatrixBuf(k, &ctx->keyData) != CRYPT_SUCCESS) {
        return BSL_MALLOC_FAIL;
    }
    for (int32_t i = 0; i < k; ++i) {
        if (DecodeBits12(ctx->keyData.vectorS[i], dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i) != CRYPT_SUCCESS) {
            return CRYPT_MLKEM_DECODE_KEY_OVERFLOW;
        }
    }
    const uint8_t *ekBuff = dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * k;
    int32_t ret = MLKEM_DecodeEk(ctx, ekBuff, ctx->info->encapsKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

int32_t MLKEM_DecodeEk(CRYPT_ML_KEM_Ctx *ctx, const uint8_t *ek, uint32_t ekLen)
{
    if (ctx == NULL || ek == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return CRYPT_MLKEM_KEYINFO_NOT_SET;
    }
    if (ctx->info->encapsKeyLen != ekLen) {
        return CRYPT_MLKEM_KEYLEN_ERROR;
    }
    uint8_t k = ctx->info->k;
    if (MLKEM_CreateMatrixBuf(k, &ctx->keyData) != CRYPT_SUCCESS) {
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = GenMatrix(ctx, ek + MLKEM_CIPHER_LEN * k, ctx->keyData.matrix, false);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    for (uint8_t i = 0; i < k; i++) {
        ret = DecodeBits12(ctx->keyData.vectorT[i], ek + MLKEM_CIPHER_LEN * i);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 14 K-PKE.Encrypt(ekPKE, m, r)
static int32_t PkeEncrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint8_t *m, uint8_t *r)
{
    uint8_t i;
    uint8_t k = ctx->info->k;
    uint8_t nonce = 0; // Step 1
    uint8_t seedE[MLKEM_SEED_LEN + 1];
    uint8_t bufEncE[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX];
    int16_t polyE2[MLKEM_N] = { 0 };
    int16_t polyC2[MLKEM_N] = { 0 };
    int16_t polyM[MLKEM_N] = { 0 };
    int16_t *polyVecY[MLKEM_K_MAX] = { 0 };
    int16_t *polyVecE1[MLKEM_K_MAX] = { 0 };
    int16_t *polyVecU[MLKEM_K_MAX] = { 0 };
    int16_t *tmpPolyVec = BSL_SAL_Calloc(MLKEM_N * k * 3, sizeof(int16_t));
    if (tmpPolyVec == NULL) {
        return BSL_MALLOC_FAIL;
    }
    // Reference the memory
    for (i = 0; i < k; ++i) {
        polyVecY[i] = tmpPolyVec + MLKEM_N * i;
        polyVecE1[i] = polyVecY[i] + k * MLKEM_N;
        polyVecU[i] = polyVecE1[i] + k * MLKEM_N;
    }
    int32_t ret = 0;
    
    GOTO_ERR_IF(SampleEta1(ctx, r, polyVecY, &nonce), ret);  // Step 9 - 12
    GOTO_ERR_IF(SampleEta2(ctx, r, polyVecE1, &nonce), ret);  // Step 13 - 16

    // Step 17
    (void)memcpy_s(seedE, MLKEM_SEED_LEN, r, MLKEM_SEED_LEN);
    seedE[MLKEM_SEED_LEN] = nonce;
    GOTO_ERR_IF(PRF(ctx->libCtx, seedE, MLKEM_SEED_LEN + 1, bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2), ret);
    MLKEM_SamplePolyCBD(polyE2, bufEncE, ctx->info->eta2);
    // Step 18
    int16_t mulCache[MLKEM_K_MAX][MLKEM_N_HALF];
    MLKEM_ComputeMulCache(k, polyVecY, mulCache, CONST_ZETA_POWER_2);
    MLKEM_TransposeMatrixMulAdd(k, (int16_t **)ctx->keyData.matrix, polyVecY, polyVecU, mulCache);
    // Step 19
    for (i = 0; i < k; i++) {
        MLKEM_ComputINTT(polyVecU[i], CONST_ZETA_POWER_1);
        MlkemAddPoly(polyVecE1[i], polyVecU[i]);
        PolyCompress(polyVecU[i], ctx->info->du);
    }
    // Step 21
    MLKEM_VectorInnerProductAddUseCache(k, ctx->keyData.vectorT, polyVecY, polyC2, mulCache);
    ByteDecode(polyM, m, 1);
    MLKEM_ComputINTT(polyC2, CONST_ZETA_POWER_1);

    PolyDeCompress(polyM, 1); // Step 20
    MlkemAddPoly(polyE2, polyC2);
    MlkemAddPoly(polyM, polyC2);
    // Step 22
    PolyCompress(polyC2, ctx->info->dv);


    // Step 22
    for (i = 0; i < k; i++) {
        ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * i, polyVecU[i], ctx->info->du);
    }
    // Step 23
    ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * k, polyC2, ctx->info->dv);
ERR:
    BSL_SAL_Free(tmpPolyVec);
    return ret;
}


// NIST.FIPS.203 Algorithm 15 K-PKE.Decrypt(dkPKE, 𝑐)
static int32_t PkeDecrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *result, const uint8_t *ciphertext)
{
    uint8_t i;
    uint8_t k = ctx->info->k;
    // tmpPolyVec = polyM || polyC2 || polyVecC1
    int16_t *tmpPolyVec = BSL_SAL_Calloc((k * 2 + 1) * MLKEM_N, sizeof(int16_t));
    if (tmpPolyVec == NULL) {
        return BSL_MALLOC_FAIL;
    }
    int16_t *polyVecC1[MLKEM_K_MAX];
    int16_t *polyC2;
    int16_t *polyM;
    // Reference the stack memory
    polyM = tmpPolyVec;
    polyC2 = tmpPolyVec + MLKEM_N;
    for (i = 0; i < k; ++i) {
        polyVecC1[i] = tmpPolyVec + MLKEM_N * (i + 2);
    }
    for (i = 0; i < k; i++) {
        ByteDecode(polyVecC1[i], ciphertext + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * i, ctx->info->du);  // Step 3
    }
    ByteDecode(polyC2, ciphertext + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * k, ctx->info->dv);   // Step 4
    for (i = 0; i < k; i++) {
        PolyDeCompress(polyVecC1[i], ctx->info->du);  // Step 3
        if (i == 0) {
            PolyDeCompress(polyC2, ctx->info->dv);  // Step 4
        }
        MLKEM_ComputNTT(polyVecC1[i], CONST_ZETA_POWER_1);
    }
    MLKEM_VectorInnerProductAdd(k, ctx->keyData.vectorS, polyVecC1, polyM, CONST_ZETA_POWER_2);
    MLKEM_ComputINTT(polyM, CONST_ZETA_POWER_1);
    // c2 - polyM

    MlkemSubPoly(polyC2, polyM);
    PolyCompress(polyM, 1);

    ByteEncode(result, polyM, 1);  // Step 7
    BSL_SAL_Free(tmpPolyVec);
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 16 ML-KEM.KeyGen_internal(𝑑,𝑧)
int32_t MLKEM_KeyGenInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *d, uint8_t *z)
{
    const CRYPT_MlKemInfo *algInfo = ctx->info;
    uint32_t dkPkeLen = MLKEM_CIPHER_LEN * algInfo->k;
    int32_t ret = MLKEM_CreateMatrixBuf(algInfo->k, &ctx->keyData);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    // (ekPKE,dkPKE) ← K-PKE.KeyGen(𝑑)
    ret = PkeKeyGen(ctx, ctx->ek, ctx->dk, d);
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

    // Store seed (d || z) in context
    ctx->hasSeed = true;
    (void)memcpy_s(ctx->seed, MLKEM_SEED_LEN, d, MLKEM_SEED_LEN);
    (void)memcpy_s(ctx->seed + MLKEM_SEED_LEN, MLKEM_SEED_LEN, z, MLKEM_SEED_LEN);

    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 17 ML-KEM.Encaps_internal(ek,𝑚)
int32_t MLKEM_EncapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *sk, uint32_t *skLen,
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
    ret = PkeEncrypt(ctx, ct, m, kr + MLKEM_SHARED_KEY_LEN);
    BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    *ctLen = ctx->info->cipherLen;
    *skLen = ctx->info->sharedLen;
    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 18 ML-KEM.Decaps_internal(dk, 𝑐)
int32_t MLKEM_DecapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t ctLen, uint8_t *sk, uint32_t *skLen)
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

    ret = PkeDecrypt(ctx, mh, ct);  // Step 5: 𝑚′ ← K-PKE.Decrypt(dkPKE, 𝑐)
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    // Step 6: (K′,r′) ← G(m′ || h)
    (void)memcpy_s(mh + MLKEM_SEED_LEN, CRYPT_SHA3_256_DIGESTSIZE, h, CRYPT_SHA3_256_DIGESTSIZE);
    ret = HashFuncG(ctx->libCtx, mh, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE, kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    // Step 8: 𝑐′ ← K-PKE.Encrypt(ekPKE,𝑚′,𝑟′)
    uint8_t *r = kr + MLKEM_SHARED_KEY_LEN;
    uint8_t *newCt = BSL_SAL_Malloc(ctLen + MLKEM_SEED_LEN);
    RETURN_RET_IF(newCt == NULL, BSL_MALLOC_FAIL);
    GOTO_ERR_IF(PkeEncrypt(ctx, newCt, mh, r), ret);

    // Step 9: if c != c′
    uint8_t mask = 0;
    for (uint32_t i = 0; i < ctLen; i++) {
        mask |= (ct[i] ^ newCt[i]);
    }
    mask = (uint8_t)(((uint16_t)mask - 1) >> 8);
    // Step 7: K = J(z || c)
    (void)memcpy_s(newCt, ctLen + MLKEM_SEED_LEN, z, MLKEM_SEED_LEN);
    (void)memcpy_s(newCt + MLKEM_SEED_LEN, ctLen, ct, ctLen);
    GOTO_ERR_IF(HashFuncJ(ctx->libCtx, newCt, ctLen + MLKEM_SEED_LEN, r, MLKEM_SHARED_KEY_LEN), ret);

    for (uint32_t i = 0; i < MLKEM_SHARED_KEY_LEN; i++) {
        sk[i] = (kr[i] & mask) | (r[i] & ~mask);
    }
    *skLen = MLKEM_SHARED_KEY_LEN;
ERR:
    BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
    BSL_SAL_Free(newCt);
    return ret;
}

#endif