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
#ifdef HITLS_CRYPTO_FRODOKEM
#include <stdlib.h>

#include "frodo_local.h"
#include "eal_cipher_local.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "securec.h"

#define FRODO_MAX_N                  1344
#define FRODO_MAX_SEED_A             16
#define FRODO_PRG_SEEDS_LEN          72
#define FRODO_PRG_AES_PLAINTEXT_SIZE 10752
#define FRODO_MATRIX_FOUR_ROWS_SIZE  5376

#define RETURN_RET_IF_ERR(FUNC, RET) \
    do {                             \
        RET = FUNC;                  \
        if (RET != CRYPT_SUCCESS) {  \
            BSL_ERR_PUSH_ERROR(RET); \
            return RET;              \
        }                            \
    } while (0)

// function signature of multiplication when PRNG = AES
typedef void (*MultFunctionAes)(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *rows,
                                int32_t rowNumber);

// function signature of multiplication when PRNG = SHAKE
typedef void (*MultFunctionShake)(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *row0,
                                  uint16_t *row1, uint16_t *row2, uint16_t *row3, int32_t rowNumber);

static inline uint16_t leToUint16(uint16_t n)
{
    uint8_t bytes[2];
    (void)memcpy_s(bytes, 2, &n, 2);
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

#define LE_TO_UINT16(n) leToUint16(n)
#define U16ToBytesLE(val, bytes) \
    (bytes)[0] = (val) & 0xff;   \
    (bytes)[1] = (val) >> 8;

static void InitAESHeaderBlockNumber(uint8_t *aesBuf, const int32_t blocksPerRow)
{
    for (int32_t blk = 0; blk < blocksPerRow; blk++) {
        for (int32_t r = 0; r < 4; r++) {
            uint8_t *P = &aesBuf[16 * (blk + r * blocksPerRow)];
            U16ToBytesLE(blk << 3, P + 2);
            for (int32_t t = 4; t < 16; t++) {
                P[t] = 0;
            }
        }
    }
}

static int32_t AESCtrEncrypt(void *ctx, EAL_CipherMethod *method, const int32_t n, uint16_t *rows, uint8_t *plaintext,
                             const int32_t blocksPerRow, int32_t rowNumber)
{
    for (int32_t blk = 0; blk < blocksPerRow; blk++) {
        U16ToBytesLE(rowNumber + 0, &plaintext[16 * (blk + 0 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 1, &plaintext[16 * (blk + 1 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 2, &plaintext[16 * (blk + 2 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 3, &plaintext[16 * (blk + 3 * blocksPerRow)]);
    }

    uint32_t outLen = 4 * blocksPerRow * 16;
    int32_t ret = method->update(ctx, plaintext, outLen, (uint8_t *)rows, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (int32_t k = 0; k < 4 * n; k++) {
        rows[k] = (uint16_t)LE_TO_UINT16(rows[k]);
    }
    return CRYPT_SUCCESS;
}

static void MultAsPlusEAES(uint16_t *out, const uint16_t *matrixST, const int32_t n, const int32_t nBar, uint16_t *rows,
                           int32_t rowNumber)
{
    const uint16_t *row0 = &rows[0 * n];
    const uint16_t *row1 = &rows[1 * n];
    const uint16_t *row2 = &rows[2 * n];
    const uint16_t *row3 = &rows[3 * n];

    for (int32_t j = 0; j < nBar; j++) {
        const uint16_t *rowST = &matrixST[j * n];
        uint16_t sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
        for (int32_t k = 0; k < n; k++) {
            uint16_t sv = rowST[k];
            sum0 += (uint16_t)((uint32_t)row0[k] * sv);
            sum1 += (uint16_t)((uint32_t)row1[k] * sv);
            sum2 += (uint16_t)((uint32_t)row2[k] * sv);
            sum3 += (uint16_t)((uint32_t)row3[k] * sv);
        }
        out[(rowNumber + 0) * nBar + j] = (uint16_t)(out[(rowNumber + 0) * nBar + j] + sum0);
        out[(rowNumber + 1) * nBar + j] = (uint16_t)(out[(rowNumber + 1) * nBar + j] + sum1);
        out[(rowNumber + 2) * nBar + j] = (uint16_t)(out[(rowNumber + 2) * nBar + j] + sum2);
        out[(rowNumber + 3) * nBar + j] = (uint16_t)(out[(rowNumber + 3) * nBar + j] + sum3);
    }
}

static void MultSaPlusEAES(uint16_t *out, const uint16_t *matrixS, const int32_t n, const int32_t nBar, uint16_t *rows,
                           int32_t rowNumber)
{
    const uint16_t *row0 = &rows[0 * n];
    const uint16_t *row1 = &rows[1 * n];
    const uint16_t *row2 = &rows[2 * n];
    const uint16_t *row3 = &rows[3 * n];

    for (int32_t k = 0; k < nBar; k++) {
        const uint16_t s0 = matrixS[k * n + (rowNumber + 0)];
        const uint16_t s1 = matrixS[k * n + (rowNumber + 1)];
        const uint16_t s2 = matrixS[k * n + (rowNumber + 2)];
        const uint16_t s3 = matrixS[k * n + (rowNumber + 3)];

        uint16_t *outRow = &out[k * n];
        for (int32_t j = 0; j < n; j++) {
            uint16_t acc = outRow[j];
            acc = (uint16_t)(acc + (uint16_t)(row0[j] * s0));
            acc = (uint16_t)(acc + (uint16_t)(row1[j] * s1));
            acc = (uint16_t)(acc + (uint16_t)(row2[j] * s2));
            acc = (uint16_t)(acc + (uint16_t)(row3[j] * s3));
            outRow[j] = acc;
        }
    }
}

static int32_t FrodoCommonMulAddAES(uint16_t *out, const uint16_t *matrixSTranspose, const uint8_t *seedA,
                                    const int32_t n, const int32_t nBar, uint16_t rows[FRODO_MATRIX_FOUR_ROWS_SIZE],
                                    uint8_t plaintext[FRODO_PRG_AES_PLAINTEXT_SIZE], MultFunctionAes multFunction)
{
    EAL_CipherMethod method = {0};
    int32_t ret = EAL_CipherFindMethod(CRYPT_CIPHER_AES128_ECB, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    void *ctx = method.newCtx(NULL, CRYPT_CIPHER_AES128_ECB);
    ret = method.initCtx(ctx, seedA, 16, NULL, 0, NULL, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    int32_t padding = CRYPT_PADDING_NONE;
    ret = method.ctrl(ctx, CRYPT_CTRL_SET_PADDING, &padding, sizeof(int32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    const int32_t blocksPerRow = n / 8;
    InitAESHeaderBlockNumber(plaintext, blocksPerRow);
    for (int32_t rowNumber = 0; rowNumber < n; rowNumber += 4) {
        ret = AESCtrEncrypt(ctx, &method, n, rows, plaintext, blocksPerRow, rowNumber);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        multFunction(out, matrixSTranspose, n, nBar, rows, rowNumber);
    }
EXIT:
    method.freeCtx(ctx);
    return ret;
}

// =================================================================================
// Static helper functions for SHAKE-based PRG
// =================================================================================

static void MulAsPlusESHAKE(uint16_t *out, const uint16_t *matrixST, const int32_t n, const int32_t nBar,
                            uint16_t *row0, uint16_t *row1, uint16_t *row2, uint16_t *row3, int32_t rowNumber)
{
    for (int32_t j = 0; j < nBar; j++) {
        const uint16_t *stRow = &matrixST[j * n];
        uint16_t sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
        for (int32_t k = 0; k < n; k++) {
            uint16_t sv = stRow[k];
            sum0 += (uint16_t)((uint32_t)row0[k] * sv);
            sum1 += (uint16_t)((uint32_t)row1[k] * sv);
            sum2 += (uint16_t)((uint32_t)row2[k] * sv);
            sum3 += (uint16_t)((uint32_t)row3[k] * sv);
        }
        out[(rowNumber + 0) * nBar + j] = (uint16_t)(out[(rowNumber + 0) * nBar + j] + sum0);
        out[(rowNumber + 1) * nBar + j] = (uint16_t)(out[(rowNumber + 1) * nBar + j] + sum1);
        out[(rowNumber + 2) * nBar + j] = (uint16_t)(out[(rowNumber + 2) * nBar + j] + sum2);
        out[(rowNumber + 3) * nBar + j] = (uint16_t)(out[(rowNumber + 3) * nBar + j] + sum3);
    }
}

static void MulSaPlusESHAKE(uint16_t *out, const uint16_t *matrixS, const int32_t n, const int32_t nBar, uint16_t *row0,
                            uint16_t *row1, uint16_t *row2, uint16_t *row3, int32_t rowNumber)
{
    for (int32_t k = 0; k < nBar; k++) {
        const uint16_t s0 = matrixS[k * n + (rowNumber + 0)];
        const uint16_t s1 = matrixS[k * n + (rowNumber + 1)];
        const uint16_t s2 = matrixS[k * n + (rowNumber + 2)];
        const uint16_t s3 = matrixS[k * n + (rowNumber + 3)];

        uint16_t *outRow = &out[k * n];
        for (int32_t j = 0; j < n; j++) {
            uint16_t acc = outRow[j];
            acc = (uint16_t)(acc + (uint16_t)(row0[j] * s0));
            acc = (uint16_t)(acc + (uint16_t)(row1[j] * s1));
            acc = (uint16_t)(acc + (uint16_t)(row2[j] * s2));
            acc = (uint16_t)(acc + (uint16_t)(row3[j] * s3));
            outRow[j] = acc;
        }
    }
}

static int32_t FrodoCommonMulAddAsPlusESHAKE(uint16_t *out, const uint16_t *matrixST, const uint8_t *seedA,
                                             const FrodoKemParams *params, const int32_t n, const int32_t nBar,
                                             uint16_t rows[FRODO_MATRIX_FOUR_ROWS_SIZE],
                                             uint8_t seeds[FRODO_PRG_SEEDS_LEN], MultFunctionShake multFunction)
{
    int32_t ret;
    const size_t inLen = 2 + (size_t)params->lenSeedA;
    uint8_t *in0 = &seeds[0 * inLen];
    uint8_t *in1 = &seeds[1 * inLen];
    uint8_t *in2 = &seeds[2 * inLen];
    uint8_t *in3 = &seeds[3 * inLen];

    for (int32_t ctr = 0; ctr < params->lenSeedA; ctr++) {
        in0[2 + ctr] = seedA[ctr];
        in1[2 + ctr] = seedA[ctr];
        in2[2 + ctr] = seedA[ctr];
        in3[2 + ctr] = seedA[ctr];
    }

    uint16_t *row0 = &rows[0 * n];
    uint16_t *row1 = &rows[1 * n];
    uint16_t *row2 = &rows[2 * n];
    uint16_t *row3 = &rows[3 * n];

    for (int32_t i = 0; i < n; i += 4) {
        U16ToBytesLE(i + 0, in0);
        U16ToBytesLE(i + 1, in1);
        U16ToBytesLE(i + 2, in2);
        U16ToBytesLE(i + 3, in3);
        RETURN_RET_IF_ERR(FrodoKemShake128((uint8_t *)row0, n * sizeof(uint16_t), in0, inLen), ret);
        RETURN_RET_IF_ERR(FrodoKemShake128((uint8_t *)row1, n * sizeof(uint16_t), in1, inLen), ret);
        RETURN_RET_IF_ERR(FrodoKemShake128((uint8_t *)row2, n * sizeof(uint16_t), in2, inLen), ret);
        RETURN_RET_IF_ERR(FrodoKemShake128((uint8_t *)row3, n * sizeof(uint16_t), in3, inLen), ret);
        multFunction(out, matrixST, n, nBar, row0, row1, row2, row3, i);
    }
    return CRYPT_SUCCESS;
}

int32_t FrodoCommonMulAddAsPlusEPortable(uint16_t *out, const uint16_t *matrixST, const uint8_t *seedA,
                                         const FrodoKemParams *params)
{
    const int32_t N = params->n;
    const int32_t nBar = params->nBar;
    uint16_t rows[4 * FRODO_MAX_N];
    if (params->prg == FRODO_PRG_AES) {
        uint8_t plaintext[FRODO_PRG_AES_PLAINTEXT_SIZE];
        return FrodoCommonMulAddAES(out, matrixST, seedA, N, nBar, rows, plaintext, MultAsPlusEAES);
    } else {
        uint8_t seeds[FRODO_PRG_SEEDS_LEN];
        return FrodoCommonMulAddAsPlusESHAKE(out, matrixST, seedA, params, N, nBar, rows, seeds, MulAsPlusESHAKE);
    }
}

int32_t FrodoCommonMulAddSaPlusEPortable(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seedA,
                                         const FrodoKemParams *params)
{
    const int32_t n = params->n;
    const int32_t nBar = params->nBar;

    for (int32_t i = 0; i < nBar * n; ++i) {
        out[i] = e[i];
    }
    uint16_t rows[4 * FRODO_MAX_N];
    if (params->prg == FRODO_PRG_AES) {
        uint8_t plaintext[FRODO_PRG_AES_PLAINTEXT_SIZE];
        return FrodoCommonMulAddAES(out, s, seedA, n, nBar, rows, plaintext, MultSaPlusEAES);
    } else {
        uint8_t seeds[FRODO_PRG_SEEDS_LEN];
        return FrodoCommonMulAddAsPlusESHAKE(out, s, seedA, params, n, nBar, rows, seeds, MulSaPlusESHAKE);
    }
}

void FrodoCommonMulAddSbPlusEPortable(uint16_t *V0, const uint16_t *STp, const uint16_t *B, const uint16_t *Epp,
                                      const FrodoKemParams *params)
{
    const size_t n = params->n;
    const size_t nBar = params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);

    for (size_t i = 0; i < nBar * nBar; i++) {
        V0[i] = (uint16_t)(Epp[i] & qMask);
    }

    for (size_t i = 0; i < nBar; i++) {
        const size_t Si = i * n;
        const size_t Vi = i * nBar;
        for (size_t k = 0; k < n; k++) {
            const uint32_t s = (uint32_t)(STp[Si + k] & qMask);
            const size_t Bk = k * nBar;
            for (size_t j = 0; j < nBar; j++) {
                const uint32_t b = (uint32_t)(B[Bk + j] & qMask);
                uint32_t acc = (uint32_t)V0[Vi + j] + s * b;
                V0[Vi + j] = (uint16_t)(acc & qMask);
            }
        }
    }
}

void FrodoCommonMulBs(uint16_t *out, const uint16_t *b, const uint16_t *s, const FrodoKemParams *params)
{
    const size_t n = params->n, nBar = params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);

    for (size_t i = 0; i < nBar; i++) {
        for (size_t j = 0; j < nBar; j++) {
            uint64_t acc = 0;
            for (size_t k = 0; k < n; k++) {
                acc += (uint32_t)(b[i * n + k] & qMask) * (uint32_t)(s[k * nBar + j] & qMask);
            }
            out[i * nBar + j] = (uint16_t)(acc & qMask);
        }
    }
}

void FrodoCommonMulBsUsingSt(uint16_t *out, const uint16_t *b, const uint16_t *sT, const FrodoKemParams *params)
{
    const size_t n = params->n, nBar = params->nBar; //size_t整改一下
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t i = 0; i < nBar; i++) {
        for (size_t j = 0; j < nBar; j++) {
            uint64_t acc = 0;
            for (size_t k = 0; k < n; k++) {
                uint16_t bIk = b[i * n + k] & qMask;
                uint16_t sKj = sT[j * n + k] & qMask;
                acc += (uint32_t)bIk * sKj;
            }
            out[i * nBar + j] = (uint16_t)(acc & qMask);
        }
    }
}

void FrodoCommonAdd(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params)
{
    const size_t ncoeff = (size_t)params->nBar * params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t t = 0; t < ncoeff; t++) {
        uint32_t sum = (uint32_t)(a[t] & qMask) + (uint32_t)(b[t] & qMask);
        out[t] = (uint16_t)(sum & qMask);
    }
}

void FrodoCommonSub(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params)
{
    const size_t ncoeff = (size_t)params->nBar * params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);
    for (size_t t = 0; t < ncoeff; t++) {
        uint32_t diff = (uint32_t)(a[t] & qMask) - (uint32_t)(b[t] & qMask);
        out[t] = (uint16_t)(diff & qMask); // when q=2^k，the operation "x & qMask" is equal to x mod q
    }
}

void FrodoCommonKeyEncode(uint16_t *out, const uint16_t *in, const FrodoKemParams *params)
{
    const uint8_t *mu = (const uint8_t *)in;
    const size_t total = (size_t)params->nBar * params->nBar;
    const uint8_t b = (uint8_t)params->extractedBits;
    const uint16_t factor = (uint16_t)(1u << (params->logq - b));

    size_t bitPos = 0;
    for (size_t t = 0; t < total; t++) {
        uint32_t x = 0;
        for (uint8_t r = 0; r < b; r++, bitPos++) {
            uint8_t byte = mu[bitPos >> 3];
            uint8_t s = bitPos & 7;
            x |= ((byte >> s) & 1u) << r;
        }
        out[t] = (uint16_t)(x * factor);
    }
}

void FrodoCommonKeyDecode(uint16_t *out, const uint16_t *in, const FrodoKemParams *params)
{
    uint8_t *mu = (uint8_t *)out;

    const size_t total = (size_t)params->nBar * params->nBar;
    const uint8_t b = (uint8_t)params->extractedBits;
    const uint8_t s = (uint8_t)(params->logq - b);
    const uint16_t round = (uint16_t)(1u << (s - 1));
    const uint16_t mask = (uint16_t)((1u << b) - 1u);

    (void)memset_s(mu, params->lenMu, 0, params->lenMu);

    size_t bitpos = 0;
    for (size_t t = 0; t < total; t++) {
        uint16_t v = in[t];
        uint16_t piece = (uint16_t)(((uint32_t)v + round) >> s) & mask;

        for (uint8_t r = 0; r < b; r++, bitpos++) {
            if ((piece >> r) & 1u) {
                mu[bitpos >> 3] |= (uint8_t)(1u << (bitpos & 7));
            }
        }
    }
}
#endif
