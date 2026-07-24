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
#include <string.h>

#include "frodo_local.h"
#include "crypt_eal_cipher.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "eal_md_local.h"

#define FRODO_MAX_N                  1344
#define FRODO_MAX_SEED_A             16
#define FRODO_PRG_SEEDS_LEN          72
#define FRODO_PRG_AES_PLAINTEXT_SIZE 10752
#define FRODO_MATRIX_FOUR_ROWS_SIZE  5376
#define FRODO_GEN_SHAKE_ID           CRYPT_MD_SHAKE128

typedef void (*FrodoMulAddFunc)(uint16_t *out, const uint16_t *matrixS, int32_t n, int32_t nBar, uint16_t *rows,
                                int32_t rowNumber);

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

static int32_t AESCtrEncrypt(CRYPT_EAL_CipherCtx *ctx, const int32_t n, uint16_t *rows, uint8_t *plaintext,
                             const int32_t blocksPerRow, int32_t rowNumber)
{
    for (int32_t blk = 0; blk < blocksPerRow; blk++) {
        U16ToBytesLE(rowNumber + 0, &plaintext[16 * (blk + 0 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 1, &plaintext[16 * (blk + 1 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 2, &plaintext[16 * (blk + 2 * blocksPerRow)]);
        U16ToBytesLE(rowNumber + 3, &plaintext[16 * (blk + 3 * blocksPerRow)]);
    }

    uint32_t outLen = 4 * blocksPerRow * 16;
    int32_t ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, outLen, (uint8_t *)rows, &outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    FrodoCommonDecodeLe16(rows, (const uint8_t *)rows, 4 * n);
    return CRYPT_SUCCESS;
}

static int32_t FrodoCommonMulAddAES(uint16_t *out, const uint16_t *matrixSTranspose, const uint8_t *seedA,
                                    const int32_t n, const int32_t nBar, uint16_t *rows, uint8_t *plaintext,
                                    FrodoMulAddFunc multFunction, void *libCtx)
{
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_ProviderCipherNewCtx(libCtx, CRYPT_CIPHER_AES128_ECB, NULL);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_CipherInit(ctx, seedA, 16, NULL, 0, true);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_NONE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    const int32_t blocksPerRow = n / 8;
    InitAESHeaderBlockNumber(plaintext, blocksPerRow);
    for (int32_t rowNumber = 0; rowNumber < n; rowNumber += 4) {
        ret = AESCtrEncrypt(ctx, n, rows, plaintext, blocksPerRow, rowNumber);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        multFunction(out, matrixSTranspose, n, nBar, rows, rowNumber);
    }
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return ret;
}

static int32_t FrodoCommonMulAddShake(uint16_t *out, const uint16_t *matrixS, const uint8_t *seedA,
                                      const FrodoKemParams *params, int32_t n, int32_t nBar, uint16_t *rows,
                                      FrodoMulAddFunc multFunction, void *libCtx)
{
    int32_t ret;
    const uint32_t inLen = 2 + (uint32_t)params->lenSeedA; // lenSeedA is FRODO_MAX_SEED_A
    uint8_t in0[2 + FRODO_MAX_SEED_A];
    uint8_t in1[2 + FRODO_MAX_SEED_A];
    uint8_t in2[2 + FRODO_MAX_SEED_A];
    uint8_t in3[2 + FRODO_MAX_SEED_A];

    memcpy(in0 + 2, seedA, params->lenSeedA);
    memcpy(in1 + 2, seedA, params->lenSeedA);
    memcpy(in2 + 2, seedA, params->lenSeedA);
    memcpy(in3 + 2, seedA, params->lenSeedA);

    uint16_t *row0 = &rows[0 * n];
    uint16_t *row1 = &rows[1 * n];
    uint16_t *row2 = &rows[2 * n];
    uint16_t *row3 = &rows[3 * n];

    for (int32_t i = 0; i < n; i += 4) {
        U16ToBytesLE(i + 0, in0);
        U16ToBytesLE(i + 1, in1);
        U16ToBytesLE(i + 2, in2);
        U16ToBytesLE(i + 3, in3);
        uint32_t rowLen = n * sizeof(uint16_t);
        RETURN_RET_IF_ERR(EAL_Md(FRODO_GEN_SHAKE_ID, libCtx, NULL, in0, inLen, (uint8_t *)row0, &rowLen, false,
            libCtx != NULL), ret);
        rowLen = n * sizeof(uint16_t);
        RETURN_RET_IF_ERR(EAL_Md(FRODO_GEN_SHAKE_ID, libCtx, NULL, in1, inLen, (uint8_t *)row1, &rowLen, false,
            libCtx != NULL), ret);
        rowLen = n * sizeof(uint16_t);
        RETURN_RET_IF_ERR(EAL_Md(FRODO_GEN_SHAKE_ID, libCtx, NULL, in2, inLen, (uint8_t *)row2, &rowLen, false,
            libCtx != NULL), ret);
        rowLen = n * sizeof(uint16_t);
        RETURN_RET_IF_ERR(EAL_Md(FRODO_GEN_SHAKE_ID, libCtx, NULL, in3, inLen, (uint8_t *)row3, &rowLen, false,
            libCtx != NULL), ret);
        FrodoCommonDecodeLe16(row0, (const uint8_t *)row0, n);
        FrodoCommonDecodeLe16(row1, (const uint8_t *)row1, n);
        FrodoCommonDecodeLe16(row2, (const uint8_t *)row2, n);
        FrodoCommonDecodeLe16(row3, (const uint8_t *)row3, n);
        multFunction(out, matrixS, n, nBar, rows, i);
    }
    return CRYPT_SUCCESS;
}

int32_t FrodoCommonMulAddAsPlusEPortable(uint16_t *out, const uint16_t *matrixST, const uint8_t *seedA,
                                         const FrodoKemParams *params, void *libCtx)
{
    const int32_t N = params->n;
    const int32_t nBar = params->nBar;
    uint16_t *rows = BSL_SAL_Malloc(4 * FRODO_MAX_N * sizeof(uint16_t));
    if (rows == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret;
#if defined(HITLS_CRYPTO_FRODOKEM_ARMV8)
    /* Transpose S^T (nBar x N) to S (N x nBar) once upfront.
     * Assembly uses outer-product MLA which requires S[k][0..7] contiguous;
     * addv-based dot-product is replaced, removing the 4-cycle throughput bottleneck. */
    uint16_t sMatrix[8 * FRODO_MAX_N]; /* nBar is always 8; max = 8*1344*2 = 21 KB */
    for (int32_t j = 0; j < nBar; j++) {
        for (int32_t k = 0; k < N; k++) {
            sMatrix[k * nBar + j] = matrixST[j * N + k];
        }
    }
    const uint16_t *matS = sMatrix;
#else
    const uint16_t *matS = matrixST;
#endif
    if (params->prg == FRODO_PRG_AES) {
        uint8_t *plaintext = BSL_SAL_Malloc(FRODO_PRG_AES_PLAINTEXT_SIZE);
        if (plaintext == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            goto EXIT;
        }
        ret = FrodoCommonMulAddAES(out, matS, seedA, N, nBar, rows, plaintext, FrodoMulAddAsPlusE, libCtx);
        BSL_SAL_FREE(plaintext);
    } else {
        ret = FrodoCommonMulAddShake(out, matS, seedA, params, N, nBar, rows, FrodoMulAddAsPlusE, libCtx);
    }
EXIT:
#if defined(HITLS_CRYPTO_FRODOKEM_ARMV8)
    BSL_SAL_CleanseData(sMatrix, sizeof(sMatrix));
#endif
    BSL_SAL_FREE(rows);
    return ret;
}

int32_t FrodoCommonMulAddSaPlusEPortable(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seedA,
                                         const FrodoKemParams *params, void *libCtx)
{
    const int32_t n = params->n;
    const int32_t nBar = params->nBar;

    memcpy(out, e, (uint32_t)nBar * n * sizeof(uint16_t));
    uint16_t rows[4 * FRODO_MAX_N];
    if (params->prg == FRODO_PRG_AES) {
        uint8_t plaintext[FRODO_PRG_AES_PLAINTEXT_SIZE];
        return FrodoCommonMulAddAES(out, s, seedA, n, nBar, rows, plaintext, FrodoMulAddSaPlusE, libCtx);
    } else {
        return FrodoCommonMulAddShake(out, s, seedA, params, n, nBar, rows, FrodoMulAddSaPlusE, libCtx);
    }
}

void FrodoCommonMulBs(uint16_t *out, const uint16_t *b, const uint16_t *s, const FrodoKemParams *params)
{
    const uint32_t n = params->n;
    const uint32_t nBar = params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);

    for (uint32_t i = 0; i < nBar; i++) {
        for (uint32_t j = 0; j < nBar; j++) {
            uint64_t acc = 0;
            for (uint32_t k = 0; k < n; k++) {
                acc += (uint32_t)(b[i * n + k] & qMask) * (uint32_t)(s[k * nBar + j] & qMask);
            }
            out[i * nBar + j] = (uint16_t)(acc & qMask);
        }
    }
}

void FrodoCommonMulBsUsingSt(uint16_t *out, const uint16_t *b, const uint16_t *sT, const FrodoKemParams *params)
{
    const uint32_t n = params->n;
    const uint32_t nBar = params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);
    for (uint32_t i = 0; i < nBar; i++) {
        for (uint32_t j = 0; j < nBar; j++) {
            uint64_t acc = 0;
            for (uint32_t k = 0; k < n; k++) {
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
    const uint32_t ncoeff = (uint32_t)params->nBar * params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);
    for (uint32_t t = 0; t < ncoeff; t++) {
        uint32_t sum = (uint32_t)(a[t] & qMask) + (uint32_t)(b[t] & qMask);
        out[t] = (uint16_t)(sum & qMask);
    }
}

void FrodoCommonSub(uint16_t *out, const uint16_t *a, const uint16_t *b, const FrodoKemParams *params)
{
    const uint32_t ncoeff = (uint32_t)params->nBar * params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);
    for (uint32_t t = 0; t < ncoeff; t++) {
        uint32_t diff = (uint32_t)(a[t] & qMask) - (uint32_t)(b[t] & qMask);
        out[t] = (uint16_t)(diff & qMask); // when q=2^k, the operation "x & qMask" is equal to x mod q
    }
}

void FrodoCommonKeyEncode(uint16_t *out, const uint8_t *mu, const FrodoKemParams *params)
{
    const uint32_t total = (uint32_t)params->nBar * params->nBar;
    const uint8_t b = (uint8_t)params->extractedBits;
    const uint16_t factor = (uint16_t)(1u << (params->logq - b));

    uint32_t bitPos = 0;
    for (uint32_t t = 0; t < total; t++) {
        uint32_t x = 0;
        for (uint8_t r = 0; r < b; r++, bitPos++) {
            uint8_t byte = mu[bitPos >> 3];
            uint8_t s = bitPos & 7;
            x |= ((byte >> s) & 1u) << r;
        }
        out[t] = (uint16_t)(x * factor);
    }
}

void FrodoCommonKeyDecode(uint8_t *mu, const uint16_t *in, const FrodoKemParams *params)
{
    const uint32_t total = (uint32_t)params->nBar * params->nBar;
    const uint8_t b = (uint8_t)params->extractedBits;
    const uint8_t s = (uint8_t)(params->logq - b);
    const uint16_t round = (uint16_t)(1u << (s - 1));
    const uint16_t mask = (uint16_t)((1u << b) - 1u);

    memset(mu, 0, params->lenMu);

    uint32_t bitpos = 0;
    for (uint32_t t = 0; t < total; t++) {
        uint16_t v = in[t];
        uint16_t piece = (uint16_t)(((uint32_t)v + round) >> s) & mask;

        for (uint8_t r = 0; r < b; r++, bitpos++) {
            uint8_t bit = (uint8_t)((piece >> r) & 1u);
            uint8_t bitMask = (uint8_t)(0u - (uint32_t)bit);
            mu[bitpos >> 3] |= bitMask & (uint8_t)(1u << (bitpos & 7));
        }
    }
}
#endif
