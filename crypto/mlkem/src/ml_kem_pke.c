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
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_utils.h"
#include "crypt_sha3.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "ml_kem_local.h"

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
    st->bufAddr = buf; // Used to release memory.
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            st->matrix[i][j] = buf + (i * k + j) * MLKEM_N;
        }
        // vectorS,vectorE,vectorT use 3 * k data blocks.
        st->vectorS[i] = buf + (k * k + 0 * k + i) * MLKEM_N;
        st->vectorE[i] = buf + (k * k + 1 * k + i) * MLKEM_N;
        st->vectorT[i] = buf + (k * k + 2 * k + i) * MLKEM_N;
    }
    return CRYPT_SUCCESS;
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
        indexR = 5 * i; // Each element in polyF has 5 bits.
        indexF = 8 * i; // Each element in r has 8 bits.
        // 8 polyF elements are padded to 5 bytes.
        r[indexR + 0] = (uint8_t)(polyF[indexF] | (polyF[indexF + 1] << 5));
        r[indexR + 1] = (uint8_t)((polyF[indexF + 1] >> 3) | (polyF[indexF + 2] << 2) | (polyF[indexF + 3] << 7));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 3] >> 1) | (polyF[indexF + 4] << 4));
        r[indexR + 3] = (uint8_t)((polyF[indexF + 4] >> 4) | (polyF[indexF + 5] << 1) | (polyF[indexF + 6] << 6));
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
void ByteEncode(uint8_t *r, int16_t *polyF, uint8_t bit)
{
    switch (bit) { // Valid bits of each element in polyF.
        case 1: // 1 Used for K-PKE.Decrypt Step 7.
            EncodeBits1(r, (uint16_t *)polyF);
            break;
        case 4: // From FIPS 203 Table 2, dv = 4
            EncodeBits4(r, (uint16_t *)polyF);
            break;
        case 5: // dv = 5
            EncodeBits5(r, (uint16_t *)polyF);
            break;
        case 10: // du = 10
            EncodeBits10(r, (uint16_t *)polyF);
            break;
        case 11: // du = 11
            EncodeBits11(r, (uint16_t *)polyF);
            break;
        case 12: // 12 Used for K-PKE.KeyGen Step 19.
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
        polyF[indexF + 2] =
            ((a[indexA + 2] >> 6) | ((uint16_t)a[indexA + 3] << 2) | ((uint16_t)a[indexA + 4] << 10)) & 0x7FF;
        polyF[indexF + 3] = ((a[indexA + 4] >> 1) | ((uint16_t)a[indexA + 5] << 7)) & 0x7FF;
        polyF[indexF + 4] = ((a[indexA + 5] >> 4) | ((uint16_t)a[indexA + 6] << 4)) & 0x7FF;
        polyF[indexF + 5] =
            ((a[indexA + 6] >> 7) | ((uint16_t)a[indexA + 7] << 1) | ((uint16_t)a[indexA + 8] << 9)) & 0x7FF;
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

// NIST.FIPS.203 Algorithm 13 K-PKE.KeyGen(𝑑)
static int32_t PkeKeyGen(CRYPT_ML_KEM_Ctx *ctx, uint8_t *pk, uint8_t *dk, uint8_t *d)
{
    int32_t ret;
    uint8_t k = ctx->info->k;
    uint8_t seed[MLKEM_SEED_LEN + 1] = {0}; // Reserved lengths of k is 1 byte.
    uint8_t digest[CRYPT_SHA3_512_DIGESTSIZE] = {0};

    // (p,q) = G(d || k)
    memcpy(seed, d, MLKEM_SEED_LEN);
    seed[MLKEM_SEED_LEN] = k;
    CRYPT_SHA3_512(digest, seed, MLKEM_SEED_LEN + 1);

    GOTO_ERR_IF(MLKEM_PKEGen(ctx, digest, pk, dk), ret);

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
    uint8_t bufEncE[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX];
    int16_t polyE2[MLKEM_N] = {0};
    int16_t polyC2[MLKEM_N] = {0};
    int16_t polyM[MLKEM_N] = {0};
    int16_t *polyVecY[MLKEM_K_MAX] = {0};
    int16_t *polyVecE1[MLKEM_K_MAX] = {0};
    int16_t *polyVecU[MLKEM_K_MAX] = {0};
    int16_t *tmpPolyVec = BSL_SAL_Calloc(MLKEM_N * k * 3, sizeof(int16_t));
    if (tmpPolyVec == NULL) {
        return BSL_MALLOC_FAIL;
    }
    // Reference the memory
    for (i = 0; i < k; ++i) {
        polyVecY[i] = tmpPolyVec + (0 * k + i) * MLKEM_N;
        polyVecE1[i] = tmpPolyVec + (1 * k + i) * MLKEM_N;
        polyVecU[i] = tmpPolyVec + (2 * k + i) * MLKEM_N;
    }
    int32_t ret = 0;

    GOTO_ERR_IF(SampleEta2(ctx, r, polyVecY, polyVecE1), ret); // Step 9 - 16
    // Step 17
    CRYPT_SHAKE256(bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2, r, MLKEM_SEED_LEN + 1);
    MLKEM_SamplePolyCBD(polyE2, bufEncE, ctx->info->eta2);

    ByteDecode(polyM, m, 1);
    PolyDeCompress(polyM, 1); // Step 20

    GOTO_ERR_IF(MLKEM_PKEEnc(k, &ctx->keyData, ctx->info->du, ctx->info->dv, ct, polyVecY, polyVecE1, polyVecU, polyE2,
                             polyM, polyC2),
                ret);

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
        ByteDecode(polyVecC1[i], ciphertext + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * i, ctx->info->du); // Step 3
    }
    ByteDecode(polyC2, ciphertext + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * k, ctx->info->dv); // Step 4
    for (i = 0; i < k; i++) {
        PolyDeCompress(polyVecC1[i], ctx->info->du); // Step 3
        if (i == 0) {
            PolyDeCompress(polyC2, ctx->info->dv); // Step 4
        }
    }
    MLKEM_PKEDec(k, &ctx->keyData, polyM, polyVecC1, polyC2, result);

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
    if (ctx->ekLen > ctx->dkLen - dkPkeLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_CPY_FAIL);
        return CRYPT_MEM_CPY_FAIL;
    }
    memcpy(ctx->dk + dkPkeLen, ctx->ek, ctx->ekLen);

    CRYPT_SHA3_256(ctx->dk + dkPkeLen + ctx->ekLen, ctx->ek, ctx->ekLen);

    if (ctx->dkLen - (dkPkeLen + ctx->ekLen + CRYPT_SHA3_256_DIGESTSIZE) < MLKEM_SEED_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_CPY_FAIL);
        return CRYPT_MEM_CPY_FAIL;
    }
    memcpy(ctx->dk + dkPkeLen + ctx->ekLen + CRYPT_SHA3_256_DIGESTSIZE, z, MLKEM_SEED_LEN);

    // Store seed (d || z) in context
    ctx->hasSeed = true;
    memcpy(ctx->seed, d, MLKEM_SEED_LEN);
    memcpy(ctx->seed + MLKEM_SEED_LEN, z, MLKEM_SEED_LEN);

    return CRYPT_SUCCESS;
}

// NIST.FIPS.203 Algorithm 17 ML-KEM.Encaps_internal(ek,𝑚)
int32_t MLKEM_EncapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *sk, uint32_t *skLen,
                             uint8_t *m)
{
    uint8_t mhek[MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE]; // m and H(ek)
    // +1: SampleEta2 writes nonce into r[MLKEM_SEED_LEN] (i.e. kr[64]) for subsequent PRF call.
    uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE + 1]; // K and r
    int32_t ret;

    //  (K,r) = G(m || H(ek))
    (void)memcpy(mhek, m, MLKEM_SEED_LEN);
    CRYPT_SHA3_256(mhek + MLKEM_SEED_LEN, ctx->ek, ctx->ekLen);
    CRYPT_SHA3_512(kr, mhek, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE);

    memcpy(sk, kr, MLKEM_SHARED_KEY_LEN);

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
    const uint8_t *dk = ctx->dk; // Step 1  dkPKE ← dk[0 : 384k]
    const uint8_t *ek = dk + MLKEM_CIPHER_LEN * algInfo->k; // Step 2  ekPKE ← dk[384k : 768k +32]
    const uint8_t *h = ek + algInfo->encapsKeyLen; // Step 3  h ← dk[768k +32 : 768k +64]
    const uint8_t *z = h + MLKEM_SEED_LEN; // Step 4  z ← dk[768k +64 : 768k +96]

    uint8_t mh[MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE]; // m′ and h
    uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE + 1]; // K' and r'
    int32_t ret;

    // NIST.FIPS.203: test = H(dk[384k : 768k + 32]) and check test == h
    CRYPT_SHA3_256(mh, ek, 384 * ctx->info->k + 32);
    if (memcmp(h, mh, CRYPT_SHA3_256_DIGESTSIZE) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_INVALID_PRVKEY);
        return CRYPT_MLKEM_INVALID_PRVKEY;
    }

    ret = PkeDecrypt(ctx, mh, ct); // Step 5: 𝑚′ ← K-PKE.Decrypt(dkPKE, 𝑐)
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    // Step 6: (K′,r′) ← G(m′ || h)
    (void)memcpy(mh + MLKEM_SEED_LEN, h, CRYPT_SHA3_256_DIGESTSIZE);
    CRYPT_SHA3_512(kr, mh, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE);
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
    (void)memcpy(newCt, z, MLKEM_SEED_LEN);
    (void)memcpy(newCt + MLKEM_SEED_LEN, ct, ctLen);
    CRYPT_SHAKE256(r, MLKEM_SHARED_KEY_LEN, newCt, ctLen + MLKEM_SEED_LEN);

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