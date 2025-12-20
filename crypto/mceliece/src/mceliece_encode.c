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
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE

#include "mceliece_local.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_util_rand.h"

// SWAR popcount
#define MAX_TRY_COUNT 50

static inline unsigned Pop64(uint64_t x)
{ // 64-bit SWAR pop-count constants—bit masks for 2-bit, 4-bit, 8-bit and byte-lane aggregation
    x -= (x >> 1) & 0x5555555555555555ULL;
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (unsigned)((x * 0x0101010101010101ULL) >> 56); // Final shift to accumulate 8 byte sums into the high byte
}

// bit-flip
static inline void VecFlip(uint8_t *v, int32_t idx)
{
    v[idx >> 3] ^= 1u << (idx & 7);
}

static inline uint64_t MatrixGetU64(const GFMatrix *matT, const int32_t row, const int32_t colBase)
{
    const int32_t k = matT->cols;
    if (colBase >= k) {
        return 0;
    }

    const uint8_t *p = &matT->data[row * matT->colsBytes + (colBase >> 3)];
    const int32_t tailBits = k - colBase; // tail bits
    const int32_t tailBytes = (tailBits + 7) >> 3;

    uint64_t w = 0;
    if (tailBytes < 8) {
        // tail: less than 8 bits
        (void)memcpy_s(&w, tailBytes, p, tailBytes);
    } else {
        // tail: full 8 bits
        (void)memcpy_s(&w, 8, p, 8);
    }

    w >>= (colBase & 7);
    if (tailBits < 64) {
        w &= (~0ULL >> (64 - tailBits)); // Mask to keep only valid low bits when fewer than 64 bits are requested
    }
    return w;
}

static int32_t EncodeVector6688(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext,
                                const McelieceParams *params)
{
    const uint8_t *pkPtr = matT->data;
    uint8_t *row = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (row == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (int32_t i = 0; i < params->mt; i++) {
        (void)memset_s(row, params->nBytes, 0, params->nBytes);
        const int32_t n64 = params->nBytes >> 3;
        uint64_t *w = (uint64_t *)row;

        for (int32_t j = 0; j < n64; j += 4) {
            w[j] = 0;
            w[j + 1] = 0;
            w[j + 2] = 0;
            w[j + 3] = 0;
        }
        for (int32_t j = n64 & ~3; j < n64; j++) {
            w[j] = 0;
        }
        for (int32_t j = n64 << 3; j < params->nBytes; j++) {
            row[j] = 0;
        }
        for (int32_t j = 0; j < params->kBytes; j++) {
            row[params->nBytes - params->kBytes + j] = pkPtr[j];
        }
        row[i >> 3] |= 1u << (i & 7u);

        uint8_t bit = 0;
        for (int32_t j = 0; j < params->nBytes; j++) {
            uint8_t t = row[j] & errorVector[j];
            t ^= t << 4;
            t ^= t << 2;
            t ^= t << 1;
            bit ^= t >> 7;
        }
        bit &= 1;
        ciphertext[i >> 3] |= (bit << (i & 7));

        pkPtr += params->kBytes;
    }

    BSL_SAL_FREE(row);
    return CRYPT_SUCCESS;
}
static void CopyHeadMT6960(uint8_t *dst, const uint8_t *src, const McelieceParams *params)
{
    int32_t wholeBytes = params->mt >> 3;
    int32_t tailBits = params->mt & 7;
    const uint64_t *s64 = (const uint64_t *)src;
    uint64_t *d64 = (uint64_t *)dst;
    int32_t n64 = wholeBytes >> 3;
    for (int32_t i = 0; i < n64; i++) {
        d64[i] = s64[i];
    }
    const uint8_t *s = src + (n64 << 3);
    uint8_t *d = dst + (n64 << 3);
    int32_t n = wholeBytes & 7;
    if (n >= 4) {
        (void)memcpy_s(d, 4, s, 4);
        s += 4;
        d += 4;
        n -= 4;
    }
    if (n >= 2) {
        (void)memcpy_s(d, 2, s, 2);
        s += 2;
        d += 2;
        n -= 2;
    }
    if (n >= 1) {
        *d = *s;
        ++s;
        ++d;
    }
    if (tailBits != 0) {
        uint8_t m = (uint8_t)((1U << tailBits) - 1);
        *d = (uint8_t)((*d & ~m) | (*s & m));
    }
}

static int32_t ComputeParity6960(uint8_t *ciphertext, const uint8_t *errorVector, const GFMatrix *matT,
                                 const McelieceParams *params)
{
    const int32_t slices = (params->k + 63) >> 6;
    uint64_t *eSlab = (uint64_t *)BSL_SAL_Malloc(slices * sizeof(uint64_t));
    if (eSlab == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    for (int32_t s = 0; s < slices; s++) {
        uint64_t w = 0;
        int32_t base = s << 6;
        int32_t limit = (base + 64 < params->k) ?
                            64 :
                            (params->k - base); // Width of one 64-bit slice processed per inner pop-count iteration
        int32_t bitIdx = params->mt + base;
        for (int32_t b = 0; b < limit; b++) {
            int32_t bi = bitIdx + b;
            uint8_t byte = errorVector[bi >> 3];
            int32_t bp = bi & 7;
            w |= ((uint64_t)((byte >> bp) & 1)) << b;
        }
        w &= (limit == 64) ? ~0ULL : (~0ULL >> (64 - limit));
        eSlab[s] = w;
    }
    static const uint8_t pop4[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
    for (int32_t r = 0; r < params->mt; r++) {
        int32_t dot = 0;
        for (int32_t s = 0; s < slices; s++) {
            uint64_t es = eSlab[s];
            uint64_t m = MatrixGetU64(matT, r, s << 6);
            uint64_t v = m & es;
            for (int32_t shift = 0; shift < 64;
                 shift += 4) { // Step size for nibble-wise pop-count using the 4-bit lookup table pop4
                dot += pop4[(v >> shift) & 0xF];
            }
        }
        if ((dot & 1) != 0) {
            VecFlip(ciphertext, r);
        }
    }
    BSL_SAL_FREE(eSlab);
    return CRYPT_SUCCESS;
}

static int32_t EncodeVector6960(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext,
                                const McelieceParams *params)
{
    CopyHeadMT6960(ciphertext, errorVector, params);
    return ComputeParity6960(ciphertext, errorVector, matT, params);
}

static void BuildRow8192(uint8_t *row, const uint8_t *pkPtr, int32_t rowIdx, const McelieceParams *params)
{
    const int32_t leading = params->nBytes - params->kBytes;
    const int32_t n64Copy = leading >> 3;
    uint64_t *w = (uint64_t *)row;

    for (int32_t j = 0; j < n64Copy; j += 4) { // Quad-word (4 * 8 = 32-byte) unroll factor
        w[j] = 0;
        w[j + 1] = 0;
        w[j + 2] = 0;
        w[j + 3] = 0;
    }
    for (int32_t j = n64Copy & ~3; j < n64Copy; j++) {
        w[j] = 0;
    }
    for (int32_t j = leading & ~7; j < leading; j++) {
        row[j] = 0;
    }
    (void)memcpy_s(row + leading, params->kBytes, pkPtr, params->kBytes);
    row[rowIdx >> 3] |= 1u << (rowIdx & 7u);
}

static void ComputeRow8192(uint8_t *ciphertext, const uint8_t *errorVector, const uint8_t *row, int32_t rowIdx,
                           const McelieceParams *params)
{
    const int32_t n64 = params->nBytes >> 3;
    const uint64_t *e64 = (const uint64_t *)errorVector;
    uint64_t acc = 0;
    for (int32_t j = 0; j < n64; j++) {
        acc ^= ((const uint64_t *)row)[j] & e64[j];
    }
    uint8_t bit = Pop64(acc) & 1;
    ciphertext[rowIdx >> 3] |= bit << (rowIdx & 7u);
}

static int32_t EncodeVector8192(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext,
                                const McelieceParams *params)
{
    const uint8_t *pkPtr = matT->data;
    uint8_t *row = (uint8_t *)BSL_SAL_Malloc(params->nBytes);
    if (row == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (int32_t i = 0; i < params->mt; i++) {
        (void)memset_s(row, params->nBytes, 0, params->nBytes);
        BuildRow8192(row, pkPtr, i, params);
        ComputeRow8192(ciphertext, errorVector, row, i, params);
        pkPtr += params->kBytes;
    }
    BSL_SAL_FREE(row);
    return CRYPT_SUCCESS;
}

// Encode: C = He, where H = (I_mt | T)
int32_t EncodeVector(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext,
                     const McelieceParams *params)
{
    switch (params->n) {
        case MCELIECE_PARA_6688_N:
            return EncodeVector6688(errorVector, matT, ciphertext, params);
        case MCELIECE_PARA_6960_N:
            return EncodeVector6960(errorVector, matT, ciphertext, params);
        case MCELIECE_PARA_8192_N:
            return EncodeVector8192(errorVector, matT, ciphertext, params);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ENCODE_FAIL);
            return CRYPT_MCELIECE_ENCODE_FAIL;
    }
}

static int32_t FixedWeightVector6688Or6960(CRYPT_MCELIECE_Ctx *ctx, uint8_t *e)
{
    const int32_t t = ctx->para->t;
    const int32_t sampleCnt = 2 * t;

    // Allocate all buffers in one block: randBytes + posList + gfBuf
    const size_t randBytesSize = sampleCnt * sizeof(uint16_t);
    const size_t posListSize = t * sizeof(uint16_t);
    const size_t gfBufSize = sampleCnt * sizeof(uint16_t);
    const size_t totalSize = randBytesSize + posListSize + gfBufSize;

    uint8_t *buffer = BSL_SAL_Malloc(totalSize);
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint8_t *randBytes = buffer;
    uint16_t *posList = (uint16_t *)(buffer + randBytesSize);
    uint16_t *gfBuf = (uint16_t *)(buffer + randBytesSize + posListSize);

    int32_t ret;
    int32_t tryCount = 0;
    int32_t duplicate = 0;

    while (tryCount < MAX_TRY_COUNT) {
        ++tryCount;
        ret = CRYPT_RandEx(ctx->libCtx, randBytes, randBytesSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        for (int32_t i = 0; i < sampleCnt; i++) {
            gfBuf[i] = ((uint16_t)randBytes[i * 2] | (uint16_t)randBytes[i * 2 + 1] << 8) & MCELIECE_Q_1;
        }

        int32_t validN = 0;
        for (int32_t i = 0; i < sampleCnt && validN < t; i++) {
            uint16_t v = gfBuf[i];
            uint16_t diff = v ^ (uint16_t)ctx->para->n;
            uint16_t cmp = v - (uint16_t)ctx->para->n;
            cmp ^= diff & (cmp ^ v ^ (1U << 15));
            if ((int16_t)cmp >> 15) {
                posList[validN] = v;
                validN++;
            }
        }

        if (validN < t) {
            continue;
        }

        duplicate = 0;
        for (int32_t i = 1; i < t && duplicate == 0; i++) {
            for (int32_t j = 0; j < i; j++) {
                duplicate |= SAME_MASK(posList[i], posList[j]);
            }
        }

        if (duplicate == 0) {
            break;
        }
    }

    if (tryCount == MAX_TRY_COUNT && duplicate != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ENCODE_FAIL);
        ret = CRYPT_MCELIECE_ENCODE_FAIL;
        goto EXIT;
    }

    (void)memset_s(e, ctx->para->nBytes, 0, ctx->para->nBytes);
    for (int32_t i = 0; i < t; i++) {
        VectorSetBit(e, posList[i], 1);
    }

EXIT:
    BSL_SAL_FREE(buffer);
    return ret;
}

static int32_t FixedWeightVector8192(CRYPT_MCELIECE_Ctx *ctx, uint8_t *e)
{
    uint8_t *randBytes = BSL_SAL_Malloc(ctx->para->t * sizeof(uint16_t)); // raw random bytes; double sampleCnt
    uint16_t *posList = (uint16_t *)BSL_SAL_Malloc(ctx->para->t * sizeof(uint16_t)); // final distinct positions
    if (randBytes == NULL || posList == NULL) {
        BSL_SAL_FREE(randBytes);
        BSL_SAL_FREE(posList);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t tryCount = 0;
    int32_t duplicate = 0;
    while (tryCount < MAX_TRY_COUNT) {
        tryCount++;
        int32_t ret = CRYPT_RandEx(ctx->libCtx, randBytes, ctx->para->t * sizeof(uint16_t));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_FREE(randBytes);
            BSL_SAL_FREE(posList);
            return ret;
        }

        for (int32_t i = 0; i < ctx->para->t; i++) { // load 13-bit values
            posList[i] = ((uint16_t)randBytes[i * 2] | (uint16_t)randBytes[i * 2 + 1] << 8) & MCELIECE_Q_1;
        }

        duplicate = 0;
        for (int32_t i = 1; i < ctx->para->t && duplicate == 0; i++) {
            for (int32_t j = 0; j < i; j++) {
                if (SAME_MASK(posList[i], posList[j]) != 0) {
                    duplicate = 1;
                    break;
                }
            }
        }
        if (duplicate == 0) {
            break; // success
        }
    }
    if (tryCount == MAX_TRY_COUNT && duplicate != 0) {
        BSL_SAL_FREE(randBytes);
        BSL_SAL_FREE(posList);
        return CRYPT_MCELIECE_ENCODE_FAIL;
    }
    uint8_t *bitMask = (uint8_t *)BSL_SAL_Malloc(ctx->para->t * sizeof(uint8_t));
    if (bitMask == NULL) {
        BSL_SAL_FREE(randBytes);
        BSL_SAL_FREE(posList);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (int32_t j = 0; j < ctx->para->t; j++) {
        bitMask[j] = 1U << (posList[j] & 7); // bit inside byte
    }

    (void)memset_s(e, ctx->para->nBytes, 0, ctx->para->nBytes); // init; 1024 B for n=8192
    for (int32_t i = 0; i < ctx->para->nBytes; i++) {
        uint8_t acc = 0;
        for (int32_t j = 0; j < ctx->para->t; j++) {
            acc |= bitMask[j] & SAME_MASK(i, posList[j] >> 3);
        }
        e[i] = acc;
    }
    BSL_SAL_FREE(bitMask);
    BSL_SAL_FREE(randBytes);
    BSL_SAL_FREE(posList);
    return CRYPT_SUCCESS;
}

int32_t FixedWeightVector(CRYPT_MCELIECE_Ctx *ctx, uint8_t *e)
{
    switch (ctx->para->n) {
        case MCELIECE_PARA_6688_N:
        case MCELIECE_PARA_6960_N:
            return FixedWeightVector6688Or6960(ctx, e);
        case MCELIECE_PARA_8192_N:
            return FixedWeightVector8192(ctx, e);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ENCODE_FAIL);
            return CRYPT_MCELIECE_ENCODE_FAIL;
    }
}
#endif
