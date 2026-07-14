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
#ifdef HITLS_CRYPTO_MCELIECE

#include <string.h>

#include "mceliece_local.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"

// SWAR popcount
#define PARA_6960_MT 1547
#define PARA_6688_8192_MT 1664

// Count how many 1-bit in x
static inline unsigned Pop64(uint64_t x)
{ // 64-bit SWAR pop-count constants—bit masks for 2-bit, 4-bit, 8-bit and byte-lane aggregation
    uint64_t tmpX = x;
    tmpX -= (tmpX >> 1) & 0x5555555555555555ULL;
    tmpX = (tmpX & 0x3333333333333333ULL) + ((tmpX >> 2) & 0x3333333333333333ULL);
    tmpX = (tmpX + (tmpX >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (unsigned)((tmpX * 0x0101010101010101ULL) >> 56); // Final shift to accumulate 8 byte sums into the high byte
}

static void CopyHeadMT(uint8_t *dst, const uint8_t *src, const McelieceParams *params)
{
    const int32_t wholeBytes = params->mt >> 3;
    const int32_t tailBits = params->mt & 7;
    memcpy(dst, src, (uint32_t)wholeBytes);
    if (tailBits != 0) {
        uint8_t mask = (uint8_t)((1U << tailBits) - 1U);
        dst[wholeBytes] = (uint8_t)((dst[wholeBytes] & (uint8_t)~mask) | (src[wholeBytes] & mask));
    }
}

static void ShiftErrorMt(uint8_t *src, uint8_t *dst, uint32_t mt, uint32_t k)
{
    switch(mt) {
        // parameter 6688,8192
        case PARA_6688_8192_MT:
            memcpy(dst, src, k >> 3);
            break;
        // parameter 6960
        case PARA_6960_MT: {
            uint32_t numBytes = (k + 7) >> 3;
            uint32_t shift = mt & 0x07;
            for (uint32_t i = 0; i < numBytes - 1; ++i) {
               dst[i] |= src[i] >> shift;
               dst[i] |= src[i + 1] << (8 - shift);
            }
            dst[numBytes - 1] = src[numBytes - 1] >> shift;
        }
        default:
            return;
    }
}

static void ComputeParity(uint8_t *ciphertext, const uint8_t *errorVector, const GFMatrix *matT,
                          const McelieceParams *params)
{
    for (int32_t r = 0; r < params->mt; r++) {
        uint8_t *row = matT->data + r * params->kBytes;
        const int32_t n64 = params->kBytes >> 3;
        int32_t leftBytes = params->kBytes - (n64 << 3);
        uint64_t acc = 0;
        for (int32_t j = 0; j < n64; j++) {
#ifdef FORCE_ADDR_ALIGN
            acc ^= GET_UINT64_LE(row, j << 3) & GET_UINT64_LE(errorVector, j << 3);
#else
            acc ^= ((const uint64_t *)row)[j] & ((const uint64_t *)errorVector)[j];
#endif
        }
        for (int32_t j = 0; j < leftBytes; ++j) {
            acc ^= row[(n64 << 3) + j] & errorVector[(n64 << 3) + j];
        }
        uint8_t bit = Pop64(acc) & 1;
        ciphertext[r >> 3] ^= bit << (r & 7u);
    }
}

// Encode: C = He, where H = (I_mt | T)
void EncodeVector(uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params)
{
    // copy e[0...mt -1] to C
    CopyHeadMT(ciphertext, errorVector, params);
    uint64_t shiftError[102] = { 0 };
    //Bit shift: errorVector = b0b1..b_{mt-1}b_{mt}....b_{n-1} --> shiftError = b_{mt}b_{mt+1}...b_{n-1}
    ShiftErrorMt(errorVector + (params->mt >> 3), (uint8_t *)shiftError, params->mt, params->k);
    // T & shiftError 
    ComputeParity(ciphertext, (const uint8_t *)shiftError, matT, params);
}

static void PositionToEConstTime(const uint16_t *posList, McelieceParams *para, uint8_t *e)
{
// Build the output in 64-bit words while keeping output addresses independent of the error positions.
    uint64_t bitValues[MCELIECE_T_MAX];
    // for j-th position, its bitmask in u64 is posList[j] & 63; word index is posList[j] >> 6
    for (int32_t j = 0; j < para->t; j++) {
        bitValues[j] = 1ULL << (posList[j] & 63);
    }
    const int32_t wordCount = (para->nBytes + 7) >> 3;
    for (int32_t i = 0; i < wordCount; i++) {
        uint64_t word = 0;
        for (int32_t j = 0; j < para->t; j++) {
            uint64_t mask = SAME_MASK(i, posList[j] >> 6);
            word |= bitValues[j] & mask;
        }
        const int32_t offset = i << 3;
        int32_t bytes = para->nBytes - offset;
        if (bytes > 8) {
            bytes = 8;
        }
        // Little-endian put word to e
        for (int32_t j = 0; j < bytes; j++) {
            e[offset + j] = (uint8_t)(word >> (j << 3));
        }
    }
    BSL_SAL_CleanseData(bitValues, para->t * sizeof(uint64_t));
}

int32_t FixedWeightVector(CRYPT_MCELIECE_Ctx *ctx, uint8_t *e)
{
    const int32_t t = ctx->para->t;
    const int32_t sampleCnt = (ctx->para->n == MCELIECE_Q) ? t : 2 * t;

    // Allocate random candidates and selected positions in one block.
    const uint32_t randBytesSize = (uint32_t)sampleCnt * sizeof(uint16_t);
    const uint32_t posListSize = (uint32_t)t * sizeof(uint16_t);
    const uint32_t totalSize = randBytesSize + posListSize;

    uint8_t *buffer = BSL_SAL_Malloc(totalSize);
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint8_t *randBytes = buffer;
    uint16_t *posList = (uint16_t *)(buffer + randBytesSize);

    int32_t ret = CRYPT_SUCCESS;
    int32_t tryCount = 0;
    uint32_t duplicate;
    while (tryCount < MCELIECE_MAX_TRY_COUNT) {
        ++tryCount;
        duplicate = 0;
        ret = CRYPT_RandEx(ctx->libCtx, randBytes, randBytesSize);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }

        int32_t validN = 0;
        for (int32_t i = 0; i < sampleCnt && validN < t; i++) {
            uint16_t v = (((uint16_t)randBytes[i * 2] | (uint16_t)randBytes[i * 2 + 1] << 8) & MCELIECE_Q_1);
            if (v < (uint16_t)ctx->para->n) {
                posList[validN] = v;
                validN++;
            }
        }

        if (validN < t) {
            if (tryCount == MCELIECE_MAX_TRY_COUNT) {
                BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ENCODE_FAIL);
                ret = CRYPT_MCELIECE_ENCODE_FAIL;
                goto EXIT;
            }
            continue;
        }
        for (int32_t i = 1; i < t; i++) {
            for (int32_t j = 0; j < i; j++) {
                duplicate |= Uint32ConstTimeEqual(posList[i], posList[j]);
            }
        }
        if (duplicate == 0) {
            break;
        } 
    }
    if (duplicate != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_ENCODE_FAIL);
        ret = CRYPT_MCELIECE_ENCODE_FAIL;
        goto EXIT;
    }
    PositionToEConstTime(posList, ctx->para, e);
EXIT:
    BSL_SAL_ClearFree(buffer, totalSize);
    return ret;
}


// Calculate syndrome from a received vector r
// Input: r is a length-n bit vector where r[0..mt-1] contains the ciphertext bits and the rest are zero
// Output: syndrome[0..2t-1]
int32_t ComputeSyndrome(const uint8_t *received, const GFPolynomial *g, const uint16_t *alpha,
                        const McelieceParams *params, uint16_t *syndrome)
{
    const int32_t syndLen = params->t << 1;

    uint16_t *gAlpha = (uint16_t *)BSL_SAL_Malloc(params->n * sizeof(uint16_t));
    uint16_t *invG2 = (uint16_t *)BSL_SAL_Malloc(params->n * sizeof(uint16_t));
    if (gAlpha == NULL || invG2 == NULL) {
        BSL_SAL_FREE(gAlpha);
        BSL_SAL_FREE(invG2);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    for (int32_t i = 0; i < params->n; i++) {
        gAlpha[i] = GFPolyEval(g, alpha[i]);
        invG2[i] = GFInverse(GFMultiplication(gAlpha[i], gAlpha[i]));
    }

    for (int32_t j = 0; j < syndLen; j++) {
        uint16_t acc = 0;
        for (int32_t b = 0; b < params->n; ++b) {
            uint32_t byteIdx = b >> 3;
            uint32_t bitIdx = b & 0x07;
            if ((received[byteIdx] & (1u << bitIdx)) != 0) {
                uint16_t t = GFMultiplication(GFPower(alpha[b], j), invG2[b]);
                acc = GFAddtion(acc, t);
            }
        }
        syndrome[j] = acc;
    }
    BSL_SAL_ClearFree(gAlpha, params->n * sizeof(uint16_t));
    BSL_SAL_ClearFree(invG2, params->n * sizeof(uint16_t));
    return CRYPT_SUCCESS;
}

static void BmInitState(GFPolynomial *polyC, GFPolynomial *polyB, int32_t *lenLFSR, uint16_t *b)
{
    GFPolySetCoeff(polyC, 0, 1);
    GFPolySetCoeff(polyB, 1, 1);
    *lenLFSR = 0;
    *b = 1;
}

// Compute discrepancy d_N = s_N + Σ C_i * s_{N-i}
static uint16_t BmComputeDiscrepancy(const uint16_t *syndrome, const GFPolynomial *polyC, const int32_t lenN,
                                     const int32_t t)
{
    uint16_t d = 0;
    int32_t loopLen = (t <= lenN) ? t : lenN;
    for (int32_t i = 0; i <= loopLen; i++) {
        d = GFAddtion(d, GFMultiplication(GFPolyGetCoeff(polyC, i), syndrome[lenN - i]));
    }
    return d;
}


// Berlekamp-Massey Algorithm according to Classic McEliece specification
// compute only error locator polynomial sigma
// Input: syndrome sequence s[0], s[1], ..., s[2t-1]
// Output: error locator polynomial sigma and error evaluator polynomial omega
static int32_t BerlekampMassey(const uint16_t *syndrome, GFPolynomial *sigma, const McelieceParams *params)
{
    GFPolynomial *polyC = GFPolyCreate(params->t);
    GFPolynomial *polyB = GFPolyCreate(params->t);
    GFPolynomial *polyT = GFPolyCreate(params->t);

    if (polyC == NULL || polyB == NULL || polyT == NULL) {
        GFPolyFree(polyC);
        GFPolyFree(polyB);
        GFPolyFree(polyT);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t lenLFSR;
    uint16_t b;
    BmInitState(polyC, polyB, &lenLFSR, &b);
    for (int32_t lenN = 0; lenN < 2 * params->t; lenN++) {
        uint16_t d = BmComputeDiscrepancy(syndrome, polyC, lenN, params->t);
        uint16_t dMask = ((uint16_t)(d - 1) >> 15 ) - 1;
        uint16_t nMask = ((uint16_t)(lenN - (lenLFSR << 1)) >> 15) - 1;
        nMask &= dMask;
        GFPolyCopy(polyT, polyC);
        uint16_t corr = GFDivision(d, b);
        GFPolyAddScaledMasked(polyC, polyB, corr, dMask);
        lenLFSR = (((~nMask) & lenLFSR) | (nMask & (lenN + 1 - lenLFSR)));
        GFPolySelectMasked(polyB, polyT, nMask);
        b = (((~nMask) & b) | (nMask & d));
        GFPolyShiftUp(polyB);
    }
    GFPolyReverse(sigma, polyC);
    GFPolyFree(polyC);
    GFPolyFree(polyB);
    GFPolyFree(polyT);
    return CRYPT_SUCCESS;
}

// true if whole syndrome is zero
static bool IsZeroSyndrome(const uint16_t *s, const int32_t t2)
{
    uint16_t accum = 0;
    for (int32_t i = 0; i < t2; i++) {
        accum |= s[i]; // bitwise OR to accumulate any non-zero bytes in the syndrome
    }
    return accum == 0;
}

// BM + Chien in one shot
static int32_t LocateErrors(const uint16_t *syn, const uint16_t *alpha, uint8_t *errorVec,
                            const McelieceParams *params)
{
    GFPolynomial *sigma = GFPolyCreate(params->t);
    if (sigma == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BerlekampMassey(syn, sigma, params);
    if (ret != CRYPT_SUCCESS) {
        GFPolyFree(sigma);
        return ret;
    }
    for (int32_t i = 0; i < params->n; i++) {
        uint16_t image = GFPolyEval(sigma, alpha[i]);
        uint32_t mask = Uint32ConstTimeIsZero(image);
        VectorSetBitMasked(errorVec, i, mask >> 31);
    }
    GFPolyFree(sigma);
    return CRYPT_SUCCESS;
}

int32_t DecodeGoppa(const uint8_t *received, const GFPolynomial *g, const uint16_t *alpha,
                    const McelieceParams *params, uint8_t *errorVector, uint16_t *decodeSyndrome)
{
    int32_t ret = ComputeSyndrome(received, g, alpha, params, decodeSyndrome);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // if decodeSyndrome is zero, meaning that it has no errors to locate, return success
    if (IsZeroSyndrome(decodeSyndrome, 2 * params->t)) {
        return CRYPT_SUCCESS;
    }
    ret = LocateErrors(decodeSyndrome, alpha, errorVector, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return ret;
}
#endif
