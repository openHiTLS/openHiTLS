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

#ifndef MCELIECE_LOCAL_H
#define MCELIECE_LOCAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "crypt_errno.h"
#include "crypt_algid.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCELIECE_GF_BITS 13

#define MCELIECE_GF_POLY    0x201B
#define MCELIECE_SEED_BYTES 48

#define MCELIECE_L      256
#define MCELIECE_SIGMA1 16
#define MCELIECE_SIGMA2 32
#define MCELIECE_MU     32
#define MCELIECE_NU     64
#define MCELIECE_T_MAX  128
#define MCELIECE_NBYTES_MAX 1024

#define MCELIECE_Q   8192 // Q = 2^m
#define MCELIECE_Q_1 8191 // Q-1

#define MCELIECE_L_BYTES ((MCELIECE_L) / (8))

#define MCELIECE_MAX_TRY_COUNT 50

#define SAME_MASK(k, val) ((uint64_t)(-(int64_t)(((((uint32_t)((k) ^ (val)))) - (1U)) >> (31))))

typedef struct GFPolynomial GFPolynomial;

typedef struct {
    uint8_t *data;
    int32_t rows;
    int32_t cols;
    int32_t colsBytes;
} GFMatrix;

typedef struct {
    uint8_t delta[MCELIECE_L_BYTES];
    uint64_t c;
    GFPolynomial *g;
    uint16_t *alpha;
    uint8_t *s;
    uint8_t *controlbits;
    uint32_t controlbitsLen;
} CMPrivateKey;

typedef struct {
    GFMatrix matT;
} CMPublicKey;

typedef struct McelieceParams {
    int32_t algId;

    int32_t m;
    int32_t n;
    int32_t t;

    int32_t mt;
    int32_t k;
    int32_t q;
    int32_t q1;

    int32_t nBytes;
    int32_t mtBytes;
    int32_t kBytes;

    int32_t privateKeyBytes;
    int32_t publicKeyBytes;
    int32_t sharedKeyBytes;
    int32_t cipherBytes;

    uint8_t semi;
    uint8_t pc;

} McelieceParams;

typedef struct Mceliece_Ctx {
    McelieceParams *para;
    CMPublicKey *publicKey;
    CMPrivateKey *privateKey;
    void *libCtx;
} CRYPT_MCELIECE_Ctx;

static inline uint64_t CMMakeMask(uint64_t x)
{
    int64_t sx = (int64_t)x;
    uint64_t nz = (uint64_t)((sx >> 63) | ((-sx) >> 63));
    return ~nz;
}
// trailing zero count
static inline int32_t CMCtz64(uint64_t x)
{
    uint64_t tmpX = x;
    int32_t c = 0;
    while ((tmpX & 1) == 0) {
        c++;
        tmpX >>= 1;
    }
    return c;
}

// Bit manipulation functions for binary vectors
static inline void VectorSetBitMasked(uint8_t *vec, const uint32_t bitIdx, const uint32_t value)
{
    const uint32_t byteIdx = bitIdx >> 3; // bitIdx / 8
    const uint32_t bitPos = bitIdx & 7;   // bitIdx % 8
    const uint8_t bitMask = (uint8_t)(1u << bitPos);
    const uint8_t valueMask = (uint8_t)(0u - (value & 1u));
    vec[byteIdx] = (uint8_t)((vec[byteIdx] & (uint8_t)~bitMask) | (valueMask & bitMask));
}

static inline uint32_t VectorGetBit(const uint8_t *vec, const uint32_t bitIdx)
{
    const uint32_t byteIdx = bitIdx >> 3; // bitIdx / 8
    const uint32_t bitPos = bitIdx & 7;   // bitIdx % 8
    return (uint32_t)((vec[byteIdx] >> bitPos) & 1u); // lsb
}

static inline int32_t VectoWeight(const uint8_t *vec, const int32_t lenBytes)
{
    int32_t weight = 0;
    for (int32_t i = 0; i < lenBytes; i++) {
        uint8_t byte = vec[i];
        for (uint32_t bit = 0; bit < 8; bit++) {
            weight += (int32_t)((byte >> bit) & 1u);
        }
    }
    return weight;
}

// =================================================================================
// Control Bits and Support Functions
// =================================================================================
/* Compute control bits for a Benes network from a permutation pi of size n=2^w.
 * out must point to ((2*w-1)*n/16) bytes, zeroed by the caller or by the impl. */
int32_t ControlBitsFromBenesNetwork(uint8_t *out, const uint16_t *pi, const int64_t w, const int64_t n);

// Derive support L[0..N-1] from control bits
int32_t SupportSetFromControlbits(uint16_t *L, const uint8_t *cbits, const int64_t w, const int32_t lenN);

// =================================================================================
// Goppa Encode and Decode Functions
// =================================================================================
// Goppa code decoding - recovers error vector from syndrome
int32_t DecodeGoppa(const uint8_t *received, const GFPolynomial *g, const uint16_t *alpha,
                    const McelieceParams *params, uint8_t *errorVector, uint16_t *decodeSyndrome);

// Generate a random vector with fixed Hamming weight t
// Used in the encapsulation phase to generate the error vector e
int32_t FixedWeightVector(CRYPT_MCELIECE_Ctx *ctx, uint8_t *output);

// Encode an error vector using the public key matrix T
// Computes C = H * e where H = [I_mt | T]
void EncodeVector(uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params);

// =================================================================================
// Poly Functions
// =================================================================================
uint16_t GFDivision(uint16_t a, uint16_t b);

uint16_t GFInverse(uint16_t a);

uint16_t GFPower(uint16_t base, int32_t exp);

uint16_t GFMultiplication(uint16_t a, uint16_t b);

uint16_t GFAddtion(uint16_t a, uint16_t b);

void GFPolyMul(GFPolynomial *out, const GFPolynomial *in0, const GFPolynomial *in1);

// Allocate a zero polynomial with a fixed coefficient range [0, degree].
GFPolynomial *GFPolyCreate(const int32_t degree);

// Cleanse and release a polynomial and its coefficient storage. Accepts NULL.
void GFPolyFree(GFPolynomial *poly);
// Evaluate poly(x) over GF(2^m).
uint16_t GFPolyEval(const GFPolynomial *poly, uint16_t x);

// Return the coefficient of poly[degree]. The caller guarantees a valid polynomial and index.
uint16_t GFPolyGetCoeff(const GFPolynomial *poly, const int32_t degree);

// Set the coefficient of poly[degree] within the polynomial's fixed degree range.
void GFPolySetCoeff(GFPolynomial *poly, const int32_t degree, const uint16_t coeff);

// Copy src into dst.
void GFPolyCopy(GFPolynomial *dst, const GFPolynomial *src);

// Return an 0xffff when a == b; otherwise return 0x0000.
uint32_t GFPolyConstTimeEqual(const GFPolynomial *a, const GFPolynomial *b);

// Reverse all coefficients across the fixed range [0, degree].
void GFPolyReverse(GFPolynomial *dst, const GFPolynomial *src);

// Compute dst[i] ^= scale * src[i] & mask.
void GFPolyAddScaledMasked(GFPolynomial *dst, const GFPolynomial *src, uint16_t scale, uint16_t mask);

// Select src into dst when mask is 0xffff, retaining dst when mask is 0x0000.
void GFPolySelectMasked(GFPolynomial *dst, const GFPolynomial *src, uint16_t mask);

// Multiply by x within the fixed range: [a0, a1, a2] -> [0, a0, a1].
void GFPolyShiftUp(GFPolynomial *poly);

// =================================================================================
// Kem Functions
// =================================================================================
int32_t SeededKeyGenInternal(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params,
                             bool isSemi);
int32_t McElieceEncapsInternal(CRYPT_MCELIECE_Ctx *ctx, uint8_t *ciphertext, uint8_t *sessionKey, bool isPc);

int32_t McElieceDecapsInternal(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey,
                               const McelieceParams *params, bool isPc);

// Matrix creation and destruction
GFMatrix *MatrixCreate(const int32_t rows, const int32_t cols);

void MatrixFree(GFMatrix *mat);

// High-level SHAKE256 function
int32_t McElieceShake256(uint8_t *output, const uint32_t outlen, const uint8_t *input, uint32_t inlen);

int32_t ComputeSyndrome(const uint8_t *received, const GFPolynomial *g, const uint16_t *alpha,
                        const McelieceParams *params, uint16_t *syndrome);
#ifdef __cplusplus
}
#endif

#endif // MCELIECE_LOCAL_H
