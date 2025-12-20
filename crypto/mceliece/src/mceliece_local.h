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
#include "securec.h"

#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCELIECE_GF_POLY    0x201B
#define MCELIECE_SEED_BYTES 48

#define MCELIECE_L      256
#define MCELIECE_SIGMA1 16
#define MCELIECE_SIGMA2 32
#define MCELIECE_MU     32
#define MCELIECE_NU     64

#define MCELIECE_Q   8192 // Q = 2^m
#define MCELIECE_Q_1 8191 // Q-1

#define MCELIECE_PARA_6688_N 6688
#define MCELIECE_PARA_6960_N 6960
#define MCELIECE_PARA_8192_N 8192

#define MCELIECE_L_BYTES ((MCELIECE_L) / (8))

#define SAME_MASK(k, val) ((uint64_t)(-(int64_t)(((((uint32_t)((k) ^ (val)))) - (1U)) >> (31))))

typedef uint16_t GFElement;
typedef struct {
    int32_t rows;
    int32_t cols;
    GFElement *data;
} GFMatrixFq;

typedef struct {
    GFElement *coeffs;
    int32_t degree;
    int32_t maxDegree;
} GFPolynomial;

typedef struct {
    uint8_t *data;
    int32_t rows;
    int32_t cols;
    int32_t colsBytes;
} GFMatrix;

typedef struct {
    uint8_t delta[MCELIECE_L_BYTES];
    uint64_t c;
    GFPolynomial g;
    GFElement *alpha;
    uint8_t *s;
    uint8_t *controlbits;
    size_t controlbitsLen;
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

static inline uint64_t CMLoad8(const uint8_t *x)
{
    uint64_t r = 0;
    memcpy_s(&r, 8, x, 8);
    return r;
}

static inline void CMStore8(uint8_t *x, uint64_t v)
{
    memcpy_s(x, 8, &v, 8);
}

// trailing zero count
static inline int32_t CMCtz64(uint64_t x)
{
    int32_t c = 0;
    while ((x & 1) == 0) {
        c++;
        x >>= 1;
    }
    return c;
}

// =================================================================================
// Control Bits and Support Functions
// =================================================================================
/* Compute control bits for a Benes network from a permutation pi of size n=2^w.
 * out must point to ((2*w-1)*n/16) bytes, zeroed by the caller or by the impl. */
int32_t CbitsFromPermNs(uint8_t *out, const int16_t *pi, int64_t w, int64_t n);

// Derive support L[0..N-1] from control bits
int32_t SupportFromCbits(GFElement *L, const uint8_t *cbits, int64_t w, int32_t lenN);

// =================================================================================
// Goppa Encode and Decode Functions
// =================================================================================
// Goppa code decoding - recovers error vector from syndrome
int32_t DecodeGoppa(const uint8_t *received, const GFPolynomial *g, const GFElement *alpha, uint8_t *errorVector,
                    int32_t errorVecLen, int32_t *decodeSuccess, const McelieceParams *params);

// Generate a random vector with fixed Hamming weight t
// Used in the encapsulation phase to generate the error vector e
int32_t FixedWeightVector(CRYPT_MCELIECE_Ctx *ctx, uint8_t *output);

// Encode an error vector using the public key matrix T
// Computes C = H * e where H = [I_mt | T]
int32_t EncodeVector(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext,
                     const McelieceParams *params);

// =================================================================================
// Poly Functions
// =================================================================================
// Compute the minimal/connection polynomial g(x) of f over GF(2^m)
// out[0..t-1] are coefficients g_0..g_{t-1} with monic leading coeff implied
// f[0..t-1] are coefficients of f(x) in GF(2^m)
// Returns 0 on success, -1 on failure (singular system)
int32_t GenPolyOverGF(GFElement *out, const GFElement *f, int32_t t, int32_t m);
// GF(2^13) add(/xor)
GFElement GFAddtion(GFElement a, GFElement b);
// GF(2^13) mul
GFElement GFMultiplication(GFElement a, GFElement b);
// GF(2^13) inverse
GFElement GFInverse(GFElement a);
// GF(2^13) division
GFElement GFDivision(GFElement a, GFElement b);
// GF(2^13) power
GFElement GFPower(GFElement base, int32_t exp);

// Polynomial creation and destruction
GFPolynomial *PolynomialCreate(const int32_t maxDegree);
void PolynomialFree(GFPolynomial *poly);

void PolynomialRoots(GFElement *out, const GFElement *f, const GFElement *L, int32_t n, int32_t t);

GFElement PolynomialEval(const GFPolynomial *poly, GFElement x);

int32_t PolynomialSetCoeff(GFPolynomial *poly, const int32_t degree, const GFElement coeff);

int32_t PolynomialCopy(GFPolynomial *dst, const GFPolynomial *src);

// =================================================================================
// Kem Functions
// =================================================================================
int32_t SeededKeyGenInternal(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params,
                             bool isSemi);
int32_t McElieceEncapsInternal(CRYPT_MCELIECE_Ctx *ctx, uint8_t *ciphertext, uint8_t *sessionKey, bool isPc);
int32_t McElieceDecapsInternal(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey,
                               const McelieceParams *params, bool isPc);
McelieceParams *McelieceGetParamsById(int32_t algID);

// Matrix creation and destruction
GFMatrix *MatrixCreate(const int32_t rows, const int32_t cols);
void MatrixFree(GFMatrix *mat);

// Matrix element access (bit-level operations)
void MatrixSetBit(GFMatrix *mat, const int32_t row, const int32_t col, const int32_t value);
int32_t MatrixGetBit(const GFMatrix *mat, const int32_t row, const int32_t col);

// Reference-style matrix operations (matching NIST implementation)
int32_t BuildParityCheckMatrixReferenceStyle(GFMatrix *matH, const GFPolynomial *g, const GFElement *support,
                                             const McelieceParams *params);
int32_t ReduceToSystematicFormReferenceStyle(GFMatrix *matH);

int32_t ColsRermutation(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots, int32_t mt);
int32_t GaussPartialSemiSystematic(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots,
                                   const int32_t mt, const int32_t paramN);

// High-level SHAKE256 function
int32_t McElieceShake256(uint8_t *output, const size_t outlen, const uint8_t *input, size_t inlen);

// Bit manipulation functions for binary vectors
void VectorSetBit(uint8_t *vec, const uint32_t bitIdx, const uint32_t value);
uint32_t VectorGetBit(const uint8_t *vec, const uint32_t bitIdx);

// Vector utility functions
int32_t VectorWeight(const uint8_t *vec, const int32_t lenBytes); // Calculate Hamming weight

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_LOCAL_H