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

#ifndef MCELIECE_TYPES_H
#define MCELIECE_TYPES_H

#include "internal/mceliece_params.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Irreducible polynomial for GF(2^13): x^13 + x^4 + x^3 + x + 1
#define MCELIECE_GF_POLY 0x201B
#define MCELIECE_SEED_BYTES 48

#define MCELIECE_L 256
#define MCELIECE_SIGMA1 16
#define MCELIECE_SIGMA2 32
#define MCELIECE_MU 32
#define MCELIECE_NU 64

#define MCELIECE_Q 8192
#define MCELIECE_Q_1 8191

#define MCELIECE_L_BYTES ((MCELIECE_L) / (8))

typedef uint16_t GFElement;
typedef struct {
    int rows;
    int cols;
    GFElement *data;
} GFMatrixFq;

typedef struct {
    GFElement *coeffs;
    int degree;
    int maxDegree;
} GFPolynomial;

typedef struct {
    uint8_t *data;
    int rows;
    int cols;
    int colsBytes;
} GFMatrix;

typedef struct {
    uint8_t delta[MCELIECE_L_BYTES];
    uint64_t c;
    GFPolynomial g;
    GFElement *alpha;
    uint8_t *s;
    // Optional: Benes control bits for support generation (size ((2*m-1)*2^m)/16 bytes)
    uint8_t *controlbits;
    size_t controlbitsLen;
} CMPrivateKey;

typedef struct {
    GFMatrix matT;
} CMPublicKey;

typedef enum {
    MCELIECE_SUCCESS = 0,
    MCELIECE_ERROR_INVALID_PARAM = -1,
    MCELIECE_ERROR_MEMORY = -2,
    MCELIECE_ERROR_DECODE_FAIL = -3,
    MCELIECE_ERROR_KEYGEN_FAIL = -4,
    MCELIECE_ERROR_GEN_E_FAIL = -5
} McElieceError;

#ifdef __cplusplus
}
#endif

#endif  // MCELIECE_TYPES_H