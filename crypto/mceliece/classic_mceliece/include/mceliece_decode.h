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

#ifndef MCELIECE_DECODE_H
#define MCELIECE_DECODE_H

#include "mceliece_types.h"
#include "mceliece_matrix_ops.h"
#include "mceliece_gf.h"
#include "mceliece_vector.h"
#include "mceliece_poly.h"
#include "mceliece_controlbits.h"

#ifdef __cplusplus
extern "C" {
#endif

// Syndrome computation - calculates syndrome for received vector
void ComputeSyndrome(const uint8_t *received, const GFPolynomial *g, const GFElement *alpha, GFElement *syndrome, const McelieceParams *params);

// Berlekamp-Massey algorithm - compute only error locator polynomial sigma
McElieceError BerlekampMassey(const GFElement *syndrome, GFPolynomial *sigma, const McelieceParams *params);

// Chien search - finds roots of error locator polynomial
McElieceError ChienSearch(const GFPolynomial *sigma, const GFElement *alpha, int *errorPositions, int *numErrors, const McelieceParams *params);

// Goppa code decoding - recovers error vector from syndrome
McElieceError DecodeGoppa(
    const uint8_t *received, const GFPolynomial *g, const GFElement *alpha, uint8_t *errorVector, int *decodeSuccess, const McelieceParams *params);

#ifdef __cplusplus
}
#endif

#endif  // MCELIECE_DECODE_H
