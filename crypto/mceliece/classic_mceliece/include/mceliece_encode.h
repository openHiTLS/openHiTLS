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

#ifndef MCELIECE_ENCODE_H
#define MCELIECE_ENCODE_H

#include "mceliece_types.h"
#include "mceliece_shake.h"
#include "mceliece_vector.h"
#include "mceliece_rng.h"
#include "mceliece_matrix_ops.h"
#ifdef __cplusplus
extern "C" {
#endif

// Generate a random vector with fixed Hamming weight t
// Used in the encapsulation phase to generate the error vector e
McElieceError FixedWeightVector(uint8_t *output, int vectorLen, int targetWeight, const McelieceParams *params);

// Encode an error vector using the public key matrix T
// Computes C = H * e where H = [I_mt | T]
void EncodeVector(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_ENCODE_H