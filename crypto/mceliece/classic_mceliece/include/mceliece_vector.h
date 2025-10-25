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

#ifndef MCELIECE_VECTOR_H
#define MCELIECE_VECTOR_H

#include "mceliece_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bit manipulation functions for binary vectors
void VectorSetBit(uint8_t *vec, int bitIdx, bool value);
int  VectorGetBit(const uint8_t *vec, int bitIdx);

// Vector utility functions
int  VectorWeight(const uint8_t *vec, int lenBytes);  // Calculate Hamming weight

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_VECTOR_H
