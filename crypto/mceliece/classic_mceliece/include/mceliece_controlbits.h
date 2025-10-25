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

#ifndef MCELIECE_CONTROLBITS_H
#define MCELIECE_CONTROLBITS_H

#include "mceliece_types.h"


/* Compute control bits for a Benes network from a permutation pi of size n=2^w.
 * out must point to ((2*w-1)*n/16) bytes, zeroed by the caller or by the impl.
 */
void CbitsFromPermNs(uint8_t *out, const int16_t *pi, long long w, long long n);

// Derive support L[0..N-1] from control bits
void SupportFromCbits(GFElement *L, const uint8_t *cbits, long long w, int lenN);


#endif // MCELIECE_CONTROLBITS_H

