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

#ifndef MCELIECE_GF_H
#define MCELIECE_GF_H

#include "mceliece_types.h"  // for MCELIECE_M/MCELIECE_Q

#ifdef __cplusplus
extern "C" {
#endif

//init
void GFInitial(int m);

// GF(2^13) add(/xor)
GFElement GFAddtion(GFElement a, GFElement b);

// GF(2^13) mul
GFElement GFMultiplication(GFElement a, GFElement b);

// GF(2^13) inverse
GFElement GFInverse(GFElement a);

// GF(2^13) division
GFElement GFDivision(GFElement a, GFElement b);

// GF(2^13) power
GFElement GFPower(GFElement base, int exp);
    

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_GF_H
