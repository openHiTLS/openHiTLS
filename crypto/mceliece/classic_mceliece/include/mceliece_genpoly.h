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

#ifndef MCELIECE_GENPOLY_H
#define MCELIECE_GENPOLY_H

#include "mceliece_types.h"
#include "mceliece_gf.h"

#ifdef __cplusplus
extern "C" {
#endif

// Compute the minimal/connection polynomial g(x) of f over GF(2^m)
// out[0..t-1] are coefficients g_0..g_{t-1} with monic leading coeff implied
// f[0..t-1] are coefficients of f(x) in GF(2^m)
// Returns 0 on success, -1 on failure (singular system)
int GenpolyOverGF(GFElement *out, const GFElement *f, int t, int m);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_GENPOLY_H


