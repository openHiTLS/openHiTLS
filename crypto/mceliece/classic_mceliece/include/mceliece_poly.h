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

#ifndef MCELIECE_POLY_H
#define MCELIECE_POLY_H

#include "mceliece_types.h"
#include "mceliece_gf.h"

#ifdef __cplusplus
extern "C" {
#endif

// Polynomial creation and destruction
GFPolynomial *PolynomialCreate(int maxDegree);
void PolynomialFree(GFPolynomial *poly);

void PolynomialRoots(GFElement *out, const GFElement *f, const GFElement *L, int n, int t);

GFElement PolynomialEval(const GFPolynomial *poly, GFElement x);

void PolynomialSetCoeff(GFPolynomial *poly, int degree, GFElement coeff);

void PolynomialCopy(GFPolynomial *dst, const GFPolynomial *src);

#ifdef __cplusplus
}
#endif

#endif  // MCELIECE_POLY_H
