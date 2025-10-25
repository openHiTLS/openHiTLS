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

#include <assert.h>
#include "mceliece_poly.h"
#include "securec.h"

GFPolynomial *PolynomialCreate(int maxDegree)
{
    GFPolynomial *poly = BSL_SAL_Malloc(sizeof(GFPolynomial));
    if (!poly) {
        return NULL;
    }

    poly->coeffs = BSL_SAL_Calloc(maxDegree + 1, sizeof(GFElement));
    if (!poly->coeffs) {
        BSL_SAL_FREE(poly);
        return NULL;
    }

    poly->degree = -1;
    poly->maxDegree = maxDegree;
    return poly;
}

void PolynomialFree(GFPolynomial *poly)
{
    if (poly) {
        if (poly->coeffs) {
            BSL_SAL_FREE(poly->coeffs);
        }
        BSL_SAL_FREE(poly);
    }
}

void PolynomialRoots(GFElement *out, const GFElement *f, const GFElement *L, const int n, const int t)
{
    for (int i = 0; i < n; i++) {
        GFElement r = f[t];
        GFElement a = L[i];

        // r = r*a + f[k]
        for (int k = t - 1; k >= 0; k--) {
            r = GFAddtion(GFMultiplication(r, a), f[k]);
        }
        out[i] = r;  // f(L[i])
    }
}

// Efficient polynomial evaluation using Horner's method
GFElement PolynomialEval(const GFPolynomial *poly, GFElement x)
{
    if (poly->degree < 0) {
        return 0;  // Zero polynomial
    }

    // Use Horner's method: start with highest degree coefficient
    GFElement result = poly->coeffs[poly->degree];

    // Iterate down to constant term
    for (int i = poly->degree - 1; i >= 0; i--) {
        result = GFMultiplication(result, x);
        result = GFAddtion(result, poly->coeffs[i]);
    }

    return result;
}

void PolynomialSetCoeff(GFPolynomial *poly, int degree, GFElement coeff)
{
    if (degree > poly->maxDegree) {
        return;
    }

    poly->coeffs[degree] = coeff;
    if (coeff != 0 && degree > poly->degree) {
        poly->degree = degree;
    } else if (coeff == 0 && degree == poly->degree) {
        int newDegree = -1;
        for (int i = poly->maxDegree; i >= 0; i--) {
            if (poly->coeffs[i] != 0) {
                newDegree = i;
                break;
            }
        }
        poly->degree = newDegree;
    }
}

void PolynomialCopy(GFPolynomial *dst, const GFPolynomial *src)
{
    if (!dst || !src) {
        return;
    }

    memset_s(dst->coeffs, (dst->maxDegree + 1) * sizeof(GFElement), 0, (dst->maxDegree + 1) * sizeof(GFElement));
    int termsToCopy = (src->degree < dst->maxDegree) ? src->degree : dst->maxDegree;

    if (src->degree < 0) {
        dst->degree = -1;
        return;
    }

    for (int i = 0; i <= termsToCopy; i++) {
        dst->coeffs[i] = src->coeffs[i];
    }

    dst->degree = termsToCopy;
    while (dst->degree >= 0 && dst->coeffs[dst->degree] == 0) {
        dst->degree--;
    }
}
