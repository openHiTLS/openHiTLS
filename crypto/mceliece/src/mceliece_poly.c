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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MCELIECE
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "mceliece_local.h"

struct GFPolynomial {
    uint16_t *coeffs;
    int32_t degree;
};

uint16_t GFAddtion(uint16_t a, uint16_t b)
{
    return (uint16_t)(a ^ b);
}

uint16_t GFMultiplication(uint16_t a, uint16_t b)
{
    uint32_t multiplicand = a & MCELIECE_Q_1;
    uint32_t multiplier = b & MCELIECE_Q_1;
    uint32_t product = 0;

    for (uint32_t i = 0; i < MCELIECE_GF_BITS; i++) {
        uint32_t bitMask = 0u - (multiplier & 1u);
        product ^= multiplicand & bitMask;

        uint32_t highBitMask = 0u - ((multiplicand >> (MCELIECE_GF_BITS - 1)) & 1u);
        multiplicand = ((multiplicand << 1) ^ (MCELIECE_GF_POLY & highBitMask)) & MCELIECE_Q_1;
        multiplier >>= 1;
    }
    return (uint16_t)product;
}

uint16_t GFPower(uint16_t base, int32_t exp)
{
    uint16_t result = 1;
    base &= MCELIECE_Q_1;
    uint32_t exponent = (uint32_t)exp;
    for (uint32_t i = 0; i < MCELIECE_GF_BITS; i++) {
        uint16_t product = GFMultiplication(result, base);
        uint16_t mask = (uint16_t)(0U - (exponent & 1U));
        result = (uint16_t)((product & mask) | (result & (uint16_t)~mask));
        base = GFMultiplication(base, base);
        exponent >>= 1;
    }
    return result;
}

uint16_t GFInverse(uint16_t a)
{
    return GFPower(a, MCELIECE_Q - 2);
}

uint16_t GFDivision(uint16_t a, uint16_t b)
{
    return GFMultiplication(a, GFInverse(b));
}

// Vector multiply in GF((2^m)^t) with reference reduction: x^t + x^7 + x^2 + x + 1
// Matches reference gf mul used in GenPolyOverGF
void GFPolyMul(GFPolynomial *out, const GFPolynomial *in0, const GFPolynomial *in1)
{
    // The degree of poly in mceliece is always t - 1;
    const int32_t t = out->degree + 1;
    // convolution
    uint16_t prod[MCELIECE_T_MAX * 2 - 1] = { 0 };
    for (int32_t i = 0; i < t; i++) {
        for (int32_t j = 0; j < t; j++) {
            prod[i + j] ^= GFMultiplication(in0->coeffs[i], in1->coeffs[j]);
        }
    }

    // reduce high terms using fixed pentanomial
    if (t == 128) {
        for (int32_t i = (t - 1) * 2; i >= t; i--) { // 7, 2, 1, 0: the exponent of prod[x]
            uint16_t v = prod[i];
            prod[i - t + 7] ^= v;
            prod[i - t + 2] ^= v;
            prod[i - t + 1] ^= v;
            prod[i - t + 0] ^= v;
        }
    } else if (t == 119) {
        for (int32_t i = (t - 1) * 2; i >= t; i--) { // 8, 0: the exponent of prod[x]
            uint16_t v = prod[i];
            prod[i - t + 8] ^= v;
            prod[i - t + 0] ^= v;
        }
    }

    for (int32_t i = 0; i < t; i++) {
        out->coeffs[i] = prod[i];
    }
}


GFPolynomial *GFPolyCreate(const int32_t degree)
{
    GFPolynomial *poly = BSL_SAL_Malloc(sizeof(GFPolynomial));
    if (poly == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    poly->coeffs = BSL_SAL_Calloc(degree + 1, sizeof(uint16_t));
    if (poly->coeffs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_FREE(poly);
        return NULL;
    }

    poly->degree = degree;
    return poly;
}

void GFPolyFree(GFPolynomial *poly)
{
    if (poly != NULL) {
        if (poly->coeffs != NULL) {
            BSL_SAL_CleanseData(poly->coeffs, (uint32_t)(poly->degree + 1) * sizeof(uint16_t));
            BSL_SAL_FREE(poly->coeffs);
        }
        BSL_SAL_FREE(poly);
    }
}

// Evaluate poly(x) = coeffs[0] + coeffs[1]x + ... over GF(2^m) using Horner's method.
uint16_t GFPolyEval(const GFPolynomial *poly, uint16_t x)
{
    // Use Horner's method: start with highest degree coefficient
    uint16_t result = poly->coeffs[poly->degree]; // form monic poly

    // Iterate down to constant term
    for (int32_t i = poly->degree - 1; i >= 0; i--) {
        result = GFMultiplication(result, x);
        result = GFAddtion(result, poly->coeffs[i]);
    }

    return result;
}

// Set one coefficient within the polynomial's fixed degree range.
void GFPolySetCoeff(GFPolynomial *poly, const int32_t degree, const uint16_t coeff)
{
    poly->coeffs[degree] = coeff;
}

// Read access is kept here so users of the opaque polynomial type cannot access coefficient storage directly.
uint16_t GFPolyGetCoeff(const GFPolynomial *poly, const int32_t degree)
{
    return poly->coeffs[degree];
}

// Copy the represented polynomial. A smaller destination capacity truncates high-degree coefficients.
void GFPolyCopy(GFPolynomial *dst, const GFPolynomial *src)
{
    int32_t termsToCopy = (src->degree < dst->degree) ? src->degree : dst->degree;

    for (int32_t i = 0; i <= termsToCopy; i++) {
        dst->coeffs[i] = src->coeffs[i];
    }
}

// Compare the complete fixed-capacity coefficient arrays without data-dependent early exit.
uint32_t GFPolyConstTimeEqual(const GFPolynomial *a, const GFPolynomial *b)
{
    if (a->degree != b->degree) {
        return 0;
    }
    uint32_t diff = 0;
    for (int32_t i = 0; i <= a->degree; i++) {
        diff |= (uint32_t)(a->coeffs[i] ^ b->coeffs[i]);
    }
    return Uint32ConstTimeEqual(diff, 0);
}

// Reverse coefficients over the complete fixed range: dst[i] = src[degree - i].
void GFPolyReverse(GFPolynomial *dst, const GFPolynomial *src)
{
    for (int32_t i = 0; i <= src->degree; i++) {
        dst->coeffs[i] = src->coeffs[src->degree - i];
    }
}

// Masked Berlekamp-Massey update: dst <- dst + mask * scale * src over GF(2^m).
void GFPolyAddScaledMasked(GFPolynomial *dst, const GFPolynomial *src, uint16_t scale, uint16_t mask)
{
    for (int32_t i = 0; i <= dst->degree; i++) {
        uint16_t term = GFMultiplication(scale, src->coeffs[i]);
        dst->coeffs[i] ^= term & mask;
    }
}

// Constant-time conditional assignment used by Berlekamp-Massey.
void GFPolySelectMasked(GFPolynomial *dst, const GFPolynomial *src, uint16_t mask)
{
    for (int32_t i = 0; i <= dst->degree; i++) {
        dst->coeffs[i] = (uint16_t)((dst->coeffs[i] & ~mask) | (src->coeffs[i] & mask));
    }
}

// Multiply by x: [a0, a1, ...] becomes [0, a0, ...], dropping the overflowing top coefficient.
void GFPolyShiftUp(GFPolynomial *poly)
{
    for (int32_t i = poly->degree; i >= 1; i--) {
        poly->coeffs[i] = poly->coeffs[i - 1];
    }
    poly->coeffs[0] = 0;
}
#endif
