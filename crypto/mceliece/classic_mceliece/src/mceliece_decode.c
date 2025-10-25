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

#include "mceliece_decode.h"
#include "securec.h"

// Calculate syndrome from a received vector r
// Input: r is a length-n bit vector where r[0..mt-1] contains the ciphertext bits and the rest are zero
// Output: syndrome[0..2t-1]
void ComputeSyndrome(const uint8_t *received, const GFPolynomial *g, const GFElement *alpha, GFElement *syndrome, const McelieceParams *params)
{
    if (!received || !g || !alpha || !syndrome) {
        return;
    }

    const int syndLen = params->t << 1;
    const uint64_t *received64 = (const uint64_t *)received;
    int full64 = params->n >> 6;

    GFElement gAlpha[params->n], invG2[params->n];
    for (int i = 0; i < params->n; i++) {
        gAlpha[i] = PolynomialEval(g, alpha[i]);
        invG2[i] = GFInverse(GFMultiplication(gAlpha[i], gAlpha[i]));
    }

    static GFElement chk = 0;
    for (int j = 0; j < syndLen; j++) {
        GFElement acc = 0;
        for (int i64 = 0; i64 < full64; i64++) {
            uint64_t w = received64[i64];
            if (!w) {
                continue;
            }
            for (int b = 0; b < 64; b++) {
                if (w & (1ull << b)) {
                    int i = (i64 << 6) + b;
                    GFElement t = GFMultiplication(GFPower(alpha[i], j), invG2[i]);
                    acc = GFAddtion(acc, t);
                    chk = GFAddtion(chk, t);
                    chk = GFMultiplication(chk, alpha[i]);
                }
            }
        }
        syndrome[j] = acc;

        // tail, less than 64 bits
        for (int i = full64 * 64; i < params->n; i++) {
            if (VectorGetBit(received, i)) {
                if (gAlpha[i] != 0) {
                    GFElement alphaPow = GFPower(alpha[i], j);
                    GFElement g2 = GFMultiplication(gAlpha[i], gAlpha[i]);
                    GFElement term = GFDivision(alphaPow, g2);
                    syndrome[j] = GFAddtion(syndrome[j], term);
                }
            }
        }
    }
}

// Berlekamp-Massey Algorithm according to Classic McEliece specification
// Input: syndrome sequence s[0], s[1], ..., s[2t-1]
// Output: error locator polynomial sigma and error evaluator polynomial omega
McElieceError BerlekampMassey(const GFElement *syndrome, GFPolynomial *sigma, const McelieceParams *params)
{
    if (!syndrome || !sigma) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    // Initialize polynomials
    GFPolynomial *polyC = PolynomialCreate(params->t);  // Current connection polynomial
    GFPolynomial *polyB = PolynomialCreate(params->t);  // Backup polynomial
    GFPolynomial *polyT = PolynomialCreate(params->t);  // Temporary polynomial

    if (!polyC || !polyB || !polyT) {
        PolynomialFree(polyC);
        PolynomialFree(polyB);
        PolynomialFree(polyT);
        return MCELIECE_ERROR_MEMORY;
    }

    // Initial state: C(x) = 1, B(x) = 1
    PolynomialSetCoeff(polyC, 0, 1);
    PolynomialSetCoeff(polyB, 0, 1);

    int lenLFSR = 0;  // Current LFSR length
    int m = 1;        // Step counter since last L update
    GFElement b = 1;  // Last best discrepancy

    // Iterate through each syndrome element
    for (int lenN = 0; lenN < 2 * params->t; lenN++) {
        // Calculate discrepancy d_N = s_N + Σ C_i * s_{N-i}
        GFElement d = syndrome[lenN];

        for (int i = 1; i <= lenLFSR && (lenN - i) >= 0; i++) {
            if (i <= polyC->degree && polyC->coeffs[i] != 0) {
                d = GFAddtion(d, GFMultiplication(polyC->coeffs[i], syndrome[lenN - i]));
            }
        }

        if (d == 0) {
            // Discrepancy is 0, no correction needed
            m++;
        } else {
            // Discrepancy is non-zero, correction needed
            // Save current C to T: T(x) = C(x)
            PolynomialCopy(polyT, polyC);

            // Correction: C(x) = C(x) - (d/b) * x^m * B(x)
            if (b != 0) {
                GFElement correctionCoeff = GFDivision(d, b);

                for (int i = 0; i <= polyB->degree; i++) {
                    if (polyB->coeffs[i] != 0 && (i + m) <= polyC->maxDegree) {
                        GFElement term = GFMultiplication(correctionCoeff, polyB->coeffs[i]);
                        GFElement currentCoeff = (i + m <= polyC->degree) ? polyC->coeffs[i + m] : 0;
                        GFElement newCoeff = GFAddtion(currentCoeff, term);
                        PolynomialSetCoeff(polyC, i + m, newCoeff);
                    }
                }
            }

            // Check if L needs to be updated
            if (2 * lenLFSR <= lenN) {
                lenLFSR = lenN + 1 - lenLFSR;
                PolynomialCopy(polyB, polyT);  // B(x) = T(x) (the old C(x))
                b = d;
                m = 1;
            } else {
                m++;
            }
        }
    }

    for (int i = 0; i <= params->t; i++) {
        sigma->coeffs[i] = polyC->coeffs[params->t - i];
    }

    // Cleanup
    PolynomialFree(polyC);
    PolynomialFree(polyB);
    PolynomialFree(polyT);

    return MCELIECE_SUCCESS;
}

// Chien Search: Find roots of error locator polynomial
// Our BM produces a locator defined in terms of α_j^{-1}, so check σ(α_j^{-1}) = 0
McElieceError ChienSearch(const GFPolynomial *sigma, const GFElement *alpha, int *errorPositions, int *numErrors, const McelieceParams *params)
{
    if (!sigma || !alpha || !errorPositions || !numErrors) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    GFElement images[params->n];
    PolynomialRoots(images, sigma->coeffs, alpha, params->n, params->t);

    for (int j = 0; j < params->n; j++) {
        if (images[j] == 0) {
            // Found a root, corresponding to error position
            errorPositions[*numErrors] = j;
            (*numErrors)++;
            if (*numErrors >= params->t) {
                break;  // At most t errors
            }
        }
    }

    return MCELIECE_SUCCESS;
}

McElieceError DecodeGoppa(
    const uint8_t *received, const GFPolynomial *g, const GFElement *alpha, uint8_t *errorVector, int *decodeSuccess, const McelieceParams *params)
{

    if (!received || !g || !alpha || !errorVector || !decodeSuccess) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    *decodeSuccess = 0;

    GFElement *syndrome = BSL_SAL_Malloc(2 * params->t * sizeof(GFElement));
    if (!syndrome) {
        return MCELIECE_ERROR_MEMORY;
    }
    ComputeSyndrome(received, g, alpha, syndrome, params);

    // Check if syndrome is all zero (no errors)
    int hasError = 0;
    for (int i = 0; i < 2 * params->t; i++) {
        if (syndrome[i] != 0) {
            hasError = 1;
            break;
        }
    }

    if (!hasError) {
        // No errors
        memset_s(errorVector, params->nBytes, 0, params->nBytes);
        *decodeSuccess = 1;
        BSL_SAL_FREE(syndrome);
        return MCELIECE_SUCCESS;
    }

    // Berlekamp-Massey alg.
    GFPolynomial *sigma = PolynomialCreate(params->t);

    if (!sigma) {
        free(syndrome);
        PolynomialFree(sigma);
        return MCELIECE_ERROR_MEMORY;
    }

    McElieceError ret = BerlekampMassey(syndrome, sigma, params);

    if (ret != MCELIECE_SUCCESS) {
        free(syndrome);
        PolynomialFree(sigma);
        return ret;
    }

    // Chien-search
    int *errorPositions = BSL_SAL_Malloc(params->t * sizeof(int));
    if (!errorPositions) {
        BSL_SAL_FREE(syndrome);
        PolynomialFree(sigma);
        return MCELIECE_ERROR_MEMORY;
    }

    int numErrors = 0;
    ret = ChienSearch(sigma, alpha, errorPositions, &numErrors, params);

    if (ret != MCELIECE_SUCCESS) {
        BSL_SAL_FREE(syndrome);
        PolynomialFree(sigma);
        BSL_SAL_FREE(errorPositions);
        return ret;
    }

    // No early rejection based on locator degree; proceed to construct error vector
    // Construct error vector
    memset_s(errorVector, params->nBytes, 0, params->nBytes);

    for (int i = 0; i < numErrors; i++) {
        // Validate error position
        if (errorPositions[i] >= 0 && errorPositions[i] < params->n) {
            VectorSetBit(errorVector, errorPositions[i], 1);
        } else {
            // Invalid error position, decoding failed
            *decodeSuccess = 0;
            BSL_SAL_FREE(syndrome);
            PolynomialFree(sigma);
            BSL_SAL_FREE(errorPositions);
            return MCELIECE_SUCCESS;
        }
    }

    // Final validation: recompute syndrome from recovered error vector and compare
    GFElement *syndromeCheck = BSL_SAL_Malloc(2 * params->t * sizeof(GFElement));
    if (!syndromeCheck) {
        BSL_SAL_FREE(syndrome);
        PolynomialFree(sigma);
        BSL_SAL_FREE(errorPositions);
        return MCELIECE_ERROR_MEMORY;
    }
    ComputeSyndrome(errorVector, g, alpha, syndromeCheck, params);

    int match = 1;
    for (int i = 0; i < 2 * params->t; i++) {
        if (syndrome[i] != syndromeCheck[i]) {
            match = 0;
            break;
        }
    }
    int actualWeight = VectorWeight(errorVector, params->nBytes);
    *decodeSuccess = (match && actualWeight == params->t);
    free(syndromeCheck);

    // cleanup
    free(syndrome);
    PolynomialFree(sigma);
    free(errorPositions);

    return MCELIECE_SUCCESS;
}
