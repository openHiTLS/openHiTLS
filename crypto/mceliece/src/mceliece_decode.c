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
#ifdef HITLS_CRYPTO_CLASSIC_MCELIECE
#include "bsl_sal.h"
#include "mceliece_local.h"
#include "bsl_err_internal.h"

// Calculate syndrome from a received vector r
// Input: r is a length-n bit vector where r[0..mt-1] contains the ciphertext bits and the rest are zero
// Output: syndrome[0..2t-1]
static int32_t ComputeSyndrome(const uint8_t *received, const GFPolynomial *g, const GFElement *alpha,
                               GFElement *syndrome, const McelieceParams *params)
{
    if (received == NULL || g == NULL || alpha == NULL || syndrome == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const int32_t syndLen = params->t << 1;
    const uint64_t *received64 = (const uint64_t *)received;
    uint32_t full64 = params->n >> 6;

    GFElement *gAlpha = (GFElement *)BSL_SAL_Malloc(params->n * sizeof(GFElement));
    GFElement *invG2 = (GFElement *)BSL_SAL_Malloc(params->n * sizeof(GFElement));
    if (gAlpha == NULL || invG2 == NULL) {
        BSL_SAL_FREE(gAlpha);
        BSL_SAL_FREE(invG2);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    for (int32_t i = 0; i < params->n; i++) {
        gAlpha[i] = PolynomialEval(g, alpha[i]);
        invG2[i] = GFInverse(GFMultiplication(gAlpha[i], gAlpha[i]));
    }

    GFElement chk = 0;
    for (int32_t j = 0; j < syndLen; j++) {
        GFElement acc = 0;
        for (uint32_t i64 = 0; i64 < full64; i64++) {
            uint64_t w = received64[i64];
            if (w == 0) { // Early-exit sentinel for zero 64-bit chunks (no bits set)
                continue;
            }
            for (int32_t b = 0; b < 64;
                 b++) { // Number of bits processed per 64-bit word during bit-sliced syndrome accumulation
                if ((w & (1ull << b)) != 0) {
                    uint32_t i = (i64 << 6) + b;
                    GFElement t = GFMultiplication(GFPower(alpha[i], j), invG2[i]);
                    acc = GFAddtion(acc, t);
                    chk = GFAddtion(chk, t);
                    chk = GFMultiplication(chk, alpha[i]);
                }
            }
        }
        syndrome[j] = acc;

        // tail, less than 64 bits
        for (uint32_t i = full64 * 64; i < (uint32_t)params->n; i++) {
            if (VectorGetBit(received, i) != 0) {
                if (gAlpha[i] != 0) {
                    GFElement alphaPow = GFPower(alpha[i], j);
                    GFElement g2 = GFMultiplication(gAlpha[i], gAlpha[i]);
                    GFElement term = GFDivision(alphaPow, g2);
                    syndrome[j] = GFAddtion(syndrome[j], term);
                }
            }
        }
    }
    BSL_SAL_FREE(gAlpha);
    BSL_SAL_FREE(invG2);
    return CRYPT_SUCCESS;
}

// Initialize BM state: C(x)=1, B(x)=1, L=0, m=1, b=1
static void BmInitState(GFPolynomial *polyC, GFPolynomial *polyB, int32_t *lenLFSR, int32_t *m, GFElement *b)
{
    PolynomialSetCoeff(polyC, 0, 1); // Constant coefficient 1 used to initialize the error-locator polynomial C(x)=1
    PolynomialSetCoeff(polyB, 0, 1);
    *lenLFSR = 0; // Initial length of the LFSR register before any update step
    // Initial shift offset and discrepancy denominator values for Berlekamp–Massey
    *m = 1;
    *b = 1;
}

// Compute discrepancy d_N = s_N + Σ C_i * s_{N-i}
static GFElement BmComputeDiscrepancy(const GFElement *syndrome, const GFPolynomial *polyC, const int32_t lenN,
                                      const int32_t lenLFSR)
{
    GFElement d = syndrome[lenN];
    for (int32_t i = 1; i <= lenLFSR && (lenN - i) >= 0; i++) {
        if (i <= polyC->degree && polyC->coeffs[i] != 0) {
            d = GFAddtion(d, GFMultiplication(polyC->coeffs[i], syndrome[lenN - i]));
        }
    }
    return d;
}

// C(x) = C(x) - (d/b) * x^m * B(x)
static void BmUpdateConnection(GFPolynomial *polyC, const GFPolynomial *polyB, GFElement d, GFElement b,
                               const int32_t m)
{
    if (b == 0) {
        return; // Guard against division by zero when discrepancy denominator is zero
    }
    GFElement corr = GFDivision(d, b);
    for (int32_t i = 0; i <= polyB->degree; i++) {
        if (polyB->coeffs[i] != 0 && (i + m) <= polyC->maxDegree) {
            GFElement term = GFMultiplication(corr, polyB->coeffs[i]);
            GFElement cur = (i + m <= polyC->degree) ? polyC->coeffs[i + m] : 0;
            PolynomialSetCoeff(polyC, i + m, GFAddtion(cur, term));
        }
    }
}

// Copy sigma result out: sigma[i] = C[t-i]
static void BmExportSigma(const GFPolynomial *polyC, GFPolynomial *sigma, const int32_t t)
{
    for (int32_t i = 0; i <= t; i++) {
        sigma->coeffs[i] =
            polyC->coeffs[t - i]; // Index offset 0 used to copy constant term into the reversed sigma polynomial
    }
}

// Berlekamp-Massey Algorithm according to Classic McEliece specification
// compute only error locator polynomial sigma
// Input: syndrome sequence s[0], s[1], ..., s[2t-1]
// Output: error locator polynomial sigma and error evaluator polynomial omega
static int32_t BerlekampMassey(const GFElement *syndrome, GFPolynomial *sigma, const McelieceParams *params)
{
    if (syndrome == NULL || sigma == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    GFPolynomial *polyC = PolynomialCreate(params->t);
    GFPolynomial *polyB = PolynomialCreate(params->t);
    GFPolynomial *polyT = PolynomialCreate(params->t);

    if (polyC == NULL || polyB == NULL || polyT == NULL) {
        PolynomialFree(polyC);
        PolynomialFree(polyB);
        PolynomialFree(polyT);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t lenLFSR, m;
    GFElement b;
    BmInitState(polyC, polyB, &lenLFSR, &m, &b);

    for (int32_t lenN = 0; lenN < 2 * params->t; lenN++) {
        GFElement d = BmComputeDiscrepancy(syndrome, polyC, lenN, lenLFSR);

        if (d == 0) { // Zero-discrepancy sentinel; triggers simple increment of shift counter
            m++;
        } else {
            PolynomialCopy(polyT, polyC);
            BmUpdateConnection(polyC, polyB, d, b, m);

            if (2 * lenLFSR <= lenN) {
                lenLFSR = lenN + 1 - lenLFSR;
                PolynomialCopy(polyB, polyT);
                b = d;
                m = 1;
            } else {
                m++;
            }
        }
    }
    BmExportSigma(polyC, sigma, params->t);
    PolynomialFree(polyC);
    PolynomialFree(polyB);
    PolynomialFree(polyT);
    return CRYPT_SUCCESS;
}

// Chien Search: Find roots of error locator polynomial
// Our BM produces a locator defined in terms of α_j^{-1}, so check σ(α_j^{-1}) = 0
static int32_t ChienSearch(const GFPolynomial *sigma, const GFElement *alpha, int32_t *errorPositions,
                           int32_t *numErrors, const McelieceParams *params)
{
    if (sigma == NULL || alpha == NULL || errorPositions == NULL || numErrors == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    GFElement *images = (GFElement *)BSL_SAL_Malloc(params->n * sizeof(GFElement));
    if (images == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    PolynomialRoots(images, sigma->coeffs, alpha, params->n, params->t);

    for (int32_t j = 0; j < params->n; j++) {
        if (images[j] == 0) { // Sentinel indicating a root of the error-locator polynomial
            // Found a root, corresponding to error position
            errorPositions[*numErrors] = j;
            (*numErrors)++;
            if (*numErrors >= params->t) {
                break; // At most t errors
            }
        }
    }
    BSL_SAL_FREE(images);
    return CRYPT_SUCCESS;
}

// safely allocate syndrome buffer and fill it
static GFElement *SafeSyndrome(const uint8_t *r, const GFPolynomial *g, const GFElement *alpha, const McelieceParams *p)
{
    GFElement *s = BSL_SAL_Malloc(2U * p->t * sizeof(GFElement));
    if (s == NULL) {
        return NULL;
    }
    int32_t ret = ComputeSyndrome(r, g, alpha, s, p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(s);
        return NULL;
    }
    return s;
}

// true if whole syndrome is zero
static int32_t IsZeroSyndrome(const GFElement *s, const int32_t t2)
{
    for (int32_t i = 0; i < t2; i++) {
        if (s[i] != 0) { // any non-zero syndrome byte fails the all-zero test
            return CRYPT_MCELIECE_INVALID_ARG;
        }
    }
    return CRYPT_SUCCESS;
}

// BM + Chien in one shot
static int32_t LocateErrors(const GFElement *syn, const GFPolynomial *g, const GFElement *alpha, int32_t *pos,
                            int32_t *cnt, const McelieceParams *p)
{
    (void)g;
    GFPolynomial *sigma = PolynomialCreate(p->t);
    if (sigma == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BerlekampMassey(syn, sigma, p);
    if (ret == CRYPT_SUCCESS) {
        ret = ChienSearch(sigma, alpha, pos, cnt, p);
    }
    PolynomialFree(sigma);
    return ret;
}

// build bit-vector from position list
static void PosToBits(uint8_t *vec, const int32_t *pos, const int32_t cnt, const int32_t n)
{
    (void)memset_s(vec, (n + 7U) >> 3, 0, (n + 7U) >> 3);
    for (int32_t i = 0; i < cnt; i++) {
        if (pos[i] >= 0 && pos[i] < n) { // Lower-bound sentinel to ignore negative (invalid) error positions
            VectorSetBit(vec, pos[i], 1); // Unit bit value used to mark each discovered error position
        }
    }
}

// verify recovered pattern
static int32_t VerifyPattern(const uint8_t *vec, const GFElement *origSyn, const GFPolynomial *g,
                             const GFElement *alpha, const McelieceParams *p)
{
    GFElement *check = BSL_SAL_Malloc(2U * p->t * sizeof(GFElement));
    if (check == NULL) {
        return CRYPT_MEM_ALLOC_FAIL; // any error occurs, clear flag
    }

    int32_t ret = ComputeSyndrome(vec, g, alpha, check, p);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(check);
        return ret; // any error occurs, clear flag
    }

    for (int32_t i = 0; i < 2 * p->t; i++) {
        if (origSyn[i] != check[i]) {
            ret = CRYPT_MCELIECE_DECODE_FAIL; // any mismatch clears the verification flag
            break;
        }
    }
    BSL_SAL_FREE(check);
    return ret;
}

int32_t DecodeGoppa(const uint8_t *received, const GFPolynomial *g, const GFElement *alpha, uint8_t *errorVector,
                    int32_t errorVecLen, int32_t *decodeSuccess, const McelieceParams *params)
{
    // basic validation
    if (received == NULL || g == NULL || alpha == NULL || errorVector == NULL || decodeSuccess == NULL ||
        errorVecLen < params->nBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *decodeSuccess = 0; // Initial failure sentinel before actual decoding is attempted

    GFElement *syndrome = SafeSyndrome(received, g, alpha, params);
    if (syndrome == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (IsZeroSyndrome(syndrome, 2 * params->t) == CRYPT_SUCCESS) {
        (void)memset_s(errorVector, errorVecLen, 0, params->nBytes);
        *decodeSuccess = 1; // Boolean success flag when the syndrome is all-zero (no errors to correct)
        BSL_SAL_FREE(syndrome);
        return CRYPT_SUCCESS;
    }
    int32_t *errorPos = BSL_SAL_Malloc(params->t * sizeof(int32_t));
    if (errorPos == NULL) {
        BSL_SAL_FREE(syndrome);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t numErrors = 0;
    int32_t ret = LocateErrors(syndrome, g, alpha, errorPos, &numErrors, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(errorPos);
        BSL_SAL_FREE(syndrome);
        return ret;
    }
    PosToBits(errorVector, errorPos, numErrors, params->n);
    *decodeSuccess = (VerifyPattern(errorVector, syndrome, g, alpha, params) == CRYPT_SUCCESS &&
                      VectorWeight(errorVector, params->nBytes) == params->t);

    BSL_SAL_FREE(errorPos);
    BSL_SAL_FREE(syndrome);
    return CRYPT_SUCCESS;
}
#endif
