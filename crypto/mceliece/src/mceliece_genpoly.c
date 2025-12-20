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
#include "bsl_err_internal.h"
#include "mceliece_local.h"

// Vector multiply in GF((2^m)^t) with reference reduction: x^t + x^7 + x^2 + x + 1
// Matches reference gf mul used in GenPolyOverGF
static void GFVecMul(GFElement *out, const GFElement *in0, const GFElement *in1, const int32_t t)
{
    // convolution
    int32_t prodLen = t * 2 - 1;
    GFElement *prod = (GFElement *)alloca((size_t)prodLen * sizeof(GFElement));
    for (int32_t i = 0; i < prodLen; i++) {
        prod[i] = 0;
    }
    for (int32_t i = 0; i < t; i++) {
        for (int32_t j = 0; j < t; j++) {
            prod[i + j] ^= GFMultiplication(in0[i], in1[j]);
        }
    }

    // reduce high terms using fixed pentanomial
    if (t == 128) {
        for (int32_t i = (t - 1) * 2; i >= t; i--) { // 7, 2, 1, 0: the exponent of prod[x]
            GFElement v = prod[i];
            prod[i - t + 7] ^= v;
            prod[i - t + 2] ^= v;
            prod[i - t + 1] ^= v;
            prod[i - t + 0] ^= v;
        }
    } else if (t == 119) {
        for (int32_t i = (t - 1) * 2; i >= t; i--) { // 8, 0: the exponent of prod[x]
            GFElement v = prod[i];
            prod[i - t + 8] ^= v;
            prod[i - t + 0] ^= v;
        }
    }

    for (int32_t i = 0; i < t; i++) {
        out[i] = prod[i];
    }
}

// Extract solution vector x of length (m*t) from reduced A,b (assumes near-RREF)
// Nothing needed: coefficients are extracted directly once matrix is reduced
// Pack x (m*t bits) into g_lower[t] over GF(2^m), diagonal-basis mapping
// Not used in compact GF elimination path
int32_t GenPolyOverGF(GFElement *out, const GFElement *f, const int32_t t, const int32_t m)
{
    (void)m;
    // Allocate (t+1) x t matrix in row-major: row r, col c at mat[r*t + c]
    GFElement *mat = (GFElement *)BSL_SAL_Malloc((size_t)(t + 1) * (size_t)t * sizeof(GFElement));
    if (mat == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // mat[0][:] = [1, 0, ..., 0]
    for (int32_t i = 0; i < t; i++) {
        mat[0 * t + i] = (i == 0) ? 1 : 0;
    }
    // mat[1][:] = f
    (void)memcpy_s(&mat[1 * t], (size_t)t * sizeof(GFElement), f, (size_t)t * sizeof(GFElement));
    // mat[2]..mat[t] by polynomial multiplication truncated to degree < t
    for (int32_t r = 2; r <= t; r++) {
        GFVecMul(&mat[r * t], &mat[(r - 1) * t], f, t);
    }
    // Reference-style elimination on columns using mask-based pivot fix
    for (int32_t j = 0; j < t; j++) {
        for (int32_t k = j + 1; k < t; k++) {
            GFElement mask = (mat[j * t + j] == 0) ? (GFElement)0xFFFF : (GFElement)0x0000;
            for (int32_t r = j; r <= t; r++) {
                mat[r * t + j] ^= (GFElement)(mat[r * t + k] & mask);
            }
        }
        /* If mat[j*t + j] == 0 the j-th pivot is zero, which means column j is entirely zero: the first t truncated
         * powers 1, f, ..., f^{t-1} are linearly dependent.  In other words, deg(f) < t (or f is the zero polynomial),
         * so no unique minimal polynomial of degree t exists. No need to continue Gaussian elimination */
        if (mat[j * t + j] == 0) {
            BSL_SAL_FREE(mat);
            BSL_ERR_PUSH_ERROR(CRYPT_MCELIECE_KEYGEN_FAIL);
            return CRYPT_MCELIECE_KEYGEN_FAIL;
        }
        GFElement inv = GFInverse(mat[j * t + j]);
        for (int32_t r = j; r <= t; r++) {
            mat[r * t + j] = GFMultiplication(mat[r * t + j], inv);
        }
        for (int32_t k = 0; k < t; k++) {
            if (k != j) {
                GFElement tk = mat[j * t + k];
                for (int32_t r = j; r <= t; r++) {
                    mat[r * t + k] ^= GFMultiplication(mat[r * t + j], tk);
                }
            }
        }
    }
    // Output last row as coefficients
    for (int32_t i = 0; i < t; i++) {
        out[i] = mat[t * t + i];
    }
    BSL_SAL_FREE(mat);
    return CRYPT_SUCCESS;
}
#endif
