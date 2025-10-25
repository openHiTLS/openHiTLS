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

#include "mceliece_genpoly.h"
#include "securec.h"

// Reference-aligned minimal connection polynomial (Berlekamp-Massey form)
// We build the (t+1) x t matrix M whose rows are 1, f, f^2, ..., f^t
// over GF(2^m) and perform the same elimination as the reference to recover
// the connection polynomial coefficients in the last row.

// Vector multiply in GF((2^m)^t) with reference reduction: x^t + x^7 + x^2 + x + 1
// Matches reference gf mul used in GenpolyOverGF
static inline void GFVecMul(GFElement *out, const GFElement *in0, const GFElement *in1, int t)
{
    // convolution
    int prodLen = t * 2 - 1;
    GFElement *prod = (GFElement *)alloca((size_t)prodLen * sizeof(GFElement));
    for (int i = 0; i < prodLen; i++) {
        prod[i] = 0;
    }
    for (int i = 0; i < t; i++) {
        for (int j = 0; j < t; j++) {
            prod[i + j] ^= GFMultiplication(in0[i], in1[j]);
        }
    }

    // reduce high terms using fixed pentanomial
    if (t == 128) {
        for (int i = (t - 1) * 2; i >= t; i--) {
            GFElement v = prod[i];
            prod[i - t + 7] ^= v;
            prod[i - t + 2] ^= v;
            prod[i - t + 1] ^= v;
            prod[i - t + 0] ^= v;
        }
    } else if (t == 119) {
        for (int i = (t - 1) * 2; i >= t; i--) {
            GFElement v = prod[i];
            prod[i - t + 8] ^= v;
            prod[i - t + 0] ^= v;
        }
    }

    for (int i = 0; i < t; i++) {
        out[i] = prod[i];
    }
}

// Extract solution vector x of length (m*t) from reduced A,b (assumes near-RREF)
// Nothing needed: coefficients are extracted directly once matrix is reduced
// Pack x (m*t bits) into g_lower[t] over GF(2^m), diagonal-basis mapping
// Not used in compact GF elimination path

int GenpolyOverGF(GFElement *out, const GFElement *f, const int t, const int m)
{
    GFInitial(m);

    // Allocate (t+1) x t matrix in row-major: row r, col c at mat[r*t + c]
    GFElement *mat = (GFElement *)BSL_SAL_Malloc((size_t)(t + 1) * (size_t)t * sizeof(GFElement));
    if (!mat) {
        return -1;
    }
    // mat[0][:] = [1, 0, ..., 0]
    for (int i = 0; i < t; i++) {
        mat[0 * t + i] = (i == 0) ? 1 : 0;
    }
    // mat[1][:] = f
    memcpy_s(&mat[1 * t], (size_t)t * sizeof(GFElement), f, (size_t)t * sizeof(GFElement));
    // mat[2]..mat[t] by polynomial multiplication truncated to degree < t
    for (int r = 2; r <= t; r++) {
        GFVecMul(&mat[r * t], &mat[(r - 1) * t], f, t);
    }

    // Reference-style elimination on columns using mask-based pivot fix

    for (int j = 0; j < t; j++) {
        for (int k = j + 1; k < t; k++) {
            GFElement mask = (mat[j * t + j] == 0) ? (GFElement)0xFFFF : (GFElement)0x0000;
            for (int r = j; r <= t; r++) {
                mat[r * t + j] ^= (GFElement)(mat[r * t + k] & mask);
            }
        }
        if (mat[j * t + j] == 0) {
            BSL_SAL_FREE(mat);
            return -1;
        }
        GFElement inv = GFInverse(mat[j * t + j]);
        for (int r = j; r <= t; r++) {
            mat[r * t + j] = GFMultiplication(mat[r * t + j], inv);
        }
        for (int k = 0; k < t; k++) {
            if (k != j) {
                GFElement tk = mat[j * t + k];
                for (int r = j; r <= t; r++) {
                    mat[r * t + k] ^= GFMultiplication(mat[r * t + j], tk);
                }
            }
        }
    }

    // Output last row as coefficients
    for (int i = 0; i < t; i++) {
        out[i] = mat[t * t + i];
    }
    BSL_SAL_FREE(mat);
    return 0;
}
