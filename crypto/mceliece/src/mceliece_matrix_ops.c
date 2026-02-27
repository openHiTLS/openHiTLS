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
#include "securec.h"
#include "mceliece_local.h"

// Extract the rightmost 9-byte from the matrix, perform a tail-shift, and write it back
#define LOAD_SHIFT_9TO8(tmp, src, tail)                                          \
    do {                                                                         \
        for (int32_t _i = 0; _i < 9; ++_i)                                       \
            (tmp)[_i] = (src)[_i];                                               \
        for (int32_t _i = 0; _i < 8; ++_i)                                       \
            (tmp)[_i] = ((tmp)[_i] >> (tail)) | ((tmp)[_i + 1] << (8 - (tail))); \
    } while (0)

#define STORE_SHIFT_8TO9(dst, tmp, tail)                                              \
    do {                                                                              \
        (dst)[0] = ((tmp)[0] << (tail)) | ((dst)[0] << (8 - (tail)) >> (8 - (tail))); \
        for (int32_t _i = 1; _i < 8; ++_i)                                            \
            (dst)[_i] = ((tmp)[_i] << (tail)) | ((tmp)[_i - 1] >> (8 - (tail)));      \
        (dst)[8] = ((dst)[8] >> (tail) << (tail)) | ((tmp)[7] >> (8 - (tail)));       \
    } while (0)

// extract 32*64 submatrix
static void ExtractSubmatrix(uint64_t buf[MCELIECE_MU], const uint8_t *mat, const int32_t colsBytes, const int32_t row,
                             const int32_t blockIdx, const int32_t tail)
{
    uint8_t tmp[9];
    for (int32_t i = 0; i < MCELIECE_MU; i++) {
        const uint8_t *src = &mat[(row + i) * colsBytes + blockIdx];
        LOAD_SHIFT_9TO8(tmp, src, tail);
        buf[i] = CMLoad8(tmp);
    }
}

// Gaussian elimination + recording the pivot column number
static int32_t GaussianElim(uint64_t buf[MCELIECE_MU], uint64_t ctzList[MCELIECE_MU], uint64_t *pivots)
{
    *pivots = 0;
    for (int32_t i = 0; i < MCELIECE_MU; i++) {
        uint64_t t = buf[i];
        for (int32_t j = i + 1; j < MCELIECE_MU; j++) {
            t |= buf[j];
        }

        if (CMMakeMask(t) != 0) {
            return CRYPT_MCELIECE_KEYGEN_FAIL; // Non-full rank
        }
        int32_t s = CMCtz64(t);
        ctzList[i] = s;
        *pivots |= UINT64_C(1) << s;

        for (int32_t j = i + 1; j < MCELIECE_MU; j++) {
            uint64_t mask = ((buf[i] >> s) & 1) - 1;
            buf[i] ^= buf[j] & mask;
        }
        for (int32_t j = i + 1; j < MCELIECE_MU; j++) {
            uint64_t mask = -((buf[j] >> s) & 1);
            buf[j] ^= buf[i] & mask;
        }
    }
    return CRYPT_SUCCESS;
}

// update pi
static void UpdatePermutation(int16_t *pi, int32_t row, const uint64_t ctzList[MCELIECE_MU])
{
    for (int32_t j = 0; j < MCELIECE_MU; j++) {
        for (int32_t k = j + 1; k < MCELIECE_NU; k++) {
            int64_t d = pi[row + j] ^ pi[row + k];
            d &= SAME_MASK(k, ctzList[j]);
            pi[row + j] ^= d;
            pi[row + k] ^= d;
        }
    }
}

// swap rightmost 64 columns
static void ApplyColSwap(uint8_t *mat, const int32_t colsBytes, const int32_t blockIdx, const int32_t tail,
                         const uint64_t ctzList[MCELIECE_MU], const int32_t mt)
{
    uint8_t tmp[9];
    for (int32_t i = 0; i < mt; i++) {
        uint8_t *dst = &mat[i * colsBytes + blockIdx];
        LOAD_SHIFT_9TO8(tmp, dst, tail);

        uint64_t t = CMLoad8(tmp);
        for (int32_t j = 0; j < MCELIECE_MU; j++) {
            uint64_t d = (t >> j) ^ (t >> ctzList[j]);
            d &= 1;
            t ^= d << ctzList[j];
            t ^= d << j;
        }
        CMStore8(tmp, t);
        STORE_SHIFT_8TO9(dst, tmp, tail);
    }
}

static uint8_t *RowRtrMoving(GFMatrix *M, const int32_t r)
{
    return M->data + (size_t)r * M->colsBytes;
}

static void XorRowMasked(uint8_t *dst, const uint8_t *src, const int32_t byteIdx, const int32_t bitInByte,
                         const int32_t colsBytes)
{
    const uint8_t loMask = (1u << bitInByte) - 1u;
    dst[byteIdx] ^= (src[byteIdx] & ~loMask); // high bits
    for (int32_t c = byteIdx + 1; c < colsBytes; c++) {
        dst[c] ^= src[c];
    }
}

GFMatrix *MatrixCreate(const int32_t rows, const int32_t cols)
{
    GFMatrix *mat = BSL_SAL_Malloc(sizeof(GFMatrix));
    if (mat == NULL) {
        return NULL;
    }

    mat->rows = rows;
    mat->cols = cols;
    mat->colsBytes = (cols + 7) / 8; // compute byte length

    mat->data = BSL_SAL_Calloc(rows * mat->colsBytes, sizeof(uint8_t));
    if (mat->data == NULL) {
        BSL_SAL_FREE(mat);
        return NULL;
    }

    return mat;
}

void MatrixFree(GFMatrix *mat)
{
    BSL_SAL_FREE(mat->data);
    BSL_SAL_FREE(mat);
}

int32_t MatrixGetBit(const GFMatrix *mat, const int32_t row, const int32_t col)
{
    if (mat == NULL || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return 0; // Return 0 instead of crashing
    }
    const uint8_t *p = &mat->data[row * mat->colsBytes + (col >> 3)];
    return (int32_t)((p[0] >> (col & 7)) & 1);
}

void MatrixSetBit(GFMatrix *mat, const int32_t row, const int32_t col, const int32_t bit)
{
    if (mat == NULL || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return; // Don't crash, just return
    }
    int32_t byteIdx = row * mat->colsBytes + (col / 8);
    int32_t bitIdx = col % 8;

    if (bit != 0) {
        mat->data[byteIdx] |= (1 << bitIdx);
    } else {
        mat->data[byteIdx] &= ~(1 << bitIdx);
    }
}

// Build H using the same bit-sliced packing and column grouping convention
// as the reference path: rows are grouped by bit position (k in 0..GFBITS-1)
// within each power i in 0..T-1; columns are packed 8-at-a-time into bytes.
int32_t BuildParityCheckMatrixReferenceStyle(GFMatrix *matH, const GFPolynomial *g, const GFElement *support,
                                             const McelieceParams *params)
{
    if (matH == NULL || g == NULL || support == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const int32_t t = params->t;
    const int32_t m = params->m;
    const int32_t n = params->n;
    if (matH->rows != t * m || matH->cols != n) {
        return CRYPT_MCELIECE_ERR_MATRIX_SIZE;
    }

    // inv[j] = 1 / g(support[j])
    GFElement *inv = (GFElement *)BSL_SAL_Malloc((size_t)n * sizeof(GFElement));
    if (inv == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // Evaluate monic polynomial g at support using our gf_* (internally bridged to ref GF)
    for (int32_t j = 0; j < n; j++) {
        GFElement a = (GFElement)(support[j] & ((1u << m) - 1u));
        // Evaluate monic polynomial: start at 1 (implicit leading coeff)
        GFElement val = 1;
        for (int32_t d = t - 1; d >= 0; d--) {
            val = GFMultiplication(val, a);
            val ^= (GFElement)g->coeffs[d];
        }
        if (val == 0) {
            BSL_SAL_FREE(inv);
            return CRYPT_MCELIECE_KEYGEN_FAIL;
        }
        inv[j] = GFInverse(val);
    }

    // Clear matrix
    (void)memset_s(matH->data, (size_t)matH->rows * (size_t)matH->colsBytes, 0,
                   (size_t)matH->rows * (size_t)matH->colsBytes);

    // Fill rows: for each i (power), for each 8-column block, for each bit k
    for (int32_t i = 0; i < t; i++) {
        for (int32_t j = 0; j < n; j += 8) {
            int32_t blockLen = (j + 8 <= n) ? 8 : (n - j);
            for (int32_t k = 0; k < m; k++) {
                uint8_t b = 0;
                // Reference mapping: MSB=col j+7 ... LSB=col j (for partial block, highest index first)
                for (int32_t tbit = blockLen - 1; tbit >= 0; tbit--) {
                    b <<= 1;
                    b |= (uint8_t)((inv[j + tbit] >> k) & 1);
                }
                int32_t row = i * m + k;
                matH->data[row * matH->colsBytes + (size_t)j / 8] = b;
            }
        }
        // inv[j] *= support[j] for next power
        for (int32_t j = 0; j < n; j++) {
            GFElement a = (GFElement)(support[j] & ((1u << m) - 1u));
            inv[j] = GFMultiplication(inv[j], a);
        }
    }

    BSL_SAL_FREE(inv);

    return CRYPT_SUCCESS;
}

int32_t ReduceToSystematicFormReferenceStyle(GFMatrix *matH)
{
    if (matH == NULL) {
        return CRYPT_NULL_INPUT;
    }
    const int32_t mt = matH->rows;
    const int32_t leftBytes = (mt + 7) / 8;

    for (int32_t byteIdx = 0; byteIdx < leftBytes; byteIdx++) {
        for (int32_t bitInByte = 0; bitInByte < 8; bitInByte++) {
            int32_t row = byteIdx * 8 + bitInByte;
            if (row >= mt) {
                break;
            }

            uint8_t *pivRow = RowRtrMoving(matH, row);
            for (int32_t r = row + 1; r < mt; r++) {
                uint8_t *curRow = RowRtrMoving(matH, r);
                // x <-- piv_row[byte_idx] ^ cur_row[byte_idx]
                uint8_t x = (uint8_t)(pivRow[byteIdx] ^ curRow[byteIdx]);
                uint8_t m = (uint8_t)((x >> bitInByte) & 1u);
                m = (uint8_t)(-(signed char)m); // 0 or 0xFF
                if (m == 0) {
                    continue;
                }
                XorRowMasked(pivRow, curRow, byteIdx, bitInByte, matH->colsBytes);
            }
            if (((pivRow[byteIdx] >> bitInByte) & 1u) == 0) {
                return CRYPT_MCELIECE_KEYGEN_FAIL;
            }
            for (int32_t r = 0; r < mt; r++) {
                if (r == row) {
                    continue;
                }
                uint8_t *curRow = RowRtrMoving(matH, r);
                uint8_t m = (uint8_t)((curRow[byteIdx] >> bitInByte) & 1u);
                m = (uint8_t)(-(signed char)m);

                for (int32_t c = 0; c < matH->colsBytes; c++) {
                    curRow[c] ^= (uint8_t)(pivRow[c] & m);
                }
            }
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t GaussPartialSemiSystematic6688(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots,
                                              const int32_t mt)
{
    for (int32_t i = 0; i < 208; i++) { // Number of byte-rows required to cover 1664 logical rows (m*t / 8)
        for (int32_t j = 0; j < 8; j++) { // 8 bits
            int32_t row = i * 8 + j;
            if (row >= 1664) { // m*t
                break;
            }
            if (row == 1632) { // m*t - 32
                if (ColsRermutation(mat, colsBytes, pi, pivots, mt) != CRYPT_SUCCESS) {
                    return CRYPT_MCELIECE_KEYGEN_FAIL;
                }
            }

            // Lower triangular elimination
            for (int32_t k = row + 1; k < 1664; k++) {
                uint8_t m = (mat[row * colsBytes + i] ^ mat[k * colsBytes + i]) >> j;
                m &= 1;
                m = -m;

                for (int32_t c = 0; c < 836; c++) { // Byte-width of the matrix for n=6688 (colsBytes = 6688 / 8)
                    uint8_t srcByte = mat[k * colsBytes + c];
                    uint8_t dstByte = mat[row * colsBytes + c];

                    for (int32_t bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00; // detect overflow
                        uint8_t xor = srcBit & m;
                        dstByte ^= (xor&mask);
                    }
                    mat[row * colsBytes + c] = dstByte;
                }
            }

            uint64_t pivotBit = (mat[row * colsBytes + i] >> j) & 1;
            uint64_t zeroMask = CMMakeMask(pivotBit);

            if (zeroMask != 0) {
                return CRYPT_MCELIECE_KEYGEN_FAIL;
            }

            // Upper triangular elimination
            for (int32_t k = 0; k < 1664; k++) {
                if (k == row) {
                    continue;
                }
                uint8_t m = (mat[k * colsBytes + i] >> j) & 1;
                m = -m;

                for (int32_t c = 0; c < 836; c++) {
                    uint8_t srcByte = mat[row * colsBytes + c];
                    uint8_t dstByte = mat[k * colsBytes + c];

                    for (int32_t bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor = srcBit & m;
                        dstByte ^= (xor&mask);
                    }
                    mat[k * colsBytes + c] = dstByte;
                }
            }
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t GaussPartialSemiSystematic6960(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots,
                                              const int32_t mt)
{
    for (int32_t i = 0; i < 194; i++) { // Number of byte-rows required to cover 1547 logical rows (ceil(1547 / 8))
        for (int32_t j = 0; j < 8; j++) {
            int32_t row = i * 8 + j;
            if (row >= 1547) { // Total logical rows of the matrix for n=6960 parameter set
                break;
            }

            if (row == 1515) { // Trigger row for column permutation phase (1547 - 32)
                if (ColsRermutation(mat, colsBytes, pi, pivots, mt) != CRYPT_SUCCESS) {
                    return CRYPT_MCELIECE_KEYGEN_FAIL;
                }
            }

            for (int32_t k = row + 1; k < 1547; k++) {
                uint8_t m = (mat[row * colsBytes + i] ^ mat[k * colsBytes + i]) >> j;
                m &= 1;
                m = -m;

                for (int32_t c = 0; c < 870; c++) { // Byte-width of the matrix for n=6960 (colsBytes = 6960 / 8)
                    uint8_t srcByte = mat[k * colsBytes + c];
                    uint8_t dstByte = mat[row * colsBytes + c];

                    for (int32_t bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor = srcBit & m;
                        dstByte ^= (xor&mask);
                    }
                    mat[row * colsBytes + c] = dstByte;
                }
            }

            uint64_t pivotBit = (mat[row * colsBytes + i] >> j) & 1;
            uint64_t zeroMask = CMMakeMask(pivotBit);

            if (zeroMask != 0) {
                return CRYPT_MCELIECE_KEYGEN_FAIL;
            }

            for (int32_t k = 0; k < 1547; k++) {
                if (k == row) {
                    continue;
                }
                uint8_t m = (mat[k * colsBytes + i] >> j) & 1;
                m = -m;

                for (int32_t c = 0; c < 870; c++) {
                    uint8_t srcByte = mat[row * colsBytes + c];
                    uint8_t dstByte = mat[k * colsBytes + c];

                    for (int32_t bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor = srcBit & m;
                        dstByte ^= (xor&mask);
                    }
                    mat[k * colsBytes + c] = dstByte;
                }
            }
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t GaussPartialSemiSystematic8192(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots,
                                              const int32_t mt)
{
    for (int32_t i = 0; i < 208; i++) { // Number of byte-rows required to cover 1664 logical rows (1664 / 8)
        for (int32_t j = 0; j < 8; j++) {
            int32_t row = i * 8 + j;
            if (row >= 1664) { // Total logical rows of the matrix for n=6688/8192 parameter set
                break;
            }

            if (row == 1632) { // Trigger row for column permutation phase (1664 - 32)
                if (ColsRermutation(mat, colsBytes, pi, pivots, mt) != CRYPT_SUCCESS) {
                    return CRYPT_MCELIECE_KEYGEN_FAIL;
                }
            }

            for (int32_t k = row + 1; k < 1664; k++) {
                uint8_t m = (mat[row * colsBytes + i] ^ mat[k * colsBytes + i]) >> j;
                m &= 1;
                m = -m;

                for (int32_t c = 0; c < 1024; c++) { // Byte-width of the matrix for n=8192 (colsBytes = 8192 / 8)
                    uint8_t srcByte = mat[k * colsBytes + c];
                    uint8_t dstByte = mat[row * colsBytes + c];

                    for (int32_t bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor = srcBit & m;
                        dstByte ^= (xor&mask);
                    }
                    mat[row * colsBytes + c] = dstByte;
                }
            }

            uint64_t pivotBit = (mat[row * colsBytes + i] >> j) & 1;
            uint64_t zeroMask = CMMakeMask(pivotBit);

            if (zeroMask != 0) {
                return CRYPT_MCELIECE_KEYGEN_FAIL;
            }

            for (int32_t k = 0; k < 1664; k++) {
                if (k == row) {
                    continue;
                }
                uint8_t m = (mat[k * colsBytes + i] >> j) & 1;
                m = -m;

                for (int32_t c = 0; c < 1024; c++) {
                    uint8_t srcByte = mat[row * colsBytes + c];
                    uint8_t dstByte = mat[k * colsBytes + c];

                    for (int32_t bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor = srcBit & m;
                        dstByte ^= (xor&mask);
                    }
                    mat[k * colsBytes + c] = dstByte;
                }
            }
        }
    }
    return CRYPT_SUCCESS;
}

/*
 * Hard-coded loop bounds are intentionally baked into three separate translation units. This lets
 * the compiler unroll inner-most bit-slice XOR loops, fold constants, and emit SIMD/vector
 * instructions without any run-time branches on paramter n. A single generic routine parameterized
 * at run time would force all trip counts into variables, instantly defeating these optimizations
 * and slowing the Gaussian elimination by several-fold -the hottest spot in key generation. The
 * small code-size penalty is traded for the large speed-up that Classic McEliece requires.
 */
int32_t GaussPartialSemiSystematic(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots,
                                   const int32_t mt, const int32_t paramN)
{
    switch (paramN) {
        case MCELIECE_PARA_6688_N:
            return GaussPartialSemiSystematic6688(mat, colsBytes, pi, pivots, mt);
        case MCELIECE_PARA_6960_N:
            return GaussPartialSemiSystematic6960(mat, colsBytes, pi, pivots, mt);
        case MCELIECE_PARA_8192_N:
            return GaussPartialSemiSystematic8192(mat, colsBytes, pi, pivots, mt);
        default:
            return CRYPT_NOT_SUPPORT;
    }
}

int32_t ColsRermutation(uint8_t *mat, const int32_t colsBytes, int16_t *pi, uint64_t *pivots, const int32_t mt)
{
    const int32_t row = mt - MCELIECE_MU;
    const int32_t blockIdx = row >> 3; // offset
    const int32_t tail = row & 7; // mod 8

    uint64_t buf[MCELIECE_MU];
    uint64_t ctzList[MCELIECE_MU];

    ExtractSubmatrix(buf, mat, colsBytes, row, blockIdx, tail);
    if (GaussianElim(buf, ctzList, pivots) != CRYPT_SUCCESS) {
        return CRYPT_MCELIECE_KEYGEN_FAIL;
    }
    UpdatePermutation(pi, row, ctzList);
    ApplyColSwap(mat, colsBytes, blockIdx, tail, ctzList, mt);

    return CRYPT_SUCCESS;
}

#endif
