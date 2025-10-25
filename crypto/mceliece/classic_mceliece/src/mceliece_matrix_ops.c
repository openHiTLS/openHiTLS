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

#include "mceliece_matrix_ops.h"

// extract 32*64 submatrix
static void ExtractSubmatrix(
    uint64_t buf[MCELIECE_MU], const uint8_t *mat, int colsBytes, int row, int blockIdx, int tail)
{
    uint8_t tmp[9];
    for (int i = 0; i < MCELIECE_MU; i++) {
        const uint8_t *src = &mat[(row + i) * colsBytes + blockIdx];
        LOAD_SHIFT_9TO8(tmp, src, tail);
        buf[i] = CMLoad8(tmp);
    }
}

// Gaussian elimination + recording the pivot column number
static int GaussianElim(uint64_t buf[MCELIECE_MU], uint64_t ctzList[MCELIECE_MU], uint64_t *pivots)
{
    *pivots = 0;
    for (int i = 0; i < MCELIECE_MU; i++) {
        uint64_t t = buf[i];
        for (int j = i + 1; j < MCELIECE_MU; j++) {
            t |= buf[j];
        }

        if (CMMakeMask(t)) {
            return -1;  // Non-full rank
        }
        int s = CMCtz64(t);
        ctzList[i] = s;
        *pivots |= UINT64_C(1) << s;

        for (int j = i + 1; j < MCELIECE_MU; j++) {
            uint64_t mask = ((buf[i] >> s) & 1) - 1;
            buf[i] ^= buf[j] & mask;
        }
        for (int j = i + 1; j < MCELIECE_MU; j++) {
            uint64_t mask = -((buf[j] >> s) & 1);
            buf[j] ^= buf[i] & mask;
        }
    }
    return 0;
}

// update pi
static void UpdatePermutation(int16_t *pi, int row, const uint64_t ctzList[MCELIECE_MU])
{
    for (int j = 0; j < MCELIECE_MU; j++) {
        for (int k = j + 1; k < MCELIECE_NU; k++) {
            int64_t d = pi[row + j] ^ pi[row + k];
            d &= SAME_MASK(k, ctzList[j]);
            pi[row + j] ^= d;
            pi[row + k] ^= d;
        }
    }
}

// swap rightmost 64 columns
static void ApplyColSwap(uint8_t *mat, int colsBytes, int blockIdx, int tail, const uint64_t ctzList[MCELIECE_MU], const int mt)
{
    uint8_t tmp[9];
    for (int i = 0; i < mt; i++) {
        uint8_t *dst = &mat[i * colsBytes + blockIdx];
        LOAD_SHIFT_9TO8(tmp, dst, tail);

        uint64_t t = CMLoad8(tmp);
        for (int j = 0; j < MCELIECE_MU; j++) {
            uint64_t d = (t >> j) ^ (t >> ctzList[j]);
            d &= 1;
            t ^= d << ctzList[j];
            t ^= d << j;
        }
        CMStore8(tmp, t);
        STORE_SHIFT_8TO9(dst, tmp, tail);
    }
}

static inline uint8_t *RowRtrMoving(const GFMatrix *M, int r)
{
    return M->data + (size_t)r * M->colsBytes;
}

static inline void XorRowMasked(uint8_t *dst, const uint8_t *src, int byteIdx, int bitInByte, int colsBytes)
{
    const uint8_t loMask = (1u << bitInByte) - 1u;
    dst[byteIdx] ^= (src[byteIdx] & ~loMask); // high bits
    for (int c = byteIdx + 1; c < colsBytes; c++) {
        dst[c] ^= src[c];
    }
}

GFMatrix *MatrixCreate(int rows, int cols)
{
    GFMatrix *mat = BSL_SAL_Malloc(sizeof(GFMatrix));
    if (!mat) {
        return NULL;
    }

    mat->rows = rows;
    mat->cols = cols;
    mat->colsBytes = (cols + 7) / 8;

    mat->data = BSL_SAL_Calloc(rows * mat->colsBytes, sizeof(uint8_t));
    if (!mat->data) {
        BSL_SAL_FREE(mat);
        return NULL;
    }

    return mat;
}

void MatrixFree(GFMatrix *mat)
{
    if (mat) {
        if (mat->data) {
            BSL_SAL_FREE(mat->data);
        }
        BSL_SAL_FREE(mat);
    }
}

int MatrixGetBit(const GFMatrix *mat, int row, int col)
{
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return 0;  // Return 0 instead of crashing
    }
    const uint8_t *p = &mat->data[row * mat->colsBytes + (col >> 3)];
    return (int)((p[0] >> (col & 7)) & 1);
}

void MatrixSetBit(GFMatrix *mat, int row, int col, int bit)
{
    if (!mat || row < 0 || row >= mat->rows || col < 0 || col >= mat->cols) {
        return;  // Don't crash, just return
    }
    int byteIdx = row * mat->colsBytes + (col / 8);
    int bitIdx = col % 8;

    if (bit) {
        mat->data[byteIdx] |= (1 << bitIdx);
    } else {
        mat->data[byteIdx] &= ~(1 << bitIdx);
    }
}

// Build H using the same bit-sliced packing and column grouping convention
// as the reference path: rows are grouped by bit position (k in 0..GFBITS-1)
// within each power i in 0..T-1; columns are packed 8-at-a-time into bytes.
int BuildParityCheckMatrixReferenceStyle(GFMatrix *matH, const GFPolynomial *g, const GFElement *support, const McelieceParams *params)
{

    if (!matH || !g || !support) {
        return -1;
    }
    const int t = params->t;
    const int m = params->m;
    const int n = params->n;
    if (matH->rows != t * m || matH->cols != n) {
        return -1;
    }

    // inv[j] = 1 / g(support[j])
    GFElement *inv = (GFElement *)BSL_SAL_Malloc((size_t)n * sizeof(GFElement));
    if (!inv) {
        return -1;
    }

    // Evaluate monic polynomial g at support using our gf_* (internally bridged to ref GF)
    for (int j = 0; j < n; j++) {
        GFElement a = (GFElement)(support[j] & ((1u << m) - 1u));
        // Evaluate monic polynomial: start at 1 (implicit leading coeff)
        GFElement val = 1;
        for (int d = t - 1; d >= 0; d--) {
            val = GFMultiplication(val, a);
            val ^= (GFElement)g->coeffs[d];
        }
        if (val == 0) {
            BSL_SAL_FREE(inv);
            return -1;
        }
        inv[j] = GFInverse(val);
    }

    // Clear matrix
    memset_s(matH->data, (size_t)matH->rows * (size_t)matH->colsBytes, 0, (size_t)matH->rows * (size_t)matH->colsBytes);

    // Fill rows: for each i (power), for each 8-column block, for each bit k
    for (int i = 0; i < t; i++) {
        for (int j = 0; j < n; j += 8) {
            int blockLen = (j + 8 <= n) ? 8 : (n - j);
            for (int k = 0; k < m; k++) {
                unsigned char b = 0;
                // Reference mapping: MSB=col j+7 ... LSB=col j (for partial block, highest index first)
                for (int tbit = blockLen - 1; tbit >= 0; tbit--) {
                    b <<= 1;
                    b |= (unsigned char)((inv[j + tbit] >> k) & 1);
                }
                int row = i * m + k;
                matH->data[row * matH->colsBytes + (size_t)j / 8] = b;
            }
        }
        // inv[j] *= support[j] for next power
        for (int j = 0; j < n; j++) {
            GFElement a = (GFElement)(support[j] & ((1u << m) - 1u));
            inv[j] = GFMultiplication(inv[j], a);
        }
    }

    BSL_SAL_FREE(inv);

    return 0;
}

int ReduceToSystematicFormReferenceStyle(GFMatrix *matH)
{
    if (!matH) {
        return -1;
    }
    const int mt = matH->rows;
    const int leftBytes = (mt + 7) / 8;

    for (int byteIdx = 0; byteIdx < leftBytes; byteIdx++) {
        for (int bitInByte = 0; bitInByte < 8; bitInByte++) {
            int row = byteIdx * 8 + bitInByte;
            if (row >= mt) {
                break;
            }
            
            uint8_t *pivRow = RowRtrMoving(matH, row);
            for (int r = row + 1; r < mt; r++) {
                uint8_t *curRow = RowRtrMoving(matH, r);

                // x = piv_row[byte_idx] ^ cur_row[byte_idx]
                unsigned char x = (unsigned char)(pivRow[byteIdx] ^ curRow[byteIdx]);
                unsigned char m = (unsigned char)((x >> bitInByte) & 1u);
                m = (unsigned char)(-(signed char)m); // 0 or 0xFF

                if (m == 0) {
                    continue;
                }
                XorRowMasked(pivRow, curRow, byteIdx, bitInByte, matH->colsBytes);
            }

            if (((pivRow[byteIdx] >> bitInByte) & 1u) == 0u) {
                return -1;
            }

            for (int r = 0; r < mt; r++) {
                if (r == row) {
                    continue;
                }
                uint8_t *curRow = RowRtrMoving(matH, r);
                unsigned char m = (unsigned char)((curRow[byteIdx] >> bitInByte) & 1u);
                m = (unsigned char)(-(signed char)m);

                for (int c = 0; c < matH->colsBytes; c++) {
                    curRow[c] ^= (unsigned char)(pivRow[c] & m);
                }
            }

        }
    }
    return 0;
}


int GaussPartialSemiSystematic6688(uint8_t *mat, int colsBytes, int16_t *pi, uint64_t *pivots, const int mt)
{
    for (int i = 0; i < 208; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            if (row >= 1664) {
                break;
            }

            if (row == 1632) {
                if (ColsRermutation(mat, colsBytes, pi, pivots, mt)) {
                    return -1;
                }
            }

            // Lower triangular elimination
            for (int k = row + 1; k < 1664; k++) {
                uint8_t m = (mat[row * colsBytes + i] ^ mat[k * colsBytes + i]) >> j;
                m &= 1;
                m = -m;

                for (int c = 0; c < 836; c++) {
                    uint8_t srcByte = mat[k * colsBytes + c];
                    uint8_t dstByte = mat[row * colsBytes + c];

                    for (int bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor   = srcBit & m;
                        dstByte ^= (xor & mask);
                    }
                    mat[row * colsBytes + c] = dstByte;
                }
            }

            uint64_t pivotBit = (mat[row * colsBytes + i] >> j) & 1;
            uint64_t zeroMask = CMMakeMask(pivotBit);

            if (zeroMask) {
                return -1;
            }

            // Upper triangular elimination
            for (int k = 0; k < 1664; k++) {
                if (k == row) continue;

                uint8_t m = (mat[k * colsBytes + i] >> j) & 1;
                m = -m;

                for (int c = 0; c < 836; c++) {
                    uint8_t srcByte = mat[row * colsBytes + c];
                    uint8_t dstByte = mat[k * colsBytes + c];

                    for (int bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor   = srcBit & m;
                        dstByte ^= (xor & mask);
                    }
                    mat[k * colsBytes + c] = dstByte;
                }
            }
        }
    }
    return 0;
}

int GaussPartialSemiSystematic6960(uint8_t *mat, int colsBytes, int16_t *pi, uint64_t *pivots, const int mt)
{
    for (int i = 0; i < 194; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            if (row >= 1547) {
                break;
            }

            if (row == 1515) {
                if (ColsRermutation(mat, colsBytes, pi, pivots, mt)) {
                    return -1;
                }
            }

            for (int k = row + 1; k < 1547; k++) {
                uint8_t m = (mat[row * colsBytes + i] ^ mat[k * colsBytes + i]) >> j;
                m &= 1;
                m = -m;

                for (int c = 0; c < 870; c++) {
                    uint8_t srcByte = mat[k * colsBytes + c];
                    uint8_t dstByte = mat[row * colsBytes + c];

                    for (int bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor   = srcBit & m;
                        dstByte ^= (xor & mask);
                    }
                    mat[row * colsBytes + c] = dstByte;
                }
            }

            uint64_t pivotBit = (mat[row * colsBytes + i] >> j) & 1;
            uint64_t zeroMask = CMMakeMask(pivotBit);

            if (zeroMask) {
                return -1;
            }

            for (int k = 0; k < 1547; k++) {
                if (k == row) {
                    continue;
                }
                uint8_t m = (mat[k * colsBytes + i] >> j) & 1;
                m = -m;

                for (int c = 0; c < 870; c++) {
                    uint8_t srcByte = mat[row * colsBytes + c];
                    uint8_t dstByte = mat[k * colsBytes + c];

                    for (int bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor   = srcBit & m;
                        dstByte ^= (xor & mask);
                    }
                    mat[k * colsBytes + c] = dstByte;
                }
            }
        }
    }
    return 0;
}


int GaussPartialSemiSystematic8192(uint8_t *mat, int colsBytes, int16_t *pi, uint64_t *pivots, const int mt)
{
    for (int i = 0; i < 208; i++) {
        for (int j = 0; j < 8; j++) {
            int row = i * 8 + j;
            if (row >= 1664) {
                break;
            }

            if (row == 1632) {
                if (ColsRermutation(mat, colsBytes, pi, pivots, mt)) {
                    return -1;
                }
            }

            for (int k = row + 1; k < 1664; k++) {
                uint8_t m = (mat[row * colsBytes + i] ^ mat[k * colsBytes + i]) >> j;
                m &= 1;
                m = -m;

                for (int c = 0; c < 1024; c++) {
                    uint8_t srcByte = mat[k * colsBytes + c];
                    uint8_t dstByte = mat[row * colsBytes + c];

                    for (int bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor   = srcBit & m;
                        dstByte ^= (xor & mask);
                    }
                    mat[row * colsBytes + c] = dstByte;
                }
            }

            uint64_t pivotBit = (mat[row * colsBytes + i] >> j) & 1;
            uint64_t zeroMask = CMMakeMask(pivotBit);

            if (zeroMask) {
                return -1;
            }

            for (int k = 0; k < 1664; k++) {
                if (k == row) continue;

                uint8_t m = (mat[k * colsBytes + i] >> j) & 1;
                m = -m;

                for (int c = 0; c < 1024; c++) {
                    uint8_t srcByte = mat[row * colsBytes + c];
                    uint8_t dstByte = mat[k * colsBytes + c];

                    for (int bit = 0; bit < 8; bit++) {
                        uint8_t mask = 1u << bit;
                        uint8_t srcBit = (srcByte & mask) ? 0xFF : 0x00;
                        uint8_t xor   = srcBit & m;
                        dstByte ^= (xor & mask);
                    }
                    mat[k * colsBytes + c] = dstByte;
                }
            }
        }
    }
    return 0;
}

int ColsRermutation(uint8_t *mat, int colsBytes, int16_t *pi, uint64_t *pivots, const int mt)
{
    const int row = mt - MCELIECE_MU;
    const int blockIdx = row >> 3;
    const int tail = row & 7;

    uint64_t buf[MCELIECE_MU];
    uint64_t ctzList[MCELIECE_MU];

    ExtractSubmatrix(buf, mat, colsBytes, row, blockIdx, tail);
    if (GaussianElim(buf, ctzList, pivots) != 0) {
        return -1;
    }
    UpdatePermutation(pi, row, ctzList);
    ApplyColSwap(mat, colsBytes, blockIdx, tail, ctzList, mt);

    return 0;
}
