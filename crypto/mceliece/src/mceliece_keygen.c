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

#include "mceliece_local.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_utils.h"

#define MCELIECE_PRG_PREFIX   64
#define MCELIECE_PRG_SEED_LEN 33

typedef struct {
    uint32_t val; // <--- must be uint32_t
    uint16_t pos;
} PairSt;

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
        (dst)[0] = ((tmp)[0] << (tail)) | ((dst)[0] & ((1U << (tail)) - 1U));          \
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
        buf[i] = GET_UINT64_LE(tmp, 0);
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
        *pivots |= 1ULL << s;

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
static void UpdatePermutation(uint16_t *pi, int32_t row, const uint64_t ctzList[MCELIECE_MU])
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

        uint64_t t = GET_UINT64_LE(tmp, 0);
        for (int32_t j = 0; j < MCELIECE_MU; j++) {
            uint64_t d = (t >> j) ^ (t >> ctzList[j]);
            d &= 1;
            t ^= d << ctzList[j];
            t ^= d << j;
        }
        PUT_UINT64_LE(t, tmp, 0);
        STORE_SHIFT_8TO9(dst, tmp, tail);
    }
}

static inline void XorRowSpanMaskedU64(uint8_t *dst, const uint8_t *src, int32_t startByte, const int32_t width,
                                       const uint8_t mask)
{
    if (startByte >= width) {
        return;
    }

    const uint64_t mask64 = 0u - (uint64_t)(mask & 1u);
    int32_t c = startByte;
    for (; c + 8 <= width; c += 8) {
#ifndef FORCE_ADDR_ALIGN
        uint64_t d = *((uint64_t *)(dst + c));
        uint64_t s = *((const uint64_t *)(src + c));
        ((uint64_t *)(dst + c))[0] = d ^ (s & mask64);
#else
        uint64_t d = GET_UINT64_LE(dst + c, 0);
        uint64_t s = GET_UINT64_LE(src + c, 0);
        PUT_UINT64_LE(d ^ (s & mask64), dst + c, 0);
#endif
    }
    for (; c < width; c++) {
        dst[c] ^= (uint8_t)(src[c] & mask);
    }
}

static inline void XorRowMaskedBits(uint8_t *dst, const uint8_t *src, const int32_t byteIdx, const int32_t bitInByte,
                                    const int32_t width, const uint8_t mask)
{
    const uint8_t loMask = (1u << bitInByte) - 1u;
    dst[byteIdx] ^= (uint8_t)(src[byteIdx] & (uint8_t)(~loMask & mask)); // pivot bit and higher bits
    XorRowSpanMaskedU64(dst, src, byteIdx + 1, width, mask);
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
    if (mat == NULL) {
        return;
    }
    BSL_SAL_FREE(mat->data);
    BSL_SAL_FREE(mat);
}

// reverses the order of the m least significant bits of a 16-bit unsigned integer x.
static uint16_t BitrevU16(const uint16_t x, const int32_t m)
{
    uint16_t r = 0;
    for (int32_t j = 0; j < m; j++) {
        r = (uint16_t)((r << 1) | ((x >> j) & 1U));
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}

static int32_t ComparePairs(const void *a, const void *b)
{
    const PairSt *p1 = (const PairSt *)a;
    const PairSt *p2 = (const PairSt *)b;
    if (p1->val < p2->val) {
        return -1;
    }
    if (p1->val > p2->val) {
        return 1;
    }
    return 0;
}


static int32_t GenerateFieldOrdering(uint16_t *alpha, const uint8_t *randomBits, const int32_t m, uint16_t *pi)
{
    PairSt *pairs = BSL_SAL_Malloc(MCELIECE_Q * sizeof(PairSt));
    if (pairs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // random q 32-bit a_i
    for (int32_t i = 0; i < MCELIECE_Q; i++) {
        pairs[i].val = GET_UINT32_LE(randomBits, i * 4); // le 32-bit
        pairs[i].pos = (uint16_t)i;
    }
    qsort(pairs, MCELIECE_Q, sizeof(PairSt), ComparePairs);
    for (int32_t i = 0; i < MCELIECE_Q_1; i++) {
        if (pairs[i].val == pairs[i + 1].val) {
            BSL_SAL_FREE(pairs);
            return CRYPT_MCELIECE_KEYGEN_FAIL;
        }
    }
    for (int32_t i = 0; i < MCELIECE_Q; i++) {
        uint16_t v = pairs[i].pos & (uint16_t)MCELIECE_Q_1;
        pi[i] = v;
        alpha[i] = (uint16_t)BitrevU16(v, m);
    }
    BSL_SAL_FREE(pairs);
    return CRYPT_SUCCESS;
}

//Compute the minimal/connection polynomial g(x) of f over GF(2^m)
static int32_t GenPolyOverGF(GFPolynomial *g, const GFPolynomial *f, const int32_t t)
{
    int32_t ret = CRYPT_SUCCESS;
    // Allocate (t+1) x t matrix in row-major: row r, col c at mat[r*t + c]
    uint16_t *mat = (uint16_t *)BSL_SAL_Malloc((uint32_t)(t + 1) * (uint32_t)t * sizeof(uint16_t));
    GFPolynomial *power = GFPolyCreate(t - 1);
    GFPolynomial *product = GFPolyCreate(t - 1);
    if (mat == NULL || power == NULL || product == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    // mat[0][:] = [1, 0, ..., 0]
    for (int32_t i = 0; i < t; i++) {
        mat[0 * t + i] = (i == 0) ? 1 : 0;
    }
    // mat[1][:] = f
    for (int32_t i = 0; i < t; i++) {
        mat[t + i] = GFPolyGetCoeff(f, i);
    }
    GFPolyCopy(power, f);
    // mat[2]..mat[t] by polynomial multiplication truncated to degree < t
    for (int32_t r = 2; r <= t; r++) {
        GFPolyMul(product, power, f);
        for (int32_t i = 0; i < t; i++) {
            mat[r * t + i] = GFPolyGetCoeff(product, i);
        }
        GFPolyCopy(power, product);
    }
    // Reference-style elimination on columns using mask-based pivot fix
    for (int32_t j = 0; j < t; j++) {
        for (int32_t k = j + 1; k < t; k++) {
            uint16_t mask = (mat[j * t + j] == 0) ? (uint16_t)0xFFFF : (uint16_t)0x0000;
            for (int32_t r = j; r <= t; r++) {
                mat[r * t + j] ^= (uint16_t)(mat[r * t + k] & mask);
            }
        }
        /* If mat[j*t + j] == 0 the j-th pivot is zero, which means column j is entirely zero: the first t truncated
         * powers 1, f, ..., f^{t-1} are linearly dependent.  In other words, deg(f) < t (or f is the zero polynomial),
         * so no unique minimal polynomial of degree t exists. No need to continue Gaussian elimination */
        if (mat[j * t + j] == 0) {
            ret = CRYPT_MCELIECE_KEYGEN_FAIL;
            goto ERR;
        }
        uint16_t inv = GFInverse(mat[j * t + j]);
        for (int32_t r = j; r <= t; r++) {
            mat[r * t + j] = GFMultiplication(mat[r * t + j], inv);
        }
        for (int32_t k = 0; k < t; k++) {
            if (k == j) {
                continue;
            }
            uint16_t tk = mat[j * t + k];
            for (int32_t r = j; r <= t; r++) {
                mat[r * t + k] ^= GFMultiplication(mat[r * t + j], tk);
            }
        }
    }
    // Output last row as coefficients
    for (int32_t i = 0; i < t; i++) {
        GFPolySetCoeff(g, i, mat[t * t + i]);
    }
ERR:
    GFPolyFree(power);
    GFPolyFree(product);
    BSL_SAL_FREE(mat);
    return ret;
}

static int32_t GenerateIrreduciblePolyFinal(GFPolynomial *g, const uint8_t *randomBits, const int32_t t,
                                            const int32_t m)
{
    int32_t ret;
    GFPolynomial *f = GFPolyCreate(t - 1);
    if (f == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    // read t little-endian 16-bit values, mask to m bits
    for (int32_t i = 0; i < t; i++) {
        uint16_t le = (uint16_t)randomBits[2 * i] | ((uint16_t)randomBits[2 * i + 1] << 8);
        GFPolySetCoeff(f, i, (uint16_t)(le & ((1U << m) - 1U)));
    }
    // Compute connection polynomial coefficients via GenPolyOverGF
    GOTO_ERR_IF(GenPolyOverGF(g, f, t), ret);
    // Complete the monic polynomial g(x) by setting the x^t coefficient.
    GFPolySetCoeff(g, t, 1);
ERR:
    GFPolyFree(f);
    return ret;
}

static int32_t GenGoppa(const uint8_t *irreduciblePolyBitsPtr, const uint8_t *fieldOrderingBitsPtr,
                        const McelieceParams *params, CMPrivateKey *sk, uint16_t *pi)
{
    int32_t ret = GenerateIrreduciblePolyFinal(sk->g, irreduciblePolyBitsPtr, params->t, params->m);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = GenerateFieldOrdering(sk->alpha, fieldOrderingBitsPtr, params->m, pi);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

static void ExtractTFromMatrix(const GFMatrix *sysH, const McelieceParams *params, GFMatrix *dstT)
{
    const int32_t tail = params->mt & 7;
    const int32_t tBytes = (params->n - params->mt + 7) / 8;
    const int32_t startByte = params->mt / 8;

    for (int32_t i = 0; i < params->mt; i++) {
        const uint8_t *row = sysH->data + i * sysH->colsBytes;
        uint8_t *out = dstT->data + i * tBytes;
        if (tail == 0) {
            (void)memcpy(out, row + startByte, (uint32_t)tBytes);
            continue;
        }
        for (int32_t j = startByte; j < (params->n - 1) / 8; j++) {
            *out++ = (uint8_t)((row[j] >> tail) | (row[j + 1] << (8 - tail)));
        }
        *out = (uint8_t)(row[(params->n - 1) / 8] >> tail);
    }
}

static void ParityCheckMatRow(uint16_t *goppaRow, int32_t power, const McelieceParams *params, GFMatrix *matH)
{
    const int32_t m = params->m;
    const int32_t n = params->n;
    for (int32_t j = 0; j < n; j += 8) {
        int32_t blockLen = (j + 8 <= n) ? 8 : (n - j);
        for (int32_t k = 0; k < m; k++) {
            uint8_t b = 0;
            // Reference mapping: MSB=col j+7 ... LSB=col j (for partial block, highest index first)
            for (int32_t tbit = blockLen - 1; tbit >= 0; tbit--) {
                b <<= 1;
                b |= (uint8_t)((goppaRow[j + tbit] >> k) & 1);
            }
            int32_t row = power * m + k;
            matH->data[row * matH->colsBytes + (uint32_t)j / 8] = b;
        }
    }
}
// Build H using the same bit-sliced packing and column grouping convention
// as the reference path: rows are grouped by bit position (k in 0..GFBITS-1)
// within each power i in 0..T-1; columns are packed 8-at-a-time into bytes.
static int32_t BuildParityCheckMatrix(GFMatrix *matH, const GFPolynomial *g, const uint16_t *support,
                                      const McelieceParams *params)
{
    const int32_t t = params->t;
    const int32_t m = params->m;
    const int32_t n = params->n;
    // inv[j] = 1 / g(support[j])
    uint16_t *inv = (uint16_t *)BSL_SAL_Malloc((uint32_t)n * sizeof(uint16_t));
    if (inv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // Evaluate monic polynomial g at support using our gf_* (internally bridged to ref GF)
    for (int32_t j = 0; j < n; j++) {
        uint16_t a = (uint16_t)(support[j] & ((1u << m) - 1u));
        // Evaluate monic polynomial: start at 1 (implicit leading coeff)
        uint16_t val = 1;
        for (int32_t d = t - 1; d >= 0; d--) {
            val = GFMultiplication(val, a);
            val ^= GFPolyGetCoeff(g, d);
        }
        if (val == 0) {
            BSL_SAL_FREE(inv);
            return CRYPT_MCELIECE_KEYGEN_FAIL;
        }
        inv[j] = GFInverse(val);
    }
    // Fill rows: for each i (power), for each 8-column block, for each bit k
    for (int32_t i = 0; i < t; i++) {
        ParityCheckMatRow(inv, i ,params, matH);
        // inv[j] *= support[j] for next power
        for (int32_t j = 0; j < n; j++) {
            uint16_t a = (uint16_t)(support[j] & ((1u << m) - 1u));
            inv[j] = GFMultiplication(inv[j], a);
        }
    }
    BSL_SAL_FREE(inv);
    return CRYPT_SUCCESS;
}

static int32_t ColsPermutation(uint8_t *mat, const int32_t colsBytes, uint16_t *pi, uint64_t *pivots, const int32_t mt)
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

static int32_t ReduceToSystematicForm(uint8_t *mat, const int32_t colsBytes, uint16_t *pi, uint64_t *pivots,
                                      const int32_t mt, bool isSemi)
{
    const int32_t mtBytes = (mt + 7) / 8;
    const int32_t permRow = mt - MCELIECE_MU;

    for (int32_t i = 0; i < mtBytes; i++) {
        for (int32_t j = 0; j < 8; j++) {
            int32_t row = i * 8 + j;
            if (row >= mt) {
                break;
            }

            uint8_t *rowPtr = mat + row * colsBytes;
            if (row == permRow && isSemi) {
                RETURN_RET_IF(ColsPermutation(mat, colsBytes, pi, pivots, mt) != CRYPT_SUCCESS,
                              CRYPT_MCELIECE_KEYGEN_FAIL);
            }
            uint8_t pivotBit = (uint8_t)((rowPtr[i] >> j) & 1u);

            for (int32_t k = row + 1; k < mt; k++) {
                uint8_t *curRow = mat + k * colsBytes;
                uint8_t curBit = (uint8_t)((curRow[i] >> j) & 1u);
                uint8_t mask = (uint8_t)(0u - (uint8_t)((pivotBit ^ 1u) & curBit));
                XorRowMaskedBits(rowPtr, curRow, i, j, colsBytes, mask);
                pivotBit |= curBit;
            }

            if (pivotBit == 0) {
                return CRYPT_MCELIECE_KEYGEN_FAIL;
            }

            for (int32_t k = 0; k < mt; k++) {
                uint8_t skipMask = (uint8_t)((k == row) - 1u);
                uint8_t *curRow = mat + k * colsBytes;
                uint8_t curBit = (uint8_t)((curRow[i] >> j) & 1u);
                uint8_t mask = (uint8_t)(0u - curBit);
                mask &= skipMask;
                XorRowMaskedBits(curRow, rowPtr, i, j, colsBytes, mask);
            }
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t KeyGenLoop(const uint8_t *sBitsPtr, const uint8_t *fieldOrderingBitsPtr,
                          const uint8_t *irreduciblePolyBitsPtr, CMPublicKey *pk, CMPrivateKey *sk,
                          const McelieceParams *params, bool isSemi)
{
    int32_t ret;
    uint16_t *pi = (uint16_t *)BSL_SAL_Malloc(sizeof(uint16_t) * MCELIECE_Q);
    GFMatrix *tmpH = MatrixCreate(params->mt, params->n);
    if (pi == NULL || tmpH == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
    ret = GenGoppa(irreduciblePolyBitsPtr, fieldOrderingBitsPtr, params, sk, pi);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = BuildParityCheckMatrix(tmpH, sk->g, sk->alpha, params);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ret = ReduceToSystematicForm(tmpH->data, tmpH->colsBytes, pi, &sk->c, params->mt, isSemi);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    if (isSemi) {
        // update the permutation of the support set in the semi-systematical param
        const int32_t start = params->mt - MCELIECE_MU;
        for (int32_t i = 0; i < MCELIECE_NU; i++) {
            sk->alpha[start + i] = (uint16_t)BitrevU16((uint16_t)pi[start + i], params->m);
        }
    }

    ExtractTFromMatrix(tmpH, params, &pk->matT);
    ret = ControlBitsFromBenesNetwork(sk->controlbits, pi, params->m, MCELIECE_Q);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    memcpy(sk->s, sBitsPtr, params->nBytes);

EXIT:
    MatrixFree(tmpH);
    BSL_SAL_FREE(pi);
    return ret;
}

static int32_t McEliecePrg(const uint8_t *seed, uint8_t *output, const uint32_t outputLen)
{
    /* tempSeed[0] is the length byte that Classic McEliece hard-codes to 64 (0x40) so that the later
     * Expand-And-Split step produces the correct number of field elements for the public key generation;
     * any other value would break the deterministic key schedule */
    // Total buffer length for key-generation seed: 1-byte length prefix + 32-byte random
    uint8_t tempSeed[MCELIECE_PRG_SEED_LEN] = {0};
    tempSeed[0] = MCELIECE_PRG_PREFIX; // the value of first element of tempSeed must be 64
    (void)memcpy_s(tempSeed + 1, MCELIECE_L_BYTES, seed, MCELIECE_L_BYTES);
    int32_t ret = McElieceShake256(output, outputLen, tempSeed, MCELIECE_PRG_SEED_LEN);
    BSL_SAL_CleanseData(tempSeed, MCELIECE_PRG_SEED_LEN);
    return ret;
}

int32_t SeededKeyGenInternal(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params,
                             bool isSemi)
{
    uint32_t sBitLen = (uint32_t)params->n;
    uint32_t irreduciblePolyBitLen = (uint32_t)MCELIECE_SIGMA1 * (uint32_t)params->t;
    uint32_t fieldOrderingBitLen = (uint32_t)MCELIECE_SIGMA2 * (uint32_t)MCELIECE_Q;
    uint32_t deltaPrimeBitLen = MCELIECE_L;

    uint32_t prgOutputBitLen = sBitLen + fieldOrderingBitLen + irreduciblePolyBitLen + deltaPrimeBitLen;
    uint32_t prgOutputByteLen = (prgOutputBitLen + 7) / 8;
    uint32_t sByteLen = (sBitLen + 7) / 8;
    uint32_t fieldOrderingByteLen = (fieldOrderingBitLen + 7) / 8;
    uint32_t deltaPrimeByteLen = (deltaPrimeBitLen + 7) / 8;

    uint8_t *rndE = (uint8_t *)BSL_SAL_Malloc(prgOutputByteLen);
    if (rndE == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(sk->delta, deltaPrimeByteLen, delta, deltaPrimeByteLen);
    int32_t ret;
    for (int32_t attempt = 0; attempt < MCELIECE_MAX_TRY_COUNT; attempt++) {
        uint8_t deltaPrime[MCELIECE_L_BYTES];
        ret = McEliecePrg(sk->delta, rndE, prgOutputByteLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_ClearFree(rndE, prgOutputByteLen);
            return ret;
        }
        (void)memcpy_s(deltaPrime, deltaPrimeByteLen, rndE + prgOutputByteLen - deltaPrimeByteLen, deltaPrimeByteLen);

        const uint8_t *sBitsPtr = rndE;
        const uint8_t *fieldOrderingBitsPtr = rndE + sByteLen;
        const uint8_t *irreducibleBitsPtr = fieldOrderingBitsPtr + fieldOrderingByteLen;

        ret = KeyGenLoop(sBitsPtr, fieldOrderingBitsPtr, irreducibleBitsPtr, pk, sk, params, isSemi);
        if (ret == CRYPT_SUCCESS || ret != CRYPT_MCELIECE_KEYGEN_FAIL) {
            break;
        }
        (void)memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
    }
    BSL_SAL_ClearFree(rndE, prgOutputByteLen);
    return ret;
}
#endif
