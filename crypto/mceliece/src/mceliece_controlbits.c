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
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "mceliece_local.h"

// Radix sort for 32-bit values (treat as unsigned for ordering)
// Sort values in ascending SIGNED order using radix with sign bias
static void RadixSortI32(uint32_t *ua, uint32_t *tmp, const int64_t n)
{
    if (ua == NULL || tmp == NULL) {
        return;
    }

    const int32_t rad = 256; // Number of buckets per radix pass (8-bit digit --> 2^8 = 256)
    size_t cnt[256];
    size_t pref[256];
    for (int32_t pass = 0; pass < 4; pass++) { // Number of radix passes for full 32-bit key (32 / 8 = 4)
        (void)memset_s(cnt, sizeof(cnt), 0, sizeof(cnt));
        int32_t shift = pass * 8; // Bit-shift per radix pass (8-bit digit size)
        for (int64_t i = 0; i < n; i++) {
            // bias for signed order: flip sign bit once across full 32-bit key
            uint32_t key =
                ua[i] ^ 0x80000000u; // Bias XOR to convert signed 32-bit values into unsigned lexicographic order
            uint32_t b = (uint32_t)((key >> shift) & 0xFFu); // 8-bit mask to extract current radix digit
            cnt[b]++;
        }
        pref[0] = 0;
        for (int32_t r = 1; r < rad; r++) {
            pref[r] = pref[r - 1] + cnt[r - 1];
        }
        for (int64_t i = 0; i < n; i++) {
            uint32_t key = ua[i] ^ 0x80000000u;
            uint32_t b = (uint32_t)((key >> shift) & 0xFFu);
            tmp[pref[b]++] = ua[i];
        }
        // swap buffers
        uint32_t *swap = ua;
        ua = tmp;
        tmp = swap;
    }
}

// 32-bit le sort
static int32_t SortU32LE(uint32_t *a, const int64_t n)
{
    // reinterpret as unsigned for radix order; allocate temporary buffer
    uint32_t *ua = (uint32_t *)a;
    uint32_t *tmp = (uint32_t *)BSL_SAL_Malloc((size_t)n * sizeof(uint32_t));
    if (tmp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    RadixSortI32(ua, tmp, n);
    BSL_SAL_FREE(tmp);
    return CRYPT_SUCCESS;
}

static void Write1BitLE(uint8_t *buf, uint32_t bit_pos, uint8_t bit)
{
    buf[bit_pos >> 3] ^=
        (uint8_t)(bit << (bit_pos & 7)); // Bit-index mask / byte-shift for bit-addressable buffer access
}

// Build 32-bit keys: (pi[i]^1, pi[i^1])
static void Build32BitsKeys(uint32_t *out, const int16_t *pi, const uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint32_t lo = (uint32_t)(pi[i] ^ 1);
        uint32_t hi = (uint32_t)pi[i ^ 1];
        out[i] = (lo << 16) | hi; // Bit-shift to pack high and low 16-bit halves into one 32-bit key
    }
}

// Extract min-index: B[i] = (px<<16) | min(px,i)
static void ExtractMinIndex(uint32_t *B, const uint32_t *A, const uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint32_t px = A[i] & 0xFFFFU;
        uint32_t cx = (px < i) ? px : i;
        B[i] = (px << 16) | cx;
    }
}

// Tag original index: A[i] = (A[i]<<16) | i
static void TagOriginalIndex(uint32_t *A, const uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        A[i] = (A[i] << 16) | i;
    }
}

// Tag parent key: A[i] = (A[i]<<16) | (B[i]>>16)
static void TagParentKey(uint32_t *A, const uint32_t *B, const uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        A[i] = (A[i] << 16) | (B[i] >> 16);
    }
}

// Small alphabet branch (w <= 10)
static int32_t ProcessSmallAlphabet(uint32_t *areaA, uint32_t *areaB, uint32_t n, uint32_t w)
{
    // 10-bit symbols
    for (uint32_t i = 0; i < n; i++) {
        areaB[i] = ((areaA[i] & 0x3FFU) << 10) | (areaB[i] & 0x3FFU);
    }
    int32_t ret;
    for (uint32_t lvl = 1; lvl < w - 1; lvl++) {
        for (uint32_t i = 0; i < n; i++) {
            areaA[i] = ((areaB[i] & ~0x3FFU) << 6) | i;
        }
        ret = SortU32LE(areaA, n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        for (uint32_t i = 0; i < n; i++) {
            areaA[i] =
                (areaA[i] << 20) |
                (areaB[i] & 0xFFFFF); // Bit-shift to pack 20-bit combined symbol during small-alphabet processing
        }
        ret = SortU32LE(areaA, n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        for (uint32_t i = 0; i < n; i++) {
            uint32_t ppcpx = areaA[i] & 0xFFFFF;
            uint32_t ppcx = (areaA[i] & 0xFFC00U) |
                            (areaB[i] & 0x3FFU); // Mask to keep upper 10 bits while combining with lower 10 bits
            areaB[i] = (ppcx < ppcpx) ? ppcx : ppcpx;
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        areaB[i] &= 0x3FFU; // 10-bit mask to keep only the final 10-bit symbol
    }
    return CRYPT_SUCCESS;
}

// Large alphabet branch (w > 10)
static int32_t ProcessLargeAlphabet(uint32_t *areaA, uint32_t *areaB, const uint32_t n, const uint32_t w)
{
    // 16-bit symbols
    for (uint32_t i = 0; i < n; i++) {
        areaB[i] = (areaA[i] << 16) | (areaB[i] & 0xFFFFU); // 16-bit mask to extract or keep 16-bit symbol halves
    }
    int32_t ret;
    for (uint32_t lvl = 1; lvl < w - 1; lvl++) {
        for (uint32_t i = 0; i < n; i++) {
            areaA[i] = (areaB[i] & ~0xFFFFU) | i;
        }
        ret = SortU32LE(areaA, n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        for (uint32_t i = 0; i < n; i++) {
            areaA[i] = (areaA[i] << 16) | (areaB[i] & 0xFFFFU);
        }
        if (lvl < w - 2) {
            for (uint32_t i = 0; i < n; i++) {
                areaB[i] = (areaA[i] & ~0xFFFFU) | (areaB[i] >> 16);
            }
            ret = SortU32LE(areaB, n);
            if (ret != CRYPT_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                return ret;
            }
            for (uint32_t i = 0; i < n; i++) {
                areaB[i] = (areaB[i] << 16) | (areaA[i] & 0xFFFFU);
            }
        }
        ret = SortU32LE(areaA, n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        for (uint32_t i = 0; i < n; i++) {
            uint32_t cpx = (areaB[i] & ~0xFFFFU) | (areaA[i] & 0xFFFFU);
            areaB[i] = (areaB[i] < cpx) ? areaB[i] : cpx;
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        areaB[i] &= 0xFFFFU;
    }
    return CRYPT_SUCCESS;
}

// Prepare parent keys for children recursion
static int32_t PrepareParentKeys(uint32_t *areaA, const int16_t *pi, const uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        areaA[i] = ((int32_t)pi[i] << 16) + i;
    }
    int32_t ret = SortU32LE(areaA, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

// Emit first half control bits and reorder
static int32_t EmitFirstHalf(uint32_t *posOut, uint8_t *out, uint32_t pos, uint32_t step, uint32_t *areaA,
                             uint32_t *areaB, const uint32_t n)
{
    for (uint32_t j = 0; j < n / 2; j++) {
        uint32_t x = 2 * j;
        uint32_t fj = areaB[x] & 1U; // Unit bit mask to extract control bit from LSB
        uint32_t tmpFx = x + fj;
        uint32_t tmpFx1 = tmpFx ^ 1U; // Toggle mask to flip least-significant bit (select sibling)

        Write1BitLE(out, pos, fj);
        pos += step;

        areaB[x] = (areaA[x] << 16) | tmpFx;
        areaB[x + 1] = (areaA[x + 1] << 16) | tmpFx1;
    }
    int32_t ret = SortU32LE(areaB, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *posOut = pos;
    return CRYPT_SUCCESS;
}

// Emit second half control bits and reorder
static int32_t EmitSecondHalf(uint32_t *posOut, uint8_t *out, uint32_t pos, uint32_t step, uint32_t *areaA,
                              uint32_t *areaB, const uint32_t n)
{
    for (uint32_t k = 0; k < n / 2; k++) {
        uint32_t y = 2 * k;
        uint32_t lk = areaB[y] & 1U;
        uint32_t tmpLy = y + lk;
        uint32_t tmpLy1 = tmpLy ^ 1U;

        Write1BitLE(out, pos, lk);
        pos += step;

        areaA[y] = (tmpLy << 16) | (areaB[y] & 0xFFFFU);
        areaA[y + 1] = (tmpLy1 << 16) | (areaB[y + 1] & 0xFFFFU);
    }
    int32_t ret = SortU32LE(areaA, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *posOut = pos;
    return CRYPT_SUCCESS;
}

// Build child permutations for recursion
static void BuildChildPerm(int16_t *q, const uint32_t *areaA, const uint32_t n)
{
    for (uint32_t j = 0; j < n / 2; j++) {
        q[j] = (int16_t)((areaA[2 * j] & 0xFFFFU) >> 1);
        q[j + n / 2] = (int16_t)((areaA[2 * j + 1] & 0xFFFFU) >> 1);
    }
}

/*
 *  Recursive Benes-network control-bit generator.
 *  Inputs:
 *    out         - output bit buffer (bit-addressable)
 *    pos         - starting bit position in 'out'
 *    step        - bit step between sibling calls
 *    pi          - permutation over 0..n-1
 *    w           - recursion depth (number of control-bit layers)
 *    n           - current segment length (always a power of 2)
 *    temp        - scratch buffer (size >= 2*n + n/4*sizeof(int16_t))
 *  The function writes control bits into 'out' and recurses on halves.
 */
static int32_t BenesNetControlbits(uint8_t *out, uint32_t pos, uint32_t step, const int16_t *pi, const uint32_t w,
                                   const uint32_t n, int32_t *temp)
{
    uint32_t *areaA = (uint32_t *)temp; // work area 0
    uint32_t *areaB = (uint32_t *)(temp + n); // work area 1
    int16_t *q = (int16_t *)(temp + n + n / 4); // perm buffer

    if (w == 1) { // Base-case sentinel – when only 1 control layer remains, emit single bit and stop
        Write1BitLE(out, pos, pi[0] & 1U);
        return CRYPT_SUCCESS;
    }
    int32_t ret;
    Build32BitsKeys(areaA, pi, n);
    ret = SortU32LE(areaA, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ExtractMinIndex(areaB, areaA, n);
    ret = SortU32LE(areaA, n); // reuse A as scratch
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    TagOriginalIndex(areaA, n);
    ret = SortU32LE(areaA, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    TagParentKey(areaA, areaB, n);
    ret = SortU32LE(areaA, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (w <= 10) { // Alphabet-size threshold to choose small-alphabet optimization path
        ret = ProcessSmallAlphabet(areaA, areaB, n, w);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        ret = ProcessLargeAlphabet(areaA, areaB, n, w);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    ret = PrepareParentKeys(areaA, pi, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint32_t posOut;
    ret = EmitFirstHalf(&posOut, out, pos, step, areaA, areaB, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pos = posOut;
    pos += (2 * w - 3) * step * (n / 2); // Coefficient 2 – total control-bit skew factor for first-half emission offset

    ret = EmitSecondHalf(&posOut, out, pos, step, areaA, areaB, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pos = posOut;
    // Coefficient 2 – total control-bit skew factor for second-half emission correction
    pos -= (2 * w - 2) * step * (n / 2);

    BuildChildPerm(q, areaA, n);
    ret = BenesNetControlbits(out, pos, step * 2, q, w - 1, n / 2, temp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BenesNetControlbits(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

// Produce L[0..N-1] equal to support_gen (bitrev of domain, then Benes, then extract low N indices)
static uint16_t BitrevMLocal(uint16_t x, const int32_t m)
{
    // Reverse only the lower m bits of x
    uint16_t r = 0;
    for (int32_t i = 0; i < m; i++) {
        r = (uint16_t)((r << 1) | ((x >> i) & 1u)); // Unit bit mask – isolate single bit during bit-reversal loop
    }
    return (uint16_t)(r & ((1u << m) - 1u));
}

// Bit helpers for bit-plane operations
static uint32_t GetBitFromVec(const uint8_t *vec, const int64_t idx)
{
    return (vec[(size_t)(idx >> 3)] >> (idx & 7)) & 1;
}

static void SetBitInVec(uint8_t *vec, const int64_t idx, const uint32_t bit)
{
    size_t byteIndex = (size_t)(idx >> 3);
    uint8_t mask = (uint8_t)(1u << (idx & 7));
    if (bit != 0) {
        vec[byteIndex] |= mask;
    } else {
        vec[byteIndex] &= (uint8_t)~mask;
    }
}

// Apply one Benes layer to a bit-vector using the given control bits
static void LayerBits(uint8_t *bitvec, const uint8_t *layerCBits, const int32_t s, const int64_t nBits)
{
    // Mask to keep shift amount within 5-bit range (prevents UB for s >= 32)
    int64_t stride = 1LL << (unsigned)(s & 31);
    int64_t index = 0;
    for (int64_t i = 0; i < nBits; i += stride * 2) {
        for (int64_t j = 0; j < stride; j++) {
            int32_t ctrl = (layerCBits[(size_t)(index >> 3)] >> (index & 7)) & 1;
            if (ctrl != 0) {
                int64_t a = i + j;
                int64_t b = i + j + stride;
                uint32_t ba =
                    GetBitFromVec(bitvec, a); // Unit bit value – represent Boolean 0/1 state in bit-vector operations
                uint32_t bb = GetBitFromVec(bitvec, b);
                SetBitInVec(bitvec, a, bb); // Unit bit value – represent Boolean 0/1 state in bit-vector operations
                SetBitInVec(bitvec, b, ba);
            }
            index++;
        }
    }
}

int32_t CbitsFromPermNs(uint8_t *out, const int16_t *pi, const int64_t w, const int64_t n)
{
    int32_t *temp = (int32_t *)BSL_SAL_Malloc(sizeof(int32_t) * (size_t)(2 * n));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memset_s(temp, sizeof(int32_t) * (size_t)(2 * n), 0, sizeof(int32_t) * (size_t)(2 * n));
    size_t outBytes = (size_t)((((2 * w - 1) * n / 2) + 7) / 8);
    (void)memset_s(out, outBytes, 0, outBytes);
    int32_t ret = BenesNetControlbits(out, 0, 1, pi, w, n, temp);
    BSL_SAL_FREE(temp);
    return ret;
}

static int32_t AllocBitPlanes(uint8_t ***planes, const int64_t w, const int64_t planeBytes)
{
    *planes = (uint8_t **)BSL_SAL_Malloc(sizeof(uint8_t *) * (size_t)w);
    if (*planes == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    for (int64_t b = 0; b < w; b++) {
        (*planes)[b] = (uint8_t *)BSL_SAL_Malloc(planeBytes);
        if ((*planes)[b] == NULL) {
            for (int64_t k = 0; k < b; k++) {
                BSL_SAL_FREE((*planes)[k]);
            }
            BSL_SAL_FREE(*planes);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        (void)memset_s((*planes)[b], planeBytes, 0, planeBytes);
    }
    return CRYPT_SUCCESS;
}

static void FreeBitPlanes(uint8_t **planes, int64_t w)
{
    for (int64_t b = 0; b < w; b++) {
        BSL_SAL_FREE(planes[b]);
    }
    BSL_SAL_FREE(planes);
}

static void InitPlanesWithBitrev(uint8_t **planes, const int64_t w, const int64_t n)
{
    for (int64_t i = 0; i < n; i++) {
        uint16_t br = BitrevMLocal((uint16_t)i, (int32_t)w);
        for (int64_t b = 0; b < w; b++) {
            uint32_t bit = (br >> b) & 1;
            if (bit != 0) {
                SetBitInVec(planes[b], i, 1);
            }
        }
    }
}

static void ApplyBenesLayers(uint8_t **planes, const uint8_t *cbits, const int64_t w, const int64_t n,
                             const int64_t layerBytes)
{
    const uint8_t *ptr = cbits;
    // forward 0..w-1
    for (int32_t s = 0; s < w; s++) {
        for (int64_t b = 0; b < w; b++) {
            LayerBits(planes[b], ptr, s, n);
        }
        ptr += layerBytes;
    }
    // backward w-2..0
    for (int32_t s = w - 2; s >= 0; s--) {
        for (int64_t b = 0; b < w; b++) {
            LayerBits(planes[b], ptr, s, n);
        }
        ptr += layerBytes;
    }
}

static void ReconstructSupport(GFElement *gfL, uint8_t **planes, const int32_t lenN, const int64_t w)
{
    for (int32_t j = 0; j < lenN; j++) {
        uint16_t val = 0;
        for (int32_t b = (int32_t)w - 1; b >= 0; b--) {
            val = (uint16_t)(val << 1);
            val |= (uint16_t)GetBitFromVec(planes[b], j);
        }
        gfL[j] = (GFElement)val;
    }
}

int32_t SupportFromCbits(GFElement *gfL, const uint8_t *cbits, const int64_t w, const int32_t lenN)
{
    if (gfL == NULL || cbits == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int64_t n = 1LL << w;
    int64_t layerBytes = n >> 4; // (n/2) bits / layer -> n/16 bytes? (original used n/16)
    size_t planeBytes = (size_t)(n >> 3); // n bits -> n/8 bytes

    uint8_t **planes = NULL;
    int32_t ret = AllocBitPlanes(&planes, w, planeBytes);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    InitPlanesWithBitrev(planes, w, n);
    ApplyBenesLayers(planes, cbits, w, n, layerBytes);
    ReconstructSupport(gfL, planes, lenN, w);
    FreeBitPlanes(planes, w);
    return CRYPT_SUCCESS;
}

#endif
