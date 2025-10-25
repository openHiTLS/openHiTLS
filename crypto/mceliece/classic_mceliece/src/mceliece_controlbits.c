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

#include "mceliece_controlbits.h"
#include "securec.h"

static inline int32_t Int32Min(int32_t a, int32_t b)
{
    return a < b ? a : b;
}

// Radix sort for 32-bit values (treat as unsigned for ordering)
// Sort values in ascending SIGNED order using radix with sign bias
static void RadixSortI32(uint32_t *ua, uint32_t *tmp, long long n)
{
    if (ua == NULL || tmp == NULL) {
        return;
    }

    const int RAD = 256;
    size_t cnt[RAD];
    size_t pref[RAD];
    for (int pass = 0; pass < 4; pass++) {
        memset_s(cnt, sizeof(cnt), 0, sizeof(cnt));
        int shift = pass * 8;
        for (long long i = 0; i < n; i++) {
            // bias for signed order: flip sign bit once across full 32-bit key
            uint32_t key = ua[i] ^ 0x80000000u;
            unsigned int b = (unsigned int)((key >> shift) & 0xFFu);
            cnt[b]++;
        }
        pref[0] = 0;
        for (int r = 1; r < RAD; r++) {
            pref[r] = pref[r - 1] + cnt[r - 1];
        }
        for (long long i = 0; i < n; i++) {
            uint32_t key = ua[i] ^ 0x80000000u;
            unsigned int b = (unsigned int)((key >> shift) & 0xFFu);
            tmp[pref[b]++] = ua[i];
        }
        // swap buffers
        uint32_t *swap = ua;
        ua = tmp;
        tmp = swap;
    }
    // 4 passes -> data back in original array pointer
}

// 32-bit le sort
static void SortU32LE(uint32_t *a, long long n)
{
    // reinterpret as unsigned for radix order; allocate temporary buffer
    uint32_t *ua = (uint32_t *)a;
    uint32_t *tmp = (uint32_t *)BSL_SAL_Malloc((size_t)n * sizeof(uint32_t));
    if (tmp) {
        RadixSortI32(ua, tmp, n);
        BSL_SAL_FREE(tmp);
    } else {    // fallback
        for (long long i = 0; i < n - 1; i++)
            for (long long j = i + 1; j < n; j++)
                if (a[j] < a[i]) {
                    uint32_t t = a[i];
                    a[i] = a[j];
                    a[j] = t;
                }
    }
}

static inline void Write1BitLE(uint8_t *buf, uint32_t bit_pos, uint8_t bit)
{
    buf[bit_pos >> 3] ^= (uint8_t)(bit << (bit_pos & 7));
}

static void Build32BitsKeys(uint32_t *out, const int16_t *pi, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint32_t lo = (uint32_t)(pi[i] ^ 1);
        uint32_t hi = (uint32_t)pi[i ^ 1];
        out[i] = (lo << 16) | hi;
    }
}

static void ExtractMinIndex(uint32_t *B, const uint32_t *A, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint32_t px = A[i] & 0xFFFFU;
        uint32_t cx = (px < i) ? px : i;
        B[i] = (px << 16) | cx;
    }
}

static void TagOriginalIndex(uint32_t *A, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        A[i] = (A[i] << 16) | i;
    }
}

static void TagParentKey(uint32_t *A, const uint32_t *B, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        A[i] = (A[i] << 16) | (B[i] >> 16);
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

static void BenesNetControlbits(
    uint8_t *out, uint32_t pos, uint32_t step, const int16_t *pi, uint32_t w, uint32_t n, int32_t *temp)
{
    uint32_t *areaA = (uint32_t *)temp;              // work area 0
    uint32_t *areaB = (uint32_t *)(temp + n);        // work area 1
    int16_t *q = (int16_t *)(temp + n + n / 4);  // perm buffer

    // base case: single bit
    if (w == 1) {
        Write1BitLE(out, pos, pi[0] & 1U);
        return;
    }

    // 32-bit keys
    Build32BitsKeys(areaA, pi, n);
    SortU32LE(areaA, n);

    // min index
    ExtractMinIndex(areaB, areaA, n);
    SortU32LE(areaA, n);  // reuse A as scratch

    // original index tag
    TagOriginalIndex(areaA, n);
    SortU32LE(areaA, n);

    // parent key tag
    TagParentKey(areaA, areaB, n);
    SortU32LE(areaA, n);

    // alphabet size branch
    if (w <= 10) {
        // small alphabet : 10-bit symbols
        for (uint32_t i = 0; i < n; i++) {
            areaB[i] = ((areaA[i] & 0x3FFU) << 10) | (areaB[i] & 0x3FFU);
        }
        for (uint32_t lvl = 1; lvl < w - 1; lvl++) {
            for (uint32_t i = 0; i < n; i++) {
                areaA[i] = ((areaB[i] & ~0x3FFU) << 6) | i;
            }
            SortU32LE(areaA, n);
            for (uint32_t i = 0; i < n; i++) {
                areaA[i] = (areaA[i] << 20) | (areaB[i] & 0xFFFFFU);
            }
            SortU32LE(areaA, n);
            for (uint32_t i = 0; i < n; i++) {
                uint32_t ppcpx = areaA[i] & 0xFFFFFU;
                uint32_t ppcx = (areaA[i] & 0xFFC00U) | (areaB[i] & 0x3FFU);
                areaB[i] = (ppcx < ppcpx) ? ppcx : ppcpx;
            }
        }
        for (uint32_t i = 0; i < n; i++) {
            areaB[i] &= 0x3FFU;
        }
    } else {
        // large alphabet: 16-bit symbols
        for (uint32_t i = 0; i < n; i++) {
            areaB[i] = (areaA[i] << 16) | (areaB[i] & 0xFFFFU);
        }
        for (uint32_t lvl = 1; lvl < w - 1; lvl++) {
            for (uint32_t i = 0; i < n; i++) {
                areaA[i] = (areaB[i] & ~0xFFFFU) | i;
            }
            SortU32LE(areaA, n);
            for (uint32_t i = 0; i < n; i++) {
                areaA[i] = (areaA[i] << 16) | (areaB[i] & 0xFFFFU);
            }
            if (lvl < w - 2) {
                for (uint32_t i = 0; i < n; i++) {
                    areaB[i] = (areaA[i] & ~0xFFFFU) | (areaB[i] >> 16);
                }
                SortU32LE(areaB, n);
                for (uint32_t i = 0; i < n; i++) {
                    areaB[i] = (areaB[i] << 16) | (areaA[i] & 0xFFFFU);
                }
            }
            SortU32LE(areaA, n);
            for (uint32_t i = 0; i < n; i++) {
                uint32_t cpx = (areaB[i] & ~0xFFFFU) | (areaA[i] & 0xFFFFU);
                areaB[i] = (areaB[i] < cpx) ? areaB[i] : cpx;
            }
        }
        for (uint32_t i = 0; i < n; i++) {
            areaB[i] &= 0xFFFFU;
        }
    }

    // parent keys for children
    for (uint32_t i = 0; i < n; i++) {
        areaA[i] = ((int32_t)pi[i] << 16) + i;
    }
    SortU32LE(areaA, n);

    // first half-recursion
    for (uint32_t j = 0; j < n / 2; j++) {
        uint32_t x = 2 * j;
        uint32_t fj = areaB[x] & 1U;
        uint32_t tmpFx = x + fj;
        uint32_t tmpFx1 = tmpFx ^ 1U;

        Write1BitLE(out, pos, fj);
        pos += step;

        areaB[x] = (areaA[x] << 16) | tmpFx;
        areaB[x + 1] = (areaA[x + 1] << 16) | tmpFx1;
    }
    SortU32LE(areaB, n);
    pos += (2 * w - 3) * step * (n / 2);

    // second half-recursion
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
    SortU32LE(areaA, n);
    pos -= (2 * w - 2) * step * (n / 2);

    // build child permutations and recurse
    for (uint32_t j = 0; j < n / 2; j++) {
        q[j] = (int16_t)((areaA[2 * j] & 0xFFFFU) >> 1);
        q[j + n / 2] = (int16_t)((areaA[2 * j + 1] & 0xFFFFU) >> 1);
    }
    BenesNetControlbits(out, pos, step * 2, q, w - 1, n / 2, temp);
    BenesNetControlbits(out, pos + step, step * 2, q + n / 2, w - 1, n / 2, temp);
}

// Produce L[0..N-1] equal to support_gen (bitrev of domain, then Benes, then extract low N indices)
static inline uint16_t BitrevMLocal(uint16_t x, int m)
{
    // Reverse only the lower m bits of x
    uint16_t r = 0;
    for (int i = 0; i < m; i++) {
        r = (uint16_t)((r << 1) | ((x >> i) & 1u));
    }
    return (uint16_t)(r & ((1u << m) - 1u));
}

// Bit helpers for bit-plane operations
static inline int GetBitFromVec(const unsigned char *vec, long long idx)
{
    return (vec[(size_t)(idx >> 3)] >> (idx & 7)) & 1;
}

static inline void SetBitInVec(unsigned char *vec, long long idx, int bit)
{
    size_t byteIndex = (size_t)(idx >> 3);
    unsigned char mask = (unsigned char)(1u << (idx & 7));
    if (bit) {
        vec[byteIndex] |= mask;
    } else {
        vec[byteIndex] &= (unsigned char)~mask;
    }
}

// Apply one Benes layer to a bit-vector using the given control bits
static void LayerBits(unsigned char *bitvec, const unsigned char *layerCBits, int s, long long nBits)
{
    long long stride = 1LL << (unsigned)(s & 31);
    long long index = 0;
    for (long long i = 0; i < nBits; i += stride * 2) {
        for (long long j = 0; j < stride; j++) {
            int ctrl = (layerCBits[(size_t)(index >> 3)] >> (index & 7)) & 1;
            if (ctrl) {
                long long a = i + j;
                long long b = i + j + stride;
                int ba = GetBitFromVec(bitvec, a);
                int bb = GetBitFromVec(bitvec, b);
                SetBitInVec(bitvec, a, bb);
                SetBitInVec(bitvec, b, ba);
            }
            index++;
        }
    }
}

void CbitsFromPermNs(uint8_t *out, const int16_t *pi, long long w, long long n)
{
    int32_t *temp = (int32_t *)BSL_SAL_Malloc(sizeof(int32_t) * (size_t)(2 * n));
    if (!temp) {
        return;
    }
    memset_s(temp, sizeof(int32_t) * (size_t)(2 * n), 0, sizeof(int32_t) * (size_t)(2 * n));
    size_t outBytes = (size_t)((((2 * w - 1) * n / 2) + 7) / 8);
    memset_s(out, outBytes, 0, outBytes);
    BenesNetControlbits(out, 0, 1, pi, w, n, temp);

    BSL_SAL_FREE(temp);
}

void SupportFromCbits(GFElement *L, const uint8_t *cbits, long long w, int lenN)
{
    if (!L || !cbits) {
        return;
    }
    long long n = 1LL << w;          // total domain size
    long long layerBytes = n >> 4;  // (n/2) bits per layer = n/16 bytes

    // Allocate bit-planes: w planes, each n bits -> n/8 bytes
    size_t planeBytes = (size_t)(n >> 3);
    unsigned char **planes = (unsigned char **)BSL_SAL_Malloc(sizeof(unsigned char *) * (size_t)w);
    if (!planes) {
        return;
    }
    for (long long b = 0; b < w; b++) {
        planes[b] = (unsigned char *)BSL_SAL_Malloc(planeBytes);
        if (!planes[b]) {
            for (long long k = 0; k < b; k++) {
                BSL_SAL_FREE(planes[k]);
            }
            BSL_SAL_FREE(planes);
            return;
        }
        memset_s(planes[b], planeBytes, 0, planeBytes);
    }

    // Initialize planes with bit-reversed indices
    for (long long i = 0; i < n; i++) {
        uint16_t br = BitrevMLocal((uint16_t)i, (int)w);
        for (long long b = 0; b < w; b++) {
            int bit = (br >> b) & 1;
            if (bit) {
                SetBitInVec(planes[b], i, 1);
            }
        }
    }

    // Apply Benes layers per reference ordering to each plane
    const unsigned char *ptr = cbits;
    // forward layers 0..w-1
    for (int s = 0; s < w; s++) {
        for (long long b = 0; b < w; b++) {
            LayerBits(planes[b], ptr, s, n);
        }
        ptr += layerBytes;
    }
    // backward layers w-2..0
    for (int s = w - 2; s >= 0; s--) {
        for (long long b = 0; b < w; b++) {
            LayerBits(planes[b], ptr, s, n);
        }
        ptr += layerBytes;
    }

    // Reconstruct support values from bit-planes
    for (int j = 0; j < lenN; j++) {
        uint16_t val = 0;
        for (int b = (int)w - 1; b >= 0; b--) {
            val = (uint16_t)(val << 1);
            val |= (uint16_t)GetBitFromVec(planes[b], j);
        }
        L[j] = (GFElement)val;
    }

    for (long long b = 0; b < w; b++) {
        free(planes[b]);
    }
    free(planes);
}
