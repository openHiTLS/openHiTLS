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

#include "mceliece_encode.h"
#include "securec.h"
#include "crypt_eal_rand.h"

// SWAR popcount
static inline unsigned Pop64(uint64_t x)
{
    x -= (x >> 1) & 0x5555555555555555ULL;
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (unsigned)((x * 0x0101010101010101ULL) >> 56);
}

// bit-flip
static inline void VecFlip(uint8_t *v, int idx)
{
    v[idx >> 3] ^= 1u << (idx & 7);
}

static inline uint64_t MatrixGetU64(const GFMatrix *matT, int row, int colBase)
{
    const int k = matT->cols;
    if (colBase >= k) {
        return 0;
    }

    const uint8_t *p = &matT->data[row * matT->colsBytes + (colBase >> 3)];
    const int tailBits = k - colBase;  // tail bits
    const int tailBytes = (tailBits + 7) >> 3;

    uint64_t w = 0;
    if (tailBytes < 8) {
        // tail: less than 8 bits
        memcpy_s(&w, tailBytes, p, tailBytes);
    } else {
        // tail: full 8 bits
        memcpy_s(&w, 8, p, 8);
    }

    w >>= (colBase & 7);
    if (tailBits < 64) {
        w &= (~0ULL >> (64 - tailBits));
    }
    return w;
}

// Encode: C = He, where H = (I_mt | T)
void EncodeVector(const uint8_t *errorVector, const GFMatrix *matT, uint8_t *ciphertext, const McelieceParams *params)
{
    if (!errorVector || !matT || !ciphertext) {
        return;
    }

    int paramN = params->n;
    if (paramN == 6688) {
        const uint8_t *pkPtr = matT->data;
        for (int i = 0; i < params->mt; i++) {
            uint8_t row[params->nBytes] __attribute__((aligned(8)));
            const int n64 = params->nBytes >> 3;
            uint64_t *w = (uint64_t *)row;
            for (int j = 0; j < n64; j += 4) {
                __builtin_prefetch(&w[j + 8], 1, 3); // L1 cache
                w[j] = 0;
                w[j + 1] = 0;
                w[j + 2] = 0;
                w[j + 3] = 0;
            }
            // clear tail
            for (int j = n64 & ~3; j < n64; j++) {
                w[j] = 0;
            }

            for (int j = n64 << 3; j < params->nBytes; j++) {
                row[j] = 0;
            }

            for (int j = 0; j < params->kBytes; j++) {
                row[params->nBytes - params->kBytes + j] = pkPtr[j];
            }

            row[i >> 3] |= 1u << (i & 7u);

            uint8_t bit = 0;
            for (size_t j = 0; j < params->nBytes; ++j) {
                uint8_t t = row[j] & errorVector[j];
                t ^= t << 4;
                t ^= t << 2;
                t ^= t << 1;
                bit ^= t >> 7;
            }
            bit &= 1;

            ciphertext[i >> 3] |= (bit << (i & 7));
            pkPtr += params->kBytes;
        }

    }
    if (paramN == 6960) {
        const int wholeBytes = params->mt >> 3;
        const int tailBits   = params->mt & 7;

        typedef uint64_t v64;
        const v64 *src64 = (const v64 *)errorVector;
        v64       *dst64 = (v64 *)ciphertext;
        int n64 = wholeBytes >> 3;
        for (int i = 0; i < n64; i++) dst64[i] = src64[i];

        uint8_t *s = (uint8_t *)errorVector + (n64 << 3);
        uint8_t *d = (uint8_t *)ciphertext   + (n64 << 3);
        int n = wholeBytes & 7;
        if (n >= 4) { memcpy_s(d, 4, s, 4); s += 4; d += 4; n -= 4; }
        if (n >= 2) { memcpy_s(d, 2, s, 2); s += 2; d += 2; n -= 2; }
        if (n >= 1) { *d = *s; ++s; ++d; }
        if (tailBits) {
            uint8_t m = (1U << tailBits) - 1;
            *d = (*d & ~m) | (*s & m);
        }

        const int slices = (params->k + 63) >> 6;
        uint64_t eSlab[slices];

        for (int s = 0; s < slices; s++) {
            uint64_t w = 0;
            int base = s << 6;
            int limit = (base + 64 < params->k) ? 64 : (params->k - base);
            int bitIdx = params->mt + base;
            for (int b = 0; b < limit; b++) {
                int bi = bitIdx + b;
                uint8_t byte = errorVector[bi >> 3];
                int bp = bi & 7;
                w |= ((uint64_t)((byte >> bp) & 1)) << b;
            }
            w &= (limit == 64) ? ~0ULL : (~0ULL >> (64 - limit));
            eSlab[s] = w;
        }

        static const uint8_t pop4[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
        for (int r = 0; r < params->mt; r++) {
            int dot = 0;
            for (int s = 0; s < slices; s++) {
                uint64_t es = eSlab[s];
                uint64_t m  = MatrixGetU64(matT, r, s << 6);
                uint64_t v  = m & es;

                for (int shift = 0; shift < 64; shift += 4) {
                    dot += pop4[(v >> shift) & 0xF];
                }
            }
            if (dot & 1) {
                VecFlip(ciphertext, r);
            }
        }

    }
    if (paramN == 8192) {
        const int leading = params->nBytes - params->kBytes;
        const uint8_t *pkPtr = matT->data;

        int i;
        for (i = 0; i <= params->mt - 4; i += 4) {
            uint8_t row[4][params->nBytes] __attribute__((aligned(8)));

            const int n64Copy = leading >> 3;
            uint64_t *w0 = (uint64_t *)row[0];
            
            for (int j = 0; j < n64Copy; j += 4) {
                __builtin_prefetch(&w0[j + 8], 1, 3);
                w0[j] = 0;
                w0[j + 1] = 0;
                w0[j + 2] = 0;
                w0[j + 3] = 0;
            }

            for (int j = n64Copy & ~3; j < n64Copy; j++) {
                w0[j] = 0;
            }

            for (int j = leading & ~7; j < leading; j++) {
                row[0][j] = 0;
            }
            
            for (int t = 1; t < 4; t++) {
                uint64_t *wt = (uint64_t *)row[t];
                for (int j = 0; j < n64Copy; j += 4) {
                    __builtin_prefetch(&wt[j + 8], 1, 3);
                    wt[j] = w0[j];
                    wt[j + 1] = w0[j + 1];
                    wt[j + 2] = w0[j + 2];
                    wt[j + 3] = w0[j + 3];
                }
                
                for (int j = n64Copy & ~3; j < n64Copy; j++) {
                    wt[j] = w0[j];
                }
                
                memcpy_s(row[t], leading & 7, row[0], leading & 7);
            }

            memcpy_s(row[0] + leading, params->kBytes, pkPtr, params->kBytes);
            memcpy_s(row[1] + leading, params->kBytes, pkPtr + params->kBytes, params->kBytes);
            memcpy_s(row[2] + leading, params->kBytes, pkPtr + 2 * params->kBytes, params->kBytes);
            memcpy_s(row[3] + leading, params->kBytes, pkPtr + 3 * params->kBytes, params->kBytes);

            uint32_t mask[4];
            for (int t = 0; t < 4; t++) {
                mask[t] = 1u << ((i + t) & 7u);
            }
            uint32_t *r32[4] = {(uint32_t *)(row[0] + (i >> 3)),
                (uint32_t *)(row[1] + ((i + 1) >> 3)),
                (uint32_t *)(row[2] + ((i + 2) >> 3)),
                (uint32_t *)(row[3] + ((i + 3) >> 3))};
            r32[0][0] |= mask[0];
            r32[1][0] |= mask[1];
            r32[2][0] |= mask[2];
            r32[3][0] |= mask[3];

            uint64_t acc64[4] = {0};
            const int n64 = params->nBytes >> 3;
            const uint64_t *e64 = (const uint64_t *)errorVector;
            for (int j = 0; j < n64; j++) {
                uint64_t ej = e64[j];
                acc64[0] ^= ((uint64_t *)row[0])[j] & ej;
                acc64[1] ^= ((uint64_t *)row[1])[j] & ej;
                acc64[2] ^= ((uint64_t *)row[2])[j] & ej;
                acc64[3] ^= ((uint64_t *)row[3])[j] & ej;
            }

            for (int t = 0; t < 4; t++) {
                uint8_t b = Pop64(acc64[t]) & 1;
                ciphertext[(i + t) >> 3] |= b << ((i + t) & 7);
            }

            pkPtr += (params->kBytes << 2);
        }
        // no tail remains
    }
}

McElieceError FixedWeightVector(uint8_t *e, int n, int t, const McelieceParams *params)
{
    int paramN = params->n;
    if (paramN == 6688 || paramN == 6960) {

        // FixedWeight alg.
        int tau = t + 10;
        size_t randomByteLen = tau * 2;  // σ₁ = 16 bits = 2 bytes per position
        uint8_t *randomBytes = BSL_SAL_Malloc(randomByteLen);
        if (!randomBytes) {
            return MCELIECE_ERROR_MEMORY;
        }

        // Generate a random seed using the system's randomness
        uint8_t seed[MCELIECE_L_BYTES];

        // // Use system randomness (this is a simple implementation)
        // // In production, you'd want a proper CSPRNG
        // FILE *urandom = fopen("/dev/urandom", "rb");
        // if (urandom) {
        //     // Use system randomness
        //     RandomSeed32(seed);
        //     fclose(urandom);
        // } else {
        //     // Fallback to time-based seed (not cryptographically secure)
        //     RandomSeed32Aslr(seed);
        // }

        CRYPT_EAL_Randbytes(seed, MCELIECE_L_BYTES);
        McEliecePrg(seed, randomBytes, randomByteLen);

        // j ∈ {0, 1, ..., τ-1}
        int *dValues = BSL_SAL_Malloc(tau * sizeof(int));
        if (!dValues) {
            BSL_SAL_FREE(randomBytes);
            return MCELIECE_ERROR_MEMORY;
        }

        for (int j = 0; j < tau; j++) {
            uint16_t d_j = (uint16_t)randomBytes[j * 2] | ((uint16_t)randomBytes[j * 2 + 1] << 8);
            dValues[j] = d_j % n;  // {0, 1, ..., n-1}
        }

        // a_0, a_1, ..., a_{t-1}
        int *positions = BSL_SAL_Malloc(t * sizeof(int));
        if (!positions) {
            BSL_SAL_FREE(randomBytes);
            BSL_SAL_FREE(dValues);
            return MCELIECE_ERROR_MEMORY;
        }

        int uniqueCount = 0;
        int maxAttempts = tau * 2;
        int attempts = 0;

        for (int i = 0; i < tau && uniqueCount < t && attempts < maxAttempts; i++) {
            int pos = dValues[i];
            int isUnique = 1;

            for (int j = 0; j < uniqueCount; j++) {
                if (positions[j] == pos) {
                    isUnique = 0;
                    break;
                }
            }

            if (isUnique) {
                positions[uniqueCount] = pos;
                uniqueCount++;
            }
            attempts++;
        }

        // retry
        if (uniqueCount < t) {
            BSL_SAL_FREE(positions);
            BSL_SAL_FREE(dValues);
            BSL_SAL_FREE(randomBytes);
            return MCELIECE_ERROR_KEYGEN_FAIL;
        }

        for (int i = 0; i < t; i++) {
            VectorSetBit(e, positions[i], 1);
        }

        BSL_SAL_FREE(positions);
        BSL_SAL_FREE(dValues);
        BSL_SAL_FREE(randomBytes);
    }
    if (paramN == 8192) {
        // no malloc
        const int tau = t + 10;
        uint64_t used[128] = {0};  // 128 = (n + 63) >> 6

        uint8_t rnd[tau * 2] __attribute__((aligned(16)));
        uint16_t pos[params->t] __attribute__((aligned(16)));

        uint8_t seed[MCELIECE_L_BYTES];
        // FILE *urandom = fopen("/dev/urandom", "rb");
        // if (urandom) {
        //     RandomSeed32(seed);
        //     fclose(urandom);
        // } else {
        //     RandomSeed32Aslr(seed);
        // }
        CRYPT_EAL_Randbytes(seed, MCELIECE_L_BYTES);
        McEliecePrg(seed, rnd, sizeof(rnd));

        int uniq = 0;
        for (int i = 0; i < tau && uniq < t; i++) {
            uint16_t u = (uint16_t)rnd[i * 2] | ((uint16_t)rnd[i * 2 + 1] << 8);
            uint16_t p = u & (n - 1);
            uint64_t mask = 1ULL << (p & 63);
            int idx64 = p >> 6;
            if (used[idx64] & mask) {
                continue;
            }
            used[idx64] |= mask;
            pos[uniq++] = p;
        }

        if (uniq < t) {
            return MCELIECE_ERROR_GEN_E_FAIL;
        }

        uint64_t masks[params->t];
        uint8_t idx8[params->t];
        int mcnt = 0;
        for (int i = 0; i < uniq; i++) {
            uint16_t p = pos[i];
            masks[mcnt] = 1ULL << (p & 63);
            idx8[mcnt] = p >> 6;
            mcnt++;
        }
        uint64_t *e64 = (uint64_t *)e;
        for (int i = 0; i < mcnt; i++) {
            e64[idx8[i]] |= masks[i];
        }
    }
    return MCELIECE_SUCCESS;
}
