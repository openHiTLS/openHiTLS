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

#include "mceliece_keygen.h"
#include "bsl_sal.h"
#include "securec.h"

typedef struct {
    uint32_t val;  // <--- must be uint32_t
    uint16_t pos;
} pair_t;


// reverses the order of the m least significant bits of a 16-bit unsigned integer x.
static inline uint16_t BitrevU16(uint16_t x, int m)
{
    uint16_t r = 0;
    for (int j = 0; j < m; j++) {
        r = (uint16_t)((r << 1) | ((x >> j) & 1U));
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}

static inline uint32_t load4(const unsigned char *x)
{
    uint32_t r = 0;
    memcpy_s(&r, 4, x, 4);
    return r;
}


static int ComparePairs(const void *a, const void *b)
{
    const pair_t *p1 = (const pair_t *)a;
    const pair_t *p2 = (const pair_t *)b;
    if (p1->val < p2->val) {
        return -1;
    }
    if (p1->val > p2->val) {
        return 1;
    }
    if (p1->pos < p2->pos) {
        return -1;
    }
    if (p1->pos > p2->pos) {
        return 1;
    }
    return 0;
}

static void U16LEToU8(uint8_t *dst, const uint16_t *src, size_t srcLen)
{
    for (size_t i = 0; i < srcLen; i++) {
        dst[i * 2] = src[i] & 0xFF;             // low bytes
        dst[i * 2 + 1] = (src[i] >> 8) & 0xFF;  // high bytes
    }
}

McElieceError SeededKeyGen(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (!delta || !pk || !sk) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    // E = s || (bits for FieldOrdering) || (bits for Irreducible) || δ'
    // len = n + σ₂q + σ₁t + l bits

    int sBitLen = params->n;
    int irreduciblePolyBitLen = MCELIECE_SIGMA1 * params->t;
    int fieldOrderingBitLen = MCELIECE_SIGMA2 * MCELIECE_Q;
    int deltaPrimeBitLen = MCELIECE_L;

    size_t prgOutputBitLen =
        sBitLen + fieldOrderingBitLen + irreduciblePolyBitLen + deltaPrimeBitLen;

    size_t prgOutputByteLen = (prgOutputBitLen + 7) >> 3;

    size_t sByteLen = (sBitLen + 7) >> 3;
    size_t fieldOrderingByteLen = (fieldOrderingBitLen + 7) >> 3;
    size_t irreduciblePolyByteLen = (irreduciblePolyBitLen + 7) >> 3;
    size_t deltaPrimeByteLen = (deltaPrimeBitLen + 7) >> 3;

    if (prgOutputByteLen !=
        sByteLen + fieldOrderingByteLen + irreduciblePolyByteLen + deltaPrimeByteLen) {
    }

    uint8_t *rndE = BSL_SAL_Malloc(prgOutputByteLen);
    if (!rndE) {
        return MCELIECE_ERROR_MEMORY;
    }

    memcpy_s(sk->delta, deltaPrimeByteLen, delta, deltaPrimeByteLen);

    int maxAttempts = 50;  // allow retries in both modes; in KAT, DRBG provides fresh bytes per attempt
    for (int attempt = 0; attempt < maxAttempts; attempt++) {
        // 1. Generate long random string E.
        McEliecePrg(sk->delta, rndE, prgOutputByteLen);

        // 2. Extract next retry seed delta' from the end of E
        uint8_t deltaPrime[MCELIECE_L_BYTES];
        memcpy_s(deltaPrime, deltaPrimeByteLen, rndE + prgOutputByteLen - deltaPrimeByteLen, deltaPrimeByteLen);
        // kat_expand_r already advanced the internal seed; nothing more to do

        // 3. Split E into parts (using byte offsets)
        const uint8_t *sBitsPtr = rndE;
        const uint8_t *fieldOrderingBitsPtr = rndE + sByteLen;
        const uint8_t *irreduciblePolyBitsPtr = fieldOrderingBitsPtr + fieldOrderingByteLen;

        // 4. Generate Goppa polynomial g (match reference order: irr poly first)
        if (GenerateIrreduciblePolyFinal(&sk->g, irreduciblePolyBitsPtr, params->t, params->m) != MCELIECE_SUCCESS) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }

        // 5. Generate support set alpha (permutation/field ordering) after g
        // Build permutation pi over 2^m mapping identity to desired support ordering.
        // Since our support alpha[j] was constructed as bitrev(pi[j]) in GenerateFieldOrdering,
        // we can recover pi[j] directly as bitrev(alpha[j]).
        int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
        if (!pi) {
            BSL_SAL_FREE(rndE);
            return MCELIECE_ERROR_MEMORY;
        }

        int16_t *pip;
        pip = pi + params->n;

        if (GenerateFieldOrdering(sk->alpha, pip, fieldOrderingBitsPtr, params->n, params->m) != MCELIECE_SUCCESS) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }

        // Ensure alpha is a support set for g (no roots of g)
        int isSupportSet = 1;
        for (int i = 0; i < params->n; i++) {
            if (PolynomialEval(&sk->g, sk->alpha[i]) == 0) {
                isSupportSet = 0;
                break;
            }
        }
        if (!isSupportSet) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }

        // 6. Generate public key T: build H and reduce to systematic form (no recording)
        int mt = params->m * params->t;
        int n = params->n;
        GFMatrix *tmpH = MatrixCreate(mt, n);
        if (!tmpH) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }
        int buildRet = BuildParityCheckMatrixReferenceStyle(tmpH, &sk->g, sk->alpha, params);
        if (buildRet != 0) {
            MatrixFree(tmpH);
            memcpy_s(sk->delta,MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }
        int sysRet = ReduceToSystematicFormReferenceStyle(tmpH);
        if (sysRet != 0) {
            MatrixFree(tmpH);
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }

        // Extract T from reduced Htmp with reference packing into pk->T storage
        // pk->T is bit-addressable; copy bit-by-bit from right block
        for (int i = 0; i < mt; i++) {
            for (int j = 0; j < (params->n - mt); j++) {
                int bit = MatrixGetBit(tmpH, i, mt + j);
                MatrixSetBit(&pk->matT, i, j, bit);
            }
        }
        // No need to reorder alpha without recording the column permutation; we'll derive support via controlbits
        MatrixFree(tmpH);

        // Compute Benes control bits for support permutation and store in secret key
        // Build a full bijection pi: first map j<N to bitrev(alpha[j]); then fill unused
        for (long long i = 0; i < params->n; i++) {
            pi[i] = -1;
        }

        unsigned char *used = (unsigned char *)BSL_SAL_Malloc(MCELIECE_Q);
        if (!used) {
            BSL_SAL_FREE(pi);
            BSL_SAL_FREE(rndE);
            return MCELIECE_ERROR_MEMORY;
        }
        memset_s(used, MCELIECE_Q, 0, MCELIECE_Q);

        for (int j = 0; j < params->n; j++) {
            uint16_t v = (uint16_t)sk->alpha[j];
            uint16_t r = 0;
            for (int bi = 0; bi < params->m; bi++) {
                r = (uint16_t)((r << 1) | ((v >> bi) & 1U));
            }
            r &= (uint16_t)((1U << params->m) - 1U);
            pi[j] = (int16_t)r;
            used[r] = 1;
        }

        BSL_SAL_FREE(used);

        size_t cbLen = (size_t)((((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8);
        if (sk->controlbits) {
            BSL_SAL_FREE(sk->controlbits);
            sk->controlbits = NULL;
        }
        sk->controlbits = (uint8_t *)BSL_SAL_Malloc(cbLen);
        if (!sk->controlbits) {
            BSL_SAL_FREE(pi);
            BSL_SAL_FREE(rndE);
            return MCELIECE_ERROR_MEMORY;
        }
        memset_s(sk->controlbits, cbLen, 0, cbLen);

        CbitsFromPermNs(sk->controlbits, pi, params->m, MCELIECE_Q);
        BSL_SAL_FREE(pi);
        sk->controlbitsLen = cbLen;
        // All steps successful

        // 7. Save other parts of private key
        // Copy s (byte-length n)
        memcpy_s(sk->s, params->nBytes, sBitsPtr, params->nBytes);

        // Other parts of private key (c, g, alpha) are already in sk structure
        // sk->alpha remains the field-ordering support; controlbits provide permutation
        BSL_SAL_FREE(rndE);
        return MCELIECE_SUCCESS;
    }

    // Reached maximum attempts, generation failed
    BSL_SAL_FREE(rndE);
    return MCELIECE_ERROR_KEYGEN_FAIL;
}

McElieceError SeededKeyGenSemi(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (!delta || !pk || !sk) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    size_t sBitLen = params->n;
    size_t irreduciblePolyBitLen = (size_t)MCELIECE_SIGMA1 * params->t;
    size_t fieldOrderingBitLen = (size_t)MCELIECE_SIGMA2 * MCELIECE_Q;
    size_t deltaPrimeBitLen = (size_t)MCELIECE_L;
    size_t prgOutputBitLen =
        sBitLen + fieldOrderingBitLen + irreduciblePolyBitLen + deltaPrimeBitLen;
    size_t prgOutputByteLen = (prgOutputBitLen + 7) / 8;
    size_t sByteLen = (sBitLen + 7) / 8;
    size_t fieldOrderingByteLen = (fieldOrderingBitLen + 7) / 8;
    size_t deltaPrimeByteLen = (deltaPrimeBitLen + 7) / 8;

    uint8_t *rngE = (uint8_t *)BSL_SAL_Malloc(prgOutputByteLen);
    if (!rngE) {
        return MCELIECE_ERROR_MEMORY;
    }

    memcpy_s(sk->delta, deltaPrimeByteLen, delta, deltaPrimeByteLen);

    int maxAttempts = 50;
    for (int attempt = 0; attempt < maxAttempts; attempt++) {
        uint8_t deltaPrime[MCELIECE_L_BYTES];
        McEliecePrg(sk->delta, rngE, prgOutputByteLen);
        memcpy_s(deltaPrime, deltaPrimeByteLen, rngE + prgOutputByteLen - deltaPrimeByteLen, deltaPrimeByteLen);

        const uint8_t *sBitsPtr = rngE;
        const uint8_t *fieldOrderingBitsPtr = rngE + sByteLen;
        const uint8_t *irreduciblePolyBitsPtr = fieldOrderingBitsPtr + fieldOrderingByteLen;

        if (GenerateIrreduciblePolyFinal(&sk->g, irreduciblePolyBitsPtr, params->t, params->m) != MCELIECE_SUCCESS) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }

        int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
        if (!pi) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }

        int16_t *pip;
        pip = pi + params->n;

        if (GenerateFieldOrdering(sk->alpha, pip, fieldOrderingBitsPtr, params->n, params->m) != MCELIECE_SUCCESS) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }
        int isSupportSet = 1;
        for (int i = 0; i < params->n; i++) {
            if (PolynomialEval(&sk->g, sk->alpha[i]) == 0) {
                isSupportSet = 0;
                break;
            }
        }
        if (!isSupportSet) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }

        GFMatrix *tmpH = MatrixCreate(params->mt, params->n);
        if (!tmpH) {
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }
        if (BuildParityCheckMatrixReferenceStyle(tmpH, &sk->g, sk->alpha, params) != 0) {
            MatrixFree(tmpH);
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }

        uint64_t pivots = 0;
        // track column permutation as we semi-systematize
        int16_t *colPerm = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * (size_t)params->n);
        if (!colPerm) {
            MatrixFree(tmpH);
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            BSL_SAL_FREE(pi);
            continue;
        }
        for (int i = 0; i < params->n; i++) {
            colPerm[i] = (int16_t)i;
        }

        // maintain global permutation pi exactly like reference
        // Initialize pi from support: pi[j] = bitrev(alpha[j]) for j<N, then fill remaining with unused values
        uint8_t *used = (uint8_t *)BSL_SAL_Calloc(MCELIECE_Q, 1);
        if (!used) {
            BSL_SAL_FREE(pi);
            BSL_SAL_FREE(colPerm);
            MatrixFree(tmpH);
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }
        for (int j = 0; j < params->n; j++) {
            uint16_t a = (uint16_t)sk->alpha[j];
            int16_t v = (int16_t)BitrevU16(a, params->m);
            pi[j] = v;
            used[(size_t)v] = 1;
        }

        BSL_SAL_FREE(used);

        // semi-systematic + set pi + return pivots
        int retGauss;
        int paramN = params->n;
        if (paramN == 6688) {
            retGauss = GaussPartialSemiSystematic6688(tmpH->data, tmpH->colsBytes, pi, &pivots, params->mt);
        }
        if (paramN == 6960) {
            retGauss = GaussPartialSemiSystematic6960(tmpH->data, tmpH->colsBytes, pi, &pivots, params->mt);
        }
        if (paramN == 8192) {
            retGauss = GaussPartialSemiSystematic8192(tmpH->data, tmpH->colsBytes, pi, &pivots, params->mt);
        }
        if (retGauss != 0) {
            MatrixFree(tmpH);
            BSL_SAL_FREE(pi);
            memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
            continue;
        }

        // store pivots in secret key
        sk->c = pivots;

        // extract T block
        const int tail = params->mt & 7;
        const int tBytes = (params->n - params->mt + 7) / 8;
        uint8_t *tBlk = pk->matT.data;

        for (int i = 0; i < params->mt; i++) {
            uint8_t *row = tmpH->data + i * tmpH->colsBytes;
            uint8_t *out = tBlk + i * tBytes;

            for (int j = params->mt / 8; j < (params->n - 1) / 8; j++) {
                *out++ = (row[j] >> tail) | (row[j + 1] << (8 - tail));
            }

            // (8-tail) bits
            *out = row[(params->n - 1) / 8] >> tail;
        }

        MatrixFree(tmpH);

        // controlbits: build directly from pi updated during mov_columns
        BSL_SAL_FREE(colPerm);
        size_t cbLen = (size_t)((((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8);
        if (sk->controlbits) {
            BSL_SAL_FREE(sk->controlbits);
            sk->controlbits = NULL;
        }
        sk->controlbits = (uint8_t *)BSL_SAL_Malloc(cbLen);
        if (!sk->controlbits) {
            BSL_SAL_FREE(pi);
            BSL_SAL_FREE(rngE);
            return MCELIECE_ERROR_MEMORY;
        }
        memset_s(sk->controlbits, cbLen, 0, cbLen);

        CbitsFromPermNs(sk->controlbits, pi, params->m, MCELIECE_Q);
        BSL_SAL_FREE(pi);
        sk->controlbitsLen = cbLen;

        memcpy_s(sk->s, params->nBytes, sBitsPtr, params->nBytes);

        BSL_SAL_FREE(rngE);
        return MCELIECE_SUCCESS;
    }

    BSL_SAL_FREE(rngE);
    return MCELIECE_ERROR_KEYGEN_FAIL;
}

McElieceError GenerateFieldOrdering(GFElement *alpha, int16_t *piTail, const uint8_t *randomBits, int n, int m)
{
    // Field ordering generation function
    pair_t *pairs = BSL_SAL_Malloc(MCELIECE_Q * sizeof(pair_t));
    if (!pairs) {
        return MCELIECE_ERROR_MEMORY;
    }

    // random q 32-bit a_i
    for (int i = 0; i < MCELIECE_Q; i++) {
        uint32_t a_i = load4(randomBits + i * 4);  // le 32-bit
        pairs[i].val = a_i;
        pairs[i].pos = i;
    }

    // Check for duplicate values
    pair_t *sortedForCheck = BSL_SAL_Malloc(MCELIECE_Q * sizeof(pair_t));
    if (!sortedForCheck) {
        BSL_SAL_FREE(pairs);
        return MCELIECE_ERROR_MEMORY;
    }
    memcpy_s(sortedForCheck, MCELIECE_Q * sizeof(pair_t), pairs, MCELIECE_Q * sizeof(pair_t));
    qsort(sortedForCheck, MCELIECE_Q, sizeof(pair_t), ComparePairs);

    int hasDuplicates = 0;
    for (int i = 0; i < MCELIECE_Q - 1; i++) {
        if (sortedForCheck[i].val == sortedForCheck[i + 1].val) {
            hasDuplicates = 1;
            break;
        }
    }
    BSL_SAL_FREE(sortedForCheck);

    if (hasDuplicates) {
        BSL_SAL_FREE(pairs);
        return MCELIECE_ERROR_KEYGEN_FAIL;
    }

    qsort(pairs, MCELIECE_Q, sizeof(pair_t), ComparePairs);

    uint16_t *pi = BSL_SAL_Malloc(MCELIECE_Q * sizeof(uint16_t));
    if (!pi) {
        BSL_SAL_FREE(pairs);
        return MCELIECE_ERROR_MEMORY;
    }
    for (int i = 0; i < MCELIECE_Q; i++) {
        pi[i] = pairs[i].pos;
    }
    BSL_SAL_FREE(pairs);

    for (int i = 0; i < MCELIECE_Q; i++) {
        uint16_t v = pi[i] & (MCELIECE_Q - 1U);
        alpha[i] = (GFElement)BitrevU16(v, m);
    }

    // tail of pi
    memcpy_s(piTail, (MCELIECE_Q - n) * sizeof(int16_t), pi + n, (MCELIECE_Q - n) * sizeof(int16_t));

    BSL_SAL_FREE(pi);
    return MCELIECE_SUCCESS;
}

McElieceError GenerateIrreduciblePolyFinal(GFPolynomial *g, const uint8_t *randomBits, int t, int m)
{
    // Ensure GF tables are initialized before any gf_* operations
    GFInitial(m);

    memset_s(g->coeffs, (g->maxDegree + 1) * sizeof(GFElement), 0, (g->maxDegree + 1) * sizeof(GFElement));
    g->degree = -1;

    // Reference-compatible packing: read t little-endian 16-bit values, mask to m bits
    // random_bits is expected to be 2*t bytes long for the poly section
    GFElement *f = BSL_SAL_Malloc(sizeof(GFElement) * t);
    if (!f) {
        return MCELIECE_ERROR_MEMORY;
    }
    for (int i = 0; i < t; i++) {
        uint16_t le = (uint16_t)randomBits[2 * i] | ((uint16_t)randomBits[2 * i + 1] << 8);
        f[i] = (GFElement)(le & ((1U << m) - 1U));
    }
    if (f[t - 1] == 0) {
        f[t - 1] = 1;
    }

    // Compute connection polynomial coefficients via GenpolyOverGF
    GFElement *gl = BSL_SAL_Malloc(sizeof(GFElement) * t);
    if (!gl) {
        BSL_SAL_FREE(f);
        return MCELIECE_ERROR_MEMORY;
    }
    if (GenpolyOverGF(gl, f, t, m) != 0) {
        BSL_SAL_FREE(f);
        BSL_SAL_FREE(gl);
        return MCELIECE_ERROR_KEYGEN_FAIL;
    }

    // Form monic g(x) = x^t + sum_{i=0}^{t-1} gl[i] x^i
    for (int i = 0; i < t; i++) {
        PolynomialSetCoeff(g, i, gl[i]);
    }
    PolynomialSetCoeff(g, t, 1);

    BSL_SAL_FREE(f);
    BSL_SAL_FREE(gl);
    return MCELIECE_SUCCESS;
}

// Private key creation
CMPrivateKey *PrivateKeyCreate(const McelieceParams *params)
{
    CMPrivateKey *sk = BSL_SAL_Calloc(sizeof(CMPrivateKey), sizeof(uint8_t));
    if (!sk) {
        return NULL;
    }

    // U/U_inv and p removed
    sk->controlbits = NULL;
    sk->controlbitsLen = 0;

    // init Goppa poly
    GFPolynomial *g = PolynomialCreate(params->t);
    if (!g) {
        BSL_SAL_FREE(sk);
        return NULL;
    }
    sk->g = *g;
    BSL_SAL_FREE(g);

    sk->alpha = BSL_SAL_Calloc(MCELIECE_Q, sizeof(GFElement));
    if (!sk->alpha) {
        BSL_SAL_FREE(sk->g.coeffs);
        BSL_SAL_FREE(sk);
        return NULL;
    }

    sk->s = BSL_SAL_Calloc(params->nBytes, sizeof(uint8_t));
    if (!sk->s) {
        BSL_SAL_FREE(sk->alpha);
        BSL_SAL_FREE(sk->g.coeffs);
        BSL_SAL_FREE(sk);
        return NULL;
    }

    sk->c = (1ULL << 32) - 1;

    return sk;
}

// Private key deallocation
void PrivateKeyFree(CMPrivateKey *sk)
{
    if (sk) {
        // p, U, U_inv removed
        if (sk->controlbits) {
            BSL_SAL_FREE(sk->controlbits);
        }
        if (sk->g.coeffs) {
            BSL_SAL_FREE(sk->g.coeffs);
        }
        if (sk->alpha) {
            BSL_SAL_FREE(sk->alpha);
        }
        if (sk->s) {
            BSL_SAL_FREE(sk->s);
        }
        BSL_SAL_FREE(sk);
    }
}

// Public key creation
CMPublicKey *PublicKeyCreate(const McelieceParams *params)
{
    CMPublicKey *pk = BSL_SAL_Calloc(sizeof(CMPublicKey), sizeof(uint8_t));
    if (!pk) {
        return NULL;
    }
    GFMatrix *matT = MatrixCreate(params->mt, params->k);
    if (!matT) {
        BSL_SAL_FREE(pk);
        return NULL;
    }

    pk->matT = *matT;
    BSL_SAL_FREE(matT);

    return pk;
}

// Public key deallocation
void PublicKeyFree(CMPublicKey *pk)
{
    if (pk) {
        if (pk->matT.data) {
            BSL_SAL_FREE(pk->matT.data);
        }
        BSL_SAL_FREE(pk);
    }
}

int PrivateKeySerializeSemi(const CMPrivateKey *sk, uint8_t *out, size_t outCapacity, size_t *outLen, const McelieceParams *params)
{
    if (!sk || !out) {
        return -1;
    }
    const size_t irrBytes = params->t << 1;
    const size_t cbLen =
        sk->controlbitsLen > 0 ? sk->controlbitsLen : (size_t)((2 * params->m - 1) * (1u << (params->m - 4)));
    const size_t sLen = params->nBytes;
    if (outCapacity < params->privateKeyBytes) {
        return -1;
    }
    size_t off = 0;
    memcpy_s(out + off, MCELIECE_L_BYTES, sk->delta, MCELIECE_L_BYTES);
    off += 32;
    // pivots value sk->c as 8 bytes little-endian
    uint64_t piv = sk->c;
    out[off + 0] = (uint8_t)(piv & 0xFFu);
    out[off + 1] = (uint8_t)((piv >> 8) & 0xFFu);
    out[off + 2] = (uint8_t)((piv >> 16) & 0xFFu);
    out[off + 3] = (uint8_t)((piv >> 24) & 0xFFu);
    out[off + 4] = (uint8_t)((piv >> 32) & 0xFFu);
    out[off + 5] = (uint8_t)((piv >> 40) & 0xFFu);
    out[off + 6] = (uint8_t)((piv >> 48) & 0xFFu);
    out[off + 7] = (uint8_t)((piv >> 56) & 0xFFu);
    off += 8;
    for (int i = 0; i < params->t; i++) {
        uint16_t c = (uint16_t)(sk->g.coeffs[i] & ((1u << params->m) - 1u));
        out[off + 2 * i + 0] = (uint8_t)(c & 0xFFu);
        out[off + 2 * i + 1] = (uint8_t)((c >> 8) & 0xFFu);
    }
    off += irrBytes;
    if (!sk->controlbits || cbLen == 0) {
        return -1;
    }
    memcpy_s(out + off, cbLen, sk->controlbits, cbLen);
    off += cbLen;
    memcpy_s(out + off, sLen, sk->s, sLen);
    off += sLen;
    if (outLen) {
        *outLen = off;
    }
    return 0;
}
