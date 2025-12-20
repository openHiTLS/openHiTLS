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

#include "mceliece_local.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"

#define MCELIECE_PRG_PREFIX   64
#define MCELIECE_PRG_SEED_LEN 33

typedef struct {
    uint32_t val; // <--- must be uint32_t
    uint16_t pos;
} PairSt;

// reverses the order of the m least significant bits of a 16-bit unsigned integer x.
static uint16_t BitrevU16(const uint16_t x, const int32_t m)
{
    uint16_t r = 0;
    for (int32_t j = 0; j < m; j++) {
        r = (uint16_t)((r << 1) | ((x >> j) & 1U));
    }
    return (uint16_t)(r & ((1U << m) - 1U));
}

static uint32_t Load4(const uint8_t *x)
{
    uint32_t r = 0;
    (void)memcpy_s(&r, 4, x, 4);
    return r;
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
    if (p1->pos < p2->pos) {
        return -1;
    }
    if (p1->pos > p2->pos) {
        return 1;
    }
    return 0;
}

static void GenPiInitial(int16_t *pi, const CMPrivateKey *sk, const McelieceParams *params)
{
    for (int32_t j = 0; j < params->n; j++) {
        uint16_t a = (uint16_t)sk->alpha[j];
        int16_t v = (int16_t)BitrevU16(a, params->m);
        pi[j] = v;
    }
    // Fill the tail of pi array from alpha (params->n to MCELIECE_Q)
    for (int64_t i = params->n; i < MCELIECE_Q; i++) {
        uint16_t a = (uint16_t)sk->alpha[i];
        pi[i] = (int16_t)BitrevU16(a, params->m);
    }
}

static int32_t GenControlBitsFromPi(CMPrivateKey *sk, const int16_t *pi, const McelieceParams *params)
{
    (void)memset_s(sk->controlbits, sk->controlbitsLen, 0, sk->controlbitsLen);
    return CbitsFromPermNs(sk->controlbits, pi, params->m, MCELIECE_Q);
}

static int32_t GenerateFieldOrdering(GFElement *alpha, const uint8_t *randomBits, const int32_t m)
{
    // Field ordering generation function
    PairSt *pairs = BSL_SAL_Malloc(MCELIECE_Q * sizeof(PairSt));
    if (pairs == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // random q 32-bit a_i
    for (int32_t i = 0; i < MCELIECE_Q; i++) {
        uint32_t ai = Load4(randomBits + i * 4); // le 32-bit
        pairs[i].val = ai;
        pairs[i].pos = i;
    }
    // Check for duplicate values
    PairSt *sortedForCheck = BSL_SAL_Malloc(MCELIECE_Q * sizeof(PairSt));
    if (sortedForCheck == NULL) {
        BSL_SAL_FREE(pairs);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(sortedForCheck, MCELIECE_Q * sizeof(PairSt), pairs, MCELIECE_Q * sizeof(PairSt));
    qsort(sortedForCheck, MCELIECE_Q, sizeof(PairSt), ComparePairs);
    int32_t hasDuplicates = 0;
    for (int32_t i = 0; i < MCELIECE_Q_1; i++) {
        if (sortedForCheck[i].val == sortedForCheck[i + 1].val) {
            hasDuplicates = 1;
            break;
        }
    }
    BSL_SAL_FREE(sortedForCheck);

    if (hasDuplicates != 0) {
        BSL_SAL_FREE(pairs);
        return CRYPT_MCELIECE_KEYGEN_FAIL;
    }
    qsort(pairs, MCELIECE_Q, sizeof(PairSt), ComparePairs);
    for (int32_t i = 0; i < MCELIECE_Q; i++) {
        uint16_t v = pairs[i].pos & (uint16_t)MCELIECE_Q_1;
        alpha[i] = (GFElement)BitrevU16(v, m);
    }
    BSL_SAL_FREE(pairs);
    return CRYPT_SUCCESS;
}

static int32_t GenerateIrreduciblePolyFinal(GFPolynomial *g, const uint8_t *randomBits, const int32_t t,
                                            const int32_t m)
{
    (void)memset_s(g->coeffs, (g->maxDegree + 1) * sizeof(GFElement), 0, (g->maxDegree + 1) * sizeof(GFElement));
    g->degree = -1;
    // Reference-compatible packing: read t little-endian 16-bit values, mask to m bits
    // random_bits is expected to be 2*t bytes long for the poly section
    GFElement *f = BSL_SAL_Malloc(sizeof(GFElement) * t);
    if (f == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    for (int32_t i = 0; i < t; i++) {
        uint16_t le = (uint16_t)randomBits[2 * i] | ((uint16_t)randomBits[2 * i + 1] << 8);
        f[i] = (GFElement)(le & ((1U << m) - 1U));
    }
    if (f[t - 1] == 0) {
        f[t - 1] = 1;
    }

    // Compute connection polynomial coefficients via GenPolyOverGF
    GFElement *gl = BSL_SAL_Malloc(sizeof(GFElement) * t);
    if (gl == NULL) {
        BSL_SAL_FREE(f);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = GenPolyOverGF(gl, f, t, m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(f);
        BSL_SAL_FREE(gl);
        return ret;
    }

    // Form monic g(x) = x^t + sum_{i=0}^{t-1} gl[i] x^i
    for (int32_t i = 0; i < t; i++) {
        PolynomialSetCoeff(g, i, gl[i]);
    }
    PolynomialSetCoeff(g, t, 1);
    BSL_SAL_FREE(f);
    BSL_SAL_FREE(gl);
    return CRYPT_SUCCESS;
}

static int32_t GenGoppaAndValidate(const uint8_t *irreduciblePolyBitsPtr, const uint8_t *fieldOrderingBitsPtr,
                                   CMPrivateKey *sk, const McelieceParams *params)
{
    int32_t ret = GenerateIrreduciblePolyFinal(&sk->g, irreduciblePolyBitsPtr, params->t, params->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = GenerateFieldOrdering(sk->alpha, fieldOrderingBitsPtr, params->m);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    int32_t isSupportSet = 1;
    for (int32_t i = 0; i < params->n; i++) {
        if (PolynomialEval(&sk->g, sk->alpha[i]) == 0) {
            isSupportSet = 0;
            break;
        }
    }
    if (isSupportSet == 0) {
        return CRYPT_MCELIECE_KEYGEN_FAIL;
    }
    return CRYPT_SUCCESS;
}

static void ExtractTFromSystematicMatrix(const GFMatrix *sysH, uint32_t mt, uint32_t n, GFMatrix *dstT)
{
    for (uint32_t i = 0; i < mt; i++) {
        for (uint32_t j = 0; j < (n - mt); j++) {
            int32_t bit = MatrixGetBit(sysH, i, mt + j);
            MatrixSetBit(dstT, i, j, bit);
        }
    }
}

static int32_t GenSystematicMatrix(CMPrivateKey *sk, CMPublicKey *pk, const McelieceParams *params)
{
    GFMatrix *tmpH = MatrixCreate(params->mt, params->n);
    if (tmpH == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BuildParityCheckMatrixReferenceStyle(tmpH, &sk->g, sk->alpha, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        MatrixFree(tmpH);
        return ret;
    }
    ret = ReduceToSystematicFormReferenceStyle(tmpH);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        MatrixFree(tmpH);
        return ret;
    }

    ExtractTFromSystematicMatrix(tmpH, params->mt, params->n, &pk->matT);
    MatrixFree(tmpH);
    return CRYPT_SUCCESS;
}

static int32_t GenSystematicMatrixSemi(CMPublicKey *pk, CMPrivateKey *sk, int16_t *pi, const McelieceParams *params)
{
    GFMatrix *tmpH = MatrixCreate(params->mt, params->n);
    if (tmpH == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = BuildParityCheckMatrixReferenceStyle(tmpH, &sk->g, sk->alpha, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        MatrixFree(tmpH);
        return ret;
    }

    uint64_t pivots = 0;
    int32_t retGauss = GaussPartialSemiSystematic(tmpH->data, tmpH->colsBytes, pi, &pivots, params->mt, params->n);
    if (retGauss != CRYPT_SUCCESS) {
        MatrixFree(tmpH);
        return CRYPT_MCELIECE_KEYGEN_FAIL;
    }
    sk->c = pivots;

    const int32_t tail = params->mt & 7;
    const int32_t tBytes = (params->n - params->mt + 7) / 8;
    uint8_t *tBlk = pk->matT.data;

    for (int32_t i = 0; i < params->mt; i++) {
        uint8_t *row = tmpH->data + i * tmpH->colsBytes;
        uint8_t *out = tBlk + i * tBytes;
        for (int32_t j = params->mt / 8; j < (params->n - 1) / 8; j++) {
            *out++ = (row[j] >> tail) | (row[j + 1] << (8 - tail));
        }
        *out = row[(params->n - 1) / 8] >> tail;
    }
    MatrixFree(tmpH);
    return CRYPT_SUCCESS;
}

static int32_t SystematicLoop(const uint8_t *sBitsPtr, const uint8_t *fieldOrderingBitsPtr,
                              const uint8_t *irreduciblePolyBitsPtr, CMPublicKey *pk, CMPrivateKey *sk,
                              const McelieceParams *params, bool isSemi)
{
    int32_t ret = GenGoppaAndValidate(irreduciblePolyBitsPtr, fieldOrderingBitsPtr, sk, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    int16_t *pi = (int16_t *)BSL_SAL_Malloc(sizeof(int16_t) * MCELIECE_Q);
    if (pi == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    GenPiInitial(pi, sk, params);

    // Branch based on semi-systematic or systematic
    if (isSemi) {
        ret = GenSystematicMatrixSemi(pk, sk, pi, params);
    } else {
        ret = GenSystematicMatrix(sk, pk, params);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(pi);
        return ret;
    }

    ret = GenControlBitsFromPi(sk, pi, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(pi);
        return ret;
    }

    (void)memcpy_s(sk->s, params->nBytes, sBitsPtr, params->nBytes);
    BSL_SAL_FREE(pi);
    return CRYPT_SUCCESS;
}
static int32_t McEliecePrg(const uint8_t *seed, uint8_t *output, const size_t outputLen)
{
    /* tempSeed[0] is the length byte that Classic McEliece hard-codes to 64 (0x40) so that the later
     * Expand-And-Split step produces the correct number of field elements for the public key generation;
     * any other value would break the deterministic key schedule */
    // Total buffer length for key-generation seed: 1-byte length prefix + 32-byte random
    uint8_t tempSeed[MCELIECE_PRG_SEED_LEN] = {0};
    tempSeed[0] = MCELIECE_PRG_PREFIX; // the value of first element of tempSeed must be 64
    (void)memcpy_s(tempSeed + 1, MCELIECE_L_BYTES, seed, MCELIECE_L_BYTES);
    int32_t ret = McElieceShake256(output, outputLen, tempSeed, MCELIECE_PRG_SEED_LEN);
    (void)memset_s(tempSeed, MCELIECE_PRG_SEED_LEN, 0, MCELIECE_PRG_SEED_LEN);
    return ret;
}

int32_t SeededKeyGenInternal(const uint8_t *delta, CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params,
                             bool isSemi)
{
    size_t sBitLen = params->n;
    size_t irreduciblePolyBitLen = (size_t)MCELIECE_SIGMA1 * params->t;
    size_t fieldOrderingBitLen = (size_t)MCELIECE_SIGMA2 * MCELIECE_Q;
    size_t deltaPrimeBitLen = MCELIECE_L;

    size_t prgOutputBitLen = sBitLen + fieldOrderingBitLen + irreduciblePolyBitLen + deltaPrimeBitLen;
    size_t prgOutputByteLen = (prgOutputBitLen + 7) / 8;
    size_t sByteLen = (sBitLen + 7) / 8;
    size_t fieldOrderingByteLen = (fieldOrderingBitLen + 7) / 8;
    size_t deltaPrimeByteLen = (deltaPrimeBitLen + 7) / 8;

    uint8_t *rndE = (uint8_t *)BSL_SAL_Malloc(prgOutputByteLen);
    if (rndE == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    (void)memcpy_s(sk->delta, deltaPrimeByteLen, delta, deltaPrimeByteLen);
    int32_t maxAttempts = 50;

    for (int32_t attempt = 0; attempt < maxAttempts; attempt++) {
        uint8_t deltaPrime[MCELIECE_L_BYTES];
        int32_t ret = McEliecePrg(sk->delta, rndE, prgOutputByteLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            BSL_SAL_FREE(rndE);
            return ret;
        }
        (void)memcpy_s(deltaPrime, deltaPrimeByteLen, rndE + prgOutputByteLen - deltaPrimeByteLen, deltaPrimeByteLen);

        const uint8_t *sBitsPtr = rndE;
        const uint8_t *fieldOrderingBitsPtr = rndE + sByteLen;
        const uint8_t *irreducibleBitsPtr = fieldOrderingBitsPtr + fieldOrderingByteLen;

        ret = SystematicLoop(sBitsPtr, fieldOrderingBitsPtr, irreducibleBitsPtr, pk, sk, params, isSemi);
        if (ret == CRYPT_SUCCESS) {
            BSL_SAL_FREE(rndE);
            return CRYPT_SUCCESS;
        }
        (void)memcpy_s(sk->delta, MCELIECE_L_BYTES, deltaPrime, MCELIECE_L_BYTES);
    }

    BSL_SAL_FREE(rndE);
    return CRYPT_MCELIECE_KEYGEN_FAIL;
}
#endif
