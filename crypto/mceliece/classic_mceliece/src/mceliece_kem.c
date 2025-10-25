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

#include "mceliece_kem.h"
#include "crypt_eal_rand.h"
#include "securec.h"

static inline void GenDeltaFromSeed(uint8_t *delta)
{
    uint8_t entropyInput[MCELIECE_SEED_BYTES];
    uint8_t kgSeed[33];
    McElieceRandombytesInit((unsigned char *)entropyInput, NULL, 256);

    kgSeed[0] = 64;
    McElieceRandombytes(kgSeed + 1, MCELIECE_L_BYTES);
    memcpy_s(delta, MCELIECE_L_BYTES, kgSeed + 1, MCELIECE_L_BYTES);
}

// KeyGen
McElieceError McElieceKeygen(CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (!pk || !sk) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    uint8_t delta[MCELIECE_L_BYTES];
    GenDeltaFromSeed(delta);
    return SeededKeyGen(delta, pk, sk, params);
}

McElieceError McElieceKeygenSemi(CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params)
{
    if (!pk || !sk) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    uint8_t delta[MCELIECE_L_BYTES];
    GenDeltaFromSeed(delta);
    return SeededKeyGenSemi(delta, pk, sk, params);
}

// Encap algorithm (non-pc parameter sets)
McElieceError McElieceEncaps(
    uint8_t *ciphertext, const CMPublicKey *pk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (!pk || !ciphertext || !sessionKey) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    int maxAttempts = 10;
    for (int attempt = 0; attempt < maxAttempts; attempt++) {
        // Step 1: Generate fixed weight vector e
        uint8_t e[params->nBytes];
        memset_s(e, params->nBytes, 0, params->nBytes);
        McElieceError ret;
        ret = FixedWeightVector(e, params->n, params->t, params);
        if (ret != MCELIECE_SUCCESS) {
            // Retry
            continue;
        }

        // Step 2: Calculate C = Encode(e, T)
        memset_s(ciphertext, params->mtBytes, 0, params->mtBytes);
        EncodeVector(e, &pk->matT, ciphertext, params);

        // Step 3: Calculate K = Hash(1, e, C) exactly like reference (no extra prefix byte)
        // Construct hash input: prefix 1 + e + C
        size_t hashInputLen = 1 + params->nBytes + params->cipherBytes;
        uint8_t *hashInput = BSL_SAL_Malloc(hashInputLen);
        if (!hashInput) {
            return MCELIECE_ERROR_MEMORY;
        }

        hashInput[0] = 1;  // prefix
        memcpy_s(hashInput + 1, params->nBytes, e, params->nBytes);
        memcpy_s(hashInput + 1 + params->nBytes, params->cipherBytes, ciphertext, params->cipherBytes);

        // Reference hashes the raw bytes (1||e||C) with SHAKE256 to 32 bytes
        // shake256(hashInput, hashInputLen, sessionKey, MCELIECE_L_BYTES);
        CMShake256(sessionKey, MCELIECE_L_BYTES, hashInput, hashInputLen);

        BSL_SAL_FREE(hashInput);
        BSL_SAL_CleanseData(e, params->nBytes);
        return MCELIECE_SUCCESS;
    }

    return MCELIECE_ERROR_KEYGEN_FAIL;  // Reached maximum attempts
}

McElieceError McElieceEncapsPC(
    uint8_t *ciphertext, const CMPublicKey *pk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (!pk || !ciphertext || !sessionKey) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    uint8_t *c0 = ciphertext;                        // front
    uint8_t *c1 = ciphertext + params->cipherBytes;  // back

    int maxAttempts = 10;
    for (int attempt = 0; attempt < maxAttempts; attempt++) {
        // Step 1: Generate fixed weight vector e
        uint8_t e[params->nBytes];
        memset_s(e, params->nBytes, 0, params->nBytes);
        McElieceError ret;
        ret = FixedWeightVector(e, params->n, params->t, params);
        if (ret != MCELIECE_SUCCESS) {
            // Retry
            continue;
        }

        // Step 2: Calculate C0 = Encode(e, T)
        memset_s(c0, params->mtBytes, 0, params->mtBytes);
        EncodeVector(e, &pk->matT, c0, params);

        // Step 3:
        // C1 = H(2, e)
        size_t hashC1Len = 1 + MCELIECE_L_BYTES;
        uint8_t *hashC1 = BSL_SAL_Malloc(hashC1Len);
        if (!hashC1) {
            return MCELIECE_ERROR_MEMORY;
        }
        hashC1[0] = 2;
        memcpy_s(hashC1 + 1, MCELIECE_L_BYTES, e, MCELIECE_L_BYTES);
        // shake256(hashC1, hashC1Len, c1, MCELIECE_L_BYTES);
        CMShake256(c1, MCELIECE_L_BYTES, hashC1, hashC1Len);

        // Step 4: Calculate K = Hash(1, e, C=(C0||C1)) exactly like reference (no extra prefix byte)
        // Construct hash input: prefix 1 + e + C
        size_t hashInputLen = 1 + params->nBytes + params->cipherBytes;
        uint8_t *hashInput = BSL_SAL_Malloc(hashInputLen);
        if (!hashInput) {
            BSL_SAL_FREE(hashC1);
            return MCELIECE_ERROR_MEMORY;
        }

        hashInput[0] = 1;  // prefix
        memcpy_s(hashInput + 1, params->nBytes, e, params->nBytes);
        memcpy_s(hashInput + 1 + params->nBytes, params->cipherBytes, c0, params->cipherBytes);

        // Reference hashes the raw bytes (1||e||C) with SHAKE256 to 32 bytes
        // shake256(hashInput, hashInputLen, sessionKey, MCELIECE_L_BYTES);
        CMShake256(sessionKey, MCELIECE_L_BYTES, hashInput, hashInputLen);

        BSL_SAL_FREE(hashC1);
        BSL_SAL_FREE(hashInput);
        BSL_SAL_CleanseData(e, params->nBytes);
        return MCELIECE_SUCCESS;
    }

    return MCELIECE_ERROR_KEYGEN_FAIL;  // Reached maximum attempts
}

// Decap algorithm (non-pc parameter sets)
McElieceError McElieceDecaps(
    const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (!ciphertext || !sk || !sessionKey) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    // Step 1: Set b = 1
    uint8_t b = 1;

    // Step 3: Try to decode
    uint8_t *e = BSL_SAL_Malloc(params->nBytes);
    if (!e) {
        return MCELIECE_ERROR_MEMORY;
    }
    // Build v = (C, 0, ..., 0) and decode directly using reordered support sk->alpha
    uint8_t *v = BSL_SAL_Calloc(params->nBytes, 1);
    if (!v) {
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_MEMORY;
    }
    for (int i = 0; i < params->mt; i++) {
        int bit = VectorGetBit(ciphertext, i);
        VectorSetBit(v, i, bit);
    }

    int decodeSuccess;
    McElieceError ret;
    // Force Benes: require controlbits and correct length; do not fallback
    size_t expectedCbLen = (size_t)((((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8);
    if (!sk->controlbits || sk->controlbitsLen != expectedCbLen) {
        BSL_SAL_FREE(v);
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    // Derive support from controlbits (reference-style Benes), then decode
    GFElement *gfL = (GFElement *)BSL_SAL_Malloc(sizeof(GFElement) * params->n);
    if (!gfL) {
        BSL_SAL_FREE(v);
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_MEMORY;
    }
    SupportFromCbits(gfL, sk->controlbits, params->m, params->n);

    ret = DecodeGoppa(v, &sk->g, gfL, e, &decodeSuccess, params);
    BSL_SAL_FREE(gfL);
    BSL_SAL_FREE(v);

    if (ret != MCELIECE_SUCCESS) {
        BSL_SAL_FREE(e);
        return ret;
    }

    if (!decodeSuccess) {
        // Decoding failed, use backup vector s
        memcpy_s(e, params->nBytes, sk->s, params->nBytes);
        b = 0;
    }

    // Step 4: Calculate K = Hash(b, e, C) exactly like reference (no extra prefix byte)
    size_t hashInputLen = 1 + params->nBytes + params->mtBytes;
    uint8_t *hashInput = BSL_SAL_Malloc(hashInputLen);
    if (!hashInput) {
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_MEMORY;
    }

    hashInput[0] = b;  // prefix
    memcpy_s(hashInput + 1, params->nBytes, e, params->nBytes);
    memcpy_s(hashInput + 1 + params->nBytes, params->mtBytes, ciphertext, params->mtBytes);

    // Reference hashes the raw bytes (b||e||C) with SHAKE256 to 32 bytes
    // shake256(hashInput, hashInputLen, sessionKey, MCELIECE_L_BYTES);
    CMShake256(sessionKey, MCELIECE_L_BYTES, hashInput, hashInputLen);

    BSL_SAL_FREE(e);
    BSL_SAL_FREE(hashInput);
    return MCELIECE_SUCCESS;
}

McElieceError McElieceDecapPC(
    const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey, const McelieceParams *params)
{
    if (!ciphertext || !sk || !sessionKey) {
        return MCELIECE_ERROR_INVALID_PARAM;
    }

    const uint8_t *c0 = ciphertext;                        // front
    const uint8_t *c1 = ciphertext + params->cipherBytes;  // back

    // Step 1: Set b = 1
    uint8_t b = 1;

    // Step 3: Try to decode
    uint8_t *e = BSL_SAL_Malloc(params->nBytes);
    if (!e) {
        return MCELIECE_ERROR_MEMORY;
    }
    // Build v = (C, 0, ..., 0) and decode directly using reordered support sk->alpha
    uint8_t *v = BSL_SAL_Calloc(params->nBytes, 1);
    if (!v) {
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_MEMORY;
    }
    for (int i = 0; i < params->mt; i++) {
        int bit = VectorGetBit(c0, i);
        VectorSetBit(v, i, bit);
    }

    int decodeSuccess;
    McElieceError ret;
    // Force Benes: require controlbits and correct length; do not fallback
    size_t expectedCbLen = (size_t)((((2 * params->m - 1) * MCELIECE_Q / 2) + 7) / 8);
    if (!sk->controlbits || sk->controlbitsLen != expectedCbLen) {
        BSL_SAL_FREE(v);
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_INVALID_PARAM;
    }
    // Derive support from controlbits (reference-style Benes), then decode
    GFElement *gfL = (GFElement *)BSL_SAL_Malloc(sizeof(GFElement) * params->n);
    if (!gfL) {
        BSL_SAL_FREE(v);
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_MEMORY;
    }
    SupportFromCbits(gfL, sk->controlbits, params->m, params->n);

    ret = DecodeGoppa(v, &sk->g, gfL, e, &decodeSuccess, params);
    BSL_SAL_FREE(gfL);
    BSL_SAL_FREE(v);

    if (ret != MCELIECE_SUCCESS) {
        BSL_SAL_FREE(e);
        return ret;
    }

    if (!decodeSuccess) {
        // Decoding failed, use backup vector s
        memcpy_s(e, params->nBytes, sk->s, params->nBytes);
        b = 0;
    }

    // Compute C1'= H(2, e)
    uint8_t c1Prime[MCELIECE_L_BYTES];
    size_t hashC1Len = 1 + MCELIECE_L_BYTES;
    uint8_t *hashC1 = BSL_SAL_Malloc(hashC1Len);
    if (!hashC1) {
        BSL_SAL_FREE(e);
        return MCELIECE_ERROR_MEMORY;
    }
    hashC1[0] = 2;
    memcpy_s(hashC1 + 1, MCELIECE_L_BYTES, e, MCELIECE_L_BYTES);
    // shake256(hashC1, hashC1Len, c1Prime, MCELIECE_L_BYTES);
    CMShake256(c1Prime, MCELIECE_L_BYTES, hashC1, hashC1Len);

    if (memcmp(c1Prime, c1, MCELIECE_L_BYTES) != 0) {
        memcpy_s(e, params->nBytes, sk->s, params->nBytes);
        b = 0;
    }

    // Step 4: Calculate K = Hash(b, e, C=(C0||C1)) exactly like reference (no extra prefix byte)
    size_t hashInputLen = 1 + params->nBytes + params->cipherBytes;
    uint8_t *hashInput = BSL_SAL_Malloc(hashInputLen);
    if (!hashInput) {
        BSL_SAL_FREE(e);
        BSL_SAL_FREE(hashC1);
        return MCELIECE_ERROR_MEMORY;
    }

    hashInput[0] = b;  // prefix
    memcpy_s(hashInput + 1, params->nBytes, e, params->nBytes);
    memcpy_s(hashInput + 1 + params->nBytes, params->cipherBytes, ciphertext, params->cipherBytes);

    // Reference hashes the raw bytes (b||e||C) with SHAKE256 to 32 bytes
    // shake256(hashInput, hashInputLen, sessionKey, MCELIECE_L_BYTES);
    CMShake256(sessionKey, MCELIECE_L_BYTES, hashInput, hashInputLen);

    BSL_SAL_FREE(e);
    BSL_SAL_FREE(hashC1);
    BSL_SAL_FREE(hashInput);
    return MCELIECE_SUCCESS;
}
