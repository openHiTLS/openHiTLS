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

/* BEGIN_HEADER */
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_frodokem.h"
#include "crypt_drbg.h"
#include "stub_utils.h"
/* END_HEADER */
static uint8_t gRandNumber = 0;
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
static CRYPT_EAL_PkeyCtx *NewFrodoKemCtx(void);
static int32_t TestRand(uint8_t *randBuf, uint32_t len);
static int32_t TestRandEx(void *libctx, uint8_t *randBuf, uint32_t len);
/* @
* @test  SDV_CRYPTO_FRODOKEM_CTRL_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyCtrl test
* @precon  nan
* @brief  1. creat context
* 2.invoke CRYPT_EAL_PkeyCtrl to transfer various exception parameters.
* 3.call CRYPT_EAL_PkeyCtrl repeatedly to set the key information.
* @expect  1.success 2.returned as expected 3.cannot be set repeatedly.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_CTRL_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    int32_t val = (int32_t)bits;
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID + 100, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_FRODOKEM_CTRL_NOT_SUPPORT);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, NULL, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val) - 1);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_FRODOKEM_CTRL_INIT_REPEATED);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

static uint32_t gFrodoRandCallCount = 0;
static uint32_t gFrodoRandLastLen = 0;
static uint32_t gFrodoRandFailAt = UINT32_MAX;
static uint8_t gFrodoRandByte = 0xA5; // 0xA5 is a fixed nonzero byte that makes injected RNG output observable.

static int32_t FrodoQualityRand(uint8_t *randBuf, uint32_t len)
{
    if (gFrodoRandCallCount == gFrodoRandFailAt) {
        gFrodoRandCallCount++;
        gFrodoRandLastLen = len;
        return -1;
    }
    gFrodoRandCallCount++;
    gFrodoRandLastLen = len;
    memset(randBuf, gFrodoRandByte, len);
    return 0;
}

static int32_t FrodoQualityRandEx(void *libCtx, uint8_t *randBuf, uint32_t len)
{
    (void)libCtx;
    return FrodoQualityRand(randBuf, len);
}

static void FrodoQualityRandReset(uint32_t failAt, uint8_t randByte)
{
    gFrodoRandCallCount = 0;
    gFrodoRandLastLen = 0;
    gFrodoRandFailAt = failAt;
    gFrodoRandByte = randByte;
}

/* The helper returns -1 for any key export or length mismatch. */
static int32_t FrodoQualityGetKeys(CRYPT_EAL_PkeyCtx *ctx, uint8_t *pub, uint32_t pubLen,
    uint8_t *prv, uint32_t prvLen)
{
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};

    pubKey.id = CRYPT_PKEY_FRODOKEM;
    pubKey.key.kemEk.data = pub;
    pubKey.key.kemEk.len = pubLen;
    prvKey.id = CRYPT_PKEY_FRODOKEM;
    prvKey.key.kemDk.data = prv;
    prvKey.key.kemDk.len = prvLen;
    if (CRYPT_EAL_PkeyGetPub(ctx, &pubKey) != CRYPT_SUCCESS) {
        return -1;
    }
    if (CRYPT_EAL_PkeyGetPrv(ctx, &prvKey) != CRYPT_SUCCESS) {
        return -1;
    }
    return (pubKey.key.kemEk.len == pubLen && prvKey.key.kemDk.len == prvLen) ?
        CRYPT_SUCCESS : -1;
}

/* The helper returns -1 when implicit-rejection outputs are inconsistent. */
static int32_t FrodoQualityCheckImplicitReject(CRYPT_EAL_PkeyCtx *ctx, const uint8_t *ct, uint32_t ctLen,
    uint8_t *ss1, uint8_t *ss2, uint32_t ssLen, const uint8_t *validSs)
{
    uint32_t outLen1 = ssLen;
    uint32_t outLen2 = ssLen;
    int32_t ret = CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ss1, &outLen1);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ss2, &outLen2);
    if (ret != CRYPT_SUCCESS || outLen1 != ssLen || outLen2 != ssLen) {
        return -1;
    }
    if (memcmp(ss1, ss2, ssLen) != 0 || memcmp(ss1, validSs, ssLen) == 0) {
        return -1;
    }
    return CRYPT_SUCCESS;
}

/* @
* @test  SDV_CRYPTO_FRODOKEM_ENCAPS_BUFFER_TC001
* @spec  -
* @title  Encapsulation output boundary and transaction test
* @precon  nan
* @brief  Test L-1/L/L+1 ciphertext and K-1/K/K+1 shared-secret capacities.
* @expect  Short buffers fail without output or length changes; sufficient buffers succeed.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_ENCAPS_BUFFER_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *cipher = NULL;
    uint8_t *shared = NULL;
    uint8_t *cipherBefore = NULL;
    uint8_t *sharedBefore = NULL;
    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    uint32_t ctCapacity = 0;
    uint32_t ssCapacity = 0;
    uint32_t ctCaps[3] = {0};
    uint32_t ssCaps[3] = {0};
    uint32_t ctExpected = 0;
    uint32_t ssExpected = 0;
    int32_t ret = 0;

    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctExpected, sizeof(ctExpected)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssExpected, sizeof(ssExpected)), CRYPT_SUCCESS);
    ctCapacity = ctExpected + 1;
    ssCapacity = ssExpected + 1;
    cipher = BSL_SAL_Malloc(ctCapacity);
    shared = BSL_SAL_Malloc(ssCapacity);
    cipherBefore = BSL_SAL_Malloc(ctCapacity);
    sharedBefore = BSL_SAL_Malloc(ssCapacity);
    ASSERT_TRUE(cipher != NULL && shared != NULL && cipherBefore != NULL && sharedBefore != NULL);
    ctCaps[0] = ctExpected - 1;
    ctCaps[1] = ctExpected;
    ctCaps[2] = ctExpected + 1;
    ssCaps[0] = ssExpected - 1;
    ssCaps[1] = ssExpected;
    ssCaps[2] = ssExpected + 1;
    /* Three capacities cover one byte below, exactly at and one byte above each limit. */
    for (uint32_t i = 0; i < 3; i++) {
        for (uint32_t j = 0; j < 3; j++) {
            /* 0xA5 is the caller-buffer sentinel checked after each boundary attempt. */
            memset(cipher, 0xA5, ctCapacity);
            memset(shared, 0xA5, ssCapacity);
            memcpy(cipherBefore, cipher, ctCapacity);
            memcpy(sharedBefore, shared, ssCapacity);
            ctLen = ctCaps[i];
            ssLen = ssCaps[j];
            ret = CRYPT_EAL_PkeyEncaps(ctx, cipher, &ctLen, shared, &ssLen);
            if (ctCaps[i] < ctExpected || ssCaps[j] < ssExpected) {
                ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
                ASSERT_TRUE(ctLen == ctCaps[i] && ssLen == ssCaps[j]);
                ASSERT_EQ(memcmp(cipher, cipherBefore, ctCapacity), 0);
                ASSERT_EQ(memcmp(shared, sharedBefore, ssCapacity), 0);
            } else {
                ASSERT_EQ(ret, CRYPT_SUCCESS);
                ASSERT_EQ(ctLen, ctExpected);
                ASSERT_EQ(ssLen, ssExpected);
                ASSERT_TRUE(cipher[ctExpected] == 0xA5 && shared[ssExpected] == 0xA5);
            }
        }
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(shared);
    BSL_SAL_FREE(cipherBefore);
    BSL_SAL_FREE(sharedBefore);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DECAPS_LENGTH_TC001
* @spec  -
* @title  Decapsulation ciphertext length boundary test
* @precon  nan
* @brief  Test zero, short, exact, long and maximum ciphertext lengths.
* @expect  Only the exact parameter ciphertext length is accepted.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_DECAPS_LENGTH_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *cipher = NULL;
    uint8_t *shared = NULL;
    uint8_t *sharedBefore = NULL;
    uint32_t ctExpected = 0;
    uint32_t ssExpected = 0;
    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    uint32_t inputLens[6] = {0}; // 6 ciphertext lengths: zero, one, short, exact, long and UINT32_MAX.
    int32_t ret = 0;

    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctExpected, sizeof(ctExpected)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssExpected, sizeof(ssExpected)), CRYPT_SUCCESS);
    cipher = BSL_SAL_Malloc(ctExpected + 1);
    shared = BSL_SAL_Malloc(ssExpected + 1);
    sharedBefore = BSL_SAL_Malloc(ssExpected + 1);
    ASSERT_TRUE(cipher != NULL && shared != NULL && sharedBefore != NULL);
    ctLen = ctExpected;
    ssLen = ssExpected;
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &ctLen, shared, &ssLen), CRYPT_SUCCESS);
    inputLens[0] = 0;
    inputLens[1] = 1;
    inputLens[2] = ctExpected - 1;
    inputLens[3] = ctExpected;
    inputLens[4] = ctExpected + 1;
    inputLens[5] = UINT32_MAX;
    /* Check every length boundary independently. */
    for (uint32_t i = 0; i < 6; i++) {
        memset(shared, 0xA5, ssExpected + 1);
        memcpy(sharedBefore, shared, ssExpected + 1);
        ssLen = ssExpected;
        ret = CRYPT_EAL_PkeyDecaps(ctx, cipher, inputLens[i], shared, &ssLen);
        if (inputLens[i] == ctExpected) {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
            ASSERT_EQ(ssLen, ssExpected);
        } else {
            ASSERT_EQ(ret, CRYPT_FRODOKEM_INVALID_CIPHER);
            ASSERT_EQ(ssLen, ssExpected);
            ASSERT_EQ(memcmp(shared, sharedBefore, ssExpected + 1), 0);
        }
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(shared);
    BSL_SAL_FREE(sharedBefore);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_IMPLICIT_REJECT_TC001
* @spec  -
* @title  Structured equal-length ciphertext implicit rejection test
* @precon  nan
* @brief  Test all-zero, all-FF, leading-zero and trailing-zero ciphertexts.
* @expect  Fallback secrets are deterministic and differ from the valid secret.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_IMPLICIT_REJECT_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *cipher = NULL;
    uint8_t *mutated = NULL;
    uint8_t *validSs = NULL;
    uint8_t *fallback1 = NULL;
    uint8_t *fallback2 = NULL;
    uint32_t ctLen = 0;
    uint32_t ssLen = 0;

    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(ssLen)), CRYPT_SUCCESS);
    cipher = BSL_SAL_Malloc(ctLen);
    mutated = BSL_SAL_Malloc(ctLen);
    validSs = BSL_SAL_Malloc(ssLen);
    fallback1 = BSL_SAL_Malloc(ssLen);
    fallback2 = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(cipher != NULL && mutated != NULL && validSs != NULL && fallback1 != NULL && fallback2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &ctLen, validSs, &ssLen), CRYPT_SUCCESS);
    /* 4 equal-length mutations: all-zero, all-FF, leading-zero and trailing-zero. */
    for (uint32_t i = 0; i < 4; i++) {
        if (i == 0) {
            memset(mutated, 0x00, ctLen);
        } else if (i == 1) {
            memset(mutated, 0xFF, ctLen);
        } else {
            memcpy(mutated, cipher, ctLen);
            /* Keep the requested zero prefix/suffix while guaranteeing a real mutation. */
            if (i == 2) {
                mutated[0] = 0;
                if (memcmp(mutated, cipher, ctLen) == 0) {
                    /* Flip the adjacent byte if the prefix is already zero. */
                    mutated[1] = (uint8_t)(cipher[1] ^ 0xFF);
                }
            } else {
                mutated[ctLen - 1] = 0;
                if (memcmp(mutated, cipher, ctLen) == 0) {
                    /* Flip the adjacent byte if the suffix is already zero. */
                    mutated[ctLen - 2] = (uint8_t)(cipher[ctLen - 2] ^ 0xFF);
                }
            }
        }
        ASSERT_EQ(FrodoQualityCheckImplicitReject(ctx, mutated, ctLen, fallback1, fallback2, ssLen, validSs), 0);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(mutated);
    BSL_SAL_FREE(validSs);
    BSL_SAL_FREE(fallback1);
    BSL_SAL_FREE(fallback2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

static uint32_t FrodoQualitySeedSeLen(int algId, uint32_t ssLen)
{
    switch (algId) {
        case CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_640_AES:
        case CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_976_AES:
        case CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_1344_AES:
            /* The standard Frodo parameter families request two shared-secret lengths. */
            return ssLen * 2;
        default:
            return ssLen;
    }
}

/* @
* @test  SDV_CRYPTO_FRODOKEM_RNG_MATRIX_TC001
* @spec  -
* @title  FrodoKEM random request and failure test
* @precon  nan
* @brief  Check key generation and encapsulation random request lengths and failures.
* @expect  Request lengths follow the parameter variant and failures produce no usable output.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_RNG_MATRIX_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *cipher = NULL;
    uint8_t *shared = NULL;
    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    uint32_t ctExpected = 0;
    uint32_t ssExpected = 0;
    uint32_t seedSeLen = 0;
    uint32_t keyRandLen = 0;
    uint32_t encapsRandLen = 0;

    TestMemInit();
    CRYPT_RandRegist(FrodoQualityRand);
    CRYPT_RandRegistEx(FrodoQualityRandEx);
    /* UINT32_MAX disables failure injection; 0x00 identifies the normal stream. */
    FrodoQualityRandReset(UINT32_MAX, 0x00);
    ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctExpected, sizeof(ctExpected)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssExpected, sizeof(ssExpected)), CRYPT_SUCCESS);
    seedSeLen = FrodoQualitySeedSeLen(algId, ssExpected);
    keyRandLen = ssExpected + seedSeLen + 16; // 16 bytes are the fixed seedA request used by Frodo key generation.
    /* The multiplier accounts for the variant-specific seedSE request length. */
    encapsRandLen = ssExpected + (seedSeLen == ssExpected ? 0 : ssExpected * 2);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(gFrodoRandLastLen, keyRandLen);
    cipher = BSL_SAL_Malloc(ctExpected);
    shared = BSL_SAL_Malloc(ssExpected);
    ASSERT_TRUE(cipher != NULL && shared != NULL);
    ctLen = ctExpected;
    ssLen = ssExpected;
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &ctLen, shared, &ssLen), CRYPT_SUCCESS);
    ASSERT_EQ(gFrodoRandLastLen, encapsRandLen);

    /* failAt=0 injects at the first RNG request; 0xFF/0x11/0x22 identify streams. */
    FrodoQualityRandReset(0, 0xFF);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), -1);
    FrodoQualityRandReset(UINT32_MAX, 0x11);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    FrodoQualityRandReset(0, 0x22);
    ctLen = ctExpected;
    ssLen = ssExpected;
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &ctLen, shared, &ssLen), -1);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(shared);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_KEYGEN_REPLACE_TC001
* @spec  -
* @title  Repeated key generation replacement test
* @precon  nan
* @brief  Generate two key pairs in one context and use the second pair.
* @expect  The second pair replaces the first and completes KEM.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_KEYGEN_REPLACE_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *pub1 = NULL;
    uint8_t *pub2 = NULL;
    uint8_t *prv1 = NULL;
    uint8_t *prv2 = NULL;
    uint8_t *cipher = NULL;
    uint8_t *shared1 = NULL;
    uint8_t *shared2 = NULL;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    uint32_t ctExpected = 0;
    uint32_t ssExpected = 0;

    TestMemInit();
    CRYPT_RandRegist(TestRand);
    CRYPT_RandRegistEx(TestRandEx);
    gRandNumber = 1;
    ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctExpected, sizeof(ctExpected)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssExpected, sizeof(ssExpected)), CRYPT_SUCCESS);
    pub1 = BSL_SAL_Malloc(pubLen);
    pub2 = BSL_SAL_Malloc(pubLen);
    prv1 = BSL_SAL_Malloc(prvLen);
    prv2 = BSL_SAL_Malloc(prvLen);
    cipher = BSL_SAL_Malloc(ctExpected);
    shared1 = BSL_SAL_Malloc(ssExpected);
    shared2 = BSL_SAL_Malloc(ssExpected);
    ASSERT_TRUE(pub1 != NULL && pub2 != NULL && prv1 != NULL && prv2 != NULL && cipher != NULL && shared1 != NULL);
    ASSERT_TRUE(shared2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(FrodoQualityGetKeys(ctx, pub1, pubLen, prv1, prvLen), CRYPT_SUCCESS);
    gRandNumber = 3; // 3 selects a distinct deterministic RNG stream for the replacement key pair.
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(FrodoQualityGetKeys(ctx, pub2, pubLen, prv2, prvLen), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(pub1, pub2, pubLen) != 0);
    ASSERT_TRUE(memcmp(prv1, prv2, prvLen) != 0);
    ctLen = ctExpected;
    ssLen = ssExpected;
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, cipher, &ctLen, shared1, &ssLen), CRYPT_SUCCESS);
    ssLen = ssExpected;
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, cipher, ctLen, shared2, &ssLen), CRYPT_SUCCESS);
    ASSERT_EQ(ssLen, ssExpected);
    ASSERT_EQ(memcmp(shared1, shared2, ssExpected), 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(pub1);
    BSL_SAL_FREE(pub2);
    BSL_SAL_FREE(prv1);
    BSL_SAL_FREE(prv2);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(shared1);
    BSL_SAL_FREE(shared2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_SETPUB_MATRIX_TC001
* @spec  -
* @title  Raw public key content and length boundary matrix test
* @precon  nan
* @brief  Test fixed binary payload patterns with L-1/L/L+1 repeated imports.
* @expect  Exact-length keys roundtrip; boundary lengths fail on fresh contexts.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_SETPUB_MATRIX_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *source = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t *pub = NULL;
    uint8_t *mutated = NULL;
    uint8_t *output = NULL;
    uint8_t *boundary = NULL;
    uint32_t pubLen = 0;

    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    source = NewFrodoKemCtx();
    ASSERT_TRUE(source != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(source, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(source), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(source, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    pub = BSL_SAL_Malloc(pubLen);
    mutated = BSL_SAL_Malloc(pubLen);
    output = BSL_SAL_Malloc(pubLen);
    boundary = BSL_SAL_Malloc(pubLen + 1);
    ASSERT_TRUE(pub != NULL && mutated != NULL && output != NULL && boundary != NULL);
    {
        CRYPT_EAL_PkeyPub sourcePub = {0};
        sourcePub.id = CRYPT_PKEY_FRODOKEM;
        sourcePub.key.kemEk.data = pub;
        sourcePub.key.kemEk.len = pubLen;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(source, &sourcePub), CRYPT_SUCCESS);
    }
    /* Four payload modes: all-zero, all-FF, leading-zero and trailing-zero. */
    for (uint32_t mode = 0; mode < 4; mode++) {
        if (mode == 0) {
            memset(mutated, 0x00, pubLen);
        } else if (mode == 1) {
            memset(mutated, 0xFF, pubLen);
        } else {
            memcpy(mutated, pub, pubLen);
            mutated[mode == 2 ? 0 : pubLen - 1] = 0;
        }
        ctx = NewFrodoKemCtx();
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
        pubKey.id = CRYPT_PKEY_FRODOKEM;
        pubKey.key.kemEk.data = mutated;
        pubKey.key.kemEk.len = pubLen;
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), CRYPT_SUCCESS);
        memset(output, 0xA5, pubLen); // 0xA5 is a sentinel confirming that the exact public-key length is written.
        pubKey.key.kemEk.data = output;
        pubKey.key.kemEk.len = pubLen;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pubKey), CRYPT_SUCCESS);
        ASSERT_EQ(memcmp(output, mutated, pubLen), 0);

        /* Boundary imports use fresh contexts because SetPub forbids repeated key setting. */
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;

        ctx = NewFrodoKemCtx();
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
        /* L-1 must be rejected before any key is stored in the context. */
        pubKey.key.kemEk.data = mutated;
        pubKey.key.kemEk.len = pubLen - 1;
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), CRYPT_INVALID_ARG);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;

        /* A fresh exact-length import must succeed. */
        ctx = NewFrodoKemCtx();
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
        pubKey.key.kemEk.data = mutated;
        pubKey.key.kemEk.len = pubLen;
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), CRYPT_SUCCESS);
        memset(output, 0xA5, pubLen);
        pubKey.key.kemEk.data = output;
        pubKey.key.kemEk.len = pubLen;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &pubKey), CRYPT_SUCCESS);
        ASSERT_EQ(memcmp(output, mutated, pubLen), 0);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;

        ctx = NewFrodoKemCtx();
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
        memcpy(boundary, mutated, pubLen);
        /* 0xA5 marks the byte beyond the valid public-key payload. */
        boundary[pubLen] = 0xA5;
        pubKey.key.kemEk.data = boundary;
        pubKey.key.kemEk.len = pubLen + 1;
        /* L+1 must also be rejected before any key is stored in the context. */
        ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &pubKey), CRYPT_INVALID_ARG);
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(source);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(pub);
    BSL_SAL_FREE(mutated);
    BSL_SAL_FREE(output);
    BSL_SAL_FREE(boundary);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_SETPRV_MATRIX_TC001
* @spec  -
* @title  Raw private key field validation test
* @precon  nan
* @brief  Test private key fields and the embedded public-key hash.
* @expect  Valid keys roundtrip; H(pk) inconsistency is rejected.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_SETPRV_MATRIX_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *source = NULL;
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};
    uint8_t *pub = NULL;
    uint8_t *prv = NULL;
    uint8_t *mutated = NULL;
    uint8_t *output = NULL;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    uint32_t ssLen = 0;
    uint32_t hashStart = 0;
    int32_t ret = 0;

    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    source = NewFrodoKemCtx();
    ASSERT_TRUE(source != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(source, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(source), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(source, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(source, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(source, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(ssLen)), CRYPT_SUCCESS);
    pub = BSL_SAL_Malloc(pubLen);
    prv = BSL_SAL_Malloc(prvLen);
    mutated = BSL_SAL_Malloc(prvLen);
    output = BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(pub != NULL && prv != NULL && mutated != NULL && output != NULL);
    {
        CRYPT_EAL_PkeyPub pubKey = {0};
        pubKey.id = CRYPT_PKEY_FRODOKEM;
        pubKey.key.kemEk.data = pub;
        pubKey.key.kemEk.len = pubLen;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPub(source, &pubKey), CRYPT_SUCCESS);
    }
    {
        CRYPT_EAL_PkeyPrv sourcePrv = {0};
        sourcePrv.id = CRYPT_PKEY_FRODOKEM;
        sourcePrv.key.kemDk.data = prv;
        sourcePrv.key.kemDk.len = prvLen;
        ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(source, &sourcePrv), CRYPT_SUCCESS);
    }
    hashStart = prvLen - ssLen;
    /* Five modes: original, first field, second field, public key and hash mutations. */
    for (uint32_t mode = 0; mode < 5; mode++) {
        memcpy(mutated, prv, prvLen);
        if (mode == 1) {
            mutated[0] ^= 0x01;
        } else if (mode == 2) {
            mutated[ssLen] ^= 0x01;
        } else if (mode == 3) {
            mutated[ssLen + pubLen] ^= 0x01;
        } else if (mode == 4) {
            mutated[hashStart] ^= 0x01;
        }
        ctx = NewFrodoKemCtx();
        ASSERT_TRUE(ctx != NULL);
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
        prvKey.id = CRYPT_PKEY_FRODOKEM;
        prvKey.key.kemDk.data = mutated;
        prvKey.key.kemDk.len = prvLen;
        ret = CRYPT_EAL_PkeySetPrv(ctx, &prvKey);
        if (mode == 0 || mode == 1 || mode == 3) {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
            memset(output, 0xA5, prvLen); // 0xA5 is a sentinel for exact-length private-key export.
            prvKey.key.kemDk.data = output;
            ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &prvKey), CRYPT_SUCCESS);
            ASSERT_EQ(memcmp(output, mutated, prvLen), 0);
        } else {
            ASSERT_EQ(ret, CRYPT_FRODOKEM_INVALID_PRVKEY);
        }
        CRYPT_EAL_PkeyFreeCtx(ctx);
        ctx = NULL;
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(source);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(pub);
    BSL_SAL_FREE(prv);
    BSL_SAL_FREE(mutated);
    BSL_SAL_FREE(output);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_STATE_CMP_TC001
* @spec  -
* @title  Partial-key state and cross-parameter comparison test
* @precon  nan
* @brief  Compare public-only, private-only and different-parameter contexts with a complete key context.
* @expect  Partial-key and different-parameter contexts are not equal to the complete key context or each other.
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_STATE_CMP_TC001(int algId)
{
    CRYPT_EAL_PkeyCtx *full = NULL;
    CRYPT_EAL_PkeyCtx *pubOnly = NULL;
    CRYPT_EAL_PkeyCtx *prvOnly = NULL;
    CRYPT_EAL_PkeyCtx *different = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    uint8_t *pub = NULL;
    uint8_t *prv = NULL;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    uint32_t differentAlgId = 0;

    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    full = NewFrodoKemCtx();
    pubOnly = NewFrodoKemCtx();
    prvOnly = NewFrodoKemCtx();
    different = NewFrodoKemCtx();
    ASSERT_TRUE(full != NULL);
    ASSERT_TRUE(pubOnly != NULL);
    ASSERT_TRUE(prvOnly != NULL);
    ASSERT_TRUE(different != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(full, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubOnly, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvOnly, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(full, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(full, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), CRYPT_SUCCESS);
    pub = BSL_SAL_Malloc(pubLen);
    prv = BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(pub != NULL && prv != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(full), CRYPT_SUCCESS);
    pubKey.id = CRYPT_PKEY_FRODOKEM;
    pubKey.key.kemEk.data = pub;
    pubKey.key.kemEk.len = pubLen;
    prvKey.id = CRYPT_PKEY_FRODOKEM;
    prvKey.key.kemDk.data = prv;
    prvKey.key.kemDk.len = prvLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(full, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(full, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubOnly, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvOnly, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(full, pubOnly), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(full, prvOnly), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(pubOnly, prvOnly), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    differentAlgId = (algId == CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE) ?
        CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE : CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(different, differentAlgId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(different), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(full, different), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(full);
    CRYPT_EAL_PkeyFreeCtx(pubOnly);
    CRYPT_EAL_PkeyFreeCtx(prvOnly);
    CRYPT_EAL_PkeyFreeCtx(different);
    BSL_SAL_FREE(pub);
    BSL_SAL_FREE(prv);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_KEYGEN_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyGen test
* @precon  nan
* @brief  1.register a random number and create a context.
* 2.invoke CRYPT_EAL_PkeyGen and transfer various parameters.
* 3.check the return value.
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_KEYGEN_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
        ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_KEYINFO_NOT_SET);

    uint32_t val = (uint32_t)bits;
    ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_NO_REGIST_RAND);

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* Use default random numbers for end-to-end testing */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_KEYGEN_API_TC002(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_ENCAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyEncaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyEncaps to transfer abnormal values.
* 3. check the return value.
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_ENCAPS_API_TC001(int bits)
{
    TestMemInit();

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(NULL, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, NULL, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, NULL, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, NULL, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    cipherLen = cipherLen + 1;

    sharedLen = 0;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    sharedLen = 32;

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DECAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyEncaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyDecaps to transfer various abnormal values.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_DECAPS_API_TC001(int bits)
{
    TestMemInit();

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyDecaps(NULL, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, NULL, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, NULL, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_INVALID_CIPHER);
    cipherLen = cipherLen + 1;

    sharedLen = 0;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    sharedLen = 32;

    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_SETPUB_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeySetPub and CRYPT_EAL_PkeyGetPub
* @precon  nan
* @brief 1.register a random number and create a context.
* 2.call CRYPT_EAL_PkeySetPub and CRYPT_EAL_PkeyGetPub and transfer various parameters.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_SETPUB_API_TC001(int bits, Hex *testEK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_EAL_ERR_ALGID);

    ek.id = CRYPT_PKEY_FRODOKEM;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_NULL_INPUT);

    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    memcpy(ek.key.kemEk.data, testEK->x, testEK->len);
    ek.key.kemEk.len = encapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_INVALID_ARG);

    ek.key.kemEk.len = encapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_INVALID_ARG);

    ek.key.kemEk.len = encapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_FRODOKEM_ABSENT_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    memset(ek.key.kemEk.data, 0, encapsKeyLen);

    ek.key.kemEk.len = encapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    ek.key.kemEk.len = encapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ek", ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ek.key.kemEk.data);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_SETPRV_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeySetPrv and CRYPT_EAL_PkeyGetPrv
* @precon  nan
* @brief 1.register a random number and create a context.
* 2.call CRYPT_EAL_PkeySetPrv and CRYPT_EAL_PkeyGetPrv and transfer various parameters.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_SETPRV_API_TC001(int bits, Hex *testDK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_EAL_ERR_ALGID);

    dk.id = CRYPT_PKEY_FRODOKEM;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_NULL_INPUT);

    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    memcpy(dk.key.kemDk.data, testDK->x, testDK->len);
    dk.key.kemDk.len = decapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_INVALID_ARG);

    dk.key.kemDk.len = decapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_INVALID_ARG);

    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data[decapsKeyLen - 1] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_FRODOKEM_INVALID_PRVKEY);
    dk.key.kemDk.data[decapsKeyLen - 1] ^= 1;

    dk.key.kemDk.len = decapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_FRODOKEM_ABSENT_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    memset(dk.key.kemDk.data, 0, decapsKeyLen);

    dk.key.kemDk.len = decapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    dk.key.kemDk.len = decapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare de", dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(dk.key.kemDk.data);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

static int32_t TestRand(uint8_t *randBuf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        randBuf[i] = gRandNumber;
    }
    return 0;
}
static int32_t TestRandEx(void *libctx, uint8_t *randBuf, uint32_t len)
{
    (void)libctx;
    return TestRand(randBuf, len);
}
/* @
* @test  SDV_CRYPTO_FRODOKEM_KEYCMP_FUNC_TC001
* @spec  -
* @title  Context Comparison and Copy Test
* @precon  nan
* @brief  1.Registers a random number that returns the specified value.
* 2. Call CRYPT_EAL_PkeyGen to generate a key pair. The first two groups of random numbers are the same,
*    and the third group of random numbers is different.
* 3. Call CRYPT_EAL_PkeyCopyCtx to copy the key pair.
* 4. Invoke CRYPT_EAL_PkeyCmp to compare key pairs.
* @expect  1.success 2.success 3.success 4.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_KEYCMP_FUNC_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestRand);
    CRYPT_RandRegistEx(TestRandEx);
    gRandNumber = 1u;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_NE(ctx, NULL);
    uint32_t val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, NULL), CRYPT_NULL_INPUT);

    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_NE(ctx2, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx2, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_SUCCESS);

    gRandNumber = 3u;
    CRYPT_EAL_PkeyCtx *ctx3 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_NE(ctx3, NULL);
    val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx3, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx3, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx3), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx3), CRYPT_FRODOKEM_KEY_NOT_EQUAL);

    CRYPT_EAL_PkeyCtx *ctx4 = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(ctx4, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx4), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx5 = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctx5 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx5), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    CRYPT_EAL_PkeyFreeCtx(ctx4);
    CRYPT_EAL_PkeyFreeCtx(ctx5);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

static uint8_t g_frodoSeed[48];
static DRBG_Ctx *g_randCtx = NULL;

static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    if (entropy == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t strengthBytes = (strength + 7) >> 3;
    entropy->len = ((strengthBytes > lenRange->min) ? strengthBytes : lenRange->min);
    if (entropy->len > lenRange->max) {
        return CRYPT_ENTROPY_RANGE_ERROR;
    }
    entropy->data = BSL_SAL_Malloc(entropy->len);
    if (entropy->data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    memcpy(entropy->data, g_frodoSeed, 48);
    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_CleanseData(entropy->data, entropy->len);
    BSL_SAL_FREE(entropy->data);
}

static int32_t NewDrbg()
{
    CRYPT_RandSeedMethod method = { 0 };
    method.getEntropy = (void *)GetEntropy;
    method.cleanEntropy = (void *)CleanEntropy;

    g_randCtx = DRBG_New(NULL, CRYPT_RAND_AES256_CTR, &method, NULL);
    if (g_randCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t RandomBytes(uint8_t *out, uint32_t outLen)
{
    return DRBG_GenerateBytes(g_randCtx, out, outLen, NULL, 0);
}

static int32_t RandSetUp()
{
    int32_t ret = NewDrbg();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = DRBG_Instantiate(g_randCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_SetRandCallBack(RandomBytes);
    return CRYPT_SUCCESS;
}

static void RandTeardown()
{
    DRBG_Free(g_randCtx);
    g_randCtx = NULL;
    CRYPT_EAL_SetRandCallBack(NULL);
}


/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_ENCAPS_DECAPS_FUNC_TC001(int bits, Hex *seed, Hex *testEk,
    Hex *testDk, Hex *testCt, Hex *testSs)
{
    TestMemInit();
    if (seed->len <= 48) {
        memcpy(g_frodoSeed, seed->x, seed->len);
    }
    ASSERT_EQ(RandSetUp(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, bits), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPrv dk = { 0 };
    CRYPT_EAL_PkeyPub ek = { 0 };
    dk.id = CRYPT_PKEY_FRODOKEM;
    ek.id = CRYPT_PKEY_FRODOKEM;
    uint32_t dkLen = 0;
    uint32_t ekLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &ekLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &dkLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ek.key.kemEk.data = BSL_SAL_Malloc(ekLen);
    ASSERT_TRUE(ek.key.kemEk.data != NULL);
    ek.key.kemEk.len = ekLen;
    dk.key.kemDk.data = BSL_SAL_Malloc(dkLen);
    ASSERT_TRUE(dk.key.kemDk.data != NULL);
    dk.key.kemDk.len = dkLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_COMPARE("ek cmp", ek.key.kemEk.data, ek.key.kemEk.len, testEk->x, testEk->len);
    ASSERT_COMPARE("dk cmp", dk.key.kemDk.data, dk.key.kemDk.len, testDk->x, testDk->len);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);
    uint32_t ssLen;
    uint32_t ctLen;
    uint8_t *ss;
    uint8_t *ss2;
    uint8_t *ct;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ss = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ss != NULL);
    ss2 = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ss2 != NULL);
    ct = BSL_SAL_Malloc(ctLen);
    ASSERT_TRUE(ct != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ct, &ctLen, ss, &ssLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("ct cmp", ct, ctLen, testCt->x, testCt->len);
    ASSERT_COMPARE("ss cmp", ss, ssLen, testSs->x, testSs->len);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ss2, &ssLen), CRYPT_SUCCESS);\
    ASSERT_COMPARE("ss2 cmp", ss2, ssLen, testSs->x, testSs->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(dk.key.kemDk.data);
    BSL_SAL_FREE(ek.key.kemEk.data);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ss);
    BSL_SAL_FREE(ss2);
    RandTeardown();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DUPKEY_API_TC001
* @spec  -
* @title  Test CRYPT_EAL_PkeyDupCtx with encaps/decaps
* @precon  nan
* @brief  1. Create a context and generate key pair
*         2. Dup the context
*         3. Compare the two contexts, expect success
*         4. Use the first context to do encaps
*         5. Use the dupped context to do decaps
*         6. Compare the shared secrets, expect them to be the same
* @expect  All operations succeed and shared secrets match
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_DUPKEY_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    // Set parameters and generate key pair
    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Dup the context
    CRYPT_EAL_PkeyCtx *ctxDup = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctxDup != NULL);

    // Compare the two contexts
    ret = CRYPT_EAL_PkeyCmp(ctx, ctxDup);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Get ciphertext and shared key lengths
    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sharedLen1 = 32;
    uint32_t sharedLen2 = 32;

    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(ciphertext != NULL);
    uint8_t *sharedKey1 = BSL_SAL_Malloc(sharedLen1);
    ASSERT_TRUE(sharedKey1 != NULL);
    uint8_t *sharedKey2 = BSL_SAL_Malloc(sharedLen2);
    ASSERT_TRUE(sharedKey2 != NULL);

    // Use first context to do encaps
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey1, &sharedLen1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Switch dupped context to decaps mode
    ret = CRYPT_EAL_PkeyDecapsInit(ctxDup, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Use dupped context to do decaps
    ret = CRYPT_EAL_PkeyDecaps(ctxDup, ciphertext, cipherLen, sharedKey2, &sharedLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Compare the shared secrets
    ASSERT_EQ(sharedLen1, sharedLen2);
    ASSERT_COMPARE("shared secret", sharedKey1, sharedLen1, sharedKey2, sharedLen2);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctxDup);
    BSL_SAL_FREE(ciphertext);
    BSL_SAL_FREE(sharedKey1);
    BSL_SAL_FREE(sharedKey2);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DUPKEY_STUB_TC001
* @spec  -
* @title  Test CRYPT_EAL_PkeyDupCtx with stubbed BSL_SAL_Malloc failure
* @precon  nan
* @brief  1. Create a context and generate key pair
*         2. Dup the context
*         3. Compare the two contexts, expect success
*         4. Use the first context to do encaps
*         5. Use the dupped context to do decaps
*         6. Compare the shared secrets, expect them to be the same
* @expect  All operations succeed and shared secrets match
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_DUPKEY_STUB_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    // Set parameters and generate key pair
    int32_t val = (int32_t)algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *cipher = NULL;
    uint8_t *sharedKey = NULL;
    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sharedLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    cipher = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(cipher != NULL);
    sharedKey = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    // Dup the context
    CRYPT_EAL_PkeyCtx *ctxDup = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctxDup != NULL);
    ret = CRYPT_EAL_PkeyEncaps(ctxDup, cipher, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyDecaps(ctxDup, cipher, cipherLen, sharedKey, &sharedLen);
    CRYPT_EAL_PkeyFreeCtx(ctxDup);
    totalMallocCount = STUB_GetMallocCallCount();
    ctxDup = NULL;
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; ++i) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        CRYPT_EAL_PkeyGen(ctx);
        ctxDup = CRYPT_EAL_PkeyDupCtx(ctx);
        CRYPT_EAL_PkeyEncaps(ctxDup, cipher, &cipherLen, sharedKey, &sharedLen);
        CRYPT_EAL_PkeyDecaps(ctxDup, cipher, cipherLen, sharedKey, &sharedLen);
        CRYPT_EAL_PkeyFreeCtx(ctxDup);
        ctxDup = NULL;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctxDup);
    CRYPT_RandRegist(NULL);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(sharedKey);
    STUB_RESTORE(BSL_SAL_Malloc);
    return;
}
/* END_CASE */

static CRYPT_EAL_PkeyCtx *NewFrodoKemCtx(void)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    return CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
}

static void GetFrodoExpectedLens(int32_t algId, uint32_t *ctLen, uint32_t *secBits, uint32_t *pubLen,
    uint32_t *prvLen, uint32_t *sharedLen)
{
    switch (algId) {
        case CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_640_AES:
            *ctLen = 9752;
            *secBits = 128;
            *pubLen = 9616;
            *prvLen = 19888;
            *sharedLen = 16;
            return;
        case CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_976_AES:
            *ctLen = 15792;
            *secBits = 192;
            *pubLen = 15632;
            *prvLen = 31296;
            *sharedLen = 24;
            return;
        case CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_1344_AES:
            *ctLen = 21696;
            *secBits = 256;
            *pubLen = 21520;
            *prvLen = 43088;
            *sharedLen = 32;
            return;
        case CRYPT_KEM_TYPE_EFRODOKEM_640_SHAKE:
        case CRYPT_KEM_TYPE_EFRODOKEM_640_AES:
            *ctLen = 9720;
            *secBits = 128;
            *pubLen = 9616;
            *prvLen = 19888;
            *sharedLen = 16;
            return;
        case CRYPT_KEM_TYPE_EFRODOKEM_976_SHAKE:
        case CRYPT_KEM_TYPE_EFRODOKEM_976_AES:
            *ctLen = 15744;
            *secBits = 192;
            *pubLen = 15632;
            *prvLen = 31296;
            *sharedLen = 24;
            return;
        case CRYPT_KEM_TYPE_EFRODOKEM_1344_SHAKE:
        case CRYPT_KEM_TYPE_EFRODOKEM_1344_AES:
            *ctLen = 21632;
            *secBits = 256;
            *pubLen = 21520;
            *prvLen = 43088;
            *sharedLen = 32;
            return;
        default:
            *ctLen = 0;
            *secBits = 0;
            *pubLen = 0;
            *prvLen = 0;
            *sharedLen = 0;
            return;
    }
}

static int32_t CheckFrodoGetNumCtrl(CRYPT_EAL_PkeyCtx *ctx, int32_t cmd, uint32_t expected)
{
    uint32_t value = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, cmd, &value, sizeof(value));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (value != expected) {
        return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, cmd, &value, sizeof(value) - 1);
    if (ret != CRYPT_INVALID_ARG) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_CTRL_GETTER_API_TC001(int algId)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t value = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SECBITS, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, NULL, sizeof(value)), CRYPT_NULL_INPUT);

    uint32_t ctLen = 0;
    uint32_t secBits = 0;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    uint32_t sharedLen = 0;
    GetFrodoExpectedLens(algId, &ctLen, &secBits, &pubLen, &prvLen, &sharedLen);

    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_SECBITS, secBits), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, pubLen), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, prvLen), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, sharedLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_STATE_NEG_API_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *src = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *pubOnly = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *prvOnly = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *repeat = NewFrodoKemCtx();
    uint8_t *pubBuf = NULL;
    uint8_t *prvBuf = NULL;
    uint8_t *ct = NULL;
    uint8_t *ss = NULL;
    ASSERT_TRUE(src != NULL);
    ASSERT_TRUE(pubOnly != NULL);
    ASSERT_TRUE(prvOnly != NULL);
    ASSERT_TRUE(repeat != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(src, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubOnly, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvOnly, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(repeat, (uint32_t)algId), CRYPT_SUCCESS);

    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(ssLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), CRYPT_SUCCESS);

    ct = BSL_SAL_Malloc(ctLen);
    ss = BSL_SAL_Malloc(ssLen);
    pubBuf = BSL_SAL_Malloc(pubLen);
    prvBuf = BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(ss != NULL);
    ASSERT_TRUE(pubBuf != NULL);
    ASSERT_TRUE(prvBuf != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(src, ct, &ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PUBKEY);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(src, ct, ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    pub.id = CRYPT_PKEY_FRODOKEM;
    prv.id = CRYPT_PKEY_FRODOKEM;
    pub.key.kemEk.data = pubBuf;
    pub.key.kemEk.len = pubLen;
    prv.key.kemDk.data = prvBuf;
    prv.key.kemDk.len = prvLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(src, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(src, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubOnly, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(pubOnly, ct, ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvOnly, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(prvOnly, ct, &ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(repeat, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(repeat, &prv), CRYPT_FRODOKEM_KEY_REPEATED_SET);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(src);
    CRYPT_EAL_PkeyFreeCtx(pubOnly);
    CRYPT_EAL_PkeyFreeCtx(prvOnly);
    CRYPT_EAL_PkeyFreeCtx(repeat);
    BSL_SAL_FREE(pubBuf);
    BSL_SAL_FREE(prvBuf);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ss);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_WRONG_PRV_FUNC_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestRand);
    CRYPT_RandRegistEx(TestRandEx);
    CRYPT_EAL_PkeyCtx *ctx1 = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *ctx2 = NewFrodoKemCtx();
    uint8_t *ct = NULL;
    uint8_t *ss1 = NULL;
    uint8_t *ss2 = NULL;
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, (uint32_t)algId), CRYPT_SUCCESS);
    gRandNumber = 1u;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx1), CRYPT_SUCCESS);
    gRandNumber = 3u;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);

    uint32_t ctLen = 0;
    uint32_t ssLen1 = 0;
    uint32_t ssLen2 = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen1, sizeof(ssLen1)), CRYPT_SUCCESS);
    ssLen2 = ssLen1;
    ct = BSL_SAL_Malloc(ctLen);
    ss1 = BSL_SAL_Malloc(ssLen1);
    ss2 = BSL_SAL_Malloc(ssLen2);
    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(ss1 != NULL);
    ASSERT_TRUE(ss2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx1, ct, &ctLen, ss1, &ssLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx2, ct, ctLen, ss2, &ssLen2), CRYPT_SUCCESS);
    ASSERT_EQ(ssLen1, ssLen2);
    ASSERT_TRUE(memcmp(ss1, ss2, ssLen1) != 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ss1);
    BSL_SAL_FREE(ss2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_MODIFIED_CT_FUNC_TC001
* @spec  -
* @title  Test implicit rejection after modifying each ciphertext partition
* @precon  nan
* @brief  1. Generate a key pair and a valid ciphertext
*         2. Modify the first, middle, and last byte of C1 and C2 separately
*         3. For salted variants, modify the first, middle, and last byte of salt separately
*         4. Decapsulate each modified ciphertext twice
* @expect  Decapsulation succeeds and returns a deterministic fallback secret
*          The fallback secret differs from the valid shared secret
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_MODIFIED_CT_FUNC_TC001(int algId, int c1Len, int c2Len, int saltLen)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NewFrodoKemCtx();
    uint8_t *ct = NULL;
    uint8_t *ctOrig = NULL;
    uint8_t *ss = NULL;
    uint8_t *ssFallback1 = NULL;
    uint8_t *ssFallback2 = NULL;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(c1Len > 0);
    ASSERT_TRUE(c2Len > 0);
    ASSERT_TRUE(saltLen >= 0);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(ssLen)), CRYPT_SUCCESS);
    ASSERT_EQ((uint32_t)c1Len + (uint32_t)c2Len + (uint32_t)saltLen, ctLen);
    const uint32_t expectedCtLen = ctLen;
    const uint32_t expectedSsLen = ssLen;

    ct = BSL_SAL_Malloc(ctLen);
    ctOrig = BSL_SAL_Malloc(ctLen);
    ss = BSL_SAL_Malloc(ssLen);
    ssFallback1 = BSL_SAL_Malloc(ssLen);
    ssFallback2 = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(ctOrig != NULL);
    ASSERT_TRUE(ss != NULL);
    ASSERT_TRUE(ssFallback1 != NULL);
    ASSERT_TRUE(ssFallback2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ctOrig, &ctLen, ss, &ssLen), CRYPT_SUCCESS);
    ASSERT_EQ(ctLen, expectedCtLen);
    ASSERT_EQ(ssLen, expectedSsLen);
    uint32_t validSsLen = ssLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ctOrig, ctLen, ssFallback1, &validSsLen), CRYPT_SUCCESS);
    ASSERT_EQ(validSsLen, ssLen);
    ASSERT_EQ(memcmp(ss, ssFallback1, ssLen), 0);

    const uint32_t c1Size = (uint32_t)c1Len;
    const uint32_t c2Start = c1Size;
    const uint32_t c2Size = (uint32_t)c2Len;
    const uint32_t saltStart = c2Start + c2Size;
    const uint32_t saltSize = (uint32_t)saltLen;
    uint32_t positions[9] = {
        0, c1Size / 2, c1Size - 1,
        c2Start, c2Start + c2Size / 2, c2Start + c2Size - 1
    };
    uint32_t positionCount = 6;
    if (saltSize > 0) {
        positions[positionCount++] = saltStart;
        positions[positionCount++] = saltStart + saltSize / 2;
        positions[positionCount++] = ctLen - 1;
    }
    for (uint32_t i = 0; i < positionCount; i++) {
        uint32_t fallbackLen1 = ssLen;
        uint32_t fallbackLen2 = ssLen;
        memcpy(ct, ctOrig, ctLen);
        ct[positions[i]] ^= 0x01;
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ssFallback1, &fallbackLen1), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ssFallback2, &fallbackLen2), CRYPT_SUCCESS);
        ASSERT_EQ(fallbackLen1, ssLen);
        ASSERT_EQ(fallbackLen2, ssLen);
        ASSERT_TRUE(memcmp(ss, ssFallback1, ssLen) != 0);
        ASSERT_EQ(memcmp(ssFallback1, ssFallback2, ssLen), 0);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ctOrig);
    BSL_SAL_FREE(ss);
    BSL_SAL_FREE(ssFallback1);
    BSL_SAL_FREE(ssFallback2);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */
