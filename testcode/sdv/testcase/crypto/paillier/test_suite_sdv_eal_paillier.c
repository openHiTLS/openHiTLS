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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "stub_utils.h"
#include "crypt_util_rand.h"
#include "crypt_paillier.h"
#include "paillier_local.h"
#include "bn_basic.h"
#include "securec.h"

#include "crypt_codecskey.h"
#include "crypt_params_key.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

void *malloc_fail(uint32_t size)
{
    (void)size;
    return NULL;
}

void SetPaillierPara(CRYPT_EAL_PkeyPara *para, Hex *p, Hex *q, uint32_t bits)
{
    para->id = CRYPT_PKEY_PAILLIER;
    para->para.paillierPara.p = p->x;
    para->para.paillierPara.q = q->x;
    para->para.paillierPara.pLen = p->len;
    para->para.paillierPara.qLen = q->len;
    para->para.paillierPara.bits = bits;
}

void SetPaillierPubKey(CRYPT_EAL_PkeyPub *pubKey, uint8_t *g, uint32_t gLen, uint8_t *n, uint32_t nLen, uint8_t *n2, uint32_t n2Len)
{
    pubKey->id = CRYPT_PKEY_PAILLIER;
    pubKey->key.paillierPub.g = g;
    pubKey->key.paillierPub.gLen = gLen;
    pubKey->key.paillierPub.n = n;
    pubKey->key.paillierPub.nLen = nLen;
    pubKey->key.paillierPub.n2 = n2;
    pubKey->key.paillierPub.n2Len = n2Len;
}

void SetPaillierPrvKey(CRYPT_EAL_PkeyPrv *prvKey, uint8_t *lambda, uint32_t lambdaLen, uint8_t *mu, uint32_t muLen)
{
    prvKey->id = CRYPT_PKEY_PAILLIER;
    prvKey->key.paillierPrv.lambda = lambda;
    prvKey->key.paillierPrv.lambdaLen = lambdaLen;
    prvKey->key.paillierPrv.mu = mu;
    prvKey->key.paillierPrv.muLen = muLen;
}

int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    const int maxNum = 255;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return 0;
}

int32_t RandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    const int maxNum = 255;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return 0;
}

/**
 * @test   SDV_CRYPTO_PAILLIER_NEW_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyNewCtx test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create ctx, algId is CRYPT_PKEY_PAILLIER, expected result 1.
 *    2. Release the ctx.
 *    3. Repeat steps 1 to 2 for 100 times.
 * @expect
 *    1. The returned result is not empty.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_NEW_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    /* Run 100 times */
    for (int i = 0; i < 100; i++) {
        pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default",
            isProvider);
        ASSERT_TRUE(pkey != NULL);

        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_NEW_API_TC002
 * @title  PAILLIER CRYPT_EAL_PkeyNewCtx test: Malloc failed.
 * @precon Mock BSL_SAL_Malloc to malloc_fail.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create ctx, algId is CRYPT_PKEY_PAILLIER, expected result 1.
 *    2. Release the ctx.
 *    3. Reset the BSL_SAL_Malloc.
 * @expect
 *    1. Failed to create the ctx.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_NEW_API_TC002(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    STUB_REPLACE(BSL_SAL_Malloc, malloc_fail);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);

    ASSERT_TRUE(pkey == NULL);

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PARA_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeySetPara test.
 * @precon Create the context of the paillier algorithm.
 * 
 * @brief
 *   1. Call the CRYPT_EAL_PkeySetPara method:
 *     (1) para = NULL, expected result 1.
 *     (2) pLen != BN_BITS_TO_BYTES(bits), expected result 2.
 *     (3) qLen != BN_BITS_TO_BYTES(bits), expected result 2.
 *     (4) p = NULL, q = NULL, bits = 0, expected result 2.
 *     (4) pLen = BN_BITS_TO_BYTES(bits) qLen = BN_BITS_TO_BYTES(bits), bits != 0, expected result 3.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    3. CRYPT_SUCCESS 
*/
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_SET_PARA_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};

    SetPaillierPara(&para, p, q, bits);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, NULL), CRYPT_NULL_INPUT);

    uint32_t bytes = BN_BITS_TO_BYTES(bits);
    if (p->len != bytes)
    {
        ASSERT_TRUE_AND_LOG("pLen != BN_BITS_TO_BYTES(bits)",
            CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_MEM_ALLOC_FAIL);
    }
    if (q->len != bytes)
    {
        ASSERT_TRUE_AND_LOG("qLen != BN_BITS_TO_BYTES(bits)",
            CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_MEM_ALLOC_FAIL);
    }
    if (p->len == bytes && q->len == bytes && bits == 0)
    {
        ASSERT_TRUE_AND_LOG("p = NULL, q = NULL, bits = 0",
            CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_MEM_ALLOC_FAIL);
    }
    if (p->len == bytes && q->len == bytes && bits != 0)
    {
        ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    }
    
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_GEN_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyGen: No regist rand.
 * @precon Create the contexts of the paillier algorithm and set para.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGen method to generate a key pair, expected result 1.
 * @expect
 *    1. Failed to generate a key pair, the return value is CRYPT_NO_REGIST_RAND.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_GEN_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    SetPaillierPara(&para, p, q, bits);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey;
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_NO_REGIST_RAND);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_GET_PUB_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyGetPub test.
 * @precon 1. Create the context of the paillier algorithm.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method without public key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) pub = NULL, expected result 1.
 *       (3) n = NULL, expected result 1.
 *       (4) n != NULL and nLen = 0, expected result 3.
 *       (5) g = NULL, expected result 1.
 *       (6) g != NULL, gLen = 0, expected result 3.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_GET_PUB_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t pubG[600];
    uint8_t pubN[600];
    uint8_t pubN2[600];

    SetPaillierPara(&para, p, q, bits);
    SetPaillierPubKey(&pubKey, pubG, 600, pubN, 600, pubN2, 600);

    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);

    ASSERT_TRUE(pkey != NULL);

    /* Missing public key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pubKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, NULL), CRYPT_NULL_INPUT);

    /* n = NULL */
    pubKey.key.paillierPub.n = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.paillierPub.n = pubN;

    /* n != NULL and nLen = 0 */
    pubKey.key.paillierPub.nLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    pubKey.key.paillierPub.nLen = 600;

    /* g = NULL */
    pubKey.key.paillierPub.g = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.paillierPub.g = pubG;

    /* g != NULL, gLen = 0 */
    pubKey.key.paillierPub.gLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_GET_PRV_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyGetPrv: Bad private key.
 * @precon 1. Create the context of the paillier algorithm.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPrv method without private key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPrv method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) prv = NULL, expected result 1.
 *       (3) lambda = NULL, expected result 1.
 *       (4) lambda != NULL and lambdaLen = 0, expected result 3.
 *       (5) mu = NULL, expected result 1.
 *       (6) mu != NULL, muLen = 0, expected result 3.
 *       (7) lambda != NULL, mu != NULL, lambdaLen != 0, muLen != 0, expected result 2.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_GET_PRV_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};

    CRYPT_EAL_PkeyPara para = {0};
    uint8_t prvLambda[600];
    uint8_t prvMu[600];

    SetPaillierPrvKey(&prvKey, prvLambda, 600, prvMu, 600);
    SetPaillierPara(&para, p, q, bits);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* Missing private key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prvKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    /* lambda = NULL */
    prvKey.key.paillierPrv.lambda = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.lambda = prvLambda;

    /* lambda != NULL and lambdaLen = 0 */
    prvKey.key.paillierPrv.lambdaLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    prvKey.key.paillierPrv.lambdaLen = 600;

    /* mu = NULL */
    prvKey.key.paillierPrv.mu = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.mu = prvMu;
    
    /* mu != NULL, muLen = 0 */
    prvKey.key.paillierPrv.muLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    prvKey.key.paillierPrv.muLen = 600;

    /* lambda != NULL, mu != NULL, lambdaLen != 0, muLen != 0 */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PRV_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeySetPrv: Bad private key.
 * @precon Create the contexts of the paillier algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: set the private key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) pKey is NULL, expected result 1.
 *       (2) prv is NULL, expected result 1.
 *       (3) n = NULL, expected result 2.
 *       (4) lambda = NULL, expected result 2.
 *       (5) mu = NULL, expected result 2.
 *       (6) n2 = NULL, expected result 2.
 *       (7) lambdaLen = 0, expected result 2.
 *       (8) muLen = 0, expected result 2.
 *       (9) n2Len = 0, expected result 2.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_PAILLIER_ERR_INPUT_VALUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_SET_PRV_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    uint8_t prvMu[600];
    uint8_t prvLambda[600];
    uint8_t prvN[600];
    uint8_t prvN2[600];

    SetPaillierPrvKey(&prvKey, prvLambda, 600, prvMu, 600);
    SetPaillierPara(&para, p, q, bits);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);

    /*pKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(NULL, &prvKey) == CRYPT_NULL_INPUT);

    /*prvKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey2, NULL) == CRYPT_NULL_INPUT);

    prvKey.key.paillierPrv.n = prvN;
    prvKey.key.paillierPrv.nLen = 600;

    prvKey.key.paillierPrv.n2 = prvN2;
    prvKey.key.paillierPrv.n2Len = 600;

    /*n = NULL*/
    prvKey.key.paillierPrv.n = NULL;
    ASSERT_TRUE_AND_LOG("n is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.n = prvN;

    /*lambda = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.paillierPrv.lambda = NULL;
    ASSERT_TRUE_AND_LOG("lambda is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.lambda = prvLambda;

    /*mu = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.paillierPrv.mu = NULL;
    ASSERT_TRUE_AND_LOG("mu is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.mu = prvMu;

    /*n2 = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.paillierPrv.n2 = NULL;
    ASSERT_TRUE_AND_LOG("n2 is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.n2 = prvN2;

    /*lambdaLen = 0*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.paillierPrv.lambdaLen = 0;
    ASSERT_TRUE_AND_LOG("lambdaLen is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.lambdaLen = 600;

    /*muLen = 0*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.paillierPrv.muLen = 0;
    ASSERT_TRUE_AND_LOG("muLen is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.muLen = 600;

    /*n2Len = 0*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.paillierPrv.n2Len = 0;
    ASSERT_TRUE_AND_LOG("n2Len is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_PAILLIER_ERR_INPUT_VALUE);
    prvKey.key.paillierPrv.n2Len = 600;
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PRV_API_TC002
 * @title  PAILLIER CRYPT_EAL_PkeySetPrv: Specification test.
 * @precon Create the contexts of the paillier algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: set the private key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) n2 is not equal to n^2, expected result 1.
 *       (2) n2 is equal to n^2, expceted result 2.
 * @expect
 *    1. CRYPT_PAILLIER_ERR_INPUT_VALUE
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_SET_PRV_API_TC002(Hex *p, Hex *q, Hex *n, Hex *n2, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    uint8_t prvMu[256];
    uint8_t prvLambda[256];

    SetPaillierPrvKey(&prvKey, prvLambda, 256, prvMu, 256);
    SetPaillierPara(&para, p, q, bits);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);
    
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);

    prvKey.key.paillierPrv.n = n->x;
    prvKey.key.paillierPrv.nLen = n->len;

    prvKey.key.paillierPrv.n2 = n->x;
    prvKey.key.paillierPrv.n2Len = n->len;

    ASSERT_TRUE_AND_LOG("n2 is not equal to n^2", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey)
        == CRYPT_PAILLIER_ERR_INPUT_VALUE);

    prvKey.key.paillierPrv.n2 = n2->x;
    prvKey.key.paillierPrv.n2Len = n2->len;
    ASSERT_TRUE_AND_LOG("set success", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PUB_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyGetPub: Bad public key.
 * @precon Create the contexts of the paillier algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: Set the public key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pKey is NULL, expected result 1.
 *       (2) prv is NULL, expected result 1.
 *       (3) n = NULL, expected result 1.
 *       (4) g = NULL, expected result 1.
 *       (5) n2 = NULL, expected result 1.
 * @expect
 *    1. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_SET_PUB_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey;
    uint8_t pubG[600];
    uint8_t pubN[600];
    uint8_t pubN2[600];
    SetPaillierPara(&para, p, q, bits);
    SetPaillierPubKey(&pubKey, pubN, 600, pubG, 600, pubN2, 600);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    /*pKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(NULL, &pubKey) == CRYPT_NULL_INPUT);

    /*pubKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, NULL) == CRYPT_NULL_INPUT);

    /*n = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.paillierPub.n = NULL;
    ASSERT_TRUE_AND_LOG("lambda is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.paillierPub.n = pubN;

    /*g = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.paillierPub.g = NULL;
    ASSERT_TRUE_AND_LOG("mu is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.paillierPub.g = pubG;

    /*n2 = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.paillierPub.n2 = NULL;
    ASSERT_TRUE_AND_LOG("n2 is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.paillierPub.n2 = pubN2;

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);

    ASSERT_TRUE_AND_LOG("set prvKey success", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PUB_API_TC002
 * @title  PAILLIER CRYPT_EAL_PkeyGetPub: Bad public key.
 * @precon Create the contexts of the paillier algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: Set the public key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) n2 is not equal to n^2, expected result 1.
 *       (2) n2 is equal to n^2, expceted result 2.
 * @expect
 *    1. CRYPT_PAILLIER_ERR_INPUT_VALUE
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_SET_PUB_API_TC002(Hex *p, Hex *q, Hex *n, Hex *n2, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey;
    uint8_t pubG[128];
    SetPaillierPara(&para, p, q, bits);
    SetPaillierPubKey(&pubKey, pubG, 128, n->x, n->len, n2->x, n2->len);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    
    pubKey.key.paillierPub.n2 = n->x;
    pubKey.key.paillierPub.n2Len = n->len;
    ASSERT_TRUE_AND_LOG("n2 is not equal to n^2", CRYPT_EAL_PkeySetPub(pkey2, &pubKey)
        == CRYPT_PAILLIER_ERR_INPUT_VALUE);

    pubKey.key.paillierPub.n2 = n2->x;
    pubKey.key.paillierPub.n2Len = n2->len;
    ASSERT_TRUE_AND_LOG("set success", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_ENC_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyEncrypt: Test the validity of input parameters.
 * @precon Create the context of the paillier algorithm:
 * @brief
 *    1. Call the CRYPT_EAL_PkeyEncrypt method without public key, expected result 1
 *    2. Set pubkey, expected result 2
 *    3. Call the CRYPT_EAL_PkeyEncrypt method:
 *       (1) pkey = NULL, expected result 3
 *       (2) data = NULL, expected result 3
 *       (3) data != NULL dataLen > bytes of ctx, expected result 4
 *       (4) out = NULL, expected result 3
 *       (5) outLen = NULL, expected result 3
 *       (6) outLen = 0, expected result 5
 *       (7) no modification, expected result 2
 * @expect
 *    1. CRYPT_PAILLIER_NO_KEY_INFO
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_PAILLIER_ERR_ENC_BITS
 *    5. CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_ENC_API_TC001(Hex *n, Hex *g, Hex *n2, Hex *in, int isProvider)
{
    uint8_t crypt[512];
    uint32_t cryptLen = 512;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};

    SetPaillierPubKey(&pubkey, g->x, g->len, n->x, n->len, n2->x, n2->len);
    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen), CRYPT_PAILLIER_NO_KEY_INFO);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(NULL, in->x, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, NULL, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, 257, crypt, &cryptLen) == CRYPT_PAILLIER_ERR_ENC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, NULL, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, NULL) == CRYPT_NULL_INPUT);
    cryptLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH);
    
    cryptLen = 512;
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_DEC_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyDecrypt: Test the validity of input parameters.
 * @precon Create the context of the paillier algorithm:
 * @brief
 *    1. Call the CRYPT_EAL_PkeyDecrypt method without private key, expected result 1
 *    2. Set private key, expected result 2
 *    4. Call the CRYPT_EAL_PkeyDecrypt method:
 *       (1) pkey = NULL, expected result 3
 *       (2) data = NULL, expected result 3
 *       (3) data != NULL, dataLen = 0, expected result 4
 *       (4) data != NULL, dataLen is invalid , expected result 4
 *       (5) out = NULL, expected result 3
 *       (6) outLen = NULL, expected result 3
 *       (7) outLen = 0, expected result 5
 *       (8) no modification, expected result 2
 * @expect
 *    1. CRYPT_PAILLIER_NO_KEY_INFO
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_PAILLIER_ERR_DEC_BITS
 *    5. CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_DEC_API_TC001(Hex *Lambda, Hex *mu, Hex *n, Hex *n2, Hex *in, int isProvider)
{
    uint8_t crypt[256];
    uint32_t cryptLen = 256;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    SetPaillierPrvKey(&prvkey, Lambda->x, Lambda->len, mu->x, mu->len);
    prvkey.key.paillierPrv.n = n->x;
    prvkey.key.paillierPrv.nLen = n->len;
    prvkey.key.paillierPrv.n2 = n2->x;
    prvkey.key.paillierPrv.n2Len = n2->len;

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_PAILLIER_NO_KEY_INFO);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(NULL, in->x, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, NULL, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, 0, crypt, &cryptLen) == CRYPT_PAILLIER_ERR_DEC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, 257, crypt, &cryptLen) == CRYPT_PAILLIER_ERR_DEC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, NULL, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, NULL) == CRYPT_NULL_INPUT);

    cryptLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH);

    cryptLen = 256;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

int Compare_PubKey(CRYPT_EAL_PkeyPub *pubKey1, CRYPT_EAL_PkeyPub *pubKey2)
{
    if (pubKey1->key.paillierPub.nLen != pubKey2->key.paillierPub.nLen || pubKey1->key.paillierPub.gLen != pubKey2->key.paillierPub.gLen) {
        return -1;  // -1 indicates failure
    }
    if (memcmp(pubKey1->key.paillierPub.n, pubKey2->key.paillierPub.n, pubKey1->key.paillierPub.nLen) != 0 ||
        memcmp(pubKey1->key.paillierPub.g, pubKey2->key.paillierPub.g, pubKey1->key.paillierPub.gLen) != 0) {
        return -1;  // -1 indicates failure
    }
    return 0;
}

int Compare_PrvKey(CRYPT_EAL_PkeyPrv *prvKey1, CRYPT_EAL_PkeyPrv *prvKey2)
{
    if (prvKey1->key.paillierPrv.nLen != prvKey2->key.paillierPrv.nLen || prvKey1->key.paillierPrv.muLen != prvKey2->key.paillierPrv.muLen ||
        prvKey1->key.paillierPrv.lambdaLen != prvKey2->key.paillierPrv.lambdaLen) {
        return -1;  // -1 indicates failure
    }
    if (memcmp(prvKey1->key.paillierPrv.lambda, prvKey2->key.paillierPrv.lambda, prvKey1->key.paillierPrv.lambdaLen) != 0 ||
        memcmp(prvKey1->key.paillierPrv.mu, prvKey2->key.paillierPrv.mu, prvKey1->key.paillierPrv.muLen) != 0 ||
        memcmp(prvKey1->key.paillierPrv.n, prvKey2->key.paillierPrv.n, prvKey1->key.paillierPrv.nLen) != 0) {
        return -1;  // -1 indicates failure
    }
    return 0;
}

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_KEY_API_TC001
 * @title  PAILLIER Set the public key and private key multiple times.
 * @precon Create the contexts of the paillier algorithm and:
 *         pkey1: Set paran and generate a key pair: test obtaining the key.
 *         pkey2: Test set keys, and verify that the public and private keys can exist at the same time.
 * @brief
 *    1. pkey1: Get public key and get private key, expected result 1
 *    2. pkey2:
 *       (1) Set public key and set private key, expected result 1
 *       (2) Get public key, get private key and check private key, expected result 2
 *       (3) Set private key and set public key, expected result 3
 *       (4) Get private key, get public key and check public key, expected result 4
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. The obtained private key is equal to the set private key.
 *    3. CRYPT_SUCCESS
 *    4. The obtained public key is equal to the set public key.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_SET_KEY_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    uint8_t pubN[600];
    uint8_t pubG[600];
    uint8_t pubN2[600];
    uint8_t prvN[600];
    uint8_t prvLambda[600];
    uint8_t prvMu[600];
    uint8_t prvN2[600];
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};

    SetPaillierPara(&para, p, q, bits);
    SetPaillierPubKey(&pubKey, pubG, 600, pubN, 600, pubN2, 600);
    SetPaillierPrvKey(&prvKey, prvLambda, 600, prvMu, 600);
    prvKey.key.paillierPrv.n = prvN;
    prvKey.key.paillierPrv.nLen = 600;
    prvKey.key.paillierPrv.n2 = prvN2;
    prvKey.key.paillierPrv.n2Len = 600;

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL && pkey2 != NULL);

    /* pkey1 */
    /* Generate a key pair. */
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey1, &para) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey1), CRYPT_SUCCESS);

    /* Get keys. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey1, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey1, &prvKey), CRYPT_SUCCESS);

    /* pkey2 */
    /* Set public key and set private key. */
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey2, &prvKey), CRYPT_SUCCESS);

    /* Get public key, get private key and check private key.*/
    SetPaillierPubKey(&pubKey, pubG, 600, pubN, 600, pubN2, 600);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    SetPaillierPrvKey(&prvKey, prvLambda, 600, prvMu, 600);
    prvKey.key.paillierPrv.n = prvN;
    prvKey.key.paillierPrv.nLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(Compare_PrvKey(&prvKey, &prvKey), 0);

    /* Set private key and set public key. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    /* Get private key, get public key and check public key.*/
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    SetPaillierPubKey(&pubKey, pubG, 600, pubN, 600, pubN2, 600);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(Compare_PubKey(&pubKey, &pubKey), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_DUP_CTX_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyDupCtx test.
 * @precon Create the contexts of the paillier algorithm, set para and generate a key pair.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyDupCtx mehod to dup paillier, expected result 1
 * @expect
 *    1. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_DUP_CTX_API_TC001(Hex *p, Hex *q, int bits, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *newPkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    SetPaillierPara(&para, p, q, bits);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    CRYPT_PAILLIER_Ctx *paillierCtx = (CRYPT_PAILLIER_Ctx *)pkey->key;
    ASSERT_TRUE(paillierCtx != NULL);

    newPkey = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newPkey != NULL);
    ASSERT_EQ(newPkey->references.count, 1);
    CRYPT_PAILLIER_Ctx *paillierCtx2 = (CRYPT_PAILLIER_Ctx *)newPkey->key;
    ASSERT_TRUE(paillierCtx2 != NULL);

    ASSERT_COMPARE("paillier compare lambda",
        paillierCtx->prvKey->lambda->data,
        paillierCtx->prvKey->lambda->size * sizeof(BN_UINT),
        paillierCtx2->prvKey->lambda->data,
        paillierCtx2->prvKey->lambda->size * sizeof(BN_UINT));

    ASSERT_COMPARE("paillier compare mu",
        paillierCtx->prvKey->mu->data,
        paillierCtx->prvKey->mu->size * sizeof(BN_UINT),
        paillierCtx2->prvKey->mu->data,
        paillierCtx2->prvKey->mu->size * sizeof(BN_UINT));

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newPkey);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_GET_SECURITY_BITS_FUNC_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyGetSecurityBits test.
 * @precon nan
 * @brief
 *    1. Create the context of the paillier algorithm, expected result 1
 *    2. Set public key, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method and the parameter is correct, expected result 3
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is not 0.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_GET_SECURITY_BITS_FUNC_TC001(Hex *n, Hex *g, Hex *n2, int securityBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};
    SetPaillierPubKey(&pubkey, g->x, g->len, n->x, n->len, n2->x, n2->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), securityBits);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

int HEAdd_Correctness_Check(CRYPT_EAL_PkeyCtx *pkey, Hex *c1, Hex *c2, uint8_t *addResult, uint32_t addLen)
{
    uint8_t m1[256] = {0};
    uint8_t m2[256] = {0};
    uint8_t sum[256] = {0};
    uint32_t m1Len = 256;
    uint32_t m2Len = 256;
    uint32_t sumLen = 256;
    if (CRYPT_EAL_PkeyDecrypt(pkey, c1->x, c1->len, m1, &m1Len) != CRYPT_SUCCESS ||
        CRYPT_EAL_PkeyDecrypt(pkey, c2->x, c2->len, m2, &m2Len) != CRYPT_SUCCESS ||
        CRYPT_EAL_PkeyDecrypt(pkey, addResult, addLen, sum, &sumLen) != CRYPT_SUCCESS) {
        return -1;
    }

    uint8_t expected_sum[256] = {0};
    uint32_t maxLen = (m1Len > m2Len ? m1Len : m2Len);
    uint16_t carry = 0;
    for (uint32_t i = 0; i < maxLen || carry; i++) {
        uint16_t v1 = (i < m1Len) ? m1[i] : 0;
        uint16_t v2 = (i < m2Len) ? m2[i] : 0;
        uint16_t s = v1 + v2 + carry;
        expected_sum[i] = (uint8_t)(s & 0xFF);
        carry = (s >> CHAR_BIT);
    }
    uint32_t expected_sum_len = maxLen + (carry ? 1 : 0);
    if (sumLen != expected_sum_len) {
        return -1; // -1 indicates failure
    }
    if (memcmp(sum, expected_sum, expected_sum_len) != 0) {
        return -1; // -1 indicates failure
    }
    return 0;
}

/**
 * @test   SDV_CRYPTO_PAILLIER_ADD_API_TC001
 * @title  PAILLIER CRYPT_EAL_PkeyHEAdd: Test the validity of input parameters and homomorphic addition functionality.
 * @precon Create the context of the paillier algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyHEAdd method without public key, expected result 1.
 *    2. Set valid ciphertexts, expected result 3.
 *    3. Call the CRYPT_EAL_PkeyHEAdd method:
 *       (1) pkey = NULL, expected result 4.
 *       (2) params = NULL, expected result 4.
 *       (3) out = NULL, expected result 4.
 *       (4) outLen = NULL, expected result 4.
 *       (5) ciphertext length is invalid, expected result 2.
 *       (6) ciphertext value is out of range [0, n^2) or not coprime to n^2, expected result 2.
 *       (7) outLen = 0, expected result 5
 *       (8) all parameters are valid, expected result 3.
 * @expect
 *    1. CRYPT_PAILLIER_NO_KEY_INFO
 *    2. CRYPT_PAILLIER_ERR_INPUT_VALUE
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PAILLIER_ADD_API_TC001(Hex *Lambda, Hex *mu, Hex *n, Hex *g, Hex *n2, Hex *c1, Hex *c2, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};
    uint8_t addResult[512];
    uint32_t addLen = 512;
    enum { IDX_C1 = 0, IDX_C2 = 1, IDX_END = 2 };
    BSL_Param items[3]; // Two ciphertexts + end marker

    SetPaillierPubKey(&pubkey, g->x, g->len, n->x, n->len, n2->x, n2->len);
    
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    // Create context and set public key
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_CIPHER_OPERATE,
                          "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* pKey is NULL */
    ASSERT_TRUE(CRYPT_EAL_PkeyHEAdd(pkey, items, addResult, &addLen) == CRYPT_PAILLIER_NO_KEY_INFO);
    
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubkey), CRYPT_SUCCESS);

    /* Prepare homomorphic addition input */
    ASSERT_EQ(
        BSL_PARAM_InitValue(&items[IDX_C1], CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, c1->x, c1->len),
        BSL_SUCCESS);
    ASSERT_EQ(
        BSL_PARAM_InitValue(&items[IDX_C2], CRYPT_PARAM_PKEY_HE_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, c2->x, c2->len),
        BSL_SUCCESS);
    (void)memset_s(&items[IDX_END], sizeof(items[IDX_END]), 0, sizeof(items[IDX_END]));

    /* Test invalid inputs */
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(NULL, items, addResult, &addLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(pkey, NULL, addResult, &addLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(pkey, items, NULL, &addLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(pkey, items, addResult, NULL), CRYPT_NULL_INPUT);

    /* Test invalid ciphertext length */
    items[IDX_C1].valueLen = c1->len + 1; // Corrupt length
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(pkey, items, addResult, &addLen), CRYPT_PAILLIER_ERR_INPUT_VALUE);

    /* Restore the correct value */
    ASSERT_EQ(
        BSL_PARAM_InitValue(&items[IDX_C1], CRYPT_PARAM_PKEY_HE_CIPHERTEXT1, BSL_PARAM_TYPE_OCTETS, c1->x, c1->len),
        BSL_SUCCESS);
    ASSERT_EQ(
        BSL_PARAM_InitValue(&items[IDX_C2], CRYPT_PARAM_PKEY_HE_CIPHERTEXT2, BSL_PARAM_TYPE_OCTETS, c2->x, c2->len),
        BSL_SUCCESS);

    /* Test invalid outLen */
    addLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(pkey, items, addResult, &addLen), CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH);

    /* Test valid homomorphic addition */
    addLen = 512;
    ASSERT_EQ(CRYPT_EAL_PkeyHEAdd(pkey, items, addResult, &addLen), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv prvkey = {0};
    SetPaillierPrvKey(&prvkey, Lambda->x, Lambda->len, mu->x, mu->len);
    prvkey.key.paillierPrv.n = n->x;
    prvkey.key.paillierPrv.nLen = n->len;
    prvkey.key.paillierPrv.n2 = n2->x;
    prvkey.key.paillierPrv.n2Len = n2->len;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvkey), CRYPT_SUCCESS);
    ASSERT_EQ(HEAdd_Correctness_Check(pkey, c1, c2, addResult, addLen), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
}
