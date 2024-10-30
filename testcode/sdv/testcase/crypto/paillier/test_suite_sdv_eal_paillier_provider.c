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
#include <pthread.h>
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_bn.h"
#include "eal_pkey_local.h"
#include "stub_replace.h"
#include "crypt_util_rand.h"
#include "crypt_paillier.h"
#include "paillier_local.h"
#include "bn_basic.h"
#include "securec.h"

#include "crypt_encode.h"
/* END_HEADER */

#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
#define CRYPT_EAL_PKEY_CIPHER_OPERATE  1
#define CRYPT_EAL_PKEY_EXCH_OPERATE    2
#define CRYPT_EAL_PKEY_SIGN_OPERATE    4

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

/**
 * @test   SDV_CRYPTO_PAILLIER_GET_PUB_PROVIDER_API_TC001
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
void SDV_CRYPTO_PAILLIER_GET_PUB_PROVIDER_API_TC001(Hex *p, Hex *q, int bits)
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
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
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

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_GET_PRV_PROVIDER_API_TC001
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
void SDV_CRYPTO_PAILLIER_GET_PRV_PROVIDER_API_TC001(Hex *p, Hex *q, int bits)
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

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    /* Missing private key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prvKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    /* lambda = NULL */
    prvKey.key.paillierPrv.lambda = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);
    prvKey.key.paillierPrv.lambda = prvLambda;

    /* lambda != NULL and lambdaLen = 0 */
    prvKey.key.paillierPrv.lambdaLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    prvKey.key.paillierPrv.lambdaLen = 600;

    /* mu = NULL */
    prvKey.key.paillierPrv.mu = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);
    prvKey.key.paillierPrv.mu = prvMu;
    
    /* mu != NULL, muLen = 0 */
    prvKey.key.paillierPrv.muLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    prvKey.key.paillierPrv.muLen = 600;

    /* lambda != NULL, mu != NULL, lambdaLen != 0, muLen != 0 */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PRV_PROVIDER_API_TC001
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
void SDV_CRYPTO_PAILLIER_SET_PRV_PROVIDER_API_TC001(Hex *p, Hex *q, int bits)
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

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);
    pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_PAILLIER);
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
exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_SET_PUB_PROVIDER_API_TC001
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
void SDV_CRYPTO_PAILLIER_SET_PUB_PROVIDER_API_TC001(Hex *p, Hex *q, int bits)
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

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);
    pkey2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

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

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_ENC_PROVIDER_API_TC001
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
void SDV_CRYPTO_PAILLIER_ENC_PROVIDER_API_TC001(Hex *n, Hex *g, Hex *n2, Hex *in)
{
    uint8_t crypt[512];
    uint32_t cryptLen = 512;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};

    SetPaillierPubKey(&pubkey, g->x, g->len, n->x, n->len, n2->x, n2->len);
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default");
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

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_DEC_PROVIDER_API_TC001
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
void SDV_CRYPTO_PAILLIER_DEC_PROVIDER_API_TC001(Hex *Lambda, Hex *mu, Hex *n, Hex *n2, Hex *in)
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

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default");
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
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PAILLIER_GET_SECURITY_BITS_PROVIDER_FUNC_TC001
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
void SDV_CRYPTO_PAILLIER_GET_SECURITY_BITS_PROVIDER_FUNC_TC001(Hex *n, Hex *g, Hex *n2, int securityBits)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};
    SetPaillierPubKey(&pubkey, g->x, g->len, n->x, n->len, n2->x, n2->len);

    TestMemInit();

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_PAILLIER, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), securityBits);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
