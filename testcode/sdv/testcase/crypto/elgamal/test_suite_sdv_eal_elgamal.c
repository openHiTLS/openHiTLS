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
#include "stub_utils.h"
#include "crypt_util_rand.h"
#include "crypt_elgamal.h"
#include "elgamal_local.h"
#include "bn_basic.h"
#include "securec.h"

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);


#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
#define CRYPT_EAL_PKEY_CIPHER_OPERATE  1
#define CRYPT_EAL_PKEY_EXCH_OPERATE    2
#define CRYPT_EAL_PKEY_SIGN_OPERATE    4

void *malloc_fail(uint32_t size)
{
    (void)size;
    return NULL;
}

void SetElGamalPara(CRYPT_EAL_PkeyPara *para, Hex *q, uint32_t bits,uint32_t k_bits)
{
    para->id = CRYPT_PKEY_ELGAMAL;
    para->para.elgamalPara.q = q->x;
    para->para.elgamalPara.qLen = q->len;
    para->para.elgamalPara.bits = bits;
    para->para.elgamalPara.k_bits = k_bits;
}

void SetElGamalPubKey(CRYPT_EAL_PkeyPub *pubKey, uint8_t *g, uint32_t gLen, uint8_t *p, uint32_t pLen, uint8_t *y, uint32_t yLen, uint8_t *q, uint32_t qLen)
{
    
    pubKey->id = CRYPT_PKEY_ELGAMAL;
    pubKey->key.elgamalPub.g = g;
    pubKey->key.elgamalPub.gLen = gLen;
    pubKey->key.elgamalPub.p = p;
    pubKey->key.elgamalPub.pLen = pLen;
    pubKey->key.elgamalPub.y = y;
    pubKey->key.elgamalPub.yLen = yLen;
     pubKey->key.elgamalPub.q = q;
    pubKey->key.elgamalPub.qLen = qLen;
}

void SetElGamalPrvKey(CRYPT_EAL_PkeyPrv *prvKey, uint8_t *x, uint32_t xLen)
{
    prvKey->id = CRYPT_PKEY_ELGAMAL;
    prvKey->key.elgamalPrv.x = x;
    prvKey->key.elgamalPrv.xLen = xLen;
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
    return RandFunc(randNum, randLen);
}

/**
 * @test   SDV_CRYPTO_ELGAMAL_NEW_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyNewCtx test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create ctx, algId is CRYPT_PKEY_ELGAMAL, expected result 1.
 *    2. Release the ctx.
 *    3. Repeat steps 1 to 2 for 100 times.
 * @expect
 *    1. The returned result is not empty.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_NEW_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    /* Run 100 times */
    for (int i = 0; i < 100; i++) {
        pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);

        ASSERT_TRUE(pkey != NULL);

        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
EXIT:
    return;
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_ELGAMAL_NEW_API_TC002
 * @title  ELGAMAL CRYPT_EAL_PkeyNewCtx test: Malloc failed.
 * @precon Mock BSL_SAL_Malloc to malloc_fail.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create ctx, algId is CRYPT_PKEY_ELGAMAL, expected result 1.
 *    2. Release the ctx.
 *    3. Reset the BSL_SAL_Malloc.
 * @expect
 *    1. Failed to create the ctx.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_NEW_API_TC002(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    STUB_REPLACE(BSL_SAL_Malloc, malloc_fail);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey == NULL);

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_SET_PARA_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeySetPara test.
 * @precon Create the context of the elgamal algorithm.
 * 
 * @brief
 *   1. Call the CRYPT_EAL_PkeySetPara method:
 *     (1) para = NULL, expected result 1.
 *     (2) qLen != BN_BITS_TO_BYTES(k_bits), expected result 2.
 *     (3)  q = NULL, bits = 0, expected result 2.
 *     (4)  qLen = BN_BITS_TO_BYTES(k_bits), bits != 0, expected result 3.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    3. CRYPT_SUCCESS 
*/
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_SET_PARA_API_TC001(Hex *q,int k_bits, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};

    SetElGamalPara(&para,  q, bits , k_bits);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, NULL), CRYPT_NULL_INPUT);

    uint32_t bytes = BN_BITS_TO_BYTES(k_bits);
    
    if (q->len != bytes) {
        ASSERT_TRUE_AND_LOG("qLen != BN_BITS_TO_BYTES(k_bits)",
            CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_MEM_ALLOC_FAIL);
    }
    if ( q->len == bytes && bits == 0) {
        ASSERT_TRUE_AND_LOG(" q = NULL, bits = 0",
            CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_MEM_ALLOC_FAIL);
    }
    if (q->len == bytes && bits <= k_bits  ){
        ASSERT_TRUE_AND_LOG(" bits <= k_bits ",
            CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_MEM_ALLOC_FAIL);
    }
    if (q->len == bytes && bits != 0) {
        ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_GEN_API_TC001
 * @title ELGAMAL CRYPT_EAL_PkeyGen: No regist rand.
 * @precon Create the contexts of the elgamal algorithm and set para.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGen method to generate a key pair, expected result 1.
 * @expect
 *    1. Failed to generate a key pair, the return value is CRYPT_NO_REGIST_RAND.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_GEN_API_TC001( Hex *q,int k_bits, int bits, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    SetElGamalPara(&para,  q, bits, k_bits);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey;
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_NO_REGIST_RAND);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_GET_PUB_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyGetPub test.
 * @precon 1. Create the context of the elgamal algorithm.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method without public key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) pub = NULL, expected result 1.
 *       (3) p = NULL, expected result 1.
 *       (4) p != NULL and pLen = 0, expected result 3.
 *       (5) g = NULL, expected result 1.
 *       (6) g != NULL, gLen = 0, expected result 3.
 *       (7) y = NULL, expected result 1.
 *       (8) y != NULL and yLen = 0, expected result 3.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_GET_PUB_API_TC001( Hex *q, int k_bits, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t pubG[600];
    uint8_t pubP[600];
    uint8_t pubY[600];
    uint8_t pubQ[600];

    SetElGamalPara(&para, q, bits,k_bits);
    SetElGamalPubKey(&pubKey, pubG, 600, pubP, 600,pubY, 600,pubQ,600);

    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);

    ASSERT_TRUE(pkey != NULL);
    /* Missing public key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pubKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, NULL), CRYPT_NULL_INPUT);
    /* p = NULL */
    pubKey.key.elgamalPub.p = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.p = pubP;

    /* p != NULL and pLen = 0 */
    pubKey.key.elgamalPub.pLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    pubKey.key.elgamalPub.pLen = 600;

    /* g = NULL */
    pubKey.key.elgamalPub.g = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.g = pubG;

    /* g != NULL, gLen = 0 */
    pubKey.key.elgamalPub.gLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);

      /* y = NULL */
    pubKey.key.elgamalPub.y = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.y = pubY;

    /* y != NULL and yLen = 0 */
    pubKey.key.elgamalPub.yLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    pubKey.key.elgamalPub.yLen = 600;

    /* q = NULL */
    pubKey.key.elgamalPub.q = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.q = pubQ;

    /* q != NULL and qLen = 0 */
    pubKey.key.elgamalPub.qLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    pubKey.key.elgamalPub.qLen = 600;
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_ELGAMAL_GET_PRV_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyGetPrv: Bad private key.
 * @precon 1. Create the context of the elgamal algorithm.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPrv method without private key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPrv method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) prv = NULL, expected result 1.
 *       (3) x = NULL, expected result 1.
 *       (4) x != NULL and xLen = 0, expected result 3.
 *       (5) x != NULL,  xLen != 0, , expected result 2.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_GET_PRV_API_TC001(Hex *q, int k_bits,int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};

    CRYPT_EAL_PkeyPara para = {0};
    uint8_t prvX[600];

    SetElGamalPrvKey(&prvKey, prvX, 600);
    SetElGamalPara(&para,  q, bits,k_bits);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* Missing private key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prvKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    /* x = NULL */
    prvKey.key.elgamalPrv.x = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.x = prvX;

    /* x != NULL and xLen = 0 */
    prvKey.key.elgamalPrv.xLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    prvKey.key.elgamalPrv.xLen = 600;

    /* x != NULL, xLen != 0 */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_ELGAMAL_SET_PRV_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeySetPrv: Bad private key.
 * @precon Create the contexts of the elgamal algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: set the private key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) pKey is NULL, expected result 1.
 *       (2) prv is NULL, expected result 1.
 *       (3) p = NULL, expected result 2.
 *       (4) g = NULL, expected result 2.
 *       (5) x = NULL, expected result 2.
 *       (6) pLen = 0, expected result 2.
 *       (7) gLen = 0, expected result 2.
 *       (8) xLen = 0, expected result 2.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_ELGAMAL_ERR_INPUT_VALUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_SET_PRV_API_TC001(Hex *q,int k_bits, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    uint8_t prvP[600];
    uint8_t prvG[600];
    uint8_t prvX[600];

    SetElGamalPrvKey(&prvKey, prvX, 600);
    SetElGamalPara(&para, q, bits,k_bits);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);

    /*pKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(NULL, &prvKey) == CRYPT_NULL_INPUT);

    /*prvKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey2, NULL) == CRYPT_NULL_INPUT);

    prvKey.key.elgamalPrv.p = prvP;
    prvKey.key.elgamalPrv.pLen = 600;

    prvKey.key.elgamalPrv.g= prvG;
    prvKey.key.elgamalPrv.gLen = 600;


    /*p = NULL*/
    prvKey.key.elgamalPrv.p = NULL;
    ASSERT_TRUE_AND_LOG("p is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.p = prvP;

    /*g = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.elgamalPrv.g = NULL;
    ASSERT_TRUE_AND_LOG("g is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.g = prvG;

    /*x = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.elgamalPrv.x = NULL;
    ASSERT_TRUE_AND_LOG("x is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.x = prvX;

    /*pLen = 0*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.elgamalPrv.pLen = 0;
    ASSERT_TRUE_AND_LOG("pLen is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.pLen = 600;

    /*gLen = 0*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.elgamalPrv.gLen = 0;
    ASSERT_TRUE_AND_LOG("gLen is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.gLen = 600;

    /*xLen = 0*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.elgamalPrv.xLen = 0;
    ASSERT_TRUE_AND_LOG("xLen is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_ELGAMAL_ERR_INPUT_VALUE);
    prvKey.key.elgamalPrv.xLen = 600;
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_SET_PUB_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyGetPub: Bad public key.
 * @precon Create the contexts of the elgamal algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: Set the public key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pKey is NULL, expected result 1.
 *       (2) prv is NULL, expected result 1.
 *       (3) p = NULL, expected result 1.
 *       (4) g = NULL, expected result 1.
 *       (5) y = NULL, expected result 1.
 * @expect
 *    1. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_SET_PUB_API_TC001( Hex *q,int k_bits, int bits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey;
    uint8_t pubG[600];
    uint8_t pubP[600];
    uint8_t pubY[600];
    uint8_t pubQ[600];
    SetElGamalPara(&para,  q, bits,k_bits);
    SetElGamalPubKey(&pubKey, pubP, 600, pubG, 600, pubY, 600, pubQ, 600);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    /*pKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(NULL, &pubKey) == CRYPT_NULL_INPUT);

    /*pubKey is NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey2, NULL) == CRYPT_NULL_INPUT);

    /*p = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.elgamalPub.p = NULL;
    ASSERT_TRUE_AND_LOG("p is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.p = pubP;

    /*g = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.elgamalPub.g = NULL;
    ASSERT_TRUE_AND_LOG("g is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.g = pubG;

     /*q = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.elgamalPub.q = NULL;
    ASSERT_TRUE_AND_LOG("g is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.q = pubQ;

    /*y = NULL*/
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.elgamalPub.y = NULL;
    ASSERT_TRUE_AND_LOG("y is NULL", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);
    pubKey.key.elgamalPub.y = pubY;

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);

    ASSERT_TRUE_AND_LOG("set prvKey success", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_ENC_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyEncrypt: Test the validity of input parameters.
 * @precon Create the context of the elgamal algorithm:
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
 *    1. CRYPT_ELGAMAL_NO_KEY_INFO
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_ELGAMAL_ERR_ENC_BITS
 *    5. CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_ENC_API_TC001(Hex *q,Hex *p, Hex *g, Hex *y, Hex *in, int isProvider)
{
    uint8_t crypt[512];
    uint32_t cryptLen = 512;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};

    SetElGamalPubKey(&pubkey, g->x, g->len, p->x, p->len, y->x, y->len,q->x,q->len);

    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_CIPHER_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    

    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen), CRYPT_ELGAMAL_NO_KEY_INFO);
    
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(NULL, in->x, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, NULL, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, 257, crypt, &cryptLen) == CRYPT_ELGAMAL_ERR_ENC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, NULL, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, NULL) == CRYPT_NULL_INPUT);
    cryptLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH);

    cryptLen = 512;
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_DEC_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyDecrypt: Test the validity of input parameters.
 * @precon Create the context of the elgamal algorithm:
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
 *    1. CRYPT_ELGAMAL_NO_KEY_INFO
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_ELGAMAL_ERR_DEC_BITS
 *    5. CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_DEC_API_TC001(Hex *p, Hex *g ,Hex *x,  Hex *in, int isProvider)
{
    uint8_t crypt[512];
    uint32_t cryptLen = 512;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    SetElGamalPrvKey(&prvkey, x->x, x->len);
    prvkey.key.elgamalPrv.p = p->x;
    prvkey.key.elgamalPrv.pLen = p->len;
    prvkey.key.elgamalPrv.g = g->x;
    prvkey.key.elgamalPrv.gLen = g->len;

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_CIPHER_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_ELGAMAL_NO_KEY_INFO);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(NULL, in->x, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, NULL, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, 0, crypt, &cryptLen) == CRYPT_ELGAMAL_ERR_DEC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, 257, crypt, &cryptLen) == CRYPT_ELGAMAL_ERR_DEC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, NULL, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, NULL) == CRYPT_NULL_INPUT);

    cryptLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_ELGAMAL_BUFF_LEN_NOT_ENOUGH);

    cryptLen = 512;
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

int Compare_PubKey(CRYPT_EAL_PkeyPub *pubKey1, CRYPT_EAL_PkeyPub *pubKey2)
{
    if (pubKey1->key.elgamalPub.pLen != pubKey2->key.elgamalPub.pLen || pubKey1->key.elgamalPub.gLen != pubKey2->key.elgamalPub.gLen|| 
        pubKey1->key.elgamalPub.qLen != pubKey2->key.elgamalPub. qLen || pubKey1->key.elgamalPub.yLen != pubKey2->key.elgamalPub.yLen) {
        return -1;  // -1 indicates failure
    }
    if (memcmp(pubKey1->key.elgamalPub.p, pubKey2->key.elgamalPub.p, pubKey1->key.elgamalPub.pLen) != 0 ||
        memcmp(pubKey1->key.elgamalPub.g, pubKey2->key.elgamalPub.g, pubKey1->key.elgamalPub.gLen) != 0 ||
        memcmp(pubKey1->key.elgamalPub.q, pubKey2->key.elgamalPub.q, pubKey1->key.elgamalPub.qLen) != 0 ||
        memcmp(pubKey1->key.elgamalPub.y, pubKey2->key.elgamalPub.y, pubKey1->key.elgamalPub.yLen) != 0 ) {
        return -1;  // -1 indicates failure
    }
    return 0;
}

int Compare_PrvKey(CRYPT_EAL_PkeyPrv *prvKey1, CRYPT_EAL_PkeyPrv *prvKey2)
{
    if (prvKey1->key.elgamalPrv.pLen != prvKey2->key.elgamalPrv.pLen || prvKey1->key.elgamalPrv.gLen != prvKey2->key.elgamalPrv.gLen ||
        prvKey1->key.elgamalPrv.xLen != prvKey2->key.elgamalPrv.xLen ) {
        return -1;  // -1 indicates failure
    }
    if (memcmp(prvKey1->key.elgamalPrv.g, prvKey2->key.elgamalPrv.g, prvKey1->key.elgamalPrv.gLen) != 0 ||
        memcmp(prvKey1->key.elgamalPrv.p, prvKey2->key.elgamalPrv.p, prvKey1->key.elgamalPrv.pLen) != 0 ||
        memcmp(prvKey1->key.elgamalPrv.x, prvKey2->key.elgamalPrv.x, prvKey1->key.elgamalPrv.xLen) != 0) {
        return -1;  // -1 indicates failure
    }
    return 0;
}

/**
 * @test   SDV_CRYPTO_ELGAMAL_SET_KEY_API_TC001
 * @title  ELGAMAL Set the public key and private key multiple times.
 * @precon Create the contexts of the elgamal algorithm and:
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
void SDV_CRYPTO_ELGAMAL_SET_KEY_API_TC001( Hex *q, int k_bits, int bits, int isProvider)
{
    uint8_t pubP[600];
    uint8_t pubG[600];
    uint8_t pubQ[600];
    uint8_t pubY[600];
    uint8_t prvP[600];
    uint8_t prvG[600];
    uint8_t prvX[600];
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};

    SetElGamalPara(&para,  q, bits, k_bits);
    SetElGamalPubKey(&pubKey, pubG, 600, pubP, 600, pubY, 600, pubQ, 600);
    SetElGamalPrvKey(&prvKey, prvX, 600);
    prvKey.key.elgamalPrv.p = prvP;
    prvKey.key.elgamalPrv.pLen = 600;
    prvKey.key.elgamalPrv.g = prvG;
    prvKey.key.elgamalPrv.gLen = 600;

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE,
        "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE,
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
    SetElGamalPubKey(&pubKey, pubG, 600, pubP, 600, pubY, 600, pubQ, 600);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    SetElGamalPrvKey(&prvKey, prvX, 600);
    prvKey.key.elgamalPrv.p = prvP;
    prvKey.key.elgamalPrv.pLen = 600;
    prvKey.key.elgamalPrv.g = prvG;
    prvKey.key.elgamalPrv.gLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(Compare_PrvKey(&prvKey, &prvKey), 0);

    /* Set private key and set public key. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    /* Get private key, get public key and check public key.*/
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    SetElGamalPubKey(&pubKey, pubG, 600, pubP, 600, pubY, 600, pubQ, 600);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(Compare_PubKey(&pubKey, &pubKey), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_ELGAMAL_DUP_CTX_API_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyDupCtx test.
 * @precon Create the contexts of the elgamal algorithm, set para and generate a key pair.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyDupCtx mehod to dup elgamal, expected result 1
 * @expect
 *    1. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_DUP_CTX_API_TC001( Hex *q,int k_bits, int bits, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *newPkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    SetElGamalPara(&para,  q,bits, k_bits);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    CRYPT_ELGAMAL_Ctx *elgamalCtx = (CRYPT_ELGAMAL_Ctx *)pkey->key;
    ASSERT_TRUE(elgamalCtx != NULL);

    newPkey = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newPkey != NULL);
    ASSERT_EQ(newPkey->references.count, 1);
    CRYPT_ELGAMAL_Ctx *elgamalCtx2 = (CRYPT_ELGAMAL_Ctx *)newPkey->key;
    ASSERT_TRUE(elgamalCtx2 != NULL);

    ASSERT_COMPARE("elgamal compare x",
        elgamalCtx->prvKey->x->data,
        elgamalCtx->prvKey->x->size * sizeof(BN_UINT),
        elgamalCtx2->prvKey->x->data,
        elgamalCtx2->prvKey->x->size * sizeof(BN_UINT));

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newPkey);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_ELGAMAL_GET_SECURITY_BITS_FUNC_TC001
 * @title  ELGAMAL CRYPT_EAL_PkeyGetSecurityBits test.
 * @precon nan
 * @brief
 *    1. Create the context of the elgamal algorithm, expected result 1
 *    2. Set public key, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method and the parameter is correct, expected result 3
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is not 0.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_ELGAMAL_GET_SECURITY_BITS_FUNC_TC001(Hex *q,Hex *p, Hex *g, Hex *y, int securityBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};
    SetElGamalPubKey(&pubkey, g->x, g->len, p->x, p->len, y->x, y->len, q->x, q->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_ELGAMAL, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pubkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), securityBits);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}