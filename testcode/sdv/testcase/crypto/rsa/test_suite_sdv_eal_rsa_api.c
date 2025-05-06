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
/* INCLUDE_BASE test_suite_sdv_eal_rsa */

/* BEGIN_HEADER */
#include "bsl_params.h"
#include "bsl_err.h"
#include "crypt_params_key.h"

/* END_HEADER */
#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
/**
 * @test   SDV_CRYPTO_RSA_NEW_API_TC001
 * @title  RSA CRYPT_EAL_PkeyNewCtx test.
 * @precon nan
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create ctx, algId is CRYPT_PKEY_RSA, expected result 1.
 *    2. Release the ctx.
 *    3. Repeat steps 1 to 2 for 100 times.
 * @expect
 *    1. The returned result is not empty.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_NEW_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    /* Run 100 times */
    for (int i = 0; i < 100; i++) {
        pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
        ASSERT_TRUE(pkey != NULL);

        CRYPT_EAL_PkeyFreeCtx(pkey);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_NEW_API_TC002
 * @title  RSA CRYPT_EAL_PkeyNewCtx test: Malloc failed.
 * @precon Mock BSL_SAL_Malloc to malloc_fail.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyNewCtx method to create ctx, algId is CRYPT_PKEY_RSA, expected result 1.
 *    2. Release the ctx.
 *    3. Reset the BSL_SAL_Malloc.
 * @expect
 *    1. Failed to create the ctx.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_NEW_API_TC002(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    FuncStubInfo tmpRpInfo = {0};

    STUB_Init();
    ASSERT_TRUE(STUB_Replace(&tmpRpInfo, BSL_SAL_Malloc, malloc_fail) == 0);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey == NULL);

EXIT:
    STUB_Reset(&tmpRpInfo);
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_PARA_API_TC001
 * @title  RSA CRYPT_EAL_PkeySetPara: The e value of para is invalid.
 * @precon Create the contexts of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPara method:
 *       (1) e = NULL, expected result 1.
 *       (2) e len = 0, expected result 1.
 *       (3) e = 0, expected result 2.
 *       (4) e is even, expected result 2.
 *       (5) e len = 1025, expected result 1.
 * @expect
 *    1. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    2. CRYPT_RSA_ERR_E_VALUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_PARA_API_TC001(int isProvider)
{
    uint8_t e[] = {1, 0, 1};
    uint8_t e2[] = {1, 0};
    uint8_t e0[] = {0, 0, 0};
    uint8_t longE[1025] = {0};
    longE[0] = 0x01;
    longE[1024] = 0x01;  // The tail of 1024 is set to 1.
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    SetRsaPara(&para, e, 3, 1024);  // bits: 1024 is valid

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    para.para.rsaPara.e = NULL;
    ASSERT_TRUE_AND_LOG("e = NULL", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.rsaPara.eLen = 0;
    ASSERT_TRUE_AND_LOG("e len = 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.rsaPara.e = e0;
    para.para.rsaPara.eLen = 1;
    ASSERT_TRUE_AND_LOG("e = 0", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_RSA_ERR_E_VALUE);

    para.para.rsaPara.eLen = 2;
    para.para.rsaPara.e = e2;
    ASSERT_TRUE_AND_LOG("e is even", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_RSA_ERR_E_VALUE);

    para.para.rsaPara.eLen = 1025;  // 1025 is invalid, but the length is sufficient.
    para.para.rsaPara.e = longE;
    ASSERT_TRUE_AND_LOG("e len = 1025", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_PARA_API_TC002
 * @title  RSA CRYPT_EAL_PkeySetPara: The bits value of para is invalid.
 * @precon Create the contexts of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPara method with invalid bits, expected result 1.
 * @expect
 *    1. CRYPT_EAL_ERR_NEW_PARA_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_PARA_API_TC002(int bits, int isProvider)
{
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};

    SetRsaPara(&para, e, 3, bits);  // eLen = 3

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_EAL_ERR_NEW_PARA_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_PARA_API_TC003
 * @title  RSA CRYPT_EAL_PkeySetPara: Success.
 * @precon Create the contexts of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPara method, key len is 1024|1025|5120|16384 bits, expected result 1.
 * @expect
 *    1. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_PARA_API_TC003(int isProvider)
{
    uint8_t e3[] = {1, 0, 1};
    uint8_t e5[] = {1, 0, 0, 0, 1};
    uint8_t e7[] = {1, 0, 0, 0, 0, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_SIGN_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    SetRsaPara(&para, e3, 3, 1024);  // Valid parameters: elen = 3, bits =1024
    ASSERT_TRUE_AND_LOG("1k key", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    para.para.rsaPara.bits = 1025;
    ASSERT_TRUE_AND_LOG("1025 bits key", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    SetRsaPara(&para, e5, 5, 5120);
    ASSERT_TRUE_AND_LOG("5k key", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    SetRsaPara(&para, e7, 7, 16384);
    ASSERT_TRUE_AND_LOG("16k key", CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GEN_API_TC001
 * @title  RSA CRYPT_EAL_PkeyGen: No regist rand.
 * @precon Create the contexts of the rsa algorithm and set para.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGen method to generate a key pair, expected result 1.
 * @expect
 *    1. Failed to genrate a key pair, the return value is CRYPT_NO_REGIST_RAND.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_API_TC001(int isProvider)
{
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};

    SetRsaPara(&para, e, 3, 1024);  // Valid parameters: elen = 3, bits =1024

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_NO_REGIST_RAND);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GET_PUB_API_TC001
 * @title  RSA CRYPT_EAL_PkeyGetPub test.
 * @precon 1. Create the context of the rsa algorithm.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method without public key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) pub = NULL, expected result 1.
 *       (3) n = NULL, expected result 1.
 *       (4) n != NULL and nLen = 0, expected result 3.
 *       (5) e = NULL, expected result 1.
 *       (6) e != NULL, eLen = 0, expected result 3.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GET_PUB_API_TC001(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t pubE[600];
    uint8_t pubN[600];

    SetRsaPara(&para, e, 3, 1024);
    SetRsaPubKey(&pubKey, pubE, 600, pubN, 600);  // 600 bytes > 1024 bits

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* Missing public key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pubKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, NULL), CRYPT_NULL_INPUT);

    /* n = NULL */
    pubKey.key.rsaPub.n = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.rsaPub.n = pubN;

    /* n != NULL and nLen = 0 */
    pubKey.key.rsaPub.nLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    pubKey.key.rsaPub.nLen = 600;

    /* e = NULL */
    pubKey.key.rsaPub.e = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.rsaPub.e = pubE;

    /* e != NULL, eLen = 0 */
    pubKey.key.rsaPub.eLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GET_PRV_API_TC001
 * @title  RSA CRYPT_EAL_PkeyGetPrv: Bad private key.
 * @precon 1. Create the context of the rsa algorithm.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPrv method without private key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPrv method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) prv = NULL, expected result 1.
 *       (3) p = NULL and q = NULL, expected result 2.
 *       (4) p = NULL and q != NULL, expected result 1.
 *       (5) p != NULL and q != NULL, expected result 2.
 *       (6) d = NULL, expected result 1.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GET_PRV_API_TC001(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};

    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t prvD[600];
    uint8_t prvN[600];
    uint8_t prvP[600];
    uint8_t prvQ[600];

    SetRsaPrvKey(&prvKey, prvN, 600, prvD, 600);
    SetRsaPara(&para, e, 3, 1024);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    /* Missing private key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prvKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    /* p is NULL and q is NULL */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    /* p = NULL and q != NULL */
    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    /* p != NULL and q != NULL */
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    /* d = NULL */
    prvKey.key.rsaPrv.d = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PRV_API_TC001
 * @title  RSA CRYPT_EAL_PkeySetPrv: Bad private key.
 * @precon Create the contexts of the rsa algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: set the private key.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) d is 0, expected result 1.
 *       (2) d is 1, expected result 1.
 *       (3) n is 0, expected result 2.
 *       (4) p is 0, expected result 1.
 *       (5) q is 0, expected result 1.
 *       (6) nLen is 2049, expected result 2.
 *       (7) p is null, expected result 3.
 * @expect
 *    1. CRYPT_RSA_ERR_INPUT_VALUE
 *    2. CRYPT_RSA_ERR_KEY_BITS
 *    3. CRYPT_RSA_NO_KEY_INFO
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PRV_API_TC001(int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t prvD[600];
    uint8_t prvN[2500];
    uint8_t prvP[600];
    uint8_t prvQ[600];
    uint8_t prvE[600];

    SetRsaPrvKey(&prvKey, prvN, 600, prvD, 600);
    SetRsaPara(&para, e, 3, 1024);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);

    (void)memset_s(prvD, sizeof(prvD), 0x00, sizeof(prvD));
    ASSERT_TRUE_AND_LOG("d is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    prvD[sizeof(prvD) - 1] = 1;
    ASSERT_TRUE_AND_LOG("d is 1", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    (void)memset_s(prvN, sizeof(prvN), 0x00, sizeof(prvN));
    ASSERT_TRUE_AND_LOG("n is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_ERR_KEY_BITS);

    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;  // 600 bytes > 1024 bits
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;  // 600 bytes > 1024 bits

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    (void)memset_s(prvP, sizeof(prvP), 0x00, sizeof(prvP));
    ASSERT_TRUE_AND_LOG("p is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    (void)memset_s(prvQ, sizeof(prvQ), 0x00, sizeof(prvQ));
    ASSERT_TRUE_AND_LOG("q is 0", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.rsaPrv.nLen = 2049;  // 2049 > MAx n len
    ASSERT_TRUE_AND_LOG("nLen is 2049", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_ERR_KEY_BITS);

    prvKey.key.rsaPrv.nLen = 600;  // 600 bytes > 1024 bits
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
    prvKey.key.rsaPrv.p = NULL;
    ASSERT_TRUE_AND_LOG("p is NULL", CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_RSA_NO_KEY_INFO);
    prvKey.key.rsaPrv.p = prvP;

    prvKey.key.rsaPrv.e = prvE;
    prvKey.key.rsaPrv.eLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);
    ASSERT_COMPARE("rsa e", prvKey.key.rsaPrv.e, prvKey.key.rsaPrv.eLen, e, 3);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey2, &prvKey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey) == CRYPT_SUCCESS);
    ASSERT_COMPARE("rsa e", prvKey.key.rsaPrv.e, prvKey.key.rsaPrv.eLen, e, 3);
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PRV_API_TC002
 * @title  RSA CRYPT_EAL_PkeySetPrv: Specification test.
 * @precon Create the context(pkey) of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPrv method:
 *       (1) d = n, expected result 1
 *       (2) n less than 1024 bits, expected result 2
 *       (3) n greater than 16384 bits, expected result 2
 *       (4) d greater than 16384 bits, expected result 2
 *       (5) d greater than n, expected result 2
 *       (6) Min len success case, expected result 3
 *       (7) Max len success case, expected result 3
 * @expect
 *    1. CRYPT_RSA_ERR_INPUT_VALUE
 *    2. CRYPT_RSA_ERR_KEY_BITS
 *    3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PRV_API_TC002(int isProvider)
{
    uint8_t prvD[2050];  // max rsa key len is 16384 bits, 16384/8 = 2048, 2050 > 2048
    uint8_t prvN[2050];  // max rsa key len is 16384 bits, 16384/8 = 2048, 2050 > 2048
    CRYPT_EAL_PkeyPrv prvKey = {0};

    (void)memset_s(prvD, sizeof(prvD), 0xff, sizeof(prvD));
    (void)memset_s(prvN, sizeof(prvN), 0xff, sizeof(prvN));
    SetRsaPrvKey(&prvKey, prvN, RSA_MIN_KEYLEN, prvD, RSA_MIN_KEYLEN);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE_AND_LOG("d = n", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    prvKey.key.rsaPrv.nLen = RSA_MIN_KEYLEN - 1;
    ASSERT_TRUE_AND_LOG("n less than 1024 bits", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_RSA_ERR_KEY_BITS);

    prvKey.key.rsaPrv.nLen = RSA_MAX_KEYLEN + 1;
    ASSERT_TRUE_AND_LOG("n greater than 16384 bits", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_RSA_ERR_KEY_BITS);

    prvKey.key.rsaPrv.nLen = RSA_MAX_KEYLEN;
    prvKey.key.rsaPrv.dLen = RSA_MAX_KEYLEN + 1;
    ASSERT_TRUE_AND_LOG("d greater than 16384 bits", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_RSA_ERR_KEY_BITS);

    prvKey.key.rsaPrv.nLen = RSA_MIN_KEYLEN;
    prvKey.key.rsaPrv.dLen = RSA_MIN_KEYLEN + 1;
    ASSERT_TRUE_AND_LOG("d greater than n", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_RSA_ERR_KEY_BITS);

    prvKey.key.rsaPrv.dLen = RSA_MIN_KEYLEN;
    prvD[0] = 0;
    ASSERT_TRUE_AND_LOG("Min len success case", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_SUCCESS);

    prvKey.key.rsaPrv.nLen = RSA_MAX_KEYLEN;
    prvKey.key.rsaPrv.dLen = RSA_MAX_KEYLEN;
    ASSERT_TRUE_AND_LOG("Max len success case", CRYPT_EAL_PkeySetPrv(pkey, &prvKey) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PUB_API_TC001
 * @title  RSA CRYPT_EAL_PkeyGetPub: Bad public key.
 * @precon Create the contexts of the rsa algorithm and set para:
 *         pkey1: Generate a key pair.
 *         pkey2: Set the public key..
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) nLen > maxNLen, expected result 1
 *       (2) n is Null, expected result 2
 *       (3) n is 0, expected result 1
 *       (4) e is NULL, expected result 2
 *       (5) e is 0, expected result 3
 * @ex   pect
 *    1. CRYPT_RSA_ERR_KEY_BITS
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_RSA_ERR_INPUT_VALUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PUB_API_TC001(int isProvider)
{
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey;
    uint8_t pubE[600];
    uint8_t pubN[2500];
    SetRsaPara(&para, e, 3, 1024);
    SetRsaPubKey(&pubKey, pubN, 600, pubE, 600);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL && pkey2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey2, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.rsaPub.nLen = 2049;
    ASSERT_TRUE_AND_LOG("nLen > maxNLen", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    pubKey.key.rsaPub.nLen = 600;  // 600 bytes > 1024 bits

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.rsaPub.n = NULL;
    ASSERT_TRUE_AND_LOG("n is Null", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);

    pubKey.key.rsaPub.n = pubN;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    (void)memset_s(pubN, sizeof(pubN), 0x00, sizeof(pubN));
    ASSERT_TRUE_AND_LOG("n is 0", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    pubKey.key.rsaPub.e = NULL;
    ASSERT_TRUE_AND_LOG("e is Null", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_NULL_INPUT);

    pubKey.key.rsaPub.e = pubE;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(pkey, &pubKey) == CRYPT_SUCCESS);
    (void)memset_s(pubE, sizeof(pubE), 0x00, sizeof(pubE));
    ASSERT_TRUE_AND_LOG("e is 0", CRYPT_EAL_PkeySetPub(pkey2, &pubKey) == CRYPT_RSA_ERR_INPUT_VALUE);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PUB_API_TC002
 * @title  RSA CRYPT_EAL_PkeySetPub: Specification test.
 * @precon Create the context(pkey) of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPub method:
 *       (1) e = n, expected result 1
 *       (2) nLen < 1024 bits, expected result 2
 *       (3) eLen > 16384 bits, expected result 2
 *       (3) nLen > 16384 bits, expected result 2
 *       (4) e > n, expected result 2
 *       (6) Min len success case, expected result 3
 *       (7) Max len success case, expected result 3
 *       (8) e = 1, expected result 1
 *       (9) n = 1, expected result 1
 * @expect
 *    1. CRYPT_RSA_ERR_INPUT_VALUE
 *    2. CRYPT_RSA_ERR_KEY_BITS
 *    3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PUB_API_TC002(int isProvider)
{
    uint8_t pubE[2050];  // max rsa key len is 16384 bits, 16384/8 = 2048, 2050 > 2048
    uint8_t pubN[2050];  // max rsa key len is 16384 bits, 16384/8 = 2048, 2050 > 2048
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubKey = {0};

    SetRsaPubKey(&pubKey, pubN, RSA_MIN_KEYLEN, pubE, RSA_MIN_KEYLEN);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    (void)memset_s(pubE, sizeof(pubE), 0xff, sizeof(pubE));
    (void)memset_s(pubN, sizeof(pubN), 0xff, sizeof(pubN));
    ASSERT_TRUE_AND_LOG("e = n", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    pubKey.key.rsaPub.nLen = RSA_MIN_KEYLEN - 1;
    ASSERT_TRUE_AND_LOG("n less than 1024 bits", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    pubKey.key.rsaPub.nLen = RSA_MAX_KEYLEN;
    pubKey.key.rsaPub.eLen = RSA_MAX_KEYLEN + 1;
    ASSERT_TRUE_AND_LOG("e greater than 16384 bits", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    pubKey.key.rsaPub.nLen = RSA_MAX_KEYLEN + 1;
    pubKey.key.rsaPub.eLen = RSA_MAX_KEYLEN;
    ASSERT_TRUE_AND_LOG("n greater than 16384 bits", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    pubKey.key.rsaPub.nLen = RSA_MIN_KEYLEN;
    pubKey.key.rsaPub.eLen = RSA_MIN_KEYLEN + 1;
    ASSERT_TRUE_AND_LOG("e greater than n", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    pubE[0] = 0;
    pubKey.key.rsaPub.eLen = RSA_MIN_KEYLEN;
    ASSERT_TRUE_AND_LOG("Min len success case", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_SUCCESS);

    pubKey.key.rsaPub.nLen = RSA_MAX_KEYLEN;
    pubKey.key.rsaPub.eLen = RSA_MAX_KEYLEN;
    ASSERT_TRUE_AND_LOG("Max len failed case", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_KEY_BITS);

    (void)memset_s(pubE, sizeof(pubE), 0, sizeof(pubE));
    ASSERT_TRUE_AND_LOG("e = 0", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_INPUT_VALUE);

    pubE[RSA_MAX_KEYLEN - 1] = 1;
    ASSERT_TRUE_AND_LOG("e = 1", CRYPT_EAL_PkeySetPub(pkey, &pubKey) == CRYPT_RSA_ERR_INPUT_VALUE);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_ENC_API_TC001
 * @title  RSA CRYPT_EAL_PkeyEncrypt: Test the validity of input parameters.
 * @precon Create the context of the rsa algorithm:
 * @brief
 *    1. Call the CRYPT_EAL_PkeyEncrypt method without public key, expected result 1
 *    2. Set pubkey and call the CRYPT_EAL_PkeyEncrypt method, expected result 2
 *    3. Set the oaep paading mode, expected result 3
 *    4. Call the CRYPT_EAL_PkeyEncrypt method:
 *       (1) pkey = NULL, expected result 4
 *       (2) data = NULL, expected result 4
 *       (3) data != NULL, dataLen = 0, expected result 3
 *       (4) data != NULL dataLen > k - 2*hashLen - 2, expected result 5
 *       (5) out = NULL, expected result 4
 *       (6) outLen = NULL, expected result 4
 *       (7) outLen = 0, expected result 6
 * @expect
 *    1. CRYPT_RSA_NO_KEY_INFO
 *    2. CRYPT_RSA_PAD_NO_SET_ERROR
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_RSA_ERR_ENC_BITS
 *    6. CRYPT_RSA_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_ENC_API_TC001(Hex *n, Hex *e, int hashId, Hex *in, int isProvider)
{
    uint8_t crypt[TMP_BUFF_LEN];
    uint32_t cryptLen = TMP_BUFF_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pubkey = {0};
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};

    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_CIPHER_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen), CRYPT_RSA_NO_KEY_INFO);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_RSA_PAD_NO_SET_ERROR);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(NULL, in->x, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, NULL, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, in->x, 0, crypt, &cryptLen), CRYPT_SUCCESS);
    // inLen > k-2hashLen-2 , 87 = (128 - 2 * 20 - 2)
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, 87, crypt, &cryptLen) == CRYPT_RSA_ERR_ENC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, NULL, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, NULL) == CRYPT_NULL_INPUT);
    cryptLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_DEC_API_TC001
 * @title  RSA CRYPT_EAL_PkeyDecrypt: Test the validity of input parameters.
 * @precon Create the context of the rsa algorithm:
 * @brief
 *    1. Call the CRYPT_EAL_PkeyDecrypt method without private key, expected result 1
 *    2. Set private and call the CRYPT_EAL_PkeyDecrypt method, expected result 2
 *    3. Set the oaep paading mode, expected result 3
 *    4. Call the CRYPT_EAL_PkeyDecrypt method:
 *       (1) pkey = NULL, expected result 4
 *       (2) data = NULL, expected result 4
 *       (3) data != NULL, dataLen = 0, expected result 3
 *       (4) data != NULL, dataLen iis invalid , expected result 5
 *       (5) out = NULL, expected result 4
 *       (6) outLen = NULL, expected result 4
 *       (7) outLen = 0, expected result 6
 *       (8) outLen = 2049(invalid), expected result 6
 * @expect
 *    1. CRYPT_RSA_NO_KEY_INFO
 *    2. CRYPT_RSA_PAD_NO_SET_ERROR
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_RSA_ERR_DEC_BITS
 *    6. CRYPT_RSA_ERR_INPUT_VALUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_DEC_API_TC001(Hex *n, Hex *d, int hashId, Hex *in, int isProvider)
{
    uint8_t crypt[TMP_BUFF_LEN];
    uint32_t cryptLen = TMP_BUFF_LEN;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Param oaepParam[3] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &hashId, sizeof(hashId), 0},
        BSL_PARAM_END};
    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE + CRYPT_EAL_PKEY_CIPHER_OPERATE,
        "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_RSA_NO_KEY_INFO);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen), CRYPT_RSA_PAD_NO_SET_ERROR);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaepParam, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(NULL, in->x, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, NULL, in->len, crypt, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, 0, crypt, &cryptLen) == CRYPT_RSA_ERR_DEC_BITS);
    const uint32_t invalidInLen = 1025;  // 1025: invalid data length
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, invalidInLen, crypt, &cryptLen) == CRYPT_RSA_ERR_DEC_BITS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, NULL, &cryptLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, NULL) == CRYPT_NULL_INPUT);

    cryptLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_RSA_ERR_INPUT_VALUE);
    cryptLen = 2049;  // 2049 is an invalid data length.
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, in->x, in->len, crypt, &cryptLen) == CRYPT_RSA_ERR_INPUT_VALUE);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_CTRL_API_TC001
 * @title  Rsa CRYPT_EAL_PkeyCtrl test.
 * @precon  Create the context of the rsa algorithm and set the private key(n, d).
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CTRL_API_TC001(Hex *n, Hex *d, Hex *salt, int hashId, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    int32_t pssSaltLen = salt->len;
    int32_t pssMdId = hashId;
    int32_t pssMgfId = hashId;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssMdId, sizeof(pssMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssMgfId, sizeof(pssMgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &pssSaltLen, sizeof(pssSaltLen), 0},
        BSL_PARAM_END};
    int32_t pkcsv15 = hashId;
    uint8_t badSalt[2500];
    (void)memset_s(badSalt, sizeof(badSalt), 'A', sizeof(badSalt));
    const uint32_t badSaltLen = 2500;  // 2500 is greater than the maximum length.

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);
    TestMemInit();
    CRYPT_RandRegist(STUB_ReplaceRandom);
    CRYPT_RandRegistEx(STUB_ReplaceRandomEx);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvkey), CRYPT_SUCCESS);

    // OAEP The parameter is a null pointer.
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, NULL, 0), CRYPT_NULL_INPUT);

    // PKCS1.5 The parameter is a null pointer.
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, NULL, sizeof(pkcsv15)), CRYPT_NULL_INPUT);
    // PKCS1.5 The parameter length is 0.
    ASSERT_EQ(
        CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, 0), CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, NULL, 0), CRYPT_NULL_INPUT);

    /* PSS saltLen: - 1 - 2 - 3 0 are valid values, -4 is invalid. */
    pssSaltLen = -4;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_RSA_ERR_SALT_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, salt->x, salt->len), CRYPT_RSA_SET_SALT_NOT_PSS_ERROR);
    pssSaltLen = salt->len;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, badSalt, badSaltLen), CRYPT_RSA_ERR_SALT_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, salt->x, salt->len), CRYPT_SUCCESS);
    int32_t pad = CRYPT_EMSA_PKCSV15;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, NULL, sizeof(pad)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &pad, 2), CRYPT_INVALID_ARG);
    pad = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_INVALID_ARG);
    pad = CRYPT_RSA_PADDINGMAX;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_INVALID_ARG);
    pad = CRYPT_EMSA_PKCSV15;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);
    pad = CRYPT_RSA_NO_PAD;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_PADDING, &pad, sizeof(pad)), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    TestRandDeInit();
}

/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_CTRL_API_TC002
 * @title  Rsa CRYPT_EAL_PkeyCtrl test.
 * @precon  Create the context of the rsa algorithm, set the private key(n, d) and set the padding type to pss.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyCtrl method:
 *       (1) opt = CRYPT_CTRL_GET_RSA_PADDING, val is null, expected result 1
 *       (2) opt = CRYPT_CTRL_GET_RSA_PADDING, expected result 2
 *       (3) opt = CRYPT_CTRL_GET_RSA_MD, val is null, expected result 3
 *       (4) opt = CRYPT_CTRL_GET_RSA_MD, expected result 4
 *       (5) opt = CRYPT_CTRL_GET_RSA_MGF, val is null, expected result 5
 *       (6) opt = CRYPT_CTRL_GET_RSA_MGF, expected result 6
 *       (7) opt = CRYPT_CTRL_GET_RSA_SALT, val is null, expected result 7
 *       (8) opt = CRYPT_CTRL_GET_RSA_SALT, expected result 8
 *       (9) opt = CRYPT_CTRL_CLR_RSA_FLAG, val is null, expected result 9
 *       (10) opt = CRYPT_CTRL_CLR_RSA_FLAG, expected result 10
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. The return value is CRYPT_SUCCESS, and the output parameter(padType) value is pss.
 *    3. CRYPT_NULL_INPUT
 *    4. The return value is CRYPT_SUCCESS, and the output parameter(mdType) value is hashId.
 *    5. CRYPT_NULL_INPUT
 *    6. The return value is CRYPT_SUCCESS, and the output parameter(mgfId) value is hashId.
 *    7. CRYPT_NULL_INPUT
 *    8. The return value is CRYPT_SUCCESS, and the output parameter(saltLen) value is para.saltLen.
 *    9. CRYPT_NULL_INPUT
 *    10. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CTRL_API_TC002(Hex *n, Hex *d, int hashId, int isProvider)
{
    uint32_t flag = CRYPT_RSA_BLINDING;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    int32_t pssSaltLen = 10;
    int32_t pssMdId = hashId;
    int32_t pssMgfId = hashId;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssMdId, sizeof(pssMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssMgfId, sizeof(pssMgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &pssSaltLen, sizeof(pssSaltLen), 0},
        BSL_PARAM_END};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    RSA_PadType padType = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_PADDING, NULL, sizeof(RSA_PadType)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(RSA_PadType)), CRYPT_SUCCESS);
    ASSERT_EQ(padType, CRYPT_EMSA_PSS);

    CRYPT_MD_AlgId mdType = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_MD, NULL, sizeof(CRYPT_MD_AlgId)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_MD, &mdType, sizeof(CRYPT_MD_AlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(mdType, hashId);

    CRYPT_MD_AlgId mgfId = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_MGF, NULL, sizeof(CRYPT_MD_AlgId)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_MGF, &mgfId, sizeof(CRYPT_MD_AlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(mgfId, hashId);

    int32_t saltLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_SALTLEN, NULL, sizeof(int32_t)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_SALTLEN, &saltLen, sizeof(int32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(saltLen, pssSaltLen);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_CLR_RSA_FLAG, NULL, sizeof(uint32_t)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_CLR_RSA_FLAG, (void *)&flag, sizeof(uint32_t)) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_CTRL_API_TC003
 * @title  Rsa CRYPT_EAL_PkeyCtrl test.
 * @precon  Create the context of the rsa algorithm, set the private key(n, d) and set the different saltLen to pss.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CTRL_API_TC003(Hex *n, Hex *d, int isProvider)
{
    CRYPT_EAL_PkeyPrv prvkey = {0};
    int32_t pssSaltLen = CRYPT_RSA_SALTLEN_TYPE_HASHLEN;
    int32_t pssMdId = CRYPT_MD_SHA256;
    int32_t pssMgfId = CRYPT_MD_SHA256;
    int32_t saltLen = 0;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssMdId, sizeof(pssMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssMgfId, sizeof(pssMgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &pssSaltLen, sizeof(pssSaltLen), 0},
        BSL_PARAM_END};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_SALTLEN, &saltLen, sizeof(int32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(saltLen, 32); // saltLen = MdSize(32)
    pssSaltLen = CRYPT_RSA_SALTLEN_TYPE_MAXLEN;
    pssParam[2].value = &pssSaltLen; // salt-len index = 2
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_SALTLEN, &saltLen, sizeof(int32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(saltLen, CRYPT_EAL_PkeyGetKeyLen(pkey) - 32 - 2); // saltLen = keyBytes - MdSize(32) - 2
    pssSaltLen = CRYPT_RSA_SALTLEN_TYPE_AUTOLEN;
    pssParam[2].value = &pssSaltLen; // salt-len index = 2
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_SALTLEN, &saltLen, sizeof(int32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(saltLen, CRYPT_EAL_PkeyGetKeyLen(pkey) - 32 - 2); // saltLen = keyBytes - MdSize(32) - 2
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


int Compare_PubKey(CRYPT_EAL_PkeyPub *pubKey1, CRYPT_EAL_PkeyPub *pubKey2)
{
    if (pubKey1->key.rsaPub.nLen != pubKey2->key.rsaPub.nLen || pubKey1->key.rsaPub.eLen != pubKey2->key.rsaPub.eLen) {
        return -1;  // -1 indicates failure
    }
    if (memcmp(pubKey1->key.rsaPub.n, pubKey2->key.rsaPub.n, pubKey1->key.rsaPub.nLen) != 0 ||
        memcmp(pubKey1->key.rsaPub.e, pubKey2->key.rsaPub.e, pubKey1->key.rsaPub.eLen) != 0) {
        return -1;  // -1 indicates failure
    }
    return 0;
}

int Compare_PrvKey(CRYPT_EAL_PkeyPrv *prvKey1, CRYPT_EAL_PkeyPrv *prvKey2)
{
    if (prvKey1->key.rsaPrv.dLen != prvKey2->key.rsaPrv.dLen || prvKey1->key.rsaPrv.nLen != prvKey2->key.rsaPrv.nLen ||
        prvKey1->key.rsaPrv.pLen != prvKey2->key.rsaPrv.pLen || prvKey1->key.rsaPrv.qLen != prvKey2->key.rsaPrv.qLen) {
        return -1;  // -1 indicates failure
    }
    if (memcmp(prvKey1->key.rsaPrv.d, prvKey2->key.rsaPrv.d, prvKey1->key.rsaPrv.dLen) != 0 ||
        memcmp(prvKey1->key.rsaPrv.n, prvKey2->key.rsaPrv.n, prvKey1->key.rsaPrv.nLen) != 0 ||
        memcmp(prvKey1->key.rsaPrv.p, prvKey2->key.rsaPrv.p, prvKey1->key.rsaPrv.pLen) != 0 ||
        memcmp(prvKey1->key.rsaPrv.q, prvKey2->key.rsaPrv.q, prvKey1->key.rsaPrv.qLen) != 0) {
        return -1;  // -1 indicates failure
    }
    return 0;
}

/**
 * @test   SDV_CRYPTO_RSA_SET_KEY_API_TC001
 * @title  Rsa: Set the public key and private key multiple times.
 * @precon Create the contexts of the rsa algorithm and:
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
void SDV_CRYPTO_RSA_SET_KEY_API_TC001(int isProvider)
{
    uint8_t e[] = {1, 0, 1};
    uint8_t pubE[600];
    uint8_t pubN[600];
    uint8_t prvD[600];
    uint8_t prvN[600];
    uint8_t prvP[600];
    uint8_t prvQ[600];
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    CRYPT_EAL_PkeyPrv prvKey = {0};

    SetRsaPubKey(&pubKey, pubE, 600, pubN, 600);  // 600 bytes > 1024 bits
    SetRsaPrvKey(&prvKey, prvN, 600, prvD, 600);
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;
    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;
    SetRsaPara(&para, e, 3, 1024);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default",
        isProvider);
    CRYPT_EAL_PkeyCtx *pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default",
        isProvider);
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
    SetRsaPubKey(&pubKey, pubE, 600, pubN, 600);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    SetRsaPrvKey(&prvKey, prvN, 600, prvD, 600);
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;
    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(Compare_PrvKey(&prvKey, &prvKey), 0);

    /* Set private key and set public key. */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    /* Get private key, get public key and check public key.*/
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey), CRYPT_SUCCESS);
    SetRsaPubKey(&pubKey, pubE, 600, pubN, 600);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(Compare_PubKey(&pubKey, &pubKey), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_DUP_CTX_API_TC001
 * @title  RSA CRYPT_EAL_PkeyDupCtx test.
 * @precon Create the contexts of the rsa algorithm, set para and generate a key pair.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyDupCtx mehod to dup rsa, expected result 1
 * @expect
 *    1. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_DUP_CTX_API_TC001(Hex *e, int bits, int isProvider)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *newPkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    SetRsaPara(&para, e->x, e->len, bits);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    CRYPT_RSA_Ctx *rsaCtx = (CRYPT_RSA_Ctx *)pkey->key;
    ASSERT_TRUE(rsaCtx != NULL);

    newPkey = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newPkey != NULL);
    ASSERT_EQ(newPkey->references.count, 1);
    CRYPT_RSA_Ctx *rsaCtx2 = (CRYPT_RSA_Ctx *)newPkey->key;
    ASSERT_TRUE(rsaCtx2 != NULL);

    ASSERT_COMPARE("rsa compare n",
        rsaCtx->prvKey->n->data,
        rsaCtx->prvKey->n->size * sizeof(BN_UINT),
        rsaCtx2->prvKey->n->data,
        rsaCtx2->prvKey->n->size * sizeof(BN_UINT));

    ASSERT_COMPARE("rsa compare d",
        rsaCtx->prvKey->d->data,
        rsaCtx->prvKey->d->size * sizeof(BN_UINT),
        rsaCtx2->prvKey->d->data,
        rsaCtx2->prvKey->d->size * sizeof(BN_UINT));

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newPkey);
    TestRandDeInit();
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_CMP_API_TC001
 * @title  RSA: CRYPT_EAL_PkeyCmp invalid parameter test.
 * @precon para id and public key.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the rsa algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set public key for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set different public key for ctx2, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_RSA_NO_KEY_INFO
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_RSA_NO_KEY_INFO
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_RSA_PUBKEY_NOT_EQUAL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CMP_API_TC001(Hex *n, Hex *e, int isProvider)
{
    uint8_t tmpE[] = {1, 0, 1};
    CRYPT_EAL_PkeyPub pub = {0};
    SetRsaPubKey(&pub, n->x, n->len, e->x, e->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default",
        isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default",
        isProvider);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_RSA_NO_KEY_INFO);  // no key

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_RSA_NO_KEY_INFO);  // ctx2 no pubkey

    SetRsaPubKey(&pub, n->x, n->len, tmpE, 3);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_RSA_PUBKEY_NOT_EQUAL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GET_SECURITY_BITS_FUNC_TC001
 * @title  RSA CRYPT_EAL_PkeyGetSecurityBits test.
 * @precon nan
 * @brief
 *    1. Create the context of the rsa algorithm, expected result 1
 *    2. Set public key, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method and the parameter is correct, expected result 3
 * @expect
 *    1. Success, and the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. The return value is not 0.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GET_SECURITY_BITS_FUNC_TC001(Hex *n, Hex *e, int securityBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    SetRsaPubKey(&pub, n->x, n->len, e->x, e->len);

    TestMemInit();

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey, &pub), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetSecurityBits(pkey), securityBits);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

#define RSA_TEST_REFERENCE_COUNT 10000
static void *RsaTestAtomic(void *arg)
{
    CRYPT_EAL_PkeyCtx *pkey = (CRYPT_EAL_PkeyCtx *)arg;
    int ref = 0;
    for (int i = 0; i < RSA_TEST_REFERENCE_COUNT; i++) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_UP_REFERENCES, &ref, sizeof(int)), CRYPT_SUCCESS);
        CRYPT_RSA_Ctx *ctx = (CRYPT_RSA_Ctx *)pkey->key;
        ASSERT_EQ(CRYPT_RSA_GetBits(ctx), 2048);  // RSA2048
        CRYPT_RSA_FreeCtx(ctx);
    }
EXIT:
    return NULL;
}

static int32_t pthreadRWLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    pthread_rwlock_t *newLock;
    newLock = (pthread_rwlock_t *)BSL_SAL_Malloc(sizeof(pthread_rwlock_t));
    if (newLock == NULL) {
        return BSL_MALLOC_FAIL;
    }
    if (pthread_rwlock_init(newLock, NULL) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    *lock = newLock;
    return BSL_SUCCESS;
}

static void pthreadRWLockFree(BSL_SAL_ThreadLockHandle lock)
{
    pthread_rwlock_destroy((pthread_rwlock_t *)lock);
    BSL_SAL_FREE(lock);
}

static int32_t pthreadRWLockReadLock(BSL_SAL_ThreadLockHandle lock)
{
    if (lock == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (pthread_rwlock_rdlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t pthreadRWLockWriteLock(BSL_SAL_ThreadLockHandle lock)
{
    if (pthread_rwlock_wrlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static int32_t pthreadRWLockUnlock(BSL_SAL_ThreadLockHandle lock)
{
    if (pthread_rwlock_unlock((pthread_rwlock_t *)lock) != 0) {
        return BSL_SAL_ERR_UNKNOWN;
    }
    return BSL_SUCCESS;
}

static uint64_t pthreadGetId(void)
{
    return (uint64_t)pthread_self();
}

/**
 * @test   SDV_CRYPTO_RSA_REFERENCES_API_TC001
 * @title  Multi-threaded reference counting test.
 * @precon Create the context of the rsa algorithm, set the private key(n, d).
 * @brief
 *    1. Create multiple threads to use ctx at the same time.
 *    2. Check whether the CTX is finally released.
 * @expect
 *    1. The reference counting is as expected.
 *    2. The memory is released successfully, and no memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_REFERENCES_API_TC001(Hex *n, Hex *d, int isProvider)
{
    BSL_ERR_Init();
    pthread_t pid1;
    pthread_t pid2;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);

    TestMemInit();
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_NEW_CB_FUNC, pthreadRWLockNew) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_FREE_CB_FUNC, pthreadRWLockFree) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_READ_LOCK_CB_FUNC, pthreadRWLockReadLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_WRITE_LOCK_CB_FUNC, pthreadRWLockWriteLock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_LOCK_UNLOCK_CB_FUNC, pthreadRWLockUnlock) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_SAL_CallBack_Ctrl(BSL_SAL_THREAD_GET_ID_CB_FUNC, pthreadGetId) == BSL_SUCCESS);

    pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(pkey->references.count, 1);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);

    pkey1 = pkey;
    ASSERT_TRUE(CRYPT_EAL_PkeyUpRef(pkey1) == CRYPT_SUCCESS);

    pkey2 = pkey;
    ASSERT_TRUE(CRYPT_EAL_PkeyUpRef(pkey2) == CRYPT_SUCCESS);
    ASSERT_EQ(pkey->references.count, 3);  // The pkey is referenced three times.

    pthread_create(&pid1, NULL, RsaTestAtomic, (void *)pkey1);
    pthread_create(&pid2, NULL, RsaTestAtomic, (void *)pkey2);

    pthread_join(pid1, NULL);  // Wait for all child threads to end.
    pthread_join(pid2, NULL);

    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    ASSERT_EQ(pkey->references.count, 1);
    CRYPT_RSA_Ctx *ctx = (CRYPT_RSA_Ctx *)pkey->key;
    ASSERT_EQ(ctx->references.count, 1);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GET_KEY_BITS_FUNC_TC001
 * @title  RSA: get key bits.
 * @brief
 *    1. Create a context of the RSA algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GET_KEY_BITS_FUNC_TC001(int id, int keyBits, int isProvider)
{
    uint8_t e3[] = {1, 0, 1};

    CRYPT_EAL_PkeyPara para;

    para.id = id;
    para.para.rsaPara.e = e3;
    para.para.rsaPara.eLen = 3;    // 3 is valid.
    para.para.rsaPara.bits = 1024; // 1024 is valid.

    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE_AND_LOG("1k key", CRYPT_EAL_PkeySetPara(pkey, &para) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SEED_KEYGEN_TC001
 * @title  RSA: 确定性种子密钥生成测试
 * @precon 具有相同种子值的两个RSA密钥生成上下文
 * @brief
 *    1. 使用相同种子值创建两个RSA密钥对，验证两个密钥对是否完全相同
 * @expect
 *    1. 两个密钥对完全相同，确认种子确定性生成功能正常
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SEED_KEYGEN_TC001(Hex *xp, Hex *xp1, Hex *xp2, Hex *xq, Hex *xq1, Hex *xq2, int isProvider)
{
    TestMemInit();
    uint8_t e[] = {1, 0, 1};
    
    uint8_t prvD1[600];
    uint8_t prvN1[600];
    uint8_t prvP1[600];
    uint8_t prvQ1[600];
    uint8_t prvD2[600];
    uint8_t prvN2[600];
    uint8_t prvP2[600];
    uint8_t prvQ2[600];
    
    // 初始化两个密钥上下文
    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;
    
    // 初始化两个相同的参数结构
    CRYPT_EAL_PkeyPara para1 = {0};
    CRYPT_EAL_PkeyPara para2 = {0};
    
    para1.id = para2.id = CRYPT_PKEY_RSA;
    
    // 设置RSA参数
    para1.para.rsaPara.e = para2.para.rsaPara.e = e;
    para1.para.rsaPara.eLen = para2.para.rsaPara.eLen = 3;
    para1.para.rsaPara.bits = para2.para.rsaPara.bits = 1024;
    
    // 设置种子参数，使用传入的Hex参数
    para1.para.rsaPara.xp = para2.para.rsaPara.xp = xp->x;
    para1.para.rsaPara.xpLen = para2.para.rsaPara.xpLen = xp->len;
    para1.para.rsaPara.xp1 = para2.para.rsaPara.xp1 = xp1->x;
    para1.para.rsaPara.xp1Len = para2.para.rsaPara.xp1Len = xp1->len;
    para1.para.rsaPara.xp2 = para2.para.rsaPara.xp2 = xp2->x;
    para1.para.rsaPara.xp2Len = para2.para.rsaPara.xp2Len = xp2->len;
    para1.para.rsaPara.xq = para2.para.rsaPara.xq = xq->x;
    para1.para.rsaPara.xqLen = para2.para.rsaPara.xqLen = xq->len;
    para1.para.rsaPara.xq1 = para2.para.rsaPara.xq1 = xq1->x;
    para1.para.rsaPara.xq1Len = para2.para.rsaPara.xq1Len = xq1->len;
    para1.para.rsaPara.xq2 = para2.para.rsaPara.xq2 = xq2->x;
    para1.para.rsaPara.xq2Len = para2.para.rsaPara.xq2Len = xq2->len;
    
    // 创建随机数生成器
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    
    // 创建第一个上下文并生成密钥
    pkey1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey1 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey1, &para1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey1), CRYPT_SUCCESS);
    
    // 创建第二个上下文并生成密钥
    pkey2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &para2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey2), CRYPT_SUCCESS);
    
    // 获取私钥
    CRYPT_EAL_PkeyPrv prvKey1 = {0};
    CRYPT_EAL_PkeyPrv prvKey2 = {0};
    
    SetRsaPrvKey(&prvKey1, prvN1, sizeof(prvN1), prvD1, sizeof(prvD1));
    SetRsaPrvKey(&prvKey2, prvN2, sizeof(prvN2), prvD2, sizeof(prvD2));
    
    prvKey1.key.rsaPrv.p = prvP1;
    prvKey1.key.rsaPrv.pLen = sizeof(prvP1);
    prvKey1.key.rsaPrv.q = prvQ1;
    prvKey1.key.rsaPrv.qLen = sizeof(prvQ1);
    prvKey2.key.rsaPrv.p = prvP2;
    prvKey2.key.rsaPrv.pLen = sizeof(prvP2);
    prvKey2.key.rsaPrv.q = prvQ2;
    prvKey2.key.rsaPrv.qLen = sizeof(prvQ2);
    
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey1, &prvKey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey2, &prvKey2), CRYPT_SUCCESS);
    
    // 验证两个密钥是否相同
    ASSERT_EQ(Compare_PrvKey(&prvKey1, &prvKey2), 0);
    
    // // 验证n值是否相同
    // ASSERT_EQ(prvKey1.key.rsaPrv.nLen, prvKey2.key.rsaPrv.nLen);
    // ASSERT_COMPARE("RSA n values", 
    //     prvKey1.key.rsaPrv.n, prvKey1.key.rsaPrv.nLen,
    //     prvKey2.key.rsaPrv.n, prvKey2.key.rsaPrv.nLen);
    
    // // 验证p值是否相同
    // ASSERT_EQ(prvKey1.key.rsaPrv.pLen, prvKey2.key.rsaPrv.pLen);
    // ASSERT_COMPARE("RSA p values", 
    //     prvKey1.key.rsaPrv.p, prvKey1.key.rsaPrv.pLen,
    //     prvKey2.key.rsaPrv.p, prvKey2.key.rsaPrv.pLen);
    
    // // 验证q值是否相同
    // ASSERT_EQ(prvKey1.key.rsaPrv.qLen, prvKey2.key.rsaPrv.qLen);
    // ASSERT_COMPARE("RSA q values", 
    //     prvKey1.key.rsaPrv.q, prvKey1.key.rsaPrv.qLen,
    //     prvKey2.key.rsaPrv.q, prvKey2.key.rsaPrv.qLen);
    
EXIT:
    // 清理资源
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    TestRandDeInit();
}
/* END_CASE */


// 0x5555565f1410: 0x0f    0xcf    0x16    0xd3    0xc2    0xe3    0x04    0x75
// 0x5555565f1418: 0xa6    0x7d    0x49    0x90    0xaa    0x20    0x85    0x00
// 0x5555565f1420: 0x7e    0xaa    0xcb    0xc9    0x35    0xd2    0x46    0x10
// 0x5555565f1428: 0x1b    0x2e    0x69    0xb5    0xb3    0xd2    0xaa    0xad
// 0x5555565f1430: 0x49    0xce    0x94    0xab    0x26    0x76    0xf7    0x34
// 0x5555565f1438: 0x97    0xc4    0x27    0x6f    0x3b    0x57    0xe1    0xea
// 0x5555565f1440: 0xe4    0x56    0x74    0xad    0xbf    0x1b    0x21    0xae
// 0x5555565f1448: 0xa8    0xa9    0x63    0xcb    0xf4    0x54    0x27    0xfd
// 0x5555565f1450: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1458: 0x41    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1460: 0xc1    0x0b    0x29    0x00    0x50    0x55    0x00    0x00
// 0x5555565f1468: 0xa2    0x8b    0x2d    0x9f    0x73    0xe3    0x25    0x46
// 0x5555565f1470: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1478: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1480: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1488: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1490: 0xd7    0x11    0xbc    0xed    0x85    0x0e    0x8c    0x46
// 0x5555565f1498: 0x61    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// 0x5555565f05d0: 0x7f    0x07    0x3d    0xd8    0x56    0x54    0xb3    0x2f
// 0x5555565f05d8: 0xa4    0x5f    0x6a    0xcc    0xae    0xd0    0x28    0x09
// 0x5555565f05e0: 0x52    0xd6    0x5a    0x93    0xf2    0xaf    0x08    0x23
// 0x5555565f05e8: 0x72    0x56    0xf3    0x78    0xf2    0xca    0xd5    0xe2
// 0x5555565f05f0: 0xc0    0x8b    0x82    0xc9    0x45    0x95    0x5c    0x97
// 0x5555565f05f8: 0x15    0xc1    0xc1    0x87    0x96    0x15    0x0f    0x3c
// 0x5555565f0600: 0x72    0x38    0x84    0xca    0x19    0xa8    0x83    0x9f
// 0x5555565f0608: 0x72    0x7a    0x25    0x18    0xd4    0x42    0x77    0xcc
// 0x5555565f0610: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f0618: 0x21    0x01    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f0620: 0x60    0x30    0x5f    0x56    0x55    0x55    0x00    0x00
// 0x5555565f0628: 0x10    0x32    0x5f    0x56    0x55    0x55    0x00    0x00
// 0x5555565f0630: 0xfc    0x4f    0xab    0x2b    0x9c    0x1b    0xbe    0xc9
// 0x5555565f0638: 0x44    0x5e    0x0e    0x11    0x4d    0x63    0x98    0x5a
// 0x5555565f0640: 0xcc    0x56    0x67    0x83    0xcb    0x28    0x20    0x90
// 0x5555565f0648: 0xf3    0xc7    0x6b    0x48    0x82    0x79    0x3a    0xc4
// 0x5555565f0650: 0xe8    0x78    0x29    0x53    0x12    0xe9    0x40    0x5d
// 0x5555565f0658: 0xbb    0x8d    0x73    0xf4    0xc4    0xcb    0x84    0x4d

// {e = 0x5555557e5290, bits = 1024, p = 0x5555565ef990, q = 0x5555557e56c0, xp = 0x0, xp1 = 0x0, xp2 = 0x0, xq = 0x0, xq1 = 0x0, xq2 = 0x0}

// xp1：
// 0x5555565ef730: 0x23    0xe2    0x4f    0x06    0xda    0xf2    0x05    0xa5
// 0x5555565ef738: 0x77    0x18    0xd6    0x00    0x48    0x98    0x79    0x77
// 0x5555565ef740: 0x86    0x17    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565ef748: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// xp2：
// 0x5555565f3a60: 0x69    0x72    0xd7    0x7e    0x7b    0xec    0xf7    0xe9
// 0x5555565f3a68: 0x25    0x50    0x6f    0x86    0xf5    0x1c    0xce    0x28
// 0x5555565f3a70: 0xec    0x1b    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3a78: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// xp：
// 0x5555565f30c0: 0xcc    0x1a    0x14    0x0f    0x0e    0x31    0x2b    0xc6
// 0x5555565f30c8: 0xe2    0x61    0xd9    0x50    0x4d    0x76    0x77    0x2d
// 0x5555565f30d0: 0xcb    0xa0    0x55    0xad    0x98    0xb3    0xf9    0x46
// 0x5555565f30d8: 0xd1    0x93    0xaf    0x3f    0x4d    0xdf    0x7d    0x1b
// 0x5555565f30e0: 0x37    0x63    0x28    0x27    0x22    0x76    0xf7    0x34
// 0x5555565f30e8: 0x97    0xc4    0x27    0x6f    0x3b    0x57    0xe1    0xea
// 0x5555565f30f0: 0xe4    0x56    0x74    0xad    0xbf    0x1b    0x21    0xae
// 0x5555565f30f8: 0xa8    0xa9    0x63    0xcb    0xf4    0x54    0x27    0xfd
// 0x5555565f3100: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3108: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3110: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3118: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3120: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3128: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3130: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3138: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// xq1：
// 0x5555565f1460: 0x6f    0x48    0x1b    0x3a    0xfe    0xbf    0x1a    0x42
// 0x5555565f1468: 0x4c    0x31    0x8a    0x91    0x82    0x39    0x19    0x45
// 0x5555565f1470: 0xf3    0x14    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1478: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1480: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f1488: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// xq2：
// 0x5555565f3a60: 0x7b    0x27    0x69    0xe6    0xaa    0xed    0xeb    0x2a
// 0x5555565f3a68: 0x47    0x01    0x46    0x60    0x63    0x12    0xc7    0x9d
// 0x5555565f3a70: 0x4b    0x18    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3a78: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// xq：
// 0x5555565f3150: 0xd3    0x3e    0xd2    0x4c    0xf7    0xd8    0x2b    0xd6
// 0x5555565f3158: 0x90    0xee    0xc0    0xf1    0x48    0xe6    0xa4    0xef
// 0x5555565f3160: 0xe7    0x7a    0x30    0x37    0xac    0x40    0xbd    0x7e
// 0x5555565f3168: 0x16    0x94    0xe2    0x0a    0x92    0xce    0xf2    0x27
// 0x5555565f3170: 0x82    0x20    0xaf    0x89    0x42    0x95    0x5c    0x97
// 0x5555565f3178: 0x15    0xc1    0xc1    0x87    0x96    0x15    0x0f    0x3c
// 0x5555565f3180: 0x72    0x38    0x84    0xca    0x19    0xa8    0x83    0x9f
// 0x5555565f3188: 0x72    0x7a    0x25    0x18    0xd4    0x42    0x77    0xcc
// 0x5555565f3190: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f3198: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f31a0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f31a8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f31b0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f31b8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f31c0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
// 0x5555565f31c8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

// xp: cc1a140f0e312bc6e261d9504d76772dcba055ad98b3f946d193af3f4ddf7d1b376328272276f73497c4276f3b57e1eae45674adbf1b21aea8a963cbf45427fd
// xp1: 23e24f06daf205a57718d600489879778617
// xp2: 6972d77e7becf7e925506f86f51cce28ec1b
// xq: d33ed24cf7d82bd690eec0f148e6a4efe77a3037ac40bd7e1694e20a92cef2278220af8942955c9715c1c18796150f3c723884ca19a8839f727a2518d44277cc
// xq1: 6f481b3afebf1a424c318a9182391945f314
// xq2: 7b2769e6aaedeb2a470146606312c79d4b18