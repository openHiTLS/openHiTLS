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
/* INCLUDE_BASE test_suite_sdv_eal_sm2 */

/* BEGIN_HEADER */

#include "eal_pkey_local.h"
/* END_HEADER */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC001
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: R is not set.
 * @precon Test Vectors for SM2: public key, private key
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set userId, server, private key and generate r, expected result 2.
 *    3. ctx2: set userId and public key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 4.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_SM2_R_NOT_SET
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC001(Hex *prvKey, Hex *pubKey, int isProvider)
{
    uint8_t userId[10] = {0};
    uint8_t localR[65];
    int32_t server = 1;
    uint8_t out[64];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SM2_R_NOT_SET);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC002
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: R is not generate.
 * @precon Test Vectors for SM2: public key, private key, R.
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set userId, server and private key, expected result 2.
 *    3. ctx2: set userId, R and public key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 4.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_SM2_R_NOT_SET
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC002(Hex *prvKey, Hex *pubKey, Hex *R, int isProvider)
{
    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t userId[10] = {0};
    int32_t server = 1;
    uint8_t out[64];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SM2_R_NOT_SET);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC003
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: UserId is not set at the local end.
 * @precon Test Vectors for SM2: public key, private key, R.
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set server, private key and generate r, expected result 2.
 *    3. ctx2: set userId, R and public key, expected result 3.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC003(Hex *prvKey, Hex *pubKey, Hex *R, int isProvider)
{
    uint8_t userId[10] = {0};
    int32_t server = 1;
    uint8_t localR[65];
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    if (isProvider) {
        CRYPT_RandRegistEx(RandFuncExSelfCheck);
    } else {
        CRYPT_RandRegistEx(RandFuncEx);
    }

    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC004
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: UserId is not set at the peer end.
 * @precon Test Vectors for SM2: public key, private key, R.
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set userId, server, private key and generate r, expected result 2.
 *    3. ctx2: set R and public key, expected result 3.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC004(Hex *prvKey, Hex *pubKey, Hex *R, int isProvider)
{
    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t userId[10] = {0};
    int32_t server = 1;
    uint8_t localR[65];
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC005
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: UserId is not set at the peer end.
 * @precon Test Vectors for SM2: public key, private key, R.
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set userId, server, private key and generate r, expected result 2.
 *    3. ctx2: set R, server and public key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 4.
 *    5. Set client and generate R for ctx1, set client for ctx2, expected result 5.
 *    6. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 6.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC005(Hex *prvKey, Hex *pubKey, Hex *R, int isProvider)
{
    uint8_t userId[10] = {0};
    int32_t server = 1;
    uint8_t out[64];
    uint8_t localR[65];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);

    server = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC006
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: Test the validity of input parameters.
 * @precon Test Vectors for SM2: public key, private key, R.
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set userId, server, private key and generate r, expected result 2.
 *    3. ctx2: set userId, R and public key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method:
 *       (1) ctx1 = NULL, expected result 4.
 *       (2) ctx2 = NULL, expected result 5.
 *       (3) out = NULL, expected result 6.
 *       (4) outLen = NULL, expected result 7.
 *       (5) outLen = 0, expected result 8.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC006(Hex *prvKey, Hex *pubKey, Hex *R, int isProvider)
{
    uint8_t userId[10] = {0};
    int32_t server = 1;
    uint8_t out[64];
    uint8_t localR[65];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(NULL, ctx2, out, &outLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, NULL, out, &outLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, NULL, &outLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, NULL) == CRYPT_NULL_INPUT);
    outLen = 0;
    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_API_TC007
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: Test the validity of input parameters.
 * @precon Test Vectors for SM2: public key, private key, R.
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1.
 *    2. ctx1: set userId, server, private key and generate r, expected result 2.
 *    3. ctx2: set userId, R and private key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 4.
 *    5. Set public key for ctx1 and ctx2, expected result 5.
 *    6. Generate R for ctx1, expected result 6.
 *    7. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 7.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_SM2_ERR_EMPTY_KEY
 *    5-7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_API_TC007(Hex *prvKey, Hex *pubKey, Hex *R, int isProvider)
{
    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t userId[10] = {0};
    int32_t server = 1;
    uint8_t out[64];
    uint8_t localR[65];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx2, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SM2_ERR_EMPTY_KEY);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx1, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CTRL_API_TC001
 * @title  SM2 CRYPT_EAL_PkeyCtrl: Test generate R and get R.
 * @precon nan
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl, and all parameters are valid, expected result 2
 *    3. Set the error random number method so that it returns zero, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCtrl, and all parameters are valid, expected result 4
 *    5. Set the correct random number method.
 *    6. Call the CRYPT_EAL_PkeyCtrl, opt = CRYPT_CTRL_GENE_SM2_R:
 *       (1) val = null, and other parameters are valid, expected result 5
 *       (2) val = null, len = 0, and other parameters are valid, expected result 6
 *       (3) val != null, len is not enough, and other parameters are valid, expected result 7
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NO_REGIST_RAND
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SM2_ERR_TRY_CNT
 *    5-6. CRYPT_NULL_INPUT
 *    7. CRYPT_ECC_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CTRL_API_TC001(int isProvider)
{
    uint8_t localR[65];
    uint8_t zero[RAND_BUF_LEN] = {0};

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_NO_REGIST_RAND);

    CRYPT_RandRegist(FakeRandFunc);
    CRYPT_RandRegistEx(FakeRandFuncEx);
    ASSERT_TRUE(SetFakeRandOutput(zero, sizeof(zero)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SM2_ERR_TRY_CNT);

    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, NULL, sizeof(localR)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(
        CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR) - 1) == CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CTRL_API_TC002
 * @title  SM2 CRYPT_EAL_PkeyCtrl: Test Set R.
 * @precon vector: valid R.
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl, opt = CRYPT_CTRL_SET_SM2_R:
 *       (1) val = null, and other parameters are valid, expected result 2
 *       (2) val = null, len = 0, and other parameters are valid, expected result 3
 *       (3) val != null, len = R->len - 1, and other parameters are valid, expected result 4
 *       (4) val != null, len = R->len + 1, and other parameters are valid, expected result 5
 *       (5) val is 0 and the length is 65 bytes, and other parameters are valid, expected result 6
 *       (6) and other parameters are valid, expected result 7
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_NULL_INPUT
 *    4-6. CRYPT_ECC_ERR_POINT_CODE
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CTRL_API_TC002(Hex *R, int isProvider)
{
    uint8_t zero[65] = {0};

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R, NULL, R->len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R, NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R, R->x, R->len - 1) == CRYPT_ECC_ERR_POINT_CODE);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R, R->x, R->len + 1) == CRYPT_ECC_ERR_POINT_CODE);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R, zero, sizeof(zero)) == CRYPT_ECC_ERR_POINT_CODE);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CTRL_API_TC003
 * @title  SM2 CRYPT_EAL_PkeyCtrl: Test set sm2 server/client.
 * @precon nan
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl, opt = CRYPT_CTRL_SET_SM2_SERVER:
 *       (1) val = null, and other parameters are valid, expected result 2
 *       (2) val = null, len = 0, and other parameters are valid, expected result 3
 *       (3) val(type is uint32_t, value is 2), len is 4, and other parameters are valid, expected result 4
 *       (4) val(type is uint32_t, value is 0xffffffff), len is 4, and other parameters are valid, expected result 5
 *       (5) val(type is uint8_t, value is 0), len is 1, and other parameters are valid, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_NULL_INPUT
 *    4-5. CRYPT_SM2_INVALID_SERVER_TYPE
 *    6. CRYPT_SM2_ERR_CTRL_LEN
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CTRL_API_TC003(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    uint32_t server = 1;
    uint8_t badServer = 1;

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, NULL, sizeof(uint32_t)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, NULL, 0) == CRYPT_NULL_INPUT);
    server = 2;
    ASSERT_TRUE(
        CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(uint32_t)) == CRYPT_SM2_INVALID_SERVER_TYPE);
    server = 0xffffffff;
    ASSERT_TRUE(
        CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(uint32_t)) == CRYPT_SM2_INVALID_SERVER_TYPE);
    ASSERT_TRUE(
        CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_SERVER, &badServer, sizeof(uint8_t)) == CRYPT_SM2_ERR_CTRL_LEN);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC001
 * @title  SM2 EAL key exchange.
 * @precon Vectors:
 *         server: The value 1 indicates the initiator, and the value 0 indicates the responder.
 *         User 1: private key, generate random number r, userId1
 *         User 2: public key, R, userId2
 * @brief
 *    1. Create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1
 *    2. Set userId1 and server for ctx1, expected result 2
 *    3. Mock BN_RandRange to generate r, expected result 3
 *    4. ctx1 generate r, expected result 4
 *    5. Set userId2 and R for ctx2, expected result 5
 *    6. Set private key for ctx1, expected result 6
 *    7. Set public key for ctx2, expected result 7
 *    8. Compute the shared key, expected result 8
 *    9. Compare the output shared secret and shared secret vector, expected result 9
 *    10. Duplicate ctx1 and ctx2, expected result 10
 *    11. dupCtx1 generate r, expected result 11
 *    12. Set R for dupCtx2, expected result 12
 *    13. Compute share secret with duplicated contexts, expected result 13
 *    14. Compare the output shared secret and shared secret vector, expected result 14
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-8. CRYPT_SUCCESS
 *    9. The two shared secrets are the same.
 *    10. Success, and two contexts are not NULL.
 *    11-13. Success, and two contexts are not NULL.
 *    14. The two shared secrets are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC001(
    Hex *prvKey, Hex *pubKey, Hex *r, Hex *R, Hex *shareKey, Hex *userId1, Hex *userId2, int server, int isProvider)
{
    uint8_t out[500];
    uint8_t localR[65];
    uint32_t outLen = shareKey->len;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *dupCtx1 = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx2 = NULL;

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_TRUE(ctx1 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId1->x, userId1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);

    // Register fake random function to return fixed r value for deterministic testing
    ASSERT_TRUE(SetFakeRandOutput(r->x, r->len) == CRYPT_SUCCESS);
    CRYPT_RandRegist(FakeRandFunc);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(FakeRandFuncEx);
#endif
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId2->x, userId2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(outLen == shareKey->len);
    ASSERT_TRUE(memcmp(out, shareKey->x, shareKey->len) == 0);

    dupCtx1 = CRYPT_EAL_PkeyDupCtx(ctx1);
    dupCtx2 = CRYPT_EAL_PkeyDupCtx(ctx2);
    ASSERT_TRUE(dupCtx1 != NULL && dupCtx2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(dupCtx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(dupCtx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(dupCtx1, dupCtx2, out, &outLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(dupCtx1);
    CRYPT_EAL_PkeyFreeCtx(dupCtx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC002
 * @title  SM2 EAL key exchange.
 * @precon Vectors:
 *         server: The value 1 indicates the initiator, and the value 0 indicates the responder.
 *         User 1: public key and private key, generate random number r, userId1
 *         User 2: public key and private key, R, userId2
 * @brief
 *    1. Create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1
 *    2. Set userId1 and server for ctx1, expected result 2
 *    3. Mock BN_RandRange to generate r, expected result 3
 *    4. ctx1 generate r, expected result 4
 *    5. Set userId2 and R for ctx2, expected result 5
 *    6. Set public key and private key for ctx1, expected result 6
 *    7. Set public key and private key for ctx2, expected result 7
 *    8. Compute the shared key, expected result 8
 *    9. Compare the output shared secret and shared secret vector, expected result 9
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-8. CRYPT_SUCCESS
 *    9. The two shared secrets are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC002(Hex *prvKey1, Hex *pubKey2, Hex *prvKey2, Hex *pubKey1, Hex *r, Hex *R,
    Hex *shareKey, Hex *userId1, Hex *userId2, int server, int isProvider)
{
    uint8_t out[500];
    uint8_t localR[65];
    uint8_t badId[10] = {0};
    uint32_t outLen = shareKey->len;
    CRYPT_EAL_PkeyPrv prv1 = {0};
    CRYPT_EAL_PkeyPub pub2 = {0};
    CRYPT_EAL_PkeyPrv prv2 = {0};
    CRYPT_EAL_PkeyPub pub1 = {0};
    SetSm2PrvKey(&prv1, prvKey1->x, prvKey1->len);
    SetSm2PubKey(&pub2, pubKey2->x, pubKey2->len);
    SetSm2PrvKey(&prv2, prvKey2->x, prvKey2->len);
    SetSm2PubKey(&pub1, pubKey1->x, pubKey1->len);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, badId, sizeof(badId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId1->x, userId1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);

    // Register fake random function to return fixed r value for deterministic testing
    ASSERT_TRUE(SetFakeRandOutput(r->x, r->len) == CRYPT_SUCCESS);
    CRYPT_RandRegist(FakeRandFunc);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(FakeRandFuncEx);
#endif
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, badId, sizeof(badId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId2->x, userId2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx1, &pub1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx2, &prv2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == shareKey->len);
    ASSERT_TRUE(memcmp(out, shareKey->x, shareKey->len) == 0);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC003
 * @title  SM2: Generate a key pair for key exchange.
 * @precon nan
 * @brief
 *    1. Create four contexts(selfCtx1, peerCtx1, selfCtx2, peerCtx2) of the SM2 algorithm, expected result 1
 *    2. Init the DRBG, expected result 2.
 *    3. Set pkg for selfCtx1 and selfCtx2, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair for selfCtx1, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen to generate a key pair for selfCtx2, expected result 5
 *    6. Get the public key from selfCtx2 and set it to peerCtx2, expected result 6
 *    7. Get the public key from selfCtx1 and set it to peerCtx1, expected result 7
 *    8. Set userId and server for selfCtx1 and selfCtx2, expected result 8
 *    9. selfCtx1 and selfCtx2 genenrate r, expected result 9
 *    10. Set userId and r for peerCtx1 and peerCtx2, expected result 10
 *    11. Compute the shared key from the privite value in selfCtx1 and the public vlaue in peerCtx1, expected result 11
 *    12. Compute the shared key from the privite value in selfCtx2 and the public vlaue in peerCtx2, expected result 12
 *    13. Compare the shared keys computed in the preceding two steps, expected result 13
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. Success.
 *    3-12. CRYPT_SUCCESS.
 *    13. The two shared keys are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC003(int pkg, int isProvider)
{
    uint8_t userId1[10];
    uint8_t userId2[10];
    uint8_t out1[500];
    uint8_t out2[500];
    uint8_t localR1[65];
    uint8_t localR2[65];
    uint32_t outLen = sizeof(out1);
    int32_t server = 1;
    int32_t client = 0;

    (void)memset_s(userId1, sizeof(userId1), 'A', sizeof(userId1));
    (void)memset_s(userId2, sizeof(userId2), 'B', sizeof(userId2));

    uint8_t pubKey1[65];
    uint8_t pubKey2[65];
    CRYPT_EAL_PkeyPub pub1, pub2;
    SetSm2PubKey(&pub1, pubKey1, sizeof(pubKey1));
    SetSm2PubKey(&pub2, pubKey2, sizeof(pubKey2));

    TestMemInit();

    CRYPT_EAL_PkeyCtx *selfCtx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *selfCtx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *peerCtx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *peerCtx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(peerCtx1 != NULL);
    ASSERT_TRUE(selfCtx2 != NULL);
    ASSERT_TRUE(selfCtx1 != NULL);
    ASSERT_TRUE(peerCtx2 != NULL);

    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx1, CRYPT_CTRL_SET_SM2_PKG, &pkg, sizeof(pkg)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx2, CRYPT_CTRL_SET_SM2_PKG, &pkg, sizeof(pkg)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(selfCtx1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(selfCtx2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(selfCtx1, &pub1) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(selfCtx2, &pub2) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(peerCtx1, &pub2) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(peerCtx2, &pub1) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx1, CRYPT_CTRL_SET_SM2_USER_ID, userId1, sizeof(userId1)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx1, CRYPT_CTRL_GENE_SM2_R, localR1, sizeof(localR1)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx2, CRYPT_CTRL_SET_SM2_USER_ID, userId2, sizeof(userId2)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx2, CRYPT_CTRL_SET_SM2_SERVER, &client, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(selfCtx2, CRYPT_CTRL_GENE_SM2_R, localR2, sizeof(localR2)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(peerCtx1, CRYPT_CTRL_SET_SM2_R, localR2, sizeof(localR2)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(peerCtx1, CRYPT_CTRL_SET_SM2_USER_ID, userId2, sizeof(userId2)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(peerCtx2, CRYPT_CTRL_SET_SM2_R, localR1, sizeof(localR1)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(peerCtx2, CRYPT_CTRL_SET_SM2_USER_ID, userId1, sizeof(userId1)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(selfCtx1, peerCtx1, out1, &outLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(selfCtx2, peerCtx2, out2, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out1, out2, outLen) == 0);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(selfCtx1);
    CRYPT_EAL_PkeyFreeCtx(selfCtx2);
    CRYPT_EAL_PkeyFreeCtx(peerCtx1);
    CRYPT_EAL_PkeyFreeCtx(peerCtx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC004
 * @title  SM2 EAL key exchange: Default identity (server).
 * @precon Vectors:
 *         User 1: private key, generate random number r, userId1
 *         User 2: public key, R, userId2
 * @brief
 *    1. Create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1
 *    2. Set userId1 for ctx1, expected result 2
 *    3. Mock BN_RandRange to generate r, expected result 3
 *    4. ctx1 generate r, expected result 4
 *    5. Set userId2 and R for ctx2, expected result 5
 *    6. Set private key for ctx1, expected result 6
 *    7. Set public key for ctx2, expected result 7
 *    8. Compute the shared key, expected result 8
 *    9. Compare the output shared secret and shared secret vector, expected result 9
 *    10. Copy ctx1 and ctx2, expected result 10
 *    11. cpyCtx1 generate r, expected result 11
 *    12. Set R for cpyCtx2, expected result 12
 *    13. Compute share secret with duplicated contexts, expected result 13
 *    14. Compare the output shared secret and shared secret vector, expected result 14
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-8. CRYPT_SUCCESS
 *    9. The two shared secrets are the same.
 *    10. Success, and two contexts are not NULL.
 *    11-13. Success, and two contexts are not NULL.
 *    14. The two shared secrets are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_FUNC_TC004(
    Hex *prvKey, Hex *pubKey, Hex *r, Hex *R, Hex *shareKey, Hex *userId1, Hex *userId2, int isProvider)
{
    uint8_t out[500];
    uint8_t localR[65];
    uint32_t outLen = shareKey->len;
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyCtx *cpyCtx1 = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx2 = NULL;

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId1->x, userId1->len) == CRYPT_SUCCESS);

    // Register fake random function to return fixed r value for deterministic testing
    ASSERT_TRUE(SetFakeRandOutput(r->x, r->len) == CRYPT_SUCCESS);
    CRYPT_RandRegist(FakeRandFunc);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(FakeRandFuncEx);
#endif
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId2->x, userId2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == shareKey->len);
    ASSERT_TRUE(memcmp(out, shareKey->x, shareKey->len) == 0);

    cpyCtx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    cpyCtx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx1 != NULL && cpyCtx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx1, ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(cpyCtx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx2, ctx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(cpyCtx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(cpyCtx1, cpyCtx2, out, &outLen), CRYPT_SUCCESS);
    ASSERT_TRUE(outLen == shareKey->len);
    ASSERT_TRUE(memcmp(out, shareKey->x, shareKey->len) == 0);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx1);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_CHECK_TC001
 * @title  SM2 EAL key exchange check.
 * @precon Vectors:
 *         server: The value 1 indicates the initiator, and the value 0 indicates the responder.
 *         User 1: private key, generate random number r, userId1, optional term S
 *         User 2: public key , R, userId2, optional term S
 * @brief
 *    1. Create two contexts(ctx1, ctx2) of the SM2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl method, opt = CRYPT_CTRL_SM2_DO_CHECK, expected result 2
 *    3. Set userId1 and server for ctx1, expected result 3
 *    4. Mock BN_RandRange to generate r, expected result 4
 *    5. ctx1 generate r, expected result 5
 *    6. Set userId2 and R for ctx2, expected result 6
 *    7. Set private key for ctx1, expected result 7
 *    8. Set public key key for ctx2, expected resul 8
 *    9. Compute the shared key, expected result 9
 *    10. Compare the output shared secret and shared secret vector, expected result 10
 *    11. Call the CRYPT_EAL_PkeyCtrl method:
 *       (1) opt = CRYPT_CTRL_SM2_DO_CHECK val len not equal to SM3_MD_SIZE, expected result 11
 *       (2) opt = CRYPT_CTRL_SM2_GET_SEND_CHECK, val len not equal to SM3_MD_SIZE, expected result 12
 *       (3) opt = CRYPT_CTRL_SM2_GET_SEND_CHECK, and Other parameters are valid, expected result 13
 *    12. Compare the output of step 11.(3) and selfS vector, expected result 14
 *    13. Call the CRYPT_EAL_PkeyCtrl method, opt = CRYPT_CTRL_SM2_DO_CHECK, expected result 15
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2. CRYPT_SM2_ERR_S_NOT_SET
 *    3-9. CRYPT_SUCCESS
 *    10. The two shared secrets are the same.
 *    11. CRYPT_SM2_ERR_DATA_LEN
 *    12. CRYPT_SM2_BUFF_LEN_NOT_ENOUGH
 *    13. CRYPT_SUCCESS
 *    14. Both are the same.
 *    15. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_CHECK_TC001(Hex *prvKey, Hex *pubKey, Hex *r, Hex *R, Hex *shareKey, Hex *userId1,
    Hex *userId2, int server, Hex *peerS, Hex *selfS, int isProvider)
{
    uint8_t out[500];
    uint8_t localR[65];
    uint32_t outLen = shareKey->len;
    uint8_t val[selfS->len];
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_TRUE(ctx1 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_DO_CHECK, peerS->x, peerS->len) == CRYPT_SM2_ERR_S_NOT_SET);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId1->x, userId1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);

    // Register fake random function to return fixed r value for deterministic testing
    ASSERT_TRUE(SetFakeRandOutput(r->x, r->len) == CRYPT_SUCCESS);
    CRYPT_RandRegist(FakeRandFunc);
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_RandRegistEx(FakeRandFuncEx);
#endif
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GENE_SM2_R, localR, sizeof(localR)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId2->x, userId2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(outLen == shareKey->len);
    ASSERT_TRUE(memcmp(out, shareKey->x, shareKey->len) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_DO_CHECK, peerS->x, peerS->len - 1) == CRYPT_SM2_ERR_DATA_LEN);
    ASSERT_TRUE(
        CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_GET_SEND_CHECK, val, selfS->len - 1) == CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_GET_SEND_CHECK, val, selfS->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(val, selfS->x, selfS->len) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_DO_CHECK, peerS->x, peerS->len) == CRYPT_SUCCESS);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_CHECK_TC002
 * @title  SM2 EAL key exchange check.
 * @precon Vectors:
 *         server: The value 1 indicates the initiator, and the value 0 indicates the responder.
 *         User 1: private key, generate random number r, userId1, optional term S
 *         User 2: public key , R, userId2, optional term S
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_CHECK_TC002(Hex *prvKey, Hex *pubKey, Hex *r, Hex *R, Hex *shareKey, Hex *userId1,
    Hex *userId2, int server, Hex *peerS, Hex *selfS, int isProvider)
{
    uint8_t out[500];
    uint32_t outLen = shareKey->len;
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t val[selfS->len];
    CRYPT_EAL_PkeyPrv prv = {0};
    CRYPT_EAL_PkeyPub pub = {0};
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);
    uint8_t random[32];
    uint32_t randomLen = 32;
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx1 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_TRUE(ctx1 != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_DO_CHECK, peerS->x, peerS->len) == CRYPT_SM2_ERR_S_NOT_SET);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_USER_ID, userId1->x, userId1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_SERVER, &server, sizeof(int32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SET_SM2_RANDOM, r->x, r->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GET_SM2_RANDOM, random, randomLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(random, r->x, r->len) == 0);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_USER_ID, userId2->x, userId2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_SM2_R, R->x, R->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx1, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx2, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyComputeShareKey(ctx1, ctx2, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(outLen == shareKey->len);
    ASSERT_TRUE(memcmp(out, shareKey->x, shareKey->len) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_DO_CHECK, peerS->x, peerS->len - 1) == CRYPT_SM2_ERR_DATA_LEN);
    ASSERT_TRUE(
        CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_GET_SEND_CHECK, val, selfS->len - 1) == CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_GET_SEND_CHECK, val, selfS->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(val, selfS->x, selfS->len) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_SM2_DO_CHECK, peerS->x, peerS->len) == CRYPT_SUCCESS);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */
