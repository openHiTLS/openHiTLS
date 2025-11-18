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

#include "crypt_eal_pkey.h"
#include "eal_pkey_local.h"
#include "crypt_sm2.h"
#include "sm2_local.h"

#define SM2_SIGN_MAX_LEN 74
#define SM2_PRVKEY_MAX_LEN 32
#define SM2_PUBKEY_LEN 65
#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
/* END_HEADER */

/**
 * @test   SDV_CRYPTO_SM2_GET_PUB_API_TC001
 * @title  SM2 CRYPT_EAL_PkeyGetPub: Test the validity of parameters.
 * @precon Prepare valid public key.
 * @brief
 *    1. Create the context of the sm2 algorithm, expected result 1
 *    2. Set the valid public key, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPub method to set public key:
 *       (1) pub.data = NULL,  expected result 3
 *       (2) pub.len is invalid (pubKey.len - 1),  expected result 4
 *       (3) all parameters are valid, expected result 5
 *       (4) pub.len = prvKey.len + 1, expected result 6
 *    4. Compare the getted key and vector, expected result 7
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_ECC_BUFF_LEN_NOT_ENOUGH
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GET_PUB_API_TC001(Hex *pubKey, int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    uint8_t buf[SM2_PUBKEY_LEN];
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_PkeyPub pub, pubOut;
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);
    SetSm2PubKey(&pubOut, NULL, sizeof(buf));

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE_AND_LOG("NULL pubKey buffer", CRYPT_EAL_PkeyGetPub(ctx, &pubOut) == CRYPT_NULL_INPUT);

    pubOut.key.eccPub.data = buf;
    pubOut.key.eccPub.len = sizeof(buf) - 1;
    ASSERT_TRUE_AND_LOG("64 len pubKey buffer", CRYPT_EAL_PkeyGetPub(ctx, &pubOut) == CRYPT_ECC_BUFF_LEN_NOT_ENOUGH);

    pubOut.key.eccPub.data = buf;
    pubOut.key.eccPub.len = sizeof(buf);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(ctx, &pubOut) == CRYPT_SUCCESS);

    pubOut.key.eccPub.data = buf;
    pubOut.key.eccPub.len = sizeof(buf) + 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(ctx, &pubOut) == CRYPT_SUCCESS);

    ASSERT_TRUE(pubOut.key.eccPub.len == SM2_PUBKEY_LEN);
    ASSERT_TRUE(memcmp(buf, pubKey->x, pubKey->len) == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_GET_PRV_API_TC001
 * @title  SM2 CRYPT_EAL_PkeyGetPrv: Test the validity of parameters.
 * @precon Prepare valid private key.
 * @brief
 *    1. Create the context of the sm2 algorithm, expected result 1
 *    2. Set the valid private key, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPrv method to set private key:
 *       (1) prv.data = NULL,  expected result 3
 *       (2) prv.len is invalid (prvKey.len - 1),  expected result 4
 *       (3) all parameters are valid, expected result 5
 *       (4) prv.len = prvKey.len + 1, expected result 6
 *    4. Compare the getted key and vector, expected result 7
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GET_PRV_API_TC001(Hex *prvKey, int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    uint8_t buf[SM2_PRVKEY_MAX_LEN];
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_PkeyPrv prv, prvOut;
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    SetSm2PrvKey(&prvOut, NULL, prvKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(ctx, &prvOut) == CRYPT_NULL_INPUT);

    prvOut.key.eccPrv.data = buf;
    prvOut.key.eccPrv.len = prvKey->len - 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(ctx, &prvOut) == CRYPT_BN_BUFF_LEN_NOT_ENOUGH);

    prvOut.key.eccPrv.data = buf;
    prvOut.key.eccPrv.len = prvKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(ctx, &prvOut) == CRYPT_SUCCESS);

    prvOut.key.eccPrv.data = buf;
    prvOut.key.eccPrv.len = prvKey->len + 1;
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPrv(ctx, &prvOut) == CRYPT_SUCCESS);

    ASSERT_TRUE(prvOut.key.eccPrv.len == prvKey->len);
    ASSERT_TRUE(memcmp(buf, prvKey->x, prvKey->len) == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SET_PUB_API_TC001
 * @title  SM2 CRYPT_EAL_PkeySetPub: Test the validity of parameters.
 * @precon Prepare valid public key.
 * @brief
 *    1. Create the context of the sm2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPrv method to set private key:
 *       (1) pub.len is invalid (pubKey.len - 1),  expected result 2
 *       (2) pub.len is invalid (pubKey.len + 1),  expected result 3
 *       (3) public key is all 0x00,  expected result 4
 *       (4) ctx.id != pub.id,  expected result 5
 * @expect
 *    1. Success, and the context is not NULL.
 *    2-4. CRYPT_ECC_ERR_POINT_CODE
 *    5. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SET_PUB_API_TC001(Hex *pubKey, int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t zero[SM2_PUBKEY_LEN] = {0};

    SetSm2PubKey(&pub, pubKey->x, pubKey->len - 1);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_ECC_ERR_POINT_CODE);

    pub.key.eccPub.len = pubKey->len + 1;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_ECC_ERR_POINT_CODE);

    pub.key.eccPub.len = pubKey->len;
    pub.key.eccPub.data = zero;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_ECC_ERR_POINT_CODE);

    pub.id = CRYPT_PKEY_ED25519;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_EAL_ERR_ALGID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SET_PRV_API_TC001
 * @title  SM2 CRYPT_EAL_PkeySetPrv: Test the validity of parameters.
 * @precon Prepare valid private key.
 * @brief
 *    1. Create the context of the sm2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPrv method to set private key:
 *       (1) prv.len is invalid (prvKey.len + 1),  expected result 2
 *       (2) private key is all 0x00,  expected result 2
 *       (3) private key is all 0xFF,  expected result 2
 *       (4) value of private key  == order(curve_sm2) - 1,  expected result 2
 *       (5) ctx id is wrong,  expected result 3
 * @expect
 *    1. Success, and the context is not NULL.
 *    2. CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY
 *    3. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SET_PRV_API_TC001(Hex *prvKey, int isProvider)
{
    uint8_t zero[SM2_PRVKEY_MAX_LEN] = {0};
    uint8_t fullF[SM2_PRVKEY_MAX_LEN];
    uint8_t prvKeyCopy[SM2_PRVKEY_MAX_LEN + 1] = {0};
    CRYPT_EAL_PkeyPrv prv = {0};

    (void)memset_s(fullF, sizeof(fullF), 0xff, sizeof(fullF));

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(memcpy_s(prvKeyCopy, SM2_PRVKEY_MAX_LEN + 1, prvKey->x, prvKey->len) == CRYPT_SUCCESS);
    SetSm2PrvKey(&prv, prvKeyCopy, prvKey->len + 1);
    ASSERT_TRUE_AND_LOG("invalid prv len", CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);

    prv.key.eccPrv.len = prvKey->len;
    prv.key.eccPrv.data = zero;
    ASSERT_TRUE_AND_LOG("zero data key", CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);
    prv.key.eccPrv.data = fullF;
    ASSERT_TRUE_AND_LOG("full 1 key", CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);

    prv.id = CRYPT_PKEY_SM2;
    prv.key.eccPrv.data = prvKey->x;
    prv.key.eccPrv.len = prvKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY);

    prv.id = CRYPT_PKEY_ED25519;
    prv.key.eccPrv.data = prvKey->x;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_EAL_ERR_ALGID);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_GET_SIGN_LEN_API_TC001
 * @title  SM2: CRYPT_EAL_PkeyGetSignLen test.
 * @precon nan
 * @brief
 *    1. Create the context of the sm2 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetSignLen method, where pkey is NULL, expected result 2.
 *    3. Call the CRYPT_EAL_PkeyGetSignLen method, where pkey is valid, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Reutrn 0.
 *    3. Return SM2_SIGN_MAX_LEN(72)
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GET_SIGN_LEN_API_TC001(int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetSignLen(NULL) == 0);
    ASSERT_EQ(CRYPT_EAL_PkeyGetSignLen(ctx), SM2_SIGN_MAX_LEN);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_GET_KEY_LEN_API_TC001
 * @title  SM2: CRYPT_EAL_PkeyGetKeyLen test.
 * @precon nan
 * @brief
 *    1. Create the context of the sm2 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGetKeyLen method, where pkey is NULL, expected result 2.
 *    3. Call the CRYPT_EAL_PkeyGetKeyLen method, where pkey is valid, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Reutrn 0.
 *    3. Return SM2_PUBKEY_LEN(65)
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GET_KEY_LEN_API_TC001(int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyLen(NULL) == 0);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyLen(ctx) == SM2_PUBKEY_LEN);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_GEN_API_TC001
 * @title  SM2: CRYPT_EAL_PkeyGen test.
 * @precon nan
 * @brief
 *    1. Create the context(pkey) of the sm2 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyGen method, expected result 2
 *    3. Register wrong rand method: FakeRandFunc(The random number it generated is 0), expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen method, expected result 4
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NO_REGIST_RAND
 *    3. CRYPT_ECC_PKEY_ERR_TRY_CNT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GEN_API_TC001(int isProvider)
{
    TestMemInit();
    uint8_t zero[RAND_BUF_LEN] = {0};
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(ctx) == CRYPT_NO_REGIST_RAND);

    ASSERT_TRUE(SetFakeRandOutput(zero, sizeof(zero)) == CRYPT_SUCCESS);
    CRYPT_RandRegist(FakeRandFunc);
    CRYPT_RandRegistEx(FakeRandFuncEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(ctx) == CRYPT_ECC_PKEY_ERR_TRY_CNT);

    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(ctx) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_API_TC001
 * @title  SM2: CRYPT_EAL_PkeySign test.
 * @precon Vertor: private key.
 * @brief
 *    1. Init the DRBG.
 *    2. Create the context of the SM2 algorithm, expected result 1.
 *    3. Call the CRYPT_EAL_PkeyCtrl method to set userId, expected result 2.
 *    4. Call the CRYPT_EAL_PkeySign method, where all parameters are valid, expected result 3.
 *    5. Free the context and create a new context of the SM2 algorithm, expected result 4.
 *    6. Call the CRYPT_EAL_PkeySetPrv method to set private key, expected result 5.
 *    7. Call the CRYPT_EAL_PkeyCtrl method to set userId, expected result 6.
 *    8. Call the CRYPT_EAL_PkeySign method, where other parameters are valid, but:
 *        (1) signLen is not enough, expected result 7
 *        (2) sign = NULL, signLen != 0, expected result 8
 *        (3) msg = NULL, msgLen != 0, expected result 9
 *        (4) msg = NULL, msgLen = 0, expected result 10
 *        (5) mdId != CRYPT_MD_SM3, msg = NULL, msgLen = 0, expected result 11
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SM2_NO_PRVKEY
 *    4. Success, and context is not NULL.
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. CRYPT_SM2_BUFF_LEN_NOT_ENOUGH
 *    8-9. CRYPT_NULL_INPUT
 *    10. CRYPT_SUCCESS
 *    11. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_API_TC001(Hex *prvKey, int isProvider)
{
    uint8_t userId[SM2_PRVKEY_MAX_LEN] = {0};  // legal id
    uint8_t msg[SM2_PRVKEY_MAX_LEN] = {0};
    uint8_t signBuf[SM2_SIGN_MAX_LEN];
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyPrv prv = {0};
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen) == CRYPT_SM2_NO_PRVKEY);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    signLen -= 1;
    ASSERT_TRUE(
        CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen) == CRYPT_SM2_BUFF_LEN_NOT_ENOUGH);

    signLen = sizeof(signBuf);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg, sizeof(msg), NULL, &signLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, sizeof(msg), signBuf, &signLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, 0, signBuf, &signLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, NULL, 0, signBuf, &signLen) == CRYPT_EAL_ERR_ALGID);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_DATA_API_TC001
 * @title  SM2: CRYPT_EAL_PkeySignData test.
 * @precon Vertor: private key.
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1.
 *    2. Set userId and private key, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySignData method, where all parameters are valid, expected result 3.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_EAL_ALG_NOT_SUPPORT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_DATA_API_TC001(Hex *prvKey, int isProvider)
{
    uint8_t userId[SM2_PRVKEY_MAX_LEN] = {0};  // legal id
    uint8_t msg[SM2_PRVKEY_MAX_LEN] = {0};
    uint8_t signBuf[SM2_SIGN_MAX_LEN];
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyPrv prv = {0};
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySignData(ctx, msg, sizeof(msg), signBuf, &signLen) == CRYPT_EAL_ALG_NOT_SUPPORT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_API_TC002
 * @title  SM2: CRYPT_EAL_PkeySign test: Random number error.
 * @precon Vertor: private key.
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1.
 *    2. Set userId and private key, expected result 2.
 *    3. Call the CRYPT_EAL_PkeySign method, where all parameters are valid, expected result 3.
 *    4. Register wrong rand method: FakeRandFunc(The random number it generated is 0), expected result 4.
 *    5. Call the CRYPT_EAL_PkeySign method, where all parameters are valid, expected result 5.
 *    6. Register correct rand method and Call the CRYPT_EAL_PkeySign method to signature, expected result 6.
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NO_REGIST_RAND
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SM2_ERR_TRY_CNT or CRYPT_ECC_POINT_BLIND_WITH_ZERO
 *    6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_API_TC002(Hex *prvKey, int isProvider)
{
    uint8_t zero[RAND_BUF_LEN] = {0};
    uint8_t userId[SM2_PRVKEY_MAX_LEN] = {0};  // legal id
    uint8_t signBuf[SM2_SIGN_MAX_LEN];
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyPrv prv = {0};

    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, 0, signBuf, &signLen) == CRYPT_NO_REGIST_RAND);

    ASSERT_TRUE(SetFakeRandOutput(zero, sizeof(zero)) == CRYPT_SUCCESS);
    CRYPT_RandRegist(FakeRandFunc);
    CRYPT_RandRegistEx(FakeRandFuncEx);
    int32_t ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, 0, signBuf, &signLen);
    /* When assembly is enabled, the error code is CRYPT_SM2_ERR_TRY_CNT. Otherwise, the error code is
     * CRYPT_ECC_POINT_BLIND_WITH_ZERO. */
    ASSERT_TRUE(ret == CRYPT_SM2_ERR_TRY_CNT || ret == CRYPT_ECC_POINT_BLIND_WITH_ZERO);

    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, 0, signBuf, &signLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_VERIFY_API_TC001
 * @title  SM2: CRYPT_EAL_PkeyVerify test.
 * @precon Vectors: public key, userId, msg, signature.
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1.
 *    2. Call the CRYPT_EAL_PkeyCtrl method to set userId, expected result 2.
 *    3. Call the CRYPT_EAL_PkeyVerify method, where all parameters are valid, expected result 3.
 *    4. Free the context and create a new context of the SM2 algorithm, expected result 4.
 *    5. Set public key, expected result 5.
 *    6. Set userId, expected result 6.
 *    7. Call the CRYPT_EAL_PkeyVerify method:
 *        (1) signLen is invalid: sign->len - 1 or sign->len + 1, expected result 7
 *        (3) msg = NULL, msgLen != 0, expected result 8
 *        (2) sign = NULL, signLen != 0, expected result 9
 *        (4) all parameters are valid, expected result 10
 *        (5) mdId != CRYPT_MD_SM3, expected result 11
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SM2_NO_PUBKEY
 *    4. Success, and context is not NULL.
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. CRYPT_DSA_DECODE_FAIL
 *    8-9. CRYPT_NULL_INPUT
 *    10. CRYPT_SUCCESS
 *    11. CRYPT_EAL_ERR_ALGID
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_VERIFY_API_TC001(Hex *pubKey, Hex *userId, Hex *msg, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t bigSign[SM2_SIGN_MAX_LEN + 1] = {0};

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len) == CRYPT_SM2_NO_PUBKEY);

    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(memcpy_s(bigSign, SM2_SIGN_MAX_LEN + 1, sign->x, sign->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len - 1),
        BSL_ASN1_ERR_DECODE_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, bigSign, SM2_SIGN_MAX_LEN + 1),
        CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, NULL, msg->len, sign->x, sign->len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, NULL, sign->len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(
        CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sign->x, sign->len) == CRYPT_EAL_ERR_ALGID);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CTRL_API_TC001
 * @title  SM2 CRYPT_EAL_PkeyCtrl: Test set user id.
 * @precon vector: valid R.
 * @brief
 *    1. Create the context of the SM2 algorithm, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCtrl, opt = CRYPT_CTRL_SET_SM2_USER_ID:
 *       (1) userId = null, idLen = 8191, and other parameters are valid, expected result 2
 *       (2) userId = null, idLen = 0, and other parameters are valid, expected result 3
 *       (3) userId != null, idLen = 8192, and other parameters are valid, expected result 4
 *       (4) userId != null, idLen = 8191, and other parameters are valid, expected result 5
 *       (5) userId != null, idLen = 1, and other parameters are valid, expected result 6
 * @expect
 *    1. Success, and context is not NULL.
 *    2. CRYPT_NULL_INPUT
 *    3-4. CRYPT_ECC_PKEY_ERR_CTRL_LEN
 *    5-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CTRL_API_TC001(int isProvider)
{
    uint8_t userId[8192] = {0};  // max id len 8191, plus one for test
    uint32_t idLen = sizeof(userId) - 1;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, NULL, idLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, 0) == CRYPT_ECC_PKEY_ERR_CTRL_LEN);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, idLen + 1) == CRYPT_ECC_PKEY_ERR_CTRL_LEN);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, idLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, 1) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_FUNC_TC001
 * @title  ED25519 signature test: set the key or duplicate the context, and sign.
 * @precon private key, userId, random number k, msg, signature.
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Set the userId and private key for ctx, expected result 2
 *    3. Mock BN_RandRange to generate k, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Compare the signgures of HiTLS and vector, expected result 5
 *    6. Call the CRYPT_EAL_PkeyDupCtx method to dup sm2 context, expected result 6
 *    7. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 7
 *    8. Compare the signgures of HiTLS and vector, expected result 8
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Both are the same.
 *    6. Success, and context is not NULL.
 *    7. CRYPT_SUCCESS
 *    8. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_FUNC_TC001(Hex *prvKey, Hex *userId, Hex *k, Hex *msg, Hex *sign, int isProvider)
{
    uint8_t signBuf[100];
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    CRYPT_EAL_PkeyPrv prv = {0};
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);

    CRYPT_RandRegist(FakeRandFunc);
    CRYPT_RandRegistEx(FakeRandFuncEx);
    ASSERT_TRUE(SetFakeRandOutput(k->x, k->len) == CRYPT_SUCCESS);

    STUB_REPLACE(BN_RandRangeEx, STUB_RandRangeK);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg->x, msg->len, signBuf, &signLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(signLen == sign->len);
    ASSERT_TRUE(memcmp(signBuf, sign->x, sign->len) == 0);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    signLen = sizeof(signBuf);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, CRYPT_MD_SM3, msg->x, msg->len, signBuf, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(signLen, sign->len);
    ASSERT_TRUE(memcmp(signBuf, sign->x, sign->len) == 0);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    STUB_RESTORE(BN_RandRangeEx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_FUNC_TC002
 * @title  SM2 EAL layer signature function test.
 * @precon prvKeyTmp, private key, userId, random number k, msg, signature.
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Repeatedly set the userId and private key of ctx, expected result 2
 *    3. Mock BN_RandRange to generate k, expected result 3
 *    4. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 4
 *    5. Compare the signgures of HiTLS and vector, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_FUNC_TC002(
    Hex *prvKeyTmp, Hex *prvKey, Hex *userId, Hex *k, Hex *msg, Hex *sign, int isProvider)
{
    uint8_t signBuf[100];
    uint8_t userIdBuf[100] = {0};
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyPrv prv = {0};
    SetSm2PrvKey(&prv, prvKeyTmp->x, prvKeyTmp->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userIdBuf, sizeof(userIdBuf)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);
    prv.key.eccPrv.data = prvKey->x;
    prv.key.eccPrv.len = prvKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);

    CRYPT_RandRegist(FakeRandFunc);
    CRYPT_RandRegistEx(FakeRandFuncEx);
    ASSERT_TRUE(SetFakeRandOutput(k->x, k->len) == CRYPT_SUCCESS);

    STUB_REPLACE(BN_RandRangeEx, STUB_RandRangeK);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg->x, msg->len, signBuf, &signLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(signLen == sign->len);
    ASSERT_TRUE(memcmp(signBuf, sign->x, sign->len) == 0);

EXIT:
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    STUB_RESTORE(BN_RandRangeEx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_VERIFY_FUNC_TC001
 * @title  SM2 verify test: set public key or duplicate the context, and verify.
 * @precon public key, userId, msg, signature.
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Set the userId and public key of ctx, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method to verify, expected result 3
 *    4. Call the CRYPT_EAL_PkeyDupCtx method to dup sm2 context, expected result 4
 *    5. Call the CRYPT_EAL_PkeyVerify method to verify, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. Success, and context is not NULL.
 *    5. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_VERIFY_FUNC_TC001(Hex *pubKey, Hex *userId, Hex *msg, Hex *sign, int isProvider)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_PkeyPub pub = {0};

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len) == CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(dupCtx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_VERIFY_FUNC_TC002
 * @title  SM2 verify test: Repeatedly set public key, and verify.
 * @precon public key, userId, msg, signature.
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Repeatedly set the userId and public key of ctx, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method to verify, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_VERIFY_FUNC_TC002(
    Hex *pubKeyTmp, Hex *pubKey, Hex *userId, Hex *msg, Hex *sign, int isProvider)
{
    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_PkeyPub pub = {0};

    SetSm2PubKey(&pub, pubKeyTmp->x, pubKeyTmp->len);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);
    pub.key.eccPub.data = pubKey->x;
    pub.key.eccPub.len = pubKey->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_VERIFY_FUNC_TC001
 * @title  SM2: Generate a key pair for signature and verify.
 * @precon nan
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Initialize the DRBG, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 3
 *    4. Set the userId for ctx, expected result 4
 *    5. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 5
 *    6. Call the CRYPT_EAL_PkeyVerify method to verify signature, expected result 6
 *    7. Call the CRYPT_EAL_PkeyDupCtx method to dup sm2 context, expected result 7
 *    8. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 8
 *    9. Call the CRYPT_EAL_PkeyVerify method to verify signature, expected result 9
 *    10. Call the CRYPT_EAL_PkeyCpyCtx method to dup sm2 context, expected result 10
 *    11. Call the CRYPT_EAL_PkeySign method to compute signature, expected result 11
 *    12. Call the CRYPT_EAL_PkeyVerify method to verify signature, expected result 12
 * @expect
 *    1. Success, and context is not NULL.
 *    2-6. CRYPT_SUCCESS
 *    7. Success, and context is not NULL.
 *    8-12. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_VERIFY_FUNC_TC001(int isProvider)
{
    uint8_t userId[SM2_PRVKEY_MAX_LEN] = {0};  // legal id
    uint8_t signBuf[SM2_SIGN_MAX_LEN];
    uint8_t msg[SM2_PRVKEY_MAX_LEN] = {0};
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(ctx) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, signLen) == CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);
    ASSERT_EQ(dupCtx->references.count, 1);
    signLen = sizeof(signBuf);
    ASSERT_EQ(CRYPT_EAL_PkeySign(dupCtx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(dupCtx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, signLen) == CRYPT_SUCCESS);

    cpyCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, ctx), CRYPT_SUCCESS);
    signLen = sizeof(signBuf);
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, signLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_VERIFY_FUNC_TC003
 * @title  SM2: Test verification failure scenario.
 * @precon public key, userId, msg, signature, one of the vectors is wrong.
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Repeatedly set the userId and public key of ctx, expected result 2
 *    3. Call the CRYPT_EAL_PkeyVerify method to verify, expected result 3
 * @expect
 *    1. Success, and context is not NULL.
 *    2-3. Not CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_VERIFY_FUNC_TC003(Hex *pubKey, Hex *userId, Hex *msg, Hex *sign, int isProvider)
{
    CRYPT_EAL_PkeyPub pub = {0};
    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId->x, userId->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);
    // Different errors will return different error codes.
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg->x, msg->len, sign->x, sign->len) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_VERIFY_FUNC_TC002
 * @title  SM2: The private/public key is not cleaned up when setting the public/private key.
 * @precon public key, userId, msg, signature, one of the vectors is wrong.
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm, expected result 1
 *    2. Repeatedly set the userId, public key and private key of ctx, expected result 2
 *    3. Call the CRYPT_EAL_PkeySign method to signature, expected result 3
 *    4. Call the CRYPT_EAL_PkeyVerify method to verify, expected result 4
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_SIGN_VERIFY_FUNC_TC002(Hex *pubKey, Hex *prvKey, int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    uint8_t userId[SM2_PRVKEY_MAX_LEN] = {0};  // legal id
    uint8_t signBuf[SM2_SIGN_MAX_LEN];
    uint8_t msg[SM2_PRVKEY_MAX_LEN] = {0};
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(ctx, &prv) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(ctx, &pub) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, signLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_KEY_PAIR_CHECK_FUNC_TC001
 * @title  SM2: key pair check.
 * @precon Registering memory-related functions.
 * @brief
 *    1. Create two contexts(pubCtx, prvCtx) of the sm2 algorithm, expected result 1
 *    2. Set public key for pubCtx, expected result 2
 *    3. Set private key for prvCtx, expected result 3
 *    4. Set userId for pubCtx and prvCtx, expected result 4
 *    5. Init the drbg, expected result 5
 *    6. Check whether the public key matches the private key, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2-5. CRYPT_SUCCESS
 *    6. Return CRYPT_SUCCESS when expect is 1, CRYPT_SM2_VERIFY_FAIL otherwise.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_KEY_PAIR_CHECK_FUNC_TC001(Hex *pubKey, Hex *prvKey, Hex *userId, int expect, int isProvider)
{
#if !defined(HITLS_CRYPTO_SM2_CHECK)
    (void)pubKey;
    (void)prvKey;
    (void)userId;
    (void)expect;
    (void)isProvider;
    SKIP_TEST();
#else
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    int expectRet = expect == 1 ? CRYPT_SUCCESS : CRYPT_SM2_PAIRWISE_CHECK_FAIL;

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);
    SetSm2PrvKey(&prv, prvKey->x, prvKey->len);

    TestMemInit();

    pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pubCtx != NULL && prvCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &prv), CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pubCtx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_SET_SM2_USER_ID, userId, sizeof(userId)) == CRYPT_SUCCESS);

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), expectRet);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_GET_KEY_BITS_FUNC_TC001
 * @title  SM2: get key bits.
 * @brief
 *    1. Create a context of the SM2 algorithm, expected result 1
 *    2. Get key bits, expected result 2
 * @expect
 *    1. Success, and context is not NULL.
 *    2. Equal to keyBits.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GET_KEY_BITS_FUNC_TC001(int id, int keyBits, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, id,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE  + CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetKeyBits(pkey) == (uint32_t)keyBits);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CHECK_KEYPAIR_FUNC_TC001
 * @title  SM2 CRYPT_EAL_PkeyPairCheck test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CHECK_KEYPAIR_FUNC_TC001(int isProvider)
{
#if !defined(HITLS_CRYPTO_SM2_CHECK)
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    uint8_t wrong[100] = {1};
    CRYPT_EAL_PkeyPub sm2PubKey = {0};
    CRYPT_EAL_PkeyPrv sm2PrvKey = {0};
    uint8_t pubKeyVector[100];
    uint32_t pubKeyVectorLen = sizeof(pubKeyVector);
    uint8_t prvKeyVector[100];
    uint32_t prvKeyVectorLen = sizeof(prvKeyVector);
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *pubCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(pubCtx != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    SetSm2PubKey(&sm2PubKey, pubKeyVector, pubKeyVectorLen);
    SetSm2PrvKey(&sm2PrvKey, prvKeyVector, prvKeyVectorLen);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pkey, pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &sm2PubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &sm2PrvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubCtx, &sm2PubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &sm2PrvKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SUCCESS);

    sm2PrvKey.key.eccPrv.data = wrong;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvCtx, &sm2PrvKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPairCheck(pubCtx, prvCtx), CRYPT_SM2_PAIRWISE_CHECK_FAIL);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
#endif
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CHECK_PRVKEY_FUNC_TC001
 * @title  SM2 CRYPT_EAL_PkeyPrvCheck test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CHECK_PRVKEY_FUNC_TC001(int isProvider)
{
#if !defined(HITLS_CRYPTO_SM2_CHECK)
    (void)isProvider;
    SKIP_TEST();
#else
    TestMemInit();
    CRYPT_EAL_PkeyPrv sm2PrvKey = {0};
    CRYPT_SM2_Ctx *ctx = NULL;
    BN_BigNum *n = NULL;
    BN_BigNum *prvKey = NULL;

    uint8_t prvKeyVector[100];
    uint32_t prvKeyVectorLen = sizeof(prvKeyVector);
    CRYPT_EAL_PkeyCtx *pkey = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    CRYPT_EAL_PkeyCtx *prvCtx = TestPkeyNewCtx(NULL, CRYPT_PKEY_SM2,
        CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default", isProvider);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_TRUE(prvCtx != NULL);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    SetSm2PrvKey(&sm2PrvKey, prvKeyVector, prvKeyVectorLen);

    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_ECC_PKEY_ERR_EMPTY_KEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    ctx = (CRYPT_SM2_Ctx *)pkey->key;
    prvKey = ctx->pkey->prvkey;
    n = ECC_GetParaN(ctx->pkey->para);

    (void)BN_Copy(prvKey, n); // key = n
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SM2_INVALID_PRVKEY);

    (void)BN_SubLimb(prvKey, prvKey, 1); // key = n - 1
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SM2_INVALID_PRVKEY);

    (void)BN_SubLimb(prvKey, prvKey, 1); // key = n - 2
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SUCCESS);

    (void)BN_Zeroize(prvKey); // key = 0
    ASSERT_EQ(CRYPT_EAL_PkeyPrvCheck(pkey), CRYPT_SM2_INVALID_PRVKEY);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BN_Destroy(n);
#endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_KEY_DECODE_CHAIN
static int32_t ImportSm2Pkey(const BSL_Param *param, void *args)
{
    CRYPT_SM2_Ctx *importSm2Ctx = CRYPT_SM2_NewCtx();
    if (importSm2Ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = CRYPT_SM2_Import(importSm2Ctx, param);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_SM2_FreeCtx(importSm2Ctx);
        return ret;
    }
    *((CRYPT_SM2_Ctx **)args) = importSm2Ctx;
    return CRYPT_SUCCESS;
}
#endif

/**
 * @test   SDV_CRYPTO_SM2_Import_Export_FUNC_TC001
 * @title  SM2 CRYPT_SM2_Import and CRYPT_SM2_Export test.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_Import_Export_FUNC_TC001(void)
{
#ifndef HITLS_CRYPTO_KEY_DECODE_CHAIN
    SKIP_TEST();
#else
    CRYPT_SM2_Ctx *srcSm2Ctx = NULL;
    CRYPT_SM2_Ctx *dstSm2Ctx = NULL;
    uint8_t msg[2] = {1, 2};
    uint8_t sign[128];
    uint32_t signLen = sizeof(sign);
    BSL_Param param[3] = {
        {CRYPT_PARAM_PKEY_PROCESS_FUNC, BSL_PARAM_TYPE_FUNC_PTR, ImportSm2Pkey, 0, 0},
        {CRYPT_PARAM_PKEY_PROCESS_ARGS, BSL_PARAM_TYPE_CTX_PTR, &dstSm2Ctx, 0, 0},
        BSL_PARAM_END
    };
    
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    srcSm2Ctx = CRYPT_SM2_NewCtx();
    ASSERT_TRUE(srcSm2Ctx != NULL);
    ASSERT_EQ(CRYPT_SM2_Gen(srcSm2Ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SM2_Export(srcSm2Ctx, param), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_SM2_Sign(srcSm2Ctx, CRYPT_MD_SM3, msg, sizeof(msg), sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_SM2_Verify(dstSm2Ctx, CRYPT_MD_SM3, msg, sizeof(msg), sign, signLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_SM2_FreeCtx(srcSm2Ctx);
    CRYPT_SM2_FreeCtx(dstSm2Ctx);
#endif
}
/* END_CASE */
