/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
/* INCLUDE_BASE test_suite_sdv_eal_sm2 */

/* BEGIN_HEADER */

#include "crypt_local_types.h"
#include "crypt_sm2.h"
#include "crypt_encode.h"
#include "eal_pkey_local.h"

#define MAX_PLAIN_TEXT_LEN 2048
#define CIPHER_TEXT_EXTRA_LEN 97
#define SM2_SIGN_MAX_LEN 72
#define SM2_PRVKEY_MAX_LEN 32
#define SM2_PUBKEY_LEN 65

#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE  0
#define CRYPT_EAL_PKEY_CIPHER_OPERATE   1
#define CRYPT_EAL_PKEY_EXCH_OPERATE     2
#define CRYPT_EAL_PKEY_SIGN_OPERATE     4

/* END_HEADER */

/**
 * @test   SDV_CRYPTO_SM2_GEN_CRYPT_PROVIDER_FUNC_TC001
 * @title  SM2: Generate key pair, encryption, decryption for the default provider.
 * @precon Vector: plaintext.
 * @brief
 *    1. Create the context of the SM2 algorithm using the default provider, expected result 1
 *    2. Initialize the DRBG.
 *    3. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 2
 *    4. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 3
 *    5. Call the CRYPT_EAL_PkeyDecrypt to decrypt ciphertext, expected result 4
 *    6. Compare the decryption result with the plaintext vector, expected result 5
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_GEN_CRYPT_PROVIDER_FUNC_TC001(Hex *msg)
{
    uint8_t cipherText[MAX_PLAIN_TEXT_LEN + CIPHER_TEXT_EXTRA_LEN];
    uint8_t plainText[MAX_PLAIN_TEXT_LEN];
    uint32_t ctLen = sizeof(cipherText);
    uint32_t ptLen = sizeof(plainText);

    TestMemInit();
    
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default");
    ASSERT_TRUE(ctx != NULL);

    CRYPT_RandRegist(RandFunc);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(ctx) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(ctx, msg->x, msg->len, cipherText, &ctLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(ctx, cipherText, ctLen, plainText, &ptLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(ptLen == msg->len);
    ASSERT_TRUE(memcmp(plainText, msg->x, msg->len) == 0);

exit:
    CRYPT_RandRegist(NULL);
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_EXCHANGE_PROVIDER_API_TC001
 * @title  SM2: CRYPT_EAL_PkeyComputeShareKey Test: R is not set for the default provider.
 * @precon Test Vectors for SM2: public key, private key
 * @brief
 *    1. Init the Drbg and create two contexts(ctx1, ctx2) of the SM2 algorithm using the default provider, expected result 1.
 *    2. ctx1: set userId, server, private key and generate r, expected result 2.
 *    3. ctx2: set userId and public key, expected result 3.
 *    4. Call the CRYPT_EAL_PkeyComputeShareKey method, expected result 4.
 * @expect
 *    1. Success, and two contexts are not NULL.
 *    2-3. CRYPT_SUCCESS
 *    4. CRYPT_SM2_R_NOT_SET
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_EXCHANGE_PROVIDER_API_TC001(Hex *prvKey, Hex *pubKey)
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
    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_EXCH_OPERATE, "provider=default");
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

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_RandRegist(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_SIGN_VERIFY_PROVIDER_FUNC_TC001
 * @title  SM2: Generate a key pair for signature and verify for the default provider.
 * @precon nan
 * @brief
 *    1. Create the context(ctx) of the sm2 algorithm using the default provider, expected result 1
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
void SDV_CRYPTO_SM2_SIGN_VERIFY_PROVIDER_FUNC_TC001(void)
{
    uint8_t userId[SM2_PRVKEY_MAX_LEN] = {0};  // legal id
    uint8_t signBuf[SM2_SIGN_MAX_LEN];
    uint8_t msg[SM2_PRVKEY_MAX_LEN] = {0};
    uint32_t signLen = sizeof(signBuf);
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ASSERT_TRUE(ctx != NULL);

    CRYPT_RandRegist(RandFunc);
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

    cpyCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, ctx), CRYPT_SUCCESS);
    signLen = sizeof(signBuf);
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, CRYPT_MD_SM3, msg, sizeof(msg), signBuf, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    CRYPT_RandRegist(NULL);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM2_CMP_PROVIDER_FUNC_TC001
 * @title  SM2: The input and output parameters address are the same for the default provider.
 * @precon Vector: private key and public key.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the SM2 algorithm using the default provider, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set public key for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set public key for ctx2, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL
 *    5-6. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM2_CMP_PROVIDER_FUNC_TC001(Hex *pubKey)
{
    CRYPT_EAL_PkeyPub pub = {0};

    SetSm2PubKey(&pub, pubKey->x, pubKey->len);

    TestMemInit();

    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtxWithLib(NULL, CRYPT_PKEY_SM2, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */