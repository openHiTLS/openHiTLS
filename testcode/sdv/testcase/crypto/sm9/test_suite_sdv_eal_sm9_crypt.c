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
/* INCLUDE_BASE test_suite_sdv_eal_sm9 */

/* BEGIN_HEADER */

#include "crypt_eal_pkey.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_sm9.h"
#include "crypt_params_key.h"
#include "bsl_params.h"
#include "securec.h"

#define SM9_ENC_MASTER_KEY_LEN 32
#define SM9_CIPHERTEXT_MAX_LEN 512
#define SM9_PLAINTEXT_MAX_LEN 256
#define SM9_KEY_TYPE_SIGN 1
#define SM9_KEY_TYPE_ENC 2

/* END_HEADER */

/**
 * @test   SDV_CRYPTO_SM9_CRYPT_API_TC001
 * @title  SM9 EAL Encrypt and Decrypt: Test basic encryption and decryption using EAL interfaces.
 * @precon Prepare valid master key and user ID.
 * @brief
 *    1. Create SM9 contexts via EAL, expected result 1
 *    2. Generate user decrypt key, expected result 2
 *    3. Set encrypt context with master public key, expected result 3
 *    4. Encrypt plaintext using EAL, expected result 4
 *    5. Set decrypt context with user private key, expected result 5
 *    6. Decrypt ciphertext using EAL, expected result 6
 *    7. Compare decrypted with original, expected result 7
 * @expect
 *    1. Success, contexts are not NULL
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. Match
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_CRYPT_API_TC001(Hex *masterKey, Hex *userId, Hex *plaintext)
{
    CRYPT_EAL_PkeyCtx *encCtx = NULL;
    CRYPT_EAL_PkeyCtx *decCtx = NULL;
    SM9_Ctx *nativeCtx = NULL;
    uint8_t ciphertext[SM9_CIPHERTEXT_MAX_LEN] = {0};
    uint32_t cipherLen = sizeof(ciphertext);
    uint8_t decrypted[SM9_PLAINTEXT_MAX_LEN] = {0};
    uint32_t decryptLen = sizeof(decrypted);
    uint8_t userKey[SM9_ENC_USR_PRIKEY_BYTES] = {0};
    uint8_t masterPubKey[SM9_ENC_SYS_PUBKEY_BYTES] = {0};
    int ret;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    // Step 1: Generate user decrypt key using native API (KGC operation)
    nativeCtx = SM9_NewCtx();
    ASSERT_TRUE(nativeCtx != NULL);
    ret = SM9_SetEncMasterKey(nativeCtx, masterKey->x);
    ASSERT_EQ(ret, SM9_OK);
    ret = SM9_GenEncUserKey(nativeCtx, userId->x, userId->len);
    ASSERT_EQ(ret, SM9_OK);
    memcpy_s(userKey, sizeof(userKey), nativeCtx->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);
    memcpy_s(masterPubKey, sizeof(masterPubKey), nativeCtx->enc_mpk, SM9_ENC_SYS_PUBKEY_BYTES);

    // Step 2: Create encrypt context and set master private key + user ID
    encCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(encCtx != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(encCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Encrypt plaintext

    ret = CRYPT_EAL_PkeyEncrypt(encCtx, plaintext->x, plaintext->len,
                                ciphertext, &cipherLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(cipherLen > plaintext->len);

    // Step 4: Create decrypt context and set master private key + user key
    decCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(decCtx != NULL);

    // First set master private key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(decCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Then set user private key (generate from master key + user ID)
    BSL_Param decParams[3];
    BSL_PARAM_InitValue(&decParams[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&decParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    decParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(decCtx, decParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Decrypt ciphertext
    ret = CRYPT_EAL_PkeyDecrypt(decCtx, ciphertext, cipherLen,
                                decrypted, &decryptLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(decryptLen, plaintext->len);

    // Step 6: Verify decrypted matches original
    ASSERT_TRUE(memcmp(decrypted, plaintext->x, plaintext->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(encCtx);
    CRYPT_EAL_PkeyFreeCtx(decCtx);
    SM9_FreeCtx(nativeCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_CRYPT_API_TC002
 * @title  SM9 EAL Encrypt: Test with NULL parameters using EAL interfaces.
 * @precon Prepare valid context.
 * @brief
 *    1. Create SM9 context via EAL, expected result 1
 *    2. Call CRYPT_EAL_PkeyEncrypt with NULL ctx, expected result 2
 *    3. Call CRYPT_EAL_PkeyDecrypt with NULL ctx, expected result 3
 *    4. Set valid keys and test NULL plaintext, expected result 4
 *    5. Test NULL ciphertext for decrypt, expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2-5. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_CRYPT_API_TC002(Hex *masterKey, Hex *userId, Hex *plaintext)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    SM9_Ctx *nativeCtx = NULL;
    uint8_t ciphertext[SM9_CIPHERTEXT_MAX_LEN] = {0};
    uint32_t cipherLen = sizeof(ciphertext);
    uint8_t decrypted[SM9_PLAINTEXT_MAX_LEN] = {0};
    uint32_t decryptLen = sizeof(decrypted);
    uint8_t userKey[SM9_ENC_USR_PRIKEY_BYTES] = {0};
    uint8_t masterPubKey[SM9_ENC_SYS_PUBKEY_BYTES] = {0};
    int ret;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Test NULL ctx for Encrypt
    ret = CRYPT_EAL_PkeyEncrypt(NULL, plaintext->x, plaintext->len,
                                ciphertext, &cipherLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Step 3: Test NULL ctx for Decrypt
    ret = CRYPT_EAL_PkeyDecrypt(NULL, ciphertext, cipherLen,
                                decrypted, &decryptLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Step 4: Set up valid keys
    nativeCtx = SM9_NewCtx();
    ASSERT_TRUE(nativeCtx != NULL);
    ret = SM9_SetEncMasterKey(nativeCtx, masterKey->x);
    ASSERT_EQ(ret, SM9_OK);
    ret = SM9_GenEncUserKey(nativeCtx, userId->x, userId->len);
    ASSERT_EQ(ret, SM9_OK);
    memcpy_s(userKey, sizeof(userKey), nativeCtx->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);
    memcpy_s(masterPubKey, sizeof(masterPubKey), nativeCtx->enc_mpk, SM9_ENC_SYS_PUBKEY_BYTES);

    // Set master private key + user ID for encryption
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Test NULL plaintext
    ret = CRYPT_EAL_PkeyEncrypt(ctx, NULL, plaintext->len,
                                ciphertext, &cipherLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Step 6: Test NULL output buffer
    ret = CRYPT_EAL_PkeyEncrypt(ctx, plaintext->x, plaintext->len,
                                NULL, &cipherLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    SM9_FreeCtx(nativeCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_CRYPT_API_TC003
 * @title  SM9 EAL Encrypt: Test encryption for different users using EAL interfaces.
 * @precon Prepare valid master key.
 * @brief
 *    1. Create SM9 contexts via EAL, expected result 1
 *    2. Generate keys for users A and B, expected result 2
 *    3. Encrypt for user A, expected result 3
 *    4. Encrypt for user B, expected result 4
 *    5. User A decrypts A's ciphertext, expected result 5
 *    6. User B decrypts B's ciphertext, expected result 6
 *    7. User A tries to decrypt B's ciphertext, expected result 7 (should fail)
 * @expect
 *    1. Success, contexts are not NULL
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_SUCCESS
 *    7. Decryption fails or produces wrong result
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_CRYPT_API_TC003(Hex *masterKey, Hex *userIdA, Hex *userIdB, Hex *plaintext)
{
    CRYPT_EAL_PkeyCtx *encCtxA = NULL;
    CRYPT_EAL_PkeyCtx *encCtxB = NULL;
    CRYPT_EAL_PkeyCtx *decCtxA = NULL;
    CRYPT_EAL_PkeyCtx *decCtxB = NULL;
    SM9_Ctx *nativeCtx = NULL;
    uint8_t ciphertextA[SM9_CIPHERTEXT_MAX_LEN] = {0};
    uint32_t cipherLenA = sizeof(ciphertextA);
    uint8_t ciphertextB[SM9_CIPHERTEXT_MAX_LEN] = {0};
    uint32_t cipherLenB = sizeof(ciphertextB);
    uint8_t decrypted[SM9_PLAINTEXT_MAX_LEN] = {0};
    uint32_t decryptLen = sizeof(decrypted);
    uint8_t userKeyA[SM9_ENC_USR_PRIKEY_BYTES] = {0};
    uint8_t userKeyB[SM9_ENC_USR_PRIKEY_BYTES] = {0};
    uint8_t masterPubKey[SM9_ENC_SYS_PUBKEY_BYTES] = {0};
    int ret;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_ENC;

    // Step 1: Generate user keys using native API (KGC operation)
    nativeCtx = SM9_NewCtx();
    ASSERT_TRUE(nativeCtx != NULL);
    ret = SM9_SetEncMasterKey(nativeCtx, masterKey->x);
    ASSERT_EQ(ret, SM9_OK);

    // Generate User A's key
    ret = SM9_GenEncUserKey(nativeCtx, userIdA->x, userIdA->len);
    ASSERT_EQ(ret, SM9_OK);
    memcpy_s(userKeyA, sizeof(userKeyA), nativeCtx->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);

    // Generate User B's key
    ret = SM9_GenEncUserKey(nativeCtx, userIdB->x, userIdB->len);
    ASSERT_EQ(ret, SM9_OK);
    memcpy_s(userKeyB, sizeof(userKeyB), nativeCtx->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);

    // Save master public key
    memcpy_s(masterPubKey, sizeof(masterPubKey), nativeCtx->enc_mpk, SM9_ENC_SYS_PUBKEY_BYTES);

    // Step 2: Create encrypt context for User A
    encCtxA = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(encCtxA != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdA->x, userIdA->len);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(encCtxA, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Encrypt for User A
    ret = CRYPT_EAL_PkeyEncrypt(encCtxA, plaintext->x, plaintext->len,
                                ciphertextA, &cipherLenA);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Create encrypt context for User B
    encCtxB = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(encCtxB != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdB->x, userIdB->len);
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(encCtxB, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Encrypt for User B
    ret = CRYPT_EAL_PkeyEncrypt(encCtxB, plaintext->x, plaintext->len,
                                ciphertextB, &cipherLenB);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 4: User A decrypts A's ciphertext
    decCtxA = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(decCtxA != NULL);

    // First set master private key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(decCtxA, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Then set user private key (generate from master key + user ID)
    BSL_Param decParams[3];
    BSL_PARAM_InitValue(&decParams[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdA->x, userIdA->len);
    BSL_PARAM_InitValue(&decParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    decParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(decCtxA, decParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    decryptLen = sizeof(decrypted);
    ret = CRYPT_EAL_PkeyDecrypt(decCtxA, ciphertextA, cipherLenA,
                                decrypted, &decryptLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(decrypted, plaintext->x, plaintext->len) == 0);

    // Step 5: User B decrypts B's ciphertext
    decCtxB = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(decCtxB != NULL);

    // First set master private key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(decCtxB, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Then set user private key (generate from master key + user ID)
    BSL_PARAM_InitValue(&decParams[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdB->x, userIdB->len);
    BSL_PARAM_InitValue(&decParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    decParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(decCtxB, decParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    decryptLen = sizeof(decrypted);
    ret = CRYPT_EAL_PkeyDecrypt(decCtxB, ciphertextB, cipherLenB,
                                decrypted, &decryptLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(decrypted, plaintext->x, plaintext->len) == 0);

    // Step 6: User A tries to decrypt B's ciphertext - should fail or produce wrong result
    decryptLen = sizeof(decrypted);
    ret = CRYPT_EAL_PkeyDecrypt(decCtxA, ciphertextB, cipherLenB,
                                decrypted, &decryptLen);
    // Either fails or decrypts to wrong plaintext
    if (ret == CRYPT_SUCCESS) {
        ASSERT_TRUE(memcmp(decrypted, plaintext->x, plaintext->len) != 0);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(encCtxA);
    CRYPT_EAL_PkeyFreeCtx(encCtxB);
    CRYPT_EAL_PkeyFreeCtx(decCtxA);
    CRYPT_EAL_PkeyFreeCtx(decCtxB);
    SM9_FreeCtx(nativeCtx);
}
/* END_CASE */
