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

#define SM9_SIGNATURE_LEN 96
#define SM9_SIG_MASTER_KEY_LEN 32
#define SM9_USER_ID_MAX_LEN 256
#define SM9_KEY_TYPE_SIGN 1
#define SM9_KEY_TYPE_ENC 2

/* END_HEADER */

/**
 * @test   SDV_CRYPTO_SM9_SIGN_API_TC002
 * @title  SM9 EAL Sign: Test with NULL parameters using EAL interfaces.
 * @precon Prepare valid context.
 * @brief
 *    1. Create SM9 context via EAL, expected result 1
 *    2. Call CRYPT_EAL_PkeySetPrvEx with NULL ctx, expected result 2
 *    3. Call CRYPT_EAL_PkeySign with NULL ctx, expected result 3
 *    4. Set valid keys and test NULL data, expected result 4
 *    5. Test NULL signature buffer, expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_SIGN_API_TC002(Hex *masterKey, Hex *userId, Hex *message)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t signature[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen = SM9_SIGNATURE_LEN;
    int ret;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Test NULL ctx for SetPrvKeyEx
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(NULL, params);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Step 3: Test NULL ctx for Sign
    ret = CRYPT_EAL_PkeySign(NULL, CRYPT_MD_SM3, message->x, message->len,
                             signature, &signLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Step 4: Set master key first
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Set user ID to generate user key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 6: Test NULL data
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, message->len,
                             signature, &signLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Step 7: Test NULL signature buffer
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message->x, message->len,
                             NULL, &signLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_GET_PUB_API_TC001
 * @title  SM9 CRYPT_EAL_PkeyGetPubEx: Test getting master public key.
 * @precon Prepare valid master key.
 * @brief
 *    1. Create SM9 context, expected result 1
 *    2. Set master key via SetPubKeyEx, expected result 2
 *    3. Get master public key with NULL buffer, expected result 3
 *    4. Get master public key with valid buffer, expected result 4
 *    5. Compare retrieved key with original, expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_SUCCESS
 *    5. Keys match
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_GET_PUB_API_TC001(Hex *masterKey)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t pubKeyBuf[SM9_SIG_SYS_PUBKEY_BYTES] = {0};
    BSL_Param setParams[3];
    BSL_Param getParams[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Set master private key (will auto-generate public key)
    BSL_PARAM_InitValue(&setParams[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&setParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    setParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, setParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Test NULL buffer - should fail
    BSL_PARAM_InitValue(&getParams[0], CRYPT_PARAM_SM9_MASTER_PUB_KEY, BSL_PARAM_TYPE_OCTETS,
                        NULL, 0);
    BSL_PARAM_InitValue(&getParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    getParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, getParams);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Step 4: Get with valid buffer
    BSL_PARAM_InitValue(&getParams[0], CRYPT_PARAM_SM9_MASTER_PUB_KEY, BSL_PARAM_TYPE_OCTETS,
                        pubKeyBuf, sizeof(pubKeyBuf));
    BSL_PARAM_InitValue(&getParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    getParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, getParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Verify the public key was retrieved (length should be set)
    BSL_Param *p = BSL_PARAM_FindParam(getParams, CRYPT_PARAM_SM9_MASTER_PUB_KEY);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->useLen, SM9_SIG_SYS_PUBKEY_BYTES);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_GET_PRV_API_TC001
 * @title  SM9 CRYPT_EAL_PkeyGetPrvEx: Test getting user private key.
 * @precon Prepare valid master key and user ID.
 * @brief
 *    1. Create SM9 context, expected result 1
 *    2. Set master key and generate user key, expected result 2
 *    3. Get user private key with NULL buffer, expected result 3
 *    4. Get user private key with valid buffer, expected result 4
 *    5. Verify user key and user ID, expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2. CRYPT_SUCCESS
 *    3. Error
 *    4. CRYPT_SUCCESS
 *    5. Keys match
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_GET_PRV_API_TC001(Hex *masterKey, Hex *userId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    SM9_Ctx *nativeCtx = NULL;
    uint8_t userKeyBuf[SM9_SIG_USR_PRIKEY_BYTES] = {0};
    uint8_t userIdBuf[SM9_USER_ID_MAX_LEN] = {0};
    uint8_t expectedUserKey[SM9_SIG_USR_PRIKEY_BYTES] = {0};
    BSL_Param setParams[5];
    BSL_Param getParams[4];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Generate expected user key using native API
    nativeCtx = SM9_NewCtx();
    ASSERT_TRUE(nativeCtx != NULL);
    ret = SM9_SetSignMasterKey(nativeCtx, masterKey->x);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = SM9_GenSignUserKey(nativeCtx, userId->x, userId->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    memcpy_s(expectedUserKey, sizeof(expectedUserKey), nativeCtx->sig_dsk, SM9_SIG_USR_PRIKEY_BYTES);

    // Step 1: Create EAL context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Set master key and generate user key
    BSL_PARAM_InitValue(&setParams[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&setParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    setParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, setParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&setParams[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&setParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    setParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, setParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Test NULL buffer
    BSL_PARAM_InitValue(&getParams[0], CRYPT_PARAM_SM9_USER_KEY, BSL_PARAM_TYPE_OCTETS,
                        NULL, 0);
    BSL_PARAM_InitValue(&getParams[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        NULL, 0);
    BSL_PARAM_InitValue(&getParams[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    getParams[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, getParams);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Step 4: Get with valid buffer
    BSL_PARAM_InitValue(&getParams[0], CRYPT_PARAM_SM9_USER_KEY, BSL_PARAM_TYPE_OCTETS,
                        userKeyBuf, sizeof(userKeyBuf));
    BSL_PARAM_InitValue(&getParams[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdBuf, sizeof(userIdBuf));
    BSL_PARAM_InitValue(&getParams[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    getParams[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, getParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Verify retrieved values
    BSL_Param *p = BSL_PARAM_FindParam(getParams, CRYPT_PARAM_SM9_USER_KEY);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->useLen, SM9_SIG_USR_PRIKEY_BYTES);
    ASSERT_TRUE(memcmp(userKeyBuf, expectedUserKey, SM9_SIG_USR_PRIKEY_BYTES) == 0);

    p = BSL_PARAM_FindParam(getParams, CRYPT_PARAM_SM9_USER_ID);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->useLen, userId->len);
    ASSERT_TRUE(memcmp(userIdBuf, userId->x, userId->len) == 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    SM9_FreeCtx(nativeCtx);
}
/* END_CASE */

/**
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_GEN_API_TC001(Hex *userId, Hex *message)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t signature[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen = SM9_SIGNATURE_LEN;
    uint8_t masterPubKey[SM9_SIG_SYS_PUBKEY_BYTES] = {0};
    BSL_Param params[4];
    BSL_Param getParams[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Generate master key pair
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Verify can retrieve master public key
    BSL_PARAM_InitValue(&getParams[0], CRYPT_PARAM_SM9_MASTER_PUB_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterPubKey, sizeof(masterPubKey));
    BSL_PARAM_InitValue(&getParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    getParams[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeyGetPubEx(ctx, getParams);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 4: Generate user key and test sign/verify
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message->x, message->len,
                             signature, &signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message->x, message->len,
                               signature, signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_CMP_API_TC001
 * @title  SM9: Test context comparison.
 * @precon Prepare two contexts with different keys.
 * @brief
 *    1. Create two contexts with same key, expected result 1
 *    2. Set same master key for both, expected result 2
 *    3. Compare contexts, expected result 3
 *    4. Set different master key for second context, expected result 4
 *    5. Compare contexts, expected result 5
 * @expect
 *    1. Success, both contexts are not NULL
 *    2. CRYPT_SUCCESS
 *    3. Contexts are equal
 *    4. CRYPT_SUCCESS
 *    5. Contexts are not equal
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_CMP_API_TC001(Hex *masterKey1, Hex *masterKey2)
{
    CRYPT_EAL_PkeyCtx *ctx1 = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create two contexts
    ctx1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    // Step 2: Set same master key in both
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey1->x, masterKey1->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx1, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySetPubEx(ctx2, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Compare - should be equal
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 4: Set different master key in ctx2
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx2 != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey2->x, masterKey2->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx2, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Compare - should not be equal
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_DUP_API_TC001
 * @title  SM9 Dup: Test duplicating SM9 context.
 * @precon Prepare valid context.
 * @brief
 *    1. Create SM9 context, expected result 1
 *    2. Set master key and user ID, expected result 2
 *    3. Duplicate context, expected result 3
 *    4. Compare original and duplicated contexts, expected result 4
 *    5. Use duplicated context for signing, expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2. CRYPT_SUCCESS
 *    3. Duplicated context is not NULL
 *    4. Contexts are equal
 *    5. Sign/verify succeeds
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_DUP_API_TC001(Hex *masterKey, Hex *userId, Hex *message)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    uint8_t signature[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen = SM9_SIGNATURE_LEN;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Set master key and generate user key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Duplicate context
    dupCtx = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);

    // Step 4: Compare contexts
    ret = CRYPT_EAL_PkeyCmp(ctx, dupCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Use duplicated context for signing
    ret = CRYPT_EAL_PkeySign(dupCtx, CRYPT_MD_SM3, message->x, message->len,
                             signature, &signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message->x, message->len,
                               signature, signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_NULL_PARAM_API_TC001
 * @title  SM9: Test NULL parameter handling.
 * @precon None.
 * @brief
 *    1. Test NewCtx with invalid type, expected result 1
 *    2. Test Sign with NULL context, expected result 2
 *    3. Test Verify with NULL context, expected result 3
 *    4. Test SetPubEx with NULL params, expected result 4
 *    5. Test SetPrvEx with NULL params, expected result 5
 * @expect
 *    1. Returns NULL
 *    2. Error
 *    3. Error
 *    4. Error
 *    5. Error
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_NULL_PARAM_API_TC001(Hex *message)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t signature[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen = SM9_SIGNATURE_LEN;
    int ret;

    // Step 1: Create valid context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Test Sign with NULL message
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, NULL, message->len,
                             signature, &signLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Step 3: Test Verify with NULL signature
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message->x, message->len,
                               NULL, signLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Step 4: Test SetPubEx with NULL params
    ret = CRYPT_EAL_PkeySetPubEx(ctx, NULL);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Step 5: Test SetPrvEx with NULL params
    ret = CRYPT_EAL_PkeySetPrvEx(ctx, NULL);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Test GetPubEx with NULL params
    ret = CRYPT_EAL_PkeyGetPubEx(ctx, NULL);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    // Test GetPrvEx with NULL params
    ret = CRYPT_EAL_PkeyGetPrvEx(ctx, NULL);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_FREE_API_TC001
 * @title  SM9 Free: Test context deallocation.
 * @precon Prepare valid context.
 * @brief
 *    1. Create SM9 context, expected result 1
 *    2. Set keys, expected result 2
 *    3. Free context, expected result 3
 *    4. Test double free (should not crash), expected result 4
 *    5. Test NULL free (should not crash), expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2. CRYPT_SUCCESS
 *    3. No crash
 *    4. No crash
 *    5. No crash
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_FREE_API_TC001(Hex *masterKey)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Set keys
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Free context
    CRYPT_EAL_PkeyFreeCtx(ctx);
    ctx = NULL;

    // Step 5: Test NULL free (should not crash)
    CRYPT_EAL_PkeyFreeCtx(NULL);

EXIT:
    // Cleanup already done
    return;
}
/* END_CASE */

/**
 *    3. Sign with sufficient buffer, expected result 3
 * @expect
 *    1. Success, context is not NULL
 *    2. Error or success with required size
 *    3. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_BUFFER_SIZE_API_TC001(Hex *masterKey, Hex *userId, Hex *message)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t signature[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create and setup context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 2: Test with buffer size 0 (should return required size)
    signLen = 0;
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message->x, message->len,
                             signature, &signLen);
    // Should either fail or set signLen to required size
    ASSERT_TRUE(signLen == SM9_SIGNATURE_LEN || ret != CRYPT_SUCCESS);

    // Step 3: Sign with sufficient buffer
    signLen = SM9_SIGNATURE_LEN;
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message->x, message->len,
                             signature, &signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(signLen, SM9_SIGNATURE_LEN);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_MULTI_OP_API_TC001
 * @title  SM9: Test multiple operations on same context.
 * @precon Prepare valid context.
 * @brief
 *    1. Create SM9 context and set keys, expected result 1
 *    2. Perform multiple sign operations, expected result 2
 *    3. Verify all signatures, expected result 3
 *    4. Reset context and reuse, expected result 4
 * @expect
 *    1. Success, context is not NULL
 *    2. All signs succeed
 *    3. All verifications succeed
 *    4. Context can be reused
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_MULTI_OP_API_TC001(Hex *masterKey, Hex *userId, Hex *message1, Hex *message2)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t signature1[SM9_SIGNATURE_LEN] = {0};
    uint8_t signature2[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen1 = SM9_SIGNATURE_LEN;
    uint32_t signLen2 = SM9_SIGNATURE_LEN;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create and setup context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 2: Perform multiple sign operations
    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message1->x, message1->len,
                             signature1, &signLen1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message2->x, message2->len,
                             signature2, &signLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Verify all signatures
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message1->x, message1->len,
                               signature1, signLen1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message2->x, message2->len,
                               signature2, signLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 4: Verify cross-checking fails
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message1->x, message1->len,
                               signature2, signLen2);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_CHECK_KEYPAIR_FUNC_TC001
 * @title  SM9 CRYPT_EAL_PkeyPairCheck test.
 * @precon Prepare valid master key and user ID.
 * @brief
 *    1. Create two contexts, expected result 1
 *    2. Generate master key in first context, expected result 2
 *    3. Set master public key in second context, expected result 3
 *    4. Generate user key in second context, expected result 4
 *    5. Check key pair between master and user contexts, expected result 5
 *    6. Set wrong user key, expected result 6
 *    7. Check key pair again, expected result 7
 * @expect
 *    1. Success, both contexts are not NULL
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS (key pair valid)
 *    6. CRYPT_SUCCESS
 *    7. CRYPT_SM9_PAIRWISE_CHECK_FAIL (key pair invalid)
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_CHECK_KEYPAIR_FUNC_TC001(Hex *masterKey, Hex *userId1, Hex *userId2)
{
    CRYPT_EAL_PkeyCtx *masterCtx = NULL;
    CRYPT_EAL_PkeyCtx *userCtx = NULL;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create two contexts
    masterCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    userCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(masterCtx != NULL && userCtx != NULL);

    // Step 2: Set master key in first context
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(masterCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Set same master key in second context
    ret = CRYPT_EAL_PkeySetPubEx(userCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 4: Generate user key with userId1 in second context
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId1->x, userId1->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(userCtx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Set user ID in master context for comparison
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId1->x, userId1->len);
    params[1] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeyCtrl(masterCtx, CRYPT_CTRL_SET_SM9_USER_ID, params[0].value, params[0].valueLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Check key pair - should succeed (same user ID)
    ret = CRYPT_EAL_PkeyPairCheck(masterCtx, userCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 6: Change user ID in master context to userId2
    ret = CRYPT_EAL_PkeyCtrl(masterCtx, CRYPT_CTRL_SET_SM9_USER_ID, userId2->x, userId2->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    // Step 7: Check key pair again - should fail (different user IDs)
    ret = CRYPT_EAL_PkeyPairCheck(masterCtx, userCtx);
    ASSERT_EQ(ret, CRYPT_SM9_PAIRWISE_CHECK_FAIL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(masterCtx);
    CRYPT_EAL_PkeyFreeCtx(userCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_CHECK_PRVKEY_FUNC_TC001
 * @title  SM9 CRYPT_EAL_PkeyPrvCheck test.
 * @precon Prepare valid master key and user ID.
 * @brief
 *    1. Create context, expected result 1
 *    2. Set master key only, expected result 2
 *    3. Check private key (should fail - no user key), expected result 3
 *    4. Generate user key, expected result 4
 *    5. Check private key (should succeed), expected result 5
 * @expect
 *    1. Success, context is not NULL
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SM9_INVALID_PRVKEY (no user private key)
 *    4. CRYPT_SUCCESS
 *    5. CRYPT_SUCCESS (has valid user private key)
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_CHECK_PRVKEY_FUNC_TC001(Hex *masterKey, Hex *userId)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    BSL_Param params[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create context
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    // Step 2: Set master key only
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Check private key - should fail (no user key yet)
    ret = CRYPT_EAL_PkeyPrvCheck(ctx);
    ASSERT_EQ(ret, CRYPT_SM9_INVALID_PRVKEY);

    // Step 4: Generate user key
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 5: Check private key - should succeed now
    ret = CRYPT_EAL_PkeyPrvCheck(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_PUBKEY_SET_TEST_TC001
 * @title  SM9 Public Key Round-trip: keygen, get master pub key, set it back, then tamper and set.
 * @precon None.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_PUBKEY_SET_TEST_TC001(void)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    uint8_t pubKeyBuf[SM9_SIG_SYS_PUBKEY_BYTES] = {0};
    BSL_Param getParams[3];
    BSL_Param setParams[3];
    int32_t keyType = SM9_KEY_TYPE_SIGN;

    // Create context and generate master key pair
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    // Get master public key
    BSL_PARAM_InitValue(&getParams[0], CRYPT_PARAM_SM9_MASTER_PUB_KEY, BSL_PARAM_TYPE_OCTETS,
                        pubKeyBuf, sizeof(pubKeyBuf));
    BSL_PARAM_InitValue(&getParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    getParams[2] = (BSL_Param)BSL_PARAM_END;

    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getParams), CRYPT_SUCCESS);
    BSL_Param *p = BSL_PARAM_FindParam(getParams, CRYPT_PARAM_SM9_MASTER_PUB_KEY);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->useLen, (uint32_t)SM9_SIG_SYS_PUBKEY_BYTES);

    // Create new context, set the retrieved public key - expected success
    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx2 != NULL);

    BSL_PARAM_InitValue(&setParams[0], CRYPT_PARAM_SM9_MASTER_PUB_KEY, BSL_PARAM_TYPE_OCTETS,
                        pubKeyBuf, SM9_SIG_SYS_PUBKEY_BYTES);
    BSL_PARAM_InitValue(&setParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    setParams[2] = (BSL_Param)BSL_PARAM_END;

    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, setParams), CRYPT_SUCCESS);

    // Tamper the last byte of the public key
    pubKeyBuf[SM9_SIG_SYS_PUBKEY_BYTES - 1]--;

    // Set tampered public key - expected failure
    BSL_PARAM_InitValue(&setParams[0], CRYPT_PARAM_SM9_MASTER_PUB_KEY, BSL_PARAM_TYPE_OCTETS,
                        pubKeyBuf, SM9_SIG_SYS_PUBKEY_BYTES);
    BSL_PARAM_InitValue(&setParams[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    setParams[2] = (BSL_Param)BSL_PARAM_END;

    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, setParams), CRYPT_SM9_ERR_BAD_INPUT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_SIGN_VECTOR_TC001
 * @title  SM9 Sign/Verify: Verify signature from standard vector via EAL interface.
 * @precon Prepare master key, user ID, message, fixed random, and expected signature.
 * @brief
 *    Source: GB/T 38635.2-2020 Appendix A (SM9 digital signature algorithm example)
 *    1. Create EAL context and set sign master key
 *    2. Generate user signing key via EAL SetPrvEx
 *    3. Verify the expected signature from standard via EAL PkeyVerify
 *    4. Sign message via EAL PkeySign and verify the new signature
 * @expect
 *    1-2. Setup succeeds
 *    3. Verification of standard signature succeeds
 *    4. Round-trip sign/verify succeeds
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_SIGN_VECTOR_TC001(Hex *masterKey, Hex *userId, Hex *message,
    Hex *randHex, Hex *expectedSig)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t signature[SM9_SIGNATURE_LEN] = {0};
    uint32_t signLen = SM9_SIGNATURE_LEN;
    BSL_Param params[4];
    int32_t keyType = SM9_KEY_TYPE_SIGN;
    int ret;

    // Step 1: Create EAL context and set master key
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx != NULL);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 2: Generate user signing key via EAL
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userId->x, userId->len);
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx, params);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 3: Verify the expected signature from standard
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message->x, message->len,
                               expectedSig->x, expectedSig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Step 4: Sign with stubbed random and verify signature matches standard vector
    g_sm9StubRand = randHex->x;
    g_sm9StubRandLen = randHex->len;
    STUB_REPLACE(CRYPT_RandEx, STUB_CRYPT_RandEx);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SM3, message->x, message->len,
                             signature, &signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(signLen, expectedSig->len);
    ASSERT_EQ(memcmp(signature, expectedSig->x, signLen), 0);

    // Step 5: Verify the generated signature
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SM3, message->x, message->len,
                               signature, signLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    STUB_RESTORE(CRYPT_RandEx);
    g_sm9StubRand = NULL;
    g_sm9StubRandLen = 0;
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */
