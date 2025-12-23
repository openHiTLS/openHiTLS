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

#include "crypt_sm9.h"
#include "crypt_params_key.h"
#include "bsl_params.h"
#include "securec.h"

#define SM9_KEYEX_RA_LEN 64
#define SM9_KEYEX_RB_LEN 64
#define SM9_SHARED_KEY_LEN 32
#define SM9_CONFIRM_LEN 32
#define SM9_KEY_TYPE_SIGN 1
#define SM9_KEY_TYPE_ENC 2

/* END_HEADER */

/**
 * @test   SDV_CRYPTO_SM9_KEYEX_API_TC001
 * @title  SM9 Key Exchange: Test via EAL ComputeShareKey interface.
 * @precon Prepare valid master key and user IDs.
 * @brief
 *    1. Create EAL contexts for Alice and Bob, expected result 1
 *    2. Set encrypt master keys via EAL, expected result 2
 *    3. Set user keys for Alice and Bob via EAL, expected result 3
 *    4. Compute shared key via EAL interface, expected result 4
 *    5. Compare shared keys, expected result 5
 *    6. Test ComputeShareKey with longer shareLen, expected result 6
 *    6. Test ComputeShareKey with shorter shareLen, expected result 7
 * @expect
 *    1. Success, contexts are not NULL
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_SUCCESS
 *    5. Shared keys match
 *    6. CRYPT_SUCCESS
 *    7. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_KEYEX_API_TC001(Hex *masterKey, Hex *userIdA, Hex *userIdB)
{
    CRYPT_EAL_PkeyCtx *ctx_a = NULL;
    CRYPT_EAL_PkeyCtx *ctx_b = NULL;
    uint8_t SK_A[SM9_SHARED_KEY_LEN] = {0};
    uint8_t SK_B[SM9_SHARED_KEY_LEN] = {0};
    uint32_t keyLen_A = SM9_SHARED_KEY_LEN;
    uint32_t keyLen_B = SM9_SHARED_KEY_LEN;
    uint8_t SK_Long[2 * SM9_SHARED_KEY_LEN  - 1] = {0};
    uint8_t SK_Short[SM9_SHARED_KEY_LEN - 1] = {0};
    uint32_t longKeyLen = sizeof(SK_Long);
    uint32_t shortKeyLen = sizeof(SK_Short);
    int ret;
    int32_t keyType = SM9_KEY_TYPE_ENC;

    // Generate master keys first (use native API for KGC operations)
    SM9_Ctx *tmpCtx_a = SM9_NewCtx();
    SM9_Ctx *tmpCtx_b = SM9_NewCtx();
    ASSERT_TRUE(tmpCtx_a != NULL && tmpCtx_b != NULL);

    ret = SM9_SetEncMasterKey(tmpCtx_a, masterKey->x);
    ASSERT_EQ(ret, SM9_OK);
    ret = SM9_SetEncMasterKey(tmpCtx_b, masterKey->x);
    ASSERT_EQ(ret, SM9_OK);

    ret = SM9_GenEncUserKey(tmpCtx_a, userIdA->x, userIdA->len);
    ASSERT_EQ(ret, SM9_OK);
    ret = SM9_GenEncUserKey(tmpCtx_b, userIdB->x, userIdB->len);
    ASSERT_EQ(ret, SM9_OK);

    // Create EAL contexts
    ctx_a = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ctx_b = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx_a != NULL && ctx_b != NULL);

    // Set master private key via EAL for both contexts
    BSL_Param params_master[3];
    BSL_PARAM_InitValue(&params_master[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params_master[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params_master[2] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPubEx(ctx_a, params_master);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySetPubEx(ctx_b, params_master);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Set user keys via EAL
    BSL_Param params_a[4];
    BSL_PARAM_InitValue(&params_a[0], CRYPT_PARAM_SM9_USER_KEY, BSL_PARAM_TYPE_OCTETS,
                        tmpCtx_a->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);
    BSL_PARAM_InitValue(&params_a[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdA->x, userIdA->len);
    BSL_PARAM_InitValue(&params_a[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params_a[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx_a, params_a);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param params_b[4];
    BSL_PARAM_InitValue(&params_b[0], CRYPT_PARAM_SM9_USER_KEY, BSL_PARAM_TYPE_OCTETS,
                        tmpCtx_b->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);
    BSL_PARAM_InitValue(&params_b[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdB->x, userIdB->len);
    BSL_PARAM_InitValue(&params_b[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params_b[3] = (BSL_Param)BSL_PARAM_END;

    ret = CRYPT_EAL_PkeySetPrvEx(ctx_b, params_b);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Compute shared key via EAL interface
    ret = CRYPT_EAL_PkeyComputeShareKey(ctx_a, ctx_b, SK_A, &keyLen_A);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyComputeShareKey(ctx_b, ctx_a, SK_B, &keyLen_B);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Verify shared keys match
    ASSERT_EQ(keyLen_A, keyLen_B);
    ASSERT_TRUE(memcmp(SK_A, SK_B, keyLen_A) == 0);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx_a, ctx_b, SK_Long, &longKeyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx_a, ctx_b, SK_Short, &shortKeyLen), CRYPT_SUCCESS);

EXIT:
    SM9_FreeCtx(tmpCtx_a);
    SM9_FreeCtx(tmpCtx_b);
    CRYPT_EAL_PkeyFreeCtx(ctx_a);
    CRYPT_EAL_PkeyFreeCtx(ctx_b);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM9_KEYEX_API_TC002
 * @title  SM9 Key Exchange: Test with NULL parameters via EAL.
 * @precon Prepare valid contexts.
 * @brief
 *    1. Create and setup a valid context, expected result 1
 *    2. Test ComputeShareKey with NULL selfCtx, expected result 2
 *    3. Test ComputeShareKey with NULL peerCtx, expected result 3
 *    4. Test ComputeShareKey with NULL output buffer, expected result 4
 *    5. Test ComputeShareKey with NULL outLen, expected result 5
 *    6. Test ComputeShareKey, expected result 6
 * @expect
 *    1. CRYPT_SUCCESS
 *    2. CRYPT_NULL_INPUT
 *    3. CRYPT_NULL_INPUT
 *    4. CRYPT_NULL_INPUT
 *    5. CRYPT_NULL_INPUT
 *    6. CRYPT_SM9_ERR_NO_MASTER_KEY
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM9_KEYEX_API_TC002(Hex *masterKey, Hex *userIdA, Hex *userIdB)
{
    CRYPT_EAL_PkeyCtx *ctx_a = NULL;
    CRYPT_EAL_PkeyCtx *ctx_b = NULL;
    uint8_t SK[SM9_SHARED_KEY_LEN] = {0};
    uint32_t keyLen = SM9_SHARED_KEY_LEN;
    int ret;
    int32_t keyType = SM9_KEY_TYPE_ENC;

    (void)userIdB;  // Unused in this test

    // Create and setup valid contexts
    ctx_a = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ctx_b = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM9);
    ASSERT_TRUE(ctx_a != NULL && ctx_b != NULL);

    // Use native API for key generation
    SM9_Ctx *tmpCtx_a = SM9_NewCtx();
    ASSERT_TRUE(tmpCtx_a != NULL);
    ret = SM9_SetEncMasterKey(tmpCtx_a, masterKey->x);
    ASSERT_EQ(ret, SM9_OK);
    ret = SM9_GenEncUserKey(tmpCtx_a, userIdA->x, userIdA->len);
    ASSERT_EQ(ret, SM9_OK);

    // Set master private key via EAL
    BSL_Param params_master[3];
    BSL_PARAM_InitValue(&params_master[0], CRYPT_PARAM_SM9_MASTER_KEY, BSL_PARAM_TYPE_OCTETS,
                        masterKey->x, masterKey->len);
    BSL_PARAM_InitValue(&params_master[1], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params_master[2] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeySetPubEx(ctx_a, params_master);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param params_a[4];
    BSL_PARAM_InitValue(&params_a[0], CRYPT_PARAM_SM9_USER_KEY, BSL_PARAM_TYPE_OCTETS,
                        tmpCtx_a->enc_dek, SM9_ENC_USR_PRIKEY_BYTES);
    BSL_PARAM_InitValue(&params_a[1], CRYPT_PARAM_SM9_USER_ID, BSL_PARAM_TYPE_OCTETS,
                        userIdA->x, userIdA->len);
    BSL_PARAM_InitValue(&params_a[2], CRYPT_PARAM_SM9_KEY_TYPE, BSL_PARAM_TYPE_INT32,
                        &keyType, sizeof(int32_t));
    params_a[3] = (BSL_Param)BSL_PARAM_END;
    ret = CRYPT_EAL_PkeySetPrvEx(ctx_a, params_a);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Test NULL selfCtx
    ret = CRYPT_EAL_PkeyComputeShareKey(NULL, ctx_b, SK, &keyLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Test NULL peerCtx
    ret = CRYPT_EAL_PkeyComputeShareKey(ctx_a, NULL, SK, &keyLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Test NULL output buffer
    ret = CRYPT_EAL_PkeyComputeShareKey(ctx_a, ctx_b, NULL, &keyLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    // Test NULL outLen
    ret = CRYPT_EAL_PkeyComputeShareKey(ctx_a, ctx_b, SK, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(ctx_a, ctx_b, SK, &keyLen), CRYPT_SM9_ERR_NO_MASTER_KEY);

EXIT:
    SM9_FreeCtx(tmpCtx_a);
    CRYPT_EAL_PkeyFreeCtx(ctx_a);
    CRYPT_EAL_PkeyFreeCtx(ctx_b);
}
/* END_CASE */
