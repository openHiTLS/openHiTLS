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
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include "securec.h"
#include "crypt_mceliece.h"
#include "crypt_eal_init.h"
#include "crypt_eal_md.h"
#include "crypt_params_key.h"
#include "crypt_drbg.h"
/* END_HEADER */

static uint8_t gRandNumber = 32;

/* @
* @test  SDV_CRYPTO_MCELIECE_CTRL_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyCtrl test
* @precon  nan
* @brief  1. create context
* 2.invoke CRYPT_EAL_PkeyCtrl to transfer various exception parameters.
* 3.call CRYPT_EAL_PkeyCtrl repeatedly to set the key information.
* @expect  1.success 2.returned as expected 3.cannot be set repeatedly.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_CTRL_API_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID + 100, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_MCELIECE_CTRL_NOT_SUPPORT);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, NULL, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val) - 1);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_MCELIECE_CTRL_INIT_REPEATED);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_MCELIECE_KEYGEN_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyGen test
* @precon  nan
* @brief  1.register a random number and create a context.
* 2.invoke CRYPT_EAL_PkeyGen and transfer various parameters.
* 3.check the return value.
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_KEYGEN_API_TC001(int algId)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_PROVIDER), CRYPT_SUCCESS);
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_MCELIECE_KEYINFO_NOT_SET);

    int32_t val = (int32_t)algId;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_NE(ret, CRYPT_SUCCESS);
    CRYPT_EAL_SetRandCallBack(TestSimpleRand);
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* Use default random numbers for end-to-end testing */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_KEYGEN_API_TC002(int algId)
{
    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_RAND), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_PROVIDER), CRYPT_SUCCESS);
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_RAND);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_MCELIECE_ENCAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyEncaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyEncaps to transfer abnormal values.
* 3. check the return value.
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_ENCAPS_API_TC001(int algId)
{
    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_RAND), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_PROVIDER), CRYPT_SUCCESS);
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(ciphertext != NULL);

    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(NULL, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, NULL, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, NULL, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, NULL, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    uint32_t savedCipherLen = cipherLen;
    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
    cipherLen = savedCipherLen;

    sharedLen = 0;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
    sharedLen = 32;

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_RAND);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MCELIECE_DECAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyDecaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyDecaps to transfer various abnormal values.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_DECAPS_API_TC001(int algId)
{
    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_RAND), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_PROVIDER), CRYPT_SUCCESS);
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(ciphertext != NULL);

    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);
    uint8_t *sharedKey2 = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyDecaps(NULL, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, NULL, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, NULL, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    uint32_t savedCipherLen = cipherLen;
    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MCELIECE_INVALID_CIPHER);
    cipherLen = savedCipherLen;

    sharedLen = 0;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);
    sharedLen = 32;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey2, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_COMPARE("shared key cmp", sharedKey2, sharedLen, sharedKey, sharedLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_FREE(sharedKey2);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_RAND);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_MCELIECE_SETPUB_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeySetPub and CRYPT_EAL_PkeyGetPub
* @precon  nan
* @brief 1.register a random number and create a context.
* 2.call CRYPT_EAL_PkeySetPub and CRYPT_EAL_PkeyGetPub and transfer various parameters.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_SETPUB_API_TC001(int algId, Hex *testEK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam[2] = {0};
    BSL_PARAM_InitValue(&pubParam[0], CRYPT_PARAM_MCELIECE_PUBKEY, BSL_PARAM_TYPE_OCTETS,
                        testEK->x, testEK->len);
    BSL_PARAM_InitValue(&pubParam[1], 0, 0, NULL, 0);

    // Test error cases
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_MCELIECE_ABSENT_PUBKEY);

    // Test setting public key with incorrect length
    BSL_Param badPubParam[2] = {0};
    BSL_PARAM_InitValue(&badPubParam[0], CRYPT_PARAM_MCELIECE_PUBKEY, BSL_PARAM_TYPE_OCTETS,
                        testEK->x, encapsKeyLen - 1);
    BSL_PARAM_InitValue(&badPubParam[1], 0, 0, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, badPubParam), CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);

    // Test setting public key successfully
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, pubParam), CRYPT_SUCCESS);

    // Test getting public key
    uint8_t *getPubKey = BSL_SAL_Malloc(encapsKeyLen);
    ASSERT_TRUE(getPubKey != NULL);
    BSL_Param getPubParam[2] = {0};
    BSL_PARAM_InitValue(&getPubParam[0], CRYPT_PARAM_MCELIECE_PUBKEY, BSL_PARAM_TYPE_OCTETS,
                        getPubKey, encapsKeyLen);
    BSL_PARAM_InitValue(&getPubParam[1], 0, 0, NULL, 0);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getPubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ek", getPubKey, encapsKeyLen, testEK->x, testEK->len);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(getPubKey);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_MCELIECE_SETPRV_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeySetPrv and CRYPT_EAL_PkeyGetPrv
* @precon  nan
* @brief 1.register a random number and create a context.
* 2.call CRYPT_EAL_PkeySetPrv and CRYPT_EAL_PkeyGetPrv and transfer various parameters.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_SETPRV_API_TC001(int algId, Hex *testDK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param prvParam[2] = {0};
    BSL_PARAM_InitValue(&prvParam[0], CRYPT_PARAM_MCELIECE_PRVKEY, BSL_PARAM_TYPE_OCTETS,
                        testDK->x, testDK->len);
    BSL_PARAM_InitValue(&prvParam[1], 0, 0, NULL, 0);

    // Test error cases
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, prvParam), CRYPT_MCELIECE_ABSENT_PRVKEY);

    // Test setting private key with incorrect length
    BSL_Param badPrvParam[2] = {0};
    BSL_PARAM_InitValue(&badPrvParam[0], CRYPT_PARAM_MCELIECE_PRVKEY, BSL_PARAM_TYPE_OCTETS,
                        testDK->x, decapsKeyLen - 1);
    BSL_PARAM_InitValue(&badPrvParam[1], 0, 0, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, badPrvParam), CRYPT_MCELIECE_BUFLEN_NOT_ENOUGH);

    // Test setting private key successfully
    ASSERT_EQ(CRYPT_EAL_PkeySetPrvEx(ctx, prvParam), CRYPT_SUCCESS);

    // Test getting private key
    uint8_t *getPrvKey = BSL_SAL_Malloc(decapsKeyLen);
    ASSERT_TRUE(getPrvKey != NULL);
    BSL_Param getPrvParam[2] = {0};
    BSL_PARAM_InitValue(&getPrvParam[0], CRYPT_PARAM_MCELIECE_PRVKEY, BSL_PARAM_TYPE_OCTETS,
                        getPrvKey, decapsKeyLen);
    BSL_PARAM_InitValue(&getPrvParam[1], 0, 0, NULL, 0);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrvEx(ctx, getPrvParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare dk", getPrvKey, decapsKeyLen, testDK->x, testDK->len);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(getPrvKey);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

static int32_t TestRand(uint8_t *randBuf, uint32_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        randBuf[i] = gRandNumber;
    }
    return 0;
}

/* @
* @test  SDV_CRYPTO_MCELIECE_KEYCMP_FUNC_TC001
* @spec  -
* @title  Context Comparison and Copy Test
* @precon  nan
* @brief  1.Registers a random number that returns the specified value.
* 2. Call CRYPT_EAL_PkeyGen to generate a key pair. The first two groups of random numbers are the same,
*    and the third group of random numbers is different.
* 3. Call CRYPT_EAL_PkeyCopyCtx to copy the key pair.
* 4. Invoke CRYPT_EAL_PkeyCmp to compare key pairs.
* @expect  1.success 2.success 3.success 4.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_KEYCMP_FUNC_TC001(int algId)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(TestRand);
    gRandNumber = 1u;

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_NE(ctx, NULL);

    int32_t val = (int32_t)algId;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, NULL), CRYPT_NULL_INPUT);

    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_NE(ctx2, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_MCELIECE_KEY_NOT_EQUAL);

    val = (int32_t)algId;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_MCELIECE_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx2, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_MCELIECE_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_SUCCESS);

    gRandNumber = 3u;
    CRYPT_EAL_PkeyCtx *ctx3 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_NE(ctx3, NULL);
    val = (int32_t)algId;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx3, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx3, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx3), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx3), CRYPT_MCELIECE_KEY_NOT_EQUAL);

    CRYPT_EAL_PkeyCtx *ctx4 = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    ASSERT_TRUE(ctx4 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(ctx4, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx4), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx5 = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctx5 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx5), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    CRYPT_EAL_PkeyFreeCtx(ctx4);
    CRYPT_EAL_PkeyFreeCtx(ctx5);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */



static uint8_t g_mcelieceSeed[48];
static DRBG_Ctx *g_randCtx = NULL;

static int32_t GetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    if (entropy == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t strengthBytes = (strength + 7) >> 3;
    entropy->len = ((strengthBytes > lenRange->min) ? strengthBytes : lenRange->min);
    if (entropy->len > lenRange->max) {
        return CRYPT_ENTROPY_RANGE_ERROR;
    }
    entropy->data = BSL_SAL_Malloc(entropy->len);
    if (entropy->data == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    memcpy_s(entropy->data, entropy->len, g_mcelieceSeed, 48);
    return CRYPT_SUCCESS;
}

static void CleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    BSL_SAL_CleanseData(entropy->data, entropy->len);
    BSL_SAL_FREE(entropy->data);
}

static int32_t NewDrbg()
{
    CRYPT_RandSeedMethod method = { 0 };
    method.getEntropy = (void *)GetEntropy;
    method.cleanEntropy = (void *)CleanEntropy;

    g_randCtx = DRBG_New(NULL, CRYPT_RAND_AES256_CTR, &method, NULL);
    if (g_randCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t RandomBytesEx(void *ctx, uint8_t *out, uint32_t outLen)
{
    (void)ctx;
    return DRBG_GenerateBytes(g_randCtx, out, outLen, NULL, 0);
}

static int32_t RandomBytes(uint8_t *out, uint32_t outLen)
{
    return DRBG_GenerateBytes(g_randCtx, out, outLen, NULL, 0);
}

static int32_t RandSetUp()
{
    int32_t ret = NewDrbg();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = DRBG_Instantiate(g_randCtx, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_RandRegistEx(RandomBytesEx);
    CRYPT_RandRegist(RandomBytes);
    return CRYPT_SUCCESS;
}

static void RandTeardown()
{
    DRBG_Free(g_randCtx);
    CRYPT_RandRegistEx(NULL);
    CRYPT_RandRegist(NULL);
}



/* @
* @test  SDV_CRYPTO_MCELIECE_ENCAPS_DECAPS_FUNC_TC001
* @spec  -
* @title  McEliece KEM Encaps/Decaps Vector Test
* @precon  nan
* @brief  1. Initialize random with test seed
* 2. Generate key pair and compare with test vectors
* 3. Perform encapsulation and compare with test vectors
* 4. Perform decapsulation and compare with test vectors
* @expect  1.success 2.keys match test vectors 3.ciphertext and shared secret match 4.shared secret matches
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_ENCAPS_DECAPS_FUNC_TC001(int algId, Hex *seed, Hex *testEk, Hex *testDk, Hex *testCt, Hex *testSs)
{
    TestMemInit();
    // Copy seed to global variable for mock random function
    (void)memcpy_s(g_mcelieceSeed, 48, seed->x, seed->len);
    ASSERT_EQ(RandSetUp(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
    ASSERT_TRUE(ctx != NULL);

    int32_t val = (int32_t)algId;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    CRYPT_EAL_PkeyPub ek = { 0 };
    dk.id = CRYPT_PKEY_MCELIECE;
    ek.id = CRYPT_PKEY_MCELIECE;

    uint32_t dkLen = 0;
    uint32_t ekLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &ekLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &dkLen, sizeof(uint32_t)), CRYPT_SUCCESS);

    ek.key.kemEk.data = BSL_SAL_Malloc(ekLen);
    ASSERT_TRUE(ek.key.kemEk.data != NULL);
    ek.key.kemEk.len = ekLen;

    dk.key.kemDk.data = BSL_SAL_Malloc(dkLen);
    ASSERT_TRUE(dk.key.kemDk.data != NULL);
    dk.key.kemDk.len = dkLen;

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_SUCCESS);

    ASSERT_COMPARE("ek cmp", ek.key.kemEk.data, ek.key.kemEk.len, testEk->x, testEk->len);
    ASSERT_COMPARE("dk cmp", dk.key.kemDk.data, dk.key.kemDk.len, testDk->x, testDk->len);

    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    uint32_t ssLen;
    uint32_t ctLen;
    uint8_t *ss = NULL;
    uint8_t *ct = NULL;

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(uint32_t)), CRYPT_SUCCESS);

    ss = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ss != NULL);
    ct = BSL_SAL_Malloc(ctLen);
    ASSERT_TRUE(ct != NULL);

    // Perform encapsulation and compare with test vectors
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ct, &ctLen, ss, &ssLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("encaps ct cmp", ct, ctLen, testCt->x, testCt->len);
    ASSERT_COMPARE("encaps ss cmp", ss, ssLen, testSs->x, testSs->len);

    // Clear ss for decaps test
    memset_s(ss, ssLen, 0, ssLen);

    // Switch to decaps mode
    ASSERT_EQ(CRYPT_EAL_PkeyDecapsInit(ctx, NULL), CRYPT_SUCCESS);

    // Perform decapsulation and compare with test vectors
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, testCt->x, testCt->len, ss, &ssLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("decaps ss cmp", ss, ssLen, testSs->x, testSs->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(dk.key.kemDk.data);
    BSL_SAL_FREE(ek.key.kemEk.data);
    BSL_SAL_FREE(ss);
    BSL_SAL_FREE(ct);
    RandTeardown();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MCELIECE_DUPKEY_API_TC001
* @spec  -
* @title  Test CRYPT_EAL_PkeyDupCtx with encaps/decaps
* @precon  nan
* @brief  1. Create a context and generate key pair
*         2. Dup the context
*         3. Compare the two contexts, expect success
*         4. Use the first context to do encaps
*         5. Use the dupped context to do decaps
*         6. Compare the shared secrets, expect them to be the same
* @expect  All operations succeed and shared secrets match
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MCELIECE_DUPKEY_API_TC001(int algId)
{
    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_RAND), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ASSERT_EQ(CRYPT_EAL_Init(CRYPT_EAL_INIT_PROVIDER), CRYPT_SUCCESS);
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_MCELIECE, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MCELIECE);
#endif
    ASSERT_TRUE(ctx != NULL);

    // Set parameters and generate key pair
    int32_t val = (int32_t)algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Dup the context
    CRYPT_EAL_PkeyCtx *ctxDup = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctxDup != NULL);

    // Compare the two contexts
    ret = CRYPT_EAL_PkeyCmp(ctx, ctxDup);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Get ciphertext and shared key lengths
    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sharedLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sharedLen1 = sharedLen;
    uint32_t sharedLen2 = sharedLen;

    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(ciphertext != NULL);
    uint8_t *sharedKey1 = BSL_SAL_Malloc(sharedLen1);
    ASSERT_TRUE(sharedKey1 != NULL);
    uint8_t *sharedKey2 = BSL_SAL_Malloc(sharedLen2);
    ASSERT_TRUE(sharedKey2 != NULL);

    // Use first context to do encaps
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey1, &sharedLen1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Switch dupped context to decaps mode
    ret = CRYPT_EAL_PkeyDecapsInit(ctxDup, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Use dupped context to do decaps
    ret = CRYPT_EAL_PkeyDecaps(ctxDup, ciphertext, cipherLen, sharedKey2, &sharedLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Compare the shared secrets
    ASSERT_EQ(sharedLen1, sharedLen2);
    ASSERT_COMPARE("shared secret", sharedKey1, sharedLen1, sharedKey2, sharedLen2);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctxDup);
    BSL_SAL_FREE(ciphertext);
    BSL_SAL_FREE(sharedKey1);
    BSL_SAL_FREE(sharedKey2);
    return;
}
/* END_CASE */
