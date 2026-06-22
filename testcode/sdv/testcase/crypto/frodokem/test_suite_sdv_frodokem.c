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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_frodokem.h"
#include "crypt_drbg.h"
#include "stub_utils.h"
/* END_HEADER */
static uint8_t gRandNumber = 0;
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
/* @
* @test  SDV_CRYPTO_FRODOKEM_CTRL_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyCtrl test
* @precon  nan
* @brief  1. creat context
* 2.invoke CRYPT_EAL_PkeyCtrl to transfer various exception parameters.
* 3.call CRYPT_EAL_PkeyCtrl repeatedly to set the key information.
* @expect  1.success 2.returned as expected 3.cannot be set repeatedly.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_CTRL_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    int32_t val = (int32_t)bits;
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID + 100, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_FRODOKEM_CTRL_NOT_SUPPORT);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, NULL, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val) - 1);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_FRODOKEM_CTRL_INIT_REPEATED);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_KEYGEN_API_TC001
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
void SDV_CRYPTO_FRODOKEM_KEYGEN_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
        ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_KEYINFO_NOT_SET);

    uint32_t val = (uint32_t)bits;
    ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_NO_REGIST_RAND);

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* Use default random numbers for end-to-end testing */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_KEYGEN_API_TC002(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_ENCAPS_API_TC001
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
void SDV_CRYPTO_FRODOKEM_ENCAPS_API_TC001(int bits)
{
    TestMemInit();

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

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

    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    cipherLen = cipherLen + 1;

    sharedLen = 0;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    sharedLen = 32;

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DECAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyEncaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyDecaps to transfer various abnormal values.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_DECAPS_API_TC001(int bits)
{
    TestMemInit();

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

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

    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_INVALID_CIPHER);
    cipherLen = cipherLen + 1;

    sharedLen = 0;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    sharedLen = 32;

    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_SETPUB_API_TC001
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
void SDV_CRYPTO_FRODOKEM_SETPUB_API_TC001(int bits, Hex *testEK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_EAL_ERR_ALGID);

    ek.id = CRYPT_PKEY_FRODOKEM;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_NULL_INPUT);

    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    memcpy(ek.key.kemEk.data, testEK->x, testEK->len);
    ek.key.kemEk.len = encapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_INVALID_ARG);

    ek.key.kemEk.len = encapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_INVALID_ARG);

    ek.key.kemEk.len = encapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_FRODOKEM_ABSENT_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    memset(ek.key.kemEk.data, 0, encapsKeyLen);

    ek.key.kemEk.len = encapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    ek.key.kemEk.len = encapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ek", ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ek.key.kemEk.data);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_FRODOKEM_SETPRV_API_TC001
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
void SDV_CRYPTO_FRODOKEM_SETPRV_API_TC001(int bits, Hex *testDK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_EAL_ERR_ALGID);

    dk.id = CRYPT_PKEY_FRODOKEM;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_NULL_INPUT);

    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    memcpy(dk.key.kemDk.data, testDK->x, testDK->len);
    dk.key.kemDk.len = decapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_INVALID_ARG);

    dk.key.kemDk.len = decapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_INVALID_ARG);

    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data[decapsKeyLen - 1] ^= 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_FRODOKEM_INVALID_PRVKEY);
    dk.key.kemDk.data[decapsKeyLen - 1] ^= 1;

    dk.key.kemDk.len = decapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_FRODOKEM_ABSENT_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    memset(dk.key.kemDk.data, 0, decapsKeyLen);

    dk.key.kemDk.len = decapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_FRODOKEM_BUFLEN_NOT_ENOUGH);
    dk.key.kemDk.len = decapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare de", dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(dk.key.kemDk.data);
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
static int32_t TestRandEx(void *libctx, uint8_t *randBuf, uint32_t len)
{
    (void)libctx;
    return TestRand(randBuf, len);
}
/* @
* @test  SDV_CRYPTO_FRODOKEM_KEYCMP_FUNC_TC001
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
void SDV_CRYPTO_FRODOKEM_KEYCMP_FUNC_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestRand);
    CRYPT_RandRegistEx(TestRandEx);
    gRandNumber = 1u;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_NE(ctx, NULL);
    uint32_t val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, NULL), CRYPT_NULL_INPUT);

    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_NE(ctx2, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx2, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_FRODOKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_SUCCESS);

    gRandNumber = 3u;
    CRYPT_EAL_PkeyCtx *ctx3 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_NE(ctx3, NULL);
    val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx3, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx3, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx3), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx3), CRYPT_FRODOKEM_KEY_NOT_EQUAL);

    CRYPT_EAL_PkeyCtx *ctx4 = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
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
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

static uint8_t g_frodoSeed[48];
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

    memcpy(entropy->data, g_frodoSeed, 48);
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
    CRYPT_EAL_SetRandCallBack(RandomBytes);
    return CRYPT_SUCCESS;
}

static void RandTeardown()
{
    DRBG_Free(g_randCtx);
    g_randCtx = NULL;
    CRYPT_EAL_SetRandCallBack(NULL);
}


/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_ENCAPS_DECAPS_FUNC_TC001(int bits, Hex *seed, Hex *testEk, Hex *testDk, Hex *testCt, Hex *testSs)
{
    TestMemInit();
    if (seed->len <= 48) {
        memcpy(g_frodoSeed, seed->x, seed->len);
    }
    ASSERT_EQ(RandSetUp(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, bits), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPrv dk = { 0 };
    CRYPT_EAL_PkeyPub ek = { 0 };
    dk.id = CRYPT_PKEY_FRODOKEM;
    ek.id = CRYPT_PKEY_FRODOKEM;
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
    uint8_t *ss;
    uint8_t *ss2;
    uint8_t *ct;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ss = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ss != NULL);
    ss2 = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ss2 != NULL);
    ct = BSL_SAL_Malloc(ctLen);
    ASSERT_TRUE(ct != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ct, &ctLen, ss, &ssLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("ct cmp", ct, ctLen, testCt->x, testCt->len);
    ASSERT_COMPARE("ss cmp", ss, ssLen, testSs->x, testSs->len);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ss2, &ssLen), CRYPT_SUCCESS);\
    ASSERT_COMPARE("ss2 cmp", ss2, ssLen, testSs->x, testSs->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(dk.key.kemDk.data);
    BSL_SAL_FREE(ek.key.kemEk.data);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ss);
    BSL_SAL_FREE(ss2);
    RandTeardown();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DUPKEY_API_TC001
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
void SDV_CRYPTO_FRODOKEM_DUPKEY_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    // Set parameters and generate key pair
    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
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

    uint32_t sharedLen1 = 32;
    uint32_t sharedLen2 = 32;

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
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_DUPKEY_STUB_TC001
* @spec  -
* @title  Test CRYPT_EAL_PkeyDupCtx with stubbed BSL_SAL_Malloc failure
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
void SDV_CRYPTO_FRODOKEM_DUPKEY_STUB_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    // Set parameters and generate key pair
    int32_t val = (int32_t)algId;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *cipher = NULL;
    uint8_t *sharedKey = NULL;
    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sharedLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &sharedLen, sizeof(sharedLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    cipher = BSL_SAL_Malloc(cipherLen);
    ASSERT_TRUE(cipher != NULL);
    sharedKey = BSL_SAL_Malloc(sharedLen);
    ASSERT_TRUE(sharedKey != NULL);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    // Dup the context
    CRYPT_EAL_PkeyCtx *ctxDup = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctxDup != NULL);
    ret = CRYPT_EAL_PkeyEncaps(ctxDup, cipher, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyDecaps(ctxDup, cipher, cipherLen, sharedKey, &sharedLen);
    CRYPT_EAL_PkeyFreeCtx(ctxDup);
    totalMallocCount = STUB_GetMallocCallCount();
    ctxDup = NULL;
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; ++i) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        CRYPT_EAL_PkeyGen(ctx);
        ctxDup = CRYPT_EAL_PkeyDupCtx(ctx);
        CRYPT_EAL_PkeyEncaps(ctxDup, cipher, &cipherLen, sharedKey, &sharedLen);
        CRYPT_EAL_PkeyDecaps(ctxDup, cipher, cipherLen, sharedKey, &sharedLen);
        CRYPT_EAL_PkeyFreeCtx(ctxDup);
        ctxDup = NULL;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctxDup);
    CRYPT_RandRegist(NULL);
    BSL_SAL_FREE(cipher);
    BSL_SAL_FREE(sharedKey);
    STUB_RESTORE(BSL_SAL_Malloc);
    return;
}
/* END_CASE */

static CRYPT_EAL_PkeyCtx *NewFrodoKemCtx(void)
{
#ifdef HITLS_CRYPTO_PROVIDER
    return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_FRODOKEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    return CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_FRODOKEM);
#endif
}

static void GetFrodoExpectedLens(int32_t algId, uint32_t *ctLen, uint32_t *secBits, uint32_t *pubLen,
    uint32_t *prvLen, uint32_t *sharedLen)
{
    switch (algId) {
        case CRYPT_KEM_TYPE_FRODOKEM_640_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_640_AES:
            *ctLen = 9752;
            *secBits = 128;
            *pubLen = 9616;
            *prvLen = 19888;
            *sharedLen = 16;
            return;
        case CRYPT_KEM_TYPE_FRODOKEM_976_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_976_AES:
            *ctLen = 15792;
            *secBits = 192;
            *pubLen = 15632;
            *prvLen = 31296;
            *sharedLen = 24;
            return;
        case CRYPT_KEM_TYPE_FRODOKEM_1344_SHAKE:
        case CRYPT_KEM_TYPE_FRODOKEM_1344_AES:
            *ctLen = 21696;
            *secBits = 256;
            *pubLen = 21520;
            *prvLen = 43088;
            *sharedLen = 32;
            return;
        case CRYPT_KEM_TYPE_EFRODOKEM_640_SHAKE:
        case CRYPT_KEM_TYPE_EFRODOKEM_640_AES:
            *ctLen = 9720;
            *secBits = 128;
            *pubLen = 9616;
            *prvLen = 19888;
            *sharedLen = 16;
            return;
        case CRYPT_KEM_TYPE_EFRODOKEM_976_SHAKE:
        case CRYPT_KEM_TYPE_EFRODOKEM_976_AES:
            *ctLen = 15744;
            *secBits = 192;
            *pubLen = 15632;
            *prvLen = 31296;
            *sharedLen = 24;
            return;
        case CRYPT_KEM_TYPE_EFRODOKEM_1344_SHAKE:
        case CRYPT_KEM_TYPE_EFRODOKEM_1344_AES:
            *ctLen = 21632;
            *secBits = 256;
            *pubLen = 21520;
            *prvLen = 43088;
            *sharedLen = 32;
            return;
        default:
            *ctLen = 0;
            *secBits = 0;
            *pubLen = 0;
            *prvLen = 0;
            *sharedLen = 0;
            return;
    }
}

static int32_t CheckFrodoGetNumCtrl(CRYPT_EAL_PkeyCtx *ctx, int32_t cmd, uint32_t expected)
{
    uint32_t value = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, cmd, &value, sizeof(value));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (value != expected) {
        return CRYPT_FRODOKEM_KEY_NOT_EQUAL;
    }
    ret = CRYPT_EAL_PkeyCtrl(ctx, cmd, &value, sizeof(value) - 1);
    if (ret != CRYPT_INVALID_ARG) {
        return ret;
    }
    return CRYPT_SUCCESS;
}

/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_CTRL_GETTER_API_TC001(int algId)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NewFrodoKemCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t value = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SECBITS, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &value, sizeof(value)),
        CRYPT_FRODOKEM_KEYINFO_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, NULL, sizeof(value)), CRYPT_NULL_INPUT);

    uint32_t ctLen = 0;
    uint32_t secBits = 0;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    uint32_t sharedLen = 0;
    GetFrodoExpectedLens(algId, &ctLen, &secBits, &pubLen, &prvLen, &sharedLen);

    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_SECBITS, secBits), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, pubLen), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, prvLen), CRYPT_SUCCESS);
    ASSERT_EQ(CheckFrodoGetNumCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, sharedLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_STATE_NEG_API_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *src = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *pubOnly = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *prvOnly = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *repeat = NewFrodoKemCtx();
    uint8_t *pubBuf = NULL;
    uint8_t *prvBuf = NULL;
    uint8_t *ct = NULL;
    uint8_t *ss = NULL;
    ASSERT_TRUE(src != NULL);
    ASSERT_TRUE(pubOnly != NULL);
    ASSERT_TRUE(prvOnly != NULL);
    ASSERT_TRUE(repeat != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(src, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pubOnly, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(prvOnly, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(repeat, (uint32_t)algId), CRYPT_SUCCESS);

    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    uint32_t pubLen = 0;
    uint32_t prvLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(ssLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(src, CRYPT_CTRL_GET_PRVKEY_LEN, &prvLen, sizeof(prvLen)), CRYPT_SUCCESS);

    ct = BSL_SAL_Malloc(ctLen);
    ss = BSL_SAL_Malloc(ssLen);
    pubBuf = BSL_SAL_Malloc(pubLen);
    prvBuf = BSL_SAL_Malloc(prvLen);
    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(ss != NULL);
    ASSERT_TRUE(pubBuf != NULL);
    ASSERT_TRUE(prvBuf != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(src, ct, &ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PUBKEY);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(src, ct, ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(src), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    pub.id = CRYPT_PKEY_FRODOKEM;
    prv.id = CRYPT_PKEY_FRODOKEM;
    pub.key.kemEk.data = pubBuf;
    pub.key.kemEk.len = pubLen;
    prv.key.kemDk.data = prvBuf;
    prv.key.kemDk.len = prvLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(src, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(src, &prv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pubOnly, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(pubOnly, ct, ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PRVKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(prvOnly, &prv), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(prvOnly, ct, &ctLen, ss, &ssLen), CRYPT_FRODOKEM_ABSENT_PUBKEY);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(repeat, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(repeat, &prv), CRYPT_FRODOKEM_KEY_REPEATED_SET);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(src);
    CRYPT_EAL_PkeyFreeCtx(pubOnly);
    CRYPT_EAL_PkeyFreeCtx(prvOnly);
    CRYPT_EAL_PkeyFreeCtx(repeat);
    BSL_SAL_FREE(pubBuf);
    BSL_SAL_FREE(prvBuf);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ss);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_WRONG_PRV_FUNC_TC001(int algId)
{
    TestMemInit();
    CRYPT_RandRegist(TestRand);
    CRYPT_RandRegistEx(TestRandEx);
    CRYPT_EAL_PkeyCtx *ctx1 = NewFrodoKemCtx();
    CRYPT_EAL_PkeyCtx *ctx2 = NewFrodoKemCtx();
    uint8_t *ct = NULL;
    uint8_t *ss1 = NULL;
    uint8_t *ss2 = NULL;
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_TRUE(ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx1, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, (uint32_t)algId), CRYPT_SUCCESS);
    gRandNumber = 1u;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx1), CRYPT_SUCCESS);
    gRandNumber = 3u;
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);

    uint32_t ctLen = 0;
    uint32_t ssLen1 = 0;
    uint32_t ssLen2 = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen1, sizeof(ssLen1)), CRYPT_SUCCESS);
    ssLen2 = ssLen1;
    ct = BSL_SAL_Malloc(ctLen);
    ss1 = BSL_SAL_Malloc(ssLen1);
    ss2 = BSL_SAL_Malloc(ssLen2);
    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(ss1 != NULL);
    ASSERT_TRUE(ss2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx1, ct, &ctLen, ss1, &ssLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx2, ct, ctLen, ss2, &ssLen2), CRYPT_SUCCESS);
    ASSERT_EQ(ssLen1, ssLen2);
    ASSERT_TRUE(memcmp(ss1, ss2, ssLen1) != 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ss1);
    BSL_SAL_FREE(ss2);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_FRODOKEM_MODIFIED_CT_FUNC_TC001
* @spec  -
* @title  Test implicit rejection after modifying each ciphertext partition
* @precon  nan
* @brief  1. Generate a key pair and a valid ciphertext
*         2. Modify the first, middle, and last byte of C1 and C2 separately
*         3. For salted variants, modify the first, middle, and last byte of salt separately
*         4. Decapsulate each modified ciphertext twice
* @expect  Decapsulation succeeds and returns a deterministic fallback secret
*          The fallback secret differs from the valid shared secret
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_FRODOKEM_MODIFIED_CT_FUNC_TC001(int algId, int c1Len, int c2Len, int saltLen)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_EAL_PkeyCtx *ctx = NewFrodoKemCtx();
    uint8_t *ct = NULL;
    uint8_t *ctOrig = NULL;
    uint8_t *ss = NULL;
    uint8_t *ssFallback1 = NULL;
    uint8_t *ssFallback2 = NULL;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(c1Len > 0);
    ASSERT_TRUE(c2Len > 0);
    ASSERT_TRUE(saltLen >= 0);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, (uint32_t)algId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);

    uint32_t ctLen = 0;
    uint32_t ssLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &ctLen, sizeof(ctLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_SHARED_KEY_LEN, &ssLen, sizeof(ssLen)), CRYPT_SUCCESS);
    ASSERT_EQ((uint32_t)c1Len + (uint32_t)c2Len + (uint32_t)saltLen, ctLen);
    const uint32_t expectedCtLen = ctLen;
    const uint32_t expectedSsLen = ssLen;

    ct = BSL_SAL_Malloc(ctLen);
    ctOrig = BSL_SAL_Malloc(ctLen);
    ss = BSL_SAL_Malloc(ssLen);
    ssFallback1 = BSL_SAL_Malloc(ssLen);
    ssFallback2 = BSL_SAL_Malloc(ssLen);
    ASSERT_TRUE(ct != NULL);
    ASSERT_TRUE(ctOrig != NULL);
    ASSERT_TRUE(ss != NULL);
    ASSERT_TRUE(ssFallback1 != NULL);
    ASSERT_TRUE(ssFallback2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ctOrig, &ctLen, ss, &ssLen), CRYPT_SUCCESS);
    ASSERT_EQ(ctLen, expectedCtLen);
    ASSERT_EQ(ssLen, expectedSsLen);
    uint32_t validSsLen = ssLen;
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ctOrig, ctLen, ssFallback1, &validSsLen), CRYPT_SUCCESS);
    ASSERT_EQ(validSsLen, ssLen);
    ASSERT_EQ(memcmp(ss, ssFallback1, ssLen), 0);

    const uint32_t c1Size = (uint32_t)c1Len;
    const uint32_t c2Start = c1Size;
    const uint32_t c2Size = (uint32_t)c2Len;
    const uint32_t saltStart = c2Start + c2Size;
    const uint32_t saltSize = (uint32_t)saltLen;
    uint32_t positions[9] = {
        0, c1Size / 2, c1Size - 1,
        c2Start, c2Start + c2Size / 2, c2Start + c2Size - 1
    };
    uint32_t positionCount = 6;
    if (saltSize > 0) {
        positions[positionCount++] = saltStart;
        positions[positionCount++] = saltStart + saltSize / 2;
        positions[positionCount++] = ctLen - 1;
    }
    for (uint32_t i = 0; i < positionCount; i++) {
        uint32_t fallbackLen1 = ssLen;
        uint32_t fallbackLen2 = ssLen;
        memcpy(ct, ctOrig, ctLen);
        ct[positions[i]] ^= 0x01;
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ssFallback1, &fallbackLen1), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ct, ctLen, ssFallback2, &fallbackLen2), CRYPT_SUCCESS);
        ASSERT_EQ(fallbackLen1, ssLen);
        ASSERT_EQ(fallbackLen2, ssLen);
        ASSERT_TRUE(memcmp(ss, ssFallback1, ssLen) != 0);
        ASSERT_EQ(memcmp(ssFallback1, ssFallback2, ssLen), 0);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_FREE(ct);
    BSL_SAL_FREE(ctOrig);
    BSL_SAL_FREE(ss);
    BSL_SAL_FREE(ssFallback1);
    BSL_SAL_FREE(ssFallback2);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */
