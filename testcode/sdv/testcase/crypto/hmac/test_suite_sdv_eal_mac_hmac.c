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
/* INCLUDE_BASE test_suite_sdv_eal_mac_hmac */

/* BEGIN_HEADER */

/* END_HEADER */

#define HMAC_MAX_BUFF_LEN (64 + 1) // CRYPT_SHA2_512_DIGESTSIZE + 1
/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC001
 * @title  Create hmac context test.
 * @precon nan
 * @brief
 *    1.Create context with invalid id, expected result 1.
 *    2.Create context using CRYPT_MAC_AlgId, expected result 2.
 * @expect
 *    1.The result is NULL.
 *    2.Create successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC001(void)
{
    TestMemInit();
    CRYPT_MAC_AlgId testIds[] = { CRYPT_MAC_HMAC_MD5, CRYPT_MAC_HMAC_SHA1, CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384, CRYPT_MAC_HMAC_SHA512, CRYPT_MAC_HMAC_SM3,
        CRYPT_MAC_HMAC_SHA3_224, CRYPT_MAC_HMAC_SHA3_256, CRYPT_MAC_HMAC_SHA3_384, CRYPT_MAC_HMAC_SHA3_512 };

    CRYPT_EAL_MacCtx *ctx = NULL;

    for (int i = 0; i < (int)(sizeof(testIds) / sizeof(CRYPT_MAC_AlgId)); i++) {
        ctx = CRYPT_EAL_MacNewCtx(testIds[i]);
        ASSERT_TRUE(ctx != NULL);
        CRYPT_EAL_MacFreeCtx(ctx);
    }

    ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_MAX);
    ASSERT_TRUE(ctx == NULL);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC002
 * @title  hmac init test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the CTX, expected result 1.
 *    2.Call CRYPT_EAL_MacInit,ctx is NULL or key is NULL but keylen not 0, expected result 2.
 *    3.Call CRYPT_EAL_MacInit,key is NULL and keyLen is 0, expected result 3.
 *    4.Call CRYPT_EAL_MacInit normally, expected result 4.
 * @expect
 *    1.Create successful.
 *    2.Return CRYPT_NULL_INPUT.
 *    3.Successful.
 *    4.Successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC002(int algId)
{
    TestMemInit();
    const uint32_t len = GetMacLen(algId);
    uint8_t key[HMAC_MAX_BUFF_LEN];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(NULL, key, len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, NULL, len), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, (uint8_t *)key, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC003
 * @title  hmac init test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the CTX, expected result 1.
 *    2.Call CRYPT_EAL_MacInit repeatedly, expected result 2.
 *    3.Call CRYPT_EAL_MacInit after update, expected result 3.
 *    4.Call CRYPT_EAL_MacReinit, expected result 4.
 * @expect
 *    1.Create successful.
 *    2.Successful.
 *    3.Successful.
 *    4.Successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC003(int algId)
{
    TestMemInit();
    const uint32_t len = GetMacLen(algId);
    uint32_t macLen = len;
    const uint32_t dataLen = HMAC_MAX_BUFF_LEN;
    uint8_t key[HMAC_MAX_BUFF_LEN];
    uint8_t mac[HMAC_MAX_BUFF_LEN];
    uint8_t data[HMAC_MAX_BUFF_LEN];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data, dataLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC004
 * @title  hmac init test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the CTX, expected result 1.
 *    2.Call CRYPT_EAL_MacUpdate before init, expected result 2.
 *    3.Call CRYPT_EAL_MacUpdate,ctx or data is NULL, expected result 3.
 *    4.Call CRYPT_EAL_MacUpdate,dataLen is 0, expected result 4.
 *    5.Call CRYPT_EAL_MacUpdate normally, expected result 5.
 * @expect
 *    1.Create successful.
 *    2.Return CRYPT_EAL_ERR_STATE.
 *    3.Return CRYPT_NULL_INPUT.
 *    4.Successful.
 *    5.Successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC004(int algId)
{
    TestMemInit();
    const uint32_t len = GetMacLen(algId);
    const uint32_t dataLen = HMAC_MAX_BUFF_LEN;
    uint8_t key[HMAC_MAX_BUFF_LEN];
    uint8_t data[HMAC_MAX_BUFF_LEN];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data, dataLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacUpdate(NULL, data, dataLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, NULL, dataLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data, dataLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC005
 * @title  hmac final test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the CTX, expected result 1.
 *    2.Call CRYPT_EAL_MacFinal before init, expected result 2.
 *    3.Call CRYPT_EAL_MacFinal,ctx or mac is NULL, expected result 3.
 *    4.Call CRYPT_EAL_MacFinal,macLen not enough, expected result 4.
 *    5.Call CRYPT_EAL_MacFinal normally, expected result 5.
 * @expect
 *    1.Create successful.
 *    2.Return CRYPT_EAL_ERR_STATE.
 *    3.Return CRYPT_NULL_INPUT.
 *    4.Return CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH.
 *    5.Successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC005(int algId)
{
    TestMemInit();
    const uint32_t len = GetMacLen(algId);
    uint32_t macLen = len;
    uint8_t key[HMAC_MAX_BUFF_LEN];
    uint8_t mac[HMAC_MAX_BUFF_LEN];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacFinal(NULL, mac, &macLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, NULL, &macLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, NULL), CRYPT_NULL_INPUT);
    macLen = GetMacLen(algId) - 1;
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH);
    macLen = GetMacLen(algId) + 1;
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC006
 * @title  get mac len test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the ctx and init, expected result 1.
 *    2.Call CRYPT_EAL_GetMacLen,the input parameter is null, expected result 2.
 *    3.Call CRYPT_EAL_GetMacLen after init,update final and deinit, expected result 3.
 * @expect
 *    1.Create successful.
 *    2.Return 0.
 *    3.Successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC006(int algId)
{
    TestMemInit();
    const uint32_t len = GetMacLen(algId);
    uint8_t key[HMAC_MAX_BUFF_LEN];
    const uint32_t dataLen = HMAC_MAX_BUFF_LEN;
    uint8_t data[HMAC_MAX_BUFF_LEN];
    uint32_t macLen = len;
    uint8_t mac[HMAC_MAX_BUFF_LEN];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(NULL), 0);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(ctx), GetMacLen(algId));

    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(ctx), GetMacLen(algId));

    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data, dataLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(ctx), GetMacLen(algId));

    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(ctx), GetMacLen(algId));

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(ctx), GetMacLen(algId));
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_API_TC007
 * @title  reinit ctx test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the ctx and init, expected result 1.
 *    2.Call CRYPT_EAL_MacReinit,the input parameter is null, expected result 2.
 *    3.Call CRYPT_EAL_MacReinit after init,update final, expected result 3.
 *    3.Call CRYPT_EAL_MacReinit after deinit, expected result 4.
 * @expect
 *    1.Create successful.
 *    2.Return 0.
 *    3.Successful.
 *    4.Return CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_API_TC007(int algId)
{
    TestMemInit();
    const uint32_t len = GetMacLen(algId);
    uint32_t macLen = len;
    const uint32_t dataLen = HMAC_MAX_BUFF_LEN;
    uint8_t key[HMAC_MAX_BUFF_LEN];
    uint8_t mac[HMAC_MAX_BUFF_LEN];
    uint8_t data[HMAC_MAX_BUFF_LEN];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MacReinit(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key, len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data, dataLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_SUCCESS);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Calculate the hmac of each group of data, expected result 1.
*     2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Hmac calculation succeeded.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_FUN_TC001(int algId, Hex *key, Hex *data, Hex *vecMac)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = GetMacLen(algId);
    uint8_t *mac = malloc(macLen);
    ASSERT_TRUE(mac != NULL);
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 result cmp", mac, macLen, vecMac->x, vecMac->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
    free(mac);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_HMAC_FUN_TC002
 * @title  Hash calculation for multiple updates,comparison with standard results.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MacNewCtx to create a ctx and initialize, expected result 1.
 *    2.Call CRYPT_EAL_MacUpdate to calculate the hash of a data segmentxpected result 2.
 *    3.Call CRYPT_EAL_MacUpdate to calculate the next data segmentxpected result 3.
 *    4.Call CRYPT_EAL_MacUpdate to calculate the next data segmentxpected result 4.
 *    5.Call CRYPT_EAL_MacFinal get the result, expected result 5.
 * @expect
 *    1.Successful
 *    2.Successful
 *    3.Successful
 *    4.Successful
 *    5.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_FUN_TC002(int algId, Hex *key, Hex *data1, Hex *data2, Hex *data3, Hex *vecMac)
{
    TestMemInit();
    uint32_t macLen = GetMacLen(algId);
    uint8_t *mac = malloc(macLen);
    ASSERT_TRUE(mac != NULL);
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data1->x, data1->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data2->x, data2->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data3->x, data3->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 result cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
    free(mac);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA1_FUN_TC003
 * @title  Test multi-thread hmac calculation.
 * @precon nan
 * @brief
 *    1.Create two threads and calculate the hmac, expected result 1.
 *    2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Hmac calculation succeeded.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_FUN_TC003(int algId, Hex *key1, Hex *data1, Hex *vecMac1, Hex *key2, Hex *data2, Hex *vecMac2)
{
    int ret;
    TestMemInit();
    const uint32_t threadNum = 2; // 2 threads
    pthread_t thrd[2];
    ThreadParameter arg[2] = {
        {.data = data1->x, .key = key1->x, .mac = vecMac1->x, .dataLen = data1->len,
         .keyLen = key1->len, .macLen = vecMac1->len, .algId = algId},
        {.data = data2->x, .key = key2->x, .mac = vecMac2->x, .dataLen = data2->len,
         .keyLen = key2->len, .macLen = vecMac2->len, .algId = algId},
    };
    for (uint32_t i = 0; i < threadNum; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)MultiThreadTest, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        pthread_join(thrd[i], NULL);
    }

EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_HMAC_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPT_HMAC_DEFAULT_PROVIDER_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *vecMac)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_MacCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
#else
    ctx = CRYPT_EAL_MacNewCtx(algId);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t macLen = GetMacLen(algId);
    uint8_t *mac = BSL_SAL_Calloc(1, macLen);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_EAL_GetMacLen(ctx), GetMacLen(algId));

    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 result cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacReinit(ctx), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
    BSL_SAL_FREE(mac);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HMAC_COPY_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx ctxC = { 0 };
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    ctxB = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxB != NULL);

    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    // Copy failed because ctxC lacks a method.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    // A directly created context can also be used as the destination for copying.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.macMeth.freeCtx(ctxC.ctx);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HMAC_DUP_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx ctxC = { 0 };
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    ctxB = CRYPT_EAL_MacDupCtx(NULL);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_MacDupCtx(&ctxC);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_MacDupCtx(ctxA);
    ASSERT_TRUE(ctxB != NULL);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_HMAC_COPY_CTX_TC001(int algId, Hex *key, Hex *data, Hex *vecMac, int isProvider)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = GetMacLen(algId);
    uint8_t mac[64];

    CRYPT_EAL_MacCtx *copyCtx1 = NULL;
    CRYPT_EAL_MacCtx *copyCtx2 = NULL;
    CRYPT_EAL_MacCtx *copyCtx3 = NULL;
    CRYPT_EAL_MacCtx *ctx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);

    copyCtx1 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx1 != NULL);
    copyCtx2 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx2 != NULL);

    // Test that the copied context functions correctly and is independent of the original context.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx1, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(copyCtx1, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx1, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    copyCtx1 = NULL;

    // Create a new copyCtx3 from ctx, use copyCtx3 for encryption, and verify functional correctness.
    copyCtx3 = CRYPT_EAL_MacDupCtx(ctx);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(copyCtx3, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx3, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac2 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(copyCtx3);
    copyCtx3 = NULL;

    macLen = GetMacLen(algId);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx2, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac3 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(ctx);
    ctx = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx2, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac4 cmp", mac, macLen, vecMac->x, vecMac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(copyCtx2);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

static int32_t TestMacCopyCtxMemCheck(int32_t algId, Hex *key, int isProvider)
{
    CRYPT_EAL_MacCtx *ctxA = NULL;
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx *srcCtx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    /* Set key in srcCtx */
    int32_t ret = CRYPT_EAL_MacInit(srcCtx, key->x, key->len);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ret = CRYPT_EAL_MacCopyCtx(ctxA, srcCtx);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ctxB = CRYPT_EAL_MacDupCtx(srcCtx);
    if (ctxB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
    CRYPT_EAL_MacFreeCtx(srcCtx);
    return ret;
}

/**
 * @test SDV_CRYPTO_CBC_MAC_COPY_CTX_STUB_TC001
 * title 1. Test the mac copy context with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_CRYPTO_HMAC_COPY_CTX_STUB_TC001(int algId, Hex *key, int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(TestMacCopyCtxMemCheck((int32_t)algId, key, isProvider), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(TestMacCopyCtxMemCheck((int32_t)algId, key, isProvider), CRYPT_SUCCESS);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */