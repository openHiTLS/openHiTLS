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
#include <pthread.h>
#include "crypt_eal_md.h"
#include "bsl_sal.h"
#include "eal_md_local.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "securec.h"
/* END_HEADER */

typedef struct {
    uint8_t *data;
    uint8_t *hash;
    uint32_t dataLen;
    uint32_t hashLen;
} ThreadParameter;

void MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint8_t out[32];
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < 10; i++) {
        ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, threadParameter->data, threadParameter->dataLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hash result cmp", out, outLen, threadParameter->hash, threadParameter->hashLen);
    }

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}

/**
 * @test   SDV_CRYPT_EAL_SM3_API_TC001
 * @title  CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal test
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdDeinit the null CTX, expected result 1.
 *    2.Invoke the CRYPT_EAL_MdNewCtx to create a CTX, expected result 2.
 *    3.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal before initialization, expected result 3 is obtained.
 *    4.Initialize the CTX and transfer null pointers to CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal. expected result 4.
 *    5.Invoke CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal normally, expected result 5.
 *    6.Call CRYPT_EAL_MdDeinit the CTX, expected result 6.
 * @expect
 *    1.Return CRYPT_NULL_INPUT
 *    2.Successful, ctx is returned.
 *    3.Return CRYPT_EAL_ERR_STATE
 *    4.Return CRYPT_NULL_INPUT
 *    5.Return CRYPT_SUCCESS
 *    6.Return CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SM3_API_TC001(void)
{
    TestMemInit();
    uint8_t input[100]; // Any length, for example, 100 bytes.
    uint32_t inLen = sizeof(input);
    uint8_t out[32]; // SM3 digest length is 32.
    uint32_t outLen = sizeof(out);
    uint32_t badOutLen = outLen - 1;
    uint32_t longOutLen = outLen + 1;

    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SM3), outLen);
    CRYPT_EAL_MdCTX *ctx = NULL;

    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_NULL_INPUT);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, inLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(NULL, input, inLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, NULL, inLen), CRYPT_NULL_INPUT);
    // Hash counting can be performed on empty strings.
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, inLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, NULL, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(NULL, out, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &badOutLen), CRYPT_SM3_OUT_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, inLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &longOutLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdGetId(ctx), CRYPT_MD_SM3);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_SUCCESS);
    
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SM3_FUNC_TC001
 * @title  CRYPT_EAL_MdFinal test without update.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx to create ctx, expected result 1.
 *    2.Call CRYPT_EAL_MdFinal get results. expected result 2.
 *    3.Compare with expected results. expected result 3.
 * @expect
 *    1.The ctx is created successful.
 *    2.Successful.
 *    2.Consistent with expected results.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SM3_FUNC_TC001(Hex *hash)
{
    TestMemInit();
    uint8_t out[32]; // SM3 digest length is 32.
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(outLen, 32);

    ASSERT_EQ(memcmp(out, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SM3_FUNC_TC002
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Calculate the hash of each group of data, expected result 1.
 *    2.Compare the result to the expected value, expected result 2.
 *    6.Call CRYPT_EAL_Md to calculate the hash value, expected result 3.
 * @expect
 *    1.Hash calculation succeeded.
 *    2.The results are as expected.
 *    3.Obtains the expected hash of data
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SM3_FUNC_TC002(Hex *data, Hex *hash)
{
    TestMemInit();
    uint8_t out[32]; // SM3 digest length is 32
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_MdCTX *ctx = NULL;

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(outLen, 32);

    ASSERT_EQ(memcmp(out, hash->x, hash->len), 0);

    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_SM3, data->x, data->len, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SM3_FUNC_TC003
 * @title  Hash calculation for multiple updates,comparison with standard results.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx to create a ctx and initialize, expected result 1.
 *    2.Call CRYPT_EAL_MdUpdate to calculate the hash of a data segmentxpected result 2.
 *    3.Call CRYPT_EAL_MdUpdate to calculate the next data segmentxpected result 3.
 *    4.Call CRYPT_EAL_MdUpdate to calculate the next data segmentxpected result 4.
 *    5.Call CRYPT_EAL_MdFinal get the result, expected result 5.
 * @expect
 *    1.Successful
 *    2.Successful
 *    3.Successful
 *    4.Successful
 *    5.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SM3_FUNC_TC003(Hex *data1, Hex *data2, Hex *data3, Hex *hash)
{
    TestMemInit();
    uint8_t out[32]; // 32 is sm3 hash size
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_MdCTX *ctx = NULL;

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data1->x, data1->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data2->x, data2->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data3->x, data3->len), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(outLen, 32);

    ASSERT_EQ(memcmp(out, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_MD_SHA2_FUNC_TC001
 * @title  Split the data and update test.
 * @precon nan
 * @brief
 *    1.Create two ctx and initialize them, expected result 1.
 *    2.Use ctx1 to update data 100 times, expected result 2.
 *    3.Use ctx2 to update all data at once, expected result 3.
 *    4.Compare two outputs, expected result 4.
 * @expect
 *    1.Successful.
 *    2.Successful.
 *    3.Successful.
 *    4.The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SM3_FUNC_TC004(void)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx1 = NULL;
    CRYPT_EAL_MdCTX *ctx2 = NULL;

    ctx1 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx1 != NULL);

    ctx2 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx2 != NULL);

    // 100! = 5050
    uint8_t input[5050];
    uint32_t inLenTotal = 0;
    uint32_t inLenBase;
    uint8_t out1[100];
    uint8_t out2[100];
    uint32_t outLen = CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SM3);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx2), CRYPT_SUCCESS);

    for (inLenBase = 1; inLenBase <= 100; inLenBase++) {
        ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx1, input + inLenTotal, inLenBase), CRYPT_SUCCESS);
        inLenTotal += inLenBase;
    }
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx1, out1, &outLen), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SM3);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx2, input, inLenTotal), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx2, out2, &outLen), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SM3);

    ASSERT_EQ(memcmp(out1, out2, outLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx1);
    CRYPT_EAL_MdFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM3_COPY_CTX_FUNC_TC001
 * @title  MD5 copy ctx function test.
 * @precon nan
 * @brief
 *    1. Create the context ctx of md algorithm, expected result 1
 *    2. Call to CRYPT_EAL_MdCopyCtx method to copy ctx, expected result 2
 *    2. Call to CRYPT_EAL_MdCopyCtx method to copy a null ctx, expected result 3
 *    3. Calculate the hash of msg, and compare the calculated result with hash vector, expected result 4
 *    4. Call to CRYPT_EAL_MdDupCtx method to copy ctx, expected result 5
 *    3. Calculate the hash of msg, and compare the calculated result with hash vector, expected result 6
 * @expect
 *    1. Success, the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_NULL_INPUT
 *    4. Success, the context is not null.
 *    5. CRYPT_SUCCESS
 *    6. Success, the hashs are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM3_COPY_CTX_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *cpyCtx = NULL;
    CRYPT_EAL_MdCTX *dupCtx = NULL;
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[32]; // SM3 digest length is 32
    uint32_t outLen = sizeof(output);

    dupCtx=CRYPT_EAL_MdDupCtx(cpyCtx);
    ASSERT_TRUE(dupCtx == NULL);
    ASSERT_EQ(CRYPT_MD_MAX, CRYPT_EAL_MdGetId(dupCtx));

    cpyCtx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_TRUE(dupCtx == NULL);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, dupCtx), CRYPT_NULL_INPUT);
    TestErrClear();
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdInit(cpyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(cpyCtx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(cpyCtx, output, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(id, cpyCtx->id);
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);

    dupCtx=CRYPT_EAL_MdDupCtx(ctx);
    ASSERT_TRUE(dupCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(dupCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(dupCtx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(dupCtx, output, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(id, CRYPT_EAL_MdGetId(dupCtx));
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_MdFreeCtx(cpyCtx);
    CRYPT_EAL_MdFreeCtx(dupCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM3_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM3_DEFAULT_PROVIDER_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, id, "provider=default");
#else
    ctx = CRYPT_EAL_MdNewCtx(id);
#endif
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[32]; // SM3 digest length is 32
    uint32_t outLen = sizeof(output);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_MD_SM3_FUNC_TC001
 * @title  Test multi-thread hash calculation.
 * @precon nan
 * @brief
 *    1.Create two threads and calculate the hash, expected result 1.
 *    2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Hash calculation succeeded.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_MD_SM3_FUNC_TC001(Hex *data, Hex *hash)
{
    int ret;
    TestMemInit();
    const uint32_t threadNum = 2;
    pthread_t thrd[2];
    ThreadParameter arg[2] = {
        {data->x, hash->x, data->len, hash->len},
        {data->x, hash->x, data->len, hash->len}
    };
    for (uint32_t i = 0; i < threadNum; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)MultiThreadTest, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        pthread_join(thrd[i], NULL);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    return;
}
/* END_CASE */
