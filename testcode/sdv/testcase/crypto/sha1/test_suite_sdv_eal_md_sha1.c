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
#include "securec.h"
#include "eal_md_local.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
/* END_HEADER */

#define SHA1_DIGEST_LEN (20)
#define DATA_MAX_LEN (65538)

typedef struct {
    uint8_t *data;
    uint8_t *hash;
    uint32_t dataLen;
    uint32_t hashLen;
} ThreadParameter;

void MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint32_t outLen = SHA1_DIGEST_LEN;
    uint8_t out[SHA1_DIGEST_LEN];
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
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
 * @test   SDV_CRYPT_EAL_SHA1_API_TC001
 * @title  Initialization interface test
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdInit and enter NULL, expected result 1.
 *    2.Call CRYPT_EAL_MdNewCtx create ctx, expected result 2.
 *    3.Call CRYPT_EAL_MdInit and use the correct ID. expected result 3.
 * @expect
 *    1.Initialization failed, return CRYPT_NULL_INPUT
 *    2.The ctx is created successfully.
 *    3.Initialization successful, return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA1_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_MAX);;
    ASSERT_TRUE(ctx == NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(NULL), CRYPT_NULL_INPUT);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);;
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA1_API_TC002
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
void SDV_CRYPT_EAL_SHA1_API_TC002(void)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;
    const uint32_t dataLen = SHA1_DIGEST_LEN;
    uint8_t data[SHA1_DIGEST_LEN];
    uint32_t digestLen = SHA1_DIGEST_LEN;
    uint8_t out[SHA1_DIGEST_LEN];
    
    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_NULL_INPUT);
    
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data, dataLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &digestLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(NULL, data, dataLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, NULL, dataLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data, dataLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(NULL, out, &digestLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, NULL, &digestLen), CRYPT_NULL_INPUT);
    digestLen = SHA1_DIGEST_LEN - 1;
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &digestLen), CRYPT_SHA1_OUT_BUFF_LEN_NOT_ENOUGH);
    digestLen = SHA1_DIGEST_LEN;
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &digestLen), CRYPT_SUCCESS);
    
    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(ctx->state, CRYPT_MD_STATE_NEW);

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test   SDV_CRYPT_EAL_SHA1_API_TC003
 * @title  Repeated hash calculation test
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx to create a CTX, expected result 1.
 *    2.Calculate the hash, expected result 2.
 *    3.Calculate the hash again, expected result 3.
 *    4.Calculate the hash again, expected result 4.
 *    5.Call CRYPT_EAL_MdFinal again, expected result 5.
 *    6.Call CRYPT_EAL_Md to calculate the hash value, expected result 6.
 * @expect
 *    1.Successful, ctx is returned.
 *    2.Obtains the hash of an empty string.
 *    3.Obtains the hash of data
 *    4.Obtains the hash of an empty string.
 *    5.Return CRYPT_EAL_ERR_STATE.
 *    6.Obtains the expected hash of data
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA1_API_TC003(Hex *hash1, Hex *data2, Hex *hash2, Hex *hash3)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;
    uint32_t digestLen = SHA1_DIGEST_LEN;
    uint8_t out[SHA1_DIGEST_LEN];
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    ASSERT_TRUE(ctx != NULL);

    // Hash calculation for the first time.
    ASSERT_TRUE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MdFinal(ctx, out, &digestLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("hash1 result cmp", out, digestLen, hash1->x, hash1->len);

    // Hash calculation for the second time.
    ASSERT_TRUE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MdUpdate(ctx, data2->x, data2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MdFinal(ctx, out, &digestLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("hash2 result cmp", out, digestLen, hash2->x, hash2->len);

    // Hash calculation for the third time.
    ASSERT_TRUE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MdFinal(ctx, out, &digestLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("hash3 result cmp", out, digestLen, hash3->x, hash3->len);

    ASSERT_TRUE(CRYPT_EAL_MdFinal(ctx, out, &digestLen) == CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_Md(CRYPT_MD_SHA1, data2->x, data2->len, out, &digestLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hash2 result cmp", out, digestLen, hash2->x, hash2->len);
    
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA1_API_TC004
 * @title  To test the function of obtaining the digest length of the hash algorithm.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdGetDigestSize,the input parameter ID is invalid, expected result 1.
 *    2.Call CRYPT_EAL_MdGetDigestSize, Using CRYPT_MD_SHA1, expected result 2.
 * @expect
*     1.Failed, return 0.
 *    2.Success, return SHA1_DIGEST_LEN.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA1_API_TC004(void)
{
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_MAX), 0);
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA1), SHA1_DIGEST_LEN);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA1_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Calculate the hash of each group of data, expected result 1.
*     2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Hash calculation succeeded.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA1_FUN_TC001(Hex *data, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;
    uint32_t digestLen = SHA1_DIGEST_LEN;
    uint8_t out[SHA1_DIGEST_LEN];
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &digestLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("hash result cmp", out, digestLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA1_FUN_TC002
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
void SDV_CRYPT_EAL_SHA1_FUN_TC002(Hex *data, Hex *hash)
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

/**
 * @test   SDV_CRYPT_EAL_SHA1_FUN_TC003
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
void SDV_CRYPT_EAL_SHA1_FUN_TC003(Hex *plain_text1, Hex *plain_text2, Hex *plain_text3, Hex *hash)
{
    unsigned char output[SHA1_DIGEST_LEN];
    uint32_t outLen = SHA1_DIGEST_LEN;

    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, plain_text1->x, plain_text1->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, plain_text2->x, plain_text2->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, plain_text3->x, plain_text3->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);

    ASSERT_COMPARE("sha1", output, outLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SHA1_COPY_CTX_FUNC_TC001
 * @title  SHA1 copy ctx function test.
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
void SDV_CRYPTO_SHA1_COPY_CTX_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *cpyCtx = NULL;
    CRYPT_EAL_MdCTX *dupCtx = NULL;
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[SHA1_DIGEST_LEN];
    uint32_t outLen = SHA1_DIGEST_LEN;
    
    dupCtx=CRYPT_EAL_MdDupCtx(cpyCtx);
    ASSERT_TRUE(dupCtx == NULL);
    ASSERT_EQ(CRYPT_MD_MAX, CRYPT_EAL_MdGetId(dupCtx));
    
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, ctx), CRYPT_NULL_INPUT);
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
 * @test   SDV_CRYPT_EAL_SHA1_FUN_TC004
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA1_FUN_TC004(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    uint8_t output[SHA1_DIGEST_LEN];
    uint32_t outLen = SHA1_DIGEST_LEN;
    CRYPT_EAL_MdCTX *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, id, "provider=default");
#else
    (void)id;
    ctx = CRYPT_EAL_MdNewCtx(id);
#endif
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */
