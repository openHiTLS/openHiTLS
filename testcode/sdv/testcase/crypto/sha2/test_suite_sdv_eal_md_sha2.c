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
#include "eal_md_local.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
/* END_HEADER */

// 100 is greater than the digest length of all SHA algorithms.
#define SHA2_OUTPUT_MAXSIZE 100

typedef struct {
    uint8_t *data;
    uint8_t *hash;
    uint32_t dataLen;
    uint32_t hashLen;
    CRYPT_MD_AlgId id;
} ThreadParameter;

void Sha2MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint32_t outLen = SHA2_OUTPUT_MAXSIZE;
    uint8_t out[SHA2_OUTPUT_MAXSIZE];
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(threadParameter->id);
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < 10; i++) { // Repeat 10 times
        ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, threadParameter->data, threadParameter->dataLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);
        ASSERT_COMPARE("hash result cmp", out, outLen, threadParameter->hash, threadParameter->hashLen);
    }

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}

/**
 * @test   SDV_CRYPT_EAL_SHA2_API_TC001
 * @title  Create sha2 context test.
 * @precon nan
 * @brief
 *    1.Create context with invalid id, expected result 1.
 *    2.Create context using CRYPT_MD_SHA224 CRYPT_MD_SHA256 CRYPT_MD_SHA384 CRYPT_MD_SHA512, expected result 2.
 * @expect
 *    1.The result is NULL.
 *    2.Create successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA2_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;

    ctx = CRYPT_EAL_MdNewCtx(-1);
    ASSERT_TRUE(ctx == NULL);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_MAX);
    ASSERT_TRUE(ctx == NULL);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA224);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MdFreeCtx(ctx);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MdFreeCtx(ctx);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA384);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MdFreeCtx(ctx);

    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA512);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA2_API_TC002
 * @title  SHA2 get the digest length test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdGetDigestSize to get the digest length, expected result 1.
 * @expect
 *    1.The value is the same as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA2_API_TC002(void)
{
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(-1), 0);
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_MAX), 0);
    // The length of the SHA224 digest is 28 characters.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA224), 28);
    // The length of the SHA256 digest is 32 characters.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA256), 32);
    // The length of the SHA384 digest is 48 characters.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA384), 48);
    // The length of the SHA512 digest is 64 characters.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA512), 64);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA2_API_TC003
 * @title  update and final test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdDeinit the null CTX, expected result 1.
 *    2.Call CRYPT_EAL_MdNewCtx create the CTX, expected result 2.
 *    3.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal before initialization, expected result 3.
 *    4.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal use null pointer, expected result 4.
 *    5.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal normally, expected result 5.
 *    6.Call CRYPT_EAL_MdDeinit the CTX, expected result 6.
 * @expect
 *    1.Return CRYPT_NULL_INPUT
 *    2.Create successful.
 *    3.Return CRYPT_EAL_ERR_STATE.
 *    4.Return CRYPT_NULL_INPUT.
 *    5.Successful.
 *    6.Return CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA2_API_TC003(int id)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;

    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_NULL_INPUT);

    ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    uint8_t input[SHA2_OUTPUT_MAXSIZE];
    const uint32_t inLen = SHA2_OUTPUT_MAXSIZE;

    uint8_t out[SHA2_OUTPUT_MAXSIZE];
    uint32_t validOutLen = CRYPT_EAL_MdGetDigestSize(id);
    uint32_t invalidOutLen = validOutLen - 1;

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, inLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &validOutLen), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(NULL, input, inLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, NULL, inLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, input, inLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(NULL, out, &validOutLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, NULL, &validOutLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &invalidOutLen), CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &validOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdGetId(ctx), id);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdIsValidAlgId(id), true);

    ASSERT_EQ(CRYPT_EAL_MdDeinit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(ctx->state, CRYPT_MD_STATE_NEW);

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
void SDV_CRYPT_EAL_MD_SHA2_FUNC_TC001(int id)
{
    if (IsMdAlgDisabled(id)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx1 = NULL;
    CRYPT_EAL_MdCTX *ctx2 = NULL;

    ctx1 = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx1 != NULL);

    ctx2 = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx2 != NULL);

    // 100! = 5050
    uint8_t input[5050];
    uint32_t inLenTotal = 0;
    uint32_t inLenBase;
    uint8_t out1[SHA2_OUTPUT_MAXSIZE];
    uint8_t out2[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = CRYPT_EAL_MdGetDigestSize(id);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx2), CRYPT_SUCCESS);

    for (inLenBase = 1; inLenBase <= 100; inLenBase++) {
        ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx1, input + inLenTotal, inLenBase), CRYPT_SUCCESS);
        inLenTotal += inLenBase;
    }
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx1, out1, &outLen), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_MdGetDigestSize(id);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx2, input, inLenTotal), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx2, out2, &outLen), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_MdGetDigestSize(id);

   ASSERT_COMPARE("sha2", out1, outLen, out2, outLen);
   ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx1);
    CRYPT_EAL_MdFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_MD_SHA2_FUNC_TC002
 * @title  Empty string test.
 * @precon nan
 * @brief
 *    1.Create ctx and initialize it, expected result 1.
 *    2.Call CRYPT_EAL_MdFinal to get the output, expected result 2.
 *    3.Compare output and vectors, expected result 3.
 * @expect
 *    1.Successful.
 *    2.Successful.
 *    3.The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_MD_SHA2_FUNC_TC002(int id, Hex *digest)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    uint8_t out[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = CRYPT_EAL_MdGetDigestSize(id);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);

    ASSERT_COMPARE("sha2", out, outLen, digest->x, digest->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_MD_SHA2_FUNC_TC003
 * @title  standard vector test.
 * @precon nan
 * @brief
 *    1.Calculate the hash of the data and compare it with the standard vector, expected result 1.
 *    2.Call CRYPT_EAL_Md to calculate the hash of the data and compare it with the standard vector, expected result 2.
 * @expect
 *    1.The results are the same.
 *    2.The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_MD_SHA2_FUNC_TC003(int algId, Hex *in, Hex *digest)
{
    if (IsMdAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;

    uint8_t out[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = CRYPT_EAL_MdGetDigestSize(algId);

    ctx = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, in->x, in->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);

    ASSERT_COMPARE("sha2", out, outLen, digest->x, digest->len);
  
    ASSERT_EQ(CRYPT_EAL_Md(algId, in->x, in->len, out, &outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("sha2", out, outLen, digest->x, digest->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_MD_SHA2_FUNC_TC004
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
void SDV_CRYPT_EAL_MD_SHA2_FUNC_TC004(int algId, Hex *plain_text1, Hex *plain_text2, Hex *plain_text3, Hex *hash)
{
    // 100 is greater than the digest length of all SHA algorithms.
    unsigned char output[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA2_OUTPUT_MAXSIZE;

    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, plain_text1->x, plain_text1->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, plain_text2->x, plain_text2->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, plain_text3->x, plain_text3->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);

    ASSERT_COMPARE("sha2", output, outLen, hash->x, hash->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_MD_SHA2_FUNC_TC005
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
void SDV_CRYPT_EAL_MD_SHA2_FUNC_TC005(int algId, Hex *data, Hex *hash)
{
    int ret;
    TestMemInit();
    const uint32_t threadNum = 2;
    pthread_t thrd[2];
    ThreadParameter arg[2] = {
        {data->x, hash->x, data->len, hash->len, algId},
        {data->x, hash->x, data->len, hash->len, algId}
    };
    for (uint32_t i = 0; i < threadNum; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)Sha2MultiThreadTest, &arg[i]);
        ASSERT_EQ(ret, 0);
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
 * @test   SDV_CRYPTO_SHA2_COPY_CTX_FUNC_TC001
 * @title  SHA2 copy ctx function test.
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
void SDV_CRYPTO_SHA2_COPY_CTX_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    if (IsMdAlgDisabled(id)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_MdCTX *cpyCtx = NULL;
    CRYPT_EAL_MdCTX *dupCtx = NULL;
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA2_OUTPUT_MAXSIZE;

    dupCtx=CRYPT_EAL_MdDupCtx(cpyCtx);
    ASSERT_TRUE(dupCtx == NULL);
    ASSERT_EQ(CRYPT_MD_MAX, CRYPT_EAL_MdGetId(dupCtx));
    
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, ctx), CRYPT_NULL_INPUT);
    cpyCtx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_TRUE(dupCtx == NULL);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, dupCtx), CRYPT_NULL_INPUT);
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
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_MdFreeCtx(cpyCtx);
    CRYPT_EAL_MdFreeCtx(dupCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SHA2_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SHA2_DEFAULT_PROVIDER_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderMdNewCtx(NULL, id, "provider=default");
#else
    ctx = CRYPT_EAL_MdNewCtx(id);
#endif
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[SHA2_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA2_OUTPUT_MAXSIZE;

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, output, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */
