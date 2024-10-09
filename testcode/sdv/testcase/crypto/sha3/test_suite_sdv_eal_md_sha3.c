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
#include "crypt_sha3.h"
#include "securec.h"
/* END_HEADER */

// 100 is greater than the digest length of all SHA algorithms.
#define SHA3_OUTPUT_MAXSIZE 100

typedef struct {
    uint8_t *data;
    uint8_t *hash;
    uint32_t dataLen;
    uint32_t hashLen;
    CRYPT_MD_AlgId id;
} ThreadParameter;

void Sha3MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint32_t outLen = SHA3_OUTPUT_MAXSIZE;
    uint8_t out[SHA3_OUTPUT_MAXSIZE];
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(threadParameter->id);
    ASSERT_TRUE(ctx != NULL);
    for (uint32_t i = 0; i < 10; i++) {
        ASSERT_TRUE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_MdUpdate(ctx, threadParameter->data, threadParameter->dataLen) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_MdFinal(ctx, out, &outLen) == CRYPT_SUCCESS);
        ASSERT_COMPARE("hash result cmp", out, outLen, threadParameter->hash, threadParameter->hashLen);
    }

exit:
    CRYPT_EAL_MdFreeCtx(ctx);
}

/**
 * @test   SDV_CRYPT_EAL_SHA3_API_TC001
 * @title  SHA3 get the digest length test.
 * @precon nan
 * @brief
 *    Call CRYPT_EAL_MdGetDigestSize to get the digest length.
 * @expect
 *    The results are correct.
 *
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA3_API_TC001(void)
{
    // The length of the SHA3_224 digest is 28.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA3_224), 28);

    // The length of the SHA3_256 digest is 32.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA3_256), 32);

    // The length of the SHA3_384 digest is 48.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA3_384), 48);

    // The length of the SHA3_512 digest is 64.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA3_512), 64);

    // The length of the SHAKE128 digest is 0.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHAKE128), 0);

    // The length of the SHAKE256 digest is 0.
    ASSERT_EQ(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHAKE256), 0);
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA3_API_TC002
 * @title  update and final test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_MdNewCtx create the CTX, expected result 1.
 *    2.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal before initialization, expected result 2.
 *    3.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal use null pointer, expected result 3.
 *    4.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal normally, expected result 4.
 * @expect
 *    1.Create successful.
 *    2.Return CRYPT_EAL_ERR_STATE.
 *    3.Return CRYPT_NULL_INPUT.
 *    4.Successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA3_API_TC002(int algId)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *sha3Ctx = NULL;
    uint8_t data[10] = {0x0e};
    uint32_t dataLen = 1;
    uint8_t output[SHA3_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA3_OUTPUT_MAXSIZE;

    sha3Ctx = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(sha3Ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(sha3Ctx, data, dataLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MdFinal(sha3Ctx, output, &outLen), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_MdInit(sha3Ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(NULL, data, dataLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(sha3Ctx, NULL, dataLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(sha3Ctx, data, dataLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdFinal(NULL, output, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(sha3Ctx, NULL, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(sha3Ctx, output, NULL), CRYPT_NULL_INPUT);

    outLen = CRYPT_EAL_MdGetDigestSize(algId) - 1;
    ASSERT_EQ(CRYPT_EAL_MdFinal(sha3Ctx, output, &outLen), CRYPT_SHA3_OUT_BUFF_LEN_NOT_ENOUGH);

    outLen = CRYPT_EAL_MdGetDigestSize(algId);
    ASSERT_EQ(CRYPT_EAL_MdFinal(sha3Ctx, output, &outLen), CRYPT_SUCCESS);
exit:
    CRYPT_EAL_MdFreeCtx(sha3Ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA3_FUNC_TC001
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
void SDV_CRYPT_EAL_SHA3_FUNC_TC001(int algId)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx1 = NULL;
    CRYPT_EAL_MdCTX *ctx2 = NULL;

    ctx1 = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(ctx1 != NULL);

    ctx2 = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(ctx2 != NULL);

    // 100! = 5050
    uint8_t input[5050];
    uint32_t inLenTotal = 0;

    uint32_t inLenBase;

    uint8_t out1[SHA3_OUTPUT_MAXSIZE];  // 100 is greater than the digest length of all SHA algorithms.
    uint8_t out2[SHA3_OUTPUT_MAXSIZE];
    uint32_t outLen = CRYPT_EAL_MdGetDigestSize(algId);

    ASSERT_EQ(CRYPT_EAL_MdInit(ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx2), CRYPT_SUCCESS);

    // update 100 times.
    for (inLenBase = 1; inLenBase <= 100; inLenBase++) {
        ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx1, input + inLenTotal, inLenBase), CRYPT_SUCCESS);
        inLenTotal += inLenBase;
    }
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx1, out1, &outLen), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_MdGetDigestSize(algId);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx2, input, inLenTotal), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx2, out2, &outLen), CRYPT_SUCCESS);

    outLen = CRYPT_EAL_MdGetDigestSize(algId);

    ASSERT_EQ(memcmp(out1, out2, outLen), 0);

exit:
    CRYPT_EAL_MdFreeCtx(ctx1);
    CRYPT_EAL_MdFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA3_FUNC_TC002
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
void SDV_CRYPT_EAL_SHA3_FUNC_TC002(int algId, Hex *data, Hex *hash)
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
        ret = pthread_create(&thrd[i], NULL, (void *)Sha3MultiThreadTest, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        pthread_join(thrd[i], NULL);
    }

exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA3_FUNC_TC003
 * @title  Standard vector test.
 * @precon nan
 * @brief
 *    Calculate the hash of the data and compare it with the standard vector.
 * @expect
 *    The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA3_FUNC_TC003(int algId, Hex *in, Hex *digest)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;

    uint8_t out[SHA3_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA3_OUTPUT_MAXSIZE;

    ctx = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, in->x, in->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, digest->len);
    ASSERT_EQ(memcmp(out, digest->x, digest->len), 0);
exit:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SHA3_FUNC_TC004
 * @title  Standard vector test of the SHAKE algorithm.
 * @precon nan
 * @brief
 *    Calculate the hash of the data and compare it with the standard vector.
 * @expect
 *    The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SHA3_FUNC_TC004(int algId, Hex *in, Hex *digest)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *ctx = NULL;

    uint8_t out[SHA3_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA3_OUTPUT_MAXSIZE;

    ctx = CRYPT_EAL_MdNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(ctx, in->x, in->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(out, digest->x, digest->len), 0);
exit:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SHA3_COPY_CTX_FUNC_TC001
 * @title  SHA3 copy ctx function test.
 * @precon nan
 * @brief
 *    1. Create the context ctx of md algorithm, expected result 1
 *    2. Call to CRYPT_EAL_MdCopyCtx method to copy ctx, expected result 2
 *    3. Calculate the hash of msg, and compare the calculated result with hash vector, expected result 3
 * @expect
 *    1. Successful, the context is not null.
 *    2. CRYPT_SUCCESS
 *    3. Successful, the hashs are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SHA3_COPY_CTX_FUNC_TC001(int id, Hex *msg, Hex *hash)
{
    TestMemInit();
    CRYPT_EAL_MdCTX *cpyCtx = NULL;
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    uint8_t output[SHA3_OUTPUT_MAXSIZE];
    uint32_t outLen = SHA3_OUTPUT_MAXSIZE;

    cpyCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_MdCTX));
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_MdCopyCtx(cpyCtx, ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdInit(cpyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(cpyCtx, msg->x, msg->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(cpyCtx, output, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(id, cpyCtx->id);
    if (ctx->id != CRYPT_MD_SHAKE128 && ctx->id != CRYPT_MD_SHAKE256) {
        ASSERT_TRUE(outLen == hash->len);
    }
    ASSERT_EQ(memcmp(output, hash->x, hash->len), 0);

exit:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_MdFreeCtx(cpyCtx);
}
/* END_CASE */
