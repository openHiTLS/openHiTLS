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

#include "crypt_eal_md.h"
#include "bsl_sal.h"
#include "eal_md_local.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "securec.h"
/* END_HEADER */

/**
 * @test   SDV_CRYPT_EAL_SM3_API_TC001
 * @title  CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal test
 * @precon nan
 * @brief
 *    1.Invoke the CRYPT_EAL_MdNewCtx to create a CTX, expected result 1.
 *    2.Call CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal before initialization, expected result 2 is obtained.
 *    3.Initialize the CTX and transfer null pointers to CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal. expected result 3.
 *    4.Invoke CRYPT_EAL_MdUpdate and CRYPT_EAL_MdFinal normally, expected result 4.
 * @expect
 *    1.Successful, ctx is returned.
 *    2.Return CRYPT_EAL_ERR_STATE
 *    3.Return CRYPT_NULL_INPUT
 *    4.Return CRYPT_SUCCESS
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
    CRYPT_EAL_MdCTX *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
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
exit:
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

exit:
    CRYPT_EAL_MdFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SM3_FUNC_TC002
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

exit:
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

exit:
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

exit:
    CRYPT_EAL_MdFreeCtx(ctx1);
    CRYPT_EAL_MdFreeCtx(ctx2);
}
/* END_CASE */
