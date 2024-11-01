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
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
/* END_HEADER */

#define DATA_LEN (64)
#define ITERATION_COUNT (1024)
#define DATA_MAX_LEN (512)
#define TEST_FAIL (-1)
#define TEST_SUCCESS (0)

void PBKDF2_SET_PARAM(CRYPT_Param *p, void *param, uint32_t paramLen)
{
    p->param = param;
    p->paramLen = paramLen;
}

/**
 * @test   SDV_CRYPT_EAL_KDF_PBKDF2_API_TC001
 * @title  pbkdf2 api test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_KdfCTX functions and set the key length to 0, expected result 1.
 *    2.Call CRYPT_EAL_KdfCTX functions and set the key is null but keyLen not 0, expected result 2.
 *    3.Call CRYPT_EAL_KdfCTX functions and set the salt length to 0, expected result 3.
 *    4.Call CRYPT_EAL_KdfCTX functions and set the salt is null but saltLen not 0, expected result 4.
 *    5.Call CRYPT_EAL_KdfCTX functions and set number of iterations to 0, expected result 5.
 *    6.Call CRYPT_EAL_KdfCTX functions and output is null or outlen is 0, expected result 6.
 *    7.Call CRYPT_EAL_KdfCTX functions use all mac algorithm ID, expected result 7.
 * @expect
 *    1.Return CRYPT_SUCCESS.
 *    2.Return CRYPT_NULL_INPUT.
 *    3.Return CRYPT_SUCCESS.
 *    4.Return CRYPT_NULL_INPUT.
 *    5.Return CRYPT_PBKDF2_PARAM_ERROR.
 *    6.Return CRYPT_PBKDF2_PARAM_ERROR.
 *    7.All successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_PBKDF2_API_TC001(void)
{
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[DATA_LEN];
    uint32_t it = ITERATION_COUNT; // The number of iterations cannot be less than 1024.. GM/T 0091-2020
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_MAC_AlgId macAlgId = CRYPT_MAC_HMAC_SHA1;

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &macAlgId, sizeof(macAlgId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param passwordParam = {CRYPT_KDF_PARAM_PASSWORD, key, keyLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_SUCCESS);

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt, saltLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    CRYPT_Param iterParam = {CRYPT_KDF_PARAM_ITER, &it, sizeof(it)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &iterParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    PBKDF2_SET_PARAM(&passwordParam, NULL, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_NULL_INPUT);

    PBKDF2_SET_PARAM(&passwordParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    PBKDF2_SET_PARAM(&passwordParam, key, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    PBKDF2_SET_PARAM(&passwordParam, key, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_SUCCESS);

    PBKDF2_SET_PARAM(&saltParam, NULL, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_NULL_INPUT);

    PBKDF2_SET_PARAM(&saltParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    PBKDF2_SET_PARAM(&saltParam, salt, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    PBKDF2_SET_PARAM(&saltParam, salt, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    uint32_t iterCntFailed = 0;
    PBKDF2_SET_PARAM(&iterParam, &iterCntFailed, sizeof(iterCntFailed));
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &iterParam), CRYPT_PBKDF2_PARAM_ERROR);

    PBKDF2_SET_PARAM(&iterParam, &it, sizeof(it));
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &iterParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_PBKDF2_PARAM_ERROR);

    macAlgId = CRYPT_MAC_HMAC_MD5;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA1;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA224;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA256;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA384;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA512;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SM3;
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCtrl(ctx, 0, NULL, 0), CRYPT_NULL_INPUT);
exit:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_PBKDF2_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_KDFCTX functions get output, expected result 1.
*     2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Successful.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_PBKDF2_FUN_TC001(int algId, Hex *key, Hex *salt, int it, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param passwordParam = {CRYPT_KDF_PARAM_PASSWORD, key->x, key->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_SUCCESS);

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt->x, salt->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    CRYPT_Param iterParam = {CRYPT_KDF_PARAM_ITER, &it, sizeof(it)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &iterParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PBKDF2_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PBKDF2_DEFAULT_PROVIDER_FUNC_TC001(int algId, Hex *key, Hex *salt, int it, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_PBKDF2, "provider=default");
    ASSERT_TRUE(ctx != NULL);

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param passwordParam = {CRYPT_KDF_PARAM_PASSWORD, key->x, key->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &passwordParam), CRYPT_SUCCESS);

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt->x, salt->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    CRYPT_Param iterParam = {CRYPT_KDF_PARAM_ITER, &it, sizeof(it)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &iterParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */
