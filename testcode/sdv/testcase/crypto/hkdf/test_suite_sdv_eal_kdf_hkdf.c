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

#include "securec.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
/* END_HEADER */

#define DATA_LEN (64)

void HKDF_SET_PARAM(CRYPT_Param *p, void *param, uint32_t paramLen)
{
    p->param = param;
    p->paramLen = paramLen;
}

static uint32_t GetMaxKeyLen(int algId)
{
    switch (algId) {
        case CRYPT_MAC_HMAC_SHA1:
            return 5100;
        case CRYPT_MAC_HMAC_SHA224:
            return 7140;
        case CRYPT_MAC_HMAC_SHA256:
            return 8160;
        case CRYPT_MAC_HMAC_SHA384:
            return 12240;
        case CRYPT_MAC_HMAC_SHA512:
            return 16320;
        default:
            return 0;
    }
}

/**
 * @test   SDV_CRYPT_EAL_KDF_HKDF_API_TC001
 * @title  hkdf api test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_KdfCTX functions and set the key length to 0, expected result 1.
 *    2.Call CRYPT_EAL_KdfCTX functions and set the key is null but keyLen not 0, expected result 2.
 *    3.Call CRYPT_EAL_KdfCTX functions and set the salt length to 0, expected result 3.
 *    4.Call CRYPT_EAL_KdfCTX functions and set the salt is null but saltLen not 0, expected result 4.
 *    5.Call CRYPT_EAL_KdfCTX functions and set the info length to 0, expected result 5.
 *    6.Call CRYPT_EAL_KdfCTX functions and set the info is null but infoLen not 0, expected result 6.
 *    7.Call CRYPT_EAL_KdfCTX functions and output is null or outlen is 0, expected result 7.
 *    8.Call CRYPT_EAL_KdfCTX functions length of the derived key exceeds the maximum, expected result 8.
 *    9.Call CRYPT_EAL_KdfCTX functions using an incorrect id, expected result 9.
 * @expect
 *    1.Return CRYPT_SUCCESS.
 *    2.Return CRYPT_NULL_INPUT.
 *    3.Return CRYPT_SUCCESS.
 *    4.Return CRYPT_NULL_INPUT.
 *    5.Return CRYPT_SUCCESS.
 *    6.Return CRYPT_NULL_INPUT.
 *    7.return CRYPT_NULL_INPUT.
 *    8.Return CRYPT_HKDF_DKLEN_OVERFLOW.
 *    9.Return CRYPT_EAL_ERR_ALGID.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_HKDF_API_TC001(int algId)
{
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[DATA_LEN];
    uint32_t infoLen = DATA_LEN;
    uint8_t info[DATA_LEN];
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param modeParam = {CRYPT_KDF_PARAM_MODE, &mode, sizeof(mode)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &modeParam), CRYPT_SUCCESS);

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, key, keyLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt, saltLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    CRYPT_Param infoParam = {CRYPT_KDF_PARAM_INFO, info, infoLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&keyParam, NULL, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_NULL_INPUT);

    HKDF_SET_PARAM(&keyParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&keyParam, key, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&keyParam, key, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&saltParam, NULL, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_NULL_INPUT);

    HKDF_SET_PARAM(&saltParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&saltParam, salt, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&saltParam, salt, saltLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&infoParam, NULL, infoLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_NULL_INPUT);

    HKDF_SET_PARAM(&infoParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&infoParam, info, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&infoParam, info, infoLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_SUCCESS);

    CRYPT_Param prkParam = {CRYPT_KDF_PARAM_PRK, key, keyLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &prkParam), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&prkParam, NULL, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &prkParam), CRYPT_NULL_INPUT);

    HKDF_SET_PARAM(&prkParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &prkParam), CRYPT_SUCCESS);

    HKDF_SET_PARAM(&prkParam, key, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &prkParam), CRYPT_SUCCESS);

    CRYPT_Param outLenParam = {CRYPT_KDF_PARAM_OUTLEN, NULL, 0};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &outLenParam), CRYPT_NULL_INPUT);

    HKDF_SET_PARAM(&outLenParam, &outLen, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &outLenParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_NULL_INPUT);

    outLen = GetMaxKeyLen(algId) + 1;
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_HKDF_DKLEN_OVERFLOW);
    outLen = DATA_LEN;

    CRYPT_MAC_AlgId macAlgIdFailed = CRYPT_MAC_MAX;
    HKDF_SET_PARAM(&macAlgIdParam, &macAlgIdFailed, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_HKDF_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCtrl(ctx, 0, NULL, 0), CRYPT_NULL_INPUT);
exit:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_KdfCTX functions get output, expected result 1.
*     2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Successful.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param modeParam = {CRYPT_KDF_PARAM_MODE, &mode, sizeof(mode)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &modeParam), CRYPT_SUCCESS);

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, key->x, key->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt->x, salt->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    CRYPT_Param infoParam = {CRYPT_KDF_PARAM_INFO, info->x, info->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_SUCCESS);

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
 * @test   SDV_CRYPTO_HKDF_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_DEFAULT_PROVIDER_FUNC_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
    ASSERT_TRUE(ctx != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param modeParam = {CRYPT_KDF_PARAM_MODE, &mode, sizeof(mode)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &modeParam), CRYPT_SUCCESS);

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, key->x, key->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    CRYPT_Param saltParam = {CRYPT_KDF_PARAM_SALT, salt->x, salt->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &saltParam), CRYPT_SUCCESS);

    CRYPT_Param infoParam = {CRYPT_KDF_PARAM_INFO, info->x, info->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &infoParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */
