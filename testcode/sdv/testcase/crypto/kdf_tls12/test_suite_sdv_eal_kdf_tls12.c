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

void KDFTLS12_SET_PARAM(CRYPT_Param *p, void *param, uint32_t paramLen)
{
    p->param = param;
    p->paramLen = paramLen;
}

/**
 * @test   SDV_CRYPT_EAL_KDF_TLS12_API_TC001
 * @title  kdftls12 interface test.
 * @precon nan
 * @brief
 *    1.Normal parameter test,the key and label can be empty,parameter limitation see unction declaration,
    expected result 1.
 * @expect
 *    1.The results are as expected, algId only supported CRYPT_MAC_HMAC_SHA256, CRYPT_MAC_HMAC_SHA384,
    and CRYPT_MAC_HMAC_SHA512.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_TLS12_API_TC001(int algId)
{
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t labelLen = DATA_LEN;
    uint8_t label[DATA_LEN];
    uint32_t seedLen = DATA_LEN;
    uint8_t seed[DATA_LEN];
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, key, keyLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    CRYPT_Param labelParam = {CRYPT_KDF_PARAM_LABEL, label, labelLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_SUCCESS);

    CRYPT_Param seedParam = {CRYPT_KDF_PARAM_SEED, seed, seedLen};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&keyParam, NULL, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_NULL_INPUT);

    KDFTLS12_SET_PARAM(&keyParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&keyParam, key, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&keyParam, key, keyLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&labelParam, NULL, labelLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_NULL_INPUT);

    KDFTLS12_SET_PARAM(&labelParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&labelParam, label, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&labelParam, label, labelLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&seedParam, NULL, seedLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_NULL_INPUT);

    KDFTLS12_SET_PARAM(&seedParam, NULL, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&seedParam, seed, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    KDFTLS12_SET_PARAM(&seedParam, seed, seedLen);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_NULL_INPUT);

    CRYPT_MAC_AlgId macAlgIdFailed = CRYPT_MAC_HMAC_SHA224;
    KDFTLS12_SET_PARAM(&macAlgIdParam, &macAlgIdFailed, 0);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_KDFTLS12_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCtrl(ctx, 0, NULL, 0), CRYPT_NULL_INPUT);
exit:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_TLS12_FUN_TC001
 * @title  kdftls12 vector test.
 * @precon nan
 * @brief
 *    1.Calculate the output using the given parameters, expected result 1.
 *    2.Compare the calculated result with the standard value, expected result 2.
 * @expect
 *    1.Calculation succeeded.
 *    2.The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_TLS12_FUN_TC001(int algId, Hex *key, Hex *label, Hex *seed, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, key->x, key->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    CRYPT_Param labelParam = {CRYPT_KDF_PARAM_LABEL, label->x, label->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_SUCCESS);

    CRYPT_Param seedParam = {CRYPT_KDF_PARAM_SEED, seed->x, seed->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_SUCCESS);

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
 * @test   SDV_CRYPTO_KDFTLS12_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_KDFTLS12_DEFAULT_PROVIDER_FUNC_TC001(int algId, Hex *key, Hex *label, Hex *seed, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
    ASSERT_TRUE(ctx != NULL);

    CRYPT_Param macAlgIdParam = {CRYPT_KDF_PARAM_MAC_ALG_ID, &algId, sizeof(algId)};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &macAlgIdParam), CRYPT_SUCCESS);

    CRYPT_Param keyParam = {CRYPT_KDF_PARAM_KEY, key->x, key->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &keyParam), CRYPT_SUCCESS);

    CRYPT_Param labelParam = {CRYPT_KDF_PARAM_LABEL, label->x, label->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &labelParam), CRYPT_SUCCESS);

    CRYPT_Param seedParam = {CRYPT_KDF_PARAM_SEED, seed->x, seed->len};
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, &seedParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */
