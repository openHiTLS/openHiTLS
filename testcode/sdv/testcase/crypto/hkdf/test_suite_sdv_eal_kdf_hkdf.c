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
#include "eal_kdf_local.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "stub_utils.h"
/* END_HEADER */

#define DATA_LEN (64)
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

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
    BSL_Param params[7] = {{0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt, saltLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info, infoLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_NULL_INPUT);

    outLen = GetMaxKeyLen(algId) + 1;
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_HKDF_DKLEN_OVERFLOW);
    outLen = DATA_LEN;

    CRYPT_MAC_AlgId macAlgIdFailed = CRYPT_MAC_MAX;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgIdFailed, sizeof(macAlgIdFailed)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_HKDF_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

EXIT:
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
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
EXIT:
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
    CRYPT_EAL_KdfCTX *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
#else
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
#endif
    ASSERT_TRUE(ctx != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_BSL_PARAM_MAKER_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
{
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), BSL_SUCCESS);
    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);

    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), BSL_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
    BSL_PARAM_MAKER_Free(maker);
    BSL_PARAM_Free(params);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_BSL_PARAM_MAKER_TC002(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
{
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_DeepPushValue(maker, CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_DeepPushValue(maker, CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_DeepPushValue(maker, CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), BSL_SUCCESS);
    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);

    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), BSL_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), BSL_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
    BSL_PARAM_MAKER_Free(maker);
    BSL_PARAM_Free(params);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_COPY_CTX_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_KdfCTX *ctxA = NULL;
    CRYPT_EAL_KdfCTX *ctxB = NULL;
    CRYPT_EAL_KdfCTX ctxC = { 0 };
    if (isProvider != 0) {
        ctxA = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
        ctxB = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
    } else {
        ctxA = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
        ctxB = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    }
    ASSERT_TRUE(ctxA != NULL);
    ASSERT_TRUE(ctxB != NULL);

    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    // Copy failed because ctxC lacks a method.
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    // A directly created context can also be used as the destination for copying.
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.method.freeCtx(ctxC.data);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctxA);
    CRYPT_EAL_KdfFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_DUP_CTX_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_KdfCTX *ctxA = NULL;
    CRYPT_EAL_KdfCTX *ctxB = NULL;
    CRYPT_EAL_KdfCTX ctxC = { 0 };
    if (isProvider != 0) {
        ctxA = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
    } else {
        ctxA = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    }
    ASSERT_TRUE(ctxA != NULL);

    ctxB = CRYPT_EAL_KdfDupCtx(NULL);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_KdfDupCtx(&ctxC);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_KdfDupCtx(ctxA);
    ASSERT_TRUE(ctxB != NULL);

EXIT:
    CRYPT_EAL_KdfFreeCtx(ctxA);
    CRYPT_EAL_KdfFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_COPY_CTX_API_TC002(int algId, Hex *key, Hex *salt, Hex *info, int isProvider)
{
    TestMemInit();
    uint32_t tmpLenA = DATA_LEN;
    uint8_t tmpBufA[DATA_LEN] = {0};
    uint32_t tmpLenB = DATA_LEN;
    uint8_t tmpBufB[DATA_LEN] = {0};
    uint32_t tmpLenC = DATA_LEN;
    uint8_t tmpBufC[DATA_LEN] = {0};

    CRYPT_EAL_KdfCTX *ctxA = NULL;
    CRYPT_EAL_KdfCTX *ctxB = NULL;
    CRYPT_EAL_KdfCTX *ctxC = NULL;
    if (isProvider != 0) {
        ctxA = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
        ctxB = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
    } else {
        ctxA = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
        ctxB = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    }
    ASSERT_TRUE(ctxA != NULL);
    ASSERT_TRUE(ctxB != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;
    BSL_Param params[7] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    int32_t id = (int32_t)algId;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &id, sizeof(id)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR,
        &tmpLenA, sizeof(tmpLenA)), CRYPT_SUCCESS);

    // Set parameters in ctxA, then copy to ctxB
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctxA, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(ctxB, ctxA), CRYPT_SUCCESS);
    ctxC = CRYPT_EAL_KdfDupCtx(ctxA);
    ASSERT_TRUE(ctxC != NULL);

    // Key derivation fails in ctxB due to unset tmpBuf length
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctxA, tmpBufA, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctxB, tmpBufB, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctxC, tmpBufC, 0), CRYPT_NULL_INPUT);

    // After setting ctxB's length, redo key derivation and compare results (should match)
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR,
        &tmpLenB, sizeof(tmpLenB)), CRYPT_SUCCESS);
    (void)memset_s(&params[1], sizeof(BSL_Param), 0, sizeof(BSL_Param));
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctxB, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctxB, tmpBufB, 0), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", tmpBufA, tmpLenA, tmpBufB, tmpLenB);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR,
        &tmpLenC, sizeof(tmpLenC)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctxC, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctxC, tmpBufC, 0), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", tmpBufA, tmpLenA, tmpBufC, tmpLenC);

EXIT:
    CRYPT_EAL_KdfFreeCtx(ctxA);
    CRYPT_EAL_KdfFreeCtx(ctxB);
    CRYPT_EAL_KdfFreeCtx(ctxC);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_HKDF_COPY_CTX_FUNC_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result, int isProvider)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = BSL_SAL_Malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = NULL;
    CRYPT_EAL_KdfCTX *copyCtx = NULL;
    CRYPT_EAL_KdfCTX *copyCtx1 = NULL;
    CRYPT_EAL_KdfCTX *copyCtx2 = NULL;
    CRYPT_EAL_KdfCTX *copyCtx3 = NULL;
    if (isProvider != 0) {
        ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
        copyCtx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
        copyCtx1 = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
        copyCtx2 = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
    } else {
        ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
        copyCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
        copyCtx1 = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
        copyCtx2 = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    }
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(copyCtx != NULL);
    ASSERT_TRUE(copyCtx1 != NULL);
    ASSERT_TRUE(copyCtx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(copyCtx, ctx), CRYPT_SUCCESS);
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    int32_t id = (int32_t)algId;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &id, sizeof(id)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(copyCtx, params), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(copyCtx1, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(copyCtx2, ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(copyCtx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result1 cmp", out, outLen, result->x, result->len);
    (void)memset_s(out, outLen, 0, outLen);
    CRYPT_EAL_KdfFreeCtx(copyCtx);
    copyCtx = NULL;

    ASSERT_EQ(CRYPT_EAL_KdfDerive(copyCtx1, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result2 cmp", out, outLen, result->x, result->len);
    (void)memset_s(out, outLen, 0, outLen);
    CRYPT_EAL_KdfFreeCtx(copyCtx1);
    copyCtx1 = NULL;

    copyCtx3 = CRYPT_EAL_KdfDupCtx(ctx);
    ASSERT_TRUE(copyCtx3 != NULL);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(copyCtx3, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result3 cmp", out, outLen, result->x, result->len);
    (void)memset_s(out, outLen, 0, outLen);
    CRYPT_EAL_KdfFreeCtx(copyCtx3);
    copyCtx3 = NULL;

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result4 cmp", out, outLen, result->x, result->len);
    (void)memset_s(out, outLen, 0, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    ctx = NULL;

    ASSERT_EQ(CRYPT_EAL_KdfDerive(copyCtx2, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result5 cmp", out, outLen, result->x, result->len);
EXIT:
    BSL_SAL_Free(out);
    CRYPT_EAL_KdfFreeCtx(ctx);
    CRYPT_EAL_KdfFreeCtx(copyCtx);
    CRYPT_EAL_KdfFreeCtx(copyCtx1);
    CRYPT_EAL_KdfFreeCtx(copyCtx2);
}
/* END_CASE */

static int32_t TestKdfCopyCtxMemCheck(int32_t algId, Hex *key, Hex *salt, Hex *info, int isProvider)
{
    CRYPT_EAL_KdfCTX *ctxA = NULL;
    CRYPT_EAL_KdfCTX *ctxB = NULL;
    CRYPT_EAL_KdfCTX *srcCtx = NULL;
    if (isProvider != 0) {
        srcCtx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
        ctxA = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
    } else {
        srcCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
        ctxA = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    }
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
    int32_t ret = CRYPT_EAL_KdfSetParam(srcCtx, params);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

    ret = CRYPT_EAL_KdfCopyCtx(ctxA, srcCtx);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ctxB = CRYPT_EAL_KdfDupCtx(srcCtx);
    if (ctxB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctxA);
    CRYPT_EAL_KdfFreeCtx(ctxB);
    CRYPT_EAL_KdfFreeCtx(srcCtx);
    return ret;
}

/**
 * @test SDV_CRYPTO_HKDF_COPY_CTX_STUB_TC001
 * title 1. Test the kdf copy context with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_COPY_CTX_STUB_TC001(int algId, Hex *key, Hex *salt, Hex *info, int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(TestKdfCopyCtxMemCheck((int32_t)algId, key, salt, info, isProvider), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++)
    {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(TestKdfCopyCtxMemCheck((int32_t)algId, key, salt, info, isProvider), CRYPT_SUCCESS);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */