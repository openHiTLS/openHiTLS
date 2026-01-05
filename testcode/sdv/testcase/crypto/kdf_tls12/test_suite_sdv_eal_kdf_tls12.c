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
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "stub_replace.h"
/* END_HEADER */

#define DATA_LEN (64)

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

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label, labelLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed, seedLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_NULL_INPUT);

    CRYPT_MAC_AlgId macAlgIdFailed = CRYPT_MAC_HMAC_SHA224;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgIdFailed, sizeof(macAlgIdFailed)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_KDFTLS12_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);
EXIT:
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

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);
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
    CRYPT_EAL_KdfCTX *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
#else
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
#endif
    ASSERT_TRUE(ctx != NULL);

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);
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
void SDV_CRYPTO_KDFTLS12_COPY_CTX_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_KdfCTX *ctxA = NULL;
    CRYPT_EAL_KdfCTX *ctxB = NULL;
    CRYPT_EAL_KdfCTX ctxC = { 0 };
    if (isProvider != 0) {
        ctxA = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
        ctxB = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
    } else {
        ctxA = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
        ctxB = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
    }
    ASSERT_TRUE(ctxA != NULL);
    ASSERT_TRUE(ctxB != NULL);

    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    // Copy failed because ctxC lacks a method.
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    // A directly created context can also be used as the destination for copying.
    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.method->freeCtx(ctxC.data);
    BSL_SAL_Free(ctxC.method);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctxA);
    CRYPT_EAL_KdfFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_KDF_TLS12_DUP_CTX_API_TC001(int isProvider)
{
    TestMemInit();
    CRYPT_EAL_KdfCTX *ctxA = NULL;
    CRYPT_EAL_KdfCTX *ctxB = NULL;
    CRYPT_EAL_KdfCTX ctxC = { 0 };
    if (isProvider != 0) {
        ctxA = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
    } else {
        ctxA = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
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
void SDV_CRYPT_EAL_KDF_TLS12_COPY_CTX_FUNC_TC001(int algId, Hex *key, Hex *label, Hex *seed, Hex *result,
    int isProvider)
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
        ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
        copyCtx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
        copyCtx1 = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
        copyCtx2 = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_KDFTLS12, "provider=default");
    } else {
        ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
        copyCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
        copyCtx1 = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
        copyCtx2 = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
    }
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(copyCtx != NULL);
    ASSERT_TRUE(copyCtx1 != NULL);
    ASSERT_TRUE(copyCtx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_KdfCopyCtx(copyCtx, ctx), CRYPT_SUCCESS);

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    int32_t id = (int32_t)algId;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &id, sizeof(id)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);
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
    CRYPT_EAL_KdfFreeCtx(copyCtx3);
}
/* END_CASE */

static int32_t TestKdfCopyCtxMemCheck(int32_t algId, Hex *key, Hex *label, Hex *seed, int isProvider)
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
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS,
        label->x, label->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS,
        seed->x, seed->len), CRYPT_SUCCESS);
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
void SDV_CRYPTO_HKDF_COPY_CTX_STUB_TC001(int algId, Hex *key, Hex *label, Hex *seed, int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_Init();
    FuncStubInfo tmpRpInfo = {0};
    ASSERT_TRUE(STUB_Replace(&tmpRpInfo, BSL_SAL_Malloc, STUB_BSL_SAL_Malloc) == 0);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(TestKdfCopyCtxMemCheck((int32_t)algId, key, label, seed, isProvider), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++)
    {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(TestKdfCopyCtxMemCheck((int32_t)algId, key, label, seed, isProvider), CRYPT_SUCCESS);
    }

EXIT:
    STUB_Reset(&tmpRpInfo);
}
/* END_CASE */