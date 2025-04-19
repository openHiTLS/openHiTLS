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
#include "crypt_pbkdf2.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
/* END_HEADER */

#define DATA_LEN (16)


/**
 * @test   SDV_CRYPT_EAL_KDF_SCRYPT_API_TC001
 * @title  Scrypt interface test.
 * @precon nan
 * @brief
 *    1.Normal parameter test,the key and salt can be empty, expected result 1.
 *    2.Abnormal parameter test,about the restriction, see the function declaration, expected result 2.
 * @expect
 *    1.Return CRYPT_SUCCESS.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_SCRYPT_API_TC001(void)
{
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[DATA_LEN];
    uint32_t N = DATA_LEN;
    uint32_t r = DATA_LEN;
    uint32_t p = DATA_LEN;
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT);
    ASSERT_TRUE(ctx != NULL);

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt, saltLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    N = 0;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SCRYPT_PARAM_ERROR);

    N = 3;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SCRYPT_PARAM_ERROR);

    N = 6;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SCRYPT_PARAM_ERROR);

    N = 65538;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SCRYPT_PARAM_ERROR);

    N = 4;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    N = DATA_LEN;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);

    r = 0;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SCRYPT_PARAM_ERROR);

    r = DATA_LEN;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    p = 0;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SCRYPT_PARAM_ERROR);

    p = DATA_LEN;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_SCRYPT_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCtrl(ctx, 0, NULL, 0), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_SCRYPT_API_TC002
 * @title  Parameters N, r, and p of the CRYPT_EAL_Scrypt interface test.
 * @precon nan
 * @brief
*     1.Abnormal parameter test,about the restriction, see the function declaration, expected result 1.
 * @expect
 *    1.The results are as expected,See Note.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_SCRYPT_API_TC002(void)
{
    // Parameter limitation:
    // N < 2^(128 * r / 8)
    // p <= ((2^32-1) * 32) / (128 * r). Equivalent to r * p <= 2^30 - 1
    // p * 128 * r < UINT32_MAX
    // 32 * r * N * sizeof(uint32_t) < UINT32_MAX => N < ((UINT32_MAX / 128) / r)
    // UINT32_MAX 0xffffffffU  /* 4294967295U */
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[DATA_LEN];
    uint32_t N = DATA_LEN;
    uint32_t r = DATA_LEN;
    uint32_t p = DATA_LEN;
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT);
    ASSERT_TRUE(ctx != NULL);

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt, saltLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    // N is 2^16 = 65536, r is 1,Not satisfied N < 2^(128 * r / 8)
    N = 65536;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    r = 1;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // N is 2^15 = 32768, r is 1,satisfied N < 2^(128 * r / 8)
    N = 32768;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    r = 1;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    // r = 2^16 = 65536, N = 2^9 = 512, Not satisfied N < ((UINT32_MAX / 128) / r)
    N = 512;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    r = 65536;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    N = DATA_LEN;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);

    // r  is 2^16 = 65536, p is 2^16 = 65536, Not satisfied p <= ((2^32-1) * 32) / (128 * r)
    r = 65536;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    p = 65536;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^16 = 65536, p = 2^14 = 16384, Not satisfied r * p <= 2^30 - 1
    r = 65536;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    p = 16384;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^16 = 65536, p = 2^9 = 512, Not satisfied p * 128 * r < UINT32_MAX
    r = 65536;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    p = 512;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^8 = 256, p = 2^22 = 4194304, Not satisfied r * p <= 2^30 - 1
    r = 256;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    p = 4194304;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^4 = 16, p = 2^26 = 67108864, Not satisfied r * p <= 2^30 - 1
    r = 16;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    p = 67108864;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^4 = 16, p = 2^21 = 2097152, Not satisfied p * 128 * r < UINT32_MAX
    r = 16;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    p = 2097152;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_SCRYPT_FUN_TC001
 * @title  Scrypt vector test.
 * @precon nan
 * @brief
 *    1.Calculate the output using the given parameters, expected result 1.
 *    2.Compare the calculated result with the standard value, expected result 2.
 * @expect
 *    1.Calculation succeeded..
 *    2.The results are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_SCRYPT_FUN_TC001(Hex *key, Hex *salt, int N, int r, int p, Hex *result)
{
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT);
    ASSERT_TRUE(ctx != NULL);
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
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
 * @test   SDV_CRYPTO_SCRYPT_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SCRYPT_DEFAULT_PROVIDER_FUNC_TC001(Hex *key, Hex *salt, int N, int r, int p, Hex *result)
{
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
     CRYPT_EAL_KdfCTX *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_SCRYPT, "provider=default");
#else
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_SCRYPT);
#endif
    ASSERT_TRUE(ctx != NULL);

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_N, BSL_PARAM_TYPE_UINT32,
        &N, sizeof(N)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_R, BSL_PARAM_TYPE_UINT32,
        &r, sizeof(r)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_P, BSL_PARAM_TYPE_UINT32,
        &p, sizeof(p)), CRYPT_SUCCESS);
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
