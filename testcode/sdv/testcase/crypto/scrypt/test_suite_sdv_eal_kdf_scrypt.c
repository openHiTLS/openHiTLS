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

#define DATA_LEN (16)

/**
 * @test   SDV_CRYPT_EAL_KDF_SCRYPT_API_TC001
 * @title  CRYPT_EAL_Scrypt interface test.
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
    ASSERT_EQ(CRYPT_EAL_Scrypt(NULL, 0, salt, saltLen, N, r, p, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, 0, salt, saltLen, N, r, p, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Scrypt(NULL, keyLen, salt, saltLen, N, r, p, out, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, NULL, 0, N, r, p, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, 0, N, r, p, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, NULL, saltLen, N, r, p, out, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 0, r, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 3, r, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 4, r, p, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 6, r, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    // 65538 = 2^16 + 2
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 65538, r, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 0, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, r, 0, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, r, p, NULL, outLen), CRYPT_SCRYPT_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, r, p, out, 0), CRYPT_SCRYPT_PARAM_ERROR);
exit:
    return;
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
    uint32_t p = DATA_LEN;
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    // N is 2^16 = 65536, r is 1,Not satisfied N < 2^(128 * r / 8)
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 65536, 1, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // N is 2^15 = 32768, r is 1,satisfied N < 2^(128 * r / 8)
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 32768, 1, p, out, outLen), CRYPT_SUCCESS);

    // r = 2^16 = 65536, N = 2^9 = 512, Not satisfied N < ((UINT32_MAX / 128) / r)
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, 512, 65536, p, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r  is 2^16 = 65536, p is 2^16 = 65536, Not satisfied p <= ((2^32-1) * 32) / (128 * r)
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 65536, 65536, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^16 = 65536, p = 2^14 = 16384, Not satisfied r * p <= 2^30 - 1
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 65536, 16384, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^16 = 65536, p = 2^9 = 512, Not satisfied p * 128 * r < UINT32_MAX
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 65536, 512, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^8 = 256, p = 2^22 = 4194304, Not satisfied r * p <= 2^30 - 1
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 256, 4194304, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^4 = 16, p = 2^26 = 67108864, Not satisfied r * p <= 2^30 - 1
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 16, 67108864, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);

    // r = 2^4 = 16, p = 2^21 = 2097152, Not satisfied p * 128 * r < UINT32_MAX
    ASSERT_EQ(CRYPT_EAL_Scrypt(key, keyLen, salt, saltLen, N, 16, 2097152, out, outLen), CRYPT_SCRYPT_PARAM_ERROR);
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_SCRYPT_API_TC001
 * @title  CRYPT_EAL_Scrypt vector test.
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
    ASSERT_EQ(CRYPT_EAL_Scrypt(key->x, key->len, salt->x, salt->len, N, r, p, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
}
/* END_CASE */
