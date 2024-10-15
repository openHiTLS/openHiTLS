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

/**
 * @test   SDV_CRYPT_EAL_KDF_PBKDF2_API_TC001
 * @title  pbkdf2 api test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_Pbkdf2 and set the key length to 0, expected result 1.
 *    2.Call CRYPT_EAL_Pbkdf2 and set the key is null but keyLen not 0, expected result 2.
 *    3.Call CRYPT_EAL_Pbkdf2 and set the salt length to 0, expected result 3.
 *    4.Call CRYPT_EAL_Pbkdf2 and set the salt is null but saltLen not 0, expected result 4.
 *    5.Call CRYPT_EAL_Pbkdf2 and set number of iterations to 0, expected result 5.
 *    6.Call CRYPT_EAL_Pbkdf2 and output is null or outlen is 0, expected result 6.
 *    7.Call CRYPT_EAL_Pbkdf2 use all mac algorithm ID, expected result 7.
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

    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, NULL, 0, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, 0, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, NULL, keyLen, salt, saltLen, it, out, outLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, NULL, 0, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, salt, 0, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, NULL, saltLen, it, out, outLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, salt, saltLen, 0, out, outLen),
        CRYPT_PBKDF2_PARAM_ERROR);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, salt, saltLen, it, NULL, outLen),
        CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, salt, saltLen, it, out, 0),
        CRYPT_PBKDF2_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_MD5, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA1, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA224, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA256, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA384, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SHA512, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(CRYPT_MAC_HMAC_SM3, key, keyLen, salt, saltLen, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_HkdfIsValidAlgId(CRYPT_MAC_HMAC_MD5), true);
    ASSERT_EQ(CRYPT_EAL_Pbkdf2IsValidAlgId(CRYPT_MAC_HMAC_MD5), true);
    ASSERT_EQ(CRYPT_EAL_Kdftls12IsValidAlgId(CRYPT_MAC_HMAC_SHA256), true);
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_PBKDF2_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_Pbkdf2 get output, expected result 1.
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
    ASSERT_EQ(CRYPT_EAL_Pbkdf2(algId, key->x, key->len, salt->x, salt->len, it, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
}
/* END_CASE */
