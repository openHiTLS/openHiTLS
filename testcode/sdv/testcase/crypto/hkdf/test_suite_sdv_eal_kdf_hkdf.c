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
 * @title  pbkdf2 api test.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_Hkdf and set the key length to 0, expected result 1.
 *    2.Call CRYPT_EAL_Hkdf and set the key is null but keyLen not 0, expected result 2.
 *    3.Call CRYPT_EAL_Hkdf and set the salt length to 0, expected result 3.
 *    4.Call CRYPT_EAL_Hkdf and set the salt is null but saltLen not 0, expected result 4.
 *    5.Call CRYPT_EAL_Hkdf and set the info length to 0, expected result 5.
 *    6.Call CRYPT_EAL_Hkdf and set the info is null but infoLen not 0, expected result 6.
 *    7.Call CRYPT_EAL_Hkdf and output is null or outlen is 0, expected result 7.
 *    8.Call CRYPT_EAL_Hkdf length of the derived key exceeds the maximum, expected result 8.
 *    9.Call CRYPT_EAL_Hkdf using an incorrect id, expected result 9.
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

    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, NULL, 0, salt, saltLen, info, infoLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, 0, salt, saltLen, info, infoLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, NULL, keyLen, salt, saltLen, info, infoLen, out, outLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, NULL, 0, info, infoLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, 0, info, infoLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, NULL, saltLen, info, infoLen, out, outLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, NULL, 0, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, info, 0, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, NULL, infoLen, out, outLen), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, info, infoLen, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, info, infoLen, out, 0), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, info, infoLen, out, outLen), CRYPT_SUCCESS);

    outLen = GetMaxKeyLen(algId) + 1;
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key, keyLen, salt, saltLen, info, infoLen, out, outLen),
        CRYPT_HKDF_DKLEN_OVERFLOW);
    outLen = DATA_LEN;
    ASSERT_EQ(CRYPT_EAL_Hkdf(CRYPT_MAC_MAX, key, keyLen, salt, saltLen, info, infoLen, out, outLen),
        CRYPT_EAL_ERR_ALGID);
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_Hkdf get output, expected result 1.
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
    ASSERT_EQ(CRYPT_EAL_Hkdf(algId, key->x, key->len, salt->x, salt->len, info->x, info->len, out, outLen),
        CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
}
/* END_CASE */
