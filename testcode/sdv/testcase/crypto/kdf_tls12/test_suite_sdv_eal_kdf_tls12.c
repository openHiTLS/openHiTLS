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

/**
 * @test   SDV_CRYPT_EAL_KDF_TLS12_API_TC001
 * @title  CRYPT_EAL_KdfTls12 interface test.
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
    ASSERT_EQ(CRYPT_EAL_KdfTls12(CRYPT_MAC_HMAC_SHA224, key, keyLen, label, labelLen, seed, seedLen, out, outLen),
        CRYPT_EAL_ERR_ALGID);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, labelLen, seed, seedLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, NULL, 0, label, labelLen, seed, seedLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, 0, label, labelLen, seed, seedLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, NULL, keyLen, label, labelLen, seed, seedLen, out, outLen),
        CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, NULL, 0, seed, seedLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, 0, seed, seedLen, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, NULL, labelLen, seed, seedLen, out, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, labelLen, NULL, 0, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, labelLen, seed, 0, out, outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, labelLen, NULL, seedLen, out, outLen),
        CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, labelLen, seed, seedLen, NULL, outLen),
        CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key, keyLen, label, labelLen, seed, seedLen, out, 0), CRYPT_NULL_INPUT);
exit:
    return;
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_TLS12_FUN_TC001
 * @title  CRYPT_EAL_Scrypt vector test.
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
    ASSERT_EQ(CRYPT_EAL_KdfTls12(algId, key->x, key->len, label->x, label->len, seed->x, seed->len, out, outLen),
        CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
exit:
    if (out != NULL) {
        free(out);
    }
}
/* END_CASE */
