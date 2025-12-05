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

#include <stdlib.h>
#include <string.h>

#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_modes_gcm.h"
#include "crypt_local_types.h"
#include "crypt_aes.h"
#include "crypt_eal_cipher.h"
#include "eal_cipher_local.h"

#define DATA_LEN 16
#define DATA_MAX_LEN 1024
#define MAX_OUTPUT 50000

/* END_HEADER */


/**
 * @test  SDV_CRYPTO_AES_MULTI_UPDATE_FUNC_TC001
 * @title  Impact of two updates on the encryption and decryption functions
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the EAL interface to encrypt a piece of data twice, and then verify the encryption result and tag. Expected result 1 is obtained.
 *    2.Call the EAL interface to decrypt a piece of data twice, and check the decryption result and tag. Expected result 2 is obtained.
 * @expect
 *    1.The encryption result and tag value are the same as expected, the verification is successful.
 *    2.The decryption result and tag value are the same as expected, the verification is successful.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_MULTI_UPDATE_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *aad, Hex *pt1, Hex *pt2, Hex *ct, Hex *tag)
{
    if (IsCipherAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint32_t tagLen = tag->len;
    uint8_t result[DATA_MAX_LEN];
    uint8_t tagResult[DATA_LEN];
    uint32_t outLen = DATA_MAX_LEN;
    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt1->x, pt1->len, result, &outLen) == CRYPT_SUCCESS);
    outLen = DATA_MAX_LEN - pt1->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt2->x, pt2->len, result + pt1->len, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len) == CRYPT_SUCCESS);
    ASSERT_COMPARE("enc result", (uint8_t *)result, pt1->len + pt2->len, ct->x, ct->len);
    ASSERT_COMPARE("enc tagResult", (uint8_t *)tagResult, tag->len, tag->x, tag->len);

    CRYPT_EAL_CipherFreeCtx(ctx);

    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);

    (void)memset_s(result, sizeof(result), 0, sizeof(result));
    (void)memset_s(tagResult, sizeof(tagResult), 0, sizeof(tagResult));
    outLen = DATA_MAX_LEN;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, ct->x, pt1->len, result, &outLen) == CRYPT_SUCCESS);
    outLen = DATA_MAX_LEN - pt1->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, ct->x + pt1->len, pt2->len, result + pt1->len, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len) == CRYPT_SUCCESS);

    ASSERT_COMPARE("dec result1", (uint8_t *)result, pt1->len, pt1->x, pt1->len);
    ASSERT_COMPARE("dec result2", (uint8_t *)result + pt1->len, pt2->len, pt2->x, pt2->len);
    ASSERT_COMPARE("dec tagResult", (uint8_t *)tagResult, tag->len, tag->x, tag->len);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_MULTI_UPDATE_FUNC_TC002
 * @title  Impact of three updates on the encryption function
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the EAL interface to encrypt a piece of data for three times, and then verify the encryption result and tag. Expected result 1 is obtained.
 *    2.Call the EAL interface to decrypt a piece of data for three times, and then verify the decryption result and tag. Expected result 2 is obtained.
 * @expect
 *    1.The encryption result and tag value are the same as expected, the verification is successful.
 *    2.The decryption result and tag value are the same as expected, the verification is successful.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_MULTI_UPDATE_FUNC_TC002(int isProvider, int algId, Hex *key, Hex *iv, Hex *aad, Hex *pt1,
    Hex *pt2, Hex *pt3, Hex *ct, Hex *tag)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    uint32_t tagLen = tag->len;
    uint8_t result[DATA_MAX_LEN];
    uint8_t tagResult[tagLen];
    uint32_t outLen = DATA_MAX_LEN;
    uint64_t count;
    ctx = (isProvider == 0) ? CRYPT_EAL_CipherNewCtx(algId) :
        CRYPT_EAL_ProviderCipherNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    if (algId == CRYPT_CIPHER_AES128_CCM || algId == CRYPT_CIPHER_AES192_CCM || algId == CRYPT_CIPHER_AES256_CCM) {
        count = pt1->len + pt2->len + pt3->len;
        ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt1->x, pt1->len, result, &outLen) == CRYPT_SUCCESS);
    outLen = DATA_MAX_LEN - pt1->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt2->x, pt2->len, result + pt1->len, &outLen) == CRYPT_SUCCESS);
    outLen = DATA_MAX_LEN - pt1->len - pt2->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt3->x, pt3->len, result + pt1->len + pt2->len, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len) == CRYPT_SUCCESS);
    ASSERT_COMPARE("enc result", (uint8_t *)result, pt1->len + pt2->len + pt3->len, ct->x, ct->len);
    ASSERT_COMPARE("enc tagResult", (uint8_t *)tagResult, tag->len, tag->x, tag->len);

    (void)memset_s(result, sizeof(result), 0, sizeof(result));
    (void)memset_s(tagResult, sizeof(tagResult), 0, sizeof(tagResult));
    outLen = DATA_MAX_LEN;
    tagLen = tag->len;
    // decrypt
    decCtx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(decCtx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    if (algId == CRYPT_CIPHER_AES128_CCM || algId == CRYPT_CIPHER_AES192_CCM || algId == CRYPT_CIPHER_AES256_CCM) {
        count = ct->len;
        ASSERT_TRUE(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(decCtx, ct->x, pt1->len, result, &outLen) == CRYPT_SUCCESS);
    outLen = DATA_MAX_LEN - pt1->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(decCtx, ct->x + pt1->len, pt2->len, result + pt1->len, &outLen) == CRYPT_SUCCESS);
    outLen = DATA_MAX_LEN - pt1->len - pt2->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(decCtx, ct->x + pt1->len + pt2->len, pt3->len, result + pt1->len + pt2->len, &outLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(result, pt1->x, pt1->len) == 0);
    ASSERT_TRUE(memcmp(result + pt1->len, pt2->x, pt2->len) == 0);
    ASSERT_TRUE(memcmp(result + pt1->len + pt2->len, pt3->x, pt3->len) == 0);
    ASSERT_TRUE(memcmp(tagResult, tag->x,  tag->len) == 0);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_GETINFO_API_TC001
 * @title  CRYPT_EAL_CipherGetInfo Checking the Algorithm Grouping Mode Function Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the GetInfo interface with a correct ID, set type to CRYPT_INFO_IS_AEAD, and set infoStatus to NULL. Expected result 1 is obtained.
 *    2.Call the GetInfo interface with a wrong ID, set type to CRYPT_INFO_IS_AEAD, and set infoStatus to not NULL. Expected result 2 is obtained.
 *    3.Call the GetInfo interface with ID CRYPT_CIPHER_AES128_CCM, set type to CRYPT_INFO_MAX, and set infoStatus to not NULL. Expected result 3 is obtained.
 *    4.Call the GetInfo interface with ID CRYPT_CIPHER_AES128_CCM, set type to CRYPT_INFO_IS_AEAD, and set infoStatus to not NULL. Expected result 4 is obtained.
 *    5.Call the GetInfo interface with ID CRYPT_CIPHER_AES128_CFB, set type to CRYPT_INFO_IS_AEAD, and set infoStatus to not NULL. Expected result 5 is obtained.
 *    6.Call the GetInfo interface with ID CRYPT_CIPHER_AES128_CCM, set type to CRYPT_INFO_IS_STREAM, and set infoStatus to not NULL. Expected result 6 is obtained.
 *    7.Call the GetInfo interface with ID CRYPT_CIPHER_SM4_CBC, set type to CRYPT_INFO_IS_STREAM, and set infoStatus to not NULL. Expected result 7 is obtained.
 *    8.Call the GetInfo interface with ID CRYPT_CIPHER_AES128_CBC, set type to CRYPT_INFO_IV_LEN. Expected result 8 is obtained.
 *    9.Call the GetInfo interface with ID CRYPT_CIPHER_AES192_CBC, set type to CRYPT_INFO_KEY_LEN. Expected result 9 is obtained.
 * @expect
 *    1.Failed. Return CRYPT_INVALID_ARG.
 *    2.Failed. Return CRYPT_ERR_ALGID.
 *    3.Failed. Return CRYPT_EAL_INTO_TYPE_NOT_SUPPORT.
 *    4.Success. Return CRYPT_SUCCESS, infoStatus is 0.
 *    5.Success. Return CRYPT_SUCCESS, infoStatus is 1.
 *    6.Success. Return CRYPT_SUCCESS, infoStatus is 1.
 *    7.Success. Return CRYPT_SUCCESS, infoStatus is 0.
 *    8.Success. Return CRYPT_SUCCESS, ivLen is 16.
 *    9.Success. Return CRYPT_SUCCESS, keyLen is 24.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_GETINFO_API_TC001(void)
{
    TestMemInit();
    uint32_t infoStatus = 0;
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES128_CCM, CRYPT_INFO_IS_AEAD, NULL) == CRYPT_INVALID_ARG);
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_MAX, CRYPT_INFO_IS_AEAD, &infoStatus) == CRYPT_ERR_ALGID);
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES128_CCM, CRYPT_INFO_MAX,
        &infoStatus) == CRYPT_EAL_INTO_TYPE_NOT_SUPPORT);
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES128_CCM, CRYPT_INFO_IS_AEAD, &infoStatus) == CRYPT_SUCCESS);
    ASSERT_TRUE(infoStatus == 1);
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES128_CFB, CRYPT_INFO_IS_AEAD, &infoStatus) == CRYPT_SUCCESS);
    ASSERT_TRUE(infoStatus == 0);

    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES128_CCM, CRYPT_INFO_IS_STREAM, &infoStatus) == CRYPT_SUCCESS);
    ASSERT_TRUE(infoStatus == 1);
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_SM4_CBC, CRYPT_INFO_IS_STREAM, &infoStatus) == CRYPT_SUCCESS);
    ASSERT_TRUE(infoStatus == 0);
    uint32_t ivLen = 0;
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES128_CBC, CRYPT_INFO_IV_LEN, &ivLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(ivLen == 16);
    uint32_t keyLen = 0;
    ASSERT_TRUE(CRYPT_EAL_CipherGetInfo(CRYPT_CIPHER_AES192_CBC, CRYPT_INFO_KEY_LEN, &keyLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(keyLen == 24);
EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_CIPHER_FUNC_TC001
* @spec  -
* @title  Testing the AES algorithm with multiple updates, setting different single-operation data lengths and
* output buffer sizes, verifying decryption correctness and ensuring no memory out-of-bounds access.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_CIPHER_FUNC_TC001(int padding, int algId, Hex *key, Hex *iv, int len1, int len2, int res)
{
    TestMemInit();
    int32_t ret;
    uint8_t testData[1025];  // The total length of data to be encrypted is 1025 bytes.
    uint8_t encData[1040];   // The encrypted data (with a maximum of 15 bytes padding) can be up to 1040 bytes.
    uint8_t decData[1040];
    uint32_t inLen = sizeof(testData);
    uint32_t encLen = sizeof(encData);
    uint32_t tmplen = 0;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", 0);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, 1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctx, padding);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, testData, inLen, encData, &encLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    tmplen = sizeof(encData) - encLen;
    ret = CRYPT_EAL_CipherFinal(ctx, encData + encLen, &tmplen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    encLen += tmplen;

    CRYPT_EAL_CipherDeinit(ctx);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctx, padding);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    tmplen = len1;
    ret = CRYPT_EAL_CipherUpdate(ctx, encData, len1, decData, &tmplen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    totalLen = tmplen;

    tmplen = len2;
    ret = CRYPT_EAL_CipherUpdate(ctx, encData + len1, len2, decData + totalLen, &tmplen);
    ASSERT_EQ(ret, res);
    if (ret == CRYPT_SUCCESS) {  // Decryption has already failed, No further decryption needed.
        totalLen += tmplen;
        tmplen = encLen - len1 - len2;
        ret = CRYPT_EAL_CipherUpdate(ctx, encData + len1 + len2, tmplen, decData + totalLen, &tmplen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        totalLen += tmplen;

        tmplen = sizeof(testData) - totalLen;  // tmplen is exactly the remaining data length.
        ret = CRYPT_EAL_CipherFinal(ctx, decData + totalLen, &tmplen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_TRUE(memcmp(testData, decData, sizeof(testData)) == 0);
    }
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */
