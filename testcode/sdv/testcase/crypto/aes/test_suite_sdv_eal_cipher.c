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
#include "stub_utils.h"

#define DATA_LEN 16
#define DATA_MAX_LEN 1024
#define MAX_OUTPUT 50000

/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

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

/* BEGIN_CASE */
void SDV_CRYPTO_CIPHER_COPY_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctxA = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxA != NULL);

    CRYPT_EAL_CipherCtx *ctxB = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxB != NULL);

    CRYPT_EAL_CipherCtx ctxC = { 0 };

    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    // Copy failed because ctxC lacks a method.
    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    CRYPT_EAL_CipherCtx *ctxD = CRYPT_EAL_CipherDupCtx(NULL);
    ASSERT_TRUE(ctxD == NULL);
    ctxD = CRYPT_EAL_CipherDupCtx(&ctxC);
    ASSERT_TRUE(ctxD == NULL);
    ctxD = CRYPT_EAL_CipherDupCtx(ctxA);
    ASSERT_TRUE(ctxD != NULL);

    // A directly created context can also be used as the destination for copying.
    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.method.freeCtx(ctxC.ctx);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxA);
    CRYPT_EAL_CipherFreeCtx(ctxB);
    CRYPT_EAL_CipherFreeCtx(ctxD);
}
/* END_CASE */

static int32_t TestCipherUpdate(CRYPT_EAL_CipherCtx *ctx, uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    uint32_t tmpLen = *outLen;
    int32_t ret = CRYPT_SUCCESS;
    uint32_t totalLen = 0;
    if (inLen > 0) {
        ret = CRYPT_EAL_CipherUpdate(ctx, in, inLen, out, &tmpLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        totalLen = tmpLen;
    }

    // Some algorithms do not support final.
    if (ctx->id != CRYPT_CIPHER_AES128_CCM && ctx->id != CRYPT_CIPHER_AES192_CCM &&
        ctx->id != CRYPT_CIPHER_AES256_CCM && ctx->id != CRYPT_CIPHER_AES128_GCM &&
        ctx->id != CRYPT_CIPHER_AES192_GCM && ctx->id != CRYPT_CIPHER_AES256_GCM &&
        ctx->id != CRYPT_CIPHER_SM4_CCM && ctx->id != CRYPT_CIPHER_SM4_GCM &&
        ctx->id != CRYPT_CIPHER_CHACHA20_POLY1305) {
        tmpLen = *outLen - totalLen;
        ret = CRYPT_EAL_CipherFinal(ctx, out + totalLen, &tmpLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        totalLen += tmpLen;
    }
    *outLen = totalLen;
EXIT:
    return ret;
}

static int32_t TestCipherSetParam(CRYPT_EAL_CipherCtx *ctx, Hex *msg, Hex *tag, Hex *aad, int padType)
{
    int32_t algId = ctx->id;
    int32_t ret = CRYPT_SUCCESS;
    if (tag->len > 0 && algId != CRYPT_CIPHER_CHACHA20_POLY1305) {
        uint32_t tagLen = tag->len;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }
    if (algId == CRYPT_CIPHER_AES128_CCM || algId == CRYPT_CIPHER_AES192_CCM || algId == CRYPT_CIPHER_AES256_CCM ||
        algId == CRYPT_CIPHER_SM4_CCM) {
        uint64_t inLen = msg->len;
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &inLen, sizeof(inLen));
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }
    if (aad->len > 0) {
        ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }
    if (padType > 0) {
        ret = CRYPT_EAL_CipherSetPadding(ctx, (int32_t)padType);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
EXIT:
    return ret;
}

static void TestForCopyCtx(int32_t algId, int isProvider)
{
    TestMemInit();
    uint8_t key[DATA_MAX_LEN];
    uint8_t iv[DATA_MAX_LEN];
    uint32_t keyLen = 0;
    uint32_t ivLen = 0;
    CRYPT_EAL_CipherCtx ctxA = {0};
    CRYPT_EAL_CipherCtx *ctxB = NULL;
    CRYPT_EAL_CipherCtx *ctxC = NULL;

    ASSERT_EQ(CRYPT_EAL_CipherGetInfo(algId, CRYPT_INFO_KEY_LEN, &keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherGetInfo(algId, CRYPT_INFO_IV_LEN, &ivLen), CRYPT_SUCCESS);

    CRYPT_EAL_CipherCtx *srcCtx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(srcCtx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);

    /* Set key and IV in srcCtx, then copy it to ctxA and ctxB. */
    ctxB = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxB != NULL);

    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(&ctxA, srcCtx), CRYPT_SUCCESS);
    // Create ctxC from srcCtx.
    ctxC = CRYPT_EAL_CipherDupCtx(srcCtx);
    ASSERT_TRUE(ctxC != NULL);

    CRYPT_EAL_CipherDeinit(srcCtx);
    ASSERT_EQ(CRYPT_EAL_CipherInit(srcCtx, key, keyLen, iv, ivLen, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(ctxB, srcCtx), CRYPT_SUCCESS);

    uint32_t encLen = DATA_MAX_LEN;
    uint32_t dupEncLen = DATA_MAX_LEN;
    uint32_t decLen = DATA_MAX_LEN;
    uint8_t inTmp[DATA_MAX_LEN - 16];
    uint8_t encTmp[DATA_MAX_LEN];
    uint8_t dupEncTmp[DATA_MAX_LEN];
    uint8_t decTmp[DATA_MAX_LEN];
    /* Use ctxA for encryption and ctxB for decryption,
     Test that the copied contexts function identically to the source context. */
    ASSERT_EQ(TestCipherUpdate(&ctxA, inTmp, sizeof(inTmp), encTmp, &encLen), CRYPT_SUCCESS);
    ASSERT_EQ(TestCipherUpdate(ctxB, encTmp, encLen, decTmp, &decLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare:", inTmp, sizeof(inTmp), decTmp, decLen);

    /* Use ctxC for encryption*/
    ASSERT_EQ(TestCipherUpdate(ctxC, inTmp, sizeof(inTmp), dupEncTmp, &dupEncLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare:", dupEncTmp, dupEncLen, encTmp, encLen);

EXIT:
    ctxA.method.freeCtx(ctxA.ctx);
    CRYPT_EAL_CipherFreeCtx(ctxB);
    CRYPT_EAL_CipherFreeCtx(ctxC);
    CRYPT_EAL_CipherFreeCtx(srcCtx);
}

static const int32_t g_algidList[] = {
    CRYPT_CIPHER_AES128_CBC, CRYPT_CIPHER_AES192_CBC, CRYPT_CIPHER_AES256_CBC,
    CRYPT_CIPHER_AES128_CTR, CRYPT_CIPHER_AES192_CTR, CRYPT_CIPHER_AES256_CTR,
    CRYPT_CIPHER_AES128_ECB, CRYPT_CIPHER_AES192_ECB, CRYPT_CIPHER_AES256_ECB,
    CRYPT_CIPHER_AES128_XTS, CRYPT_CIPHER_AES256_XTS,
    CRYPT_CIPHER_AES128_CCM, CRYPT_CIPHER_AES192_CCM, CRYPT_CIPHER_AES256_CCM,
    CRYPT_CIPHER_AES128_GCM, CRYPT_CIPHER_AES192_GCM, CRYPT_CIPHER_AES256_GCM,
    CRYPT_CIPHER_AES128_CFB, CRYPT_CIPHER_AES192_CFB, CRYPT_CIPHER_AES256_CFB,
    CRYPT_CIPHER_AES128_OFB, CRYPT_CIPHER_AES192_OFB, CRYPT_CIPHER_AES256_OFB,

    CRYPT_CIPHER_AES128_WRAP_NOPAD, CRYPT_CIPHER_AES192_WRAP_NOPAD, CRYPT_CIPHER_AES256_WRAP_NOPAD,
    CRYPT_CIPHER_AES128_WRAP_PAD, CRYPT_CIPHER_AES192_WRAP_PAD, CRYPT_CIPHER_AES256_WRAP_PAD,

    CRYPT_CIPHER_SM4_XTS, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CTR,
    CRYPT_CIPHER_SM4_HCTR, CRYPT_CIPHER_SM4_GCM, CRYPT_CIPHER_SM4_CFB, CRYPT_CIPHER_SM4_OFB,
    CRYPT_CIPHER_SM4_CCM,

    CRYPT_CIPHER_CHACHA20_POLY1305
};

/* BEGIN_CASE */
void SDV_CRYPTO_CIPHER_COPY_CTX_FUNC_TC001(int isProvider)
{
    for (size_t i = 0; i < sizeof(g_algidList) / g_algidList[0]; i++) {
        TestForCopyCtx(g_algidList[i], isProvider);
    }
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_CIPHER_COPY_CTX_FUNC_TC002(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, Hex *tag, Hex *aad,
    int isProvider, int padType)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint8_t encTmp[DATA_MAX_LEN];
    uint8_t decTmp[DATA_MAX_LEN];
    uint32_t encLen = DATA_MAX_LEN;
    uint32_t decLen = DATA_MAX_LEN;
    uint8_t tagResult[32];

    CRYPT_EAL_CipherCtx *ctxA = NULL;
    CRYPT_EAL_CipherCtx *ctxB = NULL;
    CRYPT_EAL_CipherCtx *ctxC = NULL;
    CRYPT_EAL_CipherCtx *srcCtx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(srcCtx != NULL);
    ctxA = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxA != NULL);
    ctxB = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxB != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(srcCtx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(TestCipherSetParam(srcCtx, in, tag, aad, padType), CRYPT_SUCCESS);

    // Use the copied context to encryption and then decryption.
    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(ctxA, srcCtx), CRYPT_SUCCESS);
    ASSERT_EQ(TestCipherUpdate(ctxA, in->x, in->len, encTmp, &encLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare1:", encTmp, encLen, out->x, out->len);
    if (tag->len > 0) {
        ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctxA, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len), CRYPT_SUCCESS);
        ASSERT_COMPARE("tag1:", tagResult, tag->len, tag->x, tag->len);
    }

    CRYPT_EAL_CipherDeinit(ctxA);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctxA, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(TestCipherSetParam(ctxA, in, tag, aad, padType), CRYPT_SUCCESS);
    ASSERT_EQ(TestCipherUpdate(ctxA, encTmp, encLen, decTmp, &decLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare2:", decTmp, decLen, in->x, in->len);
    if (tag->len > 0) {
        ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctxA, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len), CRYPT_SUCCESS);
        ASSERT_COMPARE("tag2:", tagResult, tag->len, tag->x, tag->len);
    }
    CRYPT_EAL_CipherFreeCtx(ctxA);
    ctxA = NULL;

    // Create a new ctxC from srcCtx, use ctxC for encryption, and verify functional correctness.
    ctxC = CRYPT_EAL_CipherDupCtx(srcCtx);
    ASSERT_TRUE(ctxC != NULL);
    ASSERT_EQ(TestCipherUpdate(ctxC, in->x, in->len, encTmp, &encLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare3:", encTmp, encLen, out->x, out->len);
    if (tag->len > 0) {
        ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctxC, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len), CRYPT_SUCCESS);
        ASSERT_COMPARE("tag3:", tagResult, tag->len, tag->x, tag->len);
    }

    uint32_t totalLen = DATA_MAX_LEN;
    uint32_t blockLen = (in->len >= 16) ? 16 : in->len;
    if ((algId >= CRYPT_CIPHER_AES128_WRAP_NOPAD && algId <= CRYPT_CIPHER_AES256_WRAP_PAD) ||
        algId == CRYPT_CIPHER_SM4_XTS) {
        blockLen = in->len;
    }
    // After encrypt a portion of data, copy the ctx and encrypt of the remaining data, then compare the results.
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(srcCtx, in->x, blockLen, encTmp, &totalLen), CRYPT_SUCCESS);
    encLen = DATA_MAX_LEN - totalLen;
    ASSERT_EQ(CRYPT_EAL_CipherCopyCtx(ctxB, srcCtx), CRYPT_SUCCESS);
    ASSERT_EQ(TestCipherUpdate(ctxB, in->x + blockLen, in->len - blockLen, encTmp + totalLen, &encLen), CRYPT_SUCCESS);
    totalLen += encLen;
    ASSERT_COMPARE("compare4:", encTmp, totalLen, out->x, out->len);
    if (tag->len > 0) {
        ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctxB, CRYPT_CTRL_GET_TAG, (uint8_t *)tagResult, tag->len), CRYPT_SUCCESS);
        ASSERT_COMPARE("tag4:", tagResult, tag->len, tag->x, tag->len);
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxA);
    CRYPT_EAL_CipherFreeCtx(srcCtx);
    CRYPT_EAL_CipherFreeCtx(ctxB);
    CRYPT_EAL_CipherFreeCtx(ctxC);
}
/* END_CASE */

static int32_t TestCipherCopyCtxMemCheck(int32_t algId, int isProvider)
{
    uint8_t key[DATA_MAX_LEN];
    uint8_t iv[DATA_MAX_LEN];
    uint32_t keyLen = 0;
    uint32_t ivLen = 0;
    CRYPT_EAL_CipherCtx *ctxA = NULL;
    CRYPT_EAL_CipherCtx *ctxB = NULL;

    ASSERT_EQ(CRYPT_EAL_CipherGetInfo(algId, CRYPT_INFO_KEY_LEN, &keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherGetInfo(algId, CRYPT_INFO_IV_LEN, &ivLen), CRYPT_SUCCESS);

    CRYPT_EAL_CipherCtx *srcCtx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    /* Set key and IV in srcCtx */
    int32_t ret = CRYPT_EAL_CipherInit(srcCtx, key, keyLen, iv, ivLen, true);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    
    ctxA = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ret = CRYPT_EAL_CipherCopyCtx(ctxA, srcCtx);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ctxB = CRYPT_EAL_CipherDupCtx(srcCtx);
    if (ctxB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxA);
    CRYPT_EAL_CipherFreeCtx(ctxB);
    CRYPT_EAL_CipherFreeCtx(srcCtx);
    return ret;
}

/**
 * @test SDV_CRYPTO_CIPHER_COPY_CTX_STUB_TC001
 * title 1. Test the cipher copy context with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CIPHER_COPY_CTX_STUB_TC001(int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    for (uint32_t i = 0; i < sizeof(g_algidList) / g_algidList[0]; i++) {
        STUB_EnableMallocFail(false);
        STUB_ResetMallocCount();
        ASSERT_EQ(TestCipherCopyCtxMemCheck(g_algidList[i], isProvider), CRYPT_SUCCESS);
        totalMallocCount = STUB_GetMallocCallCount();

        STUB_EnableMallocFail(true);
        for (uint32_t j = 0; j < totalMallocCount; j++)
        {
            STUB_ResetMallocCount();
            STUB_SetMallocFailIndex(j);
            ASSERT_NE(TestCipherCopyCtxMemCheck(g_algidList[i], isProvider), CRYPT_SUCCESS);
        }
    }
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */