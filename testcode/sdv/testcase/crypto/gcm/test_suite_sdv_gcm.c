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
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "securec.h"
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_dsa.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_bn.h"
#include "crypt_util_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_cipher.h"
/* END_HEADER */

#define SUCCESS 0
#define ERROR (-1)

typedef struct {
    uint8_t *key;
    uint8_t *iv;
    uint8_t *aad;
    uint8_t *pt;
    uint8_t *ct;
    uint8_t *tag;
    uint32_t keyLen;
    uint32_t ivLen;
    uint32_t aadLen;
    uint32_t ptLen;
    uint32_t ctLen;
    uint32_t tagLen;
    int algId;
} ThreadParameter;

void MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint32_t outLen = threadParameter->ctLen;
    uint32_t tagLen = threadParameter->tagLen;
    uint8_t out[threadParameter->ctLen];
    uint8_t tag[threadParameter->tagLen];
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(threadParameter->algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, threadParameter->key, threadParameter->keyLen, threadParameter->iv,
        threadParameter->ivLen, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, threadParameter->aad, threadParameter->aadLen) ==
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, threadParameter->pt, threadParameter->ptLen, (uint8_t *)out, &outLen) ==
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)tag, tagLen) == CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare Ct", out, threadParameter->ctLen, threadParameter->ct, threadParameter->ctLen);
    ASSERT_COMPARE("Compare Enc Tag", tag, tagLen, threadParameter->tag, threadParameter->tagLen);

    CRYPT_EAL_CipherDeinit(ctx);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, threadParameter->key, threadParameter->keyLen, threadParameter->iv,
        threadParameter->ivLen, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, threadParameter->aad, threadParameter->aadLen) ==
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, threadParameter->ct, threadParameter->ctLen, (uint8_t *)out, &outLen) ==
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)tag, tagLen) == CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare Pt", out, threadParameter->ptLen, threadParameter->pt, threadParameter->ptLen);
    ASSERT_COMPARE("Compare Dec Tag", tag, tagLen, threadParameter->tag, threadParameter->tagLen);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}

/* BEGIN_CASE */
void SDV_CRYPTO_GCM_API_TC001(int id, int keyLen, int ivLen)
{
    uint8_t key[32] = { 0 }; // The maximum length of the key is 32 bytes.
    uint8_t iv[256] = { 0 }; // The maximum length of the iv is 256 bytes.
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, (uint8_t *)iv, ivLen, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, 0) != CRYPT_SUCCESS);
    // Repeat the settings.
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, ivLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_GCM_API_TC002(int id, int keyLen)
{
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t key[32] = { 0 }; // The maximum length of the key is 32 bytes.
    uint8_t iv[256] = { 0 }; // The maximum length of the iv is 256 bytes.
    TestMemInit();
    ASSERT_TRUE(CRYPT_EAL_CipherNewCtx(99) == NULL); // 99 Indicates an invalid algorithm ID.
    ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    // 256 indicates the IV length.
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, NULL, keyLen, (uint8_t *)iv, 256, true) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, 0, (uint8_t *)iv, 256, true) !=
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, NULL, 256, true) !=
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, (uint8_t *)iv, 0, true) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(NULL, (uint8_t *)iv, 256) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, NULL, 256) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(NULL, (uint8_t *)iv, 0) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_GCM_API_TC003(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 }; // The maximum length of the key is 32 bytes.
    uint8_t iv[256] = { 0 }; // The maximum length of the iv is 256 bytes.
    uint8_t data[256];
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, data, sizeof(data)) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_GCM_API_TC004(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };   // The maximum length of the key is 32 bytes.
    uint8_t iv[13] = { 0 };
    uint8_t data[256] = { 0 };
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, data, sizeof(data)) != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_GCM_API_TC005(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 }; // The maximum length of the key is 32 bytes.
    uint8_t iv[13] = { 0 };
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, 0), CRYPT_EAL_ERR_STATE);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_GCM_API_TC006(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };   // The maximum length of the key is 32 bytes.
    uint8_t iv[13] = { 0 };
    uint8_t data[256] = { 0 };
    uint8_t out[256] = { 0 };
    uint32_t outLen = sizeof(out);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), out, &outLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_GCM_FUNC_TC001
 * @title  Test on the same address in plaintext and ciphertext
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and set tag len. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 4 is obtained.
 *    5.Call the Update interface, ctx is not NULL, and encrypt data. Expected result 5 is obtained.
 *    6.Compare the ciphertext. Expected result 6 is obtained.
 *    7.Compare the tag. Expected result 7 is obtained.
 *    8.Call the Deinit interface and Call the Init interface. Expected result 8 is obtained.
 *    9.Call the Ctrl interface set tag len. Expected result 9 is obtained.
 *    10.Call the Ctrl interface set aad. Expected result 10 is obtained.
 *    11.Call the Update interface to decrypt data. Expected result 11 is obtained.
 *    12.Compare the plaintext. Expected result 12 is obtained.
 *    13.Compare the tag. Expected result 13 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Consistent with expected vector.
 *    7.Consistent with expected vector.
 *    8.Success, Return CRYPT_SUCCESS
 *    9.Success, Return CRYPT_SUCCESS
 *    10.Success, Return CRYPT_SUCCESS
 *    11.Success, Return CRYPT_SUCCESS
 *    12.Consistent with expected vector.
 *    13.Consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_GCM_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *ct, Hex *tag)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *outTag = NULL;
    uint8_t *out = NULL;
    uint32_t tagLen = tag->len;
    uint32_t outLen = ct->len;

    out = (uint8_t *)malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    outTag = (uint8_t *)malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(memcpy_s(out, outLen, pt->x, pt->len) == EOK);
    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, out, pt->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare Ct", out, ct->len, ct->x, ct->len);
    ASSERT_COMPARE("Compare Enc Tag", outTag, tagLen, tag->x, tag->len);

    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_TRUE(memcpy_s(out, outLen, ct->x, ct->len) == EOK);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, out, ct->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare Pt", out, pt->len, pt->x, pt->len);
    ASSERT_COMPARE("Compare Dec Tag", outTag, tagLen, tag->x, tag->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    free(out);
    free(outTag);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_GCM_FUNC_TC002
 * @title  Multi-thread Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Start three threads. Expected result 1 is obtained.
 *    2.Call the eal interface in the thread for encryption. Expected result 2 is obtained.
 *    3.Call the eal interface in the thread for decryption. Expected result 2 is obtained.
 * @expect
 *    1.Success.
 *    2.The encryption is successful. The ciphertext and tag are the same as the vector.
 *    3.The decryption is successful. The plaintext and tag are consistent with the vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_GCM_FUNC_TC002(int algId, Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *ct, Hex *tag)
{
    int ret;
    TestMemInit();
    const uint32_t threadNum = 3; // Number of threads.
    pthread_t thrd[threadNum];
    ThreadParameter arg[3] = {
        // 3 threads.
        {.key = key->x, .iv = iv->x, .aad = aad->x, .pt = pt->x, .ct = ct->x, .tag = tag->x,
         .keyLen = key->len, .ivLen = iv->len, .aadLen = aad->len,
         .ptLen = pt->len, .ctLen = ct->len, .tagLen = tag->len,
         .algId = algId},
        {.key = key->x, .iv = iv->x, .aad = aad->x, .pt = pt->x, .ct = ct->x, .tag = tag->x,
         .keyLen = key->len, .ivLen = iv->len, .aadLen = aad->len,
         .ptLen = pt->len, .ctLen = ct->len, .tagLen = tag->len,
         .algId = algId},
        {.key = key->x, .iv = iv->x, .aad = aad->x, .pt = pt->x, .ct = ct->x, .tag = tag->x,
         .keyLen = key->len, .ivLen = iv->len, .aadLen = aad->len,
         .ptLen = pt->len, .ctLen = ct->len, .tagLen = tag->len,
         .algId = algId},
    };
    for (uint32_t i = 0; i < threadNum; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)MultiThreadTest, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        pthread_join(thrd[i], NULL);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    return;
}
/* END_CASE */