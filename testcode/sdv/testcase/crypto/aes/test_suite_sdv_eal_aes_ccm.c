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
#include "hitls_build.h"
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "bsl_sal.h"
#include "securec.h"

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
    int isProvider;
} ThreadParameter;

void MultiThreadTest(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    uint32_t outLen = threadParameter->ctLen;
    uint64_t msgLen = threadParameter->ctLen;
    uint32_t tagLen = threadParameter->tagLen;
    uint8_t out[threadParameter->ctLen];
    uint8_t tag[threadParameter->tagLen];
    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, threadParameter->algId, "provider=default",
        threadParameter->isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, threadParameter->key, threadParameter->keyLen, threadParameter->iv,
        threadParameter->ivLen, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)) == CRYPT_SUCCESS);
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
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)) == CRYPT_SUCCESS);
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

/* END_HEADER */

/**
 * @test  SDV_CRYPTO_AES_CCM_REINIT_API_TC001
 * @title  CRYPT_EAL_CipherReinit different iv length Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 6. Expected result 3 is obtained.
 *    4.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 7. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 13. Expected result 5 is obtained.
 *    6.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 14. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_REINIT_API_TC001(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[14] = { 0 };
    uint32_t ivLen = 0;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ivLen = 13;
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, keyLen, (uint8_t *)iv, ivLen, true) == CRYPT_SUCCESS);
    ivLen = 6;
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, ivLen) == CRYPT_MODES_IVLEN_ERROR);
    ivLen = 7;
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, ivLen) == CRYPT_SUCCESS);
    ivLen = 13;
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, ivLen) == CRYPT_SUCCESS);
    ivLen = 14;
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, ivLen) == CRYPT_MODES_IVLEN_ERROR);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_CTRL_API_TC001
 * @title  Relationship between CRYPT_CTRL_SET_MSGLEN and ivlen of the CRYPT_EAL_CipherCtrl interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and msg len is 0. Expected result 3 is obtained.
 *    4.Call the Update interface, ctx is not NULL, and plain len is 0. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 13. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and msg len is 0. Expected result 6 is obtained.
 *    7.Call the Update interface, ctx is not NULL, and plain len is 1. Expected result 7 is obtained.
 *    8.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 8. Expected result 8 is obtained.
 *    9.Call the Ctrl interface, ctx is not NULL, and msg len is 1 << ((15 - 8) * 8)) - 1. Expected result 9 is obtained.
 *    10.Call the Ctrl interface, ctx is not NULL, and msg len is 1 << ((15 - 8) * 8)). Expected result 10 is obtained.
 *    11.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 12. Expected result 11 is obtained.
 *    12.Call the Ctrl interface, ctx is not NULL, and msg len is 1 << ((15 - 12) * 8)) - 1. Expected result 12 is obtained.
 *    13.Call the Ctrl interface, ctx is not NULL, and msg len is 1 << ((15 - 12) * 8)). Expected result 13 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Success. Return CRYPT_SUCCESS.
 *    8.Success. Return CRYPT_SUCCESS.
 *    9.Success. Return CRYPT_SUCCESS.
 *    10.Failed. Return CRYPT_MODES_CTRL_MSGLEN_ERROR.
 *    11.Success. Return CRYPT_SUCCESS.
 *    12.Success. Return CRYPT_SUCCESS.
 *    13.Failed. CRYPT_MODES_CTRL_MSGLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC001(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[13] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t data[16] = { 0 };
    uint8_t out[16] = { 0 };
    uint32_t outLen = sizeof(out);
    uint64_t count = 0;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, 1, out, &outLen) == CRYPT_MODES_MSGLEN_OVERFLOW);
    ivLen = 8;
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    count = ((uint64_t)1 << ((15 - 8) * 8)) - 1;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    count = (uint64_t)1 << ((15 - 8) * 8);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) ==
        CRYPT_MODES_CTRL_MSGLEN_ERROR);
    ivLen = 12;
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    count = ((uint64_t)1 << ((15 - 12) * 8)) - 1;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    count = (uint64_t)1 << ((15 - 12) * 8);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) ==
        CRYPT_MODES_CTRL_MSGLEN_ERROR);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_UPDATE_API_TC001
 * @title  Relationship between the CRYPT_CTRL_SET_MSGLEN and the update length of the CRYPT_EAL_CipherCtrl interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and msg len is 10. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and msg len is 20. Expected result 4 is obtained.
 *    5.Call the Update interface, ctx is not NULL, and plain len is 20. Expected result 5 is obtained.
 *    6.Call the Update interface, ctx is not NULL, and plain len is 0. Expected result 6 is obtained.
 *    7.Call the Update interface, ctx is not NULL, and plain len is 10. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Failed. Return CRYPT_MODES_MSGLEN_OVERFLOW.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_UPDATE_API_TC001(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[13] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t data[20] = { 0 };
    uint32_t dataLen = 0;
    uint8_t out[20] = { 0 };
    uint32_t outLen = sizeof(out);
    uint64_t count = 0;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true) == CRYPT_SUCCESS);
    count = 10;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    count = 20;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    dataLen = 20;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, dataLen, out, &outLen) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    dataLen = 0;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, dataLen, out, &outLen) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    dataLen = 10;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, dataLen, out, &outLen) == CRYPT_MODES_MSGLEN_OVERFLOW);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_UPDATE_API_TC001
 * @title  Test after AAD is set for the CRYPT_EAL_CipherCtrl interface, msglen cannot be set.
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and set msglen. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 13. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and set msglen. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Failed. Return CRYPT_EAL_ERR_STATE.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC002(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[13] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t aad[16] = { 0 };
    uint64_t count = 0;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_CTRL_API_TC003
 * @title  CRYPT_EAL_CipherCtrl interface set aad Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 13. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Failed. Return CRYPT_EAL_ERR_STATE.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC003(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[13] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t aad[16] = { 0 };
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_CTRL_API_TC004
 * @title  CRYPT_EAL_CipherCtrl interface set tag len Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and tag len is 4. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and tag len is 6. Expected result 4 is obtained.
 *    5.Call the Ctrl interface, ctx is not NULL, and tag len is 8. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and tag len is 10. Expected result 6 is obtained.
 *    7.Call the Ctrl interface, ctx is not NULL, and tag len is 12. Expected result 7 is obtained.
 *    8.Call the Ctrl interface, ctx is not NULL, and tag len is 14. Expected result 8 is obtained.
 *    9.Call the Ctrl interface, ctx is not NULL, and tag len is 16. Expected result 9 is obtained.
 *    10.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 1. Expected result 10 is obtained.
 *    11.Call the Ctrl interface, ctx is not NULL, and tag len is 2. Expected result 11 is obtained.
 *    12.Call the Ctrl interface, ctx is not NULL, and tag len is 18. Expected result 12 is obtained.
 *    13.Call the Ctrl interface, ctx is not NULL, and tag len is 0. Expected result 13 is obtained.
 *    14.Call the Ctrl interface, ctx is not NULL, and tag len is 5. Expected result 14 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Success. Return CRYPT_SUCCESS.
 *    8.Success. Return CRYPT_SUCCESS.
 *    9.Success. Return CRYPT_SUCCESS.
 *    10.Success. Return CRYPT_SUCCESS.
 *    11.Failed. Return CRYPT_MODES_CTRL_TAGLEN_ERROR.
 *    12.Failed. Return CRYPT_MODES_CTRL_TAGLEN_ERROR.
 *    13.Failed. Return CRYPT_MODES_CTRL_TAGLEN_ERROR.
 *    14.Failed. Return CRYPT_MODES_CTRL_TAGLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC004(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[13] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint32_t tagLen;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true) == CRYPT_SUCCESS);
    tagLen = 4;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    tagLen = 6;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    tagLen = 8;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    tagLen = 10;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    tagLen = 12;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    tagLen = 14;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    tagLen = 16;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    tagLen = 2;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) ==
        CRYPT_MODES_CTRL_TAGLEN_ERROR);
    tagLen = 18;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) ==
        CRYPT_MODES_CTRL_TAGLEN_ERROR);
    tagLen = 0;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) ==
        CRYPT_MODES_CTRL_TAGLEN_ERROR);
    tagLen = 5;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) ==
        CRYPT_MODES_CTRL_TAGLEN_ERROR);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_CTRL_API_TC005
 * @title  CRYPT_EAL_CipherCtrl interface get tag Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and tag len is 8. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and msg len is 7. Expected result 4 is obtained.
 *    5.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 5 is obtained.
 *    6.Call the Update interface, ctx is not NULL, and plain len is 7. Expected result 6 is obtained.
 *    7.Call the Ctrl interface, ctx is not NULL, and get tag. Expected result 7 is obtained.
 *    8.Call the Ctrl interface, ctx is not NULL, and get tag. Expected result 8 is obtained.
 *    9.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 8. Expected result 9 is obtained.
 *    10.Call the Ctrl interface, ctx is not NULL, and get tag. Expected result 10 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Success. Return CRYPT_SUCCESS.
 *    8.Failed. Return CRYPT_EAL_ERR_STATE.
 *    9.Success. Return CRYPT_SUCCESS.
 *    10.Success. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC005(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[8] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t aad[10] = { 0 };
    uint8_t tag[16] = { 0 };
    uint8_t cmpTag[16] = { 0 };
    uint32_t tagLen;
    uint64_t count = 0;
    uint8_t data[20] = { 0 };
    uint8_t out[16] = { 0 };
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true) == CRYPT_SUCCESS);
    tagLen = 8;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    count = 7;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, 7, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, cmpTag, tagLen), CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_CTRL_API_TC006
 * @title  CRYPT_EAL_CipherCtrl interface get tag Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and msg len is 20. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and plain len is 20. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 8. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and msg len is 40. Expected result 6 is obtained.
 *    7.Call the Ctrl interface, ctx is not NULL, and plain len is 30. Expected result 7 is obtained.
 *    8.Call the Ctrl interface, ctx is not NULL, and tag len is 10. Expected result 8 is obtained.
 *    9.Call the Ctrl interface, ctx is not NULL, and get tag. Expected result 9 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Success. Return CRYPT_SUCCESS.
 *    8.Failed. Return CRYPT_EAL_ERR_STATE.
 *    9.Failed. Return CRYPT_MODES_MSGLEN_LEFT_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC006(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[8] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t tag[16] = { 0 };
    uint32_t tagLen = sizeof(tag);
    uint64_t count = 0;
    uint8_t data[40] = { 0 };
    uint32_t dataLen = 0;
    uint8_t out[40] = { 0 };
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true) == CRYPT_SUCCESS);
    count = 20;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    dataLen = 20;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, dataLen, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, ivLen) == CRYPT_SUCCESS);
    count = 40;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    dataLen = 30;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, dataLen, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    tagLen = 10;
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)), CRYPT_EAL_ERR_STATE);
    tagLen = 16;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) == CRYPT_MODES_MSGLEN_LEFT_ERROR);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_UPDATE_FUNC_TC001
 * @title AES CCM update encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface.
 *    3.Call the Reinit interface.
 *    4.Call the Ctrl interface, set msg len, tag len and aad.
 *    5.Call the Update interface, ctx is not NULL, and encrypt data. Expected result 1 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and get tag. Expected result 2 is obtained.
 *    7.Call the Init interface.
 *    8.Call the Reinit interface.
 *    9.Call the Ctrl interface, set msg len, tag len and aad.
 *    10.Call the Update interface, ctx is not NULL, and decrypt data. Expected result 3 is obtained.
 *    11.Call the Ctrl interface, ctx is not NULL, and get tag. Expected result 4 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_UPDATE_FUNC_TC001(int isProvider, int id, Hex *key, Hex *iv, Hex *aad,
    Hex *plaintext, Hex *ciphertext)
{
#ifndef HITLS_CRYPTO_CCM
    SKIP_TEST();
#endif
    TestMemInit();
    uint8_t iv0[8] = { 0 };
    uint8_t tag[16] = { 0 };
    uint32_t tagLen = sizeof(tag);
    uint64_t count;
    uint8_t out[1024] = { 0 };
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, id, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    // encrypt
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv0, sizeof(iv0), true), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len) == CRYPT_SUCCESS);
    count = plaintext->len;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    tagLen = ciphertext->len - plaintext->len;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, plaintext->x, plaintext->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out, ciphertext->x, outLen) == 0);
    ASSERT_TRUE(memcmp(tag, ciphertext->x + outLen, tagLen) == 0);

    // decrypt
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv0, sizeof(iv0), false), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len) == CRYPT_SUCCESS);
    count = plaintext->len;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)) == CRYPT_SUCCESS);
    tagLen = ciphertext->len - plaintext->len;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, ciphertext->x, plaintext->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out, plaintext->x, outLen) == 0);
    ASSERT_TRUE(memcmp(tag, ciphertext->x + outLen, tagLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test  SDV_CRYPTO_AES_CCM_CTRL_API_TC007
 * @title CRYPT_EAL_CipherCtrl state switching Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Reinit interface and then Call the Ctrl interface to get tag. Expected result 1 is obtained.
 *    2.Call the update interface and then Call the Ctrl interface to get tag. Expected result 2 is obtained.
 *    3.Call the Init interface and then Call the Ctrl interface to get tag. Expected result 3 is obtained.
 *    4.Call the Init and the Deinit interface, and then Call the Init interface. Expected result 4 is obtained.
 *    5.Call the Ctrl interface to get tag. Expected result 5 is obtained.
 *    6.Call the Init and the Deinit interface, and then Call the Ctrl interface to get tag. Expected result 6 is obtained.
 *    7.Call the Init interface and the Reinit interface, then Call the Deinit interface,
 *      and then Call the Ctrl interface to get tag. Expected result 7 is obtained.
 *    8.Call the Init interface, call the Ctrl interface set aad, set tag len. Expected result 8 is obtained.
 *    9.Call the Init interface, call the Ctrl interface set msglen, and call Update interface and Reinit interface,
 *      and then call the Ctrl interface get tag. Expected result 9 is obtained.
 *    10.Call the Init interface, call the Ctrl interface set msglen, call the update interface for encryption,
 *      and then call the Ctrl interface set msglen. Expected result 10 is obtained,
 *    11.Call the Ctrl interface get tag. Expected result 11 is obtained.
 *    12.Call the Init interface, call the Ctrl interface set msglen, call the update interface for encryption,
 *      and then call the Ctrl interface set aad. Expected result 12 is obtained,
 *    13.Call the Ctrl interface get tag. Expected result 13 is obtained.
 *    14.Call the Init interface, call the ctrl interface set msglen, call the update interface for encryption,
 *      and then call the Ctrl interface set taglen. Expected result 14 is obtained,
 *    15.Call the Ctrl interface get tag. Expected result 15 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Failed. Return CRYPT_EAL_ERR_STATE.
 *    5.Failed. Return CRYPT_EAL_ERR_STATE.
 *    6.Failed. Return CRYPT_EAL_ERR_STATE.
 *    7.Failed. Return CRYPT_EAL_ERR_STATE.
 *    9.Success. Return CRYPT_SUCCESS.
 *    10.Failed. Return CRYPT_EAL_ERR_STATE.
 *    11.Success. Return CRYPT_SUCCESS.
 *    12.Failed. Return CRYPT_EAL_ERR_STATE.
 *    13.Success. Return CRYPT_SUCCESS.
 *    14.Failed. Return CRYPT_EAL_ERR_STATE.
 *    15.Success. Return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_CTRL_API_TC007(int id, int keyLen)
{
    TestMemInit();
    uint8_t key[32] = { 0 };
    uint8_t iv[8] = { 0 };
    uint32_t ivLen = sizeof(iv);
    uint8_t tag[16] = { 0 };
    uint32_t tagLen = sizeof(tag);
    uint64_t count = 0;
    uint8_t data[40] = { 0 };
    uint8_t out[40] = { 0 };
    uint8_t aad[40] = { 0 };
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)), CRYPT_EAL_ERR_STATE);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &count, sizeof(count)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CCM_UPDATE_FUNC_TC002
 * @title  Test on the same address in plaintext and ciphertext
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and set tag len. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and set msg len. Expected result 4 is obtained.
 *    5.Call the Ctrl interface, ctx is not NULL, and set aad. Expected result 5 is obtained.
 *    6.Call the Update interface, ctx is not NULL, and encrypt data. Expected result 6 is obtained.
 *    7.Compare the ciphertext. Expected result 7 is obtained.
 *    8.Compare the tag. Expected result 8 is obtained.
 *    9.Call the Deinit interface and Call the Init interface. Expected result 9 is obtained.
 *    10.Call the Ctrl interface set tag len. Expected result 10 is obtained.
 *    11.Call the Ctrl interface set msg len. Expected result 11 is obtained.
 *    12.Call the Ctrl interface set aad. Expected result 12 is obtained.
 *    13.Call the Update interface to decrypt data. Expected result 13 is obtained.
 *    14.Compare the plaintext. Expected result 14 is obtained.
 *    15.Compare the tag. Expected result 15 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Consistent with expected vector.
 *    8.Consistent with expected vector.
 *    9.Success, Return CRYPT_SUCCESS
 *    10.Success, Return CRYPT_SUCCESS
 *    11.Success, Return CRYPT_SUCCESS
 *    12.Success, Return CRYPT_SUCCESS
 *    13.Success, Return CRYPT_SUCCESS
 *    14.Consistent with expected vector.
 *    15.Consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CCM_UPDATE_FUNC_TC002(int algId, Hex *key, Hex *iv, Hex *aad, Hex *pt,
    Hex *ct, Hex *tag)
{
#ifndef HITLS_CRYPTO_CCM
    SKIP_TEST();
#endif
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *outTag = NULL;
    uint8_t *out = NULL;
    uint32_t tagLen = tag->len;
    uint32_t outLen = pt->len;
    uint64_t msgLen = pt->len;
    out = (uint8_t *)malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    outTag = (uint8_t *)malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(memcpy_s(out, outLen, pt->x, pt->len) == EOK);
    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, out, pt->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_COMPARE("Compare Ct", out, ct->len, ct->x, ct->len);
    ASSERT_COMPARE("Compare Enc Tag", outTag, tagLen, tag->x, tag->len);

    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_TRUE(memcpy_s(out, outLen, ct->x, ct->len) == EOK);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)) == CRYPT_SUCCESS);
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
 * @test  SDV_CRYPTO_AES_CCM_MULTI_THREAD_FUNC_TC001
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
void SDV_CRYPTO_AES_CCM_MULTI_THREAD_FUNC_TC001(int isProvider, int algId, Hex *key, Hex *iv, Hex *aad,
    Hex *pt, Hex *ct, Hex *tag)
{
    int ret;
    TestMemInit();
    const uint32_t threadNum = 3; // Number of threads.
    pthread_t thrd[threadNum];
    ThreadParameter arg[3] = {
        // 3 Threads
        {.key = key->x, .iv = iv->x, .aad = aad->x, .pt = pt->x, .ct = ct->x, .tag = tag->x,
         .keyLen = key->len, .ivLen = iv->len, .aadLen = aad->len,
         .ptLen = pt->len, .ctLen = ct->len, .tagLen = tag->len,
         .algId = algId, .isProvider = isProvider},
        {.key = key->x, .iv = iv->x, .aad = aad->x, .pt = pt->x, .ct = ct->x, .tag = tag->x,
         .keyLen = key->len, .ivLen = iv->len, .aadLen = aad->len,
         .ptLen = pt->len, .ctLen = ct->len, .tagLen = tag->len,
         .algId = algId, .isProvider = isProvider},
        {.key = key->x, .iv = iv->x, .aad = aad->x, .pt = pt->x, .ct = ct->x, .tag = tag->x,
         .keyLen = key->len, .ivLen = iv->len, .aadLen = aad->len,
         .ptLen = pt->len, .ctLen = ct->len, .tagLen = tag->len,
         .algId = algId, .isProvider = isProvider},
    };
    for (uint32_t i = 0; i < threadNum; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)MultiThreadTest, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < threadNum; i++) {
        pthread_join(thrd[i], NULL);
    }

EXIT:
    return;
}
/* END_CASE */