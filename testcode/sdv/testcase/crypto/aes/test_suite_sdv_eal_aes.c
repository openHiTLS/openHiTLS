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
#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "eal_cipher_local.h"
#include "modes_local.h"
#include "bsl_sal.h"
#include "securec.h"
#include "crypto_test_util.h"

#define MAX_OUTPUT 5000
#define MCT_INNER_LOOP 1000
#define AES_BLOCKSIZE 16

#define MAX_DATA_LEN 1024
#define AES_TAG_LEN 16

static void Test_CipherOverLap(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc, uint32_t inOffset, uint32_t outOffset)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    memcpy_s(outTmp + inOffset, sizeof(outTmp) - inOffset, in->x, in->len);
    ret = CRYPT_EAL_CipherUpdate(ctx, outTmp + inOffset, in->len, outTmp + outOffset, &len);
    if (outOffset > 0 && outOffset < in->len) {
        ASSERT_TRUE(ret == CRYPT_EAL_ERR_PART_OVERLAP);
    } else {
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        len = MAX_OUTPUT - len;
        ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen + outOffset, &len);
        totalLen += len;
        ASSERT_TRUE(totalLen == out->len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        ASSERT_TRUE(memcmp(outTmp + outOffset, out->x, out->len) == 0);
    }

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}

void reportLog(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
#ifdef PRINT_TO_TERMINAL
    printf("CRYPT_EVENT_TYPE=%d, CRYPT_ALGO_TYPE=%d, algId=%d, errorCode=%d\n", oper, type, id, err);
#else
    (void)oper;
    (void)type;
    (void)id;
    (void)err;
#endif
}
/* END_HEADER */

/**
 * @test  SDV_CRYPTO_AES_NEW_CTX_API_TC001
 * @title  Impact of the invalid algorithm ID on the New interface
 * @brief
 *    1.Create the context ctx with the input parameter CRYPT_CIPHER_MAX. Expected result 1 is obtained.
 * @expect
 *    1.Failed. NULL is returned.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_NEW_CTX_API_TC001(void)
{
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_MAX);
    ASSERT_TRUE(ctx == NULL);
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_INIT_API_TC001
 * @title  Impact of Input Parameters on the CRYPT_EAL_CipherInit Interface
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the New interface with param CRYPT_CIPHER_AES192_CBC. Expected result 1 is obtained.
 *    2.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is not 0,
 *      iv is not NULL, and ivLen is not 0. Expected result 2 is obtained.
 *    3.Call the Init interface, ctx is NULL, key is not NULL, keyLen is not 0,
 *      iv is not NULL, and ivLen is not 0. Expected result 3 is obtained.
 *    4.Call the Init interface, ctx is not NULL, key is NULL, keyLen is not 0,
 *      iv is not NULL, and ivLen is not 0. Expected result 4 is obtained.
 *    5.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is 0,
 *      iv is not NULL, and ivLen is not 0. Expected result 5 is obtained.
 *    6.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is not 0,
 *      iv is NULL, and ivLen is not 0. Expected result 6 is obtained.
 *    7.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is not 0,
 *      iv is not NULL, and ivLen is 0. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Init succeeded.
 *    3.Init failed.
 *    4.Init failed.
 *    5.Init failed.
 *    6.Init failed.
 *    7.Init failed.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_INIT_API_TC001(Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(NULL, key->x, key->len, iv->x, iv->len, true);
    ASSERT_EQ_LOG("1", ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherInit(ctx, NULL, key->len, iv->x, iv->len, true);
    ASSERT_EQ_LOG("2", ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, 0, iv->x, iv->len, true);
    ASSERT_EQ_LOG("3", ret, CRYPT_AES_ERR_KEYLEN);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, NULL, iv->len, true);
    ASSERT_EQ_LOG("4", ret, CRYPT_INVALID_ARG);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 0, true);
    ASSERT_EQ_LOG("5", ret, CRYPT_MODES_IVLEN_ERROR);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_DEINIT_API_TC001
 * @title  Impact of Input Parameters on the CRYPT_EAL_CipherDeinit Interface
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Deinit interface, ctx is not NULL. Expected result 2 is obtained.
 *    3.Call the Deinit interface, ctx is NULL. Expected result 3 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The function is executed successfully.
 *    3.The function is executed successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_DEINIT_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherDeinit(NULL);
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_REINIT_API_TC001
 * @title  CRYPT_EAL_CipherReinit Interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is not 0. Expected result 3 is obtained.
 *    4.Call the Reinit interface, ctx is NULL, iv is not NULL, and ivLen is not 0. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is NULL, and ivLen is not 0. Expected result 5 is obtained.
 *    6.Call the Reinit interface, ctx is not NULL, iv is not NULL, and ivLen is 0. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Failed. Return CRYPT_NULL_INPUT.
 *    6.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_REINIT_API_TC001(Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_EAL_ERR_STATE);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(NULL, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherReinit(ctx, NULL, iv->len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, 0);
    ASSERT_TRUE(ret == CRYPT_MODES_IVLEN_ERROR);
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_UPDATE_API_TC001
 * @title  Impact of Input Parameters on the CRYPT_EAL_CipherUpdate Interface
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface, ctx is NULL, in is not NULL, and in len is not 0, out is not NULL, and out len is not NULL. Expected result 3 is obtained.
 *    4.Call the Update interface, ctx is not NULL, in is NULL, and in len is not 0, out is not NULL, and out len is not NULL. Expected result 4 is obtained.
 *    5.Call the Update interface, ctx is not NULL, in is not NULL, and in len is 0, out is not NULL, and out len is not NULL. Expected result 5 is obtained.
 *    6.Call the Update interface, ctx is not NULL, in is not NULL, and in len is not 0, out is NULL, and out len is not NULL. Expected result 6 is obtained.
 *    7.Call the Update interface, ctx is not NULL, in is not NULL, and in len is not 0, out is not NULL, and out len is NULL. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Failed. Return CRYPT_NULL_INPUT.
 *    7.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_UPDATE_API_TC001(Hex *key, Hex *iv, Hex *in)
{
    TestMemInit();
    int32_t ret;
    uint8_t out[AES_BLOCKSIZE] = {0};
    uint32_t len = AES_BLOCKSIZE;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_EQ_LOG("1", ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, out, &len);
    ASSERT_EQ_LOG("2", ret, CRYPT_SUCCESS);
    ASSERT_EQ_LOG("3", len, AES_BLOCKSIZE);
    ret = CRYPT_EAL_CipherUpdate(NULL, in->x, in->len, out, &len);
    ASSERT_EQ_LOG("4", ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherUpdate(ctx, NULL, in->len, out, &len);
    ASSERT_EQ_LOG("5", ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, 0, out, &len);
    ASSERT_EQ_LOG("6", ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, NULL, &len);
    ASSERT_EQ_LOG("7", ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, out, NULL);
    ASSERT_EQ_LOG("8", ret, CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_FINAL_API_TC001
 * @title  Impact of Input Parameters on the CRYPT_EAL_CipherFinal Interface
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 *    4.Call the Final interface, ctx is NULL, out is not NULL, and out len is not 0. Expected result 4 is obtained.
 *    5.Call the Final interface, ctx is not NULL, out is NULL, and out len is not 0. Expected result 5 is obtained.
 *    6.Call the Final interface, ctx is not NULL, out is not NULL, and out len is 0. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.The update is successful and return CRYPT_SUCCESS.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Failed. Return CRYPT_NULL_INPUT.
 *    6.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_FINAL_API_TC001(Hex *key, Hex *iv, Hex *in)
{
    TestMemInit();
    int32_t ret;
    uint8_t out[AES_BLOCKSIZE] = {0};
    uint32_t len = AES_BLOCKSIZE;
    uint32_t finLen = AES_BLOCKSIZE;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, out, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctx, out, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(NULL, out, &finLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherFinal(ctx, NULL, &finLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherFinal(ctx, out, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_CTRL_API_TC001
 * @title  Impact of Input Parameters on the CRYPT_EAL_CipherCtrl Interface
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, and type is get iv, iv is not NULL, and iv len is not 0. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, and type is get blocksize, data is not NULL, and len is not 0. Expected result 4 is obtained.
 *    5.Call the Ctrl interface, ctx is not NULL, and type is get iv, iv is NULL, and iv len is not 0. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, and type is get iv, iv is not NULL, and iv len is 0. Expected result 6 is obtained.
 *    7.Call the Ctrl interface, ctx is not NULL, and type is get blocksize, data is not NULL, and len is 0. Expected result 7 is obtained.
 *    8.Call the Ctrl interface, ctx is not NULL, and type is invalid. Expected result 8 is obtained.
 *    9.Call the Ctrl interface, ctx is not NULL, and type is get blocksize, data is NULL, and len is not 0. Expected result 9 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Failed. Return CRYPT_NULL_INPUT.
 *    6.Failed. Return CRYPT_MODE_ERR_INPUT_LEN.
 *    7.Failed. Return CRYPT_MODE_ERR_INPUT_LEN.
 *    8.Failed. Return CRYPT_MODES_METHODS_NOT_SUPPORT.
 *    9.Failed. Return CRYPT_MODE_ERR_INPUT_LEN.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_CTRL_API_TC001(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    uint8_t *ivGet[AES_BLOCKSIZE] = {0};
    const uint32_t len = AES_BLOCKSIZE;
    uint32_t blockSizeGet = 0;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, ivGet, len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, (uint8_t *)&blockSizeGet, sizeof(uint32_t));
    if (id == CRYPT_CIPHER_AES128_CBC) {
        ASSERT_EQ(blockSizeGet, AES_BLOCKSIZE);
    } else {
        ASSERT_TRUE(blockSizeGet == 1);
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, NULL, len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, ivGet, 0);
    ASSERT_TRUE(ret == CRYPT_MODE_ERR_INPUT_LEN);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, (uint8_t *)&blockSizeGet, 0);
    ASSERT_TRUE(ret == CRYPT_MODE_ERR_INPUT_LEN);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_MAX, iv->x, iv->len);
    ASSERT_EQ(ret, CRYPT_MODES_CTRL_TYPE_ERROR);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, NULL, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_MODE_ERR_INPUT_LEN);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_SET_PADDING_API_TC001
 * @title Impact of Input Parameters on the CRYPT_EAL_CipherSetPadding Interface
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the CRYPT_EAL_CipherSetPadding interface with ctx is NULL, and type set to a normal value. Expected result 3 is obtained.
 *    4.Call the CRYPT_EAL_CipherSetPadding interface with ctx is not NULL, and type set to a invalid value. Expected result 4 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 *    4.Failed. Return CRYPT_MODES_METHODS_NOT_SUPPORT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_SET_PADDING_API_TC001(Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctxCBC = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    CRYPT_EAL_CipherCtx *ctxCCM = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CCM);
    CRYPT_EAL_CipherCtx *ctxCTR = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CTR);
    ASSERT_TRUE(ctxCBC != NULL);
    ASSERT_TRUE(ctxCCM != NULL);
    ASSERT_TRUE(ctxCTR != NULL);
    ret = CRYPT_EAL_CipherInit(ctxCBC, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxCBC, CRYPT_PADDING_ZEROS);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(NULL, CRYPT_PADDING_ZEROS);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherSetPadding(ctxCBC, CRYPT_PADDING_MAX_COUNT);
    ASSERT_EQ(ret, CRYPT_MODES_PADDING_NOT_SUPPORT);
    ret = CRYPT_EAL_CipherSetPadding(ctxCCM, CRYPT_PADDING_ZEROS);
    ASSERT_EQ(ret, CRYPT_MODES_CTRL_TYPE_ERROR);
    ret = CRYPT_EAL_CipherSetPadding(ctxCTR, CRYPT_PADDING_ZEROS);
    ASSERT_EQ(ret, CRYPT_MODES_CTRL_TYPE_ERROR);

EXIT:
    CRYPT_EAL_CipherDeinit(ctxCBC);
    CRYPT_EAL_CipherFreeCtx(ctxCBC);
    CRYPT_EAL_CipherFreeCtx(ctxCCM);
    CRYPT_EAL_CipherFreeCtx(ctxCTR);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_GET_PADDING_API_TC001
 * @title  Impact of Input Parameters on the CRYPT_EAL_CipherGetPadding Interface
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the CRYPT_EAL_CipherGetPadding interface with ctx is NULL. Expected result 3 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_GET_PADDING_API_TC001(Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_ZEROS);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherGetPadding(ctx);
    ASSERT_TRUE(ret == CRYPT_PADDING_ZEROS);
    ret = CRYPT_EAL_CipherGetPadding(NULL);
    ASSERT_TRUE(ret == CRYPT_PADDING_MAX_COUNT);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001
 * @title  Impact of multiple blocks on AES calculation_KAT, MMT Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the SetPadding interface to set the padding mode CRYPT_PADDING_NONE. Expected result 2 is obtained.
 *    3.Call the Init interface. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The init is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS. The calculation result is consistent with the vector value.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen, &len);
    totalLen += len;
    ASSERT_EQ(totalLen, out->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(outTmp, out->x, out->len), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC002
 * @title Multiple update_MCT tests
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the SetPadding interface to set the padding mode. Expected result 2 is obtained.
 *    3.Call the Init interface. Expected result 3 is obtained.
 *    4.Call the Update interface for multiple times. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The init is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS. The calculation result is consistent with the vector value.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC002(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint32_t len = AES_BLOCKSIZE;
    uint8_t mctResult[MCT_INNER_LOOP][AES_BLOCKSIZE] = {0};
    uint8_t *inputTmp = in->x;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    for (uint32_t i = 0; i < MCT_INNER_LOOP; i++) {
        ret = CRYPT_EAL_CipherUpdate(ctx, inputTmp, AES_BLOCKSIZE, mctResult[i], &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        if (i == 0) {
            inputTmp = iv->x;
        } else {
            inputTmp = mctResult[i - 1];
        }
    }

    ASSERT_TRUE(memcmp(mctResult[MCT_INNER_LOOP - 1], out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC003
 * @title  After reinit, re-encrypt and decrypt data Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the SetPadding interface to set the padding mode. Expected result 2 is obtained.
 *    3.Call the Init interface. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Call the Reinit interface. Expected result 6 is obtained.
 *    7.Call the Update interface. Expected result 7 is obtained.
 *    8.Call the Final interface. Expected result 8 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The init is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS. The calculation result is consistent with the vector value.
 *    6.The reinit is successful, return CRYPT_SUCCESS.
 *    7.The update is successful, return CRYPT_SUCCESS.
 *    8.The final is successful, return CRYPT_SUCCESS. The calculation result is consistent with the vector value.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC003(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t finLen;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);

    (void)memset_s(outTmp, MAX_OUTPUT, 0, MAX_OUTPUT);
    len = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_STATE_CHANGE_API_TC001
 * @title  New, init, update, and final state transition Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx twice. Expected result 1 is obtained.
 *    2.Call the Free interface twice. Expected result 2 is obtained.
 *    3.Create the context ctx. Expected result 3 is obtained.
 *    4.Call the Init interface twice. Expected result 4 is obtained.
 *    5.Call the Update interface twice. Expected result 5 is obtained.
 *    6.Call the Final interface twice. Expected result 6 is obtained.
 *    7.Call the Update interface. Expected result 7 is obtained.
 *    8.Call the Deinit interface twice and call Free interface. Expected result 8 is obtained.
 *    9.Create the context ctx. Expected result 9 is obtained.
 *    10.Call the Update interface. Expected result 10 is obtained.
 *    11.Call the Free interface and create the context ctx. Expected result 11 is obtained.
 *    12.Call the Final interface. Expected result 12 is obtained.
 *    13.Call the Free interface and create the context ctx. Expected result 13 is obtained.
 *    14.Call the Init interface. Expected result 14 is obtained.
 *    15.Call the Update interface. Expected result 15 is obtained.
 *    16.Call the Init interface. Expected result 16 is obtained.
 *    17.Call the Free interface and create the context ctx. Expected result 17 is obtained.
 *    18.Call the Reinit interface. Expected result 18 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The free function is successfully executed.
 *    3.The creation is successful and the ctx is not empty.
 *    4.The init is successful, return CRYPT_SUCCESS.
 *    5.The update is successful, return CRYPT_SUCCESS.
 *    6.The first final is successful, the second final is failed, return CRYPT_EAL_ERR_STATE.
 *    7.Failed. return CRYPT_EAL_ERR_STATE.
 *    8.The deinit adn free function is successfully executed.
 *    9.The creation is successful and the ctx is not empty.
 *    10.Failed. return CRYPT_EAL_ERR_STATE.
 *    11.The creation is successful and the ctx is not empty.
 *    12.Failed. return CRYPT_EAL_ERR_STATE.
 *    13.The creation is successful and the ctx is not empty.
 *    14.The init is successful, return CRYPT_SUCCESS.
 *    15.The update is successful, return CRYPT_SUCCESS.
 *    16.The init is successful, return CRYPT_SUCCESS.
 *    17.The creation is successful and the ctx is not empty.
 *    18.Failed. return CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_STATE_CHANGE_API_TC001(Hex *key, Hex *iv, Hex *in, int enc)
{
    TestMemInit();
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;

    // multi new
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    CRYPT_EAL_CipherCtx *ctx1 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(ctx1 != NULL);
    CRYPT_EAL_CipherFreeCtx(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx1);
    ctx = NULL;
    ctx1 = NULL;

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    // multi init
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc) == CRYPT_SUCCESS);
    // multi update
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len) == CRYPT_SUCCESS);
    // multi final
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, outTmp, &len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, outTmp, &len) == CRYPT_EAL_ERR_STATE);
    // update after final
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len) == CRYPT_EAL_ERR_STATE);
    // multi deinit
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);

    // update after new
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len) == CRYPT_EAL_ERR_STATE);
    CRYPT_EAL_CipherFreeCtx(ctx);

    // final after new
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, outTmp, &len) == CRYPT_EAL_ERR_STATE);
    CRYPT_EAL_CipherFreeCtx(ctx);

    // init after new
    len = MAX_OUTPUT;
    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len) == CRYPT_SUCCESS);
    // init after update
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc) == CRYPT_SUCCESS);
    CRYPT_EAL_CipherFreeCtx(ctx);

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC004
 * @title  Encryption and decryption in different padding modes Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call SetPadding interface setting padding mode to CRYPT_PADDING_ISO7816, CRYPT_PADDING_ZEROS,
 *      CRYPT_PADDING_X923, CRYPT_PADDING_PKCS5, CRYPT_PADDING_PKCS7. Expected result 2 is obtained.
 *    3.Call the Init interface. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Call the init, update, and final interfaces to decrypt and verifiy the result.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The init is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS.
 *    6.The verification is successful, return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC004(int algId, Hex *key, Hex *iv, Hex *in, int padding)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint8_t result[MAX_OUTPUT] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen = leftLen - len;
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;

    len = MAX_OUTPUT;
    leftLen = MAX_OUTPUT;
    ctxDec = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxDec, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp, totalLen, result, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    leftLen -= len;
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(in->x, result, in->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherDeinit(ctxDec);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC005
 * @title  Multiple update calculation encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the update interface to update the first message. Expected result 2 is obtained.
 *    3.Call the update interface to update the second message. Expected result 3 is obtained.
 *    4.Call the update interface to update the third message. Expected result 4 is obtained.
 *    5.Call the final interface. Expected result 5 is obtained.
 *    6.Check whether the result is consistent with the test vector. Expected result 6 is obtained.
 * @expect
 *    1.The init is successful, return CRYPT_SUCCESS.
 *    2.The update is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS.
 *    6.The verification is successful.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC005(int isProvider, int algId, Hex *key, Hex *iv, Hex *in1, Hex *in2,
    Hex *in3, Hex *out, int enc)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = CRYPT_EAL_CipherUpdate(ctx, in1->x, in1->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, in2->x, in2->len, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, in3->x, in3->len, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC006
 * @title  Encryption and decryption for multiple updates in CFB mode
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the Ctrl interface to set feedback.
 *    3.Call the Ctrl interface to get feedback. Expected result 2 is obtained.
 *    4.Call the update interface to update the first message. Expected result 3 is obtained.
 *    5.Call the update interface to update the second message. Expected result 4 is obtained.
 *    6.Call the update interface to update the third message. Expected result 5 is obtained.
 *    7.Call the final interface. Expected result 6 is obtained.
 *    8.Check whether the result is consistent with the test vector. Expected result 7 is obtained.
 * @expect
 *    1.The init is successful, return CRYPT_SUCCESS.
 *    2.The get is successful, and getting FeedBack is equal to setting.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The update is successful, return CRYPT_SUCCESS.
 *    6.The final is successful, return CRYPT_SUCCESS.
 *    7.The verification is successful.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC006(int isProvider, int algId, int feed, Hex *key, Hex *iv, Hex *in1, Hex *in2,
    Hex *in3, Hex *out, int enc)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    uint32_t feedBack = feed;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, (uint32_t *)&feedBack, sizeof(uint32_t)) == CRYPT_SUCCESS);
    uint32_t tmpFeedBack = 0;
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, (uint32_t *)&tmpFeedBack, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(tmpFeedBack == (uint32_t)feed);
    ret = CRYPT_EAL_CipherUpdate(ctx, in1->x, in1->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, in2->x, in2->len, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherUpdate(ctx, in3->x, in3->len, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC007
 * @title  The input and output use the same buffer Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The final is successful, return CRYPT_SUCCESS. The result is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC007(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    TestMemInit();
    int32_t ret;
    uint32_t len = in->len;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, in->x, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen = totalLen + len;
    len = in->len - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, in->x + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(in->x, out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

typedef struct {
    int algId;
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *iv;
    uint32_t ivLen;
    uint8_t *in;
    uint32_t inLen;
    uint8_t *out;
    uint32_t outLen;
    int enc;
} TestVector;

void AES_MultiThreadTest(void *arg)
{
    TestVector *pTestVector = (TestVector *)arg;
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(pTestVector->algId);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, pTestVector->key, pTestVector->keyLen, pTestVector->iv,
        pTestVector->ivLen, pTestVector->enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, pTestVector->in, pTestVector->inLen, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen = totalLen + len;
    len = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, pTestVector->out, pTestVector->outLen) == 0);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}

/**
 * @test  SDV_CRYPTO_AES_MULTI_THREAD_FUNC_TC001
 * @title  Multi-thread Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create three threads for synchronous encryption and decryption. Expected result 1 is obtained.
 *    2.Create the context ctx. Expected result 2 is obtained.
 *    3.Call the Init interface. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Waiting for the thread to exit normally. Expected result 6 is obtained.
 * @expect
 *    1.The thread is created successfully.
 *    2.The creation is successful and the ctx is not empty.
 *    3.The init is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS. The result is consistent with the test vector.
 *    6.The thread exits successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_MULTI_THREAD_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
#define THREAD_NUM 3
    TestMemInit();
    int32_t ret;
    pthread_t thrd[THREAD_NUM];
    TestVector testVt = {.algId = algId,
        .key = key->x,
        .keyLen = key->len,
        .iv = iv->x,
        .ivLen = iv->len,
        .in = in->x,
        .inLen = in->len,
        .out = out->x,
        .outLen = out->len,
        .enc = enc};

    for (uint32_t i = 0; i < THREAD_NUM; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)AES_MultiThreadTest, &testVt);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < THREAD_NUM; i++) {
        pthread_join(thrd[i], NULL);
    }
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_OVERLAP_FUNC_TC001
 * @title  The in and out memory partially overlaps during update
 * @precon Registering memory-related functions.
 * @brief
 *    1.The in and out buff are partially overlaps. If out > in, Expected result 1 is obtained.
 *    2.The in and out buff are partially overlaps. If in > out, Expected result 2 is obtained.
 * @expect
 *    1.Failed. Return RYPT_EAL_ERR_PART_OVERLAP
 *    2.The operation is normal.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_OVERLAP_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    for (uint32_t i = 0; i <= in->len + EAL_MAX_BLOCK_LENGTH; i++) {
        Test_CipherOverLap(algId, key, iv, in, out, enc, i, 0);
    }
    for (uint32_t i = 0; i < in->len + EAL_MAX_BLOCK_LENGTH + EAL_MAX_BLOCK_LENGTH; i++) {
        Test_CipherOverLap(algId, key, iv, in, out, enc, 0, i);
    }
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC008
 * @title  Encryption in different padding modes Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call SetPadding interface setting padding mode to CRYPT_PADDING_ISO7816,
 *      CRYPT_PADDING_X923, CRYPT_PADDING_PKCS7. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Call the init, update, and final interfaces to decrypt and verifiy the result.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The setting is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS.
 *    6.The verification is successful, return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC008(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int padding)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxEnc = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen = leftLen - len;
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;

    ASSERT_TRUE(totalLen == out->len);
    ASSERT_TRUE(memcmp(out->x, outTmp, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_ENCRYPT_FUNC_TC009
 * @title  Decryption in different padding modes Test
 * @precon Registering memory-related functions and report-log functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call SetPadding interface setting padding mode to CRYPT_PADDING_ISO7816,
 *      CRYPT_PADDING_X923, CRYPT_PADDING_PKCS7. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Call the init, update, and final interfaces to decrypt and verifiy the result.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The setting is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS.
 *    6.The verification is successful, return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_ENCRYPT_FUNC_TC009(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out,
    int padding)
{
    TestMemInit();
    CRYPT_EAL_RegEventReport(reportLog);
    int32_t ret;
    uint8_t result[MAX_OUTPUT] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    len = MAX_OUTPUT;
    leftLen = MAX_OUTPUT;
    ctxDec = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxDec, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxDec, in->x, in->len, result, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen = leftLen - len;
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    totalLen += leftLen;

    ASSERT_TRUE(totalLen == out->len);
    ASSERT_TRUE(memcmp(out->x, result, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctxDec);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_EAL_AES_XTS_GET_IV_TC001
 * @title  AES-XTS: obtaining IV in different states.
 * @brief
 *    1. Get iv after init iv, and compare the getted iv with original iv, expected result 1
 *    2. Get iv after update, and compare the getted iv with original iv, expected result 2
 *    3. Get iv after final, expected result 3
 * @expect
 *    1. The IV is obtained successfully and the two IVs are the same.
 *    2. The IV is obtained successfully and the two IVs are the same.
 *    3. CRYPT_EAL_ERR_STATE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_XTS_GET_IV_TC001(int id, Hex *key, Hex *iv, Hex *plainText, Hex *cipherText)
{
    uint8_t outIv[AES_BLOCKSIZE] = {0};
    uint8_t out[MAX_OUTPUT] = {0};
    uint32_t totalOutLen = 0;
    uint32_t outLen = MAX_OUTPUT;

    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, outIv, iv->len), CRYPT_SUCCESS);
    ASSERT_COMPARE("Get iv after init", outIv, iv->len, iv->x, iv->len);

    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plainText->x, plainText->len, out, &outLen), CRYPT_SUCCESS);
    (void)memset_s(outIv, AES_BLOCKSIZE, 0, AES_BLOCKSIZE);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, outIv, iv->len), CRYPT_SUCCESS);
    ASSERT_COMPARE("Get iv after encrypt", outIv, iv->len, iv->x, iv->len);

    totalOutLen += outLen;
    outLen = MAX_OUTPUT - totalOutLen;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out + totalOutLen, &outLen), CRYPT_SUCCESS);
    totalOutLen += outLen;
    ASSERT_COMPARE("Check encrypt result", out, totalOutLen, cipherText->x, cipherText->len);

    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, outIv, iv->len), CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_AES_FUNC_TC001
* @spec  -
* @title  CBC,ECB,CTR,XTS: the influence of All-zero and All-F Data Keys on AES Calculation_KAT
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_FUNC_TC001(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t totalLen = 0;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen, &len);
    totalLen += len;
    ASSERT_TRUE(totalLen == out->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_AES_FUNC_TC005
* @spec  -
* @title  CBC,ECB,CTR,XTS: after reinit, re-encrypt and decrypt data_reinit function test
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_FUNC_TC005(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t finLen;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);

    (void)memset_s(outTmp, MAX_OUTPUT, 0, MAX_OUTPUT);
    len = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_AES_FUNC_TC010(int algId, Hex *key, Hex *iv, Hex *pt)
{
#ifndef HITLS_CRYPTO_AES_ARMV8
    (void)algId;
    (void)key;
    (void)iv;
    (void)pt;
    SKIP_TEST();
#else
    if (IsAesAlgDisabled(algId)) {
        SKIP_TEST();
    }
    uint8_t cipher[MAX_OUTPUT] = {0};
    uint32_t cipherLen = MAX_OUTPUT;
    uint8_t plain[MAX_OUTPUT] = {0};
    uint32_t plainLen = MAX_OUTPUT;

    uint8_t outTag[AEAD_MAX_TAG_LEN];
    uint32_t tagLen = AEAD_MAX_TAG_LEN;

    uint32_t finLen = 0;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    TestMemInit();

    AARCH64_PUT_CANARY();

    // Encrypt
    ASSERT_TRUE((ctx = CRYPT_EAL_CipherNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);

    if (algId == CRYPT_CIPHER_AES128_GCM || algId == CRYPT_CIPHER_AES192_GCM || algId == CRYPT_CIPHER_AES256_GCM) {
        ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, cipher, &cipherLen), CRYPT_SUCCESS);
    if (algId == CRYPT_CIPHER_AES128_CBC || algId == CRYPT_CIPHER_AES192_CBC || algId == CRYPT_CIPHER_AES256_CBC) {
        finLen = MAX_OUTPUT - cipherLen;
        ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, cipher + cipherLen, &finLen), CRYPT_SUCCESS);
        cipherLen += finLen;
    } else {
        ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, outTag, tagLen) == CRYPT_SUCCESS);
    }

    // Decrypt
    CRYPT_EAL_CipherDeinit(ctx);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, cipher, cipherLen, plain, &plainLen), CRYPT_SUCCESS);
    if (algId == CRYPT_CIPHER_AES128_CBC || algId == CRYPT_CIPHER_AES192_CBC || algId == CRYPT_CIPHER_AES256_CBC) {
        finLen = MAX_OUTPUT - plainLen;
        ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, plain + plainLen, &finLen), CRYPT_SUCCESS);
        plainLen += finLen;
    }
    ASSERT_COMPARE("AES:", plain, plainLen, pt->x, pt->len);
    CRYPT_EAL_CipherFreeCtx(ctx);
    ctx = NULL;
    ASSERT_TRUE(TestIsErrStackEmpty());
    AARCH64_CHECK_CANARY();
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
#endif
}
/* END_CASE */