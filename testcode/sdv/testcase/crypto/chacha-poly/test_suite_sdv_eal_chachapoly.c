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

#include "crypt_errno.h"
#include "crypt_eal_cipher.h"
#include "bsl_sal.h"
#include "securec.h"

/* END_HEADER */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_INIT_API_TC001
 * @title  CRYPT_EAL_CipherInit Invalid input parameter
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface, ctx is NULL, other parameters are normal. Expected result 1 is obtained.
 *    3.Call the Init interface, key is NULL, other parameters are normal. Expected result 2 is obtained.
 *    4.Call the Init interface, iv is NULL, other parameters are normal. Expected result 2 is obtained.
 * @expect
 *    1.Failed. Return CRYPT_NULL_INPUT.
 *    2.Failed. Return CRYPT_NULL_INPUT.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_INIT_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(NULL, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, NULL, sizeof(key), iv, sizeof(iv), true), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), NULL, sizeof(iv), true), CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_INIT_API_TC002
 * @title  CRYPT_EAL_CipherInit Invalid input parameter
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface with keyLen is 33, other parameters are normal. Expected result 1 is obtained.
 *    3.Call the Init interface with keyLen is 31, other parameters are normal. Expected result 2 is obtained.
 *    4.Call the Init interface with ivLen is 11, other parameters are normal. Expected result 3 is obtained.
 *    5.Call the Init interface with ivLen is 13, other parameters are normal. Expected result 4 is obtained.
 *    6.Call the Init interface with ivLen is 9, other parameters are normal. Expected result 5 is obtained.
 *    7.Call the Init interface with ivLen is 7, other parameters are normal. Expected result 6 is obtained.
 * @expect
 *    1.Failed. Return CRYPT_CHACHA20_KEYLEN_ERROR.
 *    2.Failed. Return CRYPT_CHACHA20_KEYLEN_ERROR.
 *    3.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    4.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    5.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    6.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_INIT_API_TC002(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, 33, iv, sizeof(iv), true),
        CRYPT_CHACHA20_KEYLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, (uint8_t *)key, 31, iv, sizeof(iv), true),
        CRYPT_CHACHA20_KEYLEN_ERROR);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), (uint8_t *)iv, 13, true),
        CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), (uint8_t *)iv, 11, true),
        CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), (uint8_t *)iv, 9, true),
        CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), (uint8_t *)iv, 7, true),
        CRYPT_MODES_IVLEN_ERROR);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_REINIT_API_TC001
 * @title  CRYPT_EAL_CipherReinit Invalid input parameter Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. Expected result 1 is obtained.
 *    3.Call the Reinit interface with iv is NULL, and set other parameters correctly. Expected result 2 is obtained.
 *    4.Call the Reinit interface with ctx is NULL, and set other parameters correctly. Expected result 3 is obtained.
 * @expect
 *    1.The init is successful and return CRYPT_SUCCESS.
 *    2.Failed. Return CRYPT_NULL_INPUT.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_REINIT_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, NULL, sizeof(iv)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(NULL, iv, sizeof(iv)) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_REINIT_API_TC002
 * @title  CRYPT_EAL_CipherReinit Invalid input parameter Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. Expected result 1 is obtained.
 *    3.Call the Reinit interface with ivLen is 11, and set other parameters correctly. Expected result 2 is obtained.
 *    4.Call the Reinit interface with ivLen is 13, and set other parameters correctly. Expected result 3 is obtained.
 *    5.Call the Reinit interface with ivLen is 9, and set other parameters correctly. Expected result 4 is obtained.
 *    6.Call the Reinit interface with ivLen is 7, and set other parameters correctly. Expected result 5 is obtained.
 * @expect
 *    1.The init is successful and return CRYPT_SUCCESS.
 *    2.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    3.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    4.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 *    5.Failed. Return CRYPT_MODES_IVLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_REINIT_API_TC002(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, 13) == CRYPT_MODES_IVLEN_ERROR);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, 11) == CRYPT_MODES_IVLEN_ERROR);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, 9) == CRYPT_MODES_IVLEN_ERROR);
    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, (uint8_t *)iv, 7) == CRYPT_MODES_IVLEN_ERROR);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_REINIT_API_TC003
 * @title  Call sequence error Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Reinit interface. All parameters are normal. Expected result 1 is obtained.
 * @expect
 *    1.Failed. Return CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_REINIT_API_TC003(void)
{
    TestMemInit();
    uint8_t iv[12] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);

    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv, sizeof(iv)) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_API_TC001
 * @title  Invalid input parameter of CRYPT_EAL_CipherUpdate Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. Expected result 2 is obtained.
 *    4.Call the Update interface, ctx is NULL, and other parameters are normal. Expected result 3 is obtained.
 *    4.Call the Update interface, in is NULL, and other parameters are normal. Expected result 4 is obtained.
 *    5.Call the Update interface, inLen is 0, and other parameters are normal. Expected result 5 is obtained.
 *    6.Call the Update interface, out is NULL, and other parameters are normal. Expected result 6 is obtained.
 *    7.Call the Update interface, outLen is NULL, and other parameters are normal. Expected result 7 is obtained.
 * @expect
 *    1.The init is successful and return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Success. Return CRYPT_SUCCESS.
 *    6.Failed. Return CRYPT_NULL_INPUT.
 *    7.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t data[100] = {0};
    uint8_t aad[20] = {0};
    uint8_t out[100];
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(NULL, data, sizeof(data), out, &outLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, NULL, sizeof(data), out, &outLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, 0, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), NULL, &outLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), (uint8_t *)out, NULL) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_API_TC002
 * @title  CRYPT_EAL_CipherUpdate Invalid input parameter Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. Expected result 2 is obtained.
 *    4.Call the Update interface, outLen is inLen - 1, and other parameters are normal. Expected result 3 is obtained.
 * @expect
 *    1.The init is successful and return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Failed. The buffer is not enough.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_API_TC002(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t data[100] = {0};
    uint8_t aad[20] = {0};
    uint8_t out[100];
    uint32_t outLen = sizeof(data) - 1;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_SUCCESS);

    ASSERT_NE(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), (uint8_t *)out, &outLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_API_TC003
 * @title  CRYPT_EAL_CipherUpdate Error State Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Update interface. All parameters are normal. Expected result 1 is obtained.
 * @expect
 *    1.Failed. return CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_API_TC003(void)
{
    TestMemInit();
    uint8_t data[100] = {0};
    uint8_t out[100];
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, sizeof(data), out, &outLen) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC001
 * @title  CRYPT_EAL_CipherCtrl set aad invalid parameter Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad with aad is NULL and aadLen is not 0. Expected result 2 is obtained.
 *    4.Call the Ctrl interface to set aad with ctx is NULL. Expected result 3 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Failed. Return CRYPT_NULL_INPUT.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[20] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, NULL, sizeof(aad)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(NULL, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_NULL_INPUT);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC002
 * @title  CRYPT_EAL_CipherCtrl get tag invalid parameter Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. Expected result 2 is obtained.
 *    4.Call the Ctrl interface to get tag with ctx is NULL. Expected result 3 is obtained.
 *    5.Call the Ctrl interface to get tag with data is NULL. Expected result 4 is obtained.
 *    6.Call the Ctrl interface to get tag with dataLen is 15. Expected result 5 is obtained.
 *    7.Call the Ctrl interface to get tag with dataLen is 17. Expected result 6 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Failed. Return CRYPT_MODES_TAGLEN_ERROR.
 *    6.Failed. Return CRYPT_MODES_TAGLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC002(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[20] = {0};
    uint8_t out[16];

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(NULL, CRYPT_CTRL_GET_TAG, out, sizeof(out)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, NULL, sizeof(out)) == CRYPT_NULL_INPUT);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, out, sizeof(out) - 1) == CRYPT_MODES_TAGLEN_ERROR);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, out, sizeof(out) + 1) == CRYPT_MODES_TAGLEN_ERROR);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC003
 * @title  Invalid Algorithms to call Ctrl Interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set iv. Expected result 2 is obtained.
 *    4.Call the Ctrl interface to get iv. Expected result 3 is obtained.
 *    5.Call the Ctrl interface to get blockSize. Expected result 4 is obtained.
 *    6.Call the Ctrl interface to set tag len. Expected result 5 is obtained.
 *    7.Call the Ctrl interface to set msg len. Expected result 6 is obtained.
 * @expect
 *    1.The init is successful and return CRYPT_SUCCESS.
 *    2.Setting failed.
 *    3.Getting failed.
 *    4.Getting failed.
 *    5.Setting failed. The algorithm is not supported.
 *    6.Setting failed. The algorithm is not supported.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC003(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t buf[100] = {0};
    uint8_t num = 0;
    uint32_t num32 = 0;
    uint64_t num64 = 0;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, (uint8_t *)buf, 12) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, &num, sizeof(uint8_t)) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &num32, sizeof(uint32_t)) != CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &num64, sizeof(uint64_t)) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC004
 * @title  Set aad but not initialized Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Ctrl interface to set iv. Expected result 1 is obtained.
 * @expect
 *    1.Failed. Return CRYPT_EAL_ERR_STATE.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC004(void)
{
    TestMemInit();
    uint8_t aad[20] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)), CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC005
 * @title  Set aad repeatedly Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. Expected result 2 is obtained.
 *    4.Call the Ctrl interface to set aad. Expected result 3 is obtained.
 * @expect
 *    1.The init is successful and return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Failed. The Aad has been set.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC005(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[20] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC006
 * @title  Get tag but not initialized Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Ctrl interface to get tag. Expected result 1 is obtained.
 * @expect
 *    1.Failed. Has not been initialized.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_CTRL_API_TC006(void)
{
    TestMemInit();
    uint8_t tag[16] = {0};
    const uint32_t tagLen = 16; // chacha-poly tag len is 16

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_NE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_FINAL_API_TC001
 * @title  Invalid Algorithms to call Final Interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. All parameters are normal. Expected result 2 is obtained.
 *    4.Call the Update interface. All parameters are normal. Expected result 3 is obtained.
 *    5.Call the Final interface. Expected result 4 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Failed. The algorithm is not supported.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_FINAL_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[20] = {0};
    uint8_t data[100] = {0};
    uint32_t dataLen = sizeof(data);
    uint8_t out[100];
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data, dataLen, out, &outLen) == CRYPT_SUCCESS);

    outLen = sizeof(out);
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, out, &outLen) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_SETPADDING_API_TC001
 * @title  Invalid Algorithms to call set padding Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. All parameters are normal. Expected result 2 is obtained.
 *    4.Call the Getpadding interface. Expected result 3 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Failed. The algorithm is not supported.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_SETPADDING_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[20] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_ZEROS) != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_GETPADDING_API_TC001
 * @title  Invalid Algorithms to call get padding Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx.
 *    2.Call the Init interface. All parameters are normal. Expected result 1 is obtained.
 *    3.Call the Ctrl interface to set aad. All parameters are normal. Expected result 2 is obtained.
 *    4.Call the Setpadding interface. Expected result 3 is obtained.
 * @expect
 *    1.Success. Return CRYPT_SUCCESS.
 *    2.Success. Return CRYPT_SUCCESS.
 *    3.Failed. The algorithm is not supported.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_GETPADDING_API_TC001(void)
{
    TestMemInit();
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[20] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key, sizeof(key), iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, sizeof(aad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherGetPadding(ctx) == CRYPT_PADDING_MAX_COUNT);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC001
 * @title  Encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface and set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set aad. All parameters are normal. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt data. Expected result 4 is obtained.
 *    5.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 5 is obtained.
 *    6.Call the deinit interface to deinitialize the ctx.
 *    7.Call the Init interface and set to decrypt. Expected result 6 is obtained.
 *    8.Call the Ctrl interface to set aad. All parameters are normal. Expected result 7 is obtained.
 *    9.Call the Update interface to decrypt data. Expected result 8 is obtained.
 *    10.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 9 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful and consistent with expected vector.
 *    5.Tag is consistent with expected vector.
 *    6.The init is successful and return CRYPT_SUCCESS.
 *    7.Succeeded in setting the AAD.
 *    8.The decryption is successful and consistent with origin plain data.
 *    9.Tag is consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC001(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint32_t tagLen = tag->len;
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, data->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == cipher->len);
    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);

    CRYPT_EAL_CipherDeinit(ctx);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x, cipher->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == data->len);
    ASSERT_TRUE(memcmp(out, data->x, data->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC002
 * @title  Multi segment encryption and decryption
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface and set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set aad. All parameters are normal. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt partial data. Expected result 4 is obtained.
 *    5.Call the Update interface to encrypt remaining data. Expected result 5 is obtained.
 *    6.Compare the ciphertext with the test vector. Expected result 6 is obtained.
 *    7.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 7 is obtained.
 *    8.Call the deinit interface to deinitialize the ctx.
 *    9.Call the Init interface and set to decrypt. Expected result 8 is obtained.
 *    10.Call the Ctrl interface to set aad. All parameters are normal. Expected result 9 is obtained.
 *    11.Call the Update interface to decrypt partial data. Expected result 10 is obtained.
 *    12.all the Update interface to decrypt remaining data. Expected result 11 is obtained.
 *    13.Compare the plaintext with the test vector. Expected result 12 is obtained.
 *    14.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 13 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful.
 *    5.The encryption is successful.
 *    6.Ciphertext is consistent with expected vector.
 *    7.Tag is consistent with expected vector.
 *    8.The init is successful and return CRYPT_SUCCESS.
 *    9.Succeeded in setting the AAD.
 *    10.The decryption is successful.
 *    11.The decryption is successful.
 *    12.Decryption result is consistent with origin plain data.
 *    13.Tag is consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC002(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint32_t tagLen = tag->len;
    uint32_t first = data->len / 2;
    uint32_t outLen;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    outLen = first;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, first, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outLen = data->len - first;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x + first, data->len - first, out + first, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);

    CRYPT_EAL_CipherDeinit(ctx);

    outLen = first;
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x, first, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outLen = cipher->len - first;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x + first, cipher->len - first, out + first, &outLen) ==
        CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out, data->x, data->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC003
 * @title  Encryption and decryption with reinitialization Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt with the test vector key and non-vector IV. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set non-vector AAD. Expected result 3 is obtained.
 *    4.Call the Reinit interface with the test vector IV. Expected result 4 is obtained.
 *    5.Call the Ctrl interface to set the test vector AAD. Expected result 5 is obtained.
 *    6.Call the Update interface to encrypt data. Expected result 6 is obtained.
 *    7.Compare the ciphertext with the test vector. Expected result 7 is obtained.
 *    8.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 8 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The reinitialization is successful.
 *    5.Succeeded in setting the AAD.
 *    6.The encryption is successful.
 *    7.Ciphertext is consistent with expected vector.
 *    8.Tag is consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC003(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint8_t badIv[12] = {0};
    uint8_t badAad[30] = {0};
    uint32_t tagLen = tag->len;
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, badIv, sizeof(badIv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, badAad, sizeof(badAad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, data->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == cipher->len);
    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/*
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC004
 * @title  Repeated init Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt with the non-vector key and non-vector IV. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set non-vector AAD. Expected result 3 is obtained.
 *    4.Call the init interface to set to encrypt with the test vector key and IV. Expected result 4 is obtained.
 *    5.Call the Ctrl interface to set the test vector AAD. Expected result 5 is obtained.
 *    6.Call the Update interface to encrypt data. Expected result 6 is obtained.
 *    7.Compare the ciphertext with the test vector. Expected result 7 is obtained.
 *    8.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 8 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The init is successful.
 *    5.Succeeded in setting the AAD.
 *    6.The encryption is successful.
 *    7.Ciphertext is consistent with expected vector.
 *    8.Tag is consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC004(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint8_t badIv[12] = {0};
    uint8_t badAad[30] = {0};
    uint8_t badKey[32] = {0};
    uint32_t tagLen = tag->len;
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, badKey, sizeof(badKey), badIv, sizeof(badIv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, badAad, sizeof(badAad)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, data->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == cipher->len);
    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC005
 * @title  No message scenario Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt with the test vector key and IV. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set AAD. Expected result 3 is obtained.
 *    4.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 4 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.Tag is consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC005(Hex *key, Hex *iv, Hex *aad, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint32_t tagLen = tag->len;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_COMPARE("tag equal", outTag, tagLen, tag->x, tag->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC006
 * @title  Obtaining tag repeatedly Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set AAD. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt data. Expected result 4 is obtained.
 *    5.Compare the ciphertext with the test vector. Expected result 5 is obtained.
 *    6.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 6 is obtained.
 *    7.Call the Ctrl interface again to obtain the tag and compare with test vector. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful.
 *    5.Ciphertext is consistent with expected vector.
 *    6.Tag is consistent with expected vector.
 *    7.Failed to obtain the tag for the second time.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC006(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint32_t tagLen = tag->len;
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, data->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == cipher->len);
    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen), CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC007
 * @title  Memory overlap in plaintext and ciphertext Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set AAD. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt data. The plaintext and ciphertext memory completely overlap. Expected result 4 is obtained.
 *    5.Compare the ciphertext with the test vector. Expected result 5 is obtained.
 *    6.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful.
 *    5.Ciphertext is consistent with expected vector.
 *    6.Tag is consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC007(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t buf[300];
    uint32_t tagLen = tag->len;
    uint32_t bufLen = sizeof(buf);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(memcpy_s(buf, bufLen, data->x, data->len) == 0);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, buf, data->len, buf, &bufLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(bufLen == cipher->len);
    ASSERT_TRUE(memcmp(buf, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC008
 * @title  64-bit IV encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set AAD. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt data. Expected result 4 is obtained.
 *    5.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 5 is obtained.
 *    6.Call the deinit interface to deinitialize the ctx.
 *    7.Call the init interface to set to decrypt. Expected result 6 is obtained.
 *    8.Call the Ctrl interface to set AAD. Expected result 7 is obtained.
 *    9.Call the Update interface to decrypt data. Expected result 8 is obtained.
 *    10.Compare the plaintext with the test vector. Expected result 9 is obtained.
 *    11.Call the Ctrl interface to obtain the tag and compare with encryption tag. Expected result 10 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful.
 *    5.The getting tag is successful.
 *    6.The init is successful and return CRYPT_SUCCESS.
 *    7.Succeeded in setting the AAD.
 *    8.The decryption is successful.
 *    9.Decryption result is consistent with origin plaintext.
 *    10.Tag is consistent with expected value.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC008(Hex *key, Hex *aad, Hex *data)
{
    TestMemInit();
    uint8_t outTag1[16];
    uint8_t outTag2[16];
    uint8_t out[300];
    const uint32_t tagLen = sizeof(outTag1);
    uint32_t outLen = sizeof(out);
    uint8_t iv[8];
    (void)memset_s(iv, sizeof(iv), 'A', sizeof(iv));

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv, sizeof(iv), true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, data->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag1, tagLen) == CRYPT_SUCCESS);

    CRYPT_EAL_CipherDeinit(ctx);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv, sizeof(iv), false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, out, outLen, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag2, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == data->len);
    ASSERT_TRUE(memcmp(out, data->x, data->len) == 0);
    ASSERT_TRUE(memcmp(outTag1, outTag2, tagLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC009
 * @title  Invalid tag in the encryption and decryption Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set AAD. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt data. Expected result 4 is obtained.
 *    5.Compare the ciphertext with the test vector. Expected result 5 is obtained.
 *    6.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 6 is obtained.
 *    7.Call the deinit interface to deinitialize the ctx.
 *    8.Call the init interface to set to decrypt. Expected result 7 is obtained.
 *    9.Call the Ctrl interface to set AAD. Expected result 8 is obtained.
 *    10.Call the Update interface to decrypt data. Expected result 9 is obtained.
 *    11.Compare the plaintext with the test vector. Expected result 10 is obtained.
 *    12.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 11 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful.
 *    5.Ciphertext is consistent with expected vector.
 *    6.Tag is not consistent with expected vector.
 *    7.The init is successful and return CRYPT_SUCCESS.
 *    8.Succeeded in setting the AAD.
 *    9.The decryption is successful.
 *    10.Decryption result is consistent with origin plain data.
 *    11.Tag is not consistent with expected vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC009(Hex *key, Hex *iv, Hex *aad, Hex *data, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint32_t tagLen = tag->len;
    uint32_t outLen = sizeof(out);

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, data->x, data->len, out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == cipher->len);
    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) != 0);

    CRYPT_EAL_CipherDeinit(ctx);

    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x, cipher->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(outLen == data->len);
    ASSERT_TRUE(memcmp(out, data->x, data->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) != 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test  SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC002
 * @title  Encryption and decryption of multiple segments with different lengths Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the init interface to set to encrypt. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to set AAD. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt data 1. Expected result 4 is obtained.
 *    5.Call the Update interface to encrypt data 2. Expected result 5 is obtained.
 *    6.Call the Update interface to encrypt data 3. Expected result 6 is obtained.
 *    7.Compare the ciphertext with the test vector. Expected result 7 is obtained.
 *    8.Call the Ctrl interface to obtain the tag and compare with test vector. Expected result 8 is obtained.
 *    9.Call the deinit interface to deinitialize the ctx.
 *    10.Call the init interface to set to decrypt. Expected result 9 is obtained.
 *    11.Call the Ctrl interface to set AAD. Expected result 10 is obtained.
 *    12.Call the Update interface to decrypt data 1. Expected result 11 is obtained.
 *    13.Call the Update interface to decrypt data 2. Expected result 12 is obtained.
 *    14.Call the Update interface to decrypt data 3. Expected result 13 is obtained.
 *    15.Compare the plaintext with the test vector. Expected result 14 is obtained.
 *    16.Call the Ctrl interface to obtain the tag and compare with test vector tag. Expected result 15 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the AAD.
 *    4.The encryption is successful.
 *    5.The encryption is successful.
 *    6.The encryption is successful.
 *    7.Ciphertext is consistent with expected vector.
 *    8.Tag is consistent with expected value.
 *    9.The init is successful and return CRYPT_SUCCESS.
 *    10.Succeeded in setting the AAD.
 *    11.The decryption is successful.
 *    12.The decryption is successful.
 *    13.The decryption is successful.
 *    14.Decryption result is consistent with origin plaintext.
 *    15.Tag is consistent with expected value.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_CHACHA20POLY1305_UPDATE_FUNC_TC010(Hex *key, Hex *iv, Hex *aad, Hex *pt1, Hex *pt2, Hex *pt3, Hex *cipher, Hex *tag)
{
    TestMemInit();
    uint8_t outTag[16];
    uint8_t out[300];
    uint32_t tagLen = tag->len;
    uint32_t outLen;
    uint32_t totalLen = 0;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt1->x, pt1->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    totalLen += outLen;
    outLen = sizeof(out) - pt1->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt2->x, pt2->len, out + totalLen, &outLen) == CRYPT_SUCCESS);
    totalLen += outLen;
    outLen = sizeof(out) - pt1->len - pt2->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt3->x, pt3->len, out + totalLen, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(out, cipher->x, cipher->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);

    CRYPT_EAL_CipherDeinit(ctx);

    outLen = sizeof(out);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x, pt1->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outLen = cipher->len - pt1->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x + pt1->len, pt2->len, out + pt1->len, &outLen) ==
        CRYPT_SUCCESS);
    outLen = cipher->len - pt1->len - pt2->len;
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, cipher->x + pt1->len + pt2->len, pt3->len, out + pt1->len + pt2->len, &outLen) ==
    CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out, pt1->x, pt1->len) == 0);
    ASSERT_TRUE(memcmp(out + pt1->len, pt2->x, pt2->len) == 0);
    ASSERT_TRUE(memcmp(out + pt1->len + pt2->len, pt3->x, pt3->len) == 0);
    ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */