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
#include "pthread.h"
#include "securec.h"
#include "eal_cipher_local.h"

#define BLOCKSIZE 16
#define KEYSIZE 32
#define MAXSIZE 1024
#define MAX_OUTPUT 5000
#define MAX_DATASZIE 20000

/* END_HEADER */

static int SetPadding(int isSetPadding, CRYPT_EAL_CipherCtx *ctxEnc, int padding)
{
    if (isSetPadding == 1) {
        return CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    }
    return CRYPT_SUCCESS;
}

static int Sm4CipherFinal(
    int algId,  CRYPT_EAL_CipherCtx *ctx, uint8_t *outTmp, uint32_t *finLen)
{
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        return CRYPT_EAL_CipherFinal(ctx, outTmp, finLen);
    }
    *finLen = 0;
    return CRYPT_SUCCESS;
}

/**
 * @test  SDV_CRYPTO_SM4_INIT_API_TC001
 * @title  Impact of IV validity on algorithm module initialization Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface, ctx is not NULL, iv is NULL, ivLen is 0, and key is normal value. Expected result 2 is obtained.
 *    3.Call the Init interface, ctx is not NULL, iv is not NULL, ivLen is 0, and key is normal value. Expected result 3 is obtained.
 *    4.Call the Init interface, ctx is not NULL, iv is not NULL, ivLen is 15, and key is normal value. Expected result 4 is obtained.
 *    5.Call the Init interface, ctx is not NULL, iv is not NULL, ivLen is 17, and key is normal value. Expected result 5 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Failed.
 *    3.Failed.
 *    4.Failed except for the GCM algorithm.
 *    5.Failed except for the GCM algorithm.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_INIT_API_TC001(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, NULL, 0, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 0, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, BLOCKSIZE - 1, true);
    if (id == CRYPT_CIPHER_SM4_GCM) {
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    } else {
        ASSERT_TRUE(ret != CRYPT_SUCCESS);
    }
    if (id == CRYPT_CIPHER_SM4_GCM) {
        ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, BLOCKSIZE, true);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    } else {
        ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, BLOCKSIZE + 1, true);
        ASSERT_TRUE(ret != CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_INIT_API_TC002
 * @title Impact of input parameters on the CRYPT_EAL_CipherInit interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx with CRYPT_CIPHER_SM4_XTS. Expected result 1 is obtained.
 *    2.Call the Init interface, ctx is NULL. Expected result 2 is obtained.
 *    3.Call the Init interface, ctx is not NULL, key is NULL. Expected result 3 is obtained.
 *    4.Call the Init interface, ctx is not NULL, key is not NULL, iv is NULL. Expected result 4 is obtained.
 *    5.Call the Init interface, ctx, key and iv is not NULL, keyLen is less than or greater than 32 bytes. Expected result 5 is obtained.
 *    6.Call the Init interface, ctx, key and iv is not NULL, keyLen is 32 bytes and the previous and next 16 bytes are the same. Expected result 6 is obtained.
 *    7.Call the Init interface, ctx, key and iv is not NULL, ivLen is less than or greater than 16 bytes. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Initialization failed.
 *    3.Initialization failed.
 *    4.Initialization failed.
 *    5.Initialization failed.
 *    6.Initialization failed.
 *    7.Initialization failed.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_INIT_API_TC002(Hex *key, Hex *iv, int enc)
{
    uint8_t unsafe_key[KEYSIZE] = {0};
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(NULL, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherInit(ctx, NULL, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, NULL, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_CipherInit(ctx, key->x, 0, iv->x, iv->len, enc);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, 1, iv->x, iv->len, enc);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, 16, iv->x, iv->len, enc);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, 33, iv->x, iv->len, enc);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, unsafe_key, KEYSIZE, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, unsafe_key, KEYSIZE, iv->x, iv->len, false);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 0, enc), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 1, enc), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 15, enc), CRYPT_MODES_IVLEN_ERROR);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 17, enc), CRYPT_MODES_IVLEN_ERROR);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_INIT_API_TC003
 * @title  Impact of key validity on algorithm module initialization Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface, ctx is NULL. Expected result 2 is obtained.
 *    3.Call the Init interface, ctx is not NULL, key is NULL, keyLen is 0. Expected result 3 is obtained.
 *    4.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is 0. Expected result 4 is obtained.
 *    5.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is 15. Expected result 5 is obtained.
 *    6.Call the Init interface, ctx is not NULL, key is not NULL, keyLen is 17. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Initialization failed.
 *    3.Initialization failed.
 *    4.Initialization failed.
 *    5.Initialization failed.
 *    6.Initialization failed.
*/
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_INIT_API_TC003(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(NULL, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherInit(ctx, NULL, 0, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, 0, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, BLOCKSIZE - 1, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, BLOCKSIZE + 1, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_DEINIT_API_TC001
 * @title  Impact of input parameters on the CRYPT_EAL_CipherDeinit interface Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Deinit interface, ctx is NULL. Expected result 2 is obtained.
 *    3.Call the Deinit interface. All parameters are normal. Expected result 3 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The function is executed successfully.
 *    3.The function is executed successfully.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_DEINIT_API_TC001(int id)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherDeinit(NULL);
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_REINIT_API_TC001
 * @title  CRYPT_EAL_CipherReinit for iv Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Reinit interface. Expected result 2 is obtained.
 *    3.Call the Init interface. Expected result 3 is obtained.
 *    4.Call the Reinit interface, ctx is NULL, iv is not NULL, ivLen is not 0. Expected result 4 is obtained.
 *    5.Call the Reinit interface, ctx is not NULL, iv is NULL, ivLen is not 0. Expected result 5 is obtained.
 *    6.Call the Reinit interface, ctx is not NULL, iv is not NULL, ivLen is 0. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.Failed. Return CRYPT_EAL_ERR_STATE.
 *    3.The init is successful and return CRYPT_SUCCESS.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Failed. Return CRYPT_NULL_INPUT.
 *    6.Failed. Return CRYPT_NULL_INPUT/CRYPT_MODES_IVLEN_ERROR.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_REINIT_API_TC001(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(NULL, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherReinit(ctx, NULL, iv->len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, 0);
    if (id == CRYPT_CIPHER_SM4_GCM) {
        ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    } else {
        ASSERT_TRUE(ret == CRYPT_MODES_IVLEN_ERROR);
    }
EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_UPDATE_API_TC001
 * @title  Impact of input parameters on the CRYPT_EAL_CipherUpdate interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface, ctx is NULL. Expected result 3 is obtained.
 *    4.Call the Update interface, ctx is not NULL, in is NULL. Expected result 4 is obtained.
 *    5.Call the Update interface, ctx is not NULL, in is not NULL, out is NULL. Expected result 5 is obtained.
 *    6.Call the Update interface, ctx, in, out is NULL, inLen is 1. Expected result 6 is obtained.
 *    7.Call the Update interface, ctx, in, out is NULL, outLen is NULL. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Failed. Return CRYPT_NULL_INPUT.
 *    4.Failed. Return CRYPT_NULL_INPUT.
 *    5.Failed. Return CRYPT_NULL_INPUT.
 *    6.Failed When is the XTS algorithm.
 *    7.Failed. Return CRYPT_NULL_INPUT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_UPDATE_API_TC001(int id, Hex *key, Hex *iv, Hex *in, int enc)
{
    TestMemInit();
    int32_t ret;
    uint8_t out[BLOCKSIZE * 32] = {0};
    uint32_t len = BLOCKSIZE * 32;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    len = BLOCKSIZE * 32;
    ret = CRYPT_EAL_CipherUpdate(NULL, in->x, in->len, out, &len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    len = BLOCKSIZE * 32;
    ret = CRYPT_EAL_CipherUpdate(ctx, NULL, in->len, out, &len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    len = BLOCKSIZE * 32;
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, NULL, &len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);

    len = BLOCKSIZE * 32;
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, 0, out, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    len = BLOCKSIZE * 32;
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, 1, out, &len);
    if (id == CRYPT_CIPHER_SM4_XTS) {
        ASSERT_TRUE(ret != CRYPT_SUCCESS);
    } else {
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }

    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, out, NULL);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    len = BLOCKSIZE * 32;
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, out, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(len == in->len);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_CTRL_API_TC001
 * @title  Impact of the setting type on the Ctrl setting parameters Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface, iv is IV1. Expected result 2 is obtained.
 *    3.Call the Ctrl interface to get iv. Expected result 3 is obtained.
 *    4.Call the Update interface to encrypt, inLen is 15. Expected result 4 is obtained.
 *    5.Call the Ctrl interface to get iv. Expected result 5 is obtained.
 *    6.Call the Update interface to encrypt, inLen is 1. Expected result 6 is obtained.
 *    7.Call the Ctrl interface to get iv, record as IV2. Expected result 7 is obtained.
 *    8.Call the Update interface to encrypt, inLen is 16. Expected result 8 is obtained.
 *    9.Call the Ctrl interface to get iv. Expected result 9 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Iv value is equal to IV1.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Iv value is equal to IV1.
 *    6.Success. Return CRYPT_SUCCESS.
 *    7.Iv value is not equal to IV1.
 *    8.Success. Return CRYPT_SUCCESS.
 *    9.Iv value is not equal to IV2.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_CTRL_API_TC001(Hex *key, Hex *iv, Hex *msg)
{
    TestMemInit();
    int32_t ret;
    uint8_t iv1[BLOCKSIZE] = {0};
    uint8_t iv2[BLOCKSIZE] = {0};
    const uint32_t len = BLOCKSIZE;
    uint8_t out[MAXSIZE] = {0};
    uint32_t outlen = MAXSIZE;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, iv->x, iv->len), CRYPT_MODES_CTRL_TYPE_ERROR);

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv1, len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv1, iv->x, iv->len) == 0);
    (void)memset_s(iv1, BLOCKSIZE, 0, BLOCKSIZE);

    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, BLOCKSIZE - 1, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv1, len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv1, iv->x, iv->len) == 0);
    (void)memset_s(iv1, BLOCKSIZE, 0, BLOCKSIZE);

    outlen = MAXSIZE;
    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, 1, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv1, len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv1, iv->x, iv->len) != 0);

    outlen = MAXSIZE;
    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, BLOCKSIZE, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv2, len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv2, iv1, BLOCKSIZE) != 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test  SDV_CRYPTO_SM4_CTRL_API_TC003
 * @title  Impact of input parameters on the CRYPT_EAL_CipherCtrl interface Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Ctrl interface, ctx is not NULL, type is get iv, other parameters are normal. Expected result 3 is obtained.
 *    4.Call the Ctrl interface, ctx is not NULL, type is get blocksize, other parameters are normal. Expected result 4 is obtained.
 *    5.Call the Ctrl interface, ctx is not NULL, type is get iv, data is NULL, len is 16. Expected result 5 is obtained.
 *    6.Call the Ctrl interface, ctx is not NULL, type is get iv, data is not NULL, len is 0. Expected result 6 is obtained.
 *    7.Call the Ctrl interface, ctx is not NULL, type is get blocksize, data is not NULL, len is 0. Expected result 7 is obtained.
 *    8.Call the Ctrl interface, ctx is not NULL, type is invalid value. Expected result 8 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. Return CRYPT_SUCCESS.
 *    4.Success. Return CRYPT_SUCCESS.
 *    5.Failed. Return CRYPT_NULL_INPUT.
 *    6.Failed. Return CRYPT_MODE_ERR_INPUT_LEN.
 *    7.Failed. Return CRYPT_MODE_ERR_INPUT_LEN.
 *    8.Failed. CRYPT_MODES_METHODS_NOT_SUPPORT.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_CTRL_API_TC003(Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    uint8_t *ivGet[BLOCKSIZE] = {0};
    const uint32_t len = BLOCKSIZE;
    uint32_t blockSizeGet = 0;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, ivGet, len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, (uint8_t *)&blockSizeGet, sizeof(uint32_t));
    ASSERT_TRUE(blockSizeGet == 1);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, NULL, len);
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, ivGet, 0), CRYPT_MODE_ERR_INPUT_LEN);

    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_BLOCKSIZE, (uint8_t *)&blockSizeGet, 0),
        CRYPT_MODE_ERR_INPUT_LEN);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_MAX, iv->x, iv->len), CRYPT_MODES_CTRL_TYPE_ERROR);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC001
 * @title  Call Final interface without call Update interface Test.
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Set the following padding algorithm CRYPT_PADDING_PKCS7 CRYPT_PADDING_PKCS5 CRYPT_PADDING_X923 CRYPT_PADDING_ISO7816 CRYPT_PADDING_ZEROS. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 *    5.Use the SM4 decryption handle to call the Update interface with the ciphertext. Expected result 5 is obtained.
 *    6.Call the Final interface. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.Succeeded in setting the padding algorithm.
 *    4.The ciphertext is consistent with the test vector.
 *    5.The update is successful, return CRYPT_SUCCESS.
 *    6.The plaintext is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC001(int id, Hex *key, Hex *iv, int padding, int isSetPadding)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAXSIZE] = {0};
    uint8_t result[MAXSIZE] = {0};
    uint32_t totalLen = 0;
    uint32_t decLen = MAXSIZE;
    uint32_t len = MAXSIZE;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ctxEnc = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ctxDec = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxDec, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp, len, result, &decLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += decLen;
    decLen = MAXSIZE - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + totalLen, &decLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

 /**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC002
 * @title  Encryption and decryption with setting padding algorithm Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Set the following padding algorithm CRYPT_PADDING_PKCS7 CRYPT_PADDING_PKCS5 CRYPT_PADDING_X923 CRYPT_PADDING_ISO7816 CRYPT_PADDING_ZEROS. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Use the SM4 decryption handle to call the Update interface with the ciphertext. Expected result 6 is obtained.
 *    7.Call the Final interface. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Succeeded in setting the padding algorithm.
 *    4.The update is successful and return CRYPT_SUCCESS.
 *    5.The ciphertext is consistent with the test vector.
 *    6.The update is successful and return CRYPT_SUCCESS.
 *    7.The plaintext is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC002(int algId, Hex *key, Hex *iv, int inLen, int padding)
{
    TestMemInit();
    uint8_t input[MAXSIZE] = {0};
    uint8_t outTmp[MAXSIZE] = {0};
    uint8_t result[MAXSIZE] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAXSIZE;
    uint32_t len = MAXSIZE;

    (void)memset_s(outTmp, MAXSIZE, 0xAA, MAXSIZE);
    (void)memset_s(input, MAXSIZE, 0xAA, MAXSIZE);
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ASSERT_TRUE(inLen <= MAXSIZE);
    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_CipherSetPadding(ctxEnc, padding), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctxEnc, input, inLen, outTmp, &len), CRYPT_SUCCESS);

    totalLen += len;
    leftLen -= len;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen), CRYPT_SUCCESS);
    totalLen += leftLen;

    len = MAXSIZE;
    leftLen = MAXSIZE;
    ctxDec = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxDec != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherSetPadding(ctxDec, padding), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctxDec, outTmp, totalLen, result, &len), CRYPT_SUCCESS);
    leftLen -= len;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen), CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(input, result, inLen) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC003
 * @title Input data of different lengths encryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC003(int isProvider, int id, Hex *key, Hex *plainText, Hex *cipherText, Hex *iv)
{
    if (IsSm4AlgDisabled(id)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint8_t out[MAXSIZE] = {0};
    uint32_t len = plainText->len;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, id, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plainText->x, plainText->len, out, &len), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out, cipherText->x, len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC004
 * @title  Input data of different lengths decryption Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC004(int isProvider, int id, Hex *key, Hex *plainText, Hex *cipherText, Hex *iv)
{
    if (IsSm4AlgDisabled(id)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t out[MAXSIZE] = {0};
    uint32_t len = cipherText->len;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, id, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, cipherText->x, cipherText->len, out, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out, plainText->x, len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_MULTI_UPDATE_TC001
 * @title  Multi update encryption and decryption
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface with plaintext for multi times. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 *    5.Use the SM4 decryption handle to call the Update interface with the ciphertext. Expected result 5 is obtained.
 *    6.Call the Final interface. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The final is successful, return CRYPT_SUCCESS. The cipher result is consistent with the test vector.
 *    5.The update is successful, return CRYPT_SUCCESS.
 *    6.The final is successful, return CRYPT_SUCCESS. The plain result is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_MULTI_UPDATE_TC001(int algId, Hex *key, Hex *iv, Hex *in, int updateTimes, int padding,
    int isSetPadding)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAXSIZE * 4] = {0};
    uint8_t result[MAXSIZE * 4] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAXSIZE * 4;
    uint32_t len = MAXSIZE * 4;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    for (int i = 0; i < updateTimes; i++) {
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, in->len, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
    }
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;

    len = MAXSIZE * 4;
    leftLen = MAXSIZE * 4;
    ctxDec = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp, totalLen, result, &len);
    leftLen -= len;
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(in->x, result, in->len) == 0);
    ASSERT_TRUE(memcmp(in->x, result + in->len, in->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_MULTI_UPDATE_TC002
 * @title  Multi update with different data length in encryption and decryption
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface with plaintext for 5 times. The length of the first, third, and fifth plaintext is 15 bytes.
 *      The length of the second and fourth plaintexts is 16 bytes. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 *    5.Use the SM4 decryption handle to call the Update interface with the ciphertext. Expected result 5 is obtained.
 *    6.Call the Final interface. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The final is successful, return CRYPT_SUCCESS. The cipher result is consistent with the test vector.
 *    5.The update is successful, return CRYPT_SUCCESS.
 *    6.The final is successful, return CRYPT_SUCCESS. The plain result is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_MULTI_UPDATE_TC002(int algId, Hex *key, Hex *iv, Hex *in, int padding, int isSetPadding)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAXSIZE] = {0};
    uint8_t result[MAXSIZE] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAXSIZE;
    uint32_t len = MAXSIZE;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ASSERT_TRUE(in->len >= BLOCKSIZE);
    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    for (uint32_t i = 0; i < 2; i++) { // 15bytes + 16bytes, run two times.
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, BLOCKSIZE - 1, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, BLOCKSIZE, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
    }
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, BLOCKSIZE - 1, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen -= len;
    len = leftLen;
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;

    len = MAXSIZE;
    leftLen = MAXSIZE;
    ctxDec = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp, totalLen, result, &len);
    leftLen -= len;
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(in->x, result, BLOCKSIZE - 1) == 0);
    ASSERT_TRUE(memcmp(in->x, result + BLOCKSIZE - 1, BLOCKSIZE) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_CTRL_API_TC004
 * @title  Obtaining the IV through the Ctrl interface Test in encryption
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Call the init interface to set the IV and call interface to obtain the IV. Expected result 1 is obtained.
 * @expect
 *    1.The two IVs are consistent.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_CTRL_API_TC004(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    uint8_t niv[BLOCKSIZE] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, niv, iv->len);
    ASSERT_TRUE(memcmp(niv, iv->x, iv->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_CTRL_API_TC005
 * @title  Obtaining the IV through the Ctrl interface Test in decryption
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the init interface to set the IV and call interface to obtain the IV. Expected result 1 is obtained.
 * @expect
 *    1.The two IVs are consistent.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_CTRL_API_TC005(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    uint8_t niv[BLOCKSIZE] = {0};

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, niv, iv->len);
    ASSERT_TRUE(memcmp(niv, iv->x, iv->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_REINIT_API_TC002
 * @title  Impact of input parameter validity on the iv reset interface Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface, iv is NULL, iv len is 0. Expected result 2 is obtained.
 *    3.Call the Reinit interface, iv is NULL, iv len is 0. Expected result 3 is obtained.
 *    4.Call the Reinit interface, iv is not NULL, iv len is 0. Expected result 4 is obtained.
 *    5.Call the Reinit interface, iv is not NULL, iv len is 15. Expected result 5 is obtained.
 *    6.Call the Reinit interface, iv is not NULL, iv len is 17. Expected result 6 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.The interface returns a failure.
 *    4.The interface returns a failure.
 *    5.The interface returns a failure.
 *    6.The interface returns a failure.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_REINIT_API_TC002(int algId, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, NULL, 0, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, NULL, 0);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, 0);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, BLOCKSIZE - 1);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, BLOCKSIZE + 1);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC005
 * @title  Data encryption and decryption after reinit Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 *    4.Call the Reinit interface. Expected result 4 is obtained.
 *    5.Call the Update interface. Expected result 5 is obtained.
 *    6.Call the Reinit interface. Expected result 6 is obtained.
 *    7.Call the Update interface. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.Success. The ciphertext is as expected.
 *    4.The reinit is successful and return CRYPT_SUCCESS.
 *    5.Success. The ciphertext is as expected.
 *    6.The reinit is successful and return CRYPT_SUCCESS.
 *    7.Success. The ciphertext is as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC005(int isProvider, Hex *key, Hex *in1, Hex *out1,
    Hex *iv1, Hex *in2, Hex *out2, Hex *iv2, int enc)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAXSIZE] = {0};
    uint32_t len = MAXSIZE;

    CRYPT_EAL_CipherCtx *ctx = TestCipherNewCtx(NULL, CRYPT_CIPHER_SM4_XTS, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv1->x, iv1->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in1->x, in1->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out1->x, out1->len) == 0);

    (void)memset_s(outTmp, MAXSIZE, 0, MAXSIZE);
    len = MAXSIZE;
    ret = CRYPT_EAL_CipherReinit(ctx, iv2->x, iv2->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in2->x, in2->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out2->x, out2->len) == 0);

    (void)memset_s(outTmp, MAXSIZE, 0, MAXSIZE);
    len = MAXSIZE;
    ret = CRYPT_EAL_CipherReinit(ctx, iv1->x, iv1->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in1->x, in1->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out1->x, out1->len) == 0);
EXIT:
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

void SM4_MultiThreadTest(void *arg)
{
    TestVector *pTestVector = (TestVector *)arg;
    int32_t ret;
    uint8_t outTmp[MAXSIZE] = {0};
    uint32_t len = MAXSIZE;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(pTestVector->algId);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, pTestVector->key, pTestVector->keyLen, pTestVector->iv, pTestVector->ivLen,
        pTestVector->enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, pTestVector->in, pTestVector->inLen, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, pTestVector->out, pTestVector->outLen) == 0);

EXIT:
    CRYPT_EAL_CipherDeinit(ctx);
    CRYPT_EAL_CipherFreeCtx(ctx);
}

/**
 * @test  SDV_CRYPTO_SM4_MULTI_THREAD_TC001
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
void SDV_CRYPTO_SM4_MULTI_THREAD_TC001(int algId, Hex *key, Hex *in, Hex *out, Hex *iv, int enc)
{
#define THREAD_NUM 3
    TestMemInit();
    int32_t ret;
    pthread_t thrd[THREAD_NUM];
    TestVector testVt = {
        .algId = algId,
        .key = key->x,
        .keyLen = key->len,
        .iv = iv->x,
        .ivLen = iv->len,
        .in = in->x,
        .inLen = in->len,
        .out = out->x,
        .outLen = out->len,
        .enc = enc
    };

    for (uint32_t i = 0; i < THREAD_NUM; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)SM4_MultiThreadTest, &testVt);
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
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC006
 * @title  Impact of the msg with no padding on the Update interface Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface with plain len is 17. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful and return CRYPT_SUCCESS.
 *    3.The Update is successful.
 *    4.The Final is failed.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC006(int id, Hex *key, Hex *iv, Hex *msg, int enc)
{
    TestMemInit();
    int32_t ret;
    uint8_t out[MAX_OUTPUT] = {0};
    uint32_t outlen = MAX_OUTPUT;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(msg->len == BLOCKSIZE + 1);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, msg->len, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    outlen = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherFinal(ctx, out, &outlen);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC007
 * @title  Update 0 message length Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface, data is NULL, dataLen is 0. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The Update is successful.
 *    4.The outlen is consistent with expect.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC007(int id, Hex *key, Hex *iv, int enc)
{
    TestMemInit();
    int32_t ret;
    uint8_t out[MAX_OUTPUT] = {0};
    uint32_t outlen = MAX_OUTPUT;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, NULL, 0, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (id != CRYPT_CIPHER_SM4_GCM) {
        outlen = MAX_OUTPUT;
        ret = CRYPT_EAL_CipherFinal(ctx, out, &outlen);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(outlen == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC008
 * @title  Impact of updating IV on encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 *    5.Call the Reinit interface to update iv. Expected result 5 is obtained.
 *    6.Call the Update interface. Expected result 6 is obtained.
 *    7.Call the Final interface. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The final is successful, return CRYPT_SUCCESS. The result is consistent with the test vector.
 *    5.The reinit is successful, return CRYPT_SUCCESS.
 *    6.The update is successful, return CRYPT_SUCCESS.
 *    7.The final is successful, return CRYPT_SUCCESS. The result is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC008(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
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
    ret = Sm4CipherFinal(algId, ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_COMPARE("Cipher compare", out->x, out->len, outTmp, len + finLen);

    (void)memset_s(outTmp, MAX_OUTPUT, 0, MAX_OUTPUT);
    len = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = Sm4CipherFinal(algId, ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_COMPARE("Cipher compare", out->x, out->len, outTmp, len + finLen);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC009
 * @title  Impact of updating IV and Key on encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 *    5.Call the Init interface to update iv and key. Expected result 5 is obtained.
 *    6.Call the Update interface. Expected result 6 is obtained.
 *    7.Call the Final interface. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The final is successful, return CRYPT_SUCCESS. The result is consistent with the test vector.
 *    5.The Init is successful, return CRYPT_SUCCESS.
 *    6.The update is successful, return CRYPT_SUCCESS.
 *    7.The final is successful, return CRYPT_SUCCESS. The result is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC009(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
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
    ret = Sm4CipherFinal(algId, ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);

    (void)memset_s(outTmp, MAX_OUTPUT, 0, MAX_OUTPUT);
    len = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = Sm4CipherFinal(algId, ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */


/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC010
 * @title  Impact of the padding algorithm on encryption and decryption Test
 * @precon  Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the set padding interface with CRYPT_PADDING_PKCS7, CRYPT_PADDING_PKCS5, CRYPT_PADDING_X923
 *      CRYPT_PADDING_ISO7816, CRYPT_PADDING_ZEROS, CRYPT_PADDING_NONE. Expected result 3 is obtained.
 *    4.Call the Update interface. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Use the SM4 decryption handle to call the Update interface with the ciphertext. Expected result 6 is obtained.
 *    7.Call the Final interface. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The setting is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS.
 *    6.The update is successful, return CRYPT_SUCCESS.
 *    7.The final is successful, and the plaintext is consistent with the origin data.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC010(int algId, Hex *key, Hex *iv, int inLen, int padding)
{
    TestMemInit();
    int32_t ret;
    uint8_t input[MAX_DATASZIE] = {0};
    uint8_t outTmp[MAX_DATASZIE] = {0};
    uint8_t result[MAX_DATASZIE] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_DATASZIE;
    uint32_t len = MAX_DATASZIE;

    (void)memset_s(outTmp, MAX_DATASZIE, 0xAA, MAX_DATASZIE);
    (void)memset_s(input, MAX_DATASZIE, 0xAA, MAX_DATASZIE);
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ASSERT_TRUE(inLen <= MAX_DATASZIE);
    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, input, inLen, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen -= len;
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;

    len = MAX_DATASZIE;
    leftLen = MAX_DATASZIE;
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

    ASSERT_TRUE(memcmp(input, result, inLen) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC011
 * @title  The input and output start addresses are the same Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface. Expected result 2 is obtained.
 *    3.Call the set padding interface. Expected result 3 is obtained.
 *    4.Call the Update interface with the input and output buff are same. Expected result 4 is obtained.
 *    5.Call the Final interface. Expected result 5 is obtained.
 *    6.Use the SM4 decryption handle to call the Update interface with the ciphertext. Expected result 6 is obtained.
 *    7.Call the Final interface. Expected result 7 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The setting is successful, return CRYPT_SUCCESS.
 *    4.The update is successful, return CRYPT_SUCCESS.
 *    5.The final is successful, return CRYPT_SUCCESS.
 *    6.The update is successful, return CRYPT_SUCCESS.
 *    7.The final is successful, and the plaintext is consistent with the origin data.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC011(int algId, Hex *key, Hex *iv, int inLen, int padding, int isSetPadding)
{
    TestMemInit();
    int32_t ret;
    uint8_t input[MAX_DATASZIE] = {0};
    uint8_t outTmp[MAX_DATASZIE] = {0};
    uint8_t result[MAX_DATASZIE] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_DATASZIE;
    uint32_t len = MAX_DATASZIE;

    (void)memset_s(outTmp, MAX_DATASZIE, 0xAA, MAX_DATASZIE);
    (void)memset_s(input, MAX_DATASZIE, 0xAA, MAX_DATASZIE);
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ASSERT_TRUE(inLen <= MAX_DATASZIE);
    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, outTmp, inLen, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen -= len;
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += leftLen;
    }

    len = MAX_OUTPUT;
    leftLen = MAX_OUTPUT;
    ctxDec = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = SetPadding(isSetPadding, ctxDec, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp, totalLen, result, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    leftLen -= len;
    ret = Sm4CipherFinal(algId, ctxDec, result + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(input, result, inLen) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC012
 * @title Impact of the key and iv of all 0s/all Fs on encryption and decryption Test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Create the context ctx. Expected result 1 is obtained.
 *    2.Call the Init interface, with key and iv of all 0s/all Fs. Expected result 2 is obtained.
 *    3.Call the Update interface. Expected result 3 is obtained.
 *    4.Call the Final interface. Expected result 4 is obtained.
 * @expect
 *    1.The creation is successful and the ctx is not empty.
 *    2.The init is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The final is successful, and the result is consistent with expect.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC012(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
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
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    len = MAX_OUTPUT - len;
    if (algId != CRYPT_CIPHER_SM4_GCM){
        ret = CRYPT_EAL_CipherFinal(ctx, outTmp + totalLen, &len);
        totalLen += len;
        ASSERT_TRUE(totalLen == out->len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC013
 * @title  SM4-GCM encryption full vector test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the Ctrl interface to set parameters. Expected result 2 is obtained.
 *    3.Call the update interface to update message. Expected result 3 is obtained.
 *    4.Call the Ctrl interface to get tag. Expected result 4 is obtained.
 *    5.Compare the ciphertext data. Expected result 5 is obtained.
 *    6.Compare the tag data. Expected result 6 is obtained.
 * @expect
 *    1.The init is successful, return CRYPT_SUCCESS.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The getting is successful, return CRYPT_SUCCESS.
 *    5.Ciphertext is consistent with the test vector.
 *    6.Tag is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC013(Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *ct, Hex *tag, int enc)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *outTag = NULL;
    uint8_t *out = NULL;
    uint32_t tagLen = tag->len;
    uint32_t outLen;

    if (ct->len > 0) {
        out = (uint8_t *)BSL_SAL_Malloc(ct->len * sizeof(uint8_t));
        outLen = ct->len * sizeof(uint8_t);
        ASSERT_TRUE(out != NULL);
    } else {
        out = (uint8_t *)BSL_SAL_Malloc(1 * sizeof(uint8_t));
        outLen = 1 * sizeof(uint8_t);
        ASSERT_TRUE(out != NULL);
    }

    ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_GCM);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outTag = (uint8_t *)BSL_SAL_Malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);

    if (ct->x != NULL) {
        ASSERT_TRUE(memcmp(out, ct->x, ct->len) == 0);
    }
    ASSERT_COMPARE("Compare Tag", outTag, tagLen, tag->x, tag->len);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    free(out);
    free(outTag);
}
/* END_CASE */


/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC014
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
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC014(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int padding)
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

EXIT:
    CRYPT_EAL_CipherDeinit(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC015
 * @title  Decryption in different padding modes Test
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
void SDV_CRYPTO_SM4_ENCRYPT_FUNC_TC015(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int padding)
{
    TestMemInit();
    uint8_t result[MAX_OUTPUT] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    len = MAX_OUTPUT;
    leftLen = MAX_OUTPUT;
    ctxDec = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctxDec != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherSetPadding(ctxDec, padding), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctxDec, in->x, in->len, result, &len), CRYPT_SUCCESS);
    totalLen += len;
    leftLen = leftLen - len;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen), CRYPT_SUCCESS);

    totalLen += leftLen;

    ASSERT_TRUE(totalLen == out->len);
    ASSERT_TRUE(memcmp(out->x, result, out->len) == 0);

EXIT:
    CRYPT_EAL_CipherDeinit(ctxDec);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_SM4_CCM_TC001  
 * @title  SM4-CCM KAT test from RFC8998
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_CCM_TC001(int isProvider, int algId, Hex *key, Hex *iv, Hex *aad, Hex *in, Hex *out, Hex *tag)
{
    TestMemInit();
    uint8_t result[MAX_OUTPUT] = {0};
    uint8_t outTag[16] = {0};
    uint32_t outTagLen = 16;
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    len = MAX_OUTPUT;
    leftLen = MAX_OUTPUT;
    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &outTagLen, sizeof(outTagLen)), CRYPT_SUCCESS);
    uint64_t msgLen = in->len;
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_MSGLEN, &msgLen, sizeof(msgLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, result, &len), CRYPT_SUCCESS);
    totalLen += len;
    leftLen = leftLen - len;
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, outTag, outTagLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("Compare ciphertext", result, out->len, out->x, out->len);
    ASSERT_COMPARE("Compare Tag", outTag, outTagLen, tag->x, tag->len);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_SM4_HCTR_FUNC_TC001
 * @title  HCTR mode encryption and decryption functional test against standard vector
 * @precon HCTR mode implementation is complete and registered.
 * @brief
 * 1. Init HCTR context for encryption with standard key and tweak.
 * 2. Call Update to buffer all plaintext; assert output length is 0.
 * 3. Call Final to perform encryption and get the full ciphertext.
 * 4. Compare the result with the expected ciphertext from GB/T 17964-2021.
 * 5. Repeat the process for decryption.
 * @expect
 * All steps succeed and the results match the test vectors.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_SM4_HCTR_FUNC_TC001(int isProvider, int algId, Hex *key, Hex *tweak, Hex *plain, Hex *cipher)
{
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *outTmp = NULL;
    uint8_t *decryptedTmp = NULL;
    uint32_t outLen = 0;
    int32_t ret;

    outTmp = (uint8_t *)BSL_SAL_Malloc(plain->len);
    ASSERT_TRUE(outTmp != NULL);

    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(key->len, 32);
    ASSERT_EQ(tweak->len, 16);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, tweak->x, tweak->len, true);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    outLen = plain->len;
    ret = CRYPT_EAL_CipherUpdate(ctx, plain->x, plain->len, outTmp, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(outLen, 0);

    outLen = plain->len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(outLen, plain->len);
    
    ASSERT_COMPARE("HCTR Encrypt Compare", cipher->x, cipher->len, outTmp, outLen);

    CRYPT_EAL_CipherFreeCtx(ctx);
    ctx = NULL;
    BSL_SAL_Free(outTmp);
    outTmp = NULL;

    decryptedTmp = (uint8_t *)BSL_SAL_Malloc(cipher->len);
    ASSERT_TRUE(decryptedTmp != NULL);
    
    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, tweak->x, tweak->len, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    outLen = cipher->len;
    ret = CRYPT_EAL_CipherUpdate(ctx, cipher->x, cipher->len, decryptedTmp, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(outLen, 0);

    outLen = cipher->len;
    ret = CRYPT_EAL_CipherFinal(ctx, decryptedTmp, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(outLen, cipher->len);

    ASSERT_COMPARE("HCTR Decrypt Compare", plain->x, plain->len, decryptedTmp, outLen);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    if (outTmp != NULL) {
        BSL_SAL_Free(outTmp);
    }
    if (decryptedTmp != NULL) {
        BSL_SAL_Free(decryptedTmp);
    }
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_SM4_FUNC_TC005
 * @title  Verify whether SM4 encryption and decryption will alter the values of registers d8 to d15 and x19 to x28.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_SM4_FUNC_TC005(int algId, Hex *key, Hex *iv, Hex *pt)
{
#ifndef HITLS_CRYPTO_SM4_ARMV8
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

    double canary = 1.1;
    register double d8 asm("d8");
    register double d9 asm("d9");
    register double d10 asm("d10");
    register double d11 asm("d11");
    register double d12 asm("d12");
    register double d13 asm("d13");
    register double d14 asm("d14");
    register double d15 asm("d15");
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d8) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d9) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d10) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d11) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d12) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d13) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d14) : "w"(canary) :);
    asm volatile("fmov %d0, %d1 \n\t" : "=w"(d15) : "w"(canary) :);

    long value = 0x12345678;
    register int x19 asm("x19");
    register int x20 asm("x20");
    register int x21 asm("x21");
    register int x22 asm("x22");
    register int x23 asm("x23");
    register int x24 asm("x24");
    register int x25 asm("x25");
    register int x26 asm("x26");
    register int x27 asm("x27");
    register int x28 asm("x28");
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x19) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x20) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x21) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x22) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x23) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x24) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x25) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x26) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x27) : "r"(value) :);
    asm volatile("mov %x0, %x1 \n\t" : "=r"(x28) : "r"(value) :);

    // Encrypt
    ASSERT_TRUE((ctx = CRYPT_EAL_CipherNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    if (algId == CRYPT_CIPHER_SM4_GCM) {
        ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, cipher, &cipherLen), CRYPT_SUCCESS);
    if (algId != CRYPT_CIPHER_SM4_GCM) {
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
    if (algId != CRYPT_CIPHER_SM4_GCM) {
        finLen = MAX_OUTPUT - plainLen;
        ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, plain + plainLen, &finLen), CRYPT_SUCCESS);
        plainLen += finLen;
    }

    ASSERT_COMPARE("SM4:", plain, plainLen, pt->x, pt->len);
    CRYPT_EAL_CipherFreeCtx(ctx);
    ctx = NULL;
    ASSERT_TRUE(d8 == canary);
    ASSERT_TRUE(d9 == canary);
    ASSERT_TRUE(d10 == canary);
    ASSERT_TRUE(d11 == canary);
    ASSERT_TRUE(d12 == canary);
    ASSERT_TRUE(d13 == canary);
    ASSERT_TRUE(d14 == canary);
    ASSERT_TRUE(d15 == canary);
    ASSERT_TRUE(x19 == value);
    ASSERT_TRUE(x20 == value);
    ASSERT_TRUE(x21 == value);
    ASSERT_TRUE(x22 == value);
    ASSERT_TRUE(x23 == value);
    ASSERT_TRUE(x24 == value);
    ASSERT_TRUE(x25 == value);
    ASSERT_TRUE(x26 == value);
    ASSERT_TRUE(x27 == value);
    ASSERT_TRUE(x28 == value);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
#endif
}
