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

#define FREE(res) \
    do {                        \
        if ((res) != NULL) {        \
            free(res);   \
        }                       \
    } while (0)

/* END_HEADER */

/**
 * @test  SDV_CRYPTO_AES_GCM_UPDATE_FUNC_TC001
 * @title  AES-GCM decryption full vector test
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the Ctrl interface to set parameters. Expected result 2 is obtained.
 *    3.Call the update interface to update message. Expected result 3 is obtained.
 *    4.Call the Ctrl interface to get tag. Expected result 4 is obtained.
 *    5.Compare the plaintext data. Expected result 5 is obtained.
 *    6.Compare the tag data. Expected result 6 is obtained.
 * @expect
 *    1.The init is successful, return CRYPT_SUCCESS.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The getting is successful, return CRYPT_SUCCESS.
 *    5.Plaintext is consistent with the test vector.
 *    6.Tag is consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_GCM_UPDATE_FUNC_TC001(int isProvider, int algId, Hex *key, Hex *iv,
    Hex *aad, Hex *pt, Hex *ct, Hex *tag, int result)
{
#ifndef HITLS_CRYPTO_GCM
    SKIP_TEST();
#endif
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

    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, ct->x, ct->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outTag = (uint8_t *)BSL_SAL_Malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

    if (pt->x != NULL) {
        ASSERT_TRUE(memcmp(out, pt->x, pt->len) == 0);
    }

    if (result == 0) {
        ASSERT_COMPARE("Compare Tag", outTag, tagLen, tag->x, tag->len);
    } else {
        ASSERT_TRUE(memcmp(outTag, tag->x, tag->len) != 0);
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    FREE(out);
    FREE(outTag);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_GCM_UPDATE_FUNC_TC002
 * @title  AES-GCM encryption full vector test
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
void SDV_CRYPTO_AES_GCM_UPDATE_FUNC_TC002(int isProvider, int algId, Hex *key, Hex *iv,  Hex *aad, Hex *pt, Hex *ct, Hex *tag)
{
#ifndef HITLS_CRYPTO_GCM
    SKIP_TEST();
#endif
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

    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pt->x, pt->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outTag = (uint8_t *)BSL_SAL_Malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (ct->x != NULL) {
        ASSERT_TRUE(memcmp(out, ct->x, ct->len) == 0);
    }
    ASSERT_COMPARE("Compare Tag", outTag, tagLen, tag->x, tag->len);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    FREE(out);
    FREE(outTag);
}
/* END_CASE */
