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

#include <string.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_local_types.h"
#include "crypt_aes.h"
#include "crypt_eal_cipher.h"

#define FREE(res) \
    do {                        \
        if ((res) != NULL) {        \
            BSL_SAL_Free(res);   \
        }                       \
    } while (0)

/* END_HEADER */

/**
 * @test  SDV_CRYPTO_AES_GCM_SIV_UPDATE_FUNC_TC001
 * @title  AES-GCM-SIV decryption full vector test (RFC 8452)
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the Ctrl interface to set parameters. Expected result 2 is obtained.
 *    3.Call the update interface with ciphertext || tag. Expected result 3 is obtained.
 *    4.Call the Ctrl interface to get tag. Expected result 4 is obtained.
 *    5.Compare the plaintext data. Expected result 5 is obtained.
 *    6.On success, tag matches the test vector.
 * @expect
 *    1.The init is successful, return CRYPT_SUCCESS.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.Getting tag succeeds.
 *    5.Plaintext is consistent with the test vector when verification succeeds.
 *    6.Tag output matches the test vector when verification succeeds.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_GCM_SIV_UPDATE_FUNC_TC001(int isProvider, int algId, Hex *key, Hex *iv,
    Hex *aad, Hex *pt, Hex *ct, Hex *tag)
{
#if !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_GHASH)
    SKIP_TEST();
#endif
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *outTag = NULL;
    uint8_t *out = NULL;
    uint8_t *combined = NULL;
    uint32_t tagLen = tag->len;
    uint32_t combLen = ct->len + tagLen;
    uint32_t outLen;

    if (pt->len > 0) {
        out = (uint8_t *)BSL_SAL_Malloc(pt->len * sizeof(uint8_t));
        outLen = pt->len * sizeof(uint8_t);
        ASSERT_TRUE(out != NULL);
    } else {
        out = (uint8_t *)BSL_SAL_Malloc(1 * sizeof(uint8_t));
        outLen = 1 * sizeof(uint8_t);
        ASSERT_TRUE(out != NULL);
    }

    ASSERT_TRUE(tagLen == 16); /* RFC 8452 / this implementation uses 16-byte tags */

    combined = (uint8_t *)BSL_SAL_Malloc(combLen == 0 ? 1u : combLen);
    ASSERT_TRUE(combined != NULL);
    if (ct->len > 0) {
        memcpy(combined, ct->x, ct->len);
    }
    if (tagLen > 0) {
        memcpy(combined + ct->len, tag->x, tagLen);
    }

    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, combined, combLen, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    outTag = (uint8_t *)BSL_SAL_Malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (pt->x != NULL && pt->len > 0) {
        ASSERT_TRUE(memcmp(out, pt->x, pt->len) == 0);
    }
    ASSERT_COMPARE("Compare Tag", outTag, tagLen, tag->x, tag->len);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    FREE(out);
    FREE(outTag);
    FREE(combined);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_GCM_SIV_UPDATE_FUNC_TC002
 * @title  AES-GCM-SIV encryption full vector test (RFC 8452)
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the Ctrl interface to set parameters. Expected result 2 is obtained.
 *    3.Call the update interface to buffer plaintext. Expected result 3 is obtained.
 *    4.Call the Ctrl interface to get tag (outputs ciphertext and tag). Expected result 4 is obtained.
 *    5.Compare the ciphertext and tag data. Expected result 5 is obtained.
 * @expect
 *    1.The init is successful, return CRYPT_SUCCESS.
 *    2.The setting is successful, return CRYPT_SUCCESS.
 *    3.The update is successful, return CRYPT_SUCCESS.
 *    4.The getting is successful, return CRYPT_SUCCESS.
 *    5.Ciphertext and tag are consistent with the test vector.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_GCM_SIV_UPDATE_FUNC_TC002(int isProvider, int algId, Hex *key, Hex *iv, Hex *aad, Hex *pt, Hex *ct,
    Hex *tag)
{
#if !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_GHASH)
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
    if (ct->len > 0 && ct->x != NULL) {
        ASSERT_TRUE(memcmp(out, ct->x, ct->len) == 0);
    }
    ASSERT_COMPARE("Compare Tag", outTag, tagLen, tag->x, tag->len);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    FREE(out);
    FREE(outTag);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_AES_GCM_SIV_UPDATE_FUNC_TC003
 * @title  AES-GCM-SIV decryption with CRYPT_CTRL_SET_TAG (ciphertext only in Update)
 * @precon Registering memory-related functions.
 * @brief
 *    1.Call the Init interface. Expected result 1 is obtained.
 *    2.Call the Ctrl interface to set parameters. Expected result 2 is obtained.
 *    3.Call Update with ciphertext only (no appended tag). Expected result 3 is obtained.
 *    4.Call CRYPT_CTRL_SET_TAG with the authentication tag. Expected result 4 is obtained.
 *    5.Call CRYPT_CTRL_GET_TAG to finish and verify. Expected result 5 is obtained.
 *    6.Compare plaintext and tag with the test vector.
 * @expect
 *    1–6.Success; plaintext and tag match RFC 8452 vectors.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_AES_GCM_SIV_UPDATE_FUNC_TC003(int isProvider, int algId, Hex *key, Hex *iv,
    Hex *aad, Hex *pt, Hex *ct, Hex *tag)
{
#if !defined(HITLS_CRYPTO_GCM) || !defined(HITLS_CRYPTO_GHASH)
    SKIP_TEST();
#endif
    TestMemInit();
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *outTag = NULL;
    uint8_t *out = NULL;
    uint32_t tagLen = tag->len;
    uint32_t outLen;

    if (pt->len > 0) {
        out = (uint8_t *)BSL_SAL_Malloc(pt->len * sizeof(uint8_t));
        outLen = pt->len * sizeof(uint8_t);
        ASSERT_TRUE(out != NULL);
    } else {
        out = (uint8_t *)BSL_SAL_Malloc(1 * sizeof(uint8_t));
        outLen = 1 * sizeof(uint8_t);
        ASSERT_TRUE(out != NULL);
    }

    ASSERT_TRUE(tagLen == 16);

    ctx = TestCipherNewCtx(NULL, algId, "provider=default", isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad->x, aad->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, ct->x, ct->len, (uint8_t *)out, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAG, tag->x, tagLen) == CRYPT_SUCCESS);
    outTag = (uint8_t *)BSL_SAL_Malloc(sizeof(uint8_t) * tagLen);
    ASSERT_TRUE(outTag != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, (uint8_t *)outTag, tagLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (pt->x != NULL && pt->len > 0) {
        ASSERT_TRUE(memcmp(out, pt->x, pt->len) == 0);
    }
    ASSERT_COMPARE("Compare Tag", outTag, tagLen, tag->x, tag->len);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    FREE(out);
    FREE(outTag);
}
/* END_CASE */