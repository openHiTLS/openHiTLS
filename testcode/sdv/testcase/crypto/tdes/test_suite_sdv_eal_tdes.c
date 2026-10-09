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
#include "bsl_sal.h"
#include "securec.h"

#define MAX_OUTPUT 5000
#define MAX_DATASZIE 20000
#define DES_BLOCKSIZE 8
#define AES_BLOCKSIZE 16
#define MAX_BLOCKSIZE 16
#define BITS_PRE_BYTE 8
/* END_HEADER */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC001
* @spec  -
* @precon  nan
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC001(int id, Hex *key, Hex *iv)
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
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len - 1, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len + 1, iv->x, iv->len, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC002
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC002(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, NULL, 0, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, 0, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len - 1, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len + 1, true);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC003
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC003(int id, Hex *key, Hex *iv, Hex *msg)
{
    TestMemInit();
    int32_t ret;
    uint8_t iv1[MAX_BLOCKSIZE] = {0};
    uint8_t iv2[MAX_BLOCKSIZE] = {0};
    uint32_t blockSize = MAX_BLOCKSIZE;
    uint8_t out[MAX_OUTPUT] = {0};
    uint32_t outlen = MAX_OUTPUT;

    ASSERT_TRUE(msg->len == iv->len);
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_DES_CTRLTYPE_ERROR || ret == CRYPT_TDES_CTRLTYPE_ERROR);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_REINIT_STATUS, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_EAL_CIPHER_CTRL_ERROR);

    blockSize = iv->len;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv1, blockSize);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv1, iv->x, iv->len) == 0);
    (void)memset_s(iv1, MAX_BLOCKSIZE, 0, MAX_BLOCKSIZE);

    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, msg->len - 1, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv1, blockSize);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv1, iv->x, iv->len) == 0);
    (void)memset_s(iv1, MAX_BLOCKSIZE, 0, MAX_BLOCKSIZE);

    outlen = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, 1, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv1, blockSize);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv1, iv->x, iv->len) != 0);

    outlen = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, msg->len, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_IV, iv2, blockSize);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(iv2, iv1, iv->len) != 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC004
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC004(int id, Hex *key, Hex *iv, Hex *msg)
{
    TestMemInit();
    int32_t ret;
    uint32_t feedBackGet;
    uint32_t maxFeedBack = iv->len * BITS_PRE_BYTE;
    uint8_t out[MAX_OUTPUT] = {0};
    uint32_t outlen = MAX_OUTPUT;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, NULL, sizeof(uint32_t));
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, 0);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(feedBackGet == maxFeedBack);

    uint32_t feedBackSet = maxFeedBack + 1;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, NULL, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, 0);
    ASSERT_TRUE(ret == CRYPT_MODE_ERR_INPUT_LEN);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_MODES_ERR_FEEDBACKSIZE);

    feedBackSet = 1;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(feedBackGet == 1);

    feedBackGet = 0;
    ret = CRYPT_EAL_CipherUpdate(ctx, msg->x, msg->len, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(feedBackGet == 1);

    feedBackGet = 0;
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(feedBackGet == 1);

    feedBackGet = 0;
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, sizeof(uint32_t));
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(feedBackGet == maxFeedBack);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC005
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC005(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    uint32_t feedBackGet;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_FEEDBACKSIZE, &feedBackGet, sizeof(uint32_t));
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    uint32_t feedBackSet = 1;
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, sizeof(uint32_t));
    ASSERT_TRUE(ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC006
* @spec  -
* @precon  nan
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC006(int id, Hex *key, Hex *iv, int enc)
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
    outlen = MAX_OUTPUT;
    ret = CRYPT_EAL_CipherFinal(ctx, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(outlen == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC007
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC007(int algId, Hex *key, Hex *iv, Hex *in, int padding)
{
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
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen = leftLen - len;
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
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
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC008
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC008(int id, Hex *key, Hex *iv, int padding, int isSetPadding)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint8_t result[MAX_OUTPUT] = {0};
    uint32_t totalLen = 0;
    uint32_t decLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ctxEnc = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctxEnc != NULL);
    if (isSetPadding == 1) {
        ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ctxDec = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (isSetPadding == 1) {
        ret = CRYPT_EAL_CipherSetPadding(ctxDec, padding);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
    ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp, len, result, &decLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += decLen;
    decLen = MAX_OUTPUT - totalLen;
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + totalLen, &decLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC009
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC009(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    uint8_t out[MAX_OUTPUT] = {0};
    uint32_t outlen = MAX_OUTPUT;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctx, out, &outlen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(outlen == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC010
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC010(int id, Hex *key, Hex *iv, int blockSize)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);

    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, NULL, 0);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, 0);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, blockSize - 1);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherReinit(ctx, iv->x, blockSize + 1);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC011
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC011(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_API_TC012
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_API_TC012(int id, Hex *key, Hex *iv)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_DES_ERR_KEY || ret == CRYPT_TDES_ERR_KEY);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC002
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC002(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    (void)isProvider;
    if (IsCipherAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t finLen;
#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_CipherCtx *ctx = (isProvider == 0) ? CRYPT_EAL_CipherNewCtx(algId) :
        CRYPT_EAL_ProviderCipherNewCtx(NULL, algId, "provider=default");
#else
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
#endif
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
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC003
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC003(int isProvider, int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int enc)
{
    (void)isProvider;
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint32_t len = MAX_OUTPUT;
    uint32_t finLen;

#ifdef HITLS_CRYPTO_PROVIDER
    CRYPT_EAL_CipherCtx *ctx = (isProvider == 0) ? CRYPT_EAL_CipherNewCtx(algId) :
        CRYPT_EAL_ProviderCipherNewCtx(NULL, algId, "provider=default");
#else
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
#endif
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
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, enc);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, outTmp, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    finLen = MAX_OUTPUT - len;
    ret = CRYPT_EAL_CipherFinal(ctx, outTmp + len, &finLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(outTmp, out->x, out->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC004
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC004(int algId, Hex *key, Hex *iv, int inLen, int padding)
{
    if (IsCipherAlgDisabled(algId)) {
        SKIP_TEST();
    }
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
    totalLen = len;
    leftLen -= len;
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;
    // CRYPT_PADDING_ZEROS cannot obtain the encryption length. Therefore, the return value is not checked.
    if (padding != CRYPT_PADDING_ZEROS) {
        ASSERT_TRUE(totalLen == (uint32_t)inLen);
    }
    ASSERT_TRUE(memcmp(input, result, inLen) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC005
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC005(int algId, Hex *key, Hex *iv, int inLen, int padding, int isSetPadding)
{
    if (IsCipherAlgDisabled(algId)) {
        SKIP_TEST();
    }
    uint8_t pt[inLen];
    uint8_t out[MAX_DATASZIE] = {0};
    uint32_t outLen = MAX_DATASZIE;
    uint32_t totalLen = 0;
    CRYPT_EAL_CipherCtx *ctx = NULL;

    ASSERT_TRUE(inLen <= MAX_DATASZIE);
    (void)memset_s(pt, inLen, 0xAA, inLen); // init plaintext
    (void)memset_s(out, MAX_DATASZIE, 0xAA, MAX_DATASZIE);

    TestMemInit();
    ASSERT_TRUE((ctx = CRYPT_EAL_CipherNewCtx(algId)) != NULL);

    // Encrypt
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    if (isSetPadding == 1) {
        ASSERT_EQ(CRYPT_EAL_CipherSetPadding(ctx, padding), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, inLen, out, &outLen), CRYPT_SUCCESS);
    totalLen = outLen;
    outLen = MAX_DATASZIE - totalLen;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out + totalLen, &outLen), CRYPT_SUCCESS);
    totalLen += outLen;
    ASSERT_TRUE(out[0] != 0xAA);

    CRYPT_EAL_CipherDeinit(ctx);
    outLen = MAX_DATASZIE;
    // Decrypt
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false), CRYPT_SUCCESS);
    if (isSetPadding == 1) {
        ASSERT_EQ(CRYPT_EAL_CipherSetPadding(ctx, padding), CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, out, totalLen, out, &outLen), CRYPT_SUCCESS);
    totalLen = outLen;
    outLen = MAX_DATASZIE - totalLen;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out + totalLen, &outLen), CRYPT_SUCCESS);

    // Compare result
    if (padding != CRYPT_PADDING_ZEROS) {
        ASSERT_COMPARE("Same addr encrypt and decrypt", out, totalLen + outLen, pt, (uint32_t)inLen);
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC006
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC006(int algId, Hex *key, Hex *iv, Hex *in, int updateTimes, int padding)
{
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
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    for (int i = 0; i < updateTimes; i++) {
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, in->len, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
    }
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
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
    leftLen -= len;
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(in->x, result, in->len) == 0);
    ASSERT_TRUE(memcmp(in->x, result + in->len, in->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC007
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC007(int algId, Hex *key, Hex *iv, Hex *in, int padding, int blockSize)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint8_t result[MAX_OUTPUT] = {0};
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ASSERT_TRUE(in->len >= (uint32_t)blockSize);
    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherSetPadding(ctxEnc, padding);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    for (uint32_t i = 0; i < 2; i++) { // blockSize - 1字节 + blockSize字节，执行2次
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, blockSize - 1, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, blockSize, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
    }
    ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, blockSize - 1, outTmp + totalLen, &len);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += len;
    leftLen -= len;
    len = leftLen;
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
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
    leftLen -= len;
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + len, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(in->x, result, blockSize - 1) == 0);
    ASSERT_TRUE(memcmp(in->x, result + blockSize - 1, blockSize) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC008
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC008(int algId, Hex *key, Hex *iv, Hex *in, Hex *out, int feedBackSet, int enc)
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
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, sizeof(uint32_t));
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
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC009
* @spec  -
* @prior  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC009(int algId, Hex *key, Hex *iv, Hex *in, int feedBackSet, int updateTimes)
{
    TestMemInit();
    int32_t ret;
    uint8_t outTmp[MAX_OUTPUT] = {0};
    uint8_t result[MAX_OUTPUT] = {0};
    uint8_t ivGet[MAX_BLOCKSIZE] = {0};
    uint32_t getLen = MAX_BLOCKSIZE;
    uint32_t totalLen = 0;
    uint32_t leftLen = MAX_OUTPUT;
    uint32_t len = MAX_OUTPUT;
    CRYPT_EAL_CipherCtx *ctxEnc = NULL;
    CRYPT_EAL_CipherCtx *ctxDec = NULL;

    ctxEnc = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxEnc != NULL);
    ret = CRYPT_EAL_CipherInit(ctxEnc, key->x, key->len, iv->x, iv->len, true);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctxEnc, CRYPT_CTRL_GET_IV, NULL, getLen);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    getLen = 0;
    ret = CRYPT_EAL_CipherCtrl(ctxEnc, CRYPT_CTRL_GET_IV, ivGet, getLen);
    ASSERT_TRUE(ret != CRYPT_SUCCESS);
    getLen = iv->len;
    ret = CRYPT_EAL_CipherCtrl(ctxEnc, CRYPT_CTRL_GET_IV, ivGet, getLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (feedBackSet != 0) {
        ret = CRYPT_EAL_CipherCtrl(ctxEnc, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, sizeof(uint32_t));
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
    for (int i = 0; i < updateTimes; i++) {
        ret = CRYPT_EAL_CipherUpdate(ctxEnc, in->x, in->len, outTmp + totalLen, &len);
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
    }
    ret = CRYPT_EAL_CipherFinal(ctxEnc, outTmp + totalLen, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    totalLen += leftLen;

    len = MAX_OUTPUT;
    leftLen = MAX_OUTPUT;
    totalLen = 0;
    ctxDec = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctxDec != NULL);
    ret = CRYPT_EAL_CipherInit(ctxDec, key->x, key->len, iv->x, iv->len, false);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    if (feedBackSet != 0) {
        ret = CRYPT_EAL_CipherCtrl(ctxDec, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSet, sizeof(uint32_t));
        ASSERT_TRUE(ret == CRYPT_SUCCESS);
    }
    for (int i = 0; i < updateTimes; i++) {
        ret = CRYPT_EAL_CipherUpdate(ctxDec, outTmp + totalLen, in->len, result + totalLen, &len);
        totalLen += len;
        leftLen -= len;
        len = leftLen;
    }
    ASSERT_TRUE(ret == CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherFinal(ctxDec, result + totalLen, &leftLen);
    ASSERT_TRUE(ret == CRYPT_SUCCESS);

    ASSERT_TRUE(memcmp(in->x, result, in->len) == 0);
    ASSERT_TRUE(memcmp(in->x, result + in->len, in->len) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctxEnc);
    CRYPT_EAL_CipherFreeCtx(ctxDec);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_DES_ENC_FUNC_TC001
 * @title Test on the impact of resetting IV on update and final data
 * @brief
 *    1. Create DES encryption and decryption handles (including ECB, CBC, CFB and OFB). The expected result is successful.
 *    2. Initialize the DES encryption and decryption handles. Ensure that the key IV value is valid. 
 *    In ECB mode, the IV value does not need to be set. The expected result is successful.
 *    3. When the length of the input plaintext is 1 byte and the padding algorithm is CRYPT_PADDING_PKCS7.
 *    When the length of the input plaintext is 7 bytes, the expected result is successful.
 *    4. Reset IV. The expected result is successful.
 *    5. Use the update interface of the encrypted handle to enter a segment of plaintext data.
 *    The expected result is successful.
 *    6. Reset IV. The expected result is successful.
 *    7. Invoke the Final interface of the encryption handle to obtain the encryption value.
 *    The expected result is successful.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DES_ENC_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *iv2, Hex *msg, int padding, int isSetPadding)
{
    TestMemInit();
    uint8_t outTmp[MAX_DATASZIE] = {0};
    uint32_t outLen = MAX_DATASZIE;
    uint32_t finLen;

    CRYPT_EAL_CipherCtx *ctx = NULL;

    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_SUCCESS);
    if(isSetPadding) {
        ASSERT_EQ(CRYPT_EAL_CipherSetPadding(ctx, padding), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv2->x, iv2->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, msg->x, msg->len, outTmp, &outLen), CRYPT_SUCCESS);
    finLen = MAX_DATASZIE - outLen;

    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv->x, iv->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, outTmp+outLen, &finLen), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_DES_INIT_API_TC001
 * @title  3DES weak key test
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DES_INIT_API_TC001(int algId, Hex *key, Hex *iv)
{
    TestMemInit();

    CRYPT_EAL_CipherCtx *ctx = NULL;

    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, true), CRYPT_TDES_ERR_KEY);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, false), CRYPT_TDES_ERR_KEY);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test  SDV_CRYPTO_DES_INIT_API_TC002
 * @title 3DES key check bit error test
 */
/* BEGIN_CASE */
void SDV_CRYPTO_DES_INIT_API_TC002(int algId, Hex *iv)
{
    TestMemInit();

    uint8_t key1[24] = {
        0b10000001, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b11010011, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b00011111, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001 
    };

    uint8_t key2[24] = {
        0b10100001, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b11010111, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b00011111, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001 
    };

    uint8_t key3[24] = {
        0b10100001, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b11010011, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b00111111, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001 
    };

    uint8_t key4[8] = {
        0b10100001, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
    };

    uint8_t key5[16] = {
        0b10100001, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
        0b11010011, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111, 0b11110001,
    };

    CRYPT_EAL_CipherCtx *ctx = NULL;

    ctx = CRYPT_EAL_CipherNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key1, 24, iv->x, iv->len, true), CRYPT_TDES_ERR_KEY);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key1, 24, iv->x, iv->len, false), CRYPT_TDES_ERR_KEY);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key2, 24, iv->x, iv->len, true), CRYPT_TDES_ERR_KEY);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key2, 24, iv->x, iv->len, false), CRYPT_TDES_ERR_KEY);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key3, 24, iv->x, iv->len, true), CRYPT_TDES_ERR_KEY);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key3, 24, iv->x, iv->len, false), CRYPT_TDES_ERR_KEY);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key4, 8, iv->x, iv->len, true), CRYPT_TDES_ERR_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key4, 8, iv->x, iv->len, false), CRYPT_TDES_ERR_KEYLEN);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key5, 16, iv->x, iv->len, true), CRYPT_TDES_ERR_KEYLEN);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key5, 16, iv->x, iv->len, false), CRYPT_TDES_ERR_KEYLEN);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_EAL_DES_NOT_ALIGN_FUNC_TC001
 * @title  DES/TDES-CBC/ECB/CFB/OFB Encryption and decryption tests for non-aligned addresses.
 * @precon nan
 */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_NOT_ALIGN_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *pt, Hex *ct, int feedBackSize)
{
#define MAXSIZE 1024
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t keyTmp[MAXSIZE] __attribute__((aligned(8))) = {0};
    uint8_t ivTmp[MAXSIZE] __attribute__((aligned(8))) = {0};
    uint8_t ptTmp[MAXSIZE] __attribute__((aligned(8))) = {0};
    uint8_t ctTmp[MAXSIZE] __attribute__((aligned(8))) = {0};
    uint8_t* pKey = keyTmp + 1;
    uint8_t* pIv = ivTmp + 1;
    uint8_t* pPt = ptTmp + 1;
    uint8_t* pCt = ctTmp + 1;
    uint32_t leftLen = MAXSIZE - 1;
    uint32_t totalLen = 0;

    ASSERT_TRUE(memcpy_s(pKey, MAXSIZE - 1, key->x, key->len) == EOK);
    if (algId != CRYPT_CIPHER_DES_ECB && algId != CRYPT_CIPHER_TDES_ECB){
        ASSERT_TRUE(memcpy_s(pIv, MAXSIZE - 1, iv->x, iv->len) == EOK);
    }
    ASSERT_TRUE(memcpy_s(pPt, MAXSIZE - 1, pt->x, pt->len) == EOK);
    TestMemInit();

    // Encrypt
    ASSERT_TRUE((ctx = CRYPT_EAL_CipherNewCtx(algId)) != NULL);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, pKey, key->len, pIv, iv->len, true) == CRYPT_SUCCESS);
    if (feedBackSize != 0) {
        ASSERT_EQ(
            CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSize, sizeof(uint32_t)), CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pPt, pt->len, pCt, &leftLen) == CRYPT_SUCCESS);
    totalLen = leftLen;
    leftLen = MAXSIZE - 1 - totalLen;
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, pCt + totalLen, &leftLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("DES/TDES compare Ct", pCt, totalLen + leftLen, ct->x, ct->len);

    CRYPT_EAL_CipherDeinit(ctx);
    leftLen = MAXSIZE - 1;
    // Decrypt
    ASSERT_TRUE(memcpy_s(pCt, MAXSIZE - 1, ct->x, ct->len) == EOK);
    ASSERT_TRUE(CRYPT_EAL_CipherInit(ctx, pKey, key->len, pIv, iv->len, false) == CRYPT_SUCCESS);
    if (feedBackSize != 0) {
        ASSERT_EQ(
            CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_FEEDBACKSIZE, &feedBackSize, sizeof(uint32_t)), CRYPT_SUCCESS);
    }
    ASSERT_TRUE(CRYPT_EAL_CipherUpdate(ctx, pCt, ct->len, pPt, &leftLen) == CRYPT_SUCCESS);
    totalLen = leftLen;
    leftLen = MAXSIZE - 1 - totalLen;
    ASSERT_TRUE(CRYPT_EAL_CipherFinal(ctx, pPt + totalLen, &leftLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("DES/TDES compare Pt", pPt, totalLen + leftLen, pt->x, pt->len);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC010
* @spec  -
* @title  DES-ECB, OFB, CBC Mode encryption and decryption functionality testing.
* @precon  nan
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC010(int id, int en, Hex *key, Hex *iv, Hex *in, Hex *out)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *output;
    uint32_t outLen = out->len;
    output = (uint8_t *)malloc(sizeof(uint8_t) * outLen);
    ASSERT_TRUE(output != NULL);

    ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, en);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_DES_NOKEYCHECK, NULL, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, en);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, output, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out->x, output, outLen) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    free(output);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_DES_FUNC_TC011
* @spec  -
* @title  TDES-ECB, OFB, CBC Mode encryption and decryption functionality testing.
* @precon  nan
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_DES_FUNC_TC011(int id, int en, Hex *key, Hex *iv, Hex *in, Hex *out)
{
    TestMemInit();
    int32_t ret;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint8_t *output;
    uint32_t outLen = out->len;
    output = (uint8_t *)malloc(sizeof(uint8_t) * outLen);
    ASSERT_TRUE(output != NULL);

    ctx = CRYPT_EAL_CipherNewCtx(id);
    ASSERT_TRUE(ctx != NULL);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, en);
    ASSERT_EQ(ret, CRYPT_TDES_ERR_KEY);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_DES_NOKEYCHECK, NULL, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherInit(ctx, key->x, key->len, iv->x, iv->len, en);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_CipherUpdate(ctx, in->x, in->len, output, &outLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(out->x, output, outLen) == 0);
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    free(output);
}
/* END_CASE */
