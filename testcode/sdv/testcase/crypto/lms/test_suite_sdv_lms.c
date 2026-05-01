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
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include <string.h>
#include "crypt_lms.h"
#include "lms_local.h"

/* END_HEADER */

static uint8_t g_lmsTestRandValue = 0x42;

static int32_t LmsTestRand(uint8_t *randBuf, uint32_t len)
{
    if (randBuf == NULL || len == 0) {
        return CRYPT_NULL_INPUT;
    }
    for (uint32_t i = 0; i < len; i++) {
        randBuf[i] = g_lmsTestRandValue++;
    }
    return CRYPT_SUCCESS;
}

/* @
* @test  SDV_CRYPTO_LMS_NEWCTX_API_TC001
* @spec  -
* @title  CRYPT_LMS_NewCtx basic test
* @precon  nan
* @brief  Create LMS context and verify it is not NULL
* @expect  Context creation successful
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_NEWCTX_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_CTRL_API_TC001
* @spec  -
* @title  CRYPT_LMS_Ctrl test with various parameters
* @precon  nan
* @brief  Test CRYPT_LMS_Ctrl with NULL context, setting LMS/OTS types, and getting key lengths
* @expect  NULL context fails, parameter setting and queries succeed
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_CTRL_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H10;
    int32_t ret = CRYPT_LMS_Ctrl(NULL, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t pubKeyLen = 0;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(pubKeyLen > 0);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_KEYGEN_API_TC001
* @spec  -
* @title  CRYPT_LMS_Gen test
* @precon  nan
* @brief  Generate LMS key pair and verify remaining signature count
* @expect  Key generation successful, H5 tree provides 32 signatures
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_KEYGEN_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint64_t remaining = 0;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_REMAINING, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 32); // 2^5 = 32

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_SIGN_VERIFY_API_TC001
* @spec  -
* @title  LMS sign and verify test
* @precon  nan
* @brief  Generate key, sign message, verify signature, and test with wrong message
* @expect  Valid signature verifies successfully, invalid message fails verification
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_SIGN_VERIFY_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg[] = "Test message for LMS signature";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192];
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_LMS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    ret = CRYPT_LMS_Verify(ctx, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t wrongMsg[] = "Wrong message";
    ret = CRYPT_LMS_Verify(ctx, 0, wrongMsg, sizeof(wrongMsg) - 1, sig, sigLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_DUPCTX_API_TC001
* @spec  -
* @title  CRYPT_LMS_DupCtx test
* @precon  nan
* @brief  LMS is stateful: a context holding the private key must not be
*         duplicatable (would risk OTS index reuse). A verify-only context
*         (public key only) may be duplicated and compares equal.
* @expect  DupCtx on a private-key context returns NULL; DupCtx on a
*          public-key-only context succeeds and Cmp reports equality.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_DUPCTX_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx1 = CRYPT_LMS_NewCtx();
    CRYPT_LMS_Ctx *ctx2 = NULL;
    CRYPT_LMS_Ctx *pubCtx = NULL;
    CRYPT_LMS_Ctx *pubDup = NULL;
    uint8_t pubKeyBuf[LMS_PUBKEY_LEN];
    ASSERT_TRUE(ctx1 != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W4;

    int32_t ret = CRYPT_LMS_Ctrl(ctx1, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Ctrl(ctx1, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Cloning a context that holds the private key must be refused. */
    ctx2 = CRYPT_LMS_DupCtx(ctx1);
    ASSERT_TRUE(ctx2 == NULL);

    /* Build a verify-only context by exporting the public key from ctx1
     * and importing it into a fresh ctx; that context has no private state
     * and may be duplicated safely. */
    BSL_Param getPub[2] = {
        {CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, LMS_PUBKEY_LEN, 0},
        BSL_PARAM_END};
    ret = CRYPT_LMS_GetPubKey(ctx1, getPub);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    pubCtx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(pubCtx != NULL);
    BSL_Param setPub[2] = {
        {CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, LMS_PUBKEY_LEN, LMS_PUBKEY_LEN},
        BSL_PARAM_END};
    ret = CRYPT_LMS_SetPubKey(pubCtx, setPub);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    pubDup = CRYPT_LMS_DupCtx(pubCtx);
    ASSERT_TRUE(pubDup != NULL);
    ret = CRYPT_LMS_Cmp(pubCtx, pubDup);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_LMS_FreeCtx(ctx1);
    CRYPT_LMS_FreeCtx(ctx2);
    CRYPT_LMS_FreeCtx(pubCtx);
    CRYPT_LMS_FreeCtx(pubDup);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_KEY_EXHAUSTION_API_TC001
* @spec  -
* @title  LMS key exhaustion test
* @precon  nan
* @brief  Sign 32 messages with H5 tree, verify 33rd signature fails
* @expect  First 32 signatures succeed, 33rd fails with key exhausted
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_KEY_EXHAUSTION_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg[] = "Test message";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192];
    uint32_t sigLen;

    for (int i = 0; i < 32; i++) { // 2^5 = 32
        sigLen = sizeof(sig);
        ret = CRYPT_LMS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    sigLen = sizeof(sig);
    ret = CRYPT_LMS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    uint64_t remaining = 1;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_REMAINING, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 0);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_GETSET_KEY_API_TC001
* @spec  -
* @title  LMS key get/set (export/import) test
* @precon  nan
* @brief  Generate key, export pub/prv keys, import into new context, verify signature
* @expect  Exported keys can be imported and used for verification/signing
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_GETSET_KEY_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx1 = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx1 != NULL);
    CRYPT_LMS_Ctx *ctx2 = NULL;

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    int32_t ret = CRYPT_LMS_Ctrl(ctx1, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_LMS_Ctrl(ctx1, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Sign a message with the original context */
    const uint8_t msg[] = "Key export import test message";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192];
    uint32_t sigLen = sizeof(sig);
    ret = CRYPT_LMS_Sign(ctx1, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Get key lengths */
    uint32_t pubKeyLen = 0;
    ret = CRYPT_LMS_Ctrl(ctx1, CRYPT_CTRL_LMS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint32_t prvKeyLen = 0;
    ret = CRYPT_LMS_Ctrl(ctx1, CRYPT_CTRL_LMS_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Export public key */
    uint8_t pubKeyBuf[256];
    BSL_Param pubGetParam;
    BSL_PARAM_InitValue(&pubGetParam, CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, sizeof(pubKeyBuf));
    ret = CRYPT_LMS_GetPubKey(ctx1, &pubGetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Export private key */
    uint8_t prvKeyBuf[256];
    BSL_Param prvGetParam;
    BSL_PARAM_InitValue(&prvGetParam, CRYPT_PARAM_LMS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuf, sizeof(prvKeyBuf));
    ret = CRYPT_LMS_GetPrvKey(ctx1, &prvGetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Import public key into a new context and verify */
    ctx2 = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx2 != NULL);
    ret = CRYPT_LMS_Ctrl(ctx2, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_LMS_Ctrl(ctx2, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubSetParam;
    BSL_PARAM_InitValue(&pubSetParam, CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, pubKeyLen);
    ret = CRYPT_LMS_SetPubKey(ctx2, &pubSetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Verify(ctx2, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Import private key and sign a new message */
    BSL_Param prvSetParam;
    BSL_PARAM_InitValue(&prvSetParam, CRYPT_PARAM_LMS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuf, prvKeyLen);
    ret = CRYPT_LMS_SetPrvKey(ctx2, &prvSetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg2[] = "Second message after import";
    uint8_t sig2[8192];
    uint32_t sigLen2 = sizeof(sig2);
    ret = CRYPT_LMS_Sign(ctx2, 0, msg2, sizeof(msg2) - 1, sig2, &sigLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_LMS_Verify(ctx2, 0, msg2, sizeof(msg2) - 1, sig2, sigLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_LMS_FreeCtx(ctx1);
    CRYPT_LMS_FreeCtx(ctx2);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_SIGN_VERIFY_W1_API_TC001
* @spec  -
* @title  LMS sign/verify with W1 OTS parameter
* @precon  nan
* @brief  Test sign and verify with the smallest Winternitz parameter W1
* @expect  Signature generation and verification succeed with W1
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_SIGN_VERIFY_W1_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W1;

    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg[] = "Test message for W1 OTS parameter";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[50000]; /* W1 produces larger signatures (p=265) */
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_LMS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    ret = CRYPT_LMS_Verify(ctx, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_SIGN_VERIFY_W2_API_TC001
* @spec  -
* @title  LMS sign/verify with W2 OTS parameter
* @precon  nan
* @brief  Test sign and verify with Winternitz parameter W2
* @expect  Signature generation and verification succeed with W2
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_SIGN_VERIFY_W2_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W2;

    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_LMS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg[] = "Test message for W2 OTS parameter";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[50000]; /* W2 produces larger signatures (p=133) */
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_LMS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    ret = CRYPT_LMS_Verify(ctx, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_NEWCTXEX_API_TC001
* @spec  -
* @title  CRYPT_LMS_NewCtxEx test
* @precon  nan
* @brief  Create LMS context with library context parameter
* @expect  Context creation succeeds with NULL libCtx
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_NEWCTXEX_API_TC001(void)
{
    TestMemInit();

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtxEx(NULL);
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_CTRL_SIGLEN_API_TC001
* @spec  -
* @title  LMS Ctrl GET_SIG_LEN and GET_PRVKEY_LEN test
* @precon  nan
* @brief  Test querying signature length and private key length via Ctrl
* @expect  All length queries return valid positive values
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_CTRL_SIGLEN_API_TC001(void)
{
    TestMemInit();

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W4;

    int32_t ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_SIG_LEN, &sigLen, sizeof(sigLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    uint32_t prvKeyLen = 0;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_PRVKEY_LEN, &prvKeyLen, sizeof(prvKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(prvKeyLen > 0);

    uint32_t pubKeyLen = 0;
    ret = CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(pubKeyLen > 0);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_RFC8554_KAT_TC001
* @spec  RFC 8554 Appendix F
* @title  LMS Known-Answer Test using RFC 8554 test vector
* @precon  nan
* @brief  Verify a pre-recorded LMS signature against its public key and the
*         original message. The vector is extracted from the bottom-level LMS
*         signature embedded in RFC 8554 Appendix F.1 (2-level HSS), and
*         exercises the LMS verify path directly without the HSS wrapper.
* @expect  Verification succeeds; tampering with the signature or message
*          fails verification
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_RFC8554_KAT_TC001(int lmsType, int otsType, Hex *pubKey, Hex *msg, Hex *sig)
{
    TestMemInit();

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lType = (uint32_t)lmsType;
    uint32_t oType = (uint32_t)otsType;
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lType, sizeof(lType)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &oType, sizeof(oType)), CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_LMS_SetPubKey(ctx, &pubParam), CRYPT_SUCCESS);

    // Positive: the known good signature must verify.
    ASSERT_EQ(CRYPT_LMS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);

    // Negative: a single-bit flip in the message must break verification.
    uint8_t *badMsg = BSL_SAL_Calloc(msg->len, 1);
    ASSERT_TRUE(badMsg != NULL);
    memcpy(badMsg, msg->x, msg->len);
    badMsg[0] ^= 0x01;
    ASSERT_NE(CRYPT_LMS_Verify(ctx, 0, badMsg, msg->len, sig->x, sig->len), CRYPT_SUCCESS);
    BSL_SAL_Free(badMsg);

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_ROUNDTRIP_PARAM_TC001
* @spec  RFC 8554
* @title  LMS keygen/sign/verify roundtrip with parameterized LMS/OTS types
* @precon  nan
* @brief  Generate a key pair for the given (lmsType, otsType), sign a message,
*         verify the signature, and check that tampering with the message or
*         signature causes verification to fail.
* @expect  Roundtrip succeeds; tampered message or signature fails verification
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_ROUNDTRIP_PARAM_TC001(int lmsType, int otsType)
{
    uint8_t *sig = NULL;
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(LmsTestRand);

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lType = (uint32_t)lmsType;
    uint32_t oType = (uint32_t)otsType;
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lType, sizeof(lType)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &oType, sizeof(oType)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_LMS_Gen(ctx), CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_GET_SIG_LEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);
    sig = (uint8_t *)BSL_SAL_Malloc(sigLen);
    ASSERT_TRUE(sig != NULL);

    const uint8_t msg[] = "LMS roundtrip coverage message";
    uint32_t msgLen = sizeof(msg) - 1;
    ASSERT_EQ(CRYPT_LMS_Sign(ctx, 0, msg, msgLen, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_LMS_Verify(ctx, 0, msg, msgLen, sig, sigLen), CRYPT_SUCCESS);

    /* Tampered message must fail verification */
    uint8_t badMsg[sizeof(msg) - 1];
    memcpy(badMsg, msg, msgLen);
    badMsg[0] ^= 0x01;
    ASSERT_NE(CRYPT_LMS_Verify(ctx, 0, badMsg, msgLen, sig, sigLen), CRYPT_SUCCESS);

    /* Tampered signature must fail verification */
    sig[sigLen / 2] ^= 0x01;
    ASSERT_NE(CRYPT_LMS_Verify(ctx, 0, msg, msgLen, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(sig);
    CRYPT_LMS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_LMS_NIST_ACVP_KAT_TC001
* @spec  NIST ACVP LMS-sigVer-1.0
* @title  LMS verification against NIST ACVP test vectors
* @precon  nan
* @brief  Run a pre-recorded (publicKey, message, signature) triple through
*         CRYPT_LMS_Verify and confirm the pass/fail outcome matches the
*         expected result provided by the ACVP vector set.
* @expect  Verification result matches expectPass (1 = should verify, 0 = should fail)
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_LMS_NIST_ACVP_KAT_TC001(int lmsType, int otsType, Hex *pubKey, Hex *msg, Hex *sig, int expectPass)
{
    TestMemInit();

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t lType = (uint32_t)lmsType;
    uint32_t oType = (uint32_t)otsType;
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lType, sizeof(lType)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_LMS_Ctrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &oType, sizeof(oType)), CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_LMS_SetPubKey(ctx, &pubParam), CRYPT_SUCCESS);

    int32_t ret = CRYPT_LMS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    if (expectPass) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_LMS_FreeCtx(ctx);
    return;
}
/* END_CASE */
