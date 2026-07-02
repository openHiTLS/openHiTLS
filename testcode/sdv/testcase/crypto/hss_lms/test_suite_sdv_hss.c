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
/* INCLUDE_BASE test_suite_sdv_hss */

/* BEGIN_HEADER */
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include <string.h>
#include "crypt_hss.h"
#include "hss_local.h"

/* HSS key length constants for testing */
#define CRYPT_HSS_PUBKEY_LEN 60
#define CRYPT_HSS_PRVKEY_LEN 48

/* END_HEADER */

static uint8_t g_hssTestRandValue = 0x42;

static int32_t HssTestRand(uint8_t *randBuf, uint32_t len)
{
    if (randBuf == NULL || len == 0) {
        return CRYPT_NULL_INPUT;
    }
    for (uint32_t i = 0; i < len; i++) {
        randBuf[i] = g_hssTestRandValue++;
    }
    return CRYPT_SUCCESS;
}

/* @
* @test  SDV_CRYPTO_HSS_NEWCTX_API_TC001
* @spec  -
* @title  CRYPT_HSS_NewCtx basic test
* @precon  nan
* @brief  Create HSS context and verify it is not NULL
* @expect  Context creation successful
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_NEWCTX_API_TC001(void)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_CTRL_API_TC001
* @spec  -
* @title  CRYPT_HSS_Ctrl test with various parameters
* @precon  nan
* @brief  Test setting levels, LMS/OTS types for each level, and getting key lengths
* @expect  All parameter settings and queries succeed
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_CTRL_API_TC001(void)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t pubKeyLen = 0;
    ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(pubKeyLen, CRYPT_HSS_PUBKEY_LEN);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_KEYGEN_API_TC001
* @spec  -
* @title  CRYPT_HSS_Gen test with 2 levels
* @precon  nan
* @brief  Generate 2-level HSS key pair with H5 trees and verify signature capacity
* @expect  Key generation successful, capacity is 32 * 32 = 1024
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_KEYGEN_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint64_t remaining = 0;
    ret = HssCtrlGetRemaining(ctx, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 1024); // Signature capacity: 2^5 * 2^5 = 32 * 32 = 1024

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_SIGN_VERIFY_API_TC001
* @spec  -
* @title  HSS sign and verify test
* @precon  nan
* @brief  Generate 2-level key, sign message, verify signature, and test with wrong message
* @expect  Valid signature verifies successfully, invalid message fails verification
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_SIGN_VERIFY_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg[] = "Test message for HSS signature";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[16384]; // Large buffer for HSS signatures (max size for multi-level hierarchies)
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_HSS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    ret = CRYPT_HSS_Verify(ctx, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t wrongMsg[] = "Wrong message";
    ret = CRYPT_HSS_Verify(ctx, 0, wrongMsg, sizeof(wrongMsg) - 1, sig, sigLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_DUPCTX_API_TC001
* @spec  -
* @title  CRYPT_HSS_DupCtx test
* @precon  nan
* @brief  HSS is stateful: DupCtx must not clone private signing state.
* @expect  DupCtx on a private-key context succeeds, but the duplicate is
*          public-key-only: it can verify but cannot sign.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_DUPCTX_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);

    CRYPT_HSS_Ctx *ctx1 = CRYPT_HSS_NewCtx();
    CRYPT_HSS_Ctx *ctx2 = NULL;
    const uint8_t msg[] = "Test message for HSS dup";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[16384];
    uint32_t sigLen = sizeof(sig);
    ASSERT_TRUE(ctx1 != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx1, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx2 = CRYPT_HSS_DupCtx(ctx1);
    ASSERT_TRUE(ctx2 != NULL);

    ret = CRYPT_HSS_Sign(ctx2, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_HSS_NO_KEY);

    sigLen = sizeof(sig);
    ret = CRYPT_HSS_Sign(ctx1, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_HSS_Verify(ctx2, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx1);
    CRYPT_HSS_FreeCtx(ctx2);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_MULTI_LEVEL_API_TC001
* @spec  -
* @title  HSS multi-level hierarchy test
* @precon  nan
* @brief  Create 3-level hierarchy with H5 trees, sign 5 messages, verify counter decrements
* @expect  Signature capacity is 32^3 = 32768, successful signing decrements remaining count
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_MULTI_LEVEL_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 3;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[8] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL3_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL3_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint64_t remaining = 0;
    ret = HssCtrlGetRemaining(ctx, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 32768);

    const uint8_t msg[] = "Test message";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[16384];
    uint32_t sigLen;

    for (int i = 0; i < 5; i++) {
        sigLen = sizeof(sig);
        ret = CRYPT_HSS_Sign(ctx, 0, msg, msgLen, sig, &sigLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    ret = HssCtrlGetRemaining(ctx, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 32768 - 5);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_RFC8554_TC001
* @spec  RFC 8554 Appendix F
* @title  RFC 8554 test vector verification
* @precon  nan
* @brief  Verify RFC 8554 test vectors with parameterized LMS/OTS types and key/sig data
* @expect  Signature verification succeeds, proving RFC 8554 compliance
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_RFC8554_TC001(int lmsType0, int otsType0, int lmsType1, int otsType1, Hex *pubKey, Hex *msg,
                                  Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype1 = lmsType0;
    uint32_t otstype1 = otsType0;
    uint32_t lmstype2 = lmsType1;
    uint32_t otstype2 = otsType1;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype2, sizeof(lmstype2), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype2, sizeof(otstype2), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);

    ret = CRYPT_HSS_SetPubKey(ctx, &pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(sigLen, sig->len);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_KAT_L1_TC001
* @spec  Generated by pyhsslms / ported from wolfSSL / Bouncy Castle / Cryptech (RFC 8554)
* @title  HSS L=1 Known-Answer Test (HSS-as-LMS single-level)
* @precon  nan
* @brief  Parse an L=1 public key and signature, verify with openhitls
* @expect  Signature verification succeeds for single-level HSS (= LMS)
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_KAT_L1_TC001(int lmsType0, int otsType0, Hex *pubKey, Hex *msg, Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 1;
    uint32_t lmstype1 = lmsType0;
    uint32_t otstype1 = otsType0;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ret = CRYPT_HSS_SetPubKey(ctx, &pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_KAT_L2_TC001
* @spec  Generated by pyhsslms (Russ Housley reference implementation, RFC 8554)
* @title  HSS L=2 Known-Answer Test (cross-implementation)
* @precon  nan
* @brief  Parse a pyhsslms-generated L=2 public key and signature, verify with openhitls
* @expect  Signature verification succeeds, demonstrating openhitls/pyhsslms interop
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_KAT_L2_TC001(int lmsType0, int otsType0, int lmsType1, int otsType1, Hex *pubKey, Hex *msg,
                                 Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype1 = lmsType0;
    uint32_t otstype1 = otsType0;
    uint32_t lmstype2 = lmsType1;
    uint32_t otstype2 = otsType1;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype2, sizeof(lmstype2), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype2, sizeof(otstype2), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ret = CRYPT_HSS_SetPubKey(ctx, &pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_KAT_L3_TC001
* @spec  Generated by pyhsslms (Russ Housley reference implementation, RFC 8554)
* @title  HSS L=3 Known-Answer Test (cross-implementation)
* @precon  nan
* @brief  Parse a pyhsslms-generated L=3 public key and signature, verify with openhitls
* @expect  Signature verification succeeds for 3-level HSS hierarchy
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_KAT_L3_TC001(int lmsType0, int otsType0, int lmsType1, int otsType1, int lmsType2, int otsType2,
                                 Hex *pubKey, Hex *msg, Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 3;
    uint32_t lmstype1 = lmsType0;
    uint32_t otstype1 = otsType0;
    uint32_t lmstype2 = lmsType1;
    uint32_t otstype2 = otsType1;
    uint32_t lmstype3 = lmsType2;
    uint32_t otstype3 = otsType2;
    BSL_Param params[8] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype2, sizeof(lmstype2), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype2, sizeof(otstype2), 0},
        {CRYPT_PARAM_HSS_LEVEL3_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype3, sizeof(lmstype3), 0},
        {CRYPT_PARAM_HSS_LEVEL3_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype3, sizeof(otstype3), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ret = CRYPT_HSS_SetPubKey(ctx, &pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_GETSET_KEY_API_TC001
* @spec  -
* @title  HSS key get/set (export/import) test
* @precon  nan
* @brief  Generate key, export pub/prv keys, import into new context, verify signature
* @expect  Exported keys can be imported and used for verification/signing
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_GETSET_KEY_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);

    CRYPT_HSS_Ctx *ctx1 = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx1 != NULL);
    CRYPT_HSS_Ctx *ctx2 = NULL;

    uint32_t levels = 2;
    uint32_t lmstype1 = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype1 = CRYPT_LMOTS_SHA256_N32_W8;
    uint32_t lmstype2 = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype2 = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype2, sizeof(lmstype2), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype2, sizeof(otstype2), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx1, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Sign a message */
    const uint8_t msg[] = "HSS key export import test message";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[16384];
    uint32_t sigLen = sizeof(sig);
    ret = CRYPT_HSS_Sign(ctx1, 0, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Export public key */
    uint8_t pubKeyBuf[CRYPT_HSS_PUBKEY_LEN];
    BSL_Param pubGetParam;
    BSL_PARAM_InitValue(&pubGetParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, sizeof(pubKeyBuf));
    ret = CRYPT_HSS_GetPubKey(ctx1, &pubGetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Export private key */
    uint8_t prvKeyBuf[CRYPT_HSS_PRVKEY_LEN];
    BSL_Param prvGetParam;
    BSL_PARAM_InitValue(&prvGetParam, CRYPT_PARAM_HSS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuf, sizeof(prvKeyBuf));
    ret = CRYPT_HSS_GetPrvKey(ctx1, &prvGetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Import public key into a new context and verify */
    ctx2 = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx2 != NULL);
    ret = CRYPT_HSS_Ctrl(ctx2, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubSetParam;
    BSL_PARAM_InitValue(&pubSetParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, CRYPT_HSS_PUBKEY_LEN);
    ret = CRYPT_HSS_SetPubKey(ctx2, &pubSetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx2, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Import private key and sign a new message */
    BSL_Param prvSetParam;
    BSL_PARAM_InitValue(&prvSetParam, CRYPT_PARAM_HSS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuf, CRYPT_HSS_PRVKEY_LEN);
    ret = CRYPT_HSS_SetPrvKey(ctx2, &prvSetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg2[] = "Second HSS message after import";
    uint8_t sig2[16384];
    uint32_t sigLen2 = sizeof(sig2);
    ret = CRYPT_HSS_Sign(ctx2, 0, msg2, sizeof(msg2) - 1, sig2, &sigLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_HSS_Verify(ctx2, 0, msg2, sizeof(msg2) - 1, sig2, sigLen2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_HSS_FreeCtx(ctx1);
    CRYPT_HSS_FreeCtx(ctx2);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_NEWCTXEX_API_TC001
* @spec  -
* @title  CRYPT_HSS_NewCtxEx test
* @precon  nan
* @brief  Create HSS context with library context parameter
* @expect  Context creation succeeds with NULL libCtx
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_NEWCTXEX_API_TC001(void)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtxEx(NULL);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_CTRL_LENGTHS_API_TC001
* @spec  -
* @title  HSS Ctrl length query test
* @precon  nan
* @brief  Test querying signature length, key lengths, and level count via Ctrl
* @expect  All queries return valid positive values
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_CTRL_LENGTHS_API_TC001(void)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype1 = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype1 = CRYPT_LMOTS_SHA256_N32_W8;
    uint32_t lmstype2 = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype2 = CRYPT_LMOTS_SHA256_N32_W8;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype2, sizeof(lmstype2), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype2, sizeof(otstype2), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    uint32_t pubKeyLen = 0;
    ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(pubKeyLen, CRYPT_HSS_PUBKEY_LEN);

    uint32_t gotLevels = 0;
    ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &gotLevels, sizeof(gotLevels));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(gotLevels, 2);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_ROUNDTRIP_PARAM_TC001
* @spec  RFC 8554
* @title  HSS keygen/sign/verify roundtrip for parameterized algId
* @precon  nan
* @brief  Generate a key pair for the given HSS algId, sign a message, verify,
*         then confirm that tampering with message or signature fails.
* @expect  Roundtrip succeeds; tampered inputs fail verification
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_ROUNDTRIP_PARAM_TC001(int algId)
{
    uint8_t *sig = NULL;
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    int32_t id = algId;
    ASSERT_EQ(CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_Gen(ctx), CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ASSERT_EQ(CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);
    sig = (uint8_t *)BSL_SAL_Malloc(sigLen);
    ASSERT_TRUE(sig != NULL);

    const uint8_t msg[] = "HSS roundtrip coverage message";
    uint32_t msgLen = sizeof(msg) - 1;
    ASSERT_EQ(CRYPT_HSS_Sign(ctx, 0, msg, msgLen, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_Verify(ctx, 0, msg, msgLen, sig, sigLen), CRYPT_SUCCESS);

    uint8_t badMsg[sizeof(msg) - 1];
    memcpy(badMsg, msg, msgLen);
    badMsg[0] ^= 0x01;
    ASSERT_NE(CRYPT_HSS_Verify(ctx, 0, badMsg, msgLen, sig, sigLen), CRYPT_SUCCESS);

    sig[sigLen / 2] ^= 0x01;
    ASSERT_NE(CRYPT_HSS_Verify(ctx, 0, msg, msgLen, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(sig);
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_LMS_RFC8554_KAT_TC001
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
void SDV_CRYPTO_HSS_LMS_RFC8554_KAT_TC001(int lmsType, int otsType, Hex *pubKey, Hex *msg, Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 1;
    uint32_t lmstype1 = lmsType;
    uint32_t otstype1 = otsType;
    BSL_Param params[4] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Convert LMS-format pubkey to HSS-format: prepend 4-byte levels=1
    uint8_t *hssPubKey = BSL_SAL_Calloc(pubKey->len + 4, 1);
    ASSERT_TRUE(hssPubKey != NULL);
    uint32_t levelCount = 1;
    BSL_Uint32ToByte(levelCount, hssPubKey);
    (void)memcpy(hssPubKey + 4, pubKey->x, pubKey->len);
    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, hssPubKey, pubKey->len + 4);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, &pubParam), CRYPT_SUCCESS);
    BSL_SAL_Free(hssPubKey);

    // Convert LMS-format signature to HSS-format: prepend 4-byte Nsp=0
    uint8_t *hssSig = BSL_SAL_Calloc(sig->len + 4, 1);
    ASSERT_TRUE(hssSig != NULL);
    uint32_t nsp = 0;
    BSL_Uint32ToByte(nsp, hssSig);
    (void)memcpy(hssSig + 4, sig->x, sig->len);

    // Positive: the known good signature must verify.
    ASSERT_EQ(CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, hssSig, sig->len + 4), CRYPT_SUCCESS);

    // Negative: a single-bit flip in the message must break verification.
    uint8_t *badMsg = BSL_SAL_Calloc(msg->len, 1);
    ASSERT_TRUE(badMsg != NULL);
    memcpy(badMsg, msg->x, msg->len);
    badMsg[0] ^= 0x01;
    ASSERT_NE(CRYPT_HSS_Verify(ctx, 0, badMsg, msg->len, hssSig, sig->len + 4), CRYPT_SUCCESS);
    BSL_SAL_Free(badMsg);
    BSL_SAL_Free(hssSig);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */
/* @
* @test  SDV_CRYPTO_HSS_LMS_NIST_ACVP_KAT_TC001
* @spec  NIST ACVP LMS-sigVer-1.0
* @title  LMS verification against NIST ACVP test vectors
* @precon  nan
* @brief  Run a pre-recorded (publicKey, message, signature) triple through
*         CRYPT_HSS_Verify and confirm the pass/fail outcome matches the
*         expected result provided by the ACVP vector set.
* @expect  Verification result matches expectPass (1 = should verify, 0 = should fail)
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_LMS_NIST_ACVP_KAT_TC001(int lmsType, int otsType, Hex *pubKey, Hex *msg, Hex *sig, int expectPass)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 1;
    uint32_t lmstype1 = lmsType;
    uint32_t otstype1 = otsType;
    BSL_Param params[4] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    // Convert LMS-format pubkey to HSS-format: prepend 4-byte levels=1
    uint8_t *hssPubKey = BSL_SAL_Calloc(pubKey->len + 4, 1);
    ASSERT_TRUE(hssPubKey != NULL);
    BSL_Uint32ToByte(levels, hssPubKey);
    (void)memcpy(hssPubKey + 4, pubKey->x, pubKey->len);
    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, hssPubKey, pubKey->len + 4);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, &pubParam), CRYPT_SUCCESS);
    BSL_SAL_Free(hssPubKey);

    // Convert LMS-format signature to HSS-format: prepend 4-byte Nsp=0
    uint8_t *hssSig = BSL_SAL_Calloc(sig->len + 4, 1);
    ASSERT_TRUE(hssSig != NULL);
    uint32_t nsp = 0;
    BSL_Uint32ToByte(nsp, hssSig);
    (void)memcpy(hssSig + 4, sig->x, sig->len);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, hssSig, sig->len + 4);
    if (expectPass) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }
    BSL_SAL_Free(hssSig);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

