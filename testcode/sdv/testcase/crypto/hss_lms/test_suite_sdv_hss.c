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
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include <string.h>
#include "crypt_hss.h"
#include "hss_local.h"

#define HSS_LEVEL_FIELD_LEN sizeof(uint32_t)
#define HSS_SHA256_N32_PUBKEY_LEN (LMS_PUBKEY_ROOT_OFFSET + 32)
#define HSS_SHA256_N32_WIRE_PUBKEY_LEN (HSS_LEVEL_FIELD_LEN + HSS_SHA256_N32_PUBKEY_LEN)
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

#ifdef HITLS_CRYPTO_KEY_DECODE
static int32_t DecodeHssPubKey(const Hex *pubKey, CRYPT_EAL_PkeyCtx **ctx)
{
    static const uint8_t spkiPrefix[] = {
        0x30, 0x4e, 0x30, 0x0d, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x11, 0x03, 0x3d, 0x00
    };
    if (pubKey->len != HSS_SHA256_N32_WIRE_PUBKEY_LEN) {
        return CRYPT_INVALID_ARG;
    }
    uint8_t spki[sizeof(spkiPrefix) + HSS_SHA256_N32_WIRE_PUBKEY_LEN];
    (void)memcpy(spki, spkiPrefix, sizeof(spkiPrefix));
    (void)memcpy(spki + sizeof(spkiPrefix), pubKey->x, pubKey->len);
    BSL_Buffer encoded = {spki, sizeof(spki)};
    return CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encoded, NULL, 0, ctx);
}
#endif

/* @
* @test  SDV_CRYPTO_HSS_SETPUB_LEVEL_TC001
* @spec  -
* @title  Set HSS level through the public key
* @precon  nan
* @brief  Test the LMS default and an explicit HSS level
* @expect  GetPubKey returns the imported level
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_SETPUB_LEVEL_TC001(void)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint8_t pubKey[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint8_t exported[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint32_t levels = 2;
    uint32_t exportedLevels = 0;
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, pubKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, pubKey + 4);
    BSL_Param lmsParam[2] = {
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, sizeof(pubKey), 0},
        BSL_PARAM_END
    };
    BSL_Param hssParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, sizeof(pubKey), 0},
        BSL_PARAM_END
    };
    BSL_Param getParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &exportedLevels, sizeof(exportedLevels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exported, sizeof(exported), 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, lmsParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_GetPubKey(ctx, getParam), CRYPT_SUCCESS);
    ASSERT_EQ(exportedLevels, 1);

    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, hssParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_GetPubKey(ctx, getParam), CRYPT_SUCCESS);
    ASSERT_EQ(exportedLevels, levels);

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_ERROR_STACK_TC001
* @spec  -
* @title  HSS verify error stack test
* @brief  Verify that a parse failure is pushed once
* @expect  The error stack contains one parse error
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_ERROR_STACK_TC001(void)
{
    TestMemInit();
    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    uint8_t pubKey[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint8_t msg = 0;
    uint8_t sig = 0;
    BSL_Param pubParam[2] = {
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, sizeof(pubKey), 0},
        BSL_PARAM_END
    };

    ASSERT_TRUE(ctx != NULL);
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, pubKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, pubKey + LMS_TYPE_LEN);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, pubParam), CRYPT_SUCCESS);

    BSL_ERR_ClearError();
    ASSERT_EQ(CRYPT_HSS_Verify(ctx, 0, &msg, sizeof(msg), &sig, sizeof(sig)),
        CRYPT_HSS_SIGNATURE_PARSE_FAIL);
    ASSERT_EQ(BSL_ERR_GetError(), CRYPT_HSS_SIGNATURE_PARSE_FAIL);
    ASSERT_EQ(BSL_ERR_GetError(), BSL_SUCCESS);

EXIT:
    BSL_ERR_ClearError();
    CRYPT_HSS_FreeCtx(ctx);
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

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtxEx(NULL);
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsTypes[] = {CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5};
    uint32_t otsTypes[] = {CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8};
    int32_t ret = HssParaInit(&ctx->para, 2, lmsTypes, otsTypes);
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

    uint32_t lmsTypes[] = {CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5};
    uint32_t otsTypes[] = {CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8};
    int32_t ret = HssParaInit(&ctx->para, 2, lmsTypes, otsTypes);
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

    uint32_t lmsTypes[] = {CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5};
    uint32_t otsTypes[] = {CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8};
    int32_t ret = HssParaInit(&ctx1->para, 2, lmsTypes, otsTypes);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx2 = CRYPT_HSS_DupCtx(NULL);
    ASSERT_TRUE(ctx2 == NULL);

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
void SDV_CRYPTO_HSS_CMPCTX_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssTestRand);
    CRYPT_HSS_Ctx *ctx1 = CRYPT_HSS_NewCtx();
    CRYPT_HSS_Ctx *ctx2 = NULL;
    CRYPT_HSS_Ctx *ctx3 = NULL;
    CRYPT_HSS_Ctx *ctx4 = NULL;
    ASSERT_TRUE(ctx1 != NULL);

    uint32_t lmsTypes[] = {CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5};
    uint32_t otsTypes[] = {CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8};
    int32_t ret = HssParaInit(&ctx1->para, 2, lmsTypes, otsTypes);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Gen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx2 = CRYPT_HSS_NewCtx();
    ret = HssParaInit(&ctx2->para, 2, lmsTypes, otsTypes);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_HSS_Gen(ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx3 = CRYPT_HSS_NewCtx();
    otsTypes[0] = CRYPT_LMOTS_SHA256_N32_W4;
    otsTypes[1] = CRYPT_LMOTS_SHA256_N32_W4;
    ret = HssParaInit(&ctx3->para, 2, lmsTypes, otsTypes);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_HSS_Gen(ctx3);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx4 = CRYPT_HSS_NewCtx();
    ret = HssParaInit(&ctx4->para, 1, lmsTypes, otsTypes);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Cmp(ctx1, NULL);
    ASSERT_EQ(ret, CRYPT_HSS_CMP_FALSE);

    ret = CRYPT_HSS_Cmp(ctx1, ctx2);
    ASSERT_EQ(ret, CRYPT_HSS_CMP_FALSE);

    ret = CRYPT_HSS_Cmp(ctx1, ctx3);
    ASSERT_EQ(ret, CRYPT_HSS_CMP_FALSE);

    ret = CRYPT_HSS_Cmp(ctx1, ctx4);
    ASSERT_EQ(ret, CRYPT_HSS_CMP_FALSE);

    ret = CRYPT_HSS_Cmp(ctx2, ctx3);
    ASSERT_EQ(ret, CRYPT_HSS_CMP_FALSE);

    ret = CRYPT_HSS_Cmp(ctx2, ctx4);
    ASSERT_EQ(ret, CRYPT_HSS_CMP_FALSE);

    ret = CRYPT_HSS_Cmp(ctx1, ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_HSS_FreeCtx(ctx1);
    CRYPT_HSS_FreeCtx(ctx2);
    CRYPT_HSS_FreeCtx(ctx3);
    CRYPT_HSS_FreeCtx(ctx4);
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

    uint32_t lmsTypes[] = {
        CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5};
    uint32_t otsTypes[] = {
        CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8};
    int32_t ret = HssParaInit(&ctx->para, 3, lmsTypes, otsTypes);
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

    uint32_t levels = BSL_ByteToUint32(pubKey->x);
    ASSERT_EQ(levels, 2);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN), (uint32_t)lmsType0);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN + LMS_TYPE_LEN), (uint32_t)otsType0);
    (void)lmsType1;
    (void)otsType1;

    BSL_Param pubParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x + HSS_LEVEL_FIELD_LEN,
            pubKey->len - HSS_LEVEL_FIELD_LEN, 0},
        BSL_PARAM_END
    };

    int32_t ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

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
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN), (uint32_t)lmsType0);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN + LMS_TYPE_LEN), (uint32_t)otsType0);

    BSL_Param pubOnly[2] = {
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x + HSS_LEVEL_FIELD_LEN,
            pubKey->len - HSS_LEVEL_FIELD_LEN, 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, pubOnly), CRYPT_SUCCESS);

    uint8_t exported[HSS_SHA256_N32_PUBKEY_LEN];
    uint32_t levels = 0;
    BSL_Param getParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exported, sizeof(exported), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_HSS_GetPubKey(ctx, getParam), CRYPT_SUCCESS);
    ASSERT_EQ(levels, 1);

    int32_t ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
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
* @brief  Import a pyhsslms-generated L=2 public key with and without preset parameters, then verify its signature
* @expect  Both verification paths succeed, demonstrating openhitls/pyhsslms interop
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_KAT_L2_TC001(int lmsType0, int otsType0, int lmsType1, int otsType1, Hex *pubKey, Hex *msg,
                                 Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    CRYPT_HSS_Ctx *importedCtx = NULL;
#ifdef HITLS_CRYPTO_KEY_DECODE
    CRYPT_EAL_PkeyCtx *decodedCtx = NULL;
#ifdef HITLS_CRYPTO_KEY_ENCODE
    BSL_Buffer encoded = {0};
#endif
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = BSL_ByteToUint32(pubKey->x);
    ASSERT_EQ(levels, 2);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN), (uint32_t)lmsType0);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN + LMS_TYPE_LEN), (uint32_t)otsType0);
    (void)lmsType1;
    (void)otsType1;

    BSL_Param pubParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x + HSS_LEVEL_FIELD_LEN,
            pubKey->len - HSS_LEVEL_FIELD_LEN, 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    importedCtx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(importedCtx != NULL);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(importedCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_Verify(importedCtx, 0, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_KEY_DECODE
    ASSERT_EQ(DecodeHssPubKey(pubKey, &decodedCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(decodedCtx, 0, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_KEY_ENCODE
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(decodedCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encoded),
        CRYPT_SUCCESS);
    ASSERT_TRUE(encoded.dataLen >= pubKey->len);
    ASSERT_EQ(memcmp(encoded.data + encoded.dataLen - pubKey->len, pubKey->x, pubKey->len), 0);
#endif
#endif

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_HSS_FreeCtx(importedCtx);
#ifdef HITLS_CRYPTO_KEY_DECODE
    CRYPT_EAL_PkeyFreeCtx(decodedCtx);
#ifdef HITLS_CRYPTO_KEY_ENCODE
    BSL_SAL_FREE(encoded.data);
#endif
#endif
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_KAT_L3_TC001
* @spec  Generated by pyhsslms (Russ Housley reference implementation, RFC 8554)
* @title  HSS L=3 Known-Answer Test (cross-implementation)
* @precon  nan
* @brief  Import a pyhsslms-generated L=3 public key with and without preset parameters, then verify its signature
* @expect  Both verification paths succeed for the 3-level HSS hierarchy
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_KAT_L3_TC001(int lmsType0, int otsType0, int lmsType1, int otsType1, int lmsType2, int otsType2,
                                 Hex *pubKey, Hex *msg, Hex *sig)
{
    TestMemInit();

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    CRYPT_HSS_Ctx *importedCtx = NULL;
#ifdef HITLS_CRYPTO_KEY_DECODE
    CRYPT_EAL_PkeyCtx *decodedCtx = NULL;
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = BSL_ByteToUint32(pubKey->x);
    ASSERT_EQ(levels, 3);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN), (uint32_t)lmsType0);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN + LMS_TYPE_LEN), (uint32_t)otsType0);
    (void)lmsType1;
    (void)otsType1;
    (void)lmsType2;
    (void)otsType2;

    BSL_Param pubParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x + HSS_LEVEL_FIELD_LEN,
            pubKey->len - HSS_LEVEL_FIELD_LEN, 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, sig->x, sig->len);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    importedCtx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(importedCtx != NULL);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(importedCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_Verify(importedCtx, 0, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);

#ifdef HITLS_CRYPTO_KEY_DECODE
    ASSERT_EQ(DecodeHssPubKey(pubKey, &decodedCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(decodedCtx, 0, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);
#endif

EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_HSS_FreeCtx(importedCtx);
#ifdef HITLS_CRYPTO_KEY_DECODE
    CRYPT_EAL_PkeyFreeCtx(decodedCtx);
#endif
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
    uint32_t lmsTypes[] = {CRYPT_LMS_SHA256_M32_H5, CRYPT_LMS_SHA256_M32_H5};
    uint32_t otsTypes[] = {CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMOTS_SHA256_N32_W8};
    int32_t ret = HssParaInit(&ctx1->para, levels, lmsTypes, otsTypes);
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
    uint8_t pubKeyBuf[HSS_SHA256_N32_PUBKEY_LEN];
    uint32_t exportedLevels = 0;
    BSL_Param pubGetParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &exportedLevels, sizeof(exportedLevels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, sizeof(pubKeyBuf), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_HSS_GetPubKey(ctx1, pubGetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(exportedLevels, levels);

    /* Export private key */
    uint8_t prvKeyBuf[CRYPT_HSS_PRVKEY_LEN];
    BSL_Param prvGetParam;
    BSL_PARAM_InitValue(&prvGetParam, CRYPT_PARAM_HSS_PRVKEY, BSL_PARAM_TYPE_OCTETS, prvKeyBuf, sizeof(prvKeyBuf));
    ret = CRYPT_HSS_GetPrvKey(ctx1, &prvGetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Import public key into a new context and verify */
    ctx2 = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx2 != NULL);
    BSL_Param pubSetParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &exportedLevels, sizeof(exportedLevels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, sizeof(pubKeyBuf), 0},
        BSL_PARAM_END
    };
    ret = CRYPT_HSS_SetPubKey(ctx2, pubSetParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_HSS_Verify(ctx2, 0, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Import private key and sign a new message */
    ret = HssParaInit(&ctx2->para, levels, lmsTypes, otsTypes);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
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

    ASSERT_EQ(BSL_ByteToUint32(pubKey->x), (uint32_t)lmsType);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + LMS_TYPE_LEN), (uint32_t)otsType);

    BSL_Param pubParam[2] = {0};
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, pubParam), CRYPT_SUCCESS);

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

    ASSERT_EQ(BSL_ByteToUint32(pubKey->x), (uint32_t)lmsType);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + LMS_TYPE_LEN), (uint32_t)otsType);

    BSL_Param pubParam[2] = {0};
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_HSS_SetPubKey(ctx, pubParam), CRYPT_SUCCESS);

    // Convert LMS-format signature to HSS-format: prepend 4-byte Nsp=0
    uint8_t *hssSig = BSL_SAL_Calloc(sig->len + 4, 1);
    ASSERT_TRUE(hssSig != NULL);
    uint32_t nsp = 0;
    BSL_Uint32ToByte(nsp, hssSig);
    (void)memcpy(hssSig + 4, sig->x, sig->len);

    int32_t ret = CRYPT_HSS_Verify(ctx, 0, msg->x, msg->len, hssSig, sig->len + 4);
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

/* @
* @test  SDV_CRYPTO_HSS_SETPUBKEY_API_NULL_INPUT_TC001
* @spec  -
* @title
* @precon  nan
* @brief  Test that CRYPT_HSS_SetPubKey/GetPubKey return proper error on NULL inputs
* @expect  NULL inputs return CRYPT_NULL_INPUT
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_SETPUBKEY_API_NULL_INPUT_TC001(int lmsType0, int otsType0, Hex *pubKey)
{
    TestMemInit();
    uint8_t pubKeyBuf[100];
    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN), (uint32_t)lmsType0);
    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN + LMS_TYPE_LEN), (uint32_t)otsType0);

    BSL_Param pubParam[2] = {0};
    BSL_Param getParam[2] = {0};
    int32_t ret = CRYPT_HSS_SetPubKey(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_HSS_GetPubKey(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_HSS_INVALID_PARAM);
    ret = CRYPT_HSS_GetPubKey(ctx, getParam);
    ASSERT_EQ(ret, CRYPT_HSS_NO_KEY);

    ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_HSS_INVALID_PARAM);
    ret = CRYPT_HSS_GetPubKey(ctx, getParam);
    ASSERT_EQ(ret, CRYPT_HSS_NO_KEY);

    pubParam[0].key = CRYPT_PARAM_HSS_PUBKEY;
    pubParam[0].valueType = BSL_PARAM_TYPE_OCTETS;
    pubParam[0].value = pubKey->x + HSS_LEVEL_FIELD_LEN;
    pubParam[0].valueLen = 1;

    ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_HSS_INVALID_KEY_LEN);
    ret = CRYPT_HSS_GetPubKey(ctx, getParam);
    ASSERT_EQ(ret, CRYPT_HSS_NO_KEY);

    pubParam[0].valueLen = pubKey->len - HSS_LEVEL_FIELD_LEN;
    ret = CRYPT_HSS_SetPubKey(ctx, pubParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_HSS_GetPubKey(ctx, getParam);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    getParam[0].key = CRYPT_PARAM_HSS_PUBKEY;
    getParam[0].valueType = BSL_PARAM_TYPE_OCTETS;
    getParam[0].value = pubKeyBuf;
    getParam[0].valueLen = 1;
    ret = CRYPT_HSS_GetPubKey(ctx, getParam);
    ASSERT_EQ(ret, CRYPT_HSS_INVALID_KEY_LEN);

    getParam[0].valueLen = pubKey->len - HSS_LEVEL_FIELD_LEN;
    ret = CRYPT_HSS_GetPubKey(ctx, getParam);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_HSS_FreeCtx(ctx);
    return;
}
/* END_CASE */
