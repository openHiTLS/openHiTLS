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
#include <stdio.h>
#include <string.h>
#include <string.h>
#include "crypt_types.h"
#include "bsl_err.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include "test.h"
#include "stub_utils.h"
/* END_HEADER */

#define HSS_LEVEL_FIELD_LEN sizeof(uint32_t)
#define HSS_SHA256_N32_PUBKEY_LEN (24 + 32)
#define HSS_SHA256_N32_WIRE_PUBKEY_LEN (HSS_LEVEL_FIELD_LEN + HSS_SHA256_N32_PUBKEY_LEN)
/* H=5/W=8 LMS signature and child-key lengths used by the boundary vectors. */
#define HSS_H5_W8_LMS_SIG_LEN 1292
#define HSS_H5_W8_CHILD_PUBKEY_LEN HSS_SHA256_N32_PUBKEY_LEN
/* The bottom signature starts after its 4-byte type/level prefix and child key. */
#define HSS_H5_W8_BOTTOM_SIG_OFFSET (4 + HSS_H5_W8_LMS_SIG_LEN + HSS_H5_W8_CHILD_PUBKEY_LEN)

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

static CRYPT_EAL_PkeyCtx *CreateHssContext(int isProvider)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_HSS_LMS, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    }
#endif
    (void)isProvider;
    return CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
}

static int32_t HssEalSetRawPubKey(CRYPT_EAL_PkeyCtx *ctx, uint32_t levels, uint8_t *pubKey, uint32_t pubKeyLen)
{
    BSL_Param param[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey, pubKeyLen, 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeySetPubEx(ctx, param);
}

static int32_t HssEalSetPubKey(CRYPT_EAL_PkeyCtx *ctx, const Hex *pubKey)
{
    return HssEalSetRawPubKey(ctx, BSL_ByteToUint32(pubKey->x), pubKey->x + HSS_LEVEL_FIELD_LEN,
        pubKey->len - HSS_LEVEL_FIELD_LEN);
}

/* @
* @test  SDV_CRYPTO_EAL_HSS_API_TC001
* @spec  -
* @title  Test for CtxCopy, CtxDup and CtxCmp.
* @brief
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_API_TC001(int isProvider, Hex *pubKey)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx1 = CreateHssContext(isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx3 = NULL;
    ASSERT_TRUE(ctx1 != NULL);

    ctx2 = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_EQ(HssEalSetPubKey(ctx1, pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(HssEalSetPubKey(ctx2, pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    ctx3 = CRYPT_EAL_PkeyDupCtx(ctx1);
    ASSERT_TRUE(ctx3 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx3), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(ctx2, ctx1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_HSS_CTRL_UNSUPPORTED_TC001
* @spec  -
* @title  Test that HSS parameter configuration is unsupported
* @brief
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_CTRL_UNSUPPORTED_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    int32_t algId = CRYPT_HSS_SHA256_L2_H10_H10_W4;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)),
        CRYPT_EAL_ALG_NOT_SUPPORT);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_EAL_TC001
* @spec  RFC 8554 Appendix F
* @title  RFC 8554 test vector verification
* @precon  nan
* @brief  Verify RFC 8554 test vectors with parameterized LMS/OTS types and key/sig data
* @expect  Signature verification succeeds, proving RFC 8554 compliance
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_EAL_TC001(int lmsType0, int otsType0, int lmsType1, int otsType1, Hex *pubKey, Hex *msg,
    Hex *sig)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(BSL_ByteToUint32(pubKey->x + HSS_LEVEL_FIELD_LEN), (uint32_t)lmsType0);
    (void)otsType0;
    (void)lmsType1;
    (void)otsType1;
    ASSERT_EQ(HssEalSetPubKey(ctx, pubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

static int32_t HssTestVerify(CRYPT_EAL_PkeyCtx *ctx, int lmsType0, int otsType0, int lmsType1, int otsType1,
    Hex *pubKey, Hex *msg, Hex *sig) {
    (void)lmsType0;
    (void)otsType0;
    (void)lmsType1;
    (void)otsType1;
    int32_t ret = HssEalSetPubKey(ctx, pubKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sig->x, sig->len);
}

/* @
* @test  SDV_CRYPTO_HSS_EAL_TC002
* @title  Test the verify with stub malloc fail.
* @precon  nan
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_EAL_TC002(int lmsType0, int otsType0, int lmsType1, int otsType1, Hex *pubKey, Hex *msg,
    Hex *sig)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx1 != NULL);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HssTestVerify(ctx1, lmsType0, otsType0, lmsType1, otsType1, pubKey, msg, sig), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    for (uint32_t j = 0; j < totalMallocCount; j++)
    {
        ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
        ASSERT_TRUE(ctx2 != NULL);
        STUB_EnableMallocFail(true);
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(HssTestVerify(ctx2, lmsType0, otsType0, lmsType1, otsType1, pubKey, msg, sig), CRYPT_SUCCESS);
        CRYPT_EAL_PkeyFreeCtx(ctx2);
        ctx2 = NULL;
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_LEVEL_BOUNDARY_TC001
* @spec  RFC 8554
* @title  Verify the HSS level boundary from zero through nine
* @precon  nan
* @brief  Accept levels one through eight and reject values outside the RFC range,
*         and verify that rejected configuration does not contaminate the context
* @expect  Only levels one through eight work; rejected levels leave a reusable context
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_LEVEL_BOUNDARY_TC001(int inputLevels, int expectSuccess)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t pubKey[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint8_t exported[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint32_t actualLevels = UINT32_MAX;
    BSL_Param getParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &actualLevels, sizeof(actualLevels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exported, sizeof(exported), 0},
        BSL_PARAM_END
    };

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, pubKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, pubKey + 4);

    int32_t ret = HssEalSetRawPubKey(ctx, (uint32_t)inputLevels, pubKey, sizeof(pubKey));
    if (expectSuccess != 0) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getParam), CRYPT_SUCCESS);
        ASSERT_EQ(actualLevels, (uint32_t)inputLevels);
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getParam), CRYPT_HSS_NO_KEY);
        ASSERT_EQ(HssEalSetRawPubKey(ctx, 1, pubKey, sizeof(pubKey)), CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_RFC9858_PARAM_REJECT_TC001
* @spec  RFC 9858
* @title  Reject unsupported RFC 9858 parameter types atomically
* @precon  nan
* @brief  Try representative SHA-256 n=24 and SHAKE parameter types, then reuse
*         the context with a currently supported RFC 8554 configuration
* @expect  Unsupported types fail without leaving partial parameter state
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_RFC9858_PARAM_REJECT_TC001(int lmsType, int otsType)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t pubKey[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint8_t exported[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint32_t levels = 0;
    BSL_Param getParam[3] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exported, sizeof(exported), 0},
        BSL_PARAM_END
    };

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    BSL_Uint32ToByte((uint32_t)lmsType, pubKey);
    BSL_Uint32ToByte((uint32_t)otsType, pubKey + 4);
    ASSERT_NE(HssEalSetRawPubKey(ctx, 1, pubKey, sizeof(pubKey)), CRYPT_SUCCESS);

    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, pubKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W4, pubKey + 4);
    ASSERT_EQ(HssEalSetRawPubKey(ctx, 1, pubKey, sizeof(pubKey)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, getParam), CRYPT_SUCCESS);
    ASSERT_EQ(levels, 1);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_RFC9858_PUBKEY_REJECT_TC001
* @spec  RFC 9858
* @title  Reject unsupported RFC 9858 public keys without replacing the old key
* @precon  nan
* @brief  Import n=24 and SHAKE public-key encodings into an RFC 8554 context
* @expect  Every unsupported key is rejected and the original public key remains unchanged
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_RFC9858_PUBKEY_REJECT_TC001(Hex *originalPubKey)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *referenceCtx = NULL;
    BSL_Param pubParam[2] = {0};
    /* 3 invalid encodings are tested against the unchanged reference key. */
    uint8_t invalidPubKeys[3][HSS_SHA256_N32_PUBKEY_LEN];
    /* 48 is the RFC 9858 n=24 form; 56 is the supported n=32 form length. */
    uint32_t invalidPubKeyLens[] = {48, 56, 56};
    /* These are RFC 9858/ SHAKE type codes that this implementation rejects. */
    uint32_t invalidLmsTypes[] = {0x0000000A, 0x0000000A, 0x0000000F};
    uint32_t invalidOtsTypes[] = {0x00000008, 0x00000008, 0x0000000C};
    uint8_t exportedPubKey[HSS_SHA256_N32_PUBKEY_LEN] = {0};
    uint32_t i;
    uint32_t j;

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    referenceCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL && referenceCtx != NULL);
    ASSERT_EQ(originalPubKey->len, HSS_SHA256_N32_WIRE_PUBKEY_LEN);

    ASSERT_EQ(HssEalSetPubKey(ctx, originalPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(HssEalSetPubKey(referenceCtx, originalPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, referenceCtx), CRYPT_SUCCESS);

    for (i = 0; i < 3; i++) { // 3 invalid public-key encodings cover the n=24 and SHAKE variants.
        (void)memset(invalidPubKeys[i], 0xA5, sizeof(invalidPubKeys[i]));
        BSL_Uint32ToByte(invalidLmsTypes[i], invalidPubKeys[i]);
        BSL_Uint32ToByte(invalidOtsTypes[i], invalidPubKeys[i] + 4);
        for (j = 0; j < 16; j++) {
            invalidPubKeys[i][8 + j] = (uint8_t)j;
        }
    }

    for (i = 0; i < 3; i++) { // 3 invalid public-key encodings cover the n=24 and SHAKE variants.
        BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            invalidPubKeys[i], invalidPubKeyLens[i]);
        ASSERT_NE(CRYPT_EAL_PkeySetPubEx(ctx, pubParam), CRYPT_SUCCESS);

        (void)memset(exportedPubKey, 0, sizeof(exportedPubKey));
        BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            exportedPubKey, sizeof(exportedPubKey));
        ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_SUCCESS);
        ASSERT_EQ(pubParam[0].useLen, HSS_SHA256_N32_PUBKEY_LEN);
        ASSERT_COMPARE("public key", originalPubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN,
            exportedPubKey, pubParam[0].useLen);
        ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, referenceCtx), CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(referenceCtx);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

static void HssEalBoundaryVerify(Hex *pubKey, Hex *msg, Hex *sig)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t *mutSig = NULL;

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HssEalSetPubKey(ctx, pubKey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);

    mutSig = malloc(sig->len);
    ASSERT_TRUE(mutSig != NULL);
    (void)memcpy(mutSig, sig->x, sig->len);
    mutSig[0] ^= 0xFF; // 0xFF flips every bit of the first signature byte.
    ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, mutSig, sig->len), CRYPT_SUCCESS);

EXIT:
    free(mutSig);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}

/* BEGIN_CASE */
void SDV_CRYPTO_HSS_NSPK_BOUNDARY_TC001(Hex *pubKey, Hex *msg, Hex *sig)
{
    HssEalBoundaryVerify(pubKey, msg, sig);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HSS_SIGNATURE_LENGTH_MATRIX_TC001(Hex *pubKey, Hex *msg, Hex *sig)
{
    HssEalBoundaryVerify(pubKey, msg, sig);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HSS_TYPE_CODE_MATRIX_TC001(Hex *pubKey, Hex *msg, Hex *sig)
{
    HssEalBoundaryVerify(pubKey, msg, sig);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HSS_Q_BOUNDARY_TC001(Hex *pubKey, Hex *msg, Hex *sig)
{
    HssEalBoundaryVerify(pubKey, msg, sig);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_HSS_MESSAGE_BOUNDARY_TC001(Hex *pubKey, Hex *msg, Hex *sig)
{
    HssEalBoundaryVerify(pubKey, msg, sig);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_UNSUPPORTED_PKEY_OPS_TC001
* @spec  RFC 8554
* @title  HSS EAL unsupported key-operation boundary
* @brief  Keep one generic dispatch smoke test for the production boundary:
*         HSS/LMS currently exposes public-key verification only.
* @expect  Key generation and both EAL signing entry points do not report success.
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_UNSUPPORTED_PKEY_OPS_TC001(void)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint8_t msg[1] = {0};
    uint8_t digest[32] = {0};
    uint8_t sign[4096] = {0}; // 4096 bytes is a generic signing scratch buffer for the dispatch check.
    uint32_t signLen = sizeof(sign);

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_NE(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, msg, sizeof(msg), sign, &signLen), CRYPT_SUCCESS);
    signLen = sizeof(sign);
    ASSERT_NE(CRYPT_EAL_PkeySignData(ctx, digest, sizeof(digest), sign, &signLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_CTRL_UNSUPPORTED_MATRIX_TC001
* @spec  RFC 8554
* @title  HSS Ctrl is unsupported
* @precon  nan
* @brief  Test legacy and provider contexts
* @expect  Ctrl is not registered
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_CTRL_UNSUPPORTED_MATRIX_TC001(int isProvider)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t id = CRYPT_HSS_SHA256_L1_H5_W4;

    TestMemInit();

    ctx = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id)),
        CRYPT_EAL_ALG_NOT_SUPPORT);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_PUBKEY_INPUT_MATRIX_TC001
* @spec  RFC 8554
* @title  HSS public key import/export input and field content matrix
* @precon  nan
* @brief  Test NULL params, missing pubkey param, wrong lengths, invalid headers,
*         byte patterns, and verify original key preservation after failed imports
* @expect  All invalid inputs rejected; original key preserved; byte patterns maintained
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_PUBKEY_INPUT_MATRIX_TC001(int isProvider, Hex *validPubKey)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    CRYPT_EAL_PkeyCtx *refCtx = NULL;
    BSL_Param pubParam[2] = {0};
    /* +1 supplies a trailing write-detection sentinel. */
    uint8_t exportedKey[HSS_SHA256_N32_PUBKEY_LEN + 1];
    uint8_t invalidKey[HSS_SHA256_N32_PUBKEY_LEN];
    uint8_t shortKey[HSS_SHA256_N32_PUBKEY_LEN - 1];
    uint8_t longKey[HSS_SHA256_N32_PUBKEY_LEN + 1];
    uint32_t useLen = 0;
    /* The imported fixture is a 2-level HSS public key. */
    uint32_t levels = 2;

    TestMemInit();

    ctx = CreateHssContext(isProvider);
    refCtx = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx != NULL && refCtx != NULL);

    ASSERT_EQ(HssEalSetPubKey(ctx, validPubKey), CRYPT_SUCCESS);
    ASSERT_EQ(HssEalSetPubKey(refCtx, validPubKey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, NULL), CRYPT_NULL_INPUT);

    (void)memset(shortKey, 0xA5, sizeof(shortKey));
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, shortKey, sizeof(shortKey)), CRYPT_HSS_INVALID_KEY_LEN);

    (void)memset(longKey, 0xA5, sizeof(longKey));
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, longKey, sizeof(longKey)), CRYPT_HSS_INVALID_KEY_LEN);

    (void)memset(invalidKey, 0, sizeof(invalidKey));
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, invalidKey, sizeof(invalidKey)), CRYPT_HSS_INVALID_PARAM);

    (void)memset(invalidKey, 0xFF, sizeof(invalidKey));
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, invalidKey, sizeof(invalidKey)), CRYPT_HSS_INVALID_PARAM);

    (void)memcpy(invalidKey, validPubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN);
    BSL_Uint32ToByte(99, invalidKey);
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, invalidKey, sizeof(invalidKey)), CRYPT_HSS_INVALID_PARAM);

    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, sizeof(exportedKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubParam[0].useLen, HSS_SHA256_N32_PUBKEY_LEN);
    ASSERT_COMPARE("preserved key", validPubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN,
        exportedKey, pubParam[0].useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, refCtx), CRYPT_SUCCESS);

    (void)memcpy(invalidKey, validPubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN);
    /* Offset 20 is an interior key byte; zero verifies embedded zero preservation. */
    invalidKey[20] = 0x00;
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, invalidKey, sizeof(invalidKey)), CRYPT_SUCCESS);
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, sizeof(exportedKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(exportedKey[20], 0x00);

    (void)memcpy(invalidKey, validPubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN);
    invalidKey[HSS_SHA256_N32_PUBKEY_LEN - 1] = 0x00;
    ASSERT_EQ(HssEalSetRawPubKey(ctx, levels, invalidKey, sizeof(invalidKey)), CRYPT_SUCCESS);
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, sizeof(exportedKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(exportedKey[HSS_SHA256_N32_PUBKEY_LEN - 1], 0x00);

    useLen = HSS_SHA256_N32_PUBKEY_LEN - 1;
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_HSS_INVALID_KEY_LEN);

    useLen = HSS_SHA256_N32_PUBKEY_LEN;
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubParam[0].useLen, HSS_SHA256_N32_PUBKEY_LEN);

    useLen = HSS_SHA256_N32_PUBKEY_LEN + 1;
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    /* 0xA5 is the byte beyond the key and must remain untouched. */
    exportedKey[HSS_SHA256_N32_PUBKEY_LEN] = 0xA5;
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubParam[0].useLen, HSS_SHA256_N32_PUBKEY_LEN);
    ASSERT_EQ(exportedKey[HSS_SHA256_N32_PUBKEY_LEN], 0xA5);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(refCtx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_CMP_FIELD_MATRIX_TC001
* @spec  RFC 8554
* @title  HSS context comparison field matrix
* @precon  nan
* @brief  Test NULL comparisons, same/different params, same/different keys,
*         byte-level differences in I and root, and byte patterns
* @expect  Comparison respects all fields; byte patterns preserved
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_CMP_FIELD_MATRIX_TC001(int isProvider, Hex *pubKey1, Hex *pubKey2)
{
    CRYPT_EAL_PkeyCtx *ctx1 = NULL;
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    uint32_t levels = 2; // The comparison fixture uses a 2-level HSS public key.
    uint8_t modifiedKey[HSS_SHA256_N32_PUBKEY_LEN];

    (void)pubKey2;

    TestMemInit();

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(NULL, NULL), CRYPT_SUCCESS);

    ctx1 = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(NULL, ctx1), CRYPT_NULL_INPUT);

    ctx2 = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    ASSERT_EQ(HssEalSetPubKey(ctx1, pubKey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    ASSERT_EQ(HssEalSetPubKey(ctx2, pubKey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    (void)memcpy(modifiedKey, pubKey1->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN);
    modifiedKey[12] ^= 0x01; // Offsets 12 cover an early key byte.
    ASSERT_EQ(HssEalSetRawPubKey(ctx2, levels, modifiedKey, sizeof(modifiedKey)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    (void)memcpy(modifiedKey, pubKey1->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN);
    modifiedKey[HSS_SHA256_N32_PUBKEY_LEN - 1] ^= 0x01;
    ASSERT_EQ(HssEalSetRawPubKey(ctx2, levels, modifiedKey, sizeof(modifiedKey)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    (void)memcpy(modifiedKey, pubKey1->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN);
    modifiedKey[30] ^= 0x01; // Offsets 30 cover an final key byte.
    ASSERT_EQ(HssEalSetRawPubKey(ctx2, levels, modifiedKey, sizeof(modifiedKey)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    (void)memset(modifiedKey, 0x00, HSS_SHA256_N32_PUBKEY_LEN); // 0x00 exercise degenerate full-payload patterns.
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, modifiedKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, modifiedKey + 4);
    ASSERT_EQ(HssEalSetRawPubKey(ctx2, levels, modifiedKey, sizeof(modifiedKey)), CRYPT_SUCCESS);
    ASSERT_EQ(HssEalSetRawPubKey(ctx1, levels, modifiedKey, sizeof(modifiedKey)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    (void)memset(modifiedKey, 0xFF, HSS_SHA256_N32_PUBKEY_LEN); // 0xFF exercise degenerate full-payload patterns.
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, modifiedKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, modifiedKey + 4);
    ASSERT_EQ(HssEalSetRawPubKey(ctx2, levels, modifiedKey, sizeof(modifiedKey)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_DUPCTX_INDEPENDENCE_TC001
* @spec  RFC 8554
* @title  HSS duplicated context independence
* @precon  nan
* @brief  Verify that duplicated context is independent: freeing source doesn't
*         affect copy, modifying source doesn't affect copy
* @expect  Copy remains functional after source modifications
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_DUPCTX_INDEPENDENCE_TC001(int isProvider, Hex *pubKey)
{
    CRYPT_EAL_PkeyCtx *srcCtx = NULL;
    CRYPT_EAL_PkeyCtx *dupCtx = NULL;
    BSL_Param pubParam[2] = {0};
    uint8_t srcKey[HSS_SHA256_N32_PUBKEY_LEN];
    uint8_t dupKey[HSS_SHA256_N32_PUBKEY_LEN];
    /* The source and duplicate both use a two-level HSS public key. */
    uint32_t levels = 2;

    TestMemInit();

    srcCtx = CreateHssContext(isProvider);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_EQ(HssEalSetPubKey(srcCtx, pubKey), CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(srcCtx);
    ASSERT_TRUE(dupCtx != NULL);

    (void)memset(srcKey, 0, sizeof(srcKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, srcKey, sizeof(srcKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(srcCtx, pubParam), CRYPT_SUCCESS);
    (void)memset(dupKey, 0, sizeof(dupKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, dupKey, sizeof(dupKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dupCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("src and dup keys", srcKey, HSS_SHA256_N32_PUBKEY_LEN, dupKey, HSS_SHA256_N32_PUBKEY_LEN);

    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    srcCtx = NULL;

    (void)memset(dupKey, 0, sizeof(dupKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, dupKey, sizeof(dupKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dupCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("dup key after free", pubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN,
        dupKey, pubParam[0].useLen);

    srcCtx = CreateHssContext(isProvider);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_EQ(HssEalSetPubKey(srcCtx, pubKey), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    dupCtx = NULL;
    dupCtx = CRYPT_EAL_PkeyDupCtx(srcCtx);
    ASSERT_TRUE(dupCtx != NULL);

    /* 0xA5 makes any unexpected source-key overwrite visible in the duplicate check. */
    (void)memset(srcKey, 0xA5, HSS_SHA256_N32_PUBKEY_LEN);
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, srcKey);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, srcKey + 4);
    ASSERT_EQ(HssEalSetRawPubKey(srcCtx, levels, srcKey, sizeof(srcKey)), CRYPT_SUCCESS);

    (void)memset(dupKey, 0, sizeof(dupKey));
    BSL_PARAM_InitValue(pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, dupKey, sizeof(dupKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dupCtx, pubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("dup key unchanged", pubKey->x + HSS_LEVEL_FIELD_LEN, HSS_SHA256_N32_PUBKEY_LEN,
        dupKey, pubParam[0].useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(srcCtx, dupCtx), CRYPT_HSS_CMP_FALSE);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    return;
}
/* END_CASE */
