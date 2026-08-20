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

/* RFC 8554 public keys contain a 4-byte level, two type codes, a 16-byte ID and a 32-byte root. */
#define CRYPT_HSS_PUBKEY_LEN 60
/* H=5/W=8 LMS signature and child-key lengths used by the boundary vectors. */
#define HSS_H5_W8_LMS_SIG_LEN 1292
#define HSS_H5_W8_CHILD_PUBKEY_LEN 56
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

static int32_t HssEalTestSetParam(CRYPT_EAL_PkeyCtx *ctx, uint32_t levels,
    uint32_t lmsType1, uint32_t otsType1, uint32_t lmsType2, uint32_t otsType2,
    uint32_t lmsType3, uint32_t otsType3)
{
    BSL_Param params[8] = { // 8: 7 HSS parameters plus the BSL_PARAM_END terminator.
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmsType1, sizeof(lmsType1), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otsType1, sizeof(otsType1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmsType2, sizeof(lmsType2), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otsType2, sizeof(otsType2), 0},
        {CRYPT_PARAM_HSS_LEVEL3_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmsType3, sizeof(lmsType3), 0},
        {CRYPT_PARAM_HSS_LEVEL3_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otsType3, sizeof(otsType3), 0},
        BSL_PARAM_END
    };
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
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
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx1, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx2 = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx2 != NULL);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam = { 0 };
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx1, &pubParam), CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ctx3 = CRYPT_EAL_PkeyDupCtx(ctx1);
    ASSERT_TRUE(ctx3 != NULL);
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx3);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCopyCtx(ctx2, ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_EAL_HSS_SET_PARA_ID_REPEATED_TC001
* @spec  -
* @title  Test CRYPT_CTRL_SET_PARA_BY_ID and CRYPT_CTRL_HSS_SET_PARAM
* @brief
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_SET_PARA_ID_REPEATED_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    int32_t algId = CRYPT_HSS_SHA256_L2_H10_H10_W4;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_SUCCESS);

    /* Set the same algId again — must be rejected */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &algId, sizeof(algId)), CRYPT_HSS_CTRL_INIT_REPEATED);

    /* Set a different algId — also must be rejected */
    int32_t otherAlgId = CRYPT_HSS_SHA256_L2_H15_H15_W4;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &otherAlgId, sizeof(otherAlgId)),
        CRYPT_HSS_CTRL_INIT_REPEATED);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H10;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W4;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_HSS_CTRL_INIT_REPEATED);

    ctx2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx2 != NULL);
    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    // This tests is to verify that the parameters set in the two methods are the same.
    ret = CRYPT_EAL_PkeyCmp(ctx, ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_ERR_ClearError();
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
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

    uint32_t levels = 2;
    uint32_t lmstype0 = lmsType0;
    uint32_t otstype0 = otsType0;
    uint32_t lmstype1 = lmsType1;
    uint32_t otstype1 = otsType1;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype0, sizeof(lmstype0), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype0, sizeof(otstype0), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sig->x, sig->len), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

static int32_t HssTestVerify(CRYPT_EAL_PkeyCtx *ctx, int lmsType0, int otsType0, int lmsType1, int otsType1,
    Hex *pubKey, Hex *msg, Hex *sig) {
    uint32_t levels = 2;
    uint32_t lmstype0 = lmsType0;
    uint32_t otstype0 = otsType0;
    uint32_t lmstype1 = lmsType1;
    uint32_t otstype1 = otsType1;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype0, sizeof(lmstype0), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype0, sizeof(otstype0), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype1, sizeof(lmstype1), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype1, sizeof(otstype1), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ret = CRYPT_EAL_PkeySetPubEx(ctx, &pubParam);
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
* @test  SDV_CRYPTO_HSS_PRESET_PARAM_MATRIX_TC001
* @spec  RFC 8554
* @title  Verify the complete HSS preset parameter mapping
* @precon  nan
* @brief  Set every supported preset ID and check its level, public-key length,
*         and signature length through the public EAL interface
* @expect  All 15 preset IDs map to the expected parameters and lengths
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_PRESET_PARAM_MATRIX_TC001(int algId, int expectedLevels, int expectedSigLen)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t id = algId;
    uint32_t levels = 0;
    uint32_t pubKeyLen = 0;
    uint32_t sigLen = 0;

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &id, sizeof(id)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &levels, sizeof(levels)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_EQ(levels, (uint32_t)expectedLevels);
    ASSERT_EQ(pubKeyLen, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(sigLen, (uint32_t)expectedSigLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_CUSTOM_PARAM_MATRIX_TC001
* @spec  RFC 8554
* @title  Verify custom LMS height, LMOTS width, and HSS level combinations
* @precon  nan
* @brief  Set each supported custom parameter combination and check exact lengths
* @expect  Every supported combination initializes and reports the expected lengths
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_CUSTOM_PARAM_MATRIX_TC001(int levels, int lmsType1, int otsType1,
    int lmsType2, int otsType2, int lmsType3, int otsType3, int expectedSigLen)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t actualLevels = 0;
    uint32_t pubKeyLen = 0;
    uint32_t sigLen = 0;

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(HssEalTestSetParam(ctx, (uint32_t)levels,
        (uint32_t)lmsType1, (uint32_t)otsType1, (uint32_t)lmsType2, (uint32_t)otsType2,
        (uint32_t)lmsType3, (uint32_t)otsType3), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &actualLevels, sizeof(actualLevels)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_EQ(actualLevels, (uint32_t)levels);
    ASSERT_EQ(pubKeyLen, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(sigLen, (uint32_t)expectedSigLen);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_LEVEL_BOUNDARY_TC001
* @spec  RFC 8554
* @title  Verify the HSS level boundary from zero through eight
* @precon  nan
* @brief  Accept levels one through three, reject all other RFC range boundaries,
*         and verify that rejected configuration does not contaminate the context
* @expect  Only levels one through three work; rejected levels leave a reusable context
* @prior  Level 0
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_LEVEL_BOUNDARY_TC001(int inputLevels, int expectSuccess, int expectedSigLen)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t effectiveLevels = (uint32_t)inputLevels;
    uint32_t effectiveSigLen = (uint32_t)expectedSigLen;
    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;
    int32_t ret;
    uint32_t actualLevels = 0;
    uint32_t pubKeyLen = 0;
    uint32_t sigLen = 0;
    uint32_t length = 0;
    uint8_t invalidPubKey[CRYPT_HSS_PUBKEY_LEN] = {0};
    BSL_Param invalidPubParam;

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    ret = HssEalTestSetParam(ctx, effectiveLevels, lmsType, otsType,
        lmsType, otsType, lmsType, otsType);

    if (expectSuccess != 0) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    } else {
        ASSERT_NE(ret, CRYPT_SUCCESS);

        actualLevels = UINT32_MAX;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &actualLevels, sizeof(actualLevels)), 0);
        ASSERT_EQ(actualLevels, 0);
        ASSERT_NE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
        ASSERT_NE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &length, sizeof(length)), CRYPT_SUCCESS);

        BSL_PARAM_InitValue(&invalidPubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            invalidPubKey, sizeof(invalidPubKey));
        ASSERT_NE(CRYPT_EAL_PkeySetPubEx(ctx, &invalidPubParam), CRYPT_SUCCESS);
        ASSERT_NE(CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, invalidPubKey, 1,invalidPubKey, 1), CRYPT_SUCCESS);

        effectiveLevels = 1;
        effectiveSigLen = 2352; // 2352 is the expected signature length for the supported H5/W4 test vector
        otsType = CRYPT_LMOTS_SHA256_N32_W4;
        ASSERT_EQ(HssEalTestSetParam(ctx, effectiveLevels, lmsType, otsType, lmsType, otsType, lmsType, otsType), 0);
    }

    actualLevels = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &actualLevels, sizeof(actualLevels)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_EQ(actualLevels, effectiveLevels);
    ASSERT_EQ(pubKeyLen, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(sigLen, effectiveSigLen);

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
    uint32_t levels = UINT32_MAX;
    uint32_t length = 0;

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_NE(HssEalTestSetParam(ctx, 1, (uint32_t)lmsType, (uint32_t)otsType, 0, 0, 0, 0), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &levels, sizeof(levels)), CRYPT_SUCCESS);
    ASSERT_EQ(levels, 0);
    ASSERT_NE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &length, sizeof(length)), CRYPT_SUCCESS);

    ASSERT_EQ(HssEalTestSetParam(ctx, 1, CRYPT_LMS_SHA256_M32_H5, CRYPT_LMOTS_SHA256_N32_W4, 0, 0, 0, 0), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &levels, sizeof(levels)), CRYPT_SUCCESS);
    ASSERT_EQ(levels, 1);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_EQ(length, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_EQ(length, 2352); // 2352 is the expected signature length for the supported H5/W4 test vector.

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
    BSL_Param pubParam;
    /* 3 invalid encodings are tested against the unchanged reference key. */
    uint8_t invalidPubKeys[3][CRYPT_HSS_PUBKEY_LEN];
    /* 52 is the RFC 9858 n=24 form; 60 is the supported n=32 form length. */
    uint32_t invalidPubKeyLens[] = {52, 60, 60};
    /* These are RFC 9858/ SHAKE type codes that this implementation rejects. */
    uint32_t invalidLmsTypes[] = {0x0000000A, 0x0000000A, 0x0000000F};
    uint32_t invalidOtsTypes[] = {0x00000008, 0x00000008, 0x0000000C};
    uint8_t exportedPubKey[CRYPT_HSS_PUBKEY_LEN] = {0};
    uint32_t i;
    uint32_t j;

    TestMemInit();

    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    referenceCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL && referenceCtx != NULL);
    ASSERT_EQ(originalPubKey->len, CRYPT_HSS_PUBKEY_LEN);

    /*  */
    ASSERT_EQ(HssEalTestSetParam(ctx, 2, CRYPT_LMS_SHA256_M32_H5, // 2 levels
        CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMS_SHA256_M32_H5,
        CRYPT_LMOTS_SHA256_N32_W8, 0, 0), CRYPT_SUCCESS);
    ASSERT_EQ(HssEalTestSetParam(referenceCtx, 2, CRYPT_LMS_SHA256_M32_H5, // 2 levels
        CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMS_SHA256_M32_H5,
        CRYPT_LMOTS_SHA256_N32_W8, 0, 0), CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
        originalPubKey->x, originalPubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
        originalPubKey->x, originalPubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(referenceCtx, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, referenceCtx), CRYPT_SUCCESS);

    for (i = 0; i < 3; i++) { // 3 invalid public-key encodings cover the n=24 and SHAKE variants.
        (void)memset(invalidPubKeys[i], 0xA5, sizeof(invalidPubKeys[i]));
        /* 2 is the two-level hierarchy field at the start of each key. */
        BSL_Uint32ToByte(2, invalidPubKeys[i]);
        BSL_Uint32ToByte(invalidLmsTypes[i], invalidPubKeys[i] + 4);
        BSL_Uint32ToByte(invalidOtsTypes[i], invalidPubKeys[i] + 8);
        /* The 12-byte header is followed by a 16-byte deterministic payload prefix. */
        for (j = 0; j < 16; j++) {
            invalidPubKeys[i][12 + j] = (uint8_t)j;
        }
    }

    for (i = 0; i < 3; i++) { // 3 invalid public-key encodings cover the n=24 and SHAKE variants.
        BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            invalidPubKeys[i], invalidPubKeyLens[i]);
        ASSERT_NE(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);

        (void)memset(exportedPubKey, 0, sizeof(exportedPubKey));
        BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            exportedPubKey, sizeof(exportedPubKey));
        ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
        ASSERT_EQ(pubParam.useLen, CRYPT_HSS_PUBKEY_LEN);
        ASSERT_COMPARE("public key", originalPubKey->x, originalPubKey->len, exportedPubKey, pubParam.useLen);
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
    BSL_Param pubParam;
    uint8_t *mutSig = NULL;

    TestMemInit();
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);
    /* Verify a 2-level HSS signature and then mutate its first byte. */
    ASSERT_EQ(HssEalTestSetParam(ctx, 2, CRYPT_LMS_SHA256_M32_H5, CRYPT_LMOTS_SHA256_N32_W8, CRYPT_LMS_SHA256_M32_H5,
        CRYPT_LMOTS_SHA256_N32_W8, 0, 0), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
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
    ASSERT_EQ(HssEalTestSetParam(ctx, 1, CRYPT_LMS_SHA256_M32_H5, CRYPT_LMOTS_SHA256_N32_W8, 0, 0, 0, 0), 0);

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
* @test  SDV_CRYPTO_HSS_CTRL_INPUT_MATRIX_TC001
* @spec  RFC 8554
* @title  HSS Ctrl input validation and failure state matrix
* @precon  nan
* @brief  Test NULL context, NULL val, unknown command, wrong buffer lengths,
*         incomplete BSL_Param arrays, and verify recovery after failures
* @expect  All invalid inputs are rejected; context remains recoverable
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_HSS_CTRL_INPUT_MATRIX_TC001(int isProvider)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    uint32_t levels = 0;
    uint32_t length = 0;
    /* */
    int32_t unknownCmd = 99999; // 99999 is outside the registered command and parameter-ID ranges.
    int32_t unknownId = 99999; // 99999 is outside the registered command and parameter-ID ranges.
    uint8_t shortBuf[3] = {0}; // 3-byte buffers deliberately violate the four-byte scalar contract.
    uint8_t longBuf[5] = {0}; // 5-byte buffers deliberately violate the four-byte scalar contract.
    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    BSL_Param incompleteParams[3]; // Three entries contain level, one type and an explicit incomplete terminator.

    TestMemInit();

    ctx = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_HSS_GET_LEVELS, &levels, sizeof(levels)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, NULL, sizeof(levels)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, unknownCmd, &levels, sizeof(levels)), CRYPT_HSS_INVALID_CMD);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, shortBuf, 3), CRYPT_HSS_INVALID_PARAM);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, longBuf, 5), CRYPT_HSS_INVALID_PARAM);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, NULL, 0), CRYPT_NULL_INPUT);

    incompleteParams[0].key = CRYPT_PARAM_HSS_LEVEL;
    incompleteParams[0].valueType = BSL_PARAM_TYPE_UINT32;
    incompleteParams[0].value = &levels;
    incompleteParams[0].valueLen = sizeof(levels);
    incompleteParams[0].useLen = 0;
    incompleteParams[1].key = CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE;
    incompleteParams[1].valueType = BSL_PARAM_TYPE_UINT32;
    incompleteParams[1].value = &lmsType;
    incompleteParams[1].valueLen = sizeof(lmsType);
    incompleteParams[1].useLen = 0;
    incompleteParams[2].key = 0;
    incompleteParams[2].valueType = 0;
    incompleteParams[2].value = NULL;
    incompleteParams[2].valueLen = 0;
    incompleteParams[2].useLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, incompleteParams, 0), CRYPT_HSS_INVALID_LEVEL);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &unknownId, sizeof(unknownId)),
        CRYPT_HSS_INVALID_PARAM);
    /* Length 2 is intentionally neither zero nor the required four-byte ID width. */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &unknownId, 2), CRYPT_INVALID_ARG);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &levels, sizeof(levels)), CRYPT_SUCCESS);
    ASSERT_EQ(levels, 0);

    ASSERT_EQ(HssEalTestSetParam(ctx, 1, CRYPT_LMS_SHA256_M32_H5, CRYPT_LMOTS_SHA256_N32_W4, 0, 0, 0, 0),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &levels, sizeof(levels)), CRYPT_SUCCESS);
    ASSERT_EQ(levels, 1);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_EQ(length, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &length, sizeof(length)), CRYPT_SUCCESS);
    ASSERT_EQ(length, 2352); // 2352 is the expected signature length for the supported H5/W4 test vector.

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
    BSL_Param pubParam;
    /* 60 is the valid key length; +1 supplies a trailing write-detection sentinel. */
    uint8_t exportedKey[CRYPT_HSS_PUBKEY_LEN + 1];
    uint8_t invalidKey[CRYPT_HSS_PUBKEY_LEN];
    /* 59 and 61 exercise one byte below and above the valid key length. */
    uint8_t shortKey[59];
    uint8_t longKey[61];
    uint32_t useLen = 0;
    /* The imported fixture is a 2-level HSS public key. */
    uint32_t levels = 2;
    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    TestMemInit();

    ctx = CreateHssContext(isProvider);
    refCtx = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx != NULL && refCtx != NULL);

    ASSERT_EQ(HssEalTestSetParam(ctx, levels, lmsType, otsType, lmsType, otsType, 0, 0), CRYPT_SUCCESS);
    ASSERT_EQ(HssEalTestSetParam(refCtx, levels, lmsType, otsType, lmsType, otsType, 0, 0), CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, validPubKey->x, validPubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, validPubKey->x, validPubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(refCtx, &pubParam), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, NULL), CRYPT_NULL_INPUT);

    (void)memset(shortKey, 0xA5, sizeof(shortKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, shortKey, sizeof(shortKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_HSS_INVALID_KEY_LEN);

    (void)memset(longKey, 0xA5, sizeof(longKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, longKey, sizeof(longKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_HSS_INVALID_KEY_LEN);

    (void)memset(invalidKey, 0, sizeof(invalidKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, invalidKey, sizeof(invalidKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_HSS_INVALID_PARAM);

    (void)memset(invalidKey, 0xFF, sizeof(invalidKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, invalidKey, sizeof(invalidKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_HSS_INVALID_PARAM);

    (void)memcpy(invalidKey, validPubKey->x, CRYPT_HSS_PUBKEY_LEN);
    /* 99 is an unregistered LMS type code in the 4-byte LMS type field. */
    BSL_Uint32ToByte(99, invalidKey + 4);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, invalidKey, sizeof(invalidKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_HSS_INVALID_PARAM);

    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, sizeof(exportedKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubParam.useLen, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_COMPARE("preserved key", validPubKey->x, validPubKey->len, exportedKey, pubParam.useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, refCtx), CRYPT_SUCCESS);

    (void)memcpy(invalidKey, validPubKey->x, CRYPT_HSS_PUBKEY_LEN);
    /* Offset 20 is an interior key byte; zero verifies embedded zero preservation. */
    invalidKey[20] = 0x00;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, invalidKey, sizeof(invalidKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, sizeof(exportedKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(exportedKey[20], 0x00);

    (void)memcpy(invalidKey, validPubKey->x, CRYPT_HSS_PUBKEY_LEN);
    /* Offset 59 is the final byte of the 60-byte key. */
    invalidKey[59] = 0x00;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, invalidKey, sizeof(invalidKey));
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, sizeof(exportedKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(exportedKey[59], 0x00);

    /* 59/60/61 are below, exact and above the valid public-key length. */
    useLen = 59;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_HSS_INVALID_KEY_LEN);

    useLen = 60;
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubParam.useLen, 60);

    useLen = 61;
    (void)memset(exportedKey, 0, sizeof(exportedKey));
    /* 0xA5 is the byte beyond the key and must remain untouched. */
    exportedKey[60] = 0xA5;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, exportedKey, useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(ctx, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(pubParam.useLen, 60);
    ASSERT_EQ(exportedKey[60], 0xA5);

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
    BSL_Param pubParam;
    uint32_t levels = 2; // The comparison fixture uses a 2-level HSS public key.
    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;
    uint8_t modifiedKey[CRYPT_HSS_PUBKEY_LEN];

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

    ASSERT_EQ(HssEalTestSetParam(ctx1, levels, lmsType, otsType, lmsType, otsType, 0, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    ASSERT_EQ(HssEalTestSetParam(ctx2, levels, lmsType, otsType, lmsType, otsType, 0, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey1->x, pubKey1->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx1, &pubParam), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey1->x, pubKey1->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    (void)memcpy(modifiedKey, pubKey1->x, CRYPT_HSS_PUBKEY_LEN);
    modifiedKey[12] ^= 0x01; // Offsets 12 cover an early key byte.
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, modifiedKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    (void)memcpy(modifiedKey, pubKey1->x, CRYPT_HSS_PUBKEY_LEN);
    modifiedKey[59] ^= 0x01; // Offsets 59 cover a middle key byte.
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, modifiedKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    (void)memcpy(modifiedKey, pubKey1->x, CRYPT_HSS_PUBKEY_LEN);
    modifiedKey[30] ^= 0x01; // Offsets 30 cover an final key byte.
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, modifiedKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_HSS_CMP_FALSE);

    (void)memset(modifiedKey, 0x00, CRYPT_HSS_PUBKEY_LEN); // 0x00 exercise degenerate full-payload patterns.
    /* 2 encodes the two-level hierarchy in the first four public-key bytes. */
    BSL_Uint32ToByte(2, modifiedKey);
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, modifiedKey + 4);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, modifiedKey + 8);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, modifiedKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, &pubParam), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, modifiedKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx1, &pubParam), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_SUCCESS);

    (void)memset(modifiedKey, 0xFF, CRYPT_HSS_PUBKEY_LEN); // 0xFF exercise degenerate full-payload patterns.
    /* Keep the hierarchy field at two levels while the remaining bytes are all-FF. */
    BSL_Uint32ToByte(2, modifiedKey);
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, modifiedKey + 4);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, modifiedKey + 8);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, modifiedKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(ctx2, &pubParam), CRYPT_SUCCESS);
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
    BSL_Param pubParam;
    uint8_t srcKey[CRYPT_HSS_PUBKEY_LEN];
    uint8_t dupKey[CRYPT_HSS_PUBKEY_LEN];
    /* The source and duplicate both use a two-level HSS public key. */
    uint32_t levels = 2;
    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    TestMemInit();

    srcCtx = CreateHssContext(isProvider);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_EQ(HssEalTestSetParam(srcCtx, levels, lmsType, otsType, lmsType, otsType, 0, 0), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(srcCtx, &pubParam), CRYPT_SUCCESS);

    dupCtx = CRYPT_EAL_PkeyDupCtx(srcCtx);
    ASSERT_TRUE(dupCtx != NULL);

    (void)memset(srcKey, 0, sizeof(srcKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, srcKey, sizeof(srcKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(srcCtx, &pubParam), CRYPT_SUCCESS);
    (void)memset(dupKey, 0, sizeof(dupKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, dupKey, sizeof(dupKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dupCtx, &pubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("src and dup keys", srcKey, CRYPT_HSS_PUBKEY_LEN, dupKey, CRYPT_HSS_PUBKEY_LEN);

    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    srcCtx = NULL;

    (void)memset(dupKey, 0, sizeof(dupKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, dupKey, sizeof(dupKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dupCtx, &pubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("dup key after free", pubKey->x, pubKey->len, dupKey, pubParam.useLen);

    srcCtx = CreateHssContext(isProvider);
    ASSERT_TRUE(srcCtx != NULL);
    ASSERT_EQ(HssEalTestSetParam(srcCtx, levels, lmsType, otsType, lmsType, otsType, 0, 0), CRYPT_SUCCESS);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(srcCtx, &pubParam), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    dupCtx = NULL;
    dupCtx = CRYPT_EAL_PkeyDupCtx(srcCtx);
    ASSERT_TRUE(dupCtx != NULL);

    /* 0xA5 makes any unexpected source-key overwrite visible in the duplicate check. */
    (void)memset(srcKey, 0xA5, CRYPT_HSS_PUBKEY_LEN);
    BSL_Uint32ToByte(2, srcKey); // 2 encodes the source key's two-level hierarchy field.
    BSL_Uint32ToByte(CRYPT_LMS_SHA256_M32_H5, srcKey + 4);
    BSL_Uint32ToByte(CRYPT_LMOTS_SHA256_N32_W8, srcKey + 8);
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, srcKey, CRYPT_HSS_PUBKEY_LEN);
    ASSERT_EQ(CRYPT_EAL_PkeySetPubEx(srcCtx, &pubParam), CRYPT_SUCCESS);

    (void)memset(dupKey, 0, sizeof(dupKey));
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, dupKey, sizeof(dupKey));
    ASSERT_EQ(CRYPT_EAL_PkeyGetPubEx(dupCtx, &pubParam), CRYPT_SUCCESS);
    ASSERT_COMPARE("dup key unchanged", pubKey->x, pubKey->len, dupKey, pubParam.useLen);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(srcCtx, dupCtx), CRYPT_HSS_CMP_FALSE);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(srcCtx);
    CRYPT_EAL_PkeyFreeCtx(dupCtx);
    return;
}
/* END_CASE */

