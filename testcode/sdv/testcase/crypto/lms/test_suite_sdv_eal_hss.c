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
#include "bsl_err.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_hss.h"
#include "crypt_params_key.h"
#include "test.h"

/* END_HEADER */

static uint8_t g_hssEalTestRandValue = 0x42;

static int32_t HssEalTestRand(uint8_t *randBuf, uint32_t len)
{
    if (randBuf == NULL || len == 0) {
        return CRYPT_NULL_INPUT;
    }
    for (uint32_t i = 0; i < len; i++) {
        randBuf[i] = g_hssEalTestRandValue++;
    }
    return CRYPT_SUCCESS;
}

static CRYPT_EAL_PkeyCtx *CreateHssContext(int isProvider)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_HSS, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    }
#endif
    (void)isProvider;
    return CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS);
}

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_API_TC001(int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_SetRandCallBack(HssEalTestRand);

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

    ret = CRYPT_EAL_PkeyGen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx2 = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx2 != NULL);

    ret = CRYPT_EAL_PkeyCtrl(ctx2, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ctx3 = CRYPT_EAL_PkeyDupCtx(ctx1);
    ASSERT_TRUE(ctx3 != NULL);

    const uint8_t msg[] = "Test message for HSS EAL dup";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192] = {0};
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_EAL_PkeySign(ctx3, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_HSS_NO_KEY);

    sigLen = sizeof(sig);
    ret = CRYPT_EAL_PkeySign(ctx1, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(ctx3, CRYPT_MD_SHA256, msg, msgLen, sig, sigLen);
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
* @title  CRYPT_CTRL_SET_PARA_BY_ID cannot be called twice on the same HSS context
* @brief
* 1.Create an HSS pkey context.
* 2.Set para by id with CRYPT_HSS_SHA256_L2_H10_H10, expected CRYPT_SUCCESS.
* 3.Set para by id again, expected CRYPT_HSS_CTRL_INIT_REPEATED.
* @expect  second set returns CRYPT_HSS_CTRL_INIT_REPEATED
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_SET_PARA_ID_REPEATED_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS);
    ASSERT_TRUE(ctx != NULL);

    int32_t algId = CRYPT_HSS_SHA256_L2_H10_H10;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_SUCCESS);

    /* Set the same algId again — must be rejected */
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&algId, sizeof(algId)), CRYPT_HSS_CTRL_INIT_REPEATED);

    /* Set a different algId — also must be rejected */
    int32_t otherAlgId = CRYPT_HSS_SHA256_L2_H15_H15;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID,
        (void *)&otherAlgId, sizeof(otherAlgId)), CRYPT_HSS_CTRL_INIT_REPEATED);

    BSL_ERR_ClearError();
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_SIGN_VERIFY_TC001(int isProvider)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_SetRandCallBack(HssEalTestRand);

    CRYPT_EAL_PkeyCtx *ctx = CreateHssContext(isProvider);
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    const uint8_t msg[] = "Test message for HSS EAL signature";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192] = {0};
    uint32_t sigLen = sizeof(sig);
    const uint8_t wrongMsg[] = "Wrong message";

    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, wrongMsg, sizeof(wrongMsg) - 1, sig, sigLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_CTRL_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_SetRandCallBack(HssEalTestRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS);
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
    uint64_t remaining = 0;
    uint32_t pubKeyLen = 0;

    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lmstype, sizeof(lmstype), 0},
        {CRYPT_PARAM_HSS_LEVEL2_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &otstype, sizeof(otstype), 0},
        BSL_PARAM_END
    };
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_REMAINING, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(remaining > 0);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(pubKeyLen > 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_HSS_LMS_ROUNDTRIP_PARAM_TC001
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
void SDV_CRYPTO_HSS_LMS_ROUNDTRIP_PARAM_TC001(int lmsType, int otsType)
{
    uint8_t *sig = NULL;
    TestMemInit();
    CRYPT_EAL_SetRandCallBack(HssEalTestRand);

    CRYPT_HSS_Ctx *ctx = CRYPT_HSS_NewCtx();
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 1;
    uint32_t lms = (uint32_t)lmsType;
    uint32_t ots = (uint32_t)otsType;
    BSL_Param params[6] = {
        {CRYPT_PARAM_HSS_LEVEL, BSL_PARAM_TYPE_UINT32, &levels, sizeof(levels), 0},
        {CRYPT_PARAM_HSS_LEVEL1_LMS_TYPE, BSL_PARAM_TYPE_UINT32, &lms, sizeof(lms), 0},
        {CRYPT_PARAM_HSS_LEVEL1_OTS_TYPE, BSL_PARAM_TYPE_UINT32, &ots, sizeof(ots), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_SET_PARAM, params, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_Gen(ctx), CRYPT_SUCCESS);

    uint32_t sigLen = 0;
    ASSERT_EQ(CRYPT_HSS_Ctrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &sigLen, sizeof(sigLen)), CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);
    sig = (uint8_t *)BSL_SAL_Malloc(sigLen);
    ASSERT_TRUE(sig != NULL);

    const uint8_t msg[] = "LMS roundtrip coverage message";
    uint32_t msgLen = sizeof(msg) - 1;
    ASSERT_EQ(CRYPT_HSS_Sign(ctx, 0, msg, msgLen, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HSS_Verify(ctx, 0, msg, msgLen, sig, sigLen), CRYPT_SUCCESS);

    /* Tampered message must fail verification */
    uint8_t badMsg[sizeof(msg) - 1];
    memcpy(badMsg, msg, msgLen);
    badMsg[0] ^= 0x01;
    ASSERT_NE(CRYPT_HSS_Verify(ctx, 0, badMsg, msgLen, sig, sigLen), CRYPT_SUCCESS);

    /* Tampered signature must fail verification */
    sig[sigLen / 2] ^= 0x01;
    ASSERT_NE(CRYPT_HSS_Verify(ctx, 0, msg, msgLen, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    BSL_SAL_Free(sig);
    CRYPT_HSS_FreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */
