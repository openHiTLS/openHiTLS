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
#include "bsl_params.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "crypt_params_key.h"
#include "crypt_lms.h"
#include "test.h"

/* END_HEADER */

static uint8_t g_lmsEalTestRandValue = 0x42;

static int32_t LmsEalTestRand(uint8_t *randBuf, uint32_t len)
{
    if (randBuf == NULL || len == 0) {
        return CRYPT_NULL_INPUT;
    }
    for (uint32_t i = 0; i < len; i++) {
        randBuf[i] = g_lmsEalTestRandValue++;
    }
    return CRYPT_SUCCESS;
}

static CRYPT_EAL_PkeyCtx *CreateLmsContext(int isProvider)
{
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider == 1) {
        return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_LMS, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    }
#endif
    (void)isProvider;
    return CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_LMS);
}

static int32_t SetupLmsParams(CRYPT_EAL_PkeyCtx *ctx, uint32_t lmsType, uint32_t otsType)
{
    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
}

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_LMS_API_TC001(int isProvider)
{
    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
    CRYPT_EAL_SetRandCallBack(LmsEalTestRand);

    CRYPT_EAL_PkeyCtx *ctx1 = CreateLmsContext(isProvider);
    CRYPT_EAL_PkeyCtx *ctx2 = NULL;
    CRYPT_EAL_PkeyCtx *ctx3 = NULL;
    ASSERT_TRUE(ctx1 != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    int32_t ret = SetupLmsParams(ctx1, lmsType, otsType);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx1);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ctx2 = CreateLmsContext(isProvider);
    ASSERT_TRUE(ctx2 != NULL);

    ret = SetupLmsParams(ctx2, lmsType, otsType);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx2);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCmp(ctx1, ctx2);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ctx3 = CRYPT_EAL_PkeyDupCtx(ctx1);
    ASSERT_TRUE(ctx3 != NULL);

    const uint8_t msg[] = "Test message for LMS EAL dup";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192] = {0};
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_EAL_PkeySign(ctx3, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_LMS_NO_KEY);

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

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_LMS_SIGN_VERIFY_TC001(int isProvider)
{
    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
    CRYPT_EAL_SetRandCallBack(LmsEalTestRand);

    CRYPT_EAL_PkeyCtx *ctx = CreateLmsContext(isProvider);
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;

    int32_t ret = SetupLmsParams(ctx, lmsType, otsType);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t msg[] = "Test message for LMS EAL signature";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192] = {0};
    uint32_t sigLen = sizeof(sig);

    ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(sigLen > 0);

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    const uint8_t wrongMsg[] = "Wrong message";
    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, wrongMsg, sizeof(wrongMsg) - 1, sig, sigLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_LMS_PUBKEY_VERIFY_TC001(int isProvider)
{
    TestMemInit();
    if (isProvider) {
        ASSERT_EQ(TestRandInitSelfCheck(), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    }
    CRYPT_EAL_SetRandCallBack(LmsEalTestRand);

    CRYPT_EAL_PkeyCtx *signCtx = CreateLmsContext(isProvider);
    ASSERT_TRUE(signCtx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W4;
    const uint8_t msg[] = "Test message";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192] = {0};
    uint32_t sigLen = sizeof(sig);

    CRYPT_EAL_PkeyCtx *verifyCtx = NULL;
    uint32_t pubKeyLen = 0;
    uint8_t *pubKeyBuf = NULL;
    int32_t ret = SetupLmsParams(signCtx, lmsType, otsType);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(signCtx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeySign(signCtx, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    /* Build a verify-only context by exporting the public key from signCtx
     * and importing it into a fresh ctx. We deliberately avoid DupCtx because
     * cloning a private-key-bearing stateful HBS context is unsafe. */
    ret = CRYPT_EAL_PkeyCtrl(signCtx, CRYPT_CTRL_LMS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    pubKeyBuf = BSL_SAL_Malloc(pubKeyLen);
    ASSERT_TRUE(pubKeyBuf != NULL);

    BSL_Param getPub[2] = {0};
    BSL_PARAM_InitValue(&getPub[0], CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, pubKeyLen);
    BSL_PARAM_InitValue(&getPub[1], 0, 0, NULL, 0);
    ret = CRYPT_EAL_PkeyGetPubEx(signCtx, getPub);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    verifyCtx = CreateLmsContext(isProvider);
    ASSERT_TRUE(verifyCtx != NULL);

    BSL_Param setPub[2] = {0};
    BSL_PARAM_InitValue(&setPub[0], CRYPT_PARAM_LMS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKeyBuf, pubKeyLen);
    BSL_PARAM_InitValue(&setPub[1], 0, 0, NULL, 0);
    ret = CRYPT_EAL_PkeySetPubEx(verifyCtx, setPub);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(verifyCtx, CRYPT_MD_SHA256, msg, msgLen, sig, sigLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verifyCtx);
    BSL_SAL_Free(pubKeyBuf);
    CRYPT_EAL_SetRandCallBack(NULL);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_LMS_CTRL_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_SetRandCallBack(LmsEalTestRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_LMS);
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H10;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;
    uint64_t remaining = 0;
    uint32_t pubKeyLen = 0;

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_GET_REMAINING, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 1024);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(pubKeyLen > 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_LMS_MULTIPLE_SIGN_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_SetRandCallBack(LmsEalTestRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_LMS);
    ASSERT_TRUE(ctx != NULL);

    uint32_t lmsType = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otsType = CRYPT_LMOTS_SHA256_N32_W8;
    uint64_t remaining = 0;
    const uint8_t msg[] = "Test message";
    uint32_t msgLen = sizeof(msg) - 1;
    uint8_t sig[8192] = {0};
    uint32_t sigLen;

    int32_t ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_GET_REMAINING, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 32);

    for (int i = 0; i < 5; i++) {
        sigLen = sizeof(sig);
        ret = CRYPT_EAL_PkeySign(ctx, CRYPT_MD_SHA256, msg, msgLen, sig, &sigLen);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_LMS_GET_REMAINING, &remaining, sizeof(remaining));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(remaining, 27);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    TestRandDeInit();
    return;
}
/* END_CASE */
