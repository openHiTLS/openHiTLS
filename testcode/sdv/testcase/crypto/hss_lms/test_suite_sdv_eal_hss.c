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
#include "crypt_params_key.h"
#include "crypt_hss.h"
#include "test.h"
#include "stub_utils.h"
/* END_HEADER */

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

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_HSS_CTRL_TC001(void)
{
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    ASSERT_TRUE(ctx != NULL);

    uint32_t levels = 2;
    uint32_t lmstype = CRYPT_LMS_SHA256_M32_H5;
    uint32_t otstype = CRYPT_LMOTS_SHA256_N32_W8;
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

    uint32_t getLevel = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_LEVELS, &getLevel, sizeof(getLevel));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(getLevel, levels);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_PUBKEY_LEN, &pubKeyLen, sizeof(pubKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(pubKeyLen > 0);

    uint32_t signLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_HSS_GET_SIG_LEN, &signLen, sizeof(signLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(signLen, 2644);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_SetRandCallBack(NULL);
    TestRandDeInit();
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

static int32_t HssTestVerify(int lmsType0, int otsType0, int lmsType1, int otsType1, Hex *pubKey, Hex *msg,
    Hex *sig) {
    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_HSS_LMS);
    if (ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

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
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }

    BSL_Param pubParam;
    BSL_PARAM_InitValue(&pubParam, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubKey->x, pubKey->len);
    ret = CRYPT_EAL_PkeySetPubEx(ctx, &pubParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_PkeyVerify(ctx, CRYPT_MD_SHA256, msg->x, msg->len, sig->x, sig->len);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return ret;
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
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HssTestVerify(lmsType0, otsType0, lmsType1, otsType1, pubKey, msg, sig), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++)
    {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(HssTestVerify(lmsType0, otsType0, lmsType1, otsType1, pubKey, msg, sig), CRYPT_SUCCESS);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */