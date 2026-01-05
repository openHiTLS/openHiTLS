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
#include <limits.h>
#include <pthread.h>
#include "securec.h"
#include "stub_replace.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "bsl_sal.h"
#include "eal_mac_local.h"
#include "stub_replace.h"

/* END_HEADER */
#define GMAC_DEFAULT_TAGLEN 16

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GMAC_FUNC_TC001(int id, Hex *key, Hex *iv, Hex *msg, Hex *mac)
{
    uint32_t outLen = mac->len;
    uint8_t *output = NULL;
    CRYPT_EAL_MacCtx *gmacCtx = NULL;

    ASSERT_TRUE((output = malloc(outLen)) != NULL);
    TestMemInit();
    ASSERT_TRUE((gmacCtx = CRYPT_EAL_MacNewCtx(id)) != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(gmacCtx, key->x, key->len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_TAGLEN, &outLen, sizeof(uint32_t)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(output, mac->x, outLen) == 0);

EXIT:
    free(output);
    CRYPT_EAL_MacDeinit(gmacCtx);
    CRYPT_EAL_MacFreeCtx(gmacCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GMAC_API_TC001(Hex *key, Hex *iv)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *gmacCtx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_GMAC_AES128);
    ASSERT_TRUE(gmacCtx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(gmacCtx, key->x, key->len) == CRYPT_SUCCESS);
    
    // ctrl abnormal parameter
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(NULL, CRYPT_CTRL_SET_IV, iv->x, iv->len) == CRYPT_NULL_INPUT);
    // ctrl abnormal parameter
    ASSERT_TRUE(
        CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_AAD, iv->x, iv->len) == CRYPT_EAL_MAC_CTRL_TYPE_ERROR);
    // ctrl abnormal parameter
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, NULL, iv->len) == CRYPT_NULL_INPUT);
    // ctrl abnormal parameter
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, 0) == CRYPT_NULL_INPUT);
    CRYPT_EAL_MacDeinit(gmacCtx);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_MacDeinit(gmacCtx);
    CRYPT_EAL_MacFreeCtx(gmacCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_EAL_GMAC_API_TC002(Hex *key, Hex *iv, Hex *msg, Hex *mac)
{
    TestMemInit();
    unsigned char output[GMAC_DEFAULT_TAGLEN];
    uint32_t outLen = GMAC_DEFAULT_TAGLEN;
    CRYPT_EAL_MacCtx *gmacCtx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_GMAC_AES128);
    ASSERT_TRUE(gmacCtx != NULL);

    // GMAC init abnormal parameter
    ASSERT_TRUE(CRYPT_EAL_MacInit(gmacCtx, key->x, 0) == CRYPT_AES_ERR_KEYLEN);
    ASSERT_TRUE(CRYPT_EAL_MacInit(gmacCtx, key->x, key->len) == CRYPT_SUCCESS);
    // GMAC Ctrl abnormal parameter
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len) == CRYPT_SUCCESS);

    // GMAC update abnormal parameter
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(gmacCtx, NULL, msg->len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len) == CRYPT_SUCCESS);
    // GMAC final abnormal parameter
    outLen = 0;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen) == CRYPT_MODES_TAGLEN_ERROR);
    outLen = GMAC_DEFAULT_TAGLEN;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(output, mac->x, outLen) == 0);

EXIT:
    CRYPT_EAL_MacDeinit(gmacCtx);
    CRYPT_EAL_MacFreeCtx(gmacCtx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_GMAC_STATE_FUNC_TC001
 * @title  Gmac state test
 * @precon nan
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_GMAC_STATE_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *msg, Hex *mac)
{
    uint32_t outLen = mac->len;
    unsigned char output[outLen];
    CRYPT_EAL_MacCtx *gmacCtx = NULL;

    TestMemInit();

    // ctrl, update, final and deinit after new.
    ASSERT_TRUE((gmacCtx = CRYPT_EAL_MacNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen), CRYPT_EAL_ERR_STATE);
    ASSERT_EQ(CRYPT_EAL_MacReinit(gmacCtx), CRYPT_EAL_ERR_STATE);
    CRYPT_EAL_MacDeinit(gmacCtx);

    // init after new, repeat the init
    ASSERT_EQ(CRYPT_EAL_MacInit(gmacCtx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacInit(gmacCtx, key->x, key->len), CRYPT_SUCCESS);

    // reinit after init
    ASSERT_EQ(CRYPT_EAL_MacReinit(gmacCtx), CRYPT_EAL_ALG_NOT_SUPPORT);

    // final after init
    ASSERT_EQ(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen), CRYPT_MODES_TAGLEN_ERROR);

    // update after init, repeat the update
    ASSERT_EQ(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len), CRYPT_SUCCESS);
    if (msg->len == 0) {
        ASSERT_EQ(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len), CRYPT_SUCCESS);
    } else {
        ASSERT_EQ(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len), CRYPT_MODES_AAD_REPEAT_SET_ERROR);
    }

    // ctrl after update
    ASSERT_EQ(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len), CRYPT_EAL_ERR_STATE);

    // final after update
    ASSERT_EQ(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen), CRYPT_MODES_TAGLEN_ERROR);

    // init
    ASSERT_EQ(CRYPT_EAL_MacInit(gmacCtx, key->x, key->len), CRYPT_SUCCESS);

    // ctrl after init, repeat to taglen
    ASSERT_EQ(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_TAGLEN, &outLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_TAGLEN, &outLen, sizeof(uint32_t)), CRYPT_SUCCESS);

    // final after ctrl,repeat the final
    ASSERT_EQ(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(gmacCtx, output, &outLen), CRYPT_EAL_ERR_STATE);

    // ctrl after final
    ASSERT_EQ(CRYPT_EAL_MacCtrl(gmacCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len), CRYPT_EAL_ERR_STATE);

    // update after final
    ASSERT_EQ(CRYPT_EAL_MacUpdate(gmacCtx, msg->x, msg->len), CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_MacDeinit(gmacCtx);
    CRYPT_EAL_MacFreeCtx(gmacCtx);
}
/* END_CASE */


/**
 * @test   SDV_CRYPT_EAL_GMAC_SAMEADDR_FUNC_TC001
 * @title  GMAC in/out same address test
 * @precon  nan
 * @brief
 *    1.Use the EAL-layer interface to perform GMAC calculation. The input and output addresses are the same.
 *      Expected result 1 is displayed.
 * @expect
 *    1. success
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_GMAC_SAMEADDR_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *data, Hex *mac)
{
    uint32_t outLen = data->len > mac->len ? data->len : mac->len;
    uint32_t tagLen = mac->len;
    uint8_t *out = NULL;
    CRYPT_EAL_MacCtx *ctx = NULL;

    ASSERT_TRUE((out = malloc(outLen)) != NULL);
    ASSERT_EQ(memcpy_s(out, outLen, data->x, data->len), 0);

    ASSERT_TRUE((ctx = CRYPT_EAL_MacNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv->x, iv->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, out, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, out, &tagLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("gmac result cmp", out, tagLen, mac->x, mac->len);

EXIT:
    free(out);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_GMAC_ADDR_NOT_ALIGN_FUNC_TC001
 * @title  GMAC non-address alignment test
 * @precon  nan
 * @brief
 *    1.Use the EAL layer interface to perform GMAC calculation. All buffer addresses are not aligned.
 *      Expected result 1 is obtained.
 * @expect
 *    1.success.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_GMAC_ADDR_NOT_ALIGN_FUNC_TC001(int algId, Hex *key, Hex *iv, Hex *data, Hex *mac)
{
    uint32_t outLen = data->len > mac->len ? data->len : mac->len;
    uint8_t *out = NULL;
    uint32_t tagLen = mac->len;
    CRYPT_EAL_MacCtx *ctx = NULL;
    uint8_t *keyTmp = NULL;
    uint8_t *ivTmp = NULL;
    uint8_t *dataTmp = NULL;
    ASSERT_TRUE((out = malloc(outLen)) != NULL);
    ASSERT_TRUE((keyTmp = malloc(key->len + 1)) != NULL);
    ASSERT_TRUE((ivTmp = malloc(iv->len + 1)) != NULL);
    ASSERT_TRUE((dataTmp = malloc(data->len + 1)) != NULL);

    uint8_t *pKey = keyTmp + 1;
    uint8_t *pIv = ivTmp + 1;
    uint8_t *pData = dataTmp + 1;

    ASSERT_TRUE(memcpy_s(pKey, key->len, key->x, key->len) == 0);
    ASSERT_TRUE(memcpy_s(pIv, iv->len, iv->x, iv->len) == 0);
    ASSERT_TRUE(memcpy_s(pData, data->len, data->x, data->len) == 0);
    TestMemInit();

    ASSERT_TRUE((ctx = CRYPT_EAL_MacNewCtx(algId)) != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, pKey, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, pIv, iv->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(uint32_t)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, pData, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, out, &tagLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac result cmp", out, tagLen, mac->x, mac->len);

EXIT:
    free(out);
    free(keyTmp);
    free(ivTmp);
    free(dataTmp);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_GMAC_COPY_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    CRYPT_EAL_MacCtx *ctxB = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxB != NULL);

    CRYPT_EAL_MacCtx ctxC = { 0 };

    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    // Copy failed because ctxC lacks a method.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    // A directly created context can also be used as the destination for copying.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.macMeth->freeCtx(ctxC.ctx);
    BSL_SAL_Free(ctxC.macMeth);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_GMAC_COPY_CTX_TC001(int algId, Hex *key, Hex *iv, Hex *data, Hex *vecMac, int isProvider)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = vecMac->len;
    uint8_t mac[64];

    CRYPT_EAL_MacCtx *copyCtx1 = NULL;
    CRYPT_EAL_MacCtx *copyCtx2 = NULL;
    CRYPT_EAL_MacCtx *ctx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_IV, iv->x, iv->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_TAGLEN, &macLen, sizeof(uint32_t)) == CRYPT_SUCCESS);

    copyCtx1 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx1 != NULL);
    copyCtx2 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx2 != NULL);

    // Test that the copied context functions correctly and is independent of the original context.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx1, ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacUpdate(copyCtx1, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx1, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    copyCtx1 = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx2, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac2 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(ctx);
    ctx = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx2, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac3 cmp", mac, macLen, vecMac->x, vecMac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(copyCtx2);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

static int32_t TestMacCopyCtxMemCheck(int32_t algId, Hex *key, Hex *iv, Hex *vecMac, int isProvider)
{
    CRYPT_EAL_MacCtx *ctxA = NULL;
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx *srcCtx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    /* Set key in srcCtx */
    int32_t ret = CRYPT_EAL_MacInit(srcCtx, key->x, key->len);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    uint32_t macLen = vecMac->len;
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(srcCtx, CRYPT_CTRL_SET_IV, iv->x, iv->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(srcCtx, CRYPT_CTRL_SET_TAGLEN, &macLen, sizeof(uint32_t)) == CRYPT_SUCCESS);

    ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ret = CRYPT_EAL_MacCopyCtx(ctxA, srcCtx);
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }
    ctxB = CRYPT_EAL_MacDupCtx(srcCtx);
    if (ctxB == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto EXIT;
    }

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
    CRYPT_EAL_MacFreeCtx(srcCtx);
    return ret;
}

/**
 * @test SDV_CRYPTO_CBC_MAC_COPY_CTX_STUB_TC001
 * title 1. Test the mac copy context with stub malloc fail
 *
 */
/* BEGIN_CASE */
void SDV_CRYPTO_GMAC_COPY_CTX_STUB_TC001(int algId, Hex *key, Hex *iv, Hex *vecMac, int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_Init();
    FuncStubInfo tmpRpInfo = {0};
    ASSERT_TRUE(STUB_Replace(&tmpRpInfo, BSL_SAL_Malloc, STUB_BSL_SAL_Malloc) == 0);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(TestMacCopyCtxMemCheck((int32_t)algId, key, iv, vecMac, isProvider), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(TestMacCopyCtxMemCheck((int32_t)algId, key, iv, vecMac, isProvider), CRYPT_SUCCESS);
    }

EXIT:
    STUB_Reset(&tmpRpInfo);
}
/* END_CASE */
