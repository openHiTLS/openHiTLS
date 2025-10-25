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
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "bsl_sal.h"
#include "eal_mac_local.h"

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
