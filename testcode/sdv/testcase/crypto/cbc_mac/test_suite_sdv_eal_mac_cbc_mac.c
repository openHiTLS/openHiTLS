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
#include "securec.h"
#include "crypt_eal_mac.h"
#include "eal_mac_local.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "stub_utils.h"

#define CBC_MAC_MAC_LEN 16
#define SM4_KEY_LEN 16
#define SM4_IV_LEN 16
#define SM4_BLOCK_SIZE 16
#define TEST_FAIL    (-1)
#define TEST_SUCCESS (0)
#define DATA_MAX_LEN (65538)

/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC001
* @spec  -
* @title  Impact of the algorithm ID on the CRYPT_EAL_MacNewCtx interface
* @precon  nan
* @brief  1. algorithm is CRYPT_MAC_CBC_MAC_SM4
          2. algorithm is CRYPT_MAC_MAX
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_CBC_MAC_SM4);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MacFreeCtx(ctx);

EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC003
* @spec  -
* @title  Impact of the ctx status on the CRYPT_EAL_MacInit interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC003(int algId, int padType)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t keyLen = SM4_KEY_LEN;
    uint8_t key[keyLen];
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    const uint32_t dataLen = CBC_MAC_MAC_LEN;
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC004
* @spec  -
* @title  Impact of Input Parameters on the CRYPT_EAL_MacUpdate Interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC004(int algId, int padType)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    const uint32_t dataLen = SM4_KEY_LEN;
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacUpdate(NULL, data, dataLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, NULL, dataLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC005
* @spec  -
* @title  Impact of the ctx status on the CRYPT_EAL_MacUpdate interface
* @precon  nan
* @brief
15.update成功，返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC005(int algId, int padType)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    const uint32_t dataLen = SM4_KEY_LEN;
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_EAL_ERR_STATE);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC006
* @spec  -
* @title  Impact of Input Parameters on the CRYPT_EAL_MacFinal Interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC006(int algId, int padType)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(NULL, mac, &macLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, NULL, &macLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, NULL) == CRYPT_NULL_INPUT);
    macLen = CBC_MAC_MAC_LEN - 1;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_CBC_MAC_OUT_BUFF_LEN_NOT_ENOUGH);
    macLen = CBC_MAC_MAC_LEN + 1;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC007
* @spec  -
* @title  Impact of ctx Status Change on the CRYPT_EAL_MacFinal Interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC007(int algId, int padType, Hex *key1, Hex *mac1, Hex *key2, Hex *data2, Hex *mac2, Hex *mac3)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data2->x, data2->len) == CRYPT_EAL_ERR_STATE);

    // mac1
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key1->x, key1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 result cmp", mac, macLen, mac1->x, mac1->len);

    // mac2
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key2->x, key2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data2->x, data2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("mac2 result cmp", mac, macLen, mac2->x, mac2->len);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);

    // mac3
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key2->x, key2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("mac3 result cmp", mac, macLen, mac3->x, mac3->len);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC008
* @spec  -
* @title  Impact of Input Parameters on the CRYPT_EAL_GetMacLen Interface.
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC008(int algId)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(NULL) == 0);

    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);
    uint32_t result = 0;
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_GET_MACLEN, &result, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(result == CBC_MAC_MAC_LEN);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC009
* @spec  -
* @title  Impact of the ctx Status on the CRYPT_EAL_GetMacLen Interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC009(int algId, int padType)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    const uint32_t dataLen = CBC_MAC_MAC_LEN;
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);

    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == CBC_MAC_MAC_LEN);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC010
* @spec  -
* @title  Impact of Input Parameters on the CRYPT_EAL_MacDeinit Interface Test
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC010(int algId)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(NULL);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC011
* @spec  -
* @title  Impact of Input Parameters on the CRYPT_EAL_MacReinit Interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC011(int algId)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(NULL) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_API_TC012
* @spec  -
* @title  Impact of ctx status change on the CRYPT_EAL_MacReinit interface
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_API_TC012(int algId, int padType)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = SM4_KEY_LEN;
    uint8_t key[len];
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    const uint32_t dataLen = SM4_KEY_LEN;
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_FUN_TC004
* @spec  -
* @title  Impact of All-0 and All-F Data Keys on CBC MAC Calculation
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_FUN_TC004(int algId, int padType, Hex *key, Hex *data, Hex *vecMac)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = CBC_MAC_MAC_LEN;
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 result cmp", mac, macLen, vecMac->x, vecMac->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

static int32_t UpdateMultiTime(CRYPT_EAL_MacCtx *ctx, Hex *data, int updateTimes, uint8_t *mac, uint32_t *macLen)
{
    int32_t ret = CRYPT_SUCCESS;
    for (int i = 0; i < updateTimes; i++) {
        ret = CRYPT_EAL_MacUpdate(ctx, data->x, data->len);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    return CRYPT_EAL_MacFinal(ctx, mac, macLen);
}

/* @
* @test  SDV_CRYPT_EAL_CBC_MAC_FUN_TC006
* @spec  -
* @title  Compare the cmac results of multiple updates and one update.
* @precon  nan
* @brief
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_FUN_TC006(int algId, int padType, Hex *key, Hex *data, int updateTimes)
{
    if (IsMacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen1 = CBC_MAC_MAC_LEN;
    uint8_t mac1[CBC_MAC_MAC_LEN] = {};
    uint32_t macLen2 = CBC_MAC_MAC_LEN;
    uint8_t mac2[CBC_MAC_MAC_LEN] = {};
    uint8_t *totalInData = NULL;
    uint32_t totalLen = 0;
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType,
        sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(UpdateMultiTime(ctx, data, updateTimes, mac1, &macLen1) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);

    totalInData = BSL_SAL_Calloc(data->len * updateTimes, 1);
    ASSERT_TRUE(totalInData != NULL);
    for (int i = 0; i < updateTimes; i++) {
        memcpy(totalInData + totalLen, data->x, data->len);
        totalLen += data->len;
    }
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType,
        sizeof(padType)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, totalInData, totalLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_SUCCESS);
    ASSERT_TRUE(macLen1 == macLen2);
    ASSERT_COMPARE("mac1 vs mac2 result cmp", mac2, macLen2, mac1, macLen1);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_FREE(totalInData);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_CBC_MAC_SAMEADDR_FUNC_TC001
 * @title  CBC-MAC in/out同地址测试
 * @precon  nan
 * @brief
 *    1.使用EAL层接口进行CBC-MAC计算,其中所有的输入和输出地址相同,有预期结果1
 * @expect
 *    1.计算成功，结果与mac向量一致
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_SAMEADDR_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *mac)
{
    TestMacSameAddr(algId, key, data, mac);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_CBC_MAC_ADDR_NOT_ALIGN_FUNC_TC001
 * @title  CBC-MAC 非地址对齐测试
 * @precon  nan
 * @brief
 *    1.使用EAL层接口进行CBC-MAC计算,其中所有的buffer地址未对齐,有预期结果1
 * @expect
 *    1.计算成功，结果与mac向量一致
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_ADDR_NOT_ALIGN_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *mac)
{
    TestMacAddrNotAlign(algId, key, data, mac);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_CBC_MAC_COPY_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx ctxC = { 0 };
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    ctxB = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxB != NULL);

    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(NULL, ctxA), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, NULL), CRYPT_NULL_INPUT);
    // Copy failed because ctxC lacks a method.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(ctxB, &ctxC), CRYPT_NULL_INPUT);

    // A directly created context can also be used as the destination for copying.
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(&ctxC, ctxA), CRYPT_SUCCESS);
    ctxC.macMeth.freeCtx(ctxC.ctx);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_CBC_MAC_DUP_CTX_API_TC001(int algId, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctxB = NULL;
    CRYPT_EAL_MacCtx ctxC = { 0 };
    CRYPT_EAL_MacCtx *ctxA = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctxA != NULL);

    ctxB = CRYPT_EAL_MacDupCtx(NULL);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_MacDupCtx(&ctxC);
    ASSERT_TRUE(ctxB == NULL);
    ctxB = CRYPT_EAL_MacDupCtx(ctxA);
    ASSERT_TRUE(ctxB != NULL);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctxA);
    CRYPT_EAL_MacFreeCtx(ctxB);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPT_EAL_CBC_MAC_COPY_CTX_TC001(int algId, int padType, Hex *key, Hex *data, Hex *vecMac, int isProvider)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = vecMac->len;
    uint8_t mac[64];

    CRYPT_EAL_MacCtx *copyCtx1 = NULL;
    CRYPT_EAL_MacCtx *copyCtx2 = NULL;
    CRYPT_EAL_MacCtx *copyCtx3 = NULL;
    CRYPT_EAL_MacCtx *ctx = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType)), CRYPT_SUCCESS);

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

    // Create a new copyCtx3 from ctx, use copyCtx3 for encryption, and verify functional correctness.
    copyCtx3 = CRYPT_EAL_MacDupCtx(ctx);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(copyCtx3, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx3, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac2 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(copyCtx3);
    copyCtx3 = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx2, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac3 cmp", mac, macLen, vecMac->x, vecMac->len);
    CRYPT_EAL_MacFreeCtx(ctx);
    ctx = NULL;

    macLen = vecMac->len;
    ASSERT_EQ(CRYPT_EAL_MacFinal(copyCtx2, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("mac4 cmp", mac, macLen, vecMac->x, vecMac->len);

EXIT:
    CRYPT_EAL_MacFreeCtx(copyCtx3);
    CRYPT_EAL_MacFreeCtx(copyCtx2);
    CRYPT_EAL_MacFreeCtx(copyCtx1);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

static int32_t TestMacCopyCtxMemCheck(int32_t algId, Hex *key, int isProvider)
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
    int32_t pad = CRYPT_PADDING_ZEROS;
    ret = CRYPT_EAL_MacCtrl(srcCtx, CRYPT_CTRL_SET_CBC_MAC_PADDING, &pad, sizeof(pad));
    if (ret != CRYPT_SUCCESS) {
        goto EXIT;
    }

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
void SDV_CRYPTO_CBC_MAC_COPY_CTX_STUB_TC001(int algId, Hex *key, int isProvider)
{
    TestMemInit();
    uint32_t totalMallocCount = 0;
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(TestMacCopyCtxMemCheck((int32_t)algId, key, isProvider), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();

    STUB_EnableMallocFail(true);
    for (uint32_t j = 0; j < totalMallocCount; j++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(j);
        ASSERT_NE(TestMacCopyCtxMemCheck((int32_t)algId, key, isProvider), CRYPT_SUCCESS);
    }

EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
}
/* END_CASE */