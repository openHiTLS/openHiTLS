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
// #include <limits.h>
#include <pthread.h>
#include "securec.h"
#include "crypt_eal_mac.h"
#include "eal_mac_local.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "stub_utils.h"
/* END_HEADER */

#define AES128_KEY_LEN 16
#define AES192_KEY_LEN 24
#define AES256_KEY_LEN 32
#define SM4_KEY_LEN 16
#define CMAC_MAC_AES_LEN 16
#define CMAC_MAC_LEN 16

uint32_t GetKeyLen(int algId)
{
    switch (algId) {
        case CRYPT_MAC_CMAC_AES128:
            return AES128_KEY_LEN;
        case CRYPT_MAC_CMAC_AES192:
            return AES192_KEY_LEN;
        case CRYPT_MAC_CMAC_AES256:
            return AES256_KEY_LEN;
		case CRYPT_MAC_CMAC_SM4:
            return SM4_KEY_LEN;
        default:
            return 0;
    }
}

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC001
* @spec  -
* @title valid algorithm ID and invalid algorithm ID
* @precon  nan
* @brief  1.Invoke the new interface with the input parameter CRYPT_MAC_CMAC_AES128. Expected result 1 is obtained.
2.Invoke the new interface with the input parameter CRYPT_MAC_CMAC_AES192,Expected result 2 is obtained.
3.Invoke the new interface with the input parameter CRYPT_MAC_CMAC_AES256,Expected result 3 is obtained.
4.Invoke the new interface with the input parameter CRYPT_MAC_MAX, Expected result 4 is obtained.
* @expect  1.sucess
2.sucess
3.sucess
4.failed，return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_CMAC_AES128);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MacFreeCtx(ctx);

    ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_CMAC_AES192);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MacFreeCtx(ctx);

    ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_CMAC_AES256);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MacFreeCtx(ctx);

    ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_CMAC_SM4);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */


/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC002
* @spec  -
* @title  init interface: valid input parameter, invalid input parameter
* @precon  nan
* @brief  1.Invoke the new interface. Expected result 1 is obtained.
2.Invoke the init interface and set ctx to NULL. Expected result 2 is obtained.
3.Invoke the init interface and set key to NULL. Expected result 3 is obtained.
4.Invoke the init interface. Set the key to a value other than NULL and len to a value less than the specified key
    length. Expected result 4 is obtained.
5.Invoke the init interface and ensure that the input parameters are normal. Expected result 5 is obtained.
6.Invoke the init interface. The key is not NULL and len is greater than the specified key length.
    Expected result 6 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init failed, return CRYPT_NULL_INPUT
3.init failed, return CRYPT_NULL_INPUT
4.init failed, return CRYPT_AES_ERR_KEYLEN
5.init sucess, return CRYPT_SUCCESS
6.init failed, return CRYPT_AES_ERR_KEYLEN
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC002(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    int32_t ret;
    if (algId >= CRYPT_MAC_CMAC_AES128 && algId <= CRYPT_MAC_CMAC_AES256) {
        ret = CRYPT_AES_ERR_KEYLEN;
    } else if (algId == CRYPT_MAC_CMAC_SM4) {
        ret = CRYPT_SM4_ERR_KEY_LEN;
    }
    ASSERT_TRUE(CRYPT_EAL_MacInit(NULL, key, len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, NULL, len) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len - 1) == ret);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len + 1) == ret);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC003
* @spec  -
* @title  test ctx status
* @precon  nan
* @brief  1.Invoke the new interface. Expected result 1 is obtained.
2.Invoke the init interface. Expected result 2 is obtained.
3.Invoke the init interface repeatedly. Expected result 3 is obtained.
4.Invoke the update interface. Expected result 4 is obtained.
5.Invoke the init interface. Expected result 5 is obtained.
6.Invoke the final interface. Expected result 6 is obtained.
7.Invoke the init interface. Expected result 7 is obtained.
8.Invoke the deinit interface. Expected result 8 is obtained.
9.Invoke the init interface. Expected result 9 is obtained.
10.Invoke the reinit interface. Expected result 10 is obtained.
11.Invoke the init interface. Expected result 11 is obtained.
* @expect  1.new sucess, return CRYPT_EAL_MacCtx pointer
2.init sucess, return CRYPT_SUCCESS
3.init sucess, return CRYPT_SUCCESS
4.update sucess, return CRYPT_SUCCESS
5.init sucess, return CRYPT_SUCCESS
6.final sucess, return CRYPT_SUCCESS
7.init sucess, return CRYPT_SUCCESS
8.deinit sucess
9.init sucess, return CRYPT_SUCCESS
10.reinit sucess, return CRYPT_SUCCESS
11.init sucess, return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC003(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t keyLen = GetKeyLen(algId);
    uint8_t key[keyLen];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    const uint32_t dataLen = TestGetMacLen(algId);
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, keyLen) == CRYPT_SUCCESS);

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
* @test  SDV_CRYPT_EAL_CMAC_API_TC004
* @spec  -
* @title  update: valid input parameter, invalid input parameter
* @precon  nan
* @brief  1.Invoke the new interface. Expected result 1 is obtained.
2.Invoke the init interface. Expected result 2 is obtained.
3.Invoke the update interface and set ctx to NULL. Expected result 3 is obtained.
4.Invoke the update interface. Set in to NULL and len to a value other than 0. Expected result 4 is obtained.
5.Invoke the update interface. Set in to a value other than NULL and len to 0. Expected result 5 is obtained.
6.Invoke the update interface. Set in to NULL and len to 0. Expected result 6 is obtained.
7.Invoke the update interface and ensure that the input parameters are normal. Expected result 7 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init sucess，return CRYPT_SUCCESS
3.update failed，return CRYPT_NULL_INPUT
4.update failed，return CRYPT_NULL_INPUT
5.update sucess，return CRYPT_SUCCESS
6.update sucess，return CRYPT_SUCCESS
7.update sucess，return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC004(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    const uint32_t dataLen = GetKeyLen(algId);
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);

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
* @test  SDV_CRYPT_EAL_CMAC_API_TC005
* @spec  -
* @precon  nan
* @brief  1.Invoke the new interface. Expected result 1 is obtained.
2.Invoke the update interface. Expected result 2 is obtained.
3.Invoke the new interface. Expected result 3 is obtained.
4.Invoke the update interface. Expected result 4 is obtained.
5.Invoke the final interface. Expected result 5 is obtained.
6.Invoke the new interface. Expected result 6 is obtained.
7.Invoke the new interface. Expected result 7 is obtained.
8.Invoke the deinit interface. Expected result 8 is obtained.
9.Invoke the new interface. Expected result 9 is obtained.
10.Invoke the final interface. Expected result 10 is obtained.
11.Invoke the new interface. Expected result 11 is obtained.
12.Invoke the new interface. Expected result 12 is obtained.
13.Invoke the reinit interface. Expected result 13 is obtained.
14.Invoke the new interface. Expected result 14 is obtained.
15.repeat invoke the new interface. Expected result 15 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.update failed，return RYPT_EAL_ERR_STATE
3.init sucess，return CRYPT_SUCCESS
4.update sucess，return CRYPT_SUCCESS
5.final sucess，return CRYPT_SUCCESS
6.update failed，return CRYPT_EAL_ERR_STATE
7.update failed，return CRYPT_EAL_ERR_STATE
8.
9.update failed，return CRYPT_EAL_ERR_STATE
10.final sucess，return CRYPT_EAL_ERR_STATE
11.init sucess，return CRYPT_SUCCESS
12.update sucess，return CRYPT_SUCCESS
13.reinit sucess，return CRYPT_SUCCESS
14.update sucess，return CRYPT_SUCCESS
15.update sucess，return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC005(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    const uint32_t dataLen = GetKeyLen(algId);
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
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
* @test  SDV_CRYPT_EAL_CMAC_API_TC006
* @spec  -
* @title  finsl : valid input parameter, invalid input parameter
* @precon  nan
* @brief  1.调用new接口,有预期结果1
2.调用init接口,有预期结果2
3.调用final接口，ctx为NULL,有预期结果3
4.调用final接口，out为NULL,有预期结果4
5.调用final接口，len为NULL,有预期结果5
6.调用final接口，len数值小于mac数据长度,有预期结果6
7.调用final接口，len数值大于mac数据长度,有预期结果7
8.调用init接口,有预期结果8
9.调用final接口，正常入参,有预期结果9
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init sucess，return CRYPT_SUCCESS
3.final failed，return CRYPT_NULL_INPUT
4.final failed，return CRYPT_NULL_INPUT
5.final failed，return CRYPT_NULL_INPUT
6.final failed，return CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH
7.final sucess，return CRYPT_SUCCESS
8.init sucess，return CRYPT_SUCCESS
9.final sucess，return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC006(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(NULL, mac, &macLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, NULL, &macLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, NULL) == CRYPT_NULL_INPUT);
    macLen = TestGetMacLen(algId) - 1;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH);
    macLen = TestGetMacLen(algId) + 1;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC007
* @spec  -
* @title  test final
* @precon  nan
* @brief  1.Invoke the new interface. Expected result 1 is obtained.
2.Invoke the final interface. Expected result 2 is obtained.
3.Invoke the final interface. Expected result 3 is obtained.
4.Invoke the update interface. Expected result 4 is obtained.
5.Invoke the init interface. Expected result 5 is obtained.
6.Invoke the final interface. Expected result 6 is obtained.
7.Invoke the init interface. Expected result 7 is obtained.
8.Invoke the update interface. Expected result 8 is obtained.
9.Invoke the final interface. Expected result 9 is obtained.
10.Invoke the reinit interface. Expected result 10 is obtained.
11.Invoke the final interface. Expected result 11 is obtained.
12.Invoke the init interface. Expected result 12 is obtained.
13.Invoke the reinit interface. Expected result 13 is obtained.
14.Invoke the final interface. Expected result 14 is obtained.
15.repeat invoke the final interface. Expected result 15 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.final failed，return RYPT_EAL_ERR_STATE
3.final failed，return RYPT_EAL_ERR_STATE
4.update failed，return YPT_EAL_ERR_STATE
5.init sucess，return CRYPT_SUCCESS
6.final sucess，return CRYPT_SUCCESS
7.init sucess，return CRYPT_SUCCESS
8.update sucess，return CRYPT_SUCCESS
9.final sucess，return CRYPT_SUCCESS
10.
11.final failed，return CRYPT_EAL_ERR_STATE
12.init sucess，return CRYPT_SUCCESS
13.reinit sucess，return CRYPT_SUCCESS
14.final sucess，return CRYPT_SUCCESS
15.final failed，return RYPT_EAL_ERR_STATE
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC007(int algId, Hex *key1, Hex *mac1, Hex *key2, Hex *data2, Hex *mac2, Hex *mac3)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data2->x, data2->len) == CRYPT_EAL_ERR_STATE);

    // mac1
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key1->x, key1->len) == CRYPT_SUCCESS);
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
* @test  SDV_CRYPT_EAL_CMAC_API_TC008
* @spec  -
* @title  getMacLen: valid input parameter, invalid input parameter
* @precon  nan
* @brief  1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the getLen interface and set the input parameter to NULL. Expected result 3 is obtained.
4. Invoke the getLen interface and set normal input parameters. Expected result 4 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init sucess，return CRYPT_SUCCESS
3. failed，return 0
4. sucess，return mac length
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC008(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(NULL) == 0);

    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));
    uint32_t result = 0;
    ASSERT_TRUE(CRYPT_EAL_MacCtrl(ctx, CRYPT_CTRL_GET_MACLEN, &result, sizeof(uint32_t)) == CRYPT_SUCCESS);
    ASSERT_TRUE(result == TestGetMacLen(algId));
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC009
* @spec  -
* @precon  nan
* @brief  1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the getLen interface. Expected result 2 is obtained.
3. Invoke the init interface. Expected result 3 is obtained.
4. Invoke the getLen interface. Expected result 4 is obtained.
5. Invoke the update interface. Expected result 5 is obtained.
6. Invoke the getLen interface. Expected result 6 is obtained.
7. Invoke the final interface. Expected result 7 is obtained.
8. Invoke the getLen interface. Expected result 8 is obtained.
9. Invoke the deinit interface. Expected result 9 is obtained.
10. Invoke the getLen interface. Expected result 10 is obtained.
11. Invoke the deinit interface. Expected result 11 is obtained.
12. Invoke the getLen interface. Expected result 12 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2. sucess，return mac length
3.init sucess，return CRYPT_SUCCESS
4. sucess，return mac length
5.update sucess，return CRYPT_SUCCESS
6. sucess，return mac length
7.final sucess，return CRYPT_SUCCESS
8. sucess，return mac length
9.
10. sucess，return mac length
11.deinit sucess，return CRYPT_SUCCESS
12. sucess，return mac length
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC009(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    const uint32_t dataLen = TestGetMacLen(algId);
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data, dataLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC010
* @spec  -
* @title  deinit interface test
* @precon  nan
* @brief  1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the deinit interface. Expected result 3 is obtained.
4. Invoke the deinit interface repeatedly. Expected result 4 is obtained.
5. Invoke the init interface. Expected result 5 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init sucess，return CRYPT_SUCCESS3.
4.
5.init sucess，return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC010(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(NULL);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_CMAC_API_TC011
* @spec  -
* @title  reinit test
* @precon  nan
* @brief  1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the reinit interface. The value of ctx is NULL. Expected result 3 is obtained.
4. Invoke the reinit interface. The value of ctx is not NUL. Expected result 4 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init sucess，return CRYPT_SUCCESS
3.init failed，return CRYPT_NULL_INPUT
4.reinit sucess，return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC011(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
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
* @test  SDV_CRYPT_EAL_CMAC_API_TC012
* @spec  -
* @precon  nan
* @brief  1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the reinit interface. Expected result 2 is obtained.
3. Invoke the reinit interface repeatedly. Expected result 3 is obtained.
4. Invoke the init interface. Expected result 4 is obtained.
5. Invoke the reinit interface. Expected result 5 is obtained.
6. Invoke the reinit interface repeatedly. Expected result 6 is obtained.
7. Invoke the update interface. Expected result 7 is obtained.
8. Invoke the reinit interface. Expected result 8 is obtained.
9. Invoke the final interface. Expected result 9 is obtained.
10. Invoke the reinit interface. Expected result 10 is obtained.
11. Invoke the deinit interface. Expected result 11 is obtained.
12. Invoke the reinit interface. Expected result 12 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.reinit failed，return CRYPT_NULL_INPUT
3.reinit failed，return CRYPT_NULL_INPUT
4.init sucess，return CRYPT_SUCCESS
5.reinit sucess，return CRYPT_SUCCESS
6.reinit sucess，return CRYPT_SUCCESS
7.update sucess，return CRYPT_SUCCESS
8.reinit sucess，return CRYPT_SUCCESS
9.final sucess，return CRYPT_SUCCESS
10.reinit sucess，return CRYPT_SUCCESS
11.
12.reinit failed，return CRYPT_EAL_ERR_STATE
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_API_TC012(int algId)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    const uint32_t len = GetKeyLen(algId);
    uint8_t key[len];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    const uint32_t dataLen = GetKeyLen(algId);
    uint8_t data[dataLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, len) == CRYPT_SUCCESS);
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
* @test  SDV_CRYPT_EAL_CMAC_FUN_TC004
* @spec  -
* @title  All 0s and all Fs data key
* @precon  nan
* @brief  1.Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the update interface. Expected result 3 is obtained.
4. Invoke the final interface. Expected result 4 is obtained.
* @expect  1.new sucess，return CRYPT_EAL_MacCtx pointer
2.init sucess，return CRYPT_SUCCESS
3.update sucess，return CRYPT_SUCCESS
4.final sucess，return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_FUN_TC004(int algId, Hex *key, Hex *data, Hex *vecMac)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data->x, data->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_COMPARE("mac1 result cmp", mac, macLen, vecMac->x, vecMac->len);
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
* @test  SDV_CRYPT_EAL_CMAC_FUN_TC006
* @spec  -
* @title  Compare the CMACC result with that of the CMACC result after multiple updates and one update.
* @precon  nan
* @brief  Run the updateTimes command to compare the cmac result with the update command.
*         The expected results are the same.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_FUN_TC006(int algId, Hex *key, Hex *data, int updateTimes)
{
    if (IsCmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t macLen1 = CMAC_MAC_LEN;
    uint8_t mac1[CMAC_MAC_LEN] = {};
    uint32_t macLen2 = CMAC_MAC_LEN;
    uint8_t mac2[CMAC_MAC_LEN] = {};
    uint8_t *totalInData = NULL;
    uint32_t totalLen = 0;
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(UpdateMultiTime(ctx, data, updateTimes, mac1, &macLen1) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);

    totalInData = BSL_SAL_Calloc(data->len * updateTimes, 1);
    ASSERT_TRUE(totalInData != NULL);
    for (int i = 0; i < updateTimes; i++) {
        memcpy(totalInData + totalLen, data->x, data->len);
        totalLen += data->len;
    }
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key->x, key->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, totalInData, totalLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac2, &macLen2) == CRYPT_SUCCESS);
    ASSERT_TRUE(macLen1 == macLen2);
    ASSERT_COMPARE("mac1 vs mac2 result cmp", mac2, macLen2, mac1, macLen1);

EXIT:
    BSL_SAL_FREE(totalInData);
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_CMAC_SAMEADDR_FUNC_TC001
 * @title  CMAC in/out same addr
 * @precon  nan
 * @brief
 *    1.Use the EAL layer interface to perform CMAC calculation. All input and output addresses are the same.
 *      Expected result 1 is displayed.
 * @expect
 *    1.compute sucess
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_SAMEADDR_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *mac)
{
    TestMacSameAddr(algId, key, data, mac);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_CMAC_ADDR_NOT_ALIGN_FUNC_TC001
 * @title  CMAC non-address alignment test
 * @precon  nan
 * @brief
 *    1.Use the EAL layer interface to perform CMAC calculation. All buffer addresses are not aligned.
 *      Expected result 1 is obtained.
 * @expect
 *    1.compute sucess
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_CMAC_ADDR_NOT_ALIGN_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *mac)
{
    TestMacAddrNotAlign(algId, key, data, mac);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_CMAC_COPY_CTX_API_TC001(int algId, int isProvider)
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
void SDV_CRYPTO_CMAC_DUP_CTX_API_TC001(int algId, int isProvider)
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
void SDV_CRYPT_EAL_CMAC_COPY_CTX_TC001(int algId, Hex *key, Hex *data, Hex *vecMac, int isProvider)
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

    copyCtx1 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx1 != NULL);
    copyCtx2 = (isProvider == 0) ? CRYPT_EAL_MacNewCtx(algId) :
        CRYPT_EAL_ProviderMacNewCtx(NULL, algId, "provider=default");
    ASSERT_TRUE(copyCtx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(NULL, ctx), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MacCopyCtx(copyCtx1, NULL), CRYPT_NULL_INPUT);

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
void SDV_CRYPTO_CMAC_COPY_CTX_STUB_TC001(int algId, Hex *key, int isProvider)
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