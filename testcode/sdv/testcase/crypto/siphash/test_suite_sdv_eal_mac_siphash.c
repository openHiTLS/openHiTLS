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
#include "eal_mac_local.h"
#include <limits.h>
#include <pthread.h>
#include "crypt_siphash.h"
#include "securec.h"
#include "crypt_eal_mac.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "stub_utils.h"

#define DATA_MAX_LEN (65538)  // siphash_update(key, data),  data  update len < DATA_MAX_LEN   2^16 = 65536
/* END_HEADER */

STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC001
* @spec  -
* @title Impact of the algorithm ID on the new interface_valid algorithm ID and invalid algorithm ID
* @precon nan
* @brief 1. Invoke the new interface with the input parameter CRYPT_MAC_SIPHASH_SHA1. Expected result 1 is obtained.
2. Invoke the new interface with the input parameter CRYPT_MAC_SIPHASH64. Expected result 2 is obtained.
3. Invoke the new interface with the input parameter CRYPT_MAC_SIPHASH128. Expected result 3 is obtained.
4. Invoke the new interface with the input parameter CRYPT_MAC_MAX. Expected result 7 is obtained.
* @expect 1. If the operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
3. If the operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
4. If the operation fails, NULL is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_SIPHASH64);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_EAL_MacFreeCtx(ctx);

    ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_SIPHASH128);
    ASSERT_TRUE(ctx != NULL);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC002
* @spec  -
* @title  Impact of Input Parameters on the Init Interface (Valid and Invalid Input Parameters)
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface and set ctx to NULL. Expected result 2 is obtained.
3. Invoke the init interface with key set to NULL and len set to a value other than 0. Expected result 3 is obtained.
4. Invoke the init interface with key set to NULL and len set to 0. Expected result 4 is obtained.
5. Invoke the init interface. The key is not NULL and the len is 0. Expected result 5 is obtained.
6. Invoke the init interface and ensure that the input parameters are normal. Expected result 6 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation fails, CRYPT_NULL_INPUT is returned.
3. If the init operation fails, CRYPT_NULL_INPUT is returned.
4. If the init operation fails, CRYPT_INVALID_ARG is returned.
5. If the init operation fails, CRYPT_INVALID_ARG is returned.
6. If the init operation is successful, CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC002(int algId)
{
    TestMemInit();
    uint8_t key[SIPHASH_KEY_SIZE];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(NULL, key, SIPHASH_KEY_SIZE) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, NULL, SIPHASH_KEY_SIZE) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, NULL, 0) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, 0) == CRYPT_INVALID_ARG);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC003
* @spec  -
* @title  Impact of the ctx status on the init interface
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the init interface repeatedly. Expected result 3 is obtained.
4. Invoke the update interface. Expected result 4 is obtained.
5. Invoke the init interface. Expected result 5 is obtained.
6. Invoke the final interface. Expected result 6 is obtained.
7. Invoke the init interface. Expected result 7 is obtained.
8. Invoke the deinit interface. Expected result 8 is obtained.
9. Invoke the init interface. Expected result 9 is obtained.
10. Invoke the reinit interface. Expected result 10 is obtained.
11. Invoke the init interface. Expected result 11 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation is successful, CRYPT_SUCCESS is returned.
3. If the init operation is successful, CRYPT_SUCCESS is returned.
4. If the update is successful, CRYPT_SUCCESS is returned.
5. If the init operation is successful, CRYPT_SUCCESS is returned.
6. If the final operation is successful, CRYPT_SUCCESS is returned.
7. If the init operation is successful, CRYPT_SUCCESS is returned.
8.
9. If the init operation is successful, CRYPT_SUCCESS is returned.
10. The reinit operation is successful and CRYPT_SUCCESS is returned.
11. If the init operation is successful, CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC003(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    uint8_t message[] = "e1476ccebc8fd7a5f5d1b944bd488bafa08caa713795f87e0364227b473b1cd5d83d0c72ce4ebab3e187";
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC004
* @spec  -
* @title  Impact of Input Parameters on the Update Interface (Valid and Invalid Input Parameters)
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the update interface and set ctx to NULL. Expected result 3 is obtained.
4. Invoke the update interface. Set in to NULL and len to a value other than 0. Expected result 4 is obtained.
5. Invoke the update interface. Set in to a value other than NULL and len to 0. Expected result 5 is obtained.
6. Invoke the update interface. Set in to NULL and len to 0. Expected result 6 is obtained.
7. Invoke the update interface and ensure that the input parameters are correct. Expected result 7 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation is successful, CRYPT_SUCCESS is returned.
3. If the update fails, CRYPT_NULL_INPUT is returned.
4. If the update fails, CRYPT_NULL_INPUT is returned.
5. If the update is successful, CRYPT_SUCCESS is returned.
6. If the update is successful, CRYPT_SUCCESS is returned.
7. If the update is successful, CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC004(int algId)
{
    TestMemInit();
    uint8_t key[SIPHASH_KEY_SIZE];
    uint8_t message[] = "e1476ccebc8fd7a5f5d1b944bd488bafa08caa713795f87e0364227b473b1cd5d83d0c72ce4ebab3e187";
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacUpdate(NULL, message, sizeof(message)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, NULL, sizeof(message)) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC005
* @spec  -
* @title  Impact of CTX status transition on the update interface_different CTX status
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the update interface. Expected result 2 is obtained.
3. Invoke the init interface. Expected result 3 is obtained.
4. Invoke the update interface. Expected result 4 is obtained.
5. Invoke the final interface. Expected result 5 is obtained.
6. Invoke the update interface. Expected result 6 is obtained.
7. Invoke the update interface repeatedly. Expected result 7 is obtained.
8. Invoke the deinit interface. Expected result 8 is obtained.
9. Invoke the update interface. Expected result 9 is obtained.
10. Invoke the final interface. Expected result 10 is obtained.
11. Invoke the init interface. Expected result 11 is obtained.
12. Invoke the update interface. Expected result 12 is obtained.
13. Invoke the reinit interface. Expected result 13 is obtained.
14. Invoke the update interface. Expected result 14 is obtained.
15. Invoke the update interface repeatedly. (Expected result 15)
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the update fails, CRYPT_EAL_ERR_STATE is returned.
3. If the init operation is successful, CRYPT_SUCCESS is returned.
4. If the update is successful, CRYPT_SUCCESS is returned.
5. If the final operation is successful, CRYPT_SUCCESS is returned.
6. If the update fails, CRYPT_EAL_ERR_STATE is returned.
7. If the update fails, CRYPT_EAL_ERR_STATE is returned.
8.
9. If the update fails, CRYPT_EAL_ERR_STATE is returned.
10. If the final operation is successful, CRYPT_EAL_ERR_STATE is returned.
11. If the init operation is successful, CRYPT_SUCCESS is returned.
12. If the update is successful, CRYPT_SUCCESS is returned.
13. The reinit operation is successful and CRYPT_SUCCESS is returned.
14. If the update is successful, CRYPT_SUCCESS is returned.
15. If the update is successful, CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC005(int algId)
{
    TestMemInit();
    uint8_t key[SIPHASH_KEY_SIZE];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    uint8_t message[] = "e1476ccebc8fd7a5f5d1b944bd488bafa08caa713795f87e0364227b473b1cd5d83d0c72ce4ebab3e187";
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_EAL_ERR_STATE);

    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, message, sizeof(message)) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC006
* @spec  -
* @title  Impact of input parameters on the final interface: valid and invalid input parameters
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the final interface and set ctx to NULL. Expected result 3 is obtained.
4. Invoke the final interface and set the value of out to NULL. Expected result 4 is obtained.
5. Invoke the final interface and set len to NULL. Expected result 5 is obtained.
6. Invoke the final interface. The value of len is less than the MAC data length. Expected result 6 is obtained.
7. Invoke the final interface. The value of len is greater than the MAC data length. Expected result 7 is obtained.
8. Invoke the init interface. Expected result 8 is obtained.
9. Invoke the final interface. The input parameters are normal. Expected result 9 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation is successful, CRYPT_SUCCESS is returned.
3. If the final operation fails, CRYPT_NULL_INPUT is returned.
4. If the final operation fails, CRYPT_NULL_INPUT is returned.
5. If the final operation fails, CRYPT_NULL_INPUT is returned.
6. If the final operation fails, CRYPT_SIPHASH_OUT_BUFF_LEN_NOT_ENOUGH is returned.
7. If the final operation is successful, CRYPT_SUCCESS is returned.
8. If the init operation is successful, CRYPT_SUCCESS is returned.
9. If the final operation is successful, CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC006(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);

    ASSERT_TRUE(CRYPT_EAL_MacFinal(NULL, mac, &macLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, NULL, &macLen) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, NULL) == CRYPT_NULL_INPUT);
    macLen = TestGetMacLen(algId) - 1;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SIPHASH_OUT_BUFF_LEN_NOT_ENOUGH);
    macLen = TestGetMacLen(algId) + 1;
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC007
* @spec  -
* @title  Impact of CTX status transition on the final interface_different CTX status
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the final interface. Expected result 2 is obtained.
3. Repeat the final interface. Expected result 3 is obtained.
4. Invoke the update interface. Expected result 4 is obtained.
5. Invoke the init interface. Expected result 5 is obtained.
6. Invoke the final interface. Expected result 6 is obtained.
7. Invoke the init interface. Expected result 7 is obtained.
8. Invoke the update interface. Expected result 8 is obtained.
9. Invoke the final interface. Expected result 9 is obtained.
10. Invoke the deinit interface. Expected result 10 is obtained.
11. Invoke the final interface. Expected result 11 is obtained.
12. Invoke the init interface. Expected result 12 is obtained.
13. Invoke the reinit interface. Expected result 13 is obtained.
14. Invoke the final interface. Expected result 14 is obtained.
15. Invoke the final interface repeatedly. Expected result 15 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the final operation fails, CRYPT_EAL_ERR_STATE is returned.
3. If the final operation fails, CRYPT_EAL_ERR_STATE is returned.
4. If the update fails, YPT_EAL_ERR_STATE is returned.
5. If the init operation is successful, CRYPT_SUCCESS is returned.
6. If the final operation is successful, CRYPT_SUCCESS is returned.
7. If the init operation is successful, CRYPT_SUCCESS is returned.
8. If the update is successful, CRYPT_SUCCESS is returned.
9. If the final operation is successful, CRYPT_SUCCESS is returned.
10.
11. If the final operation fails, CRYPT_EAL_ERR_STATE is returned.
12. If the init operation is successful, CRYPT_SUCCESS is returned.
13. The reinit operation is successful and CRYPT_SUCCESS is returned.
14. If the final operation is successful, CRYPT_SUCCESS is returned.
15. If the final operation fails, RYPT_EAL_ERR_STATE is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC007(int algId, Hex *key1, Hex *key2, Hex *data2)
{
    TestMemInit();
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data2->x, data2->len) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(key1->len == SIPHASH_KEY_SIZE);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key1->x, key1->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);

    ASSERT_TRUE(key2->len == SIPHASH_KEY_SIZE);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key2->x, key2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacUpdate(ctx, data2->x, data2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key2->x, key2->len) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacFinal(ctx, mac, &macLen) == CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC008
* @spec  -
* @title  Impact of input parameters on the getMacLen interface: valid and invalid input parameters
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the getLen interface and set the input parameter to NULL. Expected result 3 is obtained.
4. Invoke the getLen interface and set normal input parameters. Expected result 4 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation is successful, CRYPT_SUCCESS is returned.
3. If the operation fails, 0 is returned.
4. If the operation is successful, the MAC length corresponding to the context is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC008(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
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
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC009
* @spec  -
* @title  Impact of the CTX state on the getMacLen interface_Impact of the CTX state on the interface
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the getLen interface. Expected result 2 is obtained.
3. Invoke the init interface. Expected result 3 is obtained.
4. Invoke the getLen interface. Expected result 4 is obtained.
5. Invoke the update interface. Expected result 5 is obtained.
6. Invoke the getLen interface. Expected result 6 is obtained.
7. Invoke the final interface. Expected result 7 is obtained.
8. Invoke the getLen interface. Expected result 8 is obtained.
9. Invoke the deinit interface. Expected result 9 is obtained.
10. Invoke the getLen interface. Expected result 10 is obtained.
11. Invoke the reinit interface. Expected result 11 is obtained.
12. Invoke the getLen interface. Expected result 12 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the operation is successful, the MAC length corresponding to the context is returned.
3. If the init operation is successful, CRYPT_SUCCESS is returned.
4. If the operation is successful, the MAC length corresponding to the context is returned.
5. The update is successful and CRYPT_SUCCESS is returned.
6. If the operation is successful, the MAC length corresponding to the context is returned.
7. If the final operation is successful, CRYPT_SUCCESS is returned.
8. If the operation is successful, the MAC address length corresponding to the context is returned.
9.
10. If the operation is successful, the MAC address length corresponding to the context is returned.
11. If reinit fails, CRYPT_EAL_ERR_STATE is returned.
12. If the operation is successful, the MAC length corresponding to the context is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC009(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    uint8_t data[] = "5f81bd275320d97416e5e50d5d185d5542a157778b2d05521f27805b925e4f187d06829a2efd407ba11691";
    uint32_t dataLen = sizeof(data);
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_GetMacLen(ctx) == TestGetMacLen(algId));

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
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
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC010
* @spec  -
* @title  Deinit Interface Test_Deinit Interface Test
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the deinit interface. Expected result 3 is obtained.
4. Invoke the deinit interface repeatedly. Expected result 4 is obtained.
5. Invoke the init interface. Expected result 5 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation is successful, CRYPT_SUCCESS is returned.
3.
4.
5. If the init operation is successful, CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC010(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(ctx);
    CRYPT_EAL_MacDeinit(ctx);
    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    CRYPT_EAL_MacDeinit(NULL);
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC011
* @spec  -
* @title  Impact of Input Parameters on the Reinit Interface (Valid and Invalid Input Parameters)
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
2. Invoke the init interface. Expected result 2 is obtained.
3. Invoke the reinit interface. The value of ctx is NULL. Expected result 3 is obtained.
4. Invoke the reinit interface. The value of ctx is not NUL. Expected result 4 is obtained.
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the init operation is successful, CRYPT_SUCCESS is returned.
3. If the init operation fails, CRYPT_NULL_INPUT is returned.
4. The reinit operation is successful and CRYPT_SUCCESS is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC011(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(NULL) == CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/* @
* @test  SDV_CRYPT_EAL_SIPHASH_API_TC012
* @spec  -
* @title  Impact of CTX status transition on the reinit interface_different CTX status
* @precon nan
* @brief 1. Invoke the new interface. Expected result 1 is obtained.
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
* @expect 1. If the new operation is successful, the CRYPT_EAL_MacCtx pointer is returned.
2. If the reinit operation fails, CRYPT_EAL_ERR_STATE is returned.
3. If the reinit operation fails, CRYPT_EAL_ERR_STATE is returned.
4. If the init operation is successful, CRYPT_SUCCESS is returned.
5. The reinit operation is successful, and CRYPT_SUCCESS is returned.
6. The reinit operation is successful and CRYPT_SUCCESS is returned.
7. The update is successful and CRYPT_SUCCESS is returned.
8. The reinit operation is successful and CRYPT_SUCCESS is returned.
9. If the final operation is successful, CRYPT_SUCCESS is returned.
10. The reinit operation is successful, and CRYPT_SUCCESS is returned.
11.
12. If reinit fails, CRYPT_EAL_ERR_STATE is returned.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_API_TC012(int algId)
{
    TestMemInit();

    uint8_t key[SIPHASH_KEY_SIZE];
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    uint8_t data[] = "9c520b111bb008086c5815f450a6b7b6daec0925c4b0c8cf99f9f9ddb6198000a379fcb62527d7c361ccbda2597deecdd"
                     "055850abc6a17251c08577b";
    uint32_t dataLen = sizeof(data);
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);
    ASSERT_TRUE(CRYPT_EAL_MacReinit(ctx) == CRYPT_EAL_ERR_STATE);

    ASSERT_TRUE(CRYPT_EAL_MacInit(ctx, key, SIPHASH_KEY_SIZE) == CRYPT_SUCCESS);
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

/**
 * @test  SDV_CRYPT_EAL_SIPHASH_FUN_TC005
 * @title  Impact of calculating the siphash MAC address when the plaintext data is all 0, all f, and null
 * @precon  nan
 * @brief
 *    1. Invoke the new interface. The expected result is successful.
 *    2. Invoke the init interface. The expected result is successful.
 *    3. Invoke the update interface. The expected result is successful.
 *    4. Invoke the final interface. The expected result is successful.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_FUN_TC005(int algId, Hex *key, Hex *data)
{
    TestMemInit();
    uint32_t macLen = TestGetMacLen(algId);
    uint8_t mac[macLen];
    CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(algId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(key->len == SIPHASH_KEY_SIZE);
    ASSERT_EQ(CRYPT_EAL_MacInit(ctx, key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(ctx, data->x, data->len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(ctx, mac, &macLen), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_MacFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SIPHASH_SAMEADDR_FUNC_TC001
 * @title  SIPHASH in/out test
* @precon nan
* @brief
* 1. Use the EAL-layer interface to perform SIPHASH calculation. All input and output addresses are the same.
*    Expected result 1 is obtained.
* @expect
* 1. The calculation is successful, and the result is consistent with the MAC vector.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_SAMEADDR_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *mac)
{
    TestMacSameAddr(algId, key, data, mac);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_SIPHASH_ADDR_NOT_ALIGN_FUNC_TC001
 * @title  SIPHASH non-address alignment test
* @precon nan
* @brief
* 1. Use the EAL layer interface to perform SIPHASH calculation. All buffer addresses are not aligned.
*    Expected result 1 is obtained.
* @expect
* 1. The calculation is successful, and the result is consistent with the MAC vector.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_SIPHASH_ADDR_NOT_ALIGN_FUNC_TC001(int algId, Hex *key, Hex *data, Hex *mac)
{
    TestMacAddrNotAlign(algId, key, data, mac);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_SIPHASH_COPY_CTX_API_TC001(int algId, int isProvider)
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
void SDV_CRYPTO_SIPHASH_DUP_CTX_API_TC001(int algId, int isProvider)
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
void SDV_CRYPT_EAL_SIPHASH_COPY_CTX_TC001(int algId, Hex *key, Hex *data, Hex *vecMac, int isProvider)
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
void SDV_CRYPTO_SIPHASH_COPY_CTX_STUB_TC001(int algId, Hex *key, int isProvider)
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
