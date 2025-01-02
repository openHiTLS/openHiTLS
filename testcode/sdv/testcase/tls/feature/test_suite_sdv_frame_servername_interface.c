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

#include <stdio.h>
#include <stdint.h>
#include "config.h"
#include "hitls.h"
#include "hitls_func.h"
#include "hitls_error.h"
/* END_HEADER */

static char *g_serverName = "www.example.com";

int32_t ServernameCbErrOK(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;

    return HITLS_ACCEPT_SNI_ERR_OK;
}

#define HITLS_CFG_MAX_SIZE 1024

/** @
* @test     UT_TLS_CFG_UPREF_FUNC_TC001
* @title    test HITLS_CFG_SetServerName/HITLS_CFG_SetServerNameCb/HITLS_CFG_SetServerNameArg/HITLS_GetServernameType
*           interface
*
* @brief    1. Apply for and initialize config.Expect result 1
            2. Invoke the HITLS_CFG_NewTLS12Config interface and transfer the config parameter.Expect result 2.
            3. Set serverNameStrlen HITLS_CFG_MAX_SIZE + 1;Invoke the HITLS_CFG_SetServerName interface Expect result 3.
            4. Invoke the HITLS_CFG_NewTLS12Config interface.Expect result 4.
            5. input parameters is NULL,Invoke the HITLS_CFG_NewTLS12Config interface and .Expect result 2.
            6. Invoke the HITLS_CFG_SetServerNameCb interface ,Expect result 2.
            7. Invoke the HITLS_CFG_SetServerNameArg interface ,Expect result 2.
            8. Invoke the HITLS_CFG_GetServerNameCb interface ,Expect result 2.
            9. Invoke the HITLS_CFG_GetServerNameArg interface ,Expect result 2.
            10. Invoke the HITLS_SetServerName interface ,Expect result 2.
            11. Invoke the HITLS_SetServerName interface ,Expect result 2.
            12. Invoke the HITLS_SetServerName interface ,Expect result 6.
            13. Invoke the HITLS_SetServerName interface ,Expect result 6.
            14. Invoke the HITLS_GetServernameType interface ,Expect result 1.
* @expect   1. return Not NULL
            2. return HITLS_NULL_INPUT
            3. return HITLS_CONFIG_INVALID_LENGTH
            4. return SUCCESS
            5. return HITLS_NULL_INPUT
            6. return NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_SERVERNAME_API_TC001()
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetServerName(NULL, (uint8_t *)g_serverName, (uint32_t)strlen(g_serverName)) ==
                HITLS_NULL_INPUT);
    uint32_t errLen = HITLS_CFG_MAX_SIZE + 1;
    ASSERT_TRUE(HITLS_CFG_SetServerName(config, (uint8_t *)g_serverName, errLen) == HITLS_CONFIG_INVALID_LENGTH);
    ASSERT_TRUE(HITLS_CFG_SetServerName(config, (uint8_t *)g_serverName, (uint32_t)strlen(g_serverName)) ==
                HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetServerName(NULL, NULL, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_SetServerNameCb(NULL, ServernameCbErrOK) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetServerNameArg(NULL, NULL) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_CFG_GetServerNameCb(NULL, NULL) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetServerNameArg(NULL, NULL) == HITLS_NULL_INPUT);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_SetServerName(ctx, NULL, 0) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetServerName(NULL, (uint8_t *)g_serverName, 0) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_GetServerName(ctx, HITLS_SNI_BUTT) == NULL);
    ASSERT_TRUE(HITLS_GetServerName(NULL, HITLS_SNI_HOSTNAME_TYPE) == NULL);

    ASSERT_TRUE(HITLS_GetServernameType(ctx) != 0);
EXIT:
    HITLS_CFG_FreeConfig(config);
    HITLS_Free(ctx);
}
/* END_CASE */