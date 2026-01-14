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
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "helper.h"
#include "hitls.h"
#include "alert.h"
#include "hitls_type.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "rec_wrapper.h"
#include "common_func.h"
#include "stub_crypt.h"
/* END_HEADER */

/* @
* @test  SDV_TLS_CFG_SET_TLS_FALLBACK_SCSV_TC001
* @title  Test the behavior of the server when it receives the TLS_FALLBACK_SCSV algorithm suite carried by the lower version of clienthello.
* @brief 1. the client creates the config of tls12, and the server creates the config of tls13.Expect result 1.
*       2. the client sets HITLS_MODE_SEND_FALLBACK_SCSV.expect result 2.
*       3. connection establishment, Expect result 3.
* @expect 1. The config object is successfully created.
*       2. return HITLS_SUCCES.
*       3. Failed to establish connection, send alert ALERT_INAPPROPRIATE_FALLBACK.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_SET_TLS_FALLBACK_SCSV_TC001(int isSetMode)
{
#ifdef HITLS_TLS_FEATURE_MODE
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 18256, false);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS_ALL, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    if (isSetMode) {
        HLT_SetModeSupport(clientCtxConfig, HITLS_MODE_SEND_FALLBACK_SCSV);
    }

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    HLT_TlsConnect(clientRes->ssl);
    // Wait the remote.
    int ret = HLT_GetTlsAcceptResult(serverRes);
    if (isSetMode) {
        ASSERT_EQ(ret, HITLS_MSG_HANDLE_ERR_INAPPROPRIATE_FALLBACK);
        ALERT_Info alertInfo = { 0 };
        ALERT_GetInfo(clientRes->ssl, &alertInfo);
        ASSERT_EQ(alertInfo.flag, ALERT_FLAG_RECV);
        ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(alertInfo.description, ALERT_INAPPROPRIATE_FALLBACK);
    } else {
        ASSERT_EQ(ret, HITLS_SUCCESS);
    }

EXIT:
    HLT_FreeAllProcess();
#endif
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SET_TLS_FALLBACK_SCSV_TC001
* @title  Test the behavior of the server when it receives the TLS_FALLBACK_SCSV algorithm suite carried by the
*           lower version of clienthello.
* @brief 1. the client creates the config of tls12, and the server creates the config of tls13.Expect result 1.
*       2. the client sets HITLS_MODE_SEND_FALLBACK_SCSV.expect result 2.
*       3. connection establishment, Expect result 3.
* @expect 1. The config object is successfully created.
*       2. return HITLS_SUCCES.
*       3. Failed to establish connection, send alert ALERT_INAPPROPRIATE_FALLBACK.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_TLS_FALLBACK_SCSV_TC001(int isSetMode)
{
#ifdef HITLS_TLS_FEATURE_MODE
    FRAME_Init();

    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    if (isSetMode) {
        HITLS_CFG_SetModeSupport(c_config, HITLS_MODE_SEND_FALLBACK_SCSV);
    }
    s_config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(s_config != NULL);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    if (isSetMode) {
        ASSERT_EQ(ret, HITLS_MSG_HANDLE_ERR_INAPPROPRIATE_FALLBACK);
        ALERT_Info info = { 0 };
        ALERT_GetInfo(server->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_INAPPROPRIATE_FALLBACK);
    } else {
        ASSERT_EQ(ret, HITLS_SUCCESS);
    }

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */

/* @
* @test  UT_TLS_CFG_SET_TLS_FALLBACK_SCSV_TC002
* @title  Test the behavior of the server when it disables tls13 and receives the TLS_FALLBACK_SCSV algorithm suite
*           carried by the lower version of clienthello.
* @brief 1. the client creates the config of tls12, and the server creates the config of tlsall.Expect result 1.
*       2. the client sets HITLS_MODE_SEND_FALLBACK_SCSV. The server disables tls13. expect result 2.
*       3. connection establishment, Expect result 3.
* @expect 1. The config object is successfully created.
*       2. return HITLS_SUCCES.
*       3. return HITLS_SUCCES.
@ */
/* BEGIN_CASE */
void UT_TLS_CFG_SET_TLS_FALLBACK_SCSV_TC002()
{
#ifdef HITLS_TLS_FEATURE_MODE
    FRAME_Init();

    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_CFG_SetModeSupport(c_config, HITLS_MODE_SEND_FALLBACK_SCSV);

    s_config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetVersionForbid(s_config, TLS13_VERSION_BIT) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
#endif
}
/* END_CASE */
