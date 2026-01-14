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
#include "frame_tls.h"
#include "hitls_type.h"
#include "rec_wrapper.h"
#include "hs_ctx.h"
#include "tls.h"
#include "hitls_config.h"
#include "alert.h"

#define READ_BUF_LEN_18K (18 * 1024)
/* END_HEADER */
static uint32_t g_uiPort = 16888;
static uint32_t retry_count = 0;

int32_t cert_callback(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    uint32_t *num = arg;
    if (*num == 3) {
        return HITLS_CERT_CALLBACK_FAILED;
    }
    if ((*num)++ == 0) {
        return HITLS_CERT_CALLBACK_RETRY;
    }
    return HITLS_CERT_CALLBACK_SUCCESS;
}

/**
 * @test SDV_TLS_CERT_CALLBACK_FUNC_TC01
 * @title  cert Callback Function Test Case 1
 * @precon  nan
 * @brief   Server sets the cert callback function, and the cert callback function return HITLS_CERT_CALLBACK_FAILED.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The server returns HITLS_CALLBACK_CERT_ERROR.
 */
/* BEGIN_CASE */
void SDV_TLS_CERT_CALLBACK_FUNC_TC01(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);
    int32_t flag = 3;
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetCertCb(serverCtxConfig, cert_callback, &flag);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");

    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_CALLBACK_CERT_ERROR);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_TLS_CERT_CALLBACK_FUNC_TC02
 * @title  cert Callback Function Test Case 2
 * @precon  nan
 * @brief   Server sets the cert callback function, and the cert callback function return HITLS_CERT_CALLBACK_RETRY.
 *          The cert callback function is called twice, and the second time it returns HITLS_CERT_CALLBACK_SUCCESS.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The server returns HITLS_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_TLS_CERT_CALLBACK_FUNC_TC02(int version)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    if (version == TLS1_2 || version == TLS1_3) {
        remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    } else {
        remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, g_uiPort, true);
    }
    ASSERT_TRUE(remoteProcess != NULL);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetCertCb(serverCtxConfig, cert_callback, &retry_count);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);
    ASSERT_EQ(retry_count, 2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    retry_count = 0;
}
/* END_CASE */

/**
 * @test SDV_TLS_CERT_CALLBACK_FUNC_TC03
 * @title  cert Callback Function Test Case 3
 * @precon  nan
 * @brief   Client sets the cert callback function, and the cert callback function return HITLS_CERT_CALLBACK_RETRY.
 *          Server set client verify support, The cert callback function is called twice,
 *          and the second time it returns HITLS_CERT_CALLBACK_SUCCESS.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The link establishment is successful and cert callback function is called twice.
 */

/* BEGIN_CASE */
void SDV_TLS_CERT_CALLBACK_FUNC_TC03(int version)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    if (version == TLS1_2 || version == TLS1_3) {
        remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    } else {
        remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, g_uiPort, true);
    }
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCertCb(clientCtxConfig, cert_callback, &retry_count);
    clientRes = HLT_ProcessTlsConnect(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(retry_count, 2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    retry_count = 0;
}
/* END_CASE */

/**
 * @test SDV_TLS_CERT_CALLBACK_FUNC_TC04
 * @title  cert Callback Function Test Case 4
 * @precon  nan
 * @brief   Client sets the cert callback function, and the cert callback function return HITLS_CERT_CALLBACK_RETRY.
 *          Server set client verify support and post handshake auth, The cert callback function is called twice,
 *          and the second time it returns HITLS_CERT_CALLBACK_SUCCESS.
 *          establish a TLS connection between the client and server, expect result 1.
 * @expect  1. The link establishment is successful and cert callback function is called twice.
 */
/* BEGIN_CASE */
void SDV_TLS_CERT_CALLBACK_FUNC_TC04(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    HLT_SetPostHandshakeAuth(serverCtxConfig, true);
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetPostHandshakeAuth(clientCtxConfig, true);
    HLT_SetCertCb(clientCtxConfig, cert_callback, &retry_count);
    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(retry_count, 0);
    ASSERT_TRUE(HLT_RpcTlsVerifyClientPostHandshake(remoteProcess, serverRes->sslId) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen), 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
    ASSERT_EQ(retry_count, 2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
    retry_count = 0;
}
/* END_CASE */