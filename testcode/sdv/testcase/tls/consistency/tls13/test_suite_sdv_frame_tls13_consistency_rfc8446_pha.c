/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_tls13_consistency_rfc8446 */
#include <stdio.h>
#include "stub_replace.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "rec_wrapper.h"
#include "cert.h"
#include "securec.h"
#include "conn_init.h"
#include "hitls_crypt_init.h"
#include "hitls_psk.h"
#include "common_func.h"
#include "alert.h"
#include "process.h"
#include "bsl_sal.h"
/* END_HEADER */
#define MAX_BUF 16384

int32_t STUB_RecConnDecrypt(
    TLS_Ctx *ctx, RecConnState *state, const REC_TextInput *cryptMsg, uint8_t *data, uint32_t *dataLen)
{
    (void)ctx;
    (void)state;
    memcpy_s(data, cryptMsg->textLen, cryptMsg->text, cryptMsg->textLen);
    (void)data;
    *dataLen = cryptMsg->textLen;
    return HITLS_SUCCESS;
}

int32_t STUB_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    (void)ctx;
    (void)recordType;
    (void)data;
    (void)num;
    return HITLS_SUCCESS;
}

extern int32_t __real_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC001
* @spec  -
* @title The client does not support posthandshake, but receives a server certificate request
*             message after the connection establishment is completed.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client not to support post-handshake extension
*   3. After the connection establishment is completed, the construction server sends a certificate request message to the
*       client
*   4. Observe client behavior
* @expect
*   1. Initialization successful
*   2. Setup successful
*   3. Send successfully.
*   4. The client returns alert ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC001(void)
{
    HITLS_CryptMethodInit();
    FRAME_Init();

    // Apply and initialize config
    HITLS_Config *c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    // Set the client not to support post-handshake extension
    HITLS_CFG_SetPostHandshakeAuthSupport(c_config, false);
    HITLS_CFG_SetPostHandshakeAuthSupport(s_config, false);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // the construction server sends a certificate request message to the client
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE_REQUEST;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    STUB_Init();
    FuncStubInfo tmpStubInfo;
    STUB_Replace(&tmpStubInfo, RecConnDecrypt, STUB_RecConnDecrypt);

    uint8_t readbuff[READ_BUF_SIZE];
    uint32_t readLen;
    ASSERT_TRUE(client->ssl != NULL);

    // The client returns alert ALERT_UNEXPECTED_MESSAGE
    ASSERT_EQ(HITLS_Read(client->ssl, readbuff, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
exit:
    STUB_Reset(&tmpStubInfo);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC010
* @spec  -
* @title The server receives out-of-order messages during authentication after handshake.
* @precon  nan
* @brief
*   1. Apply and initialize config
*   2. Set the client support post-handshake extension
*   3. After the connection is established, the server receives the CertificateVerify message.
* @expect
*   1. Initialization succeeded.
*   2. Set succeeded.
*   3. The server sends an alert message, and the connection is interrupted.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC010(void)
{
    HITLS_CryptMethodInit();
    FRAME_Init();

    // Apply and initialize config
    HITLS_Config *c_config = HITLS_CFG_NewTLS13Config();
    HITLS_Config *s_config = HITLS_CFG_NewTLS13Config();

    // Set the client support post-handshake extension
    HITLS_CFG_SetPostHandshakeAuthSupport(c_config, true);
    HITLS_CFG_SetPostHandshakeAuthSupport(s_config, true);
    HITLS_CFG_SetClientVerifySupport(c_config, true);
    HITLS_CFG_SetClientVerifySupport(s_config, true);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(server->ssl), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    // the server receives the CertificateVerify message.
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE_VERIFY;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    STUB_Init();
    FuncStubInfo tmpStubInfo;
    STUB_Replace(&tmpStubInfo, RecConnDecrypt, STUB_RecConnDecrypt);

    // The server sends an alert message, and the connection is interrupted.
    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
exit:
    STUB_Reset(&tmpStubInfo);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC018
* @spec  -
* @title  Invoke the HITLS_VerifyClientPostHandshake interface during connection establishment.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the client and server to support post-handshake extension. Expected result 3 is obtained.
*   3. When a connection is established, the server is in the Try_RECV_CLIENT_HELLO state, and the
*       HITLS_VerifyClientPostHandshake interface is invoked.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The interface fails to be invoked.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC018(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Apply for and initialize the configuration file
    config = HITLS_CFG_NewTLS13Config();
    client = FRAME_CreateLink(config, BSL_UIO_SCTP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_SCTP);
    ASSERT_TRUE(server != NULL);

    // Configure the client and server to support post-handshake extension
    client->ssl->config.tlsConfig.isSupportPostHandshakeAuth = true;
    server->ssl->config.tlsConfig.isSupportPostHandshakeAuth = true;
    ASSERT_TRUE(client->ssl->config.tlsConfig.isSupportPostHandshakeAuth == true);
    ASSERT_TRUE(server->ssl->config.tlsConfig.isSupportPostHandshakeAuth == true);

    // he server is in the Try_RECV_CLIENT_HELLO state
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    // the HITLS_VerifyClientPostHandshake interface is invoked
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(client->ssl), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(server->ssl), HITLS_MSG_HANDLE_STATE_ILLEGAL);
exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC019
* @spec  -
* @title  The server does not support invoking the HITLS_VerifyClientPostHandshake interface after handshake
*           authentication.
* @precon  nan
* @brief
*   1. Apply for and initialize the configuration file. Expected result 1 is obtained.
*   2. Configure the client to support the post-handshake extension. The server does not support the post-handshake
*       extension.
*   3. Establish a connection. The server invokes the HITLS_VerifyClientPostHandshake interface to initiate
*       authentication.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The interface fails to be invoked.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_POSTHANDSHAKE_FUNC_TC019(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    // Apply for and initialize the configuration file
    config = HITLS_CFG_NewTLS13Config();
    client = FRAME_CreateLink(config, BSL_UIO_SCTP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_SCTP);
    ASSERT_TRUE(server != NULL);

    // Configure the client to support the post-handshake extension
    client->ssl->config.tlsConfig.isSupportPostHandshakeAuth = true;
    server->ssl->config.tlsConfig.isSupportPostHandshakeAuth = false;
    ASSERT_TRUE(client->ssl->config.tlsConfig.isSupportPostHandshakeAuth == true);
    ASSERT_TRUE(server->ssl->config.tlsConfig.isSupportPostHandshakeAuth == false);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    // The server invokes the HITLS_VerifyClientPostHandshake interface to initiate authentication
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(client->ssl), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_VerifyClientPostHandshake(server->ssl), HITLS_MSG_HANDLE_STATE_ILLEGAL);
exit:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */