/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_tls12_consistency_rfc5246 */
/* END_HEADER */
static void TestFrameClientChangeCompressMethod(void *msg, void *userData)
{
    (void)msg;
    (void)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->compressionMethods.state = ASSIGNED_FIELD;
    *clientHello->compressionMethods.data = 1;
}

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_ERRO_COMPRESSION_FRAGMENT_TC001
* @title  The record layer does not support compression.
* @precon  nan
* @brief   1. When the client sends a client hello message, the compression flag is changed to 1. As a result, the
connection fails to be established.
* @expect  1. Link establishment fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_ERRO_COMPRESSION_FRAGMENT_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_256_CBC_SHA");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // When the client sends a client hello message, the compression flag is changed to 1.
    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientCtxConfig, NULL);

    HLT_FrameHandle frameHandle = {
        .ctx = clientRes->ssl,
        .frameCallBack = TestFrameClientChangeCompressMethod,
        .userData = NULL,
        .expectHsType = CLIENT_HELLO,
        .expectReType = REC_TYPE_HANDSHAKE,
        .ioState = EXP_NONE,
        .pointType = POINT_SEND,
    };
    ASSERT_TRUE(HLT_SetFrameHandle(&frameHandle) == HITLS_SUCCESS);
    int ret = HLT_TlsConnect(clientRes->ssl);
    ASSERT_TRUE(ret != 0);
exit:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

static void TestFrameServerChangeCompressMethod(void *msg, void *userData)
{
    (void)msg;
    (void)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->compressionMethod.state = ASSIGNED_FIELD;
    serverHello->compressionMethod.data = 1;
}

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_ERRO_COMPRESSION_FRAGMENT_TC002
* @title  The record layer does not support compression.
* @precon  nan
* @brief   1. When the server sends the serverhello message, the compression flag is changed to 1, and the client is
expected to send the alert message.
* @expect  1. A failure message is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_ERRO_COMPRESSION_FRAGMENT_TC002(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(clientCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_256_CBC_SHA");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    /* When the server sends the serverhello message, the compression flag is changed to 1. */
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_FrameHandle frameHandle = {
        .ctx = serverRes->ssl,
        .frameCallBack = TestFrameServerChangeCompressMethod,
        .userData = NULL,
        .expectHsType = SERVER_HELLO,
        .expectReType = REC_TYPE_HANDSHAKE,
        .ioState = EXP_NONE,
        .pointType = POINT_SEND,
    };
    ASSERT_TRUE(HLT_SetFrameHandle(&frameHandle) == HITLS_SUCCESS);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
exit:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC008
* @title  two-way authentication: The certificate configured on the client does not match the signature algorithm
supported by the server. As a result, the client fails to load the certificate.
* @precon  nan
* @brief  Set the dual-end authentication, the signature algorithm supported by the server to DSA_SHA224, and the client
certificate to RSA. The expected certificate loading failure occurs on the client.
* @expect 1. The link is set up successfully.
*         2. Link establishment failure.

@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC008(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    /* Set the dual-end authentication, the signature algorithm supported by the server to DSA_SHA224, and the client
     * certificate to RSA. */
    TestSetCertPath(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    HLT_SetSignature(serverCtxConfig, "CERT_SIG_SCHEME_DSA_SHA224");

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    TestSetCertPath(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_128_GCM_SHA256");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256");

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    int ret = HLT_TlsConnect(clientRes->ssl);
    ASSERT_TRUE(ret != 0);
exit:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

int32_t SendKeyupdate_Err(HITLS_Ctx *ctx)
{
    int32_t ret;
    /** Initialize the message buffer. */
    uint8_t buf[5] = {KEY_UPDATE, 0x00, 0x00, 0x01, 0x01};
    size_t len = 5;

    /** Write records. */
    ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
    return ret;
}
/* tls12 receive keyupdate message during transporting*/
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_RECV_KEYUPDATE_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);

    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientCtxConfig->isSupportExtendMasterSecret=true;
    serverCtxConfig->isSupportExtendMasterSecret=true;
    serverCtxConfig->isSupportSessionTicket=true;
    clientCtxConfig->isSupportSessionTicket=true;

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(remoteProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf2[READ_BUF_LEN_18K] = {0};
    uint32_t readLen2= 0;
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf2, READ_BUF_LEN_18K, &readLen2) , 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf2, READ_BUF_LEN_18K, &readLen2) , 0);

    HITLS_Ctx *serverCtx = (HITLS_Ctx *)serverRes->ssl;
    ASSERT_TRUE(serverCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_EQ(SendKeyupdate_Err(serverRes->ssl) , HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen= 0;

    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(serverRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
exit:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

int32_t SendNEW_SESSION_TICKET_Err(HITLS_Ctx *ctx)
{
    int32_t ret;
    /** Initialize the message buffer. */
    uint8_t buf[32] = {NEW_SESSION_TICKET,0,0,0x1c,0x20,0xc1,};
    size_t len = 32;

    /** Write records. */
    ret = REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
    return ret;
}
/* tls12 receive NST message during transporting*/
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_RECV_NST_TC001(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);

    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientCtxConfig->isSupportExtendMasterSecret=true;
    serverCtxConfig->isSupportExtendMasterSecret=true;
    serverCtxConfig->isSupportSessionTicket=true;
    clientCtxConfig->isSupportSessionTicket=true;

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(remoteProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf2[READ_BUF_LEN_18K] = {0};
    uint32_t readLen2= 0;
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf2, READ_BUF_LEN_18K, &readLen2) , 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf2, READ_BUF_LEN_18K, &readLen2) , 0);

    HITLS_Ctx *serverCtx = (HITLS_Ctx *)serverRes->ssl;
    ASSERT_TRUE(serverCtx->state == CM_STATE_TRANSPORTING);

    ASSERT_EQ(SendNEW_SESSION_TICKET_Err(serverRes->ssl) , HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen= 0;

    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(serverRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
exit:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */