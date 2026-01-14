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
EXIT:
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
EXIT:
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
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

int32_t SendKeyupdate_Err(HITLS_Ctx *ctx)
{
    /** Initialize the message buffer. */
    uint8_t buf[5] = {KEY_UPDATE, 0x00, 0x00, 0x01, 0x01};
    size_t len = 5;

    /** Write records. */
    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
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
    clientCtxConfig->isSupportExtendedMasterSecret=true;
    serverCtxConfig->isSupportExtendedMasterSecret=true;
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

    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(serverRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

int32_t SendNEW_SESSION_TICKET_Err(HITLS_Ctx *ctx)
{
    /** Initialize the message buffer. */
    uint8_t buf[32] = {NEW_SESSION_TICKET,0,0,0x1c,0x20,0xc1,};
    size_t len = 32;

    /** Write records. */
    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
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
    clientCtxConfig->isSupportExtendedMasterSecret=true;
    serverCtxConfig->isSupportExtendedMasterSecret=true;
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
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_TLS12_StateTrans_FUNC_TC001(void)
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
    clientCtxConfig->isSupportExtendedMasterSecret=true;
    serverCtxConfig->isSupportExtendedMasterSecret=true;
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

    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, READ_BUF_LEN_18K, &readLen) , HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(serverRes->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_RECV);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HLT_FreeAllProcess();
    HLT_CleanFrameHandle();
}
/* END_CASE */
static void MalformedCipherSuiteLenCallback_01(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->cipherSuitesSize.data = 1000;
    clientHello->cipherSuitesSize.state = ASSIGNED_FIELD;
EXIT:
    return;
}
void ClientSendMalformedCipherSuiteLenMsg(HLT_FrameHandle *handle, TestPara *testPara)
{
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 16384, false);
    ASSERT_TRUE(remoteProcess != NULL);
    // The remote server listens on the TLS connection.

    HLT_Ctx_Config *serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);
    serverConfig->isSupportExtendedMasterSecret = false;
    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Configure the TLS connection on the local client.

    HLT_Ctx_Config *clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig->isSupportExtendedMasterSecret = false;
    HLT_Tls_Res *clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    // Configure the interface for constructing abnormal messages.

    handle->ctx = clientRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
    // Set up a connection and wait until the local is complete.

    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) != 0);
    // Wait the remote.
    int ret = HLT_GetTlsAcceptResult(serverRes);
    ASSERT_TRUE(ret != 0);
    if (testPara->isExpectRet) {
        ASSERT_EQ(ret, testPara->expectRet);
    }
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(clientRes->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, testPara->expectDescription);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}
/** @
* @test SDV_TLS1_2_RFC5246_MALFORMED_CIPHER_SUITE_LEN_FUN_TC001
* @spec -
* @title    The length of the cipher suite in the sent ClientHello message is greater than the specific content
            length_cipher suites length
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, and the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_MALFORMED_CIPHER_SUITE_LEN_FUN_TC001()
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedCipherSuiteLenCallback_01;
    TestPara testPara = {0};
    testPara.port = g_uiPort;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedCipherSuiteLenMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void TEST_Server_check_etm_ext(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    (void)bufSize;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(serverMsg->encryptThenMac.exType.data, HS_EX_TYPE_ENCRYPT_THEN_MAC);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* @
* @test  SDV_TLS_TLS1_2_RFC5246_HANDSHAKE_FUNC_TC001
* @spec  -
* @title  Test link establishment when the tls1.2 client cipher suite does not match the certificate.
* @precon  nan
* @brief
1. Configure the ecdhe_ecdsa cipher suite, certificate, and RSA certificate chain on the server. Expected result 1 is obtained.
2. Configure the RSA certificate and ecdsa certificate chain on the client. Expected result 2 is obtained.
3. Establish a link between the two ends. Expected result 3 is obtained.
4. Read and write data. Expected result 4 is obtained.
* @expect
1. A success message is returned.
2. A success message is returned.
3. A success message is returned.
4. Return a success message.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS1_2_RFC5246_HANDSHAKE_FUNC_TC001()
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    // Configure the ecdhe_ecdsa cipher suite, certificate, and RSA certificate chain on the server.
    HLT_SetCertPath(serverCtxConfig,
        RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, ECDSA_SHA256_EE_PATH, ECDSA_SHA256_PRIV_PATH, "NULL", "NULL");
    HLT_SetClientVerifySupport(serverCtxConfig, true);
    HLT_SetNoClientCertSupport(serverCtxConfig, false);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    // Configure the RSA certificate and ecdsa certificate chain on the client.
    HLT_SetCertPath(clientCtxConfig,
        ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        TEST_Server_check_etm_ext
    };
    RegisterWrapper(wrapper);
    // Establish a link between the two ends.
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    // Read and write data.
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */