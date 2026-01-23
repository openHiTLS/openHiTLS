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
/* INCLUDE_BASE test_suite_sdv_frame_tlcp_consistency */
/* END_HEADER */

static void Test_MisSessionId(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    if (*(bool *)user) {
        return;
    }
    *(bool *)user = true;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    ASSERT_EQ(parseLen, *len);
    frameMsg.body.hsMsg.body.serverHello.sessionId.state = MISSING_FIELD;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_SESSIONID_MISS_TC001
* @title During session recovery, the server deletes session_id after sending the server hello message. The expected
*        session recovery fails and the connection is interrupted.
* @precon  nan
* @brief   1. The client hello and server hello messages are followed by authentication and key exchange. Including
*             server certificate, server key exchange, client certificate, and client key exchange. Expected result 1.
* @expect  1. The expected handshake fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_SESSIONID_MISS_TC001()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    bool isModify = false;
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    HITLS_SetSession(client->ssl, clientSession);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &isModify,
        Test_MisSessionId
    };
    RegisterWrapper(wrapper);
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

static void Test_DiffServerKeyEx(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    if (*(bool *)user) {
        return;
    }
    *(bool *)user = true;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_KEY_EXCHANGE);
    ASSERT_EQ(parseLen, *len);
    frameType.keyExType = HITLS_KEY_EXCH_ECC;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_KEY_EXCHANGE_TC001
* @title After the client sends a certificate, the key exchange message sent by the client is different from the
*        negotiated key exchange algorithm. As a result, the link fails to be established.
* @precon  nan
* @brief   1. After the client sends a certificate, the key exchange message sent by the client must be consistent with
*          the negotiated key exchange algorithm. Expected result 1.
* @expect  1. The expected handshake fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_KEY_EXCHANGE_TC001()
{

    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    bool isModify = false;
    RecWrapper wrapper = {
        TRY_SEND_SERVER_KEY_EXCHANGE,
        REC_TYPE_HANDSHAKE,
        false,
        &isModify,
        Test_DiffServerKeyEx
    };
    RegisterWrapper(wrapper);
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
}
/* END_CASE */

/* @
 * @test   UT_TLS_TLCP_CONSISTENCY_CLIENTKXCH_VERSIONERR_TC001
 * @title  Test when the value of Client_Version on the server does not match that on the client.
 * @precon nan
 * @spec   1. "Client_Version: version number supported by the client. The server checks whether the value matches the
 *            value sent in the hello message from the client. random 46-byte random number"
 * @brief  1. The server checks whether the Client_Version matches the value sent in the hello message from the client.
 *            Expected result 1.
 * @expect 1. If the Client_Version of PreMasterSecret in the ClientKeyExChange message received by the server is
 *            different from the ClientHello message, the server reports an alarm indicating that the decryption fails
 *            and the handshake fails.
 @ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CLIENTKXCH_VERSIONERR_TC001(char *cipherSuite)
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite(cipherSuite);
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    STUB_REPLACE(GenerateEccPremasterSecret, STUB_GenerateEccPremasterSecret);
    int32_t ret = FRAME_CreateConnection(client, server, false, TRY_RECV_FINISH);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    STUB_RESTORE(GenerateEccPremasterSecret);
}
/* END_CASE */

/* @
 * @test   UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC001
 * @title  Violation of the rule that the signature certificate is before the encryption certificate is after, and
 *         check the result.
 * @precon nan
 * @spec   1. Server certificate: signature certificate is placed before the encryption certificate.
 * @brief  1. Signature certificate before encryption certificate. Expected result 1.
 * @expect 1. After the signature certificate encrypts the certificate after the server sends the certificate,
 *            the client reports an error indicating that the certificate verification fails and the handshake fails.
 @ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "sm2/ca.der",
        "sm2/inter.der",
        "sm2/sign.der",
        "sm2/enc.der",
        "sm2/sign.key.der",
        "sm2/enc.key.der",
    };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    int32_t ret;
    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_CERT_ERR_KEYUSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void TEST_SendUnexpectCertificateVerifyMsg(void *msg, void *data)
{
    FRAME_Type *frameType = (FRAME_Type *)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;

    FRAME_Msg newFrameMsg = {0};
    HS_MsgType hsTypeTmp = frameType->handshakeType;
    REC_Type recTypeTmp = frameType->recordType;
    frameType->handshakeType = CERTIFICATE_VERIFY;
    FRAME_Init();
    FRAME_GetDefaultMsg(frameType, &newFrameMsg);
    HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT); // recovery callback

    frameType->handshakeType = hsTypeTmp;
    frameType->recordType = recTypeTmp;
    FRAME_CleanMsg(frameType, frameMsg);

    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = CERTIFICATE_VERIFY;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    if (memcpy_s(msg, sizeof(FRAME_Msg), &newFrameMsg, sizeof(newFrameMsg)) != EOK) {
        Print("TEST_SendUnexpectCertificateMsg memcpy_s Error!");
    }
}

static void TEST_UnexpectMsg(HLT_FrameHandle *frameHandle, TestExpect *testExpect, bool isSupportClientVerify)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    ALERT_Info alertInfo = {0};

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverConfig != NULL);
    if (isSupportClientVerify) {
        ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, isSupportClientVerify) == 0);
    }
    HLT_Ctx_Config *clientConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(clientConfig, isSupportClientVerify) == 0);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLCP1_1, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Client Initialization
    clientRes = HLT_ProcessTlsInit(localProcess, TLCP1_1, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(frameHandle != NULL);
    frameHandle->ctx = clientRes->ssl;
    HLT_SetFrameHandle(frameHandle);
    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), testExpect->connectExpect);
    HLT_CleanFrameHandle();

    ALERT_GetInfo(clientRes->ssl, &alertInfo);
    ASSERT_TRUE(alertInfo.level == testExpect->expectLevel);
    ASSERT_EQ(alertInfo.description, testExpect->expectDescription);
    ASSERT_EQ(HLT_RpcGetTlsAcceptResult(serverRes->acceptId), testExpect->acceptExpect);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC002
* @title  The server receives the certificate verify message when receiving the certificate.
* @precon  nan
* @brief   1. Configure dual-end verification. Expected result 1.
*          2. Set the client callback type to certificate and replace it with certificate verify. Expected result 2.
* @expect  1. Expected success.
*          2. Expected server to return alert.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC002()
{
    TestExpect testExpect = {0};
    testExpect.acceptExpect = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    testExpect.expectLevel = ALERT_LEVEL_FATAL;
    testExpect.expectDescription = ALERT_UNEXPECTED_MESSAGE;
    testExpect.connectExpect = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;

    HLT_FrameHandle frameHandle = {0};
    frameHandle.frameCallBack = TEST_SendUnexpectCertificateVerifyMsg;
    frameHandle.expectHsType = CERTIFICATE;
    frameHandle.expectReType = REC_TYPE_HANDSHAKE;
    frameHandle.ioState = EXP_NONE;
    frameHandle.pointType = POINT_SEND;
    frameHandle.userData = NULL;
    TEST_UnexpectMsg(&frameHandle, &testExpect, true);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC003
* @title  Dual-end verification. The server receives the CERTIFICATION_VERIFY message when expecting to receive the
*         CLIENT_KEY_EXCHANGE message.
* @precon  nan
* @brief   1. Configure unidirectional authentication. Expected result 1.
*          2. Set the client callback mode to send certificate verify. Expected result 2.
* @expect  1. Expected success.
*          2. Expected server to return alert.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC003()
{
    TestExpect testExpect = {0};
    testExpect.acceptExpect = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    testExpect.expectLevel = ALERT_LEVEL_FATAL;
    testExpect.expectDescription = ALERT_UNEXPECTED_MESSAGE;
    testExpect.connectExpect = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;

    HLT_FrameHandle frameHandle = {0};
    frameHandle.frameCallBack = TEST_SendUnexpectCertificateVerifyMsg;
    frameHandle.expectHsType = CLIENT_KEY_EXCHANGE;
    frameHandle.expectReType = REC_TYPE_HANDSHAKE;
    frameHandle.ioState = EXP_NONE;
    frameHandle.pointType = POINT_SEND;
    frameHandle.userData = NULL;

    TEST_UnexpectMsg(&frameHandle, &testExpect, true);
}
/* END_CASE */

// Replace the message to be sent with the CERTIFICATE.
static void TEST_SendUnexpectCertificateMsg(void *msg, void *data)
{
    FRAME_Type *frameType = (FRAME_Type *)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;

    FRAME_Msg newFrameMsg = {0};
    HS_MsgType hsTypeTmp = frameType->handshakeType;
    frameType->handshakeType = CERTIFICATE;
    // Callback for changing the certificate algorithm, which is used to generate negotiation handshake messages.
    FRAME_Init();
    FRAME_GetDefaultMsg(frameType, &newFrameMsg);
    HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT); // recovery callback

    // Release the original msg.
    frameType->handshakeType = hsTypeTmp;
    FRAME_CleanMsg(frameType, frameMsg);

    // Change message.
    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = CERTIFICATE;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType->transportType = BSL_UIO_TCP;
    if (memcpy_s(msg, sizeof(FRAME_Msg), &newFrameMsg, sizeof(newFrameMsg)) != EOK) {
        Print("TEST_SendUnexpectCertificateMsg memcpy_s Error!");
    }
}

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC004
* @title  Single-end verification, indicating that the server receives the CERTIFICATION message.
* @precon  nan
* @brief   1. Configure unidirectional authentication. Expected result 1.
*          2. Set the client severhello done callback mode to send certificate verify. Expected result 2.
* @expect  1. Expected success.
*          2. Expected server to return alert.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC004()
{
    TestExpect testExpect = {0};
    testExpect.acceptExpect = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    testExpect.expectLevel = ALERT_LEVEL_FATAL;
    testExpect.expectDescription = ALERT_UNEXPECTED_MESSAGE;
    testExpect.connectExpect = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;

    HLT_FrameHandle frameHandle = {0};
    frameHandle.frameCallBack = TEST_SendUnexpectCertificateMsg;
    frameHandle.expectHsType = CLIENT_KEY_EXCHANGE;
    frameHandle.expectReType = REC_TYPE_HANDSHAKE;
    frameHandle.ioState = EXP_NONE;
    frameHandle.pointType = POINT_SEND;
    frameHandle.userData = NULL;
    TEST_UnexpectMsg(&frameHandle, &testExpect, false);
}
/* END_CASE */

static void Test_ErrCertVerify(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    if (*(bool *)user) {
        return;
    }
    *(bool *)user = true;
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_TCP;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    frameMsg.transportType = BSL_UIO_TCP;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_VERIFY);
    ASSERT_EQ(parseLen, *len);
    frameMsg.body.hsMsg.body.certificateVerify.sign.data[0]++;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* @
* @test    UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC005
* @title   Bidirectional verification. After the client sends a certificate, the certificate verify message contains
*          an incorrect digital signature or does not contain a digital signature. As a result, the link fails to be
*          established.
* @precon  nan
* @brief   1. Start a handshake. Expected result 1
*          2. Modify the certificate verify message. Expected result 2
* @expect  1. Return success
*          2. Handshake fails
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC005()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    bool isModify = false;
    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_VERIFY,
        REC_TYPE_HANDSHAKE,
        false,
        &isModify,
        Test_ErrCertVerify
    };
    RegisterWrapper(wrapper);
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
}
/* END_CASE */

/* @
* @test    UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC006
* @title   Bidirectional verification. After the client sends a certificate, the certificate verify message contains
*          an incorrect digital signature or does not contain a digital signature. As a result, the link fails to be
*          established.
* @precon  nan
* @brief   1. Start a handshake and set the ciphersuite to HITLS_ECC_SM4_CBC_SM3, Expected result 1
*          2. Modify the certificate verify message. Expected result 2
* @expect  1. Return success
*          2. Handshake fails
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CERTFICATE_TC006()
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    bool isModify = false;
    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_VERIFY,
        REC_TYPE_HANDSHAKE,
        false,
        &isModify,
        Test_ErrCertVerify
    };
    RegisterWrapper(wrapper);
    uint16_t cipherSuite = HITLS_ECC_SM4_CBC_SM3;
    HITLS_CFG_SetCipherSuites(config, &cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));
    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_NE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    ClearWrapper();
}
/* END_CASE */

static int32_t SendCcs(HITLS_Ctx *ctx, uint8_t *data, uint8_t len)
{
    /** Write records. */
    return REC_Write(ctx, REC_TYPE_CHANGE_CIPHER_SPEC, data, len);
}

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CCS_TC006
* @title   If an implementation detects a change_cipher_spec record received before the first ClientHello
*          message or after the peer's Finished message, it MUST be treated as an unexpected record type
* @precon  nan
* @brief   1. Establish a connection. Expected result 1
*          2. Send a CCS message to client. Expected result 2
*          3. Send a CCS message to server. Expected result 3
* @expect  1. Return success
*          2. client send ALERT_UNEXPECTED_MESSAGE alert
*          3. server send ALERT_UNEXPECTED_MESSAGE alert
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CCS_TC006(int isClient)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECDHE_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t data = 1;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    if (isClient != 0) {
        ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        ALERT_Info info = { 0 };
        ALERT_GetInfo(server->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
    } else {
        memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE);
        ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
        ALERT_Info info = { 0 };
        ALERT_GetInfo(client->ssl, &info);
        ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
        ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
        ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
    }

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_Finish_Len_TooLong(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);
    ASSERT_EQ(frameMsg.body.hsMsg.body.finished.verifyData.size, 12); // in RFC5246, length of verifyData is always 12.

    frameMsg.body.hsMsg.body.finished.verifyData.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.finished.verifyData.data[0] = 0x00;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Finish_Len_TooLong_client(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);
    ASSERT_EQ(frameMsg.body.hsMsg.body.finished.verifyData.size, 12); // in RFC5246, length of verifyData is always 12.
    if (ctx->isClient==true) {
        frameMsg.body.hsMsg.body.finished.verifyData.state = ASSIGNED_FIELD;
        frameMsg.body.hsMsg.body.finished.verifyData.data[0] += 1;
    }
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_ERROR_FINISH_001
* @title  An unexpected message is received when the server is in the TRY_RECV_FINISH state during the handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. Construct a CLIENT_KEY_EXCHANGE message and send it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*            ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_ERROR_FINISH_001(void)
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLCP_DTLCP11;
    testInfo.uioType = BSL_UIO_TCP;
    RecWrapper wrapper = {
        TRY_SEND_FINISH,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Finish_Len_TooLong,
    };
    RegisterWrapper(wrapper);

    testInfo.config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.client = FRAME_CreateTLCPLink(testInfo.config, testInfo.uioType, true);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateTLCPLink(testInfo.config, testInfo.uioType, false);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_ERROR_FINISH_002
* @title  An unexpected message is received when the server is in the TRY_RECV_FINISH state during the handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. Construct a CLIENT_KEY_EXCHANGE message and send it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*            ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_ERROR_FINISH_002(void)
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLCP_DTLCP11;
    testInfo.uioType = BSL_UIO_TCP;
    RecWrapper wrapper = {
        TRY_SEND_FINISH,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Finish_Len_TooLong_client,
    };
    RegisterWrapper(wrapper);

    testInfo.config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(testInfo.config != NULL);
    testInfo.client = FRAME_CreateTLCPLink(testInfo.config, testInfo.uioType, true);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateTLCPLink(testInfo.config, testInfo.uioType, false);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static int32_t GetDisorderServerCertAndKeyExchMsg(FRAME_LinkObj *server, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t tmpData[READ_BUF_SIZE] = {0};
    uint32_t tmpLen = sizeof(tmpData);
    (void)HITLS_Accept(server->ssl);
    int32_t ret = FRAME_TransportSendMsg(server->io, tmpData, tmpLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    tmpLen = readLen;

    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, &data[offset], len - offset, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    offset += readLen;

    if (memcpy_s(&data[offset], len - offset, tmpData, tmpLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += tmpLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

/* @
 * @test   UT_TLS_TLCP_CONSISTENCY_DISORDER_TC001
 * @title  Configure dual-ended verification and construct abnormal scenarios.
 * @precon nan
 * @spec   The server should send a server certificate message to the client, which always follows the server hello
 *         message. If the selected cipher suite uses the RSA, ECC, or ECDHE algorithm, the message contains the
 *         signature certificate and encryption certificate of the server.
 * @brief  1. Configure dual-end verification and construct an abnormal scenario. After the serverhello message is sent,
 *            the sequence of the certificate message and serverkeyexchange message is changed. Expected result 1.
 * @expect 1. Client returns an unexpected alert message.
 @ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_DISORDER_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_CERTIFICATE), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_HANDSHAKING);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_CERTIFICATE);

    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderServerCertAndKeyExchMsg(server, data, len, &len) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(ioUserData->recMsg.len != 0);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/* @
* @test  UT_TLS_TLCP_CONSISTENCY_DISORDER_TC002
* @title  During the handshake, the client receives the CCS when the client is receiving the clientkeyexchange.
* @precon  nan
* @brief  1. Configure the single-end authentication. After the server sends the serverhellodone message, the client
*            stops in the try send client key exchange state. Expected result 1.
*         2. Construct an unexpected CCS message and send it to the server. Expected result 2.
* @expect 1. The initialization succeeds.
*         2. The connection fails to be established and the server returns an unexpected message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_DISORDER_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECC_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE) == HITLS_SUCCESS);

    uint32_t sendLen = 6;
    uint8_t sendBuf[6] = {0x14, 0x01, 0x01, 0x00, 0x01, 0x01};

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);

    ASSERT_TRUE(server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(server->ssl->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_DISORDER_TC003
* @title  During the handshake, the clientkeyexchange message is received when the client status is receiving the
*         certificate.
* @precon  nan
* @brief  1. Configure dual-end authentication. After the server sends a serverhellodone message, the client stops in
*            the try send certificate state. Expected result 1.
*         2. Construct an unexpected clientkeyexchange message and send the message to the server. Expected result 2.
* @expect 1. The initialization succeeds.
*         2. The connection fails to be established and the server returns an unexpected message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_DISORDER_TC003(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECDHE_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
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

    ASSERT_TRUE(server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static int32_t STUB_APP_Write_Fatal(TLS_Ctx *ctx, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen)
{
    (void)data;
    (void)dataLen;
    (void)writeLen;
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    return HITLS_INTERNAL_EXCEPTION;
}

/* @
 * @test   UT_TLS_TLCP_CONSISTENCY_FATAL_ALERT_TC003
 * @title  Session processing in the case of critical alarms.
 * @precon nan
 * @spec   When a critical alarm is sent or received, both parties should immediately close the connection and discard
 *         the session ID and key of the incorrect connection. The connection closed by the critical alarm cannot be
 *         reused.
 * @brief  1. Sending a fatal alert. Expected result 1.
 *         2. The server sends a fatal alert, the session information is used for the next connection.
 *            Expected result 2.
 * @expect 1. The server fails to send data and receive data.
 *         2. The connection fails to be established.
 @ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_FATAL_ALERT_TC003(char *cipherSuite, int isResume)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite(cipherSuite);
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    HITLS_Session *Newsession = NULL;
    HITLS_Session *serverSession = NULL;
    uint32_t readLen = 0;
    uint8_t data[] = "Hello World";
    STUB_REPLACE(APP_Write, STUB_APP_Write_Fatal);
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(server->ssl, data, sizeof(data), &writeLen), HITLS_INTERNAL_EXCEPTION);
    STUB_RESTORE(APP_Write);
    ASSERT_TRUE(server->ssl->state == CM_STATE_ALERTED);

    if (isResume == 1) {
        serverSession = HITLS_GetDupSession(server->ssl);
        ASSERT_TRUE(serverSession != NULL);

        FRAME_FreeLink(client);
        client = NULL;
        FRAME_FreeLink(server);
        server = NULL;
        client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
        ASSERT_TRUE(client != NULL);
        server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
        ASSERT_TRUE(server != NULL);
        ASSERT_EQ(HITLS_SetSession(client->ssl, serverSession), 0);

        ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

        Newsession = HITLS_GetDupSession(client->ssl);

        ASSERT_TRUE(memcmp(serverSession->sessionId, Newsession->sessionId, HITLS_SESSION_ID_MAX_SIZE) != 0);
    } else {
        ASSERT_TRUE(HITLS_Write(server->ssl, data, sizeof(data), &writeLen) == HITLS_CM_LINK_FATAL_ALERTED);
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_FATAL_ALERTED);
    }

    ASSERT_TRUE(HITLS_Close(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_CLOSED);
EXIT:
    HITLS_SESS_Free(Newsession);
    HITLS_SESS_Free(serverSession);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC001
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a connection between the client and server. Expected result 1.
*         2. The client closes the link, obtains the message sent by the client, and checks whether the message is a
*            close_notify message. Expected result 2.
*         3. The server obtains the received message and checks whether the message is a close_notify message.
*            Expected result 3.
* @expect 1. The link is successfully established.
*         2. The client sends a close_notify message.
*         3. The server receives the close_notify message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECDHE_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->recMsg.msg;
    uint32_t serverreadLen = serverioUserData->recMsg.len;
    uint32_t serverparseLen = 0;
    ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);
    
    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC002
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a link between the client and server. Expected result 1.
*         2. The client closes the link, obtains the message sent by the client, and checks whether the message is a
*            close_notify message. Expected result 2.
*         3. The server processes the message received by the server, obtains the message to be sent after processing,
*            and checks whether the message is a close_notify message. Expected result 3.
* @expect 1. The link is successfully established.
*         2. The client sends a close_notify message.
*         3. The server sends a close_notify message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECDHE_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->recMsg.msg;
    uint32_t serverreadLen = serverioUserData->recMsg.len;
    uint32_t serverparseLen = 0;
    ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(server->ssl != NULL);
    serverioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    serverioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    serverioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_CM_LINK_FATAL_ALERTED);

    FRAME_Msg serverframeMsg1 = {0};
    uint8_t *serverbuffer1 = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen1 = serverioUserData->sndMsg.len;
    uint32_t serverparseLen1 = 0;
    ret = ParserTotalRecord(server, &serverframeMsg1, serverbuffer1, serverreadLen1, &serverparseLen1);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg1.type == REC_TYPE_ALERT && serverframeMsg1.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg1.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg1.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC003
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a connection between the client and server. Expected result 1.
*         2. The server closes the link, obtains the message sent by the server,
*            and checks whether the message is a close_notify message. Expected result 2.
*         3. Obtain the received message and check whether the message is a close_notify message. Expected result 3.
* @expect 1. The link is successfully established.
*         2. The server sends a close_notify message.
*         3. The client receives the close_notify message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC003(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECDHE_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen = serverioUserData->sndMsg.len;
    uint32_t serverparseLen = 0;
    int32_t ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->recMsg.msg;
    uint32_t clientreadLen = clientioUserData->recMsg.len;
    uint32_t clientparseLen = 0;
    ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC004
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a link between the client and server. Expected result 1.
*         2. The server closes the link, obtains the message sent by the server,
*            and checks whether the message is a close_notify message. Expected result 2.
*         3. The client processes the received message, obtains the message to be sent after processing,
*            and checks whether the message is a close_notify message. Expected result 3.
* @expect 1. The link is successfully established.
*         2. The client sends a close_notify message.
*         3. The server sends a close_notify message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CLOSE_NOTIFY_TC004(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite("HITLS_ECDHE_SM4_CBC_SM3");
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    // Error stack exists
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_FINISH) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = {0};
    uint8_t *serverbuffer = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen = serverioUserData->sndMsg.len;
    uint32_t serverparseLen = 0;
    int32_t ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);
    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    clientioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    FRAME_Msg clientframeMsg = {0};
    uint8_t *clientbuffer = clientioUserData->recMsg.msg;
    uint32_t clientreadLen = clientioUserData->recMsg.len;
    uint32_t clientparseLen = 0;
    ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(client->ssl != NULL);
    clientioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    clientioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_CM_LINK_FATAL_ALERTED);

    FRAME_Msg clientframeMsg1 = {0};
    uint8_t *clientbuffer1 = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen1 = clientioUserData->sndMsg.len;
    uint32_t clientparseLen1 = 0;
    ret = ParserTotalRecord(client, &clientframeMsg1, clientbuffer1, clientreadLen1, &clientparseLen1);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg1.type == REC_TYPE_ALERT);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_WARNING);
    ASSERT_EQ(alert.description, ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
 * @test   UT_TLS_TLCP_CONSISTENCY_AMEND_APPDATA_TC001
 * @title  Modify the app message received by the client, modify the encrypted data, inject the message,
 *         and observe the response from the client.
 * @precon nan
 * @spec   "AEADEncrypted = AEAD-Encrypt(write_ key, nonce, plaintext, additional data) To decrypt and verify,
 *         the cryptographic algorithm uses the key, random number, additional_data and AEADEncrypted values are used
 *         as inputs. The output is plaintext or an error indicating a decryption failure. There is no additional
 *         integrity check. I.e.: TLSCompressed. fragment= AEAD-Decrypt (write_key, nonce,AEADEncrypted,
 *         additional_data) A fatal bad_record_mac warning should be generated if decryption fails. See Appendix A for
 *         the GCM Authenticated Encryption Mode."
 * @brief  1. Set up a link, read and write data, modify the app message received by the client, modify the encrypted
 *            data, and perform message injection. Observe the response from the client. Expected result 1.
 *         2. Set up a link, read and write data, modify the app message received by the server, modify the encrypted
 *            data, and perform message injection. Observe the response of the server. Expected result 2.
 * @expect 1. The bad_record_mac alert is sent.
 *         2. The bad_record_mac alert is sent.
 @ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_AMEND_APPDATA_TC001(char *cipherSuite, int isClient)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t toSetCipherSuite = GetCipherSuite(cipherSuite);
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    FRAME_LinkObj *client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);

    FRAME_LinkObj *server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    FRAME_LinkObj *recver = isClient ? client : server;
    FRAME_LinkObj *sender = isClient ? server : client;

    uint8_t data[] = "Hello World";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(sender->ssl, data, sizeof(data), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(sender, recver) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(recver->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_APP;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_AppMsg *appMsg = &frameMsg.body.appMsg;
    uint8_t appData[] = "123";
    appMsg->appData.state = ASSIGNED_FIELD;
    ASSERT_EQ(memcpy_s(appMsg->appData.data, appMsg->appData.size, "123", sizeof(appData)), 0);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(recver->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_EQ(HITLS_Read(recver->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(recver->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_RECORD_MAC);

    ASSERT_TRUE(HITLS_Close(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_CLOSED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/* @
 * @test   UT_FRAME_FUNC_TLCP_CERT_MISMATCH_TC001
 * @title  After receiving the servehellodone message from the server, the client checks whether the server certificate
 *         is valid and whether the parameters in the servehello message are acceptable.
 * @precon nan
 * @spec   After receiving the servehellodone message from the server, the client verifies whether the server
 *         certificate is valid and whether the server's servehello message parameters are acceptable. If acceptable,
 *         the client continues the handshake process. Otherwise, a HandShakeFailure fatal alarm is sent.
 * @brief  1. Set the algorithm suite to ECDHE_SM4_CBC_SM3 on the client and server, and load the RSA certificate to
 *            the server. Expected result 1.
 *         2. Set the algorithm suite to ECC_SM4_CBC_SM3 on the client and server, and load the RSA certificate to
 *            the server. Expected result 2.
 * @expect 1. The server fails to negotiate the cipher suite (the certificate and cipher suite do not match).
 *         2. The server fails to negotiate the cipher suite (the certificate and cipher suite do not match).
 @ */
/* BEGIN_CASE */
void UT_FRAME_FUNC_TLCP_CERT_MISMATCH_TC001(char *cipherSuite)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_CertInfo certInfo = {
        "sm2/ca.der",
        "sm2/inter.der",
        "rsa_sha256/server.der",
        "sm2/sign.der",
        "rsa_sha256/server.key.der",
        "sm2/sign.key.der",
    };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t toSetCipherSuite = GetCipherSuite(cipherSuite);
    HITLS_CFG_SetCipherSuites(tlsConfig, &toSetCipherSuite, 1);

    client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);

    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.description, ALERT_HANDSHAKE_FAILURE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC001
* @title  The encryption certificate does not have a keyusage extension, and check the result.
* @precon nan
* @brief  1. Use the default configuration on the client and server，Server setting encryption certificate without 
*               keyusage extension. Expected result 1.
*         2. Start a handshake. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_BAD_CERTIFICATE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "sm2_cert/root.der",
        "sm2_cert/intCa.der",
        "sm2_cert/server_enc_no_keyusage.der",
        "sm2_cert/server_sign.der",
        "sm2_cert/server_enc_no_keyusage.key.der",
        "sm2_cert/server_sign.key.der",
    };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_CERT_ERR_EXP_CERT);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_BAD_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC002
* @title  The signing certificate does not have a keyusage extension, and check the result.
* @precon nan
* @brief  1. Use the default configuration on the client and server，Server setting signing certificate without 
*               keyusage extension. Expected result 1.
*         2. Start a handshake. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_BAD_CERTIFICATE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC002()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "sm2_cert/root.der",
        "sm2_cert/intCa.der",
        "sm2_cert/server_enc.der",
        "sm2_cert/server_sign_no_keyusage.der",
        "sm2_cert/server_enc.key.der",
        "sm2_cert/server_sign_no_keyusage.key.der",
    };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_CERT_ERR_KEYUSAGE);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_BAD_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC003
* @title  The signature certificate has an incorrect keyusage extension, and check the result.
* @precon nan
* @brief  1. Use the default configuration on the client and server，The server's signature certificate contains an
*               incorrect keyusage extension. Expected result 1.
*         2. Start a handshake. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_BAD_CERTIFICATE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC003()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "sm2_cert/root.der",
        "sm2_cert/intCa.der",
        "sm2_cert/server_enc.der",
        "sm2_cert/client_sign_err_keyusage.der",
        "sm2_cert/server_enc.key.der",
        "sm2_cert/client_sign_err_keyusage.key.der",
    };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_CERT_ERR_KEYUSAGE);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_BAD_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC004
* @title  The encryption certificate has an incorrect keyusage extension, and check the result.
* @precon nan
* @brief  1. Use the default configuration on the client and server，The server's encryption certificate contains an
*               incorrect keyusage extension. Expected result 1.
*         2. Start a handshake. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_BAD_CERTIFICATE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_KEYUSAGE_TC004()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "sm2_cert/root.der",
        "sm2_cert/intCa.der",
        "sm2_cert/client_enc_err_keyusage.der",
        "sm2_cert/server_sign.der",
        "sm2_cert/client_enc_err_keyusage.key.der",
        "sm2_cert/server_sign.key.der",
    };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_CERT_ERR_EXP_CERT);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_BAD_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
