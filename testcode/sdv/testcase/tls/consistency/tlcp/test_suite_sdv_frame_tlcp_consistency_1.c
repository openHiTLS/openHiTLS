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

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC001
* @title After initialization, the server receives a CCS message after sending the serverhellodone message and return
* an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. During the handshake, after sending the Server Hello Done message, the server
*            constructs a CCS message and sends it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The server sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC001(void)
{
    HandshakeTestInfo testInfo = { 0 };

    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
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
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC002
* @title After initialization, the client receives a CCS message after sending a client hello message and returns an
* alert message
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. During the handshake, after sending the client hello message, constructs a CCS message and sends it to the
*            client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC002(void)
{
    HandshakeTestInfo testInfo = { 0 };

    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
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
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC003
* @title During connection establishment, the client receives the serverhello message after sending the CCS message and
* expects to return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. During the handshake, after client sending the CCS, constructs a serverhello message and sends it to the
*            client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC003(void)
{
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);
    testInfo.client->ssl->hsCtx->state = TRY_RECV_FINISH;

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_EQ(FRAME_GetDefaultMsg(&frameType, &frameMsg), HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
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
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC004
* @title After initialization, construct an app message and send it to the client. The expected alert is returned.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. Durintg the handshake, When the client is in the TRY_RECV_SERVER_HELLO state, construct an APP data message
*            and send it to the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC004(void)
{
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HandshakeTestInfo testInfo = { 0 };

    FRAME_Init();
    testInfo.config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.client = FRAME_CreateTLCPLink(testInfo.config, BSL_UIO_TCP, true);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateTLCPLink(testInfo.config, BSL_UIO_TCP, false);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_IDLE);

    uint8_t appdata[] = {0x17, 0x01, 0x01, 0x00, 0x02, 0x01, 0x01};
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len),
        EOK);

    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_ALERTING);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_CM_LINK_FATAL_ALERTED);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_ALERTED);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(frameMsg.recType.data, REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC005
* @title After the connection is established, the client receives the serverhello message after receiving the app data.
*        The client is expected to return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. The client initiates a TLS conncetion request. After the handshake succeeds, constructs a serverhello
*            message and sends it to the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, HITLS_VERSION_TLCP_DTLCP11, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    /* Reassembly */
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_BAD_RECORD_MAC);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgHeader(&frameType, sndBuf, sndLen, &frameMsg, &parseLen), 0);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);

EXIT:
    CleanRecordBody(&recvframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC006
* @title After the link is established, renegotiation is not enabled. The server receives the client keyexchange message
*        and is expected to return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. After the client initiates a TLS link request. After the handshake succeeds, construct a clientkeyexchange
*            message and send it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The server sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);

    uint8_t data[5] = {0x10, 0x00, 0x00, 0x01, 0x01};
    ASSERT_EQ(REC_Write(client->ssl, REC_TYPE_HANDSHAKE, data, sizeof(data)), HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    CleanRecordBody(&recvframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC007
* @title After initialization, construct an app message and send it to the server. Expected alert is returned.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. When the client initiates a TLS link application request in the RECV_CLIENT_HELLO message on the server,
*            construct an APP message and send it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The server sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_RECORDTYPE_TC007(void)
{
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HandshakeTestInfo testInfo = { 0 };

    FRAME_Init();
    testInfo.config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.client = FRAME_CreateTLCPLink(testInfo.config, BSL_UIO_TCP, true);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateTLCPLink(testInfo.config, BSL_UIO_TCP, false);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0x17, 0x01, 0x01, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len),
        EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(frameMsg.recType.data, REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC01
* @spec   Record layer protocols include: handshake, alarm, and password specification change.
*         To support protocol extensions, the record layer protocol may support other record types.
*         Any new record types should be deassigned in addition to the Content Type values assigned for the types
*         described above.
*         If an unrecognized record type is received, ignore it.
* @title  There are only four types of record layers.
* @precon nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. When the client is in TRY_RECV_SERVER_HELLO state，receives the serverhello message whose recordType is 99，
*            Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC01(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

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

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.msg[0] = 0x99u;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
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
* @test   UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC02
* @spec   Record layer protocols include: handshake, alarm, and password specification change.
*         To support protocol extensions, the record layer protocol may support other record types.
*         Any new record types should be de-assigned in addition to the Content Type values assigned for the types
*         described above.
*         If an unrecognized record type is received, ignore it.
* @title  There are only four types of record layers.
* @precon nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. After the connection is established, the client receives abnormal messages (recordType: 99) after receiving
*            the app data. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC02(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

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

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint8_t dataBuf[] = "Hello World!";
    uint8_t readBuf[READ_BUF_SIZE];
    uint32_t readbytes;
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(server->ssl, dataBuf, sizeof(dataBuf), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.msg[0] = 0x99u;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readbytes), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(client->ssl, &info);
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
* @test   UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC03
* @spec   Record layer protocols include: handshake, alarm, and password specification change.
*         To support protocol extensions, the record layer protocol may support other record types.
*         Any new record types should be deassigned in addition to the Content Type values assigned for the types
*         described above.
*         If an unrecognized record type is received, ignore it.
* @title  There are only four types of record layers.
* @precon nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. When the server is in TRY_RECV_CLIENT_HELLO state, the server receives the client hello message whose
*            recordType is 99. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The server sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC03(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

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

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.msg[0] = 0x99u;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
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
* @test   UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC04
* @spec   Record layer protocols include: handshake, alarm, and password specification change.
*         To support protocol extensions, the record layer protocol may support other record types.
*         Any new record types should be deassigned in addition to the Content Type values assigned for the types
*         described above.
*         If an unrecognized record type is received, ignore it.
* @title  There are only four types of record layers.
* @precon nan
* @brief  1. Use the default configuration on the client and server. Expected result 1.
*         2. After the connection is established, the server receives abnormal messages (recordType: 99) after receiving
*            the app data. Expected result 2.
* @expect 1. The initialization is successful.
*         2. The server sends the ALERT_UNEXPECTED_MESSAGE message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNKNOW_RECORDTYPE_TC04(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

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

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint8_t dataBuf[] = "Hello World!";
    uint8_t readBuf[READ_BUF_SIZE];
    uint32_t readbytes;
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(client->ssl, dataBuf, sizeof(dataBuf), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.msg[0] = 0x99u;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readbytes), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
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
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC001
* @title  An unexpected message is received when the client is in the TRY_RECV_CERTIFICATIONATE state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in the TRY_RECV_CERTIFICATIONATE state, construct a Server Hello message and send it to
*            the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT. The level is ALERT_LEVEL_FATAL and
*            the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC001(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE), HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(client->io);
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
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC002
* @title  An unexpected message is received when the client is in the TRY_RECV_SERVER_KEY_EXCHANGE state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in the TRY_RECV_SERVER_KEY_EXCHANGE state, construct a Server Hello message and send it
*            to the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message. The level is ALERT_Level_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC002(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE), HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(client->io);
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
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC003
* @title  An unexpected message is received when the client is in the TRY_RECV_SERVER_HELLO_DONE state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in the TRY_RECV_SERVER_HELLO_DONE state, construct a Server Hello message and send it to
*            the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message. The level is ALERT_LEVEL_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC003(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO_DONE), HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(client->io);
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
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC004
* @title  An unexpected message is received when the client is in the TRY_RECV_FINISH state during the handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in the TRY_RECV_FINISH state, construct a Server Hello message and send it to the client
             Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message. The level is ALERT_LEVEL_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC004(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLCPConfig();
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg,
                    MAX_RECORD_LENTH,
                    ioUserData->recMsg.msg + REC_TLS_RECORD_HEADER_LEN,
                    ioUserData->recMsg.len - REC_TLS_RECORD_HEADER_LEN) == EOK);
    sndMsg.len = ioUserData->recMsg.len - REC_TLS_RECORD_HEADER_LEN;
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    REC_Write(server->ssl, REC_TYPE_HANDSHAKE, sndMsg.msg, sndMsg.len);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC005
* @title  An unexpected message is received when the client is in the TRY_RECV_CERTIFICATE_REQUEST state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in the TRY_RECV_CERTIFICATE_REQUEST state, construct a Server Hello message and send it
             to the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message. The level is ALERT_LEVEL_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC005(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_REQUEST), HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(client->io);
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
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC006
* @title  An unexpected message is received when the client is in the TRY_RECV_NEW_SESSION_TICKET state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in the TRY_RECV_NEW_SESSION_TICKET state, construct a Server Hello message and send it
*            to the client. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message. The level is ALERT_LEVEL_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC006(int version)
{
    FRAME_Init();
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    client->ssl->hsCtx->state = TRY_RECV_NEW_SESSION_TICKET;

    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC007
* @title  An unexpected message is received when the server is in the TRY_RECV_CLIENT_HELLO state during the handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. When the server is in the TRY_RECV_CLIENT_HELLO state, construct a CLIENT_KEY_EXCHANGE message and send it
*            to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*            ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC007(int version)
{
    FRAME_Init();
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    server->ssl->hsCtx->state = TRY_RECV_CLIENT_HELLO;

    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC008
* @title  An unexpected message is received when the server is in the TRY_RECV_CERTIFICATIONATE state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the server is in the TRY_RECV_CERTIFICATIONATE state, construct a CLIENT_KEY_EXCHANGE message and send
*            it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*            ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC008(int version)
{
    FRAME_Init();
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    server->ssl->hsCtx->state = TRY_RECV_CERTIFICATE;

    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC009
* @title  An unexpected message is received when the server is in the TRY_RECV_CLIENT_KEY_EXCHANGE state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the server is in the TRY_RECV_CLIENT_KEY_EXCHANGE state, construct a SERVER_HELLO message and send it
*            to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the SERVER_HELLO message, the server sends an ALERT message. The level is ALERT_Level_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC009(int version)
{
    FRAME_Init();
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    server->ssl->hsCtx->state = TRY_RECV_CLIENT_KEY_EXCHANGE;

    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}

/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC010
* @title  An unexpected message is received when the server is in the TRY_RECV_CERTIFICATIONATE_VERIFY state during the
*         handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the server is in the TRY_RECV_CERTIFICATIONATE_VERIFY state, construct a CLIENT_KEY_EXCHANGE message
*            and send it to the server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*            ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC010(int version)
{
    FRAME_Init();
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    server->ssl->hsCtx->state = TRY_RECV_CERTIFICATE_VERIFY;

    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC011
* @title  An unexpected message is received when the server is in the TRY_RECV_FINISH state during the handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the server is in the TRY_RECV_FINISH state, construct a CLIENT_KEY_EXCHANGE message and send it to the
             server. Expected result 2.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*            ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC011(int version)
{
    FRAME_Init();
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    server->ssl->hsCtx->state = TRY_RECV_FINISH;

    uint32_t parseLen = 0;
    frameType.versionType = version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);


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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC012
* @title  An unexpected message is received when the client is in the TRY_RECV_SERVER_HELLO state during the handshake.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. When the client is in the TRY_RECV_SERVER_HELLO state, construct a Server Hello Done message and send it to
*            the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello Done message, the client sends an ALERT. The level is ALERT_Level_FATAL
*            and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_UNEXPECT_HANDSHAKEMSG_TC012(int version)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    config->emsMode = HITLS_EMS_MODE_FORCE;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = true;
    config->isSupportRenegotiation = true;
    client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    FRAME_Msg parsedSHdone = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, version, REC_TYPE_HANDSHAKE, SERVER_HELLO_DONE, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &parsedSHdone) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSHdone, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &parsedSHdone);

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &parsedSHdone, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(parsedSHdone.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedSHdone.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &parsedSHdone);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC001
* @title  The client sends a Client Certificate message with the length of 2 ^ 14 + 1 bytes.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. The client initiates a connection creation request. When the client needs to send the Client Certificate
*            message, the two fields are modified as follows:
*            Certificates Length is 2 ^ 14 + 1
*            Certificates are changed to 2 ^ 14 + 1 bytes buffer.
*            After the modification is complete, send the message to the server. Expected result 2.
*         3. When the server receives the Client Certificate message, check the value returned by the HITLS_Accept
*            interface. Expected result 3.
* @expect 1. The initialization is successful.
*         2. The field is successfully modified and sent to the client.
*         3. The value returned by the HITLS_Accept interface is HITLS_REC_RECORD_OVERFLOW.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC001(void)
{
    HandshakeTestInfo testInfo = {0};

    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.certificate.certItem->cert.data);
    frameMsg.body.hsMsg.body.certificate.certItem->cert.data = certDataTemp;
    frameMsg.body.hsMsg.body.certificate.certItem->cert.size = BUF_TOOLONG_LEN;
    frameMsg.body.hsMsg.body.certificate.certItem->cert.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.certificate.certItem->certLen.data = BUF_TOOLONG_LEN;
    frameMsg.body.hsMsg.body.certificate.certItem->certLen.state = ASSIGNED_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_RECORD_OVERFLOW);

    ASSERT_TRUE(testInfo.server->ssl->hsCtx->state == TRY_RECV_CERTIFICATE);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC002
* @title  The server sends a Server Certificate message with the length of 2 ^ 14 + 1 bytes.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. The client initiates a connection creation request. When the server needs to send a Server Certificate
*            message, the two fields are modified as follows:
*            Certificates Length is 2 ^ 14 + 1
*            Certificates are changed to 2 ^ 14 + 1 bytes buffer.
*            After the modification is complete, send the modification to the server. Expected result 2.
*         3. When the client receives the Server Certificate message, check the value returned by the HITLS_Connect
*            interface. Expected result 3.
* @expect 1. The initialization is successful.
*         2. The field is successfully modified and sent to the client.
*         3. The value returned by the HITLS_Connect interface is HITLS_REC_RECORD_OVERFLOW.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC002(void)
{
    HandshakeTestInfo testInfo = {0};

    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.certificate.certItem->cert.data);
    frameMsg.body.hsMsg.body.certificate.certItem->cert.data = certDataTemp;
    frameMsg.body.hsMsg.body.certificate.certItem->cert.size = BUF_TOOLONG_LEN;
    frameMsg.body.hsMsg.body.certificate.certItem->cert.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.certificate.certItem->certLen.data = BUF_TOOLONG_LEN;
    frameMsg.body.hsMsg.body.certificate.certItem->certLen.state = ASSIGNED_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_RECORD_OVERFLOW);

    ASSERT_TRUE(testInfo.client->ssl->hsCtx->state == TRY_RECV_CERTIFICATE);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC003
* @title  The client sends a Change Cipher Spec message with the length of 2 ^ 14 + 1 bytes.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. The client initiates a link creation request. When the client needs to send a Change Cipher Spec message,
*            modify one field as follows: Length is 2 ^ 14 + 1. After the modification, the modification is sent to the
*            server. Expected result 2 is obtained.
*         3. When the server receives the Change Cipher Spec message, check the value returned by the HITLS_Accept
*            interface. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
*         2. The field is successfully modified and sent to the server.
*         3. The value returned by the HITLS_Accept interface is HITLS_REC_RECORD_OVERFLOW.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC003(void)
{
    HandshakeTestInfo testInfo = {0};

    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg.body.ccsMsg.extra.data);
    frameMsg.body.ccsMsg.extra.data = certDataTemp;
    frameMsg.body.ccsMsg.extra.size = BUF_TOOLONG_LEN;
    frameMsg.body.ccsMsg.extra.state = ASSIGNED_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_RECORD_OVERFLOW);

    ASSERT_TRUE(testInfo.server->ssl->hsCtx->state == TRY_RECV_CERTIFICATE_VERIFY);
    bool isCcsRecv = testInfo.server->ssl->method.isRecvCCS(testInfo.server->ssl);
    ASSERT_TRUE(isCcsRecv == false);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC004
* @title  The server sends a Change Cipher Spec message with the length of 2 ^ 14 + 1 bytes.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. The server initiates a link creation request. When the server needs to send a Change Cipher Spec message,
*            modify one field as follows: Length is 2 ^ 14 + 1. After the modification, the modification is sent to the
*            server. Expected result 2.
*         3. When the client receives the Change Cipher Spec message, check the value returned by the HITLS_Accept
*            interface. Expected result 3.
* @expect 1. The initialization is successful.
*         2. The field is successfully modified and sent to the client.
*         3. The value returned by the HITLS_Accept interface is HITLS_REC_RECORD_OVERFLOW.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_MSGLENGTH_TOOLONG_TC004(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    frameType1.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType1.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType1, &frameMsg1) == HITLS_SUCCESS);

    uint8_t *certDataTemp = (uint8_t *)BSL_SAL_Calloc(1, (uint32_t)BUF_TOOLONG_LEN);
    ASSERT_TRUE(certDataTemp != NULL);
    BSL_SAL_FREE(frameMsg1.body.ccsMsg.extra.data);
    frameMsg1.body.ccsMsg.extra.data = certDataTemp;
    frameMsg1.body.ccsMsg.extra.size = BUF_TOOLONG_LEN;
    frameMsg1.body.ccsMsg.extra.state = ASSIGNED_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType1, &frameMsg1, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData1->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);

    FRAME_CleanMsg(&frameType1, &frameMsg1);
    memset_s(&frameMsg1, sizeof(frameMsg1), 0, sizeof(frameMsg1));

    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_RECORD_OVERFLOW);

EXIT:
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test   UT_TLS_TLCP_CONSISTENCY_CIPHERTEXT_TOOLONG_TC001
* @title  A too long cipher text app message is sent by client or server.
* @precon nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1.
*         2. When the client is in transporting state, the server sends a message whose ciphertext length is 2 ^ 14 +
*            2048. Expected result 2.
*         3. When the server is in transporting state, the client sends a message whose ciphertext length is 2 ^ 14 +
*            2048. Expected result 3.
*         4. When the server is in transporting state, the client sends a message whose ciphertext length is 2 ^ 14 +
*            2049. Expected result 4.
*         5. When the client is in transporting state, the server sends a message whose ciphertext length is 2 ^ 14 +
*            2049. Expected result 5.
* @expect 1. The initialization is successful.
*         2. The message can be decrypted.
*         3. The message can be decrypted.
*         4. The server send an alert message.
*         5. The client send an alert message.
@ */

/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_CIPHERTEXT_TOOLONG_TC001(int isClient, int ptLen, int ctLen)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, true);
    FRAME_LinkObj *server = FRAME_CreateTLCPLink(config, BSL_UIO_TCP, false);
    FRAME_LinkObj *sender = NULL;
    FRAME_LinkObj *receiver = NULL;
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    if (isClient) {
        sender = client;
        receiver = server;
    } else {
        sender = server;
        receiver = client;
    }

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);

    uint8_t readBuf[MAX_BUF_LEN] = {0};
    uint32_t readLen = 0;

    uint8_t sendBuf[MAX_BUF_LEN] = {0};
    (void)memset_s(sendBuf + 5, REC_MAX_CIPHER_TEXT_LEN + 1, 9, REC_MAX_CIPHER_TEXT_LEN + 1);
    RecBufFree(sender->ssl->recCtx->outBuf);
    sender->ssl->recCtx->outBuf = RecBufNew(MAX_BUF_LEN);
    RecBufFree(receiver->ssl->recCtx->inBuf);
    receiver->ssl->recCtx->inBuf = RecBufNew(MAX_BUF_LEN);

    ASSERT_EQ(TlsRecordWrite(sender->ssl, REC_TYPE_APP, sendBuf, ptLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(sender, receiver), HITLS_SUCCESS);
    STUB_REPLACE(TlsRecordRead, STUB_TlsRecordRead);
#ifdef HITLS_TLS_FEATURE_RECORD_SIZE_LIMIT
    int32_t ret = ctLen > 16709 ? HITLS_REC_RECORD_OVERFLOW : HITLS_SUCCESS;
    ASSERT_EQ(TlsRecordRead(receiver->ssl, REC_TYPE_APP, readBuf, &readLen, ctLen), ret);
#else
    int32_t ret = ctLen > 18432 ? HITLS_REC_RECORD_OVERFLOW : HITLS_SUCCESS;
    ASSERT_EQ(TlsRecordRead(receiver->ssl, REC_TYPE_APP, readBuf, &readLen, ctLen), ret);
#endif
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(sender);
    FRAME_FreeLink(receiver);
    STUB_RESTORE(TlsRecordRead);
}
/* END_CASE */

/* @
 * @test   UT_TLS_TLCP_CONSISTENCY_NONZERO_MESSAGELEN_TC001
 * @title  Test the scenario where the message parameter is unacceptable.
 * @precon nan
 * @spec   1. After receiving the servehellodone message from the server, the client verifies whether the server
 *            certificate is valid and the servehello message from the server. Indicates whether the message parameter
 *            is acceptable. If acceptable, the client continues the handshake process. Otherwise, a HandShakeFailure
 *            critical alarm is sent.
 * @brief  1. After receiving the servehellodone message from the server, the client verifies whether the server
 *            certificate is valid and the servehello message from the server. Expected result 1.
 * @expect 1. During the first connection setup, the client receives a servehellodone message from the server. The
 *            message length is not 0. The expected handshake fails.
 @ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_NONZERO_MESSAGELEN_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    int32_t ret;
    ret = FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO_DONE);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO_DONE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloDoneMsg *serverHelloDone = &frameMsg.body.hsMsg.body.serverHelloDone;
    uint8_t extra[1] = {0};
    FRAME_ModifyMsgArray8(extra, 1, &serverHelloDone->extra, NULL);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_PARSE_EXCESSIVE_MESSAGE_SIZE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_SEQ_NUM_TC001
* @title  Check whether the sequence number of the read/write status in the FINISH message sent by the server/client is
          1.
* @precon  nan
* @brief  1. Configure the client/server to stay in the TRY_SEND_FINISH state. Expected result 1.
*         2. Connect the server and client once and send the message. Expected result 2.
          3. Obtain the messages sent by the server or client. Expected result 3.
          4. Parse the message sent by the local end into the hs_msg structure. Expected result 4.
          5. Check the sequence number in the sent message. Expected result 5.
          6. Enable the local end to transmit data to the peer end. Expected result 6.
          7. Obtain the messages received by the peer end. Expected result 7.
          8. Parse the message received by the peer end into the hs_msg structure. Expected result 8.
          9. Check the sequence number in the received message. Expected result 9.
* @expect 1. The initialization is successful.
*         2. If the server is successfully connected, the client returns NORMAL_RECV_BUF_EMPTY.
          3. The sending length is not null.
          4. The parsing is successful and the message header length is fixed to 5 bytes.
          5. The serial number is 1.
          6. The transmission is successful.
          7. The received length is not empty.
          8. The parsing succeeds and the message header length is fixed to 5 bytes.
          9. The serial number is 1.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_SEQ_NUM_TC001(int isClient)
{
    HandshakeTestInfo testInfo = { 0 };
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isClient = isClient;
    // Error stack exists
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    if (isClient) {
        ASSERT_TRUE(HITLS_Connect(testInfo.client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    } else {
        ASSERT_TRUE(HITLS_Accept(testInfo.server->ssl) == HITLS_SUCCESS);
    }

    HITLS_Ctx *localSsl = isClient ? testInfo.client->ssl : testInfo.server->ssl;
    ASSERT_TRUE(localSsl->recCtx->writeStates.currentState->seq == 1);

    if (isClient) {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    }

    HITLS_Ctx *remoteSsl = isClient ? testInfo.server->ssl : testInfo.client->ssl;
    if (!isClient) {
        ASSERT_TRUE(HITLS_Connect(testInfo.client->ssl) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(HITLS_Accept(testInfo.server->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    }
    ASSERT_TRUE(remoteSsl->recCtx->readStates.currentState->seq == 1);

    ASSERT_TRUE(TestIsErrStackNotEmpty());
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_SEQ_NUM_TC002
* @title  Check whether the sequence number of the read/write sequence in the APP message sent by the server/client is
          2.
* @precon  nan
* @brief  1. Configure the status of the client/server to the successful handshake. Expected result 1.
*         2. Check the server/client connection status. Expected result 2.
          3. Randomly generate 32-byte data. Expected result 3.
          4. Write app data. Expected result 4.
          5. Obtain data from the I/O sent by the local end and parse the header and content. Expected result 5.
          6. Check the sequence number in the sent message. Expected result 6.
          7. Perform I/O data transmission from the local end to the peer end. Expected result 7.
          8. Obtain data from the received I/O from the peer end and parse the header and content. Expected result 8.
          9. Check the sequence number in the received message. Expected result 9.
* @expect 1. The initialization is successful.
*         2. The link status is Transferring.
          3. The generation is successful.
          4. The writing is successful.
          5. The parsing is successful and the value of RecordType is REC_TYPE_APP.
          6. The SN is 2.
          7. The transmission is successful.
          8. The parsing is successful and the value of RecordType is REC_TYPE_APP.
          9. The SN is 2.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_SEQ_NUM_TC002(int isClient)
{
    HandshakeTestInfo testInfo = { 0 };
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.state = HS_STATE_BUTT;
    testInfo.isClient = isClient;
    // Error stack exists
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_TRANSPORTING);

    uint8_t transportData[REC_CONN_SEQ_SIZE * 4] = {0};
    uint32_t transportDataLen = sizeof(transportData) / sizeof(uint8_t);
    ASSERT_EQ(RandBytes(transportData, transportDataLen), HITLS_SUCCESS);
    HITLS_Ctx *localSsl = isClient ? testInfo.client->ssl : testInfo.server->ssl;
    uint32_t writeLen;
    ASSERT_EQ(APP_Write(localSsl, transportData, transportDataLen, &writeLen), HITLS_SUCCESS);

    ASSERT_EQ(localSsl->recCtx->writeStates.currentState->seq , 2);

    if (isClient) {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    }

    HITLS_Ctx *remoteSsl = isClient ? testInfo.server->ssl : testInfo.client->ssl;
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(APP_Read(remoteSsl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(remoteSsl->recCtx->readStates.currentState->seq , 2);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC001
* @title  The client supports tlcp, and the server supports tls_all. Establish a connection and
        expect successful chain building.
* @precon  nan
* @brief  1. Set the server version to tls_all and the client version to tlcp, and create config. Expected result 1.
*         2. Establish a connection. Expected result 2.
* @expect 1. The initialization is successful.
*         2. Successfully established connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC001()
{
    FRAME_Init();
    HITLS_Config *config_s = NULL;
    HITLS_Config *config_c = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config_c = HITLS_CFG_NewTLCPConfig();
    config_s = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    config_c->emsMode = HITLS_EMS_MODE_FORCE;
    config_s->emsMode = HITLS_EMS_MODE_FORCE;
    config_s->isSupportClientVerify = true;
    client = FRAME_CreateTLCPLink(config_c, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config_s, BSL_UIO_TCP, false);
    // Error stack exists
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC002
* @title  The client supports tlcp with HITLS-ECC_SM4_CBC_SM3 cipher suite, while the server supports tls_all version
        but disables tlcp version. The connection is established and expected to fail.
* @precon  nan
* @brief  1. Set the server version to tls_all and the client version to tlcp, and create config. Expected result 1.
*         2. Server setting to disable tlcp version。Expected result 2.
*         3. Establish a connection. Expected result 3.
* @expect 1. The initialization is successful.
*         2. Setup successful.
*         3. Failed to establish connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC002()
{
    FRAME_Init();
    HITLS_Config *config_s = NULL;
    HITLS_Config *config_c = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config_c = HITLS_CFG_NewTLCPConfig();
    config_s = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    config_s->isSupportClientVerify = true;
    HITLS_CFG_SetVersionForbid(config_s, TLCP11_VERSION_BIT);
    client = FRAME_CreateTLCPLink(config_c, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config_s, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC003
* @title  The client supports tls_all, the server supports tlcp, establishes a connection, and expects the
        connection to fail.
* @precon  nan
* @brief  1. Set the server version to tlcp and the client version to tls_all, and create config. Expected result 1.
*         2. Establish a connection. Expected result 2.
* @expect 1. The initialization is successful.
*         2. Failed to establish connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLCP_CONSISTENCY_SERVER_TLS_ALL_TC003()
{
    FRAME_Init();
    HITLS_Config *config_s = NULL;
    HITLS_Config *config_c = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    config_c = HITLS_CFG_NewTLSConfig();
    config_s = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    client = FRAME_CreateTLCPLink(config_c, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(config_s, BSL_UIO_TCP, false);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_HITLS_TLCP_PATCH_TC003
* @title  In the case of tls_all, only the tlcp version remains enabled for the client. When attempting to establish a
*           connection with the tlcp server, the connection is expected to fail.
* @precon  nan
* @brief  1. The client is configured with tls_all version, while the server is initialized with the tlcp version
*           configuration. Expected result 1.
*         2. The client disables all versions except for the tlcp version. Expected result 2.
*         3. Establish a link. Expected result 3.
* @expect 1. The initialization is successful.
*         2. Set successfully.
*         3. The connection fails to be established and the client returns HITLS_MSG_HANDLE_UNSUPPORT_VERSION.
@ */
/* BEGIN_CASE */
void SDV_HITLS_TLCP_PATCH_TC003()
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(s_config != NULL);

    HITLS_CFG_SetVersionForbid(
        c_config, SSLV3_VERSION_BIT | TLS10_VERSION_BIT | TLS11_VERSION_BIT | TLS12_VERSION_BIT | TLS13_VERSION_BIT);
    ASSERT_EQ(c_config->minVersion, 0x0101);
    ASSERT_EQ(c_config->maxVersion, 0x0101);
    FRAME_LinkObj *client = FRAME_CreateTLCPLink(c_config, BSL_UIO_TCP, true);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateTLCPLink(s_config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */