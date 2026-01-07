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
/* INCLUDE_BASE test_suite_sdv_frame_dtlcp_consistency */
/* END_HEADER */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC001
* @spec -
* @titleThe client receives a FINISH message and the CCS message is out of order.
* @precon nan
* @brief 1. Initialize the client and server based on the default configuration. Expected result 1.
* 2. The client initiates a connection request and constructs the scenario where the FINISH message and CCS message are out of order. That is, the client processes the FINISH message and then processes the CCS message. After the processing, the client continues to establish a connection. Expected result 2 is displayed.
* @expect 1: The initialization is successful.
* 2: The client waits to receive the FINISH message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderServerFinished(testInfo.server, data, len, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, data, len) == HITLS_SUCCESS);
    (void)HITLS_Connect(testInfo.client->ssl);
    ASSERT_EQ(testInfo.client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC002
* @spec -
* @titleThe server receives a FINISH message and the CCS message is out of order.
* @precon nan
* @brief 1. Initialize the client and server based on the default configuration. Expected result 1.
* 2. The client initiates a connection request and constructs the scenario where the FINISH message and CCS message are out of order. 
That is, the server processes the FINISH message and then processes the CCS message. After the processing, the server continues to 
establish a connection. Expected result 2 is displayed.
* @expect 1: The initialization is successful.
* 2: The server is waiting to receive the FINISH message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC002(void)
{
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = TRY_SEND_CLIENT_KEY_EXCHANGE;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderClientFinished1(testInfo.client, data, len, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, data, len) == HITLS_SUCCESS);
    (void)HITLS_Accept(testInfo.server->ssl);
    ASSERT_EQ(testInfo.server->ssl->state, CM_STATE_HANDSHAKING);
    ASSERT_EQ(testInfo.server->ssl->hsCtx->state, TRY_SEND_CHANGE_CIPHER_SPEC);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC003
* @spec -
* @titleThe client receives a FINISH message and the APP message is out of order.
* @precon nan
* @brief 1. Initialize the client and server using the default configuration. Expected result 1.
* 2. The client initiates a connection request and constructs the scenario where the FINISH message and APP message are out of order. That is, the client processes the APP message first, processes the FINISH message, and then continues to establish a connection. Expected result 2.
* @expect 1: Initialization succeeded.
* 2: The connection between the client and server is successfully established.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_FINISH_TC003(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderServerFinish_AppData(testInfo.server, data, len, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, data, len) == HITLS_SUCCESS);
    (void)HITLS_Connect(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(HITLS_Read(testInfo.client->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_DISORDER_TC001
* @spec -
* @titleThe server receives out-of-order APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection application by using DTLCP. Expected result 2.
* 3. Construct an app message whose SN is 2 and send it to the server. When the server invokes HiTLS_Read, expected result 3.
* 4. Construct an app message whose SN is 1 and send it to the server. When the server invokes HiTLS_Read, expected result 4.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLCP connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_DISORDER_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo), HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderApp(testInfo.client, data, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, data, len) == HITLS_SUCCESS);
    uint8_t app1Data[MAX_RECORD_LENTH] = {0};
    uint32_t app1Len = MAX_RECORD_LENTH;
    ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, app1Data, MAX_RECORD_LENTH, &app1Len) == HITLS_SUCCESS);
    uint8_t app2Data[MAX_RECORD_LENTH] = {0};
    uint32_t app2Len = MAX_RECORD_LENTH;
    ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, app2Data, MAX_RECORD_LENTH, &app2Len) == HITLS_SUCCESS);
    ASSERT_EQ(app1Len, app2Len);
    ASSERT_EQ(memcmp(app1Data, app2Data, app2Len), 0);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_DISORDER_TC002
* @spec -
* @titleThe client receives out-of-order APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection request using DTLCP. Expected result 2.
* 3. Construct an app message whose sequence number is 2 and send it to the client. When the client invokes HiTLS_Read, expected result 3.
* 4. Construct an app message whose sequence number is 1 and send it to the client. When the client invokes HiTLS_Read, expected result 4.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLCP connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_DISORDER_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo), HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderApp(testInfo.server, data, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, data, len) == HITLS_SUCCESS);
    uint8_t app1Data[MAX_RECORD_LENTH] = {0};
    uint32_t app1Len = MAX_RECORD_LENTH;
    ASSERT_TRUE(HITLS_Read(testInfo.client->ssl, app1Data, MAX_RECORD_LENTH, &app1Len) == HITLS_SUCCESS);
    uint8_t app2Data[MAX_RECORD_LENTH] = {0};
    uint32_t app2Len = MAX_RECORD_LENTH;
    ASSERT_TRUE(HITLS_Read(testInfo.client->ssl, app2Data, MAX_RECORD_LENTH, &app2Len) == HITLS_SUCCESS);
    ASSERT_EQ(app1Len, app2Len);
    ASSERT_EQ(memcmp(app1Data, app2Data, app1Len), 0);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_APPDATA_TC001
* @spec -
* @title The server receives duplicate APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection application by using DTLCP. Expected result 2.
* 3. Construct an app message whose SN is 1 and send it to the server. When the server invokes HiTLS_Read, expected result 3.
* 4. Construct the app message whose SN is 1 and send it to the server. When the server invokes HiTLS_Read, expected result 4.
* 5. The server constructs data and sends it to the client. When the client invokes HiTLS_Read, expected result 5.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLCP connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* 5: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_APPDATA_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo), HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetRepeatsApp(testInfo.client, data, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t writeData[] = {"abcd1234"};
    uint32_t writeLen = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    uint8_t tmpData[MAX_RECORD_LENTH];
    uint32_t tmpLen;
    uint32_t sendNum;
    ASSERT_TRUE(HITLS_Write(testInfo.server->ssl, writeData, writeLen, &sendNum) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportSendMsg(testInfo.server->io, tmpData, MAX_RECORD_LENTH, &tmpLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, tmpData, tmpLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readData, MAX_RECORD_LENTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, writeLen);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_APPDATA_TC002
* @spec -
* @titleThe client receives duplicate APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection application by using DTLCP. Expected result 2.
* 3. Construct an app message whose sequence number is 1 and send the message to the client. When the client invokes HiTLS_Read, expected result 3.
* 4. Construct an app message with the sequence number being 1 and send it to the client. When the client invokes HiTLS_Read, expected result 4.
* 5. The server constructs data and sends it to the client. When the client invokes HiTLS_Read, expected result 5.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLCP connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* 5: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_APPDATA_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo), HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetRepeatsApp(testInfo.server, data, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Read(testInfo.client->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, data, MAX_RECORD_LENTH, &len), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t writeData[] = {"abcd1234"};
    uint32_t writeLen = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    uint8_t tmpData[MAX_RECORD_LENTH];
    uint32_t tmpLen;
    uint32_t sendNum;
    ASSERT_TRUE(HITLS_Write(testInfo.server->ssl, writeData, writeLen, &sendNum) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportSendMsg(testInfo.server->io, tmpData, MAX_RECORD_LENTH, &tmpLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, tmpData, tmpLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readData, MAX_RECORD_LENTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, writeLen);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_CLIENT_HELLO_TC001
* @spec -
* @title The server receives a Client Hello packet after the connection is established.
* @precon nan
* @brief 1. Initialize the client and server based on the default configuration. Expected result 1.
* 2. The client initiates a connection request. Expected result 2.
* 3. Construct a Client Hello packet and send it to the server. The server invokes HiTLS_Read to receive the packet. Expected result 3.
* 4. The client invokes HiTLS_Write to send data to the server, and the server invokes HiTLS_Read to read data. (Expected result 4)
* @expect 1: Initialization succeeded.
* 2: The connection between the client and server is successfully established.
* 3: The HiTLS_Read returns an error code, indicating that the receiving buffer is empty.
* 4: The data read by the server is consistent with the data sent by the client.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_CLIENT_HELLO_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isClient = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo), HITLS_SUCCESS);
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ASSERT_TRUE(REC_Write(testInfo.client->ssl, REC_TYPE_HANDSHAKE,
        &sendBuf[REC_DTLS_RECORD_HEADER_LEN], sendLen - REC_DTLS_RECORD_HEADER_LEN) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t writeData[] = {"abcd1234"};
    uint32_t writeLen = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    uint8_t tmpData[MAX_RECORD_LENTH];
    uint32_t tmpLen;
    uint32_t sendNum;
    ASSERT_EQ(HITLS_Write(testInfo.client->ssl, writeData, writeLen, &sendNum), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportSendMsg(testInfo.client->io, tmpData, MAX_RECORD_LENTH, &tmpLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, tmpData, tmpLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readData, MAX_RECORD_LENTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, writeLen);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC8422_ECPOINT_TC001
* @spec -
* @titleThe client receives an abnormal dot format field.
* @precon nan
* @brief 1. The client and server use the default initialization. Expected result 1.
* 2. The client initiates a connection request. When the client wants to read the Server Hello message,
* Modify the Elliptic curves point formats field, change the group supported by the field to 0x01, and send the field to the client. Expected result 2.
* @expect 1. Initialization succeeded.
* 2. The client sends a FATAL ALERT with the description of ALERT_ELLEGAL_PARAMETER.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC8422_ECPOINT_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    uint8_t Gdata[] = { 0x01 };
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->pointFormats.exState = INITIAL_FIELD;
    ASSERT_TRUE(FRAME_ModifyMsgInteger(HS_EX_TYPE_POINT_FORMATS, &(serverMsg->pointFormats.exType)) == HITLS_SUCCESS);
    serverMsg->pointFormats.exLen.state = INITIAL_FIELD;
    ASSERT_TRUE(FRAME_ModifyMsgArray8(Gdata, sizeof(Gdata)/sizeof(uint8_t),
        &(serverMsg->pointFormats.exData), &(serverMsg->pointFormats.exDataLen)) == HITLS_SUCCESS);
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_UNSUPPORT_POINT_FORMAT);
    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC8422_EXTENSION_MISS_TC001
* @spec -
* @title The server receives a Client Hello packet that does not carry the group or dot format.
* @precon nan
* @brief 1. Configure the HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite on the client and initialize the cipher suite on the server by default. Expected result 1.
* 2. When the client initiates a connection request and the server is about to read ClientHello,
* Delete the supported_groups and ec_point_formats fields from the packet. Expected result 2.
* @expect 1. Initialization succeeded.
* 2. The server sends a Server Hello packet with the HITLS_ECDHE_SM4_CBC_SM3 algorithm suite.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC8422_EXTENSION_MISS_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->supportedGroups.exState = MISSING_FIELD;
    clientMsg->pointFormats.exState = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_HANDSHAKE);
    ASSERT_TRUE(frameMsg.body.hsMsg.type.data == SERVER_HELLO);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(serverMsg->cipherSuite.data, HITLS_ECDHE_SM4_CBC_SM3);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* when receive alert between finish and ccs, dtlcp should cache it*/
/* BEGIN_CASE */
void UT_DTLCP_RFC6347_RECV_ALERT_AFTER_CCS_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_UDP, true);
    FRAME_LinkObj *server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_UDP, false);
    client->needStopBeforeRecvCCS = true;
    server->needStopBeforeRecvCCS = true;
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_SetMtu(client->ssl, 16384);
    HITLS_SetMtu(server->ssl, 16384);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);

    // client receive ccs, wait to receive finish
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t alertdata[2] = {0x02, 0x0a};
    ASSERT_EQ(REC_Write(serverTlsCtx, REC_TYPE_ALERT, alertdata, sizeof(alertdata)), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    // client cache the alert, wait to receive finish
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    // server send finish, handshake success
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    // client receive finish, handshake success
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    // client read cached alert
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTED);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLCP_CONSISTENCY_RFC6347_TC001
* @spec -
* @title The client receives a Hello Request message which msg seq is not 0.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. After the client finished handshake, the client receives a Hello Request message. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client igore the message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLCP_CONSISTENCY_RFC6347_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLCPConfig();
    tlsConfig->isSupportRenegotiation = true;
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_UDP, true);
    FRAME_LinkObj *server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_UDP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_SetMtu(client->ssl, 16384);
    HITLS_SetMtu(server->ssl, 16384);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    uint8_t buf[DTLS_HS_MSG_HEADER_SIZE] = {0u};
    buf[5] = 1;
    size_t len = DTLS_HS_MSG_HEADER_SIZE;
    REC_Write(serverTlsCtx, REC_TYPE_HANDSHAKE, buf, len);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readData, MAX_RECORD_LENTH, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */