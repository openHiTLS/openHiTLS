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
#include "hs_cookie.h"
/* INCLUDE_BASE test_suite_sdv_frame_dtls12_consistency */
/* END_HEADER */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_UNEXPETED_REORD_TYPE_TC001
* @spec -
* @titleThe client and server receive the client Hello message after the connection establishment is complete.
* @precon nan
* @brief
* 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. A DTLS over SCTP connection is established between the client and server. Expected result 2.
* 3. Construct a Client Hello message and send it to the client. Check the client status. Expected result 3.
* 4. Construct a Client Hello message and send it to the server. Check the server status. Expected result 4.
* @expect
* 1. The initialization is successful.
* 2. The connection is set up successfully.
* 3. The client status is CM_STATE_TRANSPORTING.
* 4. The server is in the CM_STATE_TRANSPORTING state.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_UNEXPETED_REORD_TYPE_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = HS_STATE_BUTT;
    testInfo.isClient = false;
    testInfo.isSupportExtendMasterSecret = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    uint8_t data[1024] = {0};
    uint32_t dataSize = 0;
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    HITLS_Read(testInfo.server->ssl, data, sizeof(data), &dataSize);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(dataSize == 0);
    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    dataSize = 0 ;
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    HITLS_Read(testInfo.client->ssl, data, sizeof(data), &dataSize);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(dataSize == 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SEQ_NUMBER_TC001
* @spec -
* @title Check whether the seq number of the record layer complies with the RFC specifications during the handshake.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a connection establishment request. When the client sends a CLIENT_HELLO message, the client checks the sequence number at the Reocrd layer. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The sequence number is 0.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SEQ_NUMBER_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == recvLen);
    ASSERT_TRUE(frameMsg.body.hsMsg.sequence.data == 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SEQ_NUMBER_TC002
* @spec -
* @title Check whether the sequence number of the record layer during the handshake complies with the RFC specification.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The server continuously establishes a connection. After receiving the client Hello message, the server sends a Server Hello message and checks the sequence number at the Record layer. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The sequence number is 0.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SEQ_NUMBER_TC002(int uioType)
{
    RegDefaultMemCallback();
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == recvLen);
    ASSERT_TRUE(frameMsg.body.hsMsg.sequence.data == 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SEQ_NUMBER_TC003
* @spec -
* @title Check whether the sequence number at the record layer complies with the RFC specification during the handshake.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client sends a FINISH message during continuous connection establishment, check whether the sequence number in the record header is. Expected result 2.
3. When the server sends a FINISH message during continuous connection establishment, check the sequence number in the message. Expected result 3.
* @expect 1. The initialization is successful.
* 2. The sequence number is 0.
3. The sequence number is 0.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SEQ_NUMBER_TC003(int uioType)
{
    RegDefaultMemCallback();
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.state = TRY_RECV_FINISH;
    testInfo.isClient = false;
    ASSERT_EQ(DefaultCfgStatusPark(&testInfo, uioType), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == PARSEMSGHEADER_LEN);
    ASSERT_TRUE(frameMsg.body.hsMsg.sequence.data == 0);
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData_1 = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf_1 = ioUserData_1->recMsg.msg;
    uint32_t recvLen_1 = ioUserData_1->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen_1 = 0;
    FRAME_Msg frameMsg_1 = {0};
    FRAME_Type frameType_1 = {0};
    frameType_1.versionType = HITLS_VERSION_DTLS12;
    frameType_1.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType_1.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType_1, recvBuf_1, recvLen_1, &frameMsg_1, &parseLen_1) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen_1 == PARSEMSGHEADER_LEN);
    ASSERT_TRUE(frameMsg_1.body.hsMsg.sequence.data == 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_CleanMsg(&frameType_1, &frameMsg_1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC001
* @spec -
* @titleThe client sends a Client Certificate message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS connection creation request. When the client needs to send a Client Certificate message, the two fields are modified as follows:
Certificates Length is 2 ^ 14 + 1
Certificates are changed to 2 ^ 14 + 1 byte buffer.
After the modification is complete, send the modification to the server. Expected result 2.
3. When the server receives the Client Certificate message, check the value returned by the HITLS_Accept interface. Expected result 3.
* @expect 1. The initialization is successful.
* 2. The field is successfully modified and sent to the client.
3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
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
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC002
* @spec -
* @title The server sends a Server Certificate message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS connection creation request. When the server needs to send a Server Certificate message, the server modifies the following two fields:
Certificates Length is 2 ^ 14 + 1
Certificates are changed to 2 ^ 14 + 1 byte buffer.
After the modification is complete, send the modification to the server. Expected result 2.
3. When the client receives the Server Certificate message, check the value returned by the HITLS_Connect interface. Expected result 3.
* @expect 1. The initialization is successful.
* 2. The field is successfully modified and sent to the client.
3. The return value of the HITLS_Connect interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC002(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
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
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC003
* @spec -
* @titleThe client sends a Change Cipher Spec message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS connection establishment request and sends a Change Cipher Spec message, the client modifies one field as follows:
Length is 2 ^ 14 + 1. After the modification is complete, send the modification to the server. Expected result 2.
3. When the server receives the Change Cipher Spec message, check the value returned by the HITLS_Accept interface. Expected result 3.
* @expect 1. The initialization is successful.
* 2. The field is successfully modified and sent to the client.
3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_TOOLONG_TC003(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType.transportType = uioType;
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
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC001
* @spec -
* @title The server receives a Client Hello message with a length of zero.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request, constructs a Client Hello message with zero length, and sends the message to the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends the ALERT message. The level is ALERT_ LEVEL_FATAL, and the description is ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->extensionState = MISSING_FIELD;
    clientMsg->version.state = MISSING_FIELD;
    clientMsg->randomValue.state = MISSING_FIELD;
    clientMsg->sessionIdSize.state = MISSING_FIELD;
    clientMsg->sessionId.state = MISSING_FIELD;
    clientMsg->cookiedLen.state = MISSING_FIELD;
    clientMsg->cookie.state = MISSING_FIELD;
    clientMsg->cipherSuitesSize.state = MISSING_FIELD;
    clientMsg->cipherSuites.state = MISSING_FIELD;
    clientMsg->compressionMethodsLen.state = MISSING_FIELD;
    clientMsg->compressionMethods.state = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_PARSE_INVALID_MSG_LEN);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_DECODE_ERROR);

EXIT:

    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC002
* @spec -
* @titleThe client receives a Server Hello message with a length of zero.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request. After sending a Client Hello message, the client constructs a zero-length Server Hello message and sends it to the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends an ALERT message with the level of ALERT_Level_FATAL and description of ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->version.state = MISSING_FIELD;
    serverMsg->randomValue.state = MISSING_FIELD;
    serverMsg->sessionIdSize.state = MISSING_FIELD;
    serverMsg->sessionId.state = MISSING_FIELD;
    serverMsg->cipherSuite.state = MISSING_FIELD;
    serverMsg->compressionMethod.state = MISSING_FIELD;
    serverMsg->extensionLen.state = MISSING_FIELD;
    serverMsg->pointFormats.exState = MISSING_FIELD;
    serverMsg->extendedMasterSecret.exState = MISSING_FIELD;
    serverMsg->secRenego.exState = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_INVALID_MSG_LEN);
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
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_DECODE_ERROR);

EXIT:

    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC003
* @spec -
* @titleThe client receives a Certificate message with zero length.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request. After receiving the Server Hello message, the client constructs a zero-length Certificate message and sends it to the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends the ALERT message. The level is ALERT_ LEVEL_FATAL and the description is ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC003(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_CertificateMsg *certifiMsg = &frameMsg.body.hsMsg.body.certificate;
    certifiMsg->certsLen.state = MISSING_FIELD;
    certifiMsg->certItem->state = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_INVALID_MSG_LEN);
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
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_DECODE_ERROR);

EXIT:

    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC004
* @spec -
* @titleThe client receives a Server Key Exchange message whose length is zero.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request. After receiving the Certificate message, the client constructs a Server Key Exchange message with zero length and sends the message to the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends an ALERT message with the level of ALERT_Level_FATAL and description of ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC004(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerKeyExchangeMsg *serverKeyExMsg = &frameMsg.body.hsMsg.body.serverKeyExchange;
    serverKeyExMsg->keyEx.ecdh.curveType.state = MISSING_FIELD;
    serverKeyExMsg->keyEx.ecdh.namedcurve.state = MISSING_FIELD;
    serverKeyExMsg->keyEx.ecdh.pubKeySize.state = MISSING_FIELD;
    serverKeyExMsg->keyEx.ecdh.pubKey.state = MISSING_FIELD;
    serverKeyExMsg->keyEx.ecdh.signAlgorithm.state = MISSING_FIELD;
    serverKeyExMsg->keyEx.ecdh.signSize.state = MISSING_FIELD;
    serverKeyExMsg->keyEx.ecdh.signData.state = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_INVALID_MSG_LEN);
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
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_DECODE_ERROR);

EXIT:

    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC005
* @spec -
* @titleThe server receives a Client Key Exchange message with zero length.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request. After the server sends a Server Hello Done message, the server constructs a Client Key Exchange message with zero length and sends the message to the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends an ALERT message. The level is ALERT_Level_FATAL and the description is ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC005(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientKeyExchangeMsg *clientKeyExMsg = &frameMsg.body.hsMsg.body.clientKeyExchange;
    clientKeyExMsg->pubKey.state = MISSING_FIELD;
    clientKeyExMsg->pubKeySize.state = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_PARSE_INVALID_MSG_LEN);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_DECODE_ERROR);

EXIT:

    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC006
* @spec -
* @title The server receives a Change Cipher Spec message with zero length.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request. After receiving the Client Key Exchange message, the server constructs a Change Cipher Spec message with zero length and sends it to the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server receives the message, which is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC006(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    frameType1.versionType = HITLS_VERSION_DTLS12;
    frameType1.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType1.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType1, &frameMsg1) == HITLS_SUCCESS);
    FRAME_CcsMsg *CcsMidMsg = &frameMsg1.body.ccsMsg;
    CcsMidMsg->ccsType.state = MISSING_FIELD;
    CcsMidMsg->extra.state = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType1, &frameMsg1, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.server->io);
    ioUserData1->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:

    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC007
* @spec -
* @titleThe client receives a Change Cipher Spec message with zero length.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS over SCTP connection request. After the client sends a Finish message, it constructs a Change Cipher Spec message with zero length and sends the message to the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client receives the message, which is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_MSGLENGTH_ZERO_TC007(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    frameType1.versionType = HITLS_VERSION_DTLS12;
    frameType1.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType1.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType1, &frameMsg1) == HITLS_SUCCESS);
    FRAME_CcsMsg *CcsMidMsg = &frameMsg1.body.ccsMsg;
    CcsMidMsg->ccsType.state = MISSING_FIELD;
    CcsMidMsg->extra.state = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType1, &frameMsg1, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData1->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:

    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_COMPRESSED_TC001
* @spec -
* @titleThe server receives a Client Hello message in which the compression field is set to 1.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the server expects to receive the Client Hello packet, the server constructs the Client Hello packet with the compressed field value being 1. Check the behavior of the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends an ALERT message. The ALERT level is ALERT_LEVEL_FATAL and the description is ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_COMPRESSED_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    *(clientMsg->compressionMethods.data) = 1;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_INVALID_COMPRESSION_METHOD);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.handshakeType = SERVER_HELLO;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_DECODE_ERROR);

EXIT:

    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_COMPRESSED_TC002
* @spec -
* @titleThe client receives a Server Hello message in which the compressed field value is 1.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. After sending the Client Hello packet, the client constructs a Server Hello packet with the compressed field value being 1. Check the behavior of the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends the ALERT message. The ALERT level is ALERT_LEVEL_FATAL and the description is ALERT_ILLEGAL_PARAMETER.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_COMPRESSED_TC002(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->compressionMethod.data = 1;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_COMPRESSION_METHOD_ERR);
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
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_CIPHER_TC001
* @spec -
* @title Check whether the cipher suite selected on the server complies with the RFC.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS over SCTP connection application, the server modifies the algorithm suite field in the Client Hello packet when the server expects to receive the Client Hello packet,
Change the value to 0x00b6, 0x00b7, 0xffff, or 0xc030, and send the modification to the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends the Server Hello message, and the algorithm suite field is 0xc030.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_CIPHER_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    uint16_t suite[] = {0x00B6, 0x00B7, ILLEGAL_VALUE, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384};
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(FRAME_ModifyMsgArray16(suite, sizeof(suite)/sizeof(uint16_t),
    &(clientMsg->cipherSuites), &(clientMsg->cipherSuitesSize)) == HITLS_SUCCESS);
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
    frameType.handshakeType = SERVER_HELLO;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.cipherSuite.data, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_CIPHER_TC002
* @spec -
* @titleHow to handle unexpected cipher suites received by the client?
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS over SCTP connection request, the client constructs a Server Hello packet after sending the Client Hello message,
Change the value of the cipher suite field to 0xff and send the modified value to the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends an ALERT message. The ALERT level is ALERT_LEVEL_FATAL and the description is ALERT_ILLEGAL_PARAMETER.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_CIPHER_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->cipherSuite.data = ILLEGAL_VALUE;
      uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC001
* @spec -
* @title The server receives a Client Hello packet without the Signature Algorithms field.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS over SCTP connection request and the server expects to receive the Client Hello packet,
Delete the signature field from the Client Hello packet and send the packet to the server after the packet is modified. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends the Server Hello message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isClient = false;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.body.hsMsg.type.data == CLIENT_HELLO);
    frameMsg.body.hsMsg.body.clientHello.signatureAlgorithms.exState = MISSING_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
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
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.recType.data, REC_TYPE_HANDSHAKE);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC002
* @spec -
* @titleThe client receives the Server Hello packet carrying the Signature Algorithms field.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS over SCTP connection application, the client constructs a Server Hello packet after sending the Client Hello message,
Add the Signature Algorithms field and set its value to 0x0403. Modify the field and send it to the client. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends the ALERT message. The ALERT level is ALERT_LEVEL_FATAL and the description is ALERT_UNSUPPORTED_EXTENSION.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC002(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->secRenego.exState = INITIAL_FIELD;
    ASSERT_TRUE(FRAME_ModifyMsgInteger(HS_EX_TYPE_SIGNATURE_ALGORITHMS,
    &(serverMsg->secRenego.exType)) == HITLS_SUCCESS);
    serverMsg->secRenego.exLen.state = INITIAL_FIELD;
    uint8_t Signature[] = {SIGNATURE_ALGORITHMS};
    ASSERT_TRUE(FRAME_ModifyMsgArray8(Signature, sizeof(Signature),
    &(serverMsg->secRenego.exData), &(serverMsg->secRenego.exDataLen)) == HITLS_SUCCESS);
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_UNSUPPORTED_EXTENSION);
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
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNSUPPORTED_EXTENSION);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC003
* @spec -
* @titleThe server receives a client Hello message with abnormal signature hash fields.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a connection request, constructs an abnormal Client Hello packet, that is, the signature hash field is not in pairs, and sends the packet to the server.
* @expect 1. The initialization is successful.
* 2. After the server receives the Client Hello message, the HiTLS_ACCEPT interface returns a failure message and the server sends an ALERT message. The ALERT level is ALERT_ LEVEL_FATAL and the description is ALERT_DECODE_ERROR.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC003(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->signatureAlgorithms.exDataLen.data = HASH_EXDATA_LEN_ERROR ;
      uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_PARSE_INVALID_MSG_LEN);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.handshakeType = SERVER_HELLO;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_DECODE_ERROR);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC004
* @spec -
* @title The server receives the Client Hello packet carrying the Signature Algorithms field.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS over SCTP connection request, after the client sends the Client Hello message,
Modify the signature algorithm field by adding an invalid field value and observe the client behavior. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends the ALERT message. The ALERT level is ALERT_LEVEL_FATAL and the description is ALERT_HANDSHAKE_FAILURE.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC004(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    uint16_t Signature[] = {ILLEGAL_VALUE};
    ASSERT_TRUE(FRAME_ModifyMsgArray16(Signature, sizeof(Signature)/sizeof(uint16_t),
    &(clientMsg->signatureAlgorithms.exData), &(clientMsg->signatureAlgorithms.exDataLen)) == HITLS_SUCCESS);
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data ==  ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_HANDSHAKE_FAILURE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC005
* @spec -
* @titleThe client receives the Server Hello packet carrying the Signature Algorithms field.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the client initiates a DTLS over SCTP connection application, the client constructs a Server Hello packet after sending the Client Hello message,
Modify the signature algorithm field by adding an invalid field value and observe the client behavior. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client sends the ALERT message. The ALERT level is ALERT_LEVEL_FATAL and the description is ALERT_UNSUPPORTED_EXTENSION.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC005(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->secRenego.exState = INITIAL_FIELD;
    ASSERT_TRUE(FRAME_ModifyMsgInteger(HS_EX_TYPE_SIGNATURE_ALGORITHMS,
    &(serverMsg->secRenego.exType)) == HITLS_SUCCESS);
    serverMsg->secRenego.exLen.state = INITIAL_FIELD;
    uint8_t Signature[] = {ILLEGAL_VALUE};
    ASSERT_TRUE(FRAME_ModifyMsgArray8(Signature, sizeof(Signature),
    &(serverMsg->secRenego.exData), &(serverMsg->secRenego.exDataLen)) == HITLS_SUCCESS);
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_UNSUPPORTED_EXTENSION);
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
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNSUPPORTED_EXTENSION);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC007
* @spec -
* @titleThe client sends a Client Hello message in which the signature field is removed.
* @precon nan
* @brief 1. Use the default initialization mode on the client and server. Expected result 1.
* 2. The client initiates a connection establishment request, deletes the signature field in the client Hello message, and sends the message to the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server continues to establish a connection. The connection is successfully established.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_SIGNATURE_TC007(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->signatureAlgorithms.exState = MISSING_FIELD;
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
    frameType.handshakeType = SERVER_HELLO;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_HANDSHAKE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_CERTIFICATE_TC003
* @spec -
* @title The server receives an unexpected Client Certificate message.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. The client initiates a DTLS connection application. After sending the Server Hello Done message, the server constructs a Client Certificate message and sends it to the server. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends the ALERT message. The ALERT level is ALERT_ LEVEL_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_CERTIFICATE_TC003(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
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
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_VERSION_TC001
* @spec -
* @titleThe server receives the client hello message of DTLS1.0.
* @precon nan
* @brief 1. Retain the default configuration on the client and server, and enable peer verification on the server. Expected result 1.
* 2. When the server is in the TRY_RECV_CLIENT_HELLO state, change the negotiated version number field in the client hello message to DTLS1.0. Then, check the server behavior.
* @expect 1. The initialization is successful.
* 2. The server sends a FATAL ALERT, and the description of the ALERT is ALERT_PROTOCOL_VERSION.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_VERSION_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->version.data = HITLS_VERSION_DTLS10;
    clientMsg->version.state = ASSIGNED_FIELD;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));
    CONN_Deinit(testInfo.server->ssl);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);
    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    parseLen = 0;
    frameType.handshakeType = SERVER_HELLO;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_PROTOCOL_VERSION);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC001
* @spec -
* @titleThe client receives a Hello Request message during startup.
* @precon nan
* @brief 1. Use the default configuration on the client and server, and enable peer verification on the server. Expected result 1.
* 2. When the client starts, the client receives a Hello Request message. Expected result 2.
3. Continue to complete connection establishment and send and receive messages. (Expected result 3)
* @expect 1. The initialization is successful.
* 2. The client can process the packet normally.
3. The message is sent and received successfully.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TLS_IDLE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    FRAME_Init();
    testInfo.config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(testInfo.config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));
    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;
    testInfo.client = FRAME_CreateLink(testInfo.config, uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.config, uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.server->ssl, 0) == HITLS_SUCCESS);
    testInfo.server->ssl->hsCtx->nextSendSeq++;
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_TRANSPORTING);
    uint8_t writeData[] = {"abcd1234"};
    uint32_t writeLen = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    uint32_t sendNum;
    ASSERT_EQ(HITLS_Write(testInfo.server->ssl, writeData, writeLen, &sendNum), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readData, MAX_RECORD_LENTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, writeLen);
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC002
* @spec -
* @titleThe client receives a Hello Request message after sending a Client Hello message.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 11.
* 2. After the client sends a Client Hello message, the client receives a Hello Request message. Expected result 2.
3. Continue to establish a connection and send and receive messages. (Expected result 3)
* @expect 1. The initialization is successful.
* 2. The client can process the packet normally.
3. The message is sent and received successfully.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC002(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_SEND_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, uioType) == HITLS_SUCCESS);
    CONN_Deinit(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.server->ssl, 0) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_HANDSHAKING);
    ASSERT_EQ(clientTlsCtx->hsCtx->state, TRY_RECV_SERVER_HELLO);

EXIT:

    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC003
* @spec -
* @titleThe server receives a Hello Request message after sending a Server Hello Done message.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 11.
* 2. After sending a Server Hello Done message, the server receives a Hello Request message. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends an ALERT message with the description of ALERT_UNEXPECTED_MESSAGE.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC003(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_SEND_SERVER_HELLO_DONE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, uioType) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.client->ssl, 1) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_DTLS12;
    frameType.recordType = REC_TYPE_ALERT;
    frameType.transportType = uioType;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data ==  ALERT_LEVEL_FATAL);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC004
* @spec -
* @titleThe client receives a Hello Request message after sending a FINISH message.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 11.
* 2. After the client sends a FINISH message, the client receives a Hello Request message. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The client can process the packet normally.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC004(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, uioType) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.server->ssl, 4) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_HANDSHAKING);
    ASSERT_EQ(clientTlsCtx->hsCtx->state, TRY_RECV_NEW_SESSION_TICKET);

EXIT:

    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC005
* @spec -
* @titleThe server receives a Hello Request message after sending a FINISH message.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 11.
* 2. After the server sends a FINISH message, the server receives a Hello Request message. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server can process the packet normally.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC005(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, uioType) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.client->ssl, 1) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(testInfo.server);
    ASSERT_EQ(serverTlsCtx->state, CM_STATE_ALERTED);

EXIT:

    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC006
* @spec -
* @titleThe client receives the Hello Request message after the connection establishment is complete.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 11.
* 2. After the connection is established on the client, the client receives a Hello Request message. Expected result 2.
3. The server writes a message and the client receives the message. (Expected result 3)
* @expect 1. The initialization is successful.
* 2. The server can process the packet normally.
3. The client receives the message correctly.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC006(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = HS_STATE_BUTT;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo, uioType) == HITLS_SUCCESS);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.server->ssl, 1) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t writeData[] = {"abcd1234"};
    uint32_t writeLen = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    readLen = MAX_RECORD_LENTH;
    uint32_t sendNum;
    ASSERT_EQ(HITLS_Write(testInfo.server->ssl, writeData, writeLen, &sendNum), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC007
* @spec -
* @titleThe server receives a Hello Request message during startup.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. When the server starts, the Hello Request message is received. Expected result 2.
* @expect 1. The initialization is successful.
* 2. The server sends an ALERT. The description is ALERT_UNEXPECTED_MESSAGE.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC5246_HELLO_REQUEST_TC007(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TLS_IDLE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    HandshakeTestInfo testInfo1 = {0};
    testInfo1.state = TLS_IDLE;
    FRAME_Init();
    testInfo.config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(testInfo.config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));
    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;
    testInfo.client = FRAME_CreateLink(testInfo.config, uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.config, uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    testInfo1.server = FRAME_CreateLink(testInfo.config, uioType);
    ASSERT_TRUE(testInfo1.server != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo1.server) == HITLS_SUCCESS);
    ASSERT_TRUE(SendHelloReqWithIndex(testInfo.client->ssl, 0) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_ALERTED);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_CFG_FreeConfig(testInfo1.config);
    FRAME_FreeLink(testInfo1.server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC001
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
void UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC001(void)
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
* 2. The client initiates a connection request and constructs the scenario where the FINISH message and CCS message are out of order. That is, the server processes the FINISH message and then processes the CCS message. After the processing, the server continues to establish a connection. Expected result 2 is displayed.
* @expect 1: The initialization is successful.
* 2: The server is waiting to receive the FINISH message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC002(void)
{
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = TRY_SEND_CLIENT_KEY_EXCHANGE;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderClientFinished(testInfo.client, data, len, &len) == HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC003
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
void UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC003(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC004
* @spec -
* @titleThe server receives a FINISH message and the APP message is out of order.
* @precon nan
* @brief 1. Initialize the client and server using the default configuration. Expected result 1.
* 2. The client initiates a connection request and constructs the scenario where the FINISH message and APP message are out of order. That is, the server processes the APP message first, processes the FINISH message, and then continues to establish a connection. Expected result 2 is displayed.
* 3. After the connection is established, the client sends data to the server, and the server receives the data. (Expected result 3)
* @expect 1: Initialization succeeded.
* 2: The connection between the client and server is successfully established.
* 3: Data received by the server is consistent with data sent by the client.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_FINISH_TC004(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = TRY_SEND_FINISH;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, uioType) == HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderClientFinished_AppData(testInfo.client, data, len, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, data, len) == HITLS_SUCCESS);
    (void)HITLS_Accept(testInfo.server->ssl);
    ASSERT_EQ(testInfo.server->ssl->state, CM_STATE_HANDSHAKING);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
    (void)HITLS_Connect(testInfo.client->ssl);
    (void)HITLS_Accept(testInfo.server->ssl);
    ASSERT_EQ(testInfo.server->ssl->state, CM_STATE_HANDSHAKING);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
    (void)HITLS_Connect(testInfo.client->ssl);
    FRAME_RegCryptMethod();
    if (uioType == BSL_UIO_UDP) {
        // anti-replay
        ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    } else {
        ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_SUCCESS);
    }
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
    (void)HITLS_Connect(testInfo.client->ssl);
    uint8_t writeData[] = {"abcd1234"};
    uint32_t writeLen = strlen("abcd1234");
    uint8_t readData[MAX_RECORD_LENTH] = {0};
    uint32_t readLen = MAX_RECORD_LENTH;
    uint32_t sendNum;
    ASSERT_EQ(HITLS_Write(testInfo.server->ssl, writeData, writeLen, &sendNum), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client), HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_DISORDER_TC001
* @spec -
* @titleThe server receives out-of-order APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection application by using DTLS. Expected result 2.
* 3. Construct an app message whose SN is 2 and send it to the server. When the server invokes HiTLS_Read, expected result 3.
* 4. Construct an app message whose SN is 1 and send it to the server. When the server invokes HiTLS_Read, expected result 4.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLS connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_DISORDER_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo, uioType), HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_DISORDER_TC002
* @spec -
* @titleThe client receives out-of-order APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection request using DTLS. Expected result 2.
* 3. Construct an app message whose sequence number is 2 and send it to the client. When the client invokes HiTLS_Read, expected result 3.
* 4. Construct an app message whose sequence number is 1 and send it to the client. When the client invokes HiTLS_Read, expected result 4.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLS connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_DISORDER_TC002(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo, uioType), HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_APPDATA_TC001
* @spec -
* @title The server receives duplicate APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection application by using DTLS. Expected result 2.
* 3. Construct an app message whose SN is 1 and send it to the server. When the server invokes HiTLS_Read, expected result 3.
* 4. Construct the app message whose SN is 1 and send it to the server. When the server invokes HiTLS_Read, expected result 4.
* 5. The server constructs data and sends it to the client. When the client invokes HiTLS_Read, expected result 5.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLS connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* 5: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_APPDATA_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo, uioType), HITLS_SUCCESS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetRepeatsApp(testInfo.client, data, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_SUCCESS);
    if (uioType == BSL_UIO_UDP) {
        // anti-replay
        ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    } else {
        ASSERT_TRUE(HITLS_Read(testInfo.server->ssl, data, MAX_RECORD_LENTH, &len) == HITLS_SUCCESS);
    }
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_APPDATA_TC002
* @spec -
* @titleThe client receives duplicate APP messages.
* @precon nan
* @brief 1. Initialize the configuration on the client and server. Expected result 1.
* 2. Initiate a connection application by using DTLS. Expected result 2.
* 3. Construct an app message whose sequence number is 1 and send the message to the client. When the client invokes HiTLS_Read, expected result 3.
* 4. Construct an app message with the sequence number being 1 and send it to the client. When the client invokes HiTLS_Read, expected result 4.
* 5. The server constructs data and sends it to the client. When the client invokes HiTLS_Read, expected result 5.
* @expect 1: Initializing the configuration succeeded.
* 2: The DTLS connection is successfully created.
* 3: The interface returns a success response.
* 4: The interface returns a success response.
* 5: The interface returns a success response.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_APPDATA_TC002(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.isClient = false;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo, uioType), HITLS_SUCCESS);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_CLIENT_HELLO_TC001
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
void UT_TLS_DTLS_CONSISTENCY_RFC6347_CLIENT_HELLO_TC001(int uioType)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isClient = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_EQ(DefaultCfgStatusPark1(&testInfo, uioType), HITLS_SUCCESS);
    frameType.versionType = HITLS_VERSION_DTLS12;
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

static bool cookie_generate_success = true;
#define DTLS_COOKIE_LEN 255
static int32_t UT_CookieGenerateCb(HITLS_Ctx *ctx, uint8_t *cookie, uint32_t *cookie_len)
{
    (void)ctx;
    (void)cookie;
    if (cookie_generate_success) {
        *cookie_len = DTLS_COOKIE_LEN;
    }
    return cookie_generate_success;
}

static bool cookie_valid = true;
static int32_t UT_CookieVerifyCb(HITLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookie_len)
{
    (void)ctx;
    (void)cookie;
    (void)cookie_len;
    return cookie_valid;
}

int32_t HS_CheckCookie_Custom(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, bool *isCookieValid)
{
    *isCookieValid = false;

    /* If the client does not send the cookie, the verification is not required */
    if (clientHello->cookie == NULL) {
        return HITLS_SUCCESS;
    }
    if (ctx->globalConfig->appVerifyCookieCb == NULL) {
        return HITLS_UNREGISTERED_CALLBACK;
    }

    HITLS_AppVerifyCookieCb cookieCb = ctx->globalConfig->appVerifyCookieCb;
    int32_t isValid = cookieCb(ctx, clientHello->cookie, clientHello->cookieLen);
    if (isValid != HITLS_COOKIE_VERIFY_ERROR) {
        *isCookieValid = true;
    }
    return HITLS_SUCCESS;
}

int32_t HS_CalcCookie_Custom(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, uint8_t *cookie, uint32_t *cookieLen)
{
    (void)clientHello;
    if (ctx->globalConfig->appGenCookieCb == NULL) {
        return HITLS_UNREGISTERED_CALLBACK;
    }
    int32_t returnVal = ctx->globalConfig->appGenCookieCb(ctx, cookie, cookieLen);
    if (returnVal == HITLS_COOKIE_GENERATE_ERROR) {
        return HITLS_MSG_HANDLE_COOKIE_ERR;
    }
    return HITLS_SUCCESS;
}

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC001
* @spec -
* @title The server doesn't set appGenCookieCb or appVerifyCookieCb.
* @precon nan
* @brief 1. Configure option isSupportDtlsCookieExchange is on. Leave appGenCookieCb or appVerifyCookieCb blank.
            Check whether server and client can handshake successfully. Expected result 1.
* @expect 1. The link fails to be set up.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC001(int setGenerateCb, int setVerifyCb)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    serverTlsCtx->config.tlsConfig.isSupportDtlsCookieExchange = true;
    if (setGenerateCb) {
        serverTlsCtx->globalConfig->appGenCookieCb = UT_CookieGenerateCb;
        STUB_REPLACE(HS_CheckCookie, HS_CheckCookie_Custom);
    }
    if (setVerifyCb) {
        serverTlsCtx->globalConfig->appVerifyCookieCb = UT_CookieVerifyCb;
        STUB_REPLACE(HS_CalcCookie, HS_CalcCookie_Custom);
    }

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_UNREGISTERED_CALLBACK);

EXIT:
    STUB_RESTORE(HS_CheckCookie); STUB_RESTORE(HS_CalcCookie);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC002
* @spec -
* @title The server fails to generate cookie.
* @precon nan
* @brief 1. Configure option isSupportDtlsCookieExchange is on. Configure appGenCookieCb and appVerifyCookieCb.
            appGenCookieCb always return false.
            Check whether server and client can handshake successfully. Expected result 1.
* @expect 1. The link fails to be set up.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    serverTlsCtx->config.tlsConfig.isSupportDtlsCookieExchange = true;
    serverTlsCtx->globalConfig->appGenCookieCb = UT_CookieGenerateCb;
    serverTlsCtx->globalConfig->appVerifyCookieCb = UT_CookieVerifyCb;
    cookie_generate_success = false;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_MSG_HANDLE_COOKIE_ERR);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC003
* @spec -
* @title The server receives a Client Hello packet with invalid cookie when isSupportDtlsCookieExchange is on.
* @precon nan
* @brief 1. Configure option isSupportDtlsCookieExchange is on. Configure appGenCookieCb and appVerifyCookieCb.
            appGenCookieCb always return true and appVerifyCookieCb always return false.
            Check whether server and client can handshake successfully. Expected result 1.
* @expect 1: The link fails to be set up.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC003(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    serverTlsCtx->config.tlsConfig.isSupportDtlsCookieExchange = true;
    serverTlsCtx->globalConfig->appGenCookieCb = UT_CookieGenerateCb;
    serverTlsCtx->globalConfig->appVerifyCookieCb = UT_CookieVerifyCb;
    cookie_generate_success = true;
    cookie_valid = false;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_INTERNAL_EXCEPTION);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC003
* @spec -
* @title The server receives a Client Hello packet with valid cookie when isSupportDtlsCookieExchange is on.
* @precon nan
* @brief 1. Configure option isSupportDtlsCookieExchange is on. Configure appGenCookieCb and appVerifyCookieCb.
            appGenCookieCb always return true and appVerifyCookieCb always return true.
            Check whether server and client can handshake successfully. Expected result 1.
* @expect 1: The link is set up successfully.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC6347_HELLO_VERIFY_REQ_TC004(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    serverTlsCtx->config.tlsConfig.isSupportDtlsCookieExchange = true;
    serverTlsCtx->globalConfig->appGenCookieCb = UT_CookieGenerateCb;
    serverTlsCtx->globalConfig->appVerifyCookieCb = UT_CookieVerifyCb;
    cookie_generate_success = true;
    cookie_valid = true;

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RFC8422_ECPOINT_TC001
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
void UT_TLS_DTLS_CONSISTENCY_RFC8422_ECPOINT_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS12;
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC8422_EXTENSION_MISS_TC001
* @spec -
* @title The server receives a Client Hello packet that does not carry the group or dot format.
* @precon nan
* @brief 1. Configure the HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite on the client and initialize the cipher suite on the server by default. Expected result 1.
* 2. When the client initiates a connection request and the server is about to read ClientHello,
* Delete the supported_groups and ec_point_formats fields from the packet. Expected result 2.
* @expect 1. Initialization succeeded.
* 2. The server sends a Server Hello packet with the HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 algorithm suite.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RFC8422_EXTENSION_MISS_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo, BSL_UIO_UDP) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS12;
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
    ASSERT_EQ(serverMsg->cipherSuite.data, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* when receive alert between finish and ccs, dtls12 should cache it*/
/* BEGIN_CASE */
void UT_DTLS_RFC6347_RECV_ALERT_AFTER_CCS_TC001(int uioType)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, uioType);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, uioType);
    client->needStopBeforeRecvCCS = true;
    server->needStopBeforeRecvCCS = true;
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
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
* @test UT_TLS_DTLS_CONSISTENCY_RFC6347_TC001
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
void UT_TLS_DTLS_CONSISTENCY_RFC6347_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    tlsConfig->isSupportRenegotiation = true;
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
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

/* @
* @test UT_TLS_DTLS_CONSISTENCY_RETRANSMIT_TC001
* @spec -
* @title When testing the behavior of the client preparing to receive messages, querying the remaining timeout time,
            selecting whether to sleep, and then retransmitting the message
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. Stop the client in the TRY1 RECV_SERVER HELLO or TRY1 RECV_FINISH state. Expected result 2.
* 3. Obtain the remaining timeout period. Expected result 3.
* 4. Choose sleep mode and then resend the message. Expected result 4.
* 5. Do not sleep, and then retransmit the message. Expected result 5.
* @expect 1. The initialization is successful.
* 2. return success.
* 3. return success.
* 4. expecting the message to be successfully retransmit.
* 5. expecting to return HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_DTLS_CONSISTENCY_RETRANSMIT_TC001(int isNeedSleep, int clientState)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewDTLS12Config();
    tlsConfig->isSupportRenegotiation = true;
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, clientState) == HITLS_SUCCESS);
    uint64_t timeout = 0;
    int32_t ret = HITLS_DtlsGetTimeout(client->ssl, &timeout);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    if (isNeedSleep) {
        sleep(2); // the sleep time is greater than the timeout period, the retransmission operation is triggered
        ret = HITLS_DtlsProcessTimeout(client->ssl);
        // When there are multiple messages, retransmission will be blocked, so it will be busy.
        // If there is only one message, it will be successfully sent.
        if (ret == HITLS_REC_NORMAL_IO_BUSY) {
            ret = FRAME_TrasferMsgBetweenLink(client, server);
        }
        ASSERT_EQ(ret, HITLS_SUCCESS);
    } else {
        ret = HITLS_DtlsProcessTimeout(client->ssl);
        ASSERT_TRUE(ret == HITLS_MSG_HANDLE_DTLS_RETRANSMIT_NOT_TIMEOUT);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */