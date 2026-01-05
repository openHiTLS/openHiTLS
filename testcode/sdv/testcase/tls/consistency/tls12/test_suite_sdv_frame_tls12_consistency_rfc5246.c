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

#include <stdio.h>
#include "stub_utils.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "cert.h"
#include "securec.h"
#include "rec_wrapper.h"
#include "conn_init.h"
#include "cert_callback.h"
#include "change_cipher_spec.h"
#include "common_func.h"
#include "uio_base.h"
#include "hs.h"
#include "stub_crypt.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(int32_t, HS_DoHandshake, TLS_Ctx *);


/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC001
* @title  Verify that the server receives a 0-length Client Hello message and the expected alert is returned.
* @precon  nan
* @brief  1. Create a config and client link, and construct a 0-length client hello message.
*         Expected result 1 is obtained.
*         2. The server invokes the HITLS_Accept interface. (Expected result 2)
* @expect 1. A success message is returned.
*         2. A failure message is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC001(void)
{
    // Create a config and client link, and construct a 0-length client hello message.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
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

    // The server invokes the HITLS_Accept interface.
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

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC002
* @title  Verify that the client receives a serverhello message with a length of 0 and the expected alert is returned.
* @precon  nan
* @brief  1. Create a config and server link, and construct a 0-length server hello message.
*         Expected result 1 is obtained.
*         2. The client invokes the HITLS_Connect interface. (Expected result 2)
* @expect 1. A success message is returned.
*         2. A failure message is returned.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC002(void)
{
    // Create a config and server link, and construct a 0-length server hello message.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
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

    /* The client invokes the HITLS_Connect interface. */
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

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC003
* @title  The client receives a Certificate message with a length of zero.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained
*         2. Construct a zero-length Certificate message and send it to the client. Expected result 2 is obtained
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message with the level of ALERT_Level_FATAL and description of ALERT_DECODE_ERROR
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC003(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Construct a zero-length Certificate message and send it to the client. */
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

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC004
* @title  The client receives a Server Key Exchange message whose length is 0.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained
*         2. Construct a zero-length Server Key Exchange message and send it to the client.
*         Expected result 2 is obtained
* @expect 1. The initialization is successful
*         2. The client sends an ALERT message. The level is ALERT_LEVEL_FATAL and the description is ALERT_DECODE_ERROR
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC004(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_SERVER_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Construct a zero-length Server Key Exchange message and send it to the client. */
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
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC005
* @title  The server receives a Client Key Exchange message with zero length.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a zero-length Client Key Exchange message and send it to the server.
*         Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The server sends an ALERT message. The level is ALERT_LEVEL_FATAL and the description is ALERT_DECODE_ERROR
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC005(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    // Construct a zero-length Client Key Exchange message and send it to the server.
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

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC006
* @title  The server receives a Change Cipher Spec message with zero length.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained
*         2. Construct a Change Cipher Spec message with zero length and send it to the server.
*         Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The server sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC006(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_CERTIFICATE_VERIFY;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    FRAME_Msg frameMsg1 = { 0 };
    FRAME_Type frameType1 = { 0 };
    frameType1.versionType = HITLS_VERSION_TLS12;
    frameType1.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType1.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType1, &frameMsg1) == HITLS_SUCCESS);

    // Construct a Change Cipher Spec message with zero length and send it to the server.
    FRAME_CcsMsg *CcsMidMsg = &frameMsg1.body.ccsMsg;
    CcsMidMsg->ccsType.state = MISSING_FIELD;
    CcsMidMsg->extra.state = MISSING_FIELD;
    CcsMidMsg->extra.size = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType1, &frameMsg1, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.server->io);
    ioUserData1->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    memset_s(&frameMsg1, sizeof(frameMsg1), 0, sizeof(frameMsg1));

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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC007
* @title  The client receives a Change Cipher Spec message with a length of 0 and the data is encrypted.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained
*         2. Construct a Change Cipher Spec message with zero length and send it to the client.
*         Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC007(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_NEW_SESSION_TICKET;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    FRAME_Msg frameMsg1 = { 0 };
    FRAME_Type frameType1 = { 0 };
    frameType1.versionType = HITLS_VERSION_TLS12;
    frameType1.recordType = REC_TYPE_CHANGE_CIPHER_SPEC;
    frameType1.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType1, &frameMsg1) == HITLS_SUCCESS);

    // Construct a Change Cipher Spec message with zero length and send it to the client.
    FRAME_CcsMsg *CcsMidMsg = &frameMsg1.body.ccsMsg;
    CcsMidMsg->ccsType.state = MISSING_FIELD;
    CcsMidMsg->extra.state = MISSING_FIELD;
    CcsMidMsg->extra.size = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType1, &frameMsg1, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData1->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    memset_s(&frameMsg1, sizeof(frameMsg1), 0, sizeof(frameMsg1));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    FRAME_AlertMsg *alertMsg = &frameMsg1.body.alertMsg;
    ASSERT_EQ(alertMsg->alertLevel.data , 0);
    ASSERT_EQ(alertMsg->alertDescription.data , ALERT_CLOSE_NOTIFY);
EXIT:
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC008
* @title  The client receives a SERVER_HELLO_DONE message whose length is 0 and expects to return an alert message
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained
*         2. Construct a SERVER_HELLO_DONE message with a zero length, and send the message to the client.
*         Expected result 2 is obtained
* @expect 1. The initialization is successful
*         2. The client sends an ALERT message
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC008(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO_DONE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO_DONE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    // Construct a SERVER_HELLO_DONE message with a zero length, and send the message to the client.
    FRAME_ServerHelloDoneMsg *serverHelloDone = &frameMsg.body.hsMsg.body.serverHelloDone;
    serverHelloDone->extra.state = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC001
* @title  An unexpected message is received when the client is in the TRY_RECV_CERTIFICATIONATE
*         state during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message.
*         The level is ALERT_LEVEL_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC001(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    // Construct a Server Hello message and send it to the client.
    FRAME_Msg parsedSHdone = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, SERVER_HELLO_DONE, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &parsedSHdone) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSHdone, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &parsedSHdone);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
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
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC002
* @title  An unexpected message is received when the client is in the TRY_RECV_CERTIFICATIONATE state
*         during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message.
*         The level is ALERT_LEVEL_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC002(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    // Construct a Server Hello message and send it to the client.
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC003
* @title  An unexpected message is received when the client is in the TRY_RECV_SERVER_KEY_EXCHANGE state
*         during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message.
*         The level is ALERT_LEVEL_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC003(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_SERVER_KEY_EXCHANGE;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    // Construct a Server Hello message and send it to the client.
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC004
* @title  An unexpected message is received when the client is in the TRY_RECV_SERVER_HELLO_DONE state
*         during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message. The level is
*         ALERT_LEVEL_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC004(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO_DONE;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    // Construct a Server Hello message and send it to the client.
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC005
* @title  An unexpected message is received when the client is in the TRY_RECV_FINISH state during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message.
*         The level is ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC005(void)
{
    // Use the default configuration items to configure the client and server.
    // Construct a Server Hello message and send it to the client.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg parsedAlert = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);
    testInfo.client->ssl->hsCtx->state = TRY_RECV_FINISH;
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(sndBuf, sndLen, &parsedAlert, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(parsedAlert.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC006
* @title  An unexpected message is received when the client is in the TRY_RECV_CERTIFICATE_REQUEST
*         state during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT.
*         The level is ALERT_LEVEL_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC006(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_CERTIFICATE_REQUEST;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    // Construct a Server Hello message and send it to the client.
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC007
* @title  An unexpected message is received when the client is in the TRY_RECV_NEW_SESSION_TICKET state
*         during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a Server Hello message and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the Server Hello message, the client sends an ALERT message.
*         The level is ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC007(void)
{
    // Use the default configuration items to configure the client and server.
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    // Construct a Server Hello message and send it to the client.
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    testInfo.client->ssl->hsCtx->state = TRY_RECV_NEW_SESSION_TICKET;

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC008
* @title  An unexpected message is received when the server is in the TRY_RECV_CLIENT_HELLO state during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a CLIENT_KEY_EXCHANGE message and send it to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT.
*         The level is ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC008(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Construct a CLIENT_KEY_EXCHANGE message and send it to the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    testInfo.server->ssl->hsCtx->state = TRY_RECV_CLIENT_HELLO;

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC009
* @title  An unexpected message is received when the server is in the TRY_RECV_CERTIFICATIONATE
*         state during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a CLIENT_KEY_EXCHANGE message and send it to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*         ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC009(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Construct a CLIENT_KEY_EXCHANGE message and send it to the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    testInfo.server->ssl->hsCtx->state = TRY_RECV_CERTIFICATE;

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC010
* @title  An unexpected message is received when the server is in TRY_RECV_CLIENT_KEY_EXCHANGE state during the
*         handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a SERVER_HELLO message and send it to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the SERVER_HELLO message, the server sends an ALERT. The level is ALERT_Level_FATAL and the
*         description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC010(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Construct a SERVER_HELLO message and send it to the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    testInfo.server->ssl->hsCtx->state = TRY_RECV_CLIENT_KEY_EXCHANGE;

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CERTIFICATE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}

/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC011
* @title  An unexpected message is received when the server is in the TRY_RECV_CERTIFICATIONATE_VERIFY state during the
*         handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a CLIENT_KEY_EXCHANGE message and send it to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
*         ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC011(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Construct a CLIENT_KEY_EXCHANGE message and send it to the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    testInfo.server->ssl->hsCtx->state = TRY_RECV_CERTIFICATE_VERIFY;

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC012
* @title  An unexpected message is received when the server is in the TRY_RECV_FINISH state during the handshake.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a CLIENT_KEY_EXCHANGE message and send it to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the CLIENT_KEY_EXCHANGE message, the server sends an ALERT message. The level is
ALERT_Level_FATAL and the description is ALERT_UNEXPECTED_MESSAGE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_UNEXPECTMSG_TC012(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Construct a CLIENT_KEY_EXCHANGE message and send it to the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    testInfo.server->ssl->hsCtx->state = TRY_RECV_FINISH;

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

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

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_AEAD_EXPLICIT_IV_LENGTH_TC001
* @title  The client and server establish a connection. Check whether the sequence number in the APP message is
*         contained in the record-layer message.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. A TLS over TCP link is established between the client and server. Expected result 2 is obtained.
*         3. Randomly generate a 32-bit transmission data. Expected result 3 is obtained.
*         4. Randomly generate a serial number. Expected result 4 is obtained.
*         5. Write app data to the server.
*         6. Data transmission at the record layer.
*         7. Check the changes before and after the sequence number is sent.
*         8. Record layer data receiving.
* @expect 1. The initialization is successful.
*         2. The link is set up successfully.
*         3. The generation is successful.
*         4. The generation is successful.
*         5. The writing is successful.
*         6. Transmission is successful.
*         7. After the sending, the seqNum is increased by 1.
*         8. The data length and data content are verified successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_AEAD_EXPLICIT_IV_LENGTH_TC001()
{
    /* Use the default configuration items to configure the client and server. */
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = HS_STATE_BUTT;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* A TLS over TCP link is established between the client and server. */
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_TRANSPORTING);

    /* Randomly generate a 32-bit transmission data. */
    uint8_t transportData[REC_CONN_SEQ_SIZE * 4] = {0};
    uint32_t transportDataLen = sizeof(transportData) / sizeof(uint8_t);
    ASSERT_EQ(RandBytes(transportData, transportDataLen), HITLS_SUCCESS);
    /* Randomly generate a serial number. */
    uint8_t randSeq[REC_CONN_SEQ_SIZE] = {0};
    ASSERT_EQ(RandBytes(randSeq, REC_CONN_SEQ_SIZE), HITLS_SUCCESS);
    REC_Ctx *recCtx = (REC_Ctx *)testInfo.server->ssl->recCtx;
    recCtx->writeStates.currentState->seq = BSL_ByteToUint64(randSeq);
    uint64_t sequenceNumber = recCtx->writeStates.currentState->seq;
    uint8_t seq[REC_CONN_SEQ_SIZE] = {0};
    BSL_Uint64ToByte(sequenceNumber, seq);

    /* Write app data to the server. */
    uint32_t writeLen;
    int32_t ret = APP_Write(testInfo.server->ssl, transportData, transportDataLen, &writeLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    /* Data transmission at the record layer. */
    uint8_t tmpData[MAX_RECORD_LENTH] = {0};
    uint32_t tmpLen;
    ASSERT_TRUE(FRAME_TransportSendMsg(testInfo.server->io, tmpData, MAX_RECORD_LENTH, &tmpLen) == HITLS_SUCCESS);

    /* Check the changes before and after the sequence number is sent. */
    recCtx = (REC_Ctx *)testInfo.server->ssl->recCtx;
    uint64_t sequenceNumberAfterSend = recCtx->writeStates.currentState->seq;
    ASSERT_EQ(sequenceNumberAfterSend, sequenceNumber + 1);

    /* Record layer data receiving. */
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, tmpData, tmpLen) == HITLS_SUCCESS);
    const int32_t AEAD_TAG_LEN = 16u;
    ASSERT_EQ(tmpLen, REC_TLS_RECORD_HEADER_LEN + REC_CONN_SEQ_SIZE + transportDataLen + AEAD_TAG_LEN);

    ASSERT_TRUE(memcmp(tmpData + REC_TLS_RECORD_HEADER_LEN, seq, REC_CONN_SEQ_SIZE) == 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_READ_PENDING_STATE_TC001
* @title  Observe the changes in the status of the record layer before and after the client receives the CCS message.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client to stop the client in the TRY_RECV_FINISH
state. Expected result 1 is obtained.
*         2. Record the states at the record layer that the client reads. Expected result 2 is obtained.
*         3. Reconnect the client. Expected result 3 is obtained.
*         4. Check the states at the record layer after the client is reconnected. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
*         2. The outdatedState field is empty.
*         3. The return value for reconnection is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
*         4. OutdatedState is the previous currentState.
*            currentState is the previous pendingState.
*            The pendingState field is empty.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_READ_PENDING_STATE_TC001()
{
    /* Use the default configuration items to configure the client to stop the client in the TRY_RECV_FINISH state. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = true;
    testInfo.state = TRY_RECV_FINISH;
    testInfo.needStopBeforeRecvCCS = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Record the states at the record layer that the client reads. */
    RecConnStates *readStates = (RecConnStates *)&(testInfo.client->ssl->recCtx->readStates);
    RecConnState *oldOutdatedState = readStates->outdatedState;
    RecConnState *oldCurrentState = readStates->currentState;
    RecConnState *oldPendingState = readStates->pendingState;
    ASSERT_TRUE(oldOutdatedState == NULL);

    // Reconnect the client.
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* Check the states at the record layer after the client is reconnected. */
    RecConnState *newOutdatedState = readStates->outdatedState;
    RecConnState *newCurrentState = readStates->currentState;
    RecConnState *newPendingState = readStates->pendingState;

    ASSERT_TRUE(newOutdatedState == oldCurrentState);
    ASSERT_TRUE(newCurrentState == oldPendingState);
    ASSERT_TRUE(newPendingState == NULL);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_READ_PENDING_STATE_TC002
* @title  Check the status change of the record layer before and after the server receives the CCS message.
* @precon  nan
* @brief  1. Use the default configuration items to set the server to the TRY_RECV_FINISH state. Expected result 1 is
obtained.
*         2. Record the states of the record layer that the client reads. Expected result 2 is obtained.
*         3. Reconnect the server. Expected result 3 is obtained.
*         4. Check the states at the record layer after the client is reconnected. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
*         2. OutdatedState is empty.
*         3. The return value for reconnection is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
*         4. OutdatedState is the previous currentState.
*            currentState is the previous pendingState.
*            The pendingState field is empty.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_READ_PENDING_STATE_TC002()
{
    /* Use the default configuration items to set the server to the TRY_RECV_FINISH state. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = false;
    testInfo.state = TRY_RECV_FINISH;
    testInfo.needStopBeforeRecvCCS = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Record the states of the record layer that the client reads. */
    RecConnStates *readStates = (RecConnStates *)&(testInfo.server->ssl->recCtx->readStates);
    RecConnState *oldOutdatedState = readStates->outdatedState;
    RecConnState *oldCurrentState = readStates->currentState;
    RecConnState *oldPendingState = readStates->pendingState;
    ASSERT_TRUE(oldOutdatedState == NULL);

    // Reconnect the server.
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* Check the states at the record layer after the client is reconnected. */
    RecConnState *newOutdatedState = readStates->outdatedState;
    RecConnState *newCurrentState = readStates->currentState;
    RecConnState *newPendingState = readStates->pendingState;
    ASSERT_TRUE(newOutdatedState == oldCurrentState);
    ASSERT_TRUE(newCurrentState == oldPendingState);
    ASSERT_TRUE(newPendingState == NULL);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_WRITE_PENDING_STATE_TC001
* @title  Observe the change of the write record layer status before and after the client sends the CCS message.
* @precon  nan
* @brief  1. Use the default configuration items to set the server to the TRY_RECV_FINISH state. Expected result 1 is
obtained.
*         2. Record the states of the client write record layer. Expected result 2 is obtained.
*         3. Reconnect the server. Expected result 3 is obtained.
*         4. Check the states of the write record layer after the client is reconnected. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
*         2. The outdatedState field is empty.
*         3. The return value for reconnection is HITLS_REC_NORMAL_IO_BUSY.
*         4. OutdatedState is the previous currentState.
*            currentState is the previous pendingState.
*            The pendingState field is empty.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_WRITE_PENDING_STATE_TC001()
{
    /* Use the default configuration items to set the server to the TRY_RECV_FINISH state. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = true;
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    testInfo.needStopBeforeRecvCCS = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Record the states of the client write record layer. */
    RecConnStates *writeStates = (RecConnStates *)&(testInfo.client->ssl->recCtx->writeStates);
    RecConnState *oldOutdatedState = writeStates->outdatedState;
    RecConnState *oldCurrentState = writeStates->currentState;
    RecConnState *oldPendingState = writeStates->pendingState;
    ASSERT_TRUE(oldOutdatedState == NULL);

    // Reconnect the server.
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_IO_BUSY);

    /* Check the states of the write record layer after the client is reconnected. */
    RecConnState *newOutdatedState = writeStates->outdatedState;
    RecConnState *newCurrentState = writeStates->currentState;
    RecConnState *newPendingState = writeStates->pendingState;
    ASSERT_TRUE(newOutdatedState == oldCurrentState);
    ASSERT_TRUE(newCurrentState == oldPendingState);
    ASSERT_TRUE(newPendingState == NULL);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_WRITE_PENDING_STATE_TC002
* @title  Observe the change of the write record layer status before and after the server sends the CCS message.
* @precon  nan
* @brief  1. Use the default configuration items to configure the server to stop the server in the TRY_RECV_FINISH
state. Expected result 1 is obtained.
*         2. Record the states at the write record layer on the client. Expected result 2 is obtained.
*         3. Reconnect the server. Expected result 3 is obtained.
*         4. Check the states of the write record layer after the client is reconnected. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
*         2. The outdatedState field is empty.
*         3. The return value for reconnection is HITLS_REC_NORMAL_IO_BUSY.
*         4. OutdatedState is the previous currentState.
*            currentState is the previous pendingState.
*            The pendingState field is empty.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_WRITE_PENDING_STATE_TC002()
{
    /* Use the default configuration items to configure the server to stop the server in the TRY_RECV_FINISH state. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = false;
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    testInfo.needStopBeforeRecvCCS = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Record the states at the write record layer on the client. */
    RecConnStates *writeStates = (RecConnStates *)&(testInfo.server->ssl->recCtx->writeStates);
    RecConnState *oldOutdatedState = writeStates->outdatedState;
    RecConnState *oldCurrentState = writeStates->currentState;
    RecConnState *oldPendingState = writeStates->pendingState;
    ASSERT_TRUE(oldOutdatedState == NULL);

    // Reconnect the server.
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_IO_BUSY);

    /* Check the states of the write record layer after the client is reconnected. */
    RecConnState *newOutdatedState = writeStates->outdatedState;
    RecConnState *newCurrentState = writeStates->currentState;
    RecConnState *newPendingState = writeStates->pendingState;
    ASSERT_TRUE(newOutdatedState == oldCurrentState);
    ASSERT_TRUE(newCurrentState == oldPendingState);
    ASSERT_TRUE(newPendingState == NULL);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_MASTEKEY_TC001
* @title  Check whether the master key changes before and after the client initiates renegotiation.
* @precon  nan
* @brief  1. Use the default configuration items to configure the server so that the connection is successfully
established. Expected result 1 is obtained.
*         2. Simulate link establishment and check the TLS_Ctx and CM_State on both ends. Expected result 2 is obtained.
*         3. Obtain the current session from the client. Expected result 3 is obtained.
*         4. Obtain the masterKey from the session ID of the client. Expected result 4 is obtained.
*         5. The server sends a Hello Request message. Expected result 5 is obtained.
*         6. Reconnect the client and retransmit data on the server. Expected result 6 is obtained.
*         7. Obtain the new masterKey based on the client session ID and compare it with the old masterKey. Expected
result 7 is obtained.
* @expect 1. The initialization is successful.
*         2. The link is set up successfully. TLS_Ctx is not empty and CM_State is Transporting.
*         3. The session is not empty.
*         4. Obtained successfully.
*         5. The message is sent successfully.
*         6. The connection is successful.
*         7. The data is obtained successfully and the comparison is consistent.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RENEGOTIATION_MASTEKEY_TC001()
{
    /* Use the default configuration items to configure the server so that the connection is successfully established.
     */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = true;
    testInfo.isSupportRenegotiation = true;
    testInfo.state = HS_STATE_BUTT;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Simulate link establishment and check the TLS_Ctx and CM_State on both ends. */
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_TRANSPORTING);

    /* Obtain the current session from the client. */
    HITLS_Session *session = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(session != NULL);

    /* Obtain the masterKey from the session ID of the client. */
    uint8_t masterkey1[MAX_MASTER_KEY_SIZE] = {0};
    uint32_t masterkey1Len = MAX_MASTER_KEY_SIZE;
    ASSERT_TRUE(HITLS_SESS_GetMasterKey(session, masterkey1, &masterkey1Len) == HITLS_SUCCESS);

    /* The server sends a Hello Request message. */
    ASSERT_TRUE(HITLS_Renegotiate(testInfo.server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(testInfo.server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);

    /* Reconnect the client and retransmit data on the server. */
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_RENEGOTIATION);
    ASSERT_EQ(FRAME_CreateRenegotiationState(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(testInfo.client->ssl->state, CM_STATE_TRANSPORTING);

    /* Obtain the new masterKey based on the client session ID and compare it with the old masterKey. */
    uint8_t masterkey2[MAX_MASTER_KEY_SIZE] = {0};
    uint32_t masterkey2Len = MAX_MASTER_KEY_SIZE;
    HITLS_Session *session2 = HITLS_GetDupSession(testInfo.client->ssl);
    uint32_t masterkeylen = HITLS_SESS_GetMasterKeyLen(session2);
    ASSERT_TRUE(HITLS_SESS_GetMasterKey(session2, masterkey2, &masterkey2Len) == HITLS_SUCCESS);
    ASSERT_TRUE(memcmp(masterkey1, masterkey2, masterkeylen) != 0);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    HITLS_SESS_Free(session);
    HITLS_SESS_Free(session2);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_SEQ_NUM_TC001
* @title  Check whether the sequence number in the record layer in the FINISH message sent by the server or client is 0.
* @precon  nan
* @brief  1. Configure the client/server to stay in the TRY_SEND_FINISH state. Expected result 1 is obtained.
*         2. Connect the server and client once and send the message. Expected result 2 is obtained.
*         3. Obtain the messages sent by the server or client. Expected result 3 is obtained.
*         4. Parse the message sent by the local end into the hs_msg structure. Expected result 4 is obtained.
*         5. Check the sequence number in the sent message. Expected result 5 is obtained.
*         6. Enable the local end to transmit data to the peer end. Expected result 6 is obtained.
*         7. Obtain the messages received by the peer end. Expected result 7 is obtained.
*         8. Parse the message received by the peer end into the hs_msg structure. Expected result 8 is obtained.
*         9. Check the sequence number in the received message. Expected result 5 is obtained.
* @expect 1. The initialization is successful.
*         2. If the server is successfully connected, the client returns NORMAL_RECV_BUF_EMPTY.
*         3. The sending length is not null.
*         4. The parsing is successful, and the message header length is fixed to 5 bytes (TLS1.2).
*         5. The serial number is zero.
*         6. The transmission is successful.
*         7. The received length is not empty.
*         8. The parsing succeeds and the message header length is fixed to 5 bytes (TLS1.2).
*         9. The serial number is zero.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SEQ_NUM_TC001(int isClient)
{
    /* Configure the client/server to stay in the TRY_SEND_FINISH state. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isClient = isClient;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Connect the server and client once and send the message. */
    if (isClient) {
        ASSERT_TRUE(HITLS_Connect(testInfo.client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    } else {
        ASSERT_TRUE(HITLS_Accept(testInfo.server->ssl) == HITLS_SUCCESS);
    }

    /* Obtain the messages sent by the server or client. */
    BSL_UIO *sendIo = isClient ? testInfo.client->io : testInfo.server->io;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(sendIo);
    uint8_t *sendBuf = ioUserData->sndMsg.msg;
    uint32_t sendLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sendLen != 0);

    /* Parse the message sent by the local end into the hs_msg structure. */
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, sendBuf, sendLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == REC_TLS_RECORD_HEADER_LEN);

    /* Check the sequence number in the sent message. */
    uint8_t seqBuf[REC_CONN_SEQ_SIZE] = {0};
    ASSERT_TRUE(memcpy_s(seqBuf, sendLen, sendBuf + REC_TLS_RECORD_HEADER_LEN, REC_CONN_SEQ_SIZE) == 0);
    uint64_t seq = BSL_ByteToUint64(seqBuf);
    ASSERT_EQ(seq, 0u);

    /* Enable the local end to transmit data to the peer end. */
    if (isClient) {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    }

    /* Obtain the messages received by the peer end. */
    BSL_UIO *recvIo = isClient ? testInfo.server->io : testInfo.client->io;
    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(recvIo);
    uint8_t *recvBuf = ioUserData2->recMsg.msg;
    uint32_t recvLen = ioUserData2->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    /* Parse the message received by the peer end into the hs_msg structure. */
    uint32_t parseLen2 = 0;
    FRAME_Msg frameMsg2 = { 0 };
    FRAME_Type frameType2 = { 0 };
    frameType2.versionType = HITLS_VERSION_TLS12;
    frameType2.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType2, recvBuf, recvLen, &frameMsg2, &parseLen2) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen2 == REC_TLS_RECORD_HEADER_LEN);

    /* Check the sequence number in the received message. */
    ASSERT_TRUE(memset_s(seqBuf, REC_CONN_SEQ_SIZE, 0, REC_CONN_SEQ_SIZE) == 0);
    ASSERT_TRUE(memcpy_s(seqBuf, recvLen, recvBuf + REC_TLS_RECORD_HEADER_LEN, REC_CONN_SEQ_SIZE) == 0);
    uint64_t seq2 = BSL_ByteToUint64(seqBuf);
    ASSERT_EQ(seq2, 0u);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_CleanMsg(&frameType2, &frameMsg2);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_SEQ_NUM_TC002
* @title  Check whether the sequence number in the record layer in the FINISH message sent by the server/client is 0.
* @precon  nan
* @brief  1. Configure the client/server to the status that the handshake is successful. Expected result 1 is obtained.
*         2. Check the server/client connection status. Expected result 2 is obtained.
*         3. Randomly generate 32 bytes of data to be transmitted. Expected result 3 is obtained.
*         4. Write app data. Expected result 4 is obtained.
          5. Obtain data from the I/O sent by the local end and parse the header and content. Expected result 5 is
obtained.
          6. Check the sequence number in the sent message. Expected result 6 is obtained.
          7. Perform I/O data transmission from the local end to the peer end. Expected result 7 is obtained.
          8. Obtain data from the received I/O from the peer end and parse the header and content. Expected result 8 is
obtained.
          9. Check the sequence number in the received message. Expected result 9 is obtained.
* @expect 1. The initialization is successful.
*         2. The link status is Transferring.
          3. The generation is successful.
          4. The writing is successful.
          5. The parsing is successful, and the value of RecordType is REC_TYPE_APP.
          6. The SN is 1.
          7. The transmission is successful.
          8. The parsing is successful, and the value of RecordType is REC_TYPE_APP.
          9. The serial number is 1.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SEQ_NUM_TC002(int isClient)
{
    /* Configure the client/server to the status that the handshake is successful. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.state = HS_STATE_BUTT;
    testInfo.isClient = isClient;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);
    /* Check the server/client connection status. */
    ASSERT_TRUE(testInfo.client->ssl->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(testInfo.server->ssl->state == CM_STATE_TRANSPORTING);

    /* Randomly generate 32 bytes of data to be transmitted. */
    uint8_t transportData[REC_CONN_SEQ_SIZE * 4] = {0};
    uint32_t transportDataLen = sizeof(transportData) / sizeof(uint8_t);
    ASSERT_EQ(RandBytes(transportData, transportDataLen), HITLS_SUCCESS);
    /* Write app data. */
    HITLS_Ctx *localSsl = isClient ? testInfo.client->ssl : testInfo.server->ssl;
    uint32_t writeLen;
    ASSERT_EQ(APP_Write(localSsl, transportData, transportDataLen, &writeLen), HITLS_SUCCESS);

    /* Obtain data from the I/O sent by the local end and parse the header and content. */
    BSL_UIO *sendIo = isClient ? testInfo.client->io : testInfo.server->io;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(sendIo);
    uint8_t *sendBuf = ioUserData->sndMsg.msg;
    uint32_t sendLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sendLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, sendBuf, sendLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == REC_TLS_RECORD_HEADER_LEN);
    ASSERT_TRUE(FRAME_ParseMsgBody(&frameType, sendBuf + parseLen, sendLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameType.recordType, REC_TYPE_APP);

    /* Check the sequence number in the sent message. */
    uint8_t seqBuf[REC_CONN_SEQ_SIZE] = {0};
    ASSERT_TRUE(memcpy_s(seqBuf, sendLen, sendBuf + REC_TLS_RECORD_HEADER_LEN, REC_CONN_SEQ_SIZE) == 0);
    uint64_t seq = BSL_ByteToUint64(seqBuf);
    ASSERT_EQ(seq, 1u);

    /* Perform I/O data transmission from the local end to the peer end. */
    if (isClient) {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    }

    /* Obtain data from the received I/O from the peer end and parse the header and content. */
    BSL_UIO *recvIo = isClient ? testInfo.server->io : testInfo.client->io;
    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(recvIo);
    uint8_t *recvBuf = ioUserData2->recMsg.msg;
    uint32_t recvLen = ioUserData2->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen2 = 0;
    FRAME_Msg frameMsg2 = { 0 };
    FRAME_Type frameType2 = { 0 };
    frameType2.versionType = HITLS_VERSION_TLS12;
    frameType2.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType2, recvBuf, recvLen, &frameMsg2, &parseLen2) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen2 == REC_TLS_RECORD_HEADER_LEN);
    ASSERT_TRUE(FRAME_ParseMsgBody(&frameType2, recvBuf + parseLen2, recvLen, &frameMsg2, &parseLen2) == HITLS_SUCCESS);
    ASSERT_EQ(frameType.recordType, REC_TYPE_APP);

    /* Check the sequence number in the received message. */
    ASSERT_TRUE(memset_s(seqBuf, REC_CONN_SEQ_SIZE, 0, REC_CONN_SEQ_SIZE) == 0);
    ASSERT_TRUE(memcpy_s(seqBuf, recvLen, recvBuf + REC_TLS_RECORD_HEADER_LEN, REC_CONN_SEQ_SIZE) == 0);
    uint64_t seq2 = BSL_ByteToUint64(seqBuf);
    ASSERT_EQ(seq2, 1u);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_CleanMsg(&frameType2, &frameMsg2);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC001
* @title After initialization, the server receives a CCS message after sending the serverhellodone message and expects
to return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server, and disable peer verification on the server.
Expected result 1 is obtained.
*         2. The client initiates a TLS link application. After sending the Server Hello Done message, the server
constructs a CCS message and sends it to the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The server sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC001(void)
{
    /* Use the default configuration on the client and server, and disable peer verification on the server. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
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

    /* The client initiates a TLS link application. After sending the Server Hello Done message, the server constructs a
     * CCS message and sends it to the server. */
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC002
* @title After initialization, the client receives a CCS message after sending a client hello message and expects to
return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server, and disable peer verification on the server.
Expected result 1 is obtained.
*         2. The client initiates a TLS link application. After sending the client hello message, the client constructs
a CCS message and sends it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC002(void)
{
    /* Use the default configuration on the client and server, and disable peer verification on the server. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
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

    /* The client initiates a TLS link application. After sending the client hello message, the client constructs a CCS
     * message and sends it to the client. */
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC003
* @title During link establishment, the client receives the serverhello message after sending the CCS and expects to
return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server, and disable peer verification on the server.
Expected result 1 is obtained.
*         2. The client initiates a TLS link application. After sending the CCS, the client constructs a serverhello
message and sends it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC003(void)
{
    /* Use the default configuration on the client and server, and disable peer verification on the server. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_SEND_CHANGE_CIPHER_SPEC;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = false;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);
    testInfo.client->ssl->hsCtx->state = TRY_RECV_FINISH;

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
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

    /* The client initiates a TLS link application. After sending the CCS, the client constructs a serverhello message
     * and sends it to the client. */
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC004
* @title After initialization, construct an app message and send it to the client. The expected alert is returned.
* @precon  nan
* @brief  1. Use the default configuration on the client and server, and disable the peer end verification function on
the server. Expected result 1 is obtained.
*         2. When the client initiates a TLS link application request, construct an APP message and send it to the
client in the RECV_SERVER_HELLO message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC004(void)
{
    /* Use the default configuration on the client and server, and disable the peer end verification function on the
     * server. */
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = true;
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportClientVerify = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == 0);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len),
        EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    /* When the client initiates a TLS link application request, construct an APP message and send it to the client in
     * the RECV_SERVER_HELLO message. */
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

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
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC005
* @title After the link is set up, the client receives the serverhello message when receiving the app data. The client
is expected to return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server, and disable peer verification on the server.
Expected result 1 is obtained.
*         2. The client initiates a TLS link request. After the handshake succeeds, construct a serverhello message and
send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC005(void)
{
    /* Use the default configuration on the client and server, and disable peer verification on the server. */
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    /* The client initiates a TLS link request. After the handshake succeeds, construct a serverhello message and send
     * it to the client. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC006
* @title After the link is established, renegotiation is not enabled. The server receives a client hello message and is
expected to return an alert message.
* @precon  nan
* @brief  1. Use the default configuration on the client and server. Expected result 1 is obtained.
*         2. After the client initiates a TLS link request and handshakes successfully, construct a client hello message
and send it to the server. Expected result 2 is displayed.
* @expect 1. The initialization is successful.
*         2. The server sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC006(void)
{
    /* Use the default configuration on the client and server. */
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    /* After the client initiates a TLS link request and handshakes successfully, construct a client hello message and
     * send it to the server. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_INVALID_PROTOCOL_VERSION);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC007
* @title After initialization, construct an app message and send it to the server. The expected alert is returned.
* @precon  nan
* @brief  1. Use the default configuration on the client and server, and disable the peer end verification function on
the server. Expected result 1 is obtained.
*         2. When the client initiates a TLS link application request, construct an APP message and send it to the
server in the RECV_CLIENT_HELLO message on the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The server sends an ALERT message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_UNEXPECT_RECODETYPE_TC007(void)
{
    /* Use the default configuration on the client and server, and disable the peer end verification function on the
     * server. Expected result 1 is obtained. */
    FRAME_Msg parsedAlert = { 0 };
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = false;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportClientVerify = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == 0);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, len, appdata, sizeof(appdata)), EOK);
    ASSERT_EQ(memcpy_s(data + sizeof(appdata), len - sizeof(appdata), ioUserData->recMsg.msg, ioUserData->recMsg.len),
        EOK);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, ioUserData->recMsg.len + sizeof(appdata)), EOK);
    ioUserData->recMsg.len += sizeof(appdata);

    /* When the client initiates a TLS link application request, construct an APP message and send it to the server in
     * the RECV_CLIENT_HELLO message on the server. */
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(sndBuf, sndLen, &parsedAlert, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(parsedAlert.recType.data, REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_RECV_APPDATA_TC001
* @title  Before the first handshake, no app message is received.
* @precon  nan
* @brief  During the first handshake, the client/server receives the app message when expecting to receive the finish
message. The expected handshake fails and the handshake is interrupted.
* @expect  1. Return a failure message and interrupt the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HANDSHAKE_RECV_APPDATA_TC001(int isClient)
{
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    HandshakeTestInfo testInfo = { 0 };
    testInfo.isClient = isClient;
    testInfo.state = TRY_RECV_FINISH;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == 0);

    FrameUioUserData *ioUserData =
        isClient ? BSL_UIO_GetUserData(testInfo.client->io) : BSL_UIO_GetUserData(testInfo.server->io);

    uint8_t data[MAX_RECORD_LENTH] = {0};
    /* application data record header construction
      17 - type is 0x17 (application data)
      03 03 - protocol version is "3,3" (TLS 1.2)
      00 02 - 2 bytes of application data follows */
    uint8_t appdataRecordHeader[] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01};
    ASSERT_EQ(memcpy_s(data, MAX_RECORD_LENTH, appdataRecordHeader, sizeof(appdataRecordHeader)), EOK);
    ASSERT_EQ(memcpy_s(data + sizeof(appdataRecordHeader), MAX_RECORD_LENTH - sizeof(appdataRecordHeader),
        ioUserData->recMsg.msg, ioUserData->recMsg.len),
        EOK);
    uint32_t constructLen = ioUserData->recMsg.len + sizeof(appdataRecordHeader);
    ASSERT_EQ(memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, constructLen), EOK);
    ioUserData->recMsg.len = constructLen;
    /* During the first handshake, the client/server receives the app message when expecting to receive the finish
     * message. */
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, isClient, HS_STATE_BUTT),
        HITLS_REC_BAD_RECORD_MAC);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */



/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC001
* @title  Send a hello request when the link status is CM_STATE_IDLE.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a HelloRequest message and send it to the client. The client invokes the HITLS_Connect interface
to receive the message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the HelloRequest message, the client ignores the message and stays in the
TRY_RECV_SERVER_HELLO state after sending the ClientHello message.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC001(void)
{
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TLS_IDLE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;

    FRAME_Init();

    /* Use the configuration items to configure the client and server. */
    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(testInfo.config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    // Construct a HelloRequest message and send it to the client.
    ASSERT_TRUE(SendHelloReq(testInfo.server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(testInfo.client->ssl->hsCtx->state == TRY_RECV_SERVER_HELLO);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC002
* @title  The server sends a Hello Request message after the client sends the client hello message.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a HelloRequest message and send it to the client. The client invokes the HITLS_Connect interface
to receive the message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the HelloRequest message, the client ignores the message and stays in the
TRY_RECV_SERVER_HELLO state.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC002(void)
{
    /* Use the configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_SEND_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);

    /*  Construct a HelloRequest message and send it to the client.  */
    ASSERT_TRUE(SendHelloReq(testInfo.server->ssl) == HITLS_SUCCESS);
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC003
* @title  The server sends a Hello Request message when preparing to send CCS messages.
* @precon  nan
* @brief  1. Use configuration items to configure the client and server. Expected result 1 is obtained.
*         2. The client invokes HITLS_Connect in the Try_SEND_FINISH phase. Expected result 2 is obtained.
*         3. Construct a HelloRequest message and send it to the client. The client invokes HITLS_Connect to receive the
message. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends a FINISH message, changes the status to TRY_RECV_NEW_SESSION_TICKET, and returns
HITLS_REC_NORMAL_RECV_BUF_EMPTY.
*         3. After receiving the HelloRequest message, the client ignores the message and stays in the
TRY_RECV_NEW_SESSION_TICKET state.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC003(void)
{
    /* Use configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_SEND_FINISH;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    /* The client invokes HITLS_Connect in the Try_SEND_FINISH phase. */
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);

    /* Construct a HelloRequest message and send it to the client. The client invokes HITLS_Connect to receive the
     * message. */
    ASSERT_TRUE(SendHelloReq(testInfo.server->ssl) == HITLS_SUCCESS);
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
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC004
* @title  The server sends a hello request when the link status is CM_STATE_TRANSPORTING.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. The server sends a hello request to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends the ALERT_NO_RENEGOTIATION message successfully, but the client can continue sending and
receiving data.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    /* Use the configuration items to configure the client and server. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    /* The server sends a hello request to the client. */
    ASSERT_TRUE(SendHelloReq(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->sndMsg.len = 1;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTING);

    ioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(server->ssl->state == CM_STATE_TRANSPORTING);

    uint8_t data[] = "Hello World";
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(server->ssl, data, sizeof(data), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_SUCCESS);
    ASSERT_TRUE(readLen == sizeof(data) && memcmp(data, readBuf, readLen) == 0);

    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);
EXIT:
    CleanRecordBody(&recvframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC005
* @title  The server sends a hello request when the link status is CM_STATE_RENEGOTIATION.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server to support renegotiation. Expected result 1
is displayed.
*         2. After the link is established, the client sends a Hello Request message. The client receives the
renegotiation request message and is in the renegotiation state. At this time, the server sends a Hello Request message
again. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The expected message is sent successfully but is ignored.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    /* Use the configuration items to configure the client and server to support renegotiation. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    /* After the link is established, the client sends a Hello Request message. The client receives the renegotiation
     * request message and is in the renegotiation state. At this time, the server sends a Hello Request message again.
     */
    ASSERT_TRUE(SendHelloReq(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->sndMsg.len = 1;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_RENEGOTIATION);

    ioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_RENEGOTIATION);
    ASSERT_TRUE(client->ssl->hsCtx->state = TRY_SEND_CLIENT_HELLO);

    ASSERT_TRUE(SendHelloReq(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(client->ssl->hsCtx->state = TRY_RECV_SERVER_HELLO);

EXIT:
    CleanRecordBody(&recvframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC006
* @title  Enable the client and server to support renegotiation. After the connection between the client and server is
established, the client and server send a Hello Request message.
* @precon  nan
* @brief  1. Configure the client and server to support renegotiation. Expected result 1 is displayed.
*         2. After the link is established, the server sends the Hello Request message successfully.
* @expect 1. The initialization is successful.
*         2. The client enters the renegotiation state and sends client hello.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };

    /* Configure the client and server to support renegotiation. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    /* After the link is established, the server sends the Hello Request message successfully. */
    ASSERT_TRUE(SendHelloReq(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->sndMsg.len = 1;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_RENEGOTIATION);

    ioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_RENEGOTIATION);
    ASSERT_TRUE(client->ssl->hsCtx->state = TRY_SEND_CLIENT_HELLO);

EXIT:
    CleanRecordBody(&recvframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC007
* @title  The server receives a Hello Request message after sending the server hello done message.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. After sending a Server Hello Done message, the server receives a Hello Request message. Expected result 2
is obtained.
* @expect 1. The initialization is successful.
*         2. The server sends an ALERT. The level is ALERT_LEVEL_FATAL, and the description is
ALERT_UNEXPECTED_MESSAGE.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC007(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg parsedAlert = { 0 };
    testInfo.state = TRY_SEND_SERVER_HELLO_DONE;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusParkWithSuite(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);

    /* After sending a Server Hello Done message, the server receives a Hello Request message. */
    ASSERT_TRUE(SendHelloReq(testInfo.client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(sndBuf, sndLen, &parsedAlert, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(parsedAlert.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC008
* @title  The server sends a Hello Request message after sending the finish message. The renegotiation is successful.
The server sends a Hello Request message again. The renegotiation is successful.
* @precon  nan
* @brief  1. Configure the client and server to support renegotiation. Expected result 1 is displayed.
*         2. Send a Hello Request message after the server sends a finish message. Expected result 2 is obtained.
*         3. The server sends a Hello Request message again. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
*         2. The renegotiation succeeds.
*         3. The client ignores the Hello Request message and continues the renegotiation.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_HELLO_REQUEST_TC008(void)
{
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_FINISH;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;

    FRAME_Init();

    /* Configure the client and server to support renegotiation. */
    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;
    testInfo.config->isSupportRenegotiation = true;

    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, testInfo.state) ==
        HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(testInfo.client);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_TRANSPORTING);

    /* Send a Hello Request message after the server sends a finish message. */
    ASSERT_TRUE(SendHelloReq(testInfo.server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->sndMsg.len = 1;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_RENEGOTIATION);
    ASSERT_TRUE(testInfo.client->ssl->hsCtx->state = TRY_SEND_CLIENT_HELLO);

    /* The server sends a Hello Request message again. */
    ASSERT_TRUE(SendHelloReq(testInfo.server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(testInfo.client->ssl->hsCtx->state = TRY_RECV_SERVER_HELLO);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_HELLO_VERSION_TC001
* @title  Check the TLS protocol version carried in the clientHello message.
* @precon  nan
* @brief  1. Use configuration items to configure the client and server. Set the maximum version number of the client to
TLS1.2 and the minimum version number to TLS1.1. Expected result 1 is obtained.
*         2. Obtain and parse the client Hello message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The protocol version carried in the client Hello message is TLS1.2.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_HELLO_VERSION_TC001(void)
{
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;

    FRAME_Init();

    /* Use configuration items to configure the client and server. Set the maximum version number of the client to
     * TLS1.2 and the minimum version number to TLS1.1. */
    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    testInfo.config->minVersion = HITLS_VERSION_TLS11;
    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.config->minVersion = HITLS_VERSION_TLS12;
    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, testInfo.state) ==
        HITLS_SUCCESS);
    /* Obtain and parse the client Hello message. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    uint32_t parseLen = 0;

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientMsg->version.data == HITLS_VERSION_TLS12);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_NOT_SUPPORT_SERVER_VERSION_TC001
* @title  The client does not support the version selected by the server.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. After receiving the Server Hello message, the client changes the TLS version field in the serverhello
message to DTLS1.2 and sends the message to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message. The level is ALERT_ LEVEL_FATAL and the description is
ALERT_PROTOCOL_VERSION.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_NOT_SUPPORT_SERVER_VERSION_TC001(void)
{
    /* Use the configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* After receiving the Server Hello message, the client changes the TLS version field in the serverhello message to
     * DTLS1.2 and sends the message to the client. */
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    serverMsg->version.data = HITLS_VERSION_DTLS12;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

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
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_PROTOCOL_VERSION);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_SERVER_CHOSE_VERSION_TC001
* @title  Check the TLS protocol version carried in the serverHello message.
* @brief  1. Use the configuration items to configure the client and server. Set the maximum version number of the
client to TLS1.3 and the minimum version number to TLS1.1,
*            Set the maximum version number of the server to TLS1.2 and the minimum version number to TLS1.1. Expected
result 1 is obtained.
*         2. Obtain and parse the server Hello message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The protocol version carried in the server Hello message is TLS1.2.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SERVER_CHOSE_VERSION_TC001(void)
{
    /* Use the configuration items to configure the client and server.
       Set the maximum version number of the client to TLS1.3 and the minimum version number to TLS1.1;
       Set the maximum version number of the server to TLS1.2 and the minimum version number to TLS1.1. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;

    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    testInfo.config->maxVersion = HITLS_VERSION_TLS13;
    testInfo.config->minVersion = HITLS_VERSION_TLS11;
    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);

    testInfo.config->maxVersion = HITLS_VERSION_TLS12;
    testInfo.config->minVersion = HITLS_VERSION_TLS11;
    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, testInfo.state) ==
        HITLS_SUCCESS);
    /* Obtain and parse the server Hello message. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    uint32_t parseLen = 0;

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->version.data == HITLS_VERSION_TLS12);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_DEFAULT_SIGNATURE_EXTENSION_TC001
* @title  HITLS If no signature algorithm is specified, select the default algorithm and check whether the extension is
carried.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Check whether the client Clienet Hello message carries the signature algorithm extension.
* @expect 1. The initialization is successful.
*         2. Expected carrying expansion

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_DEFAULT_SIGNATURE_EXTENSION_TC001(void)
{
    /* Use the configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Check whether the client Clienet Hello message carries the signature algorithm extension. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientMsg->signatureAlgorithms.exState == INITIAL_FIELD);
    ASSERT_TRUE(&frameMsg.body.handshakeMsg.body.clientHello.extension.flag.haveSignatureAlgorithms);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_HELLO_WITHOUT_SIGNATURE_TC001
* @title  Default processing logic of the signature algorithm
* @precon  nan
* @brief  1. Use configuration items to configure the client and server, and set the client and service cipher suite to
HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. Expected result 1 is obtained.
*         2. Modify the client hello message so that the message does not carry the signature algorithm extension. Then,
the link is established. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The signature algorithm in the server key exchange message sent by the server is
CERT_SIG_SCHEME_ECDSA_SHA1.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_HELLO_WITHOUT_SIGNATURE_TC001(void)
{
    /* Use configuration items to configure the client and server, and set the client and service cipher suite to
     * HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;

    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(testInfo.config, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t)),
        HITLS_SUCCESS);

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    ASSERT_TRUE(StatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Modify the client hello message so that the message does not carry the signature algorithm extension. Then, the
     * link is established. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->signatureAlgorithms.exState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    testInfo.state = TRY_RECV_SERVER_KEY_EXCHANGE;
    testInfo.isClient = true;
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, testInfo.state),
        HITLS_SUCCESS);

    ASSERT_EQ(testInfo.client->ssl->hsCtx->state, TRY_RECV_SERVER_KEY_EXCHANGE);

    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf2 = ioUserData2->recMsg.msg;
    uint32_t recvLen2 = ioUserData2->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf2, recvLen2, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerKeyExchangeMsg *serverMsg = &frameMsg.body.hsMsg.body.serverKeyExchange;
    ASSERT_EQ(serverMsg->keyEx.ecdh.signAlgorithm.data, CERT_SIG_SCHEME_ECDSA_SHA1);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_HELLO_WITHOUT_SIGNATURE_TC002
* @title  Default processing logic of the signature algorithm
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server, and set the client and service cipher suite
to HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA. Expected result 1 is obtained.
*         2. Modify the client hello message so that the message does not carry the signature algorithm extension. Then,
the link is established. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The signature algorithm in the server keyexchange message sent by the server is
CERT_SIG_SCHEME_RSA_PKCS1_SHA1.

@ */

/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_HELLO_WITHOUT_SIGNATURE_TC002(void)
{
    /* Use the configuration items to configure the client and server, and set the client and service cipher suite to
     * HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;

    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA};
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(testInfo.config, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t)),
        HITLS_SUCCESS);

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    ASSERT_TRUE(StatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Modify the client hello message so that the message does not carry the signature algorithm extension. Then, the
     * link is established. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->signatureAlgorithms.exState = MISSING_FIELD;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    testInfo.state = TRY_RECV_SERVER_KEY_EXCHANGE;
    testInfo.isClient = true;
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, testInfo.state),
        HITLS_SUCCESS);

    ASSERT_EQ(testInfo.client->ssl->hsCtx->state, TRY_RECV_SERVER_KEY_EXCHANGE);

    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf2 = ioUserData2->recMsg.msg;
    uint32_t recvLen2 = ioUserData2->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_KEY_EXCHANGE;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf2, recvLen2, &frameMsg, &parseLen) == HITLS_SUCCESS);
    FRAME_ServerKeyExchangeMsg *serverMsg = &frameMsg.body.hsMsg.body.serverKeyExchange;
    ASSERT_EQ(serverMsg->keyEx.ecdh.signAlgorithm.data, CERT_SIG_SCHEME_RSA_PKCS1_SHA1);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECODE_VERSION_TC001
* @title  server can receive any version field in the recordheader of the client hello.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Change the version field in the recod header of the client hello message to 0x03ff.
* @expect 1. The initialization is successful.
*         2. The server can process the message normally and enter the next state.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECODE_VERSION_TC001(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;

    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo.config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    ASSERT_TRUE(StatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen != 5);
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == 5);

    /* Change the version field in the recod header of the client hello message to 0x03ff. */
    frameMsg.recVersion.data = 0x0300;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, recvBuf, recvLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(testInfo.server->ssl->hsCtx->state, TRY_SEND_CERTIFICATE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECODE_VERSION_TC002
* @title  server can receive any version field in the recordheader of the client hello.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Change the version field in the recod header of the client hello message to 0x03ff.
* @expect 1. The initialization is successful.
*         2. The server can process the message normally and enter the next state.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECODE_VERSION_TC002(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;

    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo.config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    ASSERT_TRUE(StatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen != 5);
    ASSERT_TRUE(FRAME_ParseMsgHeader(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(parseLen == 5);

    /* Change the version field in the recod header of the client hello message to 0x03ff. */
    frameMsg.recVersion.data = 0x03ff;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, recvBuf, recvLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(testInfo.server->ssl->hsCtx->state, TRY_SEND_CERTIFICATE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECODE_VERSION_TC003
* @title  server can receive any version field in the recordheader of the client hello message.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Change the version field in the recod header of the client hello message to 0x0399.
* @expect 1. The initialization is successful.
*         2. The server can process the message normally and enter the next state.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECODE_VERSION_TC003(void)
{
    /* Use the default configuration items to configure the client and server. */
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;

    FRAME_Init();

    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo.config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    testInfo.config->isSupportExtendMasterSecret = testInfo.isSupportExtendMasterSecret;
    testInfo.config->isSupportClientVerify = testInfo.isSupportClientVerify;
    testInfo.config->isSupportNoClientCert = testInfo.isSupportNoClientCert;

    ASSERT_TRUE(StatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);

    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    // The record length must be greater than or equal to 5 bytes.
    ASSERT_TRUE(parseLen >= 5);
    ASSERT_TRUE(FRAME_ParseTLSRecordHeader(recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    // The length of the record header must be 5 bytes.
    ASSERT_TRUE(parseLen == 5);

    /* Change the version field in the recod header of the client hello message to 0x0399. */
    frameMsg.recVersion.data = 0x0399;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, recvBuf, recvLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(testInfo.server->ssl->hsCtx->state, TRY_SEND_CERTIFICATE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* Define a new structure,
Construct the SH message with the signatureAlgorithms extension added,
Actually, the SH message should not contain the signatureAlgorithms.
*/
typedef struct {
    FRAME_Integer version;           /* Version number */
    FRAME_Array8 randomValue;        /* Random number */
    FRAME_Integer sessionIdSize;     /* session ID length */
    FRAME_Array8 sessionId;          /* session ID */
    FRAME_Integer cipherSuite;       /* Cipher suite */
    FRAME_Integer compressionMethod; /* Compression method */
    FRAME_Integer extensionLen;      /* Total length of the extension. */

    FRAME_HsExtArray8 pointFormats;         /* dot format */
    FRAME_HsExtArray8 extendedMasterSecret; /* extended master key */
    FRAME_HsExtArray8 secRenego;            /* security renegotiation */
    FRAME_HsExtArray8 sessionTicket;        /* sessionTicket */

    FRAME_HsExtArray16 signatureAlgorithms; /* algorithm signature */
} FRAME_ServerHelloMsg_WithSignatureAlgorithms;

void SetServerHelloMsgWithSignatureAlgorithms(FRAME_ServerHelloMsg_WithSignatureAlgorithms *destMsg,
    const FRAME_ServerHelloMsg *serverMsg)
{
    destMsg->version = serverMsg->version;
    destMsg->randomValue = serverMsg->randomValue;
    destMsg->sessionIdSize = serverMsg->sessionIdSize;
    destMsg->sessionId = serverMsg->sessionId;
    destMsg->cipherSuite = serverMsg->cipherSuite;
    destMsg->compressionMethod = serverMsg->compressionMethod;
    destMsg->extensionLen = serverMsg->extensionLen;

    destMsg->pointFormats = serverMsg->pointFormats;
    destMsg->extendedMasterSecret = serverMsg->extendedMasterSecret;
    destMsg->secRenego = serverMsg->secRenego;
    destMsg->sessionTicket = serverMsg->sessionTicket;
}

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_SERVER_HELLO_ADD_SIGNATURE_TC001
* @title  The server attempts to send the signatureAlgorithms extension.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server, and obtain the clientHello and serverHello
respectively. Expected result 1 is obtained.
*         2. Define a new structure, load the serverHello into the new structure, add the signatureAlgorithms extension
from the clientHello, and send the extension to the client.
* @expect 1. The initialization is successful.
*         2. The client sends an ALERT message. The level is ALERT_ LEVEL_FATAL and the description is
ALERT_UNSUPPORTED_EXTENSION.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_SERVER_HELLO_ADD_SIGNATURE_TC001(void)
{
    /* Use the configuration items to configure the client and server, and obtain the clientHello and serverHello
     * respectively. */
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData_c = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvSHbuf = ioUserData_c->recMsg.msg;
    uint32_t recvSHbufLen = ioUserData_c->recMsg.len;
    ASSERT_TRUE(recvSHbufLen != 0);

    uint32_t parsedSHlen = 0;
    FRAME_Msg parsedSH = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvSHbuf, recvSHbufLen, &parsedSH, &parsedSHlen) == HITLS_SUCCESS);

    HandshakeTestInfo testInfo2 = { 0 };
    testInfo2.state = TRY_RECV_CLIENT_HELLO;
    testInfo2.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo2) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData_s = BSL_UIO_GetUserData(testInfo2.server->io);
    uint8_t *recvCHbuf = ioUserData_s->recMsg.msg;
    uint32_t recvCHbufLen = ioUserData_s->recMsg.len;
    ASSERT_TRUE(recvCHbufLen != 0);

    /* Define a new structure, load the serverHello into the new structure, add the signatureAlgorithms extension from
     * the clientHello, and send the extension to the client. */
    uint32_t parsedCHlen = 0;
    FRAME_Msg parsedCH = { 0 };
    FRAME_Type frameType2 = { 0 };
    SetFrameType(&frameType2, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType2, recvCHbuf, recvCHbufLen, &parsedCH, &parsedCHlen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *chMsg = &parsedCH.body.hsMsg.body.clientHello;
    ASSERT_TRUE(chMsg->signatureAlgorithms.exState == INITIAL_FIELD);
    FRAME_ServerHelloMsg *shMsg = &parsedSH.body.hsMsg.body.serverHello;

    FRAME_ServerHelloMsg_WithSignatureAlgorithms shWithSigAlgExt;
    SetServerHelloMsgWithSignatureAlgorithms(&shWithSigAlgExt, shMsg);

    uint32_t sigAlgNum = chMsg->signatureAlgorithms.exData.size;
    uint16_t *chSigAlgData = chMsg->signatureAlgorithms.exData.data;
    uint32_t chSigAlgDataSize = sigAlgNum * sizeof(uint16_t);
    memcpy_s(&shWithSigAlgExt.signatureAlgorithms, sizeof(FRAME_HsExtArray16), &(chMsg->signatureAlgorithms),
        sizeof(FRAME_HsExtArray16));
    shWithSigAlgExt.signatureAlgorithms.exData.data = calloc(sigAlgNum, sizeof(uint16_t));
    memcpy_s(shWithSigAlgExt.signatureAlgorithms.exData.data, chSigAlgDataSize, chSigAlgData, chSigAlgDataSize);
    memcpy_s(&parsedSH.body.hsMsg.body.serverHello, sizeof(FRAME_ServerHelloMsg_WithSignatureAlgorithms),
        &shWithSigAlgExt, sizeof(FRAME_ServerHelloMsg_WithSignatureAlgorithms));

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSH, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData_c->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_PARSE_UNSUPPORTED_EXTENSION);

    ioUserData_c = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *sndBuf_c = ioUserData_c->sndMsg.msg;
    uint32_t sndBufLen_c = ioUserData_c->sndMsg.len;
    ASSERT_TRUE(sndBufLen_c != 0);

    uint32_t parsedAlertLen = 0;
    FRAME_Msg parsedAlert = { 0 };
    ASSERT_TRUE(FRAME_ParseTLSNonHsRecord(sndBuf_c, sndBufLen_c, &parsedAlert, &parsedAlertLen) == HITLS_SUCCESS);

    ASSERT_TRUE(parsedAlert.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &parsedAlert.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_UNSUPPORTED_EXTENSION);

EXIT:
    FRAME_CleanMsg(&frameType, &parsedSH);
    FRAME_CleanMsg(&frameType2, &parsedCH);
    FRAME_CleanNonHsRecord(REC_TYPE_ALERT, &parsedAlert);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo2.client);
    FRAME_FreeLink(testInfo2.server);
    HITLS_CFG_FreeConfig(testInfo2.config);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

void Test_RenegoWrapperFunc(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.body.clientHello.secRenego.exState, INITIAL_FIELD);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}


void Test_RenegoRemoveExtension(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    ASSERT_EQ(parseLen, *len);
    frameMsg.body.hsMsg.body.clientHello.secRenego.exState = MISSING_FIELD;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}


int32_t g_writeRet;
uint32_t g_writeLen;
bool g_isUseWriteLen;
uint8_t g_writeBuf[REC_TLS_RECORD_HEADER_LEN + REC_MAX_CIPHER_TEXT_LEN];
int32_t STUB_MethodWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    (void)uio;

    if (memcpy_s(g_writeBuf, sizeof(g_writeBuf), buf, len) != EOK) {
        return BSL_MEMCPY_FAIL;
    }

    *writeLen = len;
    if (g_isUseWriteLen) {
        *writeLen = g_writeLen;
    }
    return g_writeRet;
}

int32_t g_readRet;
uint32_t g_readLen;
uint8_t g_readBuf[REC_TLS_RECORD_HEADER_LEN + REC_MAX_CIPHER_TEXT_LEN + 1];
int32_t STUB_MethodRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    (void)uio;

    if (g_readLen != 0 && memcpy_s(buf, len, g_readBuf, g_readLen) != EOK) {
        return BSL_MEMCPY_FAIL;
    }

    *readLen = g_readLen;
    return g_readRet;
}

int32_t g_ctrlRet;
BSL_UIO_CtrlParameter g_ctrlCmd;
int32_t STUB_MethodCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    (void)larg;
    (void)uio;
    (void)param;
    if ((int32_t)g_ctrlCmd == cmd) {
        return g_ctrlRet;
    }

    return BSL_SUCCESS;
}

HITLS_Config *g_tlsConfig = NULL;
HITLS_Ctx *g_tlsCtx = NULL;
BSL_UIO *g_uio = NULL;
int32_t TlsCtxNew(BSL_UIO_TransportType type)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    const BSL_UIO_Method *ori = NULL;
    switch (type) {
        case BSL_UIO_TCP:
#ifdef HITLS_BSL_UIO_TCP
            ori = BSL_UIO_TcpMethod();
#endif
            break;
        default:
#ifdef HITLS_BSL_UIO_SCTP
            ori = BSL_UIO_SctpMethod();
#endif
            break;
    }

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    BSL_UIO_Method method = { 0 };
    memcpy(&method, ori, sizeof(method));
    method.uioWrite = STUB_MethodWrite;
    method.uioRead = STUB_MethodRead;
    method.uioCtrl = STUB_MethodCtrl;

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);
    BSL_UIO_SetInit(uio, 1);
    ASSERT_TRUE(HITLS_SetUio(ctx, uio) == HITLS_SUCCESS);

    /* Default value of stub function */
    g_writeRet = HITLS_SUCCESS;
    g_writeLen = 0;
    g_isUseWriteLen = false;

    g_readLen = 0;
    g_readRet = HITLS_SUCCESS;

    g_tlsConfig = config;
    g_tlsCtx = ctx;
    g_uio = uio;
    return HITLS_SUCCESS;
EXIT:
    BSL_UIO_Free(uio);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    return HITLS_INTERNAL_EXCEPTION;
}

void TlsCtxFree(void)
{
    BSL_UIO_Free(g_uio);
    HITLS_Free(g_tlsCtx);
    HITLS_CFG_FreeConfig(g_tlsConfig);

    g_uio = NULL;
    g_tlsCtx = NULL;
    g_tlsConfig = NULL;
}

#define BUFFER_SIZE 128
#define UT_AEAD_NONCE_SIZE 12u    /* AEAD nonce is fixed to 12. */
#define UT_AEAD_TAG_LENGTH 16

ALERT_Level g_alertLevel;
ALERT_Description g_alertDescription;
void STUB_SendAlert(const TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    (void)ctx;
    g_alertLevel = level;
    g_alertDescription = description;
    return;
}

typedef struct {
    REC_Type type;
    uint16_t version;
    uint64_t epochSeq;
    uint16_t bodyLen;
    uint8_t *body;
} RecordMsg;

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession; /* Set the session to the client for session recovery. */
} ResumeTestInfo;

static uint8_t *g_sessionId;
static uint32_t g_sessionIdSize;

int32_t NewConfig(ResumeTestInfo *testInfo)
{
    /* Construct the configuration. */
    switch (testInfo->version) {
        case HITLS_VERSION_DTLS12:
            testInfo->config = HITLS_CFG_NewDTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            testInfo->config = HITLS_CFG_NewTLS13Config();
            break;
        case HITLS_VERSION_TLS12:
            testInfo->config = HITLS_CFG_NewTLS12Config();
            break;
        default:
            break;
    }

    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }


    HITLS_CFG_SetClientVerifySupport(testInfo->config, true);
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    HITLS_CFG_SetExtendedMasterSecretSupport(testInfo->config, true);
    HITLS_CFG_SetNoClientCertSupport(testInfo->config, true);
    HITLS_CFG_SetRenegotiationSupport(testInfo->config, true);
    HITLS_CFG_SetPskServerCallback(testInfo->config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(testInfo->config, (HITLS_PskClientCb)ExampleClientCb);
    return HITLS_SUCCESS;
}

static void FreeLink(ResumeTestInfo *testInfo)
{
    /* Release resources. */
    FRAME_FreeLink(testInfo->client);
    testInfo->client = NULL;
    FRAME_FreeLink(testInfo->server);
    testInfo->server = NULL;
}

int32_t GetSessionId(ResumeTestInfo *testInfo)
{
    FRAME_Type frameType = { 0 };
    FRAME_Msg recvframeMsg = { 0 };

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo->client->io);
    uint8_t *recMsg = ioUserData->recMsg.msg;
    uint32_t recMsgLen = ioUserData->recMsg.len;

    frameType.handshakeType = SERVER_HELLO;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.versionType = testInfo->version;
    uint32_t parseLen = 0;
    int32_t ret = FRAME_ParseMsg(&frameType, recMsg, recMsgLen, &recvframeMsg, &parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Save the sessionId in the serverhello. */
    FRAME_ServerHelloMsg *serverHello = &recvframeMsg.body.hsMsg.body.serverHello;
    g_sessionIdSize = serverHello->sessionIdSize.data;
    g_sessionId = BSL_SAL_Dump(serverHello->sessionId.data, g_sessionIdSize);

    FRAME_CleanMsg(&frameType, &recvframeMsg);
    return HITLS_SUCCESS;
}

int32_t FirstHandshake(ResumeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = 0;

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server, true, TRY_RECV_SERVER_HELLO);

    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Obtain the session ID for the first connection setup. */
    ret = GetSessionId(testInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* User data transmission */
    uint8_t data[] = "Hello World";
    uint32_t writeLen;
    ret = HITLS_Write(testInfo->server->ssl, data, sizeof(data), &writeLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = FRAME_TrasferMsgBetweenLink(testInfo->server, testInfo->client);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HITLS_Read(testInfo->client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    testInfo->clientSession = HITLS_GetDupSession(testInfo->client->ssl);

    FreeLink(testInfo);
    return HITLS_SUCCESS;
}

int32_t CmpClientHelloSessionId(ResumeTestInfo *testInfo)
{
    FRAME_Type frameType = { 0 };
    /* Obtain the client hello message received by the server. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo->server->io);
    uint8_t *recMsg = ioUserData->recMsg.msg;
    uint32_t recMsgLen = ioUserData->recMsg.len;
    uint32_t parseLen = 0;

    FRAME_Msg frameMsg = { 0 };
    frameType.versionType = testInfo->version;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;

    int32_t ret = FRAME_ParseMsg(&frameType, recMsg, recMsgLen, &frameMsg, &parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Compare the sessionId in the client hello with the saved sessionId. */
    FRAME_ClientHelloMsg *clienHello = &frameMsg.body.hsMsg.body.clientHello;
    if (clienHello->sessionIdSize.data != g_sessionIdSize) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memcmp(clienHello->sessionId.data, g_sessionId, g_sessionIdSize) != 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    FRAME_CleanMsg(&frameType, &frameMsg);
    CONN_Deinit(testInfo->server->ssl);
    HITLS_Accept(testInfo->server->ssl);
    FRAME_TrasferMsgBetweenLink(testInfo->server, testInfo->client);
    return HITLS_SUCCESS;
}

int32_t CmpSessionId(ResumeTestInfo *testInfo)
{
    FRAME_Type frameType = { 0 };
    FRAME_Msg recvframeMsg = { 0 };
    /* Obtain the server hello message received by the client. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo->client->io);
    uint8_t *recMsg = ioUserData->recMsg.msg;
    uint32_t recMsgLen = ioUserData->recMsg.len;

    frameType.handshakeType = SERVER_HELLO;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.versionType = testInfo->version;
    /* Parse the server hello message. */
    uint32_t parseLen = 0;
    int32_t ret = FRAME_ParseMsg(&frameType, recMsg, recMsgLen, &recvframeMsg, &parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Check whether the received serverhello message is consistent with the saved one. */
    FRAME_ServerHelloMsg *serverHello = &recvframeMsg.body.hsMsg.body.serverHello;
    if (serverHello->sessionIdSize.data != g_sessionIdSize) {
        FRAME_CleanMsg(&frameType, &recvframeMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memcmp(serverHello->sessionId.data, g_sessionId, g_sessionIdSize) != 0) {
        FRAME_CleanMsg(&frameType, &recvframeMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }

    FRAME_CleanMsg(&frameType, &recvframeMsg);
    return HITLS_SUCCESS;
}

int32_t TryResumeBySessionId(ResumeTestInfo *testInfo)
{
    int32_t ret;
    testInfo->client = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (testInfo->clientSession != NULL) {
        ret = HITLS_SetSession(testInfo->client->ssl, testInfo->clientSession);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server, false, TRY_RECV_CLIENT_HELLO);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = CmpClientHelloSessionId(testInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = CmpSessionId(testInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* User data transmission */
    uint8_t data[] = "Hello World";
    uint32_t writeLen;
    ret = HITLS_Write(testInfo->server->ssl, data, sizeof(data), &writeLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = FRAME_TrasferMsgBetweenLink(testInfo->server, testInfo->client);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return HITLS_Read(testInfo->client->ssl, readBuf, READ_BUF_SIZE, &readLen);
}


int32_t TryResumeByTheUsingSessionId(ResumeTestInfo *testInfo)
{
    int32_t ret;
    testInfo->client = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (testInfo->clientSession != NULL) {
        ret = HITLS_SetSession(testInfo->client->ssl, testInfo->clientSession);
        if (ret != HITLS_SUCCESS) {
            goto ERR;
        }
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->server == NULL) {
        ret = HITLS_INTERNAL_EXCEPTION;
        goto ERR;
    }

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server, false, TRY_RECV_CLIENT_HELLO);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    ret = CmpClientHelloSessionId(testInfo);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    ret = CmpSessionId(testInfo);
    if (ret != HITLS_SUCCESS) {
        ret = HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID;
        goto ERR;
    }

    return HITLS_SUCCESS;

ERR:
    /* Clean up allocated resources on error */
    FRAME_FreeLink(testInfo->client);
    testInfo->client = NULL;
    FRAME_FreeLink(testInfo->server);
    testInfo->server = NULL;
    return ret;
}

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_MULTILINK_RESUME_ALERT_TC001
* @title  Test the scenario where the session recovers.
* @precon  nan
* @brief  1. First handshake between the client and server. Save the session ID. Expected result 1 is obtained.
          2. Obtain the client session and set the session to the client that performs the next handshake. Expected
result 2 is obtained.
          3. Perform the second handshake between the client and server. Expected result 3 is obtained.
          4. Use the same session ID on the client and server to restore the session. Expected result 4 is obtained.
* @expect 1. A success message is returned.
          2. A success message is returned.
          3. The session is restored successfully.
          4. The session fails.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_MULTILINK_RESUME_ALERT_TC001(int uioType, int version)
{
    g_sessionId = NULL;
    g_sessionIdSize = 0;
    FRAME_Init();

    ResumeTestInfo testInfo01 = { 0 };
    testInfo01.version = (uint16_t)version;
    testInfo01.uioType = (BSL_UIO_TransportType)uioType;

    /* First handshake between the client and server. Save the session ID. */
    ASSERT_EQ(NewConfig(&testInfo01), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTicketSupport(testInfo01.config, false);
    ASSERT_EQ(FirstHandshake(&testInfo01), HITLS_SUCCESS);

    /* Obtain the client session and set the session to the client that performs the next handshake. */
    ASSERT_TRUE(testInfo01.clientSession != NULL);
    ASSERT_EQ(TryResumeBySessionId(&testInfo01), HITLS_SUCCESS);

    ResumeTestInfo testInfo02 = { 0 };
    testInfo02.version = (uint16_t)version;
    testInfo02.uioType = (BSL_UIO_TransportType)uioType;
    /* Perform the second handshake between the client and server. */
    ASSERT_EQ(NewConfig(&testInfo02), HITLS_SUCCESS);
    HITLS_CFG_SetSessionTicketSupport(testInfo02.config, false);

    /* Use the same session ID on the client and server to restore the session. */
    testInfo02.clientSession = testInfo01.clientSession;
    ASSERT_EQ(TryResumeByTheUsingSessionId(&testInfo02), HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);
    ASSERT_TRUE(testInfo02.clientSession != NULL);

EXIT:
    FreeLink(&testInfo01);
    /* testInfo02: TryResumeByTheUsingSessionId expected to fail and clean up internally */
    BSL_SAL_FREE(g_sessionId);
    HITLS_CFG_FreeConfig(testInfo01.config);
    HITLS_SESS_Free(testInfo01.clientSession);

    HITLS_CFG_FreeConfig(testInfo02.config);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC001
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a connection between the client and server. Expected result 1 is obtained.
*         2. The client closes the link, obtains the message sent by the client, and checks whether the message is a
close_notify message. (Expected result 2)
*         3. The server obtains the received message and checks whether the message is a close_notify message. (Expected
result 3)
* @expect 1. The link is successfully established.
*         2. The client sends a close_notify message.
*         3. The server receives the close_notify message.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    /* Establish a connection between the client and server. */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_KEY_EXCHANGE);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    /* The client closes the link, obtains the message sent by the client, and checks whether the message is a
     * close_notify message. */
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = { 0 };
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    /* The server obtains the received message and checks whether the message is a close_notify message. */
    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = { 0 };
    uint8_t *serverbuffer = serverioUserData->recMsg.msg;
    uint32_t serverreadLen = serverioUserData->recMsg.len;
    uint32_t serverparseLen = 0;
    ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC002
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a connection between the client and server. Expected result 1 is obtained.
*         2. Close the link on the client, obtain the message sent by the client, and check whether the message is a
close_notify message. (Expected result 2)
*         3. The server processes the message received by the server, obtains the message to be sent after processing,
and checks whether the message is a close_notify message. (Expected result 3)
* @expect 1. The link is successfully established.
*         2. The client sends a close_notify message.
*         3. The server sends a close_notify message.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    /* Establish a connection between the client and server. */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_KEY_EXCHANGE);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    /* Close the link on the client, obtain the message sent by the client, and check whether the message is a
     * close_notify message. */
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = { 0 };
    uint8_t *clientbuffer = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen = clientioUserData->sndMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    /* The server processes the message received by the server, obtains the message to be sent after processing, and
     * checks whether the message is a close_notify message. */
    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = { 0 };
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
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_CM_LINK_FATAL_ALERTED);

    FRAME_Msg serverframeMsg1 = { 0 };
    uint8_t *serverbuffer1 = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen1 = serverioUserData->sndMsg.len;
    uint32_t serverparseLen1 = 0;
    ret = ParserTotalRecord(server, &serverframeMsg1, serverbuffer1, serverreadLen1, &serverparseLen1);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg1.type == REC_TYPE_ALERT && serverframeMsg1.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg1.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg1.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC003
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a connection between the client and server. Expected result 1 is obtained.
*         2. The server closes the link, obtains the message sent by the server, and checks whether the message is a
close_notify message. (Expected result 2)
*         3. Obtain the received message and check whether the message is a close_notify message. (Expected result 3)
* @expect 1. The link is successfully established.
*         2. The server sends a close_notify message.
*         3. The client receives the close_notify message.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    /* Establish a connection between the client and server. */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(server, client, false, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    /* The server closes the link, obtains the message sent by the server, and checks whether the message is a
     * close_notify message. */
    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = { 0 };
    uint8_t *serverbuffer = serverioUserData->sndMsg.msg;
    uint32_t serverreadLen = serverioUserData->sndMsg.len;
    uint32_t serverparseLen = 0;
    int32_t ret = ParserTotalRecord(server, &serverframeMsg, serverbuffer, serverreadLen, &serverparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(serverframeMsg.type == REC_TYPE_ALERT && serverframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(serverframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        serverframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    /* Obtain the received message and check whether the message is a close_notify message. */
    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg clientframeMsg = { 0 };
    uint8_t *clientbuffer = clientioUserData->recMsg.msg;
    uint32_t clientreadLen = clientioUserData->recMsg.len;
    uint32_t clientparseLen = 0;
    ret = ParserTotalRecord(client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_WARNING &&
        clientframeMsg.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC004
* @title  Close the link and check whether the close_notify alarm is sent.
* @precon  nan
* @brief  1. Establish a link between the client and server. Expected result 1 is obtained.
*         2. The server closes the link, obtains the message sent by the server, and checks whether the message is a
close_notify message. (Expected result 2)
*         3. The client processes the received message, obtains the message to be sent after processing, and checks
whether the message is a close_notify message. (Expected result 3)
* @expect 1. The link is successfully established.
*         2. The client sends a close_notify message.
*         3. The server sends a close_notify message.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CLOSE_NOTIFY_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    /* Establish a link between the client and server. */
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_KEY_EXCHANGE);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_KEY_EXCHANGE);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    /* The server closes the link, obtains the message sent by the server, and checks whether the message is a
     * close_notify message. */
    ASSERT_TRUE(HITLS_Close(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *serverioUserData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg serverframeMsg = { 0 };
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
    /* The client processes the received message, obtains the message to be sent after processing, and checks whether
     * the message is a close_notify message. */
    FRAME_Msg clientframeMsg = { 0 };
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
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    clientioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_IO_BUSY);
    clientioUserData->sndMsg.len = 0;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_CM_LINK_FATAL_ALERTED);
    FRAME_Msg clientframeMsg1 = { 0 };
    uint8_t *clientbuffer1 = clientioUserData->sndMsg.msg;
    uint32_t clientreadLen1 = clientioUserData->sndMsg.len;
    uint32_t clientparseLen1 = 0;
    ret = ParserTotalRecord(client, &clientframeMsg1, clientbuffer1, clientreadLen1, &clientparseLen1);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg1.type == REC_TYPE_ALERT);
    ASSERT_TRUE(clientframeMsg1.body.alertMsg.description == ALERT_CLOSE_NOTIFY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CM_CLOSE_SEND_ALERT_TC001
* @title  Disable the link abnormally and check whether the two ends send an alert.
* @precon  nan
* @brief  1. Establish a link between the client and server, and the client is disabling the link. Expected result 1 is
obtained.
*         2. Enable the client to send a critical alarm. Obtain the received message from the server and check whether
the message is an alert message. Expected result 2 is obtained.
* @expect 1. The link is successfully established and the client is in the closed state.
*         2. Check the alert message on the server.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CM_CLOSE_SEND_ALERT_TC001(void)
{
    HandshakeTestInfo testInfo = { 0 };
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = true;
    testInfo.isSupportNoClientCert = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Establish a link between the client and server, and the client is disabling the link. */
    FRAME_Msg parsedSHdone = { 0 };
    FRAME_Type frameType = { 0 };
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, SERVER_HELLO_DONE, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &parsedSHdone) == HITLS_SUCCESS);

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSHdone, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &parsedSHdone);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

    ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
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

    // Enable the client to send a critical alarm. Obtain the received message from the server and check whether the
    // message is an alert message.
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);
    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    FRAME_Msg clientframeMsg = { 0 };
    uint8_t *clientbuffer = clientioUserData->recMsg.msg;
    uint32_t clientreadLen = clientioUserData->recMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(testInfo.server, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_FATAL &&
        clientframeMsg.body.alertMsg.description == ALERT_UNEXPECTED_MESSAGE);


EXIT:
    FRAME_CleanMsg(&frameType, &parsedSHdone);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_CM_CLOSE_SEND_ALERT_TC002
* @title  Abnormally close the link and check whether the two ends send an alert.
* @precon  nan
* @brief  1. Establish a link between the client and server. The client is in the link disabling state. Expected result
1 is obtained.
*         2. Enable the client to send a critical alarm, obtain the received message from the server, and check whether
the message is an alert message. Expected result 2 is obtained.
* @expect 1. The link is successfully established and the client is in the closed state.
*         2. Check the alert message on the server.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_CM_CLOSE_SEND_ALERT_TC002(void)
{
    HandshakeTestInfo testInfo = { 0 };

    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    testInfo.isSupportExtendMasterSecret = true;
    testInfo.isSupportClientVerify = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    /* Establish a link between the client and server. The client is in the link disabling state. */
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
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

    // Enable the client to send a critical alarm, obtain the received message from the server, and check whether the
    // message is an alert message.
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client) == HITLS_SUCCESS);
    FrameUioUserData *clientioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    FRAME_Msg clientframeMsg = { 0 };
    uint8_t *clientbuffer = clientioUserData->recMsg.msg;
    uint32_t clientreadLen = clientioUserData->recMsg.len;
    uint32_t clientparseLen = 0;
    int32_t ret = ParserTotalRecord(testInfo.client, &clientframeMsg, clientbuffer, clientreadLen, &clientparseLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(clientframeMsg.type == REC_TYPE_ALERT && clientframeMsg.bodyLen == ALERT_BODY_LEN);
    ASSERT_TRUE(clientframeMsg.body.alertMsg.level == ALERT_LEVEL_FATAL &&
        clientframeMsg.body.alertMsg.description == ALERT_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_NO_CERTIFICATE_RESERVED_ALERT_TC001
* @title  The client receives the NO_CERTIFICATIONATE_RESERVED alarm.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. When the client stops receiving server hello, the server sends the NO_CERTIFICATIONATE_RESERVED alarm and
observe the response from the client.
* @expect 1. The initialization is successful.
*         2. The client ignores the message. The client should not receive the message.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_NO_CERTIFICATE_RESERVED_ALERT_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };
    FRAME_Msg sndframeMsg = { 0 };

    /* Use the default configuration items to configure the client and server. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_HELLO);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    /* When the client stops receiving server hello, the server sends the NO_CERTIFICATIONATE_RESERVED alarm and observe
     * the response from the client. */
    recvframeMsg.type = REC_TYPE_ALERT;
    recvframeMsg.version = HITLS_VERSION_TLS12;
    recvframeMsg.bodyLen = ALERT_BODY_LEN;
    recvframeMsg.epochSeq = GetEpochSeq(0, 5);
    recvframeMsg.body.alertMsg.level = ALERT_LEVEL_WARNING;
    recvframeMsg.body.alertMsg.description = ALERT_NO_CERTIFICATE_RESERVED;
    ASSERT_TRUE(PackFrameMsg(&recvframeMsg) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, recvframeMsg.buffer, recvframeMsg.len) == HITLS_SUCCESS);

    ioUserData->sndMsg.len = 0;
    ASSERT_TRUE(HITLS_Connect(clientTlsCtx) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    CleanRecordBody(&recvframeMsg);
    CleanRecordBody(&sndframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_NO_CERTIFICATE_RESERVED_ALERT_TC002
* @title  The client receives the NO_CERTIFICATIONATE_RESERVED alarm.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. When the server stops receiving the client keyexchange, the client sends the no_certificate_RESERVED alarm
and observe the message returned by the server.
* @expect 1. The initialization is successful.
*         2. The server ignores the message. The message cannot be received.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_NO_CERTIFICATE_RESERVED_ALERT_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };
    FRAME_Msg sndframeMsg = { 0 };

    /* Use the default configuration items to configure the client and server. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    /* When the server stops receiving the client keyexchange, the client sends the no_certificate_RESERVED alarm and
     * observe the message returned by the server. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
    recvframeMsg.type = REC_TYPE_ALERT;
    recvframeMsg.version = HITLS_VERSION_TLS12;
    recvframeMsg.bodyLen = ALERT_BODY_LEN;
    recvframeMsg.epochSeq = GetEpochSeq(0, 5);
    recvframeMsg.body.alertMsg.level = ALERT_LEVEL_WARNING;
    recvframeMsg.body.alertMsg.description = ALERT_NO_CERTIFICATE_RESERVED;
    ASSERT_TRUE(PackFrameMsg(&recvframeMsg) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, recvframeMsg.buffer, recvframeMsg.len) == HITLS_SUCCESS);

    ioUserData->sndMsg.len = 0;
    ASSERT_TRUE(HITLS_Accept(serverTlsCtx) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    CleanRecordBody(&recvframeMsg);
    CleanRecordBody(&sndframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_EXPORT_RESTRICTION_RESERVED_ALERT_TC001
* @title  The client receives an ERROR_RESTRICTION_RESERVED alarm.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. When the client stops receiving server hello, the server sends the export_restriction_RESERVED alarm.
* @expect 1. The initialization is successful.
*         2. The client ignores the message. The client should not receive the message.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_EXPORT_RESTRICTION_RESERVED_ALERT_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };
    FRAME_Msg sndframeMsg = { 0 };

    /* Use the default configuration items to configure the client and server. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    /* When the client stops receiving server hello, the server sends the export_restriction_RESERVED alarm. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_RECV_SERVER_HELLO);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    recvframeMsg.type = REC_TYPE_ALERT;
    recvframeMsg.version = HITLS_VERSION_TLS12;
    recvframeMsg.bodyLen = ALERT_BODY_LEN;
    recvframeMsg.epochSeq = GetEpochSeq(0, 5);
    recvframeMsg.body.alertMsg.level = ALERT_LEVEL_WARNING;
    recvframeMsg.body.alertMsg.description = ALERT_EXPORT_RESTRICTION_RESERVED;
    ASSERT_TRUE(PackFrameMsg(&recvframeMsg) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, recvframeMsg.buffer, recvframeMsg.len) == HITLS_SUCCESS);

    ioUserData->sndMsg.len = 0;
    ASSERT_TRUE(HITLS_Connect(clientTlsCtx) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    CleanRecordBody(&recvframeMsg);
    CleanRecordBody(&sndframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_EXPORT_RESTRICTION_RESERVED_ALERT_TC002
* @title  The client receives an ERROR_RESTRICTION_RESERVED alarm.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. When the server receives the client keyexchange, the client sends the export_restriction_RESERVED alarm,
             Check the message returned by the server. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The server ignores the message. The message cannot be received.

@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_EXPORT_RESTRICTION_RESERVED_ALERT_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = { 0 };
    FRAME_Msg sndframeMsg = { 0 };

    /* Use the default configuration items to configure the client and server. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    /* When the server receives the client keyexchange, the client sends the export_restriction_RESERVED alarm, check
     * the message returned by the server. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_KEY_EXCHANGE) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);

    recvframeMsg.type = REC_TYPE_ALERT;
    recvframeMsg.version = HITLS_VERSION_TLS12;
    recvframeMsg.bodyLen = ALERT_BODY_LEN;
    recvframeMsg.epochSeq = GetEpochSeq(0, 5);
    recvframeMsg.body.alertMsg.level = ALERT_LEVEL_WARNING;
    recvframeMsg.body.alertMsg.description = ALERT_EXPORT_RESTRICTION_RESERVED;
    ASSERT_TRUE(PackFrameMsg(&recvframeMsg) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(server->io, recvframeMsg.buffer, recvframeMsg.len) == HITLS_SUCCESS);

    ioUserData->sndMsg.len = 0;
    ASSERT_TRUE(HITLS_Accept(serverTlsCtx) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    CleanRecordBody(&recvframeMsg);
    CleanRecordBody(&sndframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS1_2_RFC5246_SERVER_CHOSE_VERSION_TC002
* @spec  -
* @title  Check the TLS protocol version carried in the serverHello message.
* @brief  1. Use the configuration items to configure the client and server. Change the record version in client hello
*         to 0x0305 Expected result 1 is obtained.
*         2. Obtain and parse the server Hello message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The protocol version carried in the server Hello message is TLS1.2.
* @prior  Level 1
* @auto  TRUE
@ */

/* BEGIN_CASE */
void UT_TLS1_2_RFC5246_SERVER_CHOSE_VERSION_TC002(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;

    recvBuf[2] = 0x05;
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->version.data == HITLS_VERSION_TLS12);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_CleanMsg(&frameType, &frameMsg);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_RENEGOTIATION_RECV_APP_TC001
* @spec  -
* @title  The client receives app after renegotiate request
* @precon  nan
* @brief  1. The client receives app after sending renegotiate request client hello
* @expect 1.clien read app message success
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_RENEGOTIATION_RECV_APP_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    HITLS_CFG_SetRenegotiationSupport(tlsConfig, true);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(clientTlsCtx) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_RENEGOTIATION);

    uint8_t data[] = "Hello World";
    uint32_t len;
    HITLS_Write(server->ssl, data, sizeof(data), &len);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_SUCCESS);
    ASSERT_TRUE(readLen == sizeof(data) && memcmp(data, readBuf, readLen) == 0);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_SEND_DATA_BEWTEEN_CCS_AND_FINISH
* @spec  -
* @title  The client receives a alert bewteen ccs and finish
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Server send a alert message bewteen ccs and finish. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. Client return HITLS_REC_ERR_DATA_BETWEEN_CCS_AND_FINISHED
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_SEND_DATA_BEWTEEN_CCS_AND_FINISH(void)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_FINISH), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ioUserData->sndMsg.len = 0;
    server->ssl->method.sendAlert(server->ssl, ALERT_LEVEL_FATAL, ALERT_CERTIFICATE_EXPIRED);
    ALERT_Flush(server->ssl);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_ERR_DATA_BETWEEN_CCS_AND_FINISHED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_Fragmented_Msg_FUNC_TC001
* @spec  -
* @title  The client receives a Fragmented_Msg during handshake
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Server send a Fragmented_Msg during handshake. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. Client return HITLS_REC_ERR_DATA_BETWEEN_CCS_AND_FINISHED
* @prior  Level 1
* @auto  TRUE
@ */
// To test whether fragmented messages can be received correctly. Test REC_TlsReadNbytes
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_Fragmented_Msg_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    int32_t ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(client->ssl->hsCtx->state == TRY_RECV_SERVER_HELLO);

    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(server->ssl->hsCtx->state == TRY_RECV_CLIENT_HELLO);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t dataLen = MAX_RECORD_LENTH;
    ASSERT_EQ(memcpy_s(data, MAX_RECORD_LENTH, ioUserData->sndMsg.msg, ioUserData->sndMsg.len), 0);
    dataLen = ioUserData->sndMsg.len;

    uint32_t msglength = BSL_ByteToUint16(&data[3]);
    uint32_t msgLen = (msglength - 1) / 2;
    uint32_t len = 5 + msgLen;

    uint8_t recorddata1[] = {0x16, 0x03, 0x03, 0x00, 0x46};

    BSL_Uint16ToByte((uint16_t)msgLen, &recorddata1[3]);
    ASSERT_EQ(memcpy_s(ioUserData->sndMsg.msg, MAX_RECORD_LENTH, data, len), 0);
    ASSERT_EQ(memcpy_s(ioUserData->sndMsg.msg, MAX_RECORD_LENTH, recorddata1, sizeof(recorddata1)), 0);

    uint8_t recorddata2[] = {0x16, 0x03, 0x03, 0x00, 0x53};
    msgLen = dataLen - len;
    BSL_Uint16ToByte((uint16_t)msgLen, &recorddata2[3]);
    ASSERT_EQ(memcpy_s(ioUserData->sndMsg.msg + len, MAX_RECORD_LENTH - len, recorddata2, sizeof(recorddata2)), 0);
    ioUserData->sndMsg.len = len + 5;
    ASSERT_EQ(memcpy_s(ioUserData->sndMsg.msg + ioUserData->sndMsg.len, MAX_RECORD_LENTH - len, data + len, dataLen - len), 0);
    ioUserData->sndMsg.len += dataLen - len;

    ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(ret == HITLS_REC_NORMAL_IO_BUSY);
    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(ret == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_READ_AFTER_CLOSE_TC001
* @spec  -
* @title  There is no alert during the handshake. When the handshake is halfway through, call close to break the chain,
* and then call hitls_read to read the plaintext app message. It is expected that the read message failed.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Stop the handshake state at TRY_RECV_SERVER_HELLO, expected result 2.
*         3. Call the hitls_close interface to break the chain, expected result 3.
*         4. Construct plaintext app message, call hitls_read to read, expected result 4.
* @expect 1. The initialization is successful.
*         2. Return successful.
*         3. Return successful.
*         4. Reading message failed.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_READ_AFTER_CLOSE_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t data[] = {0x17, 0x03, 0x03, 0x00, 0x0b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};
    memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, sizeof(data));
    ioUserData->recMsg.len = sizeof(data);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_CLOSED);
    ASSERT_TRUE(readLen == 0);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_READ_AFTER_CLOSE_TC002
* @spec  -
* @title  A fatal alert occurred during the handshake process. Call close to break the chain,
* and then call hitls_read to read the plaintext app message. It is expected that the read message failed.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Certificate and algorithm set do not match, establish connection, expected result 2.
*         3. Call the hitls_close interface to break the chain, expected result 3.
*         4. Construct plaintext app message, call hitls_read to read, expected result 4.
* @expect 1. The initialization is successful.
*         2. Send a fatal alert, ALERT_BAD_CERTIFICATE.
*         3. Return successful.
*         4. Reading message failed.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_READ_AFTER_CLOSE_TC002()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    uint16_t cipherSuits[] = {HITLS_RSA_WITH_AES_128_CBC_SHA256};
    HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    FRAME_CertInfo certInfo = {
        "rsa_sha512/root.der",
        "rsa_sha512/intca.der",
        "rsa_sha512/usageKeyEncipher.der",
        0,
        "rsa_sha512/usageKeyEncipher.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(tlsConfig, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    clientTlsCtx->config.tlsConfig.needCheckKeyUsage = true;
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_KEYUSAGE);

    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(client->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, ALERT_UNSUPPORTED_CERTIFICATE);
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t data[] = {0x17, 0x03, 0x03, 0x00, 0x0b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};
    memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, sizeof(data));
    ioUserData->recMsg.len = sizeof(data);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_CLOSED);
    ASSERT_TRUE(readLen == 0);
EXIT:
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

int32_t STUB_HS_DoHandshake_Warning(TLS_Ctx *ctx)
{
    ctx->method.sendAlert(ctx, ALERT_LEVEL_WARNING, ALERT_NO_CERTIFICATE_RESERVED);
    return HITLS_INTERNAL_EXCEPTION;
}

static int32_t UioWriteException(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    (void)buf;
    (void)len;
    (void)writeLen;
    return BSL_UIO_IO_EXCEPTION;
}

/* @
* @test  UT_TLS_TLS1_2_RFC5246_READ_AFTER_CLOSE_TC003
* @spec  -
* @title  During the handshake process, a warning alert occurred, and the construction of the alert failed to send. The
* status then changed to alerting, call close to break the chain, and then call hitls_read to read the plaintext app
* message. It is expected that the read message failed.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Suspend the sending of warning alerts, expected result 2.
*         3. Call the hitls_close interface to break the chain, expected result 3.
*         4. Construct plaintext app message, call hitls_read to read, expected result 4.
* @expect 1. The initialization is successful.
*         2. The status then changed to alerting.
*         3. Return successful.
*         4. Reading message failed.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_READ_AFTER_CLOSE_TC003()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    HITLS_CFG_SetRenegotiationSupport(tlsConfig, true);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_KEY_EXCHANGE) == HITLS_SUCCESS);
    STUB_REPLACE(HS_DoHandshake, STUB_HS_DoHandshake_Warning);;
    BSL_UIO *uio = HITLS_GetReadUio(clientTlsCtx);
    BSL_UIO_Method *method = (BSL_UIO_Method *)BSL_UIO_GetMethod(uio);
    ASSERT_EQ(BSL_UIO_SetMethod(method, BSL_UIO_WRITE_CB, UioWriteException), BSL_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(clientTlsCtx) == HITLS_REC_ERR_IO_EXCEPTION);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_ALERTING);

    ASSERT_EQ(BSL_UIO_SetMethod(method, BSL_UIO_WRITE_CB, FRAME_Write), BSL_SUCCESS);
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Close(clientTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_CLOSED);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t data[] = {0x17, 0x03, 0x03, 0x00, 0x0b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};
    memcpy_s(ioUserData->recMsg.msg, MAX_RECORD_LENTH, data, sizeof(data));
    ioUserData->recMsg.len = sizeof(data);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_CM_LINK_CLOSED);
    ASSERT_TRUE(readLen == 0);
EXIT:
    STUB_RESTORE(HS_DoHandshake);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_CLIENT_HELLO_ENCRYPT_THEN_MAC_TC001
* @spec  -
* @title  Check the encrypt then mac extension carried in the clientHello message.
* @precon  nan
* @brief  1. Use configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Obtain and parse the client Hello message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The  encrypt then mac extension carried in the client Hello message.
* @prior  Level 1
* @auto  TRUE
@ */

/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_CLIENT_HELLO_ENCRYPT_THEN_MAC_TC001(void)
{
    HandshakeTestInfo testInfo = { 0 };
    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };
    testInfo.state = TRY_RECV_CLIENT_HELLO;

    FRAME_Init();

    /* Use configuration items to configure the client and server. */
    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);
    ASSERT_EQ(testInfo.client->ssl->config.tlsConfig.isEncryptThenMac, 1);

    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(testInfo.server->ssl->config.tlsConfig.isEncryptThenMac, 1);

    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, testInfo.isClient, testInfo.state) ==
        HITLS_SUCCESS);
    /* Obtain and parse the client Hello message. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    uint32_t parseLen = 0;

    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientMsg->encryptThenMac.exType.data, HS_EX_TYPE_ENCRYPT_THEN_MAC);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_CLIENT_PSK_FUNC_TC001
* @spec  -
* @title  Client configured with PSK ciphersuite, without PSK callback, clienthello failed to be sent.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Set PSK ciphersuite, expected result 2
*         3. Call HITLS_Connect to start handshake, expected result 3
* @expect 1. The initialization is successful.
*         2. Return success.
*         3. Clienthello send failed, return HITLS_PACK_CLIENT_CIPHER_SUITE_ERR
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_CLIENT_PSK_FUNC_TC001()
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    uint16_t cipherSuits[] = {HITLS_RSA_PSK_WITH_AES_128_CBC_SHA};
    HITLS_CFG_SetCipherSuites(config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_PACK_CLIENT_CIPHER_SUITE_ERR);
    ASSERT_TRUE(client->ssl->hsCtx->state == TRY_SEND_CLIENT_HELLO);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS1_2_RFC5246_CLIENT_PSK_FUNC_TC002
* @spec  -
* @title  Client configured with PSK ciphersuite, with PSK callback, server use default config and with PSK callback
* configured. Handshake will success.
* @precon  nan
* @brief  1. Use the default configuration items to configure the client and server. Expected result 1
*         2. Set PSK ciphersuite to client and set psk callback to both client and server, expected result 2
*         3. Start handshake, expected result 3
* @expect 1. The initialization is successful.
*         2. Return success.
*         3. Handshake success.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS1_2_RFC5246_CLIENT_PSK_FUNC_TC002()
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetPskClientCallback(c_config, ExampleClientCb) == 0);
    ASSERT_TRUE(HITLS_CFG_SetPskServerCallback(s_config, ExampleServerCb) == 0);
    uint16_t cipherSuits[] = {HITLS_RSA_PSK_WITH_AES_128_CBC_SHA};
    HITLS_CFG_SetCipherSuites(c_config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */