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
/* INCLUDE_BASE test_suite_tls12_consistency_rfc5246_malformed_msg */
/* BEGIN_HEADER */

#include "hitls_error.h"
#include "tls.h"
#include "rec.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "frame_msg.h"

/* END_HEADER */

// Replace the message to be sent with the CERTIFICATION_VERIFY message.
void TEST_SendUnexpectCertificateVerifyMsg(void *msg, void *data)
{
    FRAME_Type *frameType = (FRAME_Type *)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    FRAME_Msg newFrameMsg = {0};
    HS_MsgType hsTypeTmp = frameType->handshakeType;
    REC_Type recTypeTmp = frameType->recordType;
    frameType->handshakeType = CERTIFICATE_VERIFY;
    FRAME_Init();  // Callback for changing the certificate algorithm, which is used to generate negotiation handshake
                   // messages.
    FRAME_GetDefaultMsg(frameType, &newFrameMsg);
    HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT);  // recovery callback
    // Release the original msg.
    frameType->handshakeType = hsTypeTmp;
    frameType->recordType = recTypeTmp;
    FRAME_CleanMsg(frameType, frameMsg);
    // Change message.
    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = CERTIFICATE_VERIFY;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    if (memcpy_s(msg, sizeof(FRAME_Msg), &newFrameMsg, sizeof(newFrameMsg)) != EOK) {
        Print("TEST_SendUnexpectCertificateMsg memcpy_s Error!");
    }
}

static void MalformedClientHelloMsgCallback_01(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;

    clientHello->version.state = SET_LEN_TO_ONE_BYTE;

    clientHello->randomValue.state = MISSING_FIELD;
    clientHello->sessionIdSize.state = MISSING_FIELD;
    clientHello->sessionId.state = MISSING_FIELD;
    clientHello->cookiedLen.state = MISSING_FIELD;
    clientHello->cookie.state = MISSING_FIELD;
    clientHello->cipherSuitesSize.state = MISSING_FIELD;
    clientHello->cipherSuites.state = MISSING_FIELD;
    clientHello->compressionMethodsLen.state = MISSING_FIELD;
    clientHello->compressionMethods.state = MISSING_FIELD;
    clientHello->extensionState = MISSING_FIELD;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC001
* @title version field only one byte _version
* @precon nan
* @brief
    1. The server stops receiving client information. 1. ClientHello exception: The version field in the constructed
    message to be sent contains only one byte and cannot be decoded. Expected result 1 is obtained.
* @expect 1. The processing result is HITLS_PARSE_INVALID_MSG_LEN.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC001(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    /* 1. The server stops receiving client information. 1. ClientHello exception: The version field in the constructed
     * message to be sent contains only one byte and cannot be decoded. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_01;

    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isExpectRet = true;
    testPara.expectRet = HITLS_PARSE_INVALID_MSG_LEN;

    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_02(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;

    clientHello->randomValue.size = 1;
    clientHello->randomValue.state = ASSIGNED_FIELD;

    clientHello->sessionIdSize.state = MISSING_FIELD;
    clientHello->sessionId.state = MISSING_FIELD;
    clientHello->cookiedLen.state = MISSING_FIELD;
    clientHello->cookie.state = MISSING_FIELD;
    clientHello->cipherSuitesSize.state = MISSING_FIELD;
    clientHello->cipherSuites.state = MISSING_FIELD;
    clientHello->compressionMethodsLen.state = MISSING_FIELD;
    clientHello->compressionMethods.state = MISSING_FIELD;
    clientHello->extensionState = MISSING_FIELD;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC002
* @title random Less than 32 bytes_random
* @precon nan
* @brief    1. The server stops receiving client hello messages. Expected result 1 is obtained.
            2. Modify the client to send the client hello message and change the random field to only one byte. Expected
            result 2 is obtained.
            3. The server continues to establish a link. (Expected result 3)
* @expect   1. Success
            2. Success
            3. Return a failure message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC002(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The server stops receiving client hello messages. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Modify the client to send the client hello message and change the random field to only one byte. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_02;

    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isExpectRet = true;
    testPara.expectRet = HITLS_PARSE_INVALID_MSG_LEN;
    /* 3. The server continues to establish a link. */
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback_03(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t sessionId[MAX_SESSION_ID_SIZE] = {0};
    ASSERT_TRUE(FRAME_ModifyMsgArray8(sessionId, MAX_SESSION_ID_SIZE, &clientHello->sessionId, NULL) == HITLS_SUCCESS);
    clientHello->sessionIdSize.data = 0u;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC003
* @titleThe session ID length of the clientHello message is 0 but the content is not null. _session ID
        length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. Expected result 2 is obtained.
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, and the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC003(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_03;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
     */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested. */
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_04(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t sessionId[MIN_SESSION_ID_SIZE - 1] = {0};
    FRAME_ModifyMsgArray8(sessionId, sizeof(sessionId), &clientHello->sessionId, &clientHello->sessionIdSize);
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC004
* @title    The length of the session ID in the clientHello message is smaller than the minimum length_session ID
            length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, and the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC004(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_04;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3.Check the status of the tested. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_05(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t sessionId[MAX_SESSION_ID_SIZE + 1] = {0};
    FRAME_ModifyMsgArray8(sessionId, sizeof(sessionId), &clientHello->sessionId, &clientHello->sessionIdSize);
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC005
* @title    The length of the session ID in the clientHello message exceeds the maximum length_session ID
            length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, and the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC005(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_05;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 3. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 4. Check the status of the tested. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback_06(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->cipherSuitesSize.data = 0;
    clientHello->cipherSuites.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC006
* @title    The length of the cipher suite in the clientHello message is 0 and the content is empty. _cipher suites
            length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC006(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_06;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested. */
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_07(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t rawData[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(
        rawData, sizeof(rawData) - 1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data -= 2;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC007
* @title    The length of the cipher suites in the clientHello message sent is an odd number_cipher suites
            length
* @precon nan
* @brief    1. The tested  functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested returns an alert message, and the status is alerted.
            4. The status of the test is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC007(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested  functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_07;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback_08(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->cipherSuitesSize.data = 0;
EXIT:
    return;
}

/* @
* @test SDV_HITLS_TEST_DTLS_MALFORMED_CLIENT_HELLO_MSG_FUN_TC010
* @title    The length of the cipher suite in the clientHello message is 0 but the content is not null. _cipher suites
            length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested returns an alert message, indicating that the status is alerted.
            4. The status of the test is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC008(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_08;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested. */
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_09(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->cipherSuites.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC009
* @title    The length of the cipher suite in the clientHello message is not 0 but the content is empty. _cipher suites
            length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested returns an alert message, and the status is alerted.
            4. The status of the test is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC009(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_09;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_10(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->cipherSuitesSize.data -= sizeof(uint16_t);
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC010
* @title    The length of the cipher suite in the sent clientHello message is less than the specific content
            length_cipher suites length
* @precon nan
* @brief    1. The tested functions as the client, and the tested functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested. Expected result 3 is obtained.
            4. Check the status of the test. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested returns an alert message, and the status is alerted.
            4. The status of the test is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC010(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested functions as the client, and the tested functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_10;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_11(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->cipherSuitesSize.data += sizeof(uint16_t);
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC011
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC011(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_11;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback_12(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->compressionMethodsLen.data = 0;
    clientHello->compressionMethods.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC012
* @title    The length of the compression list of the sent ClientHello message is 0 and the content is empty.
            _compression methods length
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC012(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_12;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test end. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested end. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_13(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t compressionMethods[] = {0, 1};
    FRAME_ModifyMsgArray8(compressionMethods, sizeof(compressionMethods),
        &clientHello->compressionMethods, &clientHello->compressionMethodsLen);
    clientHello->compressionMethodsLen.data--;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC013
* @title    The length of the compression list in the sent ClientHello message is less than the content
            length_compression methods length
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC013(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_13;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test end. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested end. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_14(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t compressionMethods[] = {0};
    FRAME_ModifyMsgArray8(compressionMethods, sizeof(compressionMethods),
        &clientHello->compressionMethods, &clientHello->compressionMethodsLen);
    clientHello->compressionMethodsLen.data++;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC014
* @title    The length of the compression list in the sent ClientHello message is greater than the content
            length_compression methods length
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC014(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_14;
    TestPara testPara = {0};
    testPara.port = PORT;
    /* 4. Check the status of the test end. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested end. */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_15(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t compressionMethods[] = {1};
    FRAME_ModifyMsgArray8(compressionMethods, sizeof(compressionMethods),
        &clientHello->compressionMethods, &clientHello->compressionMethodsLen);
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC015
* @title    The compression list of clientHello messages sent by the client does not contain compression algorithm
            _compression methods length
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC015(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    /* 1. The tested end functions as the client, and the tested end functions as the server. */
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_15;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested . */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_16(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->extensionLen.state = ASSIGNED_FIELD;
    clientHello->extensionLen.data--;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC016
* @title    The extended length of the clientHello message sent by the client is smaller than the actual message
            length_Total extended length
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC016(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_16;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback_17(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->extensionLen.state = ASSIGNED_FIELD;
    clientHello->extensionLen.data++;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC017
* @title    The extended length of the clientHello message sent by the client is greater than the actual message
            length_Total extended length
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC017(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_17;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback_18(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->pointFormats.exLen.state = ASSIGNED_FIELD;
    clientHello->pointFormats.exLen.data--;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC018
* @title    The extended length of the sent ClientHello message point format is smaller than the actual length_Extended
            point format
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
* prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC018(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_18;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_19(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->pointFormats.exLen.state = ASSIGNED_FIELD;
    clientHello->pointFormats.exLen.data++;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC019
* @title    The extended length of the sent ClientHello message point format is greater than the actual length_Extended
            point format
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC019(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_19;
    TestPara testPara = {0};
    testPara.port = PORT;
    //  4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_20(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->pointFormats.exDataLen.data = 0;
    clientHello->pointFormats.exData.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC020
* @title    The length of the sent ClientHello message is 0 and the content is empty. _ The dot format is extended
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC020(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_20;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_21(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->pointFormats.exDataLen.data = 1;
    clientHello->pointFormats.exData.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC021
* @title    The length of the point format of the clientHello message is not 0 and the content is null. _ The point
            format is extended
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC021(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_21;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_22(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->supportedGroups.exLen.data -= sizeof(uint16_t);
    clientHello->supportedGroups.exLen.state = ASSIGNED_FIELD;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC022
* @title   The length of the clientHello message that supports group extension is smaller than the actual length_Group
            extension is supported
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC022(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_22;
    TestPara testPara = {0};
    testPara.port = PORT;
    //  4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_23(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->supportedGroups.exLen.data += sizeof(uint16_t);
    clientHello->supportedGroups.exLen.state = ASSIGNED_FIELD;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC023
* @title    The length of the clientHello message that supports group extension is greater than the actual length._Group
            extension is supported
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC023(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_23;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_24(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->supportedGroups.exDataLen.data--;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC024
* @title    The clientHello message sent by the client supports the odd number of group lengths._Group extension is
            supported
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC024(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    //  1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_24;
    TestPara testPara = {0};
    testPara.port = PORT;
    //  4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_25(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->supportedGroups.exDataLen.data = 0;
    clientHello->supportedGroups.exData.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC025
* @title    The clientHello message can contain 0 characters and cannot contain any characters._Group extension is
            supported.
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC025(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_25;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    //  3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_26(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->signatureAlgorithms.exLen.state = ASSIGNED_FIELD;
    clientHello->signatureAlgorithms.exLen.data -= sizeof(uint16_t);
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC026
* @title        The extended signature algorithm length of the clientHello message is less than the actual
                length_signature algorithm extension
* @precon nan
* @brief        1. The tested end functions as the client, and the tested end functions as the server. Expected result 1
                is obtained.
                2. Obtain the message, modify the field content, and send the message. (Expected result 2)
                3. Check the status of the tested end. Expected result 3 is obtained.
                4. Check the status of the test end. Expected result 4 is obtained.
* @expect       1. A success message is returned.
                2. A success message is returned.
                3. The tested end returns an alert message, and the status is alerted.
                4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
                message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC026(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_26;
    TestPara testPara = {0};
    testPara.port = PORT;
    //  4. Check the status of the test.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_27(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->signatureAlgorithms.exLen.state = ASSIGNED_FIELD;
    clientHello->signatureAlgorithms.exLen.data += sizeof(uint16_t);
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC027
* @title    The extended signature algorithm length of the clientHello message is greater than the actual
            length_signature algorithm extension
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC027(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_27;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_28(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->signatureAlgorithms.exDataLen.data--;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC028
* @title    The signature algorithm length of the clientHello message sent by the client is an odd number_signature
            algorithm extension
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC028(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_28;
    TestPara testPara = {0};
    testPara.port = PORT;
    //  4. Check the status of the test.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_29(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->signatureAlgorithms.exDataLen.data = 0;
    clientHello->signatureAlgorithms.exData.state = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC029
* @title    The signature algorithm length of the clientHello message is 0 and the content is empty_signature algorithm
            extension
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. Expected result 2 is obtained.
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, and the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC029(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_29;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_30(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    uint8_t extendedMasterSecret[] = {0};
    FRAME_ModifyMsgArray8(extendedMasterSecret, sizeof(extendedMasterSecret),
        &clientHello->extendedMasterSecret.exData, NULL);
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC030
* @title    The length of the extended master key in the clientHello message is not 0_Extended master
            key
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC030(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_30;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_31(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->sessionTicket.exDataLen.state = ASSIGNED_FIELD;
    clientHello->sessionTicket.exDataLen.data--;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC031
* @title   The SessionTicket extension length of the clientHello message sent by the client is smaller than the actual
            length.
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
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC031(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_31;
    TestPara testPara = {0};
    testPara.isSupportSessionTicket = 1;
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_32(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->sessionTicket.exDataLen.state = ASSIGNED_FIELD;
    clientHello->sessionTicket.exDataLen.data++;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC032
* @title    The SessionTicket length of the clientHello message is greater than the actual length.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message in the alerted state.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC032(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_32;
    TestPara testPara = {0};
    testPara.isSupportSessionTicket = 1;
    testPara.port = PORT;
    //  4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_33(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->sessionTicket.exDataLen.data = 1;
    clientHello->sessionTicket.exDataLen.state = SET_LEN_TO_ONE_BYTE;
    clientHello->sessionTicket.exData.state = MISSING_FIELD;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC033
* @title    The SessionTicket length of the clientHello message is not zero and the content is empty.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns an alert message, indicating that the status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC033(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_33;
    TestPara testPara = {0};
    testPara.isSupportSessionTicket = 1;
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_34(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t rawData[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(
        rawData, sizeof(rawData) - 1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data -= 2;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC034
* @title    The extended length of the servername in the clientHello message is smaller than the actual length.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the tested end.Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC034(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_34;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the tested end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_35(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t rawData[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(
        rawData, sizeof(rawData) - 1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data += 2;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC035
* @title    The extended length of the servername in the clientHello message is greater than the actual length.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the tested end.Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC035(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_35;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the tested end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_36(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t rawData[4] = {0x00, 0x00, 0x01, 0x01};
    FRAME_ModifyMsgArray8(
        rawData, sizeof(rawData) - 1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data = 0;
    clientHello->serverName.exDataLen.data = 0;
EXIT:
    return;
}
/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC036
* @title    The extended length of the servername in the clientHello message is 0 and the content is not null.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the tested end.Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC036(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_36;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the tested end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_37(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = MISSING_FIELD;
    clientHello->serverName.exData.state = MISSING_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    clientHello->serverName.exLen.data = 0;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC037
* @title    The length of the servername extension in the clientHello message is 0 and the content is empty.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the tested end.Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC037(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_37;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the tested end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */
static void MalformedClientHelloMsgCallback_38(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->alpn.exState = INITIAL_FIELD;
    clientHello->alpn.exLen.state = ASSIGNED_FIELD;
    clientHello->alpn.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_APP_LAYER_PROTOCOLS, &clientHello->alpn.exType);
    uint8_t rawData[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(rawData, sizeof(rawData) - 1, &clientHello->alpn.exData, &clientHello->alpn.exDataLen);
    clientHello->alpn.exLen.data -= 2;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC038
* @title    The extended length of the servername in the clientHello message is smaller than the actual length.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the tested end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC038(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_38;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the tested end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    testPara.isSupportALPN = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_39(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->alpn.exState = INITIAL_FIELD;
    clientHello->alpn.exLen.state = ASSIGNED_FIELD;
    clientHello->alpn.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_APP_LAYER_PROTOCOLS, &clientHello->alpn.exType);
    uint8_t rawData[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(rawData, sizeof(rawData) - 1, &clientHello->alpn.exData, &clientHello->alpn.exDataLen);
    clientHello->alpn.exLen.data += 2;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC039
* @title    The extended length of the servername in the clientHello message is greater than the actual length.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. Return a success message.
            2. Return a success message.
            3. Return an alert message. The status of the tested end is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC039(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_39;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    testPara.isSupportALPN = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_40(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->alpn.exState = INITIAL_FIELD;
    clientHello->alpn.exLen.state = ASSIGNED_FIELD;
    clientHello->alpn.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_APP_LAYER_PROTOCOLS, &clientHello->alpn.exType);
    uint8_t rawData[4] = {0x02, 0x02, 0x01, 0x01};
    FRAME_ModifyMsgArray8(rawData, sizeof(rawData) - 1, &clientHello->alpn.exData, &clientHello->alpn.exDataLen);
    clientHello->alpn.exLen.data = 0;
    clientHello->alpn.exDataLen.data = 0;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC040
* @title    The extended length of the servername in the clientHello message is 0 and the content is not null.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the test end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC040(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    //  1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    /* 2. Obtain the message, modify the field content, and send the message. */
    handle.frameCallBack = MalformedClientHelloMsgCallback_40;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the test end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    testPara.isSupportALPN = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_41(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->alpn.exState = INITIAL_FIELD;
    clientHello->alpn.exLen.state = ASSIGNED_FIELD;
    clientHello->alpn.exDataLen.state = MISSING_FIELD;
    clientHello->alpn.exData.state = MISSING_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->alpn.exType);
    clientHello->alpn.exLen.data = 0;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC041
* @title    The extended length of the servername in the clientHello message is 0. The content is empty.
* @precon nan
* @brief    1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Obtain the message, modify the field content, and send the message. (Expected result 2)
            3. Check the status of the tested end. Expected result 3 is obtained.
            4. Check the status of the tested end. Expected result 4 is obtained.
* @expect   1. A success message is returned.
            2. A success message is returned.
            3. The tested end returns alert, and the status is alert.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC041(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    // 1. The tested end functions as the client, and the tested end functions as the server.
    handle.expectHsType = CLIENT_HELLO;
    // 2. Obtain the message, modify the field content, and send the message.
    handle.frameCallBack = MalformedClientHelloMsgCallback_41;
    TestPara testPara = {0};
    testPara.port = PORT;
    // 4. Check the status of the tested end.
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    // 3. Check the status of the tested end.
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendedMasterSecret = true;
    testPara.isSupportALPN = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_42(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->extendedMasterSecret.exType.data = 0xFFFFu;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC042
* @title The sent ClientHello message contains an unrecognized extension type _ extension type
* @precon nan
* @brief    1. The tested end functions as the client and the tested end functions as the server. Expected result 1 is
            obtained.
            2. Capture the message, modify the field content, and send the message. Expected result 2 is obtained.
            3. Check the status of the tested end. Expected result 3 is obtained. 4. Check the status of the tested end.
            Expected result 4 is obtained.
* @expect 1. A success message is returned. 2. A success message is returned. 3. The tested end returns alert and the
            status is alerted.
            4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello
            message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC042(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback_42;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_FINISH;
    testPara.expectDescription = ALERT_DECRYPT_ERROR;
    testPara.isSupportExtendedMasterSecret = false;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback_43(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;

    clientHello->extensionState = MISSING_FIELD;
    clientHello->pointFormats.exState = MISSING_FIELD;
    clientHello->supportedGroups.exState = MISSING_FIELD;
    clientHello->signatureAlgorithms.exState = MISSING_FIELD;
    clientHello->extendedMasterSecret.exState = MISSING_FIELD;
    clientHello->secRenego.exState = MISSING_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC043
* @title The sent ClientHello message does not contain any extension type.
* @precon nan
* @brief    1. The server stops receiving client hello messages. Expected result 1 is obtained.
            2. Configure the client to send a client hello message without any extension type. Expected result 2 is obtained.
            3. The server continues to establish a link. Expected result 3 is obtained.
* @expect   1. Success 2. Success 3. Success
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC043(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback_43;

    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_HANDSHAKE_FAILURE;
    testPara.isExpectRet = true;
    testPara.expectRet = HITLS_MSG_HANDLE_CIPHER_SUITE_ERR;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

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
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC006
* @titleThe client does not send the certificate. Instead, the client sends the certificate.
* @precon nan
* @brief
            1. Configure dual-end verification. Expected result 1 is obtained.
            2. Set the client severhello done callback to send certificate verify.
* @expect   1. Expected success
            2. Expected server to return alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC006()
{
    //  1. Configure dual-end verification.
    TestExpect testExpect = {0};
    testExpect.acceptExpect = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    testExpect.expectLevel = ALERT_LEVEL_FATAL;
    testExpect.expectDescription = ALERT_UNEXPECTED_MESSAGE;
    testExpect.connectExpect = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
    HLT_FrameHandle frameHandle = {0};
    // 2. Set the client severhello done callback to send certificate verify.
    frameHandle.frameCallBack = TEST_SendUnexpectClientKeyExchangeMsg;
    frameHandle.expectHsType = CERTIFICATE;
    frameHandle.expectReType = REC_TYPE_HANDSHAKE;
    frameHandle.ioState = EXP_NONE;
    frameHandle.pointType = POINT_SEND;
    frameHandle.userData = NULL;
    TEST_UnexpectMsg(&frameHandle, &testExpect, true);
    return;
}
/* END_CASE */


/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_SEND_CERTFICATE_VERITY_TC001
* @title    The client does not send the certificate. Instead, the client sends the certificate.
* @precon nan
* @brief
            1. Configure unidirectional authentication. Expected result 1 is obtained.
            2. Set the client severhello done callback to send certificate verify.
* @expect   1. Expected success
            2. Expected server to return alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CLIENT_SEND_CERTFICATE_VERITY_TC001()
{
    // 1. Configure unidirectional authentication.
    TestExpect testExpect = {0};
    testExpect.acceptExpect = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    testExpect.expectLevel = ALERT_LEVEL_FATAL;
    testExpect.expectDescription = ALERT_UNEXPECTED_MESSAGE;
    testExpect.connectExpect = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;

    HLT_FrameHandle frameHandle = {0};
    // 2. Set the client severhello done callback to send certificate verify.
    frameHandle.frameCallBack = TEST_SendUnexpectCertificateMsg;
    frameHandle.expectHsType = CLIENT_KEY_EXCHANGE;
    frameHandle.expectReType = REC_TYPE_HANDSHAKE;
    frameHandle.ioState = EXP_NONE;
    frameHandle.pointType = POINT_SEND;
    frameHandle.userData = NULL;
    TEST_UnexpectMsg(&frameHandle, &testExpect, false);
    return;
}
/* END_CASE */


/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC007
* @title  The client does not send the certificate. Instead, the client sends the certificate.
* @precon nan
* @brief
            1. Configure unidirectional authentication. Expected result 1 is obtained.
            2. Set the client severhello done callback to send certificate verify.
* @expect   1. Expected success
            2. Expected server to return alert
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CERTFICATE_VERITY_FAIL_TC007()
{
    //  1. Configure unidirectional authentication.
    TestExpect testExpect = {0};
    testExpect.acceptExpect = HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE;
    testExpect.expectLevel = ALERT_LEVEL_FATAL;
    testExpect.expectDescription = ALERT_UNEXPECTED_MESSAGE;
    testExpect.connectExpect = HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;

    HLT_FrameHandle frameHandle = {0};
    // 2. Set the client severhello done callback to send certificate verify.
    frameHandle.frameCallBack = TEST_SendUnexpectCertificateVerifyMsg;
    frameHandle.expectHsType = CLIENT_KEY_EXCHANGE;
    frameHandle.expectReType = REC_TYPE_HANDSHAKE;
    frameHandle.ioState = EXP_NONE;
    frameHandle.pointType = POINT_SEND;
    frameHandle.userData = NULL;

    TEST_UnexpectMsg(&frameHandle, &testExpect, true);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_SUPPORT_GROUP_TC001(void)
{
    FRAME_Init();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    uint16_t cipherSuite = HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA;
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(c_config, &cipherSuite, 1) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetCipherSuites(s_config, &cipherSuite, 1) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    client->ssl->config.tlsConfig.groupsSize = 0;
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_MSG_HANDLE_CIPHER_SUITE_ERR);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

void ClientSendMalformedCipherSuiteLenMsg(HLT_FrameHandle *handle, TestPara *testPara)
{
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess((HITLS), TCP, 16384, false);
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
void SDV_TLS1_2_RFC5246_MALFORMED_CIPHER_SUITE_LEN_FUN_TC001()
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
    testPara.port = PORT;
    /* 4. Check the status of the test. */
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    /* 3. Check the status of the tested */
    testPara.expectDescription = ALERT_DECODE_ERROR;
    ClientSendMalformedCipherSuiteLenMsg(&handle, &testPara);
    return;
}
/* END_CASE */