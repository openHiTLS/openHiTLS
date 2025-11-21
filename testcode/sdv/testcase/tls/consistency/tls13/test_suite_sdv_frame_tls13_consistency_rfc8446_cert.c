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
/* INCLUDE_BASE test_suite_tls13_consistency_rfc8446 */

#include <stdio.h>
#include "stub_replace.h"
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
#include "rec.h"
#include "parse.h"
#include "hs_msg.h"
#include "alert.h"
#include "hitls_crypt_init.h"
#include "common_func.h"
/* END_HEADER */

#define g_uiPort 2987

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
} HsTestInfo;

int32_t NewConfig(HsTestInfo *testInfo)
{
    /* Construct the configuration.*/
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

    if (testInfo->config == NULL || testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    HITLS_CFG_SetClientVerifySupport(testInfo->config, true);
    HITLS_CFG_SetExtenedMasterSecretSupport(testInfo->config, true);
    HITLS_CFG_SetNoClientCertSupport(testInfo->config, true);
    HITLS_CFG_SetRenegotiationSupport(testInfo->config, true);
    HITLS_CFG_SetPskServerCallback(testInfo->config, (HITLS_PskServerCb)ExampleServerCb);
    return HITLS_SUCCESS;
}
static int32_t DoHandshake(HsTestInfo *testInfo)
{
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);

    testInfo->client = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
}

static void Test_Cert_len0(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);
    FRAME_CertificateMsg *certifiMsg = &frameMsg.body.hsMsg.body.certificate;
    certifiMsg->certsLen.state = ASSIGNED_FIELD;
    certifiMsg->certsLen.data = 0;
    certifiMsg->certificateReqCtxSize.state = ASSIGNED_FIELD;
    certifiMsg->certificateReqCtxSize.data = 0;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}


static void Test_CertPackAndParse(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);
    if (frameMsg.body.hsMsg.body.certificate.certificateReqCtx.data == NULL) {
        frameMsg.body.hsMsg.body.certificate.certificateReqCtxSize.data = 1;
        frameMsg.body.hsMsg.body.certificate.certificateReqCtxSize.state = INITIAL_FIELD;
        uint8_t *cerReqData = BSL_SAL_Calloc(1, 1);
        frameMsg.body.hsMsg.body.certificate.certificateReqCtx.data = cerReqData;
        frameMsg.body.hsMsg.body.certificate.certificateReqCtx.size = 1;
        frameMsg.body.hsMsg.body.certificate.certificateReqCtx.state = INITIAL_FIELD;
    }
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC003
* @spec -
* @titleThe client receives a Certificate message with zero length.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. The client initiates a TLS over TCP connection request. When the client receives the request from the server,
            the client receives the request from the server. After receiving the Hello message, the server constructs a
            Certificate message with zero length and sends the message to the client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message with the level of ALERT_ LEVEL_FATAL and description of
*           ALERT_DECODE_ERROR.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC003(void)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    /* 1. Use the default configuration items to configure the client and server. */
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    testInfo.config->isSupportNoClientCert = false;
    testInfo.config->isSupportClientVerify = true;
    /*  2. The client initiates a TLS over TCP connection request. When the client receives the request from the server,
     *     the client receives the request from the server. After receiving the Hello message, the server constructs a
     *     Certificate message with zero length and sends the message to the client. */
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, &wrapper, Test_Cert_len0};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_EE_len0(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, ENCRYPTED_EXTENSIONS);
    memset_s(data, bufSize, 0, bufSize);
    if (ctx->isClient) {
        data[0] = ENCRYPTED_EXTENSIONS;
        data[1] = 0X00;
        data[2] = 0X00;
        data[3] = 0X00;
    }
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC004
* @spec -
* @title The client receives an EE message with zero length.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. The client initiates a TLS over TCP connection request. After receiving the client Hello message, the
*           client constructs a certificate with zero length. Send the request message to the client. Expected result 2
*           is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message with the level of ALERT_ LEVEL_FATAL and description
            ALERT_DECODE_ERROR.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC004(void)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    /*  1. Use the default configuration items to configure the client and server. */
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    testInfo.config->isSupportNoClientCert = false;
    testInfo.config->isSupportClientVerify = true;
    /* 2. The client initiates a TLS over TCP connection request. After receiving the CH message, the client
     *    constructs a EE with zero length. Send the request message to the client. */
    RecWrapper wrapper = {TRY_RECV_ENCRYPTED_EXTENSIONS, REC_TYPE_HANDSHAKE, true, &wrapper, Test_EE_len0};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC008
* @title The client receives an key update message with zero length.
* @brief    The client receives an key update message with zero length. Expect result 1
* @expect
1. The client sends an ALERT message with the level of ALERT_ LEVEL_FATAL and description ALERT_DECODE_ERROR.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;

    uint8_t keyUpdateMsg[] = {KEY_UPDATE, 0, 0, 0};
    ASSERT_TRUE(REC_Write(serverTlsCtx, REC_TYPE_HANDSHAKE, keyUpdateMsg, sizeof(keyUpdateMsg)) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen) == HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = {0};
    ALERT_GetInfo(clientTlsCtx, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_Cert_verify_len0(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_VERIFY);

    FRAME_CertificateVerifyMsg *CertveriMsg = &frameMsg.body.hsMsg.body.certificateVerify;
    CertveriMsg->signSize.data = 0;
    CertveriMsg->signSize.state = ASSIGNED_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC005
* @spec -
* @titleThe client receives a Certificate verify message whose length is zero.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. The client initiates a TLS over TCP connection request. After receiving the client Hello message, the
*               client constructs a certificate with zero length. Send the verify message to the client. Expected result
*               2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message with the level of ALERT_ LEVEL_FATAL and description
            ALERT_DECODE_ERROR.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC005(void)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    testInfo.config->isSupportNoClientCert = false;
    testInfo.config->isSupportClientVerify = true;
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE_VERIFY, REC_TYPE_HANDSHAKE, false, &wrapper, Test_Cert_verify_len0};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */


static void Test_finished_len0(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);
    FRAME_FinishedMsg *FinishedMsg = &frameMsg.body.hsMsg.body.finished;
    FinishedMsg->verifyData.size = 0;
    FinishedMsg->verifyData.state = ASSIGNED_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC006
* @spec -
* @titleThe client receives a finished message with zero length.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. The client initiates a TLS over TCP connection request and receives the request from the client.
            After the Hello message is sent, construct a finished message with zero length and send the message to the
            client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends an ALERT message. The level is ALERT_Level_FATAL and the description is
            ALERT_DECODE_ERROR.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC006(void)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    /* 1. Use the default configuration items to configure the client and server. */
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    testInfo.config->isSupportNoClientCert = false;
    testInfo.config->isSupportClientVerify = true;
    /* 2. The client initiates a TLS over TCP connection request and receives the request from the client.
     *    After the Hello message is sent, construct a finished message with zero length and send the message to the
     *    client. */
    RecWrapper wrapper = {TRY_SEND_FINISH, REC_TYPE_HANDSHAKE, false, &wrapper, Test_finished_len0};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_NewSessionTicket_len0(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, NEW_SESSION_TICKET);
    FRAME_NewSessionTicketMsg *newsessionTMsg = &frameMsg.body.hsMsg.body.newSessionTicket;
    newsessionTMsg->ticketSize.data = 0;
    newsessionTMsg->ticketSize.state = ASSIGNED_FIELD;
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC007
* @spec -
* @titleThe client receives a NewSessionTicket message with zero length.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. The client initiates a TLS over TCP connection request and receives the request from the client.
            After receiving the Hello message, construct a New SessionTicket message with zero length and send it to the
            client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The client sends the ALERT message. The level is ALERT_ LEVEL_FATAL and the description is
            ALERT_DECODE_ERROR.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_ZEROLENGTH_MSG_FUNC_TC007(void)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    /* 1. Use the default configuration items to configure the client and server. */
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    testInfo.config->isSupportNoClientCert = false;
    testInfo.config->isSupportClientVerify = true;
    /* 2. The client initiates a TLS over TCP connection request and receives the request from the client.
     *    After receiving the Hello message, construct a New SessionTicket message with zero length and send it to
     *    the client. */
    RecWrapper wrapper = {TRY_SEND_NEW_SESSION_TICKET, REC_TYPE_HANDSHAKE, false, &wrapper, Test_NewSessionTicket_len0};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_PARSE_INVALID_MSG_LEN);
    ALERT_Info info = {0};
    ALERT_GetInfo(testInfo.client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTMSG_FUNC_TC001
* @spec -
* @title Abnormal CertMsg packet
* @precon nan
* @brief 1. Enable the dual-end verification. Change the value of certificate_request_context in the certificate message
            sent by the client to a value other than 0. Expected result 1 is obtained.
            Result 1: The server sends an alert message and disconnects the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTMSG_FUNC_TC001()
{

    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_CertPackAndParse};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_CertReqAbCtxLen(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    if (frameMsg.body.hsMsg.body.certificateReq.certificateReqCtx.data == NULL) {
        ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_REQUEST);
        frameMsg.body.hsMsg.body.certificateReq.certificateReqCtxSize.data = 1;
        frameMsg.body.hsMsg.body.certificateReq.certificateReqCtxSize.state = INITIAL_FIELD;
        uint8_t *cerReqData = BSL_SAL_Calloc(1, 1);
        frameMsg.body.hsMsg.body.certificateReq.certificateReqCtx.data = cerReqData;
        frameMsg.body.hsMsg.body.certificateReq.certificateReqCtx.size = 1;
        frameMsg.body.hsMsg.body.certificateReq.certificateReqCtx.state = INITIAL_FIELD;
    }
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC001
* @spec -
* @title Abnormal CertReqMsg message
* @precon nan
* @brief 1. Enable the dual-end check. Change the value of certificate_request_context in the certificate_request
*           message sent by the server to a value other than 0. Expected result 1 is obtained. Result 1: The server
*           sends an alert message and disconnects the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC001()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertReqAbCtxLen};
    RegisterWrapper(wrapper);
    /* Handshake */
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_INVALID_CERT_REQ_CTX);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_NO_CERT_FUNC_TC001
* @spec A Finished message MUST be sent regardless of whether the Certificate message is empty.
* @title During the normal handshake, the peer certificate can be empty, the certificate message sent by the client is
*        empty, and the certificate message sent by the server is not empty. The handshake is successful. The finished
*        message is sent after the certificate message and the content is correct.
* @precon nan
* @brief 4.4.2. Certificate row114
            1. Enable the dual-end verification, allow the peer certificate to be empty, set the client certificate to
            be empty, and establish a connection.
* @expect   1. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_NO_CERT_FUNC_TC001(int isSupportNoClientCert)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        0,
        0,
        0,
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = (bool)isSupportNoClientCert;
    if (config->isSupportNoClientCert) {
        client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    } else {
        client = FRAME_CreateLink(config, BSL_UIO_TCP);
    }
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC002
* @spec
    1. If the client does not set the root certificate but the server sets the complete certificate chain, the client
    fails to construct the certificate chain, and the handshake fails and the unsupported_certificate alarm is reported.
By default, the preceding alarm is generated. In the current code, the alarm is generated as bad_certificate.
* @brief    If the client cannot construct an acceptable chain using the provided
*           certificates and decides to abort the handshake, then it MUST abort the
*           handshake with an appropriate certificate-related alert
*           (by default, "unsupported_certificate"; see Section 6.2 for more information).
* 4.4.2 Certificate row 136
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        0,
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNKNOWN_CA);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC003
* @spec
    1. The root certificate is configured on the client. Incomplete certificate chain is configured on both the client
and server. If the server fails to construct the certificate chain, the handshake fails and the unsupported_certificate
    alarm is reported. By default, the alarm is the preceding alarm. In the current code, the alarm is the
bad_certificate alarm.
* @brief If the client cannot construct an acceptable chain using the provided
*       certificates and decides to abort the handshake, then it MUST abort the
*       handshake with an appropriate certificate-related alert
*       (by default, "unsupported_certificate"; see Section 6.2 for more information).
* 4.4.2 Certificate row 136
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der",
        0,
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNKNOWN_CA);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC004
* @spec
    1. If the client sets an incorrect root certificate and the server sets a complete certificate chain, the client
    fails to construct the certificate chain, and the handshake fails and the unsupported_certificate alarm is reported.
    By default, the preceding alarm is generated. In the current code, the alarm is generated as bad_certificate.
* @brief If the client cannot construct an acceptable chain using the provided
*   certificates and decides to abort the handshake, then it MUST abort the
*   handshake with an appropriate certificate-related alert
*   (by default, "unsupported_certificate"; see Section 6.2 for more information).
* 4.4.2 Certificate row 136
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC004(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "rsa_sha/ca-3072.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNKNOWN_CA);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC005
* @spec
    1. If the client does not match a proper algorithm and fails to construct a certificate chain, the handshake fails
and the unsupported_certificate alarm is reported. By default, the preceding alarm is generated. In the current code,
the HANDSHAKE_FAILURE alarm is generated.
* @brief If the client cannot construct an acceptable chain using the provided
*       certificates and decides to abort the handshake, then it MUST abort the
*       handshake with an appropriate certificate-related alert
*       (by default, "unsupported_certificate"; see Section 6.2 for more information).
* 4.4.2 Certificate row 136
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTCHAIN_FUNC_TC005(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t serverSignAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    uint16_t clientSignAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256};
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_CFG_SetSignature(&client->ssl->config.tlsConfig, clientSignAlgs, sizeof(clientSignAlgs) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(&server->ssl->config.tlsConfig, serverSignAlgs, sizeof(serverSignAlgs) / sizeof(uint16_t));
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_ERR_NO_SERVER_CERTIFICATE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.recType.data == REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_HANDSHAKE_FAILURE);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */



static void Test_CertReqPackAndParseNoEx(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_REQUEST);
    frameMsg.body.hsMsg.body.certificateReq.signatureAlgorithmsSize.data = 0;
    frameMsg.body.hsMsg.body.certificateReq.signatureAlgorithmsSize.state = MISSING_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC002
* @spec -
* @title Abnormal CertReqMsg packet
* @precon nan
* @brief 1. Enable the dual-end verification. Change the value of certificate_request_context in the certificate_request
message sent by the server to a value other than 0. Expected result 1 is obtained. Result 1: The server sends an alert
message and disconnects the connection.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC002()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertReqPackAndParseNoEx};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_PARSE_INVALID_MSG_LEN);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_CertReqPackAndParseNoSign(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    // The eighth digit indicates the type of the first extension. Change the type of the first extension to key share.
    *(uint16_t *)(data + 8) = HS_EX_TYPE_KEY_SHARE;
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC003
* @spec -
* @title Abnormal CertReqMsg packet
* @precon nan
* @brief 1. Enable the dual-end verification, set the extension field in the server certificate request to exclude the
            signature algorithm, and establish a connection.
        Expected result: The connection fails to be established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC003()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertReqPackAndParseNoSign};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */


static void Test_CertReqPackAndParseUnknownEx(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_REQUEST);
    frameMsg.body.hsMsg.body.certificateReq.signatureAlgorithms.state = DUPLICATE_FIELD;
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

    *(uint16_t *)(data + 8) = HS_EX_TYPE_KEY_SHARE;
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC004
* @spec -
* @title Abnormal CertReqMsg packet
* @precon nan
* @brief    1. Enable the dual-end verification, set the extension field in the server certificate request to exclude
*        the signature algorithm, and establish a connection. Expected result: The connection fails to be established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC004()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertReqPackAndParseUnknownEx};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC005
* @spec -
* @title Abnormal CertReqMsg packet
* @precon nan
* @brief 1. Initialize the client and server to tls1.3, and construct the scenario where the client and server sends an
         alert message after receiving the hrr message and serverhello message, Expected Alert Message Encryption
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC005()
{

    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    testInfo.client = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));
    testInfo.server = FRAME_CreateLink(testInfo.config, testInfo.uioType);
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertReqAbCtxLen};
    RegisterWrapper(wrapper);
    ASSERT_EQ(
        FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_CERTIFICATE_REQUEST), HITLS_SUCCESS);
    HITLS_Connect(testInfo.client->ssl);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *buffer = ioUserData->sndMsg.msg;
    uint32_t len = ioUserData->sndMsg.len;
    ASSERT_TRUE(len != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {};
    ASSERT_TRUE(ParserTotalRecord(testInfo.client, &frameMsg, buffer, len, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.type, REC_TYPE_ALERT);
    ASSERT_EQ(frameMsg.body.alertMsg.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

static void Test_EmptyCertMsg(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE);
    FrameCertItem *certItem = frameMsg.body.hsMsg.body.certificate.certItem;
    frameMsg.body.hsMsg.body.certificate.certItem = NULL;
    while (certItem != NULL) {
        FrameCertItem *temp = certItem->next;
        BSL_SAL_FREE(certItem->cert.data);
        BSL_SAL_FREE(certItem->extension.data);
        BSL_SAL_FREE(certItem);
        certItem = temp;
    }
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTMSG_FUNC_TC002
* @spec -
* @title Abnormal CertReqMsg packet
* @precon nan
* @brief    1. Enable the dual-end verification. If the certificate message does not contain the certificate, the connection
            is established.
            Expected result: A decode error is returned when the connection fails to be established.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTMSG_FUNC_TC002()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_EmptyCertMsg};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTMSG_FUNC_TC003
* @spec -
* @title Abnormal CertReqMsg packet
* @precon nan
* @brief    1. Enable the single-end authentication. If the certificate message does not contain the certificate,
            establish a connection.
            Expected result: Decode error is returned when the connection fails to be set up.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTMSG_FUNC_TC003()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetClientVerifySupport(testInfo.config, false), HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_CERTIFICATE, REC_TYPE_HANDSHAKE, false, NULL, Test_EmptyCertMsg};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */


static void Test_CertReqPackAndParse(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_REQUEST);
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC000
* @spec -
* @title Verify the parsing and packaging functions of the cerreqmsg test framework.
* @precon nan
* @brief    1. Enable the dual-end check. Change the value of certificate_request_context in the certificate_request
                message sent by the server to a value other than 0.
            Expected result 1 is obtained. Result 1: The server sends an alert message and disconnects the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ABNORMAL_CERTREQMSG_FUNC_TC000()
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    RecWrapper wrapper = {TRY_SEND_CERTIFICATE_REQUEST, REC_TYPE_HANDSHAKE, false, NULL, Test_CertReqPackAndParse};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SIGN_ERR_FUNC_TC001
* @spec
* 1. Set the client server to tls1.3 and the client signature algorithm to ecdsa-sha1. The expected connection
*    establishment fails.
* @brief If the server cannot produce a certificate chain that is signed only via the indicated
* supported algorithms, then it SHOULD continue the handshake by sending the client a certificate
* chain of its choice that may include algorithms that are not known to be supported by the client.
* This fallback chain SHOULD NOT use the deprecated SHA-1 hash algorithm in general, but MAY do so
* if the client' s advertisement permits it, and MUST NOT do so otherwise.
* 4.4.2.2. Server Certificate Selection row 135
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SIGN_ERR_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo serverCertInfo = {
        "ecdsa_sha1/ca-nist521.der",
        "ecdsa_sha1/inter-nist521.der",
        "ecdsa_sha1/end384-sha1.der",
        0,
        "ecdsa_sha1/end384-sha1.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SHA1};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &serverCertInfo);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &serverCertInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH);
    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_INTERNAL_ERROR);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static int32_t GetDisorderServerEEMsg(FRAME_LinkObj *server, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t tmpData[TEMP_DATA_LEN] = {0};
    uint32_t tmpLen = sizeof(tmpData);
    (void)HITLS_Accept(server->ssl);
    int32_t ret = FRAME_TransportSendMsg(server->io, tmpData, tmpLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    tmpLen = readLen;
    uint8_t serverHelloData[TEMP_DATA_LEN] = {0};
    uint32_t serverHelloLen = sizeof(serverHelloData);
    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, serverHelloData, serverHelloLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    serverHelloLen = readLen;
    (void)HITLS_Accept(server->ssl);
    ret = FRAME_TransportSendMsg(server->io, &data[offset], len - offset, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    offset += readLen;
    if (memcpy_s(&data[offset], len - offset, serverHelloData, serverHelloLen) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }
    offset += serverHelloLen;
    *usedLen = offset;
    return HITLS_SUCCESS;
}

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECTMSG_FUNC_TC001
* @spec
1. During the handshake, the server sends an EncryptedExtensions message before the ServerHello message.
Expected result: The client returns an alert. The level is ALERT_Level_FATAL, description is ALERT_UNEXPECTED_MESSAGE,
and the handshake is interrupted.
* @brief In all handshakes, the server MUST send the EncryptedExtensions message immediately after the ServerHello
message.
* 4.3.1. Encrypted Extensions row 105
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECTMSG_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_HANDSHAKING);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_SERVER_HELLO);

    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;
    ASSERT_TRUE(GetDisorderServerEEMsg(server, data, len, &len) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(ioUserData->recMsg.len != 0);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static int32_t GetDisorderServerCertMsg(FRAME_LinkObj *server, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    uint32_t readLen = 0;
    uint32_t offset = 0;
    uint8_t tmpData[TEMP_DATA_LEN] = {0};
    uint32_t tmpLen = sizeof(tmpData);
    (void) HITLS_Accept(server->ssl);
    int32_t ret = FRAME_TransportSendMsg(server->io, tmpData, tmpLen, &readLen);
    if (readLen == 0 || ret != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    tmpLen = readLen;
    (void) HITLS_Accept(server->ssl);
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
/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECTMSG_FUNC_TC002
* @spec
1. The handshake uses certificate authentication. During the handshake, the server sends a Certificate Request message
before sending the EncryptedExtensions extension. Expected result: The client returns an alert, whose level is
ALERT_LEVEL_FATAL, description is ALERT_UNEXPECTED_MESSAGE, and the handshake is interrupted.
* @brief A server which is authenticating with a certificate MAY optionally request
* a certificate from the client. This message, if sent, MUST follow EncryptedExtensions.
* 4.3.2. Certificate Request row 107
*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_UNEXPECTMSG_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg recvframeMsg = {0};
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    config->isSupportClientVerify = true;
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_ENCRYPTED_EXTENSIONS), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_HANDSHAKING);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_ENCRYPTED_EXTENSIONS);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t len = MAX_RECORD_LENTH;

    ASSERT_TRUE(GetDisorderServerCertMsg(server, data, len, &len) == HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0);
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, data, len) == HITLS_SUCCESS);
    ASSERT_TRUE(ioUserData->recMsg.len != 0);
    // TLS1.3 Ciphertext Handshake Messages Are Out of Order, Causing Decryption Failure
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_BAD_RECORD_MAC);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_BAD_RECORD_MAC);
EXIT:
    CleanRecordBody(&recvframeMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

bool g_client = false;

static void Test_NoServerCertPackAndParse001(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_VERIFY);
    if (ctx->isClient == g_client) {
        FRAME_CleanMsg(&frameType, &frameMsg);
        SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
        ASSERT_TRUE(FRAME_GetDefaultMsg(&frameType, &frameMsg) == HITLS_SUCCESS);
    }
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_NO_CERTVERIFY_FUNC_TC001
 * @spec
 * 1. Enable the dual-end verification, make the CertificateVerify message sent by the server lose, and observe the
 * client behavior. Expected result: The client sends an alert message and the connection is disconnected.
 * 2. Enable the dual-end verification, make the CertificateVerify message sent by the client lose, and observe the
 * client behavior. Expected result: The client sends an alert message and the connection is disconnected.
 * @brief Servers MUST send this message when authenticating via a certificate.
 * Clients MUST send this message whenever authenticating via a certificate.
 * 4.4.3. Certificate Verify row 145
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NO_CERTVERIFY_FUNC_TC001(int isClient)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_client = (bool)isClient;
    /* 1. Enable the dual-end verification, make the CertificateVerify message sent by the server lose, and
     * observe the client behavior.
     * 2. Enable the dual-end verification, make the CertificateVerify message sent by the client lose, and observe
     * the client behavior. */
    RecWrapper wrapper = {TRY_RECV_CERTIFICATE_VERIFY,
        REC_TYPE_HANDSHAKE,
        true,
        NULL,
        Test_NoServerCertPackAndParse001};
    RegisterWrapper(wrapper);

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_NoCertificateSignPackAndParse001(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CERTIFICATE_VERIFY);
    if (ctx->isClient == g_client) {
        FRAME_CertificateVerifyMsg *certVerify = &frameMsg.body.hsMsg.body.certificateVerify;
        certVerify->signHashAlg.data = CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256;
        certVerify->signHashAlg.state = ASSIGNED_FIELD;
    }
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CERTVERIFY_SIGN_FUNC_TC001
 * @spec
 * 1. Enable the dual-end verification, modify the signature field in the CertificateVerify message sent by the server,
 * and observe the client behavior. The expected result is that the client sends decrypt_error and the connection is
 * disconnected.
 * 2. Enable dual-end verification, modify the signature field in the CertificateVerify message sent by the client, and
 * observe the server behavior. Expected result: The server sends decrypt_error and disconnects the connection.
 * @brief The receiver of a CertificateVerify message MUST verify the signature field.
 * 4.4.3. Certificate Verify row 151
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CERTVERIFY_SIGN_FUNC_TC001(int isClient)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_client = (bool)isClient;
    RecWrapper wrapper = {
        TRY_SEND_CERTIFICATE_VERIFY,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_NoCertificateSignPackAndParse001
    };
    RegisterWrapper(wrapper);
    FRAME_CertInfo serverCertInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    FRAME_CertInfo clientCertInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &serverCertInfo);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &clientCertInfo);
    ASSERT_TRUE(client != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_PARSE_UNSUPPORT_SIGN_ALG);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_FinishedPackAndParse001(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, FINISHED);
    if (ctx->isClient == g_client) {
        FRAME_FinishedMsg *finishMsg = &frameMsg.body.hsMsg.body.finished;
        finishMsg->verifyData.state = ASSIGNED_FIELD;
        finishMsg->verifyData.size = finishMsg->verifyData.size - 1;
    }
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_FINISHEDMSG_ERR_FUNC_TC001
 * @spec
 * 1. Modify the Finished message sent by the server and observe the client behavior. The expected result is that the
 * client sends a decrypt_error message and the connection is disconnected.
 * 2. Modify the Finished message sent by the client and observe the server behavior. The expected result is that the
 * server sends a decrypt_error message and the connection is disconnected.
 * @brief Recipients of Finished messages MUST verify that the contents are correct
 * and if incorrect MUST terminate the connection with a "decrypt_error" alert.
 * 4.4.4. Finished row 153
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_FINISHEDMSG_ERR_FUNC_TC001(int isClient)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_client = (bool)isClient;
    RecWrapper wrapper = {TRY_SEND_FINISH,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        /*  1. Modify the Finished message sent by the server and observe the client behavior. The expected result is
         * that the client sends a decrypt_error message and the connection is disconnected.
         * 2. Modify the Finished message sent by the client and observe the server behavior. */
        Test_FinishedPackAndParse001};
    RegisterWrapper(wrapper);

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_VERIFY_FINISHED_FAIL);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RSA1024CERT_FUNC_TC001
 * @spec
 * 1. Initialize the client and server to TLS1.3 and use the 1024-bit RSA certificate. The certificate verification
 * fails and connection establishment fails.
 * @brief Applications SHOULD also enforce minimum and maximum key sizes. For example,
 * certification paths containing keys or signatures weaker than 2048-bit RSA or 224-bit
 * ECDSA are not appropriate for secure applications.
 * Appendix C. Implementation Notes row 238
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RSA1024CERT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo serverCertInfo = {
        "rsa_1024/rsa_root.crt",
        "rsa_1024/rsa_intCa.crt",
        "rsa_1024/rsa_dev.crt",
        0,
        "rsa_1024/rsa_dev.key",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    const int32_t level = 2;
    HITLS_CFG_SetSecurityLevel(config, level);

    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &serverCertInfo);
    ASSERT_TRUE(server == NULL);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


static void Test_AlertPackAndParse004(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_ALERT;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);

    ASSERT_EQ(frameMsg.recType.data, REC_TYPE_ALERT);
    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_EQ(alertMsg->alertLevel.data, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertMsg->alertDescription.data, ALERT_UNKNOWN_CA);

    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CERTCHAIN_FUNC_TC001
 * @spec
 * 1, If no certificate is set on the server, the client sends a complete certificate chain, and the connection fails to be
 *   established.
 * @brief  Because certificate validation requires that trust anchors be distributed independently,
 *  a certificate that specifies a trust anchor MAY be omitted from the chain, provided that supported
 *  peers are known to possess any omitted certificates.
 * 4.4.2.  Certificate row 119
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CERTCHAIN_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        0,
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    RecWrapper wrapper = {HS_STATE_BUTT, REC_TYPE_ALERT, false, NULL, Test_AlertPackAndParse004};
    RegisterWrapper(wrapper);

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CERTCHAIN_FUNC_TC002
 * @spec
 * 1. The root certificate (any algorithm) is set on the server. The client sends a certificate chain that does not
 * contain the root certificate. The connection is successfully set up.
 * 2. The root certificate (any algorithm) is set on the client. The server sends a certificate chain without the root
 * certificate. The connection is successfully set up.
 * @brief  Because certificate validation requires that trust anchors be distributed independently,
 *  a certificate that specifies a trust anchor MAY be omitted from the chain, provided that supported
 *  peers are known to possess any omitted certificates.
 * 4.4.2.  Certificate row 119
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CERTCHAIN_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo serverCertInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    FRAME_CertInfo clientCertInfo = {
        "ecdsa/ca-nist521.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &serverCertInfo);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &clientCertInfo);
    ASSERT_TRUE(client != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CERTCHAIN_FUNC_TC003
 * @spec
 * 1. The root certificate is incorrectly set on the server. After the client sends a complete certificate chain, the
 * connection fails to be established and the error code is displayed. ALERT_BAD_CERTIFICATE
 * @brief  Because certificate validation requires that trust anchors be distributed independently,
 *  a certificate that specifies a trust anchor MAY be omitted from the chain, provided that supported
 *  peers are known to possess any omitted certificates.
 * 4.4.2.  Certificate row 119
 */
/* BEGIN_CASE */
void  UT_TLS_TLS13_RFC8446_CONSISTENCY_SERVER_CERTCHAIN_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "rsa_sha/ca-3072.der",
        "ecdsa/inter-nist521.der",
        "ecdsa/end256-sha256.der",
        0,
        "ecdsa/end256-sha256.key.der",
        0,
    };
    RecWrapper wrapper = {
        HS_STATE_BUTT,
        REC_TYPE_ALERT,
        true,
        NULL,
        Test_AlertPackAndParse004
    };
    RegisterWrapper(wrapper);

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_CERT_ERR_VERIFY_CERT_CHAIN);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTNULL_FUNC_TC001
* @spec  If the client does not send any certificates (i.e., it sends an empty Certificate message),
            the server MAY at its discretion either continue the handshake without client authentication
            or abort the handshake with a "certificate_required" alert.
* @title  The certificate list of the server is not empty. The certificate of the peer end cannot be empty. The client
          sends an empty certificate.
*         Expected result: The handshake between the two parties fails, and the server sends an alarm. The alarm level
            is ALERT_LEVEL_FATAL and the description is certificate_required.
* @precon nan
* @brief 4.4.2.4. Receiving a Certificate Message row142
            1. Enable dual-end verification. Do not allow the peer certificate to be empty, set the client certificate
            to be empty, and establish a connection.
* @expect   1. If the connection fails to be established, the server generates an alarm. The alarm level is ALERT_LEVEL_FATAL
            and the description is certificate_required.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CLIENT_CERTNULL_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "ecdsa/ca-nist521.der",
        0,
        0,
        0,
        0,
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_NO_PEER_CERTIFIACATE);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_CERTIFICATE_REQUIRED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_ECDSA_SIGN_RSA_CERT_FUNC_TC001
* @spec  Note that a certificate containing a key for one signature algorithm MAY be signed
*        using a different signature algorithm (for instance, an RSA key signed with an ECDSA key).
* @title Apply for an RSA certificate issued by the ECDSA, set the certificate on the server, and set up a connection.
         Expected result: The connection is successfully set up.
* @precon nan
* @brief 4.4.2.4. Receiving a Certificate Message row144
         1. Enable dual-end verification, apply for an RSA certificate issued by the ECDSA, set the certificate on the
         server, and set up a connection.
* @expect 1. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ECDSA_SIGN_RSA_CERT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "ecdsa_rsa_cert/rootCA.der",
        "ecdsa_rsa_cert/CA1.der",
        "ecdsa_rsa_cert/ee.der",
        0,
        "ecdsa_rsa_cert/ee.key.der",
        0,
    };
    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    config->isSupportRenegotiation = true;
    config->isSupportClientVerify = true;
    config->isSupportNoClientCert = false;
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_MD5_CERT_TC001
* @spec Apply for the ee certificate signed by the MD5 signature algorithm, set the MD5 certificate at both ends,
* set up a link, and observe the server behavior.
* Expected result: The server cannot select a proper certificate, sends bad_certificate, and disconnects the link.
* @title
* @precon nan
* @brief 4.4.2.4. Receiving a Certificate Message row143
         Any endpoint receiving any certificate which it would need to validate using any signature algorithm using an
        MD5 hash MUST abort the handshake with a "bad_certificate" alert.
* @expect 1. The link is set up successfully.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_MD5_CERT_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    HITLS_CFG_SetClientVerifySupport(config, true);
    FRAME_CertInfo certInfo = {
        "md5_cert/rsa_root.der",
        "md5_cert/rsa_intCa.der",
        "md5_cert/md5_dev.der",
        0,
        "md5_cert/md5_dev.key",
        0,
    };

    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(server != NULL);
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_CERT_CTRL_ERR_GET_SIGN_ALGO);

    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(client->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, ALERT_BAD_CERTIFICATE);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_NewSessionTicketNonceLen0(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, NEW_SESSION_TICKET);
    FRAME_NewSessionTicketMsg *newsessionTMsg = &frameMsg.body.hsMsg.body.newSessionTicket;
    newsessionTMsg->ticketNonceSize.data = 0;
    newsessionTMsg->ticketNonceSize.state = ASSIGNED_FIELD;
    newsessionTMsg->ticketNonce.state = ASSIGNED_FIELD;
    newsessionTMsg->ticketNonce.size = 0;
    BSL_SAL_Free(newsessionTMsg->ticketNonce.data);
    newsessionTMsg->ticketNonce.data = NULL;
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_TICKET_NONCE_ZEROLENGTH_MSG_TC001
* @spec -
* @title The ticketNonce length in the NewSessionTicket message received by the client is zero.
* @precon nan
* @brief    1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*           2. The client initiates a TLS over TCP connection request and receives the request from the client.
            After receiving the Hello message, construct a New SessionTicket message with a ticketNonce length of zero
            and send it to the client. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
*           2. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_TICKET_NONCE_ZEROLENGTH_MSG_TC001(void)
{
    FRAME_Init();
    HsTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    ASSERT_EQ(NewConfig(&testInfo), HITLS_SUCCESS);
    testInfo.config->isSupportNoClientCert = false;
    testInfo.config->isSupportClientVerify = true;
    RecWrapper wrapper = {
        TRY_SEND_NEW_SESSION_TICKET,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_NewSessionTicketNonceLen0
    };
    RegisterWrapper(wrapper);
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSS_PARAMETER_CHECK()
{
    FRAME_Init();
    HITLS_Config *config_c = HITLS_CFG_NewTLS12Config();
    HITLS_Config *config_s = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);
    uint16_t signAlgs_s[] = {CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512};
    HITLS_CFG_SetSignature(config_s, signAlgs_s, sizeof(signAlgs_s) / sizeof(uint16_t));
    uint16_t cipherSuite[] = {HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(config_s, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));
    FRAME_CertInfo certInfo = {
        "rsa_pss_sha256/rsa_pss_root.der",
        "rsa_pss_sha256/rsa_pss_intCa.der",
        "rsa_pss_sha256/rsa_pss_dev_sha512.der",
        0,
        "rsa_pss_sha256/rsa_pss_dev_sha512.key.der",
        0,
    };
    FRAME_LinkObj *client = FRAME_CreateLinkWithCert(config_c, BSL_UIO_TCP, &certInfo);
    FRAME_LinkObj *server = FRAME_CreateLinkWithCert(config_s, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->negotiatedInfo.signScheme, CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS13_RFC8446_SHA1_EE_CERT_TC001
* @spec -
* @title Tls1.3 sets up a SHA-1 certificate with a security level of 1, expecting the connection to fail.
* @precon nan
* @brief    1. Create a TLS1.3 configuration, first load the SHA1 certificate, then set the security level to 1, and
                establish the connection. Expected result 1 is obtained.
* @expect   1.  Link establishment failed, sending SHA1 certificate will be prohibited when checking security
                level strength.
@ */
/* BEGIN_CASE */
void SDV_TLS13_RFC8446_SHA1_EE_CERT_TC001(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_CertInfo certInfo = {
        "ecdsa_sha1/ca-nist521.der",
        "ecdsa_sha1/inter-nist521.der",
        "ecdsa_sha1/end384-sha1.der",
        0,
        "ecdsa_sha1/end384-sha1.key.der",
        0,
    };

    config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    server = FRAME_CreateLinkWithCert(config, BSL_UIO_TCP, &certInfo);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_SetSecurityLevel(client->ssl, 1);
    HITLS_SetSecurityLevel(server->ssl, 1);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_CERTIFICATE), HITLS_SUCCESS);
    int32_t ret = HITLS_Accept(server->ssl);
    ASSERT_EQ(ret, HITLS_CERT_ERR_INSECURE_SIG_ALG);

    ALERT_Info alertInfo = {0};
    ALERT_GetInfo(server->ssl, &alertInfo);
    ASSERT_EQ(alertInfo.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alertInfo.description, ALERT_INTERNAL_ERROR);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_SIGALG_SELECT_TC001(int ecPrefer)
{
    FRAME_Init();
    HITLS_Config *config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(config != NULL);

    uint16_t signAlgs1[] = {CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    uint16_t signAlgs2[] = {CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256, CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256};
    uint16_t *clientSign = ecPrefer == 1 ? signAlgs2 : signAlgs1;
    uint16_t *serverSign = ecPrefer == 1 ? signAlgs1 : signAlgs2;

    HITLS_CFG_SetSignature(config, clientSign, sizeof(signAlgs1) / sizeof(uint16_t));
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_TCP);
    HITLS_CFG_SetSignature(config, serverSign, sizeof(signAlgs2) / sizeof(uint16_t));
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_TCP);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_SignHashAlgo peerSignScheme;
    HITLS_GetPeerSignScheme(client->ssl, &peerSignScheme);
    ASSERT_EQ(ecPrefer == 1 ? CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256 : CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256, peerSignScheme);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */