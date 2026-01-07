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

#include <semaphore.h>
#include <stdio.h>
#include "process.h"
#include "securec.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "bsl_sal.h"
#include "simulate_io.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "alert.h"
#include "session_type.h"
#include "hitls_type.h"
#include "rec.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "frame_msg.h"
#include "hitls.h"
#include "hitls_config.h"
#include "bsl_uio.h"
#include "pack.h"
#include "send_process.h"
#include "parser_frame_msg.h"
#include "cert.h"
#include "rec_wrapper.h"
#include "conn_init.h"
#include "cert_callback.h"
#include "change_cipher_spec.h"
#include "common_func.h"
#include "uio_base.h"
#include "stub_crypt.h"

#define READ_BUF_SIZE (18 * 1024)
/* END_HEADER */

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendedMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isSupportRenegotiation;
    bool isServerExtendedMasterSecret;
} HandshakeTestInfo;

int32_t StatusPark(HandshakeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

static void Test_ServerHelloHaveSecRenego(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    ASSERT_EQ(frameMsg.body.hsMsg.body.serverHello.secRenego.exState, INITIAL_FIELD);
    memset_s(data, bufSize, 0, bufSize);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    testInfo->config->isSupportExtendedMasterSecret = testInfo->isSupportExtendedMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusPark(testInfo);
}

int32_t StatusPark1(HandshakeTestInfo *testInfo)
{
    if (testInfo->isServerExtendedMasterSecret == true) {
        testInfo->config->isSupportExtendedMasterSecret = true;
    } else {
        testInfo->config->isSupportExtendedMasterSecret = false;
    }
    testInfo->config->isSupportRenegotiation = false;
    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (testInfo->isServerExtendedMasterSecret == true) {
        testInfo->config->isSupportExtendedMasterSecret = false;
    } else {
        testInfo->config->isSupportExtendedMasterSecret = true;
    }
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark1(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo->config, groups, sizeof(groups) / sizeof(uint16_t));
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo->config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    testInfo->config->isSupportExtendedMasterSecret = testInfo->isSupportExtendedMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusPark1(testInfo);
}

void Test_RenegoWrapperFunc(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = {0};
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
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = {0};
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

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC001
* @titleThe client carries the renegotiation algorithm suite but does not carry the renegotiation extension.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*        2. During continuous link setup, the server checks whether the renegotiation algorithm suite is contained and
*           whether the renegotiation extension is carried when receiving the CLIENT_HELLO message.
*           Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. The renegotiation algorithm suite is expected to be carried, but the renegotiation extension is not
*           carried.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isSupportRenegotiation = true;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);
    int FlagScsv = 0;

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    for (int i = 0; i < (int)frameMsg.body.hsMsg.body.clientHello.cipherSuites.size; i++) {
        if (frameMsg.body.hsMsg.body.clientHello.cipherSuites.data[i] == 255) {
            FlagScsv = 1;
        }
    }

    ASSERT_TRUE(FlagScsv == 1);
    ASSERT_TRUE(frameMsg.body.hsMsg.body.clientHello.secRenego.exState == MISSING_FIELD);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC003
* @title  Enable the client and server to support renegotiation. Change the length of the renegotiated_connection field
*           in the server hello message to a non-zero value. Check whether the connection is successfully established.
* @precon  nan
* @brief  1. The client and server support renegotiation and connection establishment. Change the length of the
*            renegotiated_connection field in the server hello message to a non-zero value. Then, the connection
*           is established. Expected result 1 is obtained.
* @expect 1. The connection fails to be set up and an ALERT_HANDSHAKE_FAILURE message is sent.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC003(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isSupportRenegotiation = true;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

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
    ASSERT_TRUE(serverMsg->secRenego.exDataLen.data == 0u);
    serverMsg->secRenego.exDataLen.data = 1u;

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

    /* The connection fails to be set up and an ALERT_HANDSHAKE_FAILURE message is sent. */
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

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC002
* @titleThe server does not support renegotiation. The serverhello message carries the renegotiation extension.
* @precon nan
* @brief
*   1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
*   2. When the client receives a SERVER_HELLO message during continuous link establishment, the client checks whether
*     the message carries the renegotiation extension. Expected result 2 is obtained.
* @expect
*   1. The initialization is successful.
*   2. The renegotiation extension is expected to be carried.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC002(void)
{
    FRAME_Init();
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.isSupportRenegotiation = false;

    testInfo.config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(testInfo.config != NULL);

    testInfo.server = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.server != NULL);
    testInfo.client = FRAME_CreateLink(testInfo.config, BSL_UIO_TCP);
    ASSERT_TRUE(testInfo.client != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.body.hsMsg.body.serverHello.secRenego.exLen.data != 0);

    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    testInfo.state = HS_STATE_BUTT;
    ASSERT_TRUE(DefaultCfgStatusPark1(&testInfo) == HITLS_SUCCESS);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC009
* @title  Renegotiation flag condition
* @precon  nan
* @brief  1. The client and server support renegotiation and connection establishment. Before receiving the client hello
*            message, the server disables security renegotiation. Expected result 1 is displayed.
*         2. After the server receives the client hello message, enable the security renegotiation on the server.
*            Expected result 2 is displayed.
* @expect 1. The isSecureRenegotiation is false.
*         2. The isSecureRenegotiation is true.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC009(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    config->isSupportRenegotiation = true;
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->negotiatedInfo.isSecureRenegotiation == false);
    FRAME_LinkObj *client1 = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server1 = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client1, server1, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(server1->ssl->negotiatedInfo.isSecureRenegotiation == true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client1);
    FRAME_FreeLink(server1);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC013
* @title  Configure the client and server to support renegotiation. After the first handshake is complete, a
* renegotiation request is initiated. When the client sends a client hello message,
*         Modify the message and delete the renegotiation_info extension. The server is expected to return an alert
* after receiving the message.
* @precon nan
* @brief  1. The client and server support renegotiation and connection establishment. Start renegotiation. The expected
*           connection establishment is successful.
* @expect 1. When the client sends the client hello message, modify the message and remove the renegotiation_info
*           extension. As a result, the expected connection establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC013(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    /* The client and server support renegotiation and connection establishment. Start renegotiation. */
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
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    uint8_t verifyData[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataSize = 0;
    ASSERT_TRUE(
        HITLS_GetFinishVerifyData(client->ssl, verifyData, sizeof(verifyData), &verifyDataSize) == HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_RECV_CLIENT_HELLO, REC_TYPE_HANDSHAKE, true, NULL, Test_RenegoRemoveExtension};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HITLS_Renegotiate(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) != HITLS_SUCCESS);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC005
* @title  The client and server support renegotiation and connection establishment. Start renegotiation. Check whether
*         the serverhello contains the renegotiation extension. Check whether the connection is successfully
*         established and verify the negotiation behavior.
* @precon  nan
* @brief  1. The client and server support renegotiation and connection establishment. Start renegotiation. Expected
*           result 1 is obtained.
* @expect 1. Modify the cipher suite in the client hello, add the SCSV, and check whether the connection is successfully
*           set up. Expected result 2 is obtained.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC005(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    /* The client and server support renegotiation and connection establishment. Start renegotiation. */
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
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);

    uint8_t verifyData[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataSize = 0;
    ASSERT_TRUE(
        HITLS_GetFinishVerifyData(client->ssl, verifyData, sizeof(verifyData), &verifyDataSize) == HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_RECV_CLIENT_HELLO, REC_TYPE_HANDSHAKE, true, NULL, Test_RenegoWrapperFunc};
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HITLS_Renegotiate(serverTlsCtx) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(clientTlsCtx) == HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC010
* @title  Configure the client and server to support renegotiation and connection establishment. The
*           renegotiated_connection field in the client hello extension received by the server is not 0.
* @precon  nan
* @brief  1. Configure the client and server to support renegotiation and establish a connection. Expected result 1 is
*           obtained.
*         2. Modify the client hello message received by the server. Modify the renegotiated_connection field extended
*           by the (HS_EX_TYPE_RENEGOTIATION_INFO) to ensure that the length of the field is not 0.
* @expect 1. The initialization is successful.
*         2. The server sends the ALERT message. The level is ALERT_LEVEL_FATAL and the description is
*           ALERT_HANDSHAKE_FAILURE.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC010(void)
{
    /* Configure the client and server to support renegotiation and establish a connection. */
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isSupportRenegotiation = true;
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

    /* Modify the client hello message received by the server. Modify the renegotiated_connection field extended by the
     * (HS_EX_TYPE_RENEGOTIATION_INFO) to ensure that the length of the field is not 0. */
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientMsg->secRenego.exDataLen.data == 0u);
    clientMsg->secRenego.exState = INITIAL_FIELD;
    clientMsg->secRenego.exType.state = INITIAL_FIELD;
    clientMsg->secRenego.exType.data = 0xFF01u;
    clientMsg->secRenego.exLen.state = INITIAL_FIELD;
    clientMsg->secRenego.exLen.data = 2;
    clientMsg->secRenego.exDataLen.state = INITIAL_FIELD;
    clientMsg->secRenego.exDataLen.data = 1u;
    clientMsg->secRenego.exData.state = INITIAL_FIELD;
    clientMsg->secRenego.exData.size = 1;
    clientMsg->secRenego.exData.data = BSL_SAL_Calloc(1, sizeof(uint8_t));

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_TRUE(HITLS_Accept(testInfo.server->ssl) == HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);

    ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    parseLen = 0;
    frameType.recordType = REC_TYPE_ALERT;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_AlertMsg *alertMsg = &frameMsg.body.alertMsg;
    ASSERT_TRUE(alertMsg->alertLevel.data == ALERT_LEVEL_FATAL);
    ASSERT_TRUE(alertMsg->alertDescription.data == ALERT_HANDSHAKE_FAILURE);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC011
* @title  The client and server support renegotiation and connection establishment. Check whether the serverhello
*         contains the renegotiation extension. Check whether the connection is successfully established and verify the
*         negotiation behavior.
* @precon  nan
* @brief  1. If the client and server support renegotiation and connection establishment, check the serverhello message
*            that contains the renegotiation extension, and check whether the connection establishment is successful.
*           (Expected result 1)
* @expect 1. Modify the cipher suite in the client hello, add the SCSV, and check whether the connection is successfully
*           set up. Expected result 2 is obtained.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC011(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    /* If the client and server support renegotiation and connection establishment, check the serverhello message that
     * contains the renegotiation extension, and check whether the connection establishment is successful. */
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
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    /* Modify the cipher suite in the client hello, add the SCSV, and check whether the connection is successfully set
     * up. */
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ServerHelloHaveSecRenego};
    RegisterWrapper(wrapper);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ClientHello_SecRenego(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientMsg->secRenego.exState, INITIAL_FIELD);
    ASSERT_TRUE(
        clientMsg->cipherSuites.data[clientMsg->cipherSuitesSize.data / 2 - 1] != TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC004
* @title  The client and server support renegotiation and connection establishment. Check whether the clienthello
*         contains the renegotiation extension. Check whether the connection is successfully established and verify the
*         negotiation behavior.
* @precon  nan
* @brief  1. Enable the client to support renegotiation and connection establishment. Initiate renegotiation and check
*           whether the client hello contains secure Renegotiation extension and whether the cipher suite list contains
*           the SCSV cipher suite.
* @expect 1. The client hello message contain the secure Renegotiation extension but does not contain the SCSV cipher
*           suite.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC004(void)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    /* If the client and server support renegotiation and connection establishment, check the clienthello message that
     * contains the renegotiation extension, and check whether the connection establishment is successful. */
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
    ASSERT_EQ(clientTlsCtx->state, CM_STATE_IDLE);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHello_SecRenego};
    RegisterWrapper(wrapper);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyServerHello_Secrenegotiation1(
    HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
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
    serverMsg->secRenego.exData.data[0] = serverMsg->secRenego.exData.data[0] + 1;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_ModifyServerHello_Secrenegotiation2(
    HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
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
    serverMsg->secRenego.exData.data[serverMsg->secRenego.exData.size - 1] =
        serverMsg->secRenego.exData.data[serverMsg->secRenego.exData.size - 1] + 1;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test     UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC007
* @title    HITLS_GetRenegotiationState Interface Verification
* @precon   nan
* @brief    Configure the client and server to support renegotiation and connection establishment.
*           Initiate renegotiation, modify the first part of renegotiated_connection in the server hello message,
*           and check whether the connection is set up successfully.
* @expect
*       create connection failed
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyServerHello_Secrenegotiation1};
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC008
* @spec     -
* @title    HITLS_GetRenegotiationState Interface Verification
* @precon   nan
* @brief    Configure the client and server to support renegotiation and connection establishment.
*           Initiate renegotiation, modify the last part of renegotiated_connection in the server hello message,
*           and check whether the connection is set up successfully.
* @expect
*   create connection failed
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyServerHello_Secrenegotiation2};
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyServerHello_Secrenegotiation3(
    HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
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
    serverMsg->secRenego.exState = MISSING_FIELD;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC006
* @title  HITLS_GetRenegotiationState Interface Verification
* @precon  nan
* @brief Configure the client to support renegotiation and the server to support renegotiation and connection
*        establishment. Start renegotiation, construct a server hello message that does not contain the extension,
*        and check whether the connection is successfully set up.
* @expect
*   The server hello message does not contain the Secrenegotiation extension, and the connection fails to be established
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyServerHello_Secrenegotiation3};
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_HANDSHAKE_FAILURE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyClientHello_Secrenegotiation1(
    HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->secRenego.exData.data[0] = clientMsg->secRenego.exData.data[0] + 1;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC0014
* @title  The value of client_verify_data in the client hello message does not match the actual value
*          in the renegotiation state.
* @precon  nan
* @brief
*   Configure the client and server to support renegotiation.
*   After the first handshake is complete, initiate a renegotiation request.
*   When the client sends a client hello message,
*   modify the value of client_verify_data in the renegotiation_info extension.
* @expect
*   The server returns an alert message after receiving the message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC0014(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyClientHello_Secrenegotiation1};
    RegisterWrapper(wrapper);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);

    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_HANDSHAKE_FAILURE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ModifyServerHello_No_client_verify_data(
    HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
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
    serverMsg->secRenego.exData.size = 0;
    serverMsg->secRenego.exDataLen.data = 0;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC0015
* @title  The client_verify_data and server_verify_data fields of the client hello message
            are lost in the renegotiation state.
* @precon  nan
* @brief
* Configure the client and server to support renegotiation.
* After the first handshake is complete, initiate a renegotiation request.
* When the server sends a server hello message,
* delete the values of client_verify_data and server_verify_data from the renegotiation_info extension.
* @expect
*   The client returns an alert message after receiving the message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC0015(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ModifyServerHello_No_client_verify_data};
    RegisterWrapper(wrapper);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT), HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_HANDSHAKE_FAILURE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_ClientHelloHaveSecRenego(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
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
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientMsg->secRenego.exState, INITIAL_FIELD);
    clientMsg->cipherSuites.data[clientMsg->cipherSuitesSize.data / 2 - 1] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
    ASSERT_EQ(parseLen, *len);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test  UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC0012
* @title  In the renegotiation state, the client hello message carries the SCSV.
* @precon  nan
* @brief
* Configure the client and server to support renegotiation. After the first handshake is complete,
* initiate a renegotiation request. When the client sends a client hello message, modify the cipher suite and add SCSV.
* After receiving the message, the server is expected to return an alert message.
* @expect
*   The client returns an alert message after receiving the message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5746_CONSISTENCY_EXTENDED_RENEGOTIATION_FUNC_TC0012(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    bool isRenegotiation = true;
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_SetRenegotiationSupport(server->ssl, true);
    HITLS_SetClientRenegotiateSupport(server->ssl, true);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetRenegotiationState(client->ssl, &isRenegotiation) == HITLS_SUCCESS);
    ASSERT_TRUE(isRenegotiation == false);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHelloHaveSecRenego};
    RegisterWrapper(wrapper);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_MSG_HANDLE_RENEGOTIATION_FAIL);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_HANDSHAKE_FAILURE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
