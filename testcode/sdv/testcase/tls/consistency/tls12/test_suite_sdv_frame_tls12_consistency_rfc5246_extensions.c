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
#include "process.h"
#include "hitls_type.h"
#include "rec.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "frame_msg.h"
#include "stub_crypt.h"
/* END_HEADER */
#define BUF_TOOLONG_LEN ((1 << 14) + 1)

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    int32_t emsMode;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isSupportRenegotiation;
    bool isServerExtendedMasterSecret;
} HandshakeTestInfo;

int32_t StatusPark(HandshakeTestInfo *testInfo)
{
    /* Construct a link. */
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /*Set up a link and stop in a certain state. */
    if (FRAME_CreateConnection(testInfo->client, testInfo->server,
                               testInfo->isClient, testInfo->state) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    /* Construct the configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo->config, groups, sizeof(groups) / sizeof(uint16_t));
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo->config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    testInfo->config->emsMode = testInfo->emsMode;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusPark(testInfo);
}

/* @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC001
* @title The client sends a Client Certificate message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. The client initiates a DTLS link creation request. When the client needs to send a Client Certificate message, the two fields are modified as follows:
Certificates Length is 2 ^ 14 + 1
Certificates are changed to 2 ^ 14 + 1 byte buffer.
After the modification is complete, send the modification to the server. Expected result 2 is obtained.
3. When the server receives the Client Certificate message, check the value returned by the HITLS_Accept interface. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
2. The field is successfully modified and sent to the client.
3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC001(void)
{
    HandshakeTestInfo testInfo = {0};

    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isClient = false;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
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
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC002
* @title The server sends a Server Certificate message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. The client initiates a DTLS link creation request. When the server needs to send a Server Certificate message, the server modifies the following two fields:
Certificates Length is 2 ^ 14 + 1
Certificates are changed to 2 ^ 14 + 1 byte buffer.
After the modification is complete, send the modification to the server. Expected result 2 is obtained.
3. When the client receives the Server Certificate message, check the value returned by the HITLS_Connect interface. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
2. The field is successfully modified and sent to the client.
3. The return value of the HITLS_Connect interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC002(void)
{
    HandshakeTestInfo testInfo = {0};

    testInfo.state = TRY_RECV_CERTIFICATE;
    testInfo.isClient = true;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
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
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC003
* @title The client sends a Change Cipher Spec message with the length of 2 ^ 14 + 1 byte.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. When the client initiates a DTLS link establishment request and sends a Change Cipher Spec message, the client modifies one field as follows:
Length is 2 ^ 14 + 1. After the modification is complete, send the modification to the server. Expected result 2 is obtained.
3. When the server receives the Change Cipher Spec message, check the value returned by the HITLS_Accept interface. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
2. The field is successfully modified and sent to the client.
3. The return value of the HITLS_Accept interface is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC003(void)
{
    HandshakeTestInfo testInfo = {0};

    testInfo.state = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testInfo.isClient = false;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isSupportClientVerify = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS12;
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
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC004
* @title The client receives a Change Cipher Spec message with a length of zero.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. The client initiates a DTLS over SCTP link request. After sending a Finish message, the client constructs a Change Cipher Spec message with a zero length and sends the message to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
2. The client receives the message, which is HITLS_REC_NORMAL_RECV_BUF_EMPTY.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_MSGLENGTH_TOOLONG_TC004(void)
{
    HandshakeTestInfo testInfo = {0};
    testInfo.state = TRY_SEND_FINISH;
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server) == HITLS_SUCCESS);

    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    frameType1.versionType = HITLS_VERSION_TLS12;
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

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.client->io);
    ioUserData1->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);

    FRAME_CleanMsg(&frameType1, &frameMsg1);
    memset_s(&frameMsg1, sizeof(frameMsg1), 0, sizeof(frameMsg1));

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_RECORD_OVERFLOW);

    ASSERT_EQ(testInfo.client->ssl->hsCtx->state, TRY_RECV_NEW_SESSION_TICKET);
    bool isCcsRecv = testInfo.client->ssl->method.isRecvCCS(testInfo.client->ssl);
    ASSERT_TRUE(isCcsRecv == false);
EXIT:
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */


int32_t StatusPark1(HandshakeTestInfo *testInfo)
{
    if(testInfo->isServerExtendedMasterSecret == true){
        testInfo->config->emsMode = HITLS_EMS_MODE_FORCE;
    }else {
        testInfo->config->emsMode = HITLS_EMS_MODE_PREFER;
    }
    testInfo->config->isSupportRenegotiation = false;
    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if(testInfo->isServerExtendedMasterSecret == true){
        testInfo->config->emsMode = HITLS_EMS_MODE_PREFER;
    }else {
        testInfo->config->emsMode = HITLS_EMS_MODE_FORCE;
    }
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (FRAME_CreateConnection(testInfo->client, testInfo->server,
                               testInfo->isClient, testInfo->state) != HITLS_SUCCESS) {
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

    testInfo->config->emsMode = testInfo->emsMode;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusPark1(testInfo);
}


/* @
* @test UT_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_TC001
* @title The client does not forcibly verify the master key extension. The server supports the master key extension. The extended information in client hello and server hello is carried.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server, and configure the client not to forcibly verify the master key extension. The server supports this function. Expected result 1 is obtained.
2. When the client continuously sets up a link, the server receives the CLIENT_HELLO message and checks whether the extension of the master key is carried. Expected result 2 is obtained.
3. When the client receives the SERVER_HELLO message, check whether the message carries the master key extension. Expected result 2 is obtained.
4. Continue to establish the link. Expected result 3 is obtained.
* @expect 1. The initialization is successful.
2. The master key extension is expected to be carried.
3. Expected Master Key Extension
4. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};

    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    testInfo.isServerExtendedMasterSecret = true;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark1(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(frameMsg.body.hsMsg.body.clientHello.extendedMasterSecret.exState , INITIAL_FIELD);

    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_CFG_FreeConfig(testInfo.config);

    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark1(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf1 = ioUserData1->recMsg.msg;
    uint32_t recvLen1 = ioUserData1->recMsg.len;
    ASSERT_TRUE(recvLen1 != 0);

    frameType1.versionType = HITLS_VERSION_TLS12;
    frameType1.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType1, recvBuf1, recvLen1, &frameMsg1, &parseLen) == HITLS_SUCCESS);

    ASSERT_EQ(frameMsg1.body.hsMsg.body.serverHello.extendedMasterSecret.exState , INITIAL_FIELD);

    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_CFG_FreeConfig(testInfo.config);
    testInfo.state = HS_STATE_BUTT;
    ASSERT_TRUE(DefaultCfgStatusPark1(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

/* @
* @test UT_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_TC002
* @title The client supports the extension of the key for strong verification, but the server does not. The clienthello carries the extension of the master key, and the serverhello carries the extension of the master key. The link is successfully established.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server, and configure the client to forcibly verify the master key extension. The server does not support the extension. Expected result 1 is displayed.
2. When the client is continuously establishing a link, the server receives the Client_Hello message and checks whether the client_Hello message carries the master key extension. Expected result 2 is obtained.
3. When the client receives the SERVER_HELLO message, check whether the message carries the master key extension. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. Expected to carry the master key extension.
3. The master key extension is expected to be carried.
4. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_TC002(void)
{
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(s_config != NULL);

    HITLS_CFG_SetExtendedMasterSecretSupport(c_config, true);
    HITLS_CFG_SetExtendedMasterSecretSupport(s_config, false);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) , HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.body.hsMsg.body.clientHello.extendedMasterSecret.exState == INITIAL_FIELD);

    HITLS_Accept(server->ssl);
    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) , HITLS_SUCCESS);

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf1 = ioUserData1->recMsg.msg;
    uint32_t recvLen1 = ioUserData1->recMsg.len;
    ASSERT_TRUE(recvLen1 != 0);

    uint32_t parseLen1 = 0;
    frameType1.versionType = HITLS_VERSION_TLS12;
    frameType1.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType1, recvBuf1, recvLen1, &frameMsg1, &parseLen1) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg1.body.hsMsg.body.serverHello.extendedMasterSecret.exState == INITIAL_FIELD);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) , HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/* @
* @test UT_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_TC004
* @title The client and server support master key extension. The client hello message carries master key extension and the server hello message carries master key extension. The link is successfully established.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server to support master key extension. (Expected result 1)
2. When the client continuously sets up a link, the server checks whether the client_hello message carries the master key extension when receiving the CLIENT_HELLO message. Expected result 2 is obtained.
3. When the client receives the SERVER_HELLO message, check whether the message carries the master key extension. Expected result 3 is obtained.
4. Continue to establish the link. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. Expected to carry the master key extension.
3. The master key extension is expected to be carried.
4. The link is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_TC004(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};

    FRAME_Msg frameMsg1 = {0};
    FRAME_Type frameType1 = {0};
    testInfo.emsMode = HITLS_EMS_MODE_FORCE;
    testInfo.state = TRY_RECV_CLIENT_HELLO;
    testInfo.isClient = false;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    frameType.versionType = HITLS_VERSION_TLS12;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg.body.hsMsg.body.clientHello.extendedMasterSecret.exState == INITIAL_FIELD);

    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    testInfo.state = TRY_RECV_SERVER_HELLO;
    testInfo.isClient = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData1 = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf1 = ioUserData1->recMsg.msg;
    uint32_t recvLen1 = ioUserData1->recMsg.len;
    ASSERT_TRUE(recvLen1 != 0);

    frameType1.versionType = HITLS_VERSION_TLS12;
    frameType1.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType1, recvBuf1, recvLen1, &frameMsg1, &parseLen) == HITLS_SUCCESS);

    ASSERT_TRUE(frameMsg1.body.hsMsg.body.serverHello.extendedMasterSecret.exState == INITIAL_FIELD);

    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    testInfo.state = HS_STATE_BUTT;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    FRAME_CleanMsg(&frameType1, &frameMsg1);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */

static void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
    frametype->transportType = BSL_UIO_TCP;
}

/* @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_GROUP_SUPPORT_TC001
* @title Set multiple groups, among which there are groups that are not supported by the protocol version. The expected
*       group sent by the client is only the group it supports.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server. Expected result 1 is obtained.
2. Set up two groups, HITLS_EC_GROUP_SECP521R1 and HITLS_FF_DHE_2048, where HITLS_FF_DHE_2048 is not supported in
*   tls1.2. Expected result 2 is obtained.
3. Continue to establish the link， Stop the server handshake state at TRY_RECV_CLIENT_HELLO state. Expected result 3
*   is obtained.
4. Analyze the client hello message, retrieve the group list sent by the client, and check if there is only one group,
*   HITLS_EC_GROUP_SECP521R1. Expected result 4 is obtained.
* @expect 1. The initialization is successful.
2. return HITLS_SUCCESS.
3. return HITLS_SUCCESS.
4. The group list in the parsed client hello message only contains one group, HITLS_EC_GROUP_SECP521R1.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_GROUP_SUPPORT_TC001()
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx != NULL);
    ASSERT_TRUE(serverTlsCtx != NULL);

    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1, HITLS_FF_DHE_2048};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    ASSERT_EQ(HITLS_CFG_SetGroups(&(clientTlsCtx->config.tlsConfig), groups, groupsSize), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;

    FRAME_Msg frameMsg = { 0 };
    FRAME_Type frameType = { 0 };

    uint32_t parseLen = 0;
    SetFrameType(&frameType, HITLS_VERSION_TLS12, REC_TYPE_HANDSHAKE, CLIENT_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientMsg->supportedGroups.exData.data[0], HITLS_EC_GROUP_SECP521R1);
    ASSERT_EQ(clientMsg->supportedGroups.exData.size, 1);

    // Error stack exists
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackNotEmpty());

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

