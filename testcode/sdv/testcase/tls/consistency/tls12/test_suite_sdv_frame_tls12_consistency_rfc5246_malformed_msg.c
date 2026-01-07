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
#include "pack_msg.h"
#include "stub_crypt.h"
/* END_HEADER */

/* @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC009
* @title record layer allows the sending of the APPdata message with the length of zero.
* @precon nan
* @brief
    1. Establish a link. After the link is established, construct an Appdata message with zero length and send it to the
    server. Then, send an APPdata message with data to the server. Expected result 1 is obtained.
* @expect 1. Expected success
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC009(int messageLen)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    ASSERT_EQ(TlsCtxNew(BSL_UIO_TCP), HITLS_SUCCESS);
    ASSERT_EQ(REC_Init(g_tlsCtx), HITLS_SUCCESS);
    /*  1. Establish a link. After the link is established, construct an Appdata message with zero length and send it to
     * the server. Then, send an APPdata message with data to the server. */

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_TRANSPORTING);
    uint8_t data[REC_MAX_CIPHER_TEXT_LEN];
    ASSERT_EQ(REC_Write(clientTlsCtx, REC_TYPE_APP, data, messageLen), HITLS_SUCCESS);
EXIT:
    TlsCtxFree();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC010
* @title record layer allows the sending of the APPdata message with the length of zero.
* @precon nan
* @brief
1. Establish a link. After the link is established, construct an APPdata message with zero length and send it to the
client. Then, send an APPdata message with data to the client. Expected result 1 is obtained.
* @expect 1. Expected success
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_RECV_ZEROLENGTH_MSG_TC010(int messageLen)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    ASSERT_EQ(TlsCtxNew(BSL_UIO_TCP), HITLS_SUCCESS);
    ASSERT_EQ(REC_Init(g_tlsCtx), HITLS_SUCCESS);
    /* 1. Establish a link. After the link is established, construct an APPdata message with zero length and send it to
     * the client. Then, send an APPdata message with data to the client. */
    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    client = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_TRANSPORTING);

    uint8_t data[REC_MAX_CIPHER_TEXT_LEN];
    ASSERT_EQ(REC_Write(serverTlsCtx, REC_TYPE_APP, data, messageLen), HITLS_SUCCESS);
EXIT:
    TlsCtxFree();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_TLS12_RFC5246_CONSISTENCY_MISS_CLIENT_KEYEXCHANGE_TC001
* @title During the handshake, the client receives the CCS when the client is in the TRY_RECV_FINISH state.
* @precon nan
* @brief    1. Configure the single-end authentication. After the server sends the serverhellodone message, the client
            stops in the try send client key exchange state. Expected result 1
            2. Construct an unexpected CCS message and send it to the server. Expected result 2 is obtained.
* @expect   1. The initialization is successful.
            2. The connection fails to be established and the server returns an unexpected message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_MISS_CLIENT_KEYEXCHANGE_TC001(void)
{
    HandshakeTestInfo testInfo = {0};
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    /* 1. Configure the single-end authentication. After the server sends the serverhellodone message, the client
     *     stops in the try send client key exchange state. */
    testInfo.state = TRY_SEND_CLIENT_KEY_EXCHANGE;
    testInfo.isSupportExtendedMasterSecret = true;
    testInfo.isClient = true;

    testInfo.isSupportClientVerify = false;
    testInfo.isSupportNoClientCert = false;
    testInfo.needStopBeforeRecvCCS = true;
    ASSERT_TRUE(DefaultCfgStatusPark(&testInfo) == HITLS_SUCCESS);

    //  2. Construct an unexpected CCS message and send it to the server.
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
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    FRAME_DeRegCryptMethod();
}
/* END_CASE */


// To test whether fragmented messages can be received correctly. Test REC_TlsReadNbytes
/* BEGIN_CASE */
void UT_TLS_TLS12_RFC5246_CONSISTENCY_FRAGMENTED_MSG_TC001(void)
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
    // Handshake messages are divided into two records, and the two records are read separately.
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t data[MAX_RECORD_LENTH] = {0};
    uint32_t dataLen = MAX_RECORD_LENTH;
    ASSERT_EQ(memcpy_s(data, MAX_RECORD_LENTH, ioUserData->sndMsg.msg, ioUserData->sndMsg.len), 0);
    dataLen = ioUserData->sndMsg.len;

    uint32_t msglength = BSL_ByteToUint16(&data[3]);
    uint32_t msgLen = (msglength - 1) / 2;
    uint32_t len = 5 + msgLen;  // record + handshakemsg
    // Send the first segment of packets. eg.163 = （5 + 70） + 5 +83
    uint8_t recorddata1[] = {0x16, 0x03, 0x03, 0x00, 0x46};
    // The last two bytes of the first five bytes of the length of bodylen are modified.
    BSL_Uint16ToByte((uint16_t)msgLen, &recorddata1[3]);
    ASSERT_EQ(memcpy_s(ioUserData->sndMsg.msg, MAX_RECORD_LENTH, data, len), 0);
    ASSERT_EQ(memcpy_s(ioUserData->sndMsg.msg, MAX_RECORD_LENTH, recorddata1, sizeof(recorddata1)), 0);
    // Send the second segment of packets. eg.163 = 5 + 70 + （5 +83）
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
    ASSERT_EQ(ret, HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->state == CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */