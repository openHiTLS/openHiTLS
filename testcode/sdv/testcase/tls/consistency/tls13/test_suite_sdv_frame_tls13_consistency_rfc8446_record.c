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

#include "stub_utils.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
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
#include "conn_init.h"
#include "alert.h"
#include "hs_kx.h"
#include "rec_wrapper.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, RecParseInnerPlaintext, TLS_Ctx *, const uint8_t *, uint32_t *, uint8_t *);


#define MAX_RECORD_LENTH (20 * 1024)
#define ALERT_BODY_LEN 2u
const uint8_t ccsMessage[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

static int32_t SendCcs(HITLS_Ctx *ctx, uint8_t *data, uint8_t len)
{
    /** Write records. */
    int32_t ret = REC_Write(ctx, REC_TYPE_CHANGE_CIPHER_SPEC, data, len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* If isFlightTransmitEnable is enabled, the stored handshake information needs to be sent. */
    bool isFlightTransmitEnable = false;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable == true) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t SendAlert(HITLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    uint8_t data[ALERT_BODY_LEN];
    /** Obtain the alert level. */
    data[0] = level;
    data[1] = description;
    /** Write records. */
    int32_t ret = REC_Write(ctx, REC_TYPE_ALERT, data, ALERT_BODY_LEN);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* If isFlightTransmitEnable is enabled, the stored handshake information needs to be sent. */
    bool isFlightTransmitEnable = false;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable == true) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t SendErrorAlert(HITLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    uint8_t data[2 * ALERT_BODY_LEN] = {level, description, level, description};
    /** Write records. */
    int32_t ret = REC_Write(ctx, REC_TYPE_ALERT, data, 2 * ALERT_BODY_LEN);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* If isFlightTransmitEnable is enabled, the stored handshake information needs to be sent. */
    bool isFlightTransmitEnable = false;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable == true) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}
/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC001
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief    5 Record Protocol line 181
*           1. After the client sends a client hello message, the CCS message received by the client is not encrypted
*            (value: 0x01).
*           Discard the message and do not process the message. If the CCS message that is not encrypted is received
*            again (value: 0x01), the system discards the message.
*           3. Before the client receives the finished message, the client receives the CCS message that is not
*            encrypted (value: 0x01) and discards the message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg, MAX_RECORD_LENTH, ioServerData->sndMsg.msg, ioServerData->sndMsg.len) == EOK);
    sndMsg.len = ioServerData->sndMsg.len;
    ioServerData->sndMsg.len = 0;
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 1. After the client sends a client hello message, the CCS message received by the client is not encrypted */
    /* 3. Before the client receives the finished message, the client receives the CCS message that is not
     *    encrypted */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC002
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief    5 Record Protocol line 181
*           2. After the first connection is established, the server receives the client hello message and receives the
*                CCS message that is not encrypted (value: 0x01). The server discards the message and does not process
*                the message.
*           4. If the server receives the CCS message that is not encrypted (value: 0x01) before the finished message is
*                received during the first connection setup, Discard the message and do not process the message. If the
*                CCS message that is not encrypted is received again (value: 0x01), the system sends the
*                unexpected_message alarm to terminate the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);

    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;

    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 2. After the first connection is established, the server receives the client hello message and receives the
     *    CCS message that is not encrypted (value: 0x01). The server discards the message and does not process
     *     the message.
     * 4. If the server receives the CCS message that is not encrypted (value: 0x01) before the finished message is
     *    received during the first connection setup, Discard the message and do not process the message. If the
     *    CCS message that is not encrypted is received again (value: 0x01) */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* The server generates the unexpected_message alarm after receiving the CCS message for the second time. */
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC003
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief    5 Record Protocol line 181
*           5. After the session is recovered, the clien sends the clienthello message, receives the CCS message that is
*                not encrypted (value: 0x01), and discards the message.
*           7. The session is resumed. Before the finished message is received, the client receives a CCS message that
*                is not encrypted (value: 0x01). The client discards the message and does not process the message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg, MAX_RECORD_LENTH, ioServerData->sndMsg.msg, ioServerData->sndMsg.len) == EOK);
    sndMsg.len = ioServerData->sndMsg.len;
    ioServerData->sndMsg.len = 0;
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 5. After the session is recovered, the clien sends the clienthello message, receives the CCS message that is
     * not encrypted (value: 0x01), and discards the message.
     * 7. The session is resumed. Before the finished message is received, the client receives a CCS message
     * that is not encrypted (value: 0x01). */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC004
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief    5 Record Protocol line 181
*           6. After the session is resumed, the server receives a CCS message that is not encrypted (value: 0x01) after
*            receiving the client hello message,
*           The message is discarded and not processed. If the CCS message is received again and the unencrypted record
*            (value: 0x01) is not encrypted, the alarm "unexpected_message" is sent to terminate the handshake.
*           8. The session is recovered. Before the server receives the finished message, the CCS message is not
*            encrypted and the value is 0x01, and the message is discarded.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_RECV_FINISH);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 6.After the session is resumed, the server receives a CCS message that is not encrypted (value: 0x01) after
     *    receiving the client hello message,
     * 8.The session is recovered. Before the server receives the finished message, the CCS message is not
     *   encrypted and the value is 0x01 */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* The server generates the unexpected_message alarm after receiving the CCS message for the second time. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC005
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving unencrypted CCS messages, the system discards the messages.
* @precon nan
* @brief    5 Record Protocol line 181
*           9. After receiving the helloretry request, the client sends the client hello message for the second time.
*                 The received CCS message is not encrypted (value: 0x01).
*           Discard the message and do not process the message. If the CCS message is received again,
*           discard the messages.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC005(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    /* Configure the server to support only the non-default curve. The server sends the HRR message. */
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(tlsConfig, groups, groupsSize);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_HELLO_RETRY_REQUEST), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg, MAX_RECORD_LENTH, ioServerData->sndMsg.msg, ioServerData->sndMsg.len) == EOK);
    sndMsg.len = ioServerData->sndMsg.len;
    ioServerData->sndMsg.len = 0;
    uint8_t data = 1;

    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 9.After receiving the helloretry request, the client sends the client hello message for the second time.
     * The received CCS message is not encrypted (value: 0x01).
     * Discard the message and do not process the message. If the CCS message is received again and the
     * unencrypted record (value: 0x01) is received, the unexpected_message alarm is sent to terminate the handshake. */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* client will discard the ccs */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC006
* @spec   An implementation may receive an unencrypted record of
*         type change_cipher_spec consisting of the single byte
*         value 0x01 at any time after the first ClientHello message
*         has been sent or received and before the peer's Finished message
*         has been received and MUST simply drop it without further processing.
* @title  When receiving an unencrypted CCS message, the system discards the message.
* @precon nan
* @brief 5 Record Protocol line 181
*         10. After the server sends a helloretry request, the client hello message is received for the second time,
*           Send the unexpected_message alarm to terminate the handshake if the received CCS message is not encrypted
*            (value: 0x01).
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_IGNORE_CCS_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(tlsConfig, groups, groupsSize);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;

    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 10. After the server sends a helloretry request, the client hello message is received for the second time,
     *     Send the unexpected_message alarm to terminate the handshake if the received CCS message is not
     *     encrypted (value: 0x01). */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC001
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief 5 Record Protocol line 182
*           1. After the client sends a client hello message to the client, the client sends an unexpected_message alarm
*                to terminate the handshake because the client receives a CCS whose value is not 0x01.
*           7. Before the client receives the finised message, the client sends the unexpected_message alarm to
*                terminate the handshake because the client receives a CCS whose value is not 0x01.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg, MAX_RECORD_LENTH, ioServerData->sndMsg.msg, ioServerData->sndMsg.len) == EOK);
    sndMsg.len = ioServerData->sndMsg.len;
    ioServerData->sndMsg.len = 0;

    uint8_t data = 2;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* The client receives an unencrypted CCS message (value: 0x01) and sends an unexpected_message alarm to terminate
     * the handshake before the client receives the finished message. */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC002
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           2. After the client sends the client hello message to the first connection setup, the client sends the
*            unexpected_message alarm to terminate the handshake because the encrypted CCS is received.
*           9. Before the client receives the finised message, the client sends the unexpected_message alarm to
*            terminate the handshake because the client receives the encrypted CCS.
@ */

/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    serverTlsCtx->recCtx->outBuf->end = 0;
    uint32_t hashLen = SAL_CRYPT_DigestSize(serverTlsCtx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    ASSERT_EQ(
        HS_SwitchTrafficKey(serverTlsCtx, serverTlsCtx->hsCtx->serverHsTrafficSecret, hashLen, true), HITLS_SUCCESS);
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 2. After the client sends the client hello message to the first connection setup, the client sends the
     * unexpected_message alarm to terminate the handshake because the encrypted CCS is received.
     * 9. Before the client receives the finised message, the client sends the unexpected_message alarm to
     * terminate the handshake because the client receives the encrypted CCS. */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
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

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC003
* @spec An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title Send the unexpected_message alarm when receiving other CCS messages.
* @precon nan
* @brief 5 Record Protocol line 182
*   3. Before the server receives the client hello message, the server sends the unexpected_message alarm to terminate
*      the handshake because it receives a CCS with a value other than 0x01.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);

    uint8_t data = 2;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* Before the server receives the client hello message, the server sends the unexpected_message alarm to terminate
     * the handshake because the server receives a CCS with a value other than 0x01. */
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC004
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief 5 Record Protocol line 181
*           4. After the first connection is established, the server receives the client hello message and receives the
*            CCS whose value is not 0x01. Therefore, the server sends the unexpected_message alarm to terminate the
*            handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;

    uint8_t data = 2;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 4.After the first connection is established, the server receives the client hello message and receives the
     *   CCS whose value is not 0x01. Therefore, the server sends the unexpected_message alarm to terminate the
     *   handshake. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC005
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief    5 Record Protocol line 181
*           5. After the first connection is established, the server receives the client hello message and receives the
*            encrypted CCS. Therefore, the server sends the unexpected_message alarm to terminate the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC005(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;

    clientTlsCtx->recCtx->outBuf->end = 0;
    uint32_t hashLen = SAL_CRYPT_DigestSize(clientTlsCtx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    ASSERT_EQ(
        HS_SwitchTrafficKey(clientTlsCtx, clientTlsCtx->hsCtx->serverHsTrafficSecret, hashLen, true), HITLS_SUCCESS);
    /* Construct a non-0x1 CCS packet. */
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* After the first connection is established, the server receives the client hello message and receives the
     * encrypted CCS. Therefore, the server sends the unexpected_message alarm to terminate the handshake. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC006
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           8. After the client receives the finised message, the client sends the unexpected_message alarm to terminate
*            the handshake because it receives a CCS whose value is not 0x01.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->sndMsg.len = sizeof(ccsMessage);
    memcpy_s(ioServerData->sndMsg.msg, ioServerData->sndMsg.len, ccsMessage, sizeof(ccsMessage));

    ioServerData->sndMsg.msg[5] = 0x2;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 8. After the client receives the finised message, the client sends the unexpected_message alarm to terminate
     *    the handshake because it receives a CCS whose value is not 0x01. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC007
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           9. After the client receives the finised message, the client sends the unexpected_message alarm to terminate
*            the handshake because the client receives the encrypted CCS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ioServerData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 9. After the client receives the finised message, the client sends the unexpected_message alarm to terminate
     *    the handshake because the client receives the encrypted CCS */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
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

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC008
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           10. After the session is resumed, the client sends the unexpected_message alarm to terminate the handshake
*            because the client receives a CCS with a value other than 0x01.
*           15. Before the session is recovered, the client receives a CCS whose value is not 0x01. Therefore, the
*            client sends the unexpected_message alarm to terminate the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg sndMsg;
    ASSERT_TRUE(memcpy_s(sndMsg.msg, MAX_RECORD_LENTH, ioServerData->sndMsg.msg, ioServerData->sndMsg.len) == EOK);
    sndMsg.len = ioServerData->sndMsg.len;
    ioServerData->sndMsg.len = 0;
    uint8_t data = 2;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 10. After the session is resumed, the client sends the unexpected_message alarm to terminate the handshake
     *     because the client receives a CCS with a value other than 0x01.
     * 15. Before the session is recovered, the client receives a CCS whose value is not 0x01. Therefore, the
     *     client sends the unexpected_message alarm to terminate the handshake. */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC009
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon nan
* @brief    5 Record Protocol line 182
*           11. After the session is recovered, the client sends the "unexpected_message" alarm to terminate the
*                handshake because the client receives the encrypted CCS.
*           16. The session is recovered. Before the client receives the finised message, the client sends the
*                "unexpected_message" alarm to terminate the handshake because the client receives the encrypted CCS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC009(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    serverTlsCtx->recCtx->outBuf->end = 0;
    uint32_t hashLen = SAL_CRYPT_DigestSize(serverTlsCtx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    ASSERT_EQ(
        HS_SwitchTrafficKey(serverTlsCtx, serverTlsCtx->hsCtx->serverHsTrafficSecret, hashLen, true), HITLS_SUCCESS);

    uint8_t data = 1;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 11. After the session is recovered, the client sends the "unexpected_message" alarm to terminate the
     *     handshake because the client receives the encrypted CCS.
     *  16. The session is recovered. Before the client receives the finised message, the client sends the
     *     "unexpected_message" alarm to terminate the handshake because the client receives the encrypted CCS. */
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC010
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           12. Before the session is recovered, the server receives a CCS with a value other than 0x01 before receiving
*                the client hello message. Therefore, the server sends the unexpected_message alarm to terminate the
*                handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC010(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);

    uint8_t data = 2;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 12. Before the session is recovered, the server receives a CCS with a value other than 0x01 before receiving
     * the client hello message. Therefore, the server sends the unexpected_message alarm to terminate the
     * handshake. */
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC011
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon nan
* @brief 5 Record Protocol line 181
*           13. After receiving the client hello message, the server sends the unexpected_message alarm to terminate the
*                handshake because the server receives a CCS with a value other than 0x01.
*           19. Before the session is recovered, the server sends the unexpected_message alarm to terminate the
*                handshake because the server receives a CCS whose value is not 0x01.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC011(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;

    clientTlsCtx->recCtx->outBuf->end = 0;
    uint8_t data = 2;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 13. After receiving the client hello message, the server sends the unexpected_message alarm to terminate the
     *     handshake because the server receives a CCS with a value other than 0x01.
     * 19. Before the session is recovered, the server sends the unexpected_message alarm to terminate the
     *     handshake because the server receives a CCS whose value is not 0x01. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC012
* @spec     An implementation may receive an unencrypted record of
*           type change_cipher_spec consisting of the single byte
*           value 0x01 at any time after the first ClientHello message
*           has been sent or received and before the peer's Finished message
*           has been received and MUST simply drop it without further processing.
* @title    When receiving an unencrypted CCS message, the system discards the message.
* @precon   nan
* @brief    5 Record Protocol line 181
*           14. After the session is recovered, the server sends the unexpected_message alarm to terminate the handshake
*                because the server receives the encrypted CCS.
*           20. The session is recovered. Before the server receives the finised message, it receives the encrypted CCS.
*                Therefore, the server sends the "unexpected_message" alarm to terminate the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC012(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FrameMsg recMsg;
    ASSERT_TRUE(memcpy_s(recMsg.msg, MAX_RECORD_LENTH, ioServerData->recMsg.msg, ioServerData->recMsg.len) == EOK);
    recMsg.len = ioServerData->recMsg.len;
    ioServerData->recMsg.len = 0;

    clientTlsCtx->recCtx->outBuf->end = 0;
    uint32_t hashLen = SAL_CRYPT_DigestSize(clientTlsCtx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    ASSERT_EQ(
        HS_SwitchTrafficKey(clientTlsCtx, clientTlsCtx->hsCtx->serverHsTrafficSecret, hashLen, true), HITLS_SUCCESS);
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 14. After the session is recovered, the server sends the unexpected_message alarm to terminate the handshake
     *     because the server receives the encrypted CCS.
     * 20. The session is recovered. Before the server receives the finised message, it receives the encrypted
     *      CCS. Therefore, the server sends the "unexpected_message" alarm to terminate the handshake. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC013
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           17. After the session is recovered, the client receives a CCS whose value is not 0x01 and sends the
*                unexpected_message alarm to terminate the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC013(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->sndMsg.len = sizeof(ccsMessage);
    memcpy_s(ioServerData->sndMsg.msg, ioServerData->sndMsg.len, ccsMessage, sizeof(ccsMessage));
    ioServerData->sndMsg.msg[5] = 0x2;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /*  17. After the session is recovered, the client receives a CCS whose value is not 0x01 and sends the
     *  unexpected_message alarm to terminate the handshake. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC014
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           18. After the session is recovered, the client receives the finised message and receives the encrypted CCS.
*            Therefore, the client sends the unexpected_message alarm to terminate the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC014(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ioServerData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    /* 18. After the session is recovered, the client receives the finised message and receives the encrypted CCS.
     *     Therefore, the client sends the unexpected_message alarm to terminate the handshake. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(clientTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC015
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           21. After the session is recovered, the server sends the unexpected_message alarm to terminate the handshake
*                because the server receives a CCS whose value is not 0x01.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC015(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->sndMsg.len = sizeof(ccsMessage);
    memcpy_s(ioClientData->sndMsg.msg, ioClientData->sndMsg.len, ccsMessage, sizeof(ccsMessage));
    ioClientData->sndMsg.msg[5] = 0x2;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 21. After the session is recovered, the server sends the unexpected_message alarm to terminate the handshake
     *     because the server receives a CCS whose value is not 0x01. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC016
* @spec     An implementation which receives any other change_cipher_spec value or
*           which receives a protected change_cipher_spec record MUST
*           abort the handshake with an "unexpected_message" alert.
* @title    Send the unexpected_message alarm when receiving other CCS messages.
* @precon   nan
* @brief    5 Record Protocol line 182
*           22. After the session is recovered, the server sends the "unexpected_message" alarm to terminate the
*                handshake because the server receives the encrypted CCS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECEIVES_OTHER_CCS_FUNC_TC016(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);
    clientTlsCtx = FRAME_GetTlsCtx(client);
    serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    uint8_t data = 1;
    ASSERT_EQ(SendCcs(client->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    ioClientData->sndMsg.msg[0] = REC_TYPE_CHANGE_CIPHER_SPEC;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    /* 22. After the session is recovered, the server sends the "unexpected_message" alarm to terminate the
     *     handshake because the server receives the encrypted CCS. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(serverTlsCtx, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_RECORD_TYPE_FUNC_TC001
* @spec     Handshake messages MUST NOT be interleaved with other record types.
*           That is, if a handshake message is split over two or more records,
*           there MUST NOT be any other records between them.
* @title    Handshake messages must not be interleaved with other record types.
* @precon   nan
* @brief    5.1. Record Layer line 186
*           1. Handshake messages are sent to multiple records. Check whether records of other types exist between
*                the records.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_RECORD_TYPE_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

int32_t STUB_RecParseInnerPlaintext(TLS_Ctx *ctx, const uint8_t *text, uint32_t *textLen, uint8_t *recType)
{
    (void)ctx;
    (void)text;
    (void)textLen;
    *recType = (uint8_t)REC_TYPE_APP;

    return HITLS_SUCCESS;
}

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_RECORD_TYPE_FUNC_TC002
* @spec     Handshake messages MUST NOT be interleaved with other record types.
*           That is, if a handshake message is split over two or more records,
*           there MUST NOT be any other records between them.
* @title    Handshake messages must not be interleaved with other record types.
* @precon   nan
* @brief    5.1. Record Layer line 186
*           2. If multiple handshake messages are interspersed with other record (app) messages, the handshake fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_HANDSHAKE_RECORD_TYPE_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_FINISH) == HITLS_SUCCESS);
    STUB_REPLACE(RecParseInnerPlaintext, STUB_RecParseInnerPlaintext);;
    int32_t actualRet = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    if (actualRet != HITLS_REC_NORMAL_RECV_UNEXPECT_MSG) {
        printf("[TC002] MISMATCH: actual=0x%x (%d), expected=0x%x (%d)\n",
               actualRet, actualRet, HITLS_REC_NORMAL_RECV_UNEXPECT_MSG, HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    }
    ASSERT_TRUE(actualRet == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    STUB_RESTORE(RecParseInnerPlaintext);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_SINGLE_ALERT_FUNC_TC001
* @spec     A record with an Alert type MUST contain exactly one message.
* @title    A record with the Alert type must contain only one message.
* @precon   nan
* @brief    5.1. Record Layer line 186
*           1. The client sends multiple alarm messages, and the server handshake fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SINGLE_ALERT_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH) == HITLS_SUCCESS);

    clientTlsCtx->recCtx->outBuf->end = 0;
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.len = 0;
    ASSERT_TRUE(SendErrorAlert(client->ssl, ALERT_LEVEL_WARNING, ALERT_NO_CERTIFICATE_RESERVED) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_SINGLE_ALERT_FUNC_TC002
* @spec     A record with an Alert type MUST contain exactly one message.
* @title    A record with the Alert type must contain only one message.
* @precon   nan
* @brief    5.1. Record Layer line 186
*           2. When the server sends multiple alarm messages, the client handshake fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SINGLE_ALERT_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    /* Stop the client receiving the TRY_RECV_SERVER_HELLO state, and the server sending the TRY_SEND_SERVER_HELLO
     * state. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    serverTlsCtx->recCtx->outBuf->end = 0;
    ASSERT_TRUE(SendErrorAlert(server->ssl, ALERT_LEVEL_WARNING, ALERT_NO_CERTIFICATE_RESERVED) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC001
* @spec     legacy_record_version: MUST be set to 0x0303
*           for all records generated by a TLS 1.3 implementation
*           other than an initial ClientHello (i.e., one not generated
*           after a HelloRetryRequest), where it MAY also be 0x0301
*           for compatibility purposes. This field is deprecated
*           and MUST be ignored for all purposes. Previous versions of
*           TLS would use other values in this field under some circumstances.
* @title    For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*           where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*            purposes, it may be 0x0301.
* @precon nan
* @brief    5.1. Record Layer line 190
*           1. In TLS1.3, legacy_record_version is 0x0303 in the record message of the CCS.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    /* The client stops receiving the TRY_RECV_ENCRYPTED_EXTENSIONS. The server sends the EE message, but the EE message
     * is cached because the CCS message is sent first. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_ENCRYPTED_EXTENSIONS) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_ENCRYPTED_EXTENSIONS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg frameMsg = {0};
    uint8_t *buffer = ioClientData->recMsg.msg;
    uint32_t readLen = ioClientData->recMsg.len;
    uint32_t parseLen = 0;
    ASSERT_TRUE(ParserRecordHeader(&frameMsg, buffer, readLen, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.type, REC_TYPE_CHANGE_CIPHER_SPEC);
    ASSERT_TRUE(frameMsg.version == HITLS_VERSION_TLS12);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC002
* @spec     legacy_record_version: MUST be set to 0x0303
*           for all records generated by a TLS 1.3 implementation
*           other than an initial ClientHello (i.e., one not generated
*           after a HelloRetryRequest), where it MAY also be 0x0301
*           for compatibility purposes. This field is deprecated
*           and MUST be ignored for all purposes. Previous versions of
*           TLS would use other values in this field under some circumstances.
* @title    For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*           where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*            purposes, it may be 0x0301.
* @precon   nan
* @brief    5.1. Record Layer line 190
*           2. In TLS1.3, legacy_record_version is 0x0303 in the alert record message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);

    ASSERT_TRUE(SendAlert(server->ssl, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    FRAME_Msg frameMsg = {0};
    uint8_t *buffer = ioClientData->recMsg.msg;
    uint32_t readLen = ioClientData->recMsg.len;
    uint32_t parseLen = 0;
    ASSERT_TRUE(ParserRecordHeader(&frameMsg, buffer, readLen, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.type, REC_TYPE_ALERT);
    ASSERT_TRUE(frameMsg.version == HITLS_VERSION_TLS12);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC003
* @spec     legacy_record_version: MUST be set to 0x0303
*           for all records generated by a TLS 1.3 implementation
*           other than an initial ClientHello (i.e., one not generated
*           after a HelloRetryRequest), where it MAY also be 0x0301
*           for compatibility purposes. This field is deprecated
*           and MUST be ignored for all purposes. Previous versions of
*           TLS would use other values in this field under some circumstances.
* @title    For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*           where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*            purposes, it may be 0x0301.
* @precon nan
* @brief    5.1. Record Layer line 190
*           In 5. TLS1.3, legacy_record_version is set to 0x0301 in the record message of the init clienthello.
*           In 3.TLS1.3, legacy_record_version is 0x0303 in the session recovery clienthello message.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);

    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    FRAME_Msg frameMsg = {0};
    uint8_t *buffer = ioServerData->recMsg.msg;
    uint32_t readLen = ioServerData->recMsg.len;
    uint32_t parseLen = 0;
    ASSERT_TRUE(ParserRecordHeader(&frameMsg, buffer, readLen, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.type, REC_TYPE_HANDSHAKE);
    /* For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
     * where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
     * purposes, it may be 0x0301. */
    ASSERT_TRUE(frameMsg.version == HITLS_VERSION_TLS10);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ioServerData = BSL_UIO_GetUserData(server->io);
    buffer = ioServerData->recMsg.msg;
    readLen = ioServerData->recMsg.len;
    parseLen = 0;
    ASSERT_TRUE(ParserRecordHeader(&frameMsg, buffer, readLen, &parseLen) == HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.type, REC_TYPE_HANDSHAKE);
    ASSERT_TRUE(frameMsg.version == HITLS_VERSION_TLS10);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC004
* @spec     legacy_record_version: MUST be set to 0x0303
*           for all records generated by a TLS 1.3 implementation
*           other than an initial ClientHello (i.e., one not generated
*           after a HelloRetryRequest), where it MAY also be 0x0301
*           for compatibility purposes. This field is deprecated
*           and MUST be ignored for all purposes. Previous versions of
*           TLS would use other values in this field under some circumstances.
* @title    For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*           where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*            purposes, it may be 0x0301.
* @precon   nan
* @brief    5.1. Record Layer line 190
*           In TLS1.3, the value of legacy_record_version in the serverhello message is changed to 0xffff when the
*            session is recovered,
*           After the client receives the message, the client ignores this field and the session is successfully
*            restored.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC004(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    uint32_t bufOffset = 1;
    ioClientData->recMsg.msg[bufOffset] = 0x03;
    bufOffset++;
    ioClientData->recMsg.msg[bufOffset] = 0xff;
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test   UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC005
* @spec   legacy_record_version: MUST be set to 0x0303
*         for all records generated by a TLS 1.3 implementation
*         other than an initial ClientHello (i.e., one not generated
*         after a HelloRetryRequest), where it MAY also be 0x0301
*         for compatibility purposes. This field is deprecated
*         and MUST be ignored for all purposes. Previous versions of
*         TLS would use other values in this field under some circumstances.
* @title  For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*         where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*          purposes, it may be 0x0301.
* @precon nan
* @brief  5.1. Record Layer line 190
*         In TLS 7.1.3, the legacy_record_version field in the record message of the client hello message is changed to
*          0x0300. After the server receives the message, the server ignores the field and the handshake is still
*           successful.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC005(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    HITLS_Session *clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    uint32_t bufOffset = 1;
    ioClientData->recMsg.msg[bufOffset] = 0x03;
    bufOffset++;
    ioClientData->recMsg.msg[bufOffset] = 0xff;
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC006
* @spec     legacy_record_version: MUST be set to 0x0303
*           for all records generated by a TLS 1.3 implementation
*           other than an initial ClientHello (i.e., one not generated
*           after a HelloRetryRequest), where it MAY also be 0x0301
*           for compatibility purposes. This field is deprecated
*           and MUST be ignored for all purposes. Previous versions of
*           TLS would use other values in this field under some circumstances.
* @title    For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*           where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*            purposes, it may be 0x0301.
* @precon   nan
* @brief    5.1. Record Layer line 190
*           8. The server uses TLS1.2 and the value of legacy_record_version in the record message is 0x0303,
*           The client uses TLS 1.3 and the value of legacy_record_version in the record message is 0x0303. The
*            handshake is still successful.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC006(void)
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLSConfig();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(serverConfig != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC007
* @spec     legacy_record_version: MUST be set to 0x0303
*           for all records generated by a TLS 1.3 implementation
*           other than an initial ClientHello (i.e., one not generated
*           after a HelloRetryRequest), where it MAY also be 0x0301
*           for compatibility purposes. This field is deprecated
*           and MUST be ignored for all purposes. Previous versions of
*           TLS would use other values in this field under some circumstances.
* @title    For all records generated by the TLS 1.3 implementation, it must be set to 0x0303,
*           where the initial ClientHello (i.e., records not generated after HelloRetryRequest) For compatibility
*            purposes, it may be 0x0301.
* @precon   nan
* @brief    5.1. Record Layer line 190
*           9. Change TLSCiphertext.legacy_record_version in the encryption record of the app to 0xffff,
*           After the client receives the message, the client ignores this field and the session is still successful.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_RECORD_VERSION_FUNC_TC007(void)
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewTLSConfig();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(serverConfig != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_CIPHERTEXT_LENGTH_FUNC_TC001
* @spec     length: The length (in bytes) of the following TLSCiphertext.
*           encrypted_record, which is the sum of the lengths of the content and the padding,
*           plus one for the inner content type, plus any expansion added by the AEAD algorithm.
*           The length MUST NOT exceed 2^14 + 256 bytes. An endpoint that receives a record that
*           exceeds this length MUST terminate the connection with a "record_overflow" alert.
* @title    For TLS 1.3, the length of the ciphertext cannot exceed 2 ^ 14 + 256 bytes.
* @precon   nan
* @brief    5.2. Record Payload Protection line 194
*           1. A connection is established. During the connection establishment, the server receives a message whose
*           ciphertext  length is 2 ^ 14 + 257. The server is expected to send a record_overflow  alarm to
*           terminate the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CIPHERTEXT_LENGTH_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    /* The client stops receiving the TRY_RECV_ENCRYPTED_EXTENSIONS. The server sends the EE message. However, the EE
     * message is cached because the CCS message is sent first. */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.msg[3] = 0x41u;
    ioServerData->recMsg.msg[4] = 0x01u;
    /* For TLS 1.3, the length of the ciphertext cannot exceed 2 ^ 14 + 256 bytes. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_RECORD_OVERFLOW);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_CIPHERTEXT_LENGTH_FUNC_TC002
* @spec     length: The length (in bytes) of the following TLSCiphertext.
*           encrypted_record, which is the sum of the lengths of the content and the padding,
*           plus one for the inner content type, plus any expansion added by the AEAD algorithm.
*           The length MUST NOT exceed 2^14 + 256 bytes. An endpoint that receives a record that
*           exceeds this length MUST terminate the connection with a "record_overflow" alert.
* @title    For TLS 1.3, the length of the ciphertext cannot exceed 2 ^ 14 + 256 bytes.
* @precon   nan
* @brief    5.2. Record Payload Protection line 194
*           2. A connection is established. During the connection establishment, the client receives a message whose ciphertext
*            length is 2 ^ 14 + 257. The server is expected to send a record_overflow alarm to terminate the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_CIPHERTEXT_LENGTH_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_ENCRYPTED_EXTENSIONS) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_ENCRYPTED_EXTENSIONS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.msg[3] = 0x41u;
    ioClientData->recMsg.msg[4] = 0x01u;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_RECORD_OVERFLOW);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_RECORD_OVERFLOW);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_SEQUENCE_NUMBER_FUNC_TC001
* @spec     Each sequence number is set to zero at the beginning of a connection and whenever the key is changed;
*           the first record transmitted under a particular traffic key MUST use sequence number 0.
* @title    The sequence number is 0 when the connection starts or the key changes.
* @precon   nan
* @brief    5.3. Per-Record Nonce line 197
*           1. The client sends a finish packet and an app packet. After the seq number is not 0, the key is changed
*            successfully and the seq number is reset to 0.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SEQUENCE_NUMBER_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    uint32_t writeLen;
    ASSERT_TRUE(HITLS_Write(client->ssl, (uint8_t *)"Hello World", sizeof("Hello World"), &writeLen) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    REC_Ctx *recCtx = (REC_Ctx *)client->ssl->recCtx;
    ASSERT_TRUE(recCtx->writeStates.currentState->seq != 0);

    ASSERT_TRUE(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(recCtx->writeStates.currentState->seq == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_SEQUENCE_NUMBER_FUNC_TC002
* @spec     Each sequence number is set to zero at the beginning of a connection and whenever the key is changed;
*           the first record transmitted under a particular traffic key MUST use sequence number 0.
* @title    The sequence number is 0 when the connection starts or the key changes.
* @precon   nan
* @brief    5.3. Per-Record Nonce line 197
*           2. The client sends a finish packet and an app packet. After the seq number is not 0, the key fails to be
*            changed and the key is updated,
*           The seq number is not reset to 0. (It is to be confirmed whether the seq number is updated at both ends.)
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SEQUENCE_NUMBER_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint32_t writeLen;
    ASSERT_TRUE(HITLS_Write(client->ssl, (uint8_t *)"Hello World", sizeof("Hello World"), &writeLen) == HITLS_SUCCESS);
    REC_Ctx *recCtx = (REC_Ctx *)client->ssl->recCtx;
    ASSERT_TRUE(recCtx->writeStates.currentState->seq != 0);

    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->sndMsg.len = 1;

    ASSERT_TRUE(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(recCtx->writeStates.currentState->seq != 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_SEQUENCE_NUMBER_FUNC_TC003
* @spec     Each sequence number is set to zero at the beginning of a connection and whenever the key is changed;
*           the first record transmitted under a particular traffic key MUST use sequence number 0.
* @title    The sequence number is 0 when the connection starts or the key changes.
* @precon nan
* @brief    5.3. Per-Record Nonce line 197
*           1. The client sends a finish packet and an app packet. After the seq number is not 0, the key is changed
*            successfully and the seq number is reset to 0.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_SEQUENCE_NUMBER_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
    REC_Ctx *recCtx = (REC_Ctx *)server->ssl->recCtx;
    ASSERT_TRUE(recCtx->writeStates.currentState->seq != 0);

    ASSERT_TRUE(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(recCtx->writeStates.currentState->seq == 0);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    uint32_t writeLen;
    ASSERT_TRUE(HITLS_Write(server->ssl, (uint8_t *)"Hello World", sizeof("Hello World"), &writeLen) == HITLS_SUCCESS);
    ASSERT_TRUE(recCtx->writeStates.currentState->seq == 1);

    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void AppendKeyUpdateAfterRecord(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;

    const uint8_t ku[5] = { 0x18, 0x00, 0x00, 0x01, 0x00 };

    if (*len + (uint32_t)sizeof(ku) > bufSize) {
        return;
    }
    (void)memcpy_s(data + *len, bufSize - *len, ku, sizeof(ku));
    *len += (uint32_t)sizeof(ku);
}

static void AppendFinishedAfterRecord(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;

    /* Finished handshake: type=0x14, length=0 (empty verify_data as placeholder) */
    const uint8_t finished[4] = { 0x14, 0x00, 0x00, 0x00 };

    if (*len + (uint32_t)sizeof(finished) > bufSize) {
        return;
    }
    (void)memcpy_s(data + *len, bufSize - *len, finished, sizeof(finished));
    *len += (uint32_t)sizeof(finished);
}

/**
 * @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC001
 * @spec     -
 * @title    ServerHello not on record boundary - Client read key switch
 * @precon   nan
 * @brief    Server sends ServerHello with KeyUpdate appended in same record.
 *           Client should reject with fatal unexpected_message.
 * @expect   Client returns HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY and ALERT_UNEXPECTED_MESSAGE
 * @prior    Level 1
 * @auto     TRUE
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    RecWrapper wrapper = { TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, AppendKeyUpdateAfterRecord };
    RegisterWrapper(wrapper);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC002
 * @spec     -
 * @title    Server Finished not on record boundary - Client read key switch
 * @precon   nan
 * @brief    Server sends Finished with KeyUpdate appended in same record.
 *           Client should reject with fatal unexpected_message.
 * @expect   Client returns HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY and ALERT_UNEXPECTED_MESSAGE
 * @prior    Level 1
 * @auto     TRUE
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    RecWrapper wrapper = { TRY_SEND_FINISH, REC_TYPE_HANDSHAKE, false, NULL, AppendKeyUpdateAfterRecord };
    RegisterWrapper(wrapper);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC003
 * @spec     -
 * @title    Client Finished not on record boundary - Server read key switch
 * @precon   nan
 * @brief    Client sends Finished with KeyUpdate appended in same record.
 *           Server should reject with fatal unexpected_message.
 * @expect   Server returns HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY and ALERT_UNEXPECTED_MESSAGE
 * @prior    Level 1
 * @auto     TRUE
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC003(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    RecWrapper wrapper = { TRY_SEND_FINISH, REC_TYPE_HANDSHAKE, false, NULL, AppendKeyUpdateAfterRecord };
    RegisterWrapper(wrapper);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC004
 * @spec     -
 * @title    KeyUpdate not on record boundary - Server to Client
 * @precon   nan
 * @brief    Server sends KeyUpdate with another KeyUpdate appended in same record.
 *           Client should reject with fatal unexpected_message.
 * @expect   Client returns HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY and ALERT_UNEXPECTED_MESSAGE
 * @prior    Level 1
 * @auto     TRUE
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC004(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    RecWrapper wrapper = { TRY_SEND_KEY_UPDATE, REC_TYPE_HANDSHAKE, false, NULL, AppendFinishedAfterRecord };
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t ret = HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(ret, HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test     UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC005
 * @spec     -
 * @title    KeyUpdate not on record boundary - Client to Server
 * @precon   nan
 * @brief    Client sends KeyUpdate with Finished appended in same record.
 *           Server should reject with fatal unexpected_message.
 * @expect   Server returns HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY and ALERT_UNEXPECTED_MESSAGE
 * @prior    Level 1
 * @auto     TRUE
 */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_NOT_ON_RECORD_BOUNDARY_FUNC_TC005(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    RecWrapper wrapper = { TRY_SEND_KEY_UPDATE, REC_TYPE_HANDSHAKE, false, NULL, AppendFinishedAfterRecord };
    RegisterWrapper(wrapper);

    ASSERT_TRUE(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_REQUESTED) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t ret = HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(ret, HITLS_REC_ERR_NOT_ON_RECORD_BOUNDARY);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
