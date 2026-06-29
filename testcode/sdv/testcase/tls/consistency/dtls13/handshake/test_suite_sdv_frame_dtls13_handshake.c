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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <unistd.h>
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "sal_time.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_cookie.h"
#include "hitls_session.h"
#include "hitls_error.h"
#include "tls.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "simulate_io.h"
#include "stub_utils.h"
#include "alert.h"
#include "conn_init.h"
#include "record.h"
#include "rec.h"
#include "rec_header.h"
#include "hs.h"
#include "hs_common.h"
#include "hs_dtls_timer.h"
#include "hs_msg.h"
#include "hs_verify.h"
#include "parse.h"
#include "cipher_suite.h"

#define APP_READ_BUF_SIZE (18 * 1024)

static const uint8_t g_dtls13AppCookie[] = {0x64, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x63, 0x62};
static uint32_t g_dtls13AppCookieGenCnt = 0;
static uint32_t g_dtls13AppCookieVerifyCnt = 0;
typedef int32_t (*Dtls13HsChangeStateFunc)(TLS_Ctx *, uint32_t);
typedef struct HS_ChangeState_Stub {
    const char *stub_target_symbol;
    Dtls13HsChangeStateFunc stub_impl;
#ifdef STUB_PLATFORM_UNIX
    Dtls13HsChangeStateFunc real_impl;
#endif
} HS_ChangeState_Stub;
extern HS_ChangeState_Stub HS_ChangeState_stub;
typedef int32_t (*Dtls13RestoreHrrTranscriptFunc)(TLS_Ctx *, const uint8_t *, uint32_t, const uint8_t *, uint32_t);
STUB_DEFINE_RET5(int32_t, VERIFY_RestoreHelloRetryRequestTranscript, TLS_Ctx *, const uint8_t *, uint32_t,
    const uint8_t *, uint32_t)

static TLS_Ctx *g_dtls13PostHsFinishedServer = NULL;
static uint32_t g_dtls13PostHsFinishedTrySendAckCnt = 0;
static TLS_Ctx *g_dtls13KeyUpdateServer = NULL;
static uint32_t g_dtls13TrySendKeyUpdateCnt = 0;
static uint32_t g_dtls13RestoreHrrTranscriptCnt = 0;

static int32_t Dtls13ObserveChangeStateStub(TLS_Ctx *ctx, uint32_t nextState)
{
    if (ctx == g_dtls13PostHsFinishedServer && nextState == TRY_SEND_ACK) {
        g_dtls13PostHsFinishedTrySendAckCnt++;
    }
    if (ctx == g_dtls13KeyUpdateServer && nextState == TRY_SEND_KEY_UPDATE) {
        g_dtls13TrySendKeyUpdateCnt++;
    }

    Dtls13HsChangeStateFunc stubImpl = HS_ChangeState_stub.stub_impl;
    HS_ChangeState_stub.stub_impl = NULL;
    int32_t ret = HS_ChangeState(ctx, nextState);
    HS_ChangeState_stub.stub_impl = stubImpl;
    return ret;
}

static int32_t Dtls13ObserveRestoreHrrTranscriptStub(TLS_Ctx *ctx, const uint8_t *clientHelloHash,
    uint32_t clientHelloHashLen, const uint8_t *helloRetryRequest, uint32_t helloRetryRequestLen)
{
    g_dtls13RestoreHrrTranscriptCnt++;
    Dtls13RestoreHrrTranscriptFunc stubImpl = VERIFY_RestoreHelloRetryRequestTranscript_stub.stub_impl;
    VERIFY_RestoreHelloRetryRequestTranscript_stub.stub_impl = NULL;
    int32_t ret = VERIFY_RestoreHelloRetryRequestTranscript(ctx, clientHelloHash, clientHelloHashLen,
        helloRetryRequest, helloRetryRequestLen);
    VERIFY_RestoreHelloRetryRequestTranscript_stub.stub_impl = stubImpl;
    return ret;
}

static void ResetDtls13AppCookieCnt(void)
{
    g_dtls13AppCookieGenCnt = 0;
    g_dtls13AppCookieVerifyCnt = 0;
}

static int32_t Dtls13AppCookieGenCb(HITLS_Ctx *ctx, uint8_t *cookie, uint32_t *cookieLen)
{
    (void)ctx;
    if (cookie == NULL || cookieLen == NULL || *cookieLen < sizeof(g_dtls13AppCookie)) {
        return HITLS_COOKIE_GENERATE_ERROR;
    }
    memcpy(cookie, g_dtls13AppCookie, sizeof(g_dtls13AppCookie));
    *cookieLen = sizeof(g_dtls13AppCookie);
    g_dtls13AppCookieGenCnt++;
    return HITLS_COOKIE_GENERATE_SUCCESS;
}

static int32_t Dtls13AppCookieVerifyCb(HITLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookieLen)
{
    (void)ctx;
    g_dtls13AppCookieVerifyCnt++;
    if (cookieLen == sizeof(g_dtls13AppCookie) &&
        memcmp(cookie, g_dtls13AppCookie, sizeof(g_dtls13AppCookie)) == 0) {
        return HITLS_COOKIE_VERIFY_SUCCESS;
    }
    return HITLS_COOKIE_VERIFY_ERROR;
}

static int32_t Dtls13AppCookieVerifyFailCb(HITLS_Ctx *ctx, const uint8_t *cookie, uint32_t cookieLen)
{
    (void)ctx;
    (void)cookie;
    (void)cookieLen;
    g_dtls13AppCookieVerifyCnt++;
    return HITLS_COOKIE_VERIFY_ERROR;
}

int32_t Tls13ClientRecvHelloRetryRequestProcess(TLS_Ctx *ctx, const HS_Msg *msg);

static void SetDtls13FrameType(FRAME_Type *frameType, REC_Type recordType, HS_MsgType handshakeType)
{
    frameType->versionType = HITLS_VERSION_DTLS13;
    frameType->recordType = recordType;
    frameType->handshakeType = handshakeType;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType->transportType = BSL_UIO_UDP;
}

static void ForceDtlsTimerExpired(HITLS_Ctx *ctx)
{
    ctx->deadline = (BSL_TIME){BSL_TIME_SYSTEM_EPOCH_YEAR, 1, 1, 0, 0, 0, 0, 0};
}

static void BuildDtls13FinishedRetransmitMsg(uint8_t *msg, uint32_t bodyLen)
{
    msg[0] = FINISHED;
    BSL_Uint24ToByte(bodyLen, &msg[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(0, &msg[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(0, &msg[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
    BSL_Uint24ToByte(bodyLen, &msg[DTLS_HS_FRAGMENT_LEN_ADDR]);
    for (uint32_t i = 0; i < bodyLen; i++) {
        msg[DTLS_HS_MSG_HEADER_SIZE + i] = (uint8_t)(i + 1u);
    }
}

static uint32_t BuildDtls13Epoch2Record(uint8_t *msg, uint32_t msgSize)
{
    uint32_t msgLen = REC_DTLS13_UNI_HEADER_LENGTH + 1;
    if (msgSize < msgLen) {
        return 0;
    }
    msg[0] = REC_DTLS13_UNI_HEADER_FIX_BITS | REC_DTLS13_UNI_HEADER_SEQ_BIT |
        REC_DTLS13_UNI_HEADER_LEN_BIT | 2;
    msg[1] = 0;
    msg[2] = 0;
    BSL_Uint16ToByte(1, &msg[3]);
    msg[REC_DTLS13_UNI_HEADER_LENGTH] = 0xFF;
    return msgLen;
}

static bool IsFrameIoPendingRet(int32_t ret)
{
    return ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY ||
        ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}

static bool Dtls13LinkHasPendingRead(FRAME_LinkObj *link)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);
    if (ioUserData != NULL && ioUserData->recMsg.len != 0) {
        return true;
    }

    bool isPending = false;
    return HITLS_ReadHasPending(link->ssl, &isPending) == HITLS_SUCCESS && isPending;
}

static bool Dtls13LinkHasPendingSend(FRAME_LinkObj *link)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);
    return ioUserData != NULL && ioUserData->sndMsg.len != 0;
}

static int32_t Dtls13ReadControlMsg(FRAME_LinkObj *link)
{
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t ret = HITLS_Read(link->ssl, readBuf, sizeof(readBuf), &readLen);
    if (ret == HITLS_SUCCESS && readLen != 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY) {
        return HITLS_SUCCESS;
    }
    return ret;
}

static int32_t Dtls13DrainPendingControlMsg(FRAME_LinkObj *sender, FRAME_LinkObj *receiver)
{
    FrameUioUserData *senderIoUserData = BSL_UIO_GetUserData(sender->io);
    if (senderIoUserData == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (senderIoUserData->sndMsg.len == 0) {
        return HITLS_SUCCESS;
    }

    int32_t ret = FRAME_TrasferMsgBetweenLink(sender, receiver);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(receiver->ssl, readBuf, sizeof(readBuf), &readLen);
    if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY ||
        (ret == HITLS_SUCCESS && readLen == 0)) {
        return HITLS_SUCCESS;
    }
    return (ret == HITLS_SUCCESS) ? HITLS_INTERNAL_EXCEPTION : ret;
}

static bool IsDtls12HelloVerifyRequestBuffered(FRAME_LinkObj *server)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    if (ioUserData == NULL || ioUserData->sndMsg.len < REC_DTLS_RECORD_HEADER_LEN + DTLS_HS_MSG_HEADER_SIZE) {
        return false;
    }
    return ioUserData->sndMsg.msg[0] == REC_TYPE_HANDSHAKE &&
        ioUserData->sndMsg.msg[REC_DTLS_RECORD_HEADER_LEN] == HELLO_VERIFY_REQUEST;
}

static bool ParseDtls12HvrCookieFromBufferedMsg(FRAME_LinkObj *server, const uint8_t **cookie, uint32_t *cookieLen)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    if (ioUserData == NULL || cookie == NULL || cookieLen == NULL ||
        ioUserData->sndMsg.len < REC_DTLS_RECORD_HEADER_LEN + DTLS_HS_MSG_HEADER_SIZE + sizeof(uint16_t) + sizeof(uint8_t) ||
        ioUserData->sndMsg.msg[0] != REC_TYPE_HANDSHAKE ||
        ioUserData->sndMsg.msg[REC_DTLS_RECORD_HEADER_LEN] != HELLO_VERIFY_REQUEST) {
        return false;
    }

    uint32_t bodyOffset = REC_DTLS_RECORD_HEADER_LEN + DTLS_HS_MSG_HEADER_SIZE;
    uint8_t len = ioUserData->sndMsg.msg[bodyOffset + sizeof(uint16_t)];
    if (ioUserData->sndMsg.len < bodyOffset + sizeof(uint16_t) + sizeof(uint8_t) + len) {
        return false;
    }
    *cookie = &ioUserData->sndMsg.msg[bodyOffset + sizeof(uint16_t) + sizeof(uint8_t)];
    *cookieLen = len;
    return true;
}

static bool ServerRandomHasTls12Downgrade(const uint8_t *serverRandom)
{
    static const uint8_t downgradeRandom[] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
    return memcmp(&serverRandom[RANDOM_SIZE - sizeof(downgradeRandom)], downgradeRandom, sizeof(downgradeRandom)) == 0;
}

static int32_t Dtls12ProcessHelloVerifyRequest(FRAME_LinkObj *client, FRAME_LinkObj *server)
{
    int32_t ret = FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HITLS_Accept(server->ssl);
    if (!IsFrameIoPendingRet(ret)) {
        return ret;
    }

    if (!IsDtls12HelloVerifyRequestBuffered(server)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    ret = FRAME_TrasferMsgBetweenLink(server, client);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_Connect(client->ssl);
    if (!IsFrameIoPendingRet(ret)) {
        return ret;
    }
    return FRAME_TrasferMsgBetweenLink(client, server);
}

static bool NewDtlsConfigSupportsDtls12AndDtls13(const HITLS_Config *config)
{
    return config != NULL &&
        (config->originVersionMask & DTLS12_VERSION_BIT) != 0 &&
        (config->originVersionMask & DTLS13_VERSION_BIT) != 0 &&
        (config->version & DTLS12_VERSION_BIT) != 0 &&
        (config->version & DTLS13_VERSION_BIT) != 0 &&
        config->minVersion == HITLS_VERSION_DTLS12 &&
        config->maxVersion == HITLS_VERSION_DTLS13 &&
        config->cipherSuites != NULL &&
        config->cipherSuitesSize != 0 &&
        config->tls13CipherSuites != NULL &&
        config->tls13cipherSuitesSize != 0;
}

static int32_t Dtls13UseSingleKeyShareGroup(HITLS_Config *config)
{
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    return HITLS_CFG_SetGroups(config, groups, sizeof(groups) / sizeof(groups[0]));
}

static int32_t Dtls13PrepareCookieHrr(FRAME_LinkObj *client, FRAME_LinkObj *server,
    uint8_t *hrrBuf, uint32_t *hrrLen)
{
    int32_t ret = FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HITLS_Accept(server->ssl);
    if (!IsFrameIoPendingRet(ret)) {
        return ret;
    }

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    if (serverIoUserData == NULL || serverIoUserData->sndMsg.len == 0 ||
        serverIoUserData->sndMsg.len > *hrrLen) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    memcpy(hrrBuf, serverIoUserData->sndMsg.msg, serverIoUserData->sndMsg.len);
    *hrrLen = serverIoUserData->sndMsg.len;
    return HITLS_SUCCESS;
}

static int32_t Dtls13ClientProcessHrr(FRAME_LinkObj *client, FRAME_LinkObj *server)
{
    int32_t ret = FRAME_TrasferMsgBetweenLink(server, client);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HITLS_Connect(client->ssl);
    if (!IsFrameIoPendingRet(ret)) {
        return ret;
    }

    return FRAME_TrasferMsgBetweenLink(client, server);
}

static int32_t ParseDtls13BufferedHsMsg(FRAME_LinkObj *link, bool isRecvMsg, HS_MsgType handshakeType,
    FRAME_Msg *frameMsg)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);
    if (ioUserData == NULL) {
        return HITLS_NULL_INPUT;
    }
    FrameMsg *msg = isRecvMsg ? &ioUserData->recMsg : &ioUserData->sndMsg;
    if (msg->len == 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    FRAME_Type frameType = {0};
    uint32_t parseLen = 0;
    SetDtls13FrameType(&frameType, REC_TYPE_HANDSHAKE, handshakeType);
    return FRAME_ParseMsg(&frameType, msg->msg, msg->len, frameMsg, &parseLen);
}

static void Dtls13ClearServerFirstClientHello(TLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->hsCtx == NULL || ctx->hsCtx->firstClientHello == NULL) {
        return;
    }
    HS_Msg hsMsg = {0};
    hsMsg.type = CLIENT_HELLO;
    hsMsg.body.clientHello = *ctx->hsCtx->firstClientHello;
    HS_CleanMsg(&hsMsg);
    BSL_SAL_FREE(ctx->hsCtx->firstClientHello);
    ctx->hsCtx->firstClientHello = NULL;
}
/* END_HEADER */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC001
* @spec -
* @title DTLS1.3 basic handshake.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection with the frame framework.
*    3. Exchange application data in both directions.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Application data can be read and matches the written data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC001(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    uint32_t parseLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(client->ssl, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(server->ssl, true), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData != NULL);
    ASSERT_TRUE(ioUserData->recMsg.len != 0);

    SetDtls13FrameType(&frameType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);
    ASSERT_EQ(FRAME_ParseMsg(&frameType, ioUserData->recMsg.msg, ioUserData->recMsg.len, &frameMsg, &parseLen),
        HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientHello = &frameMsg.body.hsMsg.body.clientHello;
    const uint16_t expectedCipherSuites[] = {
        HITLS_AES_256_GCM_SHA384,
        HITLS_CHACHA20_POLY1305_SHA256,
        HITLS_AES_128_GCM_SHA256,
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    };
    ASSERT_EQ(clientHello->cipherSuitesSize.data % sizeof(uint16_t), 0);
    uint32_t cipherSuiteCount = clientHello->cipherSuitesSize.data / sizeof(uint16_t);
    ASSERT_EQ(cipherSuiteCount, sizeof(expectedCipherSuites) / sizeof(expectedCipherSuites[0]));
    for (uint32_t i = 0; i < cipherSuiteCount; i++) {
        ASSERT_EQ(clientHello->cipherSuites.data[i], expectedCipherSuites[i]);
    }

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t clientAppData[] = "DTLS13 client application data";
    uint8_t serverAppData[] = "DTLS13 server application data";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Write(client->ssl, clientAppData, sizeof(clientAppData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(clientAppData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(clientAppData));
    ASSERT_EQ(memcmp(readBuf, clientAppData, sizeof(clientAppData)), 0);
    ASSERT_EQ(Dtls13DrainPendingControlMsg(server, client), HITLS_SUCCESS);

    (void)memset(readBuf, 0, sizeof(readBuf));
    writeLen = 0;
    readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, serverAppData, sizeof(serverAppData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(serverAppData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(serverAppData));
    ASSERT_EQ(memcmp(readBuf, serverAppData, sizeof(serverAppData)), 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC001
* @spec -
* @title DTLS1.3 basic handshake.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection with the frame framework.
*    3. Exchange application data in both directions.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Application data can be read and matches the written data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC002(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(client->ssl, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(server->ssl, false), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t clientAppData[] = "DTLS13 client application data";
    uint8_t serverAppData[] = "DTLS13 server application data";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_Write(client->ssl, clientAppData, sizeof(clientAppData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(clientAppData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(clientAppData));
    ASSERT_EQ(memcmp(readBuf, clientAppData, sizeof(clientAppData)), 0);
    ASSERT_EQ(Dtls13DrainPendingControlMsg(server, client), HITLS_SUCCESS);

    (void)memset(readBuf, 0, sizeof(readBuf));
    writeLen = 0;
    readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, serverAppData, sizeof(serverAppData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(serverAppData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(serverAppData));
    ASSERT_EQ(memcmp(readBuf, serverAppData, sizeof(serverAppData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC003
* @spec -
* @title DTLS1.2 client negotiates with a DTLS1.3-capable server.
* @precon nan
* @brief
*    1. Create a DTLS1.2 client and a DTLS1.3-capable server that can negotiate DTLS1.2.
*    2. Establish the connection with the frame framework.
*    3. Check the server random downgrade sentinel.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. The last eight bytes of server random are 44 4F 57 4E 47 52 44 01.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC003(void)
{
    static const uint8_t downgradeRandom[] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t serverRandom[RANDOM_SIZE] = {0};
    uint32_t randomSize = sizeof(serverRandom);

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(serverConfig != NULL);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(HITLS_GetHsRandom(server->ssl, serverRandom, &randomSize, false), HITLS_SUCCESS);
    ASSERT_EQ(randomSize, RANDOM_SIZE);
    ASSERT_EQ(memcmp(&serverRandom[RANDOM_SIZE - sizeof(downgradeRandom)], downgradeRandom,
        sizeof(downgradeRandom)), 0);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC004
* @spec -
* @title DTLS1.3 ClientHello carries an empty legacy_session_id.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop when the server is about to receive ClientHello.
*    3. Parse ClientHello and check session_id length.
* @expect
*    1. ClientHello can be parsed.
*    2. The session_id length is 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC004(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    uint32_t parseLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData != NULL);
    ASSERT_TRUE(ioUserData->recMsg.len != 0);

    SetDtls13FrameType(&frameType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);
    ASSERT_EQ(FRAME_ParseMsg(&frameType, ioUserData->recMsg.msg, ioUserData->recMsg.len, &frameMsg, &parseLen),
        HITLS_SUCCESS);
    ASSERT_EQ(frameMsg.body.hsMsg.body.clientHello.sessionIdSize.data, 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC005
* @spec -
* @title DTLS1.3 server rejects invalid ClientHello legacy_version.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop when the server is about to receive ClientHello.
*    3. Modify ClientHello legacy_version to the configured invalid value and send it to the server.
* @expect
*    1. The server rejects ClientHello.
*    2. The server sends a fatal protocol_version alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC005(int legacyVersion)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    uint32_t parseLen = 0;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData != NULL);
    ASSERT_TRUE(ioUserData->recMsg.len != 0);

    SetDtls13FrameType(&frameType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);
    ASSERT_EQ(FRAME_ParseMsg(&frameType, ioUserData->recMsg.msg, ioUserData->recMsg.len, &frameMsg, &parseLen),
        HITLS_SUCCESS);
    frameMsg.body.hsMsg.body.clientHello.version.data = (uint16_t)legacyVersion;
    ASSERT_EQ(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_PROTOCOL_VERSION);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC006
* @spec -
* @title DTLS1.3 client retransmits Finished from HITLS_Read when the last flight is unacked and timed out.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish the connection and simulate an unacked client Finished in the retransmit queue.
*    3. Expire the client timer and call HITLS_Read.
* @expect
*    1. The client still has a retransmit node for Finished.
*    2. HITLS_Read triggers timeout retransmission.
*    3. The client generates retransmitted output.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC006(void)
{
    enum {
        FINISHED_BODY_LEN = 4
    };
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint8_t finishedMsg[DTLS_HS_MSG_HEADER_SIZE + FINISHED_BODY_LEN] = {0};
    char retransBuf[MAX_RECORD_LENTH] = {0};
    uint32_t retransLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);

    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    clientIoUserData->sndMsg.len = 0;
    clientIoUserData->recMsg.len = 0;
    BuildDtls13FinishedRetransmitMsg(finishedMsg, FINISHED_BODY_LEN);
    ASSERT_EQ(REC_RetransmitListPushWithAckCb(client->ssl, REC_TYPE_HANDSHAKE, finishedMsg, sizeof(finishedMsg), NULL),
        HITLS_SUCCESS);
    clientIoUserData->sndMsg.len = 0;
    bool isRetransEmpty = REC_RetransmitIsEmpty(client->ssl->recCtx);
    ASSERT_EQ(isRetransEmpty, false);
    // Force the client timer to expire and call HITLS_Read to trigger retransmission.
    client->ssl->timeoutValue = 1;
    ForceDtlsTimerExpired(client->ssl);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);

    ASSERT_EQ(FRAME_TransportSendMsg(client->io, retransBuf, sizeof(retransBuf), &retransLen), HITLS_SUCCESS);
    ASSERT_TRUE(retransLen != 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC007
* @spec -
* @title DTLS1.3 server retransmits saved ACK when receiving a retransmitted epoch-2 Finished.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection with the frame framework.
*    2. Inject an epoch-2 record into the server to simulate a retransmitted client Finished.
*    3. Call HITLS_Read on the server.
* @expect
*    1. The server keeps retrans ACK state after the handshake.
*    2. HITLS_Read ignores the retransmitted epoch-2 record.
*    3. The server sends a retransmitted ACK.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC007(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t epoch2Record[MAX_RECORD_LENTH] = {0};
    uint32_t epoch2RecordLen = 0;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint8_t ackBuf[MAX_RECORD_LENTH] = {0};
    uint32_t ackLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_TRUE(server->ssl->recCtx->readEpoch >= 2);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(server->ssl, REC_DTLS13_ACK_RETRANS) == false);

    serverIoUserData->sndMsg.len = 0;
    serverIoUserData->recMsg.len = 0;
    epoch2RecordLen = BuildDtls13Epoch2Record(epoch2Record, sizeof(epoch2Record));
    ASSERT_TRUE(epoch2RecordLen != 0);
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, epoch2Record, epoch2RecordLen), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_TransportSendMsg(server->io, ackBuf, sizeof(ackBuf), &ackLen), HITLS_SUCCESS);
    ASSERT_TRUE(ackLen == 0);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(server->ssl, REC_DTLS13_ACK_RETRANS) == false);

    ASSERT_EQ(FRAME_TransportSendMsg(server->io, ackBuf, sizeof(ackBuf), &ackLen), HITLS_SUCCESS);
    ASSERT_TRUE(ackLen != 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC008
* @spec -
* @title DTLS1.3 immediately sends ACK after receiving a post-handshake KeyUpdate.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection with the frame framework.
*    2. Server sends a post-handshake KeyUpdate.
*    3. Client reads and processes the unexpected post-handshake message.
*    4. Check the client immediately writes an ACK record.
* @expect
*    1. Handshake succeeds.
*    2. KeyUpdate is sent and delivered to the client.
*    3. Client read path processes the post-handshake message.
*    4. Client send buffer contains an ACK record.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC008(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint8_t ackBuf[MAX_RECORD_LENTH] = {0};
    uint32_t ackLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    // Disable automatic NewSessionTicket messages to avoid interference with KeyUpdate.
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_TRUE(serverIoUserData != NULL);
    clientIoUserData->sndMsg.len = 0;
    clientIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    serverIoUserData->recMsg.len = 0;

    ASSERT_EQ(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(FRAME_TransportSendMsg(client->io, ackBuf, sizeof(ackBuf), &ackLen), HITLS_SUCCESS);
    ASSERT_TRUE(ackLen != 0);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(client->ssl, REC_DTLS13_ACK_NORMAL) == true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC009
* @spec -
* @title DTLS1.3 post-handshake KeyUpdate starts retransmit timer and ACK removes it.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection without automatic NewSessionTicket messages.
*    2. Server sends a post-handshake KeyUpdate.
*    3. Client processes KeyUpdate and sends ACK.
*    4. Server processes ACK.
* @expect
*    1. KeyUpdate enters the retransmit queue and starts the retransmit timer.
*    2. ACK removes the retransmit node.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC009(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(server->ssl->recCtx) == true);

    ASSERT_EQ(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(REC_RetransmitIsEmpty(server->ssl->recCtx) == false);
    ASSERT_TRUE(server->ssl->timeoutValue != 0);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(REC_RetransmitIsEmpty(server->ssl->recCtx) == true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC010
* @spec -
* @title DTLS1.3 resumes a session with a NewSessionTicket.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection and receive a NewSessionTicket.
*    2. Set the ticket session on a new DTLS1.3 client.
*    3. Establish a second DTLS1.3 connection.
*    4. Exchange application data after the resumed handshake.
* @expect
*    1. The first connection produces a ticket session.
*    2. The second connection is marked as session reused on both endpoints.
*    3. Application data can be read and matches the written data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC010(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *clientSession = NULL;
    bool isReused = false;
    uint8_t appData[] = "DTLS13 resumed application data";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 1), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    clientSession = HITLS_GetDupSession(client->ssl);
    ASSERT_TRUE(clientSession != NULL);
    ASSERT_TRUE(HITLS_SESS_HasTicket(clientSession) == true);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    client = NULL;
    server = NULL;

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_IsSessionReused(client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);
    isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(server->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(clientSession);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC011
* @spec -
* @title DTLS1.3 completes a cookie HelloRetryRequest handshake.
* @precon nan
* @brief
*    1. Enable DTLS cookie exchange on a DTLS1.3 server.
*    2. Let the server respond to the first ClientHello with HelloRetryRequest carrying a cookie.
*    3. Let the client resend ClientHello with the cookie and complete the handshake.
*    4. Exchange application data.
* @expect
*    1. The HRR path completes.
*    2. Application data can be read after the handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC011(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t appData[] = "DTLS13 cookie exchange application data";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_TRUE(hrrLen != 0);
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC012
* @spec -
* @title DTLS1.3 cookie HRR drives the second ClientHello cookie extension.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange.
*    2. Check the first ClientHello has an empty legacy_cookie and no cookie extension.
*    3. Check the server HRR carries a cookie extension.
*    4. Check the second ClientHello carries the same cookie extension and keeps legacy_cookie empty.
* @expect
*    1. The first ClientHello has legacy_cookie length 0 and no cookie extension.
*    2. The second ClientHello has legacy_cookie length 0 and repeats the HRR cookie.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC012(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg firstClientHelloMsg = {0};
    FRAME_Msg hrrMsg = {0};
    FRAME_Msg secondClientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t hrrCookie[MAX_RECORD_LENTH] = {0};
    uint32_t hrrCookieLen = 0;

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &firstClientHelloMsg), HITLS_SUCCESS);
    FRAME_ClientHelloMsg *firstClientHello = &firstClientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(firstClientHello->cookiedLen.data, 0);
    ASSERT_EQ(firstClientHello->tls13Cookie.exState, MISSING_FIELD);

    int32_t ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(IsFrameIoPendingRet(ret));
    ASSERT_TRUE(server->ssl->timeoutValue != 0);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, false, SERVER_HELLO, &hrrMsg), HITLS_SUCCESS);
    FRAME_ServerHelloMsg *hrr = &hrrMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(hrr->tls13Cookie.exState, INITIAL_FIELD);
    ASSERT_TRUE(hrr->tls13Cookie.exDataLen.data != 0);
    ASSERT_TRUE(hrr->tls13Cookie.exDataLen.data <= sizeof(hrrCookie));
    hrrCookieLen = (uint32_t)hrr->tls13Cookie.exDataLen.data;
    memcpy(hrrCookie, hrr->tls13Cookie.exData.data, hrrCookieLen);

    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &secondClientHelloMsg), HITLS_SUCCESS);
    FRAME_ClientHelloMsg *secondClientHello = &secondClientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(secondClientHello->cookiedLen.data, 0);
    ASSERT_EQ(secondClientHello->tls13Cookie.exState, INITIAL_FIELD);
    ASSERT_EQ(secondClientHello->tls13Cookie.exDataLen.data, hrrCookieLen);
    ASSERT_EQ(memcmp(secondClientHello->tls13Cookie.exData.data, hrrCookie, hrrCookieLen), 0);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &firstClientHelloMsg);
    FRAME_CleanMsg(&serverHelloType, &hrrMsg);
    FRAME_CleanMsg(&clientHelloType, &secondClientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC013
* @spec -
* @title DTLS1.3 client rejects a second HelloRetryRequest.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange and process the first cookie HRR.
*    2. Dispatch another HRR to the client HRR processor.
* @expect
*    1. The client rejects the second HRR.
*    2. The client sends a fatal unexpected_message alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC013(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HS_Msg hrrMsg = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    int32_t ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(IsFrameIoPendingRet(ret));
    ASSERT_EQ(Tls13ClientRecvHelloRetryRequestProcess(client->ssl, &hrrMsg),
        HITLS_MSG_HANDLE_DUPLICATE_HELLO_RETYR_REQUEST);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC014
* @spec -
* @title DTLS1.3 server rejects an invalid cookie extension.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange and let the client generate a second ClientHello with cookie extension.
*    2. Tamper one byte in the cookie extension.
*    3. Send the tampered ClientHello to the server.
* @expect
*    1. The server rejects the ClientHello.
*    2. The server sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC014(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->tls13Cookie.exState, INITIAL_FIELD);
    ASSERT_TRUE(clientHello->tls13Cookie.exData.size != 0);
    clientHello->tls13Cookie.exData.data[clientHello->tls13Cookie.exData.size - 1] ^= 0x01;
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC015
* @spec -
* @title DTLS1.3 server rejects a non-empty ClientHello legacy_cookie field.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links.
*    2. Modify the first ClientHello legacy_cookie field to be non-empty.
*    3. Send the modified ClientHello to the server.
* @expect
*    1. The server rejects the ClientHello.
*    2. The server sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC015(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    uint8_t legacyCookie = 0xA5;

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    clientHello->cookiedLen.data = sizeof(legacyCookie);
    BSL_SAL_FREE(clientHello->cookie.data);
    clientHello->cookie.data = BSL_SAL_Dump(&legacyCookie, sizeof(legacyCookie));
    ASSERT_TRUE(clientHello->cookie.data != NULL);
    clientHello->cookie.size = sizeof(legacyCookie);
    clientHello->cookie.state = INITIAL_FIELD;
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC016
* @spec -
* @title DTLS1.3 server restores the HRR transcript from a cookie.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange and let the server send a cookie HRR.
*    2. Clear the server-side verify transcript before the second ClientHello arrives.
*    3. Let the server validate the cookie, restore the HRR transcript, and complete the handshake.
*    4. Exchange application data.
* @expect
*    1. The server does not depend on the old ClientHello/HRR verify transcript.
*    2. The handshake and application data exchange succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC016(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t appData[] = "DTLS13 stateless cookie transcript";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_TRUE(hrrLen != 0);
    Dtls13ClearServerFirstClientHello(server->ssl);
    VERIFY_Deinit(server->ssl->hsCtx);
    ASSERT_EQ(VERIFY_Init(server->ssl->hsCtx), HITLS_SUCCESS);

    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC017
* @spec -
* @title HITLS_CFG_NewDTLSConfig server negotiates DTLS1.2 with a DTLS1.2-only client.
* @precon nan
* @brief
*    1. Create a DTLS1.2-only client and a server with HITLS_CFG_NewDTLSConfig.
*    2. Enable DTLS cookie exchange on the server and check HelloVerifyRequest is sent.
*    3. Complete the handshake and check the negotiated version and downgrade random.
* @expect
*    1. HITLS_CFG_NewDTLSConfig enables DTLS1.2 and DTLS1.3.
*    2. The first server response is HelloVerifyRequest.
*    3. The handshake negotiates DTLS1.2 and server random carries the TLS1.2 downgrade marker.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC017(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t serverRandom[RANDOM_SIZE] = {0};
    uint32_t randomSize = sizeof(serverRandom);

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(serverConfig));
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(serverConfig, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionTicketSupport(serverConfig, false), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls12ProcessHelloVerifyRequest(client, server), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(HITLS_GetHsRandom(server->ssl, serverRandom, &randomSize, false), HITLS_SUCCESS);
    ASSERT_EQ(randomSize, RANDOM_SIZE);
    ASSERT_TRUE(ServerRandomHasTls12Downgrade(serverRandom));

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC018
* @spec -
* @title HITLS_CFG_NewDTLSConfig client negotiates DTLS1.2 with a DTLS1.2-only server.
* @precon nan
* @brief
*    1. Create a client with HITLS_CFG_NewDTLSConfig and a DTLS1.2-only server.
*    2. Enable DTLS cookie exchange on the server and check HelloVerifyRequest is sent.
*    3. Complete the handshake and check the negotiated version and downgrade random.
* @expect
*    1. HITLS_CFG_NewDTLSConfig enables DTLS1.2 and DTLS1.3.
*    2. The first server response is HelloVerifyRequest.
*    3. The handshake negotiates DTLS1.2 and server random does not carry the TLS1.2 downgrade marker.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC018(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t serverRandom[RANDOM_SIZE] = {0};
    uint32_t randomSize = sizeof(serverRandom);

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(clientConfig));
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(clientConfig), HITLS_SUCCESS);
    serverConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(serverConfig, true), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls12ProcessHelloVerifyRequest(client, server), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(HITLS_GetHsRandom(server->ssl, serverRandom, &randomSize, false), HITLS_SUCCESS);
    ASSERT_EQ(randomSize, RANDOM_SIZE);
    ASSERT_TRUE(!ServerRandomHasTls12Downgrade(serverRandom));

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC019
* @spec -
* @title DTLS1.3 disconnects when the sending handshake sequence would wrap.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection and start a post-handshake KeyUpdate from the server.
*    3. Set the server nextSendSeq to 0xffff and continue sending KeyUpdate.
* @expect
*    1. The server reports a handshake sequence error.
*    2. The server sends a fatal unexpected_message alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC019(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_TRUE(serverIoUserData != NULL);
    clientIoUserData->sndMsg.len = 0;
    clientIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    server->ssl->hsCtx->nextSendSeq = DTLS_HS_MSG_SEQ_MAX;

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC020
* @spec -
* @title DTLS1.3 disconnects when the receiving handshake sequence would wrap.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop the server before receiving the initial ClientHello.
*    3. Change the ClientHello message_seq to 0xffff and set server expectRecvSeq to 0xffff.
* @expect
*    1. The server reports a handshake sequence error.
*    2. The server sends a fatal unexpected_message alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC020(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    ASSERT_TRUE(serverIoUserData->recMsg.len >= REC_DTLS_RECORD_HEADER_LEN + DTLS_HS_MSG_HEADER_SIZE);
    BSL_Uint16ToByte(DTLS_HS_MSG_SEQ_MAX,
        &serverIoUserData->recMsg.msg[REC_DTLS_RECORD_HEADER_LEN + DTLS_HS_MSGSEQ_ADDR]);
    server->ssl->hsCtx->expectRecvSeq = DTLS_HS_MSG_SEQ_MAX;

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNMATCHED_SEQUENCE);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC021
* @spec -
* @title DTLS1.3 client clears ACK and retransmit state after receiving the server flight.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop the client after processing the server Finished and before sending client Certificate or Finished.
*    3. Check the normal ACK list and retransmit queue are cleared.
* @expect
*    1. The client enters TRY_SEND_CERTIFICATE or TRY_SEND_FINISH.
*    2. The normal ACK list is empty.
*    3. The retransmit queue is empty.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC021(int isSupportClientVerify)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    if (isSupportClientVerify != 0) {
        ASSERT_EQ(HITLS_CFG_SetClientVerifySupport(config, true), HITLS_SUCCESS);
    }
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    HITLS_HandshakeState stopState = (isSupportClientVerify != 0) ? TRY_SEND_CERTIFICATE : TRY_SEND_FINISH;
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, stopState), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, stopState);
    ASSERT_TRUE(client->ssl->recCtx->readEpoch >= 2);
    ASSERT_EQ(client->ssl->recCtx->writeEpoch, 2);
    ASSERT_TRUE(client->ssl->recCtx->writeStates.pendingState == NULL);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(client->ssl, REC_DTLS13_ACK_NORMAL) == true);
    ASSERT_TRUE(REC_RetransmitIsEmpty(client->ssl->recCtx) == true);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC022
* @spec -
* @title DTLS1.3 cookie exchange uses the configured application cookie callbacks.
* @precon nan
* @brief
*    1. Configure DTLS1.3 cookie exchange with appGenCookieCb and appVerifyCookieCb.
*    2. Check the cookie HRR carries the application cookie.
*    3. Complete the handshake and exchange application data.
* @expect
*    1. The generation callback is used for the HRR cookie.
*    2. The verification callback is used for the second ClientHello cookie.
*    3. The handshake and application data exchange succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC022(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg hrrMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t appData[] = "DTLS13 app cookie callback";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();
    ResetDtls13AppCookieCnt();
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieGenCb(config, Dtls13AppCookieGenCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieVerifyCb(config, Dtls13AppCookieVerifyCb), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(g_dtls13AppCookieGenCnt, 1);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, false, SERVER_HELLO, &hrrMsg), HITLS_SUCCESS);
    FRAME_ServerHelloMsg *hrr = &hrrMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(hrr->tls13Cookie.exState, INITIAL_FIELD);
    ASSERT_EQ(hrr->tls13Cookie.exDataLen.data, sizeof(g_dtls13AppCookie));
    ASSERT_EQ(memcmp(hrr->tls13Cookie.exData.data, g_dtls13AppCookie, sizeof(g_dtls13AppCookie)), 0);

    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(g_dtls13AppCookieVerifyCnt, 1);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &hrrMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC023
* @spec -
* @title DTLS1.3 server rejects a cookie rejected by the application callback.
* @precon nan
* @brief
*    1. Configure DTLS1.3 cookie exchange with an app cookie generator and a rejecting verifier.
*    2. Let the client echo the cookie in the second ClientHello.
*    3. Continue server processing.
* @expect
*    1. The server calls the application verifier.
*    2. The server rejects the ClientHello and sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC023(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);

    FRAME_Init();
    ResetDtls13AppCookieCnt();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieGenCb(config, Dtls13AppCookieGenCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieVerifyCb(config, Dtls13AppCookieVerifyFailCb), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(g_dtls13AppCookieGenCnt, 1);
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);
    ASSERT_EQ(g_dtls13AppCookieVerifyCnt, 1);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC024
* @spec -
* @title Two HITLS_CFG_NewDTLSConfig links negotiate DTLS1.3.
* @precon nan
* @brief
*    1. Create separate client and server configs with HITLS_CFG_NewDTLSConfig.
*    2. Create DTLS links over UDP and establish a connection.
* @expect
*    1. The connection succeeds.
*    2. Both endpoints negotiate DTLS1.3.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC024(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(clientConfig));
    serverConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(serverConfig));
    ASSERT_EQ(HITLS_CFG_SetTicketNums(serverConfig, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC025
* @spec -
* @title DTLS1.3 keeps handshake message sequence across hsCtx reinitialization.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Check the handshake sequence is saved in the connection context after hsCtx is released.
*    3. Start a post-handshake KeyUpdate and check the new hsCtx restores the saved sequence.
*    4. Send KeyUpdate and check the updated sequence is saved back to the connection context.
* @expect
*    1. DTLS1.3 handshake message sequence does not reset to 0 after hsCtx reinitialization.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC025(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint16_t savedNextSendSeq = 0;
    uint16_t savedExpectRecvSeq = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_TRUE(server->ssl->hsCtx == NULL);
    ASSERT_TRUE(server->ssl->dtls13NextSendSeq != 0);
    ASSERT_TRUE(server->ssl->dtls13ExpectRecvSeq != 0);
    savedNextSendSeq = server->ssl->dtls13NextSendSeq;
    savedExpectRecvSeq = server->ssl->dtls13ExpectRecvSeq;

    ASSERT_EQ(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_EQ(server->ssl->hsCtx->nextSendSeq, savedNextSendSeq);
    ASSERT_EQ(server->ssl->hsCtx->expectRecvSeq, savedExpectRecvSeq);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx == NULL);
    ASSERT_EQ(server->ssl->dtls13NextSendSeq, (uint16_t)(savedNextSendSeq + 1));
    ASSERT_EQ(server->ssl->dtls13ExpectRecvSeq, savedExpectRecvSeq);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC026
* @spec -
* @title DTLS1.3 returns to transporting after caching an out-of-order post-handshake message.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Make the server send a post-handshake KeyUpdate with a message sequence greater than the client's expected
*       receive sequence.
*    3. Let the client read the unexpected post-handshake message.
*    4. Let the client read again with only a future-sequence message in the reassembly queue.
* @expect
*    1. The client caches the future post-handshake message in the reassembly queue.
*    2. The client leaves the post-handshake state machine and returns to transporting.
*    3. The client does not remain in TRY_RECV_MSG when no matching sequence can be read.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC026(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint16_t clientExpectRecvSeq = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->hsCtx == NULL);
    ASSERT_TRUE(server->ssl->hsCtx == NULL);
    ASSERT_TRUE(HS_ReassQueueIsEmpty(client->ssl) == true);

    clientExpectRecvSeq = client->ssl->dtls13ExpectRecvSeq;
    server->ssl->dtls13NextSendSeq = (uint16_t)(clientExpectRecvSeq + 1);

    ASSERT_EQ(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(client->ssl->hsCtx == NULL);
    ASSERT_EQ(client->ssl->dtls13ExpectRecvSeq, clientExpectRecvSeq);
    ASSERT_TRUE(HS_ReassQueueIsEmpty(client->ssl) == false);

    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(client->ssl->hsCtx == NULL);
    ASSERT_EQ(client->ssl->dtls13ExpectRecvSeq, clientExpectRecvSeq);
    ASSERT_TRUE(HS_ReassQueueIsEmpty(client->ssl) == false);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC027
* @spec -
* @title DTLS1.3 HITLS_Write processes buffered post-handshake messages before writing app data.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Server sends a post-handshake KeyUpdate.
*    3. Directly read with REC_TYPE_APP on the client to leave the KeyUpdate in the record handshake buffer.
*    4. Client calls HITLS_Write.
* @expect
*    1. HITLS_Write enters TRY_RECV_MSG and processes the buffered KeyUpdate first.
*    2. The client returns to transporting and can continue writing application data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC027(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint8_t appData[] = "dtls13 write after buffered handshake";
    uint32_t writeLen = 0;
    int32_t ret = HITLS_SUCCESS;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_TRUE(REC_HasBufferedHsData(client->ssl) == false);

    ASSERT_EQ(HITLS_KeyUpdate(server->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_EQ(REC_Read(client->ssl, REC_TYPE_APP, readBuf, &readLen, sizeof(readBuf)),
        HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(REC_GetUnexpectedMsgType(client->ssl), REC_TYPE_HANDSHAKE);
    ASSERT_TRUE(REC_HasBufferedHsData(client->ssl) == true);

    ret = HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen);
    if (ret == HITLS_REC_NORMAL_IO_BUSY) {
        ASSERT_EQ(writeLen, 0);
        ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
        ASSERT_TRUE(client->ssl->hsCtx == NULL);
        ASSERT_TRUE(REC_HasBufferedHsData(client->ssl) == false);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        ret = HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen);
    }
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(client->ssl->hsCtx == NULL);
    ASSERT_TRUE(REC_HasBufferedHsData(client->ssl) == false);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC028
* @spec -
* @title DTLS1.3 server starts retransmit timer after sending NewSessionTicket.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 handshake and stop the server before sending NewSessionTicket.
*    2. Clear the server retransmit timer.
*    3. Let the server send NewSessionTicket.
* @expect
*    1. The server starts the retransmit timer for NewSessionTicket.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC028(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 1), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_NEW_SESSION_TICKET), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_SEND_NEW_SESSION_TICKET);

    HS_StopTimer(server->ssl);
    ASSERT_EQ(server->ssl->timeoutValue, 0);
    ASSERT_TRUE(IsFrameIoPendingRet(HITLS_Accept(server->ssl)));
    ASSERT_TRUE(server->ssl->timeoutValue != 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC029
* @spec -
* @title DTLS1.3 server rejects a second ClientHello without the requested HRR cookie.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange and let the server send a cookie HelloRetryRequest.
*    2. Let the client generate the second ClientHello and remove its cookie extension before sending it.
* @expect
*    1. The server rejects the second ClientHello.
*    2. The server sends a fatal illegal_parameter alert instead of sending a second HelloRetryRequest.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC029(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_TRUE(server->ssl->hsCtx->haveHrr);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->tls13Cookie.exState, INITIAL_FIELD);
    clientHello->tls13Cookie.exState = MISSING_FIELD;
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC030
* @spec -
* @title DTLS1.3 HRR carries both cookie and key_share when both retry reasons are present.
* @precon nan
* @brief
*    1. Configure the client to offer secp256r1 first and secp384r1 as a supported group.
*    2. Configure the server to support only secp384r1 and require DTLS1.3 cookie exchange.
*    3. Let the first ClientHello trigger HelloRetryRequest.
*    4. Parse the HelloRetryRequest and check it carries both cookie and key_share extensions.
* @expect
*    1. HRR carries a non-empty cookie extension.
*    2. HRR carries key_share selecting secp384r1.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC030(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg hrrMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint16_t clientGroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP384R1};

    FRAME_Init();
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    clientConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetGroups(clientConfig, clientGroups, sizeof(clientGroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverConfig, serverGroups, sizeof(serverGroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(serverConfig, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(clientConfig, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(serverConfig, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_TRUE(hrrLen != 0);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, false, SERVER_HELLO, &hrrMsg), HITLS_SUCCESS);

    FRAME_ServerHelloMsg *hrr = &hrrMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(hrr->tls13Cookie.exState, INITIAL_FIELD);
    ASSERT_TRUE(hrr->tls13Cookie.exDataLen.data != 0);
    ASSERT_EQ(hrr->keyShare.exState, INITIAL_FIELD);
    ASSERT_EQ(hrr->keyShare.data.group.data, HITLS_EC_GROUP_SECP384R1);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &hrrMsg);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC031
* @spec -
* @title DTLS1.3 does not enter TRY_SEND_ACK after receiving post-handshake Finished.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection with post-handshake authentication support.
*    2. The server sends a post-handshake CertificateRequest.
*    3. The client replies with Certificate, CertificateVerify and Finished.
*    4. Trace the server state changes while it processes the post-handshake client flight.
* @expect
*    1. The post-handshake authentication finishes successfully.
*    2. The server does not change to TRY_SEND_ACK when receiving the post-handshake Finished.
*    3. The ACK is flushed by the outer read path.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC031(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t ackBuf[MAX_RECORD_LENTH] = {0};
    uint32_t ackLen = 0;
    bool stubReplaced = false;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetPostHandshakeAuthSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetClientVerifySupport(config, true), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->phaState, PHA_EXTENSION);

    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_TRUE(serverIoUserData != NULL);
    clientIoUserData->sndMsg.len = 0;
    clientIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    serverIoUserData->recMsg.len = 0;

    ASSERT_EQ(HITLS_VerifyClientPostHandshake(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->phaState, PHA_REQUESTED);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    g_dtls13PostHsFinishedServer = server->ssl;
    g_dtls13PostHsFinishedTrySendAckCnt = 0;
    STUB_REPLACE(HS_ChangeState, Dtls13ObserveChangeStateStub);
    stubReplaced = true;
    for (uint32_t i = 0; i < 16 && server->ssl->phaState == PHA_REQUESTED; i++) {
        bool hasProgress = false;
        if (client->ssl->phaState == PHA_REQUESTED || Dtls13LinkHasPendingRead(client)) {
            ASSERT_EQ(Dtls13ReadControlMsg(client), HITLS_SUCCESS);
            hasProgress = true;
        }
        if (Dtls13LinkHasPendingSend(client)) {
            ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
            hasProgress = true;
        }
        if (server->ssl->phaState == PHA_REQUESTED || Dtls13LinkHasPendingRead(server)) {
            ASSERT_EQ(Dtls13ReadControlMsg(server), HITLS_SUCCESS);
            hasProgress = true;
        }
        ASSERT_TRUE(hasProgress);
    }
    ASSERT_EQ(client->ssl->phaState, PHA_EXTENSION);
    ASSERT_EQ(server->ssl->phaState, PHA_EXTENSION);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(g_dtls13PostHsFinishedTrySendAckCnt, 0);

    ASSERT_EQ(FRAME_TransportSendMsg(server->io, ackBuf, sizeof(ackBuf), &ackLen), HITLS_SUCCESS);
    ASSERT_TRUE(ackLen != 0);

EXIT:
    if (stubReplaced) {
        STUB_RESTORE(HS_ChangeState);
    }
    g_dtls13PostHsFinishedServer = NULL;
    g_dtls13PostHsFinishedTrySendAckCnt = 0;
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC032
* @spec -
* @title DTLS1.3 ignores requested KeyUpdate response while local retransmit queue is non-empty.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection and stop the server before sending NewSessionTicket.
*    2. Let the server send NewSessionTicket and keep the NST retransmit node unacked.
*    3. Let the client send KeyUpdate with request_update set to update_requested.
*    4. Trace the server state changes while it processes the KeyUpdate.
* @expect
*    1. The server keeps the NewSessionTicket retransmit node.
*    2. The server returns to transporting without changing to TRY_SEND_KEY_UPDATE.
*    3. The ACK for the received KeyUpdate is flushed by the outer read path.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC032(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint8_t ackBuf[MAX_RECORD_LENTH] = {0};
    uint32_t ackLen = 0;
    bool stubReplaced = false;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 1), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_NEW_SESSION_TICKET), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_SEND_NEW_SESSION_TICKET);

    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_TRUE(serverIoUserData != NULL);
    clientIoUserData->sndMsg.len = 0;
    clientIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    serverIoUserData->recMsg.len = 0;

    ASSERT_TRUE(IsFrameIoPendingRet(HITLS_Accept(server->ssl)));
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(REC_RetransmitIsEmpty(server->ssl->recCtx) == false);
    serverIoUserData->sndMsg.len = 0;

    ASSERT_EQ(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    g_dtls13KeyUpdateServer = server->ssl;
    g_dtls13TrySendKeyUpdateCnt = 0;
    STUB_REPLACE(HS_ChangeState, Dtls13ObserveChangeStateStub);
    stubReplaced = true;

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(server->ssl->hsCtx == NULL);
    ASSERT_EQ(server->ssl->isKeyUpdateRequest, false);
    ASSERT_EQ(g_dtls13TrySendKeyUpdateCnt, 0);
    ASSERT_TRUE(REC_RetransmitIsEmpty(server->ssl->recCtx) == false);

    ASSERT_EQ(FRAME_TransportSendMsg(server->io, ackBuf, sizeof(ackBuf), &ackLen), HITLS_SUCCESS);
    ASSERT_TRUE(ackLen != 0);

EXIT:
    if (stubReplaced) {
        STUB_RESTORE(HS_ChangeState);
    }
    g_dtls13KeyUpdateServer = NULL;
    g_dtls13TrySendKeyUpdateCnt = 0;
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC033
* @spec -
* @title DTLS1.3 stateful server HRR works with application cookie callbacks.
* @precon nan
* @brief
*    1. Configure DTLS1.3 cookie exchange with appGenCookieCb and appVerifyCookieCb.
*    2. Let the server send HelloRetryRequest with the application cookie.
*    3. Keep the server handshake transcript state and continue the second ClientHello.
*    4. Trace that VERIFY_RestoreHelloRetryRequestTranscript is not used.
*    5. Complete the handshake and exchange application data.
* @expect
*    1. The generation and verification callbacks are both used.
*    2. The server does not restore the HRR transcript from the cookie.
*    3. The handshake and application data exchange succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC033(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg hrrMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t appData[] = "DTLS13 stateful app cookie HRR";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    bool stubReplaced = false;

    FRAME_Init();
    ResetDtls13AppCookieCnt();
    g_dtls13RestoreHrrTranscriptCnt = 0;
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieGenCb(config, Dtls13AppCookieGenCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieVerifyCb(config, Dtls13AppCookieVerifyCb), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(g_dtls13AppCookieGenCnt, 1);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_TRUE(server->ssl->hsCtx->verifyCtx != NULL);
    ASSERT_TRUE(server->ssl->hsCtx->verifyCtx->dataBuf != NULL);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, false, SERVER_HELLO, &hrrMsg), HITLS_SUCCESS);

    FRAME_ServerHelloMsg *hrr = &hrrMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(hrr->tls13Cookie.exState, INITIAL_FIELD);
    ASSERT_EQ(hrr->tls13Cookie.exDataLen.data, sizeof(g_dtls13AppCookie));
    ASSERT_EQ(memcmp(hrr->tls13Cookie.exData.data, g_dtls13AppCookie, sizeof(g_dtls13AppCookie)), 0);

    STUB_REPLACE(VERIFY_RestoreHelloRetryRequestTranscript, Dtls13ObserveRestoreHrrTranscriptStub);
    stubReplaced = true;
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(g_dtls13AppCookieVerifyCnt, 1);
    ASSERT_EQ(g_dtls13RestoreHrrTranscriptCnt, 0);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    if (stubReplaced) {
        STUB_RESTORE(VERIFY_RestoreHelloRetryRequestTranscript);
    }
    g_dtls13RestoreHrrTranscriptCnt = 0;
    FRAME_CleanMsg(&serverHelloType, &hrrMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC034
* @spec -
* @title DTLS1.2/DTLS1.3 client keeps supported_versions after HelloVerifyRequest.
* @precon nan
* @brief
*    1. Create a client with HITLS_CFG_NewDTLSConfig and a DTLS1.2-only server.
*    2. Enable DTLS1.2 cookie exchange on the server.
*    3. Let the client process HelloVerifyRequest and send the second ClientHello.
*    4. Parse the second ClientHello received by the server.
* @expect
*    1. The second ClientHello carries the HVR legacy_cookie.
*    2. The second ClientHello still carries supported_versions including DTLS1.3 and DTLS1.2.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC034(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint32_t parseLen = 0;
    bool haveDtls13 = false;
    bool haveDtls12 = false;

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(clientConfig));
    serverConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(serverConfig, true), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls12ProcessHelloVerifyRequest(client, server), HITLS_SUCCESS);

    clientHelloType.versionType = HITLS_VERSION_DTLS12;
    clientHelloType.recordType = REC_TYPE_HANDSHAKE;
    clientHelloType.handshakeType = CLIENT_HELLO;
    clientHelloType.keyExType = HITLS_KEY_EXCH_ECDHE;
    clientHelloType.transportType = BSL_UIO_UDP;

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    ASSERT_TRUE(serverIoUserData->recMsg.len != 0);
    ASSERT_EQ(FRAME_ParseMsg(&clientHelloType, serverIoUserData->recMsg.msg,
        serverIoUserData->recMsg.len, &clientHelloMsg, &parseLen), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(clientHello->cookiedLen.data != 0);
    ASSERT_EQ(clientHello->supportedVersion.exState, INITIAL_FIELD);
    ASSERT_EQ(clientHello->supportedVersion.exDataLen.data % sizeof(uint16_t), 0);
    for (uint32_t i = 0; i < clientHello->supportedVersion.exData.size; i++) {
        if (clientHello->supportedVersion.exData.data[i] == HITLS_VERSION_DTLS13) {
            haveDtls13 = true;
        }
        if (clientHello->supportedVersion.exData.data[i] == HITLS_VERSION_DTLS12) {
            haveDtls12 = true;
        }
    }
    ASSERT_TRUE(haveDtls13);
    ASSERT_TRUE(haveDtls12);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC035
* @spec -
* @title DTLS1.2/DTLS1.3 server rejects DTLS1.3-capable ClientHello with legacy_cookie.
* @precon nan
* @brief
*    1. Create HITLS_CFG_NewDTLSConfig client and server links.
*    2. Modify the first ClientHello legacy_cookie field to be non-empty while keeping supported_versions.
*    3. Send the modified ClientHello to the server.
* @expect
*    1. The server selects the DTLS1.3 path and rejects the ClientHello.
*    2. The server sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC035(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    uint8_t legacyCookie = 0x5A;

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(config));

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->supportedVersion.exState, INITIAL_FIELD);
    clientHello->cookiedLen.data = sizeof(legacyCookie);
    BSL_SAL_FREE(clientHello->cookie.data);
    clientHello->cookie.data = BSL_SAL_Dump(&legacyCookie, sizeof(legacyCookie));
    ASSERT_TRUE(clientHello->cookie.data != NULL);
    clientHello->cookie.size = sizeof(legacyCookie);
    clientHello->cookie.state = INITIAL_FIELD;
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC036
* @spec -
* @title DTLS1.3 server rejects a post-HRR ClientHello without supported_versions as an invalid version.
* @precon nan
* @brief
*    1. Create HITLS_CFG_NewDTLSConfig client and server links.
*    2. Enable DTLS1.3 cookie exchange and let the server send an HRR.
*    3. Let the client generate the second ClientHello.
*    4. Remove supported_versions from the second ClientHello and send it to the server.
* @expect
*    1. The server keeps the HRR version invariant.
*    2. The server rejects the second ClientHello with illegal_parameter.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC036(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(config));
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_TRUE(server->ssl->hsCtx->haveHrr);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->supportedVersion.exState, INITIAL_FIELD);
    clientHello->supportedVersion.exState = MISSING_FIELD;
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC037
* @spec -
* @title DTLS1.3 client rejects HelloVerifyRequest after HelloRetryRequest.
* @precon nan
* @brief
*    1. Create a DTLS1.2/DTLS1.3 client context.
*    2. Mark HRR as already processed.
*    3. Check the state-machine message type dispatch for HelloVerifyRequest.
* @expect
*    1. The client treats HVR after HRR as an unexpected message.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC037(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);

    FRAME_Init();

    config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(config));
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_TRUE(client->ssl->hsCtx->haveHrr);

    client->ssl->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    ASSERT_EQ(CheckHsMsgType(client->ssl, HELLO_VERIFY_REQUEST), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC040
* @spec -
* @title DTLS1.2/DTLS1.3 server rejects a DTLS1.3-capable ClientHello after sending HVR.
* @precon nan
* @brief
*    1. Create HITLS_CFG_NewDTLSConfig client and server links.
*    2. Remove supported_versions from the first ClientHello so the server sends DTLS1.2 HVR.
*    3. Send a second ClientHello that carries the HVR legacy_cookie and restores supported_versions.
* @expect
*    1. The server does not switch from HVR to HRR.
*    2. The server rejects the DTLS1.3-capable ClientHello with non-empty legacy_cookie.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC040(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    const uint8_t *hvrCookie = NULL;
    uint32_t hvrCookieLen = 0;

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(config));
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->supportedVersion.exState, INITIAL_FIELD);
    clientHello->supportedVersion.exState = MISSING_FIELD;
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_TRUE(IsFrameIoPendingRet(HITLS_Accept(server->ssl)));
    ASSERT_TRUE(IsDtls12HelloVerifyRequestBuffered(server));
    ASSERT_TRUE(ParseDtls12HvrCookieFromBufferedMsg(server, &hvrCookie, &hvrCookieLen));
    ASSERT_TRUE(hvrCookieLen != 0);

    clientHello->supportedVersion.exState = INITIAL_FIELD;
    clientHello->cookiedLen.data = hvrCookieLen;
    BSL_SAL_FREE(clientHello->cookie.data);
    clientHello->cookie.data = BSL_SAL_Dump(hvrCookie, hvrCookieLen);
    ASSERT_TRUE(clientHello->cookie.data != NULL);
    clientHello->cookie.size = hvrCookieLen;
    clientHello->cookie.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(1u, &clientHelloMsg.body.hsMsg.sequence);
    sendLen = sizeof(sendBuf);
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    serverIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC041
* @spec -
* @title DTLS1.2/DTLS1.3 client rejects HRR after processing HVR.
* @precon nan
* @brief
*    1. Let a dual-stack client process a DTLS1.2 HVR.
*    2. Construct a valid DTLS1.3 cookie HRR from another server.
*    3. Dispatch the HRR to the client HRR processor.
* @expect
*    1. The client rejects HRR after HVR as an unexpected cross-version transition.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC041(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *dtls12ServerConfig = NULL;
    HITLS_Config *dtls13Config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *dtls12Server = NULL;
    FRAME_LinkObj *hrrClient = NULL;
    FRAME_LinkObj *hrrServer = NULL;
    FRAME_Msg hrrMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);

    FRAME_Init();
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    clientConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(clientConfig));
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(clientConfig), HITLS_SUCCESS);
    dtls12ServerConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(dtls12ServerConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(dtls12ServerConfig, true), HITLS_SUCCESS);
    dtls13Config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(dtls13Config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(dtls13Config, true), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    dtls12Server = FRAME_CreateLink(dtls12ServerConfig, BSL_UIO_UDP);
    ASSERT_TRUE(dtls12Server != NULL);
    hrrClient = FRAME_CreateLink(dtls13Config, BSL_UIO_UDP);
    ASSERT_TRUE(hrrClient != NULL);
    hrrServer = FRAME_CreateLink(dtls13Config, BSL_UIO_UDP);
    ASSERT_TRUE(hrrServer != NULL);

    ASSERT_EQ(Dtls12ProcessHelloVerifyRequest(client, dtls12Server), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->hsCtx->haveHvr);

    ASSERT_EQ(Dtls13PrepareCookieHrr(hrrClient, hrrServer, hrrBuf, &hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(hrrServer, false, SERVER_HELLO, &hrrMsg), HITLS_SUCCESS);
    FRAME_ModifyMsgInteger(1u, &hrrMsg.body.hsMsg.sequence);
    hrrLen = sizeof(hrrBuf);
    ASSERT_EQ(FRAME_PackMsg(&serverHelloType, &hrrMsg, hrrBuf, sizeof(hrrBuf), &hrrLen), HITLS_SUCCESS);
    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    clientIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, hrrBuf, hrrLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &hrrMsg);
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(dtls12ServerConfig);
    HITLS_CFG_FreeConfig(dtls13Config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(dtls12Server);
    FRAME_FreeLink(hrrClient);
    FRAME_FreeLink(hrrServer);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC042
* @spec -
* @title DTLS1.3 client final-flight retransmit is decryptable after client writes app data.
* @precon nan
* @brief
*    1. Stop the DTLS1.3 client before sending its final Finished.
*    2. Let the client send the final flight and drop that datagram.
*    3. Let the client write one app record and deliver it to the server first.
*    4. Force client timeout, retransmit the final flight, and deliver it to the server.
* @expect
*    1. The retransmitted record is still an epoch-2 DTLS1.3 record.
*    2. The server accepts the retransmitted final flight.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC042(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t dropBuf[MAX_RECORD_LENTH] = {0};
    uint8_t retransBuf[MAX_RECORD_LENTH] = {0};
    uint32_t dropLen = 0;
    uint32_t totalDropLen = 0;
    uint32_t retransLen = 0;
    bool sawRetrans = false;
    uint8_t appData[] = "dtls13 app before final retransmit";
    uint32_t writeLen = 0;
    FrameUioUserData *clientIoUserData = NULL;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_SEND_FINISH);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_RECV_FINISH);

    for (uint32_t i = 0; i < 8; i++) {
        ret = HITLS_Connect(client->ssl);
        ASSERT_TRUE(ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_IO_BUSY || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
        ASSERT_EQ(FRAME_TransportSendMsg(client->io, dropBuf, sizeof(dropBuf), &dropLen), HITLS_SUCCESS);
        totalDropLen += dropLen;
        if (ret == HITLS_SUCCESS) {
            break;
        }
    }
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(REC_RetransmitIsEmpty(client->ssl->recCtx) == false);
    ASSERT_TRUE(totalDropLen != 0);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_TRUE(clientIoUserData->sndMsg.len != 0);
    ASSERT_TRUE(REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(clientIoUserData->sndMsg.msg[0]));
    ASSERT_EQ(clientIoUserData->sndMsg.msg[0] & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK, 3);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_RECV_FINISH);

    for (uint32_t i = 0; i < 8 && server->ssl->state != CM_STATE_TRANSPORTING; i++) {
        client->ssl->timeoutValue = 1;
        ForceDtlsTimerExpired(client->ssl);
        ret = HITLS_DtlsProcessTimeout(client->ssl);
        ASSERT_TRUE(ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_IO_BUSY);
        ASSERT_EQ(FRAME_TransportSendMsg(client->io, retransBuf, sizeof(retransBuf), &retransLen), HITLS_SUCCESS);
        ASSERT_TRUE(retransLen != 0);
        sawRetrans = true;
        ASSERT_TRUE(REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(retransBuf[0]));
        ASSERT_EQ(retransBuf[0] & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK, 2);

        ASSERT_EQ(FRAME_TransportRecMsg(server->io, retransBuf, retransLen), HITLS_SUCCESS);
        ret = HITLS_Accept(server->ssl);
        ASSERT_TRUE(ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY);
        ASSERT_EQ(FRAME_TransportSendMsg(server->io, dropBuf, sizeof(dropBuf), &dropLen), HITLS_SUCCESS);
    }
    ASSERT_TRUE(sawRetrans);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
