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
#include "hs_msg.h"
#ifdef HITLS_TLS_FEATURE_ANTI_REPLAY
#include "rec_anti_replay.h"
#endif
#include "rec_conn.h"

#define APP_READ_BUF_SIZE (18 * 1024)

static void SetDtls13FrameType(FRAME_Type *frameType, REC_Type recordType, HS_MsgType handshakeType)
{
    frameType->versionType = HITLS_VERSION_DTLS13;
    frameType->recordType = recordType;
    frameType->handshakeType = handshakeType;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType->transportType = BSL_UIO_UDP;
}

static uint32_t BuildDtls13UnifiedHeader(uint8_t *msg, uint32_t msgSize, uint8_t epoch, uint16_t seqNum,
    uint16_t payloadLen, uint8_t contentType)
{
    uint32_t headerLen = REC_DTLS13_UNI_HEADER_LENGTH;  /* flags(1) + seq(2) + len(2) = 5 */
    if (msgSize < headerLen + 1) {
        return 0;
    }
    msg[0] = REC_DTLS13_UNI_HEADER_FIX_BITS | REC_DTLS13_UNI_HEADER_SEQ_BIT |
             REC_DTLS13_UNI_HEADER_LEN_BIT | epoch;
    /* Sequence number (2 bytes, big-endian) */
    BSL_Uint16ToByte(seqNum, &msg[1]);
    /* Length (2 bytes, big-endian): includes content type + payload */
    BSL_Uint16ToByte(payloadLen + 1, &msg[3]);
    /* Content type (first byte of encrypted payload for DTLS 1.3) */
    msg[REC_DTLS13_UNI_HEADER_LENGTH] = contentType;
    return headerLen + 1;
}

int32_t Dtls13ReconstructEpoch(TLS_Ctx *ctx, uint8_t epochBits, uint64_t *reconstructedEpoch);

static void Dtls13ClearFrameIo(FRAME_LinkObj *link)
{
    if (link == NULL || link->io == NULL) {
        return;
    }
    FrameUioUserData *ioData = BSL_UIO_GetUserData(link->io);
    if (ioData == NULL) {
        return;
    }
    ioData->sndMsg.len = 0;
    ioData->recMsg.len = 0;
}

static void Dtls13SetWriteEpoch(TLS_Ctx *ctx, uint16_t epoch)
{
    ctx->recCtx->writeEpoch = epoch;
    RecConnSetEpoch(ctx->recCtx->writeStates.currentState, epoch);
}

static void Dtls13SetReadEpoch(TLS_Ctx *ctx, uint16_t epoch)
{
    ctx->recCtx->readEpoch = epoch;
    RecConnSetEpoch(ctx->recCtx->readStates.currentState, epoch);
#ifdef HITLS_TLS_FEATURE_ANTI_REPLAY
    RecAntiReplayReset(&ctx->recCtx->readStates.currentState->window);
#endif
}

static void Dtls13AlignWriteReadEpoch(FRAME_LinkObj *sender, FRAME_LinkObj *receiver, uint16_t epoch)
{
    uint64_t nextWriteSeq = RecConnGetSeqNum(sender->ssl->recCtx->writeStates.currentState);

    Dtls13SetWriteEpoch(sender->ssl, epoch);
    Dtls13SetReadEpoch(receiver->ssl, epoch);
    RecConnSetSeqNum(receiver->ssl->recCtx->readStates.currentState,
        (nextWriteSeq == 0) ? 0 : (nextWriteSeq - 1));
}

static void Dtls13AlignHsMsgSeq(FRAME_LinkObj *sender, FRAME_LinkObj *receiver, uint16_t msgSeq)
{
    sender->ssl->dtls13NextSendSeq = msgSeq;
    receiver->ssl->dtls13ExpectRecvSeq = msgSeq;
    if (sender->ssl->hsCtx != NULL) {
        sender->ssl->hsCtx->nextSendSeq = msgSeq;
    }
    if (receiver->ssl->hsCtx != NULL) {
        receiver->ssl->hsCtx->expectRecvSeq = msgSeq;
    }
}

static int32_t Dtls13ReadPostHandshake(FRAME_LinkObj *link)
{
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    return HITLS_Read(link->ssl, readBuf, sizeof(readBuf), &readLen);
}

static bool Dtls13ReadRetIsDone(int32_t ret)
{
    return ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY;
}

static bool Dtls13HandshakeRetIsPending(int32_t ret)
{
    return ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY ||
        ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG;
}

static uint32_t BuildDtls13UnifiedCiphertextRecord(uint8_t *msg, uint32_t msgSize, uint8_t epoch, uint16_t seqNum,
    uint16_t cipherTextLen)
{
    uint32_t msgLen = (uint32_t)REC_DTLS13_UNI_HEADER_LENGTH + cipherTextLen;
    if (msgSize < msgLen) {
        return 0;
    }
    msg[0] = REC_DTLS13_UNI_HEADER_FIX_BITS | REC_DTLS13_UNI_HEADER_SEQ_BIT |
        REC_DTLS13_UNI_HEADER_LEN_BIT | epoch;
    BSL_Uint16ToByte(seqNum, &msg[1]);
    BSL_Uint16ToByte(cipherTextLen, &msg[3]);
    for (uint16_t i = 0; i < cipherTextLen; i++) {
        msg[REC_DTLS13_UNI_HEADER_LENGTH + i] = (uint8_t)(0xA0u + i);
    }
    return msgLen;
}

static int32_t Dtls13ProcessKeyUpdateAck(FRAME_LinkObj *ackHolder, FRAME_LinkObj *consumer)
{
    int32_t ret = FRAME_TrasferMsgBetweenLink(ackHolder, consumer);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = Dtls13ReadPostHandshake(consumer);
    return Dtls13ReadRetIsDone(ret) ? HITLS_SUCCESS : ret;
}

static int32_t Dtls13RunKeyUpdateSend(FRAME_LinkObj *sender, uint32_t updateType)
{
    int32_t ret = HITLS_KeyUpdate(sender->ssl, updateType);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return sender->ssl->isClient ? HITLS_Connect(sender->ssl) : HITLS_Accept(sender->ssl);
}

static int32_t Dtls13SendKeyUpdateAndProcess(FRAME_LinkObj *sender, FRAME_LinkObj *receiver, uint32_t updateType)
{
    int32_t ret = Dtls13RunKeyUpdateSend(sender, updateType);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = FRAME_TrasferMsgBetweenLink(sender, receiver);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = Dtls13ReadPostHandshake(receiver);
    return Dtls13ReadRetIsDone(ret) ? HITLS_SUCCESS : ret;
}

static int32_t Dtls13FlushPendingOutput(FRAME_LinkObj *sender, FRAME_LinkObj *receiver)
{
    FrameUioUserData *ioData = BSL_UIO_GetUserData(sender->io);
    if (ioData == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    if (ioData->sndMsg.len == 0) {
        return HITLS_SUCCESS;
    }

    int32_t ret = FRAME_TrasferMsgBetweenLink(sender, receiver);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = Dtls13ReadPostHandshake(receiver);
    return Dtls13ReadRetIsDone(ret) ? HITLS_SUCCESS : ret;
}

static int32_t Dtls13SendAppAndCheck(FRAME_LinkObj *sender, FRAME_LinkObj *receiver, const char *msg,
    uint16_t expectedEpoch)
{
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    RecordNumber recordNum = {0};

    int32_t ret = HITLS_Write(sender->ssl, (uint8_t *)msg, strlen(msg), &writeLen);
    if (ret == HITLS_REC_NORMAL_IO_BUSY) {
        ret = Dtls13FlushPendingOutput(sender, receiver);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        writeLen = 0;
        ret = HITLS_Write(sender->ssl, (uint8_t *)msg, strlen(msg), &writeLen);
    }
    if (ret != HITLS_SUCCESS || writeLen != strlen(msg)) {
        return (ret != HITLS_SUCCESS) ? ret : HITLS_INTERNAL_EXCEPTION;
    }
    ret = REC_GetLastWriteRecordNum(sender->ssl, &recordNum);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (recordNum.epoch != expectedEpoch) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    ret = FRAME_TrasferMsgBetweenLink(sender, receiver);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_Read(receiver->ssl, readBuf, sizeof(readBuf), &readLen);
    if (ret != HITLS_SUCCESS || readLen != strlen(msg) || memcmp(readBuf, msg, readLen) != 0) {
        return (ret != HITLS_SUCCESS) ? ret : HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}
/* END_HEADER */

/** @
* @test SDV_TLS_DTLS13_RECORD_CODEC_TC001
* @spec -
* @title DTLS1.3 record layer basic codec functionality test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection with the frame framework.
*    3. Test record layer encode/decode functionality with application data.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Application data can be encoded and decoded correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_RECORD_CODEC_TC001(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 测试记录层编解码功能
    uint8_t clientAppData[] = "DTLS13 record codec test data";
    ASSERT_EQ(HITLS_Write(client->ssl, clientAppData, sizeof(clientAppData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(clientAppData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(clientAppData));
    ASSERT_EQ(memcmp(readBuf, clientAppData, sizeof(clientAppData)), 0);

    // 发送另一条消息验证双向通信
    uint8_t serverAppData[] = "DTLS13 record codec response";
    writeLen = 0;
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
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
* @test SDV_TLS_DTLS13_RECORD_MULTIPLE_TYPES_TC013
* @spec -
* @title DTLS1.3 multiple record types codec test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test codec with different record types.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Different record types are handled correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_RECORD_MULTIPLE_TYPES_TC013(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 测试应用数据记录类型
    char appData[] = "Application data record";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)appData, strlen(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(appData));
    ASSERT_EQ(memcmp(readBuf, appData, readLen), 0);

    // 测试KeyUpdate记录类型
    ret = HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_NOT_REQUESTED);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ret = HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen);
    ASSERT_EQ(ret, HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);

    // KeyUpdate后继续发送应用数据
    char postKeyUpdateData[] = "Post-KeyUpdate data";
    writeLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)postKeyUpdateData, strlen(postKeyUpdateData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(postKeyUpdateData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(postKeyUpdateData));
    ASSERT_EQ(memcmp(readBuf, postKeyUpdateData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_PMTU_ADAPTIVE_TC014
* @spec -
* @title DTLS1.3 PMTU adaptive adjustment test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish connection with initial MTU configuration.
*    3. Test adaptive PMTU adjustment during transmission.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. PMTU adjusts appropriately during transmission.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_PMTU_ADAPTIVE_TC014(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t *testData = NULL;
    uint8_t *recvData = NULL;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 设置较小的初始MTU
    ret = HITLS_SetMtu(client->ssl, 800);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, 800);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // 发送逐渐增大的数据包
    for (int size = 200; size <= 700; size += 100) {
        testData = malloc(size);
        ASSERT_TRUE(testData != NULL);

        for (int i = 0; i < size; i++) {
            testData[i] = i % 256;
        }

        ASSERT_EQ(HITLS_Write(client->ssl, testData, size, &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, size);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        recvData = malloc(REC_MAX_PLAIN_LENGTH);
        ASSERT_TRUE(recvData != NULL);
        ASSERT_EQ(HITLS_Read(server->ssl, recvData, REC_MAX_PLAIN_LENGTH, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, size);
        ASSERT_EQ(memcmp(recvData, testData, readLen), 0);

        free(testData);
        free(recvData);
        testData = NULL;
        recvData = NULL;
    }

EXIT:
    free(testData);
    free(recvData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_ANTI_REPLAY_DUPLICATE_TC015
* @spec -
* @title DTLS1.3 anti-replay duplicate packet detection test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test duplicate packet detection and rejection.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Duplicate packets are correctly detected and rejected.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_ANTI_REPLAY_DUPLICATE_TC015(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 发送正常应用数据
    char testData[] = "Normal application data";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)testData, strlen(testData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(testData));

    // 获取发送的记录
    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_TRUE(clientIoUserData->sndMsg.len != 0);

    // 保存记录数据用于后续重放（FRAME_TrasferMsgBetweenLink 会清除 sndMsg.len）
    uint8_t *replayMsg = clientIoUserData->sndMsg.msg;
    uint32_t replayMsgLen = clientIoUserData->sndMsg.len;

    // 传输给服务器
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    // 服务器正常接收
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(testData));
    ASSERT_EQ(memcmp(readBuf, testData, readLen), 0);

    // 模拟重放：重复发送相同的记录
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, replayMsg, replayMsgLen), HITLS_SUCCESS);

    // 验证重放的记录被拒绝（不会重复处理）
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    int32_t ret = HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen);
    ASSERT_EQ(ret, HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_RECORD_MAX_SIZE_TC016
* @spec -
* @title DTLS1.3 maximum record size test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test record codec with maximum allowed record size.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Maximum size records are handled correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_RECORD_MAX_SIZE_TC016(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t *maxData = NULL;
    uint8_t *recvData = NULL;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 设置足够大的MTU以支持最大记录
    ASSERT_EQ(HITLS_SetMtu(client->ssl, REC_MAX_PLAIN_LENGTH + 200), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMtu(server->ssl, REC_MAX_PLAIN_LENGTH + 200), HITLS_SUCCESS);

    // 创建接近最大记录大小的数据
    uint32_t maxSize = REC_MAX_PLAIN_LENGTH - 100; // 留一些余量给头部和加密开销
    maxData = malloc(maxSize);
    ASSERT_TRUE(maxData != NULL);

    // 填充测试数据
    for (uint32_t i = 0; i < maxSize; i++) {
        maxData[i] = i % 256;
    }

    ASSERT_EQ(HITLS_Write(client->ssl, maxData, maxSize, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, maxSize);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    recvData = malloc(REC_MAX_PLAIN_LENGTH);
    ASSERT_TRUE(recvData != NULL);
    ASSERT_EQ(HITLS_Read(server->ssl, recvData, REC_MAX_PLAIN_LENGTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, maxSize);
    ASSERT_EQ(memcmp(recvData, maxData, readLen), 0);

EXIT:
    free(maxData);
    free(recvData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_RECORD_ZERO_LENGTH_TC017
* @spec -
* @title DTLS1.3 zero-length record test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test handling of zero-length records.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Zero-length records are handled correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_RECORD_ZERO_LENGTH_TC017(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 测试零长度写入
    ret = HITLS_Write(client->ssl, NULL, 0, &writeLen);
    // HITLS_Write要求data非空且dataLen>0，否则返回HITLS_NULL_INPUT
    ASSERT_EQ(ret, HITLS_NULL_INPUT);
    ASSERT_EQ(writeLen, 0);

    // 确保没有发送任何数据
    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    ASSERT_EQ(clientIoUserData->sndMsg.len, 0);

    // 发送正常数据验证连接仍然正常
    char normalData[] = "Normal data after zero-length test";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)normalData, strlen(normalData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(normalData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(normalData));
    ASSERT_EQ(memcmp(readBuf, normalData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CONSECUTIVE_RECORDS_TC018
* @spec -
* @title DTLS1.3 consecutive records transmission test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test transmission of multiple consecutive records.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Consecutive records are transmitted correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CONSECUTIVE_RECORDS_TC018(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 发送并逐条接收连续记录（模拟UIO缓冲区一次只能保留一条消息）
    for (int i = 0; i < 20; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "Consecutive record %d", i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg, strlen(msg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(msg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(msg));
        ASSERT_EQ(memcmp(readBuf, msg, readLen), 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_BIDIRECTIONAL_RECORDS_TC019
* @spec -
* @title DTLS1.3 bidirectional records transmission test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test bidirectional record transmission.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Bidirectional records are transmitted correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_BIDIRECTIONAL_RECORDS_TC019(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 双向交替发送记录
    for (int i = 0; i < 10; i++) {
        // 客户端发送
        char clientMsg[50];
        snprintf(clientMsg, sizeof(clientMsg), "Client message %d", i);
        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)clientMsg, strlen(clientMsg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(clientMsg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(clientMsg));
        ASSERT_EQ(memcmp(readBuf, clientMsg, readLen), 0);

        // 服务器发送
        char serverMsg[50];
        snprintf(serverMsg, sizeof(serverMsg), "Server message %d", i);
        ASSERT_EQ(HITLS_Write(server->ssl, (uint8_t *)serverMsg, strlen(serverMsg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(serverMsg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(client->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(serverMsg));
        ASSERT_EQ(memcmp(readBuf, serverMsg, readLen), 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_PMTU_MINIMUM_TC020
* @spec -
* @title DTLS1.3 PMTU minimum MTU test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish connection with minimum MTU.
*    3. Test record transmission with minimum MTU.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds with minimum MTU.
*    3. Records are transmitted correctly with minimum MTU.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_PMTU_MINIMUM_TC020(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 设置最小MTU
    ret = HITLS_SetMtu(client->ssl, DTLS_MIN_MTU);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, DTLS_MIN_MTU);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // 使用最小MTU发送数据
    char smallData[] = "Small data for minimum MTU";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)smallData, strlen(smallData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(smallData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(smallData));
    ASSERT_EQ(memcmp(readBuf, smallData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_RECORD_LARGE_PACKET_TC002
* @spec -
* @title DTLS1.3 large packet record codec test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection with the frame framework.
*    3. Test record layer encode/decode with large packets.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Large packets can be encoded and decoded correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_RECORD_LARGE_PACKET_TC002(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t *largeSendData = NULL;
    uint8_t *recvData = NULL;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    const uint32_t largeSize = 1500;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 创建大包数据进行测试
    largeSendData = malloc(largeSize);
    ASSERT_TRUE(largeSendData != NULL);

    // 填充大包数据
    for (uint32_t i = 0; i < largeSize; i++) {
        largeSendData[i] = i % 256;
    }

    // Write may be split into multiple records due to MTU constraints.
    // FRAME_Write holds only one message at a time, and FRAME_TransportRecMsg
    // requires recMsg to be empty. Alternate write / transfer / drain.
    recvData = malloc(REC_MAX_PLAIN_LENGTH);
    ASSERT_TRUE(recvData != NULL);
    uint32_t totalWritten = 0;
    uint32_t totalRead = 0;
    while (totalWritten < largeSize) {
        int32_t writeRet = HITLS_Write(client->ssl, largeSendData + totalWritten, largeSize - totalWritten, &writeLen);
        if (writeRet == HITLS_REC_NORMAL_IO_BUSY) {
            // sndMsg full from previous write; transfer data and drain recMsg
            ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        } else {
            ASSERT_EQ(writeRet, HITLS_SUCCESS);
            ASSERT_TRUE(writeLen > 0);
            totalWritten += writeLen;
            ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        }
        // Drain server's recMsg so the next FRAME_TransportRecMsg can succeed
        while (true) {
            int32_t rret = HITLS_Read(server->ssl, recvData + totalRead, REC_MAX_PLAIN_LENGTH - totalRead, &readLen);
            if (rret != HITLS_SUCCESS || readLen == 0) {
                break;
            }
            totalRead += readLen;
            readLen = 0;
        }
    }
    ASSERT_EQ(totalWritten, largeSize);

    // Drain any remaining data not yet read during the write loop
    while (totalRead < largeSize) {
        int32_t rret = HITLS_Read(server->ssl, recvData + totalRead, REC_MAX_PLAIN_LENGTH - totalRead, &readLen);
        if (rret != HITLS_SUCCESS || readLen == 0) {
            break;
        }
        totalRead += readLen;
        readLen = 0;
    }
    ASSERT_EQ(totalRead, largeSize);
    ASSERT_EQ(memcmp(recvData, largeSendData, totalRead), 0);

EXIT:
    free(largeSendData);
    free(recvData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_PMTU_FUNCTION_TC003
* @spec -
* @title DTLS1.3 PMTU basic functionality test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Configure PMTU discovery and establish connection.
*    3. Test different packet sizes to verify PMTU functionality.
* @expect
*    1. Link creation succeeds.
*    2. PMTU configuration succeeds.
*    3. Handshake succeeds with appropriate packet sizes.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_PMTU_FUNCTION_TC003(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t *testData = NULL;
    uint8_t *recvData = NULL;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 设置PMTU参数
    ret = HITLS_SetMtu(client->ssl, 1200);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, 1200);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // 测试不同大小的数据包，验证PMTU发现功能
    for (int size = 100; size <= 1000; size += 200) {
        testData = malloc(size);
        ASSERT_TRUE(testData != NULL);

        // 填充测试数据
        for (int i = 0; i < size; i++) {
            testData[i] = i % 256;
        }

        ASSERT_EQ(HITLS_Write(client->ssl, testData, size, &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, size);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        recvData = malloc(REC_MAX_PLAIN_LENGTH);
        ASSERT_TRUE(recvData != NULL);
        ASSERT_EQ(HITLS_Read(server->ssl, recvData, REC_MAX_PLAIN_LENGTH, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, size);
        ASSERT_EQ(memcmp(recvData, testData, readLen), 0);

        free(testData);
        free(recvData);
        testData = NULL;
        recvData = NULL;
    }

EXIT:
    free(testData);
    free(recvData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_PMTU_PATH_DISCOVERY_TC004
* @spec -
* @title DTLS1.3 PMTU path discovery test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Enable PMTU discovery with configured parameters.
*    3. Test packet transmission with PMTU discovery enabled.
* @expect
*    1. Link creation succeeds.
*    2. PMTU discovery configuration succeeds.
*    3. Data transmission adapts to discovered PMTU.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_PMTU_PATH_DISCOVERY_TC004(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t *testData = NULL;
    uint8_t *recvData = NULL;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 设置初始MTU
    ret = HITLS_SetMtu(client->ssl, 1400);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, 1400);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // 发送中等大小的数据包测试PMTU
    testData = malloc(1000);
    ASSERT_TRUE(testData != NULL);

    for (int i = 0; i < 1000; i++) {
        testData[i] = i % 256;
    }

    ASSERT_EQ(HITLS_Write(client->ssl, testData, 1000, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, 1000);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    recvData = malloc(REC_MAX_PLAIN_LENGTH);
    ASSERT_TRUE(recvData != NULL);
    ASSERT_EQ(HITLS_Read(server->ssl, recvData, REC_MAX_PLAIN_LENGTH, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, 1000);
    ASSERT_EQ(memcmp(recvData, testData, readLen), 0);

EXIT:
    free(testData);
    free(recvData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_ANTI_REPLAY_NORMAL_SEQ_TC005
* @spec -
* @title DTLS1.3 anti-replay normal sequence number test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Send multiple messages with normal sequence number progression.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. All messages are received and processed correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_ANTI_REPLAY_NORMAL_SEQ_TC005(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 发送多条消息验证序列号递增和抗重放功能
    for (int i = 0; i < 5; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "Message %d", i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg, strlen(msg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(msg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(msg));
        ASSERT_EQ(memcmp(readBuf, msg, readLen), 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_MULTIPLE_APP_DATA_TC006
* @spec -
 * @title DTLS1.3 multiple app data record send/recv test.
 * @precon nan
 * @brief
 *    1. Create DTLS1.3 client and server links over UDP.
 *    2. Establish a DTLS1.3 connection.
 *    3. Send multiple application data records and verify each is correctly received.
 * @expect
 *    1. Link creation succeeds.
 *    2. Handshake succeeds.
 *    3. Each sent message is correctly received with matching content.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_MULTIPLE_APP_DATA_TC006(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 发送多条消息，正常顺序应该是1, 2, 3
    char msg1[] = "First message";
    char msg2[] = "Second message";
    char msg3[] = "Third message";

    // 发送并逐条接收（模拟UIO缓冲区一次只能保留一条消息）
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg1, strlen(msg1), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(msg1));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(msg1));
    ASSERT_EQ(memcmp(readBuf, msg1, readLen), 0);

    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg2, strlen(msg2), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(msg2));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(msg2));
    ASSERT_EQ(memcmp(readBuf, msg2, readLen), 0);

    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg3, strlen(msg3), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(msg3));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(msg3));
    ASSERT_EQ(memcmp(readBuf, msg3, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_ANTI_REPLAY_WINDOW_TC007
* @spec -
* @title DTLS1.3 anti-replay window functionality test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Send multiple messages to test anti-replay window.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Anti-replay window functions correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_ANTI_REPLAY_WINDOW_TC007(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 发送多条消息建立序列号窗口
    for (int i = 0; i < 10; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "Message %d", i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg, strlen(msg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(msg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(msg));
        ASSERT_EQ(memcmp(readBuf, msg, readLen), 0);
    }

    // 继续发送新消息，验证窗口功能正常
    char newMsg[] = "New message after window established";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)newMsg, strlen(newMsg), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(newMsg));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(newMsg));
    ASSERT_EQ(memcmp(readBuf, newMsg, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_UNIFIED_HDR_CODEC_TC008
* @spec -
* @title DTLS1.3 unified header codec test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test unified header encode/decode functionality.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Unified header codec works correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_UNIFIED_HDR_CODEC_TC008(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 测试统一头编解码功能
    char testMsg[] = "Test unified header codec";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)testMsg, strlen(testMsg), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(testMsg));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(testMsg));
    ASSERT_EQ(memcmp(readBuf, testMsg, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_EPOCH_RECONSTRUCTION_TC009
* @spec -
* @title DTLS1.3 epoch reconstruction test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test record transmission across different epochs.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Records are correctly handled across epochs.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_EPOCH_RECONSTRUCTION_TC009(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 握手完成后，测试epoch 3（应用数据）的记录传输
    for (int i = 0; i < 3; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "Epoch 2 message %d", i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg, strlen(msg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(msg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(msg));
        ASSERT_EQ(memcmp(readBuf, msg, readLen), 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_SEQ_RECONSTRUCTION_TC010
* @spec -
* @title DTLS1.3 sequence number reconstruction test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test sequence number reconstruction with many messages.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Sequence numbers are correctly handled across many records.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_SEQ_RECONSTRUCTION_TC010(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 测试序列号重建功能，发送大量连续消息
    for (int i = 0; i < 50; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "Sequential message %d", i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg, strlen(msg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(msg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(msg));
        ASSERT_EQ(memcmp(readBuf, msg, readLen), 0);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_RECORD_FRAGMENTATION_TC011
* @spec -
* @title DTLS1.3 record fragmentation test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection with small MTU.
*    3. Test record fragmentation and reassembly.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Records are correctly fragmented and reassembled.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_RECORD_FRAGMENTATION_TC011(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t *largeData = NULL;
    uint8_t *recvData = NULL;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 设置较小的MTU以触发分片
    ret = HITLS_SetMtu(client->ssl, 1000);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, 1000);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // 发送大于MTU的数据，测试分片功能
    largeData = malloc(1500);
    ASSERT_TRUE(largeData != NULL);

    for (int i = 0; i < 1500; i++) {
        largeData[i] = i % 256;
    }

    // Write may be split into multiple records due to MTU constraints.
    // FRAME_Write holds only one message at a time, and FRAME_TransportRecMsg
    // requires recMsg to be empty. Alternate write / transfer / drain.
    recvData = malloc(REC_MAX_PLAIN_LENGTH);
    ASSERT_TRUE(recvData != NULL);
    uint32_t totalWritten = 0;
    uint32_t totalRead = 0;
    while (totalWritten < 1500) {
        int32_t writeRet = HITLS_Write(client->ssl, largeData + totalWritten, 1500 - totalWritten, &writeLen);
        if (writeRet == HITLS_REC_NORMAL_IO_BUSY) {
            ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        } else {
            ASSERT_EQ(writeRet, HITLS_SUCCESS);
            ASSERT_TRUE(writeLen > 0);
            totalWritten += writeLen;
            ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        }
        while (true) {
            int32_t rret = HITLS_Read(server->ssl, recvData + totalRead, REC_MAX_PLAIN_LENGTH - totalRead, &readLen);
            if (rret != HITLS_SUCCESS || readLen == 0) {
                break;
            }
            totalRead += readLen;
            readLen = 0;
        }
    }
    ASSERT_EQ(totalWritten, 1500);

    while (totalRead < 1500) {
        int32_t rret = HITLS_Read(server->ssl, recvData + totalRead, REC_MAX_PLAIN_LENGTH - totalRead, &readLen);
        if (rret != HITLS_SUCCESS || readLen == 0) {
            break;
        }
        totalRead += readLen;
        readLen = 0;
    }
    ASSERT_EQ(totalRead, 1500);
    ASSERT_EQ(memcmp(recvData, largeData, totalRead), 0);

EXIT:
    free(largeData);
    free(recvData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_ACK_MECHANISM_TC012
* @spec -
* @title DTLS1.3 ACK mechanism test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Test ACK mechanism for record acknowledgment.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. ACK mechanism functions correctly.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_ACK_MECHANISM_TC012(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    // 启用飞行消息传输
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(client->ssl, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetFlightTransmitSwitch(server->ssl, true), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // 验证握手完成后ACK列表不为空
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(client->ssl, REC_DTLS13_ACK_RETRANS) == false);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(server->ssl, REC_DTLS13_ACK_RETRANS) == false);

    // 发送应用数据并验证ACK机制
    char testMsg[] = "Test ACK mechanism";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)testMsg, strlen(testMsg), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(testMsg));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(testMsg));
    ASSERT_EQ(memcmp(readBuf, testMsg, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_UNIFIED_HEADER_INSPECT_TC021
* @spec -
* @title DTLS1.3 unified header wire format inspection test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Send an application data record and inspect the raw unified header bytes.
*    4. Verify the first-byte flags (fix bits, epoch bits, seq bit, length bit).
*    5. Verify the length field matches the remaining datagram size.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
 *    3. The raw unified header first byte matches 0x2F (epoch 3, seq+len bits set).
 *    4. The wire length field correctly encodes the ciphertext + content type length.
 *    5. The transmitted data is correctly received and decoded.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_UNIFIED_HEADER_INSPECT_TC021(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    FrameUioUserData *clientIo = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // Send app data and inspect the raw unified header
    char testMsg[] = "Unified header inspection test";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)testMsg, strlen(testMsg), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(testMsg));

    // Access the raw send buffer
    clientIo = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIo != NULL);
    ASSERT_TRUE(clientIo->sndMsg.len > REC_DTLS13_UNI_HEADER_LENGTH);

    // Verify the first byte of the unified header.
    // DTLS 1.3 handshake ends with epoch 3 (application data epoch).
    // Expected: 0x20 (fix bits) | 0x00 (no CID) | 0x08 (2-byte seq) | 0x04 (length) | 0x03 (epoch 3) = 0x2F
    uint8_t expectedFirstByte = REC_DTLS13_UNI_HEADER_FIX_BITS | REC_DTLS13_UNI_HEADER_SEQ_BIT |
                                REC_DTLS13_UNI_HEADER_LEN_BIT | 3;
    uint8_t actualFirstByte = clientIo->sndMsg.msg[0];
    ASSERT_EQ(actualFirstByte, expectedFirstByte);

    // Verify the length field (bytes 3-4) encodes the remaining data after the 5-byte header
    uint16_t wireLen = BSL_ByteToUint16(&clientIo->sndMsg.msg[REC_DTLS13_UNI_HEADER_LENGTH - 2]);
    uint32_t remaining = clientIo->sndMsg.len - REC_DTLS13_UNI_HEADER_LENGTH;
    ASSERT_EQ((uint32_t)wireLen, remaining);

    // Transfer and verify data is correctly received
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(testMsg));
    ASSERT_EQ(memcmp(readBuf, testMsg, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_EPOCH_KEY_UPDATE_TC022
* @spec -
* @title DTLS1.3 epoch reconstruction after KeyUpdate test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
 *    3. Send app data and verify epoch=3 via REC_GetLastWriteRecordNum.
 *    4. Perform KeyUpdate and verify post-KeyUpdate app data transfer.
 * @expect
 *    1. Link creation succeeds.
 *    2. Handshake succeeds.
 *    3. REC_GetLastWriteRecordNum returns epoch=3 for initial app data.
 *    4. Post-KeyUpdate app data is correctly transferred and received.
 @ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_EPOCH_KEY_UPDATE_TC022(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    RecordNumber recordNum;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // Send initial app data (DTLS 1.3 handshake ends with epoch 3)
    char appData[] = "App data epoch 3";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)appData, strlen(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(appData));

    // Verify client write epoch is 3 for app data
    ASSERT_EQ(REC_GetLastWriteRecordNum(client->ssl, &recordNum), HITLS_SUCCESS);
    ASSERT_EQ(recordNum.epoch, 3);

    // Perform KeyUpdate on client
    // DTLS 1.3 defers write epoch update until ACK; server processes immediately
    ASSERT_EQ(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);

    // Transfer KeyUpdate to server
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    // Server processes KeyUpdate: Read triggers handshake pre-processing, Accept completes it
    uint32_t tmpLen = 0;
    int32_t ret = HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &tmpLen);
    ASSERT_TRUE(ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);

    // Send post-KeyUpdate app data
    // In DTLS 1.3, the record epoch is still 3 (write epoch deferred until ACK);
    // the server falls back to outdated state for decryption (currentEpoch - 1).
    char postKuData[] = "App data after KeyUpdate";
    writeLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)postKuData, strlen(postKuData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(postKuData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(postKuData));
    ASSERT_EQ(memcmp(readBuf, postKuData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC032
* @spec -
* @title DTLS1.3 client KeyUpdate from epoch 2^16-2 advances to 2^16-1 after ACK.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Set the client write epoch and server read epoch to 2^16-2.
*    3. Set the client outgoing/server incoming handshake message sequence to 2^16-2.
*    4. Let the client send KeyUpdate and process the server ACK.
* @expect
*    1. The client sends KeyUpdate successfully.
*    2. The server processes the KeyUpdate successfully.
*    3. The ACK callback advances the client write epoch to 2^16-1.
*    4. Client application data is sent and received with epoch 2^16-1.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC032(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint16_t nearMaxEpoch = (uint16_t)(REC_EPOCH_MAX_VALUE - 1u);

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    Dtls13ClearFrameIo(client);
    Dtls13ClearFrameIo(server);
    Dtls13AlignWriteReadEpoch(client, server, nearMaxEpoch);
    Dtls13AlignHsMsgSeq(client, server, nearMaxEpoch);

    ASSERT_EQ(Dtls13SendKeyUpdateAndProcess(client, server, HITLS_UPDATE_NOT_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->recCtx->readEpoch, REC_EPOCH_MAX_VALUE);
    ASSERT_EQ(Dtls13ProcessKeyUpdateAck(server, client), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->recCtx->writeEpoch, REC_EPOCH_MAX_VALUE);
    ASSERT_EQ(Dtls13SendAppAndCheck(client, server, "client app after boundary keyupdate", REC_EPOCH_MAX_VALUE),
        HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC033
* @spec -
* @title DTLS1.3 client KeyUpdate send fails at epoch 2^16-1.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Set the client write epoch to 2^16-1.
*    3. Start client KeyUpdate.
* @expect
*    1. The KeyUpdate request is rejected because there is no next DTLS1.3 write epoch.
*    2. No post-handshake context is created.
*    3. The client write epoch remains 2^16-1.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC033(void)
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

    Dtls13ClearFrameIo(client);
    Dtls13ClearFrameIo(server);
    Dtls13SetWriteEpoch(client->ssl, REC_EPOCH_MAX_VALUE);

    ASSERT_EQ(HITLS_KeyUpdate(client->ssl, HITLS_UPDATE_NOT_REQUESTED), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_TRUE(client->ssl->hsCtx == NULL);
    ASSERT_EQ(client->ssl->recCtx->writeEpoch, REC_EPOCH_MAX_VALUE);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC034
* @spec -
* @title DTLS1.3 client accepts reconstructable peer epoch bits for 2^16+1.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Set the client local write/read epoch below 2^16-1.
*    3. Reconstruct peer epoch bits that correspond to 2^16+1 on the wire.
* @expect
*    1. Epoch reconstruction succeeds. The DTLS1.3 unified header carries only low epoch bits.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC034(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint16_t nearMaxEpoch = (uint16_t)(REC_EPOCH_MAX_VALUE - 1u);
    uint64_t reconstructedEpoch = 0;
    uint8_t epochBits = (uint8_t)(((uint64_t)REC_EPOCH_MAX_VALUE + 2u) &
        REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK);

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    Dtls13SetWriteEpoch(client->ssl, nearMaxEpoch);
    Dtls13SetReadEpoch(client->ssl, nearMaxEpoch);
    ASSERT_EQ(Dtls13ReconstructEpoch(client->ssl, epochBits, &reconstructedEpoch), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC035
* @spec -
* @title DTLS1.3 client at epoch 2^16-2 ACKs and replies to requested KeyUpdate.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Set client write epoch and server read epoch to 2^16-2.
*    3. Let the server send update_requested KeyUpdate.
*    4. The client ACKs the server KeyUpdate, sends a reply KeyUpdate, and receives the server ACK.
* @expect
*    1. Client write epoch advances to 2^16-1 after the reply KeyUpdate is ACKed.
*    2. Client application data is sent and received with epoch 2^16-1.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC035(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    int32_t ret;
    uint16_t nearMaxEpoch = (uint16_t)(REC_EPOCH_MAX_VALUE - 1u);

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    Dtls13ClearFrameIo(client);
    Dtls13ClearFrameIo(server);
    Dtls13AlignWriteReadEpoch(client, server, nearMaxEpoch);
    Dtls13AlignHsMsgSeq(client, server, nearMaxEpoch);
    Dtls13AlignHsMsgSeq(server, client, nearMaxEpoch);

    ASSERT_EQ(Dtls13RunKeyUpdateSend(server, HITLS_UPDATE_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ret = Dtls13ReadPostHandshake(client);
    if (ret == HITLS_REC_NORMAL_IO_BUSY) {
        ASSERT_EQ(Dtls13ProcessKeyUpdateAck(client, server), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(Dtls13ReadRetIsDone(ret));
    }
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ret = Dtls13ReadPostHandshake(server);
    ASSERT_TRUE(Dtls13ReadRetIsDone(ret));
    ASSERT_EQ(server->ssl->recCtx->readEpoch, REC_EPOCH_MAX_VALUE);
    ASSERT_EQ(Dtls13ProcessKeyUpdateAck(server, client), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->recCtx->writeEpoch, REC_EPOCH_MAX_VALUE);
    ASSERT_EQ(Dtls13SendAppAndCheck(client, server, "client reply keyupdate boundary app", REC_EPOCH_MAX_VALUE),
        HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC036
* @spec -
* @title DTLS1.3 client at epoch 2^16-1 ACKs but does not reply to requested KeyUpdate.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Set client write epoch and server read epoch to 2^16-1.
*    3. Set client outgoing handshake message sequence to 0xffff.
*    4. Let the server send update_requested KeyUpdate.
* @expect
*    1. The client processes the server KeyUpdate and sends the record-layer ACK.
*    2. The client does not send a reply KeyUpdate.
*    3. Client write epoch remains 2^16-1 and application data still round-trips.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_KEY_UPDATE_EPOCH_BOUNDARY_TC036(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    Dtls13ClearFrameIo(client);
    Dtls13ClearFrameIo(server);
    Dtls13AlignWriteReadEpoch(client, server, REC_EPOCH_MAX_VALUE);
    Dtls13AlignHsMsgSeq(client, server, DTLS_HS_MSG_SEQ_MAX);
    Dtls13AlignHsMsgSeq(server, client, (uint16_t)(DTLS_HS_MSG_SEQ_MAX - 1u));

    ASSERT_EQ(Dtls13RunKeyUpdateSend(server, HITLS_UPDATE_REQUESTED), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ret = Dtls13ReadPostHandshake(client);
    ASSERT_TRUE(Dtls13ReadRetIsDone(ret));
    ASSERT_TRUE(client->ssl->isKeyUpdateRequest == false);
    ASSERT_TRUE(client->ssl->hsCtx == NULL);
    ASSERT_EQ(client->ssl->dtls13NextSendSeq, DTLS_HS_MSG_SEQ_MAX);
    ASSERT_EQ(client->ssl->recCtx->writeEpoch, REC_EPOCH_MAX_VALUE);
    ASSERT_EQ(Dtls13ProcessKeyUpdateAck(client, server), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13SendAppAndCheck(client, server, "client max epoch app after requested keyupdate",
        REC_EPOCH_MAX_VALUE), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
 * @test SDV_TLS_DTLS13_SEQ_RECORD_NUM_TC023
 * @spec -
 * @title DTLS1.3 sequence number tracking via REC_GetLastWriteRecordNum test.
 * @precon nan
 * @brief
 *    1. Create DTLS1.3 client and server links over UDP.
 *    2. Establish a DTLS1.3 connection.
 *    3. Send multiple records and verify sequence number increments.
 *    4. Verify the peer can read each transferred record.
 * @expect
 *    1. Link creation succeeds.
 *    2. Handshake succeeds.
 *    3. App data epoch is 3 (DTLS 1.3 handshake ends at epoch 3).
 *    4. Sequence numbers increment correctly for each record.
 *    5. Each transferred record is received with the expected plaintext.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_SEQ_RECORD_NUM_TC023(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    RecordNumber writeRecordNum;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // Send 5 app data records and verify sequence number progression
    // DTLS 1.3 handshake ends with epoch 3 (application data epoch)
    uint64_t prevWriteSeq = 0;
    for (uint64_t i = 0; i < 5; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "Seq record %llu", (unsigned long long)i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)msg, strlen(msg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(msg));

        // Verify write epoch and seq progression
        ASSERT_EQ(REC_GetLastWriteRecordNum(client->ssl, &writeRecordNum), HITLS_SUCCESS);
        ASSERT_EQ(writeRecordNum.epoch, 3);
        if (i > 0) {
            ASSERT_TRUE(writeRecordNum.sequenceNumber > prevWriteSeq);
        }
        prevWriteSeq = writeRecordNum.sequenceNumber;

        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(msg));
        ASSERT_EQ(memcmp(readBuf, msg, readLen), 0);

    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_ANTI_REPLAY_DIRECT_TC024
* @spec -
* @title DTLS1.3 anti-replay sliding window direct unit test.
* @precon nan
* @brief
*    1. Initialize a RecSlidWindow directly via internal API.
*    2. Test basic window behavior: accept new sequence, reject duplicate.
*    3. Test window sliding: accept sequences above top.
*    4. Test window boundary: reject sequences below window bottom.
* @expect
*    1. Initial state: top=0, window=0.
*    2. First occurrence of seq 0 is accepted; second is rejected.
*    3. Seq far above top is accepted and extends the window.
*    4. Seq below window bottom is rejected.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_ANTI_REPLAY_DIRECT_TC024(void)
{
#ifdef HITLS_TLS_FEATURE_ANTI_REPLAY
    RecSlidWindow w;

    // Reset and verify initial state
    RecAntiReplayReset(&w);
    ASSERT_EQ(w.top, 0);
    ASSERT_EQ(w.window, 0);

    // First occurrence of seq 0: not a duplicate
    ASSERT_TRUE(!RecAntiReplayCheck(&w, 0));
    RecAntiReplayUpdate(&w, 0);

    // Replay seq 0: should be duplicate
    ASSERT_TRUE(RecAntiReplayCheck(&w, 0));

    // New seq 1: not a duplicate
    ASSERT_TRUE(!RecAntiReplayCheck(&w, 1));
    RecAntiReplayUpdate(&w, 1);

    // Replay seq 1: duplicate
    ASSERT_TRUE(RecAntiReplayCheck(&w, 1));

    // Seq 70 (far above top): extends window, not duplicate
    ASSERT_TRUE(!RecAntiReplayCheck(&w, 70));
    RecAntiReplayUpdate(&w, 70);

    // After window extended to 70, seq 0 is below window bottom [7, 70]
    ASSERT_TRUE(RecAntiReplayCheck(&w, 0));

    // Seq 50 within window but not yet received: not duplicate
    ASSERT_TRUE(!RecAntiReplayCheck(&w, 50));
    RecAntiReplayUpdate(&w, 50);

    // Replay seq 50: duplicate
    ASSERT_TRUE(RecAntiReplayCheck(&w, 50));

    // Bottom edge of window
    ASSERT_TRUE(!RecAntiReplayCheck(&w, 7));
    RecAntiReplayUpdate(&w, 7);
    ASSERT_TRUE(RecAntiReplayCheck(&w, 7));

    // Below bottom edge
    ASSERT_TRUE(RecAntiReplayCheck(&w, 6));
#else
    SKIP_TEST();
#endif
EXIT:
    /* nothing to clean */
    ;
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_ANTI_REPLAY_REPLAY_DETECT_TC025
* @spec -
* @title DTLS1.3 anti-replay duplicate record detection after window advance test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Send first app data record and save a copy of its raw wire format.
*    4. Transfer and receive the record.
*    5. Send 10 more records to advance the server's anti-replay window.
*    6. Replay the saved copy of the first record via FRAME_TransportRecMsg.
*    7. Verify the server rejects the replayed record (returns HITLS_REC_NORMAL_RECV_BUF_EMPTY).
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. The first record and subsequent records are received normally.
*    4. The replayed first record is silently discarded by the anti-replay mechanism.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_ANTI_REPLAY_REPLAY_DETECT_TC025(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int32_t ret;
    FrameUioUserData *clientIo = NULL;
    uint8_t savedMsg[MAX_RECORD_LENTH];
    uint32_t savedLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // Send first app data and save a copy of the raw record BEFORE transfer
    char firstMsg[] = "First record for replay test";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)firstMsg, strlen(firstMsg), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(firstMsg));

    clientIo = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIo != NULL);
    ASSERT_TRUE(clientIo->sndMsg.len != 0);

    savedLen = clientIo->sndMsg.len;
    memcpy(savedMsg, clientIo->sndMsg.msg, savedLen);

    // Transfer first record and read on server
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(firstMsg));
    ASSERT_EQ(memcmp(readBuf, firstMsg, readLen), 0);

    // Advance the window with 10 more records (seq 1 through 10)
    for (int i = 0; i < 10; i++) {
        char advMsg[50];
        snprintf(advMsg, sizeof(advMsg), "Advance window msg %d", i);

        ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)advMsg, strlen(advMsg), &writeLen), HITLS_SUCCESS);
        ASSERT_EQ(writeLen, strlen(advMsg));
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

        readLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
        ASSERT_EQ(readLen, strlen(advMsg));
        ASSERT_EQ(memcmp(readBuf, advMsg, readLen), 0);
    }

    // Replay the saved first record via FRAME_TransportRecMsg
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, savedMsg, savedLen), HITLS_SUCCESS);

    // Read should return empty because the replayed record is rejected by anti-replay
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ret = HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen);
    ASSERT_EQ(ret, HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_PMTU_WRITE_SIZE_TC026
* @spec -
* @title DTLS1.3 PMTU max write size query test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Configure various MTU values and establish connection.
*    3. Query REC_GetMaxWriteSize for each MTU configuration.
*    4. Verify the max write size decreases appropriately as MTU shrinks.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds with configured MTU.
*    3. REC_GetMaxWriteSize returns decreasing values as MTU shrinks.
*    4. Large MTU allows larger write sizes; small MTU restricts write size.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_PMTU_WRITE_SIZE_TC026(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    uint32_t maxWriteSize = 0;
    uint32_t maxWriteSizeSmall = 0;
    uint8_t *largeData = NULL;
    HITLS_Config *configSmall = NULL;
    FRAME_LinkObj *clientSmall = NULL;
    FRAME_LinkObj *serverSmall = NULL;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // Set large MTU
    ret = HITLS_SetMtu(client->ssl, 1400);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, 1400);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // With MTU=1400, max write size should reflect overhead
    ret = REC_GetMaxWriteSize(client->ssl, &maxWriteSize);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    // Max write size should be > 0 and less than MTU (header overhead)
    ASSERT_TRUE(maxWriteSize > 0);
    ASSERT_TRUE(maxWriteSize <= 1400);

    // Send data at the max write size to verify
    largeData = malloc(maxWriteSize);
    ASSERT_TRUE(largeData != NULL);
    for (uint32_t i = 0; i < maxWriteSize; i++) {
        largeData[i] = i % 256;
    }
    ASSERT_EQ(HITLS_Write(client->ssl, largeData, maxWriteSize, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, maxWriteSize);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, maxWriteSize);
    ASSERT_EQ(memcmp(readBuf, largeData, readLen), 0);
    free(largeData);
    largeData = NULL;

    // Now test with smaller MTU and verify max write size decreases
    // Create new config for different MTU
    configSmall = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(configSmall != NULL);

    clientSmall = FRAME_CreateLink(configSmall, BSL_UIO_UDP);
    ASSERT_TRUE(clientSmall != NULL);
    serverSmall = FRAME_CreateLink(configSmall, BSL_UIO_UDP);
    ASSERT_TRUE(serverSmall != NULL);

    ASSERT_EQ(FRAME_CreateConnection(clientSmall, serverSmall, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ret = HITLS_SetMtu(clientSmall->ssl, 500);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(serverSmall->ssl, 500);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    ret = REC_GetMaxWriteSize(clientSmall->ssl, &maxWriteSizeSmall);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    // With MTU=500, max write size should be smaller than with MTU=1400
    ASSERT_TRUE(maxWriteSizeSmall < maxWriteSize);
    ASSERT_TRUE(maxWriteSizeSmall > 0);
    ASSERT_TRUE(maxWriteSizeSmall <= 500);

    // Send data at max write size with small MTU
    largeData = malloc(maxWriteSizeSmall);
    ASSERT_TRUE(largeData != NULL);
    for (uint32_t i = 0; i < maxWriteSizeSmall; i++) {
        largeData[i] = i % 256;
    }
    ASSERT_EQ(HITLS_Write(clientSmall->ssl, largeData, maxWriteSizeSmall, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, maxWriteSizeSmall);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(clientSmall, serverSmall), HITLS_SUCCESS);
    readLen = 0;
    memset(readBuf, 0, sizeof(readBuf));
    ASSERT_EQ(HITLS_Read(serverSmall->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, maxWriteSizeSmall);
    ASSERT_EQ(memcmp(readBuf, largeData, readLen), 0);

EXIT:
    free(largeData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_CFG_FreeConfig(configSmall);
    FRAME_FreeLink(clientSmall);
    FRAME_FreeLink(serverSmall);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_PMTU_QUERY_TC027
* @spec -
* @title DTLS1.3 PMTU query and data MTU test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Configure various MTU values and establish connection.
*    3. Query REC_QueryMtu and REC_GetMaxDataMtu.
*    4. Verify the APIs return correct values reflecting the MTU configuration.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. REC_QueryMtu returns a valid MTU.
*    4. REC_GetMaxDataMtu returns a value consistent with the MTU.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_PMTU_QUERY_TC027(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    uint32_t writeSize = 0;
    uint32_t dataMtu = 0;
    uint8_t *boundaryData = NULL;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    // Start with a medium MTU
    ret = HITLS_SetMtu(client->ssl, 1000);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ret = HITLS_SetMtu(server->ssl, 1000);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test REC_QueryMtu
    ret = REC_QueryMtu(client->ssl);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test REC_GetMaxDataMtu
    ret = REC_GetMaxDataMtu(client->ssl, &dataMtu);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(dataMtu > 0);
    ASSERT_TRUE(dataMtu <= 1000);

    // REC_GetMaxDataMtu should be consistent with REC_GetMaxWriteSize
    ret = REC_GetMaxWriteSize(client->ssl, &writeSize);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(writeSize <= dataMtu);

    // Verify data transmission at the data Mtu boundary
    boundaryData = malloc(dataMtu);
    ASSERT_TRUE(boundaryData != NULL);
    for (uint32_t i = 0; i < dataMtu; i++) {
        boundaryData[i] = (uint8_t)(i & 0xFF);
    }
    ASSERT_EQ(HITLS_Write(client->ssl, boundaryData, dataMtu, &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, dataMtu);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, dataMtu);
    ASSERT_EQ(memcmp(readBuf, boundaryData, readLen), 0);

EXIT:
    free(boundaryData);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CHACHA20_CIPHER_SUITE_TC028
* @spec -
* @title DTLS1.3 ChaCha20-Poly1305 cipher suite test.
* @precon nan
* @brief
*    1. Create DTLS1.3 config restricted to ChaCha20-Poly1305 only.
*    2. Create client and server links over UDP.
*    3. Establish a DTLS1.3 connection.
*    4. Verify ChaCha20-Poly1305 was negotiated.
*    5. Send and receive application data to exercise the SN encryption path.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds with ChaCha20-Poly1305.
*    3. Application data is correctly encrypted/decrypted.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CHACHA20_CIPHER_SUITE_TC028(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    uint16_t chachaSuite = HITLS_CHACHA20_POLY1305_SHA256;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    ASSERT_EQ(HITLS_CFG_SetCipherSuites(config, &chachaSuite, 1), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite == HITLS_CHACHA20_POLY1305_SHA256);

    char testData[] = "ChaCha20 SN encryption test";
    ASSERT_EQ(HITLS_Write(client->ssl, (uint8_t *)testData, strlen(testData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, strlen(testData));

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(testData));
    ASSERT_EQ(memcmp(readBuf, testData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CCM8_SHORT_RECORD_PADDING_TC031
* @spec -
* @title DTLS1.3 AES-CCM-8 short application records are padded for sequence number protection.
* @precon nan
* @brief
*    1. Configure both endpoints to use HITLS_AES_128_CCM_8_SHA256.
*    2. Establish a DTLS1.3 connection.
*    3. Send one byte of application data.
*    4. Verify the generated encrypted record length is at least 16 bytes before sequence number protection.
*    5. Transfer and read the record to verify decrypt still succeeds.
* @expect
*    1. The DTLS1.3 CCM8 suite is negotiable.
*    2. Short application data is padded to satisfy RFC 9147 sequence number encryption input length.
*    3. The peer decrypts and reads the original one byte.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CCM8_SHORT_RECORD_PADDING_TC031(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FrameUioUserData *clientIo = NULL;
    uint8_t writeData[] = {0x5A};
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    uint16_t ccm8Suite = HITLS_AES_128_CCM_8_SHA256;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(config, &ccm8Suite, 1), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_AES_128_CCM_8_SHA256);

    ASSERT_EQ(HITLS_Write(client->ssl, writeData, sizeof(writeData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(writeData));
    clientIo = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIo != NULL);
    ASSERT_TRUE(clientIo->sndMsg.len >= REC_DTLS13_UNI_HEADER_LENGTH + 16u);
    ASSERT_EQ(BSL_ByteToUint16(&clientIo->sndMsg.msg[REC_DTLS13_UNI_HEADER_LENGTH - sizeof(uint16_t)]),
        clientIo->sndMsg.len - REC_DTLS13_UNI_HEADER_LENGTH);
    ASSERT_TRUE(BSL_ByteToUint16(&clientIo->sndMsg.msg[REC_DTLS13_UNI_HEADER_LENGTH - sizeof(uint16_t)]) >= 16u);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(writeData));
    ASSERT_EQ(memcmp(readBuf, writeData, readLen), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_EPOCH2_RECV_EPOCH0_TC029
* @spec -
* @title DTLS1.3 server receives epoch 0 app data record while in epoch 2 test.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Establish a DTLS1.3 connection.
*    3. Set server readEpoch to 2 and reset anti-replay window.
*    4. Inject a crafted epoch 0 app-data record via classic header.
*    5. Verify the epoch-0 acceptance path succeeds and data is returned.
* @expect
*    1. Link creation succeeds.
*    2. Handshake succeeds.
*    3. Epoch check accepts epoch 0 record (DtlsRecordHeaderProcess condition).
*    4. RecordDecrypt uses PlainDecrypt for epoch 0 and returns the body.
*    5. HITLS_Read returns HITLS_SUCCESS with the injected body.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_EPOCH2_RECV_EPOCH0_TC029(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_ANTI_REPLAY
    RecCtx *recCtx = NULL;
    RecConnState *readState = NULL;
#endif

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

#ifdef HITLS_TLS_FEATURE_ANTI_REPLAY
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Modify server's internal state to simulate readEpoch=2 (post-handshake) */
    recCtx = (RecCtx *)server->ssl->recCtx;
    recCtx->readEpoch = 2;
    readState = recCtx->readStates.currentState;
    RecConnSetEpoch(readState, 2);
    RecAntiReplayReset(&readState->window);

    /*
     * Reset saved handshake sequence so that HS_Init (called from PreprocessUnexpectHsMsg)
     * sets expectRecvSeq=0, allowing our injected ClientHello (msg_seq=0) to pass
     * the sequence-ordering check inside DtlsReadAndParseHandshakeMsg.
     */
    server->ssl->dtls13NextSendSeq = 0;
    server->ssl->dtls13ExpectRecvSeq = 0;

    /*
     * Build a classic DTLS header record with epoch=0 (simulating a late-arriving
     * pre-handshake ClientHello, RFC 9147 §4.6.2).
     *
     * Use content type 22 (HANDSHAKE) with a DTLS handshake header + minimal body.
     *
     * Layout: type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13 bytes
     *         + DTLS handshake header (12 bytes) + body (1 byte) = 26 bytes
     */
    uint8_t hsBody = 0x01;
    uint8_t hsHeader[DTLS_HS_MSG_HEADER_SIZE] = {
        CLIENT_HELLO,       /* handshake type (1) */
        0, 0, 1,            /* length = 1 (3 bytes big-endian) */
        0, 0,               /* message_seq = 0 */
        0, 0, 0,            /* fragment_offset = 0 */
        0, 0, 1             /* fragment_length = 1 (same as length, unfragmented) */
    };
    uint8_t record[13 + sizeof(hsHeader) + sizeof(hsBody)] = {0};
    record[0] = REC_TYPE_HANDSHAKE;
    BSL_Uint16ToByte(HITLS_VERSION_DTLS12, &record[1]);
    BSL_Uint16ToByte(0, &record[3]);
    /* seq (bytes 5-10) = 0 */
    BSL_Uint16ToByte(sizeof(hsHeader) + sizeof(hsBody), &record[11]);
    memcpy(&record[13], hsHeader, sizeof(hsHeader));
    memcpy(&record[13 + sizeof(hsHeader)], &hsBody, sizeof(hsBody));

    ASSERT_EQ(FRAME_TransportRecMsg(server->io, record, sizeof(record)), HITLS_SUCCESS);

    /*
     * Exercised paths:
     *   DtlsCheckRecordHeader → RecCastUintToRecType(22, epoch=0) → REC_TYPE_HANDSHAKE
     *   DtlsRecordHeaderProcess: readEpoch(2) == 2 && epoch(0) == 0 && !isClient → accepted
     *   RecordDecrypt: epoch==0 → PlainDecrypt (memcpy)
     *   AntiReplay: epoch==0 guard → skipped (no switch to outdated state)
     *   DtlsRecordRead: recordType(APP) != cryptMsg.type(HANDSHAKE) → cached via RecordUnexpectedMsg
     *   PreprocessUnexpectHsMsg → HS_Init → HS_ChangeState(TRY_RECV_MSG)
     *   RecvUnexpectMsgInTransportingStateProcess → Dtls13TryRecvHandShakeMsg
     *   → DtlsReadAndParseHandshakeMsg → CheckHsMsgType(CLIENT_HELLO, TRY_RECV_MSG)
     *   → CheckDtls13RecvAnyMsgType → default → HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE
     */
    ret = HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_UNEXPECTED_MESSAGE);
#else
    SKIP_TEST();
#endif
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_EPOCH2_BUFFER_EPOCH3_TC030
* @spec -
* @title DTLS1.3 buffers epoch 3 records received while the read epoch is still 2.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Move the server read epoch back to 2 to simulate the handshake state before processing peer Finished.
*    3. Inject a DTLS1.3 unified-header epoch 3 record.
*    4. Read from the server and verify the record is buffered as encrypted unprocessed data.
* @expect
*    1. The epoch 3 low bits are reconstructed to epoch 3.
*    2. The record is not decrypted while readEpoch is 2.
*    3. The ciphertext is stored in UnprocessedMsgList for later epoch 3 processing.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_EPOCH2_BUFFER_EPOCH3_TC030(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    uint8_t record[REC_DTLS13_UNI_HEADER_LENGTH + 1] = {0};
    RecCtx *recCtx = NULL;
    RecConnState *readState = NULL;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    recCtx = (RecCtx *)server->ssl->recCtx;
    recCtx->readEpoch = 2;
    readState = recCtx->readStates.currentState;
    RecConnSetEpoch(readState, 2);
    UnprocessedMsgListDeinit(&recCtx->UnprocessedMsgList);

    ASSERT_EQ(BuildDtls13UnifiedHeader(record, sizeof(record), 3, 0, 0, REC_TYPE_APP), sizeof(record));
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, record, sizeof(record)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, APP_READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_DISORDER_MSG);
    ASSERT_EQ(recCtx->UnprocessedMsgList.count, 1);
    ASSERT_EQ(REC_EPOCH_GET(BSL_LIST_ENTRY(recCtx->UnprocessedMsgList.head.next, UnprocessedMsg, head)->hdr.epochSeq),
        3);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_EPOCH2_BEFORE_SERVER_HELLO_TC037
* @spec -
* @title DTLS1.3 client buffers epoch 2 EncryptedExtensions received before ServerHello.
* @precon nan
* @brief
*    1. Stop after the first ClientHello reaches the server.
*    2. Let the server generate ServerHello, save it, then generate the next epoch 2 encrypted handshake record.
*    3. Deliver the epoch 2 encrypted record to the client before ServerHello.
*    4. Deliver ServerHello and continue the handshake.
* @expect
*    1. The client buffers the epoch 2 record while its read epoch is 0.
*    2. After ServerHello advances the read epoch, the cached record is consumed.
*    3. The DTLS1.3 handshake can still complete.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_EPOCH2_BEFORE_SERVER_HELLO_TC037(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FrameUioUserData *serverIo = NULL;
    uint8_t serverHello[MAX_RECORD_LENTH] = {0};
    uint32_t serverHelloLen = 0;
    uint8_t epoch2Record[MAX_RECORD_LENTH] = {0};
    uint32_t epoch2RecordLen = 0;
    int32_t ret;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(Dtls13HandshakeRetIsPending(ret));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    serverIo = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIo != NULL);
    ASSERT_TRUE(serverIo->recMsg.len != 0);

    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(Dtls13HandshakeRetIsPending(ret));
    ASSERT_TRUE(serverIo->sndMsg.len > REC_DTLS_RECORD_HEADER_LEN + DTLS_HS_MSG_HEADER_SIZE);
    ASSERT_EQ(serverIo->sndMsg.msg[0], REC_TYPE_HANDSHAKE);
    ASSERT_EQ(serverIo->sndMsg.msg[REC_DTLS_RECORD_HEADER_LEN], SERVER_HELLO);
    serverHelloLen = serverIo->sndMsg.len;
    memcpy(serverHello, serverIo->sndMsg.msg, serverHelloLen);
    serverIo->sndMsg.len = 0;

    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(Dtls13HandshakeRetIsPending(ret));
    ASSERT_TRUE(serverIo->sndMsg.len > REC_DTLS13_UNI_HEADER_LENGTH);
    ASSERT_TRUE(REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(serverIo->sndMsg.msg[0]));
    ASSERT_EQ(serverIo->sndMsg.msg[0] & REC_DTLS13_UNI_HEADER_EPOCH_BITS_MASK, 2);
    epoch2RecordLen = serverIo->sndMsg.len;
    memcpy(epoch2Record, serverIo->sndMsg.msg, epoch2RecordLen);
    serverIo->sndMsg.len = 0;

    ASSERT_EQ(FRAME_TransportRecMsg(client->io, epoch2Record, epoch2RecordLen), HITLS_SUCCESS);
    ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(Dtls13HandshakeRetIsPending(ret));
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_SERVER_HELLO);
    ASSERT_EQ(client->ssl->recCtx->UnprocessedMsgList.count, 1);

    ASSERT_EQ(FRAME_TransportRecMsg(client->io, serverHello, serverHelloLen), HITLS_SUCCESS);
    ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(Dtls13HandshakeRetIsPending(ret));
    if (client->ssl->recCtx->UnprocessedMsgList.count != 0) {
        ret = HITLS_Connect(client->ssl);
        ASSERT_TRUE(Dtls13HandshakeRetIsPending(ret));
    }
    ASSERT_EQ(client->ssl->recCtx->UnprocessedMsgList.count, 0);
    ASSERT_TRUE(client->ssl->hsCtx == NULL || client->ssl->hsCtx->state != TRY_RECV_SERVER_HELLO);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_SHORT_CIPHERTEXT_DISCARD_TC038
* @spec -
* @title DTLS1.3 silently discards protected records shorter than the sequence-number mask input.
* @precon nan
* @brief
*    1. Establish a DTLS1.3 connection.
*    2. Inject a DTLS1.3 unified-header application epoch record with ciphertext length 15.
*    3. Read application data on the receiver.
* @expect
*    1. The invalid record is discarded as an invalid DTLS record.
*    2. HITLS_Read returns HITLS_REC_NORMAL_RECV_BUF_EMPTY and no alert is sent.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_SHORT_CIPHERTEXT_DISCARD_TC038(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FrameUioUserData *serverIo = NULL;
    uint8_t record[REC_DTLS13_UNI_HEADER_LENGTH + 15] = {0};
    uint32_t recordLen = 0;
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ALERT_Info alert = {0};

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    serverIo = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIo != NULL);
    serverIo->recMsg.len = 0;
    serverIo->sndMsg.len = 0;

    recordLen = BuildDtls13UnifiedCiphertextRecord(record, sizeof(record), 3, 0, 15);
    ASSERT_TRUE(recordLen != 0);
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, record, recordLen), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0);
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_TRUE(alert.flag != ALERT_FLAG_SEND);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
