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
/* INCLUDE_BASE test_suite_sdv_frame_dtls13_cid_consistency */
#include "sal_time.h"
/* END_HEADER */

#define TEST_CID_A_LEN 4
#define TEST_CID_B_LEN 4
static uint8_t g_testCidA[TEST_CID_A_LEN] = {0x01, 0x02, 0x03, 0x04};
static uint8_t g_testCidB[TEST_CID_B_LEN] = {0xAA, 0xBB, 0xCC, 0xDD};

#define TEST_NEW_CID_LEN 4
static uint8_t g_testNewCid[TEST_NEW_CID_LEN] = {0x11, 0x22, 0x33, 0x44};

static void ForceDtlsTimerExpired(HITLS_Ctx *ctx)
{
    ctx->deadline = (BSL_TIME){BSL_TIME_SYSTEM_EPOCH_YEAR, 1, 1, 0, 0, 0, 0, 0};
}

typedef struct {
    uint8_t grant;
    uint8_t actual;
    uint8_t seed;
    HITLS_DtlsCidUsage usage;
    int32_t ret;
} TestCidReplyParam;

typedef struct {
    uint8_t called;
    uint8_t numCids;
    int32_t ret;
} TestCidErrorCbParam;

static void SetCidEntry(HITLS_DtlsCidEntry *entry, const uint8_t *cid, uint8_t cidLen)
{
    (void)memset(entry, 0, sizeof(*entry));
    entry->cidLen = cidLen;
    if (cidLen > 0) {
        (void)memcpy(entry->cidVal, cid, cidLen);
    }
}

static void FillGeneratedCid(HITLS_DtlsCidEntry *entry, uint8_t seed, uint8_t idx, uint8_t cidLen)
{
    (void)memset(entry, 0, sizeof(*entry));
    entry->cidLen = cidLen;
    for (uint8_t i = 0; i < cidLen; i++) {
        entry->cidVal[i] = (uint8_t)(seed + idx * 17u + i);
    }
}

static int32_t TestRecvRequestConnectionIdCb(HITLS_Ctx *ctx, uint8_t numCids, void *userData)
{
    TestCidReplyParam *param = (TestCidReplyParam *)userData;
    if (param == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint8_t count = (param->grant < numCids) ? param->grant : numCids;
    if (count > HITLS_DTLS_CID_LIST_MAX) {
        count = HITLS_DTLS_CID_LIST_MAX;
    }

    HITLS_DtlsCidEntry entries[HITLS_DTLS_CID_LIST_MAX] = {0};
    uint8_t cidLen = ctx->negotiatedInfo.localCidEntry.cidLen;
    for (uint8_t i = 0; i < count; i++) {
        FillGeneratedCid(&entries[i], param->seed, i, cidLen);
    }

    int32_t ret = HITLS_NewConnectionId(ctx, entries, &count, param->usage);
    param->actual = count;
    param->ret = ret;
    return ret;
}

static int32_t TestRecvRequestConnectionIdErrorCb(HITLS_Ctx *ctx, uint8_t numCids, void *userData)
{
    (void)ctx;
    TestCidErrorCbParam *param = (TestCidErrorCbParam *)userData;
    if (param == NULL) {
        return HITLS_NULL_INPUT;
    }
    param->called++;
    param->numCids = numCids;
    return param->ret;
}

static int32_t SetupCidConnection(FRAME_LinkObj **clientOut, FRAME_LinkObj **serverOut, HITLS_Config *config)
{
    /* Enable CID at config level before HITLS_New consumes the config. */
    int32_t ret = HITLS_CFG_SetDtlsCidSupport(config, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    if (client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    if (server == NULL) {
        FRAME_FreeLink(client);
        return HITLS_INTERNAL_EXCEPTION;
    }

    ret = HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN);
    if (ret != HITLS_SUCCESS) {
        FRAME_FreeLink(client);
        FRAME_FreeLink(server);
        return ret;
    }
    ret = HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN);
    if (ret != HITLS_SUCCESS) {
        FRAME_FreeLink(client);
        FRAME_FreeLink(server);
        return ret;
    }

    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    if (ret != HITLS_SUCCESS) {
        FRAME_FreeLink(client);
        FRAME_FreeLink(server);
        return ret;
    }

    *clientOut = client;
    *serverOut = server;
    return HITLS_SUCCESS;
}

static int32_t SetupNoCidConnection(FRAME_LinkObj **clientOut, FRAME_LinkObj **serverOut, HITLS_Config *config)
{
    int32_t ret = HITLS_CFG_SetDtlsCidSupport(config, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    if (client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    if (server == NULL) {
        FRAME_FreeLink(client);
        return HITLS_INTERNAL_EXCEPTION;
    }
    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    if (ret != HITLS_SUCCESS) {
        FRAME_FreeLink(client);
        FRAME_FreeLink(server);
        return ret;
    }
    *clientOut = client;
    *serverOut = server;
    return HITLS_SUCCESS;
}

/* Arm a valid NewConnectionId wire message without passing through the public API. This is used
 * only to model a non-compliant peer that sends the message although CID was not negotiated. */
static int32_t ArmInjectedNewConnectionId(HITLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    if (ctx == NULL || cid == NULL || cidLen == 0) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->negotiatedInfo.cidCtx != NULL) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    DTLS_CidCtx *cidCtx = (DTLS_CidCtx *)BSL_SAL_Calloc(1, sizeof(DTLS_CidCtx));
    if (cidCtx == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    cidCtx->currentSendIdx = HITLS_DTLS_CID_NO_IDX;
    cidCtx->recvSlots[0].state = DTLS_CID_RECV_SLOT_ACTIVE;
    cidCtx->recvSlots[0].entry.cidLen = cidLen;
    (void)memcpy(cidCtx->recvSlots[0].entry.cidVal, cid, cidLen);
    cidCtx->cidWrittenMask = 1u;
    cidCtx->cidUsage = (uint8_t)HITLS_DTLS_CID_SPARE;
    ctx->negotiatedInfo.cidCtx = cidCtx;
    ctx->newCidState = DTLS_CID_MSG_STATE_PENDING;
    return HITLS_SUCCESS;
}

static int32_t ReadPostHandshake(FRAME_LinkObj *link)
{
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    return HITLS_Read(link->ssl, readBuf, READ_BUF_SIZE, &readLen);
}

/*
 * Drive a post-handshake RequestConnectionId -> cb -> NewConnectionId exchange.
 *
 * The receiver gets the RequestConnectionId datagram in its inbox. HITLS_Read
 * processes the record, the DTLS 1.3 record layer auto-sends an ACK into the
 * outbox, and the recv callback calls HITLS_NewConnectionId which queues a
 * follow-up handshake message. Production UDP serialises both into the kernel
 * send queue without back-pressure, but the FRAME simulate UIO holds at most
 * one outbound record at a time, so the queued NewConnectionId send hits
 * HITLS_REC_NORMAL_IO_BUSY. Resume the queued send after evacuating the ACK.
 *
 * Returns HITLS_SUCCESS once the receiver has both the ACK and the
 * NewConnectionId in its outbox ready for the next FRAME_TrasferMsgBetweenLink.
 */
static int32_t DrainCidRecvCbExchange(FRAME_LinkObj *receiver, FRAME_LinkObj *sender)
{
    int32_t ret = ReadPostHandshake(receiver);
    if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
        return HITLS_SUCCESS;
    }
    if (ret != HITLS_REC_NORMAL_IO_BUSY) {
        return ret;
    }
    /* The auto ACK occupies the FRAME outbox; move it to the peer so the
     * queued NewConnectionId send can proceed on the next state-machine pump. */
    ret = FRAME_TrasferMsgBetweenLink(receiver, sender);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* Drain whatever ACK reached the sender so its retransmit list/recCtx
     * settle (peer cb-driven flows ignore the payload here). */
    uint8_t buf[READ_BUF_SIZE] = {0};
    uint32_t len = 0;
    (void)HITLS_Read(sender->ssl, buf, sizeof(buf), &len);
    /* Resume the receiver: its hsCtx state is TRY_SEND_NEW_CONNECTION_ID and
     * Connect/Accept will run HS_DoHandshake again from there. */
    if (receiver->ssl->isClient) {
        return HITLS_Connect(receiver->ssl);
    }
    return HITLS_Accept(receiver->ssl);
}

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    TestCidReplyParam reply = {1, 0, 0x60, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_PENDING);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 1);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* RFC 9147 §5.2: reqCidState fulfillment is driven by record-layer ACK,
     * not by the peer's NewConnectionId. The DrainCidRecvCbExchange helper
     * delivered the auto ACK to the client already, which fulfills the
     * RequestConnectionId via the retransmit-list callback. */
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    TestCidReplyParam reply = {1, 0, 0x70, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(client->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(server->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->reqCidState, DTLS_CID_MSG_STATE_PENDING);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_EQ(DrainCidRecvCbExchange(client, server), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 1);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* RFC 9147 §5.2: the auto ACK delivered by DrainCidRecvCbExchange already
     * acknowledged the server's RequestConnectionId. */
    DTLS_CID_OnRequestConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    const DTLS_CidSendEntry *sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testCidA, TEST_CID_A_LEN), 0);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_NEW_CID_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testNewCid, TEST_NEW_CID_LEN), 0);
    DTLS_CID_OnNewConnectionIdAcked(client->ssl);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    const DTLS_CidSendEntry *sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testCidB, TEST_CID_B_LEN), 0);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, &entry, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_NEW_CID_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testNewCid, TEST_NEW_CID_LEN), 0);
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testCidA, TEST_CID_A_LEN);
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_IMMEDIATE),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_NE(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_MSG_HANDLE_UNSUPPORT_VERSION);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC008
 * @spec RFC 9147 section 9
 * @title RequestConnectionId(num_cids=0) is a no-op and does not block a later real request
 * @precon nan
 * @brief HITLS_RequestConnectionId with numCids == 0 returns HITLS_SUCCESS without arming the CID
 *        sub-state machine (reqCidState stays IDLE): asking the peer for zero CIDs is a semantic
 *        no-op, since the RFC 9147 §9 response would be an empty NewConnectionId, which is itself a
 *        no-op on both send (HITLS_NewConnectionId SPARE+0 early-returns) and receive
 *        (DTLS_CID_ProcessPeerNewConnectionId early-returns for cidsLen == 0). Skipping the send
 *        avoids pointless traffic and state-machine churn, and mirrors
 *        HITLS_NewConnectionId(cidCount=0, SPARE) (see TC021). The receiver must still tolerate a
 *        num_cids == 0 RequestConnectionId from a non-compliant peer; that path is covered by TC018.
 * @expect 1. RequestConnectionId(num_cids=0) returns HITLS_SUCCESS.
 *         2. reqCidState stays DTLS_CID_MSG_STATE_IDLE (no send armed, nothing put on the wire).
 *         3. A subsequent RequestConnectionId(num_cids=1) returns HITLS_SUCCESS and arms
 *            reqCidState == PENDING (the no-op left no stale lock).
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Baseline: post-handshake CID state machine is idle. */
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);

    /* (1) num_cids=0: legal no-op. Returns SUCCESS without arming the state machine. */
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 0), HITLS_SUCCESS);

    /* (2) State invariant: still IDLE (no empty RequestConnectionId armed/sent). */
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);

    /* (3) The no-op left no stale lock: a subsequent real request arms the state machine normally. */
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_PENDING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC009(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, NULL, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_INVALID_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC010(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testCidA, TEST_CID_A_LEN);

    uint8_t cidCount = 0;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, NULL, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 0);

    cidCount = 0;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_IMMEDIATE),
        HITLS_INVALID_INPUT);
    ASSERT_EQ(cidCount, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC011(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_PENDING);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 2), HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC012(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);

    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);

    cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_IMMEDIATE),
        HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(cidCount, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC013(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    TestCidReplyParam reply = {9, 0, 0x80, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 9), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 9);

    uint8_t entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 10);

    HITLS_DtlsCidEntry serverEntries[10] = {0};
    entryCount = 10;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, serverEntries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 10);
    for (uint8_t i = 0; i < entryCount; i++) {
        ASSERT_EQ(serverEntries[i].cidLen, TEST_CID_B_LEN);
    }

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 10);

    HITLS_DtlsCidEntry clientEntries[10] = {0};
    entryCount = 10;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, clientEntries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 10);
    for (uint8_t i = 0; i < entryCount; i++) {
        ASSERT_EQ(clientEntries[i].cidLen, TEST_CID_B_LEN);
    }

    /* RFC 9147 §5.2: simulate the ACK that fulfils this RequestConnectionId. */
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC014(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);
    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 1);
    }

    TestCidReplyParam reply = {16, 0, 0x90, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 16), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);

    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 15);
    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    uint8_t entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, HITLS_DTLS_CID_LIST_MAX);
    /* RFC 9147 §5.2: simulate the ACK that fulfils this RequestConnectionId. */
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC015(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    TestCidReplyParam reply = {15, 0, 0xA0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 15), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 15);
    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    DTLS_CID_OnNewConnectionIdAcked(server->ssl);

    HITLS_DtlsCidEntry overflowEntries[7] = {0};
    uint8_t cidLen = server->ssl->negotiatedInfo.localCidEntry.cidLen;
    for (uint8_t i = 0; i < 7; i++) {
        FillGeneratedCid(&overflowEntries[i], 0xD0, i, cidLen);
    }

    uint8_t cidCount = 7;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, overflowEntries, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 0);
    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    cidCount = 7;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, overflowEntries, &cidCount, HITLS_DTLS_CID_IMMEDIATE),
        HITLS_INVALID_INPUT);
    ASSERT_EQ(cidCount, 0);
    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC016
 * @spec RFC 9147 section 5.2
 * @title Receiving RequestConnectionId while the peer sends an empty CID aborts with unexpected_message
 * @precon nan
 * @brief Asymmetric CID negotiation: the client advertises an EMPTY connection_id
 *        (localCidEntry.cidLen = 0) while the server advertises a real CID. The server is
 *        therefore "sending an empty Connection ID" to the client on every record. Per RFC 9147
 *        §5.2 ("Implementations MUST NOT send RequestConnectionId when sending an empty Connection
 *        ID. Implementations which detect a violation of these rules MUST terminate the connection
 *        with an 'unexpected_message' alert."), receiving a RequestConnectionId in this state must
 *        abort the connection. A compliant server is prevented from sending it by the send-side
 *        guard (HITLS_RequestConnectionId returns HITLS_MSG_HANDLE_STATE_ILLEGAL because
 *        server.peerCidEntry.cidLen == 0); a non-compliant peer is simulated by arming the CID
 *        sub-state machine directly and driving the real (encrypted) send path.
 * @expect 1. HITLS_RequestConnectionId(server, 0) is rejected with HITLS_MSG_HANDLE_STATE_ILLEGAL.
 *         2. After the non-compliant send, HITLS_Read on the client fails.
 *         3. The client sent a fatal unexpected_message alert and the connection is torn down.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC016(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client offers an EMPTY connection_id extension; server offers a real CID. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* CID is negotiated, and the client's advertised recv CID stays empty: every record the
     * server sends to the client therefore carries an empty Connection ID. */
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, true);
    ASSERT_EQ(client->ssl->negotiatedInfo.localCidEntry.cidLen, 0u);

    /* RFC 9147 §5.2 send-side guard: a compliant server must not send RequestConnectionId while
     * sending an empty CID (server.peerCidEntry.cidLen == 0 here). */
    ASSERT_EQ(HITLS_RequestConnectionId(server->ssl, 0), HITLS_MSG_HANDLE_STATE_ILLEGAL);

    /* Simulate a non-compliant peer that sends it anyway: bypass the API guard and drive the
     * real encrypted send path. numCids = 0 matches the reported scenario; the violation is
     * independent of num_cids. */
    server->ssl->reqCidState = DTLS_CID_MSG_STATE_PENDING;
    server->ssl->reqCidNum = 0;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    /* Client receives the RequestConnectionId and must abort per RFC 9147 §5.2. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_NE(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
    /* 断链: the connection has been torn down. */
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC017
 * @spec RFC 9147 section 5.2
 * @title Client with an empty own CID may still send RequestConnectionId when the peer CID is non-empty
 * @precon nan
 * @brief RFC 9147 §5.2 says "Implementations MUST NOT send RequestConnectionId when sending an empty
 *        Connection ID." The Connection ID a sender places on its outbound records is the RECEIVER's
 *        advertised CID (peerCidEntry), not the sender's own advertised CID (localCidEntry). Therefore
 *        a client that advertised an empty connection_id, but whose server peer advertised a real CID,
 *        is NOT sending an empty Connection ID and MUST be allowed to send RequestConnectionId. This
 *        test locks that behavior down: it must not be rejected just because localCidEntry.cidLen == 0.
 * @expect 1. HITLS_RequestConnectionId(client, 1) returns HITLS_SUCCESS.
 *         2. The server receives and processes the RequestConnectionId normally (no alert).
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC017(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client advertises an EMPTY connection_id; server advertises a real CID. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* The client's own recv CID is empty, but the CID it puts on outbound records to the server
     * (peerCidEntry = the server's advertised CID) is non-empty: it is NOT sending an empty CID. */
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, true);
    ASSERT_EQ(client->ssl->negotiatedInfo.localCidEntry.cidLen, 0u);
    ASSERT_TRUE(client->ssl->negotiatedInfo.peerCidEntry.cidLen > 0u);

    /* RFC 9147 §5.2: the client MUST be allowed to send RequestConnectionId here. */
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_PENDING);

    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    /* The server receives the RequestConnectionId and processes it normally (its own recv CID is
     * non-empty, so it is not an empty-CID violation). No callback is registered -> no-op. */
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC018
 * @spec RFC 9147 section 5.2 / section 9
 * @title Empty own CID + non-empty peer CID + RequestConnectionId(num_cids=0) must succeed
 * @precon nan
 * @brief Reproduces the exact scenario reported against tag dtls0715:
 *        client advertises an EMPTY connection_id extension (cidLen = 0) while the server
 *        advertises a real CID; the client then sends a post-handshake RequestConnectionId with
 *        num_cids = 0. At dtls0715 the receiver-side gate in parse.c checked
 *        `peerCidEntry.cidLen == 0`, so the server (whose peerCidEntry = the client's empty CID)
 *        wrongly replied with an unexpected_message alert, breaking the handshake.
 *
 *        Per RFC 9147 §9 (lines 2260-2263): "Implementations MUST NOT send RequestConnectionId
 *        when sending an empty Connection ID." The Connection ID a sender places on its outbound
 *        records is the RECEIVER's advertised CID (peerCidEntry), not the sender's own. The
 *        client's outbound records to the server carry the SERVER's advertised CID, which is
 *        non-empty here, so the client is NOT sending an empty Connection ID and is therefore
 *        allowed to send RequestConnectionId. The server's own localCidEntry.cidLen is non-empty,
 *        so receiving this message is not an empty-CID violation. RFC 9147 §9 (lines 2280-2282)
 *        also permits answering a request with fewer CIDs "including no CIDs at all", so num_cids
 *        = 0 is a legal no-op and MUST NOT abort. The expected behavior is handshake success.
 *
 *        Sender side: HITLS_RequestConnectionId now treats numCids == 0 as a no-op (returns
 *        HITLS_SUCCESS without arming reqCidState, mirroring HITLS_NewConnectionId(cidCount=0,
 *        SPARE) -- see TC008 / TC021). To still exercise the numCids == 0 early-return path in
 *        Dtls13RecvRequestConnectionIdProcess (the dtls0715 receiver-side regression, distinct
 *        from TC017 which uses num_cids = 1 and hits the no-callback branch), the test bypasses
 *        the API guard and drives the real encrypted send of a num_cids = 0 RequestConnectionId
 *        via direct state arming, the same non-compliant-peer technique used by TC016. num_cids = 0
 *        is a legal wire value (RFC 9147 §9 permits answering a request with "no CIDs at all"),
 *        so the receiver MUST tolerate it from any peer even though this implementation's own
 *        sender never emits it.
 * @expect 1. HITLS_RequestConnectionId(client, 0) returns HITLS_SUCCESS and leaves reqCidState IDLE.
 *         2. After the injected num_cids = 0 send, the server processes the message with no alert.
 *         3. No unexpected_message alert is emitted (the dtls0715 defect); both stay TRANSPORTING.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC018(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client offers an EMPTY connection_id extension; server offers a real CID. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* CID is negotiated; client's own recv CID stays empty while the CID the client places on
     * outbound records to the server (peerCidEntry = server's advertised CID) is non-empty. */
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, true);
    ASSERT_EQ(client->ssl->negotiatedInfo.localCidEntry.cidLen, 0u);
    ASSERT_TRUE(client->ssl->negotiatedInfo.peerCidEntry.cidLen > 0u);
    /* Server's own recv CID is non-empty: it is NOT receiving an empty-CID violation. */
    ASSERT_TRUE(server->ssl->negotiatedInfo.localCidEntry.cidLen > 0u);

    /* Sender-side no-op: RequestConnectionId(num_cids = 0) returns SUCCESS without arming the
     * state machine (mirrors HITLS_NewConnectionId(cidCount=0, SPARE)). The client does NOT put
     * an empty request on the wire through the public API. */
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 0), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);

    /* To still cover the receiver-side dtls0715 regression, simulate a non-compliant peer that
     * sends num_cids = 0 anyway: bypass the API no-op guard and drive the real encrypted send
     * path (same technique as TC016). num_cids = 0 is a legal wire value, so the receiver must
     * tolerate it from any peer. */
    client->ssl->reqCidState = DTLS_CID_MSG_STATE_PENDING;
    client->ssl->reqCidNum = 0;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    /* The server receives the RequestConnectionId(num_cids = 0). Per RFC 9147 §9 this is a legal
     * no-op: it MUST NOT abort with unexpected_message (the dtls0715 bug) and MUST stay
     * TRANSPORTING. num_cids = 0 means no NewConnectionId reply is expected either. */
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

    /* Explicitly assert no fatal alert was raised on either side (the dtls0715 defect). */
    ALERT_Info serverAlert = {0};
    ALERT_GetInfo(server->ssl, &serverAlert);
    ASSERT_NE(serverAlert.level, ALERT_LEVEL_FATAL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC019
 * @spec RFC 9147 section 9
 * @title NewConnectionId from a peer that negotiated an empty recv CID must abort
 * @precon nan
 * @brief Reproduces the second scenario reported against tag dtls0715: a peer that
 *        advertised an EMPTY connection_id (negotiated receiving an empty CID) sends
 *        a NewConnectionId. Per RFC 9147 §9 (lines 2258-2263): "Implementations which
 *        either did not negotiate the connection_id extension or which have negotiated
 *        receiving an empty CID MUST NOT send NewConnectionId." The violation is a
 *        property of the SENDER (its own advertised CID is empty), which from the
 *        receiver's perspective is peerCidEntry. At dtls0715 (and still at HEAD before
 *        this change) the receiver checked the wrong field (localCidEntry) and the
 *        process function had no guard at all, so the message was accepted.
 *
 *        The send-side guard (HITLS_NewConnectionId, localCidEntry.cidLen == 0)
 *        correctly blocks a COMPLIANT sender, so the test arms the real encrypted send
 *        path on a symmetric link and then clears the receiver's peerCidEntry to mirror
 *        an asymmetric handshake where the peer advertised an empty connection_id --
 *        the same non-compliant-peer technique used by TC016 for RequestConnectionId.
 * @expect 1. HITLS_Read on the server fails.
 *         2. The server sent a fatal unexpected_message alert.
 *         3. The connection is torn down (CM_STATE_ALERTED).
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC019(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Client queues a real NewConnectionId send (send-side guard passes: its own
     * recv CID is g_testCidA, non-empty). This populates cidCtx + cidWrittenMask
     * and arms newCidState = PENDING. */
    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);

    /* RFC 9147 §9 violation condition at the RECEIVER: the peer (client) negotiated
     * receiving an empty CID, i.e. the server's peerCidEntry.cidLen == 0. Mirror that
     * here by clearing the server's peerCidEntry; reception (which keys off the
     * server's own localCidEntry) is unaffected. */
    server->ssl->negotiatedInfo.peerCidEntry.cidLen = 0;

    /* Drive the queued NewConnectionId send on the real encrypted path. */
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    /* Server receives the NewConnectionId and MUST abort per RFC 9147 §9
     * (was silently accepted before the fix). */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_NE(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
    ASSERT_EQ(server->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC020
 * @spec RFC 9147 section 9
 * @title NewConnectionId to a receiver with an empty own CID but a non-empty peer CID must succeed
 * @precon nan
 * @brief Reproduces the third scenario reported against tag dtls0715: client
 *        advertises an EMPTY connection_id while the server advertises a real CID,
 *        and the server sends a post-handshake NewConnectionId to the client. Per
 *        RFC 9147 §9 (lines 2258-2263) the "negotiated receiving an empty CID"
 *        prohibition is a property of the SENDER: the server's own recv CID is
 *        non-empty, so the server is allowed to send NewConnectionId, and the
 *        client MUST process it normally (the offered CIDs feed the client's
 *        outbound pool and are independent of the client's own empty recv CID).
 *
 *        At dtls0715 parse.c CheckDtls13RecvAnyMsgType checked the WRONG field
 *        (localCidEntry.cidLen == 0) on NEW_CONNECTION_ID, so a receiver whose own
 *        advertised CID was empty wrongly aborted a legal message with
 *        unexpected_message. The fix delegates the empty-CID rule to
 *        Dtls13RecvNewConnectionIdProcess, which inspects peerCidEntry (the
 *        sender's recv CID) and so does not fire here.
 * @expect 1. The client processes the NewConnectionId with no alert.
 *         2. Both endpoints stay in CM_STATE_TRANSPORTING.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC020(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client advertises an EMPTY connection_id; server advertises a real CID. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Server (sender) has a non-empty own recv CID: per RFC 9147 §9 it MAY send
     * NewConnectionId. The offered CID length must match the server's own
     * localCidEntry.cidLen (CheckNewConnectionIdInput enforces this) and must not
     * duplicate an existing recv slot, so reuse TEST_CID_B_LEN with a fresh value. */
    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, &entry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);

    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    /* Client receives the NewConnectionId. RFC 9147 §9: the sender's recv CID is
     * non-empty, so this is legal and the client MUST process it normally. At
     * dtls0715 the parse.c false-positive on localCidEntry aborted this with
     * unexpected_message. */
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_NE(alert.level, ALERT_LEVEL_FATAL);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC021
 * @spec HITLS_SetRecvRequestConnectionIdCb
 * @title Passing a NULL callback clears the current RequestConnectionId callback
 * @precon nan
 * @brief Register a callback that would generate one SPARE NewConnectionId, clear it by calling
 *        HITLS_SetRecvRequestConnectionIdCb(ctx, NULL, NULL), and then receive a real encrypted
 *        RequestConnectionId(num_cids=1). The request itself is still acknowledged by DTLS, but
 *        the cleared application callback must not run and no NewConnectionId reply may be armed
 *        or delivered to the requester.
 * @expect 1. Both callback registration and callback clearing return HITLS_SUCCESS.
 *         2. The cleared callback is not invoked after RequestConnectionId is received.
 *         3. The receiver's newCidState stays IDLE and the requester's send CID list is unchanged.
 *         4. Both endpoints stay in CM_STATE_TRANSPORTING.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC021(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t sendCidBefore = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidBefore), HITLS_SUCCESS);

    TestCidReplyParam reply = {1, 0, 0xD0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply),
        HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->onRecvRequestCidCb != NULL);

    /* cb == NULL clears the previously installed callback. */
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, NULL, NULL), HITLS_SUCCESS);
    ASSERT_TRUE(server->ssl->onRecvRequestCidCb == NULL);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    /* The receiver still emits the protocol ACK, but must not invoke the cleared callback or
     * arm a NewConnectionId response. */
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(reply.actual, 0u);
    ASSERT_EQ(reply.ret, HITLS_INTERNAL_EXCEPTION);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* Deliver and consume the protocol ACK. If a NewConnectionId had been generated, processing
     * the receiver's output would grow the client's send CID list. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    uint8_t sendCidAfter = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidAfter), HITLS_SUCCESS);
    ASSERT_EQ(sendCidAfter, sendCidBefore);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC022
 * @spec HITLS_RecvRequestConnectionIdCb
 * @title A nonzero RequestConnectionId callback result sends a fatal internal_error alert
 * @precon nan
 * @brief Register a callback that records its input and returns HITLS_INVALID_INPUT without
 *        generating any CID. After receiving a real encrypted RequestConnectionId(num_cids=1),
 *        the receiver must treat the callback result as an application handling failure and send
 *        a fatal internal_error alert. Because request processing fails, HITLS_Read returns the
 *        callback's error code and the fatal alert is sent instead of completing the normal ACK
 *        and NewConnectionId response path.
 * @expect 1. The callback is invoked exactly once with num_cids=1.
 *         2. The receiver records and sends a fatal internal_error alert.
 *         3. The peer receives the same fatal internal_error alert and both endpoints become ALERTED.
 *         4. No NewConnectionId response is armed.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC022(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    TestCidErrorCbParam errorCb = {0, 0, HITLS_INVALID_INPUT};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdErrorCb, &errorCb),
        HITLS_SUCCESS);

    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    /* The callback error is returned unchanged to the receiver's application. */
    ASSERT_EQ(ReadPostHandshake(server), errorCb.ret);
    ASSERT_EQ(errorCb.called, 1u);
    ASSERT_EQ(errorCb.numCids, 1u);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    ALERT_Info serverAlert = {0};
    ALERT_GetInfo(server->ssl, &serverAlert);
    ASSERT_EQ(serverAlert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(serverAlert.description, ALERT_INTERNAL_ERROR);
    ASSERT_EQ(server->ssl->state, CM_STATE_ALERTED);

    /* Verify the fatal internal_error on the wire, not only in the sender's alert context. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_NE(ReadPostHandshake(client), HITLS_SUCCESS);

    ALERT_Info clientAlert = {0};
    ALERT_GetInfo(client->ssl, &clientAlert);
    ASSERT_EQ(clientAlert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(clientAlert.description, ALERT_INTERNAL_ERROR);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC023
 * @spec RFC 9147 section 7 / HITLS_RequestConnectionId
 * @title RequestConnectionId stays SENT across ACK loss and timeout retransmission until ACK arrives
 * @precon nan
 * @brief Send RequestConnectionId and drop its first datagram so no peer ACK is received. While
 *        reqCidState is SENT, verify that another RequestConnectionId is rejected but an independent
 *        NewConnectionId operation succeeds. Force the DTLS retransmit timer to expire, deliver the
 *        retransmitted request, and process the peer's real ACK. Finally verify that ACK returns
 *        reqCidState to IDLE and a new RequestConnectionId can be armed again.
 * @expect 1. Before ACK, reqCidState is SENT and another RequestConnectionId returns an error.
 *         2. NewConnectionId succeeds independently and sets only newCidState to PENDING.
 *         3. Timeout emits a retransmitted RequestConnectionId; reqCidState remains SENT and another
 *            RequestConnectionId still returns an error.
 *         4. Processing the peer ACK changes reqCidState to IDLE, after which RequestConnectionId
 *            succeeds again.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC023(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Send the first RequestConnectionId. It remains outstanding until its retransmit node is ACKed. */
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_TRUE(REC_RetransmitIsEmpty(client->ssl->recCtx) == false);
    ASSERT_TRUE(client->ssl->timeoutValue != 0u);

    FrameUioUserData *clientIo = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIo != NULL);
    ASSERT_TRUE(clientIo->sndMsg.len > 0u);
    /* Drop the first datagram: the peer receives no RequestConnectionId and therefore sends no ACK. */
    clientIo->sndMsg.len = 0u;

    /* (1) SENT blocks a second request while the first request is unacknowledged. */
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_NE(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);

    /* (2) NewConnectionId has an independent state machine and can be armed while RequestConnectionId
     * is SENT. Leave it PENDING so the timeout cycle below isolates retransmission of the already-sent
     * request rather than sending the newly armed message. */
    HITLS_DtlsCidEntry newEntry = {0};
    SetCidEntry(&newEntry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &newEntry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1u);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);

    /* (3) Trigger the DTLS timeout handler directly.
     * Only RequestConnectionId is currently in the retransmit list, so the output is its timeout
     * retransmission; the independently armed NewConnectionId is still only PENDING. */
    client->ssl->timeoutValue = 1;
    ForceDtlsTimerExpired(client->ssl);
    ASSERT_EQ(HITLS_DtlsProcessTimeout(client->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(clientIo->sndMsg.len > 0u);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_NE(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);

    /* Deliver the retransmitted request. The server has no application callback, so it only emits
     * the protocol ACK and does not generate a NewConnectionId response. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    /* (4) The real ACK removes the retransmit node and invokes the RequestConnectionId ACK hook. */
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_PENDING);
    /* The independent NewConnectionId operation remains pending throughout the Request ACK lifecycle. */
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC024
 * @spec RFC 9147 section 9
 * @title Client that did not negotiate CID aborts on received NewConnectionId
 * @precon nan
 * @brief Establish DTLS 1.3 with CID disabled on both endpoints. Bypass only the peer's public
 *        send-side guard to inject a valid encrypted NewConnectionId into the connection.
 * @expect The client sends fatal unexpected_message and enters CM_STATE_ALERTED.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC024(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupNoCidConnection(&client, &server, config), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, false);
    ASSERT_EQ(server->ssl->negotiatedInfo.isCidNegotiated, false);

    ASSERT_EQ(ArmInjectedNewConnectionId(server->ssl, g_testNewCid, TEST_NEW_CID_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_NE(ReadPostHandshake(client), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC025
 * @spec RFC 9147 section 9
 * @title Client that did not negotiate CID cannot send NewConnectionId
 * @precon nan
 * @brief Establish DTLS 1.3 with CID disabled, then call HITLS_NewConnectionId on the client.
 * @expect The API returns an error and no NewConnectionId state is armed.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC025(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupNoCidConnection(&client, &server, config), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, false);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_NE(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_TRUE(client->ssl->negotiatedInfo.cidCtx == NULL);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC026
 * @spec RFC 9147 section 9
 * @title Client that did not negotiate CID aborts on received RequestConnectionId
 * @precon nan
 * @brief Establish DTLS 1.3 with CID disabled. Bypass only the peer's public send-side guard and
 *        send a valid encrypted RequestConnectionId(num_cids=1).
 * @expect The client sends fatal unexpected_message and enters CM_STATE_ALERTED.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC026(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupNoCidConnection(&client, &server, config), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, false);
    ASSERT_EQ(server->ssl->negotiatedInfo.isCidNegotiated, false);

    server->ssl->reqCidNum = 1;
    server->ssl->reqCidState = DTLS_CID_MSG_STATE_PENDING;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->reqCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_NE(ReadPostHandshake(client), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC027
 * @spec RFC 9147 section 9
 * @title Client that did not negotiate CID cannot send RequestConnectionId
 * @precon nan
 * @brief Establish DTLS 1.3 with CID disabled, then call HITLS_RequestConnectionId on the client.
 * @expect The API returns an error and reqCidState remains IDLE.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC027(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupNoCidConnection(&client, &server, config), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, false);

    ASSERT_NE(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->reqCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC028
 * @spec RFC 9147 section 9
 * @title Client that negotiated an empty receive CID aborts on RequestConnectionId(num_cids=1)
 * @precon nan
 * @brief Negotiate CID asymmetrically: client receive CID is empty and server receive CID is
 *        non-empty. Simulate a non-compliant server sending RequestConnectionId(num_cids=1) while
 *        its outbound records carry the client's empty CID.
 * @expect The client sends fatal unexpected_message and enters CM_STATE_ALERTED.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC028(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, true);
    ASSERT_EQ(client->ssl->negotiatedInfo.localCidEntry.cidLen, 0u);

    ASSERT_NE(HITLS_RequestConnectionId(server->ssl, 1), HITLS_SUCCESS);
    server->ssl->reqCidNum = 1;
    server->ssl->reqCidState = DTLS_CID_MSG_STATE_PENDING;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_NE(ReadPostHandshake(client), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC029
 * @spec RFC 9147 section 9
 * @title Client that negotiated an empty receive CID cannot send NewConnectionId
 * @precon nan
 * @brief Negotiate CID with an empty client receive CID and a non-empty server receive CID, then
 *        call HITLS_NewConnectionId on the client.
 * @expect The API returns an error and newCidState remains IDLE.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC029(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, true);
    ASSERT_EQ(client->ssl->negotiatedInfo.localCidEntry.cidLen, 0u);

    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    ASSERT_NE(HITLS_NewConnectionId(client->ssl, &entry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC030
 * @spec RFC 9147 section 9
 * @title Empty-receive-CID client may request and receive a NewConnectionId from a normal CID server
 * @precon nan
 * @brief Negotiate CID asymmetrically: client receive CID is empty and server receive CID is
 *        non-empty. The client sends RequestConnectionId(num_cids=1); the server callback replies
 *        with one SPARE NewConnectionId. This is legal because the client's outbound records carry
 *        the server's non-empty CID and the server is allowed to advertise a new non-empty CID.
 * @expect The request and callback reply succeed, the client accepts the new send CID, and both
 *         endpoints remain in CM_STATE_TRANSPORTING without a fatal alert.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_UPDATE_FUNC_TC030(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.isCidNegotiated, true);
    ASSERT_EQ(client->ssl->negotiatedInfo.localCidEntry.cidLen, 0u);
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, TEST_CID_B_LEN);

    TestCidReplyParam reply = {1, 0, 0x90, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 1u);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 2u);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_NE(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC021
 * @spec RFC 9147 section 9
 * @title NewConnectionId(cidCount=0, SPARE) is a no-op and does not block a later real NewConnectionId
 * @precon nan
 * @brief HITLS_NewConnectionId with *cidCount == 0 and usage == HITLS_DTLS_CID_SPARE returns
 *        HITLS_SUCCESS without arming the CID sub-state machine and without materializing the recv
 *        slot table: conn_dtls_cid_update.c early-returns at the `requested == 0` guard before
 *        GetOrCreateCidCtx / CommitRecvCids / `newCidState = PENDING` run. It is therefore a pure
 *        no-op -- no empty NewConnectionId is put on the wire, the local recv CID list is unchanged,
 *        and newCidState stays IDLE. This intentionally differs from HITLS_RequestConnectionId
 *        (numCids=0, see TC008), which DOES arm reqCidState and sends an empty RequestConnectionId:
 *        an empty NewConnectionId carries no information, whereas num_cids=0 is a meaningful
 *        request-shape on the wire. The SENT -> IDLE lifecycle that an empty NewConnectionId would
 *        have exercised is instead covered here by the subsequent real NewConnectionId(cidCount=1).
 * @expect 1. The cidCount=0 SPARE call returns HITLS_SUCCESS and leaves *cidCount == 0.
 *         2. newCidState stays DTLS_CID_MSG_STATE_IDLE and cidCtx stays NULL (no send armed,
 *            slot table not materialized).
 *         3. The local recv CID list is unchanged (still exactly the 1 handshake-time recv CID).
 *         4. A subsequent NewConnectionId(cidCount=1, SPARE) returns HITLS_SUCCESS, *cidCount == 1,
 *            arms newCidState == PENDING, and the recv list grows to 2.
 *         5. After the real send and a peer ACK, newCidState returns to IDLE.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC021(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Baseline: post-handshake CID state machine is idle and the slot table is not yet materialized. */
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_TRUE(client->ssl->negotiatedInfo.cidCtx == NULL);

    /* (1) cidCount=0 + SPARE: legal no-op. Returns SUCCESS, out-param stays 0. */
    uint8_t zero = 0;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, NULL, &zero, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(zero, 0);

    /* (2) State invariant: still IDLE (no empty NewConnectionId armed/sent) and the slot table is
     *     still un-materialized -- proves the early-return path was taken. */
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_TRUE(client->ssl->negotiatedInfo.cidCtx == NULL);

    /* (3) recv_list invariant: the no-op added nothing; the client still advertises exactly its
     *     single handshake-time recv CID. */
    uint8_t recvCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, NULL, &recvCount), HITLS_SUCCESS);
    ASSERT_EQ(recvCount, 1);

    /* (4) The no-op left no stale lock: a subsequent real NewConnectionId arms the state machine
     *     normally and commits the new CID into the sender's recv slots. */
    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t one = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &one, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(one, 1);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    recvCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, NULL, &recvCount), HITLS_SUCCESS);
    ASSERT_EQ(recvCount, 2);

    /* (5) Drive the real send through the lifecycle: PENDING -> SENT, deliver to the peer, then the
     *     ACK hook flips it back to IDLE (mirrors TC003's lifecycle on a valid payload). */
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    DTLS_CID_OnNewConnectionIdAcked(client->ssl);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC022
 * @spec RFC 9147 section 9
 * @title NewConnectionId(SPARE) on a full recv list is a no-op (cidCount=0, state stays IDLE)
 * @precon nan
 * @brief When every recv slot is non-FREE (the 1 negotiated local CID plus 15 spare CIDs already
 *        advertised via an earlier NewConnectionId, filling all HITLS_DTLS_CID_LIST_MAX = 16 slots),
 *        HITLS_NewConnectionId has nowhere to commit a new CID. The SPARE truncation rule in
 *        conn_dtls_cid_update.c computes accepted = min(requested, freeCount) = 0 and, because SPARE
 *        tolerates truncation to zero, early-returns HITLS_SUCCESS at the `accepted == 0` guard
 *        BEFORE arming the CID sub-state machine: *cidCount stays 0, newCidState stays IDLE, and no
 *        NewConnectionId is put on the wire. (Contrast IMMEDIATE on a full list, which returns
 *        HITLS_INVALID_INPUT -- see TC015.) This case fixes cidCount = 2 and asserts the state-
 *        machine invariant directly, complementing TC015 which focuses on the truncation count and
 *        the IMMEDIATE rejection.
 * @expect 1. NewConnectionId(server, cidCount=2, SPARE) returns HITLS_SUCCESS with *cidCount == 0.
 *         2. newCidState stays DTLS_CID_MSG_STATE_IDLE (no send armed, no NewCID on the wire).
 *         3. The recv CID list stays full at HITLS_DTLS_CID_LIST_MAX (unchanged).
 *         4. The connection stays CM_STATE_TRANSPORTING on both sides.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC022(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Fill the server's recv list to HITLS_DTLS_CID_LIST_MAX: the client requests 15 spare CIDs and
     * the server's recv cb grants 15, which join the 1 negotiated local CID -> 16 = FULL. */
    TestCidReplyParam reply = {15, 0, 0xB0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 15), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 15);

    /* Baseline: server recv list is full and its NewConnectionId state machine is back to idle. */
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* RFC 9147 §9 SPARE truncation: with zero free recv slots, accepted = min(2, 0) = 0 and SPARE
     * tolerates the truncation, so the call is a no-op that does not arm the state machine. */
    HITLS_DtlsCidEntry overflowEntries[2] = {0};
    uint8_t cidLen = server->ssl->negotiatedInfo.localCidEntry.cidLen;
    FillGeneratedCid(&overflowEntries[0], 0xD0, 0, cidLen);
    FillGeneratedCid(&overflowEntries[1], 0xD0, 1, cidLen);
    uint8_t cidCount = 2;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, overflowEntries, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 0);

    /* State invariant: still IDLE (no NewConnectionId armed/sent). */
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* recv_list invariant: still full (the no-op committed nothing). */
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC023
 * @spec RFC 9147 section 9
 * @title NewConnectionId(SPARE) exact-fit: 3 active + cidCount=13 == LIST_MAX, all 13 accepted
 * @precon nan
 * @brief Boundary case for the SPARE truncation rule in conn_dtls_cid_update.c. With 3 recv slots
 *        ACTIVE and 13 FREE (freeCount == 13), requesting exactly 13 SPARE CIDs hits the exact-fit
 *        point: accepted = min(requested, freeCount) = min(13, 13) = 13 -- the ternary's strict
 *        '<' takes the freeCount branch when the two are equal, which still equals requested, so
 *        nothing is truncated. All 13 are accepted, the recv list fills to HITLS_DTLS_CID_LIST_MAX
 *        = 16, the CID sub-state machine arms (PENDING -> SENT on the wire -> IDLE on ACK), and the
 *        peer's send pool absorbs all 13. This is the boundary between TC013-style partial fill and
 *        the TC015 / TC022 full-list no-op.
 * @expect 1. NewConnectionId(server, cidCount=13, SPARE) returns HITLS_SUCCESS with *cidCount == 13.
 *         2. newCidState == PENDING and the recv list is already 16 (committed at call time, before
 *            any send / ACK).
 *         3. After the send, newCidState == SENT, the message carries usage cid_spare, and the peer
 *            absorbs all 13 (send pool -> 16) without replacing the active outbound CID.
 *         4. HITLS_GetDtlsRecvCid(NULL, &count) reports 16 both pre- and post-ACK (recv_list is not
 *            ACK-dependent).
 *         5. After the ACK hook, newCidState == IDLE; both sides stay TRANSPORTING.
 *         6. A follow-up NewConnectionId(cidCount=1, SPARE) is the full-list no-op: SUCCESS,
 *            *cidCount == 0, no send, newCidState stays IDLE, recv_list stays 16.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC023(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Pre-fill the server's recv list to 3 ACTIVE: the client requests 2 and the server's recv cb
     * grants 2 SPARE CIDs, joining the 1 negotiated local CID -> 3 ACTIVE, 13 FREE. */
    TestCidReplyParam reply = {2, 0, 0xC0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 2);
    /* Deliver the server's 2-CID reply to the client so the server outbox is clean for the next
     * send, and settle both post-handshake state machines back to idle. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);

    /* Baseline: server recv list = 3 ACTIVE, NewConnectionId state machine idle. */
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 3);
    }
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* (A) Exact-fit boundary: requested (13) == freeCount (13), so accepted = 13 with no truncation.
     *     The recv slots are committed inside the API (CommitRecvCids), so recv_list is already 16
     *     at PENDING -- before any send or ACK. */
    HITLS_DtlsCidEntry entries[HITLS_DTLS_CID_LIST_MAX] = {0};
    uint8_t cidLen = server->ssl->negotiatedInfo.localCidEntry.cidLen;
    for (uint8_t i = 0; i < 13; i++) {
        FillGeneratedCid(&entries[i], 0xE0, i, cidLen);
    }
    uint8_t cidCount = 13;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, entries, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 13);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    /* (B) Drive the send: PENDING -> SENT. recv_list stays 16 (pre-ACK checkpoint, ACK-independent).
     *     The wire usage (cid_spare vs cid_immediate) is verified on the peer side below. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    /* Peer absorbs all 13 as SPARE: send pool -> 16, and the active outbound CID is NOT replaced
     * (cid_spare appends; only cid_immediate would retire it) -- this is the semantic proof the
     * wire message carried usage cid_spare. (cidCtx->cidUsage is a transient staging field that
     * pack_new_connection_id.c clears right after packing, so it cannot be asserted post-send.) */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    {
        uint8_t sendCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
        ASSERT_EQ(sendCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(client->ssl->negotiatedInfo.peerCidEntry.cidVal, g_testCidB, TEST_CID_B_LEN), 0);

    /* (C) ACK flips the state machine to IDLE; recv_list is unchanged at 16 (post-ACK checkpoint). */
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

    /* (D) The list is now full (freeCount == 0), so a follow-up NewConnectionId(cidCount=1, SPARE)
     *     hits the accepted == 0 no-op: SUCCESS, *cidCount == 0, no send armed, state stays IDLE,
     *     recv_list stays 16. */
    HITLS_DtlsCidEntry extra = {0};
    FillGeneratedCid(&extra, 0xF0, 0, cidLen);
    uint8_t one = 1;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, &extra, &one, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(one, 0);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC024
 * @spec RFC 9147 section 9
 * @title NewConnectionId(SPARE, 16) on a 13-full recv list -> 3 accepted, new+old CIDs all matchable
 * @precon nan
 * @brief Partial-truncation-to-non-zero: with 13 recv slots ACTIVE and 3 FREE (freeCount == 3),
 *        HITLS_NewConnectionId(SPARE, cidCount=16) computes accepted = min(16, 3) = 3 -- non-zero, so
 *        unlike TC022's full-list no-op the call commits 3 new CIDs, sends a NewConnectionId carrying
 *        exactly those 3 (usage cid_spare), and reports *cidCount == 3. The recv list fills to
 *        HITLS_DTLS_CID_LIST_MAX = 16. Because usage is SPARE (not IMMEDIATE), BeginImmediateRetire
 *        is NOT run: the 13 old CIDs stay ACTIVE alongside the 3 new ones, so the record layer
 *        (rec_read.c -> DTLS_CID_IsExpectedCid) accepts inbound records tagged with ANY of the 16
 *        CIDs, both before and after the ACK. This complements TC022 (full no-op) and TC023 (exact
 *        fit) by exercising the min() truncation to a non-zero accepted count, and adds the
 *        new/old CID inbound-acceptance coverage.
 * @expect 1. NewConnectionId(server, cidCount=16, SPARE) returns HITLS_SUCCESS with *cidCount == 3.
 *         2. recv list grows 13 -> 16; all 16 entries share the original cid length.
 *         3. newCidState PENDING -> SENT on the wire; the message carries 3 CIDs, usage cid_spare.
 *         4. Pre-ACK: DTLS_CID_IsExpectedCid(server, newCid) and (server, oldCid) both true.
 *         5. After the ACK hook, newCidState == IDLE; recv list stays 16.
 *         6. Post-ACK: new+old CIDs still matchable; app-data round-trips on both succeed.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC024(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Pre-fill the server's recv list to 13 ACTIVE: client requests 12, server's recv cb grants 12
     * SPARE CIDs, joining the 1 negotiated local CID -> 13 ACTIVE, 3 FREE. */
    TestCidReplyParam reply = {12, 0, 0xC0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 12), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 12);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);

    /* Baseline: server recv list = 13 ACTIVE. */
    uint8_t cidLen = server->ssl->negotiatedInfo.localCidEntry.cidLen;
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 13);
    }

    /* Partial truncation: requested (16) > freeCount (3) -> accepted = 3. The committed CIDs keep
     * the original length (CheckNewConnectionIdInput rejects any length mismatch). */
    HITLS_DtlsCidEntry entries[HITLS_DTLS_CID_LIST_MAX] = {0};
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        FillGeneratedCid(&entries[i], 0xE0, i, cidLen);
    }
    const uint8_t *newCid = entries[0].cidVal;
    uint8_t cidCount = HITLS_DTLS_CID_LIST_MAX;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, entries, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 3);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    /* All 16 recv entries share the original cid length ("CID长度均为首次长度字节"). */
    {
        HITLS_DtlsCidEntry recvEntries[HITLS_DTLS_CID_LIST_MAX] = {0};
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, recvEntries, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
        for (uint8_t i = 0; i < recvCidCount; i++) {
            ASSERT_EQ(recvEntries[i].cidLen, cidLen);
        }
    }

    /* Drive the send: PENDING -> SENT, deliver to the peer. recv_list stays 16 (pre-ACK). */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* (pre-ACK) SPARE did not retire the old CIDs, so both the 3 new and the 13 old recv CIDs are
     * still matchable by the record layer. */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, newCid, cidLen));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));

    /* ACK flips the state machine to IDLE; recv_list unchanged at 16 (post-ACK). */
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, newCid, cidLen));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));

    /* Flush the stale auto-ACK the client queued while processing the server's NewConnectionId: the
     * FRAME outbox holds one record, so an undelivered ACK would make the app-data Write below return
     * HITLS_REC_NORMAL_IO_BUSY. The server's state machine is already IDLE (ACK hook fired above), so
     * absorbing this wire ACK is a harmless no-op. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* End-to-end proof: the peer sends app data tagged with a NEW then an OLD recv CID, and the
     * server's record layer accepts both (CID matched against the ACTIVE recv slots). */
    uint8_t appData[] = "cid-accept";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, newCid, cidLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC025
 * @spec RFC 9147 section 9
 * @title NewConnectionId(IMMEDIATE, cidCount=0) is rejected, then a real IMMEDIATE call succeeds
 * @precon nan
 * @brief IMMEDIATE must retire the peer's active outbound CID and replace it, so it requires at
 *        least one CID; an empty IMMEDIATE would leave the peer with no usable CID. Therefore
 *        HITLS_NewConnectionId with cidCount == 0 and usage == IMMEDIATE returns HITLS_INVALID_INPUT
 *        at the `requested == 0` guard in conn_dtls_cid_update.c, leaving *cidCount == 0 and newCidState
 *        untouched (IDLE) -- the early return runs before GetOrCreateCidCtx / CommitRecvCids / state
 *        arming, so the CID sub-state machine is not corrupted and a retry is not blocked. This is
 *        the IMMEDIATE counterpart of TC021 (SPARE+0 no-op); TC010 already covers the bare rejection,
 *        and this case adds the "failed call does not block a subsequent real call" assertion.
 * @expect 1. NewConnectionId(cidCount=0, IMMEDIATE) returns HITLS_INVALID_INPUT, *cidCount == 0.
 *         2. newCidState stays IDLE (the rejection did not arm the state machine).
 *         3. A subsequent NewConnectionId(cidCount=1, IMMEDIATE) returns HITLS_SUCCESS, *cidCount == 1,
 *            newCidState == PENDING.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC025(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* (1) IMMEDIATE requires >= 1 CID: cidCount=0 is rejected at the requested==0 guard, before any
     *     state is armed. */
    uint8_t zero = 0;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, NULL, &zero, HITLS_DTLS_CID_IMMEDIATE), HITLS_INVALID_INPUT);
    ASSERT_EQ(zero, 0);

    /* (2) The rejection did not corrupt the state machine: newCidState stays IDLE. */
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* (3) A subsequent real IMMEDIATE call succeeds and arms the state machine normally. */
    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t one = 1;
    ASSERT_EQ(HITLS_NewConnectionId(client->ssl, &entry, &one, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(one, 1);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC026
 * @spec RFC 9147 section 9
 * @title NewConnectionId(IMMEDIATE) retires old recv CIDs on ACK, then a truncated IMMEDIATE refill
 * @precon nan
 * @brief The IMMEDIATE counterpart of TC023 / TC024. With 3 recv slots ACTIVE, NewConnectionId
 *        (IMMEDIATE, cidCount=13) hits the exact-fit point (accepted = min(13, 13) = 13) and commits
 *        13 new ACTIVE CIDs, but first BeginImmediateRetire flips the 3 old ACTIVE slots to
 *        DEPRECATING. Pre-ACK the recv list therefore holds 3 DEPRECATING + 13 ACTIVE = 16 non-FREE
 *        (HITLS_GetDtlsRecvCid counts every non-FREE slot, so it reports 16). On ACK,
 *        DTLS_CID_OnNewConnectionIdAcked memsets every DEPRECATING slot back to FREE, so the 3 old
 *        CIDs vanish and the count drops to 13. A second NewConnectionId(IMMEDIATE, cidCount=15) then
 *        runs against 13 ACTIVE / 3 FREE: accepted = min(15, 3) = 3, the 13 are retired to
 *        DEPRECATING and 3 new ACTIVE are committed -> 16 non-FREE again. This is the key contrast
 *        with SPARE (TC023/TC024), which never retires old CIDs.
 * @expect 1. NewConnectionId(server, cidCount=13, IMMEDIATE) returns HITLS_SUCCESS, *cidCount == 13,
 *           newCidState == PENDING, recv list == 16 (3 DEPRECATING + 13 ACTIVE).
 *         2. The message carries usage cid_immediate: the peer's active outbound CID is REPLACED by
 *           the first new CID (SPARE would have left it unchanged).
 *         3. After the ACK hook, newCidState == IDLE and recv list == 13 (3 old DEPRECATING cleared).
 *         4. NewConnectionId(server, cidCount=15, IMMEDIATE) returns HITLS_SUCCESS, *cidCount == 3
 *           (truncated), recv list == 16 (13 retired + 3 new).
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC026(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Pre-fill the server's recv list to 3 ACTIVE: client requests 2, server's recv cb grants 2. */
    TestCidReplyParam reply = {2, 0, 0xC0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 2), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 2);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);

    uint8_t cidLen = server->ssl->negotiatedInfo.localCidEntry.cidLen;
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 3);
    }

    /* (1) Call 1: IMMEDIATE, exact-fit 13. BeginImmediateRetire flips the 3 old ACTIVE to
     *     DEPRECATING, then 13 new ACTIVE are committed -> 16 non-FREE (pre-ACK). */
    HITLS_DtlsCidEntry entries[HITLS_DTLS_CID_LIST_MAX] = {0};
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        FillGeneratedCid(&entries[i], 0xE0, i, cidLen);
    }
    const uint8_t *newCid1 = entries[0].cidVal;
    uint8_t cidCount = 13;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, entries, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 13);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    /* Drive the send and deliver to the peer. recv_list stays 16 (pre-ACK). */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    /* (2) usage cid_immediate proof: the peer's active outbound CID is replaced by the first new CID
     *     (SPARE would have left g_testCidB in place, as in TC023/TC024). */
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, cidLen);
    ASSERT_EQ(memcmp(client->ssl->negotiatedInfo.peerCidEntry.cidVal, newCid1, cidLen), 0);

    /* (3) ACK flips the state machine to IDLE and clears the 3 DEPRECATING slots -> recv list 13. */
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 13);
    }

    /* (4) Call 2: IMMEDIATE, cidCount=15 truncated to 3 (freeCount == 3). The 13 ACTIVE are retired
     *     to DEPRECATING and 3 new ACTIVE committed -> 16 non-FREE. */
    HITLS_DtlsCidEntry entries2[HITLS_DTLS_CID_LIST_MAX] = {0};
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        FillGeneratedCid(&entries2[i], 0xF0, i, cidLen);
    }
    cidCount = HITLS_DTLS_CID_LIST_MAX - 1; /* 15 */
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, entries2, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 3);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC027
 * @spec RFC 9147 section 7 / section 9
 * @title IMMEDIATE truncation + timeout retransmit keeps recv_list, ACK clears history, old CID revives
 * @precon nan
 * @brief With 13 recv slots ACTIVE, NewConnectionId(IMMEDIATE, cidCount=16) truncates to accepted=3
 *        (freeCount=3); BeginImmediateRetire flips the 13 old ACTIVE to DEPRECATING and 3 new (ABC)
 *        are committed ACTIVE -> 16 non-FREE pre-ACK. A timeout retransmit of NewCID(ABC) then
 *        re-sends the same bytes via REC_RetransmitListFlush (the function HITLS_DtlsProcessTimeout
 *        calls on timeout); it does NOT re-run CommitRecvCids (that ran once inside the API), so the
 *        recv_list is unchanged at 16. Once the ACK arrives, DTLS_CID_OnNewConnectionIdAcked clears
 *        the 13 DEPRECATING slots, leaving only ABC (3). One of the just-cleared old CIDs (D) is then
 *        re-advertised via NewConnectionId(SPARE): CheckRecvSlotDuplicate only compares against the
 *        3 current slots (ABC), and D was already memset to FREE, so it is accepted as a fresh ACTIVE
 *        slot -> recv 3 -> 4, and a record tagged D is matchable again.
 * @expect 1. NewConnectionId(IMMEDIATE, 16) returns SUCCESS, *cidCount == 3, recv == 16 pre-ACK.
 *         2. After REC_RetransmitListFlush, a record was re-emitted but recv_list stays 16.
 *         3. After the ACK hook, newCidState == IDLE and recv == 3 (13 old DEPRECATING cleared).
 *         4. NewConnectionId(old CID D, SPARE) returns SUCCESS, recv == 4, and IsExpectedCid(D) true.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_TX_FUNC_TC027(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Pre-fill the server's recv list to 13 ACTIVE: client requests 12, server's recv cb grants 12. */
    TestCidReplyParam reply = {12, 0, 0xC0, HITLS_DTLS_CID_SPARE, HITLS_INTERNAL_EXCEPTION};
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(server->ssl, TestRecvRequestConnectionIdCb, &reply), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_RequestConnectionId(client->ssl, 12), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(DrainCidRecvCbExchange(server, client), HITLS_SUCCESS);
    ASSERT_EQ(reply.ret, HITLS_SUCCESS);
    ASSERT_EQ(reply.actual, 12);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    DTLS_CID_OnRequestConnectionIdAcked(client->ssl);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 13);
    }
    /* The ACK hook flipped newCidState but did NOT remove the 12-CID NewConnectionId from the
     * retransmit list. Clear the list here so the retransmit step below isolates call 1's NewCID
     * (a wire ACK round-trip would also remove the node, but HITLS_Read during ACK processing can
     * itself trigger a retransmit flush in the single-record FRAME outbox, causing IO_BUSY). */
    REC_RetransmitListClean(server->ssl->recCtx);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* (1) Call 1: IMMEDIATE, cidCount=16, truncated to accepted=3. The 13 old ACTIVE retire to
     *     DEPRECATING and ABC are committed ACTIVE -> 16 non-FREE (pre-ACK). */
    HITLS_DtlsCidEntry entries[HITLS_DTLS_CID_LIST_MAX] = {0};
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        FillGeneratedCid(&entries[i], 0xE0, i, server->ssl->negotiatedInfo.localCidEntry.cidLen);
    }
    uint8_t cidCount = HITLS_DTLS_CID_LIST_MAX;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, entries, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 3);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }

    /* Drive the send and deliver the original NewCID(ABC) so the server outbox is free for the
     * retransmit flush. */
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_SENT);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* (2) Timeout retransmit: REC_RetransmitListFlush re-emits NewCID(ABC) but does not re-run
     *     CommitRecvCids, so recv_list stays 16. Prove the retransmit actually emitted a record. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData->sndMsg.len == 0u);
    ASSERT_EQ(REC_RetransmitListFlush(server->ssl), HITLS_SUCCESS);
    ASSERT_TRUE(ioUserData->sndMsg.len > 0u);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, HITLS_DTLS_CID_LIST_MAX);
    }
    /* Drop the retransmitted record so it does not interfere with the rest of the test. */
    ioUserData->sndMsg.len = 0u;

    /* (3) ACK flips the state machine to IDLE and clears the 13 DEPRECATING slots -> recv 3 (ABC). */
    DTLS_CID_OnNewConnectionIdAcked(server->ssl);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 3);
    }

    /* (4) Re-advertise an old CID D (g_testCidB, one of the 13 just cleared) via SPARE. It is not a
     *     duplicate of ABC, so it is accepted as a fresh ACTIVE slot -> recv 4, and a record tagged D
     *     is matchable again. */
    HITLS_DtlsCidEntry oldEntry = {0};
    SetCidEntry(&oldEntry, g_testCidB, TEST_CID_B_LEN);
    cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, &oldEntry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(cidCount, 1);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_PENDING);
    {
        uint8_t recvCidCount = 0;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 4);
    }
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/*
 * Receiver-side NewConnectionId helpers.
 *
 * The real sender API cannot produce the malformed shapes the receiver must reject
 * (empty cid_immediate, unknown usage value), so a RecWrapper rewrites the outbound
 * NewConnectionId body on the send path before encryption -- the same technique the
 * negotiate suite uses to splice a connection_id extension into ServerHello.
 *
 * DTLS handshake message layout: [msg_type(1)][length(3)][msg_seq(2)][frag_off(3)][frag_len(3)][body].
 * The wrapper callback receives the whole message; it patches length/frag_len and rewrites the
 * 3-byte body [cidsLen_hi][cidsLen_lo][usage] pointed to by userData.
 */
static void CraftNewCidBody(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)bufSize;
    const uint8_t *body = (const uint8_t *)userData; /* [cidsLen_hi][cidsLen_lo][usage] */
    const uint32_t bodyLen = 3u;
    data[1] = 0u; data[2] = 0u; data[3] = (uint8_t)bodyLen;       /* length */
    data[9] = 0u; data[10] = 0u; data[11] = (uint8_t)bodyLen;     /* fragment_length */
    data[12] = body[0]; data[13] = body[1]; data[14] = body[2];   /* body */
    *len = 12u + bodyLen;
}

/* Drive the (tampered) server NewConnectionId into the client's receive path. The server sends a
 * valid 1-CID NewConnectionId; the already-registered wrapper rewrites its body to the crafted shape. */
static int32_t DeliverTamperedNewCid(FRAME_LinkObj *server, FRAME_LinkObj *client)
{
    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t cidCount = 1;
    int32_t ret = HITLS_NewConnectionId(server->ssl, &entry, &cidCount, HITLS_DTLS_CID_SPARE);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = (server->ssl->isClient) ? HITLS_Connect(server->ssl) : HITLS_Accept(server->ssl);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return FRAME_TrasferMsgBetweenLink(server, client);
}

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC001
 * @spec RFC 9147 section 9
 * @title Receive NewConnectionId(cidCount=0, cid_spare): no-op, connection stays, send_list unchanged
 * @precon nan
 * @brief An empty cid_spare NewConnectionId carries no CIDs. ParseNewConnectionId accepts it
 *        (usage <= 1, and the empty-list check only fires for cid_immediate); the receive process
 *        DTLS_CID_ProcessPeerNewConnectionId returns SUCCESS at the `cidsLen == 0` guard without
 *        touching the send slot table. So the connection stays TRANSPORTING and the send pool is
 *        unchanged. (The sender API cannot emit this shape -- it treats cidCount=0 SPARE as a no-op
 *        -- so a RecWrapper crafts the empty cid_spare body on the send path.)
 * @expect 1. HITLS_Read on the receiver returns HITLS_REC_NORMAL_RECV_BUF_EMPTY (no alert, no data).
 *         2. The receiver stays CM_STATE_TRANSPORTING.
 *         3. The send CID count is unchanged.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t sendCidBefore = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidBefore), HITLS_SUCCESS);

    uint8_t body[] = {0x00, 0x00, (uint8_t)HITLS_DTLS_CID_SPARE}; /* cidsLen=0, usage=cid_spare */
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, body, CraftNewCidBody};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    uint8_t sendCidAfter = 1;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidAfter), HITLS_SUCCESS);
    ASSERT_EQ(sendCidAfter, sendCidBefore);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC002
 * @spec RFC 9147 section 9
 * @title Receive NewConnectionId(cidCount=0, cid_immediate): reject with alert, connection torn down
 * @precon nan
 * @brief cid_immediate must retire the active outbound CID and replace it, so an empty cid_immediate
 *        would leave the peer with no usable CID. ParseNewConnectionId rejects this combination with
 *        ALERT_ILLEGAL_PARAMETER ("NewConnectionId immediate with empty CID list"). The receiver
 *        aborts and tears the connection down. (Sender API cannot emit this, so RecWrapper crafts it.)
 * @expect 1. HITLS_Read on the receiver fails.
 *         2. A fatal ALERT_ILLEGAL_PARAMETER is raised.
 *         3. The receiver enters CM_STATE_ALERTED.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t body[] = {0x00, 0x00, (uint8_t)HITLS_DTLS_CID_IMMEDIATE}; /* cidsLen=0, usage=cid_immediate */
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, body, CraftNewCidBody};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_NE(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC003
 * @spec RFC 9147 section 9
 * @title Receive NewConnectionId with an unknown usage value: reject with alert, connection torn down
 * @precon nan
 * @brief The ConnectionIdUsage wire field is a 1-byte enum with only cid_immediate(0)/cid_spare(1)
 *        defined. ParseNewConnectionId rejects usage > 1 with ALERT_ILLEGAL_PARAMETER ("invalid
 *        usage value") before any CID processing. The receiver aborts and tears the connection down.
 *        (Sender API cannot emit an unknown usage, so RecWrapper crafts usage = 2.)
 * @expect 1. HITLS_Read on the receiver fails.
 *         2. A fatal ALERT_ILLEGAL_PARAMETER is raised.
 *         3. The receiver enters CM_STATE_ALERTED.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t body[] = {0x00, 0x00, 0x02}; /* cidsLen=0, usage=2 (unknown) */
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, body, CraftNewCidBody};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_NE(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/*
 * Receiver send-list seeding helpers.
 *
 * The send_list (sendSlots) is built from received NewConnectionIds; to test a specific starting
 * state we materialize cidCtx (via the receiver's own NewConnectionId call, which runs
 * GetOrCreateCidCtx) and then overwrite sendSlots directly.
 */
static void SeedSendSlot(TLS_Ctx *ctx, uint8_t idx, uint8_t state, const uint8_t *cid, uint8_t cidLen)
{
    DTLS_CidSendSlot *slot = &ctx->negotiatedInfo.cidCtx->sendSlots[idx];
    (void)memset(slot, 0, sizeof(*slot));
    slot->state = state;
    slot->entry.cidLen = cidLen;
    if (cidLen > 0) {
        (void)memcpy(slot->entry.cidVal, cid, cidLen);
    }
}

/* Reset the send table to all-FREE (no INUSE); caller re-seeds and restores currentSendIdx/peerCidEntry. */
static void ResetSendTable(TLS_Ctx *ctx)
{
    DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    (void)memset(cidCtx->sendSlots, 0, sizeof(cidCtx->sendSlots));
    cidCtx->currentSendIdx = HITLS_DTLS_CID_NO_IDX;
    (void)memset(&ctx->negotiatedInfo.peerCidEntry, 0, sizeof(ctx->negotiatedInfo.peerCidEntry));
}

/* True if any non-FREE send slot currently holds cid. */
static bool SendListHasCid(const TLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    const DTLS_CidSendSlot *slots = ctx->negotiatedInfo.cidCtx->sendSlots;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (slots[i].state != DTLS_CID_SEND_SLOT_FREE && slots[i].entry.cidLen == cidLen &&
            memcmp(slots[i].entry.cidVal, cid, cidLen) == 0) {
            return true;
        }
    }
    return false;
}

/* Materialize the receiver's cidCtx by invoking its own NewConnectionId (which runs GetOrCreateCidCtx),
 * then leave newCidState at IDLE so it does not interfere with the rest of the test. */
static void MaterializeRxCidCtx(HITLS_Ctx *ctx)
{
    HITLS_DtlsCidEntry e = {0};
    SetCidEntry(&e, g_testNewCid, TEST_NEW_CID_LEN);
    uint8_t n = 1;
    (void)HITLS_NewConnectionId(ctx, &e, &n, HITLS_DTLS_CID_SPARE);
    ctx->newCidState = DTLS_CID_MSG_STATE_IDLE;
}

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC004
 * @spec RFC 9147 section 9
 * @title SPARE NewConnectionId eviction order: FREE > USED > UNUSED, INUSE never evicted
 * @precon nan
 * @brief DtlsCidProcessSpare places each incoming SPARE CID into the lowest-index slot of the best
 *        eviction category, where the DTLS_CidSendSlotState value IS the preference rank:
 *        FREE(0) > USED(1) > UNUSED(2); INUSE(3) is skipped. Seed the receiver's send table with
 *        slot0=INUSE, slot1=UNUSED(low index), slot2=USED, slot3=FREE, slot4..15=UNUSED, then receive
 *        one NewConnectionId carrying X,Y,Z (cid_spare). X takes the FREE slot; Y evicts the USED
 *        slot (preferred over UNUSED); Z evicts the lowest-index UNUSED (slot1). The INUSE active
 *        outbound CID is never touched.
 * @expect 1. X, Y, Z are all in the send list; the evicted USED CID and the evicted UNUSED CID are gone.
 *         2. The INUSE CID (g_testCidB) is still INUSE and is the active outbound (peerCidEntry).
 *         3. 16 non-FREE slots total.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Materialize the client's cidCtx, then seed a controlled send table:
     *   slot0 = INUSE (g_testCidB), slot1 = UNUSED (cidU1, low index), slot2 = USED (cidE),
     *   slot3 = FREE, slot4..15 = UNUSED (cidU2..cidU13). */
    MaterializeRxCidCtx(client->ssl);
    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ResetSendTable(client->ssl);
    uint8_t cidE[4] = {0x0E, 0x0E, 0x0E, 0x0E};
    uint8_t cidU1[4] = {0x01, 0x01, 0x01, 0x01};
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_INUSE, g_testCidB, TEST_CID_B_LEN);
    cidCtx->currentSendIdx = 0;
    client->ssl->negotiatedInfo.peerCidEntry = cidCtx->sendSlots[0].entry;
    SeedSendSlot(client->ssl, 1, DTLS_CID_SEND_SLOT_UNUSED, cidU1, sizeof(cidU1));
    SeedSendSlot(client->ssl, 2, DTLS_CID_SEND_SLOT_USED, cidE, sizeof(cidE));
    SeedSendSlot(client->ssl, 3, DTLS_CID_SEND_SLOT_FREE, NULL, 0);
    for (uint8_t i = 0; i < 12; i++) {
        HITLS_DtlsCidEntry e = {0};
        FillGeneratedCid(&e, 0x10, i, TEST_CID_B_LEN);
        SeedSendSlot(client->ssl, (uint8_t)(4u + i), DTLS_CID_SEND_SLOT_UNUSED, e.cidVal, e.cidLen);
    }

    /* Server sends one NewConnectionId(SPARE) carrying X, Y, Z. */
    HITLS_DtlsCidEntry batch[3] = {0};
    FillGeneratedCid(&batch[0], 0xA0, 0, TEST_CID_B_LEN); /* X */
    FillGeneratedCid(&batch[1], 0xA0, 1, TEST_CID_B_LEN); /* Y */
    FillGeneratedCid(&batch[2], 0xA0, 2, TEST_CID_B_LEN); /* Z */
    uint8_t cidCount = 3;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, batch, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* X took the FREE slot, Y evicted the USED cidE, Z evicted the lowest-index UNUSED (cidU1). */
    ASSERT_TRUE(SendListHasCid(client->ssl, batch[0].cidVal, TEST_CID_B_LEN)); /* X present */
    ASSERT_TRUE(SendListHasCid(client->ssl, batch[1].cidVal, TEST_CID_B_LEN)); /* Y present */
    ASSERT_TRUE(SendListHasCid(client->ssl, batch[2].cidVal, TEST_CID_B_LEN)); /* Z present */
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidE, sizeof(cidE)));             /* cidE evicted */
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidU1, sizeof(cidU1)));           /* cidU1 evicted */
    /* INUSE active outbound untouched. */
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(cidCtx->currentSendIdx, 0u);
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(client->ssl->negotiatedInfo.peerCidEntry.cidVal, g_testCidB, TEST_CID_B_LEN), 0);
    /* All 16 slots are now non-FREE. */
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, HITLS_DTLS_CID_LIST_MAX);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC005
 * @spec RFC 9147 section 9
 * @title IMMEDIATE NewConnectionId wipes the send list and refills: A(INUSE) B C D(UNUSED)
 * @precon nan
 * @brief DtlsCidProcessImmediate clears peerCidEntry, memsets the whole sendSlots table, then writes
 *        each incoming CID into the lowest slots: slot0 becomes INUSE (the new active outbound CID,
 *        mirrored into peerCidEntry), the rest become UNUSED. Seed the receiver send table with 1
 *        INUSE + 14 UNUSED, then receive one NewConnectionId(IMMEDIATE) carrying A,B,C,D. The 15
 *        historical CIDs all vanish; A becomes the active outbound and B,C,D are UNUSED spares.
 * @expect 1. A is in slot0 as INUSE and is the active outbound (peerCidEntry == A).
 *         2. B, C, D occupy slots 1..3 as UNUSED; slots 4..15 are FREE.
 *         3. The previously-INUSE g_testCidB and all seeded UNUSED CIDs are gone.
 *         4. send CID count == 4.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Seed the client send table with 1 INUSE (g_testCidB) + 14 UNUSED (generated). */
    MaterializeRxCidCtx(client->ssl);
    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ResetSendTable(client->ssl);
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_INUSE, g_testCidB, TEST_CID_B_LEN);
    cidCtx->currentSendIdx = 0;
    client->ssl->negotiatedInfo.peerCidEntry = cidCtx->sendSlots[0].entry;
    for (uint8_t i = 1; i < 15; i++) {
        HITLS_DtlsCidEntry e = {0};
        FillGeneratedCid(&e, 0x20, i, TEST_CID_B_LEN);
        SeedSendSlot(client->ssl, i, DTLS_CID_SEND_SLOT_UNUSED, e.cidVal, e.cidLen);
    }

    /* Server sends one NewConnectionId(IMMEDIATE) carrying A,B,C,D. */
    HITLS_DtlsCidEntry batch[4] = {0};
    FillGeneratedCid(&batch[0], 0xB0, 0, TEST_CID_B_LEN); /* A */
    FillGeneratedCid(&batch[1], 0xB0, 1, TEST_CID_B_LEN); /* B */
    FillGeneratedCid(&batch[2], 0xB0, 2, TEST_CID_B_LEN); /* C */
    FillGeneratedCid(&batch[3], 0xB0, 3, TEST_CID_B_LEN); /* D */
    uint8_t cidCount = 4;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, batch, &cidCount, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* A is the new active outbound (INUSE, slot0, peerCidEntry); B,C,D are UNUSED spares. */
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(cidCtx->sendSlots[0].entry.cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[0].entry.cidVal, batch[0].cidVal, TEST_CID_B_LEN), 0);
    ASSERT_EQ(cidCtx->currentSendIdx, 0u);
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(client->ssl->negotiatedInfo.peerCidEntry.cidVal, batch[0].cidVal, TEST_CID_B_LEN), 0);
    for (uint8_t i = 1; i <= 3; i++) {
        ASSERT_EQ(cidCtx->sendSlots[i].state, DTLS_CID_SEND_SLOT_UNUSED);
        ASSERT_EQ(memcmp(cidCtx->sendSlots[i].entry.cidVal, batch[i].cidVal, TEST_CID_B_LEN), 0);
    }
    for (uint8_t i = 4; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        ASSERT_EQ(cidCtx->sendSlots[i].state, DTLS_CID_SEND_SLOT_FREE);
    }
    /* History wiped: g_testCidB and the seeded UNUSED CIDs are all gone. */
    ASSERT_TRUE(!SendListHasCid(client->ssl, g_testCidB, TEST_CID_B_LEN));
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 4);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* Generalized NewCID body crafter: builds [cidsLen(2)][cid entries: len+bytes...][usage(1)] from a
 * uniform-length CID list. Used for receiver cases the real sender cannot produce (batches > 16,
 * non-matching / max-length CIDs). */
typedef struct {
    uint8_t usage;
    uint8_t count;
    uint8_t cidLen;
    const uint8_t *cidBytes; /* count * cidLen bytes */
} CraftedNewCid;

static void CraftNewCidBodyMulti(TLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)bufSize;
    const CraftedNewCid *c = (const CraftedNewCid *)userData;
    uint32_t off = 12u; /* body follows the 12-byte DTLS handshake header */
    uint16_t cidsLen = (uint16_t)((uint32_t)c->count * (uint32_t)(c->cidLen + 1u));
    data[off++] = (uint8_t)(cidsLen >> 8);
    data[off++] = (uint8_t)(cidsLen & 0xFF);
    for (uint8_t i = 0; i < c->count; i++) {
        data[off++] = c->cidLen;
        (void)memcpy(&data[off], &c->cidBytes[(uint32_t)i * c->cidLen], c->cidLen);
        off += c->cidLen;
    }
    data[off++] = c->usage;
    uint32_t bodyLen = off - 12u;
    data[1] = (uint8_t)(bodyLen >> 16); data[2] = (uint8_t)(bodyLen >> 8); data[3] = (uint8_t)bodyLen;
    data[9] = (uint8_t)(bodyLen >> 16); data[10] = (uint8_t)(bodyLen >> 8); data[11] = (uint8_t)bodyLen;
    *len = off;
}

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC006
 * @spec RFC 9147 section 9
 * @title IMMEDIATE NewConnectionId with 17 CIDs: first 16 stored, 17th silently discarded
 * @precon nan
 * @brief DtlsCidProcessImmediate wipes the send table, then writes each incoming CID into slots
 *        0..N while processed < HITLS_DTLS_CID_LIST_MAX; processed keeps counting past the cap, so a
 *        17th CID is parsed but not stored (silently discarded). slot0 becomes INUSE (the active
 *        outbound), slots 1..15 UNUSED. (The real sender caps a batch at 16 length-matched CIDs, so
 *        a 17-CID IMMEDIATE body is crafted via RecWrapper.)
 * @expect 1. slot0 = cid0 (INUSE, active outbound); slots 1..15 = cid1..cid15 (UNUSED).
 *         2. The 17th CID is not in the send list (discarded).
 *         3. send CID count == 16.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* 17 distinct 4-byte CIDs; the wrapper crafts an IMMEDIATE NewConnectionId carrying all 17. */
    uint8_t cidBytes[17 * TEST_CID_B_LEN];
    for (uint8_t i = 0; i < 17; i++) {
        for (uint8_t b = 0; b < TEST_CID_B_LEN; b++) {
            cidBytes[(uint32_t)i * TEST_CID_B_LEN + b] = (uint8_t)(0x30u + i * 17u + b);
        }
    }
    CraftedNewCid crafted = {(uint8_t)HITLS_DTLS_CID_IMMEDIATE, 17, TEST_CID_B_LEN, cidBytes};
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, &crafted, CraftNewCidBodyMulti};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    /* slot0 = cid0 INUSE (active outbound); slots 1..15 = cid1..cid15 UNUSED. */
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(cidCtx->currentSendIdx, 0u);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[0].entry.cidVal, &cidBytes[0], TEST_CID_B_LEN), 0);
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(client->ssl->negotiatedInfo.peerCidEntry.cidVal, &cidBytes[0], TEST_CID_B_LEN), 0);
    for (uint8_t i = 1; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        ASSERT_EQ(cidCtx->sendSlots[i].state, DTLS_CID_SEND_SLOT_UNUSED);
        ASSERT_EQ(memcmp(cidCtx->sendSlots[i].entry.cidVal, &cidBytes[(uint32_t)i * TEST_CID_B_LEN],
                         TEST_CID_B_LEN), 0);
    }
    /* The 17th CID (index 16) is discarded. */
    ASSERT_TRUE(!SendListHasCid(client->ssl, &cidBytes[16u * TEST_CID_B_LEN], TEST_CID_B_LEN));
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, HITLS_DTLS_CID_LIST_MAX);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC007
 * @spec RFC 9147 section 9
 * @title Receive a max-length (254-byte) CID via IMMEDIATE NewConnectionId
 * @precon nan
 * @brief The ConnectionId wire field is opaque<0..2^8-1>; a 254-byte CID is near the 255-byte cap.
 *        The send entry (DTLS_CidSendEntry = HITLS_DtlsCidEntry.cidVal[HITLS_DTLS_CID_LEN_MAX=255]) can
 *        hold it, while the 32-byte local recv slot cannot -- so this shape is only reachable on the
 *        receive side and is crafted via RecWrapper. DtlsCidProcessImmediate wipes the table and
 *        writes the 254-byte CID into slot0 as INUSE (the active outbound), mirrored into peerCidEntry.
 * @expect 1. slot0 holds the 254-byte CID as INUSE; peerCidEntry.cidLen == 254 and matches.
 *         2. send CID count == 1; the connection stays TRANSPORTING.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t cid254[254];
    for (uint16_t i = 0; i < 254u; i++) {
        cid254[i] = (uint8_t)i;
    }
    CraftedNewCid crafted = {(uint8_t)HITLS_DTLS_CID_IMMEDIATE, 1u, (uint8_t)sizeof(cid254), cid254};
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, &crafted, CraftNewCidBodyMulti};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(cidCtx->sendSlots[0].entry.cidLen, (uint8_t)sizeof(cid254));
    ASSERT_EQ(memcmp(cidCtx->sendSlots[0].entry.cidVal, cid254, sizeof(cid254)), 0);
    ASSERT_EQ(cidCtx->currentSendIdx, 0u);
    ASSERT_EQ(client->ssl->negotiatedInfo.peerCidEntry.cidLen, (uint8_t)sizeof(cid254));
    ASSERT_EQ(memcmp(client->ssl->negotiatedInfo.peerCidEntry.cidVal, cid254, sizeof(cid254)), 0);
    uint8_t sendCidCount = 99u;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 1u);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC008
 * @spec RFC 9147 section 9
 * @title SPARE NewConnectionId batch cap: 17 CIDs -> 16 stored, 17th silently discarded
 * @precon nan
 * @brief DtlsCidProcessSpare stores at most HITLS_DTLS_CID_LIST_MAX new (non-duplicate) CIDs per
 *        batch (`if (processed >= LIST_MAX) break;`). Seed the send table all-FREE so each incoming
 *        CID simply takes the next FREE slot (no eviction entanglement), then receive one
 *        NewConnectionId(cid_spare) carrying 17 distinct CIDs. The first 16 fill slots 0..15; the
 *        17th is discarded.
 * @expect 1. CIDs 0..15 are present; CID 16 (the 17th) is absent.
 *         2. send CID count == 16.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    MaterializeRxCidCtx(client->ssl);
    ResetSendTable(client->ssl); /* all 16 slots FREE: isolate the per-batch cap from eviction */
    /* Restore a non-empty peerCidEntry so the RFC 9147 §9 receiver guard does not reject the
     * incoming NewConnectionId as "peer negotiated an empty CID" (which would raise
     * unexpected_message before the cap is exercised). */
    client->ssl->negotiatedInfo.peerCidEntry.cidLen = TEST_CID_B_LEN;
    (void)memcpy(client->ssl->negotiatedInfo.peerCidEntry.cidVal, g_testCidB, TEST_CID_B_LEN);

    uint8_t cidBytes[17 * TEST_CID_B_LEN];
    for (uint8_t i = 0; i < 17u; i++) {
        for (uint8_t b = 0; b < TEST_CID_B_LEN; b++) {
            cidBytes[(uint32_t)i * TEST_CID_B_LEN + b] = (uint8_t)(0x40u + i * 17u + b);
        }
    }
    CraftedNewCid crafted = {(uint8_t)HITLS_DTLS_CID_SPARE, 17u, TEST_CID_B_LEN, cidBytes};
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, &crafted, CraftNewCidBodyMulti};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        ASSERT_TRUE(SendListHasCid(client->ssl, &cidBytes[(uint32_t)i * TEST_CID_B_LEN], TEST_CID_B_LEN));
    }
    ASSERT_TRUE(!SendListHasCid(client->ssl, &cidBytes[16u * TEST_CID_B_LEN], TEST_CID_B_LEN));
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, HITLS_DTLS_CID_LIST_MAX);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC009
 * @spec RFC 9147 section 9
 * @title SPARE NewConnectionId de-dup: a CID already in the send list is skipped, not re-counted
 * @precon nan
 * @brief DtlsCidProcessSpare checks each incoming CID against the current send list and `continue`s
 *        on a match without consuming a slot or incrementing the per-batch processed counter. Seed
 *        one UNUSED CID (cidDup), then receive one NewConnectionId(cid_spare) carrying [cidDup,
 *        cidNew]. cidDup is de-duped (skipped); only cidNew is stored.
 * @expect 1. cidDup is still present (once) and cidNew is present.
 *         2. send CID count == 2 (the duplicate did not add a slot).
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC009(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    MaterializeRxCidCtx(client->ssl);
    ResetSendTable(client->ssl);
    /* Restore a non-empty peerCidEntry so the RFC 9147 §9 receiver guard does not reject the
     * incoming NewConnectionId as "peer negotiated an empty CID". */
    client->ssl->negotiatedInfo.peerCidEntry.cidLen = TEST_CID_B_LEN;
    (void)memcpy(client->ssl->negotiatedInfo.peerCidEntry.cidVal, g_testCidB, TEST_CID_B_LEN);
    uint8_t cidDup[4] = {0x09, 0x09, 0x09, 0x09};
    uint8_t cidNew[4] = {0x0A, 0x0A, 0x0A, 0x0A};
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_UNUSED, cidDup, sizeof(cidDup));

    uint8_t batch[2 * 4];
    (void)memcpy(batch, cidDup, sizeof(cidDup));
    (void)memcpy(&batch[4], cidNew, sizeof(cidNew));
    CraftedNewCid crafted = {(uint8_t)HITLS_DTLS_CID_SPARE, 2u, (uint8_t)sizeof(cidDup), batch};
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, &crafted, CraftNewCidBodyMulti};
    RegisterWrapper(wrapper);

    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(SendListHasCid(client->ssl, cidDup, sizeof(cidDup)));
    ASSERT_TRUE(SendListHasCid(client->ssl, cidNew, sizeof(cidNew)));
    uint8_t sendCidCount = 99u;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 2u);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC010
 * @spec RFC 9147 section 9
 * @title After an IMMEDIATE replacement, a later SPARE NewConnectionId appends to the new send list
 * @precon nan
 * @brief Seed the post-IMMEDIATE send-list state directly (A=INUSE active outbound, B/C/D=UNUSED
 *        spares, slots 4..15 FREE), then receive a normal SPARE NewConnectionId carrying one fresh
 *        CID E. SPARE does not retire anything: E is appended into a FREE slot as UNUSED, A stays
 *        INUSE, and B/C/D are untouched. This mirrors the "receive D as cid_spare after cid_immediate"
 *        tail of the IMMEDIATE scenario.
 * @expect 1. A is still INUSE (active outbound); B/C/D still UNUSED.
 *         2. E is present (UNUSED); send CID count == 5.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_NEW_CONNECTION_ID_RX_FUNC_TC010(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Seed the post-IMMEDIATE state: slot0=A(INUSE), slot1..3=B,C,D(UNUSED). */
    MaterializeRxCidCtx(client->ssl);
    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ResetSendTable(client->ssl);
    uint8_t cidA[4] = {0xA1, 0xA2, 0xA3, 0xA4};
    uint8_t cidB[4] = {0xB1, 0xB2, 0xB3, 0xB4};
    uint8_t cidC[4] = {0xC1, 0xC2, 0xC3, 0xC4};
    uint8_t cidD[4] = {0xD1, 0xD2, 0xD3, 0xD4};
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_INUSE, cidA, sizeof(cidA));
    cidCtx->currentSendIdx = 0;
    client->ssl->negotiatedInfo.peerCidEntry = cidCtx->sendSlots[0].entry;
    SeedSendSlot(client->ssl, 1, DTLS_CID_SEND_SLOT_UNUSED, cidB, sizeof(cidB));
    SeedSendSlot(client->ssl, 2, DTLS_CID_SEND_SLOT_UNUSED, cidC, sizeof(cidC));
    SeedSendSlot(client->ssl, 3, DTLS_CID_SEND_SLOT_UNUSED, cidD, sizeof(cidD));

    /* Server sends a real SPARE NewConnectionId carrying one fresh CID E. */
    uint8_t cidE[4] = {0xE1, 0xE2, 0xE3, 0xE4};
    HITLS_DtlsCidEntry entry = {0};
    SetCidEntry(&entry, cidE, sizeof(cidE));
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, &entry, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* A still INUSE (active outbound); B/C/D untouched; E appended as UNUSED. */
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[0].entry.cidVal, cidA, sizeof(cidA)), 0);
    ASSERT_EQ(cidCtx->sendSlots[1].state, DTLS_CID_SEND_SLOT_UNUSED);
    ASSERT_EQ(cidCtx->sendSlots[2].state, DTLS_CID_SEND_SLOT_UNUSED);
    ASSERT_EQ(cidCtx->sendSlots[3].state, DTLS_CID_SEND_SLOT_UNUSED);
    ASSERT_TRUE(SendListHasCid(client->ssl, cidE, sizeof(cidE)));
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 5u);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* True if the current INUSE send slot (and peerCidEntry, which mirrors it) equals cid. */
static bool CurrentSendIs(const TLS_Ctx *ctx, const uint8_t *cid, uint8_t cidLen)
{
    const DTLS_CidCtx *cidCtx = ctx->negotiatedInfo.cidCtx;
    if (cidCtx == NULL || cidCtx->currentSendIdx >= HITLS_DTLS_CID_LIST_MAX) {
        return false;
    }
    const DTLS_CidSendSlot *slot = &cidCtx->sendSlots[cidCtx->currentSendIdx];
    if (slot->state != DTLS_CID_SEND_SLOT_INUSE || slot->entry.cidLen != cidLen) {
        return false;
    }
    if (cidLen > 0 && memcmp(slot->entry.cidVal, cid, cidLen) != 0) {
        return false;
    }
    if (ctx->negotiatedInfo.peerCidEntry.cidLen != cidLen) {
        return false;
    }
    if (cidLen > 0 && memcmp(ctx->negotiatedInfo.peerCidEntry.cidVal, cid, cidLen) != 0) {
        return false;
    }
    return true;
}

static uint8_t CountSendSlotsInState(const TLS_Ctx *ctx, uint8_t state)
{
    uint8_t count = 0;
    const DTLS_CidSendSlot *slots = ctx->negotiatedInfo.cidCtx->sendSlots;
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        if (slots[i].state == state) {
            count++;
        }
    }
    return count;
}

/* Send one valid NewConnectionId, but replace its body on the encrypted send path with crafted.
 * The trigger CID is committed to the sender's recv list, which lets a later receiver ACK use a
 * SwitchSendCid-selected value that the sender actually recognizes. The caller drains that ACK
 * when another crafted message must follow. */
static int32_t ReceiveCraftedNewCid(FRAME_LinkObj *sender, FRAME_LinkObj *receiver,
    const HITLS_DtlsCidEntry *trigger, const CraftedNewCid *crafted)
{
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false,
        (void *)crafted, CraftNewCidBodyMulti};
    RegisterWrapper(wrapper);

    uint8_t cidCount = 1;
    int32_t ret = HITLS_NewConnectionId(sender->ssl, trigger, &cidCount, HITLS_DTLS_CID_SPARE);
    if (ret == HITLS_SUCCESS) {
        ret = sender->ssl->isClient ? HITLS_Connect(sender->ssl) : HITLS_Accept(sender->ssl);
    }
    if (ret == HITLS_SUCCESS) {
        ret = FRAME_TrasferMsgBetweenLink(sender, receiver);
    }
    ClearWrapper();
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return ReadPostHandshake(receiver);
}

/**
 * @test SDV_TLS_DTLS13_CID_SWITCH_SEND_CID_FUNC_TC001
 * @spec RFC 9147 section 9
 * @title HITLS_SwitchSendCid: input validation, auto-pick, explicit switch, and exhaustion
 * @precon nan
 * @brief Drive HITLS_SwitchSendCid through a cumulative sequence on a seeded send table holding
 *        A(1B, INUSE), B(255B, UNUSED), C(255B, UNUSED). Covers:
 *          (1,3) cid=NULL paired with a non-zero cidLen is rejected (self-consistent pointer/length
 *                contract -- cid=NULL must pair with cidLen=0);
 *          (2)   cid=NULL + cidLen=0 auto-picks the lowest-index UNUSED slot (B);
 *          (4)   explicit cid=C switches to C;
 *          (5)   explicit cid=A with a mismatched cidLen (5) or 0 is rejected;
 *          (6)   explicit cid=A with cidLen=1 switches to A (recycling the USED slot);
 *          (7)   switching to the already-INUSE A is a no-op success;
 *          (8)   auto-pick fails once no UNUSED slot remains;
 *          (9)   after a fresh SPARE NewConnectionId(D, 254B) replenishes an UNUSED slot, auto-pick
 *                selects D.
 *        Each switch marks the previous INUSE slot USED and mirrors the new INUSE into peerCidEntry.
 * @expect Each step's return value and the resulting INUSE CID match the design (see inline asserts).
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_SWITCH_SEND_CID_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Seed: slot0 = A(1B, INUSE), slot1 = B(255B, UNUSED), slot2 = C(255B, UNUSED). */
    MaterializeRxCidCtx(client->ssl);
    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ResetSendTable(client->ssl);
    uint8_t cidA[1] = {0xA1};
    uint8_t cidB[255];
    uint8_t cidC[255];
    uint8_t cidD[254];
    for (uint16_t i = 0; i < 255u; i++) {
        cidB[i] = (uint8_t)i;
        cidC[i] = (uint8_t)(255u - i);
    }
    for (uint16_t i = 0; i < 254u; i++) {
        cidD[i] = (uint8_t)(0x80u + i);
    }
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_INUSE, cidA, sizeof(cidA));
    cidCtx->currentSendIdx = 0;
    client->ssl->negotiatedInfo.peerCidEntry = cidCtx->sendSlots[0].entry;
    SeedSendSlot(client->ssl, 1, DTLS_CID_SEND_SLOT_UNUSED, cidB, sizeof(cidB));
    SeedSendSlot(client->ssl, 2, DTLS_CID_SEND_SLOT_UNUSED, cidC, sizeof(cidC));
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));

    /* (1) cid=NULL + cidLen=255: inconsistent pair -> rejected. A stays INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 255u), HITLS_NULL_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));

    /* (2) cid=NULL + cidLen=0: auto-pick the lowest-index UNUSED (B). */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0u), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));

    /* (3) cid=NULL + cidLen=8: inconsistent pair -> rejected. B stays INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 8u), HITLS_NULL_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));

    /* (4) explicit cid=C(255) -> switch to C. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidC, sizeof(cidC)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidC, sizeof(cidC)));

    /* (5a) explicit cid=A with cidLen=5 (A is 1 byte) -> no match -> INVALID_INPUT; C stays INUSE.
     * (5b) explicit cid=A with cidLen=0 -> inconsistent pair -> NULL_INPUT; C stays INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, 5u), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, 0u), HITLS_NULL_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidC, sizeof(cidC)));

    /* (6) explicit cid=A(1) -> recycle the USED slot A; A becomes INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, sizeof(cidA)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));

    /* (7) switch to the already-INUSE A again -> success, A still INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, sizeof(cidA)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));

    /* (8) auto-pick with no UNUSED slot left (A INUSE, B/C USED) -> INVALID_INPUT; A stays INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0u), HITLS_INVALID_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));

    /* (9) receive a fresh SPARE NewConnectionId(D, 254B) -> D takes a USED slot as UNUSED, then
     *     auto-pick selects D. */
    CraftedNewCid crafted = {(uint8_t)HITLS_DTLS_CID_SPARE, 1u, (uint8_t)sizeof(cidD), cidD};
    RecWrapper wrapper = {TRY_SEND_NEW_CONNECTION_ID, REC_TYPE_HANDSHAKE, false, &crafted, CraftNewCidBodyMulti};
    RegisterWrapper(wrapper);
    ASSERT_EQ(DeliverTamperedNewCid(server, client), HITLS_SUCCESS);
    ClearWrapper();
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0u), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidD, sizeof(cidD)));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_SWITCH_SEND_CID_FUNC_TC002
 * @spec RFC 9147 section 9
 * @title SwitchSendCid across SPARE eviction and an IMMEDIATE max-length replacement
 * @precon nan
 * @brief Seed a full send list with 12 UNUSED CIDs, one INUSE CID, E/F as USED, and one FREE slot.
 *        Receive SPARE [A,B,C,D], exercise explicit and automatic switching, then receive another
 *        16-CID SPARE batch before replacing the complete history with one 254-byte IMMEDIATE CID.
 *        The scenario verifies that SPARE placement follows FREE > USED > UNUSED while preserving
 *        INUSE, that explicit switching may recycle a USED CID, and that IMMEDIATE leaves only its
 *        first CID INUSE.
 * @expect 1. SPARE [A,B,C,D] replaces FREE, E, F, and one old UNUSED slot: A-D are UNUSED,
 *            11 old UNUSED CIDs remain, and the original active CID stays INUSE.
 *         2. Explicit B succeeds; automatic switching succeeds and retires B; missing F fails;
 *            switching to the current CID is a no-op success; explicit B can be recycled to INUSE.
 *         3. The 16-CID SPARE batch leaves B INUSE and the first 15 batch CIDs UNUSED. Because B is
 *            protected, A/C/D are evicted and the 16th batch CID is silently discarded.
 *         4. Explicit A then fails without changing B.
 *         5. IMMEDIATE E(254 bytes) wipes the history and leaves only E INUSE; automatic switching
 *            fails because no UNUSED slot exists, while explicit switching to E succeeds.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_SWITCH_SEND_CID_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    MaterializeRxCidCtx(client->ssl);
    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ResetSendTable(client->ssl);

    uint8_t cidE[TEST_CID_B_LEN] = {0xE1, 0xE2, 0xE3, 0xE4};
    uint8_t cidF[TEST_CID_B_LEN] = {0xF1, 0xF2, 0xF3, 0xF4};
    uint8_t oldUnused[12][TEST_CID_B_LEN] = {0};
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_INUSE, g_testCidB, TEST_CID_B_LEN);
    cidCtx->currentSendIdx = 0;
    client->ssl->negotiatedInfo.peerCidEntry = cidCtx->sendSlots[0].entry;
    for (uint8_t i = 0; i < 12u; i++) {
        for (uint8_t b = 0; b < TEST_CID_B_LEN; b++) {
            oldUnused[i][b] = (uint8_t)(0x10u + i * 13u + b);
        }
        SeedSendSlot(client->ssl, (uint8_t)(i + 1u), DTLS_CID_SEND_SLOT_UNUSED,
            oldUnused[i], TEST_CID_B_LEN);
    }
    SeedSendSlot(client->ssl, 13, DTLS_CID_SEND_SLOT_USED, cidE, sizeof(cidE));
    SeedSendSlot(client->ssl, 14, DTLS_CID_SEND_SLOT_USED, cidF, sizeof(cidF));
    SeedSendSlot(client->ssl, 15, DTLS_CID_SEND_SLOT_FREE, NULL, 0);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_UNUSED), 12u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_INUSE), 1u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_USED), 2u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_FREE), 1u);

    /* Receive SPARE [A,B,C,D]. A takes FREE, B/C replace E/F, and D replaces the lowest-index
     * UNUSED slot. Commit B as the sender's real trigger CID so later ACK records sent with B are
     * accepted after SwitchSendCid selects it. */
    uint8_t cidA[TEST_CID_B_LEN] = {0xA1, 0xA2, 0xA3, 0xA4};
    uint8_t cidB[TEST_CID_B_LEN] = {0xB1, 0xB2, 0xB3, 0xB4};
    uint8_t cidC[TEST_CID_B_LEN] = {0xC1, 0xC2, 0xC3, 0xC4};
    uint8_t cidD[TEST_CID_B_LEN] = {0xD1, 0xD2, 0xD3, 0xD4};
    uint8_t spareAbcd[4 * TEST_CID_B_LEN] = {0};
    (void)memcpy(&spareAbcd[0 * TEST_CID_B_LEN], cidA, TEST_CID_B_LEN);
    (void)memcpy(&spareAbcd[1 * TEST_CID_B_LEN], cidB, TEST_CID_B_LEN);
    (void)memcpy(&spareAbcd[2 * TEST_CID_B_LEN], cidC, TEST_CID_B_LEN);
    (void)memcpy(&spareAbcd[3 * TEST_CID_B_LEN], cidD, TEST_CID_B_LEN);
    CraftedNewCid firstSpare = {(uint8_t)HITLS_DTLS_CID_SPARE, 4u, TEST_CID_B_LEN, spareAbcd};
    HITLS_DtlsCidEntry triggerB = {0};
    SetCidEntry(&triggerB, cidB, sizeof(cidB));
    ASSERT_EQ(ReceiveCraftedNewCid(server, client, &triggerB, &firstSpare),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(SendListHasCid(client->ssl, cidA, sizeof(cidA)));
    ASSERT_TRUE(SendListHasCid(client->ssl, cidB, sizeof(cidB)));
    ASSERT_TRUE(SendListHasCid(client->ssl, cidC, sizeof(cidC)));
    ASSERT_TRUE(SendListHasCid(client->ssl, cidD, sizeof(cidD)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidE, sizeof(cidE)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidF, sizeof(cidF)));
    ASSERT_TRUE(CurrentSendIs(client->ssl, g_testCidB, TEST_CID_B_LEN));
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_UNUSED), 15u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_INUSE), 1u);

    /* Drain the first NewConnectionId ACK before arming the next crafted send. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* Explicit B, then automatic selection. Slot1 is D, the lowest-index UNUSED, so auto-pick
     * selects D and marks B USED. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidB, sizeof(cidB)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0u), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidD, sizeof(cidD)));
    ASSERT_EQ(cidCtx->sendSlots[13].state, DTLS_CID_SEND_SLOT_USED); /* B */

    /* F was evicted by C: explicit F fails and D stays active. Switching to current D is a
     * no-op success; a later explicit B recycles its USED slot back to INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidF, sizeof(cidF)), HITLS_INVALID_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidD, sizeof(cidD)));
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidD, sizeof(cidD)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidD, sizeof(cidD)));
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidB, sizeof(cidB)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));

    /* Receive 16 distinct SPARE CIDs. Only 15 slots are evictable because B is INUSE: batch[0..14]
     * must occupy each non-INUSE slot once and batch[15] must be silently discarded. */
    uint8_t spare16[HITLS_DTLS_CID_LIST_MAX * TEST_CID_B_LEN] = {0};
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        for (uint8_t b = 0; b < TEST_CID_B_LEN; b++) {
            spare16[(uint32_t)i * TEST_CID_B_LEN + b] = (uint8_t)(0x40u + i);
        }
    }
    CraftedNewCid secondSpare = {(uint8_t)HITLS_DTLS_CID_SPARE, HITLS_DTLS_CID_LIST_MAX,
        TEST_CID_B_LEN, spare16};
    HITLS_DtlsCidEntry trigger2 = {0};
    FillGeneratedCid(&trigger2, 0x72, 0, TEST_CID_B_LEN);
    ASSERT_EQ(ReceiveCraftedNewCid(server, client, &trigger2, &secondSpare),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_UNUSED), 15u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_INUSE), 1u);
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX - 1u; i++) {
        ASSERT_TRUE(SendListHasCid(client->ssl, &spare16[(uint32_t)i * TEST_CID_B_LEN], TEST_CID_B_LEN));
    }
    ASSERT_TRUE(!SendListHasCid(client->ssl,
        &spare16[(HITLS_DTLS_CID_LIST_MAX - 1u) * TEST_CID_B_LEN], TEST_CID_B_LEN));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidA, sizeof(cidA)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidC, sizeof(cidC)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidD, sizeof(cidD)));

    /* A has been evicted; the failed explicit switch must preserve B. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, sizeof(cidA)), HITLS_INVALID_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));

    /* Drain the second ACK while B is still a sender-recognized recv CID. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* IMMEDIATE E(254 bytes) wipes the complete history and becomes the only active send CID. */
    uint8_t immediateE[254] = {0};
    for (uint16_t i = 0; i < sizeof(immediateE); i++) {
        immediateE[i] = (uint8_t)(0x80u + i);
    }
    CraftedNewCid immediate = {(uint8_t)HITLS_DTLS_CID_IMMEDIATE, 1u,
        (uint8_t)sizeof(immediateE), immediateE};
    HITLS_DtlsCidEntry trigger3 = {0};
    FillGeneratedCid(&trigger3, 0x83, 0, TEST_CID_B_LEN);
    ASSERT_EQ(ReceiveCraftedNewCid(server, client, &trigger3, &immediate),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(CurrentSendIs(client->ssl, immediateE, sizeof(immediateE)));
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_INUSE), 1u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_UNUSED), 0u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_USED), 0u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_FREE), 15u);
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 1u);

    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0u), HITLS_INVALID_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, immediateE, sizeof(immediateE)));
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, immediateE, sizeof(immediateE)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, immediateE, sizeof(immediateE)));

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test SDV_TLS_DTLS13_CID_SWITCH_SEND_CID_FUNC_TC003
 * @spec RFC 9147 section 9
 * @title SwitchSendCid across repeated IMMEDIATE replacement and a later SPARE refill
 * @precon nan
 * @brief Seed 15 historical send CIDs, receive IMMEDIATE [A,B,C,D], exercise explicit and automatic
 *        switching, then receive a 17-CID IMMEDIATE batch and finally reintroduce D as SPARE. This
 *        verifies that every IMMEDIATE message wipes the complete send-list history, stores at most
 *        16 entries, and leaves later SPARE CIDs selectable.
 * @expect 1. IMMEDIATE [A,B,C,D] removes all 15 historical CIDs and writes A INUSE, B/C/D UNUSED.
 *         2. Explicit A is a no-op success; automatic switching selects B and marks A USED;
 *            explicit A then recycles A back to INUSE.
 *         3. A 17-CID IMMEDIATE batch wipes A/B/C/D, stores entries 0..15 with entry 0 INUSE and
 *            entries 1..15 UNUSED, and silently discards entry 16.
 *         4. Explicit switching to old A or discarded entry 16 fails without changing entry 0.
 *         5. A later SPARE D is stored as UNUSED and can be explicitly switched to INUSE.
 * @prior  Level 1
 * @auto   TRUE
 */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_SWITCH_SEND_CID_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Seed 15 historical send CIDs: slot0 INUSE, slots1..14 UNUSED, slot15 FREE. */
    MaterializeRxCidCtx(client->ssl);
    DTLS_CidCtx *cidCtx = client->ssl->negotiatedInfo.cidCtx;
    ASSERT_TRUE(cidCtx != NULL);
    ResetSendTable(client->ssl);
    SeedSendSlot(client->ssl, 0, DTLS_CID_SEND_SLOT_INUSE, g_testCidB, TEST_CID_B_LEN);
    cidCtx->currentSendIdx = 0;
    client->ssl->negotiatedInfo.peerCidEntry = cidCtx->sendSlots[0].entry;
    uint8_t oldCids[14][TEST_CID_B_LEN] = {0};
    for (uint8_t i = 0; i < 14u; i++) {
        for (uint8_t b = 0; b < TEST_CID_B_LEN; b++) {
            oldCids[i][b] = (uint8_t)(0x10u + i * 9u + b);
        }
        SeedSendSlot(client->ssl, (uint8_t)(i + 1u), DTLS_CID_SEND_SLOT_UNUSED,
            oldCids[i], TEST_CID_B_LEN);
    }
    ASSERT_TRUE(CurrentSendIs(client->ssl, g_testCidB, TEST_CID_B_LEN));
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_INUSE), 1u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_UNUSED), 14u);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_FREE), 1u);
    uint8_t sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 15u);

    /* Receive IMMEDIATE [A,B,C,D]. Use A as the real trigger CID so the server recognizes the ACK
     * that the client sends with its newly selected A. */
    uint8_t cidA[TEST_CID_B_LEN] = {0xA1, 0xA2, 0xA3, 0xA4};
    uint8_t cidB[TEST_CID_B_LEN] = {0xB1, 0xB2, 0xB3, 0xB4};
    uint8_t cidC[TEST_CID_B_LEN] = {0xC1, 0xC2, 0xC3, 0xC4};
    uint8_t cidD[TEST_CID_B_LEN] = {0xD1, 0xD2, 0xD3, 0xD4};
    uint8_t immediateAbcd[4 * TEST_CID_B_LEN] = {0};
    (void)memcpy(&immediateAbcd[0 * TEST_CID_B_LEN], cidA, TEST_CID_B_LEN);
    (void)memcpy(&immediateAbcd[1 * TEST_CID_B_LEN], cidB, TEST_CID_B_LEN);
    (void)memcpy(&immediateAbcd[2 * TEST_CID_B_LEN], cidC, TEST_CID_B_LEN);
    (void)memcpy(&immediateAbcd[3 * TEST_CID_B_LEN], cidD, TEST_CID_B_LEN);
    CraftedNewCid firstImmediate = {(uint8_t)HITLS_DTLS_CID_IMMEDIATE, 4u,
        TEST_CID_B_LEN, immediateAbcd};
    HITLS_DtlsCidEntry triggerA = {0};
    SetCidEntry(&triggerA, cidA, sizeof(cidA));
    ASSERT_EQ(ReceiveCraftedNewCid(server, client, &triggerA, &firstImmediate),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(cidCtx->sendSlots[1].state, DTLS_CID_SEND_SLOT_UNUSED);
    ASSERT_EQ(cidCtx->sendSlots[2].state, DTLS_CID_SEND_SLOT_UNUSED);
    ASSERT_EQ(cidCtx->sendSlots[3].state, DTLS_CID_SEND_SLOT_UNUSED);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[1].entry.cidVal, cidB, sizeof(cidB)), 0);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[2].entry.cidVal, cidC, sizeof(cidC)), 0);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[3].entry.cidVal, cidD, sizeof(cidD)), 0);
    ASSERT_EQ(CountSendSlotsInState(client->ssl, DTLS_CID_SEND_SLOT_FREE), 12u);
    ASSERT_TRUE(!SendListHasCid(client->ssl, g_testCidB, TEST_CID_B_LEN));
    for (uint8_t i = 0; i < 14u; i++) {
        ASSERT_TRUE(!SendListHasCid(client->ssl, oldCids[i], TEST_CID_B_LEN));
    }
    sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, 4u);

    /* Drain the ACK that was packed with A before exercising local switches. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* Explicit current A succeeds. Automatic mode selects B and retires A; explicit A then recycles
     * the USED slot and becomes INUSE again. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, sizeof(cidA)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0u), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidB, sizeof(cidB)));
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_USED);
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, sizeof(cidA)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidA, sizeof(cidA)));

    /* Receive 17 IMMEDIATE CIDs. Entries 0..15 replace all history; entry 16 is silently discarded.
     * Commit entry 0 on the sender so the receiver's ACK remains valid after the immediate switch. */
    uint8_t immediate17[(HITLS_DTLS_CID_LIST_MAX + 1u) * TEST_CID_B_LEN] = {0};
    for (uint8_t i = 0; i < HITLS_DTLS_CID_LIST_MAX + 1u; i++) {
        for (uint8_t b = 0; b < TEST_CID_B_LEN; b++) {
            immediate17[(uint32_t)i * TEST_CID_B_LEN + b] = (uint8_t)(0x40u + i);
        }
    }
    CraftedNewCid secondImmediate = {(uint8_t)HITLS_DTLS_CID_IMMEDIATE,
        HITLS_DTLS_CID_LIST_MAX + 1u, TEST_CID_B_LEN, immediate17};
    HITLS_DtlsCidEntry triggerBatch0 = {0};
    SetCidEntry(&triggerBatch0, &immediate17[0], TEST_CID_B_LEN);
    ASSERT_EQ(ReceiveCraftedNewCid(server, client, &triggerBatch0, &secondImmediate),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_TRUE(CurrentSendIs(client->ssl, &immediate17[0], TEST_CID_B_LEN));
    ASSERT_EQ(cidCtx->sendSlots[0].state, DTLS_CID_SEND_SLOT_INUSE);
    ASSERT_EQ(memcmp(cidCtx->sendSlots[0].entry.cidVal, &immediate17[0], TEST_CID_B_LEN), 0);
    for (uint8_t i = 1; i < HITLS_DTLS_CID_LIST_MAX; i++) {
        ASSERT_EQ(cidCtx->sendSlots[i].state, DTLS_CID_SEND_SLOT_UNUSED);
        ASSERT_EQ(memcmp(cidCtx->sendSlots[i].entry.cidVal,
            &immediate17[(uint32_t)i * TEST_CID_B_LEN], TEST_CID_B_LEN), 0);
    }
    ASSERT_TRUE(!SendListHasCid(client->ssl,
        &immediate17[HITLS_DTLS_CID_LIST_MAX * TEST_CID_B_LEN], TEST_CID_B_LEN));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidA, sizeof(cidA)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidB, sizeof(cidB)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidC, sizeof(cidC)));
    ASSERT_TRUE(!SendListHasCid(client->ssl, cidD, sizeof(cidD)));
    sendCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, NULL, &sendCidCount), HITLS_SUCCESS);
    ASSERT_EQ(sendCidCount, HITLS_DTLS_CID_LIST_MAX);

    /* Old A and discarded entry 16 are not selectable; both failures preserve entry 0 as INUSE. */
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidA, sizeof(cidA)), HITLS_INVALID_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, &immediate17[0], TEST_CID_B_LEN));
    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl,
        &immediate17[HITLS_DTLS_CID_LIST_MAX * TEST_CID_B_LEN], TEST_CID_B_LEN), HITLS_INVALID_INPUT);
    ASSERT_TRUE(CurrentSendIs(client->ssl, &immediate17[0], TEST_CID_B_LEN));

    /* Drain the second ACK while entry 0 is still current and recognized by the sender. */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(server), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* Reintroduce old D as a real SPARE NewConnectionId, then explicitly switch to it. */
    HITLS_DtlsCidEntry spareD = {0};
    SetCidEntry(&spareD, cidD, sizeof(cidD));
    uint8_t cidCount = 1;
    ASSERT_EQ(HITLS_NewConnectionId(server->ssl, &spareD, &cidCount, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(ReadPostHandshake(client), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(SendListHasCid(client->ssl, cidD, sizeof(cidD)));
    ASSERT_TRUE(CurrentSendIs(client->ssl, &immediate17[0], TEST_CID_B_LEN));

    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, cidD, sizeof(cidD)), HITLS_SUCCESS);
    ASSERT_TRUE(CurrentSendIs(client->ssl, cidD, sizeof(cidD)));

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
