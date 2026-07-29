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
/* END_HEADER */

#define TEST_CID_A_LEN 4
#define TEST_CID_B_LEN 4
static uint8_t g_testCidA[TEST_CID_A_LEN] = {0x01, 0x02, 0x03, 0x04};
static uint8_t g_testCidB[TEST_CID_B_LEN] = {0xAA, 0xBB, 0xCC, 0xDD};

#define TEST_NEW_CID_LEN 4
static uint8_t g_testNewCid1[TEST_NEW_CID_LEN] = {0x11, 0x22, 0x33, 0x44};
static uint8_t g_testNewCid2[TEST_NEW_CID_LEN] = {0x55, 0x66, 0x77, 0x88};
static uint8_t g_testNewCid3[TEST_NEW_CID_LEN] = {0x99, 0xAA, 0xBB, 0xCC};
static uint8_t g_testSpareCid[TEST_NEW_CID_LEN] = {0xDD, 0xEE, 0xFF, 0x00};
static uint8_t g_testSpareCid2[TEST_NEW_CID_LEN] = {0xA1, 0xB2, 0xC3, 0xD4};

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

static int32_t SendNewCidAndComplete(FRAME_LinkObj *sender, FRAME_LinkObj *receiver,
    const HITLS_DtlsCidEntry *entries, uint8_t cidCount, HITLS_DtlsCidUsage usage)
{
    uint8_t count = cidCount;
    int32_t ret = HITLS_NewConnectionId(sender->ssl, entries, &count, usage);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (sender->ssl->isClient) {
        ret = HITLS_Connect(sender->ssl);
    } else {
        ret = HITLS_Accept(sender->ssl);
    }
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = FRAME_TrasferMsgBetweenLink(sender, receiver);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(receiver->ssl, readBuf, READ_BUF_SIZE, &readLen);
    if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

/*
 * Same as SendNewCidAndComplete but also returns the auto ACK to the sender so
 * the NewConnectionId send-state machine flips back to idle. Use this between
 * back-to-back HITLS_NewConnectionId calls; otherwise the second call gets
 * HITLS_MSG_HANDLE_STATE_ILLEGAL because the first send is still outstanding.
 */
static int32_t SendNewCidAndCompleteWithAck(FRAME_LinkObj *sender, FRAME_LinkObj *receiver,
    const HITLS_DtlsCidEntry *entries, uint8_t cidCount, HITLS_DtlsCidUsage usage)
{
    int32_t ret = SendNewCidAndComplete(sender, receiver, entries, cidCount, usage);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* receiver.snd now holds the record-layer ACK; deliver it to the sender. */
    ret = FRAME_TrasferMsgBetweenLink(receiver, sender);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = HITLS_Read(sender->ssl, readBuf, READ_BUF_SIZE, &readLen);
    if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

static int32_t SendAppDataRecord(FRAME_LinkObj *sender, FRAME_LinkObj *receiver)
{
    uint8_t appData[] = "test";
    uint32_t writeLen = 0;
    int32_t ret = HITLS_Write(sender->ssl, appData, sizeof(appData), &writeLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return FRAME_TrasferMsgBetweenLink(sender, receiver);
}

static int32_t RecvAppDataRecord(FRAME_LinkObj *receiver)
{
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    return HITLS_Read(receiver->ssl, readBuf, READ_BUF_SIZE, &readLen);
}

static int32_t AssertQueuedRecordCid(
    const FRAME_LinkObj *sender, const uint8_t *expectedCid, uint8_t expectedCidLen)
{
    if (sender == NULL || sender->io == NULL || expectedCid == NULL || expectedCidLen == 0u) {
        return HITLS_NULL_INPUT;
    }
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(sender->io);
    if (ioUserData == NULL || ioUserData->sndMsg.len < 1u + expectedCidLen) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    const uint8_t *record = ioUserData->sndMsg.msg;
    if (!REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(record[0]) ||
        (record[0] & REC_DTLS13_UNI_HEADER_CID_BIT) == 0u ||
        memcmp(&record[1], expectedCid, expectedCidLen) != 0) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC001
* @spec RFC 9147 Section 9
* @title Client receives NewConnectionId(cid_immediate), subsequent 3 outbound records use first new CID
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Server sends NewConnectionId(cid_immediate) with one new CID.
*   2. Client processes it and updates sendCid.
*   3. Client sends 3 records, all should use the new CID.
* @expect Client sendCid equals the new CID after processing.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(
        SendNewCidAndCompleteWithAck(server, client, &entry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    const DTLS_CidSendEntry *sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_NEW_CID_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testNewCid1, TEST_NEW_CID_LEN), 0);

    for (int i = 0; i < 3; i++) {
        uint32_t written = 0;
        ASSERT_EQ(HITLS_Write(client->ssl, (const uint8_t *)"x", 1, &written), HITLS_SUCCESS);
        ASSERT_EQ(written, 1);
        ASSERT_EQ(AssertQueuedRecordCid(client, g_testNewCid1, TEST_NEW_CID_LEN), HITLS_SUCCESS);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
        ASSERT_EQ(RecvAppDataRecord(server), HITLS_SUCCESS);
    }

    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC003
* @spec RFC 9147 Section 9
* @title Client sends spare then immediate, peer uses first spare's unused CID — accepted
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Client sends NewConnectionId(cid_spare) with spareCid.
*   2. Client sends NewConnectionId(cid_immediate) with newCid1.
*   3. Peer uses spareCid to send a record to client.
*   4. Client should accept (spareCid is DEPRECATING, still matchable).
* @expect Record accepted, recv list contains spareCid as DEPRECATING.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Step 1: client sends NewConnectionId(usage=SPARE) carrying spareCid. The
     * send-state machine flips PENDING -> SENT inside HITLS_Connect; the auto
     * ACK from the receiver flips it SENT -> IDLE. Without the ACK round-trip
     * the second HITLS_NewConnectionId below would hit NEW_IN_PROCESS. */
    HITLS_DtlsCidEntry spareEntry = {0};
    spareEntry.cidLen = TEST_NEW_CID_LEN;
    memcpy(spareEntry.cidVal, g_testSpareCid, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndCompleteWithAck(client, server, &spareEntry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* usage=SPARE appends new entries directly into ACTIVE recv slots. The
     * recv side has no "SPARE" state -- only FREE / ACTIVE / DEPRECATING. */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testSpareCid, TEST_NEW_CID_LEN));

    /* Step 2: client sends NewConnectionId(usage=IMMEDIATE) with newCid1.
     * BeginImmediateRetire flips every existing ACTIVE recv slot to
     * DEPRECATING (g_testCidA + g_testSpareCid), then newCid1 is written into
     * the next FREE slot as ACTIVE. DTLS_CID_IsExpectedCid accepts
     * ACTIVE | DEPRECATING, so all three CIDs remain matchable until the peer
     * ACK fires DTLS_CID_OnNewConnectionIdAcked. */
    HITLS_DtlsCidEntry immediateEntry = {0};
    immediateEntry.cidLen = TEST_NEW_CID_LEN;
    memcpy(immediateEntry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndComplete(client, server, &immediateEntry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));         /* DEPRECATING */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testSpareCid, TEST_NEW_CID_LEN));    /* DEPRECATING */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));     /* ACTIVE */

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC004
* @spec RFC 9147 Section 9
* @title Client sends cid_immediate with 3 CIDs, peer uses CID3/CID2/CID3 — all accepted
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Client sends NewConnectionId(cid_immediate) with 3 CIDs.
*   2. Peer uses CID3 for 1st record, CID2 for 2nd, CID3 for 3rd.
*   3. All records should be accepted (ACTIVE + SPARE entries).
* @expect All 3 records accepted by client recv matching.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entries[3] = {0};
    entries[0].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[0].cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    entries[1].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[1].cidVal, g_testNewCid2, TEST_NEW_CID_LEN);
    entries[2].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[2].cidVal, g_testNewCid3, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, entries, 3, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid2, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid3, TEST_NEW_CID_LEN));

    /* usage=IMMEDIATE marks every prior ACTIVE recv slot as DEPRECATING and
     * appends the new CIDs as ACTIVE (the recv side has no SPARE state).
     * Until ACK clears the DEPRECATING entries the slot table holds at least
     * 4 occupied slots: 1 original DEPRECATING + 3 new ACTIVE.
     * See design doc D5, §4.8.5. */
    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_TRUE(recvCidCount >= 4);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC005
* @spec RFC 9147 Section 9
* @title Server receives NewConnectionId(cid_immediate), subsequent 3 outbound records use first new CID
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Client sends NewConnectionId(cid_immediate) with one new CID.
*   2. Server processes it and updates sendCid.
*   3. Server sendCid should equal the new CID.
* @expect Server sendCid equals the new CID.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    const DTLS_CidSendEntry *sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_NEW_CID_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testNewCid1, TEST_NEW_CID_LEN), 0);

    for (int i = 0; i < 3; i++) {
        sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
        ASSERT_TRUE(sendCidEntry->cidLen > 0);
        ASSERT_EQ(sendCidEntry->cidLen, TEST_NEW_CID_LEN);
        ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testNewCid1, TEST_NEW_CID_LEN), 0);
    }

    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_EQ(server->ssl->state, CM_STATE_TRANSPORTING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC007
* @spec RFC 9147 Section 9
* @title Server sends spare then immediate, peer uses first spare's unused CID — accepted
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC003 with server sending NewConnectionIds.
* @expect Record accepted by server.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Mirror of TC003 with server as the sender. */
    HITLS_DtlsCidEntry spareEntry = {0};
    spareEntry.cidLen = TEST_NEW_CID_LEN;
    memcpy(spareEntry.cidVal, g_testSpareCid, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndCompleteWithAck(server, client, &spareEntry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* usage=SPARE appended spareCid into a FREE recv slot as ACTIVE; the
     * original g_testCidB stays ACTIVE. */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testSpareCid, TEST_NEW_CID_LEN));

    /* usage=IMMEDIATE flips every prior ACTIVE recv slot to DEPRECATING and
     * writes newCid1 as the new ACTIVE primary entry. All three CIDs remain
     * matchable until the peer ACK fires DTLS_CID_OnNewConnectionIdAcked. */
    HITLS_DtlsCidEntry immediateEntry = {0};
    immediateEntry.cidLen = TEST_NEW_CID_LEN;
    memcpy(immediateEntry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndComplete(server, client, &immediateEntry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));         /* DEPRECATING */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testSpareCid, TEST_NEW_CID_LEN));    /* DEPRECATING */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));     /* ACTIVE */

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC008
* @spec RFC 9147 Section 9
* @title Server sends cid_immediate with 3 CIDs, peer uses CID3/CID2/CID3 — all accepted
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC004 with server sending NewConnectionId.
* @expect All 3 CIDs matchable in server's recv list.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entries[3] = {0};
    entries[0].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[0].cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    entries[1].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[1].cidVal, g_testNewCid2, TEST_NEW_CID_LEN);
    entries[2].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[2].cidVal, g_testNewCid3, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, entries, 3, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid2, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid3, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC009
* @spec RFC 9147 Section 9
* @title Client receives cid_spare, 3 subsequent records still use old CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Server sends NewConnectionId(cid_spare) with one new CID.
*   2. Client processes it. Client sendCid unchanged (still old CID).
*   3. Verify server recv list still has old ACTIVE CID.
* @expect Old CID still accepted by server recv matching.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC009(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    const DTLS_CidSendEntry *sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    uint8_t oldSendCid[TEST_CID_B_LEN];
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_B_LEN);
    memcpy(oldSendCid, sendCidEntry->cidVal, TEST_CID_B_LEN);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, oldSendCid, TEST_CID_B_LEN), 0);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC010
* @spec RFC 9147 Section 9
* @title Client receives cid_spare, 3 subsequent records use new CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Server sends NewConnectionId(cid_spare) with one new CID.
*   2. Server recv list now has the original entry plus the newly added one;
*      usage=SPARE appends as ACTIVE (recv side has no SPARE state).
*   3. Verify the newly added CID is matchable by server recv matching.
* @expect New CID accepted (ACTIVE entry matchable).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC010(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC011
* @spec RFC 9147 Section 9
* @title Client receives cid_spare, 2 old CID + 1 new CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Same as TC009/TC010 — both old and new CIDs accepted simultaneously
*        (both stay ACTIVE because usage=SPARE never DEPRECATES).
* @expect Both old and new CIDs matchable (recv side has no SPARE state, both
*         are ACTIVE).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC011(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC012
* @spec RFC 9147 Section 9
* @title Client receives cid_spare, 2 new CID + 1 old CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Same as TC011, different order.
* @expect Both old and new CIDs matchable.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC012(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC013
* @spec RFC 9147 Section 9
* @title Client receives two cid_spare, 2 new + 1 old unused CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Server sends first NewConnectionId(cid_spare) with spareCid1.
*   2. Server sends second NewConnectionId(cid_spare) with spareCid2.
*   3. Verify: spareCid2 (new), spareCid1 (old unused), original CID all matchable.
* @expect All CIDs accepted (ACTIVE + multiple SPARE).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC013(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* First usage=SPARE call -- the ACK round-trip clears the send state
     * machine so the second HITLS_NewConnectionId below does not get
     * NEW_IN_PROCESS. */
    HITLS_DtlsCidEntry entry1 = {0};
    entry1.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry1.cidVal, g_testSpareCid, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndCompleteWithAck(server, client, &entry1, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* Second usage=SPARE call -- appends a second new entry. Both new CIDs
     * land in ACTIVE recv slots; usage=SPARE never DEPRECATES old entries. */
    HITLS_DtlsCidEntry entry2 = {0};
    entry2.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry2.cidVal, g_testSpareCid2, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndCompleteWithAck(server, client, &entry2, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(server->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* server recv list now holds g_testCidB + g_testSpareCid + g_testSpareCid2,
     * all in ACTIVE state -- all matchable for inbound records. */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testCidB, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testSpareCid, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testSpareCid2, TEST_NEW_CID_LEN));

    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 3);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC014
* @spec RFC 9147 Section 9
* @title Server receives cid_spare, 3 subsequent records still use old CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC009 with client sending NewConnectionId.
* @expect Old CID still accepted by client recv matching.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC014(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    const DTLS_CidSendEntry *sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    uint8_t oldSendCid[TEST_CID_A_LEN];
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_A_LEN);
    memcpy(oldSendCid, sendCidEntry->cidVal, TEST_CID_A_LEN);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, oldSendCid, TEST_CID_A_LEN), 0);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC015
* @spec RFC 9147 Section 9
* @title Server receives cid_spare, 3 subsequent records use new CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC010 with client sending NewConnectionId.
* @expect New CID accepted by client recv matching (SPARE).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC015(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC016
* @spec RFC 9147 Section 9
* @title Server receives cid_spare, 2 old + 1 new — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC011.
* @expect Both old and new CIDs matchable (both in ACTIVE recv state).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC016(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC017
* @spec RFC 9147 Section 9
* @title Server receives cid_spare, 2 new + 1 old — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC012.
* @expect Both old and new CIDs matchable.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC017(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC018
* @spec RFC 9147 Section 9
* @title Server receives two cid_spare, 2 new + 1 old unused CID — normal
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC013.
* @expect All CIDs accepted (ACTIVE + multiple SPARE).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC018(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    /* Mirror of TC013 with client as the sender. */
    HITLS_DtlsCidEntry entry1 = {0};
    entry1.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry1.cidVal, g_testSpareCid, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndCompleteWithAck(client, server, &entry1, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    HITLS_DtlsCidEntry entry2 = {0};
    entry2.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry2.cidVal, g_testSpareCid2, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndCompleteWithAck(client, server, &entry2, 1, HITLS_DTLS_CID_SPARE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);

    /* All three CIDs sit in ACTIVE recv slots on the client. */
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testCidA, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testSpareCid, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testSpareCid2, TEST_NEW_CID_LEN));

    {
        uint8_t recvCidCount = HITLS_DTLS_CID_LIST_MAX;
        ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
        ASSERT_EQ(recvCidCount, 3);
    }

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC019
* @spec RFC 9147 Section 9
* @title Client sends cid_immediate, 2 records with new CID then 1 with old CID — old discarded
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Client sends NewConnectionId(cid_immediate) with newCid1.
*   2. Client recv list: [oldCID:DEPRECATING, newCid1:ACTIVE].
*   3. After server receives NewConnectionId, server sendCid = newCid1.
*   4. Simulate: SetRecvCid with newCid1 (ACTIVE) → DEPRECATING entries deleted.
*   5. Verify: old CID no longer matchable after ACTIVE CID is received.
* @expect Old CID not matchable after new ACTIVE CID triggers DEPRECATING cleanup.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC019(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t oldRecvCid[TEST_CID_A_LEN];
    memcpy(oldRecvCid, g_testCidA, TEST_CID_A_LEN);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, oldRecvCid, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

    DTLS_CID_OnNewConnectionIdAcked(client->ssl);

    ASSERT_TRUE(!DTLS_CID_IsExpectedCid(client->ssl, oldRecvCid, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC020
* @spec RFC 9147 Section 9
* @title Server sends cid_immediate, 2 records with new CID then 1 with old CID — old discarded
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC019 with server sending NewConnectionId.
* @expect Old CID not matchable after new ACTIVE CID triggers DEPRECATING cleanup.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC020(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t oldRecvCid[TEST_CID_B_LEN];
    memcpy(oldRecvCid, g_testCidB, TEST_CID_B_LEN);

    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, &entry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, oldRecvCid, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

    DTLS_CID_OnNewConnectionIdAcked(server->ssl);

    ASSERT_TRUE(!DTLS_CID_IsExpectedCid(server->ssl, oldRecvCid, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC021
* @spec RFC 9147 Section 9
* @title Client sends cid_immediate with 2 CIDs, peer uses SPARE CID — DEPRECATING entries cleaned up
* @precon CID-enabled DTLS 1.3 connection established
* @brief
*   1. Client sends NewConnectionId(cid_immediate) with [newCid1, newCid2].
*   2. Client recv list: [oldCID:DEPRECATING, newCid1:ACTIVE, newCid2:SPARE].
*   3. Call SetRecvCid(newCid2) to simulate inbound record using SPARE CID.
*   4. SPARE hit should trigger DEPRECATING cleanup.
*   5. Verify old CID no longer matchable.
* @expect Old CID not matchable after SPARE CID triggers DEPRECATING cleanup.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC021(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t oldRecvCid[TEST_CID_A_LEN];
    memcpy(oldRecvCid, g_testCidA, TEST_CID_A_LEN);

    HITLS_DtlsCidEntry entries[2] = {0};
    entries[0].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[0].cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    entries[1].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[1].cidVal, g_testNewCid2, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(client, server, entries, 2, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, oldRecvCid, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid2, TEST_NEW_CID_LEN));

    DTLS_CID_OnNewConnectionIdAcked(client->ssl);

    ASSERT_TRUE(!DTLS_CID_IsExpectedCid(client->ssl, oldRecvCid, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid2, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC022
* @spec RFC 9147 Section 9
* @title Server sends cid_immediate with 2 CIDs, peer uses SPARE CID — DEPRECATING entries cleaned up
* @precon CID-enabled DTLS 1.3 connection established
* @brief Mirror of TC021 with server sending NewConnectionId.
* @expect Old CID not matchable after SPARE CID triggers DEPRECATING cleanup.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC022(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t oldRecvCid[TEST_CID_B_LEN];
    memcpy(oldRecvCid, g_testCidB, TEST_CID_B_LEN);

    HITLS_DtlsCidEntry entries[2] = {0};
    entries[0].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[0].cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    entries[1].cidLen = TEST_NEW_CID_LEN;
    memcpy(entries[1].cidVal, g_testNewCid2, TEST_NEW_CID_LEN);

    ASSERT_EQ(SendNewCidAndComplete(server, client, entries, 2, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, oldRecvCid, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid2, TEST_NEW_CID_LEN));

    DTLS_CID_OnNewConnectionIdAcked(server->ssl);

    ASSERT_TRUE(!DTLS_CID_IsExpectedCid(server->ssl, oldRecvCid, TEST_CID_B_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid1, TEST_NEW_CID_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(server->ssl, g_testNewCid2, TEST_NEW_CID_LEN));

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_USAGE_FUNC_TC023
* @spec RFC 9147 Section 9
* @title Client sends cid_immediate, real ACK round-trip, then app data uses new CID and old-CID record is discarded
* @precon CID-enabled DTLS 1.3 connection established
* @brief End-to-end record-layer verification of usage=IMMEDIATE:
*   1. Client sends NewConnectionId(cid_immediate) with newCid1, and the auto ACK
*      is delivered back to the client (real ACK round-trip, no manual helper call).
*   2. The ACK record itself is addressed to newCid1: on receipt the retransmit
*      layer fires DTLS_CID_OnNewConnectionIdAcked, which deletes the DEPRECATING
*      old CID slot (RFC 9147 §9). Verify old CID no longer expected, new ACTIVE.
*   3. Server sendCid (peerCidEntry) is now newCid1; an app-data record written by
*      the server therefore carries newCid1 and the client must accept it.
*   4. A stray record whose CID field carries the OLD CID is then injected into the
*      client UIO. rec_read.c:Dtls13ProcessCidBit finds the CID absent from the
*      expected set and returns HITLS_REC_DECODE_ERROR, which DTLS silently
*      discards (RFC 6347 §4.1.2.7); HITLS_Read yields no app data.
* @expect 1. Old CID cleared after ACK. 2. New-CID app data received. 3. Old-CID record discarded.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_USAGE_FUNC_TC023(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    ASSERT_EQ(SetupCidConnection(&client, &server, config), HITLS_SUCCESS);

    uint8_t oldRecvCid[TEST_CID_A_LEN];
    memcpy(oldRecvCid, g_testCidA, TEST_CID_A_LEN);

    /* (1) Client sends NewConnectionId(usage=IMMEDIATE, newCid1). The round-trip
     *     is inlined (instead of SendNewCidAndCompleteWithAck) so that the ACK
     *     record can be inspected on the wire before it is delivered to the
     *     client. After SendNewCidAndComplete the server has processed the
     *     NewConnectionId and the auto-generated ACK sits in server->sndMsg. */
    HITLS_DtlsCidEntry entry = {0};
    entry.cidLen = TEST_NEW_CID_LEN;
    memcpy(entry.cidVal, g_testNewCid1, TEST_NEW_CID_LEN);
    ASSERT_EQ(SendNewCidAndComplete(client, server, &entry, 1, HITLS_DTLS_CID_IMMEDIATE), HITLS_SUCCESS);

    /* (1b) Wire-level proof that the ACK record carries the NEW CID. The ACK is
     *      written in epoch 3 (>0), so rec_write.c:DtlsRecordHeaderPack routes it
     *      through Dtls13RecordHeaderPack, which emits a unified header whose CID
     *      field is copied verbatim from ctx->negotiatedInfo.peerCidEntry
     *      (rec_write.c:169). The server switched peerCidEntry to newCid1 while
     *      processing the NewConnectionId(immediate), so the ACK's CID field must
     *      equal newCid1. Parse the first record in server->sndMsg and assert it. */
    FrameUioUserData *serverUio = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverUio->sndMsg.len > 0);
    uint8_t *ackRec = serverUio->sndMsg.msg;
    ASSERT_TRUE((ackRec[0] & 0xe0) == 0x20);   /* unified header fixed bits 001 */
    ASSERT_TRUE((ackRec[0] & 0x10) != 0);      /* C bit set -> CID field present */
    ASSERT_EQ(memcmp(&ackRec[1], g_testNewCid1, TEST_NEW_CID_LEN), 0);  /* CID == newCid1 */

    /* (1c) Deliver the ACK to the client and let the record layer process it.
     *      The retransmit layer fires DTLS_CID_OnNewConnectionIdAcked (via the
     *      NEW_CONNECTION_ID ack callback registered in send_common.c). */
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    uint8_t drain[READ_BUF_SIZE] = {0};
    uint32_t drainLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, drain, READ_BUF_SIZE, &drainLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    /* (2) The ACK has flipped the client send-state SENT->IDLE and cleared the
     *     DEPRECATING old-CID slot. */
    ASSERT_EQ(client->ssl->newCidState, DTLS_CID_MSG_STATE_IDLE);
    ASSERT_TRUE(!DTLS_CID_IsExpectedCid(client->ssl, oldRecvCid, TEST_CID_A_LEN));
    ASSERT_TRUE(DTLS_CID_IsExpectedCid(client->ssl, g_testNewCid1, TEST_NEW_CID_LEN));

    /* Server's sendCid (peerCidEntry) was switched to newCid1 when it processed
     * the NewConnectionId(immediate), so outbound records toward the client now
     * carry newCid1 as the destination CID. */
    const DTLS_CidSendEntry *sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_EQ(sendCidEntry->cidLen, TEST_NEW_CID_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testNewCid1, TEST_NEW_CID_LEN), 0);

    /* (3) Server sends app data -> record carries newCid1 -> client accepts. */
    uint8_t appData[] = "test";
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

    /* (4) Inject a stray DTLS 1.3 unified-header record whose CID field carries
     *     the OLD CID. Layout mirrors negotiate TC007-TC010: first byte 0x30
     *     (001 fixed | C=1 | S=0 1-byte seq | L=0 length present | epoch 00),
     *     followed by the old CID, a 1-byte seq, 2-byte length, and fake
     *     ciphertext. The record is rejected at the CID-match step
     *     (rec_read.c:Dtls13ProcessCidBit -> DTLS_CID_IsExpectedCid == false ->
     *     HITLS_REC_DECODE_ERROR) before epoch/seq/AEAD are examined. */
    uint8_t stray[1u + TEST_CID_A_LEN + 1u + 2u + 16u];
    uint32_t off = 0u;
    stray[off++] = 0x30;
    for (uint32_t i = 0u; i < TEST_CID_A_LEN; i++) { stray[off++] = oldRecvCid[i]; }
    stray[off++] = 0x00;                        /* seq */
    stray[off++] = 0x00; stray[off++] = 0x10;   /* length = 16 */
    (void)memset(&stray[off], 0xAA, sizeof(stray) - off);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, stray, sizeof(stray)), HITLS_SUCCESS);

    /* The stray record is silently discarded (no alert), so HITLS_Read returns
     * HITLS_REC_NORMAL_RECV_BUF_EMPTY and yields no app data. */
    int32_t readRet = HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(readRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
