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

/*
 * Test suite: TLS 1.3 server-side handling of the client "early_data" extension (RFC 8446 4.2.10).
 *
 * Scenarios:
 *  1. Server silently discards AEAD-undecryptable 0-RTT records and completes the handshake.
 *  2. Discard byte limit (> REC_MAX_EARLY_DATA_DISCARD_SIZE) terminates with unexpected_message.
 *  3. Empty application_data records are discarded while in 0-RTT discard mode.
 *  4. Records shorter than the minimum ciphertext length are discarded.
 *  5. early_data without pre_shared_key is rejected with missing_extension.
 *  6. early_data in the second ClientHello after HRR is rejected with illegal_parameter.
 *  7. After HRR, plaintext early data records are skipped (not cached/delivered).
 *  8. Regression: without early_data, an undecryptable record still fails with bad_record_mac.
 *  9. After HRR, empty early data records are skipped instead of aborting the handshake.
 */

/* BEGIN_HEADER */
#include <stdio.h>
#include <string.h>
#include "stub_utils.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hlt.h"
#include "hlt_type.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "rec_wrapper.h"
#include "common_func.h"
#include "conn_init.h"
#include "hs_extensions.h"
#include "hitls_crypt_init.h"
#include "alert.h"
#include "record.h"
#include "hs_kx.h"

STUB_DEFINE_RET5(int32_t, CompareBinder, TLS_Ctx *, const PreSharedKey *, uint8_t *, uint32_t, uint32_t);

#define ED_JUNK_BUF_SIZE (20u * 1024u)

/* Which ClientHello(s) the wrapper injects the early_data extension into. */
typedef enum {
    ED_ADD_ALL = 0,
    ED_ADD_CH1_ONLY,
    ED_ADD_CH2_ONLY,
} EdAddMode;

/* Binder comparison always succeeds: the wrapper injects bytes into a ClientHello that already
 * carries binders, so the server-side recomputation cannot match the client-side one. */
extern int32_t CompareBinder(TLS_Ctx *ctx, const PreSharedKey *pskNode, uint8_t *psk, uint32_t pskLen,
    uint32_t truncateHelloLen);
static int32_t Ed_CompareBinder_Success(TLS_Ctx *ctx, const PreSharedKey *pskNode, uint8_t *psk,
    uint32_t pskLen, uint32_t truncateHelloLen)
{
    (void)ctx;
    (void)pskNode;
    (void)psk;
    (void)pskLen;
    (void)truncateHelloLen;
    return 0;
}


typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
} EdTestInfo;

/* Full first handshake, after which the client owns a resumption ticket. */
static int32_t EdDoHandshake(EdTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateLink(testInfo->c_config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    testInfo->server = FRAME_CreateLink(testInfo->s_config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
}

/* Tear down the links of the first handshake and create fresh ones for resumption. */
static int32_t EdPrepareResumption(EdTestInfo *testInfo)
{
    testInfo->clientSession = HITLS_GetDupSession(testInfo->client->ssl);
    if (testInfo->clientSession == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    FRAME_FreeLink(testInfo->client);
    testInfo->client = NULL;
    FRAME_FreeLink(testInfo->server);
    testInfo->server = NULL;

    testInfo->client = FRAME_CreateLink(testInfo->c_config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    testInfo->server = FRAME_CreateLink(testInfo->s_config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SetSession(testInfo->client->ssl, testInfo->clientSession);
}

static void EdCleanTestInfo(EdTestInfo *testInfo)
{
    HITLS_SESS_Free(testInfo->clientSession);
    testInfo->clientSession = NULL;
    HITLS_CFG_FreeConfig(testInfo->c_config);
    testInfo->c_config = NULL;
    HITLS_CFG_FreeConfig(testInfo->s_config);
    testInfo->s_config = NULL;
    FRAME_FreeLink(testInfo->client);
    testInfo->client = NULL;
    FRAME_FreeLink(testInfo->server);
    testInfo->server = NULL;
}

/*
 * Build count fake 0-RTT application_data records (type 17, junk body). The server cannot decrypt
 * them because they are (supposedly) protected with the client early traffic key.
 */
static uint32_t EdMakeJunkAppRecords(uint8_t *buf, uint32_t bufSize, uint32_t bodyLen, uint32_t count)
{
    uint32_t off = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (off + 5u + bodyLen > bufSize) {
            break;
        }
        buf[off++] = 0x17;
        buf[off++] = 0x03;
        buf[off++] = 0x03;
        buf[off++] = (uint8_t)(bodyLen >> 8);
        buf[off++] = (uint8_t)(bodyLen & 0xff);
        for (uint32_t j = 0; j < bodyLen; j++) {
            buf[off++] = (uint8_t)(0xA5 ^ (i + j));
        }
    }
    return off;
}

/*
 * Let the client produce its current flight, then push junkRecords || flight to the server so that
 * the junk arrives first, exactly as in-flight 0-RTT data would.
 */
static int32_t EdPushJunkThenClientFlight(FRAME_LinkObj *client, FRAME_LinkObj *server,
    const uint8_t *junk, uint32_t junkLen)
{
    int32_t ret = HITLS_Connect(client->ssl);
    if (ret != HITLS_REC_NORMAL_IO_BUSY && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY && ret != HITLS_SUCCESS) {
        return ret;
    }
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint32_t flightLen = ioUserData->sndMsg.len;
    uint8_t *buf = BSL_SAL_Calloc(1u, junkLen + flightLen);
    if (buf == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    if (junkLen != 0) {
        memcpy(buf, junk, junkLen);
    }
    if (flightLen != 0) {
        memcpy(buf + junkLen, ioUserData->sndMsg.msg, flightLen);
    }
    ret = FRAME_TransportRecMsg(server->io, buf, junkLen + flightLen);
    BSL_SAL_Free(buf);
    ioUserData->sndMsg.len = 0;
    return ret;
}

/* Upper bound on HITLS_Accept retries: every skipped 0-RTT record yields one empty-buffer
 * return. HITLS_Accept reports the record-layer code directly, so both the raw BUF_EMPTY and
 * its user-side HITLS_WANT_READ mapping mean "keep driving". */
#define ED_ACCEPT_MAX_DRIVE 64u

/*
 * Drive HITLS_Accept in a loop: the record layer skips at most one rejected 0-RTT record per
 * invocation and reports it through an empty-buffer return, so the caller must keep retrying
 * until a terminal result (success, alert or exhaustion of the in-flight records).
 */
static int32_t EdDriveAccept(FRAME_LinkObj *server)
{
    int32_t ret = HITLS_SUCCESS;
    for (uint32_t i = 0; i < ED_ACCEPT_MAX_DRIVE; i++) {
        ret = HITLS_Accept(server->ssl);
        if (ret != HITLS_WANT_READ && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            break;
        }
    }
    return ret;
}

/*
 * ClientHello wrapper: inject an empty "early_data" (42) extension. The extension is inserted
 * before the pre_shared_key extension because RFC 8446 4.2.11 requires pre_shared_key to stay the
 * last extension of the ClientHello.
 */
static void Ed_Client_Ch_AddEarlyData(TLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)user;
    bool ch2Only = (ctx->hsCtx != NULL && ctx->hsCtx->haveHrr);
    bool ch1Only = !ch2Only;
    EdAddMode mode = ED_ADD_ALL;
    if (user != NULL) {
        mode = *(EdAddMode *)user;
    }
    if ((mode == ED_ADD_CH1_ONLY && !ch1Only) || (mode == ED_ADD_CH2_ONLY && !ch2Only)) {
        return;
    }

    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    /* Tolerate partial parses: the wrapper may fire again on the already-injected message, and the
     * frame parser does not know extension 42, so it stops there. Never abort the handshake. */
    if (parseLen != *len || frameMsg.body.hsMsg.type.data != CLIENT_HELLO) {
        goto EXIT;
    }

    static const uint8_t earlyData[] = { 0x00, 0x2a, 0x00, 0x00 };
    FRAME_ClientHelloMsg *ch = &frameMsg.body.hsMsg.body.clientHello;
    /* Total on-wire size of the psk extension: 4-byte header + extension_data (0 if absent). */
    bool hasPsk = (ch->psks.exState != MISSING_FIELD);
    uint32_t pskExtLen = hasPsk ? (uint32_t)ch->psks.exLen.data + 4u : 0u;

    ch->extensionLen.state = ASSIGNED_FIELD;
    ch->extensionLen.data += sizeof(earlyData);
    frameMsg.body.hsMsg.length.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.length.data += sizeof(earlyData);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

    /* RFC 8446 4.2.11: pre_shared_key must remain the last extension, so insert before it;
     * without psk, simply append at the end. */
    uint32_t insertPos = *len - pskExtLen;
    if (pskExtLen != 0) {
        memmove(&data[insertPos + sizeof(earlyData)], &data[insertPos], pskExtLen);
    }
    memcpy(&data[insertPos], earlyData, sizeof(earlyData));
    *len += sizeof(earlyData);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}
/* END_HEADER */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC001()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 512, 3); /* 1536 bytes of 0-RTT */

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    /* Drive to the point where the client is about to send its Finished. */
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    /* 0-RTT records hit the server before the (handshake-key protected) Finished. */
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    /* The server digests the 0-RTT records and the compat CCS (one per Accept retry). The client
     * Finished is not on the wire yet, so any of these intermediate returns is legal. */
    int32_t acceptRet = EdDriveAccept(testInfo.server);
    ASSERT_TRUE(acceptRet == HITLS_SUCCESS || acceptRet == HITLS_WANT_READ ||
        acceptRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
        acceptRet == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    /* No alert so far and the connection is still alive. */
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_NO);
    /* Complete the handshake (the client now sends its Finished). */
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    /* No garbage is delivered to the application. */
    uint8_t readBuf[ED_JUNK_BUF_SIZE] = { 0 };
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, ED_JUNK_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(testInfo.client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC002()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    /* 17 * 1020 = 17340 bytes of body, above the 16384 limit. */
    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 1020, 17);
    ASSERT_TRUE(junkLen != 0);

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    ASSERT_TRUE(EdDriveAccept(testInfo.server) == HITLS_REC_ERR_RECV_UNEXPECTED_MSG);

    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNEXPECTED_MESSAGE);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC003()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 0, 3); /* 3 empty records */

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    int32_t acceptRet = EdDriveAccept(testInfo.server);
    ASSERT_TRUE(acceptRet == HITLS_SUCCESS || acceptRet == HITLS_WANT_READ ||
        acceptRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
        acceptRet == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_NO);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t readBuf[ED_JUNK_BUF_SIZE] = { 0 };
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, ED_JUNK_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC004()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 2, 2); /* 2 records of 2 bytes */

    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    int32_t acceptRet = EdDriveAccept(testInfo.server);
    ASSERT_TRUE(acceptRet == HITLS_SUCCESS || acceptRet == HITLS_WANT_READ ||
        acceptRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
        acceptRet == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_NO);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t readBuf[ED_JUNK_BUF_SIZE] = { 0 };
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, ED_JUNK_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC005()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    /* Fresh handshake: the ClientHello has no pre_shared_key extension. */
    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_MISSING_EXTENSION);

    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_MISSING_EXTENSION);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC006()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    /* Group mismatch forces a HelloRetryRequest on the resumption handshake. */
    uint16_t clientGroups[] = { HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1 };
    uint16_t serverGroups[] = { HITLS_EC_GROUP_SECP256R1 };
    ASSERT_EQ(HITLS_CFG_SetGroups(testInfo.c_config, clientGroups,
        sizeof(clientGroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(testInfo.s_config, serverGroups,
        sizeof(serverGroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    /* Inject early_data only into the second ClientHello (RFC 8446 4.2.10 forbids it there).
     * Register the wrapper only now so that the first handshake stays untouched. */
    static EdAddMode mode = ED_ADD_CH2_ONLY;
    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &mode, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_ILLEGAL_EARLY_DATA);

    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC007()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    uint16_t clientGroups[] = { HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1 };
    uint16_t serverGroups[] = { HITLS_EC_GROUP_SECP256R1 };
    ASSERT_EQ(HITLS_CFG_SetGroups(testInfo.c_config, clientGroups,
        sizeof(clientGroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(testInfo.s_config, serverGroups,
        sizeof(serverGroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    /* Inject early_data only into the resumption ClientHello. Register the wrapper only now so
     * that the first handshake stays untouched. */
    static EdAddMode mode = ED_ADD_CH1_ONLY;
    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &mode, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    /* Drive the resumption handshake manually until the server has sent the HelloRetryRequest
     * (group mismatch) and is waiting for the second ClientHello. */
    for (uint32_t i = 0; i < 10u; i++) {
        if (testInfo.server->ssl->hsCtx != NULL && testInfo.server->ssl->hsCtx->haveHrr) {
            break;
        }
        (void)HITLS_Connect(testInfo.client->ssl);
        (void)FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server);
        (void)HITLS_Accept(testInfo.server->ssl);
        (void)FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client);
    }
    ASSERT_TRUE(testInfo.server->ssl->hsCtx != NULL && testInfo.server->ssl->hsCtx->haveHrr == true);
    /* Fake in-flight 0-RTT records arrive before the second ClientHello; the server has no read
     * keys yet, so they arrive as plaintext application_data records. */
    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 64, 3);
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    int32_t acceptRet = EdDriveAccept(testInfo.server);
    ASSERT_TRUE(acceptRet == HITLS_SUCCESS || acceptRet == HITLS_WANT_READ ||
        acceptRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
        acceptRet == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_NO);
    /* Finish the handshake. */
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* The early data records must have been skipped, not delivered. */
    uint8_t readBuf[ED_JUNK_BUF_SIZE] = { 0 };
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, ED_JUNK_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(testInfo.client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC008()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    /* Plain full handshake, no early_data extension anywhere. */
    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_SEND_FINISH), HITLS_SUCCESS);
    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 512, 1);
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    /* The record is genuinely corrupt: the connection must fail with bad_record_mac. */
    ASSERT_TRUE(EdDriveAccept(testInfo.server) == HITLS_REC_BAD_RECORD_MAC);

    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_BAD_RECORD_MAC);

EXIT:
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_TLS_TLS13_EARLY_DATA_SERVER_DISCARD_FUNC_TC009()
{
    FRAME_Init();
    EdTestInfo testInfo = { 0 };
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);
    ASSERT_TRUE(testInfo.s_config != NULL);

    uint16_t clientGroups[] = { HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1 };
    uint16_t serverGroups[] = { HITLS_EC_GROUP_SECP256R1 };
    ASSERT_EQ(HITLS_CFG_SetGroups(testInfo.c_config, clientGroups,
        sizeof(clientGroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(testInfo.s_config, serverGroups,
        sizeof(serverGroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    ASSERT_EQ(EdDoHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(EdPrepareResumption(&testInfo), HITLS_SUCCESS);

    static EdAddMode mode = ED_ADD_CH1_ONLY;
    RecWrapper wrapper = { TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, &mode, Ed_Client_Ch_AddEarlyData };
    RegisterWrapper(wrapper);
    STUB_REPLACE(CompareBinder, Ed_CompareBinder_Success);

    /* Drive the resumption handshake manually until the server has sent the HelloRetryRequest
     * (group mismatch) and is waiting for the second ClientHello. */
    for (uint32_t i = 0; i < 10u; i++) {
        if (testInfo.server->ssl->hsCtx != NULL && testInfo.server->ssl->hsCtx->haveHrr) {
            break;
        }
        (void)HITLS_Connect(testInfo.client->ssl);
        (void)FRAME_TrasferMsgBetweenLink(testInfo.client, testInfo.server);
        (void)HITLS_Accept(testInfo.server->ssl);
        (void)FRAME_TrasferMsgBetweenLink(testInfo.server, testInfo.client);
    }
    ASSERT_TRUE(testInfo.server->ssl->hsCtx != NULL && testInfo.server->ssl->hsCtx->haveHrr == true);
    /* Fake in-flight empty 0-RTT records arrive before the second ClientHello; the server has no
     * read keys yet, so they arrive as plaintext application_data records with a zero-length body.
     * They must be skipped instead of aborting the handshake. */
    static uint8_t junk[ED_JUNK_BUF_SIZE];
    uint32_t junkLen = EdMakeJunkAppRecords(junk, ED_JUNK_BUF_SIZE, 0, 3); /* 3 empty records */
    ASSERT_EQ(EdPushJunkThenClientFlight(testInfo.client, testInfo.server, junk, junkLen), HITLS_SUCCESS);
    int32_t acceptRet = EdDriveAccept(testInfo.server);
    ASSERT_TRUE(acceptRet == HITLS_SUCCESS || acceptRet == HITLS_WANT_READ ||
        acceptRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY ||
        acceptRet == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(testInfo.server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_NO);
    /* Finish the handshake. */
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* The early data records must have been skipped, not delivered. */
    uint8_t readBuf[ED_JUNK_BUF_SIZE] = { 0 };
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(testInfo.server->ssl, readBuf, ED_JUNK_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(testInfo.client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);

EXIT:
    ClearWrapper();
    STUB_RESTORE(CompareBinder);
    EdCleanTestInfo(&testInfo);
}
/* END_CASE */
