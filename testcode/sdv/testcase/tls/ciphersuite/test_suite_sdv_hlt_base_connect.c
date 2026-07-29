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
#include <unistd.h>
#include <semaphore.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hitls_build.h"
#include "hlt.h"
#include "logger.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "hitls.h"
#include "hitls_dtls_cid.h"
#include "hitls_debug.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "hitls_type.h"
#include "hs_msg.h"
#include "rec_header.h"
#include "test.h"
/* END_HEADER */

#define READ_BUF_LEN_18K (18 * 1024)
#define PORT 10088

#if defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_FEATURE_DTLS_CID)
#define DTLS13_CID_HLT_LEN 4u

static const uint8_t g_hltClientCid[DTLS13_CID_HLT_LEN] = {0x01, 0x02, 0x03, 0x04};
static const uint8_t g_hltServerCid[DTLS13_CID_HLT_LEN] = {0xAA, 0xBB, 0xCC, 0xDD};

typedef struct {
    bool tampered;
    const uint8_t *expectedCid;
    uint8_t expectedCidLen;
    uint32_t seenCidRecords;
    uint32_t tamperCidRecordIndex;
    uint32_t maxRecordLen;
} Dtls13CidTamperState;

static Dtls13CidTamperState g_dtls13CidTamperState;

#ifdef HITLS_TLS_FEATURE_INDICATOR
#define DTLS13_CID_REQUEST_NUM 2u

static const uint8_t g_hltServerNewCids[DTLS13_CID_REQUEST_NUM][DTLS13_CID_HLT_LEN] = {
    {0x10, 0x11, 0x12, 0x13},
    {0x20, 0x21, 0x22, 0x23},
};

typedef struct {
    uint32_t recvRequestMsgCount;
    uint32_t sendNewCidMsgCount;
    uint32_t recvRequestCbCount;
    uint8_t lastRequestedNum;
    uint8_t cbAcceptedNum;
    int32_t cbRet;
    bool malformedMsg;
    uint8_t newCidCount;
    uint8_t newCidUsage;
    HITLS_DtlsCidEntry newCids[DTLS13_CID_REQUEST_NUM];
} Dtls13CidRequestResponseState;

static bool ParseObservedNewConnectionId(const uint8_t *body, uint32_t bodyLen,
    Dtls13CidRequestResponseState *state)
{
    if (body == NULL || state == NULL || bodyLen < 3u) {
        return false;
    }

    uint16_t cidsLen = (uint16_t)(((uint16_t)body[0] << 8u) | body[1]);
    if ((uint32_t)cidsLen + 3u != bodyLen) {
        return false;
    }

    uint32_t offset = 2u;
    uint32_t cidsEnd = offset + cidsLen;
    uint8_t cidCount = 0;
    while (offset < cidsEnd) {
        uint8_t cidLen = body[offset++];
        if (offset + cidLen > cidsEnd || cidCount >= DTLS13_CID_REQUEST_NUM) {
            return false;
        }
        state->newCids[cidCount].cidLen = cidLen;
        if (cidLen > 0u) {
            (void)memcpy(state->newCids[cidCount].cidVal, &body[offset], cidLen);
        }
        offset += cidLen;
        cidCount++;
    }
    state->newCidCount = cidCount;
    state->newCidUsage = body[cidsEnd];
    return true;
}

static void ObserveDtls13CidPostHandshakeMsg(int32_t writePoint, int32_t tlsVersion, int32_t contentType,
    const void *msg, uint32_t msgLen, HITLS_Ctx *ctx, void *arg)
{
    (void)tlsVersion;
    (void)ctx;
    Dtls13CidRequestResponseState *state = (Dtls13CidRequestResponseState *)arg;
    if (state == NULL || contentType != REC_TYPE_HANDSHAKE || msg == NULL || msgLen < DTLS_HS_MSG_HEADER_SIZE) {
        return;
    }

    const uint8_t *data = (const uint8_t *)msg;
    uint32_t bodyLen = ((uint32_t)data[DTLS_HS_MSGLEN_ADDR] << 16u) |
        ((uint32_t)data[DTLS_HS_MSGLEN_ADDR + 1u] << 8u) | data[DTLS_HS_MSGLEN_ADDR + 2u];
    if (bodyLen + DTLS_HS_MSG_HEADER_SIZE != msgLen) {
        state->malformedMsg = true;
        return;
    }

    const uint8_t *body = &data[DTLS_HS_MSG_HEADER_SIZE];
    if (writePoint == 0 && data[0] == REQUEST_CONNECTION_ID) {
        state->recvRequestMsgCount++;
        if (bodyLen != 1u) {
            state->malformedMsg = true;
            return;
        }
        state->lastRequestedNum = body[0];
        return;
    }

    if (writePoint == 1 && data[0] == NEW_CONNECTION_ID) {
        state->sendNewCidMsgCount++;
        if (!ParseObservedNewConnectionId(body, bodyLen, state)) {
            state->malformedMsg = true;
        }
    }
}

static int32_t HltRecvRequestConnectionIdCb(HITLS_Ctx *ctx, uint8_t numCids, void *userData)
{
    Dtls13CidRequestResponseState *state = (Dtls13CidRequestResponseState *)userData;
    if (state == NULL) {
        return HITLS_NULL_INPUT;
    }

    state->recvRequestCbCount++;
    state->lastRequestedNum = numCids;

    uint8_t count = (numCids < DTLS13_CID_REQUEST_NUM) ? numCids : DTLS13_CID_REQUEST_NUM;
    HITLS_DtlsCidEntry entries[DTLS13_CID_REQUEST_NUM] = {0};
    for (uint8_t i = 0; i < count; i++) {
        entries[i].cidLen = DTLS13_CID_HLT_LEN;
        (void)memcpy(entries[i].cidVal, g_hltServerNewCids[i], DTLS13_CID_HLT_LEN);
    }

    state->cbRet = HITLS_NewConnectionId(ctx, entries, &count, HITLS_DTLS_CID_SPARE);
    state->cbAcceptedNum = count;
    return state->cbRet;
}
#endif

static bool IsDtls13UnifiedRecordWithCid(const uint8_t *buf, uint32_t len, const uint8_t *cid, uint8_t cidLen)
{
    if (buf == NULL || cid == NULL || len < 1u + cidLen || cidLen == 0) {
        return false;
    }
    if (!REC_DTLS13_UNI_HEADER_FIX_BITS_TYPE(buf[0]) ||
        (buf[0] & REC_DTLS13_UNI_HEADER_CID_BIT) != REC_DTLS13_UNI_HEADER_CID_BIT) {
        return false;
    }
    return memcmp(&buf[1], cid, cidLen) == 0;
}

static int32_t TamperSelectedDtls13CidRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    int32_t ret = BSL_UIO_UdpMethod()->uioRead(uio, buf, len, readLen);
    if (ret != BSL_SUCCESS || readLen == NULL || *readLen == 0 || g_dtls13CidTamperState.tampered) {
        return ret;
    }

    uint8_t *data = (uint8_t *)buf;
    if (IsDtls13UnifiedRecordWithCid(data, *readLen, g_dtls13CidTamperState.expectedCid,
        g_dtls13CidTamperState.expectedCidLen)) {
        if (g_dtls13CidTamperState.maxRecordLen != 0 && *readLen > g_dtls13CidTamperState.maxRecordLen) {
            return ret;
        }
        g_dtls13CidTamperState.seenCidRecords++;
        if (g_dtls13CidTamperState.seenCidRecords != g_dtls13CidTamperState.tamperCidRecordIndex) {
            return ret;
        }
        (void)memset(&data[1], 0xEE, g_dtls13CidTamperState.expectedCidLen);
        g_dtls13CidTamperState.tampered = true;
    }
    return ret;
}

#endif


bool SkipTlsTest(int connType, int version)
{
    switch (version) {
#ifdef HITLS_TLS_PROTO_TLS13
        case TLS1_3:
            break;
#endif
#ifdef HITLS_TLS_PROTO_TLS12
        case TLS1_2:
            break;
#endif
#ifdef HITLS_TLS_PROTO_DTLS12
        case DTLS1_2:
            break;
#endif
#ifdef HITLS_TLS_PROTO_DTLS13
        case DTLS1_3:
            break;
#endif
#ifdef HITLS_TLS_PROTO_TLCP11
        case TLCP1_1:
            break;
#endif
#ifdef HITLS_TLS_PROTO_DTLCP11
        case DTLCP1_1:
            break;
#endif
#if defined(HITLS_TLS_CONFIG_VERSION) && (defined(HITLS_TLS_PROTO_TLS12) || defined(HITLS_TLS_PROTO_TLS13))
        case TLS_ALL:
            break;
#endif
        default:
            return true;
    }
    switch (connType) {
#ifdef HITLS_BSL_UIO_TCP
        case TCP:
            break;
#endif
#ifdef HITLS_BSL_UIO_UDP
        case UDP:
            break;
#endif
        default:
            return true;
    }
    return false;
}

/* BEGIN_CASE */
void SDV_TLS_BASE_CONNECT_TC01(int connType, int version)
{
    if (SkipTlsTest(connType, version)) {
        SKIP_TEST();
        return;
    }

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);
    if (version == TLCP1_1 || version == DTLCP1_1) {
        serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
        clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    } else {
        serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
        clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    }
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    // Configure link information on the server.
    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Configure link information on the client.
    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test SDV_TLS_BASE_CONNECT_DTLS13_CID_REQUEST_RESPONSE_TC01
* @spec RFC 9147 section 5.2
* @title DTLS 1.3 server ignores RequestConnectionId without a callback and replies after callback registration
* @precon nan
* @brief The HLT test uses real UDP sockets. On the first RequestConnectionId(2), the server has no
*        recvRequestConnectionId callback and therefore acknowledges but otherwise ignores the request.
*        The test then registers the application callback, sends another RequestConnectionId(2), and
*        verifies that the callback calls HITLS_NewConnectionId and the server emits a NewConnectionId
*        containing exactly two spare CIDs.
* @expect 1. The server receives the first RequestConnectionId(2), does not invoke an application callback,
*            and does not send NewConnectionId.
*         2. After callback registration, the server invokes it with numCids=2.
*         3. The callback successfully queues two CIDs through HITLS_NewConnectionId.
*         4. The server sends one well-formed NewConnectionId containing those two CIDs with SPARE usage.
*         5. Application data remains usable after both post-handshake exchanges.
@ */
/* BEGIN_CASE */
void SDV_TLS_BASE_CONNECT_DTLS13_CID_REQUEST_RESPONSE_TC01(void)
{
#if !(defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP) && \
      defined(HITLS_TLS_FEATURE_DTLS_CID) && defined(HITLS_TLS_FEATURE_INDICATOR))
    SKIP_TEST();
    return;
#else
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen = 0;
    const char *ignoredClientMsg = "request without callback";
    const char *ignoredServerMsg = "request ignored";
    const char *handledClientMsg = "request with callback";
    const char *handledServerMsg = "new cid sent";
    const char *finalClientMsg = "new cid processed";
    Dtls13CidRequestResponseState state = {0};
    state.cbRet = HITLS_INTERNAL_EXCEPTION;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_EQ(HLT_SetDtlsCidSupport(serverCtxConfig, true), HITLS_SUCCESS);
    ASSERT_EQ(HLT_SetDtlsCidSupport(clientCtxConfig, true), HITLS_SUCCESS);

    /* Keep the server local so the test can change the application callback
     * between the two requests and observe its actual outbound handshake message. */
    serverRes = HLT_ProcessTlsInit(localProcess, DTLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(serverRes->ssl, g_hltServerCid, DTLS13_CID_HLT_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMsgCb(serverRes->ssl, ObserveDtls13CidPostHandshakeMsg), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetMsgCbArg(serverRes->ssl, &state), HITLS_SUCCESS);
    serverRes->acceptId = HLT_TlsAccept(serverRes->ssl);
    ASSERT_TRUE(serverRes->acceptId != 0);

    clientRes = HLT_ProcessTlsInit(remoteProcess, DTLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_RpcTlsSetDtlsCid(remoteProcess, clientRes->sslId, g_hltClientCid,
        DTLS13_CID_HLT_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_SUCCESS);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(serverRes->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

    /* Scenario 1: no callback is registered. The request is consumed and ACKed,
     * but the server must not queue or send NewConnectionId. */
    ASSERT_EQ(HLT_RpcTlsRequestConnectionId(remoteProcess, clientRes->sslId,
        DTLS13_CID_REQUEST_NUM), HITLS_SUCCESS);
    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, clientRes, (uint8_t *)ignoredClientMsg,
        strlen(ignoredClientMsg)), HITLS_SUCCESS);
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(ignoredClientMsg));
    ASSERT_EQ(memcmp(readBuf, ignoredClientMsg, readLen), 0);
    ASSERT_TRUE(state.recvRequestMsgCount >= 1u);
    ASSERT_EQ(state.lastRequestedNum, DTLS13_CID_REQUEST_NUM);
    ASSERT_EQ(state.recvRequestCbCount, 0u);
    ASSERT_EQ(state.sendNewCidMsgCount, 0u);
    ASSERT_TRUE(!state.malformedMsg);

    /* Let the client consume the request ACK before issuing the next request. */
    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)ignoredServerMsg,
        strlen(ignoredServerMsg)), HITLS_SUCCESS);
    (void)memset(readBuf, 0, sizeof(readBuf));
    readLen = 0;
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(ignoredServerMsg));
    ASSERT_EQ(memcmp(readBuf, ignoredServerMsg, readLen), 0);

    /* Scenario 2: the application callback answers RequestConnectionId(2) by
     * calling HITLS_NewConnectionId with two deterministic spare CIDs. */
    uint32_t requestMsgCountBeforeCallback = state.recvRequestMsgCount;
    ASSERT_EQ(HITLS_SetRecvRequestConnectionIdCb(serverRes->ssl, HltRecvRequestConnectionIdCb, &state),
        HITLS_SUCCESS);
    ASSERT_EQ(HLT_RpcTlsRequestConnectionId(remoteProcess, clientRes->sslId,
        DTLS13_CID_REQUEST_NUM), HITLS_SUCCESS);
    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, clientRes, (uint8_t *)handledClientMsg,
        strlen(handledClientMsg)), HITLS_SUCCESS);
    (void)memset(readBuf, 0, sizeof(readBuf));
    readLen = 0;
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(handledClientMsg));
    ASSERT_EQ(memcmp(readBuf, handledClientMsg, readLen), 0);

    ASSERT_TRUE(state.recvRequestMsgCount > requestMsgCountBeforeCallback);
    ASSERT_EQ(state.lastRequestedNum, DTLS13_CID_REQUEST_NUM);
    ASSERT_EQ(state.recvRequestCbCount, 1u);
    ASSERT_EQ(state.cbRet, HITLS_SUCCESS);
    ASSERT_EQ(state.cbAcceptedNum, DTLS13_CID_REQUEST_NUM);
    ASSERT_EQ(state.sendNewCidMsgCount, 1u);
    ASSERT_TRUE(!state.malformedMsg);
    ASSERT_EQ(state.newCidCount, DTLS13_CID_REQUEST_NUM);
    ASSERT_EQ(state.newCidUsage, HITLS_DTLS_CID_SPARE);
    for (uint8_t i = 0; i < DTLS13_CID_REQUEST_NUM; i++) {
        ASSERT_EQ(state.newCids[i].cidLen, DTLS13_CID_HLT_LEN);
        ASSERT_EQ(memcmp(state.newCids[i].cidVal, g_hltServerNewCids[i], DTLS13_CID_HLT_LEN), 0);
    }

    uint8_t recvCidCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(serverRes->ssl, NULL, &recvCidCount), HITLS_SUCCESS);
    ASSERT_EQ(recvCidCount, 1u + DTLS13_CID_REQUEST_NUM);

    /* The client must process the encrypted NewConnectionId before returning
     * the following application record. Its subsequent application write also
     * carries the NewConnectionId ACK back to the server. */
    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)handledServerMsg,
        strlen(handledServerMsg)), HITLS_SUCCESS);
    (void)memset(readBuf, 0, sizeof(readBuf));
    readLen = 0;
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(handledServerMsg));
    ASSERT_EQ(memcmp(readBuf, handledServerMsg, readLen), 0);

    ASSERT_EQ(HLT_ProcessTlsWrite(remoteProcess, clientRes, (uint8_t *)finalClientMsg,
        strlen(finalClientMsg)), HITLS_SUCCESS);
    (void)memset(readBuf, 0, sizeof(readBuf));
    readLen = 0;
    ASSERT_EQ(HLT_ProcessTlsRead(localProcess, serverRes, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, strlen(finalClientMsg));
    ASSERT_EQ(memcmp(readBuf, finalClientMsg, readLen), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
#endif
}
/* END_CASE */

/** @
* @test SDV_TLS_BASE_CONNECT_DTLS13_CID_APP_DATA_DISCARD_TC01
* @spec -
* @title DTLS 1.3 CID app data silently discards one wrong-CID datagram after negotiation
* @precon nan
* @brief The HLT test uses real UDP sockets instead of the frame simulated UIO. Both peers enable
*        DTLS 1.3 CID before the handshake. After CID negotiation completes, a warmup application-data
*        round-trip drains all post-handshake messages (ACK + NewSessionTickets) so that the UDP read
*        hook sees only the two subsequent application-data datagrams. The hook changes the CID bytes
*        in the first of those datagrams to an unrecognized value. The client silently discards that
*        datagram per RFC 9147 section 4.5.2, then accepts the next application-data record with the
*        negotiated CID.
* @expect 1. The client hook tampers exactly one CID-protected datagram.
*         2. The tampered application-data datagram is not delivered.
*         3. A subsequent application-data datagram with the negotiated CID is delivered.
@ */
/* BEGIN_CASE */
void SDV_TLS_BASE_CONNECT_DTLS13_CID_APP_DATA_DISCARD_TC01(void)
{
#if !(defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_FEATURE_DTLS_CID))
    SKIP_TEST();
    return;
#else
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen = 0;
    const char *dropMsg = "drop me";
    const char *testMsg = "Hello World";

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(HLT_SetDtlsCidSupport(serverCtxConfig, true) == 0);
    ASSERT_TRUE(HLT_SetDtlsCidSupport(clientCtxConfig, true) == 0);

    serverRes = HLT_ProcessTlsInit(remoteProcess, DTLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    int32_t ret = HLT_RpcTlsSetDtlsCid(remoteProcess, serverRes->sslId, g_hltServerCid,
        DTLS13_CID_HLT_LEN);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    clientRes = HLT_ProcessTlsInit(localProcess, DTLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HITLS_SetDtlsRecvCid(clientRes->ssl, g_hltClientCid, DTLS13_CID_HLT_LEN) == HITLS_SUCCESS);

    int acceptId = HLT_RpcTlsAccept(remoteProcess, serverRes->sslId);
    ASSERT_TRUE(acceptId != -1);
    ret = HLT_TlsConnect(clientRes->ssl);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HLT_RpcGetTlsAcceptResult(acceptId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    bool isCidNeg = false;
    ret = HITLS_GetDtlsIsCidNegotiated(clientRes->ssl, &isCidNeg);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

    /* Drain post-handshake messages (ACK + NewSessionTickets) so the hook only
     * sees the two application-data datagrams we send below. */
    ret = HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)testMsg, strlen(testMsg));
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HLT_ProcessTlsRead(localProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(readLen == strlen(testMsg));

    /* Install hook: tamper the next CID datagram (dropMsg), then let the
     * following one (testMsg) through. */
    g_dtls13CidTamperState.tampered = false;
    g_dtls13CidTamperState.expectedCid = g_hltClientCid;
    g_dtls13CidTamperState.expectedCidLen = DTLS13_CID_HLT_LEN;
    g_dtls13CidTamperState.seenCidRecords = 0;
    g_dtls13CidTamperState.tamperCidRecordIndex = 1;
    g_dtls13CidTamperState.maxRecordLen = 0;
    HLT_FrameHandle frameHandle = {0};
    frameHandle.ctx = clientRes->ssl;
    frameHandle.method.uioRead = TamperSelectedDtls13CidRead;
    ret = HLT_SetFrameHandle(&frameHandle);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ret = HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)dropMsg, strlen(dropMsg));
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)testMsg, strlen(testMsg));
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HLT_ProcessTlsRead(localProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(g_dtls13CidTamperState.tampered);
    ASSERT_TRUE(readLen == strlen(testMsg));
    ASSERT_TRUE(memcmp(testMsg, readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
#endif
}
/* END_CASE */

/** @
* @test SDV_TLS_BASE_CONNECT_DTLS13_CID_FINISH_UNKNOWN_CID_RETRANSMIT_TC01
* @spec -
* @title DTLS 1.3 handshake succeeds after server Finished record CID is tampered and retransmitted
* @precon nan
* @brief Both peers negotiate DTLS 1.3 CID. The client installs a UDP read hook that overwrites
*        the CID bytes of the server's Finished record (the 4th CID datagram in the encrypted
*        flight) with an unrecognized value (0xEE). The record layer silently discards it at the
*        CID-list check (rec_read.c Dtls13GetRecordUnifiedHeader returns
*        HITLS_REC_NORMAL_RECV_BUF_EMPTY before AEAD). The preceding records (EE, Cert, CV) are
*        received with the correct CID and processed normally. After the server's DTLS
*        retransmission timer fires, the Finished is resent with the negotiated CID, the client
*        consumes it, and the handshake completes.
* @expect 1. The hook tampers the Finished CID datagram.
*         2. HITLS_Connect returns HITLS_SUCCESS after retransmission.
*         3. CID is negotiated on the client.
*         4. Application data works after the handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_BASE_CONNECT_DTLS13_CID_FINISH_UNKNOWN_CID_RETRANSMIT_TC01(void)
{
#if !(defined(HITLS_TLS_PROTO_DTLS13) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_FEATURE_DTLS_CID))
    SKIP_TEST();
    return;
#else
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    uint8_t readBuf[READ_BUF_LEN_18K] = {0};
    uint32_t readLen = 0;
    const char *testMsg = "Hello World";

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(HLT_SetDtlsCidSupport(serverCtxConfig, true) == 0);
    ASSERT_TRUE(HLT_SetDtlsCidSupport(clientCtxConfig, true) == 0);

    serverRes = HLT_ProcessTlsInit(remoteProcess, DTLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    int32_t ret = HLT_RpcTlsSetDtlsCid(remoteProcess, serverRes->sslId, g_hltServerCid,
        DTLS13_CID_HLT_LEN);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    clientRes = HLT_ProcessTlsInit(localProcess, DTLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HITLS_SetDtlsRecvCid(clientRes->ssl, g_hltClientCid, DTLS13_CID_HLT_LEN) == HITLS_SUCCESS);

    /* Install the hook BEFORE the handshake. The server's encrypted flight is
     * sent as 4 CID datagrams (EE, Certificate, CertVerify, Finished). The hook
     * skips the first three and tampers only the Finished (index 4). After
     * tampering, tampered=true so the retransmitted Finished passes through. */
    g_dtls13CidTamperState.tampered = false;
    g_dtls13CidTamperState.expectedCid = g_hltClientCid;
    g_dtls13CidTamperState.expectedCidLen = DTLS13_CID_HLT_LEN;
    g_dtls13CidTamperState.seenCidRecords = 0;
    g_dtls13CidTamperState.tamperCidRecordIndex = 4;
    g_dtls13CidTamperState.maxRecordLen = 0;
    HLT_FrameHandle frameHandle = {0};
    frameHandle.ctx = clientRes->ssl;
    frameHandle.method.uioRead = TamperSelectedDtls13CidRead;
    ret = HLT_SetFrameHandle(&frameHandle);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    int acceptId = HLT_RpcTlsAccept(remoteProcess, serverRes->sslId);
    ASSERT_TRUE(acceptId != -1);
    ret = HLT_TlsConnect(clientRes->ssl);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HLT_RpcGetTlsAcceptResult(acceptId);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    ASSERT_TRUE(g_dtls13CidTamperState.tampered);

    bool isCidNeg = false;
    ret = HITLS_GetDtlsIsCidNegotiated(clientRes->ssl, &isCidNeg);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

    /* Verify application data works after the retransmitted handshake. */
    HLT_CleanFrameHandle();
    ret = HLT_ProcessTlsWrite(remoteProcess, serverRes, (uint8_t *)testMsg, strlen(testMsg));
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ret = HLT_ProcessTlsRead(localProcess, clientRes, readBuf, READ_BUF_LEN_18K, &readLen);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    ASSERT_TRUE(readLen == strlen(testMsg));
    ASSERT_TRUE(memcmp(testMsg, readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
#endif
}
/* END_CASE */
