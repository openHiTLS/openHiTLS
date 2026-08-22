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
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "sal_time.h"
#include "uio_abstraction.h"
#include "uio_base.h"
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
#include "hs_extensions.h"
#include "hs_msg.h"
#include "hs_verify.h"
#include "transcript_hash.h"
#include "parse.h"
#include "cipher_suite.h"
#include "crypt.h"
#include "rec_wrapper.h"

#define APP_READ_BUF_SIZE (18 * 1024)
#define TEST_SHA256_DIGEST_LEN 32u

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

static TLS_Ctx *g_dtls13PostHsFinishedServer = NULL;
static uint32_t g_dtls13PostHsFinishedTrySendAckCnt = 0;
static TLS_Ctx *g_dtls13KeyUpdateServer = NULL;
static uint32_t g_dtls13TrySendKeyUpdateCnt = 0;
static BslUioCtrlCb g_dtls13OrigUioCtrl = NULL;

static int32_t Dtls13PeerAddrFailCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    if (cmd == BSL_UIO_GET_PEER_IP_ADDR) {
        return BSL_UIO_FAIL;
    }
    return g_dtls13OrigUioCtrl == NULL ? BSL_SUCCESS : g_dtls13OrigUioCtrl(uio, cmd, larg, param);
}

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

static void BuildDtlsHsMsg(uint8_t *msg, HS_MsgType type, uint16_t seq, const uint8_t *body, uint32_t bodyLen)
{
    msg[0] = (uint8_t)type;
    BSL_Uint24ToByte(bodyLen, &msg[DTLS_HS_MSGLEN_ADDR]);
    BSL_Uint16ToByte(seq, &msg[DTLS_HS_MSGSEQ_ADDR]);
    BSL_Uint24ToByte(0, &msg[DTLS_HS_FRAGMENT_OFFSET_ADDR]);
    BSL_Uint24ToByte(bodyLen, &msg[DTLS_HS_FRAGMENT_LEN_ADDR]);
    (void)memcpy(&msg[DTLS_HS_MSG_HEADER_SIZE], body, bodyLen);
}

static uint32_t BuildDtls13TranscriptMsg(uint8_t *out, const uint8_t *dtlsMsg, uint32_t dtlsMsgLen)
{
    (void)memcpy(out, dtlsMsg, HS_MSG_HEADER_SIZE);
    (void)memcpy(&out[HS_MSG_HEADER_SIZE], &dtlsMsg[DTLS_HS_MSG_HEADER_SIZE],
        dtlsMsgLen - DTLS_HS_MSG_HEADER_SIZE);
    return HS_MSG_HEADER_SIZE + dtlsMsgLen - DTLS_HS_MSG_HEADER_SIZE;
}

static int32_t CalcSha256(const uint8_t *data, uint32_t dataLen, uint8_t *digest, uint32_t *digestLen)
{
    return SAL_CRYPT_Digest(NULL, NULL, HITLS_HASH_SHA_256, data, dataLen, digest, digestLen);
}

static int32_t CalcSha256TwoBlocks(const uint8_t *data1, uint32_t dataLen1, const uint8_t *data2,
    uint32_t dataLen2, uint8_t *digest, uint32_t *digestLen)
{
    HITLS_HASH_Ctx *hashCtx = SAL_CRYPT_DigestInit(NULL, NULL, HITLS_HASH_SHA_256);
    if (hashCtx == NULL) {
        return HITLS_CRYPT_ERR_DIGEST;
    }
    int32_t ret = SAL_CRYPT_DigestUpdate(hashCtx, data1, dataLen1);
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_DigestUpdate(hashCtx, data2, dataLen2);
    }
    if (ret == HITLS_SUCCESS) {
        ret = SAL_CRYPT_DigestFinal(hashCtx, digest, digestLen);
    }
    SAL_CRYPT_DigestFree(hashCtx);
    return ret;
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

static void Dtls13MoveCurrentCookieMacKeyToPre(TLS_Ctx *ctx)
{
    CookieInfo *cookieInfo = &ctx->negotiatedInfo.cookieInfo;
    memcpy(cookieInfo->preMacKey, cookieInfo->macKey, MAC_KEY_LEN);
    memset(cookieInfo->macKey, 0xA5, MAC_KEY_LEN);
    if (memcmp(cookieInfo->preMacKey, cookieInfo->macKey, MAC_KEY_LEN) == 0) {
        cookieInfo->macKey[0] ^= 0xFF;
    }
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

static void SetDtlsHandshakeFrameType(FRAME_Type *frameType, uint16_t version, HS_MsgType handshakeType)
{
    frameType->versionType = version;
    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = handshakeType;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType->transportType = BSL_UIO_UDP;
}

static int32_t ParseDtlsBufferedHsMsg(FRAME_LinkObj *link, bool isRecvMsg, uint16_t version,
    HS_MsgType handshakeType, FRAME_Msg *frameMsg)
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
    SetDtlsHandshakeFrameType(&frameType, version, handshakeType);
    return FRAME_ParseMsg(&frameType, msg->msg, msg->len, frameMsg, &parseLen);
}

static int32_t ConfigDtlsStatefulSessionResume(HITLS_Config *config)
{
    int32_t ret = HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_BOTH);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_CFG_SetSessionTicketSupport(config, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_CFG_SetTicketNums(config, 0);
}

static HITLS_Config *NewDtls12AndDtls13Config(void)
{
    HITLS_Config *config = HITLS_CFG_NewDTLSConfig();
    if (config == NULL) {
        return NULL;
    }
    if (!NewDtlsConfigSupportsDtls12AndDtls13(config) ||
        ConfigDtlsStatefulSessionResume(config) != HITLS_SUCCESS ||
        Dtls13UseSingleKeyShareGroup(config) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    return config;
}

static int32_t PrepareDtls12Session(HITLS_Config *clientConfig, HITLS_Config *serverConfig,
    HITLS_Session **session, uint8_t *sessionId, uint32_t *sessionIdSize)
{
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    int32_t ret = ConfigDtlsStatefulSessionResume(clientConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = ConfigDtlsStatefulSessionResume(serverConfig);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    if (client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    if (server == NULL) {
        FRAME_FreeLink(client);
        return HITLS_INTERNAL_EXCEPTION;
    }

    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    if (ret == HITLS_SUCCESS) {
        *session = HITLS_GetDupSession(client->ssl);
        if (*session == NULL) {
            ret = HITLS_INTERNAL_EXCEPTION;
        }
    }
    if (ret == HITLS_SUCCESS) {
        *sessionIdSize = HITLS_SESSION_ID_MAX_SIZE;
        ret = HITLS_SESS_GetSessionId(*session, sessionId, sessionIdSize);
    }

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    return ret;
}

static bool DtlsClientHelloHasSupportedVersion(const FRAME_ClientHelloMsg *clientHello, uint16_t version)
{
    if (clientHello->supportedVersion.exState == MISSING_FIELD ||
        clientHello->supportedVersion.exData.data == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < clientHello->supportedVersion.exData.size; i++) {
        if (clientHello->supportedVersion.exData.data[i] == version) {
            return true;
        }
    }
    return false;
}

static bool DtlsFrameSessionIdEquals(const FRAME_Integer *size, const FRAME_Array8 *sessionId,
    const uint8_t *expected, uint32_t expectedSize)
{
    return size->data == expectedSize && sessionId->data != NULL && sessionId->size == expectedSize &&
        memcmp(sessionId->data, expected, expectedSize) == 0;
}

static int32_t DtlsCheckNegotiatedVersionAndResume(FRAME_LinkObj *client, uint16_t expectedVersion,
    bool expectedResume)
{
    uint16_t version = 0;
    bool isReused = false;
    int32_t ret = HITLS_GetNegotiatedVersion(client->ssl, &version);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (version != expectedVersion) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    ret = HITLS_IsSessionReused(client->ssl, &isReused);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return isReused == expectedResume ? HITLS_SUCCESS : HITLS_INTERNAL_EXCEPTION;
}

static HITLS_Session *g_dtlsLowVersionResumeSession = NULL;

static HITLS_Session *DtlsLowVersionResumeSessionGetCb(HITLS_Ctx *ctx, const uint8_t *data, int32_t len,
    int32_t *copy)
{
    (void)ctx;
    if (g_dtlsLowVersionResumeSession == NULL || data == NULL || len <= 0 || copy == NULL) {
        return NULL;
    }

    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint32_t sessionIdSize = sizeof(sessionId);
    if (HITLS_SESS_GetSessionId(g_dtlsLowVersionResumeSession, sessionId, &sessionIdSize) != HITLS_SUCCESS ||
        sessionIdSize != (uint32_t)len || memcmp(sessionId, data, sessionIdSize) != 0) {
        return NULL;
    }

    *copy = 1;
    return g_dtlsLowVersionResumeSession;
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

static int32_t Dtls13SetClientHelloCookieExt(FRAME_ClientHelloMsg *clientHello, const uint8_t *cookie,
    uint32_t cookieLen)
{
    if (clientHello == NULL || cookie == NULL || cookieLen == 0) {
        return HITLS_INVALID_INPUT;
    }
    uint8_t *cookieData = BSL_SAL_Dump(cookie, cookieLen);
    if (cookieData == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    BSL_SAL_FREE(clientHello->tls13Cookie.exData.data);
    clientHello->tls13Cookie.exState = INITIAL_FIELD;
    clientHello->tls13Cookie.exType.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exType.data = HS_EX_TYPE_COOKIE;
    clientHello->tls13Cookie.exLen.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exLen.data = sizeof(uint16_t) + cookieLen;
    clientHello->tls13Cookie.exDataLen.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exDataLen.data = cookieLen;
    clientHello->tls13Cookie.exData.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exData.size = cookieLen;
    clientHello->tls13Cookie.exData.data = cookieData;
    return HITLS_SUCCESS;
}

static int32_t Dtls13SetClientHelloEmptyCookieExt(FRAME_ClientHelloMsg *clientHello)
{
    if (clientHello == NULL) {
        return HITLS_INVALID_INPUT;
    }

    BSL_SAL_FREE(clientHello->tls13Cookie.exData.data);
    clientHello->tls13Cookie.exState = INITIAL_FIELD;
    clientHello->tls13Cookie.exType.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exType.data = HS_EX_TYPE_COOKIE;
    clientHello->tls13Cookie.exLen.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exLen.data = sizeof(uint16_t);
    clientHello->tls13Cookie.exDataLen.state = INITIAL_FIELD;
    clientHello->tls13Cookie.exDataLen.data = 0;
    clientHello->tls13Cookie.exData.state = MISSING_FIELD;
    clientHello->tls13Cookie.exData.size = 0;
    clientHello->tls13Cookie.exData.data = NULL;
    return HITLS_SUCCESS;
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
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC038
* @spec -
* @title DTLS1.3 server rejects an initial ClientHello with a fake cookie extension.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange.
*    2. Modify the first ClientHello to carry a TLS1.3 cookie extension before any HRR is sent.
*    3. Send the modified ClientHello to the server.
* @expect
*    1. The server rejects the unsolicited cookie in ClientHello processing.
*    2. The server rejects the ClientHello and sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC038(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    uint8_t fakeCookie[] = {0x44, 0x31, 0x33, 0x66, 0x61, 0x6b, 0x65};

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->tls13Cookie.exState, MISSING_FIELD);
    ASSERT_EQ(Dtls13SetClientHelloCookieExt(clientHello, fakeCookie, sizeof(fakeCookie)), HITLS_SUCCESS);
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
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC039
* @spec -
* @title DTLS1.3 app-cookie server rejects an initial ClientHello cookie without invoking app verify.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange with application cookie callbacks.
*    2. Modify the first ClientHello to carry the application cookie before any HRR is sent.
*    3. Send the modified ClientHello to the server.
* @expect
*    1. The server rejects the ClientHello as an unsolicited first-flight cookie.
*    2. The application verify callback is not invoked.
*    3. The server sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC039(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);

    FRAME_Init();
    ResetDtls13AppCookieCnt();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

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

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->tls13Cookie.exState, MISSING_FIELD);
    ASSERT_EQ(Dtls13SetClientHelloCookieExt(clientHello, g_dtls13AppCookie, sizeof(g_dtls13AppCookie)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);
    ASSERT_EQ(g_dtls13AppCookieGenCnt, 0);
    ASSERT_EQ(g_dtls13AppCookieVerifyCnt, 0);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    ResetDtls13AppCookieCnt();
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC016
* @spec -
* @title DTLS1.3 default cookie requires the server to keep the HRR transcript.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange and let the server send a cookie HRR.
*    2. Clear the server-side verify transcript before the second ClientHello arrives.
*    3. Let the client send the second ClientHello carrying the cookie.
* @expect
*    1. The server verifies the cookie, but cannot complete the handshake without the preserved HRR transcript.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC016(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);

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
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) != HITLS_SUCCESS);

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
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(clientConfig), HITLS_SUCCESS);
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
*    4. Complete the handshake and exchange application data.
* @expect
*    1. The generation and verification callbacks are both used.
*    2. The handshake and application data exchange succeed.
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
    ASSERT_TRUE(server->ssl->hsCtx != NULL);
    ASSERT_TRUE(server->ssl->hsCtx->verifyCtx != NULL);
    ASSERT_TRUE(server->ssl->hsCtx->verifyCtx->dataBuf != NULL);
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
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(clientConfig), HITLS_SUCCESS);
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
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

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
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);
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
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);
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

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC043
* @spec -
* @title DTLS1.3 default cookie verification accepts cookie generated by previous MAC key.
* @precon nan
* @brief
*    1. Configure DTLS1.3 cookie exchange and generate a cookie HRR.
*    2. Let the client send the second ClientHello carrying the cookie.
*    3. Simulate server cookie MAC key rotation before processing the second ClientHello.
*    4. Complete the handshake.
* @expect
*    1. The HRR cookie is generated by the default cookie path.
*    2. The server verifies the cookie through preMacKey.
*    3. The DTLS1.3 handshake succeeds.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC043(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    uint8_t zeroMacKey[MAC_KEY_LEN] = {0};

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
    ASSERT_TRUE(server->ssl->negotiatedInfo.cookie != NULL);
    ASSERT_TRUE(server->ssl->negotiatedInfo.cookieSize != 0);
    ASSERT_TRUE(memcmp(server->ssl->negotiatedInfo.cookieInfo.macKey, zeroMacKey, MAC_KEY_LEN) != 0);

    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    Dtls13MoveCurrentCookieMacKeyToPre(server->ssl);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC044
* @spec -
* @title DTLS raw transcript cache replays as DTLS1.2 raw or DTLS1.3 TLS-style data by negotiated version.
* @precon nan
* @brief
*    1. Append a complete DTLS handshake message as raw cache data before a hash algorithm is selected.
*    2. Rebuild the transcript hash as DTLS1.2 and compare with SHA256 over the full DTLS message.
*    3. Rebuild the transcript hash as DTLS1.3 and compare with SHA256 over the TLS-style transcript message.
* @expect
*    1. The same raw cache entry can produce both version-specific transcript hashes.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC044(void)
{
    HS_Ctx hsCtx = {0};
    uint8_t body[] = {0x11, 0x22, 0x33, 0x44};
    uint8_t dtlsMsg[DTLS_HS_MSG_HEADER_SIZE + sizeof(body)] = {0};
    uint8_t dtls13Msg[HS_MSG_HEADER_SIZE + sizeof(body)] = {0};
    uint32_t dtls13MsgLen = 0;
    uint8_t expected[MAX_DIGEST_SIZE] = {0};
    uint8_t actual[MAX_DIGEST_SIZE] = {0};
    uint32_t expectedLen = sizeof(expected);
    uint32_t actualLen = sizeof(actual);

    BuildDtlsHsMsg(dtlsMsg, CLIENT_HELLO, 3, body, sizeof(body));
    dtls13MsgLen = BuildDtls13TranscriptMsg(dtls13Msg, dtlsMsg, sizeof(dtlsMsg));

    ASSERT_EQ(VERIFY_Init(&hsCtx), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_AppendDtlsRaw(hsCtx.verifyCtx, dtlsMsg, sizeof(dtlsMsg), VERIFY_TRANSCRIPT_RAW), HITLS_SUCCESS);

    ASSERT_EQ(VERIFY_SetHashWithVersion(NULL, NULL, hsCtx.verifyCtx, HITLS_HASH_SHA_256, HITLS_VERSION_DTLS12),
        HITLS_SUCCESS);
    ASSERT_EQ(CalcSha256(dtlsMsg, sizeof(dtlsMsg), expected, &expectedLen), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_CalcSessionHash(hsCtx.verifyCtx, actual, &actualLen), HITLS_SUCCESS);
    ASSERT_EQ(actualLen, expectedLen);
    ASSERT_EQ(memcmp(actual, expected, expectedLen), 0);

    expectedLen = sizeof(expected);
    actualLen = sizeof(actual);
    ASSERT_EQ(VERIFY_SetHashWithVersion(NULL, NULL, hsCtx.verifyCtx, HITLS_HASH_SHA_256, HITLS_VERSION_DTLS13),
        HITLS_SUCCESS);
    ASSERT_EQ(CalcSha256(dtls13Msg, dtls13MsgLen, expected, &expectedLen), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_CalcSessionHash(hsCtx.verifyCtx, actual, &actualLen), HITLS_SUCCESS);
    ASSERT_EQ(actualLen, expectedLen);
    ASSERT_EQ(memcmp(actual, expected, expectedLen), 0);

EXIT:
    VERIFY_Deinit(&hsCtx);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC045
* @spec -
* @title Mixed HRR transcript cache keeps message_hash canonical and converts raw HRR for DTLS1.3 replay.
* @precon nan
* @brief
*    1. Append a TLS1.3 synthetic message_hash as canonical transcript data.
*    2. Append a raw DTLS HelloRetryRequest message.
*    3. Rebuild as DTLS1.3 and compare with SHA256 over message_hash plus TLS-style HRR.
* @expect
*    1. The synthetic message_hash is not treated as a DTLS raw message.
*    2. The raw HRR is converted to TLS-style transcript data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC045(void)
{
    HS_Ctx hsCtx = {0};
    uint8_t msgHash[HS_MSG_HEADER_SIZE + TEST_SHA256_DIGEST_LEN] = {0};
    uint8_t hrrBody[] = {0xaa, 0xbb, 0xcc};
    uint8_t hrr[DTLS_HS_MSG_HEADER_SIZE + sizeof(hrrBody)] = {0};
    uint8_t hrrTranscript[HS_MSG_HEADER_SIZE + sizeof(hrrBody)] = {0};
    uint32_t hrrTranscriptLen = 0;
    uint8_t expected[MAX_DIGEST_SIZE] = {0};
    uint8_t actual[MAX_DIGEST_SIZE] = {0};
    uint32_t expectedLen = sizeof(expected);
    uint32_t actualLen = sizeof(actual);

    msgHash[0] = MESSAGE_HASH;
    BSL_Uint24ToByte(TEST_SHA256_DIGEST_LEN, &msgHash[DTLS_HS_MSGLEN_ADDR]);
    for (uint32_t i = 0; i < TEST_SHA256_DIGEST_LEN; i++) {
        msgHash[HS_MSG_HEADER_SIZE + i] = (uint8_t)(i + 1u);
    }
    BuildDtlsHsMsg(hrr, SERVER_HELLO, 1, hrrBody, sizeof(hrrBody));
    hrrTranscriptLen = BuildDtls13TranscriptMsg(hrrTranscript, hrr, sizeof(hrr));

    ASSERT_EQ(VERIFY_Init(&hsCtx), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_Append(hsCtx.verifyCtx, msgHash, sizeof(msgHash)), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_AppendDtlsRaw(hsCtx.verifyCtx, hrr, sizeof(hrr), VERIFY_TRANSCRIPT_RAW), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_SetHashWithVersion(NULL, NULL, hsCtx.verifyCtx, HITLS_HASH_SHA_256, HITLS_VERSION_DTLS13),
        HITLS_SUCCESS);

    ASSERT_EQ(CalcSha256TwoBlocks(msgHash, sizeof(msgHash), hrrTranscript, hrrTranscriptLen, expected, &expectedLen),
        HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_CalcSessionHash(hsCtx.verifyCtx, actual, &actualLen), HITLS_SUCCESS);
    ASSERT_EQ(actualLen, expectedLen);
    ASSERT_EQ(memcmp(actual, expected, expectedLen), 0);

EXIT:
    VERIFY_Deinit(&hsCtx);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC046
* @spec -
* @title DTLS1.3 binder prior transcript skips the current ClientHello cache block and converts earlier raw blocks.
* @precon nan
* @brief
*    1. Cache raw DTLS ClientHello1, raw DTLS HRR and raw DTLS ClientHello2.
*    2. Feed cached transcript to a SHA256 context as DTLS1.3 while skipping the last cache block.
*    3. Compare with SHA256 over TLS-style ClientHello1 and TLS-style HRR.
* @expect
*    1. The current ClientHello2 is excluded from the prior transcript.
*    2. Earlier DTLS raw messages are converted to TLS-style transcript data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC046(void)
{
    HS_Ctx hsCtx = {0};
    HITLS_HASH_Ctx *hashCtx = NULL;
    uint8_t ch1Body[] = {0x01, 0x02};
    uint8_t hrrBody[] = {0x03, 0x04, 0x05};
    uint8_t ch2Body[] = {0x06, 0x07, 0x08};
    uint8_t ch1[DTLS_HS_MSG_HEADER_SIZE + sizeof(ch1Body)] = {0};
    uint8_t hrr[DTLS_HS_MSG_HEADER_SIZE + sizeof(hrrBody)] = {0};
    uint8_t ch2[DTLS_HS_MSG_HEADER_SIZE + sizeof(ch2Body)] = {0};
    uint8_t ch1Transcript[HS_MSG_HEADER_SIZE + sizeof(ch1Body)] = {0};
    uint8_t hrrTranscript[HS_MSG_HEADER_SIZE + sizeof(hrrBody)] = {0};
    uint32_t ch1TranscriptLen = 0;
    uint32_t hrrTranscriptLen = 0;
    uint8_t expected[MAX_DIGEST_SIZE] = {0};
    uint8_t actual[MAX_DIGEST_SIZE] = {0};
    uint32_t expectedLen = sizeof(expected);
    uint32_t actualLen = sizeof(actual);

    BuildDtlsHsMsg(ch1, CLIENT_HELLO, 0, ch1Body, sizeof(ch1Body));
    BuildDtlsHsMsg(hrr, SERVER_HELLO, 1, hrrBody, sizeof(hrrBody));
    BuildDtlsHsMsg(ch2, CLIENT_HELLO, 2, ch2Body, sizeof(ch2Body));
    ch1TranscriptLen = BuildDtls13TranscriptMsg(ch1Transcript, ch1, sizeof(ch1));
    hrrTranscriptLen = BuildDtls13TranscriptMsg(hrrTranscript, hrr, sizeof(hrr));

    ASSERT_EQ(VERIFY_Init(&hsCtx), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_AppendDtlsRaw(hsCtx.verifyCtx, ch1, sizeof(ch1), VERIFY_TRANSCRIPT_RAW), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_AppendDtlsRaw(hsCtx.verifyCtx, hrr, sizeof(hrr), VERIFY_TRANSCRIPT_RAW), HITLS_SUCCESS);
    ASSERT_EQ(VERIFY_AppendDtlsRaw(hsCtx.verifyCtx, ch2, sizeof(ch2), VERIFY_TRANSCRIPT_RAW), HITLS_SUCCESS);

    hashCtx = SAL_CRYPT_DigestInit(NULL, NULL, HITLS_HASH_SHA_256);
    ASSERT_TRUE(hashCtx != NULL);
    ASSERT_EQ(VERIFY_UpdateCachedTranscriptHash(hashCtx, hsCtx.verifyCtx->dataBuf, HITLS_VERSION_DTLS13, 1),
        HITLS_SUCCESS);
    ASSERT_EQ(SAL_CRYPT_DigestFinal(hashCtx, actual, &actualLen), HITLS_SUCCESS);
    SAL_CRYPT_DigestFree(hashCtx);
    hashCtx = NULL;

    ASSERT_EQ(CalcSha256TwoBlocks(ch1Transcript, ch1TranscriptLen, hrrTranscript, hrrTranscriptLen,
        expected, &expectedLen), HITLS_SUCCESS);
    ASSERT_EQ(actualLen, expectedLen);
    ASSERT_EQ(memcmp(actual, expected, expectedLen), 0);

EXIT:
    SAL_CRYPT_DigestFree(hashCtx);
    VERIFY_Deinit(&hsCtx);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC047
* @spec -
* @title DTLS1.3-capable client can negotiate DTLS1.2 with EMS without corrupting transcript hash.
* @precon nan
* @brief
*    1. Create a HITLS_CFG_NewDTLSConfig client and a DTLS1.2-only server.
*    2. Force EMS on both endpoints and disable session tickets.
*    3. Complete the handshake without DTLS cookie exchange and exchange application data.
* @expect
*    1. The handshake succeeds and negotiates DTLS1.2.
*    2. EMS is negotiated.
*    3. Finished verification and application data exchange succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC047(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t appData[] = "DTLS12 EMS fallback transcript";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(NewDtlsConfigSupportsDtls12AndDtls13(clientConfig));
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(clientConfig, HITLS_EMS_MODE_FORCE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionTicketSupport(clientConfig, false), HITLS_SUCCESS);
    serverConfig = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetExtendedMasterSecretMode(serverConfig, HITLS_EMS_MODE_FORCE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionTicketSupport(serverConfig, false), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(client->ssl->negotiatedInfo.isExtendedMasterSecret);
    ASSERT_TRUE(server->ssl->negotiatedInfo.isExtendedMasterSecret);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC048
* @spec -
* @title DTLS1.3 server-only application cookie callbacks can complete a handshake.
* @precon nan
* @brief
*    1. Create a DTLS1.3 client without application cookie callbacks.
*    2. Create a DTLS1.3 server with appGenCookieCb and appVerifyCookieCb.
*    3. Enable DTLS cookie exchange on the server.
*    4. Complete the handshake and exchange application data.
* @expect
*    1. The client does not install application cookie callbacks.
*    2. The server generation and verification callbacks are both used once.
*    3. The handshake and application data exchange succeed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC048(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t appData[] = "DTLS13 server app cookie";
    uint8_t readBuf[APP_READ_BUF_SIZE] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    FRAME_Init();
    ResetDtls13AppCookieCnt();

    clientConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(clientConfig, 0), HITLS_SUCCESS);

    serverConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(serverConfig, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(serverConfig, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieGenCb(serverConfig, Dtls13AppCookieGenCb), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCookieVerifyCb(serverConfig, Dtls13AppCookieVerifyCb), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(client->ssl->globalConfig->appGenCookieCb == NULL);
    ASSERT_TRUE(client->ssl->globalConfig->appVerifyCookieCb == NULL);
    ASSERT_TRUE(server->ssl->globalConfig->appGenCookieCb == Dtls13AppCookieGenCb);
    ASSERT_TRUE(server->ssl->globalConfig->appVerifyCookieCb == Dtls13AppCookieVerifyCb);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_EQ(g_dtls13AppCookieGenCnt, 1);
    ASSERT_EQ(g_dtls13AppCookieVerifyCnt, 1);

    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(appData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC049
* @spec -
* @title DTLS1.3 client sends an ACK on timeout after receiving part of the server EE flight.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop the server after sending EncryptedExtensions and before sending Certificate.
*    3. Let the client process the partial server flight and wait for CertificateRequest.
*    4. Force the client's DTLS handshake timer to expire and process timeout.
* @expect
*    1. The client keeps pending ACK state after receiving the partial server flight.
*    2. The client handshake timer is still active before timeout processing.
*    3. Timeout processing sends an ACK and clears the normal ACK list.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC049(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t ackBuf[MAX_RECORD_LENTH] = {0};
    uint32_t ackLen = 0;

    FRAME_Init();

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_SEND_CERTIFICATE), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_CERTIFICATE_REQUEST);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(client->ssl, REC_DTLS13_ACK_NORMAL) == false);
    ASSERT_TRUE(REC_Dtls13AckListIsEmpty(client->ssl, REC_DTLS13_ACK_RETRANS) == false);
    ASSERT_TRUE(client->ssl->timeoutValue != 0);

    ForceDtlsTimerExpired(client->ssl);
    ASSERT_EQ(HITLS_DtlsProcessTimeout(client->ssl), HITLS_SUCCESS);

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
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC050
* @spec -
* @title DTLS1.3 default-cookie server rejects a MAC-valid cookie that differs from current HRR cookie.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange and let the server send HRR with Cookie1.
*    2. Let the client send ClientHello2 with Cookie1.
*    3. Modify the server-side saved current HRR cookie before processing ClientHello2.
* @expect
*    1. Cookie1 is HMAC-valid under the same server cookie key.
*    2. The server rejects Cookie1 because it does not match ctx->negotiatedInfo.cookie.
*    3. The server sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC050(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);

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
    ASSERT_TRUE(server->ssl->negotiatedInfo.cookie != NULL);
    ASSERT_TRUE(server->ssl->negotiatedInfo.cookieSize != 0);

    ASSERT_EQ(Dtls13ClientProcessHrr(client, server), HITLS_SUCCESS);
    server->ssl->negotiatedInfo.cookie[0] ^= 0x01;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);

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
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC051
* @spec -
* @title DTLS1.3 default-cookie server fails the handshake when peer address cannot be obtained.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange.
*    2. Make the server UIO fail BSL_UIO_GET_PEER_IP_ADDR.
*    3. Let the server process ClientHello1 and try to generate HRR cookie.
* @expect
*    1. Cookie generation fails instead of falling back to an addressless cookie.
*    2. The server sends a fatal internal_error alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC051(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint8_t hrrBuf[MAX_RECORD_LENTH] = {0};
    uint32_t hrrLen = sizeof(hrrBuf);
    BSL_UIO *serverUio = NULL;

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
    serverUio = server->ssl->uio;
    ASSERT_TRUE(serverUio != NULL);

    g_dtls13OrigUioCtrl = serverUio->method.uioCtrl;
    serverUio->method.uioCtrl = Dtls13PeerAddrFailCtrl;

    ASSERT_EQ(Dtls13PrepareCookieHrr(client, server, hrrBuf, &hrrLen), HITLS_MSG_HANDLE_COOKIE_ERR);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_INTERNAL_ERROR);

EXIT:
    if (serverUio != NULL && g_dtls13OrigUioCtrl != NULL) {
        serverUio->method.uioCtrl = g_dtls13OrigUioCtrl;
    }
    g_dtls13OrigUioCtrl = NULL;
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC052
* @spec -
* @title DTLS1.3 server rejects an initial ClientHello with an empty cookie extension and sends decode_error.
* @precon nan
* @brief
*    1. Enable DTLS1.3 cookie exchange.
*    2. Modify the first ClientHello to carry a cookie extension whose cookie vector length is zero.
*    3. Send the modified ClientHello to the server.
* @expect
*    1. The server rejects the malformed cookie extension during ClientHello parsing.
*    2. HITLS_Accept returns HITLS_PARSE_INVALID_MSG_LEN.
*    3. The server sends a fatal decode_error alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC052(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    int32_t ret;

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCookieExchangeSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(IsFrameIoPendingRet(ret));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);
    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(clientHello->tls13Cookie.exState, MISSING_FIELD);
    ASSERT_EQ(Dtls13SetClientHelloEmptyCookieExt(clientHello), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_PARSE_INVALID_MSG_LEN);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_DECODE_ERROR);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC053
* @spec -
* @title DTLS1.3 server rejects the first ClientHello carrying a non-empty cookie extension.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links.
*    2. Stop when the server is about to receive the first ClientHello.
*    3. Add a non-empty TLS1.3 cookie extension to that first ClientHello.
*    4. Send the modified ClientHello to the server.
* @expect
*    1. The server rejects the first ClientHello.
*    2. The server sends a fatal illegal_parameter alert instead of ServerHello.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC053(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    const uint8_t cookie[] = {0x64, 0x74, 0x6c, 0x73, 0x31, 0x33};

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
    ASSERT_EQ(clientHello->tls13Cookie.exState, MISSING_FIELD);
    ASSERT_EQ(Dtls13SetClientHelloCookieExt(clientHello, cookie, sizeof(cookie)), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    serverIoUserData->sndMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);
    CONN_Deinit(server->ssl);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_MSG_HANDLE_COOKIE_ERR);
    ASSERT_EQ(server->ssl->hsCtx->state, TRY_RECV_CLIENT_HELLO);

    ALERT_Info alert = {0};
    ALERT_GetInfo(server->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
    ASSERT_TRUE(serverIoUserData->sndMsg.len != 0);
    ASSERT_TRUE(serverIoUserData->sndMsg.msg[0] != REC_TYPE_HANDSHAKE);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC054
* @spec -
* @title DTLS1.3 clears the current retransmit flight before caching a future-sequence handshake message.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop after the client sends ClientHello and enters TRY_RECV_SERVER_HELLO.
*    3. Let the server produce ServerHello, then change ServerHello message_seq to one greater than the client's
*       expected receive sequence.
*    4. Mark the client as DTLS1.3 negotiated, then deliver the modified ServerHello to the client.
* @expect
*    1. The client initially has a ClientHello retransmit node.
*    2. The future-sequence ServerHello is cached in the reassembly queue.
*    3. The client retransmit queue is cleared before the out-of-order path returns.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC054(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    uint16_t expectRecvSeq = 0;
    int32_t ret;

    FRAME_Init();
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_SERVER_HELLO);
    ASSERT_TRUE(REC_RetransmitIsEmpty(client->ssl->recCtx) == false);
    ASSERT_TRUE(HS_ReassQueueIsEmpty(client->ssl) == true);

    ASSERT_EQ(ParseDtls13BufferedHsMsg(client, true, SERVER_HELLO, &serverHelloMsg), HITLS_SUCCESS);

    expectRecvSeq = client->ssl->hsCtx->expectRecvSeq;
    FRAME_ModifyMsgInteger((uint32_t)(expectRecvSeq + 1u), &serverHelloMsg.body.hsMsg.sequence);
    ASSERT_EQ(FRAME_PackMsg(&serverHelloType, &serverHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    client->ssl->negotiatedInfo.version = HITLS_VERSION_DTLS13;
    clientIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, sendBuf, sendLen), HITLS_SUCCESS);

    ret = HITLS_Connect(client->ssl);
    ASSERT_TRUE(IsFrameIoPendingRet(ret));
    ASSERT_EQ(client->ssl->hsCtx->expectRecvSeq, expectRecvSeq);
    ASSERT_TRUE(HS_ReassQueueIsEmpty(client->ssl) == false);
    ASSERT_TRUE(REC_RetransmitIsEmpty(client->ssl->recCtx) == true);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC055
* @spec -
* @title DTLS1.3 server does not echo a non-empty ClientHello legacy_session_id.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop after the client sends ClientHello to the server.
*    3. Modify ClientHello to carry a non-empty legacy_session_id.
*    4. Let the server process the modified ClientHello and send ServerHello.
*    5. Parse ServerHello and check legacy_session_id_echo.
* @expect
*    1. The modified ClientHello can be packed and delivered.
*    2. The server negotiates DTLS1.3.
*    3. The ServerHello legacy_session_id_echo length is 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC055(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);
    int32_t ret;

    FRAME_Init();
    SetDtls13FrameType(&clientHelloType, REC_TYPE_HANDSHAKE, CLIENT_HELLO);
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, true, CLIENT_HELLO, &clientHelloMsg), HITLS_SUCCESS);

    for (uint32_t i = 0; i < sizeof(sessionId); i++) {
        sessionId[i] = (uint8_t)(i + 1u);
    }

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_EQ(FRAME_ModifyMsgArray8(sessionId, sizeof(sessionId), &clientHello->sessionId,
        &clientHello->sessionIdSize), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_PackMsg(&clientHelloType, &clientHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *serverIoUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIoUserData != NULL);
    serverIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, sendBuf, sendLen), HITLS_SUCCESS);

    ret = HITLS_Accept(server->ssl);
    ASSERT_TRUE(IsFrameIoPendingRet(ret));
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);

    ASSERT_EQ(ParseDtls13BufferedHsMsg(server, false, SERVER_HELLO, &serverHelloMsg), HITLS_SUCCESS);
    ASSERT_EQ(serverHelloMsg.body.hsMsg.body.serverHello.sessionIdSize.data, 0);

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC056
* @spec -
* @title DTLS1.3 client rejects a non-empty ServerHello legacy_session_id_echo.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server links over UDP.
*    2. Stop after the client receives ServerHello.
*    3. Modify ServerHello to carry a non-empty legacy_session_id_echo.
*    4. Deliver the modified ServerHello to the client.
* @expect
*    1. The modified ServerHello can be packed and delivered.
*    2. The client rejects the ServerHello with an illegal session ID error.
*    3. The client sends a fatal illegal_parameter alert.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC056(void)
{
    HITLS_Config *config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    uint32_t sendLen = sizeof(sendBuf);

    FRAME_Init();
    SetDtls13FrameType(&serverHelloType, REC_TYPE_HANDSHAKE, SERVER_HELLO);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(config, 0), HITLS_SUCCESS);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(config), HITLS_SUCCESS);

    client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtls13BufferedHsMsg(client, true, SERVER_HELLO, &serverHelloMsg), HITLS_SUCCESS);

    for (uint32_t i = 0; i < sizeof(sessionId); i++) {
        sessionId[i] = (uint8_t)(i + 1u);
    }

    FRAME_ServerHelloMsg *serverHello = &serverHelloMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(FRAME_ModifyMsgArray8(sessionId, sizeof(sessionId), &serverHello->sessionId,
        &serverHello->sessionIdSize), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_PackMsg(&serverHelloType, &serverHelloMsg, sendBuf, sizeof(sendBuf), &sendLen), HITLS_SUCCESS);

    FrameUioUserData *clientIoUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIoUserData != NULL);
    clientIoUserData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, sendBuf, sendLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC057
* @spec -
* @title DTLS1.3/DTLS1.2 client sends DTLS1.2 session id without PSK extension.
* @precon nan
* @brief
*    1. Establish a DTLS1.2-only stateful session.
*    2. Create a DTLS1.3/DTLS1.2 client and set the DTLS1.2 session.
*    3. Stop after the second ClientHello reaches the server.
*    4. Parse ClientHello.
* @expect
*    1. ClientHello carries the previous DTLS1.2 session id.
*    2. ClientHello does not carry the pre_shared_key extension.
*    3. ClientHello supported_versions contains DTLS1.2 and DTLS1.3.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC057(void)
{
    FRAME_Init();
    HITLS_Config *dtls12ClientConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *dtls12ServerConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *resumeClientConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    FRAME_Msg clientHelloMsg = {0};
    FRAME_Type clientHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint32_t sessionIdSize = sizeof(sessionId);

    ASSERT_TRUE(dtls12ClientConfig != NULL && dtls12ServerConfig != NULL);
    SetDtlsHandshakeFrameType(&clientHelloType, HITLS_VERSION_DTLS13, CLIENT_HELLO);

    ASSERT_EQ(PrepareDtls12Session(dtls12ClientConfig, dtls12ServerConfig, &session, sessionId, &sessionIdSize),
        HITLS_SUCCESS);
    ASSERT_TRUE(sessionIdSize > 0);

    resumeClientConfig = NewDtls12AndDtls13Config();
    ASSERT_TRUE(resumeClientConfig != NULL);
    client = FRAME_CreateLink(resumeClientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(dtls12ServerConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtlsBufferedHsMsg(server, true, HITLS_VERSION_DTLS13, CLIENT_HELLO, &clientHelloMsg),
        HITLS_SUCCESS);

    FRAME_ClientHelloMsg *clientHello = &clientHelloMsg.body.hsMsg.body.clientHello;
    ASSERT_TRUE(DtlsFrameSessionIdEquals(&clientHello->sessionIdSize, &clientHello->sessionId, sessionId,
        sessionIdSize));
    ASSERT_EQ(clientHello->psks.exState, MISSING_FIELD);
    ASSERT_TRUE(DtlsClientHelloHasSupportedVersion(clientHello, HITLS_VERSION_DTLS12));
    ASSERT_TRUE(DtlsClientHelloHasSupportedVersion(clientHello, HITLS_VERSION_DTLS13));

EXIT:
    FRAME_CleanMsg(&clientHelloType, &clientHelloMsg);
    HITLS_CFG_FreeConfig(dtls12ClientConfig);
    HITLS_CFG_FreeConfig(dtls12ServerConfig);
    HITLS_CFG_FreeConfig(resumeClientConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC058
* @spec -
* @title DTLS1.3 ServerHello without DTLS1.2 session id continues as a full DTLS1.3 handshake.
* @precon nan
* @brief
*    1. Establish a DTLS1.2-only stateful session.
*    2. Create a DTLS1.3/DTLS1.2 client and server.
*    3. Set the DTLS1.2 session on the client and stop after ServerHello.
*    4. Parse ServerHello, then continue the handshake.
* @expect
*    1. ServerHello selects DTLS1.3 and does not echo the ClientHello session id.
*    2. The handshake completes as DTLS1.3.
*    3. The DTLS1.2 session is not marked as resumed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC058(void)
{
    FRAME_Init();
    HITLS_Config *dtls12ClientConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *dtls12ServerConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *resumeClientConfig = NULL;
    HITLS_Config *resumeServerConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint32_t sessionIdSize = sizeof(sessionId);

    ASSERT_TRUE(dtls12ClientConfig != NULL && dtls12ServerConfig != NULL);
    SetDtlsHandshakeFrameType(&serverHelloType, HITLS_VERSION_DTLS13, SERVER_HELLO);

    ASSERT_EQ(PrepareDtls12Session(dtls12ClientConfig, dtls12ServerConfig, &session, sessionId, &sessionIdSize),
        HITLS_SUCCESS);
    resumeClientConfig = NewDtls12AndDtls13Config();
    resumeServerConfig = NewDtls12AndDtls13Config();
    ASSERT_TRUE(resumeClientConfig != NULL && resumeServerConfig != NULL);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(resumeClientConfig), HITLS_SUCCESS);

    client = FRAME_CreateLink(resumeClientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(resumeServerConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtlsBufferedHsMsg(client, true, HITLS_VERSION_DTLS13, SERVER_HELLO, &serverHelloMsg),
        HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverHello = &serverHelloMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(serverHello->supportedVersion.data.data, HITLS_VERSION_DTLS13);
    ASSERT_EQ(serverHello->sessionIdSize.data, 0);
    ASSERT_EQ(serverHello->sessionId.size, 0);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(DtlsCheckNegotiatedVersionAndResume(client, HITLS_VERSION_DTLS13, false), HITLS_SUCCESS);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(dtls12ClientConfig);
    HITLS_CFG_FreeConfig(dtls12ServerConfig);
    HITLS_CFG_FreeConfig(resumeClientConfig);
    HITLS_CFG_FreeConfig(resumeServerConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC059
* @spec -
* @title DTLS1.2 ServerHello echoing a DTLS1.2 session id resumes the DTLS1.2 session.
* @precon nan
* @brief
*    1. Establish a DTLS1.2-only stateful session.
*    2. Create a DTLS1.3/DTLS1.2 client and a DTLS1.2-only server with the previous cache.
*    3. Set the DTLS1.2 session on the client and stop after ServerHello.
*    4. Parse ServerHello, then continue the handshake.
* @expect
*    1. ServerHello selects DTLS1.2 and echoes the ClientHello session id.
*    2. The handshake completes as DTLS1.2 session resumption.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC059(void)
{
    FRAME_Init();
    HITLS_Config *dtls12ClientConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *dtls12ServerConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *resumeClientConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint32_t sessionIdSize = sizeof(sessionId);

    ASSERT_TRUE(dtls12ClientConfig != NULL && dtls12ServerConfig != NULL);
    SetDtlsHandshakeFrameType(&serverHelloType, HITLS_VERSION_DTLS12, SERVER_HELLO);

    ASSERT_EQ(PrepareDtls12Session(dtls12ClientConfig, dtls12ServerConfig, &session, sessionId, &sessionIdSize),
        HITLS_SUCCESS);
    resumeClientConfig = NewDtls12AndDtls13Config();
    ASSERT_TRUE(resumeClientConfig != NULL);

    client = FRAME_CreateLink(resumeClientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(dtls12ServerConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtlsBufferedHsMsg(client, true, HITLS_VERSION_DTLS12, SERVER_HELLO, &serverHelloMsg),
        HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverHello = &serverHelloMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(serverHello->version.data, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(DtlsFrameSessionIdEquals(&serverHello->sessionIdSize, &serverHello->sessionId, sessionId,
        sessionIdSize));

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(DtlsCheckNegotiatedVersionAndResume(client, HITLS_VERSION_DTLS12, true), HITLS_SUCCESS);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(dtls12ClientConfig);
    HITLS_CFG_FreeConfig(dtls12ServerConfig);
    HITLS_CFG_FreeConfig(resumeClientConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC060
* @spec -
* @title DTLS1.3/DTLS1.2 server selects DTLS1.3 full handshake for a DTLS1.2 session-id ClientHello.
* @precon nan
* @brief
*    1. Establish a DTLS1.2-only stateful session.
*    2. Create a new DTLS1.3/DTLS1.2 client and server.
*    3. Set the DTLS1.2 session on the client and stop after ServerHello.
*    4. Parse ServerHello, then continue the handshake.
* @expect
*    1. The server selects DTLS1.3 and does not echo the ClientHello session id.
*    2. The handshake completes as a full DTLS1.3 handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC060(void)
{
    FRAME_Init();
    HITLS_Config *dtls12ClientConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *dtls12ServerConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *resumeClientConfig = NULL;
    HITLS_Config *resumeServerConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint32_t sessionIdSize = sizeof(sessionId);

    ASSERT_TRUE(dtls12ClientConfig != NULL && dtls12ServerConfig != NULL);
    SetDtlsHandshakeFrameType(&serverHelloType, HITLS_VERSION_DTLS13, SERVER_HELLO);

    ASSERT_EQ(PrepareDtls12Session(dtls12ClientConfig, dtls12ServerConfig, &session, sessionId, &sessionIdSize),
        HITLS_SUCCESS);
    resumeClientConfig = NewDtls12AndDtls13Config();
    resumeServerConfig = NewDtls12AndDtls13Config();
    ASSERT_TRUE(resumeClientConfig != NULL && resumeServerConfig != NULL);
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(resumeClientConfig), HITLS_SUCCESS);

    client = FRAME_CreateLink(resumeClientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(resumeServerConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtlsBufferedHsMsg(client, true, HITLS_VERSION_DTLS13, SERVER_HELLO, &serverHelloMsg),
        HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverHello = &serverHelloMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(serverHello->supportedVersion.data.data, HITLS_VERSION_DTLS13);
    ASSERT_EQ(serverHello->sessionIdSize.data, 0);
    ASSERT_EQ(serverHello->sessionId.size, 0);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(DtlsCheckNegotiatedVersionAndResume(client, HITLS_VERSION_DTLS13, false), HITLS_SUCCESS);

EXIT:
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(dtls12ClientConfig);
    HITLS_CFG_FreeConfig(dtls12ServerConfig);
    HITLS_CFG_FreeConfig(resumeClientConfig);
    HITLS_CFG_FreeConfig(resumeServerConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC061
* @spec -
* @title DTLS1.3/DTLS1.2 client resumes DTLS1.2 when the new server disables DTLS1.3.
* @precon nan
* @brief
*    1. Establish a DTLS1.2-only stateful session.
*    2. Create a DTLS1.3/DTLS1.2 client and a new DTLS1.2-only server.
*    3. Provide the previous session through the server session-get callback.
*    4. Set the DTLS1.2 session on the client.
*    5. Parse ServerHello and continue the handshake.
* @expect
*    1. ServerHello selects DTLS1.2 and echoes the ClientHello session id.
*    2. The previous DTLS1.2 session is resumed.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC061(void)
{
    FRAME_Init();
    HITLS_Config *dtls12ClientConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *dtls12ServerConfig = HITLS_CFG_NewDTLS12Config();
    HITLS_Config *resumeClientConfig = NULL;
    HITLS_Config *resumeServerConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    FRAME_Msg serverHelloMsg = {0};
    FRAME_Type serverHelloType = {0};
    uint8_t sessionId[HITLS_SESSION_ID_MAX_SIZE] = {0};
    uint32_t sessionIdSize = sizeof(sessionId);

    ASSERT_TRUE(dtls12ClientConfig != NULL && dtls12ServerConfig != NULL);
    SetDtlsHandshakeFrameType(&serverHelloType, HITLS_VERSION_DTLS12, SERVER_HELLO);

    ASSERT_EQ(PrepareDtls12Session(dtls12ClientConfig, dtls12ServerConfig, &session, sessionId, &sessionIdSize),
        HITLS_SUCCESS);
    resumeClientConfig = NewDtls12AndDtls13Config();
    resumeServerConfig = NewDtls12AndDtls13Config();
    ASSERT_TRUE(resumeClientConfig != NULL && resumeServerConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetVersionForbid(resumeServerConfig, DTLS13_VERSION_BIT), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionCacheMode(resumeServerConfig,
        HITLS_SESS_CACHE_SERVER | HITLS_SESS_DISABLE_INTERNAL_LOOKUP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetSessionGetCb(resumeServerConfig, DtlsLowVersionResumeSessionGetCb), HITLS_SUCCESS);
    g_dtlsLowVersionResumeSession = session;

    client = FRAME_CreateLink(resumeClientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(resumeServerConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(client->ssl, session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    ASSERT_EQ(ParseDtlsBufferedHsMsg(client, true, HITLS_VERSION_DTLS12, SERVER_HELLO, &serverHelloMsg),
        HITLS_SUCCESS);
    FRAME_ServerHelloMsg *serverHello = &serverHelloMsg.body.hsMsg.body.serverHello;
    ASSERT_EQ(serverHello->version.data, HITLS_VERSION_DTLS12);
    ASSERT_TRUE(DtlsFrameSessionIdEquals(&serverHello->sessionIdSize, &serverHello->sessionId, sessionId,
        sessionIdSize));

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(DtlsCheckNegotiatedVersionAndResume(client, HITLS_VERSION_DTLS12, true), HITLS_SUCCESS);

EXIT:
    g_dtlsLowVersionResumeSession = NULL;
    FRAME_CleanMsg(&serverHelloType, &serverHelloMsg);
    HITLS_CFG_FreeConfig(dtls12ClientConfig);
    HITLS_CFG_FreeConfig(dtls12ServerConfig);
    HITLS_CFG_FreeConfig(resumeClientConfig);
    HITLS_CFG_FreeConfig(resumeServerConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC062
* @spec RFC 7919
* @title DTLS1.3 establishes a connection with an FFDHE key exchange group.
* @precon nan
* @brief
*    1. Create DTLS1.3 client and server configurations.
*    2. Configure both peers with the same FFDHE group.
*    3. Establish a UDP frame connection and exchange application data.
* @expect
*    1. The handshake succeeds and negotiates the configured FFDHE group.
*    2. The server receives the application data unchanged.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC062(int group)
{
    FRAME_Init();
    HITLS_Config *clientConfig = HITLS_CFG_NewDTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewDTLS13Config();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    uint16_t namedGroup = (uint16_t)group;
    uint8_t writeData[] = "DTLS1.3 FFDHE";
    uint8_t readData[sizeof(writeData)] = {0};
    uint32_t writeLen = 0;
    uint32_t readLen = 0;

    ASSERT_TRUE(clientConfig != NULL && serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetGroups(clientConfig, &namedGroup, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverConfig, &namedGroup, 1), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL && server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->negotiatedInfo.negotiatedGroup, namedGroup);
    ASSERT_EQ(server->ssl->negotiatedInfo.negotiatedGroup, namedGroup);

    ASSERT_EQ(HITLS_Write(client->ssl, writeData, sizeof(writeData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(writeLen, sizeof(writeData));
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(server->ssl, readData, sizeof(readData), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(writeData));
    ASSERT_EQ(memcmp(writeData, readData, readLen), 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static void Test_CorruptServerHelloKeyShare(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize,
    void *userData)
{
    (void)ctx;
    (void)userData;
    FRAME_Type frameType = {0};
    SetDtls13FrameType(&frameType, REC_TYPE_HANDSHAKE, SERVER_HELLO);
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_DTLS13;
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen), HITLS_SUCCESS);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    uint8_t *keyExchange = serverMsg->keyShare.data.keyExchange.data;
    uint32_t keyExchangeLen = serverMsg->keyShare.data.keyExchange.size;
    ASSERT_TRUE(keyExchange != NULL && keyExchangeLen > 0);
    keyExchange[keyExchangeLen - 1] ^= 0xFF;
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC063
* @title   SAL_CRYPT_CalcEcdhSharedSecret fails on the client; verify the client sends a fatal alert and disconnects.
* @precon  nan
* @brief   1. Register a RecWrapper that corrupts the key_share public key in the ServerHello as the server sends it.
*          2. Establish a DTLS1.3 handshake. The client receives a corrupted ServerHello and ECDH fails.
* @expect  1. The handshake fails.
*          2. The client sends a fatal alert (ALERT_FLAG_SEND) and transitions to CM_STATE_ALERTED.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_HANDSHAKE_CONSISTENCY_FUNC_TC063(void)
{
    HITLS_Config *clientConfig = NULL;
    HITLS_Config *serverConfig = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    clientConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(clientConfig != NULL);
    serverConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(clientConfig, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetTicketNums(serverConfig, 0), HITLS_SUCCESS);
    /* Force ECDH group (secp256r1) so that SAL_CRYPT_CalcEcdhSharedSecret is used
     * instead of KEM, and the corrupted key causes the ECDH computation to fail. */
    uint16_t ecdheGroup = HITLS_EC_GROUP_SECP256R1;
    ASSERT_EQ(HITLS_CFG_SetGroups(clientConfig, &ecdheGroup, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverConfig, &ecdheGroup, 1), HITLS_SUCCESS);

    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_CorruptServerHelloKeyShare};
    RegisterWrapper(wrapper);

    client = FRAME_CreateLink(clientConfig, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverConfig, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ALERT_Info alert = {0};
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
    ASSERT_EQ(client->ssl->state, CM_STATE_ALERTED);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
