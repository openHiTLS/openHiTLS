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

#include <string.h>
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hs_ctx.h"
#include "hs_common.h"
#include "change_cipher_spec.h"
#include "stub_utils.h"

/* Stub definitions - works with dynamic linking (.dylib/.so)
 * With shared libraries, dlsym(RTLD_NEXT) can find the real implementation at runtime
 * NOTE: STUB mechanism disabled for macOS static linking compatibility
 * Using direct state polling approach instead (see FRAME_CreateConnection)
 */
STUB_DEFINE_RET2(int32_t, HS_ChangeState, TLS_Ctx *, uint32_t);

#include "frame_tls.h"
#include "frame_io.h"
#include "frame_link.h"
#include "simulate_io.h"
#include "parse.h"
#include "rec_wrapper.h"
#define ENTER_USER_SPECIFY_STATE (HITLS_UIO_FAIL_START + 0xFFFF)

#define READ_BUF_SIZE 18432
HITLS_HandshakeState g_nextState;
bool g_isClient;

int32_t FRAME_TrasferMsgBetweenLink(FRAME_LinkObj *linkA, FRAME_LinkObj *linkB)
{
    int32_t ret = HITLS_SUCCESS;
    uint32_t readLen = 0;
    char *buffer = BSL_SAL_Calloc(1u, MAX_RECORD_LENTH);
    if (buffer == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    // linkA->io->userData to buffer
    ret = FRAME_TransportSendMsg(linkA->io, buffer, MAX_RECORD_LENTH, &readLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buffer);
        return ret;
    }
    if (readLen == 0) {
        BSL_SAL_FREE(buffer);
        return HITLS_SUCCESS;
    }

    // buffer to linkB->io->userData
    ret = FRAME_TransportRecMsg(linkB->io, buffer, readLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(buffer);
        return ret;
    }

    BSL_SAL_FREE(buffer);
    return HITLS_SUCCESS;
}

static int32_t STUB_ChangeState(TLS_Ctx *ctx, uint32_t nextState)
{
    real_HS_ChangeState_func_t realFunc = get_real_HS_ChangeState();
    int32_t ret = HITLS_SUCCESS;
    if (realFunc != NULL) {
        ret = realFunc(ctx, nextState);
    } else {
        HS_Ctx *hsCtx = (HS_Ctx *)ctx->hsCtx;
        hsCtx->state = nextState;
    }
    if (ret != HITLS_SUCCESS || g_nextState != nextState || g_isClient != ctx->isClient) {
        return ret;
    }
    HS_CleanMsg(ctx->hsCtx->hsMsg);
    ctx->hsCtx->hsMsg = NULL;
    return HITLS_REC_NORMAL_RECV_BUF_EMPTY;
}

static bool StateCompare(FRAME_LinkObj *link, bool isClient, HITLS_HandshakeState state)
{
    if ((isClient == link->ssl->isClient) && (link->ssl->hsCtx != NULL) && (link->ssl->hsCtx->state == state)) {
        if (state != TRY_RECV_FINISH && state != TRY_RECV_CERTIFICATE) {
            return true;
        }
        /* In tls1.3, if the single-end verification is used, the server may receive the CCS message in the TRY_RECV_FINISH phase */
        if (state == TRY_RECV_FINISH){
            if (link->needStopBeforeRecvCCS || CCS_IsRecv(link->ssl) == true ||
                ((link->ssl->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13 ||
                  link->ssl->config.tlsConfig.maxVersion == HITLS_VERSION_DTLS13) && isClient == true) ||
                ((link->ssl->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13 ||
                  link->ssl->config.tlsConfig.maxVersion == HITLS_VERSION_DTLS13) &&
                link->ssl->config.tlsConfig.isSupportClientVerify == true)) {
            return true;
            }
        }
        // In tls1.3, the server may receive the CCS message in the TRY_RECV_CERTIFICATIONATE phase
        if (state == TRY_RECV_CERTIFICATE){
            if (link->needStopBeforeRecvCCS || CCS_IsRecv(link->ssl) == true ||
                link->ssl->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11 ||
#ifdef HITLS_TLS_PROTO_TLS13
                link->ssl->hsCtx->haveHrr == true ||
#endif /* HITLS_TLS_PROTO_TLS13 */
                link->ssl->config.tlsConfig.maxVersion != HITLS_VERSION_TLS13 || isClient == true) {
                return true;
            }
        }
    }
    return false;
}

static bool FrameIsDtls13Link(const FRAME_LinkObj *link)
{
    return link != NULL && link->ssl != NULL && link->ssl->negotiatedInfo.version == HITLS_VERSION_DTLS13;
}

static bool FrameHasPendingRead(FRAME_LinkObj *link)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);
    if (ioUserData != NULL && ioUserData->recMsg.len != 0) {
        return true;
    }

    bool isPending = false;
    if (HITLS_ReadHasPending(link->ssl, &isPending) != HITLS_SUCCESS) {
        return false;
    }
    return isPending;
}

static bool FrameHasPendingSend(FRAME_LinkObj *link)
{
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);
    return ioUserData != NULL && ioUserData->sndMsg.len != 0;
}

static int32_t FrameReadDtls13ControlMsg(FRAME_LinkObj *link)
{
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t ret = HITLS_Read(link->ssl, readBuf, READ_BUF_SIZE, &readLen);
    if (ret == HITLS_SUCCESS || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY) {
        return HITLS_SUCCESS;
    }
    return ret;
}

static int32_t FrameDrainDtls13PostHandshake(FRAME_LinkObj *client, FRAME_LinkObj *server)
{
    if (!FrameIsDtls13Link(client) || !FrameIsDtls13Link(server)) {
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < 8; i++) {
        bool hasProgress = false;
        int32_t ret = HITLS_SUCCESS;
        if (FrameHasPendingRead(client)) {
            ret = FrameReadDtls13ControlMsg(client);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            hasProgress = true;
        }
        if (FrameHasPendingRead(server)) {
            ret = FrameReadDtls13ControlMsg(server);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            hasProgress = true;
        }
        if (FrameHasPendingSend(server)) {
            ret = FRAME_TrasferMsgBetweenLink(server, client);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            hasProgress = true;
        }
        if (FrameHasPendingSend(client)) {
            ret = FRAME_TrasferMsgBetweenLink(client, server);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
            hasProgress = true;
        }
        if (!hasProgress) {
            return HITLS_SUCCESS;
        }
    }
    return HITLS_SUCCESS;
}

int32_t FRAME_CreateConnection(FRAME_LinkObj *client, FRAME_LinkObj *server, bool isClient, HITLS_HandshakeState state)
{
    int32_t clientRet;
    int32_t serverRet;
    int32_t ret;
    uint32_t count = 0;

    if (client == NULL || server == NULL) {
        return HITLS_NULL_INPUT;
    }

    // Apply registered wrappers EARLY - before first HITLS_Connect/Accept
    // This initializes recCtx and installs wrappers before handshake begins
    // Matches HLT framework pattern in hlt_func.c:LocalProcessTlsInit
    ApplyWrapperToConnectionEarly(client->ssl);
    ApplyWrapperToConnectionEarly(server->ssl);

    g_isClient = isClient;
    g_nextState = state;
    STUB_REPLACE(HS_ChangeState, STUB_ChangeState);

    do {
        // Check whether the client needs to be stopped. If yes, return success
        if (StateCompare(client, isClient, state)) {
            ret = HITLS_SUCCESS;
            break;
        }

        // Invoke the client to establish a connection
        clientRet = HITLS_Connect(client->ssl);
        if (clientRet != HITLS_SUCCESS) {
            ret = clientRet;
            if ((clientRet != HITLS_REC_NORMAL_IO_BUSY) && (clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        // Transfer the message to the server
        ret = FRAME_TrasferMsgBetweenLink(client, server);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        // Check whether the server needs to be stopped. If yes, return success
        if (StateCompare(server, isClient, state)) {
            ret = HITLS_SUCCESS;
            break;
        }

        // Invoke the server to establish a connection
        serverRet = HITLS_Accept(server->ssl);
        if (serverRet != HITLS_SUCCESS) {
            ret = serverRet;
            if ((serverRet != HITLS_REC_NORMAL_IO_BUSY) && (serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        // Transfer the message to the client
        ret = FRAME_TrasferMsgBetweenLink(server, client);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        /* To receive TLS1.3 new session ticket messages */
        if (clientRet == HITLS_SUCCESS && client->ssl->config.tlsConfig.maxVersion == HITLS_VERSION_TLS13) {
            uint8_t readBuf[READ_BUF_SIZE] = {0};
            uint32_t readLen = 0;
            ret = HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen);
            // No application data. return HITLS_REC_NORMAL_RECV_BUF_EMPTY
            if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
                break;
            }
        }

        if (clientRet == HITLS_SUCCESS && client->ssl->config.tlsConfig.maxVersion == HITLS_VERSION_DTLS13) {
            ret = FrameDrainDtls13PostHandshake(client, server);
            if (ret != HITLS_SUCCESS) {
                break;
            }
        }

        // If the connection is set up on both sides, return success
        if (clientRet == HITLS_SUCCESS && serverRet == HITLS_SUCCESS) {
            ret = HITLS_SUCCESS;
            break;
        }

        count++;
        ret = HITLS_INTERNAL_EXCEPTION;
    // Prevent infinite loop. No more than 30 messages are exchanged between the client and server during the handshake
    } while (count < 30);

    //Check whether the hsCtx status meets the expectation. If hsCtx is destructed, HITLS_INTERNAL_EXCEPTION is returned
    if (state != HS_STATE_BUTT) {
        FRAME_LinkObj *point = (isClient) ? (client) : (server);
        if (point->ssl->hsCtx == NULL) {
            ret = HITLS_INTERNAL_EXCEPTION;
        } else if (point->ssl->hsCtx->state != state) {
            ret = HITLS_INTERNAL_EXCEPTION;
        }
    }

    STUB_RESTORE(HS_ChangeState);
    return ret;
}

int32_t FRAME_CreateRenegotiation(FRAME_LinkObj *linkA, FRAME_LinkObj *linkB)
{
    int32_t clientRet;
    int32_t serverRet;
    int32_t ret;
    uint32_t count = 0;
    // renegotiation signal
    uint8_t writeBuf[1] = {1};
    uint8_t readBuf[32] = {0}; // buffer for receive temporary messages, 32 bytes long
    uint32_t readBufLen = 0;

    if (linkA->ssl->state != CM_STATE_RENEGOTIATION) {
        return HITLS_SUCCESS;
    }

    do {
        uint32_t len = 0;
        clientRet = HITLS_Write(linkA->ssl, writeBuf, sizeof(writeBuf), &len);
        if (clientRet != HITLS_SUCCESS) {
            ret = clientRet;
            if ((clientRet != HITLS_REC_NORMAL_IO_BUSY) && (clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        ret = FRAME_TrasferMsgBetweenLink(linkA, linkB);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        readBufLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        serverRet = HITLS_Read(linkB->ssl, readBuf, sizeof(readBuf), &readBufLen);
        if (serverRet != HITLS_SUCCESS) {
            ret = serverRet;
            if ((serverRet != HITLS_REC_NORMAL_IO_BUSY) && (serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        ret = FRAME_TrasferMsgBetweenLink(linkB, linkA);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        // If the connection is set up on both sides, return success
        if (clientRet == HITLS_SUCCESS && serverRet == HITLS_SUCCESS &&
            linkA->ssl->state == CM_STATE_TRANSPORTING && linkB->ssl->state == CM_STATE_TRANSPORTING) {
            if ((readBufLen != sizeof(writeBuf)) ||
                (memcmp(writeBuf, readBuf, readBufLen) != 0)) {
                ret = HITLS_INTERNAL_EXCEPTION;
            } else {
                ret = HITLS_SUCCESS;
            }
            break;
        }

        count++;
        ret = HITLS_INTERNAL_EXCEPTION;
    // Prevent infinite loop. No more than 30 messages are exchanged between the client and server during the handshake
    } while (count < 30);

    return ret;
}

int32_t FRAME_CreateRenegotiationServer(FRAME_LinkObj *server, FRAME_LinkObj *client)
{
    int32_t clientRet;
    int32_t serverRet;
    int32_t ret;
    uint32_t count = 0;
    // renegotiation signal
    uint8_t readBuf[32] = {0}; // buffer for receive temporary messages, 32 bytes long
    uint32_t readBufLen = 0;

    if (server->ssl->state != CM_STATE_RENEGOTIATION) {
        return HITLS_SUCCESS;
    }
    do {
        readBufLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        serverRet = HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readBufLen);
        if (serverRet != HITLS_SUCCESS) {
            ret = serverRet;
            if ((serverRet != HITLS_REC_NORMAL_IO_BUSY) && (serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        ret = FRAME_TrasferMsgBetweenLink(server, client);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        readBufLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        clientRet = HITLS_Read(client->ssl, readBuf, sizeof(readBuf), &readBufLen);
        if (clientRet != HITLS_SUCCESS) {
            ret = clientRet;
            if ((clientRet != HITLS_REC_NORMAL_IO_BUSY) && (clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        ret = FRAME_TrasferMsgBetweenLink(client, server);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        // If the connection is set up on both sides, return success
        if (clientRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY && serverRet == HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
            server->ssl->state == CM_STATE_TRANSPORTING && client->ssl->state == CM_STATE_TRANSPORTING) {
            ret = HITLS_SUCCESS;
            break;
        }

        count++;
        ret = HITLS_INTERNAL_EXCEPTION;
    // Prevent infinite loop. No more than 30 messages are exchanged between the client and server during the handshake
    } while (count < 30);

    return ret;
}

int32_t FRAME_CreateRenegotiationState(FRAME_LinkObj *client, FRAME_LinkObj *server, bool isClient, HITLS_HandshakeState state)
{
    int32_t clientRet;
    int32_t serverRet;
    int32_t ret;
    uint32_t count = 0;
    // renegotiation signal
    uint8_t writeBuf[1] = {1};
    uint8_t readBuf[32] = {0}; // buffer for receive temporary messages, 32 bytes long
    uint32_t readBufLen = 0;

    if (client->ssl->state != CM_STATE_RENEGOTIATION) {
        return HITLS_SUCCESS;
    }

    g_isClient = isClient;
    g_nextState = state;
    STUB_REPLACE(HS_ChangeState, STUB_ChangeState);

    do {
        // Check whether the client needs to be stopped. If yes, return success
        if (StateCompare(client, isClient, state)) {
            ret = HITLS_SUCCESS;
            break;
        }
        uint32_t len = 0;
        clientRet = HITLS_Write(client->ssl, writeBuf, sizeof(writeBuf), &len);
        if (clientRet != HITLS_SUCCESS) {
            ret = clientRet;
            if ((clientRet != HITLS_REC_NORMAL_IO_BUSY) && (clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        ret = FRAME_TrasferMsgBetweenLink(client, server);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        // Check whether the server needs to be stopped. If yes, return success
        if (StateCompare(server, isClient, state)) {
            ret = HITLS_SUCCESS;
            break;
        }

        readBufLen = 0;
        memset(readBuf, 0, sizeof(readBuf));
        serverRet = HITLS_Read(server->ssl, readBuf, sizeof(readBuf), &readBufLen);
        if (serverRet != HITLS_SUCCESS) {
            ret = serverRet;
            if ((serverRet != HITLS_REC_NORMAL_IO_BUSY) && (serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY)) {
                break;
            }
        }

        ret = FRAME_TrasferMsgBetweenLink(server, client);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        // If the connection is set up on both sides, return success
        if (clientRet == HITLS_SUCCESS && serverRet == HITLS_SUCCESS &&
            client->ssl->state == CM_STATE_TRANSPORTING && server->ssl->state == CM_STATE_TRANSPORTING) {
            if ((readBufLen != sizeof(writeBuf)) ||
                (memcmp(writeBuf, readBuf, readBufLen) != 0)) {
                ret = HITLS_INTERNAL_EXCEPTION;
            } else {
                ret = HITLS_SUCCESS;
            }
            break;
        }

        count++;
        ret = HITLS_INTERNAL_EXCEPTION;
    // Prevent infinite loop. No more than 30 messages are exchanged between the client and server during the handshake
    } while (count < 30);

    //Check whether the hsCtx status meets the expectation. If hsCtx is destructed, HITLS_INTERNAL_EXCEPTION is returned
    if (state != HS_STATE_BUTT) {
        FRAME_LinkObj *point = (isClient) ? (client) : (server);
        if (point->ssl->hsCtx == NULL) {
            ret = HITLS_INTERNAL_EXCEPTION;
        } else if (point->ssl->hsCtx->state != state) {
            ret = HITLS_INTERNAL_EXCEPTION;
        }
    }
    STUB_RESTORE(HS_ChangeState);
    return ret;
}
