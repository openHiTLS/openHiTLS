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

#include <semaphore.h>
#include <unistd.h>
#include "securec.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_session.h"
#include "hitls_error.h"
#include "session.h"
#include "hlt.h"
#include "alert.h"
#include "frame_msg.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "process.h"
#include "hitls_type.h"
#include "session_type.h"
#include "cert_mgr.h"
#include "cert_mgr_ctx.h"
#include "hitls_cert_type.h"
#include "hs_extensions.h"
#include "rec_wrapper.h"
/* END_HEADER */

static uint32_t g_uiPort = 2569;
#define READ_BUF_SIZE 20
#define TEMP_DATA_LEN 1024

int32_t GetSessionCacheMode(HLT_Ctx_Config *config)
{
    return config->setSessionCache;
}

static void FrameCallBack_SerrverHello_MasteKey_Add(void *msg, void *userData)
{
    // ServerHello exception: The masterkey extension is added to the sent ServerHello message.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverhello = &frameMsg->body.hsMsg.body.serverHello;
    serverhello->extensionLen.state = INITIAL_FIELD;
    serverhello->extendedMasterSecret.exState = INITIAL_FIELD;
    serverhello->extendedMasterSecret.exType.state = INITIAL_FIELD;
    serverhello->extendedMasterSecret.exType.data = HS_EX_TYPE_EXTENDED_MASTER_SECRET;
    serverhello->extendedMasterSecret.exLen.state = INITIAL_FIELD;
    serverhello->extendedMasterSecret.exLen.data = 0u;
EXIT:
    return;
}
static void FrameCallBack_SerrverHello_MasteKey_MISS(void *msg, void *userData)
{
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverhello = &frameMsg->body.hsMsg.body.serverHello;

    serverhello->extendedMasterSecret.exState = MISSING_FIELD;
EXIT:
    return;
}

/** @
* @test SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC006
* @title    When the session is resumed, the client receives the server hello message that carries the master key
*            extension.
* @precon nan
* @brief    1. The client and server do not support the extension connection establishment. Expected result 1 is
*               obtained.
*           2. Disconnect the connection, save the session, and restore the session.
*           3. During session restoration, modify the server hello message to carry the master secret extension.
*              Expected result 2 is obtained.
*           4. Establish a connection and observe the connection establishment status. (Expected result 3)
* @expect   1. The connection is set up successfully.
*           2. The modification is successful.
*           3. Session restoration fails and the handshake is interrupted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC006(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    int32_t cnt = 1;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_SetExtendedMasterSecretSupport(clientCtxConfig, false);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // 1. The client and server do not support the extension connection establishment.
    HLT_SetExtendedMasterSecretSupport(clientCtxConfig, false);

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        DataChannelParam channelParam;
        channelParam.port = g_uiPort;
        channelParam.type = connType;
        channelParam.isBlock = true;
        sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
        ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
        remoteProcess->connFd = sockFd.peerFd;
        localProcess->connFd = sockFd.srcFd;
        remoteProcess->connType = connType;
        localProcess->connType = connType;
        int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);

        HLT_Ssl_Config *serverSslConfig;
        serverSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(serverSslConfig != NULL);
        serverSslConfig->sockFd = remoteProcess->connFd;
        serverSslConfig->connType = connType;
        ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
        HLT_RpcTlsAccept(remoteProcess, serverSslId);
        void *clientSsl = HLT_TlsNewSsl(clientConfig);
        ASSERT_TRUE(clientSsl != NULL);

        HLT_Ssl_Config *clientSslConfig;
        clientSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(clientSslConfig != NULL);
        clientSslConfig->sockFd = localProcess->connFd;
        clientSslConfig->connType = connType;

        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            HLT_CleanFrameHandle();
            HLT_FrameHandle handle = {0};
            handle.pointType = POINT_RECV;
            handle.userData = (void *)&handle;
            handle.expectReType = REC_TYPE_HANDSHAKE;

            handle.expectHsType = SERVER_HELLO;
            // 3. During session restoration, modify the server hello message to carry the master key extension.
            handle.frameCallBack = FrameCallBack_SerrverHello_MasteKey_Add;
            handle.ctx = clientSsl;
            ASSERT_TRUE(HLT_SetFrameHandle(&handle) == 0);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            // 4. Establish a connection and observe the connection establishment status.
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) != 0);
        } else {
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
            ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
            ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
            ASSERT_TRUE(readLen == strlen(writeBuf));
            ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
            //  2. Disconnect the connection, save the session, and restore the session.
            ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
            ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
            HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
            HLT_CloseFd(sockFd.srcFd, localProcess->connType);

            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }

        cnt++;
    } while (cnt < 3);
EXIT:
    HLT_CleanFrameHandle();
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test     SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC007
* @title    When the session is resumed, the client receives a server hello message that does not carry the master key
*            extension.
* @precon nan
* @brief    1. The client and server support the extension connection establishment. Expected result 1 is obtained.
*           2. Disconnect the connection, save the session, and restore the session.
*           3. During session recovery, modify the server hello command on the server to cause the master key extension
*              to be lost. Expected result 2 is obtained.
*           4. Establish a connection and observe the connection setup status. (Expected result 3)
* @expect   1. The connection is set up successfully.
*           2. The modification is successful.
*           3. Session restoration fails and the handshake is interrupted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC007(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    int32_t cnt = 1;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);
    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        DataChannelParam channelParam;
        channelParam.port = g_uiPort;
        channelParam.type = connType;
        channelParam.isBlock = true;
        sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
        ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
        remoteProcess->connFd = sockFd.peerFd;
        localProcess->connFd = sockFd.srcFd;
        remoteProcess->connType = connType;
        localProcess->connType = connType;

        int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);

        HLT_Ssl_Config *serverSslConfig;
        serverSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(serverSslConfig != NULL);
        serverSslConfig->sockFd = remoteProcess->connFd;
        serverSslConfig->connType = connType;
        ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
        HLT_RpcTlsAccept(remoteProcess, serverSslId);

        void *clientSsl = HLT_TlsNewSsl(clientConfig);
        ASSERT_TRUE(clientSsl != NULL);

        HLT_Ssl_Config *clientSslConfig;
        clientSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(clientSslConfig != NULL);
        clientSslConfig->sockFd = localProcess->connFd;
        clientSslConfig->connType = connType;

        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            HLT_CleanFrameHandle();
            HLT_FrameHandle handle = {0};
            handle.pointType = POINT_RECV;
            handle.userData = (void *)&handle;
            handle.expectReType = REC_TYPE_HANDSHAKE;
            handle.expectHsType = SERVER_HELLO;
            /* 3. During session recovery, modify the server hello command on the server to cause the master key
             * extension to be lost. */
            handle.frameCallBack = FrameCallBack_SerrverHello_MasteKey_MISS;
            handle.ctx = clientSsl;
            ASSERT_TRUE(HLT_SetFrameHandle(&handle) == 0);

            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            // 4. Establish a connection and observe the connection setup status.
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) != 0);
        } else {
            // 1. The client and server support the extension connection establishment.
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
            ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
            ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
            ASSERT_TRUE(readLen == strlen(writeBuf));
            ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);

            ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
            ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
            HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
            // 2. Disconnect the connection, save the session, and restore the session.
            HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
            HLT_CloseFd(sockFd.srcFd, localProcess->connType);

            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        cnt++;
    } while (cnt < 3);
EXIT:
    HLT_CleanFrameHandle();
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test     SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC008
* @title    Resume sessions on servers that do not support session recovery.
* @precon nan
* @brief    1. The client and server support the extension connection establishment. Disconnect the connection and save
*             the session.
*            2. Apply for another server that does not support the extension and establish a connection. Expected result
*                2 is obtained.
* @expect   1. The connection is successfully established.
*           2. Session restoration fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC008(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    HLT_FD sockFd2 = {0};
    int cunt = 1;
    int32_t serverConfigId = 0;
    int32_t serverConfigId2 = 0;

    HITLS_Session *session = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_Ctx_Config *serverCtxConfig2 = HLT_NewCtxConfig(NULL, "SERVER");
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
    serverConfigId2 = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    serverConfigId2 = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    // 2. Apply for another server that does not support the extension and establish a connection.
    HLT_SetExtendedMasterSecretSupport(serverCtxConfig2, false);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    do {
        if (session != NULL) {

            DataChannelParam channelParam2;
            channelParam2.port = g_uiPort;
            channelParam2.type = connType;
            channelParam2.isBlock = true;
            sockFd2 = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam2);
            ASSERT_TRUE((sockFd2.srcFd > 0) && (sockFd2.peerFd > 0));
            remoteProcess->connFd = sockFd2.peerFd;
            localProcess->connFd = sockFd2.srcFd;
            remoteProcess->connType = connType;
            localProcess->connType = connType;

            int32_t serverSslId2 = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId2);

            HLT_Ssl_Config *serverSslConfig2;
            serverSslConfig2 = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(serverSslConfig2 != NULL);
            serverSslConfig2->sockFd = remoteProcess->connFd;
            serverSslConfig2->connType = connType;
            ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId2, serverSslConfig2) == 0);
            HLT_RpcTlsAccept(remoteProcess, serverSslId2);

            void *clientSsl = HLT_TlsNewSsl(clientConfig);
            ASSERT_TRUE(clientSsl != NULL);

            HLT_Ssl_Config *clientSslConfig;
            clientSslConfig = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(clientSslConfig != NULL);
            clientSslConfig->sockFd = localProcess->connFd;
            clientSslConfig->connType = connType;

            HLT_TlsSetSsl(clientSsl, clientSslConfig);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) != 0);
        } else {
            DataChannelParam channelParam;
            channelParam.port = g_uiPort;
            channelParam.type = connType;
            channelParam.isBlock = true;
            sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
            ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
            remoteProcess->connFd = sockFd.peerFd;
            localProcess->connFd = sockFd.srcFd;
            remoteProcess->connType = connType;
            localProcess->connType = connType;
            int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);
            HLT_Ssl_Config *serverSslConfig;
            serverSslConfig = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(serverSslConfig != NULL);
            serverSslConfig->sockFd = remoteProcess->connFd;
            serverSslConfig->connType = connType;
            ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
            HLT_RpcTlsAccept(remoteProcess, serverSslId);
            void *clientSsl = HLT_TlsNewSsl(clientConfig);
            ASSERT_TRUE(clientSsl != NULL);
            HLT_Ssl_Config *clientSslConfig;
            clientSslConfig = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(clientSslConfig != NULL);
            clientSslConfig->sockFd = localProcess->connFd;
            clientSslConfig->connType = connType;
            HLT_TlsSetSsl(clientSsl, clientSslConfig);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);

            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);
        cunt++;
    } while (cunt <= 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

static void Test_ClientHelloWithnoEMS(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS12;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->extendedMasterSecret.exState = MISSING_FIELD;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/** @
* @test     SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC009
* @title    Resume sessions that both support no EMS on the client and server
* @precon nan
* @brief    1. The client and server that does not support the extension connection establishment.
*              Disconnect the connection and save the session.
*            2. Apply for another server that does not support the extension and establish a connection. Expected result
*                2 is obtained.
* @expect   1. The connection is successfully established.
*           2. Session restoration success.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC7627_CONSISTENCY_EXTENDED_MASTER_SECRET_FUNC_TC009(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_FD sockFd = {0};
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    int32_t cnt = 1;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_SetExtendedMasterSecretSupport(clientCtxConfig, false);

    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetExtendedMasterSecretSupport(serverCtxConfig, false);

#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    do {
        if (session != NULL) {
            ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
            ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
        } else {
            RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ClientHelloWithnoEMS};
            RegisterWrapper(wrapper);
        }
        DataChannelParam channelParam;
        channelParam.port = g_uiPort;
        channelParam.type = connType;
        channelParam.isBlock = true;
        sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
        ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
        remoteProcess->connFd = sockFd.peerFd;
        localProcess->connFd = sockFd.srcFd;
        remoteProcess->connType = connType;
        localProcess->connType = connType;
        int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);

        HLT_Ssl_Config *serverSslConfig;
        serverSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(serverSslConfig != NULL);
        serverSslConfig->sockFd = remoteProcess->connFd;
        serverSslConfig->connType = connType;
        ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
        HLT_RpcTlsAccept(remoteProcess, serverSslId);
        void *clientSsl = HLT_TlsNewSsl(clientConfig);
        ASSERT_TRUE(clientSsl != NULL);

        HLT_Ssl_Config *clientSslConfig;
        clientSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(clientSslConfig != NULL);
        clientSslConfig->sockFd = localProcess->connFd;
        clientSslConfig->connType = connType;

        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            bool isReused = false;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_TRUE(isReused == true);
        } else {
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
            ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
            ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
            ASSERT_TRUE(readLen == strlen(writeBuf));
            ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
            ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
            ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
            HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
            HLT_CloseFd(sockFd.srcFd, localProcess->connType);

            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }

        cnt++;
    } while (cnt < 3);
EXIT:
    ClearWrapper();
    HLT_CleanFrameHandle();
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */