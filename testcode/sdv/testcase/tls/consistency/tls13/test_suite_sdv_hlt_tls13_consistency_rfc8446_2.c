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
#include "cert.h"
#include "process.h"
#include "securec.h"
#include "session_type.h"
#include "rec_wrapper.h"
#include "common_func.h"
#include "conn_init.h"
#include "hs_extensions.h"
#include "hitls_crypt_init.h"
#include "crypt_util_rand.h"
#include "alert.h"
/* END_HEADER */

#define PORT 23456
#define READ_BUF_SIZE (18 * 1024)

typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;       // Set the session to the client for session recovery.
    HITLS_TicketKeyCb serverKeyCb;
} ResumeTestInfo;

typedef struct{
    char *ClientCipherSuite;
    char *ServerCipherSuite;
    char *ClientGroup;
    char *ServerGroup;
    uint8_t ClientKeyExchangeMode;
    uint8_t ServerKeyExchangeMode;
    uint8_t psk[PSK_MAX_LEN];
    bool SetNothing;
    bool SuccessOrFail;
} SetInfo;

void SetConfig(HLT_Ctx_Config *clientconfig, HLT_Ctx_Config *serverconfig, SetInfo setInfo)
{
    if ( !setInfo.SetNothing ) {

        // Configure the server configuration.
        if (setInfo.ServerCipherSuite != NULL) {
            HLT_SetCipherSuites(serverconfig, setInfo.ServerCipherSuite);
        }
        if (setInfo.ServerGroup != NULL) {
            HLT_SetGroups(serverconfig, setInfo.ServerGroup);
        }
        memcpy_s(serverconfig->psk, PSK_MAX_LEN, setInfo.psk, sizeof(setInfo.psk));

        if ( (setInfo.ClientKeyExchangeMode & (TLS13_KE_MODE_PSK_WITH_DHE | TLS13_KE_MODE_PSK_ONLY)) != 0) {
            clientconfig->keyExchMode = setInfo.ClientKeyExchangeMode;
        }

        // Configure the client configuration.
        if (setInfo.ClientCipherSuite != NULL) {
            HLT_SetCipherSuites(clientconfig, setInfo.ClientCipherSuite);
        }
        if (setInfo.ClientGroup != NULL) {
            HLT_SetGroups(clientconfig, setInfo.ClientGroup);
        }
        memcpy_s(clientconfig->psk, PSK_MAX_LEN, setInfo.psk, sizeof(setInfo.psk));
        if ( (setInfo.ServerKeyExchangeMode & (TLS13_KE_MODE_PSK_WITH_DHE | TLS13_KE_MODE_PSK_ONLY)) != 0) {
            serverconfig->keyExchMode = setInfo.ServerKeyExchangeMode;
        }
    }
}

void ClientCreatConnectWithPara(HLT_FrameHandle *handle, SetInfo setInfo)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    // Create a process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // The local client and remote server listen on the TLS connection.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the config file.
    SetConfig(clientConfig, serverConfig, setInfo);

    // Listening connection.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    // Configure the interface for constructing abnormal messages.
    handle->ctx = clientRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);

    // Establish a connection.
    if ( setInfo.SuccessOrFail ) {
       ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) == 0);
    }else {
        ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) != 0);
    }

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

void ServerCreatConnectWithPara(HLT_FrameHandle *handle, SetInfo setInfo)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    // Create a process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // The local client and remote server listen on the TLS connection.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the config file.
    SetConfig(clientConfig, serverConfig, setInfo);

    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Insert abnormal message callback.
    handle->ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);

    // Client listening connection.
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLS1_3, clientConfig, NULL);

    if ( setInfo.SuccessOrFail ) {
       ASSERT_TRUE(clientRes != NULL);
    }else {
        ASSERT_TRUE(clientRes == NULL);
    }

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

void ResumeConnectWithPara(HLT_FrameHandle *handle, SetInfo setInfo)
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

    // Apply for the config context.
    void *clientConfig = HLT_TlsNewCtx(TLS1_3);
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the session restoration function.
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");

#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, TLS1_3, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, TLS1_3, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (cnt == 2) {
            SetConfig(clientCtxConfig, serverCtxConfig, setInfo);
            ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
            ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
        }
        DataChannelParam channelParam;
        channelParam.port = PORT;
        channelParam.type = TCP;
        channelParam.isBlock = true;
        sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
        ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
        remoteProcess->connFd = sockFd.peerFd;
        localProcess->connFd = sockFd.srcFd;
        remoteProcess->connType = TCP;
        localProcess->connType = TCP;

        // The server applies for the context.
        int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);

        HLT_Ssl_Config *serverSslConfig;
        serverSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(serverSslConfig != NULL);
        serverSslConfig->sockFd = remoteProcess->connFd;
        serverSslConfig->connType = TCP;
        // Set the FD.
        ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
        HLT_RpcTlsAccept(remoteProcess, serverSslId);

        // Client, applying for context
        void *clientSsl = HLT_TlsNewSsl(clientConfig);
        ASSERT_TRUE(clientSsl != NULL);

        HLT_Ssl_Config *clientSslConfig;
        clientSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(clientSslConfig != NULL);
        clientSslConfig->sockFd = localProcess->connFd;
        clientSslConfig->connType = TCP;

        // Set the FD.
        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            handle->ctx = clientSsl;
            ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);

            if(!setInfo.SuccessOrFail){
                ASSERT_TRUE(HLT_TlsConnect(clientSsl) != 0);
            }else {
                ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            }
        }
        else {
            // Negotiation
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            // Data read/write
            ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
            ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
            ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
            ASSERT_TRUE(readLen == strlen(writeBuf));
            ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
            // Disable the connection.
            ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
            ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
            HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);
            HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
            HLT_CloseFd(sockFd.srcFd, localProcess->connType);

            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_HasTicket(session) == true);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }cnt++;
    } while (cnt < 3); // Perform the connection twice.

EXIT:
    HITLS_SESS_Free(session);
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

static void FrameCallBack_ClientHello_PskBinder_Miss(void *msg, void *userData)
{
    // ClientHello exception: The Binder field in the ClientHello message is lost.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clienthello = &frameMsg->body.hsMsg.body.clientHello;

    clienthello->psks.binders.state = MISSING_FIELD;
    clienthello->psks.binderSize.state = ASSIGNED_FIELD;
    clienthello->psks.binderSize.data = 0;
    clienthello->psks.exLen.state = INITIAL_FIELD;

EXIT:
    return;
}

static void FrameCallBack_ClientHello_LegacyVersion_Unsafe(void *msg, void *userData)
{
    // ClientHello exception: The sent ClientHello message has its LegacyVersion set to SSL3.0.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clienthello = &frameMsg->body.hsMsg.body.clientHello;

    clienthello->version.state = ASSIGNED_FIELD;
    clienthello->version.data = HITLS_VERSION_SSL30;
EXIT:
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_PSKBINDER_FUNC_TC002
* @brief 4.2.11-Pre-Shared Key Extension-97
* @spec  the server MUST validate the corresponding binder value (see Section 4.2.11.2 below).
*         If this value is not present or does not validate, the server MUST abort the handshake.
* @title  Modify the binder of client hello so that it is lost.
* @precon  nan
* @brief
* 1. The connection is established and the session is restored.
* 2. Modify the binder in the psk extension of the client hello message sent by the client so that the binder is lost.
*    Observe the behavior of the server.
* @expect
* 1. The setting is successful.
* 2. The server terminates the handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_PSKBINDER_FUNC_TC002()
{
    // The connection is established and the session is restored.
    SetInfo setInfo = {0};
    setInfo.SetNothing = 1;
    setInfo.SuccessOrFail = 0;
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    // Modify the binder in the psk extension of the client hello message sent by the client so that the binder is lost.
    // Observe the behavior of the server.
    handle.frameCallBack = FrameCallBack_ClientHello_PskBinder_Miss;
    ResumeConnectWithPara(&handle, setInfo);
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_VERSION_FUNC_TC001
* @brief 4.2.11-Pre-Shared Key Extension-97
* @spec  Implementations MUST NOT send a ClientHello.legacy_version or ServerHello.legacy_version set to 0x0300 or less.
*        Any endpoint receiving a Hello message with ClientHello.legacy_version or ServerHello.legacy_version set to
*        0x0300 MUST abort the handshake with a "protocol_version" alert.
* @title  The server receives a client hello message whose legacy_version is 0x0300.
* @precon  nan
* @brief
* 1. Change the value of legacy_version in the client Hello message to 0x0300.
* 2. Observe the server behavior.
* @expect
* 1. The setting is successful.
* 2. The server terminates the handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_LEGACY_VERSION_FUNC_TC001()
{
    // Change the value of legacy_version in the client Hello message to 0x0300.
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Observe the server behavior.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = FrameCallBack_ClientHello_LegacyVersion_Unsafe;
    handle.ctx = clientRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(&handle) == 0);

    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) != 0);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

static void TEST_Server13_33_Err(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)data;
    (void)len;
    (void)bufSize;
    uint32_t writeLen;
    uint32_t sendLen = 5;
    if (ctx->isClient==false){
        uint8_t sendBuf[5] = {*(int *)user, 0x03, 0x03, 0x00, 0x00};
    for (int i = 0; i < 33; i++) {
        ASSERT_EQ(BSL_UIO_Write(ctx->uio, sendBuf, sendLen, &writeLen),0);
    }
    return;
    }
EXIT:
    return;
}

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_EMPTY_RECORDS_FUNC_TC001
* @title  0-length CCS or handshake is received during tls13 handshake proccess.
* @precon  nan
* @brief   1. Start a handshake with tls13 config, Expected result 1
*          2. Modify the server hello message. Expected result 2
* @expect  1. Return success
*          2. Handshake fails
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_EMPTY_RECORDS_FUNC_TC001(int rec_type)
{
    CRYPT_RandRegist(TestSimpleRand);
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8889, true);
    ASSERT_TRUE(remoteProcess != NULL);

    // Configure link information on the server.
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    serverCtxConfig->needCheckKeyUsage = true;

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        &rec_type,
        TEST_Server13_33_Err
    };
    RegisterWrapper(wrapper);

    // The server listens on the TLS link.
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_3, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configure link information on the client.
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_3, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);
    ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_SEND);
    ASSERT_EQ(
        (ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId),ALERT_UNEXPECTED_MESSAGE);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_APPDATA_MAX_LENGTH
* @spec  -
* @title  In the TLS1.3 scenario, after the link is established, the app data with the maximum length is sent.
    It is expected that the app data can be properly processed.
* @precon  nan
* @brief  1.Configuring TLS1.3 Link Establishment. Expected result 1 is displayed.
          2.Sending large packets. Expected result 2 is obtained.
* @expect 1.Return success
          2.Return success
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_APPDATA_MAX_LENGTH(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, 8888, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    uint8_t writeData[REC_MAX_PLAIN_LENGTH] = {1};
    uint32_t writeLen = REC_MAX_PLAIN_LENGTH;
    uint8_t readData[REC_MAX_PLAIN_LENGTH] = {0};
    uint32_t readLen = REC_MAX_PLAIN_LENGTH;

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, clientRes, writeData, writeLen) , 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, serverRes, readData, readLen, &readLen) , 0);
    ASSERT_EQ(readLen , REC_MAX_PLAIN_LENGTH);
    ASSERT_EQ(memcmp(writeData, readData, readLen) , 0);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */
