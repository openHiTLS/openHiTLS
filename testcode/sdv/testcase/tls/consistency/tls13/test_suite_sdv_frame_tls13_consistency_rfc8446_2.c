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
#include "stub_replace.h"
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
#include "alert.h"
#include "record.h"
#include "hs_kx.h"
#include "bsl_log.h"
#include "cert_callback.h"
/* END_HEADER */

#define PORT 23456
#define READ_BUF_SIZE (18 * 1024)
#define ALERT_BODY_LEN 2u

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
static int32_t DoHandshake(ResumeTestInfo *testInfo)
{
    /* Construct a connection. */
    testInfo->client = FRAME_CreateLink(testInfo->c_config, testInfo->uioType);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (testInfo->clientSession != NULL) {
        int32_t ret = HITLS_SetSession(testInfo->client->ssl, testInfo->clientSession);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    testInfo->server = FRAME_CreateLink(testInfo->s_config, testInfo->uioType);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
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

static void Test_ServerAddKeyExchangeMode(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // Add the KeyExchangeMode extension to server hello.
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    uint8_t pskMode[] = {0, 0x2d, 0, 2, 1, 1};
    frameMsg.body.hsMsg.length.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.length.data += sizeof(pskMode);
    frameMsg.body.hsMsg.body.serverHello.extensionLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.serverHello.extensionLen.data = frameMsg.body.hsMsg.body.serverHello.extensionLen.data + sizeof(pskMode);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

    ASSERT_EQ(memcpy_s(&data[*len], bufSize - *len, &pskMode, sizeof(pskMode)), EOK);
    *len += sizeof(pskMode);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Server_KeyShare_Miss(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // The keyshare extension of server hello is lost.
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO);

    frameMsg.body.hsMsg.body.serverHello.keyShare.exState = MISSING_FIELD;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Client_MasterSecret_Miss(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // The MasterSecret extension of client hello is lost.
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);

    frameMsg.body.hsMsg.body.clientHello.extendedMasterSecret.exState = MISSING_FIELD;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Client_ObfuscatedTicketAge_NotZero(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // The value of ObfuscatedTicketAge is not 0 for the external preset PSK.
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);

    frameMsg.body.hsMsg.body.clientHello.psks.identities.data->obfuscatedTicketAge.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.psks.identities.data->obfuscatedTicketAge.data = 2;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Client_ObfuscatedTicketAge_Zero(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // The value of ObfuscatedTicketAge is 0 for the PSK generated by the session.
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);

    frameMsg.body.hsMsg.body.clientHello.psks.identities.data->obfuscatedTicketAge.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.psks.identities.data->obfuscatedTicketAge.data = 0;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_Client_Binder_Unnormal(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    // Change the binder value of the psk extension of the client hello message.
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_TLS13;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLS13;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);

    uint8_t binder[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,};
    frameMsg.body.hsMsg.body.clientHello.psks.binders.data->binder.state = ASSIGNED_FIELD;
    memcpy_s(frameMsg.body.hsMsg.body.clientHello.psks.binders.data->binder.data, PSK_MAX_LEN, binder, sizeof(binder));

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void FrameCallBack_ServerHello_KeyShare_Add(void *msg, void *userData)
{
    // ServerHello exception: The sent ServerHello message carries the keyshare extension.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverhello = &frameMsg->body.hsMsg.body.serverHello;

    serverhello->keyShare.exState = INITIAL_FIELD;
    serverhello->keyShare.exLen.state = INITIAL_FIELD;
    serverhello->keyShare.data.state = INITIAL_FIELD;
    serverhello->keyShare.data.group.state = ASSIGNED_FIELD;
    serverhello->keyShare.data.group.data = HITLS_EC_GROUP_SECP256R1;

    FRAME_ModifyMsgInteger(HS_EX_TYPE_KEY_SHARE, &serverhello->keyShare.exType);
    uint8_t uu[] = {0x00, 0x15, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56};
    FRAME_ModifyMsgArray8(uu, sizeof(uu), &serverhello->keyShare.data.keyExchange, &serverhello->keyShare.data.keyExchangeLen);

EXIT:
    return;
}

static void FrameCallBack_ClientHello_PskExchangeMode_Miss(void *msg, void *userData)
{
    // ClientHello exception: The sent ClientHello message causes the Psk_Exchange_Mode extension to be lost.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clienthello = &frameMsg->body.hsMsg.body.clientHello;

    clienthello->pskModes.exState = MISSING_FIELD;
EXIT:
    return;
}

static void FrameCallBack_ClientHello_KeyShare_Miss(void *msg, void *userData)
{
    // ClientHello exception: The KeyShare extension of the ClientHello message is lost.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clienthello = &frameMsg->body.hsMsg.body.clientHello;

    clienthello->keyshares.exState = MISSING_FIELD;
EXIT:
    return;
}

/** @
* @test  UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC001
* @brief 2.1-Incorrect DHE Share-6
* @spec  If no common cryptographic parameters can be negotiated, the server MUST abort the handshake with an
*        appropriate alert.
* @title  The server sends an hrr message to request the key_share. The negotiation succeeds.
* @precon  nan
* @brief
* 1. Set the group (HITLS_EC_GROUP_SECP256R1 and HITLS_EC_GROUP_SECP384R1) on the client and set the group
*    (HITLS_EC_GROUP_SECP384R1) on the server. Expected result 1 is obtained.
* 2. Establish a connection, stop the server in the TRY_SEND_HELLO_RETRY_REQUEST state, and check whether the value of
*    the group field is HITLS_EC_GROUP_SECP384R1. (Expected result 2)
* 3. Continue to establish the connection. Expected result 3 is obtained.
* @expect
* 1. The setting is successful.
* 2. The value of the group field is HITLS_EC_GROUP_SECP384R1.
* 3. The connection is set up successfully.
@ */
/* BEGIN_CASE */

void UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC001()
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientconfig = NULL;
    HITLS_Config *serverconfig = NULL;
    clientconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientconfig != NULL);
    serverconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverconfig != NULL);

    // Set the group (HITLS_EC_GROUP_SECP256R1 and HITLS_EC_GROUP_SECP384R1) on the client and set the group
    // (HITLS_EC_GROUP_SECP384R1) on the server.
    uint16_t clientgroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t servergroups[] = {HITLS_EC_GROUP_SECP384R1};
    ASSERT_EQ(HITLS_CFG_SetGroups(clientconfig, clientgroups, sizeof(clientgroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverconfig, servergroups, sizeof(servergroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientconfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverconfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_IO_BUSY);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    uint8_t *sndBuf = ioUserData->sndMsg.msg;
    uint32_t sndLen = ioUserData->sndMsg.len;
    ASSERT_TRUE(sndLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, sndBuf, sndLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    // Establish a connection, stop the server in the TRY_SEND_HELLO_RETRY_REQUEST state, and check whether the value of
    // the group field is HITLS_EC_GROUP_SECP384R1.
    FRAME_ServerHelloMsg *Hello_Retry_RequestMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(Hello_Retry_RequestMsg->keyShare.data.group.data == HITLS_EC_GROUP_SECP384R1);

    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_SEND_CLIENT_HELLO), HITLS_SUCCESS);

    // Continue to establish the connection.
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(clientconfig);
    HITLS_CFG_FreeConfig(serverconfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC002
* @brief 2.1-Incorrect DHE Share-6
* @spec  If no common cryptographic parameters can be negotiated, the server MUST abort the handshake with an
*        appropriate alert.
* @title  The server receives two unsupported key_share messages.
* @precon  nan
* @brief
* 1. Set the group (HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1, and HITLS_EC_GROUP_SECP521R1) on the client and
*    set the group (HITLS_EC_GROUP_SECP384R1) on the server. Expected result 1 is obtained.
* 2. Establish a connection, stop the server in TRY_SEND_HELLO_RETRY_REQUEST state, and change the value of the group
*    field in the connection to HITLS_EC_GROUP_SECP521R1. Expected result 2 is obtained.
* 3. Continue to establish a connection and observe the connection establishment result. Expected result 3 is obtained.
* @expect
* 1. The setting is successful.
* 2. The modification is successful.
* 3. The server sends a request again, and the client returns HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC002()
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientconfig = NULL;
    HITLS_Config *serverconfig = NULL;
    clientconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientconfig != NULL);
    serverconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverconfig != NULL);

    // Set the group (HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1, and HITLS_EC_GROUP_SECP521R1) on the client
    // and set the group (HITLS_EC_GROUP_SECP384R1) on the server.
    uint16_t clientgroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1, HITLS_EC_GROUP_SECP521R1};
    uint16_t servergroups[] = {HITLS_EC_GROUP_SECP384R1};
    ASSERT_EQ(HITLS_CFG_SetGroups(clientconfig, clientgroups, sizeof(clientgroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverconfig, servergroups, sizeof(servergroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientconfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverconfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recBuf = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recBuf, recLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    // Establish a connection, stop the server in TRY_SEND_HELLO_RETRY_REQUEST state, and change the value of the group
    // field in the connection to HITLS_EC_GROUP_SECP521R1.
    FRAME_ServerHelloMsg *Hello_Retry_RequestMsg = &frameMsg.body.hsMsg.body.serverHello;
    Hello_Retry_RequestMsg->keyShare.data.group.state = ASSIGNED_FIELD;
    Hello_Retry_RequestMsg->keyShare.data.group.data = HITLS_EC_GROUP_SECP521R1;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_EQ(HITLS_Connect(client->ssl) , HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl) , HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(HITLS_Connect(client->ssl) , HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);

    // Continue to establish a connection and observe the connection establishment result.
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl) , HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(clientconfig);
    HITLS_CFG_FreeConfig(serverconfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC003
* @brief 2.1-Incorrect DHE Share-6
* @spec  If no common cryptographic parameters can be negotiated, the server MUST abort the handshake with an
*        appropriate alert.
* @title  The client receives the key_share with the same elliptic curve for the second time.
* @precon  nan
* @brief
* 1. Set the group (HITLS_EC_GROUP_SECP256R1 and HITLS_EC_GROUP_SECP384R1) on the client and set the group
*     (HITLS_EC_GROUP_SECP384R1) on the server. Expected result 1 is obtained.
* 2. Establish a connection, stop the server in the TRY_SEND_HELLO_RETRY_REQUEST state, and change the value of the
*    group field to HITLS_EC_GROUP_SECP256R1. Expected result 2 is obtained.
* 3. Continue connection establishment and observe the connection establishment result. Expected result 3 is obtained.
* @expect
* 1. The setting is successful.
* 2. The modification is successful.
* 3. The connection fails to be established. After receiving the request message, the client returns
*     HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC003()
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientconfig = NULL;
    HITLS_Config *serverconfig = NULL;
    clientconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientconfig != NULL);
    serverconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverconfig != NULL);

    // Set the group (HITLS_EC_GROUP_SECP256R1 and HITLS_EC_GROUP_SECP384R1) on the client and set the group
    // (HITLS_EC_GROUP_SECP384R1) on the server.
    uint16_t clientgroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t servergroups[] = {HITLS_EC_GROUP_SECP384R1};
    ASSERT_EQ(HITLS_CFG_SetGroups(clientconfig, clientgroups, sizeof(clientgroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverconfig, servergroups, sizeof(servergroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientconfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverconfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recBuf = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recBuf, recLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    // Establish a connection, stop the server in the TRY_SEND_HELLO_RETRY_REQUEST state, and change the value of the
    // group field to HITLS_EC_GROUP_SECP256R1.
    FRAME_ServerHelloMsg *Hello_Retry_RequestMsg = &frameMsg.body.hsMsg.body.serverHello;
    Hello_Retry_RequestMsg->keyShare.data.group.state = ASSIGNED_FIELD;
    Hello_Retry_RequestMsg->keyShare.data.group.data = HITLS_EC_GROUP_SECP256R1;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    ASSERT_EQ(HITLS_Connect(client->ssl) , HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(clientconfig);
    HITLS_CFG_FreeConfig(serverconfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC004
* @brief 2.1-Incorrect DHE Share-6
* @spec  If no common cryptographic parameters can be negotiated, the server MUST abort the handshake with an
*        appropriate alert.
* @title  The client receives an unsupported elliptic curve key_share request.
* @precon  nan
* @brief
*   1. Set the group (HITLS_EC_GROUP_SECP256R1 and HITLS_EC_GROUP_SECP384R1) on the client and set the group
*       (HITLS_EC_GROUP_SECP384R1) on the server. Expected result 1 is obtained.
*   2. Establish a connection, stop the server in the TRY_SEND_HELLO_RETRY_REQUEST state, and change the value of the
*       group field to HITLS_EC_GROUP_SECP521R1. Expected result 2 is obtained.
*   3. Continue connection establishment and observe the connection establishment result. Expected result 3 is obtained.
* @expect
*   1. The setting is successful.
*   2. The modification is successful.
*   3. The connection fails to be established. After receiving the request message, the client returns
*       HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC004()
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientconfig = NULL;
    HITLS_Config *serverconfig = NULL;
    clientconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientconfig != NULL);
    serverconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverconfig != NULL);

    // Set the group (HITLS_EC_GROUP_SECP256R1 and HITLS_EC_GROUP_SECP384R1) on the client and set the group
    // (HITLS_EC_GROUP_SECP384R1) on the server.
    uint16_t clientgroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t servergroups[] = {HITLS_EC_GROUP_SECP384R1};
    ASSERT_EQ(HITLS_CFG_SetGroups(clientconfig, clientgroups, sizeof(clientgroups) / sizeof(uint16_t)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(serverconfig, servergroups, sizeof(servergroups) / sizeof(uint16_t)), HITLS_SUCCESS);

    client = FRAME_CreateLink(clientconfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverconfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(HITLS_Connect(client->ssl) == HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Accept(server->ssl) == HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recBuf = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recBuf, recLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    // Establish a connection, stop the server in the TRY_SEND_HELLO_RETRY_REQUEST state, and change the value of the
    // group field to HITLS_EC_GROUP_SECP521R1.
    FRAME_ServerHelloMsg *Hello_Retry_RequestMsg = &frameMsg.body.hsMsg.body.serverHello;
    Hello_Retry_RequestMsg->keyShare.data.group.state = ASSIGNED_FIELD;
    Hello_Retry_RequestMsg->keyShare.data.group.data = HITLS_EC_GROUP_SECP521R1;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    // Continue connection establishment and observe the connection establishment result.
    ASSERT_EQ(HITLS_Connect(client->ssl) , HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(clientconfig);
    HITLS_CFG_FreeConfig(serverconfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC005
* @brief 2.1.  Incorrect DHE Share
* @spec  If the client has not provided a sufficient "key_share" extension (e.g., it includes only DHE or ECDHE groups
    unacceptable to or unsupported by the server), the server corrects the mismatch with a HelloRetryRequest and the
    client needs to restart the handshake with an appropriate "key_share" extension, as shown in Figure 2. If no common
    cryptographic parameters can be negotiated, the server MUST abort the handshake with an appropriate alert.
* @title  Configure groups_list:"brainpoolP512r1:X25519" on the client and groups_list:"brainpoolP512r1:X25519" on the
    server. Observe the link setup result and check whether the server sends Hello_Retry_Requset.
* @precon  nan
* @brief
1. Configure groups_list:"brainpoolP512r1:X25519" on the client and groups_list:"brainpoolP512r1:X25519" on the
    server.
* @expect
1. Send clienthello with X25519 keyshare. The link is established successfully.
2. The server does not send Hello_Retry_Requset.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_CONSISTENCY_RFC8446_REQUEST_CLIENT_HELLO_FUNC_TC005()
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientconfig = NULL;
    HITLS_Config *serverconfig = NULL;
    clientconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientconfig != NULL);
    serverconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverconfig != NULL);

    uint16_t clientgroups[] = {HITLS_EC_GROUP_BRAINPOOLP512R1, HITLS_EC_GROUP_CURVE25519};
    uint16_t servergroups[] = {HITLS_EC_GROUP_BRAINPOOLP512R1, HITLS_EC_GROUP_CURVE25519};
    ASSERT_EQ(HITLS_CFG_SetGroups(serverconfig, servergroups, sizeof(servergroups)/sizeof(uint16_t)) , HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(clientconfig, clientgroups, sizeof(clientgroups)/sizeof(uint16_t)) , HITLS_SUCCESS);

    client = FRAME_CreateLink(clientconfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverconfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recBuf = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recBuf, recLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverHello = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverHello->keyShare.data.group.data == HITLS_EC_GROUP_CURVE25519);
    ASSERT_EQ(server->ssl->hsCtx->haveHrr, false);

    // Continue to establish the link.
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(clientconfig);
    HITLS_CFG_FreeConfig(serverconfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_EXCHANGE_MODES_MISS_FUNC_TC001
* @brief 4.2.9-Pre-Shared Key Exchange Modes-77
* @spec  In order to use PSKs, clients MUST also send a "psk_key_exchange_modes" extension.
* @title  Preset psk Client Lost Pre-Shared Key Exchange Modes Extension
* @precon  nan
* @brief
* 1. Preset the psk, modify the client hello message sent by the client to make the psk_key_exchange_modes extension
*    lost, and observe the server behavior.
* @expect
* 1. Connect establishment is interrupted.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_EXCHANGE_MODES_MISS_FUNC_TC001()
{
    // Preset the psk, modify the client hello message sent by the client to make the psk_key_exchange_modes extension
    // lost, and observe the server behavior.
    SetInfo setInfo = {0};
    memcpy_s(setInfo.psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
    setInfo.ClientCipherSuite = "HITLS_AES_128_GCM_SHA256";
    setInfo.ClientCipherSuite = "HITLS_AES_128_GCM_SHA256";
    setInfo.SuccessOrFail = 0;
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = FrameCallBack_ClientHello_PskExchangeMode_Miss;
    ClientCreatConnectWithPara(&handle, setInfo);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_EXCHANGE_MODES_MISS_FUNC_TC002
* @brief 4.2.9-Pre-Shared Key Exchange Modes-77
* @spec  In order to use PSKs, clients MUST also send a "psk_key_exchange_modes" extension.
* @title  psk session recovery client lost Pre-Shared Key Exchange Modes extension
* @precon  nan
* @brief
* 1. Preset the psk, modify the client hello message sent by the client to make the psk_key_exchange_modes extension
lost, and observe the server behavior.
* @expect
* 1. Connect establishment is interrupted.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_EXCHANGE_MODES_MISS_FUNC_TC002()
{
    // Preset the psk, modify the client hello message sent by the client to make the psk_key_exchange_modes extension
    // lost, and observe the server behavior.
    SetInfo setInfo = {0};
    setInfo.SetNothing = 1;
    setInfo.SuccessOrFail = 0;
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = FrameCallBack_ClientHello_PskExchangeMode_Miss;
    ResumeConnectWithPara(&handle, setInfo);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_EXCHANGE_MODES_ADD_FUNC_TC001
* @brief 4.2.9-Pre-Shared Key Exchange Modes-80
* @spec  The server MUST NOT send a "psk_key_exchange_modes" extension.
* @title  The session restoration server carries psk_key_exchange_modes.
* @precon  nan
* @brief
* 1. Establish a connection, save the session, and restore the session.
* 2. Modify the server hello message sent by the server to carry the psk_key_exchange_mode extension and observe the
*    client behavior.
* @expect
* 1. The connection is successfully established and the session is restored.
* 2. The client sends an alert message and disconnects the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSK_EXCHANGE_MODES_ADD_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    // Establish a connection, save the session, and restore the session.
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    ASSERT_TRUE(testInfo.c_config != NULL);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);

    // Modify the server hello message sent by the server to carry the psk_key_exchange_mode extension and observe the
    // client behavior.
    RecWrapper wrapper = {TRY_SEND_SERVER_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_ServerAddKeyExchangeMode};
    RegisterWrapper(wrapper);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_PARSE_UNSUPPORTED_EXTENSION);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_ADD_FUNC_TC001
* @brief 4.2.9-Pre-Shared Key Exchange Modes-80
* @spec  psk_ke:  PSK-only key establishment.  In this mode, the server MUST NOT supply a "key_share" value.
* @title  Preset the PSK. In psk_ke mode, the server carries the key_share extension.
* @precon  nan
* @brief
* 1. Preset PSK
* 2. Set psk_key_exchange_mode to psk_ke on the client and server,
* 3. Modify the server hello message sent by the server to carry the key_share extension and observe the client
*    behavior.
* @expect
* 1. The setting is successful.
* 2. The setting is successful.
* 3. The client sends an alert message and disconnects the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_ADD_FUNC_TC001()
{
    // Preset PSK
    SetInfo setInfo = {0};
    memcpy_s(setInfo.psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
    setInfo.ClientCipherSuite = "HITLS_AES_128_GCM_SHA256";
    setInfo.ClientCipherSuite = "HITLS_AES_128_GCM_SHA256";
    // Set psk_key_exchange_mode to psk_ke on the client and server
    setInfo.ClientKeyExchangeMode = TLS13_KE_MODE_PSK_ONLY;
    setInfo.ServerKeyExchangeMode = TLS13_KE_MODE_PSK_ONLY;
    setInfo.SuccessOrFail = 0;
    // Modify the server hello message sent by the server to carry the key_share extension and observe the client
    // behavior.
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = FrameCallBack_ServerHello_KeyShare_Add;
    ServerCreatConnectWithPara(&handle, setInfo);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_MISS_FUNC_TC001
* @brief 4.2.9-Pre-Shared Key Exchange Modes-77
* @spec  psk_dhe_ke:  PSK with (EC)DHE key establishment.  In this mode, the
*       client and server MUST supply "key_share" values as described in Section 4.2.8.
* @title  Session Recovery Client Lost Key_share Extension
* @precon  nan
* @brief
* 1. When the session is recovered, modify the client hello message sent by the client so that the Key_Share extension
*   is lost. Observe the server behavior.
* @expect
* 1. Connect establishment is interrupted.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_MISS_FUNC_TC001()
{
    // When the session is recovered, modify the client hello message sent by the client so that the Key_Share extension
    // is lost. Observe the server behavior.
    SetInfo setInfo = {0};
    setInfo.SetNothing = 1;
    setInfo.SuccessOrFail = 0;
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = FrameCallBack_ClientHello_KeyShare_Miss;
    ResumeConnectWithPara(&handle, setInfo);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_MISS_FUNC_TC002
* @brief 4.2.9-Pre-Shared Key Exchange Modes-80
* @spec  psk_dhe_ke:  PSK with (EC)DHE key establishment.  In this mode, the
*       client and server MUST supply "key_share" values as described in Section 4.2.8.
* @title  Server: psk_key_exchange_mode: The key_share extension is lost under psk_dhe_ke.
* @precon  nan
* @brief
* 1. Preset PSK
* 2. Set psk_key_exchange_mode to psk_dhe_ke on the client server, modify the server hello message sent by the server to
*     lose the key_share extension, and observe the client behavior.
* @expect
* 1. The setting is successful.
* 2. The client sends an alert message to disconnect the connection.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_KEY_SHARE_MISS_FUNC_TC002()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Server_KeyShare_Miss
    };
    RegisterWrapper(wrapper);

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    // Preset PSK
    char psk[] = "aaaaaaaaaaaaaaaa";
    ASSERT_TRUE(ExampleSetPsk(psk) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskClientCallback(testInfo.c_config, ExampleClientCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskServerCallback(testInfo.s_config, ExampleServerCb) == HITLS_SUCCESS);

    // Set psk_key_exchange_mode to psk_dhe_ke on the client server, modify the server hello message sent by the server
    // to lose the key_share extension, and observe the client behavior.
    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT),
        HITLS_MSG_HANDLE_HANDSHAKE_FAILURE);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_OBFUSCATED_TICKET_AGE_FUNC_TC001
* @brief 4.2.11-Pre-Shared Key Extension-93
* @spec  For identities established externally, an obfuscated_ticket_age of 0 SHOULD be used, and servers MUST ignore
*        the value
* @title  The obfuscated_ticket_age of the preset PSK is not 0.
* @precon  nan
* @brief
* 1. Preset PSK
* 2. Modify the obfuscated_ticket_age field in the psk extension in the client hello message sent by the client to
*    ensure that the field is not 0.
* 3. Establish a connection.
* @expect
* 1. The setting is successful.
* 2. The modification is successful.
* 3. The connection is successfully established and certificate authentication is performed.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_OBFUSCATED_TICKET_AGE_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_Client_ObfuscatedTicketAge_NotZero
    };
    RegisterWrapper(wrapper);

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    // Preset PSK
    char psk[] = "aaaaaaaaaaaaaaaa";
    ASSERT_TRUE(ExampleSetPsk(psk) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskClientCallback(testInfo.c_config, ExampleClientCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskServerCallback(testInfo.s_config, ExampleServerCb) == HITLS_SUCCESS);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Modify the obfuscated_ticket_age field in the psk extension in the client hello message sent by the client to
    // ensure that the field is not 0.
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverhelloMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverhelloMsg->pskSelectedIdentity.exLen.data == 0);

    // Establish a connection.
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    ClearWrapper();
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

extern int32_t CompareBinder(TLS_Ctx *ctx, const PreSharedKey *pskNode, uint8_t *psk, uint32_t pskLen,
    uint32_t truncateHelloLen);

static int32_t CompareBinder_Success(TLS_Ctx *ctx, const PreSharedKey *pskNode, uint8_t *psk, uint32_t pskLen,
    uint32_t truncateHelloLen)
{
    (void)ctx;
    (void)pskNode;
    (void)psk;
    (void)pskLen;
    (void)truncateHelloLen;
    return 0;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_OBFUSCATED_TICKET_AGE_FUNC_TC002
* @brief 4.2.11-Pre-Shared Key Extension-93
* @spec  For identities established externally, an obfuscated_ticket_age of 0 SHOULD be used, and servers MUST ignore
*        the value
* @title  The obfuscated_ticket_age of the PSK generated by the session is 0.
* @precon  nan
* @brief
* 1. Preset PSK
* 2. Modify the obfuscated_ticket_age field in the psk extension in the client hello message sent by the client to
*    ensure that the value is not 0.
* 3. Establish a connection.
* @expect
* 1. The setting is successful.
* 2. The modification is successful.
* 3. Certificate authentication
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_OBFUSCATED_TICKET_AGE_FUNC_TC002()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    // Preset PSK
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Modify the obfuscated_ticket_age field in the psk extension in the client hello message sent by the client to
    // ensure that the value is not 0.
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_Client_ObfuscatedTicketAge_Zero};
    RegisterWrapper(wrapper);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);

    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, CompareBinder, CompareBinder_Success);

    // Establish a connection.
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(testInfo.client->ssl, &isReused), HITLS_SUCCESS);
    ASSERT_EQ(isReused, true);
EXIT:
    ClearWrapper();
    STUB_Reset(&stubInfo);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_OBFUSCATED_TICKET_AGE_FUNC_TC003
* @brief 4.2.11-Pre-Shared Key Extension-93
* @spec  For identities established externally, an obfuscated_ticket_age of 0 SHOULD be used, and servers MUST ignore
*        the value
* @title  The obfuscated_ticket_age of the PSK generated by the session is different from the original value.
* @precon  nan
* @brief
* 1. Preset PSK
* 2. Modify the obfuscated_ticket_age field in the psk extension in the client hello message sent by the client to
*    ensure that the field is not 0.
* 3. Establish a connection.
* @expect
* 1. The setting is successful.
* 2. The modification is successful.
* 3. Certificate authentication
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_OBFUSCATED_TICKET_AGE_FUNC_TC003()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    // Preset PSK
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Modify the obfuscated_ticket_age field in the psk extension in the client hello message sent by the client to
    // ensure that the field is not 0.
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_Client_ObfuscatedTicketAge_NotZero};
    RegisterWrapper(wrapper);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);

    STUB_Init();
    FuncStubInfo stubInfo = {0};
    STUB_Replace(&stubInfo, CompareBinder, CompareBinder_Success);

    // Establish a connection.
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    ClearWrapper();
    STUB_Reset(&stubInfo);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

#define SESSION_SZ 10
static HITLS_Session *g_userSession[SESSION_SZ];
static int g_sessionSz = 0;

void ClearSessoins()
{
    for (int i = 0; i < g_sessionSz; i++) {
        HITLS_SESS_Free(g_userSession[i]);
    }
    g_sessionSz = 0;
}

HITLS_Session *GetSession(int index)
{
    if (index < g_sessionSz) {
        return HITLS_SESS_Dup(g_userSession[index]);
    }
    return NULL;
}

void AddSession(HITLS_Session *session)
{
    if (g_sessionSz < SESSION_SZ - 1) {
        g_userSession[g_sessionSz] = session;
        g_sessionSz++;
    }
}

int32_t Test_NewSessionCb(HITLS_Ctx *ctx, HITLS_Session *session)
{
    (void)ctx;
    if (ctx->isClient && HITLS_SESS_IsResumable(session)) {
        AddSession(session);
        return 1;
    }
    return 0;
}

static int32_t Test_PskUseSessionCb_WithSHA256(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **id,
    uint32_t *idLen, HITLS_Session **session)
{
    (void)ctx;
    (void)hashAlgo;
    (void)id;
    (void)idLen;
    static uint8_t identity[] = "123456";

    if (g_sessionSz > 0) {
        *id = identity;
        *idLen = sizeof(identity);
        *session = GetSession(g_sessionSz - 1);
        (*session)->cipherSuite = HITLS_AES_128_GCM_SHA256;
        return HITLS_PSK_USE_SESSION_CB_SUCCESS;
    }
    return HITLS_PSK_USE_SESSION_CB_FAIL;
}
static int32_t Test_PskUseSessionCb_WithSHA384(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **id,
    uint32_t *idLen, HITLS_Session **session)
{
    (void)ctx;
    (void)hashAlgo;
    (void)id;
    (void)idLen;
    static uint8_t identity[] = "123456";

    if (g_sessionSz > 0) {
        *id = identity;
        *idLen = sizeof(identity);
        *session = GetSession(g_sessionSz - 1);
        (*session)->cipherSuite = HITLS_AES_256_GCM_SHA384;
        return HITLS_PSK_USE_SESSION_CB_SUCCESS;
    }
    return HITLS_PSK_USE_SESSION_CB_FAIL;
}
static int32_t Test_PskUseSessionCb_Default(HITLS_Ctx *ctx, uint32_t hashAlgo, const uint8_t **id,
    uint32_t *idLen, HITLS_Session **session)
{
    (void)ctx;
    (void)hashAlgo;
    (void)id;
    (void)idLen;
    static uint8_t identity[] = "123456";

    if (g_sessionSz > 0) {
        *id = identity;
        *idLen = sizeof(identity);
        *session = GetSession(g_sessionSz - 1);

        HITLS_Session *newSession = HITLS_SESS_New();
        (*session)->cipherSuite = newSession->cipherSuite;
        HITLS_SESS_Free(newSession);

        return HITLS_PSK_USE_SESSION_CB_SUCCESS;
    }
    return HITLS_PSK_USE_SESSION_CB_FAIL;
}

static int32_t Test_PskFindSessionCb_WithSHA256(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
    HITLS_Session **session)
{
    (void)ctx;
    (void)identity;
    (void)identityLen;

    if (g_sessionSz > 0) {
        *session = GetSession(g_sessionSz - 1);
        (*session)->cipherSuite = HITLS_AES_128_GCM_SHA256;
        return HITLS_PSK_FIND_SESSION_CB_SUCCESS;
    }
    return HITLS_PSK_FIND_SESSION_CB_FAIL;
}

static int32_t Test_PskFindSessionCb_WithSHA384(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
    HITLS_Session **session)
{
    (void)ctx;
    (void)identity;
    (void)identityLen;

    if (g_sessionSz > 0) {
        *session = GetSession(g_sessionSz - 1);
        (*session)->cipherSuite = HITLS_AES_256_GCM_SHA384;
        return HITLS_PSK_FIND_SESSION_CB_SUCCESS;
    }
    return HITLS_PSK_FIND_SESSION_CB_FAIL;
}

static int32_t Test_PskFindSessionCb_Default(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
    HITLS_Session **session)
{
    (void)ctx;
    (void)identity;
    (void)identityLen;

    if (g_sessionSz > 0) {
        *session = GetSession(g_sessionSz - 1);

        HITLS_Session *newSession = HITLS_SESS_New();
        (*session)->cipherSuite = newSession->cipherSuite;
        HITLS_SESS_Free(newSession);

        return HITLS_PSK_FIND_SESSION_CB_SUCCESS;
    }
    return HITLS_PSK_FIND_SESSION_CB_FAIL;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC001
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256 if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*        cipher suite.
* @title  The hash settings on the client and server are inconsistent.
* @precon  nan
* @brief
* 1. Preset the PSK. The client invokes HITLS_PskUseSessionCb to set the hash to sha256, and the service invokes
*    HITLS_PskFindSessionCb to set the hash to sha384.
* 2. Connect establishment
* @expect
* 1. The setting is successful.
* 2. Connect establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetNewSessionCb(testInfo.c_config, Test_NewSessionCb);

    // Preset the PSK.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // The client invokes HITLS_PskUseSessionCb to set the hash to sha256, and the service invokes
    // HITLS_PskFindSessionCb to set the hash to sha384.
    HITLS_CFG_SetPskUseSessionCallback(testInfo.c_config, Test_PskUseSessionCb_WithSHA256);
    HITLS_CFG_SetPskFindSessionCallback(testInfo.s_config, Test_PskFindSessionCb_WithSHA384);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Connect establishment
    ASSERT_TRUE(
        FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT) == HITLS_MSG_HANDLE_PSK_INVALID);
EXIT:
    ClearSessoins();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @   UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC007
* @test  UT_TLS13_RFC8446_PSKHASH_TC001_1
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256. if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*        cipher suite.
* @title  The hash settings on the client and server are inconsistent.
* @precon  nan
* @brief
* 1. Preset the PSK. The client invokes HITLS_PskUseSessionCb to set the hash to sha384, and the service invokes
*    HITLS_PskFindSessionCb to set the hash to sha256.
* 2. Connect establishment
* @expect
* 1. The setting is successful.
* 2. Connect establishment fails.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC007()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetNewSessionCb(testInfo.c_config, Test_NewSessionCb);

    // Preset the PSK.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // The client invokes HITLS_PskUseSessionCb to set the hash to sha384, and the service invokes
    // HITLS_PskFindSessionCb to set the hash to sha256.
    HITLS_CFG_SetPskUseSessionCallback(testInfo.c_config, Test_PskUseSessionCb_WithSHA384);
    HITLS_CFG_SetPskFindSessionCallback(testInfo.s_config, Test_PskFindSessionCb_WithSHA256);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Connect establishment
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE) , HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    ClearSessoins();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC002
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256.if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*        cipher suite.
* @title  The hash set does not match the hash of the negotiated cipher suite.
* @precon  nan
* @brief
* 1. Preset the PSK. The client and service monotonically use the HITLS_PskUseSessionCb to set the hash to sha256 and
*    the negotiation cipher suite to sha384.
* 2. Connect establishment
* @expect
* 1. The setting is successful.
* 2. If the PSK authentication fails, perform certificate authentication.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC002()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetNewSessionCb(testInfo.c_config, Test_NewSessionCb);

    // Preset the PSK.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // The client and service monotonically use the HITLS_PskUseSessionCb to set the hash to sha256 and the negotiation
    // cipher suite to sha384.
    uint16_t cipher_suite[] = {HITLS_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite) / sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite) / sizeof(uint16_t));
    HITLS_CFG_SetPskUseSessionCallback(testInfo.c_config, Test_PskUseSessionCb_WithSHA256);
    HITLS_CFG_SetPskFindSessionCallback(testInfo.s_config, Test_PskFindSessionCb_WithSHA256);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Connect establishment
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    ClearSessoins();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC003
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256.if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*        cipher suite.
* @title  The hash set by the hash matches the hash of the negotiated cipher suite.
* @precon  nan
* @brief
* 1. Preset the PSK. Use the HITLS_PskUseSessionCb command to set the hash to sha256 and the negotiation cipher suite to
*    sha256.
* 2. Connect establishment
* @expect
* 1. The setting is successful.
* 2. The connection is set up successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC003()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetNewSessionCb(testInfo.c_config, Test_NewSessionCb);

    // Preset the PSK.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Use the HITLS_PskUseSessionCb command to set the hash to sha256 and the negotiation cipher suite to sha256.
    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256 };
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetPskUseSessionCallback(testInfo.c_config, Test_PskUseSessionCb_WithSHA256);
    HITLS_CFG_SetPskFindSessionCallback(testInfo.s_config, Test_PskFindSessionCb_WithSHA256);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Connect establishment
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recBuf = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recBuf, recLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *ServerHello = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(ServerHello->pskSelectedIdentity.data.data == 0);

    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

EXIT:
    ClearSessoins();
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC004
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256 if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*        cipher suite.
* @title  The default client hash is sha256.
* @precon  nan
* @brief
* 1. Preset the PSK. The client does not set the hash algorithm. The server sets the hash algorithm to 256 and the
*     negotiation cipher suite to sha256.
* 2. Establish a connection and check the hash algorithm on the client.
* @expect
* 1. The setting is successful.
* 2. The connection is set up successfully, and the hash algorithm on the client is 256.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC004()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetNewSessionCb(testInfo.c_config, Test_NewSessionCb);

    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256 };

    // Preset the PSK.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // The client does not set the hash algorithm. The server sets the hash algorithm to 256 and the negotiation cipher
    // suite to sha256.
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite) / sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite) / sizeof(uint16_t));
    HITLS_CFG_SetPskUseSessionCallback(testInfo.c_config, Test_PskUseSessionCb_Default);
    HITLS_CFG_SetPskFindSessionCallback(testInfo.s_config, Test_PskFindSessionCb_WithSHA256);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Establish a connection and check the hash algorithm on the client.
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE) != HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC005
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256.if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*        cipher suite.
* @title  The default hash on the server is sha256.
* @precon  nan
* @brief
* 1. Preset the PSK. The server does not set the hash algorithm. The client sets the hash algorithm to 256 and the
*    negotiation cipher suite to sha256.
* 2. Establish a connection and check the hash algorithm on the server.
* @expect
* 1. The setting is successful.
* 2. The connection is set up successfully, and the hash algorithm on the server is 256.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC005()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetNewSessionCb(testInfo.c_config, Test_NewSessionCb);

    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256 };

    // Preset the PSK.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // The server does not set the hash algorithm. The client sets the hash algorithm to 256 and the negotiation cipher
    // suite to sha256.
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite) / sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite) / sizeof(uint16_t));
    HITLS_CFG_SetPskUseSessionCallback(testInfo.c_config, Test_PskUseSessionCb_WithSHA256);
    HITLS_CFG_SetPskFindSessionCallback(testInfo.s_config, Test_PskFindSessionCb_Default);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Establish a connection and check the hash algorithm on the server.
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE) != HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC006
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec  For externally established PSKs, the Hash algorithm MUST be set when the PSK is established or default to
*        SHA-256.if no such algorithm is defined. The server MUST ensure that it selects a compatible PSK (if any) and
*         cipher suite.
* @title  The hash setting is inconsistent with the negotiated cipher suite.
* @precon  nan
* @brief
* 1. The client invokes the HITLS_PskClientCb interface to set the preset PSK. The server invokes the HITLS_PskClientCb
*     interface to set the preset PSK.
* 2. The algorithm suite negotiation result is 384,
* 3. Establish a connection.
* @expect
* 1. The setting is successful.
* 2. The setting is successful.
* 3. The connection is successfully established and certificate authentication is performed.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKHASH_FUNC_TC006()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();

    // The client invokes the HITLS_PskClientCb interface to set the preset PSK. The server invokes the HITLS_PskClientCb interface to set the preset PSK.
    char psk[] = "aaaaaaaaaaaaaaaa";
    ASSERT_TRUE(ExampleSetPsk(psk) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskClientCallback(testInfo.c_config, ExampleClientCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetPskServerCallback(testInfo.s_config, ExampleServerCb) == HITLS_SUCCESS);

    // The algorithm suite negotiation result is 384
    uint16_t cipher_suite[] = { HITLS_AES_256_GCM_SHA384 };
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    // Establish a connection.
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE) , HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKBINDER_FUNC_TC001
* @brief 4.2.11-Pre-Shared Key Extension-97
* @spec  the server MUST validate the corresponding binder value (see Section 4.2.11.2 below).
*         If this value is not present or does not validate, the server MUST abort the handshake.
* @title  Modify the binder of client hello to make the server verification fail.
* @precon  nan
* @brief
* 1. The connection is established and the session is restored.
* 2. Change the value of binder in the psk extension of the client hello message sent by the client, and observe the
*    behavior on the server.
* @expect
* 1. The setting is successful.
* 2. The server terminates the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKBINDER_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    // The connection is established and the session is restored.
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Change the value of binder in the psk extension of the client hello message sent by the client, and observe the
    // behavior on the server.
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_Client_Binder_Unnormal};
    RegisterWrapper(wrapper);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_PSK_INVALID);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKBINDER_FUNC_TC003
* @brief 4.2.11-Pre-Shared Key Extension-97
* @spec  the server MUST validate the corresponding binder value (see Section 4.2.11.2 below).
*         If this value is not present or does not validate, the server MUST abort the handshake.
* @title  Modify the client hello message so that the server fails to verify the binder.
* @precon  nan
* @brief
* 1. The connection is established and the session is restored.
* 2. Discard the master_secret extension of the client hello message sent by the client and observe the behavior of the
*    server.
* @expect
* 1. The setting is successful.
* 2. The server terminates the handshake.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_PSKBINDER_FUNC_TC003()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);

    // The connection is established and the session is restored.
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Discard the master_secret extension of the client hello message sent by the client and observe the behavior of
    // the server.
    RecWrapper wrapper = {TRY_SEND_CLIENT_HELLO, REC_TYPE_HANDSHAKE, false, NULL, Test_Client_MasterSecret_Miss};
    RegisterWrapper(wrapper);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_EQ(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession), HITLS_SUCCESS);

    ASSERT_EQ(
        FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT), HITLS_MSG_HANDLE_PSK_INVALID);
EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECODE_VERSION_FUNC_TC001
* @brief 4.2.11-Pre-Shared Key Extension-97
* @spec  Implementations MUST NOT send any records with a version less than 0x0300.
*         Implementations SHOULD NOT accept any records with a version less than 0x0300
* @title  The server receives a client hello message whose recode version is 0x0300/0x0200.
* @precon  nan
* @brief
* 1. Change the recode version of the client hello message sent by the client to 0x0300/0x0200.
* 2. Observe the server behavior.
* @expect
* 1. The setting is successful.
* 2. Connect establishment success/failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECODE_VERSION_FUNC_TC001(int value, int expect)
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_RECV_CLIENT_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    /* Change the recode version of the client hello message sent by the client to 0x0300/0x0200. */
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    frameMsg.recVersion.data = value;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.server->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    /* Observe the server behavior. */
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Accept(testInfo.server->ssl), expect);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECODE_VERSION_FUNC_TC002
* @brief 4.2.11-Pre-Shared Key Extension-97
* @spec  Implementations MUST NOT send any records with a version less than 0x0300.
*         Implementations SHOULD NOT accept any records with a version less than 0x0300
* @title  The client receives the server hello message whose recode version is 0x0300/0x0200.
* @precon  nan
* @brief
* 1. Change the recode version of the client hello message sent by the server to 0x0300/0x0200.
* 2. Observe client behavior.
* @expect
* 1. The setting is successful.
* 2. Connect establishment success/failure
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECODE_VERSION_FUNC_TC002(int value, int expect)
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;

    testInfo.s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.s_config != NULL);
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(testInfo.c_config != NULL);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    /* Change the recode version of the client hello message sent by the server to 0x0300/0x0200. */
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    frameMsg.recVersion.data = value;

    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &frameMsg, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);

    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(testInfo.client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    FRAME_CleanMsg(&frameType, &frameMsg);
    memset_s(&frameMsg, sizeof(frameMsg), 0, sizeof(frameMsg));

    /* Observe client behavior. */
    ASSERT_TRUE(testInfo.server->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), expect);
EXIT:
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC001
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec
* @title  Two PSKs. Select the first one when the conditions are met.
* @precon  nan
* @brief
* 1. The PSK is generated during connection establishment, and set to the client.
* 2. Preset the PSK and establish a connection.
* @expect
* 1. The setting is successful.
* 2. The connection is successfully set up and the first PSK is selected.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC001()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();

    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256 };
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // The PSK is generated during connection establishment, and set to the client.
    HITLS_CFG_SetPskClientCallback(testInfo.c_config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.s_config, (HITLS_PskServerCb)ExampleServerCb);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) , HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    /* Preset the PSK and establish a connection. */
    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.exLen.data != 0);
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.data.data == 0);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_SESS_Free(testInfo.clientSession);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC002
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec
* @title  Two psks. If the former one does not meet the requirements, select the second one.
* @precon  nan
* @brief
* 1. The PSK is generated during connection establishment. Configure the default 384 algorithm suite on the client.
* 2. Set the 256 cipher suite, preset the PSK, and establish a connection.
* @expect
* 1. The setting is successful.
* 2. The connection is successfully established and the second cipher suite is selected.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC002()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();

    // The PSK is generated during connection establishment. Configure the default 384 algorithm suite on the client.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    /* Set the 256 cipher suite, preset the PSK, and establish a connection. */
    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256, HITLS_AES_256_GCM_SHA384 };
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite[0])/sizeof(uint16_t));

    HITLS_CFG_SetPskClientCallback(testInfo.c_config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.s_config, (HITLS_PskServerCb)ExampleServerCb);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) , HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.exLen.data != 0);
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.data.data == 1);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_SESS_Free(testInfo.clientSession);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC003
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec
* @title Neither of the two PSKs meets the requirements. Select certificate authentication.
* @precon nan
* @brief
* 1. Set the 256 algorithm suite and set up a connection to generate a PSK, and set to the client.
* 2. Set the 384 algorithm suite, preset the PSK, and establish a connection.
* @expect
* 1. The setting is successful.
* 2. The connection is successfully established and the PSK authentication is performed.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC003()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();

    // Set the 256 algorithm suite and set up a connection to generate a PSK, and set to the client.
    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256 };
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));

    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Set the 384 algorithm suite, preset the PSK, and establish a connection.
    cipher_suite[0] = HITLS_AES_256_GCM_SHA384;
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));

    HITLS_CFG_SetPskClientCallback(testInfo.c_config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.s_config, (HITLS_PskServerCb)ExampleServerCb);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) , HITLS_SUCCESS);

    /* Obtain the message buffer. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    /* Parse the structure to the msg structure. */
    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.exLen.data == 0);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_SEND_CERTIFICATE) , HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_SESS_Free(testInfo.clientSession);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC004
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec
* @title Trigger the hrr message and select the PSK.
* @precon nan
* @brief
* 1. The PSK is generated during connection establishment, and set on the client.
* 2. Set a group so that the server triggers the hrr message, preset the PSK, and establish a connection.
* @expect
* 1. The setting is successful.
* 2. The connection is successfully set up. The server sends the hrr message and selects the PSK.
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC004()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();

    // The PSK is generated during connection establishment, and set on the client.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    // Set a group so that the server triggers the hrr message, preset the PSK, and establish a connection.
    uint16_t clientGroups[] = {HITLS_EC_GROUP_CURVE25519, HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.c_config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t));
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo.s_config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t));

    HITLS_CFG_SetPskClientCallback(testInfo.c_config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.s_config, (HITLS_PskServerCb)ExampleServerCb);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) , HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(testInfo.server->ssl->hsCtx->haveHrr == true);
    serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.data.data == 0);
    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(testInfo.client->ssl), HITLS_REC_NORMAL_IO_BUSY);

    FrameUioUserData *ioUserData2 = BSL_UIO_GetUserData(testInfo.client->io);
    uint32_t sendLen = ioUserData2->sndMsg.len;
    ASSERT_TRUE(sendLen != 0);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_SESS_Free(testInfo.clientSession);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC005
* @brief 4.2.11-Pre-Shared Key Extension-94
* @spec
* @title Compatibility between session restoration and user-configured PSK
* @precon nan
* @brief
1. create a tls1.3 connection
2. Configure the user-defined PSK through the callback function.
3. Ensure that the PSK length configured by the user is greater than the PSK length for session restoration.
4. Establish a link again.
* @expect
1. The connection is successful.
2. Configuration succeeded.
3. Configuration succeeded.
4. The connection is successful.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RESUMEPSK_AND_SETPSK_FUNC_TC005()
{
    FRAME_Init();

    ResumeTestInfo testInfo = {0};
    testInfo.version = HITLS_VERSION_TLS13;
    testInfo.uioType = BSL_UIO_TCP;
    testInfo.c_config = HITLS_CFG_NewTLS13Config();
    testInfo.s_config = HITLS_CFG_NewTLS13Config();

    // The PSK is generated during link establishment. Configure the default 384 algorithm suite on the client.
    ASSERT_EQ(DoHandshake(&testInfo), HITLS_SUCCESS);
    testInfo.clientSession = HITLS_GetDupSession(testInfo.client->ssl);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    FRAME_FreeLink(testInfo.client);
    testInfo.client = NULL;
    FRAME_FreeLink(testInfo.server);
    testInfo.server = NULL;

    /* Set the 256 cipher suite, preset the PSK, and establish a link. */
    uint16_t cipher_suite[] = { HITLS_AES_128_GCM_SHA256, HITLS_AES_256_GCM_SHA384};
    HITLS_CFG_SetCipherSuites(testInfo.c_config, cipher_suite, sizeof(cipher_suite)/sizeof(uint16_t));
    HITLS_CFG_SetCipherSuites(testInfo.s_config, cipher_suite, sizeof(cipher_suite[0])/sizeof(uint16_t));

    ExampleSetPsk("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    HITLS_CFG_SetPskClientCallback(testInfo.c_config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetPskServerCallback(testInfo.s_config, (HITLS_PskServerCb)ExampleServerCb);

    testInfo.client = FRAME_CreateLink(testInfo.c_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.client != NULL);
    testInfo.server = FRAME_CreateLink(testInfo.s_config, testInfo.uioType);
    ASSERT_TRUE(testInfo.server != NULL);
    ASSERT_TRUE(HITLS_SetSession(testInfo.client->ssl, testInfo.clientSession) == HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, TRY_RECV_SERVER_HELLO) , HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverMsg = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.exLen.data != 0);
    ASSERT_TRUE(serverMsg->pskSelectedIdentity.data.data == 1);

    ASSERT_TRUE(testInfo.client->ssl != NULL);
    ASSERT_EQ(FRAME_CreateConnection(testInfo.client, testInfo.server, true, HS_STATE_BUTT) , HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_SESS_Free(testInfo.clientSession);
    HITLS_CFG_FreeConfig(testInfo.c_config);
    HITLS_CFG_FreeConfig(testInfo.s_config);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
}
/* END_CASE */

/* During the TLS1.3 HRR handshaking, application messages can not be received*/
/* BEGIN_CASE */
void UT_TLS13_RFC8446_HRR_APP_RECV_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLSConfig();
    tlsConfig->isSupportClientVerify = true;
    HITLS_CFG_SetKeyExchMode(tlsConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(&(serverTlsCtx->config.tlsConfig), groups, groupsSize);
    /* 1. Initialize the client and server to tls1.3, construct the scenario where the supportedversion values carried
        by serverhello and hrr are different, */
    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    CONN_Deinit(serverTlsCtx);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);

    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_SEND_CHANGE_CIPHER_SPEC);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == TRY_SEND_CLIENT_HELLO);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    uint32_t sendLenapp = 7;
    uint8_t sendBufapp[7] = {0x17, 0x03, 0x03, 0x00, 0x02, 0x05, 0x05};
    uint32_t writeLen;
    BSL_UIO_Write(clientTlsCtx->uio, sendBufapp, sendLenapp, &writeLen);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(serverTlsCtx), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS1_3_RFC8446_Legacy_Version_TC001
* @spec     For TLS 1.3, the legacy_record_version set to 0x0403 to client will get alert
* @title    For TLS 1.3, the legacy_record_version set to 0x0403 to client will get alert
* @precon   nan
* @brief    5.1.  Record Layer line 190
*           legacy_record_version: MUST be set to 0x0303 for all records generated by a TLS 1.3
            implementation other than an initial ClientHello (i.e., one not generated after a HelloRetryRequest),
            where it MAY also be 0x0301 for compatibility purposes. This field is deprecated and MUST be ignored
            for all purposes. Previous versions of TLS would use other values in this field under some circumstances.
@ */
/* BEGIN_CASE */
void UT_TLS1_3_RFC8446_Legacy_Version_TC001(int statehs)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    /* Configure the server to support only the non-default curve. The server sends the HRR message. */
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(tlsConfig, groups, groupsSize);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, statehs) == HITLS_SUCCESS);
    ASSERT_TRUE(clientTlsCtx->hsCtx->state == (HITLS_HandshakeState)statehs);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.msg[1] = 0x04u;
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_INVALID_PROTOCOL_VERSION);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    if (statehs == TRY_RECV_SERVER_HELLO) {
        ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
    } else {
        ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test     UT_TLS1_3_RFC8446_Legacy_Version_TC002
* @spec     For TLS 1.3, the legacy_record_version set to 0x0403 to server will get alert
* @title    For TLS 1.3, the legacy_record_version set to 0x0403 to server will get alert
* @precon   nan
* @brief    5.1.  Record Layer line 190
*           legacy_record_version: MUST be set to 0x0303 for all records generated by a TLS 1.3
            implementation other than an initial ClientHello (i.e., one not generated after a HelloRetryRequest),
            where it MAY also be 0x0301 for compatibility purposes. This field is deprecated and MUST be ignored
            for all purposes. Previous versions of TLS would use other values in this field under some circumstances.
@ */
/* BEGIN_CASE */
void UT_TLS1_3_RFC8446_Legacy_Version_TC002(int statehs)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    /* Configure the server to support only the non-default curve. The server sends the HRR message. */
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(tlsConfig, groups, groupsSize);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, statehs) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == (HITLS_HandshakeState)statehs);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
    ioClientData->recMsg.msg[1] = 0x04u;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_INVALID_PROTOCOL_VERSION);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    if (statehs == TRY_RECV_CLIENT_HELLO) {
        ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
    } else {
        ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test UT_TLS_TLS13_RFC8446_CONSISTENCY_ALERT_PROCESS_TC001
* @spec -
* @title During connection establishment, tls13 server receives a warning alert, the connection state change to alerted
* @precon nan
* @brief 1. Initialize the client and server. Expected result 1.
* 2. Initiate a connection, keep the connection status in the receive_client_key_exchange state,
     and simulate the scenario where the server receives a warning alert message. (Expected result 2)
* @expect 1. Complete initialization.
* 2. the connection state of server change to alerted
* @prior Level 2
* @auto TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_ALERT_PROCESS_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = false;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(FRAME_CreateConnection(client, server, false, TRY_RECV_CERTIFICATE), HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_HANDSHAKING);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint8_t alertMsg[2] = {ALERT_LEVEL_WARNING, ALERT_NO_RENEGOTIATION};
    ASSERT_EQ(REC_Write(clientTlsCtx, REC_TYPE_ALERT, alertMsg, sizeof(alertMsg)), HITLS_SUCCESS);
    // clear the certificate verify in the cache
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    ASSERT_EQ(REC_Write(clientTlsCtx, REC_TYPE_ALERT, alertMsg, sizeof(alertMsg)), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_ALERTED);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_HELLO_REQUEST_TC001
* @spec  -
* @title  Send a hello request when the link status is CM_STATE_IDLE.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a HelloRequest message and send it to the client. The client invokes the HITLS_Connect interface
    to receive the message. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the HelloRequest message, the client ignores the message and stays in the
    TRY_RECV_SERVER_HELLO state after sending the ClientHello message.
* @prior  Level 1
* @auto  TRUE
@ */

/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_HELLO_REQUEST_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

    // Construct a HelloRequest message and send it to the client.
    uint8_t buf[HS_MSG_HEADER_SIZE] = {0u};
    size_t len = HS_MSG_HEADER_SIZE;
    REC_Write(server->ssl, REC_TYPE_HANDSHAKE, buf, len);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(server, client) == HITLS_SUCCESS);

    ASSERT_TRUE(client->ssl != NULL);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(client->ssl->hsCtx->state == TRY_RECV_SERVER_HELLO);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
    frametype->transportType = BSL_UIO_TCP;
}

/** @
* @test  UT_TLS_TLS13_RFC8446_MODIFIED_SESSID_FROM_SH_TC002
* @spec  -
* @title  Send a empty session id to client.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a server hello message with empty session id and send it to the client.
             Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the HelloRequest message, the client send a ILLEGAL_PARAMETER alert.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_MODIFIED_SESSID_FROM_SH_TC002()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recvBuf = ioUserData->recMsg.msg;
    uint32_t recvLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recvLen != 0);
    FRAME_Msg parsedSH = {0};
    uint32_t parseLen = 0;
    FRAME_Type frameType = {0};
    SetFrameType(&frameType, HITLS_VERSION_TLS13, REC_TYPE_HANDSHAKE, SERVER_HELLO, HITLS_KEY_EXCH_ECDHE);
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recvBuf, recvLen, &parsedSH, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *shMsg = &parsedSH.body.hsMsg.body.serverHello;
    shMsg->sessionId.size = 0;
    shMsg->sessionId.state = MISSING_FIELD;
    shMsg->sessionIdSize.data = 0;
    uint32_t sendLen = MAX_RECORD_LENTH;
    uint8_t sendBuf[MAX_RECORD_LENTH] = {0};
    ASSERT_TRUE(FRAME_PackMsg(&frameType, &parsedSH, sendBuf, sendLen, &sendLen) == HITLS_SUCCESS);
    ioUserData->recMsg.len = 0;
    ASSERT_TRUE(FRAME_TransportRecMsg(client->io, sendBuf, sendLen) == HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_MSG_HANDLE_ILLEGAL_SESSION_ID);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(client->ssl, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    FRAME_CleanMsg(&frameType, &parsedSH);
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test  UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_MUTI_CCS_TC001
* @spec  -
* @title  IN TLS1.3, mutiple ccs can be received.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct a ChangeCipherSpec message and send it to the client five times. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. return HITLS_REC_NORMAL_RECV_BUF_EMPTY.
* @prior  Level 1
* @auto  TRUE
@ */
/* IN TLS1.3, mutiple ccs can be received*/
/* BEGIN_CASE */
void UT_TLS_TLS13_RFC8446_CONSISTENCY_RECV_MUTI_CCS_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_VERIFY) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    uint32_t sendLenccs = 6;
    uint8_t sendBufccs[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    uint32_t writeLen;
    for (int i = 0; i < 5; i++) {
        BSL_UIO_Write(serverTlsCtx->uio, sendBufccs, sendLenccs, &writeLen);
        ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
        ASSERT_EQ(HITLS_Connect(clientTlsCtx), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    }
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

static int32_t SendCcs(HITLS_Ctx *ctx, uint8_t *data, uint8_t len)
{
    /** Write records. */
    int32_t ret = REC_Write(ctx, REC_TYPE_CHANGE_CIPHER_SPEC, data, len);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* If isFlightTransmitEnable is enabled, the stored handshake information needs to be sent. */
    bool isFlightTransmitEnable = false;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable == true) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}

static int32_t SendAlert(HITLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    uint8_t data[ALERT_BODY_LEN];
    /** Obtain the alert level. */
    data[0] = level;
    data[1] = description;
    /** Write records. */
    int32_t ret = REC_Write(ctx, REC_TYPE_ALERT, data, ALERT_BODY_LEN);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    /* If isFlightTransmitEnable is enabled, the stored handshake information needs to be sent. */
    bool isFlightTransmitEnable = false;
    (void)HITLS_GetFlightTransmitSwitch(ctx, &isFlightTransmitEnable);
    if (isFlightTransmitEnable == true) {
        ret = BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
        if (ret == BSL_UIO_IO_BUSY) {
            return HITLS_REC_NORMAL_IO_BUSY;
        }
        if (ret != BSL_SUCCESS) {
            return HITLS_REC_ERR_IO_EXCEPTION;
        }
    }
    return HITLS_SUCCESS;
}

/** @
* @test  UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_RECEIVES_ENCRYPTED_CCS_TC001
* @spec  -
* @title  The encrypted CCS is received when the plaintext CCS is received.
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct encrypted CCS and send it to the client. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the CCS message, the client send a UNEXPECTED_MESSAGE alert.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_RECEIVES_ENCRYPTED_CCS_TC001(void)
{
    FRAME_Init();

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO) == HITLS_SUCCESS);
    // Sends serverhello to the peer end.
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    // Processing serverhello
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    serverTlsCtx->recCtx->outBuf->end = 0;
    uint32_t hashLen = SAL_CRYPT_DigestSize(serverTlsCtx->negotiatedInfo.cipherSuiteInfo.hashAlg);
    ASSERT_EQ(HS_SwitchTrafficKey(serverTlsCtx, serverTlsCtx->hsCtx->serverHsTrafficSecret, hashLen, true),
        HITLS_SUCCESS);
    uint8_t data = 1;
    // send crypto ccs
    ASSERT_EQ(SendCcs(server->ssl, &data, sizeof(data)), HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->sndMsg.msg[0] = REC_TYPE_APP;
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(client->io);
    ioClientData->recMsg.len = 0;
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    // process crypto ccs
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

#define ALERT_UNKNOWN_DESCRIPTION 254

/** @
* @test  UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_UNKNOWN_DESCRIPTION_TC001
* @spec  -
* @title  RFC8446 6.2 All alerts defined below in this section, as well as all unknown alerts,
        are universally considered fatal as of TLS 1.3 (see Section 6).
* @precon  nan
* @brief  1. Use the configuration items to configure the client and server. Expected result 1 is obtained.
*         2. Construct alert message with alert level warning and ALERT_UNKNOWN_DESCRIPTION, and send it to the server.
            Expected result 2 is obtained.
* @expect 1. The initialization is successful.
*         2. After receiving the alert message, the server send a FATAL alert.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_UNKNOWN_DESCRIPTION_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportClientVerify = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_FINISH) == HITLS_SUCCESS);

    ASSERT_TRUE(SendAlert(client->ssl, ALERT_LEVEL_WARNING, ALERT_UNKNOWN_DESCRIPTION) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    HITLS_Ctx *Ctx = FRAME_GetTlsCtx(server);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(Ctx, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_UNKNOWN_DESCRIPTION);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS13_RFC8446_REQUEST_CLIENT_HELLO_TC008
* @brief 2.1.  Incorrect DHE Share
* @spec  If the client has not provided a sufficient "key_share" extension (e.g., it includes only DHE or ECDHE groups
    unacceptable to or unsupported by the server), the server corrects the mismatch with a HelloRetryRequest and the
    client needs to restart the handshake with an appropriate "key_share" extension, as shown in Figure 2. If no common
    cryptographic parameters can be negotiated, the server MUST abort the handshake with an appropriate alert.
* @title  Configure groups_list:"brainpoolP512r1:X25519" on the client and groups_list:"brainpoolP512r1:X25519" on the
    server. Observe the link setup result and check whether the server sends Hello_Retry_Requset.
* @precon  nan
* @brief
1. Configure groups_list:"brainpoolP512r1:X25519" on the client and groups_list:"brainpoolP512r1:X25519" on the
    server.
* @expect
1. Send clienthello with X25519 keyshare. The link is established successfully.
2. The server does not send Hello_Retry_Requset.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_REQUEST_CLIENT_HELLO_TC001()
{
    FRAME_Init();
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Config *clientconfig = NULL;
    HITLS_Config *serverconfig = NULL;
    clientconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(clientconfig != NULL);
    serverconfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(serverconfig != NULL);

    uint16_t clientgroups[] = {HITLS_EC_GROUP_BRAINPOOLP512R1, HITLS_EC_GROUP_CURVE25519};
    uint16_t servergroups[] = {HITLS_EC_GROUP_BRAINPOOLP512R1, HITLS_EC_GROUP_CURVE25519};
    ASSERT_EQ(HITLS_CFG_SetGroups(serverconfig, servergroups, sizeof(servergroups)/sizeof(uint16_t)) , HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(clientconfig, clientgroups, sizeof(clientgroups)/sizeof(uint16_t)) , HITLS_SUCCESS);

    client = FRAME_CreateLink(clientconfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(serverconfig, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *recBuf = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen != 0);

    uint32_t parseLen = 0;
    FRAME_Msg frameMsg = {0};
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = SERVER_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    ASSERT_TRUE(FRAME_ParseMsg(&frameType, recBuf, recLen, &frameMsg, &parseLen) == HITLS_SUCCESS);

    FRAME_ServerHelloMsg *serverHello = &frameMsg.body.hsMsg.body.serverHello;
    ASSERT_TRUE(serverHello->keyShare.data.group.data == HITLS_EC_GROUP_CURVE25519);
    ASSERT_EQ(server->ssl->hsCtx->haveHrr, false);

    // Continue to establish the link.
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    HITLS_CFG_FreeConfig(clientconfig);
    HITLS_CFG_FreeConfig(serverconfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/** @
* @test     UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_Legacy_Version_TC001
* @spec     For TLS 1.3, the legacy_record_version set to 0x0403 to server will get alert
* @title    For TLS 1.3, the legacy_record_version set to 0x0403 to server will get alert
* @precon   nan
* @brief    5.1.  Record Layer line 190
*           legacy_record_version: MUST be set to 0x0303 for all records generated by a TLS 1.3
            implementation other than an initial ClientHello (i.e., one not generated after a HelloRetryRequest),
            where it MAY also be 0x0301 for compatibility purposes. This field is deprecated and MUST be ignored
            for all purposes. Previous versions of TLS would use other values in this field under some circumstances.
@ */
/* BEGIN_CASE */
void UT_TLS_SDV_TLS1_3_RFC8446_CONSISTENCY_Legacy_Version_TC001(int statehs)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportExtendedMasterSecret = true;
    tlsConfig->isSupportClientVerify = true;
    tlsConfig->isSupportNoClientCert = true;

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    client = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    /* Configure the server to support only the non-default curve. The server sends the HRR message. */
    const uint16_t groups[] = {HITLS_EC_GROUP_SECP521R1};
    uint32_t groupsSize = sizeof(groups) / sizeof(uint16_t);
    HITLS_CFG_SetGroups(tlsConfig, groups, groupsSize);
    server = FRAME_CreateLink(tlsConfig, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, statehs) == HITLS_SUCCESS);
    ASSERT_TRUE(serverTlsCtx->hsCtx->state == (HITLS_HandshakeState)statehs);
    FrameUioUserData *ioClientData = BSL_UIO_GetUserData(server->io);
    ioClientData->recMsg.msg[1] = 0x04u;
    ASSERT_EQ(HITLS_Accept(server->ssl), HITLS_REC_INVALID_PROTOCOL_VERSION);
    ALERT_Info info = {0};
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    if (statehs == TRY_RECV_CLIENT_HELLO) {
        ASSERT_EQ(info.description, ALERT_PROTOCOL_VERSION);
    } else {
        ASSERT_EQ(info.description, ALERT_DECODE_ERROR);
    }
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */