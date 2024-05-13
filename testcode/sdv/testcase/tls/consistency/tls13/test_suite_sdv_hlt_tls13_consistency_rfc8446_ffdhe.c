/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */
/* INCLUDE_BASE test_suite_tls13_consistency_rfc8446 */
#include <stdio.h>
#include "stub_replace.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_uio.h"
#include "tls.h"
#include "hs_ctx.h"
#include "pack.h"
#include "send_process.h"
#include "frame_link.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "rec_wrapper.h"
#include "cert.h"
#include "securec.h"
#include "conn_init.h"
#include "hitls_crypt_init.h"
#include "hitls_psk.h"
#include "common_func.h"
#include "alert.h"
#include "process.h"
#include "bsl_sal.h"
/* END_HEADER */

#define PORT 6666
#define MAX_BUF_SIZE 18432

void GetStrGroup(int ConnType, int group, char** strgroup)
{
    if (ConnType == HITLS) {
        switch (group) {
        case HITLS_FF_DHE_2048:
            *strgroup = "HITLS_FF_DHE_2048";break;
        case HITLS_FF_DHE_3072:
            *strgroup = "HITLS_FF_DHE_3072";break;
        case HITLS_FF_DHE_4096:
            *strgroup = "HITLS_FF_DHE_4096";break;
        case HITLS_FF_DHE_6144:
            *strgroup = "HITLS_FF_DHE_6144";break;
        case HITLS_FF_DHE_8192:
            *strgroup = "HITLS_FF_DHE_8192";break;
        default:
            break;
        }
    } else {
        switch (group) {
        case HITLS_FF_DHE_2048:
            *strgroup = "ffdhe2048";break;
        case HITLS_FF_DHE_3072:
            *strgroup = "ffdhe3072";break;
        case HITLS_FF_DHE_4096:
            *strgroup = "ffdhe4096";break;
        case HITLS_FF_DHE_6144:
            *strgroup = "ffdhe6144";break;
        case HITLS_FF_DHE_8192:
            *strgroup = "ffdhe8192";break;
        default:
            break;
        }
    }
}

void HRR_ClientGroupSetInfo(int ClientType, int group, char** clientgroup)
{
    if (ClientType == HITLS) {
        switch (group) {
        case HITLS_FF_DHE_2048:
            *clientgroup = "HITLS_EC_GROUP_SECP256R1:HITLS_FF_DHE_2048";break;
        case HITLS_FF_DHE_3072:
            *clientgroup = "HITLS_EC_GROUP_SECP256R1:HITLS_FF_DHE_3072";break;
        case HITLS_FF_DHE_4096:
            *clientgroup = "HITLS_EC_GROUP_SECP256R1:HITLS_FF_DHE_4096";break;
        case HITLS_FF_DHE_6144:
            *clientgroup = "HITLS_EC_GROUP_SECP256R1:HITLS_FF_DHE_6144";break;
        case HITLS_FF_DHE_8192:
            *clientgroup = "HITLS_EC_GROUP_SECP256R1:HITLS_FF_DHE_8192";break;
        default:
            break;
        }
    } else {
        switch (group) {
        case HITLS_FF_DHE_2048:
            *clientgroup = "P-256:ffdhe2048";break;
        case HITLS_FF_DHE_3072:
            *clientgroup = "P-256:ffdhe3072";break;
        case HITLS_FF_DHE_4096:
            *clientgroup = "P-256:ffdhe4096";break;
        case HITLS_FF_DHE_6144:
            *clientgroup = "P-256:ffdhe6144";break;
        case HITLS_FF_DHE_8192:
            *clientgroup = "P-256:ffdhe8192";break;
        default:
            break;
        }
    }
}

static void Test_FFDHE_Key_ERROR(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
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

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.state = ASSIGNED_FIELD;

    memset_s(frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.data,
            frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.data, 255,
            frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.data );

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_FFDHE_Key_Client_DecodeError(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
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

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.state = ASSIGNED_FIELD;

    memset_s(frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.data,
            frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.data, 8, 10);
    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_FFDHE_KeyLen_LessThenStandard(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
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

    frameMsg.body.hsMsg.body.clientHello.keyshares.exLen.state = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exLen.data += (120 - 256);

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShareLen.state = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShareLen.data += (120 - 256);

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.data = 120;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.data);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.data = BSL_SAL_Malloc(120);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.size = 120;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_FFDHE_KeyLen_MoreThenStandard(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
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

    frameMsg.body.hsMsg.body.clientHello.keyshares.exLen.state = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exLen.data += (1100 - 256);

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShareLen.state = INITIAL_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShareLen.data += (1100 - 256);

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.data = 1100;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.state = ASSIGNED_FIELD;
    BSL_SAL_FREE(frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.data);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.data = BSL_SAL_Malloc(1100);
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchange.size = 1100;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static void Test_FFDHE_KeyLen_Error(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
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

    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.state = ASSIGNED_FIELD;
    frameMsg.body.hsMsg.body.clientHello.keyshares.exKeyShares.data->keyExchangeLen.data = 128;

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);

exit:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/**
 * @brief tls1.3 ffdhe base testcase
 * base test case
 */
/* BEGIN_CASE */
void UT_TLS13_RFC8446_FFDHE_TC001()
{
    int version = TLS1_3;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportClientVerify = true;
    clientCtxConfig->isSupportPostHandshakeAuth = true;
    HLT_SetGroups(clientCtxConfig, "HITLS_FF_DHE_4096");

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportClientVerify = true;
    serverCtxConfig->isSupportPostHandshakeAuth = true;
    serverCtxConfig->securitylevel = 0;
    HLT_SetGroups(serverCtxConfig, "HITLS_FF_DHE_4096");

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 18889;
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

    int ret = HLT_TlsConnect(clientSsl);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcTlsClose(remoteProcess, serverSslId);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC001
* @spec  -
* @title  Verifying the HRR Link Setup Function When the FFDHE Group Is Used
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Configure the client and server to support ffdhe2048, and set the client to ffdhe2048 as the second supported
&       group.
*   3. Establish a connection and read and write data.
*   4. Switch the group to ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The connection is set up successfully, and data is read and written successfully.
*   4. The connection is set up successfully and data is read and written successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC001(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support ffdhe2048, and set the client to ffdhe2048 as the second supported
    // group.
    GetStrGroup(ServerType, group, &servergroup);
    HRR_ClientGroupSetInfo(ClientType, group, &clientgroup);

    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Establish a connection and read and write data.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    HITLS_Ctx *clientTlsCtx = clientRes->ssl;
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.negotiatedGroup, group);

    uint8_t readBuf[MAX_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC002
* @spec  -
* @title  Verifying the FFDHE Curve Function in PSK Link Establishment
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Set the PSK mode to psk_with_dhe.
*   3. Configure the client and server to support FFDHE2048.
*   4. Establish a connection and read and write data.
*   5. Switch the group to ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The connection is set up successfully and data is read and written successfully.
*   5. The connection is successfully set up, and data is successfully read and written.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC002(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Set the PSK mode to psk_with_dhe.
    HLT_SetKeyExchMode(serverConfig, TLS13_KE_MODE_PSK_WITH_DHE);
    HLT_SetKeyExchMode(clientConfig, TLS13_KE_MODE_PSK_WITH_DHE);

    // Configure the client and server to support FFDHE2048.
    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    memcpy_s(clientConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));
    memcpy_s(serverConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));

    HLT_SetCipherSuites(serverConfig, "HITLS_AES_128_GCM_SHA256");
    HLT_SetCipherSuites(clientConfig, "HITLS_AES_128_GCM_SHA256");
    HLT_SetGroups(clientConfig, clientgroup);
    HLT_SetGroups(serverConfig, servergroup);

    // Establish a connection and read and write data.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    HITLS_Ctx *clientTlsCtx = clientRes->ssl;
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.negotiatedGroup , group);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.tls13BasicKeyExMode , TLS13_KE_MODE_PSK_WITH_DHE);

    uint8_t readBuf[MAX_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC003
* @spec  -
* @title  Verifying the Function of Using the FFDHE Curve for Certificate Rejection Authentication in psk_only Mode
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Set the PSK only on the client.
*   3. Set the PSK mode of the client and server to psk_with_only.
*   4. Set the client and server to ffdhe2048.
*   5. Establish a connection and read and write data.
*   6. Switch the group to ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The setting is successful.
*   5. The connection is successfully set up, and data is successfully read and written.
*   6. The connection is successfully set up, and data is successfully read and written.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC003(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    HLT_SetCipherSuites(serverConfig, "HITLS_AES_128_GCM_SHA256");
    HLT_SetCipherSuites(clientConfig, "HITLS_AES_128_GCM_SHA256");

    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    // Set the PSK only on the client.
    memcpy_s(clientConfig->psk, PSK_MAX_LEN, "12121212121212", sizeof("12121212121212"));

    // Set the PSK mode of the client and server to psk_with_only.
    HLT_SetKeyExchMode(clientConfig, TLS13_KE_MODE_PSK_ONLY);
    HLT_SetKeyExchMode(serverConfig, TLS13_KE_MODE_PSK_ONLY);

    // Set the client and server to ffdhe2048.
    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Establish a connection and read and write data.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), 0);

    HITLS_Ctx *clientTlsCtx = clientRes->ssl;
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.negotiatedGroup , group);
    ASSERT_EQ(clientTlsCtx->negotiatedInfo.tls13BasicKeyExMode , TLS13_CERT_AUTH_WITH_DHE);

    uint8_t readBuf[MAX_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
exit:
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC004
* @spec  -
* @title  The key length in the keyshare file is less than the length required by the RFC.
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Configure the client and server to support ffdhe2048.
*   3. Change the value of Key Exchange Length in the keyshare field in the client hello packet to 120.
*   4. Establish a connection and observe the server behavior.
*   5. Switch the group to ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192, and repeat the preceding operations.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The modification is successful.
*   4. The server sends an alert message to disconnect the connection.
*   5. The server sends an alert message to disconnect the connection.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC004(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support ffdhe2048.
    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Change the value of Key Exchange Length in the keyshare field in the client hello packet to 120.
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_FFDHE_KeyLen_LessThenStandard
    };
    RegisterWrapper(wrapper);

    // Establish a connection and observe the server behavior.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
exit:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC005
* @spec  -
* @title  The key length in the keyshare file is greater than the length required by the RFC.
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Configure the client and server to support FFDHE2048.
*   3. Change the value of Key Exchange Length in the keyshare message sent by the client to 8800.
*   4. Establish a connection and observe the server behavior.
*   5. Switch groups ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192. Repeat the preceding operations.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The setting is successful.
*   4. The modification is successful.
*   5. The server sends an alert message to disconnect the connection.
*   6. The server sends an alert message to disconnect the connection.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC005(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support FFDHE2048.
    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Change the value of Key Exchange Length in the keyshare message sent by the client to 8800.
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_FFDHE_KeyLen_MoreThenStandard
    };
    RegisterWrapper(wrapper);

    // Establish a connection and observe the server behavior.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_MSG_HANDLE_ILLEGAL_SELECTED_GROUP);
exit:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC006
* @spec  -
* @title  The server fails to parse the key in the keyshare file.
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Configure the client and server to support FFDHE2048.
*   3. Change the values of all bits of the key in the keyshare of the client hello packet to 0xff.
*   4. Establish a connection and observe the server behavior.
*   5. Switch groups ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192. Repeat the preceding operations.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The modification is successful.
*   4. The server sends an alert message to disconnect the connection.
*   5. The server sends an alert message to disconnect the connection.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC006(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support FFDHE2048.
    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Change the values of all bits of the key in the keyshare of the client hello packet to 0xff.
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_FFDHE_Key_ERROR
    };
    RegisterWrapper(wrapper);

    // Establish a connection and observe the server behavior.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_CRYPT_ERR_CALC_SHARED_KEY);
exit:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC007
* @spec  -
* @title  The server successfully parses the incorrect key in keyshare.
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Configure the client and server to support the elliptic curve ffdhe2048.
*   3. Change the value of the first 10 bits of the key in the keyshare of the client hello packet to 8.
*   4. Establish a connection and observe the client.
*   5. Switch the elliptic curve and repeat the preceding operations.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The modification is successful.
*   4. The client is disconnected due to decryption failure.
*   5. Client decryption fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC007(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support the elliptic curve ffdhe2048.
    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Change the value of the first 10 bits of the key in the keyshare of the client hello packet to 8.
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_FFDHE_Key_Client_DecodeError
    };
    RegisterWrapper(wrapper);

    // Establish a connection and observe the client.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
exit:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

/** @
* @test  SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC008
* @spec  -
* @title  The key value in keyshare does not match the Key Exchange Length value. Parsing failed.
* @precon  nan
* @brief
*   1. Apply for and initialize the TLS1.3 configuration file.
*   2. Configure the client and server to support FFDHE2048.
*   3. Change the length of the key in the keyshare of the client hello packet to 1024 bits.
*   4. Establish a connection and observe the server behavior.
* @expect
*   1. The initialization is successful.
*   2. The setting is successful.
*   3. The modification is successful.
*   4. The server sends an alert message to disconnect the connection.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS13_RFC8446_CONSISTENCY_DHE_GROUP_FUNC_TC008(int ClientType, int ServerType, int group)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    char *servergroup;
    char *clientgroup;

    localProcess = HLT_InitLocalProcess(ClientType);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(ServerType, TCP, PORT, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // Apply for and initialize the TLS1.3 configuration file.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    // Configure the client and server to support FFDHE2048.
    GetStrGroup(ClientType, group, &clientgroup);
    GetStrGroup(ServerType, group, &servergroup);

    HLT_SetGroups(serverConfig, servergroup);
    HLT_SetGroups(clientConfig, clientgroup);

    // Change the length of the key in the keyshare of the client hello packet to 1024 bits.
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        Test_FFDHE_KeyLen_Error
    };
    RegisterWrapper(wrapper);

    // Establish a connection and observe the server behavior.
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_3, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLS1_3, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_PARSE_INVALID_MSG_LEN);
exit:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */