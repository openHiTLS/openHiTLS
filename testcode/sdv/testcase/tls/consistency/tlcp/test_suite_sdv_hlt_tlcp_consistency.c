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
#include "hs_ctx.h"
#include "pack.h"
#include "process.h"
#include "session_type.h"
#include "hitls_type.h"
#include "send_process.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "uio_base.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "cert.h"
#include "app.h"
#include "hlt.h"
#include "alert.h"
#include "securec.h"
#include "record.h"
#include "rec_wrapper.h"
#include "conn_init.h"
#include "cert_callback.h"
#include "change_cipher_spec.h"
#include "common_func.h"
#include "crypt_util_rand.h"
/* END_HEADER */

static uint32_t g_uiPort = 16888;
#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define REC_CONN_SEQ_SIZE 8u            /* SN size */
#define PORT 11111
typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendedMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isServerExtendedMasterSecret;
    bool isSupportRenegotiation; /* Renegotiation support flag */
    bool needStopBeforeRecvCCS;  /* For CCS test, stop at TRY_RECV_FINISH stage before CCS message is received. */
} HandshakeTestInfo;

int32_t GetSessionCacheMode(HLT_Ctx_Config* config)
{
    return config->setSessionCache;
}

/* @
* @test    SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC001
* @title   Modify the resume flag on the client. Resumption fails
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Modify the resume flag and resume the session. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. Resumption fails
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC001(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    int32_t cachemode = 0;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(clientCtxConfig != NULL);
    ASSERT_TRUE(serverCtxConfig != NULL);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    cachemode = GetSessionCacheMode(clientCtxConfig);
    ASSERT_EQ(cachemode , HITLS_SESS_CACHE_SERVER);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        DataChannelParam channelParam;
        channelParam.port = PORT;
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
            SESS_Disable(session);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == false);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
        }
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

        if (cnt == 2)
        {
            HITLS_Session *Newsession = NULL;
            Newsession = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(memcmp(session->sessionId, Newsession->sessionId, HITLS_SESSION_ID_MAX_SIZE) != 0);
            HITLS_SESS_Free(Newsession);
        } else {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        cnt++;
    } while (cnt <= 2);

EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC002
* @title  During session resumption, set none cipher suite. The resumption fails
* @precon  nan
* @brief  1. Establish a connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. During session resumption, do not set the cipher suite and resume the session. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. Failed to resume the session.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC002(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    uint16_t sess_Ciphersuite;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    do {
        DataChannelParam channelParam;
        channelParam.port = PORT;
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
        if (session != NULL ) {
            HITLS_SESS_GetCipherSuite(session, &sess_Ciphersuite);
            ASSERT_TRUE(HITLS_SESS_SetCipherSuite(session, 0) == HITLS_SUCCESS);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_EQ(HLT_TlsConnect(clientSsl), HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE);
        } else {
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
            ASSERT_TRUE(HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
            ASSERT_TRUE(memset_s(readBuf, READ_BUF_SIZE, 0, READ_BUF_SIZE) == EOK);
            ASSERT_TRUE(HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen) == 0);
            ASSERT_TRUE(readLen == strlen(writeBuf));
            ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
        }
        ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
        ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
        HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
        HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);

        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);

        if (cnt == 1) {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        cnt++;
    } while (cnt < 3);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC003
* @title  Session resume succeed
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. The client carries the session ID for first connection establishment and resumes the session.
          The server sends the same session ID in the hello message. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. The session is resumed successfully
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC003(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    do {
        DataChannelParam channelParam;
        channelParam.port = PORT;
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
            ASSERT_EQ(HLT_TlsConnect(clientSsl), HITLS_SUCCESS);
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
        }
        ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
        ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
        HLT_TlsRead(clientSsl, readBuf, READ_BUF_SIZE, &readLen);
        HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, READ_BUF_SIZE, &readLen);

        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);

        if (cnt == 1) {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        cnt++;
    } while (cnt < 3);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC004
* @title  Use same session to resume two connections
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Use same session to resume two different connections at the same time. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. The session is resumed successfully on both connections at the same time
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC004(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    HLT_FD sockFd2 = {0};
    int count = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    void *clientConfig2 = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(clientConfig2 != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *clientCtxConfig2 = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig2, clientCtxConfig2) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (session != NULL) {
            DataChannelParam channelParam2;
            channelParam2.port = PORT;
            channelParam2.type = connType;
            channelParam2.isBlock = true;
            sockFd2 = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam2);
            ASSERT_TRUE((sockFd2.srcFd > 0) && (sockFd2.peerFd > 0));
            remoteProcess->connType = connType;
            localProcess->connType = connType;
            remoteProcess->connFd = sockFd2.peerFd;
            localProcess->connFd = sockFd2.srcFd;

            int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);
            HLT_Ssl_Config *serverSslConfig;
            serverSslConfig = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(serverSslConfig != NULL);
            serverSslConfig->sockFd = remoteProcess->connFd;
            serverSslConfig->connType = connType;

            ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
            HLT_RpcTlsAccept(remoteProcess, serverSslId);

            void *clientSsl = HLT_TlsNewSsl(clientConfig2);
            ASSERT_TRUE(clientSsl != NULL);

            HLT_Ssl_Config *clientSslConfig;
            clientSslConfig = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(clientSslConfig != NULL);
            clientSslConfig->sockFd = localProcess->connFd;
            clientSslConfig->connType = connType;

            HLT_TlsSetSsl(clientSsl, clientSslConfig);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);

            HITLS_Session *Newsession = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(Newsession != NULL);
            ASSERT_TRUE(memcmp(session->sessionId, Newsession->sessionId, HITLS_SESSION_ID_MAX_SIZE) == 0);
            HITLS_SESS_Free(Newsession);
        }
        DataChannelParam channelParam;
        channelParam.port = PORT;
        channelParam.type = connType;
        channelParam.isBlock = true;
        sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
        ASSERT_TRUE((sockFd.srcFd > 0) && (sockFd.peerFd > 0));
        remoteProcess->connFd = sockFd.peerFd;
        localProcess->connFd = sockFd.srcFd;

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
        }
        ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
        ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
        ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);

        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);

        HITLS_SESS_Free(session);
        session = HITLS_GetDupSession(clientSsl);
        ASSERT_TRUE(session != NULL);
        ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        if (count == 2) {
            bool isReused = false;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_TRUE(isReused == true);
        }
        count++;
    } while (count <= 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test  SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC005
* @title  Multiple connections can be established using the same session
* @precon nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Use same session to resume three connections. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. The sessions are all resumed successfully
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC005(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    int32_t cachemode = 0;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    cachemode = GetSessionCacheMode(clientCtxConfig);
    ASSERT_EQ(cachemode , HITLS_SESS_CACHE_SERVER);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {

        DataChannelParam channelParam;
        channelParam.port = PORT;
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
        }
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

        if (cnt != 1) {
            HITLS_Session *Newsession = NULL;
            Newsession = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(memcmp(session->sessionId, Newsession->sessionId, HITLS_SESSION_ID_MAX_SIZE) == 0);
            HITLS_SESS_Free(Newsession);
        } else {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        cnt++;
    } while (cnt <= 4);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test    SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC006
* @title   Modify the session ID on the client. Resumption fails
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Modify the session ID and resume the session. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. Resumption fails
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC006(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    int32_t cachemode = 0;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    cachemode = GetSessionCacheMode(clientCtxConfig);
    ASSERT_EQ(cachemode , HITLS_SESS_CACHE_SERVER);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {

        DataChannelParam channelParam;
        channelParam.port = PORT;
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
            session->sessionId[0] -= 1;
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
        }
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

        if (cnt == 2) {
            HITLS_Session *Newsession = NULL;
            Newsession = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(memcmp(session->sessionId, Newsession->sessionId, HITLS_SESSION_ID_MAX_SIZE) != 0);
            HITLS_SESS_Free(Newsession);
        } else {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
            ASSERT_TRUE(HITLS_SESS_IsResumable(session) == true);
        }
        cnt++;
    } while (cnt <= 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test    SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC007
* @title   Modify the session cipher suite on the client. Resumption fails
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Modify the session cipher suite and resume the session. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. Resumption fails
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC007(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    int32_t cachemode = 0;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    uint16_t sess_Ciphersuite;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    cachemode = GetSessionCacheMode(clientCtxConfig);
    ASSERT_EQ(cachemode , HITLS_SESS_CACHE_SERVER);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {

        DataChannelParam channelParam;
        channelParam.port = PORT;
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
        if (cnt == 1) {
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
        } else {
            HITLS_SESS_GetCipherSuite(session, &sess_Ciphersuite);
            if(sess_Ciphersuite == HITLS_ECC_SM4_CBC_SM3) {
                ASSERT_TRUE(HITLS_SESS_SetCipherSuite(session, HITLS_ECDHE_SM4_CBC_SM3) == HITLS_SUCCESS);
            } else {
                ASSERT_TRUE(HITLS_SESS_SetCipherSuite(session, HITLS_ECC_SM4_CBC_SM3) == HITLS_SUCCESS);
            }
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == HITLS_MSG_HANDLE_ILLEGAL_CIPHER_SUITE);
        }
        cnt++;
    } while (cnt <= 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test    SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC008
* @title   Modify the session master key on the client. Resumption fails
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Modify the session master key and resume the session. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. Resumption fails
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC008(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    int32_t cachemode = 0;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    cachemode = GetSessionCacheMode(clientCtxConfig);
    ASSERT_EQ(cachemode , HITLS_SESS_CACHE_SERVER);
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (session != NULL) {
            session->masterKey[0] -= 1;
            ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
        }
        DataChannelParam channelParam;
        channelParam.port = PORT;
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
        if (cnt == 1) {
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
        } else {
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_EQ(HLT_TlsConnect(clientSsl), HITLS_REC_BAD_RECORD_MAC);
        }
        cnt++;
    } while (cnt <= 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_TRANSPORT_FUNC_TC01(void)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLCP1_1, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientCtxConfig != NULL);
    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLCP1_1, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    uint8_t writeBuf[READ_BUF_SIZE] = {0};
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, writeBuf, 16384) == 0);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == 16384);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test    SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC009
* @title   set the session cache mode on the client server. try to Resumption
* @precon  nan
* @brief  1. Configure the session cache mode establish the connection. Expected result 1
          2. Perform the first handshake, obtain and save the session. Expected result 2
          3. Try resume the session. Expected result 3
* @expect 1. Return success
          2. The handshake is complete and obtain the session successfully
          3. HITLS_SESS_CACHE_NO and HITLS_SESS_CACHE_CLIENT resumption fails, otherwise successful
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP_CONSISTENCY_RESUME_FUNC_TC009(int mode)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    int cnt = 1;
    int32_t serverConfigId = 0;

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    void *clientConfig = HLT_TlsNewCtx(TLCP1_1);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, TLCP1_1, false, serverCtxConfig->providerPath,
        serverCtxConfig->providerNames, serverCtxConfig->providerLibFmts, serverCtxConfig->providerCnt,
        serverCtxConfig->attrName);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, TLCP1_1, false);
#endif
    HLT_SetSessionCacheMode(clientCtxConfig, mode);
    HLT_SetSessionCacheMode(serverCtxConfig, mode);

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    do{
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

        int32_t serverSslId = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);
        HLT_Ssl_Config *serverSslConfig;
        serverSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(serverSslConfig != NULL);
        serverSslConfig->sockFd = remoteProcess->connFd;
        serverSslConfig->connType = TCP;
        ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId, serverSslConfig) == 0);
        HLT_RpcTlsAccept(remoteProcess, serverSslId);

        void *clientSsl = HLT_TlsNewSsl(clientConfig);
        ASSERT_TRUE(clientSsl != NULL);
        HLT_Ssl_Config *clientSslConfig;
        clientSslConfig = HLT_NewSslConfig(NULL);
        ASSERT_TRUE(clientSslConfig != NULL);
        clientSslConfig->sockFd = localProcess->connFd;
        clientSslConfig->connType = TCP;

        HLT_TlsSetSsl(clientSsl, clientSslConfig);
        if (session != NULL) {
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
        }
        ASSERT_EQ(HLT_TlsConnect(clientSsl) , 0);

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

        if (cnt == 2) {
            if (mode == HITLS_SESS_CACHE_NO || mode == HITLS_SESS_CACHE_CLIENT){
                bool isReused = false;
                HITLS_IsSessionReused(clientSsl, &isReused);
                ASSERT_TRUE(isReused == false);
            } else {
                bool isReused = false;
                HITLS_IsSessionReused(clientSsl, &isReused);
                ASSERT_TRUE(isReused == true);
            }
        } else {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
        }cnt++;
    }while(cnt < 3);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

#define ALERT_BODY_LEN 2u   /* Alert data length */
static int32_t SendAlert(HITLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    uint8_t data[ALERT_BODY_LEN];
    /** Obtain the alert level. */
    data[0] = level;
    data[1] = description;
    /** Write records. */
    return REC_Write(ctx, REC_TYPE_ALERT, data, ALERT_BODY_LEN);
}

/* BEGIN_CASE */
void SDV_TLS_TLCP1_1_LEVEL_UNKNOWN_ALERT_TC001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportClientVerify = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, TRY_SEND_CLIENT_KEY_EXCHANGE) == HITLS_SUCCESS);

    ASSERT_TRUE(SendAlert(client->ssl, ALERT_LEVEL_UNKNOWN, ALERT_NO_RENEGOTIATION) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    HITLS_Ctx *Ctx = FRAME_GetTlsCtx(server);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(Ctx, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_TLS_TLCP1_1_LEVEL_UNKNOWN_ALERT_TC002(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    tlsConfig->isSupportClientVerify = true;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_TRUE(FRAME_CreateConnection(client, server, false, TRY_SEND_SERVER_HELLO) == HITLS_SUCCESS);

    ASSERT_TRUE(SendAlert(server->ssl, ALERT_LEVEL_UNKNOWN, ALERT_DECODE_ERROR) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    HITLS_Ctx *Ctx = FRAME_GetTlsCtx(client);
    ALERT_Info alert = { 0 };
    ALERT_GetInfo(Ctx, &alert);
    ASSERT_EQ(alert.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(alert.description, ALERT_ILLEGAL_PARAMETER);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test    SDV_TLS_TLCP1_1_TRANSPORT_FUNC_TC01
* @title   decrypt the app data with length 16384.
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Perform the a handshake. Expected result 2
          3. Send the app data with length 16384. Expected result 3
* @expect 1. Return success
          2. The handshake is complete
          3. The app data is decrypted successfully
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP1_1_TRANSPORT_FUNC_TC01(void)
{
    CRYPT_RandRegist(TestSimpleRand);
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverCtxConfig != NULL);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLCP1_1, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientCtxConfig != NULL);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, TLCP1_1, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    uint8_t writeBuf[READ_BUF_SIZE] = {0};
    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, writeBuf, 16384) == 0);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, READ_BUF_SIZE, &readLen) == 0);
    ASSERT_TRUE(readLen == 16384);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

static void TEST_Client_SessionidLength_TooLong(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)user;
    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_TLCP_DTLCP11;
    FRAME_Msg frameMsg = {0};
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_TLCP_DTLCP11;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(parseLen, *len);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, CLIENT_HELLO);
    FRAME_ClientHelloMsg *clientMsg = &frameMsg.body.hsMsg.body.clientHello;
    clientMsg->sessionIdSize.data = 33;
    BSL_SAL_Free(clientMsg->sessionId.data);
    clientMsg->sessionId.data = BSL_SAL_Calloc(33, sizeof(uint8_t));
    clientMsg->sessionId.size = 0;
    clientMsg->sessionId.state = ASSIGNED_FIELD;
    const uint8_t sessionId_temp[33] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
    ASSERT_TRUE(memcpy_s(clientMsg->sessionId.data, sizeof(sessionId_temp) / sizeof(uint8_t),
    sessionId_temp, sizeof(sessionId_temp) / sizeof(uint8_t)) == 0);

    FRAME_PackRecordBody(&frameType, &frameMsg, data, bufSize, len);
EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

/* @
* @test    SDV_TLS_TLCP1_1_RESUME_FAILED_TC001
* @title   test wrong session id length client hello.
* @precon  nan
* @brief  1. Establish the connection. Expected result 1
          2. Client send a client hello with wrong session id length. Expected result 2
* @expect 1. Return success
          2. Server return HITLS_PARSE_INVALID_MSG_LEN error
@ */
/* BEGIN_CASE */
void SDV_TLS_TLCP1_1_RESUME_FAILED_TC001(void)
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

    serverConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverConfig != NULL);
    clientConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientConfig != NULL);
     RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        TEST_Client_SessionidLength_TooLong
    };
    RegisterWrapper(wrapper);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLCP1_1, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    clientRes = HLT_ProcessTlsConnect(localProcess, TLCP1_1, clientConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);

    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes) , HITLS_PARSE_INVALID_MSG_LEN);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */