/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
/* END_HEADER */

#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define REC_TLS_RECORD_HEADER_LEN 5     /* recode header length */
#define REC_CONN_SEQ_SIZE 8u            /* SN size */
#define PORT 11111
typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isServerExtendMasterSecret;
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);

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

exit:
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    uint16_t sess_Ciphersuite;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
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
exit:
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
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
            uint8_t isReused = 0;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_TRUE(isReused == 1);
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
exit:
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

    HITLS_Session *session = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    void *clientConfig2 = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(clientConfig2 != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *clientCtxConfig2 = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);

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
            uint8_t isReused = 0;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_TRUE(isReused == 1);
        }
        count++;
    } while (count <= 2);
exit:
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);

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
exit:
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);

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
exit:
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    uint16_t sess_Ciphersuite;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);

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
exit:
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);

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
exit:
    HITLS_SESS_Free(session);
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

    HITLS_Session *session = NULL;
    const char *writeBuf = "Hello world";
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);
 
    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, TLCP1_1, false);
    void *clientConfig = HLT_TlsNewCtx(TLCP1_1, true);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
 
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
                uint8_t isReused = -1;
                HITLS_IsSessionReused(clientSsl, &isReused);
                ASSERT_TRUE(isReused == 0);
            } else {
                uint8_t isReused = -1;
                HITLS_IsSessionReused(clientSsl, &isReused);
                ASSERT_TRUE(isReused == 1);
            }
        } else {
            session = HITLS_GetDupSession(clientSsl);
            ASSERT_TRUE(session != NULL);
        }cnt++;
    }while(cnt < 3);
exit:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */