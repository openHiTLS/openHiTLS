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

#include "hlt.h"
#include "process.h"
#include "session.h"
#include "hitls_config.h"
#include "hitls_crypt_init.h"
/* END_HEADER */

/** @
* @test     SDV_TLS12_RESUME_FUNC_TC001
* @title    Test the PSK-based session resume of tls12.
*
* @brief    1. at first handshake, config the client does not support tickets, 
but the server supports tickets. Expect result 1
            2. after first handshake, config the client support tickets, Expect result 2
* @expect   1. connect success
            2. resume success
@ */
/* BEGIN_CASE */
void SDV_TLS12_RESUME_FUNC_TC001()
{
    int version = TLS1_2;
    int connType = TCP;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    HITLS_Session *session = NULL;
    int32_t cnt = 0;
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportSessionTicket = false;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportSessionTicket = true;
    HLT_SetPsk(clientCtxConfig, "123456789");
    HLT_SetPsk(serverCtxConfig, "123456789");
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
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
        if (cnt > 0) {
            clientCtxConfig->isSupportSessionTicket = true;
            ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
        }
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
        if (cnt == 0) {
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
        } else {
            int ret = HLT_TlsConnect(clientSsl);
            ASSERT_EQ(ret, HITLS_SUCCESS);
            uint8_t isReused = 0;
            ASSERT_TRUE(HITLS_IsSessionReused(clientSsl, &isReused) == HITLS_SUCCESS);
            ASSERT_EQ(isReused, 1);
        }
        ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
        HLT_RpcTlsClose(remoteProcess, serverSslId);
        HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
        HLT_CloseFd(sockFd.srcFd, localProcess->connType);
        HITLS_SESS_Free(session);
        session = HITLS_GetDupSession(clientSsl);
        ASSERT_TRUE(session != NULL);
        cnt++;
    } while (cnt < 3);

exit:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */