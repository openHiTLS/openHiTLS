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
#include <stddef.h>
#include <unistd.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_state_recv.h"
#include "conn_init.h"
#include "recv_process.h"
#include "stub_crypt.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "cert.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "hlt.h"
#include "sctp_channel.h"
#include "rec_wrapper.h"
#include "process.h"
#include "pthread.h"
#include "unistd.h"
#include "rec_header.h"
#include "bsl_log.h"
#include "cert_callback.h"
#include "bsl_uio.h"
#include "uio_abstraction.h"
/* END_HEADER */

#define BUF_SIZE_DTO_TEST 18432

void Hello(void *ssl)
{
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_TlsWrite(ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
EXIT:
    return;
}

/**
* @test SDV_TLS_DTLCP_HANDSHAKE_FUNC_TC001
* @spec -
* @title Check whether DTLCP over SCTP can handshake successfully.
* @precon nan
* @brief
* 1. Use the default configuration items to configure the client and server. Expected result 1.
* 2. A DTLCP over SCTP connection is established between the client and server. Expected result 2.
* 3. Construct a app message and send it to the client. Check the server ret. Expected result 3.
* @expect
* 1. The initialization is successful.
* 2. The connection is set up successfully.
* 3. The server ret is HITLS_SUCCESS.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLCP_HANDSHAKE_FUNC_TC001(int connType)
{
    if (connType == SCTP && !IsEnableSctpAuth()) {
        return;
    }
    bool certverifyflag = true;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, 16790, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfigTLCP(NULL, "SERVER", false);
    ASSERT_TRUE(serverCtxConfig != NULL);

    serverCtxConfig->isSupportClientVerify = certverifyflag;

    serverRes = HLT_ProcessTlsAccept(localProcess, DTLCP1_1, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfigTLCP(NULL, "CLIENT", true);
    ASSERT_TRUE(clientCtxConfig != NULL);

    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLCP1_1, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")), HITLS_SUCCESS);
    uint8_t readBuf[1024] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/*
* @
* @test SDV_TLS_DTLCP_CONSISTENCY_RFC5246_UNEXPETED_REORD_TYPE_TC001
* @Specifications-
* @Title1. Construct a scenario where renegotiation messages and application messages are sent at the same time. 
*  It is expected that the server processes renegotiation messages first.
* @preconan
* @short
* @ Previous Level 1
* @autotrue
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLCP_CONSISTENCY_RFC5246_UNEXPETED_REORD_TYPE_TC001()
{
    int version = TLS1_2;
    int connType = TCP;
    int32_t serverConfigId = 0;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    HITLS_Session *session = NULL;
    TLS_TYPE local = HITLS;
    TLS_TYPE remote = HITLS;
    localProcess = HLT_InitLocalProcess(local);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(remote);
    ASSERT_TRUE(remoteProcess != NULL);
    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_SetRenegotiationSupport(clientCtxConfig, true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetRenegotiationSupport(serverCtxConfig, true);
    HLT_SetClientRenegotiateSupport(serverCtxConfig, true);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);
    DataChannelParam channelParam;
    channelParam.port = 1666;
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
    ASSERT_TRUE(HITLS_Renegotiate(clientSsl) == HITLS_SUCCESS);
    const char *writeBuf = "Hello world";
    pthread_t thrd;
    ASSERT_TRUE(pthread_create(&thrd, NULL, (void *)Hello, clientSsl) == 0);
    sleep(2);
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;
    ASSERT_TRUE(memset_s(readBuf, BUF_SIZE_DTO_TEST, 0, BUF_SIZE_DTO_TEST) == EOK);
    ASSERT_TRUE(HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, BUF_SIZE_DTO_TEST, &readLen) == 0);
    pthread_join(thrd, NULL);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
    ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);

EXIT:
    ClearWrapper();
    HLT_CleanFrameHandle();
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */
