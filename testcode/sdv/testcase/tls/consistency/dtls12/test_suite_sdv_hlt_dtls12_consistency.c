/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
#include "stub_replace.h"
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
/* END_HEADER */

#define BUF_SIZE_DTO_TEST 18432

void Hello(void *ssl)
{
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_TlsWrite(ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
exit:
    return;
}

/*
* @
* @test SDV_TLS_DTLS_CONSISTENCY_RFC5246_UNEXPETED_REORD_TYPE_TC001
* @Specifications-
* @Title1. Construct a scenario where renegotiation messages and application messages are sent at the same time. It is expected that the server processes renegotiation messages first.
* @preconan
* @short
* @ Previous Level 1
* @autotrue
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS_CONSISTENCY_RFC5246_UNEXPETED_REORD_TYPE_TC001()
{
    int version = TLS1_2;
    int connType = TCP;
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
    int32_t serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
    void *clientConfig = HLT_TlsNewCtx(version, true);
    ASSERT_TRUE(clientConfig != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_SetRenegotiationSupport(clientCtxConfig, true);
    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    HLT_SetRenegotiationSupport(serverCtxConfig, true);
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
    HLT_RpcTlsWrite(remoteProcess, serverSslId, (uint8_t *)writeBuf, strlen(writeBuf));
    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;
    ASSERT_TRUE(memset_s(readBuf, BUF_SIZE_DTO_TEST, 0, BUF_SIZE_DTO_TEST) == EOK);
    ASSERT_TRUE(HLT_RpcTlsRead(remoteProcess, serverSslId, readBuf, BUF_SIZE_DTO_TEST, &readLen) == 0);
    pthread_join(thrd, NULL);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
    ASSERT_TRUE(HLT_TlsRead(clientSsl,  readBuf, BUF_SIZE_DTO_TEST, &readLen) == 0);
    ASSERT_TRUE(readLen == strlen(writeBuf));
    ASSERT_TRUE(memcmp(writeBuf, readBuf, readLen) == 0);
    ASSERT_TRUE(HLT_RpcTlsClose(remoteProcess, serverSslId) == 0);
    ASSERT_TRUE(HLT_TlsClose(clientSsl) == 0);
    HLT_RpcCloseFd(remoteProcess, sockFd.peerFd, remoteProcess->connType);
    HLT_CloseFd(sockFd.srcFd, localProcess->connType);

exit:
    ClearWrapper();
    HLT_CleanFrameHandle();
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */