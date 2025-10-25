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
#include "stub_utils.h"
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
#include "record.h"
/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, REC_Write, TLS_Ctx *, REC_Type, const uint8_t *, uint32_t);


#define REC_DTLS_RECORD_HEADER_LEN 13
#define BUF_SIZE_DTO_TEST 18432

void Hello(void *ssl)
{
    const char *writeBuf = "Hello world";
    ASSERT_TRUE(HLT_TlsWrite(ssl, (uint8_t *)writeBuf, strlen(writeBuf)) == 0);
EXIT:
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
    int32_t serverConfigId = 0;
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
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    HLT_SetClientRenegotiateSupport(serverCtxConfig, true);
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

static void Test_CertificateParse001(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)ctx;
    (void)bufSize;
    (void)user;
    FRAME_Type frameType = { 0 };
    frameType.versionType = HITLS_VERSION_DTLS12;
    FRAME_Msg frameMsg = { 0 };
    frameMsg.recType.data = REC_TYPE_HANDSHAKE;
    frameMsg.length.data = *len;
    frameMsg.recVersion.data = HITLS_VERSION_DTLS12;
    uint32_t parseLen = 0;
    FRAME_ParseMsgBody(&frameType, data, *len, &frameMsg, &parseLen);
    ASSERT_EQ(frameMsg.body.hsMsg.type.data, SERVER_HELLO_DONE);
    int *t = (int*)user;
    if (*t == 0) {
        // Change the sequence number to 20
        data[5] = 20;
    }
    (*t)++;

EXIT:
    FRAME_CleanMsg(&frameType, &frameMsg);
    return;
}

static uint32_t DtlsTimerCallBack(HITLS_Ctx *ctx, uint32_t us)
{
    (void)ctx;
    (void)us;
    return 1000000; // timeout value is 1 second.
}

/* @
* @test  SDV_TLS_DTLS_CONSISTENCY_RFC6347_MTU_TC001
* @title  Multiple timeout retransmissions result in a decrease in MTU
* @precon  nan
* @brief  1. Establish a link using UDP with dtls12 and construct timeout retransmission three times.
          Expected result 1 is obtained.
* @expect 1. MTU reduced from 1472 to 548
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS_CONSISTENCY_RFC6347_MTU_TC001()
{
    int32_t port = 18888;
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, port, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    int32_t user = 0;
    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO_DONE,
        REC_TYPE_HANDSHAKE,
        false,
        &user,
        Test_CertificateParse001
    };
    RegisterWrapper(wrapper);
    HLT_Tls_Res *tlsRes = HLT_ProcessTlsInit(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(tlsRes != NULL);
    HITLS_SetDtlsTimerCb(tlsRes->ssl, DtlsTimerCallBack);
    (void)HLT_TlsAccept(tlsRes->ssl);

    HITLS_Ctx *ctx = tlsRes->ssl;
    HITLS_SetNoQueryMtu(ctx, false);
    ASSERT_EQ(ctx->config.pmtu, 1472);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes == NULL);
    ASSERT_EQ(ctx->config.pmtu, 548);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */

int32_t STUB_REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num)
{
    static int32_t count = 0;
    if (data[0] == CERTIFICATE && count == 0) {
        int32_t hsFragmentLength = BSL_ByteToUint24(&data[DTLS_HS_FRAGMENT_LEN_ADDR]);
        int32_t fragmentLength = hsFragmentLength + DTLS_HS_MSG_HEADER_SIZE + REC_DTLS_RECORD_HEADER_LEN;
        // On the third retransmission, the message length became 548
        ASSERT_EQ(fragmentLength, 548);
        count++;
    }
    return ctx->recCtx->recWrite(ctx, recordType, data, num);
EXIT:
    return -1;
}

static void Test_Timeout001(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len, uint32_t bufSize, void *user)
{
    (void)data;
    (void)len;
    (void)bufSize;
    (void)user;
    sleep(1);
    ASSERT_EQ(HITLS_DtlsProcessTimeout(ctx), HITLS_SUCCESS);
    sleep(2);
    ASSERT_EQ(HITLS_DtlsProcessTimeout(ctx), HITLS_SUCCESS);
    STUB_REPLACE(REC_Write, STUB_REC_Write);;
    sleep(4);
    ASSERT_EQ(HITLS_DtlsProcessTimeout(ctx), HITLS_SUCCESS);

EXIT:
    STUB_RESTORE(REC_Write);
    return;
}

/* @
* @test  SDV_TLS_DTLS_CONSISTENCY_RFC6347_MTU_TC002
* @title  Multiple timeout retransmissions result in a decrease in MTU
* @precon  nan
* @brief  1. Establish a link using UDP with dtls12 and construct timeout retransmission three times.
          Expected result 1 is obtained.
* @expect 1. MTU reduced from 1472 to 548. On the third retransmission, the message length became 548
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS_CONSISTENCY_RFC6347_MTU_TC002()
{
    HLT_ConfigTimeOut("10");
    int32_t port = 18888;
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, UDP, port, true);
    ASSERT_TRUE(localProcess != NULL);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = NULL;
    HLT_Ctx_Config *clientCtxConfig = NULL;
    serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverCtxConfig != NULL);
    ASSERT_TRUE(clientCtxConfig != NULL);

    RecWrapper wrapper = {TRY_RECV_CLIENT_KEY_EXCHANGE, REC_TYPE_HANDSHAKE, true, NULL, Test_Timeout001};
    RegisterWrapper(wrapper);
    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Tls_Res *clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);
    uint8_t readData[REC_MAX_PLAIN_LENGTH] = {0};
    uint32_t readLen = REC_MAX_PLAIN_LENGTH;

    ASSERT_EQ(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")), 0);
    ASSERT_EQ(HLT_ProcessTlsRead(remoteProcess, clientRes, readData, readLen, &readLen), 0);
    ASSERT_EQ(readLen, strlen("Hello World"));
    ASSERT_EQ(memcmp("Hello World", readData, readLen), 0);
EXIT:
    ClearWrapper();
    HLT_FreeAllProcess();
}
/* END_CASE */
