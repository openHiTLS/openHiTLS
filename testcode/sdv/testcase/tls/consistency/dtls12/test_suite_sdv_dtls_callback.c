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
#include <unistd.h>
#include <semaphore.h>
#include "alert.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "bsl_bytes.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "frame_link.h"
#include "frame_io.h"
#include "hitls_debug.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hlt.h"
#include "hlt_type.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "logger.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "process.h"
#include "rec.h"
#include "record.h"
#include "rec_conn.h"
#include "securec.h"
#include "simulate_io.h"
#include "tls.h"
/* END_HEADER */

#define BUF_SIZE_DTO_TEST 18432
#define ROOT_PEM "%s/ca.der:%s/inter.der"
#define INTCA_PEM "%s/inter.der"
#define SERVER_PEM "%s/server.der"
#define SERVER_KEY_PEM "%s/server.key.der"
#define CLIENT_PEM "%s/client.der"
#define CLIENT_KEY_PEM "%s/client.key.der"
#define BYTE_SIZE 8

#define EXAMPLE_INFO_STATE_MASK         0x0FFF
#define EXAMPLE_INFO_LOOP               0x01
#define EXAMPLE_INFO_EXIT               0x02
#define EXAMPLE_INFO_READ               0x04
#define EXAMPLE_INFO_WRITE              0x08
#define EXAMPLE_INFO_HANDSHAKE_START    0x10
#define EXAMPLE_INFO_HANDSHAKE_DONE     0x20
#define EXAMPLE_INFO_STATE_CONNECT      0x1000
#define EXAMPLE_INFO_STATE_ACCECP       0x2000
#define EXAMPLE_INFO_ALERT              0x4000

#define ACCEPT_LOOP 8193
#define ACCEPT_EXIT 8194
#define CONNECT_LOOP 4097
#define CONNECT_EXIT 4098
#define ALERT_READ 16388
#define ALERT_WRITE 16392

static uint32_t g_uiPort = 16790;

int g_countserverloop = 0;
int g_countclientloop = 0;
int g_readalert = 0;
int g_writealert = 0;
int g_serverdonequit = 0;
int g_clientdonequit = 0;
int g_serverstart = 0;
int g_clientstart = 0;
int g_handdone = 0;

void FreeGFlags()
{
    g_countserverloop = 0;
    g_countclientloop = 0;
    g_readalert = 0;
    g_writealert = 0;
    g_serverdonequit = 0;
    g_clientdonequit = 0;
    g_serverstart = 0;
    g_clientstart = 0;
    g_handdone = 0;
}

static int SetCertPath(HLT_Ctx_Config *ctxConfig, const char *certStr, bool isServer)
{
    int ret;
    char caCertPath[50];
    char chainCertPath[30];
    char eeCertPath[30];
    char privKeyPath[30];

    ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_PEM, certStr, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(chainCertPath, sizeof(chainCertPath), INTCA_PEM, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(eeCertPath, sizeof(eeCertPath), isServer ? SERVER_PEM : CLIENT_PEM, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(privKeyPath, sizeof(privKeyPath), isServer ? SERVER_KEY_PEM : CLIENT_KEY_PEM, certStr);
    ASSERT_TRUE(ret > 0);
    HLT_SetCaCertPath(ctxConfig, (char *)caCertPath);
    HLT_SetChainCertPath(ctxConfig, (char *)chainCertPath);
    HLT_SetEeCertPath(ctxConfig, (char *)eeCertPath);
    HLT_SetPrivKeyPath(ctxConfig, (char *)privKeyPath);
    return 0;
EXIT:
    return -1;
}

void ExampleInfoCallback(const HITLS_Ctx *ctx, int32_t eventType, int32_t value)
{
    if (ctx != NULL) {
        (void)value;
        if (eventType == EXAMPLE_INFO_HANDSHAKE_START) {
            g_serverstart = 1;
            g_clientstart = 1;
        }
        if (eventType == EXAMPLE_INFO_HANDSHAKE_DONE) {
            g_handdone = 1;
        }
        if (eventType == ACCEPT_LOOP) {
            g_countserverloop++;
        }
        if (eventType == CONNECT_LOOP) {
            g_countclientloop++;
        }
        if (eventType == ACCEPT_EXIT) {
            g_serverdonequit = 1;
        }
        if (eventType == CONNECT_EXIT) {
            g_clientdonequit = 1;
        }
        if (g_serverdonequit == 1) {
            if (eventType == ALERT_READ) {
                g_readalert = 1;
            }
        }
        if (g_clientdonequit == 1) {
            if (eventType == ALERT_READ) {
                g_readalert = 1;
            }
        }
        if (g_serverdonequit == 1) {
            if (eventType == ALERT_WRITE) {
                g_writealert = 1;
            }
        }
        fflush(stdout);
    }
}

/* BEGIN_CASE */
void HITLS_DTLS1_2_INFOCB_SDV_23_0_2_014(int isCertVerify, int count, int version, int connType)
{
    bool certverifyflag = false;
    if (isCertVerify == 1) {
        certverifyflag = true;
    }

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    serverCtxConfig->isSupportClientVerify = certverifyflag;
    serverCtxConfig->infoCb = ExampleInfoCallback;

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
    ASSERT_EQ(g_countserverloop, count);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    FreeGFlags();
}
/* END_CASE */

/* BEGIN_CASE */
void HITLS_DTLS1_2_INFOCB_SDV_23_0_2_015(int isCertVerify, int count, int version, int connType)
{
    bool certverifyflag = false;
    if (isCertVerify == 1) {
        certverifyflag = true;
    }

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    DataChannelParam channelParam = {0};
    channelParam.port = g_uiPort;
    channelParam.type = connType;
    channelParam.isBlock = true;
    sockFd = HLT_CreateDataChannel(localProcess, remoteProcess, channelParam);
    ASSERT_TRUE(sockFd.srcFd > 0);
    ASSERT_TRUE(sockFd.peerFd > 0);
    remoteProcess->connFd = sockFd.peerFd;
    remoteProcess->connType = connType;
    localProcess->connFd = sockFd.srcFd;
    localProcess->connType = connType;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    serverCtxConfig->isSupportClientVerify = certverifyflag;

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    SetCertPath(serverCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    clientCtxConfig->infoCb = ExampleInfoCallback;
    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsInit(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, clientRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[BUF_SIZE_DTO_TEST] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, serverRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
    ASSERT_EQ(g_countclientloop, count);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    FreeGFlags();
}
/* END_CASE */

static void Serverstartflag()
{
    ASSERT_EQ(g_serverstart, 1);
EXIT:
    return;
}

/* BEGIN_CASE */
void HITLS_DTLS1_2_INFOCB_SDV_23_0_2_011(int count, int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    serverCtxConfig->infoCb = ExampleInfoCallback;

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_FrameHandle handle = {0};
    handle.ctx = serverRes->ssl;
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = Serverstartflag;
    ASSERT_TRUE(HLT_SetFrameHandle(&handle) == HITLS_SUCCESS);

    clientRes = HLT_ProcessTlsConnect(remoteProcess, version, clientCtxConfig, NULL);

    HLT_GetTlsAcceptResult(serverRes);

    ASSERT_EQ(g_countserverloop, count);

    ASSERT_TRUE(TestIsErrStackEmpty());
    
EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    FreeGFlags();
}
/* END_CASE */