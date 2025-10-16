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

/* INCLUDE_BASE ../consistency/tls12/test_suite_tls12_consistency_rfc5246_malformed_msg */
/* BEGIN_HEADER */
#include <unistd.h>
#include <semaphore.h>
#include "hitls_build.h"
#ifdef HITLS_TLS_FEATURE_ALPN
#include "process.h"
#include "securec.h"
#include "hlt.h"
#include "hlt_type.h"
#include "hitls_alpn.h"
#include "hitls_type.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_uio.h"
#include "hitls_error.h"
#include "hitls_func.h"
#include "tls.h"

/* END_HEADER */

#define ROOT_PEM "%s/ca.der:%s/inter.der"
#define INTCA_PEM "%s/ca.der"
#define SERVER_PEM "%s/server.der"
#define SERVER_KEY_PEM "%s/server.key.der"
#define CLIENT_PEM "%s/client.der"
#define CLIENT_KEY_PEM "%s/client.key.der"

static const char *g_alpnftp1 = "ftp";
static uint32_t g_uiPort = 16792;

static uint8_t C_parsedList[100];
uint32_t C_parsedListLen;

static int SetCertPath(HLT_Ctx_Config *ctxConfig, const char *certStr, bool isServer)
{
    int ret;
    char caCertPath[50];
    char chainCertPath[30];
    char eecertPath[30];
    char privKeyPath[30];

    ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_PEM, certStr, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(chainCertPath, sizeof(chainCertPath), INTCA_PEM, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(eecertPath, sizeof(eecertPath), isServer ? SERVER_PEM : CLIENT_PEM, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(privKeyPath, sizeof(privKeyPath), isServer ? SERVER_KEY_PEM : CLIENT_KEY_PEM, certStr);
    ASSERT_TRUE(ret > 0);

    HLT_SetCaCertPath(ctxConfig, (char *)caCertPath);
    HLT_SetChainCertPath(ctxConfig, (char *)chainCertPath);
    HLT_SetEeCertPath(ctxConfig, (char *)eecertPath);
    HLT_SetPrivKeyPath(ctxConfig, (char *)privKeyPath);
    return 0;
EXIT:
    return -1;
}

void Audata()
{
    printf("-\n");
}

/* BEGIN_CASE */
void SDV_TLS_ALPN_CALLBACK_FUNC_TC01(int version, int connType)
{
    bool certverifyflag = false;
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
    HLT_SetAlpnProtosSelectCb(serverCtxConfig, "ExampleAlpnCb", "Audata");

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    clientCtxConfig->isSupportClientVerify = certverifyflag;

    ExampleAlpnParseProtocolList(C_parsedList, &C_parsedListLen, (uint8_t *)g_alpnftp1, (uint32_t)strlen(g_alpnftp1));
    memcpy(clientCtxConfig->alpnList, C_parsedList, C_parsedListLen);

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_MSG_HANDLE_ALPN_PROTOCOL_NO_MATCH);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);

    uint8_t *alpnProtosname = NULL;
    uint32_t alpnProtosnameLen = 0;
    HITLS_GetSelectedAlpnProto(clientRes->ssl, &alpnProtosname, &alpnProtosnameLen);
    ASSERT_TRUE(alpnProtosname == NULL);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}
/* END_CASE */
#endif