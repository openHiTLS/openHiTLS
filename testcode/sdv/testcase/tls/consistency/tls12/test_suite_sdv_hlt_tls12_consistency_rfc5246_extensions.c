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

#include <semaphore.h>
#include "process.h"
#include "securec.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "bsl_sal.h"
#include "simulate_io.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "alert.h"
#include "session_type.h"
#include "process.h"
#include "hitls_type.h"
#include "rec.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "frame_msg.h"
/* END_HEADER */

#define PORT 19800

#define MAX_SESSION_ID_SIZE TLS_HS_MAX_SESSION_ID_SIZE
#define MIN_SESSION_ID_SIZE TLS_HS_MIN_SESSION_ID_SIZE
#define COOKIE_SIZE 32u
#define DN_SIZE 32u
#define EXTRA_DATA_SIZE 12u
#define MAX_PROTOCOL_LEN1 65536
#define READ_BUF_SIZE 18432
#define ROOT_DER "%s/ca.der:%s/inter.der"
#define INTCA_DER "%s/inter.der"
#define SERVER_DER "%s/server.der"
#define SERVER_KEY_DER "%s/server.key.der"
#define CLIENT_DER "%s/client.der"
#define CLIENT_KEY_DER "%s/client.key.der"
typedef struct {
    int port;
    HITLS_HandshakeState expectHsState; // Expected Local Handshake Status
    bool alertRecvFlag;     // Indicates whether the alert is received. The value fasle indicates the sent alert, and the value true indicates the received alert
    ALERT_Description expectDescription; // Expected alert description on the test end
    bool isSupportClientVerify;
    bool isSupportExtendMasterSecret;
    bool isSupportRenegotiation;
    bool isSupportSessionTicket;
    bool isSupportDhCipherSuites;
    bool isSupportSni;
    bool isSupportAlpn;
    bool isExpectRet;
    int expectRet;                        // Expected return value. isExpectRet needs to be enabled
    const char *serverGroup;              // Configure the group supported by the server. If this parameter is not specified, the default value is used
    const char *serverSignature;          // Configure the signature algorithm supported by the server. If this parameter is left empty, the default value is used
    const char *clientGroup;              // Configure the group supported by the client. If this parameter is not specified, the default value is used
    const char *clientSignature;          // Configure the signature algorithm supported by the client. If this parameter is left empty, the default value is used
} TestPara;

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isSupportRenegotiation;
    bool isServerExtendMasterSecret;
} HandshakeTestInfo;



int32_t ExampleAlpnParseProtocolList2(uint8_t *out, uint32_t *outLen, uint8_t *in, uint32_t inLen)
{
    if (out == NULL || outLen == NULL || in == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (inLen == 0 || inLen > MAX_PROTOCOL_LEN1) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    uint32_t i = 0u;
    uint32_t commaNum = 0u;
    uint32_t startPos = 0u;

    for (i = 0u; i <= inLen; ++i) {
        if (i == inLen || in[i] == ',') {
            if (i == startPos) {
                ++startPos;
                ++commaNum;
                continue;
            }
            out[startPos - commaNum] = (uint8_t)(i - startPos);
            startPos = i + 1;
        } else {
            out[i + 1 - commaNum] = in[i];
        }
    }

    *outLen = inLen + 1 - commaNum;

    return HITLS_SUCCESS;
}

/* The local server initiates a link creation request: Ignore whether the link creation is successful. */
void ServerAccept(HLT_FrameHandle *handle, TestPara *testPara)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    //Create a process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, true);
    ASSERT_TRUE(remoteProcess != NULL);

    //The local server listens on the TLS link.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    //Configure the interface for constructing abnormal packets.
    handle->ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);

    //Set up a TLS link on the remote client.
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetExtendedMasterSecretSupport(clientConfig, testPara->isSupportExtendMasterSecret) == 0);
    clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    HLT_RpcTlsConnect(remoteProcess, clientRes->sslId);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

void ServerSendMalformedRecordHeaderMsg(HLT_FrameHandle *handle, TestPara *testPara)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    //Create a process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, true);
    ASSERT_TRUE(remoteProcess != NULL);

    //The local server listens on the TLS link.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    serverConfig->isSupportSessionTicket = testPara->isSupportSessionTicket;
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);
    ASSERT_TRUE(HLT_SetRenegotiationSupport(serverConfig, testPara->isSupportRenegotiation) == 0);

    if (testPara->isSupportSni) {
        ASSERT_TRUE(HLT_SetServerNameCb(serverConfig, "ExampleSNICb") == 0);
        ASSERT_TRUE(HLT_SetServerNameArg(serverConfig, "ExampleSNIArg") == 0);
    }
    if (testPara->isSupportAlpn) {
        ASSERT_TRUE(HLT_SetAlpnProtosSelectCb(serverConfig, "ExampleAlpnCb", "ExampleAlpnData") == 0);
    }
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(serverConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(serverConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(serverConfig,
            RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    if (testPara->serverGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(serverConfig, testPara->serverGroup) == 0);
    }
    if (testPara->serverSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(serverConfig, testPara->serverSignature) == 0);
    }
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    //Configure the interface for constructing abnormal packets.
    handle->ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);

    //Set up a TLS link on the remote client.
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetExtendedMasterSecretSupport(clientConfig, testPara->isSupportExtendMasterSecret) == 0);
    ASSERT_TRUE(HLT_SetRenegotiationSupport(clientConfig, testPara->isSupportRenegotiation) == 0);
    clientConfig->isSupportSessionTicket = testPara->isSupportSessionTicket;
    if (testPara->isSupportSni) {
        ASSERT_TRUE(HLT_SetServerName(clientConfig, "testServer") == 0);
    }
    if (testPara->isSupportAlpn) {
        static const char *alpn = "http,ftp";
        uint8_t ParsedList[100] = {0};
        uint32_t ParsedListLen;
        ExampleAlpnParseProtocolList2(ParsedList, &ParsedListLen, (uint8_t *)alpn, (uint32_t)strlen(alpn));
        ASSERT_TRUE(HLT_SetAlpnProtos(clientConfig, (const char *)ParsedList) == 0);
    }
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(clientConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(clientConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(clientConfig,
            RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    if (testPara->clientGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(clientConfig, testPara->clientGroup) == 0);
    }
    if (testPara->clientSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(clientConfig, testPara->clientSignature) == 0);
    }
    clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    if (testPara->isExpectRet) {
        ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), testPara->expectRet);
    } else {
        ASSERT_TRUE(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId) != 0);
    }

    //Wait for the local end.
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);

    //Confirm the final status.
    ASSERT_TRUE(((HITLS_Ctx *)(serverRes->ssl))->state == CM_STATE_ALERTED);
    ASSERT_TRUE(((HITLS_Ctx *)(serverRes->ssl))->hsCtx != NULL);
    ASSERT_EQ(((HITLS_Ctx *)(serverRes->ssl))->hsCtx->state, testPara->expectHsState);
    ASSERT_TRUE(HLT_RpcTlsGetStatus(remoteProcess, clientRes->sslId) == CM_STATE_ALERTED);

    if (testPara->alertRecvFlag) {
        ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_RECV);
    } else {
        ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, clientRes->sslId), ALERT_FLAG_SEND);
    }

    ASSERT_EQ((ALERT_Level)HLT_RpcTlsGetAlertLevel(remoteProcess, clientRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ((ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId),
        testPara->expectDescription);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

void ClientSendMalformedRecordHeaderMsg(HLT_FrameHandle *handle, TestPara *testPara)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    //Create a process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, false);
    ASSERT_TRUE(remoteProcess != NULL);

    //The remote server listens on the TLS link.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(serverConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(serverConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(serverConfig,
            RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);

    serverConfig->isSupportSessionTicket = testPara->isSupportSessionTicket;
    ASSERT_TRUE(HLT_SetRenegotiationSupport(serverConfig, testPara->isSupportRenegotiation) == 0);

    if (testPara->isSupportSni) {
        ASSERT_TRUE(HLT_SetServerNameCb(serverConfig, "ExampleSNICb") == 0);
        ASSERT_TRUE(HLT_SetServerNameArg(serverConfig, "ExampleSNIArg") == 0);
    }
    if (testPara->isSupportAlpn) {
        ASSERT_TRUE(HLT_SetAlpnProtosSelectCb(serverConfig, "ExampleAlpnCb", "ExampleAlpnData") == 0);
    }

    if (testPara->serverGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(serverConfig, testPara->serverGroup) == 0);
    }
    if (testPara->serverSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(serverConfig, testPara->serverSignature) == 0);
    }
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    //Configure the TLS connection on the local client.
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);

    ASSERT_TRUE(HLT_SetRenegotiationSupport(clientConfig, testPara->isSupportRenegotiation) == 0);
    clientConfig->isSupportSessionTicket = testPara->isSupportSessionTicket;
    if (testPara->isSupportSni) {
        ASSERT_TRUE(HLT_SetServerName(clientConfig, "testServer") == 0);
    }
    if (testPara->isSupportAlpn) {
        static const char *alpn = "http,ftp";
        uint8_t ParsedList[100] = {0};
        uint32_t ParsedListLen;
        ExampleAlpnParseProtocolList2(ParsedList, &ParsedListLen, (uint8_t *)alpn, (uint32_t)strlen(alpn));
        ASSERT_TRUE(HLT_SetAlpnProtos(clientConfig, (const char *)ParsedList) == 0);
    }
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(clientConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(clientConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(clientConfig,
            RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    if (testPara->clientGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(clientConfig, testPara->clientGroup) == 0);
    }
    if (testPara->clientSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(clientConfig, testPara->clientSignature) == 0);
    }
    ASSERT_TRUE(HLT_SetExtendedMasterSecretSupport(clientConfig, testPara->isSupportExtendMasterSecret) == 0);
    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    //Configure the interface for constructing abnormal packets.
    handle->ctx = clientRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);

    //Set up a link and wait until the local end is complete.
    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) != 0);

    //Wait the remote end.
    int ret = HLT_GetTlsAcceptResult(serverRes);
    ASSERT_TRUE(ret != 0);

    if (testPara->isExpectRet) {
        ASSERT_EQ(ret, testPara->expectRet);
    }

    //Final status confirmation
    ASSERT_EQ(HLT_RpcTlsGetStatus(remoteProcess, serverRes->sslId), CM_STATE_ALERTED);
    if (testPara->alertRecvFlag) {
        ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_RECV);
    } else {
        ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_SEND);
    }
    ASSERT_EQ((ALERT_Level)HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ((ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId),
        testPara->expectDescription);
    ASSERT_TRUE(((HITLS_Ctx *)(clientRes->ssl))->state == CM_STATE_ALERTED);
    ASSERT_TRUE(((HITLS_Ctx *)(clientRes->ssl))->hsCtx != NULL);
    ASSERT_EQ(((HITLS_Ctx *)(clientRes->ssl))->hsCtx->state, testPara->expectHsState);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

static int SetCertPath(HLT_Ctx_Config *ctxConfig, const char *certStr, bool isServer)
{
    int ret;
    char caCertPath[50] = {0};
    char chainCertPath[30] = {0};
    char eeCertPath[30] = {0};
    char privKeyPath[30] = {0};

    ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_DER, certStr, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(chainCertPath, sizeof(chainCertPath), INTCA_DER, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(eeCertPath, sizeof(eeCertPath), isServer ? SERVER_DER : CLIENT_DER, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(privKeyPath, sizeof(privKeyPath), isServer ? SERVER_KEY_DER : CLIENT_KEY_DER, certStr);
    ASSERT_TRUE(ret > 0);
    HLT_SetCaCertPath(ctxConfig, (char *)caCertPath);
    HLT_SetChainCertPath(ctxConfig, (char *)chainCertPath);
    HLT_SetEeCertPath(ctxConfig, (char *)eeCertPath);
    HLT_SetPrivKeyPath(ctxConfig, (char *)privKeyPath);
    return 0;
EXIT:
    return -1;
}

static int SetCertPath1(HLT_Ctx_Config *ctxConfig, const char *certStr, const char *certStr1, bool isServer)
{
    int ret;
    char caCertPath[50] = {0};
    char chainCertPath[30] = {0};
    char eeCertPath[30] = {0};
    char privKeyPath[30] = {0};

    ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_DER, certStr1, certStr1);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(chainCertPath, sizeof(chainCertPath), INTCA_DER, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(eeCertPath, sizeof(eeCertPath), isServer ? SERVER_DER : CLIENT_DER, certStr);
    ASSERT_TRUE(ret > 0);
    ret = sprintf_s(privKeyPath, sizeof(privKeyPath), isServer ? SERVER_KEY_DER : CLIENT_KEY_DER, certStr);
    ASSERT_TRUE(ret > 0);
    HLT_SetCaCertPath(ctxConfig, (char *)caCertPath);
    HLT_SetChainCertPath(ctxConfig, (char *)chainCertPath);
    HLT_SetEeCertPath(ctxConfig, (char *)eeCertPath);
    HLT_SetPrivKeyPath(ctxConfig, (char *)privKeyPath);
    return 0;
EXIT:
    return -1;
}


static void GetDefaultPointFormats(FRAME_HsExtArray8 *exField)
{
    exField->exState = INITIAL_FIELD;
    exField->exType.state = INITIAL_FIELD;
    exField->exType.data = HS_EX_TYPE_POINT_FORMATS;
    uint8_t data[] = {0};
    FRAME_ModifyMsgArray8(data, sizeof(data), &exField->exData, &exField->exDataLen);
    exField->exLen.state = INITIAL_FIELD;
    exField->exLen.data = exField->exDataLen.data + sizeof(uint8_t);
}

static void MalformedServerHelloMsgCallback001(void *msg, void *userData)
{
    // ServerHello exception: Duplicate point format extension.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;

    GetDefaultPointFormats(&serverHello->pointFormats);
    serverHello->pointFormats.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC010
* @title extension_serverhello point format extension duplicate
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. Expected result 2 is obtained.
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the tested end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC010(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE; // Message type to be modified
    handle.expectHsType = SERVER_HELLO; // Handshake message type to be modified
    handle.frameCallBack = MalformedServerHelloMsgCallback001; // reconstruction callback
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.isSupportExtendMasterSecret = true;
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedServerHelloMsgCallback002(void *msg, void *userData)
{
    // ServerHello exception: The extended master key extension is duplicate
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->extendedMasterSecret.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC011
* @title extension_serverHello extension master key extension duplicate
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the tested end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC011(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = MalformedServerHelloMsgCallback002;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.isSupportExtendMasterSecret = true;
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedServerHelloMsgCallback003(void *msg, void *userData)
{
    // ServerHello exception: The extended renegotiation extension is repeated.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->secRenego.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC012
* @title extension_serverHello renegotiation extension duplicate
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC012(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = MalformedServerHelloMsgCallback003;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportRenegotiation = true;
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedServerHelloMsgCallback004(void *msg, void *userData)
{
    // ServerHello exception: Duplicate sessionticket extension.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->sessionTicket.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC013
* @title extension_serverHello sessionticket extension duplicate
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. Expected result 2 is obtained.
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC013(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = MalformedServerHelloMsgCallback004;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSessionTicket = true;
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedServerHelloMsgCallback005(void *msg, void *userData)
{
    // serverHello exception: The serverName extension is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->serverName.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC014
* @title extension_serverHello servername extension duplicate
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. Expected result 2 is obtained.
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message in the alerted state.
4. The status of the tested end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC014(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = MalformedServerHelloMsgCallback005;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSni = true;
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedServerHelloMsgCallback006(void *msg, void *userData)
{
    // ServerHello exception: The alpn extension is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;
    serverHello->alpn.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC014
* @title extension_serverHello Alpn extension duplicate
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. Expected result 2 is obtained.
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the tested end is alerted.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC009(void)
{
    HLT_FrameHandle handle = {0};
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = SERVER_HELLO;
    handle.frameCallBack = MalformedServerHelloMsgCallback006;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportAlpn = true;
    testPara.expectHsState = TRY_RECV_CLIENT_KEY_EXCHANGE;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ServerSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback002(void *msg, void *userData)
{
    // ClientHello exception: The format extension of the sent ClientHello message is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->pointFormats.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC002
* @title The point format extension of the ClientHello message is duplicate
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, and the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC002(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback002;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback003(void *msg, void *userData)
{
    // ClientHello exception: The signature algorithm extension of the sent ClientHello message is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->signatureAlgorithms.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC003
* @title The signature algorithm extension for the clientHello message sent by the client is duplicate._Signature algorithm extension
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC003(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback003;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback004(void *msg, void *userData)
{
    // ClientHello exception: The sent ClientHello message supports group extension repetition.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->supportedGroups.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC004
* @title The clientHello message sent by the client supports group extension repetition._Group extension is supported.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC004(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback004;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


static void MalformedClientHelloMsgCallback005(void *msg, void *userData)
{
    // ClientHello exception: The extended master key extension in the sent ClientHello message is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->extendedMasterSecret.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC005
* @title Extended master key for the clientHello message that is sent repeatedly_Extended master key
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC005(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback005;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    testPara.isSupportExtendMasterSecret = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

static void MalformedClientHelloMsgCallback006(void *msg, void *userData)
{
    // ClientHello exception: The extended sessionticket extension of the clientHello message is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->sessionTicket.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC006
* @title The sessionticket extension for the clientHello message sent by the client is duplicate.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC006(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback006;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSessionTicket = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

// ClientHello exception: The extension servername of the clientHello message is duplicate.
static void MalformedClientHelloMsgCallback007(void *msg, void *userData)
{
    // ClientHello exception: The extension servername of the clientHello message is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = DUPLICATE_FIELD;
    clientHello->serverName.exLen.state = INITIAL_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t uu[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(uu, sizeof(uu)-1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC007
* @title The servername extension of the clientHello message is duplicate _servername.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC007(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback007;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSni = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

// ClientHello exception: The extended alpn extension of the clientHello message is duplicate.
static void MalformedClientHelloMsgCallback008(void *msg, void *userData)
{
    // ClientHello exception: The extended alpn extension of the clientHello message is duplicate.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->alpn.exState = DUPLICATE_FIELD;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC008
* @title The alpn extension of the clientHello message is repeated _alpn.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, indicating that the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC008(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback008;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_ILLEGAL_PARAMETER;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportAlpn = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC001
* @title The sessionticket field is carried during the first connection setup. The extended field is not carried during the session recovery. The expected result is that the session recovery fails and the handshake is performed again.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Enable the session ticket function and initiate link establishment. Expected result 2 is obtained.
3. Configure the client not to support sessionticket during session restoration. Expected result 3 is obtained.
* @expect 1. A success message is returned.
2. The link is successfully established.
3. If the session fails to be restored, a new link is established.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC001(int version, int connType)
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

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportSessionTicket = true;
    clientCtxConfig->isSupportRenegotiation = false;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportSessionTicket = true;
    serverCtxConfig->isSupportRenegotiation = false;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (cnt == 2) {
            clientCtxConfig->isSupportSessionTicket = false;
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
        if (session != NULL) {
            ASSERT_TRUE(clientCtxConfig->isSupportSessionTicket == false);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
        }
        else {

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
            ASSERT_TRUE(HITLS_SESS_HasTicket(session) == true);
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
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC002
* @title The sessionticket field is not carried during the first connection setup. The extended field is carried during session recovery. The expected result is that the session recovery fails and the handshake is performed again.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Disable the session ticket function and initiate link establishment. Expected result 2 is obtained.
3. Configure the client to support sessionticket during session restoration. Expected result 3 is obtained.
* @expect 1. A success message is returned.
2. The link is set up successfully.
3. The session is restored successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC002(int version, int connType)
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

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportSessionTicket = false;
    clientCtxConfig->isSupportRenegotiation = false;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportSessionTicket = false;
    serverCtxConfig->isSupportRenegotiation = false;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif

    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (cnt == 2) {
            clientCtxConfig->isSupportSessionTicket = true;
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
        if (session != NULL) {
            ASSERT_TRUE(clientCtxConfig->isSupportSessionTicket == true);
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
        }
        else {
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
        }

        cnt++;
    } while (cnt < 3);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC003
* @title Renegotiation is carried in the first link setup message, and this extended field is not carried in the session recovery message. The expected result is that the session recovery is successful.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Enable renegotiation and initiate link establishment. Expected result 2 is obtained.
3. Configure the client not to support renegotiation during session restoration. Expected result 3 is obtained.
* @expect 1. A success message is returned.
2. The link is set up successfully.
3. The session is restored successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC003(int version, int connType)
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

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportSessionTicket = false;
    clientCtxConfig->isSupportRenegotiation = true;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportSessionTicket = false;
    serverCtxConfig->isSupportRenegotiation = true;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (cnt == 2) {
            clientCtxConfig->isSupportRenegotiation = false;
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
        if (session != NULL) {
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
        }
        else {
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
        }

        cnt++;
    } while (cnt < 3);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC004
* @title The first link establishment does not carry the renegotiation IE, and the session recovery IE carries the extended field. The expected result is that the session recovery is successful.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Disable renegotiation and initiate link establishment. Expected result 2 is obtained.
3. Configure the client to support renegotiation during session restoration. Expected result 3 is obtained.
* @expect 1. A success message is returned.
2. The link is set up successfully.
3. The session is restored successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_RESUME_TAKE_EXTENSION_TC004(int version, int connType)
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

    void *clientConfig = HLT_TlsNewCtx(version);
    ASSERT_TRUE(clientConfig != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    clientCtxConfig->isSupportSessionTicket = false;
    clientCtxConfig->isSupportRenegotiation = false;

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    serverCtxConfig->isSupportSessionTicket = false;
    serverCtxConfig->isSupportRenegotiation = false;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    serverConfigId = HLT_RpcProviderTlsNewCtx(remoteProcess, version, false, NULL, NULL, NULL, 0, NULL);
#else
    serverConfigId = HLT_RpcTlsNewCtx(remoteProcess, version, false);
#endif
    ASSERT_TRUE(HLT_TlsSetCtx(clientConfig, clientCtxConfig) == 0);
    ASSERT_TRUE(HLT_RpcTlsSetCtx(remoteProcess, serverConfigId, serverCtxConfig) == 0);

    do {
        if (cnt == 2) {
            clientCtxConfig->isSupportRenegotiation = true;
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
        if (session != NULL) {
            ASSERT_TRUE(HITLS_SetSession(clientSsl, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl) == 0);
        }
        else {
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
        }

        cnt++;
    } while (cnt < 3);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC001
* @title The handshake fails because different cipher suites are configured on the client and server.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Configure different cipher suites on the client and server and initiate link establishment. (Expected result 2)
* @expect 1. A success message is returned.
2. The link fails to be established.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC001(int version, int connType)
{
    bool certverifyflag = false;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
    serverCtxConfig->isSupportClientVerify = certverifyflag;

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC003
* @title The RSA and ECDSA cipher suites are configured on the client and server, and the ECDSA certificate is configured. The handshake is successful.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Configure the RSA and ECDSA cipher suites and ECDSA certificates on the client and server, and initiate link establishment. (Expected result 2)
* @expect 1. A success message is returned.
2. Link establishment fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC003(int version, int connType)
{
    bool certverifyflag = false;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath(serverCtxConfig, "ecdsa_sha256", true);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_RSA_WITH_AES_128_CBC_SHA256:HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
    serverCtxConfig->isSupportClientVerify = certverifyflag;

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_RSA_WITH_AES_128_CBC_SHA256:HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_SUCCESS);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

void MalformedClientHellocallback001(void *msg, void *userData)
{
    // ClientHello is abnormal. ClientHello modifies the algorithm suite.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;

    /* Modify the structure. */
    uint16_t suite[] = {0x00fe, HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    ASSERT_TRUE(FRAME_ModifyMsgArray16(suite, sizeof(suite)/sizeof(uint16_t),
    &(clientHello->cipherSuites), &(clientHello->cipherSuitesSize)) == HITLS_SUCCESS);

EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC002
* @title The client and server set incorrect and correct cipher suites. The handshake succeeds.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Configure different cipher suites on the client and server and initiate link establishment. (Expected result 2)
* @expect 1. A success message is returned.
2. A link is established normally. An error is reported during hash check.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC002(int version, int connType)
{
    bool certverifyflag = false;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    DataChannelParam channelParam = {0};
    channelParam.port = PORT;
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

    HLT_SetLegacyRenegotiateSupport(clientCtxConfig, true);
    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsInit(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    HLT_FrameHandle handle = {0};
    handle.ctx = clientRes->ssl;
    handle.userData = (void*)&handle;
    handle.pointType = POINT_SEND;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHellocallback001;
    ASSERT_TRUE(HLT_SetFrameHandle(&handle) == HITLS_SUCCESS);
    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_REC_BAD_RECORD_MAC);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

void MalformedServerHellocallback001(void *msg, void *userData)
{
    // ServerHello packet: Check the serverHello algorithm suite.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ServerHelloMsg *serverHello = &frameMsg->body.hsMsg.body.serverHello;

    /* Determine algorithm suite */
    ASSERT_EQ(serverHello->cipherSuite.data, 0x6d);

EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC004
* @title Set insecure and secure cipher suites on the client and server, set the ECDSA certificate, and select the secure cipher suite as expected.
* @precon nan
* @brief 1. The tested end functions as the server and the tested end functions as the client. Expected result 1 is obtained.
2. Configure insecure and secure cipher suites on the client and server, configure the ECDSA certificate, and initiate link establishment. (Expected result 2)
* @expect 1. A success message is returned.
2. The link is successfully established and the security algorithm suite is selected.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_NEGOTIATE_CIPHERSUITE_TC004(int version, int connType)
{
    bool certverifyflag = false;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_CreateRemoteProcess(HITLS);
    ASSERT_TRUE(remoteProcess != NULL);

    DataChannelParam channelParam = {0};
    channelParam.port = PORT;
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
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_DH_ANON_WITH_AES_256_CBC_SHA256:HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
    serverCtxConfig->isSupportClientVerify = certverifyflag;

    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    SetCertPath(clientCtxConfig, "ecdsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_DH_ANON_WITH_AES_256_CBC_SHA256:HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsInit(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_TlsConnect(clientRes->ssl), HITLS_SUCCESS);
    ASSERT_EQ(HLT_GetTlsAcceptResult(serverRes), HITLS_SUCCESS);
    ASSERT_EQ(((HITLS_Ctx *)clientRes->ssl)->negotiatedInfo.cipherSuiteInfo.cipherSuite, HITLS_DH_ANON_WITH_AES_256_CBC_SHA256);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */


//The clientHello is abnormal. The extended servername length of the clientHello message is smaller than the actual length.
static void MalformedClientHelloMsgCallback009(void *msg, void *userData)
{
    //The clientHello is abnormal. The extended servername length of the clientHello message is smaller than the actual length.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t uu[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(uu, sizeof(uu)-1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data--;
    clientHello->serverName.exLen.data--;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC007
* @title The extended length of the servername in the clientHello message is smaller than the actual length.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, and the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC048(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback009;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSni = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


//The clientHello message is abnormal. The extended servername length of the clientHello message is greater than the actual length.
static void MalformedClientHelloMsgCallback010(void *msg, void *userData)
{
    //The clientHello message is abnormal. The extended servername length of the clientHello message is greater than the actual length.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t uu[13] = {0x00, 0x00, 0x09, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x63, 0x6F, 0x6d};
    FRAME_ModifyMsgArray8(uu, sizeof(uu)-1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data++;
    clientHello->serverName.exLen.data++;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC007
* @title The extended length of the servername in the clientHello message is greater than the actual length.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, and the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC047(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback010;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSni = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


// ClientHello exception: The extended length of the servername in the clientHello message is 0 and the content is not null.
static void MalformedClientHelloMsgCallback011(void *msg, void *userData)
{
    // ClientHello exception: The length of the extended servername in the clientHello message is 0 and the content is not null.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = INITIAL_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    uint8_t uu[4] = {0x00, 0x00, 0x01,0x01};
    FRAME_ModifyMsgArray8(uu, sizeof(uu)-1, &clientHello->serverName.exData, &clientHello->serverName.exDataLen);
    clientHello->serverName.exLen.data = 0;
    clientHello->serverName.exDataLen.data = 0;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC007
* @title The extended length of the servername in the clientHello message is 0 and the content is not null.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, and the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC046(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback011;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSni = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */


//The clientHello is abnormal. The extended length of the servername in the clientHello message is 0. The content is empty.
static void MalformedClientHelloMsgCallback012(void *msg, void *userData)
{
    //The clientHello is abnormal. The extended length of the servername in the clientHello message is 0. The content is empty.
    HLT_FrameHandle *handle = (HLT_FrameHandle *)userData;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    ASSERT_EQ(frameMsg->body.hsMsg.type.data, handle->expectHsType);
    FRAME_ClientHelloMsg *clientHello = &frameMsg->body.hsMsg.body.clientHello;
    clientHello->serverName.exState = INITIAL_FIELD;
    clientHello->serverName.exLen.state = ASSIGNED_FIELD;
    clientHello->serverName.exDataLen.state = MISSING_FIELD;
    clientHello->serverName.exData.state = MISSING_FIELD;
    FRAME_ModifyMsgInteger(HS_EX_TYPE_SERVER_NAME, &clientHello->serverName.exType);
    clientHello->serverName.exLen.data = 0;
EXIT:
    return;
}

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_REPEAT_EXTENSION_TC007
* @title The extended length of the servername in the clientHello message is 0. The content is empty.
* @precon nan
* @brief 1. The tested end functions as the client, and the tested end functions as the server. Expected result 1 is obtained.
2. Obtain the message, modify the field content, and send the message. (Expected result 2)
3. Check the status of the tested end. Expected result 3 is obtained.
4. Check the status of the test end. Expected result 4 is obtained.
* @expect 1. A success message is returned.
2. A success message is returned.
3. The tested end returns an alert message, and the status is alerted.
4. The status of the test end is alerted, and the handshake status is ready to receive the serverHello message.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MALFORMED_CLIENT_HELLO_MSG_FUN_TC045(void)
{
    HLT_FrameHandle handle = {0};
    handle.pointType = POINT_SEND;
    handle.userData = (void *)&handle;
    handle.expectReType = REC_TYPE_HANDSHAKE;
    handle.expectHsType = CLIENT_HELLO;
    handle.frameCallBack = MalformedClientHelloMsgCallback012;
    TestPara testPara = {0};
    testPara.port = PORT;
    testPara.expectHsState = TRY_RECV_SERVER_HELLO;
    testPara.expectDescription = ALERT_DECODE_ERROR;
    testPara.isSupportExtendMasterSecret = true;
    testPara.isSupportSni = true;
    ClientSendMalformedRecordHeaderMsg(&handle, &testPara);
    return;
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHERSUITE_NOT_SUITABLE_CERT_TC003
* @title When dual-end authentication is configured, the cipher suite is set to RSA, the RSA certificate is set on the server, and the ECDSA certificate is set on the client, the link fails to be established.
* @precon nan
* @brief 1. Use the default configuration items to configure the client and server, set the cipher suite to RSA, set the RSA certificate on the server, and set the ECDSA certificate on the client. Expected result 1 is obtained.
2. Initiate a link establishment request. Expected result 2 is obtained.
* @expect 1. The initialization is successful.
2. Link establishment fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_CIPHERSUITE_NOT_SUITABLE_CERT_TC003(int version, int connType)
{
    bool certverifyflag = true;

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, PORT, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath1(serverCtxConfig, "rsa_sha256", "ecdsa_sha256", true);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
    serverCtxConfig->isSupportClientVerify = certverifyflag;

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    SetCertPath1(clientCtxConfig, "ecdsa_sha256", "rsa_sha256", false);
    HLT_SetCipherSuites(clientCtxConfig, "HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
    clientCtxConfig->isSupportClientVerify = certverifyflag;

    clientRes = HLT_ProcessTlsInit(remoteProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    ASSERT_EQ(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId), HITLS_REC_NORMAL_RECV_UNEXPECT_MSG);

    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
}
/* END_CASE */

/* @
* @test SDV_TLS_TLS12_RFC5246_CONSISTENCY_MULTILINK_RESUME_ALERT_TC002
* @title Apply for establishing and disconnecting a link between the client and server, apply for two links, and use the session ID of the previous session to restore the session. The restoration is expected to be successful.
* @precon nan
* @brief 1. Apply for establishing and disconnecting a link between the client and server.
2. Apply for two links and use the session ID of the previous session to restore the session. The restoration is expected to be successful.
* @expect 1. The link is successfully established.
2. The restoration is successful.
@ */
/* BEGIN_CASE */
void SDV_TLS_TLS12_RFC5246_CONSISTENCY_MULTILINK_RESUME_ALERT_TC002(int version, int connType)
{
    Process *localProcess = NULL;
    Process *remoteProcess = NULL;
    HLT_FD sockFd = {0};
    HLT_FD sockFd2 = {0};
    int cunt = 1;
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

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    HLT_Ctx_Config *clientCtxConfig2 = HLT_NewCtxConfig(NULL, "CLIENT");

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
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

            int32_t serverSslId2 = HLT_RpcTlsNewSsl(remoteProcess, serverConfigId);

            HLT_Ssl_Config *serverSslConfig2;
            serverSslConfig2 = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(serverSslConfig2 != NULL);
            serverSslConfig2->sockFd = remoteProcess->connFd;
            serverSslConfig2->connType = connType;

            ASSERT_TRUE(HLT_RpcTlsSetSsl(remoteProcess, serverSslId2, serverSslConfig2) == 0);
            HLT_RpcTlsAccept(remoteProcess, serverSslId2);

            void *clientSsl2 = HLT_TlsNewSsl(clientConfig2);
            ASSERT_TRUE(clientSsl2 != NULL);

            HLT_Ssl_Config *clientSslConfig2;
            clientSslConfig2 = HLT_NewSslConfig(NULL);
            ASSERT_TRUE(clientSslConfig2 != NULL);
            clientSslConfig2->sockFd = localProcess->connFd;
            clientSslConfig2->connType = connType;

            HLT_TlsSetSsl(clientSsl2, clientSslConfig2);
            ASSERT_TRUE(HITLS_SetSession(clientSsl2, session) == HITLS_SUCCESS);
            ASSERT_TRUE(HLT_TlsConnect(clientSsl2) == 0);

            HITLS_Session *Newsession = HITLS_GetDupSession(clientSsl2);
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
        cunt++;
    } while (cunt <= 2);
EXIT:
    HITLS_SESS_Free(session);
    HLT_FreeAllProcess();
}
/* END_CASE */