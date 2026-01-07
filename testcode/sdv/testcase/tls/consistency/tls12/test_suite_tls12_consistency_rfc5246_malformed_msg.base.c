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

#include <semaphore.h>
#include "securec.h"
#include "hitls_error.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "alert.h"
#include "record.h"
#include "bsl_uio.h"
#include "hitls.h"
#include "pack_frame_msg.h"
#include "parser_frame_msg.h"

#define MAX_SESSION_ID_SIZE TLS_HS_MAX_SESSION_ID_SIZE
#define MIN_SESSION_ID_SIZE TLS_HS_MIN_SESSION_ID_SIZE
#define COOKIE_SIZE 32u
#define DN_SIZE 32u
#define EXTRA_DATA_SIZE 12u
#define PORT 8005  // The SDV test is a parallel test. The port number used by each test suite must be unique.
// for sni
int32_t ServernameCbErrOK(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;

    return HITLS_ACCEPT_SNI_ERR_OK;
}
// end for sni
// for alpn
#define MAX_PROTOCOL_LEN 65536

/* UserData structure transferred by the server to the alpnCb callback. */
typedef struct TlsAlpnExtCtx_ {
    uint8_t *serverAlpnList;
    uint32_t serverAlpnListLen;
} TlsAlpnExtCtx;

/* Select callback for the alpn on the server. */
int32_t ExampleAlpnCbForLlt(HITLS_Ctx *ctx, uint8_t **selectedProto, uint8_t *selectedProtoSize,
    uint8_t *clientAlpnList, uint32_t clientAlpnListSize, void *userData)
{
    (void)ctx;
    int32_t ret = 0u;
    TlsAlpnExtCtx *alpnData = (TlsAlpnExtCtx *)userData;
    uint8_t *selected = NULL;
    uint8_t selectedLen = 0u;

    ret = HITLS_SelectAlpnProtocol(&selected, &selectedLen, alpnData->serverAlpnList, alpnData->serverAlpnListLen,
        clientAlpnList, clientAlpnListSize);
    if (ret != HITLS_SUCCESS) {
        return ret;
    } else if (selected == NULL) {
        return HITLS_ALPN_ERR_ALERT_FATAL;
    }

    *selectedProto = selected;
    *selectedProtoSize = selectedLen;

    return HITLS_SUCCESS;
}

/* Parse the comma-separated application layer protocols transferred by the executable function. */
int32_t ExampleAlpnParseProtocolList(uint8_t *out, uint32_t *outLen, uint8_t *in, uint32_t inLen)
{
    if (out == NULL || outLen == NULL || in == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (inLen == 0 || inLen > MAX_PROTOCOL_LEN) {
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

int32_t ExampleAlpnParseProtocolList2(uint8_t *out, uint32_t *outLen, uint8_t *in, uint32_t inLen)
{
    if (out == NULL || outLen == NULL || in == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (inLen == 0 || inLen > MAX_PROTOCOL_LEN) {
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

// end for alpn

typedef struct {
    int port;
    HITLS_HandshakeState expectHsState;
    bool alertRecvFlag;
    ALERT_Description expectDescription;
    bool isSupportClientVerify;
    bool isSupportExtendedMasterSecret;
    bool isSupportSni;
    bool isSupportALPN;
    bool isSupportDhCipherSuites;
    bool isSupportSessionTicket;
    bool isExpectRet;
    int expectRet;
    const char *serverGroup;
    const char *serverSignature;
    const char *clientGroup;
    const char *clientSignature;
} TestPara;

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    bool isSupportExtendedMasterSecret;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isSupportRenegotiation;
    bool isSupportSessionTicket;
    bool needStopBeforeRecvCCS;
} HandshakeTestInfo;
int32_t StatusPark(HandshakeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    /* CCS test, so that the TRY_RECV_FINISH is stopped before the CCS packet is received.
     * The default value is False, which does not affect the original test.
     */
    testInfo->client->needStopBeforeRecvCCS = testInfo->isClient ? testInfo->needStopBeforeRecvCCS : false;
    testInfo->server->needStopBeforeRecvCCS = testInfo->isClient ? false : testInfo->needStopBeforeRecvCCS;
    /** Set up a connection and stop in a certain state. */
    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();
    /* Construct the configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(testInfo->config, groups, sizeof(groups) / sizeof(uint16_t));
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(testInfo->config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    testInfo->config->isSupportExtendedMasterSecret = testInfo->isSupportExtendedMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportSessionTicket = testInfo->isSupportSessionTicket;
    return StatusPark(testInfo);
}

/* The local server initiates a connection creation request: Ignore whether the link creation is successful.*/
void ServerAccept(HLT_FrameHandle *handle, TestPara *testPara)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;
    // Create a process.
    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, true);
    ASSERT_TRUE(remoteProcess != NULL);
    // The local server listens on the TLS connection.
    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Configure the interface for constructing abnormal messages.
    handle->ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
    // Set up a TLS connection on the remote client.

    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetExtendedMasterSecretSupport(clientConfig, testPara->isSupportExtendedMasterSecret) == 0);
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
    // Create a process.

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, true);
    ASSERT_TRUE(remoteProcess != NULL);
    // The local server listens on the TLS link.

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);
    ASSERT_TRUE(HLT_SetSessionTicketSupport(serverConfig, testPara->isSupportSessionTicket) == 0);
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(serverConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(serverConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(
            serverConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    if (testPara->serverGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(serverConfig, testPara->serverGroup) == 0);
    }
    if (testPara->serverSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(serverConfig, testPara->serverSignature) == 0);
    }
    serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Configure the interface for constructing abnormal messages.
    handle->ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
    // Set up a TLS connection on the remote client.

    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetExtendedMasterSecretSupport(clientConfig, testPara->isSupportExtendedMasterSecret) == 0);
    ASSERT_TRUE(HLT_SetSessionTicketSupport(clientConfig, testPara->isSupportSessionTicket) == 0);
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(clientConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(clientConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(
            clientConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
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
    // Wait for the local.
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);
    // Confirm the final status.

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
    ASSERT_EQ(
        (ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId), testPara->expectDescription);
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
    // Create a process.

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, false);
    ASSERT_TRUE(remoteProcess != NULL);
    // The remote server listens on the TLS connection.

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(HLT_SetSessionTicketSupport(serverConfig, testPara->isSupportSessionTicket) == 0);
    if (testPara->isSupportSni) {
        ASSERT_TRUE(HLT_SetServerNameCb(serverConfig, "ExampleSNIArg") == 0);
        ASSERT_TRUE(HLT_SetServerNameArg(serverConfig, "ExampleSNIArg") == 0);
    }
    if (testPara->isSupportALPN) {
        ASSERT_TRUE(HLT_SetAlpnProtosSelectCb(serverConfig, "ExampleAlpnCb", "ExampleAlpnData") == 0);
    }
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(serverConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(serverConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(
            serverConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);
    if (testPara->serverGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(serverConfig, testPara->serverGroup) == 0);
    }
    if (testPara->serverSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(serverConfig, testPara->serverSignature) == 0);
    }
    serverConfig->isSupportExtendedMasterSecret = false;
    serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    // Configure the TLS connection on the local client.

    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetSessionTicketSupport(clientConfig, testPara->isSupportSessionTicket) == 0);
    if (testPara->isSupportSni) {
        ASSERT_TRUE(HLT_SetServerNameCb(clientConfig, "testServer") == 0);
    }
    if (testPara->isSupportALPN) {
        static const char *alpn = "http,ftp";
        uint8_t ParsedList[100] = {0};
        uint32_t ParsedListLen;
        ExampleAlpnParseProtocolList2(ParsedList, &ParsedListLen, (uint8_t *)alpn, (uint32_t)strlen(alpn));
        ASSERT_TRUE(HLT_SetAlpnProtos(clientConfig, (const char *)ParsedList) == 0);
    }
    if (testPara->isSupportDhCipherSuites) {
        ASSERT_TRUE(HLT_SetCipherSuites(clientConfig, "HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 0);
        ASSERT_TRUE(HLT_SetSignature(clientConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256") == 0);
        HLT_SetCertPath(
            clientConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    }
    if (testPara->clientGroup != NULL) {
        ASSERT_TRUE(HLT_SetGroups(clientConfig, testPara->clientGroup) == 0);
    }
    if (testPara->clientSignature != NULL) {
        ASSERT_TRUE(HLT_SetSignature(clientConfig, testPara->clientSignature) == 0);
    }
    ASSERT_TRUE(HLT_SetExtendedMasterSecretSupport(clientConfig, testPara->isSupportExtendedMasterSecret) == 0);
    clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);
    // Configure the interface for constructing abnormal messages.

    handle->ctx = clientRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
    // Set up a connection and wait until the local is complete.

    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) != 0);
    // Wait the remote.
    int ret = HLT_GetTlsAcceptResult(serverRes);
    ASSERT_TRUE(ret != 0);
    if (testPara->isExpectRet) {
        ASSERT_EQ(ret, testPara->expectRet);
    }
    // Final status confirmation
    ASSERT_EQ(HLT_RpcTlsGetStatus(remoteProcess, serverRes->sslId), CM_STATE_ALERTED);
    if (testPara->alertRecvFlag) {
        ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_RECV);
    } else {
        ASSERT_EQ(HLT_RpcTlsGetAlertFlag(remoteProcess, serverRes->sslId), ALERT_FLAG_SEND);
    }
    ASSERT_EQ((ALERT_Level)HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ(
        (ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId), testPara->expectDescription);
    ASSERT_TRUE(((HITLS_Ctx *)(clientRes->ssl))->state == CM_STATE_ALERTED);
    ASSERT_TRUE(((HITLS_Ctx *)(clientRes->ssl))->hsCtx != NULL);
    ASSERT_EQ(((HITLS_Ctx *)(clientRes->ssl))->hsCtx->state, testPara->expectHsState);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

// for UT_TLS1_2_RFC5246_RECV_ZEROLENGTH_MSG_TC009 - UT_TLS1_2_RFC5246_RECV_ZEROLENGTH_MSG_TC010

int32_t g_writeRet;
uint32_t g_writeLen;
bool g_isUseWriteLen;
uint8_t g_writeBuf[REC_DTLS_RECORD_HEADER_LEN + REC_MAX_CIPHER_TEXT_LEN];
int32_t STUB_MethodWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    (void)uio;

    if (memcpy_s(g_writeBuf, sizeof(g_writeBuf), buf, len) != EOK) {
        return BSL_MEMCPY_FAIL;
    }

    *writeLen = len;
    if (g_isUseWriteLen) {
        *writeLen = g_writeLen;
    }
    return g_writeRet;
}

int32_t g_readRet;
uint32_t g_readLen;
uint8_t g_readBuf[REC_DTLS_RECORD_HEADER_LEN + REC_MAX_CIPHER_TEXT_LEN];
int32_t STUB_MethodRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    (void)uio;

    if (g_readLen != 0 && memcpy_s(buf, len, g_readBuf, g_readLen) != EOK) {
        return BSL_MEMCPY_FAIL;
    }

    *readLen = g_readLen;
    return g_readRet;
}

int32_t g_ctrlRet;
BSL_UIO_CtrlParameter g_ctrlCmd;
int32_t STUB_MethodCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    (void)larg;
    (void)uio;
    (void)param;
    if ((int32_t)g_ctrlCmd == cmd) {
        return g_ctrlRet;
    }

    return BSL_SUCCESS;
}

HITLS_Config *g_tlsConfig = NULL;
HITLS_Ctx *g_tlsCtx = NULL;
BSL_UIO *g_uio = NULL;
int32_t TlsCtxNew(BSL_UIO_TransportType type)
{
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    const BSL_UIO_Method *ori = NULL;
    switch (type) {
        case BSL_UIO_TCP:
#ifdef HITLS_BSL_UIO_TCP
            ori = BSL_UIO_TcpMethod();
#endif
            break;
        default:
#ifdef HITLS_BSL_UIO_SCTP
            ori = BSL_UIO_SctpMethod();
#endif
            break;
    }

    config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    BSL_UIO_Method method = {0};
    memcpy(&method, ori, sizeof(method));
    method.uioWrite = STUB_MethodWrite;
    method.uioRead = STUB_MethodRead;
    method.uioCtrl = STUB_MethodCtrl;

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);
    ASSERT_TRUE(HITLS_SetUio(ctx, uio) == HITLS_SUCCESS);

    /* Default value of stub function */
    g_writeRet = HITLS_SUCCESS;
    g_writeLen = 0;
    g_isUseWriteLen = false;

    g_readLen = 0;
    g_readRet = HITLS_SUCCESS;

    g_tlsConfig = config;
    g_tlsCtx = ctx;
    g_uio = uio;
    return HITLS_SUCCESS;
EXIT:
    BSL_UIO_Free(uio);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    return HITLS_INTERNAL_EXCEPTION;
}

void TlsCtxFree(void)
{
    BSL_UIO_Free(g_uio);
    HITLS_Free(g_tlsCtx);
    HITLS_CFG_FreeConfig(g_tlsConfig);

    g_uio = NULL;
    g_tlsCtx = NULL;
    g_tlsConfig = NULL;
}

// for UT_TLS1_2_RFC5246_RECV_ZEROLENGTH_MSG_TC009 - UT_TLS1_2_RFC5246_RECV_ZEROLENGTH_MSG_TC010
// for UT_TLS1_2_RFC5246_MISS_CLIENT_KEYEXCHANGE_TC001
#define PARSEMSGHEADER_LEN 13
#define ILLEGAL_VALUE 0xFF
#define HASH_EXDATA_LEN_ERROR 23        /* Length of the CLIENT_HELLOW signature hash field. */
#define SIGNATURE_ALGORITHMS 0x04, 0x03 /* Field added to the end of the  SERVER_HELLOW message */
#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define TEMP_DATA_LEN 1024              /* Length of a single packet. */

int32_t DefaultCfgStatusParkWithSuite(HandshakeTestInfo *testInfo)
{
    FRAME_Init();
    /** Construct the configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));
    testInfo->config->isSupportExtendedMasterSecret = testInfo->isSupportExtendedMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusPark(testInfo);
}

int32_t SendHelloReq(HITLS_Ctx *ctx)
{
    uint8_t buf[HS_MSG_HEADER_SIZE] = {0u};
    size_t len = HS_MSG_HEADER_SIZE;

    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
}

int32_t ConstructAnEmptyCertMsg(FRAME_LinkObj *link)
{
    FRAME_Msg frameMsg = {0};
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);

    uint8_t *buffer = ioUserData->recMsg.msg;
    uint32_t len = ioUserData->recMsg.len;
    if (len == 0) {
        return HITLS_MEMCPY_FAIL;
    }
    /** Parse the message. */
    uint32_t parseLen = 0;
    if (ParserTotalRecord(link, &frameMsg, buffer, len, &parseLen) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    /** Construct a message. */
    CERT_Item *tmpCert = frameMsg.body.handshakeMsg.body.certificate.cert;
    frameMsg.body.handshakeMsg.body.certificate.cert = NULL;
    frameMsg.bodyLen = 15;

    if (PackFrameMsg(&frameMsg) != HITLS_SUCCESS) {
        frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
        CleanRecordBody(&frameMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }
    ioUserData->recMsg.len = 0;
    if (FRAME_TransportRecMsg(link->io, frameMsg.buffer, frameMsg.len) != HITLS_SUCCESS) {
        frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
        CleanRecordBody(&frameMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }
    frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
    CleanRecordBody(&frameMsg);
    return HITLS_SUCCESS;
}

int32_t RandBytes(uint8_t *randNum, uint32_t randLen)
{
    srand(time(0));
    const int maxNum = 256u;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return HITLS_SUCCESS;
}
// for UT_TLS1_2_RFC5246_MISS_CLIENT_KEYEXCHANGE_TC001
// for UT_TLS1_2_RFC5246_CERTFICATE_VERITY_FAIL_TC006 - UT_TLS1_2_RFC5246_CERTFICATE_VERITY_FAIL_TC007

typedef struct {
    int connectExpect;                    // Expected connect result Return value on end C.
    int acceptExpect;                     // Expected accept result returned value on the s end.
    ALERT_Level expectLevel;              // Expected alert level.
    ALERT_Description expectDescription;  // Expected alert description of the tested end.
} TestExpect;

// Replace the sent message with ClientKeyExchange.
void TEST_SendUnexpectClientKeyExchangeMsg(void *msg, void *data)
{
    FRAME_Type *frameType = (FRAME_Type *)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    FRAME_Msg newFrameMsg = {0};
    HS_MsgType hsTypeTmp = frameType->handshakeType;
    REC_Type recTypeTmp = frameType->recordType;
    frameType->handshakeType = CLIENT_KEY_EXCHANGE;
    FRAME_Init();  // Callback for changing the certificate algorithm, which is used to generate the negotiation
                   // handshake message.
    FRAME_GetDefaultMsg(frameType, &newFrameMsg);
    HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT);  // recovery callback
    FRAME_ModifyMsgInteger(frameMsg->epoch.data, &newFrameMsg.epoch);
    FRAME_ModifyMsgInteger(frameMsg->sequence.data, &newFrameMsg.sequence);
    FRAME_ModifyMsgInteger(frameMsg->body.hsMsg.sequence.data, &newFrameMsg.body.hsMsg.sequence);
    // Release the original msg.
    frameType->handshakeType = hsTypeTmp;
    frameType->recordType = recTypeTmp;
    FRAME_CleanMsg(frameType, frameMsg);
    // Change message.
    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = CLIENT_KEY_EXCHANGE;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    if (memcpy_s(msg, sizeof(FRAME_Msg), &newFrameMsg, sizeof(newFrameMsg)) != EOK) {
        Print("TEST_SendUnexpectClientKeyExchangeMsg memcpy_s Error!");
    }
}

// Replace the message to be sent with the certificate.
void TEST_SendUnexpectCertificateMsg(void *msg, void *data)
{
    FRAME_Type *frameType = (FRAME_Type *)data;
    FRAME_Msg *frameMsg = (FRAME_Msg *)msg;
    FRAME_Msg newFrameMsg = {0};
    HS_MsgType hsTypeTmp = frameType->handshakeType;
    frameType->handshakeType = CERTIFICATE;
    /* Callback for changing the certificate algorithm, which is used to generate the negotiation handshake message. */
    FRAME_Init();
    FRAME_GetDefaultMsg(frameType, &newFrameMsg);
    HLT_TlsRegCallback(HITLS_CALLBACK_DEFAULT);  // recovery callback
    // Release the original msg.
    frameType->handshakeType = hsTypeTmp;
    FRAME_CleanMsg(frameType, frameMsg);
    // Change message.

    frameType->recordType = REC_TYPE_HANDSHAKE;
    frameType->handshakeType = CERTIFICATE;
    frameType->keyExType = HITLS_KEY_EXCH_ECDHE;
    if (memcpy_s(msg, sizeof(FRAME_Msg), &newFrameMsg, sizeof(newFrameMsg)) != EOK) {
        Print("TEST_SendUnexpectCertificateMsg memcpy_s Error!");
    }
}
