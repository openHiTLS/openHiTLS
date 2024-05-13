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
#include "securec.h"
#include "tls_config.h"
#include "tls.h"
#include "hitls_type.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "frame_tls.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_state_recv.h"
#include "transcript_hash.h"
#include "conn_init.h"
#include "recv_process.h"
#include "stub_replace.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "common_func.h"
#include "hitls_crypt_init.h"

#define TEST_SERVERNAME_LENGTH 20
#define READ_BUF_SIZE 18432

/* END_HEADER */
typedef struct {
    uint16_t version;
    BSL_UIO_TransportType uioType;
    HITLS_Config *s_config;
    HITLS_Config *c_config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_Session *clientSession;
    HITLS_TicketKeyCb serverKeyCb;
} SniTestInfo;


typedef struct {
    char servername[TEST_SERVERNAME_LENGTH + 1];
    int32_t alert;
} SNI_Arg;


static SNI_Arg *sniArg = NULL;
static char *g_serverName = "www.example.com";
static uint8_t *g_sessionId;
static uint32_t g_sessionIdSize;

int32_t ServernameCbErrOK(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;

    return HITLS_ACCEPT_SNI_ERR_OK;
}

int32_t ServernameCbErrAlertFatal(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;

    return HITLS_ACCEPT_SNI_ERR_ALERT_FATAL;
}

int32_t ServernameCbErrNoack(HITLS_Ctx *ctx, int *alert, void *arg)
{
    (void)ctx;
    (void)alert;
    (void)arg;

    return HITLS_ACCEPT_SNI_ERR_NOACK;
}

void STUB_SendAlert(TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    (void)ctx;
    (void)level;
    (void)description;
    return;
}

typedef struct TEST_SNI_DEAL_CB {
    uint32_t sniState;
    HITLS_SniDealCb sniDealCb;
} TEST_SNI_DEAL_CB;

static TEST_SNI_DEAL_CB g_ServernameCbs[] = {{HITLS_ACCEPT_SNI_ERR_OK, ServernameCbErrOK},
    {HITLS_ACCEPT_SNI_ERR_ALERT_FATAL, ServernameCbErrAlertFatal},
    {HITLS_ACCEPT_SNI_ERR_NOACK, ServernameCbErrNoack},
    {HITLS_ACCEPT_SNI_ERR_NOACK, NULL}};

typedef struct {
    HITLS_Config *clientConfig;
    HITLS_Config *serverConfig;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    HITLS_SniDealCb sniDealCb;
    HITLS_Session *clientSession;
    uint16_t version;
    BSL_UIO_TransportType type;
} HandshakeTestInfo;

int32_t CreateConfig(HITLS_Config **cfg, uint16_t version)
{

    switch (version) {
        case HITLS_VERSION_DTLS12:
            *cfg = HITLS_CFG_NewDTLS12Config();
            break;
        case HITLS_VERSION_TLS13:
            *cfg = HITLS_CFG_NewTLS13Config();
            break;
        case HITLS_VERSION_TLS12:
            *cfg = HITLS_CFG_NewTLS12Config();
            break;
        default:
            break;
    }

    if (*cfg == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

void FreeSNIArg(SNI_Arg *sniArg)
{
    if (sniArg != NULL) {
        BSL_SAL_FREE(sniArg);
    }
}

void SetCommonConfig(HITLS_Config **config)
{
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    HITLS_CFG_SetGroups(*config, groups, sizeof(groups) / sizeof(uint16_t));
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetSignature(*config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    const uint16_t cipherSuites[] = {HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(*config, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    HITLS_CFG_SetClientVerifySupport(*config, true);
    HITLS_CFG_SetExtenedMasterSecretSupport(*config, true);
    HITLS_CFG_SetNoClientCertSupport(*config, true);
    HITLS_CFG_SetRenegotiationSupport(*config, true);
    HITLS_CFG_SetPskServerCallback(*config, (HITLS_PskServerCb)ExampleServerCb);
    HITLS_CFG_SetPskClientCallback(*config, (HITLS_PskClientCb)ExampleClientCb);
    HITLS_CFG_SetSessionTicketSupport(*config, false);
    HITLS_CFG_SetCloseCheckKeyUsage(*config, false);
}

static int32_t CreateLink(HandshakeTestInfo *testInfo)
{
    testInfo->client = FRAME_CreateLink(testInfo->clientConfig, testInfo->type);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (testInfo->clientSession != NULL) {
        int32_t ret = HITLS_SetSession(testInfo->client->ssl, testInfo->clientSession);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    testInfo->server = FRAME_CreateLink(testInfo->serverConfig, testInfo->type);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    return HITLS_SUCCESS;
}

static int32_t DefaultCfgAndLink(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    CreateConfig(&(testInfo->clientConfig), testInfo->version);
    if (testInfo->clientConfig == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    SetCommonConfig(&(testInfo->clientConfig));
    HITLS_CFG_SetServerName(testInfo->clientConfig, (uint8_t *)g_serverName, (uint32_t)strlen((char *)g_serverName));


    CreateConfig(&(testInfo->serverConfig), testInfo->version);
    if (testInfo->serverConfig == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    SetCommonConfig(&(testInfo->serverConfig));
    HITLS_CFG_SetServerNameCb(testInfo->serverConfig, testInfo->sniDealCb);

    sniArg = (SNI_Arg *)BSL_SAL_Calloc(1, sizeof(SNI_Arg));
    snprintf_s(sniArg->servername, sizeof(sniArg->servername), strlen(g_serverName), "%s", g_serverName);
    if (HITLS_CFG_SetServerNameArg(testInfo->serverConfig, sniArg) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return CreateLink(testInfo);
}

int32_t GetSessionId(HandshakeTestInfo *testInfo)
{
    FRAME_Type frameType = {0};
    FRAME_Msg recvframeMsg = {0};

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo->client->io);
    uint8_t *recMsg = ioUserData->recMsg.msg;
    uint32_t recMsgLen = ioUserData->recMsg.len;

    frameType.handshakeType = SERVER_HELLO;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.versionType = testInfo->version;
    uint32_t parseLen = 0;
    int32_t ret = FRAME_ParseMsg(&frameType, recMsg, recMsgLen, &recvframeMsg, &parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    FRAME_ServerHelloMsg *serverHello = &recvframeMsg.body.hsMsg.body.serverHello;
    g_sessionIdSize = serverHello->sessionIdSize.data;
    BSL_SAL_FREE(g_sessionId);
    g_sessionId = BSL_SAL_Dump(serverHello->sessionId.data, g_sessionIdSize);

    FRAME_CleanMsg(&frameType, &recvframeMsg);
    return HITLS_SUCCESS;
}

int32_t FirstHandshake(HandshakeTestInfo *testInfo)
{
    int32_t ret = FRAME_CreateConnection(testInfo->client, testInfo->server, true, TRY_RECV_SERVER_HELLO);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = GetSessionId(testInfo);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = FRAME_CreateConnection(testInfo->client, testInfo->server, true, HS_STATE_BUTT);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t data[] = "Hello World";
    ret = HITLS_Write(testInfo->server->ssl, data, sizeof(data));
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ret = FRAME_TrasferMsgBetweenLink(testInfo->server, testInfo->client);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ret = HITLS_Read(testInfo->client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    testInfo->clientSession = HITLS_GetDupSession(testInfo->client->ssl);

    FRAME_FreeLink(testInfo->client);
    testInfo->client = NULL;
    FRAME_FreeLink(testInfo->server);
    testInfo->server = NULL;
    return HITLS_SUCCESS;
}


/* @
* @test  UT_TLS_SNI_RESUME_SERVERNAME_FUNC_TC001
* @title  During session resumption, the serverName extension of clientHello
          is different from that in first handshake
* @precon  nan
* @brief  1. For the first handshake, set serverName to www.example.com in the clientHello. 
          Expected result 1
          2. During session resumption, changed serverName of clientHello to www.sss.com. Expected result 2
          3. process the client hello. Expected result 2
* @expect 1. The serverName extension is set successfully and the handshake succeeds
          2. return success
@ */
/* BEGIN_CASE */
void UT_TLS_SNI_RESUME_SERVERNAME_FUNC_TC001(int version, int type)
{
    g_sessionId = NULL;
    g_sessionIdSize = 0;
    HandshakeTestInfo testInfo = {0};
    testInfo.version = (uint16_t)version;
    testInfo.type = (BSL_UIO_TransportType)type;
    testInfo.sniDealCb = ServernameCbErrOK;

    ASSERT_EQ(DefaultCfgAndLink(&testInfo), HITLS_SUCCESS);
    ASSERT_EQ(FirstHandshake(&testInfo), HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.clientSession != NULL);

    ASSERT_TRUE(CreateLink(&testInfo) == HITLS_SUCCESS);
    ASSERT_TRUE(
        FRAME_CreateConnection(testInfo.client, testInfo.server, false, TRY_RECV_CLIENT_HELLO) == HITLS_SUCCESS);
    ASSERT_TRUE(testInfo.server->ssl->hsCtx->state == TRY_RECV_CLIENT_HELLO);
    CONN_Deinit(testInfo.server->ssl);

    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(testInfo.server->io);
    uint8_t *buffer = ioUserData->recMsg.msg;
    uint32_t len = ioUserData->recMsg.len;
    ASSERT_TRUE(len != 0);

    FRAME_Msg frameMsg = {0};
    uint32_t parseLen = 0;

    ASSERT_TRUE(ParserTotalRecord(testInfo.server, &frameMsg, buffer, len, &parseLen) == HITLS_SUCCESS);
    ASSERT_TRUE(frameMsg.body.handshakeMsg.type == CLIENT_HELLO);

    char *hostName = "www.sss.com";
    uint8_t *serverName = frameMsg.body.handshakeMsg.body.clientHello.extension.content.serverName;
    uint16_t serverNameSize = frameMsg.body.handshakeMsg.body.clientHello.extension.content.serverNameSize;
    frameMsg.body.handshakeMsg.body.clientHello.extension.content.serverNameSize = strlen(hostName) + 1;
    frameMsg.body.handshakeMsg.body.clientHello.extension.content.serverName = (uint8_t *)hostName;

    testInfo.server->ssl->method.sendAlert = STUB_SendAlert;
    HS_Init(testInfo.server->ssl);

    if (testInfo.type == BSL_UIO_TCP) {
        ASSERT_TRUE(Tls12ServerRecvClientHelloProcess(testInfo.server->ssl, &frameMsg.body.handshakeMsg) ==
                    HITLS_SUCCESS);
    } else {
        ASSERT_TRUE(DtlsServerRecvClientHelloProcess(testInfo.server->ssl, &frameMsg.body.handshakeMsg) ==
                    HITLS_SUCCESS);
    }
    frameMsg.body.handshakeMsg.body.clientHello.extension.content.serverName = serverName;
    frameMsg.body.handshakeMsg.body.clientHello.extension.content.serverNameSize = serverNameSize;

exit:
    BSL_SAL_FREE(g_sessionId);
    CleanRecordBody(&frameMsg);
    HITLS_CFG_FreeConfig(testInfo.clientConfig);
    HITLS_CFG_FreeConfig(testInfo.serverConfig);
    FRAME_FreeLink(testInfo.client);
    FRAME_FreeLink(testInfo.server);
    HITLS_SESS_Free(testInfo.clientSession);
    FreeSNIArg(sniArg);
}
/* END_CASE */