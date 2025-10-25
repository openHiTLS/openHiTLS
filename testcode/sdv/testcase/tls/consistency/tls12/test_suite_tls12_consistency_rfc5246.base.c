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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
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
#include "app.h"
#include "alert.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "recv_process.h"
#include "stub_utils.h"
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
#include "logger.h"
#include "alert.h"
#include "stub_crypt.h"
#include "rec_wrapper.h"

#define PARSEMSGHEADER_LEN 13           /* Message header length */
#define ILLEGAL_VALUE 0xFF              /* Invalid value */
#define HASH_EXDATA_LEN_ERROR 23        /* Length of the content of the client_HELLOW signature hash field */
#define SIGNATURE_ALGORITHMS 0x04, 0x03 /* Fields added to the SERVER_HELLOW message */
#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */
#define READ_BUF_LEN_18K (18 * 1024)
#define TEMP_DATA_LEN 1024              /* Length of a single message */
#define ALERT_BODY_LEN 2u   /* Alert data length */
#define GetEpochSeq(epoch, seq) (((uint64_t)(epoch) << 48) | (seq))

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
    bool needStopBeforeRecvCCS;  /* CCS test, so that the TRY_RECV_FINISH stops before the CCS message is received */
} HandshakeTestInfo;

typedef struct {
    char *cipher;
    char *groups;
    char *signAlg;
    char *cert;
} CipherInfo;

typedef struct {
    int port;
    HITLS_HandshakeState expectHsState; // Expected Local Handshake Status.
    bool alertRecvFlag;     // Indicates whether the alert is received. The value fasle indicates the sent alert, and the value true indicates the received alert.
    ALERT_Description expectDescription; // Expected alert description of the test end.
    bool isSupportClientVerify; // Indicates whether to use the dual-end verification.
    bool isSupportExtendMasterSecret; // Indicates whether to use an extended master key.
    bool isSupportDhCipherSuites; // Indicates whether to use the DHE cipher suite
    bool isExpectRet;                     // Indicates whether the return value is expected.
    int expectRet;                        // Expected return value. The isExpectRet function needs to be enabled.
    const char *serverGroup;              // Configure the group supported by the server. If this parameter is not specified, the default value is used.
    const char *serverSignature;          // Configure the signature algorithm supported by the server. If this parameter is left empty, the default value is used.
    const char *clientGroup;              // Configure the group supported by the client. If this parameter is left empty, the default value is used.
    const char *clientSignature;          // Configure the signature algorithm supported by the client. If this parameter is left empty, the default value is used.
} TestPara;

int32_t StatusPark(HandshakeTestInfo *testInfo)
{
    /** Construct link */
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Perform the CCS test so that the TRY_RECV_FINISH is stopped before the CCS message is received.
     * The default value is False, which does not affect the original test.
     */
    testInfo->client->needStopBeforeRecvCCS = testInfo->isClient ? testInfo->needStopBeforeRecvCCS : false;
    testInfo->server->needStopBeforeRecvCCS = testInfo->isClient ? false : testInfo->needStopBeforeRecvCCS;

    /** Establish a link and stop in a certain state. */
    if (FRAME_CreateConnection(testInfo->client, testInfo->server, testInfo->isClient, testInfo->state) !=
        HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    /** Construct configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;

    return StatusPark(testInfo);
}

int32_t DefaultCfgStatusParkWithSuite(HandshakeTestInfo *testInfo)
{
    FRAME_Init();

    /** Construct configuration. */
    testInfo->config = HITLS_CFG_NewTLS12Config();
    if (testInfo->config == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    HITLS_CFG_SetCheckKeyUsage(testInfo->config, false);
    uint16_t cipherSuits[] = {HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
    HITLS_CFG_SetCipherSuites(testInfo->config, cipherSuits, sizeof(cipherSuits) / sizeof(uint16_t));

    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusPark(testInfo);
}

int32_t StatusPark1(HandshakeTestInfo *testInfo)
{
    /* Construct a link. */
    if(testInfo->isServerExtendMasterSecret == true){
        testInfo->config->isSupportExtendMasterSecret = true;
    }else {
        testInfo->config->isSupportExtendMasterSecret = false;
    }
    testInfo->config->isSupportRenegotiation = false;
    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if(testInfo->isServerExtendMasterSecret == true){
        testInfo->config->isSupportExtendMasterSecret = false;
    }else {
        testInfo->config->isSupportExtendMasterSecret = true;
    }
    testInfo->config->isSupportRenegotiation = testInfo->isSupportRenegotiation;
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Set up a link and stop in a certain state. */
    if (FRAME_CreateConnection(testInfo->client, testInfo->server,
                               testInfo->isClient, testInfo->state) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t DefaultCfgStatusPark1(HandshakeTestInfo *testInfo)
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

    testInfo->config->isSupportExtendMasterSecret = testInfo->isSupportExtendMasterSecret;
    testInfo->config->isSupportClientVerify = testInfo->isSupportClientVerify;
    testInfo->config->isSupportNoClientCert = testInfo->isSupportNoClientCert;

    return StatusPark1(testInfo);
}

int32_t StatusPark2(HandshakeTestInfo *testInfo)
{
    /* Construct a link. */
    testInfo->client = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->client == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    testInfo->server = FRAME_CreateLink(testInfo->config, BSL_UIO_TCP);
    if (testInfo->server == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* Establish a link and stop in a certain state. */
    if (FRAME_CreateConnection(testInfo->client, testInfo->server,
                               testInfo->isClient, testInfo->state) != HITLS_SUCCESS) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t SendHelloReq(HITLS_Ctx *ctx)
{
    /** Initialize the message buffer. */
    uint8_t buf[HS_MSG_HEADER_SIZE] = {0u};
    size_t len = HS_MSG_HEADER_SIZE;

    /** Write records. */
    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
}

int32_t ConstructAnEmptyCertMsg(FRAME_LinkObj *link)
{
    FRAME_Msg frameMsg = {0};
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(link->io);

    /** Obtain the message buffer. */
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

    /** reassemble */
    if (PackFrameMsg(&frameMsg) != HITLS_SUCCESS) {
        frameMsg.body.handshakeMsg.body.certificate.cert = tmpCert;
        CleanRecordBody(&frameMsg);
        return HITLS_INTERNAL_EXCEPTION;
    }

    /** Message injection */
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
    for (uint32_t i = randLen - 1; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return HITLS_SUCCESS;
}

#define TEST_CLIENT_SEND_FAIL 1
uint32_t g_uiPort = 8889;

void TestSetCertPath(HLT_Ctx_Config *ctxConfig, char *SignatureType)
{
    if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA1", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA1")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA256")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA384")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA384_EE_PATH, RSA_SHA384_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA512", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA512")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA512_EE_PATH, RSA_SHA512_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA384_EE_PATH,
            ECDSA_SHA384_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA512_EE_PATH,
            ECDSA_SHA512_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_ECDSA_SHA1", strlen("CERT_SIG_SCHEME_ECDSA_SHA1")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA1_CA_PATH,
            ECDSA_SHA1_CHAIN_PATH,
            ECDSA_SHA1_EE_PATH,
            ECDSA_SHA1_PRIV_PATH,
            "NULL",
            "NULL");
    }
}

void ClientSendMalformedRecordHeaderMsg(HLT_FrameHandle *handle, TestPara *testPara)
{
    // Create a process.
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, false);
    ASSERT_TRUE(remoteProcess != NULL);

    // The remote server listens on the TLS link.
    HLT_Ctx_Config *serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig != NULL);

    ASSERT_TRUE(HLT_SetCipherSuites(serverConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0);
    ASSERT_TRUE(HLT_SetGroups(serverConfig, "HITLS_EC_GROUP_SECP256R1") == 0);
    ASSERT_TRUE(HLT_SetSignature(serverConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256") == 0);
    TestSetCertPath(serverConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig, testPara->isSupportClientVerify) == 0);

    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(remoteProcess, TLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configure the TLS connection on the local client.
    HLT_Ctx_Config *clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig != NULL);
    ASSERT_TRUE(HLT_SetCipherSuites(clientConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0);
    ASSERT_TRUE(HLT_SetGroups(clientConfig, "HITLS_EC_GROUP_SECP256R1") == 0);
    ASSERT_TRUE(HLT_SetSignature(clientConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256") == 0);
    TestSetCertPath(clientConfig, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");

    HLT_Tls_Res *clientRes = HLT_ProcessTlsInit(localProcess, TLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    // Configure the interface for constructing abnormal messages.
    handle->ctx = clientRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
    // Set up a link and wait for the local end to complete the link.
    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) != 0);
    // Wait the remote end.
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);

    // Confirm the final status.
    ASSERT_EQ(HLT_RpcTlsGetStatus(remoteProcess, serverRes->sslId), CM_STATE_ALERTED);
    ASSERT_EQ((ALERT_Level)HLT_RpcTlsGetAlertLevel(remoteProcess, serverRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ((ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, serverRes->sslId),
        testPara->expectDescription);
    ASSERT_EQ(((HITLS_Ctx *)(clientRes->ssl))->hsCtx->state, testPara->expectHsState);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

void ServerSendMalformedRecordHeaderMsg(HLT_FrameHandle *handle, TestPara *testPara)
{
    // Create a process.
    HLT_Process *localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HLT_Process *remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, testPara->port, true);
    ASSERT_TRUE(remoteProcess != NULL);
    // The local server listens on the TLS link.
    HLT_Ctx_Config *serverConfig1 = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverConfig1 != NULL);
    ASSERT_TRUE(HLT_SetClientVerifySupport(serverConfig1, testPara->isSupportClientVerify) == 0);

    ASSERT_TRUE(HLT_SetCipherSuites(serverConfig1, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0);
    ASSERT_TRUE(HLT_SetGroups(serverConfig1, "HITLS_EC_GROUP_SECP256R1") == 0);
    ASSERT_TRUE(HLT_SetSignature(serverConfig1, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256") == 0);
    TestSetCertPath(serverConfig1, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");

    HLT_Tls_Res *serverRes = HLT_ProcessTlsAccept(localProcess, TLS1_2, serverConfig1, NULL);
    ASSERT_TRUE(serverRes != NULL);

    // Configure the interface for constructing abnormal messages.
    handle->ctx = serverRes->ssl;
    ASSERT_TRUE(HLT_SetFrameHandle(handle) == 0);
    // Set up a TLS link on the remote client.
    HLT_Ctx_Config *clientConfig1 = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientConfig1 != NULL);

    ASSERT_TRUE(HLT_SetCipherSuites(clientConfig1, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0);
    ASSERT_TRUE(HLT_SetGroups(clientConfig1, "HITLS_EC_GROUP_SECP256R1") == 0);
    ASSERT_TRUE(HLT_SetSignature(clientConfig1, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256") == 0);
    TestSetCertPath(clientConfig1, "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256");
    HLT_Tls_Res *clientRes = HLT_ProcessTlsInit(remoteProcess, TLS1_2, clientConfig1, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_RpcTlsConnect(remoteProcess, clientRes->sslId) != 0);
    // Wait for the local end.
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) != 0);
    // Confirm the final status.
    ASSERT_EQ(((HITLS_Ctx *)(serverRes->ssl))->hsCtx->state, testPara->expectHsState);
    ASSERT_TRUE(HLT_RpcTlsGetStatus(remoteProcess, clientRes->sslId) == CM_STATE_ALERTED);
    ASSERT_EQ((ALERT_Level)HLT_RpcTlsGetAlertLevel(remoteProcess, clientRes->sslId), ALERT_LEVEL_FATAL);
    ASSERT_EQ((ALERT_Description)HLT_RpcTlsGetAlertDescription(remoteProcess, clientRes->sslId),
        testPara->expectDescription);

EXIT:
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    return;
}

void SetFrameType(FRAME_Type *frametype, uint16_t versionType, REC_Type recordType, HS_MsgType handshakeType,
    HITLS_KeyExchAlgo keyExType)
{
    frametype->versionType = versionType;
    frametype->recordType = recordType;
    frametype->handshakeType = handshakeType;
    frametype->keyExType = keyExType;
    frametype->transportType = BSL_UIO_TCP;
}