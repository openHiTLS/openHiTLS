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

#include <stdlib.h>
#include <semaphore.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "securec.h"
#include "bsl_sal.h"
#include "alert.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_reg.h"
#include "hitls_config.h"
#include "tls_config.h"
#include "hitls.h"
#include "hitls_func.h"
#include "pack_frame_msg.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_cert_type.h"
#include "crypt_util_rand.h"
#include "common_func.h"
#include "frame_tls.h"
#include "conn_init.h"
#include "tls.h"
#include "simulate_io.h"
#include "frame_io.h"
#include "frame_link.h"
#include "stub_replace.h"
#include "session_type.h"
#include "cert_callback.h"
#include "bsl_sal.h"
#include "sal_net.h"
#include "parse_msg.h"
#include "hs_msg.h"
#include "hitls_crypt_init.h"
#include "uio_abstraction.h"
#include "process.h"
#include "rec_wrapper.h"
#include "hs_ctx.h"
#include "hitls_type.h"
/* END_HEADER */

#define Port 7788
#define READ_BUF_SIZE 18432
#define ROOT_DER "%s/ca.der:%s/inter.der"
#define INTCA_DER "%s/inter.der"
#define SERVER_DER "%s/server.der"
#define SERVER_KEY_DER "%s/server.key.der"
#define CLIENT_DER "%s/client.der"
#define CLIENT_KEY_DER "%s/client.key.der"
#define RENEGOTIATE_FAIL 1
#define MAX_CERT_LIST 4294967295
#define MIN_CERT_LIST 0

static uint32_t g_useFlight = 0; /* Range required in the test case */
static uint32_t g_flag;          /* Used to record the number of handshake messages in the current flight. */
static uint32_t g_flight = 0;    /* is used to record the number of the current flight */
static HLT_FrameHandle g_frameHandle;
static HITLS_Config *GetHitlsConfigViaVersion(int ver)
{
    switch (ver) {
        case TLS1_2:
        case HITLS_VERSION_TLS12:
            return HITLS_CFG_NewTLS12Config();
        case TLS1_3:
        case HITLS_VERSION_TLS13:
            return HITLS_CFG_NewTLS13Config();
        case DTLS1_2:
        case HITLS_VERSION_DTLS12:
            return HITLS_CFG_NewDTLS12Config();
        default:
            return NULL;
    }
}

static void TEST_MsgHandle(void *msg, void *data)
{
    (void)data;
    (void)msg;
}

/* Verify whether the parsed msg meets the requirements. Restrict the msg input parameter. */
static bool CheckHandleType(FRAME_Msg *msg)
{
    if (msg->recType.data != REC_TYPE_HANDSHAKE) {
        if (msg->recType.data == (uint64_t)g_frameHandle.expectReType) {
            return true;
        }
    } else {
        if (msg->recType.data == (uint64_t)g_frameHandle.expectReType &&
            msg->body.hsMsg.type.data == (uint64_t)g_frameHandle.expectHsType) {
            return true;
        }
    }
    return false;
}

/* Obtain the frameType. The input parameters frameHandle and frameType must not be empty. */
static int32_t GetFrameType(HLT_FrameHandle *frameHandle, FRAME_Type *frameType)
{
    if (frameHandle->ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    TLS_Ctx *tmpCtx = (TLS_Ctx *)frameHandle->ctx;
    frameType->versionType = tmpCtx->negotiatedInfo.version > 0 ?
        tmpCtx->negotiatedInfo.version : tmpCtx->config.tlsConfig.maxVersion;
    frameType->keyExType = tmpCtx->hsCtx->kxCtx->keyExchAlgo;
    frameType->recordType = frameHandle->expectReType;
    frameType->handshakeType = frameHandle->expectHsType;
    return HITLS_SUCCESS;
}

static int32_t STUB_Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    FRAME_Msg msg = {0};
    uint32_t parseLen = 0;
    uint32_t offset = 0;
    uint32_t msgCnt = 0;
    FRAME_Type frameType = { 0 };
    (void)GetFrameType(&g_frameHandle, &frameType);

    g_flight++;
    while (offset < len) {
        (void)FRAME_ParseMsgHeader(&frameType, &((uint8_t*)buf)[offset], len - offset, &msg, &parseLen);
        offset += parseLen + msg.length.data;
        if (g_flight == g_useFlight) {
            msgCnt++;
        }
        FRAME_CleanMsg(&frameType, &msg);
    }
    if (CheckHandleType(&msg) && g_flight == g_useFlight) {
        g_flag = msgCnt;
    }

    return BSL_UIO_TcpMethod()->uioWrite(uio, buf, len, writeLen);
}


static int SetCertPath(HLT_Ctx_Config *ctxConfig, const char *certStr, bool isServer)
{
    char caCertPath[50];
    char chainCertPath[30];
    char eeCertPath[30];
    char privKeyPath[30];

    int32_t ret = sprintf_s(caCertPath, sizeof(caCertPath), ROOT_DER, certStr, certStr);
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

/* @
* @test SDV_TLS_CFG_SET_GET_VERIFYNONESUPPORT_FUNC_TC001
* @title The server does not verify the client certificate.
* @precon nan
* @brief
* 1. The server invokes the HITLS_CFG_SetVerifyNoneSupport and sets the parameter to false. Expected result 1 is
*    obtained.
* 2. The server invokes the HITLS_CFG_SetVerifyNoneSupport interface to obtain the configuration result. (Expected
*    result 2)
* 3. The server invokes the HITLS_SetVerifyNoneSupport interface and sets it to true. Expected result 3 is obtained.
* 4. The server invokes the HITLS_GetVerifyNoneSupport interface to obtain the configuration result. (Expected result 4)
* 4. Establish a connection. Expected result 4 is obtained.
* @expect
* 1. The setting is successful.
* 2. The setting is successful.
* 3. The setting is successful.
* 4. The connection is successfully established.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_SET_GET_VERIFYNONESUPPORT_FUNC_TC001(int version, int connType)
{
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    bool c_flag = 0;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, Port, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    ASSERT_EQ(SetCertPath(serverCtxConfig, "ecdsa_sha256", true), 0);
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

    serverRes = HLT_ProcessTlsAccept(localProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HITLS_SetVerifyNoneSupport(serverRes->ssl, true);
    HITLS_GetVerifyNoneSupport(serverRes->ssl, &c_flag);
    ASSERT_TRUE(c_flag == 1);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetCertPath(clientCtxConfig, "ecdsa_sha256/ca.der", "NULL", "NULL", "NULL", "NULL", "NULL");
    HLT_SetCipherSuites(serverCtxConfig, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

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

/** @
* @test HITLS_TLS1_2_Config_SDV_23_0_5_047
* @title Enable dual-end verification. The server verifies the client certificate only once.
* @precon nan
* @brief
* 1. The server invokes the HITLS_CFG_SetClientVerifySupport and sets the parameter to true.
* 2. Set the value of HITLS_CFG_SetClientOnceVerifySupport to false when the server invokes the
* HITLS_CFG_SetClientOnceVerifySupport.
* 3. The server invokes the HITLS_CFG_SetClientOnceVerifySupport interface to obtain the configuration result.
* 4. The server invokes the HITLS_SetClientOnceVerifySupport interface and sets it to true.
* 5. The server invokes the HITLS_SetClientOnceVerifySupport interface to obtain the configuration result.
* 6. Establish a connection. After the connection is established, perform renegotiation. Stop the status on the server to
* TRY_SEND_CERTIFICATIONATE_REQUEST. The expected result is obtained.
* @expect
* 1. If the status fails to be stopped, the certificate will not be verified during the renegotiation.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_SET_GET_CLIENTVERIFYUPPORT_FUNC_TC001(int clientverify)
{
    FRAME_Init();

    HITLS_Config *config_c = NULL;
    HITLS_Config *config_s = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    config_c = HITLS_CFG_NewTLS12Config();
    config_s = HITLS_CFG_NewTLS12Config();

    ASSERT_TRUE(config_c != NULL);
    ASSERT_TRUE(config_s != NULL);

    bool c_flag;

    if (clientverify) {
        HITLS_CFG_SetClientVerifySupport(config_s, true);
    } else {
        HITLS_CFG_SetClientVerifySupport(config_s, false);
    }

    HITLS_CFG_SetClientOnceVerifySupport(config_s, false);
    HITLS_CFG_GetClientOnceVerifySupport(config_s, &c_flag);
    ASSERT_TRUE(c_flag == 0);

    client = FRAME_CreateLink(config_c, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(config_s, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    HITLS_SetClientOnceVerifySupport(server->ssl, true);
    HITLS_GetClientOnceVerifySupport(server->ssl, &c_flag);
    ASSERT_TRUE(c_flag == 1);
    HITLS_SetRenegotiationSupport(server->ssl, true);
    HITLS_SetRenegotiationSupport(client->ssl, true);
    HITLS_GetRenegotiationSupport(server->ssl, &c_flag);
    ASSERT_TRUE(c_flag == 1);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t verifyDataNew[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataNewSize = 0;
    uint8_t verifyDataOld[MAX_DIGEST_SIZE] = {0};
    uint32_t verifyDataOldSize = 0;
    ASSERT_TRUE(HITLS_GetFinishVerifyData(server->ssl, verifyDataOld, sizeof(verifyDataOld),
        &verifyDataOldSize) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_Renegotiate(client->ssl) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_Renegotiate(server->ssl) == HITLS_SUCCESS);
    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, TRY_SEND_CERTIFICATE_REQUEST), HITLS_INTERNAL_EXCEPTION);
    ASSERT_TRUE(HITLS_GetFinishVerifyData(server->ssl, verifyDataNew, sizeof(verifyDataNew),
        &verifyDataNewSize) == HITLS_SUCCESS);
    ASSERT_TRUE(memcmp(verifyDataNew, verifyDataOld, verifyDataOldSize) != 0);
EXIT:
    HITLS_CFG_FreeConfig(config_c);
    HITLS_CFG_FreeConfig(config_s);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_ADD_CAINDICATION_FUNC_TC001
* @title: Add different CA flag indication types.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_AddCAIndication interface and set the transferred caType to HITLS_TRUSTED_CA_PRE_AGREED and
*    HITLS_TRUSTED_CA_PRE_AGREED respectively. HITLS_TRUSTED_CA_KEY_SHA1, HITLS_TRUSTED_CA_X509_NAME,
*    HITLS_TRUSTED_CA_CERT_SHA1, When the HITLS_TRUSTED_CA_UNKNOWN macro is used, expected result 1 is obtained.
* 2. Check the return value of the interface. Expected result 2 is obtained.
* @expect
* 1. The invoking is successful.
* 2. The interface returns HITLS_SUCCESS.
@ */

/* BEGIN_CASE */
void SDV_TLS_CFG_ADD_CAINDICATION_FUNC_TC001(int tlsVersion)
{
    FRAME_Init();
    HITLS_Config *config = NULL;
    uint8_t data[] = {0};
    uint32_t len = sizeof(data);

    config = GetHitlsConfigViaVersion(tlsVersion);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_PRE_AGREED, data, len) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_KEY_SHA1, data, len) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_X509_NAME, data, len) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_CERT_SHA1, data, len) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_AddCAIndication(config, HITLS_TRUSTED_CA_UNKNOWN, data, len) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_GET_CIPHERBYID_FUNC_TC001
* @title Obtain the CipherId based on the known cipher suite.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_GetCipherByID and set the transferred id to the HITLS_AES_128_GCM_SHA256 macro to obtain the
*     HITLS_Cipher structure. (Expected result 1)
* 2. Invoke the HITLS_CFG_GetCipherId interface and transfer the obtained structure. (Expected result 2)
* @expect
* 1. The interface returns the corresponding HITLS_Cipher structure.
* 2. HITLS_CIPHER_AES_128_GCM is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_CIPHERBYID_FUNC_TC001()
{
    FRAME_Init();
    HITLS_CipherAlgo cipherAlgo;


    const HITLS_Cipher* cipher  = HITLS_CFG_GetCipherByID(HITLS_AES_128_GCM_SHA256);
    HITLS_CFG_GetCipherId(cipher, &cipherAlgo);
    ASSERT_EQ(cipherAlgo, HITLS_CIPHER_AES_128_GCM);

EXIT:
     return;
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_GET_AUTHID_FUNC_TC001
* @title Self-registration cipher. Invoke the interface to obtain the AuthId.
* @precon nan
* @brief
* 1. Register a HITLS_Cipher structure, set cipherid to HITLS_AUTH_NULL, and call HITLS_CFG_GetAuthId. Expected result 1
*     is obtained.
* @expect
* 1. HITLS_AUTH_NULL is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_AUTHID_FUNC_TC001()
{
    FRAME_Init();
    HITLS_AuthAlgo cipherSuite;
    HITLS_Cipher *cipher = (HITLS_Cipher *)malloc(sizeof(HITLS_Cipher));
    cipher->authAlg = HITLS_AUTH_NULL;

    HITLS_CFG_GetAuthId(cipher, &cipherSuite);
    ASSERT_EQ(cipherSuite, HITLS_AUTH_NULL);

EXIT:
     free(cipher);
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_GET_CIPHERSUITENAME_FUNC_TC001
* @title Query the name of the algorithm suite.
* @precon nan
* @brief
* 1. Set cipher to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 and invoke the HITLS_CFG_GetCipherSuiteName interface.
*     Expected result 1 is obtained.
* @expect
* 1. Return value of the char* conversion interface, which is the same as that of the
*    HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_CIPHERSUITENAME_FUNC_TC001()
{
    FRAME_Init();
    const HITLS_Cipher* cipher = HITLS_CFG_GetCipherByID(HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);

    const uint8_t* name = HITLS_CFG_GetCipherSuiteName(cipher);
    ASSERT_TRUE(strcmp((char *)name, "HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0);
EXIT:
    return;
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_GET_CIPHERVERSION_FUNC_TC001
* @title Query the cipher suite version and obtain the algorithm based on the ID.
* @precon nan
* @brief
* 1. Set cipher to HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 () and invoke the HITLS_CFG_GetCipherVersion interface.
*    (Expected result 1)
* 2. Set cipher to HITLS_AES_128_GCM_SHA256 () and invoke the HITLS_CFG_GetCipherVersion interface. (Expected result 2)
* 3. Set cipher to HITLS_RSA_WITH_AES_128_CBC_SHA () and invoke the HITLS_CFG_GetCipherVersion interface. (Expected
* result 3)
* @expect
* 1. Interface return value: HITLS_VERSION_TLS12
* 2. Interface return value: HITLS_VERSION_TLS13, HITLS_VERSION_TLS13
* 3. Interface return value: HITLS_VERSION_SSL30
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_CIPHERVERSION_FUNC_TC001()
{
    FRAME_Init();
    int32_t version;
    const HITLS_Cipher *cipher = HITLS_CFG_GetCipherByID(HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    ASSERT_EQ(HITLS_CFG_GetCipherVersion(cipher, &version), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_VERSION_TLS12, version);

    cipher = HITLS_CFG_GetCipherByID(HITLS_AES_128_GCM_SHA256);
    ASSERT_EQ(HITLS_CFG_GetCipherVersion(cipher, &version), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_VERSION_TLS13, version);

    cipher = HITLS_CFG_GetCipherByID(HITLS_RSA_WITH_AES_128_CBC_SHA);
    ASSERT_EQ(HITLS_CFG_GetCipherVersion(cipher, &version), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_VERSION_SSL30, version);
EXIT:
    version = 1;
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_GET_CIPHERSUITE_FUNC_TC001
* @title Obtain the cipher suite based on the supported cipher suite ID.
* @precon nan
* @brief
* 1. Invoke the HITLS_CFG_GetCipherByID and set the input ID to the HITLS_AES_128_GCM_SHA256 macro to obtain the
*    cipherinfo structure. Expected result 1 is obtained.
* 2. Invoke the HITLS_CFG_GetCipherSuite interface and transfer the obtained structure. (Expected result 2)
* @expect
* 1. The interface returns the corresponding HITLS_Cipher structure.
* 2. HITLS_AES_128_GCM_SHA256 is returned.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_CIPHERSUITE_FUNC_TC001()
{
    FRAME_Init();
    uint16_t cipherSuite;
    const HITLS_Cipher* cipher  = HITLS_CFG_GetCipherByID(HITLS_AES_128_GCM_SHA256);

    HITLS_CFG_GetCipherSuite(cipher, &cipherSuite);
    ASSERT_EQ(cipherSuite, HITLS_AES_128_GCM_SHA256);

EXIT:
     return;
}
/* END_CASE */

/** @
* @test  SDV_TLS_CFG_GET_FLIGHTTRANSMITSWITH_FUNC_TC001
* @titleThe client sends messages by flight.
* @precon nan
* @brief 1. The server invokes the HITLS_CFG_SetFlightTransmitSwitch interface and sets the parameter to false. Expected
            result 1 is obtained.
        2. The server invokes the HITLS_CFG_GetFlightTransmitSwitch interface to obtain the configuration result.
            (Expected result 2)
        3. The client invokes the HITLS_SetFlightTransmitSwitch interface to set the parameter to true. Expected result
            3 is obtained.
        4. The client invokes the HITLS_GetFlightTransmitSwitch interface to obtain the configuration result. Expected
            result 4 is obtained.
        5. Establish a link and count the number of messages sent by the client in the second flight. Expected result 5
            is obtained.
* @expect
        1. The setting is successful.
        2. The obtained result is false.
        3. The setting is successful.
        4. The obtained result is true.
        5. The connection is set up successfully, and the number of the second flight messages sent by the client is 3.
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_FLIGHTTRANSMITSWITH_FUNC_TC001(int version)
{
    FRAME_Init();

    HITLS_Config *Config = NULL;
    HITLS_Ctx *ctx = NULL;
    bool support;
    Config = GetHitlsConfigViaVersion(version);
    ASSERT_TRUE(Config != NULL);
    ctx = HITLS_New(Config);
    ASSERT_TRUE(ctx != NULL);

    HITLS_CFG_SetFlightTransmitSwitch(Config, false);
    HITLS_CFG_GetFlightTransmitSwitch(Config, &support);
    ASSERT_TRUE(support == false);

    HITLS_SetFlightTransmitSwitch(ctx, true);
    HITLS_GetFlightTransmitSwitch(ctx, &support);
    ASSERT_TRUE(support == true);

    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    remoteProcess = HLT_LinkRemoteProcess(HITLS, TCP, Port, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    HLT_SetFlightTransmitSwitch(serverCtxConfig, false);
    serverRes = HLT_ProcessTlsAccept(remoteProcess, version, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);

    HLT_SetFlightTransmitSwitch(clientCtxConfig, true);
    clientRes = HLT_ProcessTlsInit(localProcess, version, clientCtxConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    HLT_FrameHandle frameHandle = {
        .ctx = clientRes->ssl,
        .frameCallBack = TEST_MsgHandle,
        .userData = NULL,
        .expectHsType = CLIENT_KEY_EXCHANGE,
        .expectReType = REC_TYPE_HANDSHAKE,
        .ioState = EXP_NONE,
        .pointType = POINT_SEND,
        .method.uioWrite = STUB_Write,
    };
    ASSERT_TRUE(HLT_SetFrameHandle(&frameHandle) == HITLS_SUCCESS);
    g_useFlight = 2;
    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) == HITLS_SUCCESS);
    if (version == TLS1_2) {
        ASSERT_EQ(g_flag, 3);
    } else {
        ASSERT_EQ(g_flag, 2);
    }

    HLT_CleanFrameHandle();
EXIT:
    g_flag = 0;
    g_flight = 0;
    HLT_CleanFrameHandle();
    HLT_FreeAllProcess();
    HITLS_CFG_FreeConfig(Config);
    HITLS_Free(ctx);
    return;
}
/* END_CASE */

/** @
* @test SDV_TLS_CFG_GET_MAXCERTLIST_API_TC001
* @title HTLS_CFG_SetMaxCertList, HITLS_CFG_GetMaxCertList, HITLS_SetMaxCertList, and HITLS_GetMaxCertList APIs
* @precon nan
* @brief
* 1. Apply for and initialize config and ctx.
* 2. Set the certificate chain length config to null and invoke the HITLS_CFG_SetMaxCertList interface.
* 3. Invoke the HITLS_CFG_GetMaxCertList interface and check the output parameter value.
* 4. Set the maximum length of the certificate chain by calling the HITLS_CFG_SetMaxCertList interface.
* 5. Invoke the HITLS_CFG_GetMaxCertList interface and check the output parameter value.
* 6. Set the minimum certificate chain length by calling the HITLS_CFG_SetMaxCertList interface.
* 7. Invoke the HITLS_CFG_GetMaxCertList interface and check the output parameter value.
* 8. Use the HITLS_SetMaxCertList and HITLS_GetMaxCertList interfaces to repeat the preceding test.
* @expect
* 1. Initialization succeeds.
* 2. HITLS_NULL_INPUT is returned.
* 3. HITLS_NULL_INPUT is returned.
* 4. The interface returns HITLS_SUCCESS.
* 5. The value of MaxCertList returned by the interface is 2 ^ 32 - 1.
* 6. The interface returns the HITLS_SUCCESS.
* 7. The value of MaxCertList returned by the interface is 0.
* 8. Same as above
@ */
/* BEGIN_CASE */
void SDV_TLS_CFG_GET_MAXCERTLIST_API_TC001()
{
    FRAME_Init();
    HITLS_Config *tlsConfig;
    HITLS_Ctx *ctx = NULL;
    tlsConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    uint32_t maxSize;

    ASSERT_TRUE(HITLS_CFG_SetMaxCertList(NULL, MAX_CERT_LIST) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetMaxCertList(NULL, &maxSize) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetMaxCertList(tlsConfig, MAX_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxCertList(tlsConfig, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MAX_CERT_LIST);

    ASSERT_TRUE(HITLS_CFG_SetMaxCertList(tlsConfig, MIN_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetMaxCertList(tlsConfig, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MIN_CERT_LIST);

    ASSERT_TRUE(HITLS_SetMaxCertList(NULL, MAX_CERT_LIST) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetMaxCertList(NULL, &maxSize) == HITLS_NULL_INPUT);

    ASSERT_TRUE(HITLS_SetMaxCertList(ctx, MAX_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetMaxCertList(ctx, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MAX_CERT_LIST);

    ASSERT_TRUE(HITLS_SetMaxCertList(ctx, MIN_CERT_LIST) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetMaxCertList(ctx, &maxSize) == HITLS_SUCCESS);
    ASSERT_TRUE(maxSize == MIN_CERT_LIST);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */
