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
#include "securec.h"
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "hitls.h"
#include "process.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_func.h"
#include "hitls.h"
#include "conn_init.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "hs_common.h"
#include "change_cipher_spec.h"
#include "stub_utils.h"

#define READ_BUF_SIZE 18432
#define Port 7788
#define ROOT_DER "%s/ca.der:%s/inter.der"
#define INTCA_DER "%s/inter.der"
#define SERVER_DER "%s/server.der"
#define SERVER_KEY_DER "%s/server.key.der"
#define CLIENT_DER "%s/client.der"
#define CLIENT_KEY_DER "%s/client.key.der"
#define BUF_SZIE 18432

/* END_HEADER */

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET2(int32_t, REC_GetMaxWriteSize, const TLS_Ctx *, uint32_t *);

static uint32_t g_uiPort = 18889;

static void SetCertPath_2(HLT_Ctx_Config *ctxConfig, char *cipherSuite)
{
    if (strstr(cipherSuite, "RSA") != NULL) {
        HLT_SetCertPath(ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, NULL, NULL);
    } else if (strstr(cipherSuite, "ECDSA") != NULL) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA_CA_PATH, ECDSA_SHA_CHAIN_PATH, ECDSA_SHA1_EE_PATH, ECDSA_SHA1_PRIV_PATH, NULL, NULL);
    } else {
        HLT_SetCertPath(ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, NULL, NULL);
    }
}

/**
 * @test SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC001
 * @title To test the setting of the HITLS_SetCipherServerPreference interface of the dtls.
 * @precon By default, the algorithm preferred by the client is preferred.
 * @brief
 * 1. Initialize the hitls.
 * 2. Create an SSL ctx object.
 * 3. Create an SSL object.
 * 4. Connect
 * 5. Check for connection errors.
 * 6. Check whether the negotiated cipher suite is the client preference.
 * 7. Check whether the negotiated group is the client preference.
 * 8. Check that the negotiated signature algorithm is the client preference.
 * @expect
 * 1. successful
 * 2. successful
 * 3. successful
 * 4. successful
 * 5. successful
 * 6. successful
 * 7. successful
 * 8. successful
 */
/* BEGIN_CASE */
void SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC001(char *serverCipherSuite, char *clientCipherSuite, int expectResult)
{
    if (!IsEnableSctpAuth()) {
        return;
    }
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HILT_TransportType connType = SCTP;
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);
    SetCertPath_2(serverCtxConfig, serverCipherSuite);
    HLT_SetGroups(serverCtxConfig, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    HLT_SetCipherSuites(serverCtxConfig, serverCipherSuite);
    HLT_SetSignature(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384:CERT_SIG_SCHEME_RSA_PKCS1_SHA512");

    serverRes = HLT_ProcessTlsAccept(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath_2(clientCtxConfig, clientCipherSuite);
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP384R1:HITLS_EC_GROUP_SECP256R1");
    HLT_SetCipherSuites(clientCtxConfig, clientCipherSuite);
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA512:CERT_SIG_SCHEME_RSA_PKCS1_SHA384");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[BUF_SZIE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    HITLS_Ctx *testCtx = (HITLS_Ctx *)serverRes->ssl;

    ASSERT_TRUE(testCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite == expectResult);

    ASSERT_TRUE(testCtx->negotiatedInfo.negotiatedGroup == HITLS_EC_GROUP_SECP384R1);

    ASSERT_TRUE(testCtx->negotiatedInfo.signScheme == CERT_SIG_SCHEME_RSA_PKCS1_SHA512);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC002
 * @title To test the setting of the HITLS_SetCipherServerPreference interface of the dtls.
 * @precon Set the algorithm for preferentially selecting the server-side preference.
 * @brief
 * 1. Initialize the hitls.
 * 2. Create an SSL ctx object.
 * 3. Create an SSL object.
 * 4. Connect
 * 5. Check for connection errors.
 * 6. Check whether the negotiated algorithm is the server preference.
 * @expect
 * 1. successful
 * 2. successful
 * 3. successful
 * 4. successful
 * 5. successful
 * 6. successful
 */
/* BEGIN_CASE */
void SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC002(char *serverCipherSuite, char *clientCipherSuite, int expectResult)
{
    if (!IsEnableSctpAuth()) {
        return;
    }
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HILT_TransportType connType = SCTP;
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath_2(serverCtxConfig, serverCipherSuite);
    HLT_SetGroups(serverCtxConfig, "NULL");
    HLT_SetCipherSuites(serverCtxConfig, serverCipherSuite);
    HLT_SetSignature(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384:CERT_SIG_SCHEME_RSA_PKCS1_SHA512");

    serverRes = HLT_ProcessTlsAccept(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    int32_t ret = HITLS_SetCipherServerPreference(serverRes->ssl, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);
    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath_2(clientCtxConfig, clientCipherSuite);
    HLT_SetGroups(clientCtxConfig, "NULL");
    HLT_SetCipherSuites(clientCtxConfig, clientCipherSuite);
    HLT_SetSignature(clientCtxConfig, "NULL");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[BUF_SZIE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    HITLS_Ctx *testCtx = (HITLS_Ctx *)serverRes->ssl;

    ASSERT_TRUE(testCtx->negotiatedInfo.cipherSuiteInfo.cipherSuite == expectResult);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC003
 * @title To test the setting of the HITLS_SetCipherServerPreference interface of the dtls.
 * @precon Set the signature algorithm preferred by the server.
 * @brief
 * 1. Initialize the hitls.
 * 2. Create an SSL ctx object.
 * 3. Create an SSL object.
 * 4. Connect
 * 5. Check for connection errors.
 * 6. Check whether the negotiated signature algorithm is the server preference.
 * @expect
 * 1. successful
 * 2. successful
 * 3. successful
 * 4. successful
 * 5. successful
 * 6. successful
 */
/* BEGIN_CASE */
void SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC003(char *serverCipherSuite, char *clientCipherSuite)
{
    if (!IsEnableSctpAuth()) {
        return;
    }
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HILT_TransportType connType = SCTP;
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath_2(serverCtxConfig, serverCipherSuite);
    HLT_SetCipherSuites(serverCtxConfig, serverCipherSuite);
    HLT_SetGroups(serverCtxConfig, "NULL");
    HLT_SetSignature(serverCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384:CERT_SIG_SCHEME_RSA_PKCS1_SHA512");

    serverRes = HLT_ProcessTlsAccept(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    int32_t ret = HITLS_SetCipherServerPreference(serverRes->ssl, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath_2(clientCtxConfig, clientCipherSuite);
    HLT_SetCipherSuites(clientCtxConfig, clientCipherSuite);
    HLT_SetGroups(clientCtxConfig, "NULL");
    HLT_SetSignature(clientCtxConfig, "CERT_SIG_SCHEME_RSA_PKCS1_SHA512:CERT_SIG_SCHEME_RSA_PKCS1_SHA384");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[BUF_SZIE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    HITLS_Ctx *testCtx = (HITLS_Ctx *)serverRes->ssl;

    ASSERT_TRUE(testCtx->negotiatedInfo.signScheme == CERT_SIG_SCHEME_RSA_PKCS1_SHA384);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

/**
 * @test SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC004
 * @title To test the setting of the HITLS_SetCipherServerPreference interface of the dtls.
 * @precon Set the preference group of the server.
 * @brief
 * 1. Initialize the hitls.
 * 2. Create an SSL ctx object.
 * 3. Create an SSL object.
 * 4. Connect
 * 5. Check for connection errors.
 * 6. Check whether the negotiated group is the server preference.
 * @expect
 * 1. successful
 * 2. successful
 * 3. successful
 * 4. successful
 * 5. successful
 * 6. successful
 */
/* BEGIN_CASE */
void SDV_HITLS_CM_HITLS_GetNegotiateGroup_FUNC_TC004(char *serverCipherSuite, char *clientCipherSuite)
{
    if (!IsEnableSctpAuth()) {
        return;
    }
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HILT_TransportType connType = SCTP;
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, g_uiPort, true);
    ASSERT_TRUE(remoteProcess != NULL);

    HLT_Ctx_Config *serverCtxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    ASSERT_TRUE(serverCtxConfig != NULL);

    SetCertPath_2(serverCtxConfig, serverCipherSuite);
    HLT_SetCipherSuites(serverCtxConfig, serverCipherSuite);
    HLT_SetGroups(serverCtxConfig, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1");
    HLT_SetSignature(serverCtxConfig, "NULL");

    serverRes = HLT_ProcessTlsAccept(localProcess, DTLS1_2, serverCtxConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);

    int32_t ret = HITLS_SetCipherServerPreference(serverRes->ssl, true);
    ASSERT_TRUE(ret == HITLS_SUCCESS);

    HLT_Ctx_Config *clientCtxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(clientCtxConfig != NULL);
    SetCertPath_2(clientCtxConfig, clientCipherSuite);
    HLT_SetCipherSuites(clientCtxConfig, clientCipherSuite);
    HLT_SetGroups(clientCtxConfig, "HITLS_EC_GROUP_SECP384R1:HITLS_EC_GROUP_SECP256R1");
    HLT_SetSignature(clientCtxConfig, "NULL");

    clientRes = HLT_ProcessTlsConnect(remoteProcess, DTLS1_2, clientCtxConfig, NULL);

    ASSERT_TRUE(clientRes != NULL);
    ASSERT_TRUE(HLT_GetTlsAcceptResult(serverRes) == 0);

    ASSERT_TRUE(HLT_ProcessTlsWrite(localProcess, serverRes, (uint8_t *)"Hello World", strlen("Hello World")) == 0);
    uint8_t readBuf[BUF_SZIE] = {0};
    uint32_t readLen;
    ASSERT_TRUE(HLT_ProcessTlsRead(remoteProcess, clientRes, readBuf, sizeof(readBuf), &readLen) == 0);
    ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    HITLS_Ctx *testCtx = (HITLS_Ctx *)serverRes->ssl;

    ASSERT_TRUE(testCtx->negotiatedInfo.negotiatedGroup == HITLS_EC_GROUP_SECP256R1);

EXIT:
    HLT_FreeAllProcess();
}
/* END_CASE */

int32_t REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len);

int32_t STUB_REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len)
{
    (void)ctx;
    *len = 100;
    return HITLS_SUCCESS;
}

/* @
* @test  SDV_TLS_CM_FRAGMENTATION_FUNC_TC001
* @title  DTLS Message Fragmentation
* @precon  nan
* @brief
* 1. Initialize the client and server processes.
* 2. The interface for obtaining the maximum message length is stubbed and the maximum message length is changed to 100.
* 3. Creat and connect linck.
* @expect
* 1. The initialization is successful.
* 2. The stub is successful.
* 3. The link is set up successfully.
@ */
/* BEGIN_CASE */
void SDV_TLS_CM_FRAGMENTATION_FUNC_TC001(void)
{
    if (!IsEnableSctpAuth()) {
        return;
    }
    HLT_Tls_Res *serverRes = NULL;
    HLT_Tls_Res *clientRes = NULL;
    HLT_Process *localProcess = NULL;
    HLT_Process *remoteProcess = NULL;
    HLT_Ctx_Config *serverConfig = NULL;
    HLT_Ctx_Config *clientConfig = NULL;

    localProcess = HLT_InitLocalProcess(HITLS);
    ASSERT_TRUE(localProcess != NULL);
    HILT_TransportType connType = SCTP;
    remoteProcess = HLT_LinkRemoteProcess(HITLS, connType, Port, false);
    ASSERT_TRUE(remoteProcess != NULL);

    serverConfig = HLT_NewCtxConfig(NULL, "SERVER");
    clientConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    ASSERT_TRUE(serverConfig != NULL);
    ASSERT_TRUE(clientConfig != NULL);

    serverRes = HLT_ProcessTlsAccept(remoteProcess, DTLS1_2, serverConfig, NULL);
    ASSERT_TRUE(serverRes != NULL);
    STUB_REPLACE(REC_GetMaxWriteSize, STUB_REC_GetMaxWriteSize);;

    clientRes = HLT_ProcessTlsInit(localProcess, DTLS1_2, clientConfig, NULL);
    ASSERT_TRUE(clientRes != NULL);

    ASSERT_TRUE(HLT_TlsConnect(clientRes->ssl) == 0);
EXIT:
    STUB_RESTORE(REC_GetMaxWriteSize);
    HLT_FreeAllProcess();
}
/* END_CASE */